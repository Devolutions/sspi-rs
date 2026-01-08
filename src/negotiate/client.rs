use std::io::Write;
use std::mem;

use picky_krb::constants::gss_api::ACCEPT_INCOMPLETE;
use picky_krb::gss_api::{NegTokenTarg, NegTokenTarg1};

use crate::generator::YieldPointLocal;
use crate::negotiate::generators::{
    generate_final_neg_token_targ, generate_mech_type_list, generate_neg_token_init, generate_neg_token_targ_1,
};
use crate::negotiate::NegotiateState;
use crate::utils::parse_target_name;
use crate::{
    AuthIdentity, BufferType, ClientRequestFlags, ClientResponseFlags, CredentialsBuffers, Error, ErrorKind,
    InitializeSecurityContextResult, Negotiate, NegotiatedProtocol, Result, SecurityBuffer, SecurityStatus, SspiImpl,
};

/// Performs one authentication step.
///
/// The user should call this function until it returns `SecurityStatus::Ok`.
#[instrument(ret, fields(protocol = negotiate.protocol_name()), skip_all)]
pub(crate) async fn initialize_security_context<'a>(
    negotiate: &'a mut Negotiate,
    yield_point: &mut YieldPointLocal,
    builder: &'a mut crate::builders::FilledInitializeSecurityContext<
        '_,
        '_,
        <Negotiate as SspiImpl>::CredentialsHandle,
    >,
) -> Result<InitializeSecurityContextResult> {
    if let Some(target_name) = &builder.target_name {
        negotiate.check_target_name_for_ntlm_downgrade(target_name);
    }

    if let Some(Some(CredentialsBuffers::AuthIdentity(identity))) = builder.credentials_handle {
        let auth_identity =
            AuthIdentity::try_from(&*identity).map_err(|e| Error::new(ErrorKind::InvalidParameter, e))?;
        let account_name = auth_identity.username.account_name();
        let domain_name = auth_identity.username.domain_name().unwrap_or("");
        negotiate.negotiate_protocol(account_name, domain_name)?;
        negotiate.auth_identity = Some(CredentialsBuffers::AuthIdentity(auth_identity.into()));
    }

    #[cfg(feature = "scard")]
    if let Some(Some(CredentialsBuffers::SmartCard(identity))) = builder.credentials_handle {
        use crate::NegotiatedProtocol;

        if let NegotiatedProtocol::Ntlm(_) = &negotiate.protocol {
            // If the user provided smart card credentials, then they definitely want to use Kerberos,
            // because NTLM does not support scard logon.

            use crate::kerberos::client::generators::get_client_principal_realm;
            use crate::{detect_kdc_url, Kerberos, KerberosConfig};

            let username = crate::utils::bytes_to_utf16_string(&identity.username)?;
            let host = detect_kdc_url(&get_client_principal_realm(&username, ""))
                .ok_or_else(|| Error::new(ErrorKind::NoAuthenticatingAuthority, "can not detect KDC url"))?;
            debug!("Negotiate: try Kerberos");

            let config = KerberosConfig {
                kdc_url: Some(host),
                client_computer_name: Some(negotiate.client_computer_name.clone()),
            };

            negotiate.protocol = NegotiatedProtocol::Kerberos(Kerberos::new_client_from_config(config)?);
        }
    }

    match negotiate.state {
        NegotiateState::Initial => {
            let sname = if builder
                .context_requirements
                .contains(ClientRequestFlags::USE_SESSION_KEY)
            {
                let (service_name, service_principal_name) =
                    parse_target_name(builder.target_name.ok_or_else(|| {
                        Error::new(
                            ErrorKind::NoCredentials,
                            "Service target name (service principal name) is not provided",
                        )
                    })?)?;

                Some([service_name, service_principal_name])
            } else {
                None
            };

            debug!(?sname);

            let package_list = Negotiate::parse_package_list_config(&negotiate.package_list);
            let mech_types = generate_mech_type_list(
                matches!(&negotiate.protocol, NegotiatedProtocol::Kerberos(_)),
                !package_list.ntlm,
            )?;

            let encoded_neg_token_init = picky_asn1_der::to_vec(&generate_neg_token_init(
                sname.as_ref().map(|sname| sname.as_slice()),
                mech_types,
            )?)?;

            let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
            output_token.buffer.write_all(&encoded_neg_token_init)?;

            negotiate.state = NegotiateState::InProgress;

            Ok(InitializeSecurityContextResult {
                status: SecurityStatus::ContinueNeeded,
                flags: ClientResponseFlags::empty(),
                expiry: None,
            })
        }
        NegotiateState::InProgress => {
            let input = builder
                .input
                .as_mut()
                .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "input buffers must be specified"))?;

            let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;
            let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(input_token.buffer.as_slice())?;
            let NegTokenTarg {
                neg_result,
                supported_mech,
                response_token,
                mech_list_mic,
            } = neg_token_targ.0;

            let neg_result = neg_result.0.map(|neg_result| neg_result.0 .0);
            if neg_result.as_deref() != Some(&ACCEPT_INCOMPLETE) {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    format!("unexpected NegResult: {neg_result:?}. expected ACCEPT_INCOMPLETE({ACCEPT_INCOMPLETE:?})"),
                ));
            }

            if let Some(selected_mech) = supported_mech.0 {
                let selected_mech = &selected_mech.0;

                negotiate.negotiate_protocol_by_mech_type(selected_mech)?;
            }

            let token = response_token.0.map(|token| token.0 .0);
            if let Some(token) = token {
                let input_token = SecurityBuffer::find_buffer_mut(input, BufferType::Token)?;
                input_token.buffer = token;
            }

            let result = match &mut negotiate.protocol {
                NegotiatedProtocol::Pku2u(pku2u) => {
                    let mut credentials_handle =
                        negotiate.auth_identity.as_mut().and_then(|c| c.clone().auth_identity());
                    let mut transformed_builder = builder.full_transform(Some(&mut credentials_handle));

                    let result = pku2u.initialize_security_context_impl(&mut transformed_builder)?;

                    builder.output = mem::take(&mut transformed_builder.output);

                    result
                }
                NegotiatedProtocol::Kerberos(kerberos) => {
                    kerberos.initialize_security_context_impl(yield_point, builder).await?
                }
                NegotiatedProtocol::Ntlm(ntlm) => {
                    let mut credentials_handle =
                        negotiate.auth_identity.as_mut().and_then(|c| c.clone().auth_identity());
                    let mut transformed_builder = builder.full_transform(Some(&mut credentials_handle));

                    let result = ntlm.initialize_security_context_impl(&mut transformed_builder)?;

                    builder.output = mem::take(&mut transformed_builder.output);

                    result
                }
            };

            if result.status == SecurityStatus::Ok {
                negotiate.state = NegotiateState::Ok;

                let mech_list_mic = mech_list_mic.0.map(|token| token.0 .0);
                if let Some(mech_list_mic) = mech_list_mic {
                    let package_list = Negotiate::parse_package_list_config(&negotiate.package_list);
                    let mech_types = generate_mech_type_list(
                        matches!(&negotiate.protocol, NegotiatedProtocol::Kerberos(_)),
                        !package_list.ntlm,
                    )?;
                    let mech_types = picky_asn1_der::to_vec(&mech_types)?;

                    negotiate.protocol.validate_mic_token(&mech_list_mic, &mech_types)?;
                }

                prepare_final_neg_token(negotiate, builder)?;
            } else {
                if let Some(token) = SecurityBuffer::find_buffer_mut(&mut builder.output, BufferType::Token).ok() {
                    let output_token = if !builder.context_requirements.contains(ClientRequestFlags::USE_DCE_STYLE) {
                        // Wrap in a NegToken.
                        picky_asn1_der::to_vec(&generate_neg_token_targ_1(Some(mem::take(&mut token.buffer))))?
                    } else {
                        // Do not wrap if the `USE_DCE_STYLE` flag is set.
                        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/190ab8de-dc42-49cf-bf1b-ea5705b7a087
                        mem::take(&mut token.buffer)
                    };

                    token.buffer = output_token;
                }
            }

            Ok(result)
        }
        NegotiateState::Ok => Err(Error::new(
            ErrorKind::OutOfSequence,
            "initialize_security_context called after negotiation completed",
        )),
    }
}

fn prepare_final_neg_token(
    negotiate: &mut Negotiate,
    builder: &mut crate::builders::FilledInitializeSecurityContext<'_, '_, <Negotiate as SspiImpl>::CredentialsHandle>,
) -> Result<()> {
    let package_list = Negotiate::parse_package_list_config(&negotiate.package_list);
    let mech_types = generate_mech_type_list(
        matches!(&negotiate.protocol, NegotiatedProtocol::Kerberos(_)),
        !package_list.ntlm,
    )?;
    let mech_types = picky_asn1_der::to_vec(&mech_types)?;
    let neg_token_targ = generate_final_neg_token_targ(Some(negotiate.protocol.generate_mic_token(&mech_types)?));

    let encoded_final_neg_token_targ = picky_asn1_der::to_vec(&neg_token_targ)?;

    let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
    output_token.buffer.write_all(&encoded_final_neg_token_targ)?;

    Ok(())
}
