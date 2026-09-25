mod change_password;
pub mod extractors;
pub mod generators;
pub mod kdc;
pub mod principal;

use self::extractors::{
    decrypt_ap_rep, extract_encryption_params_from_as_rep, extract_seq_number_from_ap_rep,
    extract_sub_session_key_from_ap_rep, extract_tgt_ticket_with_oid,
};
use self::generators::{
    ChecksumOptions, ChecksumValues, EncKey, GenerateAsReqOptions, GenerateAuthenticatorOptions, GssFlags,
    generate_ap_rep, generate_ap_req, generate_as_req_kdc_body, generate_authenticator,
};
use self::principal::{
    ClientPrincipalName, get_client_principal_name, get_client_principal_name_type, get_client_principal_realm,
};
use crate::channel_bindings::ChannelBindings;
use crate::generator::YieldPointLocal;
use crate::kerberos::client::generators::generate_tgt_req;
use crate::kerberos::config::KdcResolution;
use crate::kerberos::messages::{decode_krb_message, generate_iakrb_proxy_message, generate_krb_message};
use crate::kerberos::pa_datas::AsRepSessionKeyExtractor;
use crate::kerberos::utils::serialize_message;
use crate::kerberos::{DEFAULT_ENCRYPTION_TYPE, EC, TGT_SERVICE_NAME};
use crate::pku2u::generate_authenticator_extension;
use crate::utils::{generate_random_symmetric_key, parse_target_name};
use crate::{
    BufferType, ClientRequestFlags, ClientResponseFlags, CredentialsBuffers, Error, ErrorKind,
    InitializeSecurityContextResult, Kerberos, KerberosState, Result, Secret, SecurityBuffer, SecurityStatus, SspiImpl,
};
pub use change_password::change_password;
use kdc::as_exchange::{AsExchange, AsExchangeOutput};
use kdc::tgs_exchange::{TgsExchange, TgsExchangeOutput};
use oid::ObjectIdentifier;
use picky_asn1_x509::oids;
use picky_krb::constants::gss_api::{AP_REP_TOKEN_ID, AP_REQ_TOKEN_ID, AUTHENTICATOR_CHECKSUM_TYPE, TGT_REQ_TOKEN_ID};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{PrincipalName, Ticket};
use picky_krb::messages::{ApRep, AsRep, TgsRep};
use rand::rngs::{StdRng, SysRng};
use rand_core::{Rng as _, SeedableRng as _};
use std::io::Write;

#[allow(
    clippy::enum_variant_names,
    reason = "the `Exchange` postfix is meaningful for these variant names"
)]
#[derive(Debug, Default, Clone, PartialEq)]
pub enum KerberosClientState {
    #[default]
    TgtExchange,
    BeforeAsExchange,
    AsExchange {
        as_exchange: AsExchange,
        mech_id: ObjectIdentifier,
        tgt_ticket: Option<Ticket>,
    },
    BeforeTgsExchange {
        as_rep: AsRep,
        mech_id: ObjectIdentifier,
        tgt_ticket: Option<Ticket>,
    },
    TgsExchange {
        tgs_exchange: TgsExchange,
        context_requirements: ClientRequestFlags,
        mech_id: ObjectIdentifier,
    },
    BeforeApExchange {
        tgs_rep: TgsRep,
        session_key: Secret<Vec<u8>>,
        context_requirements: ClientRequestFlags,
        mech_id: ObjectIdentifier,
    },
    ApExchange,
}

/// Inspects the `sname` of a ticket returned in a TGS-REP to decide whether it is a cross-realm
/// referral TGT rather than the requested service ticket.
///
/// A referral TGT has an `sname` of the form `krbtgt/<NEXT_REALM>` (RFC 4120 §3.3.3.2). In that
/// case this returns `Some(next_realm)` and the caller must re-issue the TGS-REQ to `<NEXT_REALM>`.
/// For an actual service ticket (e.g. `TERMSRV/host`) it returns `None`.
fn referral_target_realm(sname: &PrincipalName) -> Option<String> {
    let names = &sname.name_string.0.0;

    match names.as_slice() {
        [service, realm] if service.to_string().eq_ignore_ascii_case(TGT_SERVICE_NAME) => Some(realm.to_string()),
        _ => None,
    }
}

/// Performs one authentication step.
///
/// The user should call this function until it returns `SecurityStatus::Ok`.
pub async fn initialize_security_context<'a>(
    client: &'a mut Kerberos,
    yield_point: &mut YieldPointLocal,
    builder: &'a mut crate::builders::FilledInitializeSecurityContext<
        '_,
        '_,
        <Kerberos as SspiImpl>::CredentialsHandle,
    >,
) -> Result<InitializeSecurityContextResult> {
    trace!(?builder);

    loop {
        let status = match std::mem::replace(&mut client.state, KerberosState::Client(Box::default())) {
            KerberosState::Client(state) => {
                match *state {
                    KerberosClientState::TgtExchange => {
                        if builder
                            .context_requirements
                            .contains(ClientRequestFlags::USE_SESSION_KEY)
                        {
                            client.krb5_user_to_user = true;

                            let (service_name, service_principal_name) =
                                parse_target_name(builder.target_name.ok_or_else(|| {
                                    Error::new(
                                        ErrorKind::NoCredentials,
                                        "Service target name (service principal name) is not provided",
                                    )
                                })?)?;

                            debug!(
                                ?service_name,
                                ?service_principal_name,
                                "target_name = {:?}",
                                builder.target_name
                            );

                            let tgt_req = generate_tgt_req(&[service_name, service_principal_name])?;

                            let encoded_neg_tgt_req =
                                if !builder.context_requirements.contains(ClientRequestFlags::USE_DCE_STYLE) {
                                    generate_krb_message(oids::krb5_user_to_user(), TGT_REQ_TOKEN_ID, tgt_req)?
                                } else {
                                    // Do not wrap if the `USE_DCE_STYLE` flag is set.
                                    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/190ab8de-dc42-49cf-bf1b-ea5705b7a087
                                    picky_asn1_der::to_vec(&tgt_req)?
                                };

                            let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                            output_token.buffer = encoded_neg_tgt_req;

                            client.state = KerberosState::Client(Box::new(KerberosClientState::BeforeAsExchange));

                            Some(SecurityStatus::ContinueNeeded)
                        } else {
                            client.state = KerberosState::Client(Box::new(KerberosClientState::BeforeAsExchange));

                            None
                        }
                    }
                    KerberosClientState::BeforeAsExchange => {
                        let input = builder
                            .input
                            .as_ref()
                            .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "input buffers must be specified"))?;

                        if let Ok(sec_buffer) = SecurityBuffer::find_buffer(input, BufferType::ChannelBindings) {
                            client.channel_bindings = Some(ChannelBindings::from_bytes(&sec_buffer.buffer)?);
                        }

                        let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)
                            .map(|security_buffer| security_buffer.buffer.as_slice())
                            .unwrap_or_default();

                        let (tgt_ticket, mech_id) =
                            if let Some((tbt_ticket, mech_oid)) = extract_tgt_ticket_with_oid(input_token)? {
                                (Some(tbt_ticket), mech_oid.0)
                            } else {
                                (None, oids::krb5())
                            };
                        client.krb5_user_to_user = mech_id == oids::krb5_user_to_user();

                        let credentials =
                            builder.credentials_handle.as_ref().unwrap().as_ref().ok_or_else(|| {
                                Error::new(ErrorKind::WrongCredentialHandle, "No credentials provided")
                            })?;

                        let (username, realm, cname_type) = match credentials {
                            CredentialsBuffers::AuthIdentity(auth_identity) => {
                                let username = auth_identity.user.to_string();
                                let domain = auth_identity.domain.to_string();

                                let realm = get_client_principal_realm(&username, &domain);
                                let cname_type = get_client_principal_name_type(&username, &domain);

                                (username, realm, cname_type)
                            }
                            #[cfg(feature = "scard")]
                            CredentialsBuffers::SmartCard(smart_card) => {
                                let username = smart_card.username.to_string();

                                let realm = get_client_principal_realm(&username, "");
                                let cname_type = get_client_principal_name_type(&username, "");

                                (username, realm.to_uppercase(), cname_type)
                            }
                            CredentialsBuffers::Keytab(keytab) => {
                                // The name type is read off the principal's user name format explicitly.
                                let ClientPrincipalName {
                                    name,
                                    realm_domain,
                                    name_type,
                                } = get_client_principal_name(&keytab.principal);

                                let realm = get_client_principal_realm(name, realm_domain);

                                (name.to_owned(), realm, name_type)
                            }
                        };

                        client.realm = Some(realm.clone());

                        let mut rand = StdRng::try_from_rng(&mut SysRng)?;
                        let options = GenerateAsReqOptions {
                            realm: &realm,
                            username: &username,
                            cname_type,
                            snames: &[TGT_SERVICE_NAME, &realm],
                            // 4 = size of u32
                            nonce: &rand.next_u32().to_be_bytes(),
                            hostname: &client.config.client_computer_name,
                            context_requirements: builder.context_requirements,
                        };
                        let kdc_req_body = generate_as_req_kdc_body(&options)?;

                        let salt = match credentials {
                            CredentialsBuffers::AuthIdentity(auth_identity) => {
                                let domain = auth_identity.domain.to_string();
                                format!("{domain}{username}").into_bytes()
                            }
                            _ => Vec::new(),
                        };

                        #[cfg(feature = "scard")]
                        {
                            use crate::pku2u::generate_client_dh_parameters;

                            client.dh_parameters = Some(generate_client_dh_parameters(&mut rand));
                        }

                        let as_exchange = AsExchange::new(
                            client.is_iakerb(),
                            kdc_req_body,
                            credentials.extract_password(),
                            salt,
                            #[cfg(feature = "scard")]
                            client.dh_parameters.clone().expect("DH parameters are set above"),
                            #[cfg(feature = "scard")]
                            rand.next_u32().to_be_bytes(),
                        );

                        client.state = KerberosState::Client(Box::new(KerberosClientState::AsExchange {
                            as_exchange,
                            mech_id,
                            tgt_ticket,
                        }));

                        None
                    }
                    KerberosClientState::AsExchange {
                        mut as_exchange,
                        mech_id,
                        tgt_ticket,
                    } => {
                        let credentials =
                            builder.credentials_handle.as_ref().unwrap().as_ref().ok_or_else(|| {
                                Error::new(ErrorKind::WrongCredentialHandle, "No credentials provided")
                            })?;

                        match client.config.kdc_resolution {
                            KdcResolution::IAKerb => {
                                let input = builder.input.as_ref().ok_or_else(|| {
                                    Error::new(ErrorKind::InvalidToken, "input buffers must be specified")
                                })?;

                                let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)
                                    .map(|security_buffer| security_buffer.buffer.as_slice())
                                    .unwrap_or_default();

                                match as_exchange.step(
                                    credentials,
                                    &client.encryption_params,
                                    input_token,
                                    &mut client.iakerb_cookie,
                                    &mut client.iakerb_gss_transcript,
                                )? {
                                    AsExchangeOutput::SendRequest(as_req) => {
                                        let output_token =
                                            SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                                        output_token.buffer =
                                            generate_iakrb_proxy_message(client.iakerb_cookie.take(), as_req)?;
                                        client.iakerb_gss_transcript.extend_from_slice(&output_token.buffer);

                                        client.state =
                                            KerberosState::Client(Box::new(KerberosClientState::AsExchange {
                                                as_exchange,
                                                mech_id,
                                                tgt_ticket,
                                            }));

                                        Some(SecurityStatus::ContinueNeeded)
                                    }
                                    AsExchangeOutput::Done(as_rep) => {
                                        client.state =
                                            KerberosState::Client(Box::new(KerberosClientState::BeforeTgsExchange {
                                                as_rep,
                                                mech_id,
                                                tgt_ticket,
                                            }));

                                        None
                                    }
                                }
                            }
                            KdcResolution::KdcUrl(_) => {
                                let mut as_response = Vec::new();

                                let as_rep = loop {
                                    let output = as_exchange.step(
                                        credentials,
                                        &client.encryption_params,
                                        &as_response,
                                        &mut client.iakerb_cookie,
                                        &mut client.iakerb_gss_transcript,
                                    )?;
                                    match output {
                                        AsExchangeOutput::SendRequest(as_req) => {
                                            as_response =
                                                client.send(yield_point, &serialize_message(&as_req)?).await?;
                                        }
                                        AsExchangeOutput::Done(as_rep) => {
                                            break as_rep;
                                        }
                                    }
                                };

                                client.state =
                                    KerberosState::Client(Box::new(KerberosClientState::BeforeTgsExchange {
                                        as_rep,
                                        mech_id,
                                        tgt_ticket,
                                    }));

                                None
                            }
                        }
                    }
                    KerberosClientState::BeforeTgsExchange {
                        as_rep,
                        mech_id,
                        tgt_ticket,
                    } => {
                        debug!("AS exchange finished successfully.");

                        client.realm = Some(as_rep.0.crealm.0.to_string());

                        let (encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep)?;

                        let encryption_type = CipherSuite::try_from(usize::from(encryption_type))?;

                        client.encryption_params.encryption_type = Some(encryption_type);

                        let credentials =
                            builder.credentials_handle.as_ref().unwrap().as_ref().ok_or_else(|| {
                                Error::new(ErrorKind::WrongCredentialHandle, "No credentials provided")
                            })?;
                        let password = credentials.extract_password();

                        let mut session_key_extractor = match credentials {
                            CredentialsBuffers::AuthIdentity(_) => AsRepSessionKeyExtractor::AuthIdentity {
                                salt: &salt,
                                password: password.as_ref(),
                                enc_params: &mut client.encryption_params,
                            },
                            CredentialsBuffers::Keytab(keytab) => AsRepSessionKeyExtractor::Keytab {
                                key: keytab.key.as_ref(),
                                enc_params: &client.encryption_params,
                            },
                            #[cfg(feature = "scard")]
                            CredentialsBuffers::SmartCard(_) => AsRepSessionKeyExtractor::SmartCard {
                                dh_parameters: client.dh_parameters.as_mut().unwrap(),
                                enc_params: &mut client.encryption_params,
                            },
                        };
                        let session_key = session_key_extractor.session_key(&as_rep)?;

                        let mut context_requirements = builder.context_requirements;

                        if client.krb5_user_to_user
                            && !context_requirements.contains(ClientRequestFlags::USE_SESSION_KEY)
                        {
                            warn!(
                                "KRB5 U2U has been negotiated (selected by the server) but the USE_SESSION_KEY flag is not set. Forcibly turning it on..."
                            );
                            context_requirements.set(ClientRequestFlags::USE_SESSION_KEY, true);
                        }

                        client.state = KerberosState::Client(Box::new(KerberosClientState::TgsExchange {
                            tgs_exchange: TgsExchange::new(
                                client.is_iakerb(),
                                as_rep.0.crealm.to_string(),
                                as_rep.0.ticket.0.clone(),
                                session_key,
                                // KDC-REP that the AP_REQ authenticator (cname/crealm) for the next hop is built from.
                                as_rep.0.clone(),
                                // Only meaningful for U2U; carried on the first hop and dropped afterwards.
                                tgt_ticket.map(|ticket| vec![ticket]),
                                context_requirements,
                            ),
                            context_requirements,
                            mech_id,
                        }));

                        None
                    }
                    KerberosClientState::TgsExchange {
                        mut tgs_exchange,
                        context_requirements,
                        mech_id,
                    } => {
                        let service_principal = builder.target_name.ok_or_else(|| {
                            Error::new(
                                ErrorKind::NoCredentials,
                                "Service target name (service principal name) is not provided",
                            )
                        })?;

                        match client.config.kdc_resolution {
                            KdcResolution::IAKerb => {
                                let input = builder.input.as_ref().ok_or_else(|| {
                                    Error::new(ErrorKind::InvalidToken, "input buffers must be specified")
                                })?;
                                let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)
                                    .map(|security_buffer| security_buffer.buffer.as_slice())
                                    .unwrap_or_default();

                                match tgs_exchange.step(
                                    client.channel_bindings.as_ref(),
                                    &client.encryption_params,
                                    service_principal,
                                    input_token,
                                    &mut client.iakerb_cookie,
                                    &mut client.iakerb_gss_transcript,
                                )? {
                                    TgsExchangeOutput::SendRequest((tgs_req, _realm)) => {
                                        let output_token =
                                            SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                                        output_token.buffer =
                                            generate_iakrb_proxy_message(client.iakerb_cookie.take(), tgs_req)?;
                                        client.iakerb_gss_transcript.extend_from_slice(&output_token.buffer);

                                        client.state =
                                            KerberosState::Client(Box::new(KerberosClientState::TgsExchange {
                                                tgs_exchange,
                                                context_requirements,
                                                mech_id,
                                            }));

                                        Some(SecurityStatus::ContinueNeeded)
                                    }
                                    TgsExchangeOutput::Done((tgs_rep, session_key)) => {
                                        client.state =
                                            KerberosState::Client(Box::new(KerberosClientState::BeforeApExchange {
                                                tgs_rep,
                                                session_key,
                                                context_requirements,
                                                mech_id,
                                            }));

                                        None
                                    }
                                }
                            }
                            KdcResolution::KdcUrl(_) => {
                                let mut response = Vec::new();

                                loop {
                                    match tgs_exchange.step(
                                        client.channel_bindings.as_ref(),
                                        &client.encryption_params,
                                        service_principal,
                                        &response,
                                        &mut client.iakerb_cookie,
                                        &mut client.iakerb_gss_transcript,
                                    )? {
                                        TgsExchangeOutput::SendRequest((tgs_req, realm)) => {
                                            response = client
                                                .send_for_realm(yield_point, realm, &serialize_message(&tgs_req)?)
                                                .await?;
                                        }
                                        TgsExchangeOutput::Done((tgs_rep, session_key)) => {
                                            client.state = KerberosState::Client(Box::new(
                                                KerberosClientState::BeforeApExchange {
                                                    tgs_rep,
                                                    session_key,
                                                    context_requirements,
                                                    mech_id,
                                                },
                                            ));
                                            break;
                                        }
                                    }
                                }

                                None
                            }
                        }
                    }
                    KerberosClientState::BeforeApExchange {
                        tgs_rep,
                        session_key,
                        context_requirements,
                        mech_id,
                    } => {
                        client.encryption_params.session_key = Some(session_key);

                        let mut rand = StdRng::try_from_rng(&mut SysRng)?;

                        let enc_type = client
                            .encryption_params
                            .encryption_type
                            .as_ref()
                            .unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
                        let authenticator_sub_key = generate_random_symmetric_key(enc_type, &mut rand);

                        // the original flag is
                        // GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG
                        // we want to be able to turn of sign and seal, so we leave confidentiality and integrity flags out
                        let mut flags: GssFlags = builder.context_requirements.into();
                        if flags.contains(GssFlags::GSS_C_DELEG_FLAG) {
                            // Below are reasons why we turn off the GSS_C_DELEG_FLAG flag.
                            //
                            // RFC4121: The Kerberos Version 5 GSS-API. Section 4.1.1:  Authenticator Checksum
                            // https://datatracker.ietf.org/doc/html/rfc4121#section-4.1.1.1
                            //
                            // "The length of the checksum field MUST be at least 24 octets when GSS_C_DELEG_FLAG is not set,
                            // and at least 28 octets plus Dlgth octets when GSS_C_DELEG_FLAG is set."
                            // Out implementation _always_ uses the 24 octets checksum and do not support Kerberos credentials delegation.
                            //
                            // "When delegation is used, a ticket-granting ticket will be transferred in a KRB_CRED message."
                            // We do not support KRB_CRED messages. So, the GSS_C_DELEG_FLAG flags should be turned off.
                            warn!(
                                "Kerberos ApReq Authenticator checksum GSS_C_DELEG_FLAG is not supported. Turning it off..."
                            );
                            flags.remove(GssFlags::GSS_C_DELEG_FLAG);
                        }
                        debug!(?flags, "ApReq Authenticator checksum flags");

                        let mut checksum_value = ChecksumValues::default();
                        checksum_value.set_flags(flags);

                        let extensions = match client.config.kdc_resolution {
                            KdcResolution::IAKerb => {
                                // IAKerb requires an extension of type `GSS_EXTS_FINISHED` that contains `KRB-FINISHED`
                                // with checksum of all IAKerb GSS-API tokens, concatenated in the chronological order.
                                //
                                // [IAKERB Finish Message](https://datatracker.ietf.org/doc/html/draft-ietf-kitten-iakerb-03#section-4)
                                vec![generate_authenticator_extension(
                                    &authenticator_sub_key,
                                    &client.iakerb_gss_transcript,
                                    &enc_type.cipher().checksum_type(),
                                )?]
                            }
                            KdcResolution::KdcUrl(_) => Vec::new(),
                        };

                        let authenticator_options = GenerateAuthenticatorOptions {
                            kdc_rep: &tgs_rep.0,
                            // The AP_REQ Authenticator sequence number should be the same as `seq_num` in the first Kerberos Wrap/MIC token generated
                            // by the `encrypt_message`/`generate_mic_token` method. So, we set the next sequence number but do not increment the counter,
                            // which will be incremented on each `encrypt_message`/`generate_mic_token` method call.
                            seq_num: Some(client.seq_number + 1),
                            sub_key: Some(EncKey {
                                key_type: enc_type.clone(),
                                key_value: authenticator_sub_key,
                            }),

                            checksum: Some(ChecksumOptions {
                                checksum_type: AUTHENTICATOR_CHECKSUM_TYPE.to_vec(),
                                checksum_value,
                            }),
                            channel_bindings: client.channel_bindings.as_ref(),
                            extensions,
                        };

                        let authenticator = generate_authenticator(authenticator_options)?;

                        let ap_req = generate_ap_req(
                            tgs_rep.0.ticket.0,
                            client
                                .encryption_params
                                .session_key
                                .as_ref()
                                .ok_or_else(|| Error::new(ErrorKind::InternalError, "session key is not set"))?,
                            &authenticator,
                            &client.encryption_params,
                            context_requirements.into(),
                        )?;

                        let encoded_neg_ap_req =
                            if !builder.context_requirements.contains(ClientRequestFlags::USE_DCE_STYLE) {
                                generate_krb_message(mech_id, AP_REQ_TOKEN_ID, ap_req)?
                            } else {
                                // Do not wrap if the `USE_DCE_STYLE` flag is set.
                                // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/190ab8de-dc42-49cf-bf1b-ea5705b7a087
                                picky_asn1_der::to_vec(&ap_req)?
                            };

                        let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                        output_token.buffer = encoded_neg_ap_req;

                        client.state = KerberosState::Client(Box::new(KerberosClientState::ApExchange));

                        Some(SecurityStatus::ContinueNeeded)
                    }
                    KerberosClientState::ApExchange => {
                        let input = builder
                            .input
                            .as_ref()
                            .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Input buffers must be specified"))?;
                        let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;

                        if builder.context_requirements.contains(ClientRequestFlags::USE_DCE_STYLE) {
                            debug!("AP Exchange DCE Style");
                            // The `EC` field depends on the authentication type. For example, during RDP auth
                            // it is equal to 0, but during RPC auth it is equal to EC.
                            client.encryption_params.ec = EC;

                            use picky_krb::messages::ApRep;

                            let ap_rep: ApRep = picky_asn1_der::from_bytes(&input_token.buffer)?;

                            let session_key = client
                                .encryption_params
                                .session_key
                                .as_ref()
                                .ok_or_else(|| Error::new(ErrorKind::InternalError, "session key is not set"))?;
                            let ap_rep_enc_part = decrypt_ap_rep(&ap_rep, session_key, &client.encryption_params)?;
                            let sub_session_key = extract_sub_session_key_from_ap_rep(&ap_rep_enc_part)?;
                            client.remote_seq_number = extract_seq_number_from_ap_rep(&ap_rep_enc_part)?;

                            let seq_number_bytes = ap_rep_enc_part
                                .0
                                .seq_number
                                .0
                                .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "missing seq-number in ap_rep"))?
                                .0
                                .0
                                .clone();

                            trace!(?sub_session_key, "DCE AP_REP sub-session key");

                            client.encryption_params.sub_session_key = Some(sub_session_key);

                            let ap_rep = generate_ap_rep(session_key, seq_number_bytes, &client.encryption_params)?;
                            let ap_rep = picky_asn1_der::to_vec(&ap_rep)?;

                            let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                            output_token.buffer.write_all(&ap_rep)?;
                        } else {
                            debug!("AP Exchange NOT DCE Style");
                            let ap_rep = decode_krb_message::<ApRep>(&input_token.buffer, AP_REP_TOKEN_ID)?;

                            let session_key = client
                                .encryption_params
                                .session_key
                                .as_ref()
                                .ok_or_else(|| Error::new(ErrorKind::InternalError, "session key is not set"))?;
                            let ap_rep_enc_part = decrypt_ap_rep(&ap_rep, session_key, &client.encryption_params)?;
                            let sub_session_key = extract_sub_session_key_from_ap_rep(&ap_rep_enc_part)?;
                            client.remote_seq_number = extract_seq_number_from_ap_rep(&ap_rep_enc_part)?;

                            client.encryption_params.sub_session_key = Some(sub_session_key);
                        }

                        client.state = KerberosState::Final;
                        Some(SecurityStatus::Ok)
                    }
                }
            }
            KerberosState::Final | KerberosState::Server(_) => {
                return Err(Error::new(
                    ErrorKind::OutOfSequence,
                    format!("got wrong Kerberos state: {:?}", client.state),
                ));
            }
        };

        if let Some(status) = status {
            trace!(output_buffers = ?builder.output);

            return Ok(InitializeSecurityContextResult {
                status,
                flags: ClientResponseFlags::empty(),
                expiry: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::referral_target_realm;
    use picky_asn1::restricted_string::IA5String;
    use picky_asn1::wrapper::{Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, IntegerAsn1};
    use picky_krb::constants::types::{NT_PRINCIPAL, NT_SRV_INST};
    use picky_krb::data_types::{KerberosStringAsn1, PrincipalName};

    fn principal_name(name_type: u8, names: &[&str]) -> PrincipalName {
        PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![name_type])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(
                names
                    .iter()
                    .map(|n| KerberosStringAsn1::from(IA5String::from_string((*n).to_owned()).unwrap()))
                    .collect::<Vec<_>>(),
            )),
        }
    }

    #[test]
    fn referral_target_realm_detects_cross_realm_tgt() {
        // krbtgt/<NEXT_REALM> => chase into NEXT_REALM.
        let sname = principal_name(NT_SRV_INST, &["krbtgt", "DEV.RJM.LOCAL"]);
        assert_eq!(referral_target_realm(&sname), Some("DEV.RJM.LOCAL".to_owned()));
    }

    #[test]
    fn referral_target_realm_is_case_insensitive_on_service() {
        // The service component comparison must ignore case ("krbtgt" vs "KRBTGT").
        let sname = principal_name(NT_SRV_INST, &["KrbTgt", "CORP.EXAMPLE.COM"]);
        assert_eq!(referral_target_realm(&sname), Some("CORP.EXAMPLE.COM".to_owned()));
    }

    #[test]
    fn referral_target_realm_ignores_actual_service_ticket() {
        // A real service ticket (TERMSRV/host) is not a referral.
        let sname = principal_name(NT_SRV_INST, &["TERMSRV", "WIN-UE7FOENEK0D.dev.rjm.local"]);
        assert_eq!(referral_target_realm(&sname), None);
    }

    #[test]
    fn referral_target_realm_ignores_non_two_component_names() {
        // A lone "krbtgt" (one component) or a 3-component name is not a referral.
        assert_eq!(referral_target_realm(&principal_name(NT_PRINCIPAL, &["krbtgt"])), None);
        assert_eq!(
            referral_target_realm(&principal_name(NT_SRV_INST, &["krbtgt", "A.COM", "B.COM"])),
            None
        );
        assert_eq!(referral_target_realm(&principal_name(NT_SRV_INST, &[])), None);
    }

    #[test]
    fn referral_target_realm_ignores_non_krbtgt_two_component_service() {
        // Two components but not krbtgt (e.g. host-based service with an instance) is not a referral.
        let sname = principal_name(NT_SRV_INST, &["cifs", "fileserver.dev.rjm.local"]);
        assert_eq!(referral_target_realm(&sname), None);
    }
}
