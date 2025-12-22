use crate::generator::YieldPointLocal;
use crate::ntlm::NtlmConfig;
use crate::{
    AuthIdentity, CredentialsBuffers, Error, ErrorKind, InitializeSecurityContextResult, Negotiate, NegotiatedProtocol,
    Ntlm, Result, SspiImpl,
};

/// Performs one authentication step.
///
/// The user should call this function until it returns `SecurityStatus::Ok`.
#[instrument(ret, fields(protocol = negotiate.protocol_name()), skip_all)]
pub(crate) async fn initialize_security_context<'a>(
    negotiate: &'a mut Negotiate,
    yield_point: &mut YieldPointLocal,
    builder: &'a mut crate::builders::FilledInitializeSecurityContext<'_, <Negotiate as SspiImpl>::CredentialsHandle>,
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

    if let NegotiatedProtocol::Kerberos(kerberos) = &mut negotiate.protocol {
        match kerberos.initialize_security_context_impl(yield_point, builder).await {
            Result::Err(Error {
                error_type: ErrorKind::NoCredentials,
                ..
            }) => {
                warn!("Negotiate: Fall back to the NTLM");

                let ntlm_config = kerberos
                    .config()
                    .client_computer_name
                    .clone()
                    .map(NtlmConfig::new)
                    .unwrap_or_default();
                negotiate.protocol = NegotiatedProtocol::Ntlm(Ntlm::with_auth_identity(
                    negotiate.auth_identity.clone().and_then(|c| c.auth_identity()),
                    ntlm_config,
                ));
            }
            result => return result,
        };
    }

    match &mut negotiate.protocol {
        NegotiatedProtocol::Pku2u(pku2u) => {
            let mut credentials_handle = negotiate.auth_identity.as_mut().and_then(|c| c.clone().auth_identity());
            let mut transformed_builder = builder.full_transform(Some(&mut credentials_handle));

            pku2u.initialize_security_context_impl(&mut transformed_builder)
        }
        NegotiatedProtocol::Kerberos(kerberos) => kerberos.initialize_security_context_impl(yield_point, builder).await,
        NegotiatedProtocol::Ntlm(ntlm) => {
            let mut credentials_handle = negotiate.auth_identity.as_mut().and_then(|c| c.clone().auth_identity());
            let mut transformed_builder = builder.full_transform(Some(&mut credentials_handle));

            ntlm.initialize_security_context_impl(&mut transformed_builder)
        }
    }
}
