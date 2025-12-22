use crate::builders::FilledAcceptSecurityContext;
use crate::generator::YieldPointLocal;
use crate::{AcceptSecurityContextResult, Negotiate, NegotiatedProtocol, Result, SspiImpl};

/// Performs one authentication step.
///
/// The user should call this function until it returns `SecurityStatus::Ok`.
pub(crate) async fn accept_security_context(
    negotiate: &mut Negotiate,
    yield_point: &mut YieldPointLocal,
    builder: FilledAcceptSecurityContext<'_, <Negotiate as SspiImpl>::CredentialsHandle>,
) -> Result<AcceptSecurityContextResult> {
    match &mut negotiate.protocol {
        NegotiatedProtocol::Pku2u(pku2u) => {
            let mut creds_handle = builder
                .credentials_handle
                .as_ref()
                .and_then(|creds| (*creds).clone())
                .and_then(|creds_handle| creds_handle.auth_identity());
            let new_builder = builder.full_transform(Some(&mut creds_handle));
            pku2u.accept_security_context_impl(yield_point, new_builder).await
        }
        NegotiatedProtocol::Kerberos(kerberos) => kerberos.accept_security_context_impl(yield_point, builder).await,
        NegotiatedProtocol::Ntlm(ntlm) => {
            let mut creds_handle = builder
                .credentials_handle
                .as_ref()
                .and_then(|creds| (*creds).clone())
                .and_then(|creds_handle| creds_handle.auth_identity());
            let new_builder = builder.full_transform(Some(&mut creds_handle));
            ntlm.accept_security_context_impl(new_builder)
        }
    }
}
