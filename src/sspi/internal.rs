pub mod credssp;

use crate::sspi::{
    self,
    builders::{
        AcceptSecurityContextResult, AcquireCredentialsHandleResult,
        InitializeSecurityContextResult,
    },
    FilledAcceptSecurityContext, FilledAcquireCredentialsHandle, FilledInitializeSecurityContext,
};

pub trait SspiImpl
where
    Self: Sized,
{
    type CredentialsHandle;
    type AuthenticationData;

    fn acquire_credentials_handle_impl(
        &mut self,
        builder: FilledAcquireCredentialsHandle<
            '_,
            Self,
            Self::CredentialsHandle,
            Self::AuthenticationData,
        >,
    ) -> sspi::Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>>;

    fn initialize_security_context_impl(
        &mut self,
        builder: FilledInitializeSecurityContext<'_, Self, Self::CredentialsHandle>,
    ) -> sspi::Result<InitializeSecurityContextResult>;

    fn accept_security_context_impl(
        &mut self,
        builder: FilledAcceptSecurityContext<'_, Self, Self::CredentialsHandle>,
    ) -> sspi::Result<AcceptSecurityContextResult>;
}
