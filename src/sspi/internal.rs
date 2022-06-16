pub mod credssp;

use crate::sspi::builders::{
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, InitializeSecurityContextResult,
};
use crate::sspi::{self, FilledAcceptSecurityContext, FilledAcquireCredentialsHandle, FilledInitializeSecurityContext};

pub trait SspiImpl {
    type CredentialsHandle;
    type AuthenticationData;

    fn acquire_credentials_handle_impl<'a>(
        &'a mut self,
        builder: FilledAcquireCredentialsHandle<'a, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> sspi::Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>>;

    fn initialize_security_context_impl<'a>(
        &mut self,
        builder: &mut FilledInitializeSecurityContext<'a, Self::CredentialsHandle>,
    ) -> sspi::Result<InitializeSecurityContextResult>;

    fn accept_security_context_impl<'a>(
        &'a mut self,
        builder: FilledAcceptSecurityContext<'a, Self::AuthenticationData, Self::CredentialsHandle>,
    ) -> sspi::Result<AcceptSecurityContextResult>;
}
