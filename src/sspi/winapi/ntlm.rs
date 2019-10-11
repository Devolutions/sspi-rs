use std::{marker::PhantomData, ptr};

use winapi::shared::rpcdce::SEC_WINNT_AUTH_IDENTITY_W;

use super::{
    str_to_win_wstring, CredentialsGuard, SecurityPackage, SEC_WINNT_AUTH_IDENTITY_UNICODE,
};
use crate::sspi::{
    self,
    builders::{
        AcceptSecurityContextResult, AcquireCredentialsHandle, AcquireCredentialsHandleResult,
        InitializeSecurityContextResult,
    },
    internal::SspiImpl,
    ntlm::AuthIdentity,
    CertTrustStatus, ContextNames, ContextSizes, DecryptionFlags, EncryptionFlags,
    FilledAcceptSecurityContext, FilledAcquireCredentialsHandle, FilledInitializeSecurityContext,
    PackageInfo, SecurityBuffer, SecurityPackageType, SecurityStatus, Sspi,
};

/// Represents a wrapper for Windows-provided NTLM.
pub struct Ntlm(SecurityPackage);

impl Ntlm {
    pub fn new() -> Self {
        Self(SecurityPackage::from_package_type(
            SecurityPackageType::Ntlm,
        ))
    }
}

impl Default for Ntlm {
    fn default() -> Self {
        Self::new()
    }
}

impl SspiImpl for Ntlm {
    type CredentialsHandle = CredentialsGuard;
    type AuthenticationData = AuthIdentity;

    fn acquire_credentials_handle_impl(
        &mut self,
        builder: FilledAcquireCredentialsHandle<
            '_,
            Self,
            Self::CredentialsHandle,
            Self::AuthenticationData,
        >,
    ) -> sspi::Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        let (identity, _auth_data) = if let Some(auth_data) = builder.auth_data {
            let domain_str = auth_data.domain.clone().unwrap_or_default();
            let mut user = str_to_win_wstring(auth_data.username.as_str());
            let mut domain = str_to_win_wstring(domain_str.as_str());
            let mut password = str_to_win_wstring(auth_data.password.as_str());

            let mut identity = SEC_WINNT_AUTH_IDENTITY_W {
                User: user.as_mut_ptr(),
                UserLength: auth_data.username.len() as u32,
                Domain: domain.as_mut_ptr(),
                DomainLength: domain_str.len() as u32,
                Password: password.as_mut_ptr(),
                PasswordLength: auth_data.password.len() as u32,
                Flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
            };

            (
                &mut identity as *mut _ as *mut _,
                Some((user, domain, password)),
            )
        } else {
            (ptr::null_mut(), None)
        };

        let builder = AcquireCredentialsHandle {
            inner: Some(&mut self.0),
            phantom_cred_handle: PhantomData,
            phantom_cred_use_set: PhantomData,

            credential_use: builder.credential_use,

            principal_name: builder.principal_name,
            logon_id: builder.logon_id,
            auth_data: Some(&identity),
        };

        builder.execute()
    }

    fn initialize_security_context_impl(
        &mut self,
        builder: FilledInitializeSecurityContext<'_, Self, Self::CredentialsHandle>,
    ) -> sspi::Result<InitializeSecurityContextResult> {
        builder.transform(&mut self.0).execute()
    }

    fn accept_security_context_impl(
        &mut self,
        builder: FilledAcceptSecurityContext<'_, Self, Self::CredentialsHandle>,
    ) -> sspi::Result<AcceptSecurityContextResult> {
        builder.transform(&mut self.0).execute()
    }
}

impl Sspi for Ntlm {
    fn complete_auth_token(
        &mut self,
        token: &mut [SecurityBuffer],
    ) -> sspi::Result<SecurityStatus> {
        self.0.complete_auth_token(token)
    }

    fn encrypt_message(
        &mut self,
        flags: EncryptionFlags,
        message: &mut [SecurityBuffer],
        sequence_number: u32,
    ) -> sspi::Result<SecurityStatus> {
        self.0.encrypt_message(flags, message, sequence_number)
    }

    fn decrypt_message(
        &mut self,
        message: &mut [SecurityBuffer],
        sequence_number: u32,
    ) -> sspi::Result<DecryptionFlags> {
        self.0.decrypt_message(message, sequence_number)
    }

    fn query_context_sizes(&mut self) -> sspi::Result<ContextSizes> {
        self.0.query_context_sizes()
    }

    fn query_context_names(&mut self) -> sspi::Result<ContextNames> {
        self.0.query_context_names()
    }

    fn query_context_package_info(&mut self) -> sspi::Result<PackageInfo> {
        self.0.query_context_package_info()
    }
    fn query_context_cert_trust_status(&mut self) -> sspi::Result<CertTrustStatus> {
        self.0.query_context_cert_trust_status()
    }
}
