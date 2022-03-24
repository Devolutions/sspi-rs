pub mod config;
// #[cfg(feature = "with_reqwest")]
mod client;
pub mod reqwest_client;
mod server;

use thiserror::Error;
use url::Url;

use self::config::KerberosConfig;
use super::ntlm::AuthIdentityBuffers;
use crate::{
    sspi,
    sspi::{Sspi, SspiEx, SspiImpl},
    AcquireCredentialsHandleResult, AuthIdentity, CredentialUse,
};

pub const KERBEROS_VERSION: u8 = 0x05;
pub const SERVICE_NAME: &str = "krbtgt";

#[derive(Error, Debug)]
pub enum NetworkClientError {
    #[error("url error: {0}")]
    UrlError(String),
    #[error("IO error: {0:?}")]
    IoError(#[from] std::io::Error),
}

pub trait NetworkClient {
    fn send(&self, url: Url, data: &[u8]) -> Result<Vec<u8>, NetworkClientError>;
    fn send_http(&self, url: Url, data: &[u8]) -> Result<Vec<u8>, NetworkClientError>;
}

pub enum KerberosState {
    Preauthentication,
    ApExchange,
    Final,
}

pub struct Kerberos {
    state: KerberosState,
    config: KerberosConfig,
    auth_identity: Option<AuthIdentityBuffers>,
}

impl Kerberos {
    pub fn with_config(config: KerberosConfig) -> Self {
        Self {
            state: KerberosState::Preauthentication,
            config,
            auth_identity: None,
        }
    }
}

impl Sspi for Kerberos {
    fn complete_auth_token(
        &mut self,
        token: &mut [crate::SecurityBuffer],
    ) -> crate::Result<crate::SecurityStatus> {
        todo!()
    }

    fn encrypt_message(
        &mut self,
        flags: crate::EncryptionFlags,
        message: &mut [crate::SecurityBuffer],
        sequence_number: u32,
    ) -> crate::Result<crate::SecurityStatus> {
        todo!()
    }

    fn decrypt_message(
        &mut self,
        message: &mut [crate::SecurityBuffer],
        sequence_number: u32,
    ) -> crate::Result<crate::DecryptionFlags> {
        todo!()
    }

    fn query_context_sizes(&mut self) -> crate::Result<crate::ContextSizes> {
        todo!()
    }

    fn query_context_names(&mut self) -> crate::Result<crate::ContextNames> {
        todo!()
    }

    fn query_context_package_info(&mut self) -> crate::Result<crate::PackageInfo> {
        todo!()
    }

    fn query_context_cert_trust_status(&mut self) -> crate::Result<crate::CertTrustStatus> {
        todo!()
    }
}

impl SspiImpl for Kerberos {
    type CredentialsHandle = Option<AuthIdentityBuffers>;

    type AuthenticationData = AuthIdentity;

    fn acquire_credentials_handle_impl(
        &mut self,
        builder: crate::builders::FilledAcquireCredentialsHandle<
            '_,
            Self,
            Self::CredentialsHandle,
            Self::AuthenticationData,
        >,
    ) -> super::Result<crate::AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        if builder.credential_use == CredentialUse::Outbound && builder.auth_data.is_none() {
            return Err(sspi::Error::new(
                sspi::ErrorKind::NoCredentials,
                String::from("The client must specify the auth data"),
            ));
        }

        self.auth_identity = builder.auth_data.cloned().map(AuthIdentityBuffers::from);

        Ok(AcquireCredentialsHandleResult {
            credentials_handle: self.auth_identity.clone(),
            expiry: None,
        })
    }

    fn initialize_security_context_impl(
        &mut self,
        builder: crate::builders::FilledInitializeSecurityContext<
            '_,
            Self,
            Self::CredentialsHandle,
        >,
    ) -> super::Result<crate::InitializeSecurityContextResult> {
        let credentials = builder.credentials_handle.unwrap().as_ref().unwrap();
        //
        let state = match self.state {
            KerberosState::Preauthentication => {}
            KerberosState::ApExchange => {}
            KerberosState::Final => {}
        };
        todo!()
    }

    fn accept_security_context_impl(
        &mut self,
        builder: crate::builders::FilledAcceptSecurityContext<'_, Self, Self::CredentialsHandle>,
    ) -> super::Result<crate::AcceptSecurityContextResult> {
        todo!()
    }
}

impl SspiEx for Kerberos {
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) {
        self.auth_identity = Some(identity.into());
    }
}
