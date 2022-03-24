pub mod config;
// #[cfg(feature = "with_reqwest")]
mod client;
pub mod reqwest_client;
mod server;
mod utils;

use picky_krb::messages::{AsRep, TgsRep};
use thiserror::Error;
use url::Url;

use self::config::KerberosConfig;
use self::{
    client::{
        extract_encryption_params_from_as_rep, extract_session_key_from_as_rep, generate_as_req,
        generate_authenticator_from_as_rep, generate_tgs_req,
    },
    utils::serialize_message,
};
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
    fn send(&self, url: &Url, data: &[u8]) -> Result<Vec<u8>, NetworkClientError>;
    fn send_http(&self, url: &Url, data: &[u8]) -> Result<Vec<u8>, NetworkClientError>;
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
        _token: &mut [crate::SecurityBuffer],
    ) -> crate::Result<crate::SecurityStatus> {
        todo!()
    }

    fn encrypt_message(
        &mut self,
        _flags: crate::EncryptionFlags,
        _message: &mut [crate::SecurityBuffer],
        _sequence_number: u32,
    ) -> crate::Result<crate::SecurityStatus> {
        todo!()
    }

    fn decrypt_message(
        &mut self,
        _message: &mut [crate::SecurityBuffer],
        _sequence_number: u32,
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

        let state = match self.state {
            KerberosState::Preauthentication => {
                let username = String::from_utf8(credentials.user.clone()).unwrap();
                let domain = String::from_utf8(credentials.domain.clone()).unwrap();
                let password = String::from_utf8(credentials.password.clone()).unwrap();

                let as_req = generate_as_req(&username, &password, &domain);
                let response = self
                    .config
                    .network_client
                    .send(&self.config.url, &serialize_message(&as_req))
                    .unwrap();

                let as_rep: AsRep = picky_asn1_der::from_bytes(&response[4..]).unwrap();

                let (_encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep);
                let authenticator = generate_authenticator_from_as_rep(&as_rep);
                let session_key = extract_session_key_from_as_rep(&as_rep, &salt, &password);

                let tgs_req = generate_tgs_req(
                    &username,
                    &as_rep.0.crealm.0.to_string(),
                    &session_key,
                    as_rep.0.ticket.0,
                    &authenticator,
                );

                let response = self
                    .config
                    .network_client
                    .send(&self.config.url, &serialize_message(&tgs_req))
                    .unwrap();

                let tsg_rep: TgsRep = picky_asn1_der::from_bytes(&response[4..]).unwrap();
                todo!()
            }
            KerberosState::ApExchange => {}
            KerberosState::Final => {}
        };
        todo!()
    }

    fn accept_security_context_impl(
        &mut self,
        _builder: crate::builders::FilledAcceptSecurityContext<'_, Self, Self::CredentialsHandle>,
    ) -> super::Result<crate::AcceptSecurityContextResult> {
        todo!()
    }
}

impl SspiEx for Kerberos {
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) {
        self.auth_identity = Some(identity.into());
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use picky_krb::messages::{AsRep, TgsRep};
    use url::Url;

    use super::reqwest_client::ReqwestNetworkClient;
    use super::NetworkClient;
    use super::{
        client::{
            extract_encryption_params_from_as_rep, extract_session_key_from_as_rep,
            generate_as_req, generate_authenticator_from_as_rep, generate_tgs_req,
        },
        utils::serialize_message,
    };

    #[test]
    fn test_tgs_rep_obraining() {
        let network_client = ReqwestNetworkClient::new();
        let url = Url::from_str("tcp://192.168.0.109:88").unwrap();

        let username = "w83".to_owned();
        let domain = "QKATION.COM".to_owned();
        let password = "qweQWE123!@#".to_owned();

        let as_req = generate_as_req(&username, &password, &domain);

        let response = network_client
            .send(&url, &serialize_message(&as_req))
            .unwrap();

        println!("as response: {:?}", response);

        let as_rep: AsRep = picky_asn1_der::from_bytes(&response[4..]).unwrap();

        let (_encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep);
        let authenticator = generate_authenticator_from_as_rep(&as_rep);
        let session_key = extract_session_key_from_as_rep(&as_rep, &salt, &password);

        let tgs_req = generate_tgs_req(
            &username,
            &as_rep.0.crealm.0.to_string(),
            &session_key,
            as_rep.0.ticket.0,
            &authenticator,
        );

        println!("tgs_req: {:?}", tgs_req);

        let response = network_client
            .send(&url, &serialize_message(&tgs_req))
            .unwrap();

        println!("tgs response: {:?}", response);

        let tgs_rep: TgsRep = picky_asn1_der::from_bytes(&response[4..]).unwrap();
        println!("tgs_rep: {:?}", tgs_rep);
    }
}
