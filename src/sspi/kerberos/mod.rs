pub mod config;
// #[cfg(feature = "with_reqwest")]
mod client;
pub mod reqwest_client;
mod server;
mod utils;

use std::{env, fmt::Debug, io::Write, str::FromStr};

use kerberos_crypto::new_kerberos_cipher;
use lazy_static::lazy_static;
use picky_krb::messages::{ApRep, ApReq, AsRep, TgsRep};
use url::Url;

use self::{
    client::{
        extract_encryption_params_from_as_rep, extract_session_key_from_as_rep,
        extract_session_key_from_tgs_rep, generate_ap_req, generate_as_req,
        generate_authenticator_from_kdc_rep, generate_tgs_req,
    },
    config::KerberosConfig,
    reqwest_client::ReqwestNetworkClient,
    utils::serialize_message,
};
use super::ntlm::AuthIdentityBuffers;
use crate::{
    sspi,
    sspi::{Error, ErrorKind, Result, Sspi, SspiEx, SspiImpl, PACKAGE_ID_NONE},
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity, ClientResponseFlags,
    ContextNames, ContextSizes, CredentialUse, DecryptionFlags, InitializeSecurityContextResult,
    PackageCapabilities, PackageInfo, SecurityBuffer, SecurityBufferType, SecurityPackageType,
    SecurityStatus, ServerResponseFlags,
};

pub const PKG_NAME: &str = "Kerberos";
pub const KERBEROS_VERSION: u8 = 0x05;
pub const SERVICE_NAME: &str = "krbtgt";

const KDC_TYPE_ENV: &str = "KDC_TYPE";
const URL_ENV: &str = "URL";

lazy_static! {
    pub static ref PACKAGE_INFO: PackageInfo = PackageInfo {
        capabilities: PackageCapabilities::empty(),
        rpc_id: PACKAGE_ID_NONE,
        max_token_len: 0xbb80, // 48 000 bytes: default maximum token len in windows
        name: SecurityPackageType::Kerberos,
        comment: String::from("Kerberos Security Package\0"),
    };
}

pub trait NetworkClient: Debug {
    fn send(&self, url: &Url, data: &[u8]) -> Result<Vec<u8>>;
    fn send_http(&self, url: &Url, data: &[u8]) -> Result<Vec<u8>>;
    fn clone(&self) -> Box<dyn NetworkClient>;
}

#[derive(Debug, Clone)]
pub enum KerberosState {
    Preauthentication,
    ApExchange,
    Final,
}

#[derive(Debug, Clone)]
pub struct Kerberos {
    state: KerberosState,
    config: KerberosConfig,
    auth_identity: Option<AuthIdentityBuffers>,

    // encryption keys
    client_secret_key: Option<Vec<u8>>,
    session_key1: Option<Vec<u8>>,
    session_key2: Option<Vec<u8>>,
    server_secret_key: Option<Vec<u8>>,
}

impl Kerberos {
    pub fn new_client_from_env() -> Self {
        Self {
            state: KerberosState::Preauthentication,
            config: KerberosConfig {
                url: Url::from_str(&env::var(URL_ENV).unwrap()).unwrap(),
                kdc_type: env::var(KDC_TYPE_ENV).unwrap().into(),
                network_client: Box::new(ReqwestNetworkClient::new()),
            },
            auth_identity: None,

            client_secret_key: None,
            session_key1: None,
            session_key2: None,
            server_secret_key: None,
        }
    }

    pub fn new_server_from_env() -> Self {
        Self {
            state: KerberosState::ApExchange,
            config: KerberosConfig {
                url: Url::from_str(&env::var(URL_ENV).unwrap()).unwrap(),
                kdc_type: env::var(KDC_TYPE_ENV).unwrap().into(),
                network_client: Box::new(ReqwestNetworkClient::new()),
            },
            auth_identity: None,

            client_secret_key: None,
            session_key1: None,
            session_key2: None,
            server_secret_key: None,
        }
    }
}

impl Sspi for Kerberos {
    fn complete_auth_token(&mut self, _token: &mut [SecurityBuffer]) -> Result<SecurityStatus> {
        Ok(SecurityStatus::Ok)
    }

    fn encrypt_message(
        &mut self,
        _flags: crate::EncryptionFlags,
        message: &mut [SecurityBuffer],
        _sequence_number: u32,
    ) -> Result<SecurityStatus> {
        SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?; // check if exists
        let data = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;

        let cipther =
            new_kerberos_cipher(kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96).unwrap();

        let key = if let Some(key) = self.server_secret_key.as_ref() {
            key
        } else if let Some(key) = self.session_key2.as_ref() {
            key
        } else if let Some(key) = self.session_key1.as_ref() {
            key
        } else if let Some(key) = self.client_secret_key.as_ref() {
            key
        } else {
            return Err(Error::new(
                ErrorKind::EncryptFailure,
                "No encryption key provided".into(),
            ));
        };

        *data.buffer.as_mut() = cipther.encrypt(key, 2, &data.buffer);

        Ok(SecurityStatus::Ok)
    }

    fn decrypt_message(
        &mut self,
        message: &mut [SecurityBuffer],
        _sequence_number: u32,
    ) -> Result<crate::DecryptionFlags> {
        SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?; // check if exists
        let data = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;

        let cipther =
            new_kerberos_cipher(kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96).unwrap();

        for key in vec![
            self.server_secret_key.as_ref(),
            self.session_key2.as_ref(),
            self.session_key1.as_ref(),
            self.client_secret_key.as_ref(),
        ] {
            if let Some(key) = key {
                if let Ok(unencrypted_data) = cipther.decrypt(key, 2, &data.buffer) {
                    *data.buffer.as_mut() = unencrypted_data;
                    return Ok(DecryptionFlags::empty());
                }
            }
        }

        return Err(Error::new(
            ErrorKind::MessageAltered,
            "Signature verification failed, something nasty is going on!".to_owned(),
        ));
    }

    fn query_context_sizes(&mut self) -> Result<ContextSizes> {
        Ok(ContextSizes {
            max_token: 2010,
            max_signature: 16,
            block: 0,
            security_trailer: 16,
        })
    }

    fn query_context_names(&mut self) -> Result<ContextNames> {
        if let Some(ref identity_buffers) = self.auth_identity {
            let identity: AuthIdentity = identity_buffers.clone().into();
            Ok(ContextNames {
                username: identity.username,
                domain: identity.domain,
            })
        } else {
            Err(sspi::Error::new(
                sspi::ErrorKind::NoCredentials,
                String::from("Requested Names, but no credentials were provided"),
            ))
        }
    }

    fn query_context_package_info(&mut self) -> Result<PackageInfo> {
        sspi::query_security_package_info(SecurityPackageType::Kerberos)
    }

    fn query_context_cert_trust_status(&mut self) -> Result<crate::CertTrustStatus> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "Certificate trust status is not supported".to_owned(),
        ))
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
    ) -> Result<crate::AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
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
    ) -> Result<crate::InitializeSecurityContextResult> {
        let credentials = builder.credentials_handle.unwrap().as_ref().unwrap();

        let status = match self.state {
            KerberosState::Preauthentication => {
                let username = String::from_utf8(credentials.user.clone()).unwrap();
                let domain = String::from_utf8(credentials.domain.clone()).unwrap();
                let password = String::from_utf8(credentials.password.clone()).unwrap();

                let as_req = generate_as_req(&username, &password, &domain);
                let response = self
                    .config
                    .network_client
                    .send(&self.config.url, &serialize_message(&as_req))?;

                let as_rep: AsRep =
                    picky_asn1_der::from_bytes(&response[4..]).map_err(|e| Error {
                        error_type: ErrorKind::DecryptFailure,
                        description: format!("{:?}", e),
                    })?;

                let (_encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep)?;
                let authenticator = generate_authenticator_from_kdc_rep(&as_rep.0);
                let session_key1 = extract_session_key_from_as_rep(&as_rep, &salt, &password)?;

                let tgs_req = generate_tgs_req(
                    &username,
                    &as_rep.0.crealm.0.to_string(),
                    &session_key1,
                    as_rep.0.ticket.0,
                    &authenticator,
                );

                let response = self
                    .config
                    .network_client
                    .send(&self.config.url, &serialize_message(&tgs_req))?;

                let tgs_rep: TgsRep = picky_asn1_der::from_bytes(&response[4..])
                    .map_err(|e| Error::new(ErrorKind::DecryptFailure, format!("{:?}", e)))?;

                let session_key2 = extract_session_key_from_tgs_rep(&tgs_rep, &session_key1)?;
                let authenticator = generate_authenticator_from_kdc_rep(&tgs_rep.0);

                let ap_req = generate_ap_req(tgs_rep.0.ticket.0, &session_key2, &authenticator);

                // write ap_req
                let output_token =
                    SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token
                    .buffer
                    .write_all(&picky_asn1_der::to_vec(&ap_req).unwrap())?;

                self.state = KerberosState::ApExchange;

                SecurityStatus::CompleteNeeded
            }
            KerberosState::ApExchange => {
                let input = builder.input.ok_or_else(|| {
                    sspi::Error::new(
                        ErrorKind::InvalidToken,
                        "Input buffers must be specified".into(),
                    )
                })?;
                let input_token = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;

                let _ap_rep: ApRep = picky_asn1_der::from_bytes(&input_token.buffer)
                    .map_err(|e| Error::new(ErrorKind::DecryptFailure, format!("{:?}", e)))?;

                // handle ap_rep

                println!("all good in ap_rep");

                self.state = KerberosState::Final;

                SecurityStatus::Ok
            }
            KerberosState::Final => {
                return Err(Error::new(
                    ErrorKind::OutOfSequence,
                    format!("Got wrong Kerberos state: {:?}", self.state),
                ))
            }
        };

        Ok(InitializeSecurityContextResult {
            status,
            flags: ClientResponseFlags::empty(),
            expiry: None,
        })
    }

    fn accept_security_context_impl(
        &mut self,
        builder: crate::builders::FilledAcceptSecurityContext<'_, Self, Self::CredentialsHandle>,
    ) -> Result<crate::AcceptSecurityContextResult> {
        let input = builder.input.ok_or_else(|| {
            sspi::Error::new(
                ErrorKind::InvalidToken,
                "Input buffers must be specified".into(),
            )
        })?;

        let status = match &self.state {
            KerberosState::ApExchange => {
                let input_token = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;

                let _ap_req: ApReq = picky_asn1_der::from_bytes(&input_token.buffer)
                    .map_err(|e| Error::new(ErrorKind::DecryptFailure, format!("{:?}", e)))?;

                self.state = KerberosState::Final;

                SecurityStatus::Ok
            }
            state => {
                return Err(Error::new(
                    ErrorKind::OutOfSequence,
                    format!("Got wrong Kerberos state: {:?}", state),
                ))
            }
        };

        Ok(AcceptSecurityContextResult {
            status,
            flags: ServerResponseFlags::empty(),
            expiry: None,
        })
    }
}

impl SspiEx for Kerberos {
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) {
        let cipher = new_kerberos_cipher(kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96).unwrap();
        let salt = cipher.generate_salt(&identity.domain.clone().unwrap_or_default(), &identity.username);
        let key = cipher.generate_key_from_string(&identity.username, &salt);
        
        self.client_secret_key = Some(key);
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
            generate_as_req, generate_authenticator_from_kdc_rep, generate_tgs_req,
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

        let (_encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep).unwrap();
        let authenticator = generate_authenticator_from_kdc_rep(&as_rep.0);
        let session_key = extract_session_key_from_as_rep(&as_rep, &salt, &password).unwrap();

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
