pub mod config;
// #[cfg(feature = "with_reqwest")]
mod client;
pub mod gssapi;
mod negotiate;
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
        extractors::{
            extract_encryption_params_from_as_rep, extract_session_key_from_as_rep,
            extract_session_key_from_tgs_rep,
        },
        generators::{
            generate_ap_req, generate_as_req, generate_authenticator_for_ap_req,
            generate_authenticator_for_tgs_ap_req, generate_tgs_req,
        },
    },
    config::KerberosConfig,
    negotiate::{extract_tgt_ticket, generate_neg_ap_req, generate_neg_token_init},
    reqwest_client::ReqwestNetworkClient,
    utils::{serialize_message, utf16_bytes_to_string},
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

const DEFAULT_ENCRYPTION_TYPE: i32 = kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96;

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
    Negotiate,
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
    session_key: Option<Vec<u8>>,
    server_secret_key: Option<Vec<u8>>,

    key_usage_number: Option<i32>,
    encryption_type: Option<i32>,
}

impl Kerberos {
    pub fn new_client_from_env() -> Self {
        Self {
            state: KerberosState::Negotiate,
            config: KerberosConfig {
                url: Url::from_str(&env::var(URL_ENV).unwrap()).unwrap(),
                kdc_type: env::var(KDC_TYPE_ENV).unwrap().into(),
                network_client: Box::new(ReqwestNetworkClient::new()),
            },
            auth_identity: None,

            client_secret_key: None,
            session_key: None,
            server_secret_key: None,

            key_usage_number: None,
            encryption_type: None,
        }
    }

    pub fn new_server_from_env() -> Self {
        Self {
            state: KerberosState::Negotiate,
            config: KerberosConfig {
                url: Url::from_str(&env::var(URL_ENV).unwrap()).unwrap(),
                kdc_type: env::var(KDC_TYPE_ENV).unwrap().into(),
                network_client: Box::new(ReqwestNetworkClient::new()),
            },
            auth_identity: None,

            client_secret_key: None,
            session_key: None,
            server_secret_key: None,

            key_usage_number: None,
            encryption_type: None,
        }
    }

    pub fn set_seq_num(&mut self, seq_num: u32) {
        self.seq_number = seq_num;
    }

    pub fn next_seq_number(&mut self) -> u32 {
        let seq_num = self.seq_number;
        self.seq_number = seq_num + 1;

        seq_num
    }
}

impl Sspi for Kerberos {
    fn complete_auth_token(&mut self, _token: &mut [SecurityBuffer]) -> Result<SecurityStatus> {
        println!("complete_auth_token");

        Ok(SecurityStatus::Ok)
    }

    fn encrypt_message(
        &mut self,
        _flags: crate::EncryptionFlags,
        message: &mut [SecurityBuffer],
        _sequence_number: u32,
    ) -> Result<SecurityStatus> {
        println!("encrypt message");

        SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?; // check if exists
        let data = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;

        let cipther =
            new_kerberos_cipher(self.encryption_type.unwrap_or(DEFAULT_ENCRYPTION_TYPE)).unwrap();

        let key = if let Some(key) = self.session_key.as_ref() {
            key
        } else if let Some(key) = self.client_secret_key.as_ref() {
            key
        } else {
            return Err(Error::new(
                ErrorKind::EncryptFailure,
                "No encryption key provided".into(),
            ));
        };

        *data.buffer.as_mut() =
            cipther.encrypt(key, self.key_usage_number.unwrap_or(2), &data.buffer);

        Ok(SecurityStatus::Ok)
    }

    fn decrypt_message(
        &mut self,
        message: &mut [SecurityBuffer],
        _sequence_number: u32,
    ) -> Result<crate::DecryptionFlags> {
        println!("decrypt message");

        SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?; // check if exists
        let data = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;

        let cipher =
            new_kerberos_cipher(self.encryption_type.unwrap_or(DEFAULT_ENCRYPTION_TYPE)).unwrap();

        let key = if let Some(key) = self.session_key.as_ref() {
            key
        } else {
            return Err(Error::new(
                ErrorKind::EncryptFailure,
                "No encryption key provided".into(),
            ));
        };

        if let Ok(decrypted_data) =
            cipher.decrypt(key, self.key_usage_number.unwrap_or(24), &data.buffer)
        {
            *data.buffer.as_mut() = decrypted_data;
            return Ok(DecryptionFlags::empty());
        }

        Err(Error::new(
            ErrorKind::MessageAltered,
            "Signature verification failed, something nasty is going on!".to_owned(),
        ))
    }

    fn query_context_sizes(&mut self) -> Result<ContextSizes> {
        println!("query context sizes");

        Ok(ContextSizes {
            max_token: 2010,
            max_signature: 16,
            block: 0,
            security_trailer: 16,
        })
    }

    fn query_context_names(&mut self) -> Result<ContextNames> {
        println!("query context names");

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
        println!("query context package info");

        sspi::query_security_package_info(SecurityPackageType::Kerberos)
    }

    fn query_context_cert_trust_status(&mut self) -> Result<crate::CertTrustStatus> {
        println!("query context cert");

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
        println!("acquire credentials handle");

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
        println!("initialize_security_context_impl");

        let status = match self.state {
            KerberosState::Negotiate => {
                let credentials = builder.credentials_handle.unwrap().as_ref().unwrap();

                let username = utf16_bytes_to_string(&credentials.user);
                let domain = utf16_bytes_to_string(&credentials.domain);

                let output_token =
                    SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token.buffer.write_all(
                    &picky_asn1_der::to_vec(&generate_neg_token_init(&format!(
                        "{}.{}",
                        username,
                        domain.to_ascii_lowercase()
                    )))
                    .unwrap(),
                )?;

                self.state = KerberosState::Preauthentication;

                println!("nego data sent!");

                SecurityStatus::ContinueNeeded
            }
            KerberosState::Preauthentication => {
                let input = builder.input.ok_or_else(|| {
                    sspi::Error::new(
                        ErrorKind::InvalidToken,
                        "Input buffers must be specified".into(),
                    )
                })?;
                let input_token = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;
                let b = input_token.buffer.clone();
                println!("nego response: {:?}", b);

                let tgt_ticket = extract_tgt_ticket(&b);

                let credentials = builder.credentials_handle.unwrap().as_ref().unwrap();

                let username = utf16_bytes_to_string(&credentials.user);
                let domain = utf16_bytes_to_string(&credentials.domain);
                let password = utf16_bytes_to_string(&credentials.password);

                let as_req = generate_as_req(&username, &password, &domain);

                let response = self
                    .config
                    .network_client
                    .send(&self.config.url, &serialize_message(&as_req))?;

                let as_rep: AsRep =
                    // first 4 bytes is message leb. skipping them
                    picky_asn1_der::from_bytes(&response[4..]).map_err(|e| Error {
                        error_type: ErrorKind::DecryptFailure,
                        description: format!("{:?}", e),
                    })?;

                println!("yes, as_rep parsed");

                let (_encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep)?;
                let authenticator = generate_authenticator_for_tgs_ap_req(&as_rep.0);

                let session_key_1 = extract_session_key_from_as_rep(&as_rep, &salt, &password)?;

                let tgs_req = generate_tgs_req(
                    &username,
                    &as_rep.0.crealm.0.to_string(),
                    &session_key_1,
                    as_rep.0.ticket.0,
                    &authenticator,
                    Some(vec![tgt_ticket]),
                );

                let response = self
                    .config
                    .network_client
                    .send(&self.config.url, &serialize_message(&tgs_req))?;

                println!("tgs req here");

                // first 4 bytes is message leb. skipping them
                let tgs_rep: TgsRep = picky_asn1_der::from_bytes(&response[4..])
                    .map_err(|e| Error::new(ErrorKind::DecryptFailure, format!("{:?}", e)))?;

                self.session_key =
                    Some(extract_session_key_from_tgs_rep(&tgs_rep, &session_key_1)?);


                println!("{:?}", self.session_key);

                let authenticator =
                    generate_authenticator_for_ap_req(&tgs_rep.0, self.next_seq_number());
                println!("new ap_req authenticator: {:?}", authenticator);

                let ap_req = generate_ap_req(
                    tgs_rep.0.ticket.0,
                    self.session_key.as_ref().unwrap(),
                    &authenticator,
                );

                let output_token =
                    SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token
                    .buffer
                    .write_all(&picky_asn1_der::to_vec(&generate_neg_ap_req(ap_req)).unwrap())?;

                println!("ap_req has been written");

                self.state = KerberosState::ApExchange;

                SecurityStatus::ContinueNeeded
            }
            KerberosState::ApExchange => {
                println!("got response from ap_req:");
                let input = builder.input.ok_or_else(|| {
                    sspi::Error::new(
                        ErrorKind::InvalidToken,
                        "Input buffers must be specified".into(),
                    )
                })?;
                let input_token = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;
                println!("input: {:?}", input_token.buffer);

                // let _ap_rep: ApRep = picky_asn1_der::from_bytes(&input_token.buffer)
                //     .map_err(|e| Error::new(ErrorKind::DecryptFailure, format!("{:?}", e)))?;

                // handle ap_rep

                println!("all good in ap_rep");

                self.state = KerberosState::Final;

                SecurityStatus::Ok
            }
            _ => {
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
        println!("accept security context");

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
        println!("custom set auth identity");

        let cipher =
            new_kerberos_cipher(kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96).unwrap();
        let salt = cipher.generate_salt(
            &identity.domain.clone().unwrap_or_default(),
            &identity.username,
        );
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
            extractors::{extract_encryption_params_from_as_rep, extract_session_key_from_as_rep},
            generators::{
                generate_as_req, generate_authenticator_for_tgs_ap_req, generate_tgs_req,
            },
        },
        utils::serialize_message,
    };

    #[test]
    fn test_tgs_rep_obraining() {
        let network_client = ReqwestNetworkClient::new();
        let url = Url::from_str("tcp://192.168.0.103:88").unwrap();

        let username = "p3".to_owned();
        let domain = "QKATION.COM".to_owned();
        let password = "qweQWE123!@#".to_owned();

        let as_req = generate_as_req(&username, &password, &domain);

        println!("as req: {:?}", as_req);

        let response = network_client
            .send(&url, &serialize_message(&as_req))
            .unwrap();

        println!("as response: {:?}", response);

        let as_rep: AsRep = picky_asn1_der::from_bytes(&response[4..]).unwrap();

        let (_encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep).unwrap();
        let authenticator = generate_authenticator_for_tgs_ap_req(&as_rep.0);
        let session_key = extract_session_key_from_as_rep(&as_rep, &salt, &password).unwrap();

        let tgs_req = generate_tgs_req(
            &username,
            &as_rep.0.crealm.0.to_string(),
            &session_key,
            as_rep.0.ticket.0,
            &authenticator,
            None,
        );

        println!("tgs_req: {:?}", tgs_req);

        let response = network_client
            .send(&url, &serialize_message(&tgs_req))
            .unwrap();

        println!("tgs response: {:?}", response);

        let tgs_rep: TgsRep = picky_asn1_der::from_bytes(&response[4..]).unwrap();
        println!("tgs_rep: {:?}", tgs_rep);
    }

    #[test]
    fn test_octet_string() {
        use crate::sspi::internal::credssp::TsRequest;

        let mut ts_request = TsRequest::default();
        ts_request.nego_tokens = Some(vec![1, 2, 3, 4, 5]);

        let mut res_data = Vec::new();
        ts_request.encode_ts_request(&mut res_data);

        println!("{:?}", res_data);
    }
}
