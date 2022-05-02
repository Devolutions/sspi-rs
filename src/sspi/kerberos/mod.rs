pub mod config;
// #[cfg(feature = "with_reqwest")]
mod client;
pub mod gssapi;
mod negotiate;
pub mod reqwest_client;
mod server;
mod utils;

use std::{env, fmt::Debug, io::Write, str::FromStr};

use kerberos_crypto::{new_kerberos_cipher, AesSizes};
use lazy_static::lazy_static;
use picky_krb::constants::key_usages::{ACCEPTOR_SEAL, INITIATOR_SEAL};
use picky_krb::{
    constants::key_usages::ACCEPTOR_SIGN,
    messages::{ApReq, AsRep, KrbError, TgsRep},
};
use rand::{rngs::OsRng, Rng};
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
        AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96,
    },
    config::KerberosConfig,
    negotiate::{extract_tgt_ticket, generate_neg_ap_req, generate_neg_token_init, NegTokenTarg1},
    reqwest_client::ReqwestNetworkClient,
    utils::{serialize_message, utf16_bytes_to_string},
};
use super::ntlm::AuthIdentityBuffers;
use crate::{
    sspi::{
        self,
        kerberos::{
            client::{
                extractors::extract_salt_from_krb_error,
                generators::generate_as_req_without_pre_auth,
            },
            gssapi::{validate_mic_token, MicToken, WrapToken},
            negotiate::{generate_final_neg_token_targ, get_mech_list},
            server::extractors::{
                extract_ap_rep_from_neg_token_targ, extract_sub_session_key_from_ap_rep,
            },
            utils::unwrap_krb_response,
        },
    },
    sspi::{Error, ErrorKind, Result, Sspi, SspiEx, SspiImpl, PACKAGE_ID_NONE},
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity, ClientResponseFlags,
    ContextNames, ContextSizes, CredentialUse, DecryptionFlags, InitializeSecurityContextResult,
    PackageCapabilities, PackageInfo, SecurityBuffer, SecurityBufferType, SecurityPackageType,
    SecurityStatus, ServerResponseFlags,
};

pub const PKG_NAME: &str = "Kerberos\0";
pub const KERBEROS_VERSION: u8 = 0x05;
pub const TGT_SERVICE_NAME: &str = "krbtgt";
pub const SERVICE_NAME: &str = "TERMSRV";

const KDC_TYPE_ENV: &str = "KDC_TYPE";
const URL_ENV: &str = "URL";

const DEFAULT_ENCRYPTION_TYPE: i32 = AES256_CTS_HMAC_SHA1_96;

/// [MS-KILE](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-KILE/%5bMS-KILE%5d.pdf)
/// The RRC field is 12 if no encryption is requested or 28 if encryption is requested
const RRC: u16 = 28;

lazy_static! {
    pub static ref PACKAGE_INFO: PackageInfo = PackageInfo {
        capabilities: PackageCapabilities::empty(),
        rpc_id: PACKAGE_ID_NONE,
        max_token_len: 0xbb80, // 48 000 bytes: default maximum token len in Windows
        name: SecurityPackageType::Kerberos,
        comment: String::from("Kerberos Security Package\0"),
    };

    pub static ref NEGO_PACKAGE_INFO: PackageInfo = PackageInfo {
        capabilities: PackageCapabilities::empty(),
        rpc_id: PACKAGE_ID_NONE,
        max_token_len: 0xbb80, // 48 000 bytes: default maximum token len in Windows
        name: SecurityPackageType::Other("Negotiate\0".into()),
        comment: String::from("Negotiate Security Package\0"),
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
    PubKeyAuth,
    Credentials,
    Final,
}

#[derive(Debug, Clone)]
pub struct EncryptionParams {
    encryption_type: Option<i32>,
    session_key: Option<Vec<u8>>,
    sub_session_key: Option<Vec<u8>>,
    sspi_encrypt_key_usage: i32,
    sspi_decrypt_key_usage: i32,
}

impl EncryptionParams {
    pub fn default_for_client() -> Self {
        Self {
            encryption_type: None,
            session_key: None,
            sub_session_key: None,
            sspi_encrypt_key_usage: INITIATOR_SEAL,
            sspi_decrypt_key_usage: ACCEPTOR_SEAL,
        }
    }

    pub fn default_for_server() -> Self {
        Self {
            encryption_type: None,
            session_key: None,
            sub_session_key: None,
            sspi_encrypt_key_usage: ACCEPTOR_SEAL,
            sspi_decrypt_key_usage: INITIATOR_SEAL,
        }
    }

    pub fn aes_sizes(&self) -> Option<AesSizes> {
        self.encryption_type.map(|e_type| match e_type {
            AES256_CTS_HMAC_SHA1_96 => AesSizes::Aes256,
            AES128_CTS_HMAC_SHA1_96 => AesSizes::Aes128,
            _ => AesSizes::Aes256,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Kerberos {
    state: KerberosState,
    config: KerberosConfig,
    auth_identity: Option<AuthIdentityBuffers>,
    encryption_params: EncryptionParams,
    seq_number: u32,
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
            encryption_params: EncryptionParams::default_for_client(),
            seq_number: OsRng::new().unwrap().gen::<u32>(),
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
            encryption_params: EncryptionParams::default_for_server(),
            seq_number: OsRng::new().unwrap().gen::<u32>(),
        }
    }

    pub fn next_seq_number(&mut self) -> u32 {
        self.seq_number += 1;
        self.seq_number
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
        println!("encrypt message");

        SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?; // check if exists
        let data = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;
        println!("data.buffer.len(): {}", data.buffer.len());
        println!("data to encrypt: {:?}", data.buffer);


        let cipher = new_kerberos_cipher(
            self.encryption_params
                .encryption_type
                .unwrap_or(DEFAULT_ENCRYPTION_TYPE),
        )
        .unwrap();

        let seq_number = self.next_seq_number();

        // the sub-session key is always preferred over the session key
        let key = if let Some(key) = self.encryption_params.sub_session_key.as_ref() {
            key
        } else if let Some(key) = self.encryption_params.session_key.as_ref() {
            key
        } else if let Some(key) = self.client_secret_key.as_ref() {
            key
        } else {
            return Err(Error::new(
                ErrorKind::EncryptFailure,
                "No encryption key provided".into(),
            ));
        };
        let key_usage = self.encryption_params.sspi_encrypt_key_usage;

        let mut wrap_token = WrapToken::with_seq_number(seq_number as u64);

        let mut payload = data.buffer.to_vec();
        payload.extend_from_slice(&wrap_token.header());

        let mut checksum = cipher.encrypt(key, key_usage, &payload);
        checksum.rotate_right(RRC.into());

        wrap_token.set_rrc(RRC);
        wrap_token.set_checksum(checksum);

        let mut raw_wrap_token = Vec::with_capacity(92);
        wrap_token.encode(&mut raw_wrap_token)?;

        match self.state {
            KerberosState::PubKeyAuth => {
                *data.buffer.as_mut() = raw_wrap_token[16..].to_vec();
                let header = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?;
                *header.buffer.as_mut() = raw_wrap_token[0..16].to_vec();
            }
            KerberosState::Credentials => {
                *data.buffer.as_mut() = raw_wrap_token[60..].to_vec();
                let header = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?;
                *header.buffer.as_mut() = raw_wrap_token[0..60].to_vec();
            }
            _ => {
                *data.buffer.as_mut() = cipher.encrypt(key, key_usage, &data.buffer);
            }
        };

        Ok(SecurityStatus::Ok)
    }

    fn decrypt_message(
        &mut self,
        message: &mut [SecurityBuffer],
        _sequence_number: u32,
    ) -> Result<crate::DecryptionFlags> {
        println!("decrypt message");

        let mut encrypted = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?
            .buffer
            .clone();
        let data = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;

        encrypted.extend_from_slice(&data.buffer);

        let cipher = new_kerberos_cipher(
            self.encryption_params
                .encryption_type
                .unwrap_or(DEFAULT_ENCRYPTION_TYPE),
        )
        .unwrap();

        // the sub-session key is always preferred over the session key
        let key = if let Some(key) = self.encryption_params.sub_session_key.as_ref() {
            key
        } else if let Some(key) = self.encryption_params.session_key.as_ref() {
            key
        } else {
            return Err(Error::new(
                ErrorKind::EncryptFailure,
                "No encryption key provided".into(),
            ));
        };
        let key_usage = self.encryption_params.sspi_decrypt_key_usage;

        println!("key for decryption: {:?}", key);
        println!("data for decryption: {:?}", &encrypted);

        match self.state {
            KerberosState::PubKeyAuth => {
                let mut wrap_token = WrapToken::decode(&*encrypted)?;

                wrap_token.checksum.rotate_left(RRC.into());

                let mut decrypted = cipher
                    .decrypt(key, key_usage, &wrap_token.checksum)
                    .unwrap();
                // remove wrap token header
                decrypted.truncate(decrypted.len() - WrapToken::header_len());

                self.state = KerberosState::Credentials;

                *data.buffer.as_mut() = decrypted;
                return Ok(DecryptionFlags::empty());
            }
            // KerberosState::Credentials => {}
            _ => {
                if let Ok(decrypted_data) = cipher.decrypt(key, key_usage, &data.buffer) {
                    *data.buffer.as_mut() = decrypted_data;
                    return Ok(DecryptionFlags::empty());
                }
            }
        };

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
            security_trailer: 60,
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

                SecurityStatus::ContinueNeeded
            }
            KerberosState::Preauthentication => {
                println!("pre");
                let input = builder.input.ok_or_else(|| {
                    sspi::Error::new(
                        ErrorKind::InvalidToken,
                        "Input buffers must be specified".into(),
                    )
                })?;
                let input_token = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;

                let tgt_ticket = extract_tgt_ticket(&input_token.buffer)?;

                let credentials = builder.credentials_handle.unwrap().as_ref().unwrap();

                let username = utf16_bytes_to_string(&credentials.user);
                let domain = utf16_bytes_to_string(&credentials.domain);
                let password = utf16_bytes_to_string(&credentials.password);
                let mut salt = format!("{}{}", domain, username);

                let as_req = generate_as_req_without_pre_auth(&username, &domain);

                let response = self
                    .config
                    .network_client
                    .send(&self.config.url, &serialize_message(&as_req))?;

                // first 4 bytes is message len. skipping them
                let as_rep_error: KrbError = unwrap_krb_response(&response[4..])?;

                if let Some(correct_salt) = extract_salt_from_krb_error(&as_rep_error)? {
                    salt = correct_salt;
                }

                let as_req = generate_as_req(
                    &username,
                    salt.as_bytes(),
                    &password,
                    &domain,
                    &self.encryption_params,
                );

                let response = self
                    .config
                    .network_client
                    .send(&self.config.url, &serialize_message(&as_req))?;

                // first 4 bytes is message len. skipping them
                let as_rep: AsRep = unwrap_krb_response(&response[4..])?;

                println!("yes, as_rep parsed");

                let (encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep)?;
                self.encryption_params.encryption_type = Some(encryption_type as i32);

                let mut authenticator = generate_authenticator_for_tgs_ap_req(&as_rep.0);

                let session_key_1 = extract_session_key_from_as_rep(
                    &as_rep,
                    &salt,
                    &password,
                    &self.encryption_params,
                )?;

                let tgs_req = generate_tgs_req(
                    &username,
                    &as_rep.0.crealm.0.to_string(),
                    &session_key_1,
                    as_rep.0.ticket.0,
                    &mut authenticator,
                    Some(vec![tgt_ticket]),
                    &self.encryption_params,
                );

                let response = self
                    .config
                    .network_client
                    .send(&self.config.url, &serialize_message(&tgs_req))?;

                println!("tgs req here");

                // first 4 bytes is message len. skipping them
                let tgs_rep: TgsRep = unwrap_krb_response(&response[4..])?;

                self.encryption_params.session_key = Some(extract_session_key_from_tgs_rep(
                    &tgs_rep,
                    &session_key_1,
                    &self.encryption_params,
                )?);


                println!("{:?}", self.encryption_params);

                let authenticator =
                    generate_authenticator_for_ap_req(&tgs_rep.0, self.next_seq_number());
                println!("new ap_req authenticator: {:?}", authenticator);

                let ap_req = generate_ap_req(
                    tgs_rep.0.ticket.0,
                    self.encryption_params.session_key.as_ref().unwrap(),
                    &authenticator,
                    &self.encryption_params,
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
                    Error::new(
                        ErrorKind::InvalidToken,
                        "Input buffers must be specified".into(),
                    )
                })?;
                let input_token = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;

                let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)
                    .map_err(|err| Error {
                        error_type: ErrorKind::InvalidToken,
                        description: format!("{:?}", err),
                    })?;

                let ap_rep = extract_ap_rep_from_neg_token_targ(&neg_token_targ)?;

                self.encryption_params.sub_session_key = Some(extract_sub_session_key_from_ap_rep(
                    &ap_rep,
                    self.encryption_params.session_key.as_ref().unwrap(),
                    &self.encryption_params
                )?);

                if let Some(ref token) = neg_token_targ.0.mech_list_mic.0 {
                    validate_mic_token(&token.0 .0, ACCEPTOR_SIGN, &self.encryption_params)?;
                }

                println!("session_key: {:?}", self.encryption_params);
                println!("all good in ap_rep");

                let neg_token_targ = generate_final_neg_token_targ(
                    Some(MicToken::generate_initiator_raw(
                        picky_asn1_der::to_vec(&get_mech_list()).unwrap(),
                        self.seq_number as u64,
                        self.encryption_params.sub_session_key.as_ref().unwrap(),
                    )), // None
                );

                let output_token =
                    SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token
                    .buffer
                    .write_all(&picky_asn1_der::to_vec(&neg_token_targ).unwrap())?;

                self.state = KerberosState::PubKeyAuth;

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
        self.auth_identity = Some(identity.into());
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use picky_krb::messages::{AsRep, TgsRep};
    use url::Url;

    use crate::sspi::kerberos::client::AES256_CTS_HMAC_SHA1_96;
    use crate::sspi::kerberos::EncryptionParams;

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

        let enc_params = EncryptionParams {
            encryption_type: Some(AES256_CTS_HMAC_SHA1_96),
            session_key: None,
            sub_session_key: None,
            sspi_decrypt_key_usage: 0,
            sspi_encrypt_key_usage: 0,
        };

        let as_req = generate_as_req(&username, "QKATION.COMp3", &password, &domain, &enc_params);

        println!("as req: {:?}", as_req);

        let response = network_client
            .send(&url, &serialize_message(&as_req))
            .unwrap();

        println!("as response: {:?}", response);

        let as_rep: AsRep = picky_asn1_der::from_bytes(&response[4..]).unwrap();

        let (_encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep).unwrap();
        let mut authenticator = generate_authenticator_for_tgs_ap_req(&as_rep.0);
        let session_key =
            extract_session_key_from_as_rep(&as_rep, &salt, &password, &enc_params).unwrap();

        let tgs_req = generate_tgs_req(
            &username,
            &as_rep.0.crealm.0.to_string(),
            &session_key,
            as_rep.0.ticket.0,
            &mut authenticator,
            None,
            &enc_params,
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
        ts_request.encode_ts_request(&mut res_data).unwrap();

        println!("{:?}", res_data);
    }
}
