mod client;
pub mod config;
mod encryption_params;
pub mod network_client;
mod server;
mod utils;

use std::fmt::Debug;
use std::io::Write;
use std::str::FromStr;

use kerberos_crypto::new_kerberos_cipher;
use lazy_static::lazy_static;
use picky_krb::constants::key_usages::ACCEPTOR_SIGN;
use picky_krb::data_types::{KrbResult, ResultExt};
use picky_krb::gss_api::{NegTokenTarg1, WrapToken};
use picky_krb::messages::{ApReq, AsRep, TgsRep};
use rand::rngs::OsRng;
use rand::Rng;
use reqwest::Url;

use self::client::extractors::{
    extract_encryption_params_from_as_rep, extract_session_key_from_as_rep, extract_session_key_from_tgs_rep,
};
use self::client::generators::{
    generate_ap_req, generate_as_req, generate_authenticator_for_ap_req, generate_authenticator_for_tgs_ap_req,
    generate_neg_ap_req, generate_neg_token_init, generate_passwd_as_req, generate_tgs_req, DEFAULT_AP_REQ_OPTIONS, generate_krb_priv_request, generate_authenticator_for_krb_priv,
};
use self::client::{AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96};
use self::config::{KdcType, KerberosConfig};
use self::encryption_params::EncryptionParams;
use self::network_client::reqwest_network_client::ReqwestNetworkClient;
use self::server::extractors::extract_tgt_ticket;
use self::utils::{serialize_message, utf16_bytes_to_utf8_string};
use crate::builders::ChangePassword;
use crate::sspi::kerberos::client::extractors::extract_salt_from_krb_error;
use crate::sspi::kerberos::client::generators::{
    generate_as_req_without_pre_auth, generate_final_neg_token_targ, get_mech_list,
};
use crate::sspi::kerberos::server::extractors::{
    extract_ap_rep_from_neg_token_targ, extract_sub_session_key_from_ap_rep,
};
use crate::sspi::kerberos::utils::{generate_initiator_raw, validate_mic_token};
use crate::sspi::ntlm::AuthIdentityBuffers;
use crate::sspi::{self, Error, ErrorKind, Result, Sspi, SspiEx, SspiImpl, PACKAGE_ID_NONE};
use crate::{
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity, ClientResponseFlags, ContextNames,
    ContextSizes, CredentialUse, DecryptionFlags, InitializeSecurityContextResult, PackageCapabilities, PackageInfo,
    SecurityBuffer, SecurityBufferType, SecurityPackageType, SecurityStatus, ServerResponseFlags,
};

pub const PKG_NAME: &str = "Kerberos";
pub const KERBEROS_VERSION: u8 = 0x05;
pub const TGT_SERVICE_NAME: &str = "krbtgt";
pub const SERVICE_NAME: &str = "TERMSRV";
pub const KADMIN: &str = "kadmin";
pub const CHANGE_PASSWORD_SERVICE_NAME: &str = "changepw";

pub const SSPI_KDC_URL_ENV: &str = "SSPI_KDC_URL";

const DEFAULT_ENCRYPTION_TYPE: i32 = AES256_CTS_HMAC_SHA1_96;

/// [MS-KILE](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-KILE/%5bMS-KILE%5d.pdf)
/// The RRC field is 12 if no encryption is requested or 28 if encryption is requested
const RRC: u16 = 28;
// wrap token header len
const MAX_SIGNATURE: usize = 16;
// minimal len to fit encrypted public key in wrap token
const SECURITY_TRAILER: usize = 60;

lazy_static! {
    pub static ref PACKAGE_INFO: PackageInfo = PackageInfo {
        capabilities: PackageCapabilities::empty(),
        rpc_id: PACKAGE_ID_NONE,
        max_token_len: 0xbb80, // 48 000 bytes: default maximum token len in Windows
        name: SecurityPackageType::Kerberos,
        comment: String::from("Kerberos Security Package"),
    };
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
pub struct Kerberos {
    state: KerberosState,
    config: KerberosConfig,
    auth_identity: Option<AuthIdentityBuffers>,
    encryption_params: EncryptionParams,
    seq_number: u32,
    realm: Option<String>,
}

impl Kerberos {
    pub fn new_client_from_config(config: KerberosConfig) -> Result<Self> {
        Ok(Self {
            state: KerberosState::Negotiate,
            config,
            auth_identity: None,
            encryption_params: EncryptionParams::default_for_client(),
            seq_number: OsRng::new()?.gen::<u32>(),
            realm: None,
        })
    }

    pub fn new_server_from_config(config: KerberosConfig) -> Result<Self> {
        Ok(Self {
            state: KerberosState::Negotiate,
            config,
            auth_identity: None,
            encryption_params: EncryptionParams::default_for_server(),
            seq_number: OsRng::new()?.gen::<u32>(),
            realm: None,
        })
    }

    pub fn next_seq_number(&mut self) -> u32 {
        self.seq_number += 1;
        self.seq_number
    }

    fn send(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.config.kdc_type {
            KdcType::Kdc => self.config.network_client.send(&self.config.url, data),
            KdcType::KdcProxy => self
                .config
                .network_client
                .send_http(&self.config.url, data, self.realm.clone()),
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
        SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?;
        let data = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;

        let cipher = new_kerberos_cipher(
            self.encryption_params
                .encryption_type
                .unwrap_or(DEFAULT_ENCRYPTION_TYPE),
        )?;

        let seq_number = self.next_seq_number();

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
            KerberosState::PubKeyAuth | KerberosState::Credentials => {
                *data.buffer.as_mut() = raw_wrap_token[SECURITY_TRAILER..].to_vec();
                let header = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?;
                *header.buffer.as_mut() = raw_wrap_token[0..SECURITY_TRAILER].to_vec();
            }
            _ => {
                return Err(Error {
                    error_type: ErrorKind::OutOfSequence,
                    description: "Kerberos context is not established or finished".to_owned(),
                })
            }
        };

        Ok(SecurityStatus::Ok)
    }

    fn decrypt_message(
        &mut self,
        message: &mut [SecurityBuffer],
        _sequence_number: u32,
    ) -> Result<crate::DecryptionFlags> {
        let mut encrypted = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?
            .buffer
            .clone();
        let data = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;

        encrypted.extend_from_slice(&data.buffer);

        let cipher = new_kerberos_cipher(
            self.encryption_params
                .encryption_type
                .unwrap_or(DEFAULT_ENCRYPTION_TYPE),
        )?;

        // the sub-session key is always preferred over the session key
        let key = if let Some(key) = self.encryption_params.sub_session_key.as_ref() {
            key
        } else if let Some(key) = self.encryption_params.session_key.as_ref() {
            key
        } else {
            return Err(Error::new(
                ErrorKind::DecryptFailure,
                "No encryption key provided".into(),
            ));
        };
        let key_usage = self.encryption_params.sspi_decrypt_key_usage;

        let mut wrap_token = WrapToken::decode(encrypted.as_slice())?;

        wrap_token.checksum.rotate_left(RRC.into());

        let mut decrypted = cipher.decrypt(key, key_usage, &wrap_token.checksum)?;
        // remove wrap token header
        decrypted.truncate(decrypted.len() - WrapToken::header_len());

        match self.state {
            KerberosState::PubKeyAuth => {
                self.state = KerberosState::Credentials;

                *data.buffer.as_mut() = decrypted;
                Ok(DecryptionFlags::empty())
            }
            KerberosState::Credentials => {
                self.state = KerberosState::Final;

                *data.buffer.as_mut() = decrypted;
                Ok(DecryptionFlags::empty())
            }
            _ => {
                *data.buffer.as_mut() = decrypted;
                Ok(DecryptionFlags::empty())
            }
        }
    }

    fn query_context_sizes(&mut self) -> Result<ContextSizes> {
        Ok(ContextSizes {
            max_token: PACKAGE_INFO.max_token_len,
            max_signature: MAX_SIGNATURE as u32,
            block: 0,
            security_trailer: SECURITY_TRAILER as u32,
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

    fn change_password(&mut self, change_password: ChangePassword) -> Result<()> {
        // as ex error
        let username = &change_password.account_name;
        let domain = &change_password.domain_name;
        let password = &change_password.old_password;

        let mut salt = format!("{}{}", domain, username);

        let as_req = generate_as_req_without_pre_auth(username, domain)?;

        let response = self.send(&serialize_message(&as_req)?)?;

        // first 4 bytes is message len. skipping them
        let mut d = picky_asn1_der::Deserializer::new_from_bytes(&response[4..]);
        let as_rep: KrbResult<AsRep> = KrbResult::deserialize(&mut d)?;

        if as_rep.is_ok() {
            return Err(Error {
                error_type: ErrorKind::InternalError,
                description: "KDC server should not proccess AS_REQ without the pa-pac data".to_owned(),
            });
        }

        if let Some(correct_salt) = extract_salt_from_krb_error(&as_rep.unwrap_err())? {
            salt = correct_salt;
        }

        let as_req = generate_passwd_as_req(&username, salt.as_bytes(), password, domain, &self.encryption_params)?;

        let response = self.send(&serialize_message(&as_req)?)?;

        // first 4 bytes is message len. skipping them
        let mut d = picky_asn1_der::Deserializer::new_from_bytes(&response[4..]);
        let as_rep: KrbResult<AsRep> = KrbResult::deserialize(&mut d)?;
        let as_rep = as_rep?;

        self.realm = Some(as_rep.0.crealm.0.to_string());

        let (encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep)?;
        self.encryption_params.encryption_type = Some(encryption_type as i32);

        let session_key =
            extract_session_key_from_as_rep(&as_rep, &salt, &password, &self.encryption_params)?;

        println!("session key: {:?}", session_key);

        let seq_num = self.next_seq_number();
        let authenticator = generate_authenticator_for_krb_priv(&as_rep.0, seq_num)?;
        println!("authenticator key: {:?}", authenticator.0.subkey);
        let krb_priv = generate_krb_priv_request(as_rep.0.ticket.0, &session_key, change_password.new_password.as_bytes(), &authenticator, &self.encryption_params, seq_num)?;

        self.config.url = Url::from_str("tcp://192.168.0.108:464").unwrap();
        let response = self.send(&serialize_message(&krb_priv)?)?;
        println!("response: {:?}", response);

        Ok(())
    }
}

impl SspiImpl for Kerberos {
    type CredentialsHandle = Option<AuthIdentityBuffers>;

    type AuthenticationData = AuthIdentity;

    fn acquire_credentials_handle_impl(
        &mut self,
        builder: crate::builders::FilledAcquireCredentialsHandle<'_, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> Result<crate::AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        if builder.credential_use == CredentialUse::Outbound && builder.auth_data.is_none() {
            return Err(Error::new(
                ErrorKind::NoCredentials,
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
        builder: &mut crate::builders::FilledInitializeSecurityContext<'_, Self::CredentialsHandle>,
    ) -> Result<crate::InitializeSecurityContextResult> {
        let status = match self.state {
            KerberosState::Negotiate => {
                let credentials = builder
                    .credentials_handle
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .ok_or_else(|| Error {
                        error_type: ErrorKind::NoCredentials,
                        description: "No credentials provided".to_owned(),
                    })?;

                let username = utf16_bytes_to_utf8_string(&credentials.user);
                let domain = utf16_bytes_to_utf8_string(&credentials.domain);

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token
                    .buffer
                    .write_all(&picky_asn1_der::to_vec(&generate_neg_token_init(&format!(
                        "{}.{}",
                        username,
                        domain.to_ascii_lowercase()
                    ))?)?)?;

                self.state = KerberosState::Preauthentication;

                SecurityStatus::ContinueNeeded
            }
            KerberosState::Preauthentication => {
                let input = builder.input.as_ref().ok_or_else(|| {
                    sspi::Error::new(ErrorKind::InvalidToken, "Input buffers must be specified".into())
                })?;
                let input_token = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;

                let tgt_ticket = extract_tgt_ticket(&input_token.buffer)?;

                let credentials = builder
                    .credentials_handle
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .ok_or_else(|| Error {
                        error_type: ErrorKind::NoCredentials,
                        description: "No credentials provided".to_owned(),
                    })?;

                let username = utf16_bytes_to_utf8_string(&credentials.user);
                let domain = utf16_bytes_to_utf8_string(&credentials.domain);
                let password = utf16_bytes_to_utf8_string(&credentials.password);
                let mut salt = format!("{}{}", domain, username);

                self.realm = Some(domain.clone());

                let as_req = generate_as_req_without_pre_auth(&username, &domain)?;

                let response = self.send(&serialize_message(&as_req)?)?;

                // first 4 bytes is message len. skipping them
                let mut d = picky_asn1_der::Deserializer::new_from_bytes(&response[4..]);
                let as_rep: KrbResult<AsRep> = KrbResult::deserialize(&mut d)?;

                if as_rep.is_ok() {
                    return Err(Error {
                        error_type: ErrorKind::InternalError,
                        description: "KDC server should not proccess AS_REQ without the pa-pac data".to_owned(),
                    });
                }

                if let Some(correct_salt) = extract_salt_from_krb_error(&as_rep.unwrap_err())? {
                    salt = correct_salt;
                }

                let as_req = generate_as_req(&username, salt.as_bytes(), &password, &domain, &self.encryption_params)?;

                let response = self.send(&serialize_message(&as_req)?)?;

                // first 4 bytes is message len. skipping them
                let mut d = picky_asn1_der::Deserializer::new_from_bytes(&response[4..]);
                let as_rep: KrbResult<AsRep> = KrbResult::deserialize(&mut d)?;
                let as_rep = as_rep?;

                self.realm = Some(as_rep.0.crealm.0.to_string());

                let (encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep)?;
                self.encryption_params.encryption_type = Some(encryption_type as i32);

                let mut authenticator = generate_authenticator_for_tgs_ap_req(&as_rep.0)?;

                let session_key_1 =
                    extract_session_key_from_as_rep(&as_rep, &salt, &password, &self.encryption_params)?;

                let service_principal = builder.target_name.ok_or_else(|| Error {
                    error_type: ErrorKind::NoCredentials,
                    description: "Service target name (service principal name) is not provided".into(),
                })?;

                let tgs_req = generate_tgs_req(
                    &as_rep.0.crealm.0.to_string(),
                    service_principal,
                    &session_key_1,
                    as_rep.0.ticket.0,
                    &mut authenticator,
                    tgt_ticket.map(|ticket| vec![ticket]),
                    &self.encryption_params,
                )?;

                let response = self.send(&serialize_message(&tgs_req)?)?;

                // first 4 bytes is message len. skipping them
                let mut d = picky_asn1_der::Deserializer::new_from_bytes(&response[4..]);
                let tgs_rep: KrbResult<TgsRep> = KrbResult::deserialize(&mut d)?;
                let tgs_rep = tgs_rep?;

                self.encryption_params.session_key = Some(extract_session_key_from_tgs_rep(
                    &tgs_rep,
                    &session_key_1,
                    &self.encryption_params,
                )?);

                let authenticator = generate_authenticator_for_ap_req(&tgs_rep.0, self.next_seq_number())?;

                let ap_req = generate_ap_req(
                    tgs_rep.0.ticket.0,
                    self.encryption_params.session_key.as_ref().unwrap(),
                    &authenticator,
                    &self.encryption_params,
                    &DEFAULT_AP_REQ_OPTIONS,
                )?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token
                    .buffer
                    .write_all(&picky_asn1_der::to_vec(&generate_neg_ap_req(ap_req)?)?)?;

                self.state = KerberosState::ApExchange;

                SecurityStatus::ContinueNeeded
            }
            KerberosState::ApExchange => {
                let input = builder
                    .input
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Input buffers must be specified".into()))?;
                let input_token = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;

                let neg_token_targ: NegTokenTarg1 =
                    picky_asn1_der::from_bytes(&input_token.buffer).map_err(|err| Error {
                        error_type: ErrorKind::InvalidToken,
                        description: format!("{:?}", err),
                    })?;

                let ap_rep = extract_ap_rep_from_neg_token_targ(&neg_token_targ)?;

                self.encryption_params.sub_session_key = Some(extract_sub_session_key_from_ap_rep(
                    &ap_rep,
                    self.encryption_params.session_key.as_ref().unwrap(),
                    &self.encryption_params,
                )?);

                if let Some(ref token) = neg_token_targ.0.mech_list_mic.0 {
                    validate_mic_token(&token.0 .0, ACCEPTOR_SIGN, &self.encryption_params)?;
                }

                let neg_token_targ = generate_final_neg_token_targ(Some(generate_initiator_raw(
                    picky_asn1_der::to_vec(&get_mech_list())?,
                    self.seq_number as u64,
                    self.encryption_params.sub_session_key.as_ref().unwrap(),
                )?));

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token
                    .buffer
                    .write_all(&picky_asn1_der::to_vec(&neg_token_targ)?)?;

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
        builder: crate::builders::FilledAcceptSecurityContext<'_, Self::AuthenticationData, Self::CredentialsHandle>,
    ) -> Result<crate::AcceptSecurityContextResult> {
        let input = builder
            .input
            .ok_or_else(|| sspi::Error::new(ErrorKind::InvalidToken, "Input buffers must be specified".into()))?;

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
