pub mod client;
pub mod config;
mod encryption_params;
pub mod flags;
pub mod server;
mod utils;

use std::fmt::Debug;
use std::io::Write;

pub use encryption_params::EncryptionParams;
use lazy_static::lazy_static;
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{ExplicitContextTag0, ExplicitContextTag1, OctetStringAsn1, Optional};
use picky_asn1_x509::oids;
use picky_krb::constants::gss_api::AUTHENTICATOR_CHECKSUM_TYPE;
use picky_krb::constants::key_usages::ACCEPTOR_SIGN;
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{KerberosStringAsn1, KrbResult, ResultExt};
use picky_krb::gss_api::{NegTokenTarg1, WrapToken};
use picky_krb::messages::{ApReq, AsRep, KdcProxyMessage, KrbPrivMessage, TgsRep};
use rand::rngs::OsRng;
use rand::Rng;
use url::Url;

use self::client::extractors::{
    extract_encryption_params_from_as_rep, extract_session_key_from_as_rep, extract_session_key_from_tgs_rep,
};
use self::client::generators::{
    generate_ap_req, generate_as_req, generate_as_req_kdc_body, generate_authenticator, generate_krb_priv_request,
    generate_neg_ap_req, generate_neg_token_init, generate_pa_datas_for_as_req, generate_tgs_req,
    get_client_principal_name_type, get_client_principal_realm, ChecksumOptions, EncKey, GenerateAsPaDataOptions,
    GenerateAsReqOptions, GenerateAuthenticatorOptions, AUTHENTICATOR_DEFAULT_CHECKSUM,
};
use self::config::KerberosConfig;
use self::server::extractors::extract_tgt_ticket;
use self::utils::{serialize_message, unwrap_hostname};
use super::channel_bindings::ChannelBindings;
use crate::builders::ChangePassword;
use crate::kerberos::client::extractors::{extract_salt_from_krb_error, extract_status_code_from_krb_priv_response};
use crate::kerberos::client::generators::{generate_final_neg_token_targ, get_mech_list, GenerateTgsReqOptions};
use crate::kerberos::server::extractors::{extract_ap_rep_from_neg_token_targ, extract_sub_session_key_from_ap_rep};
use crate::kerberos::utils::{generate_initiator_raw, parse_target_name, validate_mic_token};
use crate::network_client::NetworkProtocol;
use crate::utils::{generate_random_symmetric_key, get_encryption_key, utf16_bytes_to_utf8_string};
use crate::{
    detect_kdc_url, AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers,
    ClientRequestFlags, ClientResponseFlags, ContextNames, ContextSizes, CredentialUse, DecryptionFlags, Error,
    ErrorKind, InitializeSecurityContextResult, PackageCapabilities, PackageInfo, Result, SecurityBuffer,
    SecurityBufferType, SecurityPackageType, SecurityStatus, ServerResponseFlags, Sspi, SspiEx, SspiImpl,
    PACKAGE_ID_NONE,
};

pub const PKG_NAME: &str = "Kerberos";
pub const KERBEROS_VERSION: u8 = 0x05;
pub const TGT_SERVICE_NAME: &str = "krbtgt";
pub const KADMIN: &str = "kadmin";
pub const CHANGE_PASSWORD_SERVICE_NAME: &str = "changepw";

// pub const SSPI_KDC_URL_ENV: &str = "SSPI_KDC_URL";
pub const DEFAULT_ENCRYPTION_TYPE: CipherSuite = CipherSuite::Aes256CtsHmacSha196;

/// [MS-KILE](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-KILE/%5bMS-KILE%5d.pdf)
/// The RRC field is 12 if no encryption is requested or 28 if encryption is requested
pub const RRC: u16 = 28;
// wrap token header len
pub const MAX_SIGNATURE: usize = 16;
// minimal len to fit encrypted public key in wrap token
pub const SECURITY_TRAILER: usize = 60;
/// [Kerberos Change Password and Set Password Protocols](https://datatracker.ietf.org/doc/html/rfc3244#section-2)
/// "The service accepts requests on UDP port 464 and TCP port 464 as well."
const KPASSWD_PORT: u16 = 464;

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
    kdc_url: Option<Url>,
    channel_bindings: Option<ChannelBindings>,
}

impl Kerberos {
    pub fn new_client_from_config(config: KerberosConfig) -> Result<Self> {
        let kdc_url = config.url.clone();

        Ok(Self {
            state: KerberosState::Negotiate,
            config,
            auth_identity: None,
            encryption_params: EncryptionParams::default_for_client(),
            seq_number: OsRng.gen::<u32>(),
            realm: None,
            kdc_url,
            channel_bindings: None,
        })
    }

    pub fn new_server_from_config(config: KerberosConfig) -> Result<Self> {
        let kdc_url = config.url.clone();

        Ok(Self {
            state: KerberosState::Negotiate,
            config,
            auth_identity: None,
            encryption_params: EncryptionParams::default_for_server(),
            seq_number: OsRng.gen::<u32>(),
            realm: None,
            kdc_url,
            channel_bindings: None,
        })
    }

    pub fn config(&self) -> &KerberosConfig {
        &self.config
    }

    pub fn next_seq_number(&mut self) -> u32 {
        self.seq_number += 1;
        self.seq_number
    }

    #[instrument(level = "debug", ret, skip(self))]
    pub fn get_kdc(&self) -> Option<(String, Url)> {
        let realm = self.realm.to_owned()?;
        if let Some(kdc_url) = &self.kdc_url {
            Some((realm, kdc_url.to_owned()))
        } else {
            let kdc_url = detect_kdc_url(&realm)?;
            Some((realm, kdc_url))
        }
    }

    fn send(&self, data: &[u8]) -> Result<Vec<u8>> {
        if let Some((realm, kdc_url)) = self.get_kdc() {
            let protocol = NetworkProtocol::from_url_scheme(kdc_url.scheme()).ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidParameter,
                    format!("Invalid protocol `{}` for KDC server", kdc_url.scheme()),
                )
            })?;

            if !self.config.network_client.is_protocol_supported(protocol) {
                return Err(Error::new(
                    ErrorKind::InvalidParameter,
                    format!(
                        "Network protocol `{}` is not supported by `{}` network client. Supported protocols are: {:?}",
                        kdc_url.scheme(),
                        self.config.network_client.name(),
                        self.config.network_client.supported_protocols(),
                    ),
                ));
            }

            return match protocol {
                NetworkProtocol::Tcp => self.config.network_client.send(protocol, kdc_url, data),
                NetworkProtocol::Udp => {
                    if data.len() < 4 {
                        return Err(Error::new(
                            ErrorKind::InternalError,
                            format!(
                                "kerberos message has invalid length. expected >= 4 but got {}",
                                data.len()
                            ),
                        ));
                    }

                    // First 4 bytes are message length and it’s not included when using UDP
                    self.config.network_client.send(protocol, kdc_url, &data[4..])
                }
                NetworkProtocol::Http | NetworkProtocol::Https => {
                    let data = OctetStringAsn1::from(data.to_vec());
                    let domain = KerberosStringAsn1::from(IA5String::from_string(realm)?);

                    let kdc_proxy_message = KdcProxyMessage {
                        kerb_message: ExplicitContextTag0::from(data),
                        target_domain: Optional::from(Some(ExplicitContextTag1::from(domain))),
                        dclocator_hint: Optional::from(None),
                    };

                    let message_request = picky_asn1_der::to_vec(&kdc_proxy_message)?;
                    let result_bytes = self.config.network_client.send(protocol, kdc_url, &message_request)?;
                    let message_response: KdcProxyMessage = picky_asn1_der::from_bytes(&result_bytes)?;
                    Ok(message_response.kerb_message.0 .0)
                }
            };
        }
        Err(Error::new(ErrorKind::NoAuthenticatingAuthority, "No KDC server found"))
    }

    pub fn as_exchange(
        &mut self,
        options: GenerateAsReqOptions,
        mut pa_data_options: GenerateAsPaDataOptions,
    ) -> Result<AsRep> {
        pa_data_options.with_pre_auth = false;
        let pa_datas = generate_pa_datas_for_as_req(&pa_data_options)?;
        let kdc_req_body = generate_as_req_kdc_body(&options)?;
        let as_req = generate_as_req(&pa_datas, kdc_req_body);

        let response = self.send(&serialize_message(&as_req)?)?;

        // first 4 bytes are message len. skipping them
        let mut d = picky_asn1_der::Deserializer::new_from_bytes(&response[4..]);
        let as_rep: KrbResult<AsRep> = KrbResult::deserialize(&mut d)?;

        if as_rep.is_ok() {
            error!("KDC replied with AS_REP to the AS_REQ without the encrypted timestamp. The KRB_ERROR expected.");

            return Err(Error::new(
                ErrorKind::InternalError,
                "KDC server should not process AS_REQ without the pa-pac data",
            ));
        }

        if let Some(correct_salt) = extract_salt_from_krb_error(&as_rep.unwrap_err())? {
            debug!("salt extracted successfully from the KRB_ERROR");

            pa_data_options.salt = correct_salt.as_bytes().to_vec()
        }

        pa_data_options.with_pre_auth = true;
        let pa_datas = generate_pa_datas_for_as_req(&pa_data_options)?;

        let kdc_req_body = generate_as_req_kdc_body(&options)?;
        let as_req = generate_as_req(&pa_datas, kdc_req_body);

        let response = self.send(&serialize_message(&as_req)?)?;

        // first 4 bytes are message len. skipping them
        let mut d = picky_asn1_der::Deserializer::new_from_bytes(&response[4..]);
        let as_rep: KrbResult<AsRep> = KrbResult::deserialize(&mut d)?;

        as_rep.map_err(|err| {
            error!(?err, "AS exchange error");
            err.into()
        })
    }
}

impl Sspi for Kerberos {
    #[instrument(level = "debug", ret, fields(state = ?self.state), skip_all)]
    fn complete_auth_token(&mut self, _token: &mut [SecurityBuffer]) -> Result<SecurityStatus> {
        Ok(SecurityStatus::Ok)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, _flags, _sequence_number))]
    fn encrypt_message(
        &mut self,
        _flags: crate::EncryptionFlags,
        message: &mut [SecurityBuffer],
        _sequence_number: u32,
    ) -> Result<SecurityStatus> {
        trace!(encryption_params = ?self.encryption_params);

        // checks if the Token buffer present
        let _ = SecurityBuffer::find_buffer(message, SecurityBufferType::Token)?;
        let data = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;

        let cipher = self
            .encryption_params
            .encryption_type
            .as_ref()
            .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
            .cipher();

        let seq_number = self.next_seq_number();

        let key = get_encryption_key(&self.encryption_params)?;

        let key_usage = self.encryption_params.sspi_encrypt_key_usage;

        let mut wrap_token = WrapToken::with_seq_number(seq_number as u64);

        let mut payload = data.buffer.to_vec();
        payload.extend_from_slice(&wrap_token.header());

        let mut checksum = cipher.encrypt(key, key_usage, &payload)?;
        checksum.rotate_right(RRC.into());

        wrap_token.set_rrc(RRC);
        wrap_token.set_checksum(checksum);

        let mut raw_wrap_token = Vec::with_capacity(92);
        wrap_token.encode(&mut raw_wrap_token)?;

        match self.state {
            KerberosState::PubKeyAuth | KerberosState::Credentials | KerberosState::Final => {
                *data.buffer.as_mut() = raw_wrap_token[SECURITY_TRAILER..].to_vec();
                let header = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?;
                *header.buffer.as_mut() = raw_wrap_token[0..SECURITY_TRAILER].to_vec();
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::OutOfSequence,
                    "Kerberos context is not established",
                ))
            }
        };

        Ok(SecurityStatus::Ok)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, _sequence_number))]
    fn decrypt_message(
        &mut self,
        message: &mut [SecurityBuffer],
        _sequence_number: u32,
    ) -> Result<crate::DecryptionFlags> {
        trace!(encryption_params = ?self.encryption_params);

        let mut encrypted = if let Ok(buffer) = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token) {
            buffer
        } else {
            SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Stream)?
        }
        .buffer
        .clone();
        let data = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;

        encrypted.extend_from_slice(&data.buffer);

        let cipher = self
            .encryption_params
            .encryption_type
            .as_ref()
            .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
            .cipher();

        let key = get_encryption_key(&self.encryption_params)?;

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

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_sizes(&mut self) -> Result<ContextSizes> {
        Ok(ContextSizes {
            max_token: PACKAGE_INFO.max_token_len,
            max_signature: MAX_SIGNATURE as u32,
            block: 0,
            security_trailer: SECURITY_TRAILER as u32,
        })
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_names(&mut self) -> Result<ContextNames> {
        if let Some(ref identity_buffers) = self.auth_identity {
            let identity: AuthIdentity = identity_buffers.clone().into();
            Ok(ContextNames {
                username: identity.username,
                domain: identity.domain,
            })
        } else {
            Err(crate::Error::new(
                crate::ErrorKind::NoCredentials,
                String::from("Requested Names, but no credentials were provided"),
            ))
        }
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_package_info(&mut self) -> Result<PackageInfo> {
        crate::query_security_package_info(SecurityPackageType::Kerberos)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_cert_trust_status(&mut self) -> Result<crate::CertTrustStatus> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "Certificate trust status is not supported".to_owned(),
        ))
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, change_password))]
    fn change_password(&mut self, change_password: ChangePassword) -> Result<()> {
        let username = &change_password.account_name;
        let domain = &change_password.domain_name;
        let password = &change_password.old_password;

        let salt = format!("{}{}", domain, username);

        let cname_type = get_client_principal_name_type(username, domain);
        let realm = &get_client_principal_realm(username, domain);
        let hostname = unwrap_hostname(self.config.hostname.as_deref())?;

        let as_rep = self.as_exchange(
            GenerateAsReqOptions {
                realm,
                username,
                cname_type,
                snames: &[KADMIN, CHANGE_PASSWORD_SERVICE_NAME],
                // 4 = size of u32
                nonce: &OsRng.gen::<[u8; 4]>(),
                hostname: &hostname,
                context_requirements: ClientRequestFlags::empty(),
            },
            GenerateAsPaDataOptions {
                password: password.as_ref(),
                salt: salt.as_bytes().to_vec(),
                enc_params: self.encryption_params.clone(),
                with_pre_auth: false,
            },
        )?;

        info!("AS exchange finished successfully.");

        self.realm = Some(as_rep.0.crealm.0.to_string());

        let (encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep)?;
        info!(?encryption_type, "Negotiated encryption type");

        self.encryption_params.encryption_type = Some(CipherSuite::try_from(encryption_type as usize)?);

        let session_key = extract_session_key_from_as_rep(&as_rep, &salt, password.as_ref(), &self.encryption_params)?;

        let seq_num = self.next_seq_number();

        let enc_type = self
            .encryption_params
            .encryption_type
            .as_ref()
            .unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
        let authenticator_seb_key = generate_random_symmetric_key(enc_type, &mut OsRng);

        let authenticator = generate_authenticator(GenerateAuthenticatorOptions {
            kdc_rep: &as_rep.0,
            seq_num: Some(seq_num),
            sub_key: Some(EncKey {
                key_type: enc_type.clone(),
                key_value: authenticator_seb_key,
            }),
            checksum: None,
            channel_bindings: self.channel_bindings.as_ref(),
            extensions: Vec::new(),
        })?;

        let krb_priv = generate_krb_priv_request(
            as_rep.0.ticket.0,
            &session_key,
            change_password.new_password.as_ref().as_bytes(),
            &authenticator,
            &self.encryption_params,
            seq_num,
            &hostname,
        )?;

        if let Some((_realm, mut kdc_url)) = self.get_kdc() {
            kdc_url
                .set_port(Some(KPASSWD_PORT))
                .map_err(|_| Error::new(ErrorKind::InvalidParameter, "Cannot set port for KDC URL"))?;

            let response = self.send(&serialize_message(&krb_priv)?)?;
            trace!(?response, "Change password raw response");

            let krb_priv_response = KrbPrivMessage::deserialize(&response[4..]).map_err(|err| {
                Error::new(
                    ErrorKind::InvalidToken,
                    format!("Cannot deserialize krb_priv_response: {:?}", err),
                )
            })?;

            let result_status = extract_status_code_from_krb_priv_response(
                &krb_priv_response.krb_priv,
                &authenticator.0.subkey.0.as_ref().unwrap().0.key_value.0 .0,
                &self.encryption_params,
            )?;

            if result_status != 0 {
                return Err(Error::new(
                    ErrorKind::WrongCredentialHandle,
                    format!("unsuccessful krb result code: {}. expected 0", result_status),
                ));
            }
        } else {
            return Err(Error::new(
                ErrorKind::NoAuthenticatingAuthority,
                "No KDC server found!".to_owned(),
            ));
        }

        Ok(())
    }
}

impl SspiImpl for Kerberos {
    type CredentialsHandle = Option<AuthIdentityBuffers>;

    type AuthenticationData = AuthIdentity;

    #[instrument(level = "trace", ret, fields(state = ?self.state), skip(self))]
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

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, builder))]
    fn initialize_security_context_impl(
        &mut self,
        builder: &mut crate::builders::FilledInitializeSecurityContext<'_, Self::CredentialsHandle>,
    ) -> Result<crate::InitializeSecurityContextResult> {
        trace!(?builder);

        let status = match self.state {
            KerberosState::Negotiate => {
                let credentials = builder
                    .credentials_handle
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::NoCredentials, "No credentials provided"))?;

                let username = utf16_bytes_to_utf8_string(&credentials.user);
                let domain = utf16_bytes_to_utf8_string(&credentials.domain);
                let (service_name, _) = parse_target_name(builder.target_name.ok_or_else(|| {
                    Error::new(
                        ErrorKind::NoCredentials,
                        "Service target name (service principal name) is not provided",
                    )
                })?)?;

                let encoded_neg_token_init = picky_asn1_der::to_vec(&generate_neg_token_init(
                    &format!("{}.{}", username, domain.to_ascii_lowercase(),),
                    service_name,
                )?)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token.buffer.write_all(&encoded_neg_token_init)?;

                self.state = KerberosState::Preauthentication;

                SecurityStatus::ContinueNeeded
            }
            KerberosState::Preauthentication => {
                let input = builder
                    .input
                    .as_ref()
                    .ok_or_else(|| crate::Error::new(ErrorKind::InvalidToken, "Input buffers must be specified"))?;

                if let Ok(sec_buffer) =
                    SecurityBuffer::find_buffer(builder.input.as_ref().unwrap(), SecurityBufferType::ChannelBindings)
                {
                    self.channel_bindings = Some(ChannelBindings::from_bytes(&sec_buffer.buffer)?);
                }

                let input_token = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;

                let tgt_ticket = extract_tgt_ticket(&input_token.buffer)?;

                let credentials = builder
                    .credentials_handle
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::WrongCredentialHandle, "No credentials provided"))?;

                let username = utf16_bytes_to_utf8_string(&credentials.user);
                let domain = utf16_bytes_to_utf8_string(&credentials.domain);
                let password = utf16_bytes_to_utf8_string(credentials.password.as_ref());
                let salt = format!("{}{}", domain, username);

                self.realm = Some(get_client_principal_realm(&username, &domain));

                let cname_type = get_client_principal_name_type(&username, &domain);
                let realm = &get_client_principal_realm(&username, &domain);

                let as_rep = self.as_exchange(
                    GenerateAsReqOptions {
                        realm,
                        username: &username,
                        cname_type,
                        snames: &[TGT_SERVICE_NAME, realm],
                        // 4 = size of u32
                        nonce: &OsRng.gen::<[u8; 4]>(),
                        hostname: &unwrap_hostname(self.config.hostname.as_deref())?,
                        context_requirements: builder.context_requirements,
                    },
                    GenerateAsPaDataOptions {
                        password: &password,
                        salt: salt.as_bytes().to_vec(),
                        enc_params: self.encryption_params.clone(),
                        with_pre_auth: false,
                    },
                )?;

                info!("AS exchange finished successfully.");

                self.realm = Some(as_rep.0.crealm.0.to_string());

                let (encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep)?;

                let encryption_type = CipherSuite::try_from(encryption_type as usize)?;

                self.encryption_params.encryption_type = Some(encryption_type);

                let mut authenticator = generate_authenticator(GenerateAuthenticatorOptions {
                    kdc_rep: &as_rep.0,
                    seq_num: Some(OsRng.gen::<u32>()),
                    sub_key: None,
                    checksum: None,
                    channel_bindings: self.channel_bindings.as_ref(),
                    extensions: Vec::new(),
                })?;

                let session_key_1 =
                    extract_session_key_from_as_rep(&as_rep, &salt, &password, &self.encryption_params)?;

                let service_principal = builder.target_name.ok_or_else(|| {
                    Error::new(
                        ErrorKind::NoCredentials,
                        "Service target name (service principal name) is not provided",
                    )
                })?;

                let tgs_req = generate_tgs_req(GenerateTgsReqOptions {
                    realm: &as_rep.0.crealm.0.to_string(),
                    service_principal,
                    session_key: &session_key_1,
                    ticket: as_rep.0.ticket.0,
                    authenticator: &mut authenticator,
                    additional_tickets: tgt_ticket.map(|ticket| vec![ticket]),
                    enc_params: &self.encryption_params,
                    context_requirements: builder.context_requirements,
                })?;

                let response = self.send(&serialize_message(&tgs_req)?)?;

                // first 4 bytes are message len. skipping them
                let mut d = picky_asn1_der::Deserializer::new_from_bytes(&response[4..]);
                let tgs_rep: KrbResult<TgsRep> = KrbResult::deserialize(&mut d)?;
                let tgs_rep = tgs_rep?;

                info!("TGS exchange finished successfully");

                let session_key_2 =
                    extract_session_key_from_tgs_rep(&tgs_rep, &session_key_1, &self.encryption_params)?;

                self.encryption_params.session_key = Some(session_key_2);

                let seq_num = self.next_seq_number();

                let enc_type = self
                    .encryption_params
                    .encryption_type
                    .as_ref()
                    .unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
                let authenticator_sub_key = generate_random_symmetric_key(enc_type, &mut OsRng);

                let authenticator = generate_authenticator(GenerateAuthenticatorOptions {
                    kdc_rep: &tgs_rep.0,
                    seq_num: Some(seq_num),
                    sub_key: Some(EncKey {
                        key_type: enc_type.clone(),
                        key_value: authenticator_sub_key,
                    }),
                    checksum: Some(ChecksumOptions {
                        checksum_type: AUTHENTICATOR_CHECKSUM_TYPE.to_vec(),
                        checksum_value: AUTHENTICATOR_DEFAULT_CHECKSUM.to_vec(),
                    }),
                    channel_bindings: self.channel_bindings.as_ref(),
                    extensions: Vec::new(),
                })?;

                // FIXME: properly negotiate mech id - Windows always does KRB5 U2U
                let mech_id = oids::krb5_user_to_user();

                let mut context_requirements = builder.context_requirements;

                if mech_id == oids::krb5_user_to_user() {
                    // KRB5 U2U always needs the use-session-key flag
                    context_requirements.set(ClientRequestFlags::USE_SESSION_KEY, true);
                }

                let ap_req = generate_ap_req(
                    tgs_rep.0.ticket.0,
                    self.encryption_params.session_key.as_ref().unwrap(),
                    &authenticator,
                    &self.encryption_params,
                    context_requirements.into(),
                )?;

                let encoded_neg_ap_req = picky_asn1_der::to_vec(&generate_neg_ap_req(ap_req, mech_id)?)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token.buffer.write_all(&encoded_neg_ap_req)?;

                self.state = KerberosState::ApExchange;

                SecurityStatus::ContinueNeeded
            }
            KerberosState::ApExchange => {
                let input = builder
                    .input
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Input buffers must be specified"))?;
                let input_token = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;

                let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;

                let ap_rep = extract_ap_rep_from_neg_token_targ(&neg_token_targ)?;

                let sub_session_key = extract_sub_session_key_from_ap_rep(
                    &ap_rep,
                    self.encryption_params.session_key.as_ref().unwrap(),
                    &self.encryption_params,
                )?;

                self.encryption_params.sub_session_key = Some(sub_session_key);

                info!("Sub-session key from the AP_REP successfully extracted");

                if let Some(ref token) = neg_token_targ.0.mech_list_mic.0 {
                    validate_mic_token(&token.0 .0, ACCEPTOR_SIGN, &self.encryption_params)?;
                }

                let neg_token_targ = generate_final_neg_token_targ(Some(generate_initiator_raw(
                    picky_asn1_der::to_vec(&get_mech_list())?,
                    self.seq_number as u64,
                    self.encryption_params.sub_session_key.as_ref().unwrap(),
                )?));

                let encoded_final_neg_token_targ = picky_asn1_der::to_vec(&neg_token_targ)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token.buffer.write_all(&encoded_final_neg_token_targ)?;

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

        trace!(output_buffers = ?builder.output);

        Ok(InitializeSecurityContextResult {
            status,
            flags: ClientResponseFlags::empty(),
            expiry: None,
        })
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, builder))]
    fn accept_security_context_impl(
        &mut self,
        builder: crate::builders::FilledAcceptSecurityContext<'_, Self::AuthenticationData, Self::CredentialsHandle>,
    ) -> Result<crate::AcceptSecurityContextResult> {
        let input = builder
            .input
            .ok_or_else(|| crate::Error::new(ErrorKind::InvalidToken, "Input buffers must be specified"))?;

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
    #[instrument(level = "trace", ret, fields(state = ?self.state), skip(self))]
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) {
        self.auth_identity = Some(identity.into());
    }
}

#[cfg(test)]
mod tests {
    use picky_krb::constants::key_usages::{ACCEPTOR_SEAL, INITIATOR_SEAL};
    use picky_krb::crypto::CipherSuite;

    use super::EncryptionParams;
    use crate::network_client::{NetworkClient, NetworkProtocol};
    use crate::{EncryptionFlags, Kerberos, KerberosConfig, KerberosState, SecurityBuffer, SecurityBufferType, Sspi};

    struct NetworkClientMock;

    impl NetworkClient for NetworkClientMock {
        fn send(&self, _protocol: NetworkProtocol, _url: url::Url, _data: &[u8]) -> crate::Result<Vec<u8>> {
            unreachable!("unsupported protocol")
        }

        fn box_clone(&self) -> Box<dyn NetworkClient> {
            Box::new(Self)
        }

        fn name(&self) -> &'static str {
            "Mock"
        }

        fn supported_protocols(&self) -> &[crate::network_client::NetworkProtocol] {
            &[]
        }
    }

    #[test]
    fn stream_buffer_decryption() {
        // https://learn.microsoft.com/en-us/windows/win32/secauthn/sspi-kerberos-interoperability-with-gssapi

        let session_key = vec![
            137, 60, 120, 245, 164, 179, 76, 200, 242, 96, 57, 174, 111, 209, 90, 76, 58, 117, 55, 138, 81, 75, 110,
            235, 80, 228, 14, 238, 76, 128, 139, 81,
        ];
        let sub_session_key = vec![
            35, 147, 211, 63, 83, 48, 241, 34, 97, 95, 27, 106, 195, 18, 95, 91, 17, 45, 187, 6, 26, 195, 16, 108, 123,
            119, 121, 155, 58, 142, 204, 74,
        ];

        let mut kerberos_server = Kerberos {
            state: KerberosState::Final,
            config: KerberosConfig {
                url: None,
                network_client: Box::new(NetworkClientMock),
                hostname: None,
            },
            auth_identity: None,
            encryption_params: EncryptionParams {
                encryption_type: Some(CipherSuite::Aes256CtsHmacSha196),
                session_key: Some(session_key.clone()),
                sub_session_key: Some(sub_session_key.clone()),
                sspi_encrypt_key_usage: INITIATOR_SEAL,
                sspi_decrypt_key_usage: ACCEPTOR_SEAL,
            },
            seq_number: 0,
            realm: None,
            kdc_url: None,
            channel_bindings: None,
        };

        let mut kerberos_client = Kerberos {
            state: KerberosState::Final,
            config: KerberosConfig {
                url: None,
                network_client: Box::new(NetworkClientMock),
                hostname: None,
            },
            auth_identity: None,
            encryption_params: EncryptionParams {
                encryption_type: Some(CipherSuite::Aes256CtsHmacSha196),
                session_key: Some(session_key),
                sub_session_key: Some(sub_session_key),
                sspi_encrypt_key_usage: ACCEPTOR_SEAL,
                sspi_decrypt_key_usage: INITIATOR_SEAL,
            },
            seq_number: 0,
            realm: None,
            kdc_url: None,
            channel_bindings: None,
        };

        let plain_message = b"some plain message";

        let mut message = [
            SecurityBuffer {
                buffer: Vec::new(),
                buffer_type: SecurityBufferType::Token,
            },
            SecurityBuffer {
                buffer: plain_message.to_vec(),
                buffer_type: SecurityBufferType::Data,
            },
        ];

        kerberos_server
            .encrypt_message(EncryptionFlags::empty(), &mut message, 0)
            .unwrap();

        let mut buffer = message[0].buffer.clone();
        buffer.extend_from_slice(&message[1].buffer);
        let mut message = [
            SecurityBuffer {
                buffer,
                buffer_type: SecurityBufferType::Stream,
            },
            SecurityBuffer {
                buffer: Vec::new(),
                buffer_type: SecurityBufferType::Data,
            },
        ];

        kerberos_client.decrypt_message(&mut message, 0).unwrap();

        assert_eq!(message[1].buffer, plain_message);
    }
}
