pub mod client;
pub mod config;
mod encryption_params;
pub mod flags;
mod pa_datas;
pub mod server;
mod utils;

use std::fmt::Debug;
use std::io::Write;
use std::sync::LazyLock;

pub use encryption_params::EncryptionParams;
use picky::key::PrivateKey;
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{ExplicitContextTag0, ExplicitContextTag1, OctetStringAsn1, Optional};
use picky_asn1_x509::oids;
use picky_krb::constants::gss_api::AUTHENTICATOR_CHECKSUM_TYPE;
use picky_krb::constants::key_usages::ACCEPTOR_SIGN;
use picky_krb::crypto::{CipherSuite, DecryptWithoutChecksum, EncryptWithoutChecksum};
use picky_krb::data_types::{KerberosStringAsn1, KrbResult, ResultExt};
use picky_krb::gss_api::{NegTokenTarg1, WrapToken};
use picky_krb::messages::{ApReq, AsRep, KdcProxyMessage, KdcReqBody, KrbPrivMessage, TgsRep};
use rand::rngs::OsRng;
use rand::Rng;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use sha1::{Digest, Sha1};
use url::Url;

use self::client::extractors::{
    extract_encryption_params_from_as_rep, extract_session_key_from_as_rep, extract_session_key_from_tgs_rep,
};
use self::client::generators::{
    generate_ap_req, generate_as_req, generate_as_req_kdc_body, generate_krb_priv_request, generate_neg_ap_req,
    generate_neg_token_init, generate_pa_datas_for_as_req, generate_tgs_req, get_client_principal_name_type,
    get_client_principal_realm, ChecksumOptions, ChecksumValues, EncKey, GenerateAsPaDataOptions, GenerateAsReqOptions,
    GenerateAuthenticatorOptions,
};
use self::config::KerberosConfig;
use self::pa_datas::AsReqPaDataOptions;
use self::server::extractors::extract_tgt_ticket;
use self::utils::{serialize_message, unwrap_hostname};
use super::channel_bindings::ChannelBindings;
use crate::builders::ChangePassword;
use crate::generator::{GeneratorChangePassword, GeneratorInitSecurityContext, NetworkRequest, YieldPointLocal};
use crate::kerberos::client::extractors::{extract_salt_from_krb_error, extract_status_code_from_krb_priv_response};
use crate::kerberos::client::generators::{
    generate_ap_rep, generate_authenticator, generate_final_neg_token_targ, get_mech_list, GenerateTgsReqOptions,
    GssFlags,
};
use crate::kerberos::pa_datas::AsRepSessionKeyExtractor;
use crate::kerberos::server::extractors::{
    extract_ap_rep_from_neg_token_targ, extract_seq_number_from_ap_rep, extract_sub_session_key_from_ap_rep,
};
use crate::kerberos::utils::{generate_initiator_raw, validate_mic_token};
use crate::network_client::NetworkProtocol;
use crate::pk_init::{self, DhParameters};
use crate::pku2u::generate_client_dh_parameters;
use crate::utils::{
    extract_encrypted_data, generate_random_symmetric_key, get_encryption_key, parse_target_name, save_decrypted_data,
    utf16_bytes_to_utf8_string,
};
use crate::{
    check_if_empty, detect_kdc_url, AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity,
    BufferType, ClientRequestFlags, ClientResponseFlags, ContextNames, ContextSizes, CredentialUse, Credentials,
    CredentialsBuffers, DecryptionFlags, Error, ErrorKind, InitializeSecurityContextResult, PackageCapabilities,
    PackageInfo, Result, SecurityBuffer, SecurityBufferFlags, SecurityBufferRef, SecurityPackageType, SecurityStatus,
    ServerResponseFlags, Sspi, SspiEx, SspiImpl, PACKAGE_ID_NONE,
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

pub static PACKAGE_INFO: LazyLock<PackageInfo> = LazyLock::new(|| PackageInfo {
    capabilities: PackageCapabilities::empty(),
    rpc_id: PACKAGE_ID_NONE,
    max_token_len: 0xbb80, // 48 000 bytes: default maximum token len in Windows
    name: SecurityPackageType::Kerberos,
    comment: String::from("Kerberos Security Package"),
});

#[derive(Debug, Clone)]
pub enum KerberosState {
    Negotiate,
    Preauthentication,
    ApExchange,
    ApRepDce,
    PubKeyAuth,
    Credentials,
    Final,
}

#[derive(Debug, Clone)]
pub struct Kerberos {
    state: KerberosState,
    config: KerberosConfig,
    auth_identity: Option<CredentialsBuffers>,
    encryption_params: EncryptionParams,
    seq_number: u32,
    realm: Option<String>,
    kdc_url: Option<Url>,
    channel_bindings: Option<ChannelBindings>,
    dh_parameters: Option<DhParameters>,
}

impl Kerberos {
    pub fn new_client_from_config(config: KerberosConfig) -> Result<Self> {
        let kdc_url = config.kdc_url.clone();

        Ok(Self {
            state: KerberosState::Negotiate,
            config,
            auth_identity: None,
            encryption_params: EncryptionParams::default_for_client(),
            seq_number: OsRng.gen::<u32>(),
            realm: None,
            kdc_url,
            channel_bindings: None,
            dh_parameters: None,
        })
    }

    pub fn new_server_from_config(config: KerberosConfig) -> Result<Self> {
        let kdc_url = config.kdc_url.clone();

        Ok(Self {
            state: KerberosState::Negotiate,
            config,
            auth_identity: None,
            encryption_params: EncryptionParams::default_for_server(),
            seq_number: OsRng.gen::<u32>(),
            realm: None,
            kdc_url,
            channel_bindings: None,
            dh_parameters: None,
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

    async fn send<'data>(&self, yield_point: &mut YieldPointLocal, data: &'data [u8]) -> Result<Vec<u8>> {
        if let Some((realm, kdc_url)) = self.get_kdc() {
            let protocol = NetworkProtocol::from_url_scheme(kdc_url.scheme()).ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidParameter,
                    format!("Invalid protocol `{}` for KDC server", kdc_url.scheme()),
                )
            })?;

            return match protocol {
                NetworkProtocol::Tcp => {
                    let request = NetworkRequest {
                        protocol,
                        url: kdc_url.clone(),
                        data: data.to_vec(),
                    };
                    yield_point.suspend(request).await
                }
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
                    let request = NetworkRequest {
                        protocol,
                        url: kdc_url.clone(),
                        data: data[4..].to_vec(),
                    };
                    yield_point.suspend(request).await
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
                    let request = NetworkRequest {
                        protocol,
                        url: kdc_url,
                        data: message_request,
                    };
                    let result_bytes = yield_point.suspend(request).await?;
                    let message_response: KdcProxyMessage = picky_asn1_der::from_bytes(&result_bytes)?;
                    Ok(message_response.kerb_message.0 .0)
                }
            };
        }
        Err(Error::new(ErrorKind::NoAuthenticatingAuthority, "No KDC server found"))
    }

    fn prepare_final_neg_token(
        &mut self,
        builder: &mut crate::builders::FilledInitializeSecurityContext<'_, <Self as SspiImpl>::CredentialsHandle>,
    ) -> Result<()> {
        let neg_token_targ = generate_final_neg_token_targ(Some(generate_initiator_raw(
            picky_asn1_der::to_vec(&get_mech_list())?,
            self.seq_number as u64,
            self.encryption_params
                .sub_session_key
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::InternalError, "kerberos sub-session key is not set"))?,
        )?));

        let encoded_final_neg_token_targ = picky_asn1_der::to_vec(&neg_token_targ)?;

        let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
        output_token.buffer.write_all(&encoded_final_neg_token_targ)?;
        Ok(())
    }

    pub async fn as_exchange(
        &mut self,
        yield_point: &mut YieldPointLocal,
        kdc_req_body: &KdcReqBody,
        mut pa_data_options: AsReqPaDataOptions<'_>,
    ) -> Result<AsRep> {
        pa_data_options.with_pre_auth(false);
        let pa_datas = pa_data_options.generate()?;
        let as_req = generate_as_req(pa_datas, kdc_req_body.clone());

        let response = self.send(yield_point, &serialize_message(&as_req)?).await?;

        // first 4 bytes are message len. skipping them
        {
            let mut d = picky_asn1_der::Deserializer::new_from_bytes(&response[4..]);
            let as_rep: KrbResult<AsRep> = KrbResult::deserialize(&mut d)?;

            if as_rep.is_ok() {
                error!(
                    "KDC replied with AS_REP to the AS_REQ without the encrypted timestamp. The KRB_ERROR expected."
                );

                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    "KDC server should not process AS_REQ without the pa-pac data",
                ));
            }

            if let Some(correct_salt) = extract_salt_from_krb_error(&as_rep.unwrap_err())? {
                debug!("salt extracted successfully from the KRB_ERROR");

                pa_data_options.with_salt(correct_salt.as_bytes().to_vec());
            }
        }

        pa_data_options.with_pre_auth(true);
        let pa_datas = pa_data_options.generate()?;

        let as_req = generate_as_req(pa_datas, kdc_req_body.clone());

        let response = self.send(yield_point, &serialize_message(&as_req)?).await?;

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
        message: &mut [SecurityBufferRef],
        _sequence_number: u32,
    ) -> Result<SecurityStatus> {
        trace!(encryption_params = ?self.encryption_params);

        // checks if the Token buffer present
        let _ = SecurityBufferRef::find_buffer(message, BufferType::Token)?;
        // Find `Data` buffers but skip `Data` buffers with the `READONLY_WITH_CHECKSUM`/`READONLY` flag.
        let data_to_encrypt =
            SecurityBufferRef::buffers_of_type_and_flags(message, BufferType::Data, SecurityBufferFlags::NONE);

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

        let mut payload = data_to_encrypt.fold(Vec::new(), |mut acc, buffer| {
            acc.extend_from_slice(buffer.data());
            acc
        });
        payload.extend_from_slice(&wrap_token.header());

        let EncryptWithoutChecksum {
            mut encrypted,
            confounder,
            ki: _,
        } = cipher.encrypt_no_checksum(key, key_usage, &payload)?;

        // Find `Data` buffers (including `Data` buffers with the `READONLY_WITH_CHECKSUM` flag).
        let data_to_sign =
            SecurityBufferRef::buffers_of_type(message, BufferType::Data).fold(confounder, |mut acc, buffer| {
                acc.extend_from_slice(buffer.data());
                acc
            });

        let checksum_suite = cipher.checksum_type().hasher();
        let checksum = checksum_suite.checksum(key, key_usage, &data_to_sign)?;

        encrypted.extend_from_slice(&checksum);

        encrypted.rotate_right(RRC.into());

        wrap_token.set_rrc(RRC);
        wrap_token.set_checksum(encrypted);

        let mut raw_wrap_token = Vec::with_capacity(92);
        wrap_token.encode(&mut raw_wrap_token)?;

        match self.state {
            KerberosState::PubKeyAuth | KerberosState::Credentials | KerberosState::Final => {
                if raw_wrap_token.len() < SECURITY_TRAILER {
                    return Err(Error::new(ErrorKind::EncryptFailure, "Cannot encrypt the data"));
                }

                let (token, data) = raw_wrap_token.split_at(SECURITY_TRAILER);

                let data_buffer = SecurityBufferRef::buffers_of_type_and_flags_mut(
                    message,
                    BufferType::Data,
                    SecurityBufferFlags::NONE,
                )
                .next()
                .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "no buffer was provided with type Data"))?;

                data_buffer.write_data(data)?;

                let token_buffer = SecurityBufferRef::find_buffer_mut(message, BufferType::Token)?;
                token_buffer.write_data(token)?;
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
    fn decrypt_message(&mut self, message: &mut [SecurityBufferRef], _sequence_number: u32) -> Result<DecryptionFlags> {
        trace!(encryption_params = ?self.encryption_params);

        let encrypted = extract_encrypted_data(message)?;

        let cipher = self
            .encryption_params
            .encryption_type
            .as_ref()
            .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
            .cipher();

        let key = get_encryption_key(&self.encryption_params)?;

        let key_usage = self.encryption_params.sspi_decrypt_key_usage;

        let wrap_token = WrapToken::decode(encrypted.as_slice())?;

        let mut checksum = wrap_token.checksum;
        // TODO: add doc comment
        checksum.rotate_left((RRC + wrap_token.ec).into());

        let DecryptWithoutChecksum {
            plaintext: decrypted,
            confounder,
            checksum,
            ki: _,
        } = cipher.decrypt_no_checksum(key, key_usage, &checksum)?;

        let plaintext_len = decrypted.len() - usize::from(wrap_token.ec) - WrapToken::header_len();

        let plaintext = &decrypted[0..plaintext_len];
        let wrap_token_header = &decrypted[plaintext_len..];

        // Find `Data` buffers (including `Data` buffers with the `READONLY_WITH_CHECKSUM` flag).
        let mut data_to_sign =
            SecurityBufferRef::buffers_of_type(message, BufferType::Data).fold(confounder, |mut acc, buffer| {
                if buffer
                    .buffer_flags()
                    .contains(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM)
                {
                    acc.extend_from_slice(buffer.data());
                } else {
                    // The `Data` buffer contains encrypted data, but the checksum was calculated over the decrypted data.
                    // So, we replace encrypted data with decrypted one.
                    // Note: our implementation expect maximum one plain `DATA` buffer but multiple `DATA` buffers
                    // with `SECBUFFER_READONLY_WITH_CHECKSUM` flag are allowed.
                    acc.extend_from_slice(&plaintext);
                }
                acc
            });
        data_to_sign.extend_from_slice(wrap_token_header);

        let calculated_checksum = cipher.encryption_checksum(key, key_usage, &data_to_sign)?;

        if calculated_checksum != checksum {
            return Err(picky_krb::crypto::KerberosCryptoError::IntegrityCheck.into());
        }

        save_decrypted_data(plaintext, message)?;

        match self.state {
            KerberosState::PubKeyAuth => {
                self.state = KerberosState::Credentials;
                Ok(DecryptionFlags::empty())
            }
            KerberosState::Credentials => {
                self.state = KerberosState::Final;
                Ok(DecryptionFlags::empty())
            }
            _ => Ok(DecryptionFlags::empty()),
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
        if let Some(CredentialsBuffers::AuthIdentity(identity_buffers)) = &self.auth_identity {
            let identity =
                AuthIdentity::try_from(identity_buffers).map_err(|e| Error::new(ErrorKind::InvalidParameter, e))?;

            return Ok(ContextNames {
                username: identity.username,
            });
        }
        if let Some(CredentialsBuffers::SmartCard(ref identity_buffers)) = self.auth_identity {
            let username = utf16_bytes_to_utf8_string(&identity_buffers.username);
            let username = crate::Username::parse(&username).map_err(|e| Error::new(ErrorKind::InvalidParameter, e))?;
            return Ok(ContextNames { username });
        }
        Err(crate::Error::new(
            crate::ErrorKind::NoCredentials,
            String::from("Requested Names, but no credentials were provided"),
        ))
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

    fn change_password<'a>(&'a mut self, change_password: ChangePassword<'a>) -> Result<GeneratorChangePassword> {
        Ok(GeneratorChangePassword::new(move |mut yield_point| async move {
            self.change_password(&mut yield_point, change_password).await
        }))
    }
}

impl SspiImpl for Kerberos {
    type CredentialsHandle = Option<CredentialsBuffers>;

    type AuthenticationData = Credentials;

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

        self.auth_identity = builder
            .auth_data
            .cloned()
            .map(|auth_data| auth_data.try_into())
            .transpose()?;

        Ok(AcquireCredentialsHandleResult {
            credentials_handle: self.auth_identity.clone(),
            expiry: None,
        })
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, builder))]
    fn accept_security_context_impl(
        &mut self,
        builder: crate::builders::FilledAcceptSecurityContext<'_, Self::CredentialsHandle>,
    ) -> Result<crate::AcceptSecurityContextResult> {
        let input = builder
            .input
            .ok_or_else(|| crate::Error::new(ErrorKind::InvalidToken, "Input buffers must be specified"))?;

        let status = match &self.state {
            KerberosState::ApExchange => {
                let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;

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

    fn initialize_security_context_impl<'a>(
        &'a mut self,
        builder: &'a mut crate::builders::FilledInitializeSecurityContext<Self::CredentialsHandle>,
    ) -> Result<GeneratorInitSecurityContext> {
        Ok(GeneratorInitSecurityContext::new(move |mut yield_point| async move {
            self.initialize_security_context_impl(&mut yield_point, builder).await
        }))
    }
}

impl<'a> Kerberos {
    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, change_password))]
    pub async fn change_password(
        &'a mut self,
        yield_point: &mut YieldPointLocal,
        change_password: ChangePassword<'a>,
    ) -> Result<()> {
        let username = &change_password.account_name;
        let domain = &change_password.domain_name;
        let password = &change_password.old_password;

        let salt = format!("{}{}", domain, username);

        let cname_type = get_client_principal_name_type(username, domain);
        let realm = &get_client_principal_realm(username, domain);
        let hostname = unwrap_hostname(self.config.client_computer_name.as_deref())?;

        let options = GenerateAsReqOptions {
            realm,
            username,
            cname_type,
            snames: &[KADMIN, CHANGE_PASSWORD_SERVICE_NAME],
            // 4 = size of u32
            nonce: &OsRng.gen::<u32>().to_ne_bytes(),
            hostname: &hostname,
            context_requirements: ClientRequestFlags::empty(),
        };
        let kdc_req_body = generate_as_req_kdc_body(&options)?;

        let pa_data_options = AsReqPaDataOptions::AuthIdentity(GenerateAsPaDataOptions {
            password: password.as_ref(),
            salt: salt.as_bytes().to_vec(),
            enc_params: self.encryption_params.clone(),
            with_pre_auth: false,
        });

        let as_rep = self.as_exchange(yield_point, &kdc_req_body, pa_data_options).await?;

        info!("AS exchange finished successfully.");

        self.realm = Some(as_rep.0.crealm.0.to_string());

        let (encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep)?;
        info!(?encryption_type, "Negotiated encryption type");

        self.encryption_params.encryption_type = Some(CipherSuite::try_from(usize::from(encryption_type))?);

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

            let response = self.send(yield_point, &serialize_message(&krb_priv)?).await?;
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

    pub(crate) async fn initialize_security_context_impl(
        &'a mut self,
        yield_point: &mut YieldPointLocal,
        builder: &'a mut crate::builders::FilledInitializeSecurityContext<'_, <Self as SspiImpl>::CredentialsHandle>,
    ) -> Result<crate::InitializeSecurityContextResult> {
        trace!(?builder);

        let status = match self.state {
            KerberosState::Negotiate => {
                let (service_name, _service_principal_name) =
                    parse_target_name(builder.target_name.ok_or_else(|| {
                        Error::new(
                            ErrorKind::NoCredentials,
                            "Service target name (service principal name) is not provided",
                        )
                    })?)?;

                let (username, service_name) = match check_if_empty!(
                    builder.credentials_handle.as_ref().unwrap().as_ref(),
                    "AuthIdentity is not provided"
                ) {
                    CredentialsBuffers::AuthIdentity(auth_identity) => {
                        let username = utf16_bytes_to_utf8_string(&auth_identity.user);
                        let domain = utf16_bytes_to_utf8_string(&auth_identity.domain);

                        (format!("{}.{}", username, domain.to_ascii_lowercase()), service_name)
                    }
                    CredentialsBuffers::SmartCard(_) => (_service_principal_name.into(), service_name),
                };
                debug!(username, service_name);

                let encoded_neg_token_init =
                    picky_asn1_der::to_vec(&generate_neg_token_init(&username, service_name)?)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
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
                    SecurityBuffer::find_buffer(builder.input.as_ref().unwrap(), BufferType::ChannelBindings)
                {
                    self.channel_bindings = Some(ChannelBindings::from_bytes(&sec_buffer.buffer)?);
                }

                let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;

                let tgt_ticket = extract_tgt_ticket(&input_token.buffer)?;

                let credentials = builder
                    .credentials_handle
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::WrongCredentialHandle, "No credentials provided"))?;

                let (username, password, realm, cname_type) = match credentials {
                    CredentialsBuffers::AuthIdentity(auth_identity) => {
                        let username = utf16_bytes_to_utf8_string(&auth_identity.user);
                        let domain = utf16_bytes_to_utf8_string(&auth_identity.domain);
                        let password = utf16_bytes_to_utf8_string(auth_identity.password.as_ref());

                        let realm = get_client_principal_realm(&username, &domain);
                        let cname_type = get_client_principal_name_type(&username, &domain);

                        (username, password, realm, cname_type)
                    }
                    CredentialsBuffers::SmartCard(smart_card) => {
                        let username = utf16_bytes_to_utf8_string(&smart_card.username);
                        let password = utf16_bytes_to_utf8_string(smart_card.pin.as_ref());

                        let realm = get_client_principal_realm(&username, "");
                        let cname_type = get_client_principal_name_type(&username, "");

                        (username, password, realm.to_uppercase(), cname_type)
                    }
                };
                self.realm = Some(realm.clone());

                let options = GenerateAsReqOptions {
                    realm: &realm,
                    username: &username,
                    cname_type,
                    snames: &[TGT_SERVICE_NAME, &realm],
                    // 4 = size of u32
                    nonce: &OsRng.gen::<[u8; 4]>(),
                    hostname: &unwrap_hostname(self.config.client_computer_name.as_deref())?,
                    context_requirements: builder.context_requirements,
                };
                let kdc_req_body = generate_as_req_kdc_body(&options)?;

                let pa_data_options =
                    match credentials {
                        CredentialsBuffers::AuthIdentity(auth_identity) => {
                            let domain = utf16_bytes_to_utf8_string(&auth_identity.domain);
                            let salt = format!("{}{}", domain, username);

                            AsReqPaDataOptions::AuthIdentity(GenerateAsPaDataOptions {
                                password: &password,
                                salt: salt.as_bytes().to_vec(),
                                enc_params: self.encryption_params.clone(),
                                with_pre_auth: false,
                            })
                        }
                        CredentialsBuffers::SmartCard(smart_card) => {
                            let private_key_pem =
                                utf16_bytes_to_utf8_string(smart_card.private_key_pem.as_ref().ok_or_else(|| {
                                    Error::new(ErrorKind::InternalError, "scard private key is missing")
                                })?);
                            self.dh_parameters = Some(generate_client_dh_parameters(&mut OsRng)?);

                            AsReqPaDataOptions::SmartCard(Box::new(pk_init::GenerateAsPaDataOptions {
                                p2p_cert: picky_asn1_der::from_bytes(&smart_card.certificate)?,
                                kdc_req_body: &kdc_req_body,
                                dh_parameters: self.dh_parameters.clone().unwrap(),
                                sign_data: Box::new(move |data_to_sign| {
                                    let mut sha1 = Sha1::new();
                                    sha1.update(data_to_sign);
                                    let hash = sha1.finalize().to_vec();
                                    let private_key = PrivateKey::from_pem_str(&private_key_pem)?;
                                    let rsa_private_key = RsaPrivateKey::try_from(&private_key)?;
                                    Ok(rsa_private_key.sign(Pkcs1v15Sign::new::<Sha1>(), &hash)?)
                                }),
                                with_pre_auth: false,
                                authenticator_nonce: OsRng.gen::<[u8; 4]>(),
                            }))
                        }
                    };

                let as_rep = self.as_exchange(yield_point, &kdc_req_body, pa_data_options).await?;

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

                let mut session_key_extractor = match credentials {
                    CredentialsBuffers::AuthIdentity(_) => AsRepSessionKeyExtractor::AuthIdentity {
                        salt: &salt,
                        password: &password,
                        enc_params: &mut self.encryption_params,
                    },
                    CredentialsBuffers::SmartCard(_) => AsRepSessionKeyExtractor::SmartCard {
                        dh_parameters: self.dh_parameters.as_mut().unwrap(),
                        enc_params: &mut self.encryption_params,
                    },
                };
                let session_key_1 = session_key_extractor.session_key(&as_rep)?;

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

                let response = self.send(yield_point, &serialize_message(&tgs_req)?).await?;

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

                // the original flag is
                // GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG
                // we want to be able to turn of sign and seal, so we leave confidentiality and integrity flags out
                let mut flags: GssFlags = builder.context_requirements.into();
                if flags.contains(GssFlags::GSS_C_DELEG_FLAG) {
                    // Below are reasons why we turn off the GSS_C_DELEG_FLAG flag.
                    //
                    // RFC4121: The Kerberos Version 5 GSS-API. Section 4.1.1:  Authenticator Checksum
                    // https://datatracker.ietf.org/doc/html/rfc4121#section-4.1.1.1
                    //
                    // "The length of the checksum field MUST be at least 24 octets when GSS_C_DELEG_FLAG is not set,
                    // and at least 28 octets plus Dlgth octets when GSS_C_DELEG_FLAG is set."
                    // Out implementation _always_ uses the 24 octets checksum and do not support Kerberos credentials delegation.
                    //
                    // "When delegation is used, a ticket-granting ticket will be transferred in a KRB_CRED message."
                    // We do not support KRB_CRED messages. So, the GSS_C_DELEG_FLAG flags should be turned off.
                    warn!("Kerberos ApReq Authenticator checksum GSS_C_DELEG_FLAG is not supported. Turning it off...");
                    flags.remove(GssFlags::GSS_C_DELEG_FLAG);
                }
                info!(?flags, "ApReq Authenticator checksum flags");

                let mut checksum_value = ChecksumValues::default();
                checksum_value.set_flags(flags);

                let authenticator_options = GenerateAuthenticatorOptions {
                    kdc_rep: &tgs_rep.0,
                    seq_num: Some(seq_num),
                    sub_key: Some(EncKey {
                        key_type: enc_type.clone(),
                        key_value: authenticator_sub_key,
                    }),

                    checksum: Some(ChecksumOptions {
                        checksum_type: AUTHENTICATOR_CHECKSUM_TYPE.to_vec(),
                        checksum_value,
                    }),
                    channel_bindings: self.channel_bindings.as_ref(),
                    extensions: Vec::new(),
                };

                let authenticator = generate_authenticator(authenticator_options)?;
                let encoded_auth = picky_asn1_der::to_vec(&authenticator)?;
                info!(encoded_ap_req_authenticator = ?encoded_auth);

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

                let encoded_neg_ap_req = if !builder.context_requirements.contains(ClientRequestFlags::USE_DCE_STYLE) {
                    // Wrap in a NegToken.
                    picky_asn1_der::to_vec(&generate_neg_ap_req(ap_req, mech_id)?)?
                } else {
                    // Do not wrap if the `USE_DCE_STYLE` flag is set.
                    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/190ab8de-dc42-49cf-bf1b-ea5705b7a087
                    picky_asn1_der::to_vec(&ap_req)?
                };

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                output_token.buffer.write_all(&encoded_neg_ap_req)?;

                self.state = KerberosState::ApExchange;

                SecurityStatus::ContinueNeeded
            }
            KerberosState::ApExchange => {
                let input = builder
                    .input
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Input buffers must be specified"))?;
                let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;

                let neg_token_targ = {
                    let mut d = picky_asn1_der::Deserializer::new_from_bytes(&input_token.buffer);
                    let neg_token_targ: NegTokenTarg1 = KrbResult::deserialize(&mut d)??;
                    neg_token_targ
                };

                let ap_rep = extract_ap_rep_from_neg_token_targ(&neg_token_targ)?;

                let session_key = self.encryption_params.session_key.as_ref().unwrap();
                let sub_session_key =
                    extract_sub_session_key_from_ap_rep(&ap_rep, session_key, &self.encryption_params)?;

                self.encryption_params.sub_session_key = Some(sub_session_key);

                if let Some(ref token) = neg_token_targ.0.mech_list_mic.0 {
                    validate_mic_token(&token.0 .0, ACCEPTOR_SIGN, &self.encryption_params)?;
                }

                if builder.context_requirements.contains(ClientRequestFlags::USE_DCE_STYLE) {
                    use picky_krb::messages::ApRep;
                    // use byteorder::{LittleEndian, ReadBytesExt};
                    // use picky_asn1::wrapper::ObjectIdentifierAsn1;

                    debug!("try to parse: {:?}", input_token.buffer);

                    // let mut reader = &input_token.buffer.as_slice()[3..];
                    // let _id: ObjectIdentifierAsn1 = picky_asn1_der::from_reader(&mut reader).unwrap();
                    // let _krb_id = reader.read_u16::<LittleEndian>().unwrap();
                    let ap_rep: ApRep = picky_asn1_der::from_bytes(&input_token.buffer).unwrap();

                    debug!("parsed dce ap rep");

                    let session_key = self.encryption_params.session_key.as_ref().unwrap();
                    let sub_session_key =
                        extract_sub_session_key_from_ap_rep(&ap_rep, session_key, &self.encryption_params)?;
                    let seq_number = extract_seq_number_from_ap_rep(&ap_rep, session_key, &self.encryption_params)?;

                    debug!(?sub_session_key, "DCE AP_REP sub-session key");

                    self.encryption_params.sub_session_key = Some(sub_session_key);

                    let ap_rep = generate_ap_rep(session_key, seq_number, &self.encryption_params)?;

                    let ap_rep = picky_asn1_der::to_vec(&ap_rep)?;

                    let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                    output_token.buffer.write_all(&ap_rep)?;

                    self.state = KerberosState::ApRepDce;

                    SecurityStatus::ContinueNeeded
                } else {
                    self.prepare_final_neg_token(builder)?;
                    self.state = KerberosState::PubKeyAuth;
                    SecurityStatus::Ok
                }
            }
            KerberosState::ApRepDce => {
                self.prepare_final_neg_token(builder)?;
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
}

impl SspiEx for Kerberos {
    #[instrument(level = "trace", ret, fields(state = ?self.state), skip(self))]
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) -> Result<()> {
        self.auth_identity = Some(identity.try_into()?);

        Ok(())
    }
}

#[cfg(any(feature = "__test-data", test))]
pub mod test_data {
    use picky_krb::constants::key_usages::{ACCEPTOR_SEAL, INITIATOR_SEAL};
    use picky_krb::crypto::CipherSuite;

    use super::{EncryptionParams, KerberosConfig, KerberosState};
    use crate::Kerberos;

    const SESSION_KEY: &[u8] = &[
        21, 56, 207, 133, 152, 47, 177, 117, 223, 235, 169, 237, 173, 202, 11, 254, 142, 185, 237, 5, 97, 79, 112, 46,
        73, 182, 117, 0, 35, 91, 24, 66,
    ];
    const SUB_SESSION_KEY: &[u8] = &[
        146, 61, 191, 46, 26, 68, 247, 94, 124, 95, 1, 190, 15, 185, 245, 64, 18, 203, 212, 49, 43, 222, 254, 217, 85,
        222, 7, 92, 254, 153, 105, 144,
    ];

    pub fn fake_client() -> Kerberos {
        Kerberos {
            state: KerberosState::Final,
            config: KerberosConfig {
                kdc_url: None,
                client_computer_name: None,
            },
            auth_identity: None,
            encryption_params: EncryptionParams {
                encryption_type: Some(CipherSuite::Aes256CtsHmacSha196),
                session_key: Some(SESSION_KEY.to_vec()),
                sub_session_key: Some(SUB_SESSION_KEY.to_vec()),
                sspi_encrypt_key_usage: INITIATOR_SEAL,
                sspi_decrypt_key_usage: ACCEPTOR_SEAL,
            },
            seq_number: 1234,
            realm: None,
            kdc_url: None,
            channel_bindings: None,
            dh_parameters: None,
        }
    }

    pub fn fake_server() -> Kerberos {
        Kerberos {
            state: KerberosState::Final,
            config: KerberosConfig {
                kdc_url: None,
                client_computer_name: None,
            },
            auth_identity: None,
            encryption_params: EncryptionParams {
                encryption_type: Some(CipherSuite::Aes256CtsHmacSha196),
                session_key: Some(SESSION_KEY.to_vec()),
                sub_session_key: Some(SUB_SESSION_KEY.to_vec()),
                sspi_encrypt_key_usage: ACCEPTOR_SEAL,
                sspi_decrypt_key_usage: INITIATOR_SEAL,
            },
            seq_number: 0,
            realm: None,
            kdc_url: None,
            channel_bindings: None,
            dh_parameters: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{EncryptionFlags, SecurityBufferFlags, SecurityBufferRef, Sspi};

    use picky_krb::constants::key_usages::{ACCEPTOR_SEAL, INITIATOR_SEAL};
    use picky_krb::crypto::CipherSuite;

    use super::{EncryptionParams, KerberosConfig, KerberosState};
    use crate::Kerberos;

    #[test]
    fn stream_buffer_decryption() {
        // https://learn.microsoft.com/en-us/windows/win32/secauthn/sspi-kerberos-interoperability-with-gssapi

        let mut kerberos_server = super::test_data::fake_server();
        let mut kerberos_client = super::test_data::fake_client();

        let plain_message = b"some plain message";

        let mut token = [0; 1024];
        let mut data = plain_message.to_vec();
        let mut message = [
            SecurityBufferRef::token_buf(token.as_mut_slice()),
            SecurityBufferRef::data_buf(data.as_mut_slice()),
        ];

        kerberos_server
            .encrypt_message(EncryptionFlags::empty(), &mut message, 0)
            .unwrap();

        let mut buffer = message[0].data().to_vec();
        buffer.extend_from_slice(message[1].data());

        let mut message = [
            SecurityBufferRef::stream_buf(&mut buffer),
            SecurityBufferRef::data_buf(&mut []),
        ];

        kerberos_client.decrypt_message(&mut message, 0).unwrap();

        assert_eq!(message[1].data(), plain_message);
    }

    #[test]
    fn secbuffer_readonly_with_checksum() {
        // All values in this test (session keys, sequence number, encrypted and decrypted data) were extracted
        // from the original Windows Kerberos implementation calls.
        // We keep this test to guarantee full compatibility with the original Kerberos.

        let session_key = [
            114, 67, 55, 26, 76, 210, 61, 0, 164, 44, 11, 133, 108, 220, 234, 145, 61, 144, 123, 45, 54, 175, 164, 168,
            99, 18, 99, 240, 242, 157, 95, 134,
        ];
        let sub_session_key = [
            91, 11, 188, 227, 10, 91, 180, 246, 64, 129, 251, 200, 118, 82, 109, 65, 241, 177, 109, 32, 124, 39, 127,
            171, 222, 132, 199, 199, 126, 110, 3, 166,
        ];

        let mut kerberos_server = Kerberos {
            state: KerberosState::Final,
            config: KerberosConfig {
                kdc_url: None,
                client_computer_name: None,
            },
            auth_identity: None,
            encryption_params: EncryptionParams {
                encryption_type: Some(CipherSuite::Aes256CtsHmacSha196),
                session_key: Some(session_key.to_vec()),
                sub_session_key: Some(sub_session_key.to_vec()),
                sspi_encrypt_key_usage: ACCEPTOR_SEAL,
                sspi_decrypt_key_usage: INITIATOR_SEAL,
            },
            seq_number: 681238048,
            realm: None,
            kdc_url: None,
            channel_bindings: None,
            dh_parameters: None,
        };

        // RPC header
        let header = [
            5, 0, 0, 3, 16, 0, 0, 0, 60, 1, 76, 0, 1, 0, 0, 0, 208, 0, 0, 0, 0, 0, 0, 0,
        ];
        // RPC security trailer header
        let trailer = [16, 6, 8, 0, 0, 0, 0, 0];
        // Encrypted data in RPC Request
        let enc_data = [
            41, 85, 192, 239, 104, 188, 180, 100, 229, 73, 83, 199, 77, 83, 79, 17, 163, 206, 241, 29, 90, 28, 89, 203,
            83, 176, 160, 252, 197, 221, 76, 113, 185, 141, 16, 200, 149, 55, 32, 96, 29, 49, 57, 124, 181, 147, 110,
            198, 125, 116, 150, 47, 35, 224, 117, 25, 10, 229, 201, 222, 153, 101, 131, 93, 204, 32, 9, 145, 186, 45,
            224, 160, 131, 23, 236, 111, 88, 48, 54, 4, 118, 114, 129, 119, 130, 164, 178, 4, 110, 74, 37, 1, 215, 177,
            16, 204, 238, 83, 255, 40, 240, 32, 209, 213, 90, 19, 126, 58, 34, 33, 72, 15, 206, 96, 67, 15, 169, 248,
            176, 9, 173, 196, 159, 239, 250, 120, 206, 52, 53, 229, 230, 66, 64, 109, 100, 21, 77, 193, 3, 40, 183,
            209, 177, 152, 165, 171, 108, 151, 112, 134, 53, 165, 128, 145, 147, 167, 5, 72, 35, 101, 42, 183, 67, 101,
            48, 255, 84, 208, 112, 199, 154, 62, 185, 87, 204, 228, 45, 30, 184, 47, 129, 145, 245, 168, 118, 174, 48,
            98, 174, 167, 208, 0, 113, 246, 219, 29, 192, 171, 97, 117, 115, 120, 115, 45, 44, 113, 62, 39,
        ];
        // Unencrypted data in RPC Request
        let plaintext = [
            108, 0, 0, 0, 0, 0, 0, 0, 108, 0, 0, 0, 0, 0, 0, 0, 1, 0, 4, 128, 84, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 20,
            0, 0, 0, 2, 0, 64, 0, 2, 0, 0, 0, 0, 0, 36, 0, 3, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 223, 243,
            137, 88, 86, 131, 83, 53, 105, 218, 109, 33, 80, 4, 0, 0, 0, 0, 20, 0, 2, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1,
            0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 138, 227, 19, 113, 2, 244, 54,
            113, 2, 64, 40, 0, 96, 89, 120, 185, 79, 82, 223, 17, 139, 109, 131, 220, 222, 215, 32, 133, 1, 0, 0, 0,
            51, 5, 113, 113, 186, 190, 55, 73, 131, 25, 181, 219, 239, 156, 204, 54, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0,
        ];
        // RPC Request security trailer data. Basically, it's a GSS API Wrap token
        let security_trailer_data = [
            5, 4, 6, 255, 0, 16, 0, 28, 0, 0, 0, 0, 40, 154, 222, 33, 170, 177, 218, 93, 176, 5, 210, 44, 38, 242, 179,
            168, 249, 202, 242, 199, 63, 162, 33, 40, 106, 186, 187, 28, 11, 229, 207, 219, 66, 86, 243, 16, 158, 100,
            133, 159, 87, 153, 196, 14, 251, 169, 164, 12, 18, 85, 182, 56, 72, 30, 137, 238, 50, 122, 73, 95, 109,
            194, 60, 120,
        ];

        let mut header_data = header.to_vec();
        let mut encrypted_data = enc_data.to_vec();
        let mut trailer_data = trailer.to_vec();
        let mut token_data = security_trailer_data.to_vec();
        let mut message = vec![
            SecurityBuffer::data_buf(&mut header_data)
                .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
            SecurityBuffer::data_buf(&mut encrypted_data),
            SecurityBuffer::data_buf(&mut trailer_data)
                .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
            SecurityBuffer::token_buf(&mut token_data),
        ];

        kerberos_server.decrypt_message(&mut message, 0).unwrap();

        assert_eq!(header[..], message[0].data()[..]);
        assert_eq!(plaintext[..], message[1].data()[..]);
        assert_eq!(trailer[..], message[2].data()[..]);
    }

    #[test]
    fn rpc_request_decryption() {
        let mut kerberos_server = super::test_data::fake_server();
        let mut kerberos_client = super::test_data::fake_client();

        let plain_message_data = b"some plain message";
        let mut plain_message = plain_message_data.to_vec();

        let first_buff_data = b"test";
        let mut first_buff = first_buff_data.to_vec();
        let third_buff_data = b"msg";
        let mut third_buff = third_buff_data.to_vec();
        let mut token = [0; 1024];

        let mut message = [
            SecurityBufferRef::token_buf(&mut token),
            SecurityBufferRef::data_buf(&mut first_buff)
                .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
            SecurityBufferRef::data_buf(&mut plain_message),
            SecurityBufferRef::data_buf(&mut third_buff)
                .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
        ];

        kerberos_server
            .encrypt_message(EncryptionFlags::empty(), &mut message, 0)
            .unwrap();

        assert!(!message[0].data().is_empty());
        assert_eq!(message[1].data(), first_buff_data);
        assert!(!message[2].data().is_empty());
        assert_eq!(message[3].data(), third_buff_data);

        kerberos_client.decrypt_message(&mut message, 0).unwrap();

        assert_eq!(message[2].data(), plain_message_data);
    }
}
