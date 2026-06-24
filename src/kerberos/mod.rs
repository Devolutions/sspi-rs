pub mod client;
pub mod config;
mod encryption_params;
pub mod flags;
mod messages;
mod pa_datas;
pub mod server;
#[cfg(test)]
mod tests;
pub(crate) mod utils;

use std::collections::HashMap;
use std::sync::LazyLock;

use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{ExplicitContextTag0, ExplicitContextTag1, OctetStringAsn1, Optional};
use picky_krb::crypto::aes::{AesSize, checksum_sha_aes};
use picky_krb::crypto::{CipherSuite, DecryptWithoutChecksum, EncryptWithoutChecksum};
use picky_krb::data_types::KerberosStringAsn1;
use picky_krb::gss_api::WrapToken;
use picky_krb::messages::{IAKerbCookie, KdcProxyMessage};
use rand::rngs::{StdRng, SysRng};
use rand_core::{Rng as _, SeedableRng as _};
use time::{Duration, OffsetDateTime};
use url::Url;

pub use self::client::initialize_security_context;
use self::config::{KdcResolution, KerberosConfig};
pub use self::encryption_params::EncryptionParams;
pub use self::server::{ServerProperties, accept_security_context};
use super::channel_bindings::ChannelBindings;
use crate::builders::ChangePassword;
use crate::generator::{
    GeneratorAcceptSecurityContext, GeneratorChangePassword, GeneratorInitSecurityContext, NetworkRequest,
    YieldPointLocal,
};
use crate::kerberos::client::KerberosClientState;
use crate::kerberos::server::KerberosServerState;
use crate::network_client::NetworkProtocol;
#[cfg(feature = "scard")]
use crate::pk_init::DhParameters;
/// Compatibility re-export; prefer the package-neutral [`crate::rcg`] module.
#[doc(no_inline)]
pub use crate::rcg as remote_guard;
use crate::utils::{extract_encrypted_data, get_encryption_key, save_decrypted_data};
use crate::{
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity, BufferType, ContextNames, ContextSizes,
    CredentialUse, Credentials, CredentialsBuffers, DecryptionFlags, Error, ErrorKind, PACKAGE_ID_NONE,
    PackageCapabilities, PackageInfo, Result, SecurityBuffer, SecurityBufferFlags, SecurityBufferRef,
    SecurityPackageType, SecurityStatus, SessionKeys, Sspi, SspiEx, SspiImpl, detect_kdc_url, detect_kdc_urls, rcg,
};

pub const PKG_NAME: &str = "Kerberos";
pub const KERBEROS_VERSION: u8 = 0x05;
pub const TGT_SERVICE_NAME: &str = "krbtgt";
pub const KADMIN: &str = "kadmin";
pub const CHANGE_PASSWORD_SERVICE_NAME: &str = "changepw";

// pub const SSPI_KDC_URL_ENV: &str = "SSPI_KDC_URL";
pub const DEFAULT_ENCRYPTION_TYPE: CipherSuite = CipherSuite::Aes256CtsHmacSha196;

/// [3.4.5.4.1 Kerberos Binding of GSS_WrapEx()](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e94b3acd-8415-4d0d-9786-749d0c39d550)
/// The RRC field is 12 if no encryption is requested or 28 if encryption is requested
pub const RRC: u16 = 28;
// wrap token header len
pub const MAX_SIGNATURE: u8 = 16;
/// Required `TOKEN` buffer length during data encryption (`encrypt_message` method call).
///
/// **Note**: Actual security trailer len is `SECURITY_TRAILER` + `EC`. The `EC` field is negotiated
// during the authentication process.
pub const SECURITY_TRAILER: u8 = 60;

/// [3.4.5.4.1 Kerberos Binding of GSS_WrapEx()](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e94b3acd-8415-4d0d-9786-749d0c39d550)
///
/// The extra count (EC) must not be zero. The sender should set extra count (EC) to 1 block - 16 bytes.
pub(crate) const EC: u16 = 16;

pub static PACKAGE_INFO: LazyLock<PackageInfo> = LazyLock::new(|| PackageInfo {
    capabilities: PackageCapabilities::empty(),
    rpc_id: PACKAGE_ID_NONE,
    max_token_len: 0xbb80, // 48 000 bytes: default maximum token len in Windows
    name: SecurityPackageType::Kerberos,
    comment: String::from("Kerberos Security Package"),
});

#[derive(Debug, Default, Clone, PartialEq)]
pub enum KerberosState {
    Client(Box<KerberosClientState>),
    Server(KerberosServerState),
    Final,
    #[default]
    Failed,
}

#[derive(Debug, Clone)]
pub struct Kerberos {
    pub(crate) state: KerberosState,
    pub(crate) config: KerberosConfig,
    pub(crate) auth_identity: Option<CredentialsBuffers>,
    pub(crate) encryption_params: EncryptionParams,
    pub(crate) seq_number: u32,
    pub(crate) realm: Option<String>,
    pub(crate) channel_bindings: Option<ChannelBindings>,
    #[cfg(feature = "scard")]
    pub(crate) dh_parameters: Option<DhParameters>,
    pub(crate) krb5_user_to_user: bool,
    pub(crate) server: Option<Box<ServerProperties>>,
    pub(crate) remote_seq_number: u32,
    /// KDC time minus local time, learned from a clock-skew error during AS pre-authentication.
    pub(crate) clock_offset: Duration,
    /// Opaque data, if sent by the server, must be copied verbatim into the next [`IAKerbProxyMessage`](picky_krb::gss_api::IAKerbProxyMessage).
    pub(crate) iakerb_cookie: IAKerbCookie,
    /// Transcript of the `IAKerb` `GSS-API` tokens exchanged between the client and the server.
    pub(crate) iakerb_gss_transcript: Vec<u8>,
    /// Remote Credential Guard state. `None` unless Remote Credential Guard was explicitly enabled.
    pub(crate) remote_guard: Option<Box<rcg::RemoteGuardState>>,
    /// KDC that last answered for a realm, keyed by the upper-cased realm name.
    ///
    /// Reused for the following messages of the same authentication and re-resolved only when it stops answering.
    pub(crate) kdc_cache: HashMap<String, Url>,
}

impl Kerberos {
    pub fn new_client_from_config(config: KerberosConfig) -> Result<Self> {
        let mut rand = StdRng::try_from_rng(&mut SysRng)?;

        Ok(Self {
            state: KerberosState::Client(Box::default()),
            config,
            auth_identity: None,
            encryption_params: EncryptionParams::default_for_client(),
            seq_number: rand.next_u32(),
            realm: None,
            channel_bindings: None,
            #[cfg(feature = "scard")]
            dh_parameters: None,
            krb5_user_to_user: false,
            server: None,
            remote_seq_number: 0,
            clock_offset: Duration::ZERO,
            iakerb_cookie: None,
            iakerb_gss_transcript: Vec::new(),
            remote_guard: None,
            kdc_cache: HashMap::new(),
        })
    }

    pub fn new_server_from_config(config: KerberosConfig, server_properties: ServerProperties) -> Result<Self> {
        let mut rand = StdRng::try_from_rng(&mut SysRng)?;

        Ok(Self {
            state: KerberosState::Server(KerberosServerState::TgtExchange),
            config,
            auth_identity: None,
            encryption_params: EncryptionParams::default_for_server(),
            seq_number: rand.next_u32(),
            realm: None,
            channel_bindings: None,
            #[cfg(feature = "scard")]
            dh_parameters: None,
            krb5_user_to_user: false,
            server: Some(Box::new(server_properties)),
            remote_seq_number: 0,
            clock_offset: Duration::ZERO,
            iakerb_cookie: None,
            iakerb_gss_transcript: Vec::new(),
            remote_guard: None,
            kdc_cache: HashMap::new(),
        })
    }

    pub fn is_client(&self) -> bool {
        self.server.is_none()
    }

    pub fn is_iakerb(&self) -> bool {
        matches!(self.config.kdc_resolution, KdcResolution::IAKerb)
    }

    pub(crate) fn current_kdc_time(&self) -> Result<OffsetDateTime> {
        OffsetDateTime::now_utc()
            .checked_add(self.clock_offset)
            .ok_or_else(|| Error::new(ErrorKind::TimeSkew, "KDC clock offset is out of range"))
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
        match &self.config.kdc_resolution {
            KdcResolution::IAKerb => None,
            KdcResolution::KdcUrl(kdc_url) => {
                let realm = self.realm.to_owned()?;
                if let Some(kdc_url) = kdc_url {
                    Some((realm, kdc_url.to_owned()))
                } else {
                    let kdc_url = detect_kdc_url(&realm)?;
                    Some((realm, kdc_url))
                }
            }
        }
    }

    async fn send(&mut self, yield_point: &mut YieldPointLocal, data: &[u8]) -> Result<Vec<u8>> {
        let realm = self
            .realm
            .clone()
            .ok_or_else(|| Error::new(ErrorKind::NoAuthenticatingAuthority, "no KDC server found"))?;
        self.send_for_realm(yield_point, &realm, data).await
    }

    /// Sends a Kerberos message to the KDC responsible for `realm`, failing over across candidates.
    ///
    /// See [`send_for_realm_with`](Self::send_for_realm_with); candidates come from [`detect_kdc_urls`].
    pub(crate) async fn send_for_realm(
        &mut self,
        yield_point: &mut YieldPointLocal,
        realm: &str,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        self.send_for_realm_with(yield_point, realm, data, detect_kdc_urls)
            .await
    }

    /// Sends a Kerberos message to the KDC responsible for `realm`, resolving candidates with `detect`.
    ///
    /// The KDC that last answered for `realm` is reused across the messages of an authentication and is
    /// re-resolved only if it stops answering.
    /// When resolving, the candidates [`select_kdc_urls`] returns are tried in order.
    /// Failover advances on any error from [`send_to`](Self::send_to), which is mostly a transport failure
    /// (could not connect, no reply) but also covers errors such as an unsupported URL scheme.
    /// Any reply from a KDC, including a KRB-ERROR, is a valid answer and is returned as-is.
    async fn send_for_realm_with(
        &mut self,
        yield_point: &mut YieldPointLocal,
        realm: &str,
        data: &[u8],
        detect: impl FnOnce(&str) -> Vec<Url>,
    ) -> Result<Vec<u8>> {
        let mut last_error = None;
        let mut already_tried = None;
        // Realms are case-insensitive, so normalize the cache key to avoid duplicate entries.
        let cache_key = realm.to_ascii_uppercase();

        // Prefer the KDC that last answered for this realm (stickiness across messages).
        if let Some(pinned) = self.kdc_cache.get(&cache_key).cloned() {
            match self.send_to(yield_point, realm, pinned.clone(), data).await {
                Ok(response) => return Ok(response),
                Err(error) => {
                    warn!(kdc = %pinned, %error, realm, "Pinned KDC failed; re-resolving candidates");
                    self.kdc_cache.remove(&cache_key);
                    already_tried = Some(pinned);
                    last_error = Some(error);
                }
            }
        }

        let kdc_urls = select_kdc_urls(realm, self.realm.as_deref(), &self.config.kdc_resolution, detect);
        if kdc_urls.is_empty() {
            return Err(last_error.unwrap_or_else(|| {
                Error::new(
                    ErrorKind::NoAuthenticatingAuthority,
                    format!("no KDC server found for realm `{realm}`"),
                )
            }));
        }

        let candidate_count = kdc_urls.len();
        for (index, kdc_url) in kdc_urls.into_iter().enumerate() {
            // Don't immediately retry the pinned KDC we just failed over from.
            if already_tried.as_ref() == Some(&kdc_url) {
                continue;
            }
            match self.send_to(yield_point, realm, kdc_url.clone(), data).await {
                Ok(response) => {
                    self.kdc_cache.insert(cache_key, kdc_url);
                    return Ok(response);
                }
                Err(error) => {
                    warn!(
                        kdc = %kdc_url,
                        %error,
                        candidate = index + 1,
                        candidate_count,
                        realm,
                        "KDC request failed; trying next candidate if available"
                    );
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            Error::new(
                ErrorKind::NoAuthenticatingAuthority,
                format!("no KDC server reachable for realm `{realm}`"),
            )
        }))
    }

    async fn send_to(
        &self,
        yield_point: &mut YieldPointLocal,
        realm: &str,
        kdc_url: Url,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let protocol = NetworkProtocol::from_url_scheme(kdc_url.scheme()).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidParameter,
                format!("Invalid protocol `{}` for KDC server", kdc_url.scheme()),
            )
        })?;

        match protocol {
            NetworkProtocol::Tcp => {
                let request = NetworkRequest {
                    protocol,
                    url: kdc_url,
                    data: data.to_vec(),
                };
                yield_point.suspend(request).await
            }
            NetworkProtocol::Udp => {
                // First 4 bytes are message length and it’s not included when using UDP
                let Some(data) = data.get(4..) else {
                    return Err(Error::new(
                        ErrorKind::InternalError,
                        format!(
                            "kerberos message has invalid length. expected >= 4 but got {}",
                            data.len()
                        ),
                    ));
                };

                let request = NetworkRequest {
                    protocol,
                    url: kdc_url,
                    data: data.to_vec(),
                };
                yield_point.suspend(request).await
            }
            NetworkProtocol::Http | NetworkProtocol::Https => {
                let data = OctetStringAsn1::from(data.to_vec());
                let domain = KerberosStringAsn1::from(IA5String::from_string(realm.to_owned())?);

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
                Ok(message_response.kerb_message.0.0)
            }
        }
    }
}

impl Sspi for Kerberos {
    #[instrument(level = "debug", ret, fields(state = ?self.state), skip_all)]
    fn complete_auth_token(&mut self, _token: &mut [SecurityBuffer]) -> Result<SecurityStatus> {
        Ok(SecurityStatus::Ok)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, _flags))]
    fn encrypt_message(
        &mut self,
        _flags: crate::EncryptionFlags,
        message: &mut [SecurityBufferRef<'_>],
    ) -> Result<SecurityStatus> {
        if self.state != KerberosState::Final {
            return Err(Error::new(
                ErrorKind::OutOfSequence,
                format!("Kerberos context is not established: current state: {:?}", self.state),
            ));
        }

        if let Some(remote_guard) = self.remote_guard.as_deref_mut() {
            return remote_guard.encrypt_message(message);
        }

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

        let mut wrap_token = WrapToken::with_seq_number(seq_number.into());
        if self.server.is_some() {
            // [Flags Field](https://datatracker.ietf.org/doc/html/rfc4121#section-4.2.2):
            //
            // The meanings of bits in this field (the least significant bit is bit 0) are as follows:
            //   Bit    Name             Description
            //  --------------------------------------------------------------
            //   0   SentByAcceptor   When set, this flag indicates the sender
            //                        is the context acceptor.  When not set,
            //                        it indicates the sender is the context
            //                        initiator.
            // When the Kerberos is used as the Kerberos server we have to set the `SentByAcceptor` flag.
            wrap_token.flags |= 0x01;
        }
        wrap_token.ec = self.encryption_params.ec;

        let mut payload = data_to_encrypt.fold(Vec::new(), |mut acc, buffer| {
            acc.extend_from_slice(buffer.data());
            acc
        });
        // Add filler bytes to payload vector.
        // More info:
        // * [4.2.3.  EC Field](https://datatracker.ietf.org/doc/html/rfc4121#section-4.2.3):
        //   In Wrap tokens with confidentiality, the EC field SHALL be used to encode the number of octets in the filler.
        // * [4.2.4.  Encryption and Checksum Operations](https://datatracker.ietf.org/doc/html/rfc4121#section-4.2.4):
        //   payload = plaintext-data | filler | "header"
        payload.extend_from_slice(&vec![0; usize::from(self.encryption_params.ec)]);
        payload.extend_from_slice(&wrap_token.header());

        let EncryptWithoutChecksum {
            mut encrypted,
            confounder,
            ki: _,
        } = cipher.encrypt_no_checksum(key.as_ref(), key_usage, &payload)?;

        // Find `Data` buffers (including `Data` buffers with the `READONLY_WITH_CHECKSUM` flag).
        let mut data_to_sign =
            SecurityBufferRef::buffers_of_type(message, BufferType::Data).fold(confounder, |mut acc, buffer| {
                acc.extend_from_slice(buffer.data());
                acc
            });
        // Add filler bytes to payload vector.
        // More info:
        // * [4.2.3.  EC Field](https://datatracker.ietf.org/doc/html/rfc4121#section-4.2.3):
        //   In Wrap tokens with confidentiality, the EC field SHALL be used to encode the number of octets in the filler.
        // * [4.2.4.  Encryption and Checksum Operations](https://datatracker.ietf.org/doc/html/rfc4121#section-4.2.4):
        //   payload = plaintext-data | filler | "header"
        data_to_sign.extend_from_slice(&vec![0; usize::from(self.encryption_params.ec)]);
        data_to_sign.extend_from_slice(&wrap_token.header());

        let checksum = cipher.encryption_checksum(key.as_ref(), key_usage, &data_to_sign)?;

        encrypted.extend_from_slice(&checksum);

        // [3.4.5.4.1 Kerberos Binding of GSS_WrapEx()](learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e94b3acd-8415-4d0d-9786-749d0c39d550):
        // The trailing metadata H1 is rotated by RRC+EC bytes, which is different from RRC alone.
        encrypted.rotate_right(usize::from(RRC + self.encryption_params.ec));

        wrap_token.set_rrc(RRC);
        wrap_token.set_checksum(encrypted);

        let mut raw_wrap_token = Vec::with_capacity(wrap_token.checksum.len() + WrapToken::header_len());
        wrap_token.encode(&mut raw_wrap_token)?;

        let security_trailer_len = self.query_context_sizes()?.security_trailer.try_into()?;

        let (token, data) = if raw_wrap_token.len() < security_trailer_len {
            let empty_data: &[u8] = &[];
            (raw_wrap_token.as_slice(), empty_data)
        } else {
            raw_wrap_token.split_at(security_trailer_len)
        };

        let data_buffer =
            SecurityBufferRef::buffers_of_type_and_flags_mut(message, BufferType::Data, SecurityBufferFlags::NONE)
                .next()
                .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "no buffer was provided with type Data"))?;

        data_buffer.write_data(data)?;

        let token_buffer = SecurityBufferRef::find_buffer_mut(message, BufferType::Token)?;
        token_buffer.write_data(token)?;

        Ok(SecurityStatus::Ok)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn decrypt_message(&mut self, message: &mut [SecurityBufferRef<'_>]) -> Result<DecryptionFlags> {
        if self.state != KerberosState::Final {
            return Err(Error::new(
                ErrorKind::OutOfSequence,
                format!("Kerberos context is not established: current state: {:?}", self.state),
            ));
        }

        if let Some(remote_guard) = self.remote_guard.as_deref_mut() {
            return remote_guard.decrypt_message(message);
        }

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
        // [Flags Field](https://datatracker.ietf.org/doc/html/rfc4121#section-4.2.2):
        //
        // The meanings of bits in this field (the least significant bit is bit 0) are as follows:
        //   Bit    Name             Description
        //  --------------------------------------------------------------
        //   0   SentByAcceptor   When set, this flag indicates the sender
        //                        is the context acceptor.  When not set,
        //                        it indicates the sender is the context
        //                        initiator.
        let is_server = u8::from(self.server.is_some());
        // If the Kerberos acts as the Kerberos application server, then the `SentByAcceptor` flag
        // of the incoming WRAP token must be disabled (because it is sent by initiator).
        if wrap_token.flags & 0x01 == is_server {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                "invalid WRAP token SentByAcceptor flag",
            ));
        }
        //        1   Sealed           When set in Wrap tokens, this flag
        //                             indicates confidentiality is provided
        //                             for.  It SHALL NOT be set in MIC tokens.
        //
        // When the Sealed flag is clear, this is an integrity-only Wrap token
        // (GSS_Wrap with conf_req_flag == FALSE, RFC 4121 §4.2.4): the data is
        // carried in cleartext followed by the checksum, rather than encrypted.
        // Stock SASL/GSSAPI clients (e.g. Java/Kafka) use conf=false for the
        // RFC 4752 security-layer negotiation reply, so the acceptor must
        // accept it instead of demanding confidentiality.
        if wrap_token.flags & 0b10 != 0b10 {
            // The integrity-only checksum is the AES-SHA1 keyed HMAC
            // (`checksum_sha_aes`), which is only defined for the AES cipher
            // suites. Reject non-AES contexts (e.g. `Des3CbcSha1Kd`) explicitly
            // rather than silently treating them as AES-256, which would produce
            // incorrect checksum validation.
            let aes_size = self.encryption_params.aes_size().ok_or_else(|| {
                Error::new(
                    ErrorKind::UnsupportedFunction,
                    "integrity-only WRAP tokens are only supported for AES cipher suites",
                )
            })?;
            return decrypt_integrity_only_wrap(&wrap_token, key.as_ref(), &aes_size, key_usage, message);
        }

        let mut checksum = wrap_token.checksum;
        // [3.4.5.4.1 Kerberos Binding of GSS_WrapEx()](learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e94b3acd-8415-4d0d-9786-749d0c39d550):
        // The trailing metadata H1 is rotated by RRC+EC bytes, which is different from RRC alone.
        checksum.rotate_left((RRC + wrap_token.ec).into());

        let DecryptWithoutChecksum {
            plaintext: decrypted,
            confounder,
            checksum,
            ki: _,
        } = cipher.decrypt_no_checksum(key.as_ref(), key_usage, &checksum)?;

        if decrypted.len() < usize::from(wrap_token.ec) + WrapToken::header_len() {
            return Err(Error::new(ErrorKind::DecryptFailure, "decrypted data is too short"));
        }

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
                    acc.extend_from_slice(plaintext);
                }
                acc
            });
        data_to_sign.extend_from_slice(wrap_token_header);

        let calculated_checksum = cipher.encryption_checksum(key.as_ref(), key_usage, &data_to_sign)?;

        if calculated_checksum != checksum {
            return Err(picky_krb::crypto::KerberosCryptoError::IntegrityCheck.into());
        }

        save_decrypted_data(plaintext, message)?;

        Ok(DecryptionFlags::empty())
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_sizes(&mut self) -> Result<ContextSizes> {
        // We prevent users from calling `query_context_sizes` on a non-established security context
        // because it can lead to invalid values being returned.
        if self.state != KerberosState::Final {
            return Err(Error::new(
                ErrorKind::OutOfSequence,
                format!("Kerberos context is not established: current state: {:?}", self.state),
            ));
        }

        let security_trailer = if self.remote_guard.is_some() {
            u32::from(SECURITY_TRAILER)
        } else {
            u32::from(SECURITY_TRAILER) + u32::from(self.encryption_params.ec)
        };

        Ok(ContextSizes {
            max_token: PACKAGE_INFO.max_token_len,
            max_signature: MAX_SIGNATURE.into(),
            block: 0,
            security_trailer,
        })
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_names(&mut self) -> Result<ContextNames> {
        if let Some(client) = self.server.as_ref().and_then(|server| server.client.as_ref()) {
            return Ok(ContextNames {
                username: client.clone(),
            });
        }

        if let Some(CredentialsBuffers::AuthIdentity(identity_buffers)) = &self.auth_identity {
            let identity =
                AuthIdentity::try_from(identity_buffers).map_err(|e| Error::new(ErrorKind::InvalidParameter, e))?;

            return Ok(ContextNames {
                username: identity.username,
            });
        }

        #[cfg(feature = "scard")]
        if let Some(CredentialsBuffers::SmartCard(ref identity_buffers)) = self.auth_identity {
            let username = identity_buffers.username.to_string();
            let username = crate::Username::parse(&username).map_err(|e| Error::new(ErrorKind::InvalidParameter, e))?;
            return Ok(ContextNames { username });
        }

        Err(Error::new(
            ErrorKind::NoCredentials,
            "requested names, but no credentials were provided",
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
            "certificate trust status is not supported".to_owned(),
        ))
    }

    #[instrument(level = "debug", fields(state = ?self.state), skip(self))]
    fn query_context_session_key(&self) -> Result<SessionKeys> {
        if self.remote_guard.is_some() {
            return Err(Error::new(
                ErrorKind::UnsupportedFunction,
                "the session key of a remote credential guard context cannot be exported",
            ));
        }

        Ok(SessionKeys {
            session_key: get_encryption_key(&self.encryption_params)?.clone(),
        })
    }

    fn change_password<'a>(&'a mut self, change_password: ChangePassword<'a>) -> Result<GeneratorChangePassword<'a>> {
        Ok(GeneratorChangePassword::new(move |mut yield_point| async move {
            client::change_password(self, &mut yield_point, change_password).await
        }))
    }

    fn make_signature(
        &mut self,
        _flags: u32,
        _message: &mut [SecurityBufferRef<'_>],
        _sequence_number: u32,
    ) -> Result<()> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "make_signature is not supported. use encrypt_message to sign messages instead",
        ))
    }

    fn verify_signature(&mut self, _message: &mut [SecurityBufferRef<'_>], _sequence_number: u32) -> Result<u32> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "verify_signature is not supported. use decrypt_message to verify signatures instead",
        ))
    }
}

/// Verifies an integrity-only (GSS_Wrap conf_req_flag == FALSE) Wrap token and
/// returns its cleartext payload in the message buffers.
///
/// Per RFC 4121 §4.2.4, an unsealed Wrap token carries the data in the clear
/// followed by the checksum: `{header | plaintext | checksum}`, right-rotated
/// by RRC. The checksum is computed over `plaintext | header`, where the EC and
/// RRC fields of the 16-octet header are zeroed for the computation. Wrap tokens
/// — sealed or not — use the SEAL key usage (the SIGN usage is reserved for MIC
/// tokens), so `key_usage` is the same value the sealed path uses. The checksum
/// itself is the keyed get_mic checksum (Kc-derived), not the Ki-derived
/// encryption integrity hash used for the confidential path.
fn decrypt_integrity_only_wrap(
    wrap_token: &WrapToken,
    key: &[u8],
    aes_size: &AesSize,
    key_usage: i32,
    message: &mut [SecurityBufferRef<'_>],
) -> Result<DecryptionFlags> {
    // `WrapToken::decode` stores everything after the 16-octet header in
    // `checksum`; for an unsealed token that is `plaintext | trailing-checksum`.
    let mut data = wrap_token.checksum.clone();
    if data.is_empty() {
        return Err(Error::new(ErrorKind::DecryptFailure, "empty integrity-only WRAP token"));
    }

    // Undo the sender's right rotation. For integrity-only tokens the rotation
    // is by RRC alone (the EC octets are checksum, not filler).
    let rotate = usize::from(wrap_token.rrc) % data.len();
    data.rotate_left(rotate);

    let ec = usize::from(wrap_token.ec);
    if data.len() < ec {
        return Err(Error::new(
            ErrorKind::DecryptFailure,
            "integrity-only WRAP token shorter than its checksum",
        ));
    }
    let plaintext_len = data.len() - ec;
    let (plaintext, received_checksum) = data.split_at(plaintext_len);

    // Checksum input: plaintext followed by the 16-octet header with the EC and
    // RRC fields zeroed (RFC 4121 §4.2.4).
    let mut header = wrap_token.header();
    header[4..8].copy_from_slice(&[0, 0, 0, 0]);

    let mut to_sign = plaintext.to_vec();
    to_sign.extend_from_slice(&header);

    let calculated = checksum_sha_aes(key, key_usage, &to_sign, aes_size)?;

    if calculated.as_slice() != received_checksum {
        return Err(picky_krb::crypto::KerberosCryptoError::IntegrityCheck.into());
    }

    save_decrypted_data(plaintext, message)?;

    Ok(DecryptionFlags::empty())
}

impl SspiImpl for Kerberos {
    type CredentialsHandle = Option<CredentialsBuffers>;

    type AuthenticationData = Credentials;

    #[instrument(level = "trace", ret, fields(state = ?self.state), skip(self))]
    fn acquire_credentials_handle_impl(
        &mut self,
        builder: crate::builders::FilledAcquireCredentialsHandle<'_, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        if builder.credential_use == CredentialUse::Outbound && builder.auth_data.is_none() {
            return Err(Error::new(
                ErrorKind::NoCredentials,
                "the client must specify the auth data",
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
    fn accept_security_context_impl<'a>(
        &'a mut self,
        builder: crate::builders::FilledAcceptSecurityContext<'a, Self::CredentialsHandle>,
    ) -> Result<GeneratorAcceptSecurityContext<'a>> {
        Ok(GeneratorAcceptSecurityContext::new(move |mut yield_point| async move {
            self.accept_security_context_impl(&mut yield_point, builder).await
        }))
    }

    fn initialize_security_context_impl<'ctx, 'b, 'g>(
        &'ctx mut self,
        builder: &'b mut crate::builders::FilledInitializeSecurityContext<'ctx, 'ctx, Self::CredentialsHandle>,
    ) -> Result<GeneratorInitSecurityContext<'g>>
    where
        'ctx: 'b,
        'b: 'g,
    {
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
        client::change_password(self, yield_point, change_password).await
    }

    pub(crate) async fn accept_security_context_impl(
        &mut self,
        yield_point: &mut YieldPointLocal,
        builder: crate::builders::FilledAcceptSecurityContext<'a, <Self as SspiImpl>::CredentialsHandle>,
    ) -> Result<AcceptSecurityContextResult> {
        accept_security_context(self, yield_point, builder).await
    }

    pub(crate) async fn initialize_security_context_impl(
        &'a mut self,
        yield_point: &mut YieldPointLocal,
        builder: &'a mut crate::builders::FilledInitializeSecurityContext<
            '_,
            '_,
            <Self as SspiImpl>::CredentialsHandle,
        >,
    ) -> Result<crate::InitializeSecurityContextResult> {
        initialize_security_context(self, yield_point, builder).await
    }
}

impl SspiEx for Kerberos {
    #[instrument(level = "trace", ret, fields(state = ?self.state), skip(self))]
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) -> Result<()> {
        self.auth_identity = Some(identity.try_into()?);

        Ok(())
    }

    fn verify_mic_token(&mut self, token: &[u8], data: &[u8], _: crate::private::Sealed) -> Result<()> {
        if let Some(remote_guard) = self.remote_guard.as_deref_mut() {
            return remote_guard.verify_mic(token, data).map_err(|mut error| {
                error.description = format!("SPNEGO mechListMIC verification failed: {}", error.description);
                error
            });
        }

        // The sequence number verification is only enforced for the acceptor side.
        // RFC 1964 §1.2.1 / RFC 4121 make sequence-number checking optional and tied to
        // the `SEQUENCE_DETECT`/`REPLAY_DETECT` flags negotiated at context establishment.
        // This client does not negotiate those flags.
        // Additionally, Windows acceptor signs the SPNEGO mechListMIC with sequence number 0
        // regardless of the AP-REP sequence number, so enforcing this on the initiator side
        // breaks interop with the Windows implementation.
        let enforce_sequence_number = !self.is_client();

        utils::validate_mic_token(
            self.is_client(),
            enforce_sequence_number,
            self.remote_seq_number.into(),
            token,
            &self.encryption_params,
            data,
        )
    }

    fn generate_mic_token(&mut self, data: &[u8], _: crate::private::Sealed) -> Result<Vec<u8>> {
        if let Some(remote_guard) = self.remote_guard.as_deref_mut() {
            return remote_guard.generate_mic(data);
        }

        // Do not increment sequence number for MIC token if security context is not established.
        // We do not want to mess up the sequence number.
        let seq_number = if self.encryption_params.sub_session_key.is_some() {
            self.next_seq_number()
        } else {
            0
        };
        let session_key = self
            .encryption_params
            .sub_session_key
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::InternalError, "kerberos sub-session key is not set"))?;
        let aes_size = self
            .encryption_params
            .active_key_aes_size()
            .or_else(|| self.encryption_params.aes_size())
            .unwrap_or(AesSize::Aes256);
        utils::generate_mic_token(
            self.is_client(),
            u64::from(seq_number),
            data.to_vec(),
            session_key,
            &aes_size,
        )
    }
}

/// Chooses the ordered candidate KDC URLs for `target_realm`.
///
/// For the client's home realm, the resolution strategy decides: a configured KDC URL (e.g. a KDC proxy) is the
/// sole candidate, an unset one falls back to `detect`, and IAKerb yields no candidate because the KDC is reached
/// through the application server instead.
/// Any other realm is a cross-realm referral hop and is always resolved via `detect`, which honors
/// `SSPI_KDC_URL_<REALM>`, krb5.conf and DNS SRV records.
/// `detect` is injected so the routing decision can be unit-tested without a live resolver.
fn select_kdc_urls(
    target_realm: &str,
    home_realm: Option<&str>,
    kdc_resolution: &KdcResolution,
    detect: impl FnOnce(&str) -> Vec<Url>,
) -> Vec<Url> {
    if home_realm.is_some_and(|home| home.eq_ignore_ascii_case(target_realm)) {
        match kdc_resolution {
            KdcResolution::KdcUrl(Some(kdc_url)) => return vec![kdc_url.clone()],
            KdcResolution::KdcUrl(None) => {}
            KdcResolution::IAKerb => return Vec::new(),
        }
    }
    detect(target_realm)
}

#[cfg(any(feature = "__test-data", test))]
pub mod test_data {
    use std::collections::HashMap;
    use std::time::Duration;

    use picky_asn1::restricted_string::IA5String;
    use picky_asn1::wrapper::{Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, IntegerAsn1};
    use picky_krb::constants::key_usages::{ACCEPTOR_SEAL, INITIATOR_SEAL};
    use picky_krb::constants::types::NT_SRV_INST;
    use picky_krb::crypto::CipherSuite;
    use picky_krb::data_types::{KerberosStringAsn1, PrincipalName};
    use picky_krb::gss_api::MechTypeList;

    use super::{EncryptionParams, KerberosConfig, KerberosState};
    use crate::kerberos::ServerProperties;
    use crate::kerberos::config::KdcResolution;
    use crate::{AuthIdentityBuffers, CredentialsBuffers, Kerberos, Secret, Utf16String, ZeroizedUtf16String};

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
                kdc_resolution: KdcResolution::KdcUrl(None),
                client_computer_name: "hostname".into(),
            },
            auth_identity: Some(CredentialsBuffers::AuthIdentity(AuthIdentityBuffers {
                user: Utf16String::from_str("fake_user"),
                domain: Utf16String::from_str("FAKE_DOMAIN"),
                password: Secret::new(ZeroizedUtf16String(Utf16String::from_str("fake_password"))),
            })),
            encryption_params: EncryptionParams {
                encryption_type: Some(CipherSuite::Aes256CtsHmacSha196),
                session_key: Some(SESSION_KEY.to_vec().into()),
                sub_session_key: Some(SUB_SESSION_KEY.to_vec().into()),
                sspi_encrypt_key_usage: INITIATOR_SEAL,
                sspi_decrypt_key_usage: ACCEPTOR_SEAL,
                ec: 0,
            },
            seq_number: 1234,
            realm: None,
            channel_bindings: None,
            #[cfg(feature = "scard")]
            dh_parameters: None,
            krb5_user_to_user: false,
            server: None,
            remote_seq_number: 0,
            clock_offset: time::Duration::ZERO,
            iakerb_cookie: None,
            iakerb_gss_transcript: Vec::new(),
            remote_guard: None,
            kdc_cache: HashMap::new(),
        }
    }

    pub fn fake_server_properties() -> ServerProperties {
        ServerProperties {
            mech_types: MechTypeList::from(Vec::new()),
            max_time_skew: Duration::from_secs(3 * 60),
            ticket_decryption_key: None,
            service_name: PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string("TERMSRV".to_owned()).unwrap()),
                    KerberosStringAsn1::from(IA5String::from_string("VM1.example.com".to_owned()).unwrap()),
                ])),
            },
            additional_service_keys: Vec::new(),
            user: None,
            client: None,
            authenticators_cache: Default::default(),
        }
    }

    pub fn fake_server() -> Kerberos {
        Kerberos {
            state: KerberosState::Final,
            config: KerberosConfig {
                kdc_resolution: KdcResolution::KdcUrl(None),
                client_computer_name: "hostname".into(),
            },
            auth_identity: None,
            encryption_params: EncryptionParams {
                encryption_type: Some(CipherSuite::Aes256CtsHmacSha196),
                session_key: Some(SESSION_KEY.to_vec().into()),
                sub_session_key: Some(SUB_SESSION_KEY.to_vec().into()),
                sspi_encrypt_key_usage: ACCEPTOR_SEAL,
                sspi_decrypt_key_usage: INITIATOR_SEAL,
                ec: 0,
            },
            seq_number: 0,
            realm: None,
            channel_bindings: None,
            #[cfg(feature = "scard")]
            dh_parameters: None,
            krb5_user_to_user: false,
            server: Some(Box::new(fake_server_properties())),
            remote_seq_number: 0,
            clock_offset: time::Duration::ZERO,
            iakerb_cookie: None,
            iakerb_gss_transcript: Vec::new(),
            remote_guard: None,
            kdc_cache: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod select_kdc_urls_tests {
    use url::Url;

    use super::select_kdc_urls;
    use crate::KdcResolution;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn home_realm_with_configured_kdc_uses_only_the_configured_url() {
        let configured = url("tcp://home-dc.rjm.local:88");
        let resolution = KdcResolution::KdcUrl(Some(configured.clone()));
        let result = select_kdc_urls("RJM.LOCAL", Some("RJM.LOCAL"), &resolution, |_| {
            panic!("detection must not run for the configured home realm")
        });
        assert_eq!(result, vec![configured]);
    }

    #[test]
    fn home_realm_match_is_case_insensitive() {
        let configured = url("tcp://home-dc.rjm.local:88");
        let resolution = KdcResolution::KdcUrl(Some(configured.clone()));
        let result = select_kdc_urls("rjm.local", Some("RJM.LOCAL"), &resolution, |_| {
            panic!("a case-only difference is still the home realm; detection must not run")
        });
        assert_eq!(result, vec![configured]);
    }

    #[test]
    fn referral_realm_ignores_configured_kdc_and_uses_detection() {
        let configured = url("tcp://home-dc.rjm.local:88");
        let detected = url("tcp://child-dc.dev.rjm.local:88");
        let resolution = KdcResolution::KdcUrl(Some(configured));
        let result = select_kdc_urls("DEV.RJM.LOCAL", Some("RJM.LOCAL"), &resolution, |realm| {
            assert_eq!(realm, "DEV.RJM.LOCAL");
            vec![detected.clone()]
        });
        assert_eq!(result, vec![detected]);
    }

    #[test]
    fn home_realm_without_configured_kdc_falls_back_to_detection() {
        // Detection may yield several KDCs; their order is preserved for failover.
        let detected = vec![url("tcp://dc1.rjm.local:88"), url("tcp://dc2.rjm.local:88")];
        let result = select_kdc_urls("RJM.LOCAL", Some("RJM.LOCAL"), &KdcResolution::KdcUrl(None), |_| {
            detected.clone()
        });
        assert_eq!(result, detected);
    }

    #[test]
    fn iakerb_home_realm_has_no_kdc_candidate() {
        let result = select_kdc_urls("RJM.LOCAL", Some("RJM.LOCAL"), &KdcResolution::IAKerb, |_| {
            panic!("IAKerb reaches the KDC through the application server; detection must not run")
        });
        assert!(result.is_empty());
    }
}

#[cfg(test)]
mod kdc_failover_tests {
    use url::Url;

    use super::Kerberos;
    use super::test_data::fake_client;
    use crate::generator::{Generator, GeneratorState, NetworkRequest};
    use crate::{Error, ErrorKind};

    const REALM: &str = "EXAMPLE.COM";
    const DC1: &str = "tcp://dc1.example.com:88";
    const DC2: &str = "tcp://dc2.example.com:88";
    // Any length-prefixed message will do: the fake network never parses it.
    const REQUEST: &[u8] = &[0, 0, 0, 2, 0x30, 0x00];

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    /// Fake KDC network: unreachable KDCs fail with an error naming them, the others reply with their own URL.
    #[derive(Default)]
    struct FakeNetwork {
        unreachable: Vec<Url>,
        requests: Vec<Url>,
    }

    impl FakeNetwork {
        fn unreachable(kdcs: &[&str]) -> Self {
            Self {
                unreachable: kdcs.iter().map(|kdc| url(kdc)).collect(),
                requests: Vec::new(),
            }
        }

        fn respond(&mut self, request: &NetworkRequest) -> crate::Result<Vec<u8>> {
            self.requests.push(request.url.clone());
            if self.unreachable.contains(&request.url) {
                Err(Error::new(
                    ErrorKind::NoAuthenticatingAuthority,
                    format!("{} is unreachable", request.url),
                ))
            } else {
                Ok(request.url.as_str().as_bytes().to_vec())
            }
        }

        fn requests(&self) -> Vec<&str> {
            self.requests.iter().map(Url::as_str).collect()
        }
    }

    /// Drives one `send_for_realm_with` call to completion against `network`, resolving to `candidates`.
    fn send(kerberos: &mut Kerberos, network: &mut FakeNetwork, candidates: &[&str]) -> crate::Result<Vec<u8>> {
        let candidates: Vec<Url> = candidates.iter().map(|kdc| url(kdc)).collect();
        let mut generator: Generator<'_, NetworkRequest, crate::Result<Vec<u8>>, crate::Result<Vec<u8>>> =
            Generator::new(move |mut yield_point| async move {
                kerberos
                    .send_for_realm_with(&mut yield_point, REALM, REQUEST, move |_| candidates)
                    .await
            });

        let mut state = generator.start();
        loop {
            match state {
                GeneratorState::Suspended(request) => state = generator.resume(network.respond(&request)),
                GeneratorState::Completed(result) => return result,
            }
        }
    }

    fn pinned(kerberos: &Kerberos) -> Option<&str> {
        kerberos.kdc_cache.get(REALM).map(Url::as_str)
    }

    // oracle: mutant failover stops at the first candidate that answers
    #[test]
    fn first_answering_candidate_is_pinned_and_the_rest_are_not_tried() {
        let mut kerberos = fake_client();
        let mut network = FakeNetwork::default();

        let response = send(&mut kerberos, &mut network, &[DC1, DC2]).unwrap();

        assert_eq!(response, DC1.as_bytes());
        assert_eq!(network.requests(), [DC1]);
        assert_eq!(pinned(&kerberos), Some(DC1));
    }

    // oracle: mutant failover skips an unreachable candidate and pins the one that answers
    #[test]
    fn unreachable_candidate_fails_over_to_the_next_which_is_pinned() {
        let mut kerberos = fake_client();
        let mut network = FakeNetwork::unreachable(&[DC1]);

        let response = send(&mut kerberos, &mut network, &[DC1, DC2]).unwrap();

        assert_eq!(response, DC2.as_bytes());
        assert_eq!(network.requests(), [DC1, DC2]);
        assert_eq!(pinned(&kerberos), Some(DC2));
    }

    // oracle: mutant a pinned KDC is reused ahead of the candidate list
    #[test]
    fn pinned_kdc_is_reused_for_the_next_message() {
        let mut kerberos = fake_client();
        kerberos.kdc_cache.insert(REALM.to_owned(), url(DC2));
        let mut network = FakeNetwork::default();

        let response = send(&mut kerberos, &mut network, &[DC1, DC2]).unwrap();

        assert_eq!(response, DC2.as_bytes());
        assert_eq!(network.requests(), [DC2]);
        assert_eq!(pinned(&kerberos), Some(DC2));
    }

    // oracle: mutant a failed pinned KDC is dropped, not retried, and the next answering candidate is pinned
    #[test]
    fn failed_pinned_kdc_is_replaced_without_being_retried() {
        let mut kerberos = fake_client();
        kerberos.kdc_cache.insert(REALM.to_owned(), url(DC2));
        let mut network = FakeNetwork::unreachable(&[DC2]);

        let response = send(&mut kerberos, &mut network, &[DC1, DC2]).unwrap();

        assert_eq!(response, DC1.as_bytes());
        assert_eq!(network.requests(), [DC2, DC1]);
        assert_eq!(pinned(&kerberos), Some(DC1));
    }

    // oracle: mutant the last candidate's error is reported and nothing stays pinned
    #[test]
    fn all_candidates_unreachable_reports_the_last_error_and_unpins() {
        let mut kerberos = fake_client();
        kerberos.kdc_cache.insert(REALM.to_owned(), url(DC1));
        let mut network = FakeNetwork::unreachable(&[DC1, DC2]);

        let error = send(&mut kerberos, &mut network, &[DC1, DC2]).unwrap_err();

        assert_eq!(error.description, format!("{DC2} is unreachable"));
        assert_eq!(network.requests(), [DC1, DC2]);
        assert_eq!(pinned(&kerberos), None);
    }

    // oracle: mutant no candidate means no authenticating authority, without touching the network
    #[test]
    fn no_candidate_is_no_authenticating_authority() {
        let mut kerberos = fake_client();
        let mut network = FakeNetwork::default();

        let error = send(&mut kerberos, &mut network, &[]).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::NoAuthenticatingAuthority);
        assert!(network.requests().is_empty());
    }
}
