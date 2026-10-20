//! RDPEAR Kerberos operations performed with the keys owned by a [`RemoteGuardSession`].
//!
//! MS-RDPEAR [3.1.5 Message Processing Events and Sequencing Rules] lets the
//! server ask the client to perform Kerberos operations that need the user's keys. Reusable TGT keys
//! remain in the session and are represented by opaque handles. Ordinary service-ticket session keys
//! are returned in the decrypted KDC reply, as described in [4.1 Requesting a Service Ticket] and observed
//! in the native Windows provider. They must only be delivered over this connection's protected RDPEAR
//! channel. This is not an API for exporting TGT keys or the CredSSP protection key.
//!
//! Every operation is restricted to the RFC 4120 key usages it is meant for, and each key is restricted to
//! its role (ticket-granting or service session key). Operation failures do not affect message protection.
//! A poisoned session rejects every operation with [`ErrorKind::ContextExpired`] before processing input.
//!
//! [3.1.5 Message Processing Events and Sequencing Rules]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/
//! [4.1 Requesting a Service Ticket]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/

use std::fmt;

use picky_asn1::date::GeneralizedTime;
use picky_asn1::wrapper::{
    ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3, ExplicitContextTag4,
    ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag8, IntegerAsn1, OctetStringAsn1,
    Optional,
};
use picky_krb::constants::key_usages::{
    AP_REP_ENC, AP_REQ_AUTHENTICATOR, TGS_REP_ENC_SESSION_KEY, TGS_REP_ENC_SUB_KEY, TGS_REQ_AUTH_DATA_SESSION_KEY,
    TGS_REQ_AUTH_DATA_SUB_KEY, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR_CKSUM,
};
use picky_krb::constants::types::AP_REP_MSG_TYPE;
use picky_krb::crypto::CipherSuite;
use picky_krb::crypto::aes::checksum_sha_aes;
use picky_krb::data_types::{
    Authenticator, AuthenticatorInner, AuthorizationData, Checksum, EncApRepPart, EncryptedData, EncryptionKey,
    KerberosTime,
};
use picky_krb::messages::{ApRep, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, KdcReqBody};
use time::{Duration, OffsetDateTime};
use zeroize::{Zeroize as _, Zeroizing};

use super::key_store::KeyRole;
use super::session::RemoteGuardSession;
use super::{FILETIME_UNIX_EPOCH_OFFSET_SECONDS, aes_cipher_suite, etype_of, integer_to_i32, wrap};
use crate::crypto::compute_md5;
use crate::kerberos::{KERBEROS_VERSION, TGT_SERVICE_NAME};
use crate::{Error, ErrorKind, Result, Secret};

/// Upper bound on any ASN.1 input of an operation.
pub const MAX_OPERATION_INPUT_LEN: usize = 64 * 1024;

/// Largest accepted `SkewTime` magnitude (one day, in 100-nanosecond units).
const MAX_SKEW_TIME: i64 = 864_000_000_000;

/// Number of server-supplied authenticator subkeys remembered by a session.
const MAX_SERVER_SUBKEYS: usize = 64;

/// Unkeyed RSA-MD5 checksum type ([RFC 3961]).
///
/// [RFC 3961]: https://www.rfc-editor.org/rfc/rfc3961#section-6.1.1
const RSA_MD5: i32 = 7;

/// HMAC-SHA1-96-AES128 checksum type ([RFC 3962]).
///
/// [RFC 3962]: https://www.rfc-editor.org/rfc/rfc3962
const HMAC_SHA1_96_AES128: i32 = 15;
/// HMAC-SHA1-96-AES256 checksum type ([RFC 3962]).
///
/// [RFC 3962]: https://www.rfc-editor.org/rfc/rfc3962
const HMAC_SHA1_96_AES256: i32 = 16;

/// Reference to a key in a `KERB_RPC_ENCRYPTION_KEY` structure
/// (MS-RDPEAR [2.2.1.2.8 KERB_RPC_ENCRYPTION_KEY]).
///
/// `encryption_type` is `reserved2` and `value` is the content of `reserved3`. For keys owned by the session,
/// `value` is an opaque handle issued by the session. For an ordinary service-ticket key returned by
/// [`RemoteGuardSession::unpack_kdc_reply_body`], the returned key bytes may also reference that retained
/// service key. Arbitrary raw keys are not accepted as session-key references, and TGT keys always
/// require opaque handles. Operation-specific raw server subkeys are described on their request fields.
///
/// [2.2.1.2.8 KERB_RPC_ENCRYPTION_KEY]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/
#[derive(Clone, Copy)]
pub struct KeyReference<'a> {
    pub encryption_type: i32,
    pub value: &'a [u8],
}

impl fmt::Debug for KeyReference<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyReference")
            .field("encryption_type", &self.encryption_type)
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// `ComputeTgsChecksum` request (MS-RDPEAR [2.2.2.1.7 ComputeTgsChecksum]).
///
/// [2.2.2.1.7 ComputeTgsChecksum]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/
#[derive(Debug, Clone, Copy)]
pub struct ComputeTgsChecksumRequest<'a> {
    /// DER-encoded `KDC-REQ-BODY`.
    pub request_body: &'a [u8],
    /// Session key of a ticket-granting ticket owned by the session.
    pub key: KeyReference<'a>,
    /// 7 (unkeyed RSA-MD5), 15 (AES128), or 16 (AES256). Keyed types must match the key's encryption type.
    pub checksum_type: i32,
}

/// `BuildEncryptedAuthData` request (MS-RDPEAR [2.2.2.1.8 BuildEncryptedAuthData]).
///
/// [2.2.2.1.8 BuildEncryptedAuthData]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/
#[derive(Debug, Clone, Copy)]
pub struct BuildEncryptedAuthDataRequest<'a> {
    /// 4 (TGS-REQ authorization data, session key) or 5 (TGS-REQ authorization data, subkey).
    pub key_usage: u32,
    /// For key usage 4, the session key of a ticket-granting ticket owned by the session. For key usage 5,
    /// a subkey previously supplied by the server to [`RemoteGuardSession::create_ap_req_authenticator`].
    pub key: KeyReference<'a>,
    /// DER-encoded `AuthorizationData`.
    pub plain_auth_data: &'a [u8],
}

/// `CreateApReqAuthenticator` request (MS-RDPEAR [2.2.2.1.4 CreateApReqAuthenticator]).
///
/// [2.2.2.1.4 CreateApReqAuthenticator]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/
#[derive(Debug, Clone, Copy)]
pub struct CreateApReqAuthenticatorRequest<'a> {
    /// For key usage 7, the session key of a ticket-granting ticket owned by the session. For key usage 11,
    /// a service ticket session key owned by the session.
    pub encryption_key: KeyReference<'a>,
    pub sequence_number: u32,
    /// Components of the client name. They must match the authenticated client (ASCII case-insensitive).
    pub client_name: &'a [String],
    /// Must match the authenticated client realm (ASCII case-insensitive).
    pub client_realm: &'a str,
    /// Signed adjustment to the client's UTC clock in 100-nanosecond units, bounded to one day.
    /// This is the adjustment supplied by the caller; the initial KDC clock offset is not added again.
    pub skew_time: i64,
    /// Raw AES authenticator subkey chosen by the server, not an opaque session handle. It is
    /// remembered for key usages 5 and 9. Unsupported for TGS authenticators (key usage 7): a peer-known
    /// subkey would let the peer decrypt a subsequent TGT reply without the client's key isolation.
    pub sub_key: Option<KeyReference<'a>>,
    /// DER-encoded `AuthorizationData`.
    pub auth_data: Option<&'a [u8]>,
    /// DER-encoded `Checksum`.
    pub gss_checksum: Option<&'a [u8]>,
    /// 7 (TGS-REQ PA-TGS-REQ authenticator) or 11 (AP-REQ authenticator).
    pub key_usage: u32,
}

/// `CreateApReqAuthenticator` result.
pub struct ApReqAuthenticator {
    /// Authenticator time as a FILETIME (100-nanosecond intervals since 1601-01-01 UTC).
    pub authenticator_time: i64,
    /// DER-encoded `EncryptedData` containing the authenticator.
    pub authenticator: Vec<u8>,
}

impl fmt::Debug for ApReqAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApReqAuthenticator")
            .field("authenticator_time", &self.authenticator_time)
            .field("authenticator_len", &self.authenticator.len())
            .finish()
    }
}

/// `UnpackKdcReplyBody` request (MS-RDPEAR [2.2.2.1.6 UnpackKdcReplyBody]).
///
/// [2.2.2.1.6 UnpackKdcReplyBody]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/
#[derive(Debug, Clone, Copy)]
pub struct UnpackKdcReplyBodyRequest<'a> {
    /// DER-encoded `EncryptedData` of a TGS-REP.
    pub encrypted_data: &'a [u8],
    /// For key usage 8, the session key of a ticket-granting ticket owned by the session. For key usage 9,
    /// a subkey previously supplied by the server.
    pub key: KeyReference<'a>,
    /// FAST strengthen key. Not supported: must be `None`.
    pub strengthen_key: Option<KeyReference<'a>>,
    /// 8 (TGS-REP, session key) or 9 (TGS-REP, subkey). AS-REP (3) is not supported.
    pub key_usage: u32,
}

/// `DecryptApReply` request (MS-RDPEAR [2.2.2.1.5 DecryptApReply]).
///
/// [2.2.2.1.5 DecryptApReply]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/
#[derive(Debug, Clone, Copy)]
pub struct DecryptApReplyRequest<'a> {
    /// DER-encoded `EncryptedData` of an AP-REP.
    pub encrypted_reply: &'a [u8],
    /// A service ticket session key owned by the session.
    pub key: KeyReference<'a>,
}

/// `PackApReply` request (MS-RDPEAR [2.2.2.1.9 PackApReply]).
///
/// `reply_body` is encrypted with `session_key` (key usage 12) and placed in the `enc-part` of the `reply`
/// template, as described in MS-RDPEAR [3.1.5.9 RemoteCallKerbPackApReply]. The template must be a canonical
/// DER-encoded `KRB_AP_REP` with `pvno` 5 and `msg-type` 15; the contents of its `enc-part` are replaced.
///
/// [2.2.2.1.9 PackApReply]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/
/// [3.1.5.9 RemoteCallKerbPackApReply]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/
#[derive(Debug, Clone, Copy)]
pub struct PackApReplyRequest<'a> {
    /// DER-encoded `KRB_AP_REP` template.
    pub reply: &'a [u8],
    /// DER-encoded `EncAPRepPart`.
    pub reply_body: &'a [u8],
    /// A service ticket session key owned by the session.
    pub session_key: KeyReference<'a>,
}

struct ServerSubkey {
    cipher_suite: CipherSuite,
    key: Secret<Vec<u8>>,
}

/// Authenticator subkeys supplied by the server, bounded and evicted oldest first.
#[derive(Default)]
pub(crate) struct ServerSubkeys {
    entries: Vec<ServerSubkey>,
}

impl ServerSubkeys {
    fn remember(&mut self, cipher_suite: CipherSuite, key: &[u8]) {
        if self.find(&cipher_suite, key).is_some() {
            return;
        }

        if self.entries.len() >= MAX_SERVER_SUBKEYS {
            self.entries.remove(0);
        }

        self.entries.push(ServerSubkey {
            cipher_suite,
            key: Secret::new(key.to_vec()),
        });
    }

    fn find(&self, cipher_suite: &CipherSuite, key: &[u8]) -> Option<&ServerSubkey> {
        let mut found = None;
        for entry in &self.entries {
            if wrap::constant_time_eq(entry.key.as_ref(), key) && found.is_none() {
                found = Some(entry);
            }
        }

        found.filter(|entry| entry.cipher_suite == *cipher_suite)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}

fn check_input_len(input: &[u8]) -> Result<()> {
    if input.is_empty() || input.len() > MAX_OPERATION_INPUT_LEN {
        return Err(Error::new(
            ErrorKind::InvalidParameter,
            "remote credential guard operation input has an invalid length",
        ));
    }

    Ok(())
}

fn decode<T: serde::de::DeserializeOwned>(input: &[u8], what: &str) -> Result<T> {
    check_input_len(input)?;

    picky_asn1_der::from_bytes(input).map_err(|_| Error::new(ErrorKind::InvalidToken, format!("invalid {what}")))
}

fn encrypted_data(cipher_suite: &CipherSuite, cipher: Vec<u8>) -> EncryptedData {
    EncryptedData {
        etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![u8::from(cipher_suite)])),
        kvno: Optional::from(None),
        cipher: ExplicitContextTag2::from(OctetStringAsn1::from(cipher)),
    }
}

fn filetime(time: OffsetDateTime, microseconds: u32) -> Result<i64> {
    time.unix_timestamp()
        .checked_add(FILETIME_UNIX_EPOCH_OFFSET_SECONDS)
        .and_then(|seconds| seconds.checked_mul(10_000_000))
        .and_then(|ticks| ticks.checked_add(i64::from(microseconds) * 10))
        .ok_or_else(|| Error::new(ErrorKind::TimeSkew, "authenticator time is out of range"))
}

/// Resolved key of an operation.
struct OperationKey {
    cipher_suite: CipherSuite,
    key: Secret<Vec<u8>>,
}

impl RemoteGuardSession {
    fn owned_key(&self, reference: KeyReference<'_>, role: KeyRole) -> Result<OperationKey> {
        let stored = self.key_store.get(reference.encryption_type, reference.value, role)?;

        Ok(OperationKey {
            cipher_suite: stored.cipher_suite.clone(),
            key: stored.key.clone(),
        })
    }

    fn server_subkey(&self, reference: KeyReference<'_>) -> Result<OperationKey> {
        let cipher_suite = aes_cipher_suite(reference.encryption_type)?;
        let entry = self
            .server_subkeys
            .find(&cipher_suite, reference.value)
            .ok_or_else(|| Error::new(ErrorKind::NoKerbKey, "unknown remote credential guard subkey"))?;

        Ok(OperationKey {
            cipher_suite: entry.cipher_suite.clone(),
            key: entry.key.clone(),
        })
    }

    fn decrypt_encrypted_data(&self, input: &[u8], key: &OperationKey, usage: i32) -> Result<Zeroizing<Vec<u8>>> {
        let encrypted: EncryptedData = decode(input, "encrypted data")?;

        if integer_to_i32(&encrypted.etype.0)? != etype_of(&key.cipher_suite) {
            return Err(Error::new(
                ErrorKind::AlgorithmMismatch,
                "encrypted data does not use the encryption type of the key",
            ));
        }

        let plaintext = key
            .cipher_suite
            .cipher()
            .decrypt(key.key.as_ref(), usage, &encrypted.cipher.0.0)
            .map_err(|_| {
                Error::new(
                    ErrorKind::DecryptFailure,
                    "failed to decrypt remote credential guard data",
                )
            })?;

        Ok(Zeroizing::new(plaintext))
    }

    fn encrypt_to_der(&self, key: &OperationKey, usage: i32, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = key.cipher_suite.cipher().encrypt(key.key.as_ref(), usage, plaintext)?;

        Ok(picky_asn1_der::to_vec(&encrypted_data(&key.cipher_suite, cipher))?)
    }

    /// Computes the PA-TGS-REQ authenticator checksum of a `KDC-REQ-BODY`.
    ///
    /// Supports the AES keyed checksum matching the TGT key (key usage 6), or explicitly requested
    /// unkeyed RSA-MD5 (type 7), as used by Windows. The TGT key reference is validated in either case;
    /// RSA-MD5 does not use the key or replace the authenticator's AES encryption.
    ///
    /// Returns a DER-encoded `Checksum`.
    pub fn compute_tgs_checksum(&mut self, request: ComputeTgsChecksumRequest<'_>) -> Result<Vec<u8>> {
        self.check_usable()?;

        let _: KdcReqBody = decode(request.request_body, "KDC-REQ-BODY")?;

        let key = self.owned_key(request.key, KeyRole::TicketGranting)?;
        let expected_checksum_type = match key.cipher_suite {
            CipherSuite::Aes128CtsHmacSha196 => HMAC_SHA1_96_AES128,
            _ => HMAC_SHA1_96_AES256,
        };
        if request.checksum_type != RSA_MD5 && request.checksum_type != expected_checksum_type {
            return Err(Error::new(
                ErrorKind::AlgorithmMismatch,
                "checksum type does not match the encryption type of the key",
            ));
        }

        let checksum = if request.checksum_type == RSA_MD5 {
            compute_md5(request.request_body).to_vec()
        } else {
            let aes_size = wrap::aes_size(&key.cipher_suite)?;
            checksum_sha_aes(
                key.key.as_ref(),
                TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR_CKSUM,
                request.request_body,
                &aes_size,
            )?
        };

        Ok(picky_asn1_der::to_vec(&Checksum {
            cksumtype: ExplicitContextTag0::from(IntegerAsn1::from(vec![
                u8::try_from(request.checksum_type)
                    .map_err(|_| Error::new(ErrorKind::InternalError, "checksum type"))?,
            ])),
            checksum: ExplicitContextTag1::from(OctetStringAsn1::from(checksum)),
        })?)
    }

    /// Encrypts TGS-REQ authorization data (key usage 4 or 5).
    ///
    /// Returns a DER-encoded `EncryptedData`.
    pub fn build_encrypted_auth_data(&mut self, request: BuildEncryptedAuthDataRequest<'_>) -> Result<Vec<u8>> {
        self.check_usable()?;

        let _: AuthorizationData = decode(request.plain_auth_data, "authorization data")?;

        let (key, usage) = match i32::try_from(request.key_usage) {
            Ok(TGS_REQ_AUTH_DATA_SESSION_KEY) => (
                self.owned_key(request.key, KeyRole::TicketGranting)?,
                TGS_REQ_AUTH_DATA_SESSION_KEY,
            ),
            Ok(TGS_REQ_AUTH_DATA_SUB_KEY) => (self.server_subkey(request.key)?, TGS_REQ_AUTH_DATA_SUB_KEY),
            _ => {
                return Err(Error::new(
                    ErrorKind::UnsupportedFunction,
                    "unsupported key usage for encrypted authorization data",
                ));
            }
        };

        self.encrypt_to_der(&key, usage, request.plain_auth_data)
    }

    /// Creates an encrypted authenticator for a TGS-REQ (key usage 7) or an AP-REQ (key usage 11).
    pub fn create_ap_req_authenticator(
        &mut self,
        request: CreateApReqAuthenticatorRequest<'_>,
    ) -> Result<ApReqAuthenticator> {
        self.check_usable()?;

        let (key, usage) = match i32::try_from(request.key_usage) {
            Ok(TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR) => (
                self.owned_key(request.encryption_key, KeyRole::TicketGranting)?,
                TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
            ),
            Ok(AP_REQ_AUTHENTICATOR) => (
                self.owned_key(request.encryption_key, KeyRole::Service)?,
                AP_REQ_AUTHENTICATOR,
            ),
            _ => {
                return Err(Error::new(
                    ErrorKind::UnsupportedFunction,
                    "unsupported key usage for an authenticator",
                ));
            }
        };

        self.check_client_identity(request.client_name, request.client_realm)?;

        if !(-MAX_SKEW_TIME..=MAX_SKEW_TIME).contains(&request.skew_time) {
            return Err(Error::new(
                ErrorKind::TimeSkew,
                "authenticator skew time is out of range",
            ));
        }

        if usage == TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR && request.sub_key.is_some() {
            return Err(Error::new(
                ErrorKind::UnsupportedFunction,
                "server-supplied subkeys are not supported for TGS authenticators",
            ));
        }

        let sub_key = request
            .sub_key
            .map(|sub_key| -> Result<(CipherSuite, &[u8])> {
                let cipher_suite = aes_cipher_suite(sub_key.encryption_type)?;
                if sub_key.value.len() != cipher_suite.cipher().key_size() {
                    return Err(Error::new(
                        ErrorKind::InvalidParameter,
                        "subkey length does not match its encryption type",
                    ));
                }
                if self.key_store.contains_handle(sub_key.value) {
                    return Err(Error::new(
                        ErrorKind::InvalidParameter,
                        "a session key handle cannot be used as an authenticator subkey",
                    ));
                }

                Ok((cipher_suite, sub_key.value))
            })
            .transpose()?;

        let authorization_data = request
            .auth_data
            .map(|auth_data| decode::<AuthorizationData>(auth_data, "authorization data"))
            .transpose()?;
        let cksum = request
            .gss_checksum
            .map(|checksum| decode::<Checksum>(checksum, "checksum"))
            .transpose()?;

        let now = OffsetDateTime::now_utc()
            .checked_add(Duration::nanoseconds_i128(i128::from(request.skew_time) * 100))
            .ok_or_else(|| Error::new(ErrorKind::TimeSkew, "authenticator skew time is out of range"))?;
        let now = now
            .replace_nanosecond(now.microsecond() * 1_000)
            .map_err(|_| Error::new(ErrorKind::InternalError, "invalid authenticator time"))?;
        let microseconds = now.microsecond();

        let authenticator = Authenticator::from(AuthenticatorInner {
            authenticator_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
            crealm: ExplicitContextTag1::from(self.binding.realm_asn1()?),
            cname: ExplicitContextTag2::from(self.binding.name.clone()),
            cksum: Optional::from(cksum.map(ExplicitContextTag3::from)),
            cusec: ExplicitContextTag4::from(IntegerAsn1::from_bytes_be_unsigned(microseconds.to_be_bytes().to_vec())),
            ctime: ExplicitContextTag5::from(KerberosTime::from(GeneralizedTime::from(now))),
            subkey: Optional::from(sub_key.as_ref().map(|(cipher_suite, value)| {
                ExplicitContextTag6::from(EncryptionKey {
                    key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![u8::from(cipher_suite)])),
                    key_value: ExplicitContextTag1::from(OctetStringAsn1::from(value.to_vec())),
                })
            })),
            seq_number: Optional::from((request.sequence_number != 0).then(|| {
                ExplicitContextTag7::from(IntegerAsn1::from_bytes_be_unsigned(
                    request.sequence_number.to_be_bytes().to_vec(),
                ))
            })),
            authorization_data: Optional::from(authorization_data.map(ExplicitContextTag8::from)),
        });

        let encoded = Zeroizing::new(picky_asn1_der::to_vec(&authenticator)?);
        let authenticator = self.encrypt_to_der(&key, usage, &encoded)?;

        if let Some((cipher_suite, value)) = sub_key {
            self.server_subkeys.remember(cipher_suite, value);
        }

        Ok(ApReqAuthenticator {
            authenticator_time: filetime(now, microseconds)?,
            authenticator,
        })
    }

    /// Decrypts the encrypted part of a TGS-REP (key usage 8 or 9).
    ///
    /// TGT and referral-TGT keys are retained and replaced by opaque handles in the returned DER-encoded
    /// `EncTGSRepPart` (or `EncASRepPart`, if the KDC used that tag). Ordinary service-ticket session keys
    /// are retained and returned unchanged so that the remote host can authenticate to that service.
    ///
    /// The returned DER can contain a service key: send it only in an authenticated, encrypted RDPEAR
    /// response for this connection and erase the plaintext after use. No reusable TGT or CredSSP
    /// protection key is released.
    pub fn unpack_kdc_reply_body(&mut self, request: UnpackKdcReplyBodyRequest<'_>) -> Result<Vec<u8>> {
        self.check_usable()?;

        if request.strengthen_key.is_some() {
            return Err(Error::new(
                ErrorKind::UnsupportedFunction,
                "FAST strengthen keys are not supported by remote credential guard",
            ));
        }

        let (key, usage) = match i32::try_from(request.key_usage) {
            Ok(TGS_REP_ENC_SESSION_KEY) => (
                self.owned_key(request.key, KeyRole::TicketGranting)?,
                TGS_REP_ENC_SESSION_KEY,
            ),
            Ok(TGS_REP_ENC_SUB_KEY) => (self.server_subkey(request.key)?, TGS_REP_ENC_SUB_KEY),
            _ => {
                return Err(Error::new(
                    ErrorKind::UnsupportedFunction,
                    "unsupported key usage for a KDC reply",
                ));
            }
        };

        let plaintext = self.decrypt_encrypted_data(request.encrypted_data, &key, usage)?;

        let (mut reply, as_rep_tag) = match picky_asn1_der::from_bytes::<EncTgsRepPart>(&plaintext) {
            Ok(reply) => (reply.0, false),
            Err(_) => match picky_asn1_der::from_bytes::<EncAsRepPart>(&plaintext) {
                Ok(reply) => (reply.0, true),
                Err(_) => return Err(Error::new(ErrorKind::InvalidToken, "invalid KDC reply body")),
            },
        };

        let reference = self.store_reply_key(&mut reply)?;
        reply.key.0.key_value = ExplicitContextTag1::from(OctetStringAsn1::from(reference));

        let encoded = if as_rep_tag {
            let mut reply = EncAsRepPart::from(reply);
            let encoded = picky_asn1_der::to_vec(&reply);
            reply.0.key.0.key_value.0.0.zeroize();
            encoded
        } else {
            let mut reply = EncTgsRepPart::from(reply);
            let encoded = picky_asn1_der::to_vec(&reply);
            reply.0.key.0.key_value.0.0.zeroize();
            encoded
        };

        Ok(encoded?)
    }

    fn store_reply_key(&mut self, reply: &mut EncKdcRepPart) -> Result<Vec<u8>> {
        let key = Secret::new(std::mem::take(&mut reply.key.0.key_value.0.0));
        let cipher_suite = aes_cipher_suite(integer_to_i32(&reply.key.0.key_type.0)?)?;

        let role = match reply.sname.0.name_string.0.0.first() {
            Some(service) if service.0.as_bytes().eq_ignore_ascii_case(TGT_SERVICE_NAME.as_bytes()) => {
                KeyRole::TicketGranting
            }
            _ => KeyRole::Service,
        };

        let encryption_type = etype_of(&cipher_suite);
        let handle = self.key_store.insert(cipher_suite, key, role, &mut self.rng)?;

        if role == KeyRole::TicketGranting {
            Ok(handle)
        } else {
            Ok(self.key_store.get(encryption_type, &handle, role)?.key.as_ref().clone())
        }
    }

    /// Decrypts the encrypted part of an AP-REP (key usage 12).
    ///
    /// Returns a DER-encoded `EncAPRepPart`. The subkey it may contain was chosen by the service and is
    /// returned to the server as is.
    pub fn decrypt_ap_reply(&mut self, request: DecryptApReplyRequest<'_>) -> Result<Secret<Vec<u8>>> {
        self.check_usable()?;

        let key = self.owned_key(request.key, KeyRole::Service)?;
        let plaintext = self.decrypt_encrypted_data(request.encrypted_reply, &key, AP_REP_ENC)?;

        let reply: EncApRepPart = picky_asn1_der::from_bytes(&plaintext)
            .map_err(|_| Error::new(ErrorKind::InvalidToken, "invalid AP-REP encrypted part"))?;

        Ok(Secret::new(picky_asn1_der::to_vec(&reply)?))
    }

    /// Encrypts an `EncAPRepPart` (key usage 12) into the `enc-part` of a `KRB_AP_REP` template.
    ///
    /// Returns the DER-encoded `KRB_AP_REP`. The template is rejected unless it is canonical DER and has
    /// `pvno` 5 and `msg-type` 15. Its whole `enc-part` is replaced: `etype` becomes the session key's
    /// encryption type and `kvno` is omitted. All other template fields are returned unchanged.
    pub fn pack_ap_reply(&mut self, request: PackApReplyRequest<'_>) -> Result<Vec<u8>> {
        self.check_usable()?;

        let mut reply: ApRep = decode(request.reply, "AP-REP template")?;
        if picky_asn1_der::to_vec(&reply)? != request.reply {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                "AP-REP template is not DER-encoded",
            ));
        }
        // Raw comparisons also reject non-minimal INTEGER encodings.
        if reply.0.pvno.0.0 != [KERBEROS_VERSION] || reply.0.msg_type.0.0 != [AP_REP_MSG_TYPE] {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                "AP-REP template has an unexpected protocol version or message type",
            ));
        }

        // IntegerAsn1 preserves the input bytes instead of normalizing them during serialization.
        let enc_part = &reply.0.enc_part.0;
        let etype = enc_part.etype.0.0.as_slice();
        let kvno = enc_part.kvno.0.as_ref().map(|value| value.0.0.as_slice());
        for value in [Some(etype), kvno].into_iter().flatten() {
            let minimal = match value {
                [] => false,
                [0, next, ..] => next & 0x80 != 0,
                [0xFF, next, ..] => next & 0x80 == 0,
                _ => true,
            };
            if !minimal {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    "AP-REP template has an invalid INTEGER encoding",
                ));
            }
        }
        // INVARIANT: Both INTEGER values, when present, are nonempty and minimally encoded.
        if etype.len() > 4
            || kvno.is_some_and(|value| value[0] & 0x80 != 0 || value.len() > 5 || (value.len() == 5 && value[0] != 0))
        {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                "AP-REP template has an INTEGER outside its permitted range",
            ));
        }

        let _: EncApRepPart = decode(request.reply_body, "AP-REP encrypted part")?;

        let key = self.owned_key(request.session_key, KeyRole::Service)?;
        let cipher = key
            .cipher_suite
            .cipher()
            .encrypt(key.key.as_ref(), AP_REP_ENC, request.reply_body)?;

        reply.0.enc_part = ExplicitContextTag2::from(encrypted_data(&key.cipher_suite, cipher));

        Ok(picky_asn1_der::to_vec(&reply)?)
    }

    fn check_client_identity(&self, client_name: &[String], client_realm: &str) -> Result<()> {
        let names = &self.binding.name.name_string.0.0;

        let name_matches = names.len() == client_name.len()
            && names
                .iter()
                .zip(client_name)
                .all(|(expected, actual)| expected.0.as_bytes().eq_ignore_ascii_case(actual.as_bytes()));

        if !name_matches || !self.binding.realm.eq_ignore_ascii_case(client_realm) {
            return Err(Error::new(
                ErrorKind::NoCredentials,
                "the authenticator client does not match the authenticated user",
            ));
        }

        Ok(())
    }
}
