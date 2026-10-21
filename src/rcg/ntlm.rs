//! NTLM supplemental credential of Remote Credential Guard.
//!
//! Initial authentication stays Kerberos-only. When explicitly enabled, the client additionally sends an
//! NTLM supplemental credential in `TSRemoteGuardCreds.supplementalCreds` (MS-CSSP
//! [2.2.1.2.3 TSRemoteGuardCreds] and its behavior note 22), so that the remote NTLM package can redirect
//! NTLMv2 computations back to the client over MS-RDPEAR ([2.2.2.2 NTLM Messages]).
//!
//! The NTOWF of the user never leaves the client. The supplemental credential carries:
//! - `Flags` = N (NT OWF present) only;
//! - a zero `CredentialKey` without the C flag: deriving the credential key requires the user SID, which the
//!   client does not know, and the key is a reusable secret;
//! - `CredentialKeyType` = `DomainUserCredKey`;
//! - a random per-session handle as the `reserved` blob.
//!
//! MS-RDPEAR [2.2.1.3.6 MSV1_0_REMOTE_ENCRYPTED_SECRETS] describes the credential returned by the server as
//! client-opaque and implementation-specific. A live Windows callback preserved the handle and flags
//! `(NT, LM, SHA) = (1, 0, 0)`, but populated `DomainUserCredKey` and a nonzero credential key despite
//! C-clear import. These two fields are ignored: NTLMv2 and credential comparison use the client-owned
//! NT OWF, not a credential key received from the server. References must have the NT-only flags and
//! exactly match the handle of the current session.
//!
//! Native NDR32 encoding and decoding with the inspected Windows metadata accept synthetic references
//! of this shape. A fresh Windows logon also verified the corrected callback validation end to end:
//! default-credential NTLMv2 authentication completed with a protected MIC, and SMB administrative-share
//! access by IP succeeded (see [`crate::rcg`]).
//! Reconnecting to an existing target logon did not refresh its credential binding in the tested setup;
//! a fresh target logon is required. Handles from an earlier connection are not accepted by a new session.
//!
//! Only NTLMv2 is supported: NTLMv1 and LM computations are never performed.
//!
//! [2.2.1.2.3 TSRemoteGuardCreds]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/7ef8229c-44ea-4c1b-867f-00369b882b38
//! [2.2.2.2 NTLM Messages]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/
//! [2.2.1.3.6 MSV1_0_REMOTE_ENCRYPTED_SECRETS]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/

use std::fmt;

use rand::rngs::StdRng;
use rand_core::Rng as _;
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use super::FILETIME_UNIX_EPOCH_OFFSET_SECONDS;
use super::session::RemoteGuardSession;
use super::wrap::constant_time_eq;
use crate::crypto::{compute_hmac_md5, compute_md4};
use crate::ntlm::NTLM_HASH_PREFIX;
use crate::{CredentialsBuffers, Error, ErrorKind, Secret, Utf16String, Utf16StringExt};

/// Name of the security package in the NTLM `TSRemoteGuardPackageCred` (MS-CSSP 2.2.1.2.3.1).
pub(crate) const NTLM_PACKAGE_NAME: &str = "NTLM";

/// `Version` of `NTLM_REMOTE_SUPPLEMENTAL_CREDENTIAL`.
const SUPPLEMENTAL_CREDENTIAL_VERSION: u32 = 0xFFFF_0002;
/// N flag of `NTLM_REMOTE_SUPPLEMENTAL_CREDENTIAL`: the NT OWF is present.
const SUPPLEMENTAL_CREDENTIAL_FLAG_NT_OWF: u32 = 0x2;
/// `DomainUserCredKey` value of `MSV1_0_CREDENTIAL_KEY_TYPE`.
pub const DOMAIN_USER_CREDENTIAL_KEY_TYPE: u32 = 2;
/// Length of `MSV1_0_CREDENTIAL_KEY`.
pub const CREDENTIAL_KEY_LEN: usize = 20;

/// Tag at the start of the opaque credential handle.
const HANDLE_TAG: &[u8; 4] = b"RGN1";
const HANDLE_RANDOM_LEN: usize = 32;
/// Length of the opaque credential handle carried in `reserved` / `reserved6`.
pub const NTLM_CREDENTIAL_HANDLE_LEN: usize = HANDLE_TAG.len() + HANDLE_RANDOM_LEN;
/// `NTLM_CREDENTIAL_HANDLE_LEN` as the `reservedsize` field.
const HANDLE_LEN_U32: u32 = 36;
const _: () = assert!(NTLM_CREDENTIAL_HANDLE_LEN == 36);

const NT_OWF_LEN: usize = 16;
const CHALLENGE_LEN: usize = 8;
/// `RespType`, `HiRespType`, `Z(6)`, `Time`, `ClientChallenge`, and `Z(4)` before `ServerName`.
const NTLMV2_TEMP_HEADER_LEN: usize = 28;
/// `Z(4)` after `ServerName`.
const NTLMV2_TEMP_TRAILER_LEN: usize = 4;
/// Largest `ServerName` such that the response length fits the `USHORT Ntlm3ResponseLength`.
pub const MAX_NTLM_SERVER_NAME_LEN: usize = USHORT_MAX - NT_OWF_LEN - NTLMV2_TEMP_HEADER_LEN - NTLMV2_TEMP_TRAILER_LEN;
/// `u16::MAX` as a `usize`.
const USHORT_MAX: usize = 0xFFFF;

const AV_ID_EOL: u16 = 0;
const AV_ID_TIMESTAMP: u16 = 7;

/// Names to which redirected NTLM computations are bound.
///
/// A redirected `Lm20GetNtlm3ChallengeResponse` request is accepted only if its `UserName` and
/// `LogonDomainName` are equal, ignoring case, to these names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NtlmRedirectionNames {
    /// User name, for example the SAM account name.
    pub user: String,
    /// Logon domain name, for example the NetBIOS domain name. May be empty.
    pub domain: String,
}

/// NTLM redirection policy configured on the CredSSP client.
#[derive(Clone, Debug)]
pub(crate) struct NtlmRedirectionPolicy {
    pub(crate) names: Option<NtlmRedirectionNames>,
}

impl NtlmRedirectionPolicy {
    pub(crate) fn new(names: Option<NtlmRedirectionNames>) -> crate::Result<Self> {
        if names.as_ref().is_some_and(|names| names.user.is_empty()) {
            return Err(Error::new(
                ErrorKind::InvalidParameter,
                "NTLM redirection user name is empty",
            ));
        }

        Ok(Self { names })
    }
}

/// The NTLM credential owned by a Remote Credential Guard session.
pub(crate) struct NtlmCredential {
    nt_owf: Secret<[u8; NT_OWF_LEN]>,
    /// Upper-cased bound user name.
    user: Utf16String,
    /// Upper-cased bound domain name.
    domain: Utf16String,
    handle: [u8; NTLM_CREDENTIAL_HANDLE_LEN],
}

impl fmt::Debug for NtlmCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtlmCredential").finish_non_exhaustive()
    }
}

impl NtlmCredential {
    /// Builds the NTLM credential of a password identity.
    ///
    /// Returns `None` when the identity has no NT OWF: smart card credentials, or an empty password.
    pub(crate) fn from_identity(
        identity: Option<&CredentialsBuffers>,
        policy: &NtlmRedirectionPolicy,
        rng: &mut StdRng,
    ) -> crate::Result<Option<Self>> {
        let Some(CredentialsBuffers::AuthIdentity(identity)) = identity else {
            return Ok(None);
        };

        let password = identity.password.as_ref().0.as_slice();
        if password.is_empty() || identity.user.is_empty() {
            return Ok(None);
        }

        let nt_owf = nt_owf(password)?;

        let (user, domain) = match &policy.names {
            Some(names) => (Utf16String::from_str(&names.user), Utf16String::from_str(&names.domain)),
            None => (identity.user.clone(), identity.domain.clone()),
        };

        Ok(Some(Self::new(nt_owf, &user, &domain, rng)))
    }

    pub(super) fn new(
        nt_owf: Secret<[u8; NT_OWF_LEN]>,
        user: &Utf16String,
        domain: &Utf16String,
        rng: &mut StdRng,
    ) -> Self {
        let mut handle = [0; NTLM_CREDENTIAL_HANDLE_LEN];
        let (tag, random) = handle.split_at_mut(HANDLE_TAG.len());
        tag.copy_from_slice(HANDLE_TAG);
        rng.fill_bytes(random);

        Self {
            nt_owf,
            user: user.to_uppercase(),
            domain: domain.to_uppercase(),
            handle,
        }
    }

    /// Encodes the `NTLM_REMOTE_SUPPLEMENTAL_CREDENTIAL` of this credential.
    ///
    /// The structure is encoded as consecutive little-endian fields followed by the `reserved` bytes.
    /// The inspected native importer reads this prefix and the declared blob length; it does not require
    /// the unexplained trailer emitted by FreeRDP's unused writer. An end-to-end NTLMv2 exchange using
    /// this encoding succeeded on a fresh Windows logon (see [`crate::rcg`]).
    pub(crate) fn supplemental_credential(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(4 + 4 + CREDENTIAL_KEY_LEN + 4 + 4 + NTLM_CREDENTIAL_HANDLE_LEN);
        buffer.extend_from_slice(&SUPPLEMENTAL_CREDENTIAL_VERSION.to_le_bytes());
        buffer.extend_from_slice(&SUPPLEMENTAL_CREDENTIAL_FLAG_NT_OWF.to_le_bytes());
        buffer.extend_from_slice(&[0; CREDENTIAL_KEY_LEN]);
        buffer.extend_from_slice(&DOMAIN_USER_CREDENTIAL_KEY_TYPE.to_le_bytes());
        buffer.extend_from_slice(&HANDLE_LEN_U32.to_le_bytes());
        buffer.extend_from_slice(&self.handle);

        buffer
    }

    fn check_reference(&self, reference: &NtlmCredentialReference<'_>) -> crate::Result<()> {
        let fields_valid = (reference.reserved1 == 1) & (reference.reserved2 == 0) & (reference.reserved3 == 0);
        let handle_valid = constant_time_eq(reference.encrypted_secrets, &self.handle);

        if !(fields_valid & handle_valid) {
            return Err(Error::new(
                ErrorKind::InvalidHandle,
                "the NTLM credential does not belong to this remote credential guard session",
            ));
        }

        Ok(())
    }

    fn check_names(&self, user: &Utf16String, domain: &Utf16String) -> crate::Result<()> {
        if user.to_uppercase() != self.user || domain.to_uppercase() != self.domain {
            return Err(Error::new(
                ErrorKind::LogonDenied,
                "the NTLM request names do not match the remote credential guard identity",
            ));
        }

        Ok(())
    }
}

/// Computes the NTOWF of a password ([MS-NLMP] 3.3.1), or decodes an NT hash given with the
/// [`NTLM_HASH_PREFIX`].
///
/// [MS-NLMP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
pub(super) fn nt_owf(password: &[u16]) -> crate::Result<Secret<[u8; NT_OWF_LEN]>> {
    let prefix = NTLM_HASH_PREFIX.encode_utf16();
    let prefix_len = prefix.clone().count();

    if password.len() >= prefix_len && prefix.zip(password).all(|(expected, actual)| expected == *actual) {
        let hex = password.get(prefix_len..).unwrap_or_default();
        let invalid_hash = || Error::new(ErrorKind::InvalidParameter, "invalid NT hash in the password");

        if hex.len() != NT_OWF_LEN * 2 {
            return Err(invalid_hash());
        }

        let mut hash = Secret::new([0; NT_OWF_LEN]);
        for (byte, digits) in hash.as_mut().iter_mut().zip(hex.chunks_exact(2)) {
            let digit = |unit: u16| char::from_u32(u32::from(unit)).and_then(|c| c.to_digit(16));
            let (Some(high), Some(low)) = (
                digits.first().and_then(|&u| digit(u)),
                digits.get(1).and_then(|&u| digit(u)),
            ) else {
                return Err(invalid_hash());
            };
            *byte = u8::try_from(high * 16 + low).map_err(|_| invalid_hash())?;
        }

        return Ok(hash);
    }

    let password_bytes = Zeroizing::new(password.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<_>>());

    Ok(Secret::new(compute_md4(&password_bytes)))
}

/// Reference to the NTLM credential of a session, as found in an RDPEAR `MSV1_0_REMOTE_ENCRYPTED_SECRETS`.
///
/// All fields are passed exactly as received. For this client's N-only, C-clear supplemental credential,
/// a reference is valid only if it has the handle of the session, `(reserved1, reserved2, reserved3)` is
/// `(1, 0, 0)`. `credential_key_type` and `credential_key` are ignored for both NTLMv2 challenge-response
/// and credential comparison; Windows may populate them even though the supplemental C flag is clear.
/// Neither field is used to identify the credential or compute a response.
#[derive(Clone, Copy)]
pub struct NtlmCredentialReference<'a> {
    /// `reserved1` BOOLEAN, NT OWF present. Must be 1.
    pub reserved1: u8,
    /// `reserved2` BOOLEAN, LM OWF present. Must be 0.
    pub reserved2: u8,
    /// `reserved3` BOOLEAN, SHA OWF present. Must be 0.
    pub reserved3: u8,
    /// `reserved4`, an `MSV1_0_CREDENTIAL_KEY_TYPE` value. Ignored.
    pub credential_key_type: u32,
    /// `reserved5`, an `MSV1_0_CREDENTIAL_KEY`. Ignored, never stored or used as key material.
    pub credential_key: &'a [u8; CREDENTIAL_KEY_LEN],
    /// `reserved6`, the opaque credential handle.
    pub encrypted_secrets: &'a [u8],
}

impl fmt::Debug for NtlmCredentialReference<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtlmCredentialReference")
            .field("reserved1", &self.reserved1)
            .field("reserved2", &self.reserved2)
            .field("reserved3", &self.reserved3)
            .field("credential_key_type", &self.credential_key_type)
            .field("encrypted_secrets_len", &self.encrypted_secrets.len())
            .finish_non_exhaustive()
    }
}

/// Input of an RDPEAR `Lm20GetNtlm3ChallengeResponse` operation (MS-RDPEAR 2.2.2.2.2).
#[derive(Clone, Copy)]
pub struct Lm20GetNtlm3ChallengeResponseRequest<'a> {
    /// Credential of the session.
    pub credential: NtlmCredentialReference<'a>,
    /// `UserName` as UTF-16LE bytes.
    pub user_name: &'a [u8],
    /// `LogonDomainName` as UTF-16LE bytes.
    pub logon_domain_name: &'a [u8],
    /// `ServerName` bytes, interpreted as the MS-NLMP `ServerName` (an `AV_PAIR` list terminated by
    /// `MsvAvEOL`).
    ///
    /// The inspected native NTLMv2 helper searches this buffer for `MsvAvTimestamp` and copies the raw
    /// bytes into the response. It is not interpreted as a UTF-16 host name.
    pub server_name: &'a [u8],
    /// `ChallengeToClient`, the server challenge.
    pub challenge_to_client: [u8; CHALLENGE_LEN],
}

impl fmt::Debug for Lm20GetNtlm3ChallengeResponseRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lm20GetNtlm3ChallengeResponseRequest")
            .field("credential", &self.credential)
            .field("user_name_len", &self.user_name.len())
            .field("logon_domain_name_len", &self.logon_domain_name.len())
            .field("server_name_len", &self.server_name.len())
            .finish_non_exhaustive()
    }
}

/// Output of an RDPEAR `Lm20GetNtlm3ChallengeResponse` operation (MS-RDPEAR 2.2.2.2.2).
pub struct Ntlm3ChallengeResponse {
    /// `Ntlm3Response`, the NTLMv2 `NtChallengeResponse` (`NTProofStr` followed by `temp`).
    pub ntlm3_response: Vec<u8>,
    /// `Lm3Response.Response`, the HMAC part of the LMv2 response.
    ///
    /// Computed separately from the native package's LM-response suppression policy. The remote package
    /// decides whether to include the LMv2 response in its authenticate message.
    pub lm3_response: [u8; NT_OWF_LEN],
    /// `Lm3Response.ChallengeFromClient`, the client challenge used by both responses.
    pub challenge_from_client: [u8; CHALLENGE_LEN],
    /// `UserSessionKey`, the NTLMv2 `SessionBaseKey`.
    pub user_session_key: Secret<[u8; NT_OWF_LEN]>,
    /// `LmSessionKey`.
    ///
    /// Intentionally zero: no LM credential is held, and NTLMv2 derives the key exchange key from the full
    /// `SessionBaseKey`. The inspected native helper copies its first eight bytes here, but this client
    /// does not implement that convention. The zero value was accepted in the bounded Windows NTLMv2
    /// integration run described in [`crate::rcg`]; this does not establish equivalence for other consumers.
    pub lm_session_key: Secret<[u8; CHALLENGE_LEN]>,
}

impl fmt::Debug for Ntlm3ChallengeResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ntlm3ChallengeResponse")
            .field("ntlm3_response_len", &self.ntlm3_response.len())
            .finish_non_exhaustive()
    }
}

/// Output of an RDPEAR `CompareCredentials` operation (MS-RDPEAR 2.2.2.2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NtlmCredentialComparison {
    /// `AreNtOwfsEqual`.
    pub are_nt_owfs_equal: bool,
    /// `AreLmOwfsEqual`.
    pub are_lm_owfs_equal: bool,
    /// `AreShaOwfsEqual`.
    pub are_sha_owfs_equal: bool,
}

/// Validates an MS-NLMP `ServerName` (`AV_PAIR` list) and returns its `MsvAvTimestamp`, if any.
///
/// The list must be well formed and end exactly with a single `MsvAvEOL`.
fn parse_server_name(server_name: &[u8]) -> crate::Result<Option<u64>> {
    let invalid = || Error::new(ErrorKind::InvalidToken, "NTLM ServerName is not a valid AV_PAIR list");

    if server_name.len() > MAX_NTLM_SERVER_NAME_LEN {
        return Err(Error::new(ErrorKind::InvalidParameter, "NTLM ServerName is too long"));
    }

    let mut timestamp = None;
    let mut rest = server_name;
    loop {
        let (header, after_header) = rest.split_at_checked(4).ok_or_else(invalid)?;
        let id = u16::from_le_bytes([header[0], header[1]]);
        let len = usize::from(u16::from_le_bytes([header[2], header[3]]));
        let (value, after_value) = after_header.split_at_checked(len).ok_or_else(invalid)?;

        match id {
            AV_ID_EOL => {
                if len != 0 || !after_value.is_empty() {
                    return Err(invalid());
                }

                return Ok(timestamp);
            }
            AV_ID_TIMESTAMP => {
                let value: [u8; 8] = value.try_into().map_err(|_| invalid())?;
                if timestamp.replace(u64::from_le_bytes(value)).is_some() {
                    return Err(invalid());
                }
            }
            _ => {}
        }

        rest = after_value;
    }
}

fn parse_name(name: &[u8], what: &str) -> crate::Result<Utf16String> {
    Utf16String::from_bytes_le(name)
        .map_err(|_| Error::new(ErrorKind::InvalidParameter, format!("NTLM {what} is not valid UTF-16")))
}

/// Computes the NTLMv2 responses ([MS-NLMP] 3.3.2).
///
/// [MS-NLMP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
pub(super) fn compute_ntlm3_response(
    nt_owf: &[u8; NT_OWF_LEN],
    user: &Utf16String,
    domain: &Utf16String,
    server_name: &[u8],
    server_challenge: &[u8; CHALLENGE_LEN],
    client_challenge: &[u8; CHALLENGE_LEN],
    time: u64,
) -> crate::Result<Ntlm3ChallengeResponse> {
    let mut user_and_domain = Zeroizing::new(user.to_uppercase().to_bytes_le());
    user_and_domain.extend_from_slice(domain.as_bytes_le());
    let response_key = Zeroizing::new(compute_hmac_md5(nt_owf, &user_and_domain)?);

    let mut ntlm3_response = vec![0; NT_OWF_LEN];
    ntlm3_response.reserve(NTLMV2_TEMP_HEADER_LEN + server_name.len() + NTLMV2_TEMP_TRAILER_LEN);
    ntlm3_response.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0]);
    ntlm3_response.extend_from_slice(&time.to_le_bytes());
    ntlm3_response.extend_from_slice(client_challenge);
    ntlm3_response.extend_from_slice(&[0; 4]);
    ntlm3_response.extend_from_slice(server_name);
    ntlm3_response.extend_from_slice(&[0; NTLMV2_TEMP_TRAILER_LEN]);

    if u16::try_from(ntlm3_response.len()).is_err() {
        return Err(Error::new(ErrorKind::InvalidParameter, "NTLM ServerName is too long"));
    }

    let (nt_proof_str, temp) = ntlm3_response.split_at_mut(NT_OWF_LEN);
    let mut proof_input = Vec::with_capacity(CHALLENGE_LEN + temp.len());
    proof_input.extend_from_slice(server_challenge);
    proof_input.extend_from_slice(temp);
    nt_proof_str.copy_from_slice(&compute_hmac_md5(response_key.as_ref(), &proof_input)?);

    let session_base_key = compute_hmac_md5(response_key.as_ref(), nt_proof_str)?;

    let mut lm_input = [0; CHALLENGE_LEN * 2];
    lm_input[..CHALLENGE_LEN].copy_from_slice(server_challenge);
    lm_input[CHALLENGE_LEN..].copy_from_slice(client_challenge);
    let lm3_response = compute_hmac_md5(response_key.as_ref(), &lm_input)?;

    Ok(Ntlm3ChallengeResponse {
        ntlm3_response,
        lm3_response,
        challenge_from_client: *client_challenge,
        user_session_key: Secret::new(session_base_key),
        lm_session_key: Secret::new([0; CHALLENGE_LEN]),
    })
}

pub(super) fn current_filetime(clock_offset: Duration) -> crate::Result<u64> {
    let out_of_range = || Error::new(ErrorKind::TimeSkew, "current time is out of range");

    let now = OffsetDateTime::now_utc()
        .checked_add(clock_offset)
        .ok_or_else(out_of_range)?;
    let ticks = now.unix_timestamp_nanos() / 100 + i128::from(FILETIME_UNIX_EPOCH_OFFSET_SECONDS) * 10_000_000;

    u64::try_from(ticks).map_err(|_| out_of_range())
}

impl RemoteGuardSession {
    fn ntlm_credential(&self) -> crate::Result<&NtlmCredential> {
        self.check_usable()?;

        self.ntlm.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::NoCredentials,
                "no NTLM credential was delegated in this remote credential guard session",
            )
        })
    }

    /// Returns `true` if this session holds an NTLM credential and is usable.
    ///
    /// The credential exists only if NTLM redirection was enabled with
    /// [`CredSspClient::enable_remote_guard_ntlm`](crate::credssp::CredSspClient::enable_remote_guard_ntlm)
    /// and the client authenticated with a password or an NT hash.
    pub fn ntlm_available(&self) -> bool {
        self.ntlm_credential().is_ok()
    }

    /// Performs an RDPEAR `Lm20GetNtlm3ChallengeResponse` operation: the NTLMv2 computations of
    /// [MS-NLMP] 3.3.2 with the NT OWF of the session.
    ///
    /// The request must reference the credential of this session and name the bound identity, ignoring case.
    /// `server_name` must be a well-formed `AV_PAIR` list: when it carries an `MsvAvTimestamp`, that time is
    /// used, otherwise the current time adjusted by the KDC clock offset. A new random client challenge is
    /// used for each call.
    ///
    /// Failures do not affect message protection.
    ///
    /// [MS-NLMP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
    pub fn lm20_get_ntlm3_challenge_response(
        &mut self,
        request: &Lm20GetNtlm3ChallengeResponseRequest<'_>,
    ) -> crate::Result<Ntlm3ChallengeResponse> {
        let credential = self.ntlm_credential()?;
        credential.check_reference(&request.credential)?;

        let user = parse_name(request.user_name, "UserName")?;
        let domain = parse_name(request.logon_domain_name, "LogonDomainName")?;
        credential.check_names(&user, &domain)?;

        let time = match parse_server_name(request.server_name)? {
            Some(timestamp) => timestamp,
            None => current_filetime(self.clock_offset)?,
        };

        let mut client_challenge = [0; CHALLENGE_LEN];
        self.rng.fill_bytes(&mut client_challenge);

        let credential = self.ntlm_credential()?;
        compute_ntlm3_response(
            credential.nt_owf.as_ref(),
            &user,
            &domain,
            request.server_name,
            &request.challenge_to_client,
            &client_challenge,
            time,
        )
    }

    /// Performs an RDPEAR `CompareCredentials` operation.
    ///
    /// Both references must designate the credential of this session. A session holds a single credential
    /// with only an NT OWF, so the NT OWFs are equal and there are no LM or SHA OWFs to match.
    pub fn compare_ntlm_credentials(
        &self,
        lhs: &NtlmCredentialReference<'_>,
        rhs: &NtlmCredentialReference<'_>,
    ) -> crate::Result<NtlmCredentialComparison> {
        let credential = self.ntlm_credential()?;
        credential.check_reference(lhs)?;
        credential.check_reference(rhs)?;

        Ok(NtlmCredentialComparison {
            are_nt_owfs_equal: true,
            are_lm_owfs_equal: false,
            are_sha_owfs_equal: false,
        })
    }
}
