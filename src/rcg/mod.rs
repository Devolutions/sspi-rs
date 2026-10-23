//! Remote Credential Guard client support.
//!
//! Remote Credential Guard redirects Kerberos operations from the remote host back to the client, so
//! reusable TGT keys and long-term user secrets stay client-owned (MS-CSSP [2.2.1.2.3 TSRemoteGuardCreds],
//! [MS-RDPEAR]).
//!
//! This module provides:
//! - the Kerberos-only authentication mode used by [`CredSspMode::RemoteGuard`](crate::credssp::CredSspMode::RemoteGuard);
//! - the `TSRemoteGuardCreds` logon credential (`KERB_TICKET_LOGON` with a service ticket and a `KRB-CRED`);
//! - [`RemoteGuardSession`], which takes ownership of the authenticated CredSSP Kerberos context after the
//!   CredSSP exchange and exposes message protection and a restricted set of RDPEAR Kerberos operations;
//! - optionally, an NTLM supplemental credential and the RDPEAR NTLMv2 operations that use it (see
//!   [`CredSspClient::enable_remote_guard_ntlm`](crate::credssp::CredSspClient::enable_remote_guard_ntlm)).
//!   NTLM is never used for the initial authentication.
//!
//! Reusable TGT keys and the CredSSP protection key remain client-owned. Redirected service-ticket
//! replies intentionally contain the service session key, as required for the remote host to use the
//! ticket. Callers must protect those replies with this connection's live [`RemoteGuardSession`] and
//! erase the plaintext after use. Follow-up service-key operations only accept keys retained by this
//! session; arbitrary raw keys are not accepted.
//!
//! TGS authenticators with a server-supplied subkey are unsupported: such a key would let the remote
//! host decrypt subsequent TGT replies outside the client's key isolation. They fail explicitly before
//! creating an authenticator. TGS requests without a subkey and service AP-REQ subkeys are supported.
//! IAKerb proxy negotiation is unsupported in this mode: configure [`crate::KdcResolution::KdcUrl`]
//! for direct KDC or KDC-proxy communication. Ordinary authentication retains IAKerb support.
//!
//! An IronRDP integration run on 2026-10-19 confirmed initial Windows desktop logon with strict TLS,
//! Kerberos-only authentication, and the NTLMv2 supplement enabled. The connection remained established for
//! 25 seconds, and a 1024x768 framebuffer capture showed the logged-in desktop and taskbar.
//! That initial-logon run did not exercise redirected operations. Its result does not independently
//! validate native credential layouts, opaque-handle interpretation, or RDPEAR operation interoperability.
//! See the documentation of each item for the assumptions that still need to be validated.
//!
//! A subsequent fresh-logon run on the same date verified redirected NTLMv2 authentication end to end:
//! the authenticated callback completed successfully, Windows reported a protected MIC and a session key,
//! and SMB administrative-share access by IP succeeded with the default RCG credentials.
//! Windows populated credential-key metadata despite C-clear import; these unused fields are ignored.
//!
//! Supplemental NTLM redirection remains experimental and requires a fresh target logon. Reconnecting to
//! an existing target logon retained its old credential binding in the tested setup; the new connection
//! did not receive an NTLMv2 callback. No credential state is transferred between client sessions.
//! Initial RCG authentication remains Kerberos-only even when NTLM redirection is enabled.
//!
//! Observed redirected Kerberos operations returned success after adding checksum type 7, but outbound
//! Kerberos SMB access still prompted for credentials. Successful outbound Kerberos authentication remains
//! unverified; the NTLM result does not resolve that failure or establish general native-layout compatibility.
//! The returned service-key contract and authenticator skew handling have since been corrected against
//! the public specification and native provider. These corrections have only synthetic local validation,
//! not a new Windows interoperability run; they do not establish that the observed Kerberos failure is fixed.
//!
//! [2.2.1.2.3 TSRemoteGuardCreds]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/7ef8229c-44ea-4c1b-867f-00369b882b38
//! [MS-RDPEAR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/

mod asn1;
mod kerberos;
mod key_store;
mod logon;
mod ntlm;
mod session;
mod wrap;

use std::fmt;

use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::IntegerAsn1;
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{EncryptionKey, PrincipalName, Realm, Ticket};
use rand::rngs::{StdRng, SysRng};
use rand_core::SeedableRng as _;
use time::Duration;
use zeroize::Zeroizing;

pub use self::kerberos::{
    ApReqAuthenticator, BuildEncryptedAuthDataRequest, ComputeTgsChecksumRequest, CreateApReqAuthenticatorRequest,
    DecryptApReplyRequest, KeyReference, MAX_OPERATION_INPUT_LEN, PackApReplyRequest, UnpackKdcReplyBodyRequest,
};
use self::key_store::KeyStore;
use self::ntlm::NtlmCredential;
pub(crate) use self::ntlm::NtlmRedirectionPolicy;
pub use self::ntlm::{
    CREDENTIAL_KEY_LEN, DOMAIN_USER_CREDENTIAL_KEY_TYPE, Lm20GetNtlm3ChallengeResponseRequest,
    MAX_NTLM_SERVER_NAME_LEN, NTLM_CREDENTIAL_HANDLE_LEN, Ntlm3ChallengeResponse, NtlmCredentialComparison,
    NtlmCredentialReference, NtlmRedirectionNames,
};
pub use self::session::RemoteGuardSession;
pub use self::wrap::MAX_TOKEN_LEN as MAX_WRAP_TOKEN_LEN;
use crate::kerberos::client::KerberosClientState;
use crate::utils::{extract_encrypted_data, save_decrypted_data};
use crate::{
    BufferType, DecryptionFlags, Error, ErrorKind, Kerberos, KerberosState, Secret, SecurityBufferFlags,
    SecurityBufferRef, SecurityStatus,
};

/// Name of the security package in `TSRemoteGuardPackageCred` (MS-CSSP 2.2.1.2.3.1).
pub(crate) const KERBEROS_PACKAGE_NAME: &str = "Kerberos";

/// Seconds between 1601-01-01 (FILETIME epoch) and 1970-01-01 (Unix epoch).
const FILETIME_UNIX_EPOCH_OFFSET_SECONDS: i64 = 11_644_473_600;

/// A ticket-granting ticket captured during the initial authentication.
pub(crate) struct CapturedTgt {
    pub(crate) realm: String,
    pub(crate) ticket: Ticket,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) session_key: Secret<Vec<u8>>,
}

impl CapturedTgt {
    /// Captures a TGT. The session key must be an AES key of `cipher_suite`.
    pub(crate) fn new(
        realm: String,
        ticket: Ticket,
        cipher_suite: CipherSuite,
        session_key: Secret<Vec<u8>>,
    ) -> crate::Result<Self> {
        wrap::aes_size(&cipher_suite)?;

        if session_key.as_ref().len() != cipher_suite.cipher().key_size() {
            return Err(Error::new(
                ErrorKind::AlgorithmMismatch,
                "TGT session key length does not match its encryption type",
            ));
        }

        Ok(Self {
            realm,
            ticket,
            cipher_suite,
            session_key,
        })
    }
}

/// The client identity that authenticated the CredSSP context.
#[derive(Clone)]
pub(crate) struct ClientBinding {
    pub(crate) name: PrincipalName,
    pub(crate) realm: String,
}

impl ClientBinding {
    pub(crate) fn realm_asn1(&self) -> crate::Result<Realm> {
        Ok(Realm::from(IA5String::from_string(self.realm.clone())?))
    }
}

/// RFC 4121 protection state of the authenticated context.
///
/// Sequence numbers count tokens actually produced and accepted on the CredSSP context, so they continue
/// unchanged into the RDPEAR channel.
pub(crate) struct ProtectionContext {
    cipher_suite: CipherSuite,
    key: Secret<Vec<u8>>,
    next_send_seq: u64,
    next_recv_seq: u64,
}

impl ProtectionContext {
    pub(crate) fn new(
        cipher_suite: CipherSuite,
        key: Secret<Vec<u8>>,
        next_send_seq: u64,
        next_recv_seq: u64,
    ) -> crate::Result<Self> {
        wrap::aes_size(&cipher_suite)?;

        if key.as_ref().len() != cipher_suite.cipher().key_size() {
            return Err(Error::new(
                ErrorKind::InvalidParameter,
                "remote credential guard context key length does not match its encryption type",
            ));
        }

        Ok(Self {
            cipher_suite,
            key,
            next_send_seq,
            next_recv_seq,
        })
    }

    pub(crate) fn seal(&mut self, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
        if plaintext.len() > wrap::MAX_TOKEN_LEN - wrap::SEAL_OVERHEAD {
            return Err(Error::new(ErrorKind::InvalidParameter, "message is too large to wrap"));
        }

        let token = wrap::seal(
            &self.cipher_suite,
            self.key.as_ref(),
            wrap::Sender::Initiator,
            self.next_send_seq,
            plaintext,
        )?;
        self.next_send_seq += 1;

        Ok(token)
    }

    pub(crate) fn unseal(&mut self, token: &[u8]) -> crate::Result<Zeroizing<Vec<u8>>> {
        let plaintext = wrap::unseal(
            &self.cipher_suite,
            self.key.as_ref(),
            wrap::Sender::Acceptor,
            self.next_recv_seq,
            token,
        )?;
        self.next_recv_seq += 1;

        Ok(plaintext)
    }

    pub(crate) fn mic(&mut self, message: &[u8]) -> crate::Result<Vec<u8>> {
        let token = wrap::mic(
            &self.cipher_suite,
            self.key.as_ref(),
            wrap::Sender::Initiator,
            self.next_send_seq,
            message,
        )?;
        self.next_send_seq += 1;

        Ok(token)
    }

    pub(crate) fn verify_mic(&mut self, message: &[u8], token: &[u8]) -> crate::Result<()> {
        wrap::verify_mic(
            &self.cipher_suite,
            self.key.as_ref(),
            wrap::Sender::Acceptor,
            self.next_recv_seq,
            message,
            token,
        )?;
        self.next_recv_seq += 1;

        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn sequence_numbers(&self) -> (u64, u64) {
        (self.next_send_seq, self.next_recv_seq)
    }
}

/// Remote Credential Guard state attached to a client [`Kerberos`] context.
///
/// Cloning yields a poisoned, empty state: a live Remote Credential Guard context is never duplicated.
#[derive(Default)]
pub(crate) struct RemoteGuardState {
    poisoned: bool,
    pub(crate) home_tgt: Option<CapturedTgt>,
    pub(crate) service_tgt: Option<CapturedTgt>,
    pub(crate) binding: Option<ClientBinding>,
    pub(crate) context: Option<ProtectionContext>,
    pub(crate) key_store: KeyStore,
    pub(crate) ntlm: Option<NtlmCredential>,
    logon_built: bool,
}

impl Clone for RemoteGuardState {
    fn clone(&self) -> Self {
        Self {
            poisoned: true,
            ..Self::default()
        }
    }
}

impl fmt::Debug for RemoteGuardState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteGuardState")
            .field("poisoned", &self.poisoned)
            .field("home_tgt", &self.home_tgt.is_some())
            .field("service_tgt", &self.service_tgt.is_some())
            .field("context", &self.context.is_some())
            .field("key_store", &self.key_store)
            .field("ntlm", &self.ntlm.is_some())
            .field("logon_built", &self.logon_built)
            .finish_non_exhaustive()
    }
}

impl RemoteGuardState {
    fn check_usable(&self) -> crate::Result<()> {
        if self.poisoned {
            return Err(Error::new(
                ErrorKind::ContextExpired,
                "remote credential guard context is unusable after a previous failure",
            ));
        }

        Ok(())
    }

    /// Runs `f` on the protection context and poisons the state if `f` fails.
    pub(crate) fn with_context<T>(
        &mut self,
        f: impl FnOnce(&mut ProtectionContext) -> crate::Result<T>,
    ) -> crate::Result<T> {
        self.check_usable()?;

        let context = self.context.as_mut().ok_or_else(|| {
            Error::new(
                ErrorKind::OutOfSequence,
                "remote credential guard context is not established",
            )
        })?;

        let result = f(context);
        if result.is_err() {
            self.poison();
        }

        result
    }

    /// Disables Remote Credential Guard for this context and drops its tickets, keys, and NTLM credential.
    pub(crate) fn poison(&mut self) {
        self.poisoned = true;
        self.home_tgt = None;
        self.service_tgt = None;
        self.context = None;
        self.key_store = KeyStore::default();
        self.ntlm = None;
    }

    /// Establishes the protection context from the acceptor subkey of the AP-REP.
    ///
    /// Remote Credential Guard requires mutual authentication with an AES acceptor subkey: all later tokens,
    /// including the RDPEAR messages, are protected with it.
    pub(crate) fn establish_context(
        &mut self,
        acceptor_subkey: Option<&EncryptionKey>,
        next_send_seq: u64,
        next_recv_seq: u64,
    ) -> crate::Result<()> {
        self.check_usable()?;

        if self.context.is_some() {
            return Err(Error::new(
                ErrorKind::OutOfSequence,
                "remote credential guard context is already established",
            ));
        }
        if self.binding.is_none() || self.home_tgt.is_none() || self.service_tgt.is_none() {
            return Err(Error::new(
                ErrorKind::InternalError,
                "remote credential guard tickets were not captured during authentication",
            ));
        }

        let subkey = acceptor_subkey.ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidToken,
                "remote credential guard requires an acceptor subkey in the AP-REP",
            )
        })?;
        let cipher_suite = aes_cipher_suite(integer_to_i32(&subkey.key_type.0)?)?;

        self.context = Some(ProtectionContext::new(
            cipher_suite,
            Secret::new(subkey.key_value.0.0.clone()),
            next_send_seq,
            next_recv_seq,
        )?);

        Ok(())
    }

    /// Seals the single `Data` buffer and writes the first [`wrap::SEAL_OVERHEAD`] bytes of the token to the
    /// `Token` buffer and the rest of the token to the `Data` buffer.
    pub(crate) fn encrypt_message(&mut self, message: &mut [SecurityBufferRef<'_>]) -> crate::Result<SecurityStatus> {
        check_data_buffers(message)?;

        if SecurityBufferRef::find_buffer(message, BufferType::Token)?.buf_len() < wrap::SEAL_OVERHEAD {
            return Err(Error::new(ErrorKind::BufferTooSmall, "the Token buffer is too small"));
        }

        let plaintext = Zeroizing::new(
            SecurityBufferRef::buffers_of_type_and_flags(message, BufferType::Data, SecurityBufferFlags::NONE)
                .next()
                .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "no buffer was provided with type Data"))?
                .data()
                .to_vec(),
        );

        let token = self.with_context(|context| context.seal(&plaintext))?;

        // The sequence number is consumed: any failure from here on poisons the context.
        let result = (|| {
            let (header, body) = token
                .split_at_checked(wrap::SEAL_OVERHEAD)
                .ok_or_else(|| Error::new(ErrorKind::InternalError, "wrap token is too short"))?;

            SecurityBufferRef::buffers_of_type_and_flags_mut(message, BufferType::Data, SecurityBufferFlags::NONE)
                .next()
                .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "no buffer was provided with type Data"))?
                .write_data(body)?;
            SecurityBufferRef::find_buffer_mut(message, BufferType::Token)?.write_data(header)
        })();

        if result.is_err() {
            self.poison();
        }
        result?;

        Ok(SecurityStatus::Ok)
    }

    /// Unseals a token given as `Token` and `Data` buffers, or as a `Stream` buffer.
    pub(crate) fn decrypt_message(&mut self, message: &mut [SecurityBufferRef<'_>]) -> crate::Result<DecryptionFlags> {
        check_data_buffers(message)?;

        let token = extract_encrypted_data(message)?;
        let plaintext = self.with_context(|context| context.unseal(&token))?;

        if let Err(error) = save_decrypted_data(&plaintext, message) {
            self.poison();
            return Err(error);
        }

        Ok(DecryptionFlags::empty())
    }

    pub(crate) fn generate_mic(&mut self, data: &[u8]) -> crate::Result<Vec<u8>> {
        self.with_context(|context| context.mic(data))
    }

    pub(crate) fn verify_mic(&mut self, token: &[u8], data: &[u8]) -> crate::Result<()> {
        self.with_context(|context| context.verify_mic(data, token))
    }

    fn into_session(self, clock_offset: Duration) -> crate::Result<RemoteGuardSession> {
        self.check_usable()?;

        if !self.logon_built {
            return Err(Error::new(
                ErrorKind::OutOfSequence,
                "remote credential guard logon credentials have not been sent",
            ));
        }

        let context = self.context.ok_or_else(|| {
            Error::new(
                ErrorKind::OutOfSequence,
                "remote credential guard context is not established",
            )
        })?;
        let binding = self.binding.ok_or_else(|| {
            Error::new(
                ErrorKind::InternalError,
                "remote credential guard client identity is missing",
            )
        })?;

        RemoteGuardSession::new(context, binding, self.key_store, self.ntlm, clock_offset)
    }

    pub(crate) fn mark_logon_built(&mut self) {
        self.logon_built = true;
        self.home_tgt = None;
        self.service_tgt = None;
    }

    pub(crate) fn is_logon_built(&self) -> bool {
        self.logon_built
    }
}

pub(crate) fn rng() -> crate::Result<StdRng> {
    Ok(StdRng::try_from_rng(&mut SysRng)?)
}

/// Remote Credential Guard protects exactly one plain `Data` buffer per message: read-only (signed but not
/// encrypted) buffers are not supported.
fn check_data_buffers(message: &[SecurityBufferRef<'_>]) -> crate::Result<()> {
    let mut data_buffers = SecurityBufferRef::buffers_of_type(message, BufferType::Data);

    if data_buffers.any(|buffer| !buffer.buffer_flags().is_empty()) {
        return Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "remote credential guard does not support read-only Data buffers",
        ));
    }
    if SecurityBufferRef::buffers_of_type(message, BufferType::Data).count() > 1 {
        return Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "remote credential guard supports a single Data buffer",
        ));
    }

    Ok(())
}

/// Converts a DER `INTEGER` that must fit in an `Int32`.
pub(crate) fn integer_to_i32(value: &IntegerAsn1) -> crate::Result<i32> {
    let out_of_range = || Error::new(ErrorKind::InvalidToken, "integer is out of the Int32 range");

    let bytes = value.as_signed_bytes_be();
    // Non-minimal encodings may carry redundant sign bytes, so accept up to 8 bytes and range-check the value.
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(out_of_range());
    }

    let fill = if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        0xFF
    } else {
        0x00
    };
    let mut buf = [fill; 8];
    let start = buf.len() - bytes.len();
    buf.get_mut(start..).ok_or_else(out_of_range)?.copy_from_slice(bytes);

    i32::try_from(i64::from_be_bytes(buf)).map_err(|_| out_of_range())
}

/// Cipher suite for an RFC 3961 encryption type number, restricted to AES.
pub(crate) fn aes_cipher_suite(etype: i32) -> crate::Result<CipherSuite> {
    let suite = usize::try_from(etype)
        .ok()
        .and_then(|etype| CipherSuite::try_from(etype).ok())
        .ok_or_else(|| Error::new(ErrorKind::AlgorithmMismatch, "unsupported kerberos encryption type"))?;
    wrap::aes_size(&suite)?;

    Ok(suite)
}

pub(crate) fn etype_of(cipher_suite: &CipherSuite) -> i32 {
    i32::from(u8::from(cipher_suite))
}

impl Kerberos {
    /// Enables Remote Credential Guard for this client context.
    ///
    /// Must be called before the first `initialize_security_context` call.
    pub(crate) fn enable_remote_guard(&mut self) -> crate::Result<()> {
        if !self.is_client() {
            return Err(Error::new(
                ErrorKind::UnsupportedFunction,
                "remote credential guard is only supported for Kerberos clients",
            ));
        }
        if !matches!(&self.state, KerberosState::Client(state) if matches!(state.as_ref(), KerberosClientState::TgtExchange))
        {
            return Err(Error::new(
                ErrorKind::OutOfSequence,
                "remote credential guard must be enabled before authentication starts",
            ));
        }
        if self.is_iakerb() {
            return Err(Error::new(
                ErrorKind::UnsupportedFunction,
                "remote credential guard requires a direct KDC or KDC proxy connection",
            ));
        }
        if self.remote_guard.is_some() {
            return Ok(());
        }

        self.remote_guard = Some(Box::default());

        Ok(())
    }

    pub(crate) fn is_remote_guard(&self) -> bool {
        self.remote_guard.is_some()
    }

    pub(crate) fn remote_guard_mut(&mut self) -> crate::Result<&mut RemoteGuardState> {
        self.remote_guard.as_deref_mut().ok_or_else(|| {
            Error::new(
                ErrorKind::InternalError,
                "remote credential guard is not enabled for this context",
            )
        })
    }

    /// Takes the authenticated Remote Credential Guard context out of this Kerberos context.
    ///
    /// The Kerberos context cannot protect messages afterwards.
    pub(crate) fn take_remote_guard_session(&mut self) -> crate::Result<RemoteGuardSession> {
        if self.state != KerberosState::Final {
            return Err(Error::new(
                ErrorKind::OutOfSequence,
                "kerberos context is not established",
            ));
        }

        let state = self.remote_guard.take().ok_or_else(|| {
            Error::new(
                ErrorKind::UnsupportedFunction,
                "remote credential guard is not enabled for this context",
            )
        })?;
        // A poisoned state stays behind so the Kerberos context fails closed instead of falling back to the
        // regular message protection.
        self.remote_guard = Some(Box::new(RemoteGuardState {
            poisoned: true,
            ..RemoteGuardState::default()
        }));
        // The session owns the only copy of the context key from now on.
        self.encryption_params.session_key = None;
        self.encryption_params.sub_session_key = None;

        state.into_session(self.clock_offset)
    }
}

#[cfg(test)]
mod tests;
