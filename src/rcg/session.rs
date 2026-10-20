use std::fmt;

use rand::rngs::StdRng;
use time::Duration;
use zeroize::Zeroize as _;

use super::kerberos::ServerSubkeys;
use super::key_store::KeyStore;
use super::ntlm::NtlmCredential;
use super::{ClientBinding, ProtectionContext, wrap};
use crate::{Error, ErrorKind, Result, Secret};

/// The authenticated Remote Credential Guard session of a completed CredSSP exchange.
///
/// Obtained with [`CredSspClient::take_remote_guard_session`](crate::credssp::CredSspClient::take_remote_guard_session)
/// after the CredSSP client finished and sent the `TSRemoteGuardCreds` credentials. With the `tsssp`
/// feature, `SspiCredSsp::take_remote_guard_session` provides the same handoff. The session owns:
/// - the RFC 4121 protection context that authenticated the CredSSP exchange (acceptor subkey, negotiated
///   encryption type, and the send and receive sequence numbers already consumed by CredSSP);
/// - the keys of the tickets delegated in the logon credential. These keys never leave the session: the
///   server refers to them through opaque key references (see [`KeyReference`](super::KeyReference));
/// - ordinary service-ticket keys obtained by redirected TGS operations. These are retained for
///   authorized follow-up operations, but are also returned to the remote host in protected RDPEAR
///   replies so that it can authenticate to those services. They are not reusable TGT keys;
/// - when NTLM redirection is enabled, the NT OWF of the user, referred to by the server through an opaque
///   handle (see [`NtlmCredentialReference`](super::NtlmCredentialReference)).
///
/// The session cannot be cloned. Any failure of [`unwrap`](Self::unwrap), or of message sealing in
/// [`wrap`](Self::wrap), permanently disables all operations and erases the protection key, ticket keys,
/// remembered server subkeys, and NTLM credential, so the caller must close the channel.
/// All secrets are zeroized when erased or when the session is dropped.
///
/// Initial Windows desktop logon and redirected NTLMv2 SMB authentication have been observed with a fresh
/// target logon (see [`crate::rcg`]). Reconnects to an existing target logon and outbound Kerberos
/// authentication remain unsupported or unverified as detailed there.
pub struct RemoteGuardSession {
    context: ProtectionContext,
    poisoned: bool,
    pub(super) binding: ClientBinding,
    pub(super) key_store: KeyStore,
    pub(super) server_subkeys: ServerSubkeys,
    pub(super) ntlm: Option<NtlmCredential>,
    pub(super) rng: StdRng,
    pub(super) clock_offset: Duration,
}

impl fmt::Debug for RemoteGuardSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteGuardSession")
            .field("poisoned", &self.poisoned)
            .field("key_store", &self.key_store)
            .field("ntlm", &self.ntlm.is_some())
            .finish_non_exhaustive()
    }
}

impl RemoteGuardSession {
    pub(super) fn new(
        context: ProtectionContext,
        binding: ClientBinding,
        key_store: KeyStore,
        ntlm: Option<NtlmCredential>,
        clock_offset: Duration,
    ) -> Result<Self> {
        Ok(Self {
            context,
            poisoned: false,
            binding,
            key_store,
            server_subkeys: ServerSubkeys::default(),
            ntlm,
            rng: super::rng()?,
            clock_offset,
        })
    }

    pub(super) fn check_usable(&self) -> Result<()> {
        if self.poisoned {
            return Err(Error::new(
                ErrorKind::ContextExpired,
                "remote credential guard session is unusable after a previous failure",
            ));
        }

        Ok(())
    }

    fn poison(&mut self) {
        self.poisoned = true;
        self.context.key.zeroize();
        self.key_store = KeyStore::default();
        self.server_subkeys = ServerSubkeys::default();
        self.ntlm = None;
    }

    /// Seals `plaintext` into an RFC 4121 wrap token sent by the initiator.
    ///
    /// Uses the acceptor subkey and the next initiator sequence number of the CredSSP context. A message
    /// larger than [`MAX_WRAP_TOKEN_LEN`](super::MAX_WRAP_TOKEN_LEN) minus the token overhead is rejected
    /// without consuming a sequence number or disabling the session.
    pub fn wrap(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.check_usable()?;

        if plaintext.len() > wrap::MAX_TOKEN_LEN - wrap::SEAL_OVERHEAD {
            return Err(Error::new(ErrorKind::InvalidParameter, "message is too large to wrap"));
        }

        let result = self.context.seal(plaintext);
        if result.is_err() {
            self.poison();
        }

        result
    }

    /// Verifies and unseals an RFC 4121 wrap token sent by the acceptor.
    ///
    /// The token must be sealed, carry the acceptor flags, use the expected next acceptor sequence number,
    /// and pass the integrity check. Any rotation count is accepted. On failure the session is disabled.
    pub fn unwrap(&mut self, token: &[u8]) -> Result<Secret<Vec<u8>>> {
        self.check_usable()?;

        match self.context.unseal(token) {
            Ok(mut plaintext) => Ok(Secret::new(std::mem::take(&mut *plaintext))),
            Err(error) => {
                self.poison();
                Err(error)
            }
        }
    }

    #[cfg(test)]
    pub(super) fn sequence_numbers(&self) -> (u64, u64) {
        self.context.sequence_numbers()
    }

    #[cfg(test)]
    pub(super) fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    #[cfg(test)]
    pub(super) fn has_protection_key(&self) -> bool {
        !self.context.key.as_ref().is_empty()
    }
}
