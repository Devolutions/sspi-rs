mod config;
mod messages;
#[cfg(test)]
mod test;

use std::fmt::Debug;
use std::io;

use bitflags::bitflags;
use byteorder::{LittleEndian, WriteBytesExt};
use lazy_static::lazy_static;
use messages::{client, server};

pub use self::config::NtlmConfig;
use super::channel_bindings::ChannelBindings;
use crate::crypto::{compute_hmac_md5, Rc4, HASH_SIZE};
use crate::generator::GeneratorInitSecurityContext;
use crate::utils::{extract_encrypted_data, save_decrypted_data};
use crate::{
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers, CertTrustStatus,
    ClientRequestFlags, ClientResponseFlags, ContextNames, ContextSizes, CredentialUse, DecryptionFlags,
    EncryptionFlags, Error, ErrorKind, FilledAcceptSecurityContext, FilledAcquireCredentialsHandle,
    FilledInitializeSecurityContext, InitializeSecurityContextResult, OwnedSecurityBuffer, PackageCapabilities,
    PackageInfo, SecurityBuffer, SecurityBufferType, SecurityPackageType, SecurityStatus, ServerResponseFlags, Sspi,
    SspiEx, SspiImpl, PACKAGE_ID_NONE,
};

pub const PKG_NAME: &str = "NTLM";
pub const NTLM_VERSION_SIZE: usize = 8;
pub const DEFAULT_NTLM_VERSION: [u8; NTLM_VERSION_SIZE] = [0x0a, 0x00, 0x63, 0x45, 0x00, 0x00, 0x00, 0x0f];

pub const ENCRYPTED_RANDOM_SESSION_KEY_SIZE: usize = 16;
pub const SIGNATURE_SIZE: usize = SIGNATURE_VERSION_SIZE + SIGNATURE_CHECKSUM_SIZE + SIGNATURE_SEQ_NUM_SIZE;

const CHALLENGE_SIZE: usize = 8;
const SESSION_KEY_SIZE: usize = 16;
const MESSAGE_INTEGRITY_CHECK_SIZE: usize = 16;
const LM_CHALLENGE_RESPONSE_BUFFER_SIZE: usize = HASH_SIZE + CHALLENGE_SIZE;

const SIGNATURE_VERSION_SIZE: usize = 4;
const SIGNATURE_SEQ_NUM_SIZE: usize = 4;
const SIGNATURE_CHECKSUM_SIZE: usize = 8;
const MESSAGES_VERSION: u32 = 1;

lazy_static! {
    pub static ref PACKAGE_INFO: PackageInfo = PackageInfo {
        capabilities: PackageCapabilities::empty(),
        rpc_id: PACKAGE_ID_NONE,
        max_token_len: 0xb48,
        name: SecurityPackageType::Ntlm,
        comment: String::from("NTLM Security Package"),
    };
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum NtlmState {
    Initial,
    Negotiate,
    Challenge,
    Authenticate,
    Completion,
    Final,
}

/// Specifies the NT LAN Manager (NTLM) Authentication Protocol, used for authentication between clients and servers.
/// NTLM is used by application protocols to authenticate remote users and, optionally, to provide session security when requested by the application.
///
/// # MSDN
///
/// * [[MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4)
#[derive(Debug, Clone)]
pub struct Ntlm {
    config: NtlmConfig,

    negotiate_message: Option<NegotiateMessage>,
    challenge_message: Option<ChallengeMessage>,
    authenticate_message: Option<AuthenticateMessage>,

    channel_bindings: Option<ChannelBindings>,

    state: NtlmState,
    flags: NegotiateFlags,
    identity: Option<AuthIdentityBuffers>,
    version: [u8; NTLM_VERSION_SIZE],

    send_single_host_data: bool,

    signing: bool, // integrity
    sealing: bool, // confidentiality
    send_signing_key: [u8; HASH_SIZE],
    recv_signing_key: [u8; HASH_SIZE],
    send_sealing_key: Option<Rc4>,
    recv_sealing_key: Option<Rc4>,

    session_key: Option<[u8; SESSION_KEY_SIZE]>,
}

#[derive(Debug, Clone)]
struct Mic {
    value: [u8; MESSAGE_INTEGRITY_CHECK_SIZE],
    offset: u8,
}

#[derive(Debug, Clone)]
struct NegotiateMessage {
    message: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ChallengeMessage {
    message: Vec<u8>,
    target_info: Vec<u8>,
    server_challenge: [u8; CHALLENGE_SIZE],
    timestamp: u64,
}

#[derive(Debug, Clone)]
struct AuthenticateMessage {
    message: Vec<u8>,
    mic: Option<Mic>,
    target_info: Vec<u8>,
    client_challenge: [u8; CHALLENGE_SIZE],
    encrypted_random_session_key: Option<[u8; ENCRYPTED_RANDOM_SESSION_KEY_SIZE]>,
}

impl Ntlm {
    pub fn new() -> Self {
        Self {
            config: NtlmConfig::default(),

            negotiate_message: None,
            challenge_message: None,
            authenticate_message: None,

            channel_bindings: None,

            state: NtlmState::Initial,
            flags: NegotiateFlags::empty(),
            identity: None,
            version: DEFAULT_NTLM_VERSION,

            send_single_host_data: false,

            signing: true,
            sealing: true,
            send_signing_key: [0x00; HASH_SIZE],
            recv_signing_key: [0x00; HASH_SIZE],
            send_sealing_key: None,
            recv_sealing_key: None,
            session_key: None,
        }
    }

    pub fn with_config(config: NtlmConfig) -> Self {
        Self {
            config,

            negotiate_message: None,
            challenge_message: None,
            authenticate_message: None,

            channel_bindings: None,

            state: NtlmState::Initial,
            flags: NegotiateFlags::empty(),
            identity: None,
            version: DEFAULT_NTLM_VERSION,

            send_single_host_data: false,

            signing: true,
            sealing: true,
            send_signing_key: [0x00; HASH_SIZE],
            recv_signing_key: [0x00; HASH_SIZE],
            send_sealing_key: None,
            recv_sealing_key: None,
            session_key: None,
        }
    }

    pub fn with_auth_identity(identity: Option<AuthIdentityBuffers>, config: NtlmConfig) -> Self {
        Self {
            config,

            negotiate_message: None,
            challenge_message: None,
            authenticate_message: None,

            channel_bindings: None,

            state: NtlmState::Initial,
            flags: NegotiateFlags::empty(),
            identity,
            version: DEFAULT_NTLM_VERSION,

            send_single_host_data: false,

            signing: true,
            sealing: true,
            send_signing_key: [0x00; HASH_SIZE],
            recv_signing_key: [0x00; HASH_SIZE],
            send_sealing_key: None,
            recv_sealing_key: None,
            session_key: None,
        }
    }

    fn config(&self) -> &NtlmConfig {
        &self.config
    }

    pub fn set_version(&mut self, version: [u8; NTLM_VERSION_SIZE]) {
        self.version = version;
    }

    pub fn session_key(&self) -> Option<[u8; SESSION_KEY_SIZE]> {
        self.session_key
    }
}

impl Default for Ntlm {
    fn default() -> Self {
        Self::with_config(Default::default())
    }
}

impl SspiImpl for Ntlm {
    type CredentialsHandle = Option<AuthIdentityBuffers>;
    type AuthenticationData = AuthIdentity;

    #[instrument(level = "trace", ret, fields(state = ?self.state), skip(self))]
    fn acquire_credentials_handle_impl(
        &mut self,
        builder: FilledAcquireCredentialsHandle<'_, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> crate::Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        if builder.credential_use == CredentialUse::Outbound && builder.auth_data.is_none() {
            return Err(crate::Error::new(
                crate::ErrorKind::NoCredentials,
                "The client must specify the auth data",
            ));
        }

        self.identity = builder.auth_data.cloned().map(AuthIdentityBuffers::from);

        Ok(AcquireCredentialsHandleResult {
            credentials_handle: self.identity.clone(),
            expiry: None,
        })
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, builder))]
    fn accept_security_context_impl(
        &mut self,
        builder: FilledAcceptSecurityContext<'_, Self::CredentialsHandle>,
    ) -> crate::Result<AcceptSecurityContextResult> {
        let input = builder
            .input
            .ok_or_else(|| crate::Error::new(crate::ErrorKind::InvalidToken, "Input buffers must be specified"))?;
        let status = match self.state {
            NtlmState::Initial => {
                let input_token = OwnedSecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;
                let output_token = OwnedSecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;

                self.state = NtlmState::Negotiate;
                server::read_negotiate(self, input_token.buffer.as_slice())?;

                server::write_challenge(self, &mut output_token.buffer)?
            }
            NtlmState::Authenticate => {
                let input_token = OwnedSecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;

                self.identity = builder.credentials_handle.cloned().flatten();

                if let Ok(sec_buffer) = OwnedSecurityBuffer::find_buffer(input, SecurityBufferType::ChannelBindings) {
                    self.channel_bindings = Some(ChannelBindings::from_bytes(&sec_buffer.buffer)?);
                }

                server::read_authenticate(self, input_token.buffer.as_slice())?
            }
            _ => {
                return Err(crate::Error::new(
                    crate::ErrorKind::OutOfSequence,
                    format!("got wrong NTLM state: {:?}", self.state),
                ))
            }
        };

        Ok(AcceptSecurityContextResult {
            status,
            flags: ServerResponseFlags::empty(),
            expiry: None,
        })
    }

    #[instrument(ret, fields(state = ?self.state), skip_all)]
    fn initialize_security_context_impl(
        &mut self,
        builder: &mut FilledInitializeSecurityContext<'_, Self::CredentialsHandle>,
    ) -> crate::Result<GeneratorInitSecurityContext> {
        Ok(self.initialize_security_context_impl(builder).into())
    }
}

impl Ntlm {
    pub(crate) fn initialize_security_context_impl(
        &mut self,
        builder: &mut FilledInitializeSecurityContext<'_, <Self as SspiImpl>::CredentialsHandle>,
    ) -> crate::Result<InitializeSecurityContextResult> {
        trace!(?builder);

        let status = match self.state {
            NtlmState::Initial => {
                let output_token = OwnedSecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                self.state = NtlmState::Negotiate;

                self.signing = builder.context_requirements.contains(ClientRequestFlags::INTEGRITY);
                self.sealing = builder
                    .context_requirements
                    .contains(ClientRequestFlags::CONFIDENTIALITY);

                if self.sealing {
                    self.signing = true; // sealing implies signing
                }

                client::write_negotiate(self, &mut output_token.buffer)?
            }
            NtlmState::Challenge => {
                let input = builder.input.as_ref().ok_or_else(|| {
                    crate::Error::new(
                        crate::ErrorKind::InvalidToken,
                        "Input buffers must be specified on subsequent calls",
                    )
                })?;
                let input_token = OwnedSecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;
                let output_token = OwnedSecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;

                if let Ok(sec_buffer) = OwnedSecurityBuffer::find_buffer(
                    builder.input.as_ref().unwrap(),
                    SecurityBufferType::ChannelBindings,
                ) {
                    self.channel_bindings = Some(ChannelBindings::from_bytes(&sec_buffer.buffer)?);
                }

                client::read_challenge(self, input_token.buffer.as_slice())?;

                client::write_authenticate(
                    self,
                    builder
                        .credentials_handle
                        .as_ref()
                        .expect("CredentialsHandle must be passed to the method")
                        .as_ref()
                        .expect("CredentialsHandle must be Some for the client's method"),
                    &mut output_token.buffer,
                )?
            }
            _ => {
                return Err(crate::Error::new(
                    crate::ErrorKind::OutOfSequence,
                    format!("Got wrong NTLM state: {:?}", self.state),
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

impl Sspi for Ntlm {
    #[instrument(level = "debug", ret, fields(state = ?self.state), skip_all)]
    fn complete_auth_token(&mut self, _token: &mut [OwnedSecurityBuffer]) -> crate::Result<SecurityStatus> {
        server::complete_authenticate(self)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, _flags))]
    fn encrypt_message(
        &mut self,
        _flags: EncryptionFlags,
        message: &mut [SecurityBuffer],
        sequence_number: u32,
    ) -> crate::Result<SecurityStatus> {
        if self.send_sealing_key.is_none() {
            self.complete_auth_token(&mut [])?;
        }

        SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?; // check if exists
        let data = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;

        let digest = compute_digest(&self.send_signing_key, sequence_number, data.data())?;

        let encrypted_data = self.send_sealing_key.as_mut().unwrap().process(data.data());
        if encrypted_data.len() < data.buf_len() {
            return Err(Error::new(ErrorKind::BufferTooSmall, "The Data buffer is too small"));
        }
        data.write_data(&encrypted_data)?;

        let checksum = self
            .send_sealing_key
            .as_mut()
            .unwrap()
            .process(&digest[0..SIGNATURE_CHECKSUM_SIZE]);

        let signature_buffer = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?;
        if signature_buffer.buf_len() < SIGNATURE_SIZE {
            return Err(Error::new(ErrorKind::BufferTooSmall, "The Token buffer is too small"));
        }
        let signature = compute_signature(&checksum, sequence_number);
        signature_buffer.write_data(signature.as_slice())?;

        Ok(SecurityStatus::Ok)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self, sequence_number))]
    fn decrypt_message(
        &mut self,
        message: &mut [SecurityBuffer],
        sequence_number: u32,
    ) -> crate::Result<DecryptionFlags> {
        if self.recv_sealing_key.is_none() {
            self.complete_auth_token(&mut [])?;
        }

        let encrypted = extract_encrypted_data(message)?;

        if encrypted.len() < 16 {
            return Err(Error::new(ErrorKind::MessageAltered, "Invalid encrypted message size!"));
        }

        let (signature, encrypted_message) = encrypted.split_at(16);

        let decrypted = self.recv_sealing_key.as_mut().unwrap().process(encrypted_message);

        save_decrypted_data(&decrypted, message)?;

        let digest = compute_digest(&self.recv_signing_key, sequence_number, &decrypted)?;
        let checksum = self
            .recv_sealing_key
            .as_mut()
            .unwrap()
            .process(&digest[0..SIGNATURE_CHECKSUM_SIZE]);
        let expected_signature = compute_signature(&checksum, sequence_number);

        if signature != expected_signature.as_ref() {
            return Err(Error::new(
                ErrorKind::MessageAltered,
                "Signature verification failed, something nasty is going on!",
            ));
        }

        Ok(DecryptionFlags::empty())
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_sizes(&mut self) -> crate::Result<ContextSizes> {
        Ok(ContextSizes {
            max_token: 2010,
            max_signature: 16,
            block: 0,
            security_trailer: 16,
        })
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_names(&mut self) -> crate::Result<ContextNames> {
        if let Some(identity_buffers) = &self.identity {
            let identity =
                AuthIdentity::try_from(identity_buffers).map_err(|e| Error::new(ErrorKind::InvalidParameter, e))?;

            Ok(ContextNames {
                username: identity.username,
            })
        } else {
            Err(crate::Error::new(
                crate::ErrorKind::NoCredentials,
                "Requested Names, but no credentials were provided",
            ))
        }
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_package_info(&mut self) -> crate::Result<PackageInfo> {
        crate::query_security_package_info(SecurityPackageType::Ntlm)
    }

    #[instrument(level = "debug", ret, fields(state = ?self.state), skip(self))]
    fn query_context_cert_trust_status(&mut self) -> crate::Result<CertTrustStatus> {
        Err(crate::Error::new(
            crate::ErrorKind::UnsupportedFunction,
            "Certificate trust status is not supported",
        ))
    }

    fn change_password(
        &mut self,
        _: crate::builders::ChangePassword,
    ) -> crate::Result<crate::generator::GeneratorChangePassword> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "NTLM does not support change pasword",
        ))
    }
}

impl SspiEx for Ntlm {
    #[instrument(level = "trace", ret, fields(state = ?self.state), skip(self))]
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) -> crate::Result<()> {
        self.identity = Some(identity.into());

        Ok(())
    }
}

impl NegotiateMessage {
    fn new(message: Vec<u8>) -> Self {
        Self { message }
    }
}

impl ChallengeMessage {
    fn new(message: Vec<u8>, target_info: Vec<u8>, server_challenge: [u8; CHALLENGE_SIZE], timestamp: u64) -> Self {
        Self {
            message,
            target_info,
            server_challenge,
            timestamp,
        }
    }
}

impl AuthenticateMessage {
    fn new(
        message: Vec<u8>,
        mic: Option<Mic>,
        target_info: Vec<u8>,
        client_challenge: [u8; CHALLENGE_SIZE],
        encrypted_random_session_key: Option<[u8; ENCRYPTED_RANDOM_SESSION_KEY_SIZE]>,
    ) -> Self {
        Self {
            message,
            mic,
            target_info,
            client_challenge,
            encrypted_random_session_key,
        }
    }
}

impl Mic {
    fn new(value: [u8; MESSAGE_INTEGRITY_CHECK_SIZE], offset: u8) -> Self {
        Self { value, offset }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct NegotiateFlags: u32 {
        /// W-bit
        /// requests 56-bit encryption
        const NTLM_SSP_NEGOTIATE56 = 0x8000_0000;

        /// V-bit
        /// requests explicit key exchange
        const NTLM_SSP_NEGOTIATE_KEY_EXCH = 0x4000_0000;

        /// U-bit
        /// requests an 128 bit session key
        const NTLM_SSP_NEGOTIATE128 = 0x2000_0000;

        /// r1
        const NTLM_SSP_NEGOTIATE_RESERVED1  = 0x1000_0000;

        /// r2
        const NTLM_SSP_NEGOTIATE_RESERVED2 = 0x0800_0000;

        /// r3
        const NTLM_SSP_NEGOTIATE_RESERVED3 = 0x0400_0000;

        /// r6
        const NTLM_SSP_NEGOTIATE_VERSION = 0x0200_0000;

        /// r4
        const NTLM_SSP_NEGOTIATE_RESERVED4 = 0x0100_0000;

        /// S-bit
        const NTLM_SSP_NEGOTIATE_TARGET_INFO = 0x0080_0000;

        /// R
        const NTLM_SSP_NEGOTIATE_REQUEST_NON_NT_SESSION_KEY = 0x0040_0000;

        /// r5
        const NTLM_SSP_NEGOTIATE_RESERVED5 = 0x0020_0000;

        /// Q
        const NTLM_SSP_NEGOTIATE_IDENTIFY = 0x0010_0000;

        /// P-bit
        /// NTLMv2 Session Security
        const NTLM_SSP_NEGOTIATE_EXTENDED_SESSION_SECURITY = 0x0008_0000;

        /// r6
        const NTLM_SSP_NEGOTIATE_RESERVED6 = 0x0004_0000;

        /// O
        const NTLM_SSP_NEGOTIATE_TARGET_TYPE_SERVER = 0x0002_0000;

        /// N
        const NTLM_SSP_NEGOTIATE_TARGET_TYPE_DOMAIN = 0x0001_0000;

        /// M-bit
        /// requests a signature block
        const NTLM_SSP_NEGOTIATE_ALWAYS_SIGN = 0x0000_8000;

        /// r7
        const NTLM_SSP_NEGOTIATE_RESERVED7 = 0x0000_4000;

        /// L-bit
        const NTLM_SSP_NEGOTIATE_WORKSTATION_SUPPLIED = 0x0000_2000;

        /// K-bit
        const NTLM_SSP_NEGOTIATE_DOMAIN_SUPPLIED = 0x0000_1000;

        /// J
        const NTLM_SSP_NEGOTIATE_ANONYMOUS = 0x0000_0800;

        /// r8
        const NTLM_SSP_NEGOTIATE_RESERVED8 = 0x0000_0400;

        /// H-bit
        /// NTLMv1 Session Security, deprecated, insecure and not supported by us
        const NTLM_SSP_NEGOTIATE_NTLM = 0x0000_0200;

        /// r9
        const NTLM_SSP_NEGOTIATE_RESERVED9 = 0x0000_0100;

        /// G-bit
        /// LM Session Security, deprecated, insecure and not supported by us
        const NTLM_SSP_NEGOTIATE_LM_KEY = 0x0000_0080;

        /// F
        const NTLM_SSP_NEGOTIATE_DATAGRAM = 0x0000_0040;

        /// E-bit
        /// session key negotiation with message confidentiality
        const NTLM_SSP_NEGOTIATE_SEAL = 0x0000_0020;

        /// D-bit
        const NTLM_SSP_NEGOTIATE_SIGN = 0x0000_0010;

        /// r10
        const NTLM_SSP_NEGOTIATE_SIGN_RESERVED10 = 0x0000_0008;

        /// C-bit
        const NTLM_SSP_NEGOTIATE_REQUEST_TARGET = 0x0000_0004;

        /// B-bit
        const NTLM_SSP_NEGOTIATE_OEM = 0x0000_0002;

        /// A-bit
        const NTLM_SSP_NEGOTIATE_UNICODE = 0x0000_0001;
    }
}

fn compute_digest(key: &[u8], seq_num: u32, data: &[u8]) -> io::Result<[u8; 16]> {
    let mut digest_data = Vec::with_capacity(SIGNATURE_SEQ_NUM_SIZE + data.len());
    digest_data.write_u32::<LittleEndian>(seq_num)?;
    digest_data.extend_from_slice(data);

    compute_hmac_md5(key, &digest_data)
}

fn compute_signature(checksum: &[u8], seq_num: u32) -> [u8; SIGNATURE_SIZE] {
    let mut signature = [0x00; SIGNATURE_SIZE];
    signature[..SIGNATURE_VERSION_SIZE].clone_from_slice(&MESSAGES_VERSION.to_le_bytes());
    signature[SIGNATURE_VERSION_SIZE..SIGNATURE_VERSION_SIZE + SIGNATURE_CHECKSUM_SIZE].clone_from_slice(checksum);
    signature[SIGNATURE_VERSION_SIZE + SIGNATURE_CHECKSUM_SIZE..].clone_from_slice(&seq_num.to_le_bytes());

    signature
}
