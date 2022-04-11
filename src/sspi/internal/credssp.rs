cfg_if::cfg_if! {
    if #[cfg(fuzzing)] {
        pub mod ts_request;
    } else {
        mod ts_request;
    }
}

pub use ts_request::TsRequest;

use std::io;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use rand::{rngs::OsRng, Rng};

use crate::{
    crypto::compute_sha256,
    sspi::{
        self,
        internal::SspiImpl,
        kerberos::Kerberos,
        ntlm::{AuthIdentity, AuthIdentityBuffers, Ntlm, SIGNATURE_SIZE},
        CertTrustStatus, ClientRequestFlags, ContextNames, ContextSizes, CredentialUse,
        DataRepresentation, DecryptionFlags, EncryptionFlags, FilledAcceptSecurityContext,
        FilledAcquireCredentialsHandle, FilledInitializeSecurityContext, PackageInfo,
        SecurityBuffer, SecurityBufferType, SecurityStatus, ServerRequestFlags, Sspi, SspiEx,
    },
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, InitializeSecurityContextResult,
};
use ts_request::{NONCE_SIZE, TS_REQUEST_VERSION};

pub const EARLY_USER_AUTH_RESULT_PDU_SIZE: usize = 4;

const HASH_MAGIC_LEN: usize = 38;
const SERVER_CLIENT_HASH_MAGIC: &[u8; HASH_MAGIC_LEN] = b"CredSSP Server-To-Client Binding Hash\0";
const CLIENT_SERVER_HASH_MAGIC: &[u8; HASH_MAGIC_LEN] = b"CredSSP Client-To-Server Binding Hash\0";

/// Provides an interface for implementing proxy credentials structures.
pub trait CredentialsProxy {
    type AuthenticationData;

    /// A method signature for implementing a behavior of searching and returning
    /// a user password based on a username and a domain provided as arguments.
    ///
    /// # Arguments
    ///
    /// * `username` - the username string
    /// * `domain` - the domain string (optional)
    fn auth_data_by_user(
        &mut self,
        username: String,
        domain: Option<String>,
    ) -> io::Result<Self::AuthenticationData>;
}

macro_rules! try_cred_ssp_server {
    ($e:expr, $ts_request:ident) => {
        match $e {
            Ok(v) => v,
            Err(e) => {
                let error = sspi::Error::from(e);
                $ts_request.error_code = Some(construct_error(&error));

                return Err(ServerError {
                    ts_request: $ts_request,
                    error,
                });
            }
        }
    };
}

/// Indicates to the `CredSspClient` whether or not to transfer
/// the credentials in the auth_info `TsRequest` field.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CredSspMode {
    WithCredentials,
    /// Indicates that the client requires credential-less logon over CredSSP (also known as "restricted admin mode").
    CredentialLess,
}

/// The result of a CredSSP client processing.
#[derive(Debug, Clone)]
pub enum ClientState {
    /// Used as a result of processing of negotiation tokens.
    ReplyNeeded(TsRequest),
    /// Used as a result of processing of authentication info.
    FinalMessage(TsRequest),
}

/// The result of a CredSSP server processing.
#[derive(Debug, Clone)]
pub enum ServerState {
    /// Used as a result of processing of negotiation tokens.
    ReplyNeeded(TsRequest),
    /// Used as a result of the final state. Contains result of processing of authentication info.
    Finished(AuthIdentity),
}

/// The error of a CredSSP server processing.
/// Contains `TsRequest` with non-empty `error_code`, and the error which caused the server to fail.
#[derive(Debug, Clone)]
pub struct ServerError {
    pub ts_request: TsRequest,
    pub error: sspi::Error,
}

/// The Early User Authorization Result PDU is sent from server to client
/// and is used to convey authorization information to the client.
/// This PDU is only sent by the server if the client advertised support for it
/// by specifying the ['HYBRID_EX protocol'](struct.SecurityProtocol.htlm)
/// of the [RDP Negotiation Request (RDP_NEG_REQ)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3)
/// and it MUST be sent immediately after the CredSSP handshake has completed.
#[derive(Debug, Copy, Clone, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum EarlyUserAuthResult {
    /// The user has permission to access the server.
    Success = 0,
    /// The user does not have permission to access the server.
    AccessDenied = 5,
}

impl EarlyUserAuthResult {
    pub fn from_buffer(mut stream: impl io::Read) -> Result<Self, io::Error> {
        let result = stream.read_u32::<LittleEndian>()?;

        EarlyUserAuthResult::from_u32(result).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Got invalid Early User Authorization Result: {:x}", result),
            )
        })
    }
    pub fn to_buffer(self, mut stream: impl io::Write) -> Result<(), io::Error> {
        stream.write_u32::<LittleEndian>(self.to_u32().unwrap())
    }
    pub fn buffer_len(self) -> usize {
        EARLY_USER_AUTH_RESULT_PDU_SIZE
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum CredSspState {
    NegoToken,
    AuthInfo,
    Final,
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum EndpointType {
    Client,
    Server,
}

/// Implements the CredSSP *client*. The client's credentials are to
/// be securely delegated to the server.
///
/// # MSDN
///
/// * [Glossary](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/97e4a826-1112-4ab4-8662-cfa58418b4c1)
#[derive(Debug, Clone)]
pub struct CredSspClient {
    state: CredSspState,
    context: Option<CredSspContext>,
    credentials: AuthIdentity,
    public_key: Vec<u8>,
    cred_ssp_mode: CredSspMode,
    client_nonce: [u8; NONCE_SIZE],
    credentials_handle: Option<AuthIdentityBuffers>,
    ts_request_version: u32,
}

impl CredSspClient {
    pub fn new(
        public_key: Vec<u8>,
        credentials: AuthIdentity,
        cred_ssp_mode: CredSspMode,
    ) -> sspi::Result<Self> {
        Ok(Self {
            state: CredSspState::NegoToken,
            context: None,
            credentials,
            public_key,
            cred_ssp_mode,
            client_nonce: OsRng::new()?.gen::<[u8; NONCE_SIZE]>(),
            credentials_handle: None,
            ts_request_version: TS_REQUEST_VERSION,
        })
    }

    pub fn new_with_version(
        public_key: Vec<u8>,
        credentials: AuthIdentity,
        cred_ssp_mode: CredSspMode,
        ts_request_version: u32,
    ) -> sspi::Result<Self> {
        Ok(Self {
            state: CredSspState::NegoToken,
            context: None,
            credentials,
            public_key,
            cred_ssp_mode,
            client_nonce: OsRng::new()?.gen::<[u8; NONCE_SIZE]>(),
            credentials_handle: None,
            ts_request_version,
        })
    }

    pub fn process(&mut self, mut ts_request: TsRequest) -> sspi::Result<ClientState> {
        ts_request.check_error()?;
        if let Some(ref mut context) = self.context {
            context.check_peer_version(ts_request.version)?;
        } else {
            self.context = Some(CredSspContext::new(SspiContext::Kerberos(
                Kerberos::new_client_from_env(),
            )));
            let AcquireCredentialsHandleResult {
                credentials_handle, ..
            } = self
                .context
                .as_mut()
                .unwrap()
                .sspi_context
                .acquire_credentials_handle()
                .with_auth_data(&self.credentials)
                .with_credential_use(CredentialUse::Outbound)
                .execute()?;
            self.credentials_handle = credentials_handle;
        }

        ts_request.version = self.ts_request_version;

        match self.state {
            CredSspState::NegoToken => {
                let input_token = SecurityBuffer::new(
                    ts_request.nego_tokens.take().unwrap_or_default(),
                    SecurityBufferType::Token,
                );
                let mut output_token = vec![SecurityBuffer::new(
                    Vec::with_capacity(1024),
                    SecurityBufferType::Token,
                )];

                let mut credentials_handle = self.credentials_handle.take();
                let result = self
                    .context
                    .as_mut()
                    .unwrap()
                    .sspi_context
                    .initialize_security_context()
                    .with_credentials_handle(&mut credentials_handle)
                    .with_context_requirements(ClientRequestFlags::empty())
                    .with_target_data_representation(DataRepresentation::Native)
                    .with_input(&mut [input_token])
                    .with_output(&mut output_token)
                    .execute()?;
                self.credentials_handle = credentials_handle;
                ts_request.nego_tokens = Some(output_token.remove(0).buffer);

                if result.status == SecurityStatus::Ok {
                    let peer_version = self.context.as_ref().unwrap().peer_version.expect(
                            "An encrypt public key client function cannot be fired without any incoming TSRequest",
                        );
                    ts_request.pub_key_auth =
                        Some(self.context.as_mut().unwrap().encrypt_public_key(
                            self.public_key.as_ref(),
                            EndpointType::Client,
                            &Some(self.client_nonce),
                            peer_version,
                        )?);
                    ts_request.client_nonce = Some(self.client_nonce);
                    self.state = CredSspState::AuthInfo;
                }

                Ok(ClientState::ReplyNeeded(ts_request))
            }
            CredSspState::AuthInfo => {
                ts_request.nego_tokens = None;

                let pub_key_auth = ts_request.pub_key_auth.take().ok_or_else(|| {
                    sspi::Error::new(
                        sspi::ErrorKind::InvalidToken,
                        String::from("Expected an encrypted public key"),
                    )
                })?;
                let peer_version =
                        self.context.as_ref().unwrap().peer_version.expect(
                            "An decrypt public key client function cannot be fired without any incoming TSRequest",
                        );
                self.context.as_mut().unwrap().decrypt_public_key(
                    self.public_key.as_ref(),
                    pub_key_auth.as_ref(),
                    EndpointType::Client,
                    &Some(self.client_nonce),
                    peer_version,
                )?;

                ts_request.auth_info =
                    Some(self.context.as_mut().unwrap().encrypt_ts_credentials(
                        &self.credentials.clone().into(),
                        self.cred_ssp_mode,
                    )?);

                self.state = CredSspState::Final;

                Ok(ClientState::FinalMessage(ts_request))
            }
            CredSspState::Final => panic!(
                "CredSSP client's 'process' method must not be fired after the 'Finished' state"
            ),
        }
    }
}

/// Implements the CredSSP *server*. The client's credentials
/// securely delegated to the server for authentication using TLS.
///
/// # MSDN
///
/// * [Glossary](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/97e4a826-1112-4ab4-8662-cfa58418b4c1)
#[derive(Debug, Clone)]
pub struct CredSspServer<C: CredentialsProxy<AuthenticationData = AuthIdentity>> {
    credentials: C,
    state: CredSspState,
    context: Option<CredSspContext>,
    public_key: Vec<u8>,
    credentials_handle: Option<AuthIdentityBuffers>,
    ts_request_version: u32,
}

impl<C: CredentialsProxy<AuthenticationData = AuthIdentity>> CredSspServer<C> {
    pub fn new(public_key: Vec<u8>, credentials: C) -> sspi::Result<Self> {
        Ok(Self {
            state: CredSspState::NegoToken,
            context: None,
            credentials,
            public_key,
            credentials_handle: None,
            ts_request_version: TS_REQUEST_VERSION,
        })
    }

    pub fn new_with_version(
        public_key: Vec<u8>,
        credentials: C,
        ts_request_version: u32,
    ) -> sspi::Result<Self> {
        Ok(Self {
            state: CredSspState::NegoToken,
            context: None,
            credentials,
            public_key,
            credentials_handle: None,
            ts_request_version,
        })
    }

    pub fn process(&mut self, mut ts_request: TsRequest) -> Result<ServerState, ServerError> {
        if self.context.is_none() {
            self.context = Some(CredSspContext::new(SspiContext::Kerberos(
                Kerberos::new_server_from_env(),
            )));
            let AcquireCredentialsHandleResult {
                credentials_handle, ..
            } = try_cred_ssp_server!(
                self.context
                    .as_mut()
                    .unwrap()
                    .sspi_context
                    .acquire_credentials_handle()
                    .with_credential_use(CredentialUse::Inbound)
                    .execute(),
                ts_request
            );
            self.credentials_handle = credentials_handle;
        }
        try_cred_ssp_server!(
            self.context
                .as_mut()
                .unwrap()
                .check_peer_version(ts_request.version),
            ts_request
        );

        ts_request.version = self.ts_request_version;

        match self.state {
            CredSspState::AuthInfo => {
                let auth_info = try_cred_ssp_server!(
                    ts_request.auth_info.take().ok_or_else(|| {
                        sspi::Error::new(
                            sspi::ErrorKind::InvalidToken,
                            String::from("Expected an encrypted ts credentials"),
                        )
                    }),
                    ts_request
                );

                let read_credentials = try_cred_ssp_server!(
                    self.context
                        .as_mut()
                        .unwrap()
                        .decrypt_ts_credentials(&auth_info),
                    ts_request
                );
                self.state = CredSspState::Final;

                Ok(ServerState::Finished(read_credentials.into()))
            }
            CredSspState::NegoToken => {
                let input = try_cred_ssp_server!(
                    ts_request.nego_tokens.take().ok_or_else(|| {
                        sspi::Error::new(
                            sspi::ErrorKind::InvalidToken,
                            String::from("Got empty nego_tokens field"),
                        )
                    }),
                    ts_request
                );
                let input_token = SecurityBuffer::new(input, SecurityBufferType::Token);
                let mut output_token = vec![SecurityBuffer::new(
                    Vec::with_capacity(1024),
                    SecurityBufferType::Token,
                )];

                let mut credentials_handle = self.credentials_handle.take();
                match try_cred_ssp_server!(
                    self.context
                        .as_mut()
                        .unwrap()
                        .sspi_context
                        .accept_security_context()
                        .with_credentials_handle(&mut credentials_handle)
                        .with_context_requirements(ServerRequestFlags::empty())
                        .with_target_data_representation(DataRepresentation::Native)
                        .with_input(&mut [input_token])
                        .with_output(&mut output_token)
                        .execute(),
                    ts_request
                ) {
                    AcceptSecurityContextResult { status, .. }
                        if status == SecurityStatus::ContinueNeeded =>
                    {
                        ts_request.nego_tokens = Some(output_token.remove(0).buffer);
                    }
                    AcceptSecurityContextResult { status, .. }
                        if status == SecurityStatus::CompleteNeeded =>
                    {
                        let ContextNames { username, domain } = try_cred_ssp_server!(
                            self.context
                                .as_mut()
                                .unwrap()
                                .sspi_context
                                .query_context_names(),
                            ts_request
                        );
                        let auth_data = try_cred_ssp_server!(
                            self.credentials
                                .auth_data_by_user(username, domain)
                                .map_err(|e| sspi::Error::new(
                                    sspi::ErrorKind::LogonDenied,
                                    e.to_string()
                                )),
                            ts_request
                        );
                        self.context
                            .as_mut()
                            .unwrap()
                            .sspi_context
                            .custom_set_auth_identity(auth_data);

                        try_cred_ssp_server!(
                            self.context
                                .as_mut()
                                .unwrap()
                                .sspi_context
                                .complete_auth_token(&mut []),
                            ts_request
                        );
                        ts_request.nego_tokens = None;

                        let pub_key_auth = try_cred_ssp_server!(
                            ts_request.pub_key_auth.take().ok_or_else(|| {
                                sspi::Error::new(
                                    sspi::ErrorKind::InvalidToken,
                                    String::from("Expected an encrypted public key"),
                                )
                            }),
                            ts_request
                        );
                        let peer_version = self.context.as_ref().unwrap().peer_version.expect(
                            "An decrypt public key server function cannot be fired without any incoming TSRequest",
                        );
                        try_cred_ssp_server!(
                            self.context.as_mut().unwrap().decrypt_public_key(
                                self.public_key.as_ref(),
                                pub_key_auth.as_ref(),
                                EndpointType::Server,
                                &ts_request.client_nonce,
                                peer_version,
                            ),
                            ts_request
                        );
                        let pub_key_auth = try_cred_ssp_server!(
                            self.context.as_mut().unwrap().encrypt_public_key(
                                self.public_key.as_ref(),
                                EndpointType::Server,
                                &ts_request.client_nonce,
                                peer_version,
                            ),
                            ts_request
                        );
                        ts_request.pub_key_auth = Some(pub_key_auth);

                        self.state = CredSspState::AuthInfo;
                    }
                    _ => unreachable!(),
                };
                self.credentials_handle = credentials_handle;

                Ok(ServerState::ReplyNeeded(ts_request))
            }
            CredSspState::Final => panic!(
                "CredSSP server's 'process' method must not be fired after the 'Finished' state"
            ),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum SspiContext {
    #[allow(dead_code)]
    Ntlm(Ntlm),
    Kerberos(Kerberos),
}

impl SspiImpl for SspiContext {
    type CredentialsHandle = Option<AuthIdentityBuffers>;
    type AuthenticationData = AuthIdentity;

    fn acquire_credentials_handle_impl(
        &mut self,
        builder: FilledAcquireCredentialsHandle<
            '_,
            Self,
            Self::CredentialsHandle,
            Self::AuthenticationData,
        >,
    ) -> sspi::Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        match self {
            SspiContext::Ntlm(ntlm) => builder.transform(ntlm).execute(),
            SspiContext::Kerberos(kerberos) => builder.transform(kerberos).execute(),
        }
    }

    fn initialize_security_context_impl(
        &mut self,
        builder: FilledInitializeSecurityContext<'_, Self, Self::CredentialsHandle>,
    ) -> sspi::Result<InitializeSecurityContextResult> {
        match self {
            SspiContext::Ntlm(ntlm) => builder.transform(ntlm).execute(),
            SspiContext::Kerberos(kerberos) => builder.transform(kerberos).execute(),
        }
    }

    fn accept_security_context_impl(
        &mut self,
        builder: FilledAcceptSecurityContext<'_, Self, Self::CredentialsHandle>,
    ) -> sspi::Result<AcceptSecurityContextResult> {
        match self {
            SspiContext::Ntlm(ntlm) => builder.transform(ntlm).execute(),
            SspiContext::Kerberos(kerberos) => builder.transform(kerberos).execute(),
        }
    }
}

impl Sspi for SspiContext {
    fn complete_auth_token(
        &mut self,
        token: &mut [SecurityBuffer],
    ) -> sspi::Result<SecurityStatus> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.complete_auth_token(token),
            SspiContext::Kerberos(kerberos) => kerberos.complete_auth_token(token),
        }
    }

    fn encrypt_message(
        &mut self,
        flags: EncryptionFlags,
        message: &mut [SecurityBuffer],
        sequence_number: u32,
    ) -> sspi::Result<SecurityStatus> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.encrypt_message(flags, message, sequence_number),
            SspiContext::Kerberos(kerberos) => {
                kerberos.encrypt_message(flags, message, sequence_number)
            }
        }
    }

    fn decrypt_message(
        &mut self,
        message: &mut [SecurityBuffer],
        sequence_number: u32,
    ) -> sspi::Result<DecryptionFlags> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.decrypt_message(message, sequence_number),
            SspiContext::Kerberos(kerberos) => kerberos.decrypt_message(message, sequence_number),
        }
    }

    fn query_context_sizes(&mut self) -> sspi::Result<ContextSizes> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_sizes(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_sizes(),
        }
    }
    fn query_context_names(&mut self) -> sspi::Result<ContextNames> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_names(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_names(),
        }
    }
    fn query_context_package_info(&mut self) -> sspi::Result<PackageInfo> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_package_info(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_package_info(),
        }
    }
    fn query_context_cert_trust_status(&mut self) -> sspi::Result<CertTrustStatus> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_cert_trust_status(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_cert_trust_status(),
        }
    }
}

impl SspiEx for SspiContext {
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.custom_set_auth_identity(identity),
            SspiContext::Kerberos(kerberos) => kerberos.custom_set_auth_identity(identity),
        }
    }
}

#[derive(Debug, Clone)]
struct CredSspContext {
    peer_version: Option<u32>,
    sspi_context: SspiContext,
    send_seq_num: u32,
    recv_seq_num: u32,
}

impl CredSspContext {
    fn new(sspi_context: SspiContext) -> Self {
        Self {
            peer_version: None,
            send_seq_num: 0,
            recv_seq_num: 0,
            sspi_context,
        }
    }

    fn check_peer_version(&mut self, other_peer_version: u32) -> sspi::Result<()> {
        if let Some(peer_version) = self.peer_version {
            if peer_version != other_peer_version {
                Err(sspi::Error::new(
                    sspi::ErrorKind::MessageAltered,
                    format!(
                        "CredSSP peer changed protocol version from {} to {}",
                        peer_version, other_peer_version
                    ),
                ))
            } else {
                Ok(())
            }
        } else {
            self.peer_version = Some(other_peer_version);

            Ok(())
        }
    }

    fn encrypt_public_key(
        &mut self,
        public_key: &[u8],
        endpoint: EndpointType,
        client_nonce: &Option<[u8; NONCE_SIZE]>,
        peer_version: u32,
    ) -> sspi::Result<Vec<u8>> {
        let hash_magic = match endpoint {
            EndpointType::Client => CLIENT_SERVER_HASH_MAGIC,
            EndpointType::Server => SERVER_CLIENT_HASH_MAGIC,
        };

        if peer_version < 5 {
            self.encrypt_public_key_echo(public_key, endpoint)
        } else {
            self.encrypt_public_key_hash(
                public_key,
                hash_magic,
                &client_nonce.ok_or(sspi::Error::new(
                    sspi::ErrorKind::InvalidToken,
                    String::from(
                        "client nonce from the TSRequest is empty, but a peer version is >= 5",
                    ),
                ))?,
            )
        }
    }

    fn decrypt_public_key(
        &mut self,
        public_key: &[u8],
        encrypted_public_key: &[u8],
        endpoint: EndpointType,
        client_nonce: &Option<[u8; NONCE_SIZE]>,
        peer_version: u32,
    ) -> sspi::Result<()> {
        let hash_magic = match endpoint {
            EndpointType::Client => SERVER_CLIENT_HASH_MAGIC,
            EndpointType::Server => CLIENT_SERVER_HASH_MAGIC,
        };

        if peer_version < 5 {
            self.decrypt_public_key_echo(public_key, encrypted_public_key, endpoint)
        } else {
            self.decrypt_public_key_hash(
                public_key,
                encrypted_public_key,
                hash_magic,
                &client_nonce.ok_or(sspi::Error::new(
                    sspi::ErrorKind::InvalidToken,
                    String::from(
                        "client nonce from the TSRequest is empty, but a peer version is >= 5",
                    ),
                ))?,
            )
        }
    }

    fn encrypt_public_key_echo(
        &mut self,
        public_key: &[u8],
        endpoint: EndpointType,
    ) -> sspi::Result<Vec<u8>> {
        let mut public_key = public_key.to_vec();

        match self.sspi_context {
            SspiContext::Ntlm(_) => {
                if endpoint == EndpointType::Server {
                    integer_increment_le(&mut public_key);
                }
            }
            SspiContext::Kerberos(_) => {}
        };

        self.encrypt_message(&public_key)
    }

    fn encrypt_public_key_hash(
        &mut self,
        public_key: &[u8],
        hash_magic: &[u8],
        client_nonce: &[u8],
    ) -> sspi::Result<Vec<u8>> {
        let mut data = hash_magic.to_vec();
        data.extend(client_nonce);
        data.extend(public_key);
        let encrypted_public_key = compute_sha256(&data);

        match &mut self.sspi_context {
            SspiContext::Ntlm(_) => self.encrypt_message(&encrypted_public_key),
            SspiContext::Kerberos(kerberos) => {
                let mut wrap_token = WrapToken::with_seq_number(kerberos.next_seq_number() as u64);

                let mut payload = encrypted_public_key.to_vec();
                payload.extend_from_slice(&wrap_token.header());

                println!("payload len: {}", payload.len());

                let checksum = self.encrypt_message(&payload)?;
                println!("check len: {}", checksum.len());

                wrap_token.set_rrc(28);

                let checksum = rotate_right(checksum, 48);

                wrap_token.set_checksum(checksum);

                let mut raw_wrap_token = Vec::with_capacity(92);
                wrap_token.encode(&mut raw_wrap_token)?;

                println!("res token len: {:?}", raw_wrap_token.len());

                Ok(raw_wrap_token)
            }
        }
    }

    fn decrypt_public_key_echo(
        &mut self,
        public_key: &[u8],
        encrypted_public_key: &[u8],
        endpoint: EndpointType,
    ) -> sspi::Result<()> {
        let mut decrypted_public_key = self.decrypt_message(encrypted_public_key)?;
        if endpoint == EndpointType::Client {
            integer_decrement_le(&mut decrypted_public_key);
        }

        if public_key != decrypted_public_key.as_slice() {
            return Err(sspi::Error::new(
                sspi::ErrorKind::MessageAltered,
                String::from("Could not verify a public key echo"),
            ));
        }

        Ok(())
    }

    fn decrypt_public_key_hash(
        &mut self,
        public_key: &[u8],
        encrypted_public_key: &[u8],
        hash_magic: &[u8],
        client_nonce: &[u8],
    ) -> sspi::Result<()> {
        let decrypted_public_key = self.decrypt_message(encrypted_public_key)?;

        let mut data = hash_magic.to_vec();
        data.extend(client_nonce);
        data.extend(public_key);
        let expected_public_key = compute_sha256(&data);

        if expected_public_key.as_ref() != decrypted_public_key.as_slice() {
            return Err(sspi::Error::new(
                sspi::ErrorKind::MessageAltered,
                String::from("Could not verify a public key hash"),
            ));
        }

        Ok(())
    }

    fn encrypt_ts_credentials(
        &mut self,
        credentials: &AuthIdentityBuffers,
        cred_ssp_mode: CredSspMode,
    ) -> sspi::Result<Vec<u8>> {
        let ts_credentials = ts_request::write_ts_credentials(credentials, cred_ssp_mode)?;

        self.encrypt_message(&ts_credentials)
    }

    fn decrypt_ts_credentials(&mut self, auth_info: &[u8]) -> sspi::Result<AuthIdentityBuffers> {
        let ts_credentials_buffer = self.decrypt_message(auth_info)?;

        Ok(ts_request::read_ts_credentials(
            ts_credentials_buffer.as_slice(),
        )?)
    }

    fn encrypt_message(&mut self, input: &[u8]) -> sspi::Result<Vec<u8>> {
        let mut buffers = vec![
            SecurityBuffer::new(Vec::with_capacity(1024), SecurityBufferType::Token),
            SecurityBuffer::new(input.to_vec(), SecurityBufferType::Data),
        ];

        let send_seq_num = self.send_seq_num;

        self.sspi_context
            .encrypt_message(EncryptionFlags::empty(), &mut buffers, send_seq_num)?;

        let mut output = SecurityBuffer::find_buffer(&buffers, SecurityBufferType::Token)?
            .buffer
            .clone();
        output.append(
            &mut SecurityBuffer::find_buffer_mut(&mut buffers, SecurityBufferType::Data)?.buffer,
        );

        self.send_seq_num += 1;

        // there will be magic transform for the kerberos

        Ok(output)
    }

    fn decrypt_message(&mut self, input: &[u8]) -> sspi::Result<Vec<u8>> {
        let (signature, data) = input.split_at(SIGNATURE_SIZE);

        let mut buffers = vec![
            SecurityBuffer::new(data.to_vec(), SecurityBufferType::Data),
            SecurityBuffer::new(signature.to_vec(), SecurityBufferType::Token),
        ];

        let recv_seq_num = self.recv_seq_num;

        self.sspi_context
            .decrypt_message(&mut buffers, recv_seq_num)?;

        let output = SecurityBuffer::find_buffer(&buffers, SecurityBufferType::Data)?
            .buffer
            .clone();

        self.recv_seq_num += 1;

        Ok(output)
    }
}

fn integer_decrement_le(buffer: &mut [u8]) {
    for elem in buffer.iter_mut() {
        let (value, overflow) = elem.overflowing_sub(1);
        *elem = value;
        if !overflow {
            break;
        }
    }
}

fn integer_increment_le(buffer: &mut [u8]) {
    for elem in buffer.iter_mut() {
        let (value, overflow) = elem.overflowing_add(1);
        *elem = value;
        if !overflow {
            break;
        }
    }
}

fn construct_error(e: &sspi::Error) -> u32 {
    ((e.error_type as i64 & 0x0000_FFFF) | (0x7 << 16) | 0xC000_0000) as u32
}
