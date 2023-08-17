cfg_if::cfg_if! {
    if #[cfg(fuzzing)] {
        pub mod ts_request;
    } else {
        mod ts_request;
    }
}
#[cfg(feature = "tsssp")]
pub mod sspi_cred_ssp;

use std::io;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use rand::rngs::OsRng;
use rand::Rng;
pub use ts_request::{NStatusCode, TsRequest};
use ts_request::{NONCE_SIZE, TS_REQUEST_VERSION};

#[cfg(feature = "tsssp")]
use self::sspi_cred_ssp::SspiCredSsp;
use crate::builders::{ChangePassword, EmptyInitializeSecurityContext};
use crate::crypto::compute_sha256;
use crate::kerberos::config::KerberosConfig;
use crate::kerberos::{self, Kerberos};
use crate::ntlm::{self, Ntlm, NtlmConfig, SIGNATURE_SIZE};
use crate::pku2u::{self, Pku2u, Pku2uConfig};
use crate::{
    negotiate, AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers,
    CertContext, CertTrustStatus, ClientRequestFlags, ConnectionInfo, ContextNames, ContextSizes, CredentialUse,
    Credentials, CredentialsBuffers, DataRepresentation, DecryptionFlags, EncryptionFlags, Error, ErrorKind,
    FilledAcceptSecurityContext, FilledAcquireCredentialsHandle, FilledInitializeSecurityContext,
    InitializeSecurityContextResult, Negotiate, NegotiateConfig, PackageInfo, SecurityBuffer, SecurityBufferType,
    SecurityStatus, ServerRequestFlags, Sspi, SspiEx, SspiImpl, StreamSizes,
};

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
    fn auth_data_by_user(&mut self, username: String, domain: Option<String>) -> io::Result<Self::AuthenticationData>;
}

macro_rules! try_cred_ssp_server {
    ($e:expr, $ts_request:ident) => {
        match $e {
            Ok(v) => v,
            Err(e) => {
                let error = crate::Error::from(e);
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
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
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
    pub error: crate::Error,
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

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum CredSspState {
    NegoToken,
    AuthInfo,
    Final,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum EndpointType {
    Client,
    Server,
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ClientMode {
    Negotiate(NegotiateConfig),
    Kerberos(KerberosConfig),
    Pku2u(Pku2uConfig),
    Ntlm(NtlmConfig),
}

/// Implements the CredSSP *client*. The client's credentials are to
/// be securely delegated to the server.
///
/// # MSDN
///
/// * [Glossary](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/97e4a826-1112-4ab4-8662-cfa58418b4c1)
#[derive(Debug)]
pub struct CredSspClient {
    state: CredSspState,
    context: Option<CredSspContext>,
    credentials: AuthIdentity,
    public_key: Vec<u8>,
    cred_ssp_mode: CredSspMode,
    client_nonce: [u8; NONCE_SIZE],
    credentials_handle: Option<AuthIdentityBuffers>,
    ts_request_version: u32,
    client_mode: Option<ClientMode>,
    service_principal_name: String,
}

impl CredSspClient {
    pub fn new(
        public_key: Vec<u8>,
        credentials: AuthIdentity,
        cred_ssp_mode: CredSspMode,
        client_mode: ClientMode,
        service_principal_name: String,
    ) -> crate::Result<Self> {
        Ok(Self {
            state: CredSspState::NegoToken,
            context: None,
            credentials,
            public_key,
            cred_ssp_mode,
            client_nonce: OsRng.gen::<[u8; NONCE_SIZE]>(),
            credentials_handle: None,
            ts_request_version: TS_REQUEST_VERSION,
            client_mode: Some(client_mode),
            service_principal_name,
        })
    }

    pub fn new_with_version(
        public_key: Vec<u8>,
        credentials: AuthIdentity,
        cred_ssp_mode: CredSspMode,
        ts_request_version: u32,
        client_mode: ClientMode,
        service_principal_name: String,
    ) -> crate::Result<Self> {
        Ok(Self {
            state: CredSspState::NegoToken,
            context: None,
            credentials,
            public_key,
            cred_ssp_mode,
            client_nonce: OsRng.gen::<[u8; NONCE_SIZE]>(),
            credentials_handle: None,
            ts_request_version,
            client_mode: Some(client_mode),
            service_principal_name,
        })
    }

    #[instrument(fields(state = ?self.state), skip_all)]
    pub fn process(&mut self, mut ts_request: TsRequest) -> crate::Result<ClientState> {
        ts_request.check_error()?;
        if let Some(ref mut context) = self.context {
            context.check_peer_version(ts_request.version)?;
        } else {
            self.context = match self
                .client_mode
                .take()
                .expect("CredSsp client mode should never be empty")
            {
                ClientMode::Negotiate(negotiate_config) => Some(CredSspContext::new(SspiContext::Negotiate(
                    Negotiate::new(negotiate_config)?,
                ))),
                ClientMode::Kerberos(kerberos_config) => Some(CredSspContext::new(SspiContext::Kerberos(
                    Kerberos::new_client_from_config(kerberos_config)?,
                ))),
                ClientMode::Pku2u(pku2u) => Some(CredSspContext::new(SspiContext::Pku2u(
                    Pku2u::new_client_from_config(pku2u)?,
                ))),
                ClientMode::Ntlm(ntlm) => Some(CredSspContext::new(SspiContext::Ntlm(Ntlm::with_config(ntlm)))),
            };
            let AcquireCredentialsHandleResult { credentials_handle, .. } = self
                .context
                .as_mut()
                .unwrap()
                .sspi_context
                .acquire_credentials_handle()
                .with_auth_data(&Credentials::AuthIdentity(self.credentials.clone()))
                .with_credential_use(CredentialUse::Outbound)
                .execute()?;
            self.credentials_handle = credentials_handle.map(|c| c.auth_identity().unwrap());
        }

        ts_request.version = self.ts_request_version;

        match self.state {
            CredSspState::NegoToken => {
                let mut input_token = [SecurityBuffer::new(
                    ts_request.nego_tokens.take().unwrap_or_default(),
                    SecurityBufferType::Token,
                )];
                let mut output_token = vec![SecurityBuffer::new(Vec::with_capacity(1024), SecurityBufferType::Token)];

                let mut credentials_handle = self.credentials_handle.take().map(CredentialsBuffers::AuthIdentity);
                let cred_ssp_context = self.context.as_mut().unwrap();
                let mut builder = EmptyInitializeSecurityContext::<<SspiContext as SspiImpl>::CredentialsHandle>::new()
                    .with_credentials_handle(&mut credentials_handle)
                    .with_context_requirements(ClientRequestFlags::MUTUAL_AUTH | ClientRequestFlags::USE_SESSION_KEY)
                    .with_target_data_representation(DataRepresentation::Native)
                    .with_target_name(&self.service_principal_name)
                    .with_input(&mut input_token)
                    .with_output(&mut output_token);
                let result = cred_ssp_context
                    .sspi_context
                    .initialize_security_context_impl(&mut builder)?;
                self.credentials_handle = credentials_handle.map(|c| c.auth_identity().unwrap());
                ts_request.nego_tokens = Some(output_token.remove(0).buffer);

                if result.status == SecurityStatus::Ok {
                    info!("CredSSp finished NLA stage.");

                    let peer_version =
                        self.context.as_ref().unwrap().peer_version.expect(
                            "An encrypt public key client function cannot be fired without any incoming TSRequest",
                        );
                    ts_request.pub_key_auth = Some(self.context.as_mut().unwrap().encrypt_public_key(
                        self.public_key.as_ref(),
                        EndpointType::Client,
                        &Some(self.client_nonce),
                        peer_version,
                    )?);
                    ts_request.client_nonce = Some(self.client_nonce);

                    if let Some(nego_tokens) = &ts_request.nego_tokens {
                        if nego_tokens.is_empty() {
                            ts_request.nego_tokens = None;
                        }
                    }

                    self.state = CredSspState::AuthInfo;
                }

                Ok(ClientState::ReplyNeeded(ts_request))
            }
            CredSspState::AuthInfo => {
                ts_request.nego_tokens = None;

                let pub_key_auth = ts_request.pub_key_auth.take().ok_or_else(|| {
                    crate::Error::new(
                        crate::ErrorKind::InvalidToken,
                        String::from("Expected an encrypted public key"),
                    )
                })?;
                let peer_version = self
                    .context
                    .as_ref()
                    .unwrap()
                    .peer_version
                    .expect("An decrypt public key client function cannot be fired without any incoming TSRequest");
                self.context.as_mut().unwrap().decrypt_public_key(
                    self.public_key.as_ref(),
                    pub_key_auth.as_ref(),
                    EndpointType::Client,
                    &Some(self.client_nonce),
                    peer_version,
                )?;

                let auth_identity: AuthIdentityBuffers = self.credentials.clone().into();
                ts_request.auth_info =
                    Some(self.context.as_mut().unwrap().encrypt_ts_credentials(
                        &CredentialsBuffers::AuthIdentity(auth_identity),
                        self.cred_ssp_mode,
                    )?);
                info!("tscredentials has been written");

                self.state = CredSspState::Final;

                Ok(ClientState::FinalMessage(ts_request))
            }
            CredSspState::Final => Err(Error::new(
                ErrorKind::InternalError,
                "CredSSP client's 'process' method must not be fired after the 'Finished' state",
            )),
        }
    }
}

/// Implements the CredSSP *server*. The client's credentials
/// securely delegated to the server for authentication using TLS.
///
/// # MSDN
///
/// * [Glossary](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/97e4a826-1112-4ab4-8662-cfa58418b4c1)
#[derive(Debug)]
pub struct CredSspServer<C: CredentialsProxy<AuthenticationData = AuthIdentity>> {
    credentials: C,
    state: CredSspState,
    context: Option<CredSspContext>,
    public_key: Vec<u8>,
    credentials_handle: Option<AuthIdentityBuffers>,
    ts_request_version: u32,
    context_config: Option<ClientMode>,
}

impl<C: CredentialsProxy<AuthenticationData = AuthIdentity>> CredSspServer<C> {
    pub fn new(public_key: Vec<u8>, credentials: C, client_mode: ClientMode) -> crate::Result<Self> {
        Ok(Self {
            state: CredSspState::NegoToken,
            context: None,
            credentials,
            public_key,
            credentials_handle: None,
            ts_request_version: TS_REQUEST_VERSION,
            context_config: Some(client_mode),
        })
    }

    pub fn new_with_version(
        public_key: Vec<u8>,
        credentials: C,
        ts_request_version: u32,
        client_mode: ClientMode,
    ) -> crate::Result<Self> {
        Ok(Self {
            state: CredSspState::NegoToken,
            context: None,
            credentials,
            public_key,
            credentials_handle: None,
            ts_request_version,
            context_config: Some(client_mode),
        })
    }

    #[allow(clippy::result_large_err)]
    #[instrument(fields(state = ?self.state), skip_all)]
    pub fn process(&mut self, mut ts_request: TsRequest) -> Result<ServerState, ServerError> {
        if self.context.is_none() {
            self.context = match self
                .context_config
                .take()
                .expect("CredSsp client mode should never be empty")
            {
                ClientMode::Negotiate(_) => {
                    return Err(ServerError {
                        ts_request,
                        error: crate::Error::new(
                            ErrorKind::UnsupportedFunction,
                            "Negotiate module is not supported for the CredSsp server",
                        ),
                    })
                }
                ClientMode::Kerberos(kerberos_config) => Some(CredSspContext::new(SspiContext::Kerberos(
                    try_cred_ssp_server!(Kerberos::new_server_from_config(kerberos_config), ts_request),
                ))),
                ClientMode::Ntlm(ntlm) => Some(CredSspContext::new(SspiContext::Ntlm(Ntlm::with_config(ntlm)))),
                ClientMode::Pku2u(pku2u) => Some(CredSspContext::new(SspiContext::Pku2u(try_cred_ssp_server!(
                    Pku2u::new_server_from_config(pku2u),
                    ts_request
                )))),
            };
            let AcquireCredentialsHandleResult { credentials_handle, .. } = try_cred_ssp_server!(
                self.context
                    .as_mut()
                    .unwrap()
                    .sspi_context
                    .acquire_credentials_handle()
                    .with_credential_use(CredentialUse::Inbound)
                    .execute(),
                ts_request
            );
            self.credentials_handle = credentials_handle.map(|c| c.auth_identity().unwrap());
        }
        try_cred_ssp_server!(
            self.context.as_mut().unwrap().check_peer_version(ts_request.version),
            ts_request
        );

        ts_request.version = self.ts_request_version;

        match self.state {
            CredSspState::AuthInfo => {
                let auth_info = try_cred_ssp_server!(
                    ts_request.auth_info.take().ok_or_else(|| {
                        crate::Error::new(
                            crate::ErrorKind::InvalidToken,
                            String::from("Expected an encrypted ts credentials"),
                        )
                    }),
                    ts_request
                );

                let read_credentials = try_cred_ssp_server!(
                    self.context.as_mut().unwrap().decrypt_ts_credentials(&auth_info),
                    ts_request
                );

                self.state = CredSspState::Final;

                Ok(ServerState::Finished(read_credentials.auth_identity().unwrap().into()))
            }
            CredSspState::NegoToken => {
                let input = ts_request.nego_tokens.take().unwrap_or_default();
                let input_token = SecurityBuffer::new(input, SecurityBufferType::Token);
                let mut output_token = vec![SecurityBuffer::new(Vec::with_capacity(1024), SecurityBufferType::Token)];

                let mut credentials_handle = self.credentials_handle.take().map(CredentialsBuffers::AuthIdentity);
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
                    AcceptSecurityContextResult { status, .. } if status == SecurityStatus::ContinueNeeded => {
                        ts_request.nego_tokens = Some(output_token.remove(0).buffer);
                    }
                    AcceptSecurityContextResult { status, .. } if status == SecurityStatus::CompleteNeeded => {
                        let ContextNames { username, domain } = try_cred_ssp_server!(
                            self.context.as_mut().unwrap().sspi_context.query_context_names(),
                            ts_request
                        );
                        let auth_data = try_cred_ssp_server!(
                            self.credentials
                                .auth_data_by_user(username, domain)
                                .map_err(|e| crate::Error::new(crate::ErrorKind::LogonDenied, e.to_string())),
                            ts_request
                        );
                        try_cred_ssp_server!(
                            self.context
                                .as_mut()
                                .unwrap()
                                .sspi_context
                                .custom_set_auth_identity(Credentials::AuthIdentity(auth_data)),
                            ts_request
                        );

                        try_cred_ssp_server!(
                            self.context.as_mut().unwrap().sspi_context.complete_auth_token(&mut []),
                            ts_request
                        );
                        ts_request.nego_tokens = None;

                        let pub_key_auth = try_cred_ssp_server!(
                            ts_request.pub_key_auth.take().ok_or_else(|| {
                                crate::Error::new(
                                    crate::ErrorKind::InvalidToken,
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
                self.credentials_handle = credentials_handle.map(|c| c.auth_identity().unwrap());

                Ok(ServerState::ReplyNeeded(ts_request))
            }
            CredSspState::Final => Err(ServerError {
                ts_request,
                error: Error::new(
                    ErrorKind::InternalError,
                    "CredSSP server's 'process' method must not be fired after the 'Finished' state",
                ),
            }),
        }
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SspiContext {
    Ntlm(Ntlm),
    Kerberos(Kerberos),
    Negotiate(Negotiate),
    Pku2u(Pku2u),
    #[cfg(feature = "tsssp")]
    CredSsp(SspiCredSsp),
}

impl SspiContext {
    pub fn package_name(&self) -> &str {
        match self {
            SspiContext::Ntlm(_) => ntlm::PKG_NAME,
            SspiContext::Kerberos(_) => kerberos::PKG_NAME,
            SspiContext::Negotiate(_) => negotiate::PKG_NAME,
            SspiContext::Pku2u(_) => pku2u::PKG_NAME,
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(_) => crate::credssp::sspi_cred_ssp::PKG_NAME,
        }
    }
}

impl SspiImpl for SspiContext {
    type CredentialsHandle = Option<CredentialsBuffers>;
    type AuthenticationData = Credentials;

    #[instrument(ret, fields(security_package = self.package_name()), skip_all)]
    fn acquire_credentials_handle_impl<'a>(
        &'a mut self,
        builder: FilledAcquireCredentialsHandle<'a, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> crate::Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        Ok(match self {
            SspiContext::Ntlm(ntlm) => {
                let auth_identity = if let Some(Credentials::AuthIdentity(identity)) = builder.auth_data {
                    identity
                } else {
                    return Err(Error::new(
                        ErrorKind::NoCredentials,
                        "Auth identity is not provided for the Pku2u",
                    ));
                };
                builder
                    .full_transform(ntlm, Some(auth_identity))
                    .execute()?
                    .transform_credentials_handle(&|a: Option<AuthIdentityBuffers>| {
                        a.map(CredentialsBuffers::AuthIdentity)
                    })
            }
            SspiContext::Kerberos(kerberos) => builder.transform(kerberos).execute()?,
            SspiContext::Negotiate(negotiate) => builder.transform(negotiate).execute()?,
            SspiContext::Pku2u(pku2u) => {
                let auth_identity = if let Some(Credentials::AuthIdentity(identity)) = builder.auth_data {
                    identity
                } else {
                    return Err(Error::new(
                        ErrorKind::NoCredentials,
                        "Auth identity is not provided for the Pku2u",
                    ));
                };
                builder
                    .full_transform(pku2u, Some(auth_identity))
                    .execute()?
                    .transform_credentials_handle(&|a: Option<AuthIdentityBuffers>| {
                        a.map(CredentialsBuffers::AuthIdentity)
                    })
            }
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => builder.transform(credssp).execute()?,
        })
    }

    #[instrument(ret, fields(security_package = self.package_name()), skip_all)]
    fn initialize_security_context_impl<'a>(
        &mut self,
        builder: &mut FilledInitializeSecurityContext<'a, Self::CredentialsHandle>,
    ) -> crate::Result<InitializeSecurityContextResult> {
        match self {
            SspiContext::Ntlm(ntlm) => {
                let mut auth_identity = if let Some(Some(CredentialsBuffers::AuthIdentity(ref identity))) =
                    builder.credentials_handle_mut()
                {
                    Some(identity.clone())
                } else {
                    None
                };
                let mut new_builder = builder.full_transform(Some(&mut auth_identity));
                ntlm.initialize_security_context_impl(&mut new_builder)
            }
            SspiContext::Kerberos(kerberos) => kerberos.initialize_security_context_impl(builder),
            SspiContext::Negotiate(negotiate) => negotiate.initialize_security_context_impl(builder),
            SspiContext::Pku2u(pku2u) => {
                let mut auth_identity = if let Some(Some(CredentialsBuffers::AuthIdentity(ref identity))) =
                    builder.credentials_handle_mut()
                {
                    Some(identity.clone())
                } else {
                    None
                };
                let mut new_builder = builder.full_transform(Some(&mut auth_identity));
                pku2u.initialize_security_context_impl(&mut new_builder)
            }
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.initialize_security_context_impl(builder),
        }
    }

    #[instrument(ret, fields(security_package = self.package_name()), skip_all)]
    fn accept_security_context_impl<'a>(
        &'a mut self,
        builder: FilledAcceptSecurityContext<'a, Self::AuthenticationData, Self::CredentialsHandle>,
    ) -> crate::Result<AcceptSecurityContextResult> {
        match self {
            SspiContext::Ntlm(ntlm) => {
                let auth_identity =
                    if let Some(Some(CredentialsBuffers::AuthIdentity(identity))) = builder.credentials_handle {
                        identity.clone()
                    } else {
                        return Err(Error::new(
                            ErrorKind::NoCredentials,
                            "Auth identity is not provided for the Pku2u",
                        ));
                    };
                builder.full_transform(ntlm, Some(&mut Some(auth_identity))).execute()
            }
            SspiContext::Kerberos(kerberos) => builder.transform(kerberos).execute(),
            SspiContext::Negotiate(negotiate) => builder.transform(negotiate).execute(),
            SspiContext::Pku2u(pku2u) => {
                let auth_identity =
                    if let Some(Some(CredentialsBuffers::AuthIdentity(identity))) = builder.credentials_handle {
                        identity.clone()
                    } else {
                        return Err(Error::new(
                            ErrorKind::NoCredentials,
                            "Auth identity is not provided for the Pku2u",
                        ));
                    };
                builder.full_transform(pku2u, Some(&mut Some(auth_identity))).execute()
            }
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => builder.transform(credssp).execute(),
        }
    }
}

impl Sspi for SspiContext {
    #[instrument(ret, fields(security_package = self.package_name()), skip(self))]
    fn complete_auth_token(&mut self, token: &mut [SecurityBuffer]) -> crate::Result<SecurityStatus> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.complete_auth_token(token),
            SspiContext::Kerberos(kerberos) => kerberos.complete_auth_token(token),
            SspiContext::Negotiate(negotiate) => negotiate.complete_auth_token(token),
            SspiContext::Pku2u(pku2u) => pku2u.complete_auth_token(token),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.complete_auth_token(token),
        }
    }

    #[instrument(ret, fields(security_package = self.package_name()), skip(self))]
    fn encrypt_message(
        &mut self,
        flags: EncryptionFlags,
        message: &mut [SecurityBuffer],
        sequence_number: u32,
    ) -> crate::Result<SecurityStatus> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.encrypt_message(flags, message, sequence_number),
            SspiContext::Kerberos(kerberos) => kerberos.encrypt_message(flags, message, sequence_number),
            SspiContext::Negotiate(negotiate) => negotiate.encrypt_message(flags, message, sequence_number),
            SspiContext::Pku2u(pku2u) => pku2u.encrypt_message(flags, message, sequence_number),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.encrypt_message(flags, message, sequence_number),
        }
    }

    #[instrument(ret, fields(security_package = self.package_name()), skip(self))]
    fn decrypt_message(
        &mut self,
        message: &mut [SecurityBuffer],
        sequence_number: u32,
    ) -> crate::Result<DecryptionFlags> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.decrypt_message(message, sequence_number),
            SspiContext::Kerberos(kerberos) => kerberos.decrypt_message(message, sequence_number),
            SspiContext::Negotiate(negotiate) => negotiate.decrypt_message(message, sequence_number),
            SspiContext::Pku2u(pku2u) => pku2u.decrypt_message(message, sequence_number),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.decrypt_message(message, sequence_number),
        }
    }

    #[instrument(ret, fields(security_package = self.package_name()), skip(self))]
    fn query_context_sizes(&mut self) -> crate::Result<ContextSizes> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_sizes(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_sizes(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_sizes(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_sizes(),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.query_context_sizes(),
        }
    }

    #[instrument(ret, fields(security_package = self.package_name()), skip(self))]
    fn query_context_names(&mut self) -> crate::Result<ContextNames> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_names(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_names(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_names(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_names(),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.query_context_names(),
        }
    }

    #[instrument(ret, fields(security_package = self.package_name()), skip(self))]
    fn query_context_stream_sizes(&mut self) -> crate::Result<StreamSizes> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_stream_sizes(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_stream_sizes(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_stream_sizes(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_stream_sizes(),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.query_context_stream_sizes(),
        }
    }

    #[instrument(ret, fields(security_package = self.package_name()), skip(self))]
    fn query_context_package_info(&mut self) -> crate::Result<PackageInfo> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_package_info(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_package_info(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_package_info(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_package_info(),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.query_context_package_info(),
        }
    }

    #[instrument(ret, fields(security_package = self.package_name()), skip(self))]
    fn query_context_cert_trust_status(&mut self) -> crate::Result<CertTrustStatus> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_cert_trust_status(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_cert_trust_status(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_cert_trust_status(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_cert_trust_status(),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.query_context_cert_trust_status(),
        }
    }

    #[instrument(ret, fields(security_package = self.package_name()), skip(self))]
    fn query_context_remote_cert(&mut self) -> crate::Result<CertContext> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_remote_cert(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_remote_cert(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_remote_cert(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_remote_cert(),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.query_context_remote_cert(),
        }
    }

    #[instrument(ret, fields(security_package = self.package_name()), skip(self))]
    fn query_context_negotiation_package(&mut self) -> crate::Result<PackageInfo> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_negotiation_package(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_negotiation_package(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_negotiation_package(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_negotiation_package(),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.query_context_negotiation_package(),
        }
    }

    #[instrument(ret, fields(security_package = self.package_name()), skip(self))]
    fn query_context_connection_info(&mut self) -> crate::Result<ConnectionInfo> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_connection_info(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_connection_info(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_connection_info(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_connection_info(),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.query_context_connection_info(),
        }
    }

    #[instrument(ret, fields(security_package = self.package_name()), skip_all)]
    fn change_password(&mut self, change_password: ChangePassword) -> crate::Result<()> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.change_password(change_password),
            SspiContext::Kerberos(kerberos) => kerberos.change_password(change_password),
            SspiContext::Negotiate(negotiate) => negotiate.change_password(change_password),
            SspiContext::Pku2u(pku2u) => pku2u.change_password(change_password),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.change_password(change_password),
        }
    }
}

impl SspiEx for SspiContext {
    // #[instrument(level = "trace", ret, fields(security_package = self.package_name()), skip(self))]
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) -> crate::Result<()> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.custom_set_auth_identity(identity.auth_identity().ok_or_else(|| {
                Error::new(
                    ErrorKind::IncompleteCredentials,
                    "Provided credentials are not password-based",
                )
            })?),
            SspiContext::Kerberos(kerberos) => kerberos.custom_set_auth_identity(identity),
            SspiContext::Negotiate(negotiate) => negotiate.custom_set_auth_identity(identity),
            SspiContext::Pku2u(pku2u) => pku2u.custom_set_auth_identity(identity.auth_identity().ok_or_else(|| {
                Error::new(
                    ErrorKind::IncompleteCredentials,
                    "Provided credentials are not password-based",
                )
            })?),
            #[cfg(feature = "tsssp")]
            SspiContext::CredSsp(credssp) => credssp.custom_set_auth_identity(identity),
        }
    }
}

#[derive(Debug)]
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

    fn check_peer_version(&mut self, other_peer_version: u32) -> crate::Result<()> {
        if let Some(peer_version) = self.peer_version {
            if peer_version != other_peer_version {
                Err(crate::Error::new(
                    crate::ErrorKind::MessageAltered,
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
    ) -> crate::Result<Vec<u8>> {
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
                &client_nonce.ok_or(crate::Error::new(
                    crate::ErrorKind::InvalidToken,
                    String::from("client nonce from the TSRequest is empty, but a peer version is >= 5"),
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
    ) -> crate::Result<()> {
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
                &client_nonce.ok_or(crate::Error::new(
                    crate::ErrorKind::InvalidToken,
                    String::from("client nonce from the TSRequest is empty, but a peer version is >= 5"),
                ))?,
            )
        }
    }

    fn encrypt_public_key_echo(&mut self, public_key: &[u8], endpoint: EndpointType) -> crate::Result<Vec<u8>> {
        let mut public_key = public_key.to_vec();

        if let SspiContext::Ntlm(_) = self.sspi_context {
            if endpoint == EndpointType::Server {
                integer_increment_le(&mut public_key);
            }
        }

        self.encrypt_message(&public_key)
    }

    fn encrypt_public_key_hash(
        &mut self,
        public_key: &[u8],
        hash_magic: &[u8],
        client_nonce: &[u8],
    ) -> crate::Result<Vec<u8>> {
        let mut data = hash_magic.to_vec();
        data.extend(client_nonce);
        data.extend(public_key);

        self.encrypt_message(&compute_sha256(&data))
    }

    fn decrypt_public_key_echo(
        &mut self,
        public_key: &[u8],
        encrypted_public_key: &[u8],
        endpoint: EndpointType,
    ) -> crate::Result<()> {
        let mut decrypted_public_key = self.decrypt_message(encrypted_public_key)?;
        if endpoint == EndpointType::Client {
            integer_decrement_le(&mut decrypted_public_key);
        }

        if public_key != decrypted_public_key.as_slice() {
            error!("Expected and decrypted public key are not the same");

            return Err(crate::Error::new(
                crate::ErrorKind::MessageAltered,
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
    ) -> crate::Result<()> {
        let decrypted_public_key = self.decrypt_message(encrypted_public_key)?;

        let mut data = hash_magic.to_vec();
        data.extend(client_nonce);
        data.extend(public_key);
        let expected_public_key = compute_sha256(&data);

        if expected_public_key.as_ref() != decrypted_public_key.as_slice() {
            error!("Expected and decrypted public key hash are not the same");

            return Err(crate::Error::new(
                crate::ErrorKind::MessageAltered,
                String::from("Could not verify a public key hash"),
            ));
        }

        Ok(())
    }

    fn encrypt_ts_credentials(
        &mut self,
        credentials: &CredentialsBuffers,
        cred_ssp_mode: CredSspMode,
    ) -> crate::Result<Vec<u8>> {
        self.encrypt_message(&ts_request::write_ts_credentials(credentials, cred_ssp_mode)?)
    }

    fn decrypt_ts_credentials(&mut self, auth_info: &[u8]) -> crate::Result<CredentialsBuffers> {
        let ts_credentials_buffer = self.decrypt_message(auth_info)?;

        ts_request::read_ts_credentials(ts_credentials_buffer.as_slice())
    }

    fn encrypt_message(&mut self, input: &[u8]) -> crate::Result<Vec<u8>> {
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
        output.append(&mut SecurityBuffer::find_buffer_mut(&mut buffers, SecurityBufferType::Data)?.buffer);

        self.send_seq_num += 1;

        Ok(output)
    }

    fn decrypt_message(&mut self, input: &[u8]) -> crate::Result<Vec<u8>> {
        let (signature, data) = input.split_at(SIGNATURE_SIZE);
        let mut buffers = vec![
            SecurityBuffer::new(data.to_vec(), SecurityBufferType::Data),
            SecurityBuffer::new(signature.to_vec(), SecurityBufferType::Token),
        ];

        let recv_seq_num = self.recv_seq_num;

        self.sspi_context.decrypt_message(&mut buffers, recv_seq_num)?;

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

fn construct_error(e: &crate::Error) -> NStatusCode {
    let code = ((e.error_type as i64 & 0x0000_FFFF) | (0x7 << 16) | 0xC000_0000) as u32;
    NStatusCode(code)
}

#[cfg(test)]
mod tests {
    use static_assertions::assert_impl_one;

    use super::CredSspClient;

    #[test]
    fn cred_sspi_client_is_send() {
        assert_impl_one!(CredSspClient: Send);
    }

    #[test]
    fn cred_sspi_client_is_sync() {
        assert_impl_one!(CredSspClient: Sync);
    }
}
