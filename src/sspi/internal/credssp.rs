cfg_if::cfg_if! {
    if #[cfg(fuzzing)] {
        pub mod ts_request;
    } else {
        mod ts_request;
    }
}

use std::io;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use rand::rngs::OsRng;
use rand::Rng;
pub use ts_request::TsRequest;
use ts_request::{NONCE_SIZE, TS_REQUEST_VERSION};

use crate::builders::{ChangePassword, EmptyInitializeSecurityContext};
use crate::crypto::compute_sha256;
use crate::sspi::internal::SspiImpl;
use crate::sspi::kerberos::config::KerberosConfig;
use crate::sspi::kerberos::Kerberos;
use crate::sspi::ntlm::{AuthIdentity, AuthIdentityBuffers, Ntlm, SIGNATURE_SIZE};
use crate::sspi::pku2u::Pku2uConfig;
use crate::sspi::{
    self, CertTrustStatus, ClientRequestFlags, ContextNames, ContextSizes, CredentialUse, DataRepresentation,
    DecryptionFlags, EncryptionFlags, FilledAcceptSecurityContext, FilledAcquireCredentialsHandle,
    FilledInitializeSecurityContext, PackageInfo, SecurityBuffer, SecurityBufferType, SecurityStatus,
    ServerRequestFlags, Sspi, SspiEx,
};
use crate::{
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, ErrorKind, InitializeSecurityContextResult, Negotiate,
    NegotiateConfig, Pku2u,
};

pub const EARLY_USER_AUTH_RESULT_PDU_SIZE: usize = 4;

const HASH_MAGIC_LEN: usize = 38;
pub const SERVER_CLIENT_HASH_MAGIC: &[u8; HASH_MAGIC_LEN] = b"CredSSP Server-To-Client Binding Hash\0";
pub const CLIENT_SERVER_HASH_MAGIC: &[u8; HASH_MAGIC_LEN] = b"CredSSP Client-To-Server Binding Hash\0";

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
pub enum ClientMode {
    Negotiate(NegotiateConfig),
    Kerberos(KerberosConfig),
    Pku2u(Pku2uConfig),
    Ntlm,
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
    client_mode: ClientMode,
    service_principal_name: String,
}

impl CredSspClient {
    pub fn new(
        public_key: Vec<u8>,
        credentials: AuthIdentity,
        cred_ssp_mode: CredSspMode,
        client_mode: ClientMode,
        service_principal_name: String,
    ) -> sspi::Result<Self> {
        Ok(Self {
            state: CredSspState::NegoToken,
            context: None,
            credentials,
            // public_key: vec![48, 130, 1, 10, 2, 130, 1, 1, 0, 205, 145, 202, 14, 211, 90, 9, 57, 201, 82, 174, 149, 31, 144, 56, 21, 255, 170, 18, 31, 144, 135, 109, 251, 163, 28, 59, 223, 208, 158, 196, 250, 235, 72, 119, 207, 27, 111, 174, 26, 191, 111, 119, 254, 246, 121, 105, 241, 139, 246, 224, 36, 79, 243, 64, 59, 121, 255, 77, 254, 198, 138, 194, 237, 252, 149, 123, 7, 230, 18, 178, 118, 194, 47, 128, 5, 199, 153, 59, 90, 147, 77, 117, 0, 254, 85, 14, 197, 132, 169, 142, 94, 250, 217, 89, 82, 175, 157, 44, 174, 96, 169, 202, 110, 170, 184, 128, 245, 14, 74, 254, 10, 132, 168, 46, 43, 48, 162, 113, 66, 120, 53, 83, 219, 172, 67, 28, 175, 176, 38, 97, 154, 53, 210, 137, 170, 241, 184, 156, 124, 175, 142, 172, 19, 0, 16, 77, 121, 115, 59, 31, 42, 84, 105, 121, 113, 199, 177, 124, 100, 73, 151, 42, 96, 229, 100, 158, 250, 34, 18, 125, 245, 73, 180, 154, 236, 64, 109, 130, 187, 83, 115, 15, 251, 21, 235, 147, 15, 96, 61, 6, 248, 7, 83, 60, 123, 178, 187, 116, 102, 99, 121, 134, 233, 14, 142, 1, 28, 214, 57, 144, 104, 15, 159, 157, 235, 241, 240, 145, 131, 145, 109, 35, 203, 21, 245, 176, 130, 140, 121, 77, 230, 215, 176, 176, 107, 190, 173, 87, 116, 34, 184, 136, 214, 44, 153, 173, 67, 113, 219, 216, 128, 121, 25, 244, 141, 2, 3, 1, 0, 1],
            public_key,
            cred_ssp_mode,
            client_nonce: OsRng::default().gen::<[u8; NONCE_SIZE]>(),
            credentials_handle: None,
            ts_request_version: TS_REQUEST_VERSION,
            client_mode,
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
    ) -> sspi::Result<Self> {
        Ok(Self {
            state: CredSspState::NegoToken,
            context: None,
            credentials,
            // public_key: vec![48, 130, 1, 10, 2, 130, 1, 1, 0, 205, 145, 202, 14, 211, 90, 9, 57, 201, 82, 174, 149, 31, 144, 56, 21, 255, 170, 18, 31, 144, 135, 109, 251, 163, 28, 59, 223, 208, 158, 196, 250, 235, 72, 119, 207, 27, 111, 174, 26, 191, 111, 119, 254, 246, 121, 105, 241, 139, 246, 224, 36, 79, 243, 64, 59, 121, 255, 77, 254, 198, 138, 194, 237, 252, 149, 123, 7, 230, 18, 178, 118, 194, 47, 128, 5, 199, 153, 59, 90, 147, 77, 117, 0, 254, 85, 14, 197, 132, 169, 142, 94, 250, 217, 89, 82, 175, 157, 44, 174, 96, 169, 202, 110, 170, 184, 128, 245, 14, 74, 254, 10, 132, 168, 46, 43, 48, 162, 113, 66, 120, 53, 83, 219, 172, 67, 28, 175, 176, 38, 97, 154, 53, 210, 137, 170, 241, 184, 156, 124, 175, 142, 172, 19, 0, 16, 77, 121, 115, 59, 31, 42, 84, 105, 121, 113, 199, 177, 124, 100, 73, 151, 42, 96, 229, 100, 158, 250, 34, 18, 125, 245, 73, 180, 154, 236, 64, 109, 130, 187, 83, 115, 15, 251, 21, 235, 147, 15, 96, 61, 6, 248, 7, 83, 60, 123, 178, 187, 116, 102, 99, 121, 134, 233, 14, 142, 1, 28, 214, 57, 144, 104, 15, 159, 157, 235, 241, 240, 145, 131, 145, 109, 35, 203, 21, 245, 176, 130, 140, 121, 77, 230, 215, 176, 176, 107, 190, 173, 87, 116, 34, 184, 136, 214, 44, 153, 173, 67, 113, 219, 216, 128, 121, 25, 244, 141, 2, 3, 1, 0, 1],
            public_key,
            cred_ssp_mode,
            client_nonce: OsRng::default().gen::<[u8; NONCE_SIZE]>(),
            credentials_handle: None,
            ts_request_version,
            client_mode,
            service_principal_name,
        })
    }

    pub fn process(&mut self, mut ts_request: TsRequest) -> sspi::Result<ClientState> {
        ts_request.check_error()?;
        if let Some(ref mut context) = self.context {
            context.check_peer_version(ts_request.version)?;
        } else {
            self.context = match &self.client_mode {
                ClientMode::Negotiate(negotiate_config) => Some(CredSspContext::new(SspiContext::Negotiate(
                    Negotiate::new(negotiate_config.clone())?,
                ))),
                ClientMode::Kerberos(kerberos_config) => Some(CredSspContext::new(SspiContext::Kerberos(
                    Kerberos::new_client_from_config(kerberos_config.clone())?,
                ))),
                ClientMode::Pku2u(pku2u) => Some(CredSspContext::new(SspiContext::Pku2u(
                    Pku2u::new_client_from_config(pku2u.clone())?,
                ))),
                ClientMode::Ntlm => Some(CredSspContext::new(SspiContext::Ntlm(Ntlm::new()))),
            };
            let AcquireCredentialsHandleResult { credentials_handle, .. } = self
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
                let mut input_token = [SecurityBuffer::new(
                    ts_request.nego_tokens.take().unwrap_or_default(),
                    SecurityBufferType::Token,
                )];
                let mut output_token = vec![SecurityBuffer::new(Vec::with_capacity(1024), SecurityBufferType::Token)];

                let mut credentials_handle = self.credentials_handle.take();
                let cred_ssp_context = self.context.as_mut().unwrap();
                let mut builder = EmptyInitializeSecurityContext::<<SspiContext as SspiImpl>::CredentialsHandle>::new()
                    .with_credentials_handle(&mut credentials_handle)
                    .with_context_requirements(ClientRequestFlags::empty())
                    .with_target_data_representation(DataRepresentation::Native)
                    .with_target_name(&self.service_principal_name)
                    .with_input(&mut input_token)
                    .with_output(&mut output_token);
                let result = cred_ssp_context
                    .sspi_context
                    .initialize_security_context_impl(&mut builder)?;
                self.credentials_handle = credentials_handle;
                ts_request.nego_tokens = Some(output_token.remove(0).buffer);

                if result.status == SecurityStatus::Ok {
                    println!("start auth info");
                    println!("public key: {:?}", self.public_key);
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
                    ts_request.nego_tokens = None;
                    self.state = CredSspState::AuthInfo;
                }

                Ok(ClientState::ReplyNeeded(ts_request))
            }
            CredSspState::AuthInfo => {
                println!("got pub key auth reply. start credentials transferring");
                ts_request.nego_tokens = None;

                let pub_key_auth = ts_request.pub_key_auth.take().ok_or_else(|| {
                    sspi::Error::new(
                        sspi::ErrorKind::InvalidToken,
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

                self.credentials = AuthIdentity {
                    username: "s7@dataans.com".into(),
                    password: "wwwWWW222@@@".into(),
                    domain: Some("AzureAD".into()),
                };

                ts_request.auth_info = Some(
                    self.context
                        .as_mut()
                        .unwrap()
                        .encrypt_ts_credentials(&self.credentials.clone().into(), self.cred_ssp_mode)?,
                );

                self.state = CredSspState::Final;

                Ok(ClientState::FinalMessage(ts_request))
            }
            CredSspState::Final => {
                panic!("CredSSP client's 'process' method must not be fired after the 'Finished' state")
            }
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
    context_config: ClientMode,
}

impl<C: CredentialsProxy<AuthenticationData = AuthIdentity>> CredSspServer<C> {
    pub fn new(public_key: Vec<u8>, credentials: C, client_mode: ClientMode) -> sspi::Result<Self> {
        println!("server's public key: {:?}", public_key);
        Ok(Self {
            state: CredSspState::NegoToken,
            context: None,
            credentials,
            public_key: vec![48, 130, 1, 10, 2, 130, 1, 1, 0, 205, 145, 202, 14, 211, 90, 9, 57, 201, 82, 174, 149, 31, 144, 56, 21, 255, 170, 18, 31, 144, 135, 109, 251, 163, 28, 59, 223, 208, 158, 196, 250, 235, 72, 119, 207, 27, 111, 174, 26, 191, 111, 119, 254, 246, 121, 105, 241, 139, 246, 224, 36, 79, 243, 64, 59, 121, 255, 77, 254, 198, 138, 194, 237, 252, 149, 123, 7, 230, 18, 178, 118, 194, 47, 128, 5, 199, 153, 59, 90, 147, 77, 117, 0, 254, 85, 14, 197, 132, 169, 142, 94, 250, 217, 89, 82, 175, 157, 44, 174, 96, 169, 202, 110, 170, 184, 128, 245, 14, 74, 254, 10, 132, 168, 46, 43, 48, 162, 113, 66, 120, 53, 83, 219, 172, 67, 28, 175, 176, 38, 97, 154, 53, 210, 137, 170, 241, 184, 156, 124, 175, 142, 172, 19, 0, 16, 77, 121, 115, 59, 31, 42, 84, 105, 121, 113, 199, 177, 124, 100, 73, 151, 42, 96, 229, 100, 158, 250, 34, 18, 125, 245, 73, 180, 154, 236, 64, 109, 130, 187, 83, 115, 15, 251, 21, 235, 147, 15, 96, 61, 6, 248, 7, 83, 60, 123, 178, 187, 116, 102, 99, 121, 134, 233, 14, 142, 1, 28, 214, 57, 144, 104, 15, 159, 157, 235, 241, 240, 145, 131, 145, 109, 35, 203, 21, 245, 176, 130, 140, 121, 77, 230, 215, 176, 176, 107, 190, 173, 87, 116, 34, 184, 136, 214, 44, 153, 173, 67, 113, 219, 216, 128, 121, 25, 244, 141, 2, 3, 1, 0, 1],
            credentials_handle: None,
            ts_request_version: TS_REQUEST_VERSION,
            context_config: client_mode,
        })
    }

    pub fn new_with_version(
        public_key: Vec<u8>,
        credentials: C,
        ts_request_version: u32,
        client_mode: ClientMode,
    ) -> sspi::Result<Self> {
        Ok(Self {
            state: CredSspState::NegoToken,
            context: None,
            credentials,
            public_key,
            credentials_handle: None,
            ts_request_version,
            context_config: client_mode,
        })
    }

    pub fn process(&mut self, mut ts_request: TsRequest) -> Result<ServerState, ServerError> {
        if self.context.is_none() {
            self.context = match &self.context_config {
                ClientMode::Negotiate(_) => {
                    return Err(ServerError {
                        ts_request,
                        error: sspi::Error::new(
                            ErrorKind::UnsupportedFunction,
                            "Negotiate module is not supported for the CredSsp server".into(),
                        ),
                    })
                }
                ClientMode::Kerberos(kerberos_config) => Some(CredSspContext::new(SspiContext::Kerberos(
                    try_cred_ssp_server!(Kerberos::new_server_from_config(kerberos_config.clone()), ts_request),
                ))),
                ClientMode::Ntlm => Some(CredSspContext::new(SspiContext::Ntlm(Ntlm::new()))),
                ClientMode::Pku2u(pku2u) => Some(CredSspContext::new(SspiContext::Pku2u(
                    try_cred_ssp_server!(Pku2u::new_server_from_config(pku2u.clone()), ts_request)
                ))),
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
            self.credentials_handle = credentials_handle;
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
                        sspi::Error::new(
                            sspi::ErrorKind::InvalidToken,
                            String::from("Expected an encrypted ts credentials"),
                        )
                    }),
                    ts_request
                );

                println!("auth_info: {:?}", auth_info);

                let read_credentials = try_cred_ssp_server!(
                    self.context.as_mut().unwrap().decrypt_ts_credentials(&auth_info),
                    ts_request
                );
                panic!("creds: {:?}", read_credentials);
                self.state = CredSspState::Final;

                Ok(ServerState::Finished(read_credentials.into()))
            }
            CredSspState::NegoToken => {
                println!("public key: {:?}", self.public_key);
                // let input = try_cred_ssp_server!(
                //     ts_request
                //         .nego_tokens
                //         .take()
                //         .ok_or_else(|| {
                //             sspi::Error::new(
                //                 sspi::ErrorKind::InvalidToken,
                //                 String::from("Got empty nego_tokens field"),
                //             )
                //         }),
                //     ts_request
                // );
                let input = ts_request.nego_tokens.take().unwrap_or(Vec::new());
                let input_token = SecurityBuffer::new(input, SecurityBufferType::Token);
                let mut output_token = vec![SecurityBuffer::new(Vec::with_capacity(1024), SecurityBufferType::Token)];

                println!("ts_request: {:?}", ts_request);

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
                    AcceptSecurityContextResult { status, .. } if status == SecurityStatus::ContinueNeeded => {
                        ts_request.nego_tokens = Some(output_token.remove(0).buffer);
                    }
                    AcceptSecurityContextResult { status, .. } if status == SecurityStatus::CompleteNeeded => {
                        println!("I'M HERE: TS_REQUEST: {:?}", ts_request);
                        println!("--------------------------------");

                        let ContextNames { username, domain } = try_cred_ssp_server!(
                            self.context.as_mut().unwrap().sspi_context.query_context_names(),
                            ts_request
                        );
                        println!("context names here");
                        let auth_data = try_cred_ssp_server!(
                            self.credentials
                                .auth_data_by_user(username, domain)
                                .map_err(|e| sspi::Error::new(sspi::ErrorKind::LogonDenied, e.to_string())),
                            ts_request
                        );
                        self.context
                            .as_mut()
                            .unwrap()
                            .sspi_context
                            .custom_set_auth_identity(auth_data);
                        println!("custom auth identity are set");

                        try_cred_ssp_server!(
                            self.context.as_mut().unwrap().sspi_context.complete_auth_token(&mut []),
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
                    q => unreachable!("AcceptSecurityContextResult: {:?}", q),
                };
                self.credentials_handle = credentials_handle;

                Ok(ServerState::ReplyNeeded(ts_request))
            }
            CredSspState::Final => {
                panic!("CredSSP server's 'process' method must not be fired after the 'Finished' state")
            }
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum SspiContext {
    Ntlm(Ntlm),
    Kerberos(Kerberos),
    Negotiate(Negotiate),
    Pku2u(Pku2u),
}

impl SspiImpl for SspiContext {
    type CredentialsHandle = Option<AuthIdentityBuffers>;
    type AuthenticationData = AuthIdentity;

    fn acquire_credentials_handle_impl<'a>(
        &'a mut self,
        builder: FilledAcquireCredentialsHandle<'a, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> sspi::Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        match self {
            SspiContext::Ntlm(ntlm) => builder.transform(ntlm).execute(),
            SspiContext::Kerberos(kerberos) => builder.transform(kerberos).execute(),
            SspiContext::Negotiate(negotiate) => builder.transform(negotiate).execute(),
            SspiContext::Pku2u(pku2u) => builder.transform(pku2u).execute(),
        }
    }

    fn initialize_security_context_impl<'a>(
        &mut self,
        builder: &mut FilledInitializeSecurityContext<'a, Self::CredentialsHandle>,
    ) -> sspi::Result<InitializeSecurityContextResult> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.initialize_security_context_impl(builder),
            SspiContext::Kerberos(kerberos) => kerberos.initialize_security_context_impl(builder),
            SspiContext::Negotiate(negotiate) => negotiate.initialize_security_context_impl(builder),
            SspiContext::Pku2u(pku2u) => pku2u.initialize_security_context_impl(builder),
        }
    }

    fn accept_security_context_impl<'a>(
        &'a mut self,
        builder: FilledAcceptSecurityContext<'a, Self::AuthenticationData, Self::CredentialsHandle>,
    ) -> sspi::Result<AcceptSecurityContextResult> {
        match self {
            SspiContext::Ntlm(ntlm) => builder.transform(ntlm).execute(),
            SspiContext::Kerberos(kerberos) => builder.transform(kerberos).execute(),
            SspiContext::Negotiate(negotiate) => builder.transform(negotiate).execute(),
            SspiContext::Pku2u(pku2u) => builder.transform(pku2u).execute(),
        }
    }
}

impl Sspi for SspiContext {
    fn complete_auth_token(&mut self, token: &mut [SecurityBuffer]) -> sspi::Result<SecurityStatus> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.complete_auth_token(token),
            SspiContext::Kerberos(kerberos) => kerberos.complete_auth_token(token),
            SspiContext::Negotiate(negotiate) => negotiate.complete_auth_token(token),
            SspiContext::Pku2u(pku2u) => pku2u.complete_auth_token(token),
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
            SspiContext::Kerberos(kerberos) => kerberos.encrypt_message(flags, message, sequence_number),
            SspiContext::Negotiate(negotiate) => negotiate.encrypt_message(flags, message, sequence_number),
            SspiContext::Pku2u(pku2u) => pku2u.encrypt_message(flags, message, sequence_number),
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
            SspiContext::Negotiate(negotiate) => negotiate.decrypt_message(message, sequence_number),
            SspiContext::Pku2u(pku2u) => pku2u.decrypt_message(message, sequence_number),
        }
    }

    fn query_context_sizes(&mut self) -> sspi::Result<ContextSizes> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_sizes(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_sizes(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_sizes(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_sizes(),
        }
    }
    fn query_context_names(&mut self) -> sspi::Result<ContextNames> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_names(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_names(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_names(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_names(),
        }
    }
    fn query_context_package_info(&mut self) -> sspi::Result<PackageInfo> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_package_info(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_package_info(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_package_info(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_package_info(),
        }
    }
    fn query_context_cert_trust_status(&mut self) -> sspi::Result<CertTrustStatus> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.query_context_cert_trust_status(),
            SspiContext::Kerberos(kerberos) => kerberos.query_context_cert_trust_status(),
            SspiContext::Negotiate(negotiate) => negotiate.query_context_cert_trust_status(),
            SspiContext::Pku2u(pku2u) => pku2u.query_context_cert_trust_status(),
        }
    }

    fn change_password(&mut self, change_password: ChangePassword) -> crate::Result<()> {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.change_password(change_password),
            SspiContext::Kerberos(kerberos) => kerberos.change_password(change_password),
            SspiContext::Negotiate(negotiate) => negotiate.change_password(change_password),
            SspiContext::Pku2u(pku2u) => pku2u.change_password(change_password),
        }
    }
}

impl SspiEx for SspiContext {
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) {
        match self {
            SspiContext::Ntlm(ntlm) => ntlm.custom_set_auth_identity(identity),
            SspiContext::Kerberos(kerberos) => kerberos.custom_set_auth_identity(identity),
            SspiContext::Negotiate(negotiate) => negotiate.custom_set_auth_identity(identity),
            SspiContext::Pku2u(pku2u) => pku2u.custom_set_auth_identity(identity),
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
                    String::from("client nonce from the TSRequest is empty, but a peer version is >= 5"),
                ))?,
            )
        }
    }

    fn encrypt_public_key_echo(&mut self, public_key: &[u8], endpoint: EndpointType) -> sspi::Result<Vec<u8>> {
        let mut public_key = public_key.to_vec();

        match self.sspi_context {
            SspiContext::Ntlm(_) => {
                if endpoint == EndpointType::Server {
                    integer_increment_le(&mut public_key);
                }
            }
            SspiContext::Kerberos(_) => {}
            SspiContext::Negotiate(_) => {}
            SspiContext::Pku2u(_) => {}
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

        self.encrypt_message(&compute_sha256(&data))
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
        println!("start decrypt");
        let decrypted_public_key = self.decrypt_message(encrypted_public_key)?;
        println!("finish decrypt");

        let mut data = hash_magic.to_vec();
        data.extend(client_nonce);
        data.extend(public_key);
        let expected_public_key = compute_sha256(&data);

        if expected_public_key.as_ref() != decrypted_public_key.as_slice() {
            println!("hashes are not the same");
            return Err(sspi::Error::new(
                sspi::ErrorKind::MessageAltered,
                String::from("Could not verify a public key hash"),
            ));
        } else {
            println!("yes, they are the same");
        }

        Ok(())
    }

    fn encrypt_ts_credentials(
        &mut self,
        credentials: &AuthIdentityBuffers,
        cred_ssp_mode: CredSspMode,
    ) -> sspi::Result<Vec<u8>> {
        let encoded_ts_creds = ts_request::write_ts_credentials(credentials, cred_ssp_mode)?;
        println!("encoded_ts_creds: {:?}", encoded_ts_creds);
        self.encrypt_message(&encoded_ts_creds)
    }

    fn decrypt_ts_credentials(&mut self, auth_info: &[u8]) -> sspi::Result<AuthIdentityBuffers> {
        let ts_credentials_buffer = self.decrypt_message(auth_info)?;
        println!("decrypted creds: {:?}", ts_credentials_buffer);

        Ok(ts_request::read_ts_credentials(ts_credentials_buffer.as_slice())?)
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
        output.append(&mut SecurityBuffer::find_buffer_mut(&mut buffers, SecurityBufferType::Data)?.buffer);

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

fn construct_error(e: &sspi::Error) -> u32 {
    ((e.error_type as i64 & 0x0000_FFFF) | (0x7 << 16) | 0xC000_0000) as u32
}
