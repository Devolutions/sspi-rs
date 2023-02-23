mod tls_connection;

use std::sync::Arc;

use lazy_static::lazy_static;
use picky_asn1_x509::Certificate;
use rand::rngs::OsRng;
use rand::Rng;
use rustls::{ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection};

use self::tls_connection::{danger, TlsConnection, TLS_PACKET_HEADER_LEN};
use super::ts_request::NONCE_SIZE;
use super::{CredSspContext, CredSspMode, EndpointType, SspiContext, TsRequest};
use crate::builders::EmptyInitializeSecurityContext;
use crate::{
    builders, negotiate, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers, CertContext,
    CertEncodingType, CertTrustErrorStatus, CertTrustInfoStatus, CertTrustStatus, ClientRequestFlags,
    ClientResponseFlags, ConnectionInfo, ContextNames, ContextSizes, CredentialUse, DataRepresentation,
    DecryptionFlags, EncryptionFlags, Error, ErrorKind, InitializeSecurityContextResult, PackageCapabilities,
    PackageInfo, Result, SecurityBuffer, SecurityBufferType, SecurityPackageType, SecurityStatus, Sspi, SspiEx,
    SspiImpl, StreamSizes, PACKAGE_ID_NONE,
};

pub const PKG_NAME: &str = "CREDSSP";

lazy_static! {
    pub static ref PACKAGE_INFO: PackageInfo = PackageInfo {
        capabilities: PackageCapabilities::empty(),
        rpc_id: PACKAGE_ID_NONE,
        max_token_len: negotiate::PACKAGE_INFO.max_token_len + 1,
        name: SecurityPackageType::CredSsp,
        comment: String::from("CredSsp security package"),
    };
}

#[derive(Debug, Clone)]
enum CredSspState {
    Tls,
    NegoToken,
    AuthInfo,
    Final,
}

#[derive(Debug)]
pub struct SspiCredSsp {
    state: CredSspState,
    cred_ssp_context: Box<CredSspContext>,
    auth_identity: Option<AuthIdentityBuffers>,
    tls_connection: TlsConnection,
    nonce: Option<[u8; NONCE_SIZE]>,
}

impl SspiCredSsp {
    pub fn new_client(sspi_context: SspiContext) -> Result<Self> {
        // "stub_string" - we don't check the server's certificate validity so we can use any server name
        let example_com = "stub_string".try_into().unwrap();
        let client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification))
            .with_no_client_auth();
        let config = Arc::new(client_config);

        Ok(Self {
            state: CredSspState::Tls,
            cred_ssp_context: Box::new(CredSspContext::new(sspi_context)),
            auth_identity: None,
            tls_connection: TlsConnection::Rustls(Connection::Client(
                ClientConnection::new(config, example_com)
                    .map_err(|err| Error::new(ErrorKind::InternalError, err.to_string()))?,
            )),
            nonce: Some(OsRng::default().gen::<[u8; NONCE_SIZE]>()),
        })
    }

    /// * `sspi_context` is a security package that will be used for authorization
    /// * `certificates` is a vector of DER-encoded X.509 certificates
    /// * `private_key` is a raw private key. it is DER-encoded ASN.1 in either PKCS#8 or PKCS#1 format.
    pub fn new_server(sspi_context: SspiContext, certificates: Vec<Vec<u8>>, private_key: Vec<u8>) -> Result<Self> {
        let server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(
                certificates.into_iter().map(rustls::Certificate).collect(),
                rustls::PrivateKey(private_key),
            )
            .map_err(|err| Error::new(ErrorKind::InternalError, err.to_string()))?;
        let config = Arc::new(server_config);

        Ok(Self {
            state: CredSspState::Tls,
            cred_ssp_context: Box::new(CredSspContext::new(sspi_context)),
            auth_identity: None,
            tls_connection: TlsConnection::Rustls(Connection::Server(
                ServerConnection::new(config).map_err(|err| Error::new(ErrorKind::InternalError, err.to_string()))?,
            )),
            // nonce for the server will be in the incoming TsRequest
            nonce: None,
        })
    }

    fn raw_peer_public_key(&mut self) -> Result<Vec<u8>> {
        let peer_certificate = self.query_context_remote_cert()?.cert;

        let raw_public_key = match peer_certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
        {
            picky_asn1_x509::PublicKey::Rsa(rsa_pk) => picky_asn1_der::to_vec(&rsa_pk.0)?,
            picky_asn1_x509::PublicKey::Ec(ec) => picky_asn1_der::to_vec(&ec)?,
            picky_asn1_x509::PublicKey::Ed(ed) => picky_asn1_der::to_vec(&ed)?,
        };

        Ok(raw_public_key)
    }

    fn decrypt_and_decode_ts_request(&mut self, input: &[SecurityBuffer]) -> Result<TsRequest> {
        let encrypted_ts_request = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;
        let raw_ts_request = self.tls_connection.decrypt_tls(&encrypted_ts_request.buffer)?;

        let ts_request = TsRequest::from_buffer(&raw_ts_request)?;
        ts_request.check_error()?;

        Ok(ts_request)
    }
}

impl Sspi for SspiCredSsp {
    #[instrument(level = "debug", ret, fields(state = ?self.state), skip_all)]
    fn complete_auth_token(&mut self, _token: &mut [SecurityBuffer]) -> Result<SecurityStatus> {
        Ok(SecurityStatus::Ok)
    }

    #[instrument(level = "debug", ret, fields(state = self.state.as_ref()), skip(self, _flags))]
    fn encrypt_message(
        &mut self,
        _flags: EncryptionFlags,
        message: &mut [SecurityBuffer],
        _sequence_number: u32,
    ) -> Result<SecurityStatus> {
        let plain_message = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;
        let plain_message_len = plain_message.buffer.len();

        let mut stream_header_data = self.tls_connection.encrypt_tls(&plain_message.buffer)?;
        let mut stream_data = stream_header_data.split_off(TLS_PACKET_HEADER_LEN);
        let stream_trailer_data = stream_data.split_off(plain_message_len);

        if let Ok(stream_header) = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::StreamHeader) {
            stream_header.buffer = stream_header_data;
        } else {
            let empty_buffer = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Empty)?;
            empty_buffer.buffer_type = SecurityBufferType::StreamHeader;
            empty_buffer.buffer = stream_header_data;
        }

        let plain_message = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;
        plain_message.buffer = stream_data;

        if let Ok(trailer) = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::StreamTrailer) {
            trailer.buffer = stream_trailer_data;
        } else {
            let empty_buffer = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Empty)?;
            empty_buffer.buffer_type = SecurityBufferType::StreamTrailer;
            empty_buffer.buffer = stream_trailer_data;
        }

        Ok(SecurityStatus::Ok)
    }

    #[instrument(level = "debug", ret, fields(state = self.state.as_ref()), skip(self, _sequence_number))]
    fn decrypt_message(&mut self, message: &mut [SecurityBuffer], _sequence_number: u32) -> Result<DecryptionFlags> {
        // CredSsp decrypt_message function just calls corresponding function from the Schannel
        // MSDN: message must contain four buffers
        // https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--schannel
        if message.len() < 4 {
            return Err(Error::new(
                ErrorKind::InvalidParameter,
                "Input message mut contain four buffers".into(),
            ));
        }

        let encrypted_message = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;

        if encrypted_message.buffer.len() < TLS_PACKET_HEADER_LEN {
            return Err(Error::new(
                ErrorKind::DecryptFailure,
                "Input TLS message is too short".into(),
            ));
        }

        let stream_header_data = encrypted_message.buffer[0..TLS_PACKET_HEADER_LEN].to_vec();
        let decrypted_data = self.tls_connection.decrypt_tls(&encrypted_message.buffer)?;
        let stream_trailer_data = encrypted_message.buffer[(TLS_PACKET_HEADER_LEN + decrypted_data.len())..].to_vec();

        // buffers order is important. MSTSC won't work with another buffers order
        message[0].buffer_type = SecurityBufferType::StreamHeader;
        message[0].buffer = stream_header_data;

        message[1].buffer_type = SecurityBufferType::Data;
        message[1].buffer = decrypted_data;

        message[2].buffer_type = SecurityBufferType::StreamTrailer;
        message[2].buffer = stream_trailer_data;

        Ok(DecryptionFlags::empty())
    }

    #[instrument(level = "debug", ret, fields(state = self.state.as_ref()), skip(self))]
    fn query_context_sizes(&mut self) -> Result<ContextSizes> {
        self.cred_ssp_context.sspi_context.query_context_sizes()
    }

    #[instrument(level = "debug", ret, fields(state = self.state.as_ref()), skip(self))]
    fn query_context_names(&mut self) -> Result<ContextNames> {
        self.cred_ssp_context.sspi_context.query_context_names()
    }

    #[instrument(level = "debug", ret, fields(state = self.state.as_ref()), skip(self))]
    fn query_context_stream_sizes(&mut self) -> Result<StreamSizes> {
        self.tls_connection.stream_sizes()
    }

    #[instrument(level = "debug", ret, fields(state = self.state.as_ref()), skip(self))]
    fn query_context_package_info(&mut self) -> Result<PackageInfo> {
        crate::query_security_package_info(SecurityPackageType::CredSsp)
    }

    #[instrument(level = "debug", ret, fields(state = self.state.as_ref()), skip(self))]
    fn query_context_cert_trust_status(&mut self) -> Result<CertTrustStatus> {
        // The CredSSP server does not request the client's X.509 certificate (thus far, the client is anonymous).
        // we do not check certificate validity
        Ok(CertTrustStatus {
            error_status: CertTrustErrorStatus::NO_ERROR,
            info_status: CertTrustInfoStatus::IS_SELF_SIGNED,
        })
    }

    #[instrument(level = "debug", ret, fields(state = self.state.as_ref()), skip(self))]
    fn query_context_remote_cert(&mut self) -> Result<CertContext> {
        let certificates = self.tls_connection.peer_certificates()?;
        let raw_server_certificate = certificates.get(0).ok_or_else(|| {
            Error::new(
                ErrorKind::CertificateUnknown,
                "Can not acquire server certificate".into(),
            )
        })?;

        let server_certificate: Certificate = picky_asn1_der::from_bytes(raw_server_certificate)?;

        Ok(CertContext {
            encoding_type: CertEncodingType::X509AsnEncoding,
            raw_cert: raw_server_certificate.to_vec(),
            cert: server_certificate,
        })
    }

    #[instrument(level = "debug", ret, fields(state = self.state.as_ref()), skip(self))]
    fn query_context_negotiation_package(&mut self) -> Result<PackageInfo> {
        self.cred_ssp_context.sspi_context.query_context_package_info()
    }

    #[instrument(level = "debug", ret, fields(state = self.state.as_ref()), skip(self))]
    fn query_context_connection_info(&mut self) -> Result<ConnectionInfo> {
        self.tls_connection.connection_info()
    }

    #[instrument(level = "debug", ret, fields(state = self.state.as_ref()), skip_all)]
    fn change_password(&mut self, _change_password: builders::ChangePassword) -> Result<()> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "ChangePassword is not supported in SspiCredSsp context".into(),
        ))
    }
}

impl SspiImpl for SspiCredSsp {
    type CredentialsHandle = Option<AuthIdentityBuffers>;
    type AuthenticationData = AuthIdentity;

    #[instrument(level = "trace", ret, fields(state = self.state.as_ref()), skip(self))]
    fn acquire_credentials_handle_impl<'a>(
        &'a mut self,
        builder: builders::FilledAcquireCredentialsHandle<'a, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> Result<crate::AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        if builder.credential_use == CredentialUse::Outbound && builder.auth_data.is_none() {
            return Err(Error::new(
                ErrorKind::NoCredentials,
                "The client must specify the auth data".into(),
            ));
        }

        self.auth_identity = builder.auth_data.cloned().map(AuthIdentityBuffers::from);

        Ok(AcquireCredentialsHandleResult {
            credentials_handle: self.auth_identity.clone(),
            expiry: None,
        })
    }

    #[instrument(ret, fields(state = self.state.as_ref()), skip_all)]
    fn initialize_security_context_impl<'a>(
        &mut self,
        builder: &mut builders::FilledInitializeSecurityContext<'a, Self::CredentialsHandle>,
    ) -> Result<crate::InitializeSecurityContextResult> {
        trace!(?builder);

        let status = match &self.state {
            CredSspState::Tls => {
                // input token can not present on the first call
                let input_token = builder
                    .input
                    .as_mut()
                    .and_then(|buffers| SecurityBuffer::find_buffer_mut(buffers, SecurityBufferType::Token).ok())
                    .map(|sec_buffer| sec_buffer.buffer.as_slice())
                    .unwrap_or_default();
                let (bytes_written, tls_buffer) = self.tls_connection.process_tls_packets(input_token)?;

                if bytes_written == 0 {
                    self.state = CredSspState::NegoToken;

                    // delete the previous TLS message
                    builder.input = None;

                    return self.initialize_security_context_impl(builder);
                }

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token.buffer = tls_buffer;

                SecurityStatus::ContinueNeeded
            }
            CredSspState::NegoToken => {
                // decrypt and decode TsRequest from input buffers
                let mut ts_request = builder
                    .input
                    .as_ref()
                    .map(|input| self.decrypt_and_decode_ts_request(input))
                    .unwrap_or_else(|| Ok(TsRequest::default()))?;

                self.cred_ssp_context.check_peer_version(ts_request.version)?;

                let mut input_token = vec![SecurityBuffer::new(
                    ts_request.nego_tokens.take().unwrap_or_default(),
                    SecurityBufferType::Token,
                )];

                let mut output_token = vec![SecurityBuffer::new(Vec::with_capacity(1024), SecurityBufferType::Token)];

                let mut inner_builder =
                    EmptyInitializeSecurityContext::<<SspiContext as SspiImpl>::CredentialsHandle>::new()
                        .with_credentials_handle(builder.credentials_handle.take().ok_or_else(|| {
                            Error::new(
                                ErrorKind::WrongCredentialHandle,
                                "credentials handle is not present".into(),
                            )
                        })?)
                        .with_context_requirements(ClientRequestFlags::empty())
                        .with_target_data_representation(DataRepresentation::Native);
                if let Some(target_name) = &builder.target_name {
                    inner_builder = inner_builder.with_target_name(target_name);
                }
                let mut inner_builder = inner_builder
                    .with_input(&mut input_token)
                    .with_output(&mut output_token);

                let result = self
                    .cred_ssp_context
                    .sspi_context
                    .initialize_security_context_impl(&mut inner_builder)?;

                ts_request.nego_tokens = Some(output_token.remove(0).buffer);

                if result.status == SecurityStatus::Ok {
                    let public_key = self.raw_peer_public_key()?;

                    let peer_version = self
                        .cred_ssp_context
                        .peer_version
                        .expect("An encrypt public key client function cannot be fired without any incoming TSRequest");
                    ts_request.pub_key_auth = Some(self.cred_ssp_context.encrypt_public_key(
                        &public_key,
                        EndpointType::Client,
                        &self.nonce,
                        peer_version,
                    )?);

                    ts_request.client_nonce = self.nonce;

                    if let Some(nego_tokens) = &ts_request.nego_tokens {
                        if nego_tokens.is_empty() {
                            ts_request.nego_tokens = None;
                        }
                    }

                    self.state = CredSspState::AuthInfo;
                }

                let mut encoded_ts_request = Vec::new();
                ts_request.encode_ts_request(&mut encoded_ts_request)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token.buffer = self.tls_connection.encrypt_tls(&encoded_ts_request)?;

                SecurityStatus::ContinueNeeded
            }
            CredSspState::AuthInfo => {
                let mut ts_request = builder
                    .input
                    .as_ref()
                    .map(|input| self.decrypt_and_decode_ts_request(input))
                    .unwrap_or_else(|| Ok(TsRequest::default()))?;

                ts_request.nego_tokens = None;

                let pub_key_auth = ts_request
                    .pub_key_auth
                    .take()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Expected an encrypted public key".into()))?;
                let peer_version = self
                    .cred_ssp_context
                    .peer_version
                    .expect("An encrypt public key client function cannot be fired without any incoming TSRequest");

                let peer_public_key = self.raw_peer_public_key()?;
                self.cred_ssp_context.decrypt_public_key(
                    &peer_public_key,
                    pub_key_auth.as_ref(),
                    EndpointType::Client,
                    &self.nonce,
                    peer_version,
                )?;

                let credentials = builder
                    .credentials_handle
                    .take()
                    .and_then(|c| c.as_ref())
                    .ok_or_else(|| {
                        Error::new(
                            ErrorKind::WrongCredentialHandle,
                            "credentials handle is not present".into(),
                        )
                    })?;

                ts_request.auth_info = Some(
                    self.cred_ssp_context
                        .encrypt_ts_credentials(credentials, CredSspMode::WithCredentials)?,
                );

                let mut encoded_ts_request = Vec::new();
                ts_request.encode_ts_request(&mut encoded_ts_request)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token.buffer = self.tls_connection.encrypt_tls(&encoded_ts_request)?;

                self.state = CredSspState::Final;

                SecurityStatus::Ok
            }
            CredSspState::Final => {
                return Err(Error::new(
                    ErrorKind::OutOfSequence,
                    "Error: Initialize security context function has been called after authorization".into(),
                ));
            }
        };

        trace!(?builder);

        Ok(InitializeSecurityContextResult {
            status,
            flags: ClientResponseFlags::empty(),
            expiry: None,
        })
    }

    #[instrument(level = "debug", ret, fields(state = self.state.as_ref()), skip(self, _builder))]
    fn accept_security_context_impl<'a>(
        &'a mut self,
        _builder: builders::FilledAcceptSecurityContext<'a, Self::AuthenticationData, Self::CredentialsHandle>,
    ) -> Result<crate::AcceptSecurityContextResult> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "AcceptSecurityContext is not supported in SspiCredSsp context".into(),
        ))
    }
}

impl SspiEx for SspiCredSsp {
    #[instrument(level = "trace", ret, fields(state = self.state.as_ref()), skip(self))]
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) {
        self.auth_identity = Some(identity.into());
    }
}
