use std::io::{Read, Write};
use std::sync::Arc;

use lazy_static::lazy_static;
use picky_asn1_x509::Certificate;
use rand::rngs::OsRng;
use rand::Rng;
use rustls::{ClientConfig, ClientConnection, Connection, ProtocolVersion, ServerConfig, ServerConnection};

use super::ts_request::NONCE_SIZE;
use super::{CredSspContext, CredSspMode, EndpointType, SspiContext, TsRequest};
use crate::builders::EmptyInitializeSecurityContext;
use crate::internal::SspiImpl;
use crate::sspi::{
    self, CertContext, CertEncodingType, ConnectionCipher, ConnectionHash, ConnectionInfo, ConnectionKeyExchange,
    ConnectionProtocol, PACKAGE_ID_NONE,
};
use crate::utils::file_message;
use crate::{
    builders, negotiate, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers, CertTrustErrorStatus,
    CertTrustInfoStatus, CertTrustStatus, ClientRequestFlags, ClientResponseFlags, ContextNames, ContextSizes,
    CredentialUse, DataRepresentation, DecryptionFlags, EncryptionFlags, Error, ErrorKind,
    InitializeSecurityContextResult, PackageCapabilities, PackageInfo, Result, SecurityBuffer, SecurityBufferType,
    SecurityPackageType, SecurityStatus, Sspi, SspiEx,
};

pub const PKG_NAME: &str = "CREDSSP";

lazy_static! {
    pub static ref PACKAGE_INFO: PackageInfo = PackageInfo {
        capabilities: PackageCapabilities::empty(),
        rpc_id: PACKAGE_ID_NONE,
        max_token_len: negotiate::PACKAGE_INFO.max_token_len + 1,
        name: SecurityPackageType::CredSsp,
        comment: String::from("CredSsp"),
    };
}

pub mod danger {
    use std::time::SystemTime;

    use rustls::client::{ServerCertVerified, ServerCertVerifier};
    use rustls::{Certificate, Error, ServerName};

    pub struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &Certificate,
            _intermediates: &[Certificate],
            _server_name: &ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: SystemTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
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
    tls_connection: Connection,
    nonce: Option<[u8; NONCE_SIZE]>,
}

impl SspiCredSsp {
    pub fn new_client(sspi_context: SspiContext) -> Result<Self> {
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
            tls_connection: Connection::Client(
                ClientConnection::new(config, example_com)
                    .map_err(|err| Error::new(ErrorKind::InternalError, err.to_string()))?,
            ),
            nonce: Some(OsRng::default().gen::<[u8; NONCE_SIZE]>()),
        })
    }

    pub fn new_server(sspi_context: SspiContext) -> Result<Self> {
        let server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![], rustls::PrivateKey(vec![]))
            .map_err(|err| Error::new(ErrorKind::InternalError, err.to_string()))?;
        let config = Arc::new(server_config);

        Ok(Self {
            state: CredSspState::Tls,
            cred_ssp_context: Box::new(CredSspContext::new(sspi_context)),
            auth_identity: None,
            tls_connection: Connection::Server(
                ServerConnection::new(config).map_err(|err| Error::new(ErrorKind::InternalError, err.to_string()))?,
            ),
            // nonce for the server will be in the incoming TsRequest
            nonce: None,
        })
    }

    fn encrypt_tls(&mut self, plain_data: &[u8]) -> Result<Vec<u8>> {
        file_message("start encrypt_tls");

        let mut writer = self.tls_connection.writer();
        writer.write(plain_data)?;

        let mut tls_buffer = Vec::new();
        file_message("before write encrypted tls");
        let bytes_written = self.tls_connection.write_tls(&mut tls_buffer)?;
        file_message(&format!(
            "after write encrypted tls: {} {:?}",
            bytes_written, tls_buffer
        ));

        Ok(tls_buffer)
    }

    fn decrypt_tls(&mut self, mut payload: &[u8]) -> Result<Vec<u8>> {
        file_message("start decrypt_tls");

        self.tls_connection.read_tls(&mut payload)?;
        file_message("before process new packets");
        let tls_state = self
            .tls_connection
            .process_new_packets()
            .map_err(|err| Error::new(ErrorKind::InternalError, err.to_string()))?;
        file_message(&format!("tls_state: {:?}", tls_state));

        let mut reader = self.tls_connection.reader();

        let mut plain_data = vec![0; 2048];
        let plain_data_len = reader.read(&mut plain_data)?;

        plain_data.resize(plain_data_len, 0);

        Ok(plain_data)
    }

    fn raw_peer_public_key(&self) -> Result<Vec<u8>> {
        if let Some(certificates) = self.tls_connection.peer_certificates() {
            file_message(&format!(
                "peer certificates present :) {:?} {}",
                certificates,
                certificates.len()
            ));
            let raw_server_certificate = certificates.get(0).map(|cert| &cert.0).ok_or_else(|| {
                Error::new(
                    ErrorKind::CertificateUnknown,
                    "Can not acquire server certificate".into(),
                )
            })?;

            let server_certificate: Certificate = picky_asn1_der::from_bytes(raw_server_certificate)?;

            let raw_public_key = match server_certificate
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
            {
                picky_asn1_x509::PublicKey::Rsa(rsa_pk) => picky_asn1_der::to_vec(&rsa_pk.0)?,
                picky_asn1_x509::PublicKey::Ec(_) => todo!(),
                picky_asn1_x509::PublicKey::Ed(_) => todo!(),
            };

            file_message(&format!("encoded public key: {:?}", raw_public_key));

            Ok(raw_public_key)
        } else {
            file_message("no peer certificates :(");
            Err(Error::new(
                ErrorKind::CertificateUnknown,
                "The server certificate is not present".into(),
            ))
        }
    }
}

impl Sspi for SspiCredSsp {
    fn complete_auth_token(&mut self, _token: &mut [SecurityBuffer]) -> Result<SecurityStatus> {
        file_message("SSPI: complete auth token");
        Ok(SecurityStatus::Ok)
    }

    fn encrypt_message(
        &mut self,
        _flags: EncryptionFlags,
        message: &mut [SecurityBuffer],
        _sequence_number: u32,
    ) -> Result<SecurityStatus> {
        file_message(&format!("SSPI: encrypt_message: {:?}", message));

        for sb in message.iter() {
            file_message(&format!("{:?} {}", sb.buffer_type, sb.buffer.len()));
        }

        let plain_message = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;
        let plain_len = plain_message.buffer.len();

        let encrypted_message = self.encrypt_tls(&plain_message.buffer)?;

        file_message(&format!(
            "lens: plain({}), encrypted({})",
            plain_len,
            encrypted_message.len()
        ));

        // plain_message.buffer = encrypted_message;

        let stream_header_data = encrypted_message[0..5].to_vec();
        let data = encrypted_message[5..(5 + plain_len)].to_vec();
        let stream_trailer_data = encrypted_message[(5 + plain_len)..].to_vec();
        file_message(&format!(
            "h({}), d({}), t({})",
            stream_header_data.len(),
            data.len(),
            stream_trailer_data.len()
        ));

        if let Ok(stream_header) = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::StreamHeader) {
            file_message(&format!("old header len: {}", stream_header.buffer.len()));
            stream_header.buffer = stream_header_data;
        } else {
            let empty_buffer = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Empty)?;
            empty_buffer.buffer_type = SecurityBufferType::StreamHeader;
            empty_buffer.buffer = stream_header_data;
        }

        let plain_message = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;
        plain_message.buffer = data;

        if let Ok(trailer) = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::StreamTrailer) {
            file_message(&format!("old trailer len: {}", trailer.buffer.len()));
            trailer.buffer = stream_trailer_data;
        } else {
            let empty_buffer = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Empty)?;
            empty_buffer.buffer_type = SecurityBufferType::StreamTrailer;
            empty_buffer.buffer = stream_trailer_data;
        }

        file_message(&format!("finish encrypt_message: {:?}", message));

        Ok(SecurityStatus::Ok)
    }

    fn decrypt_message(&mut self, message: &mut [SecurityBuffer], _sequence_number: u32) -> Result<DecryptionFlags> {
        file_message(&format!("SSPI: decrypt: {:?}", message));

        let encrypted_message = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;

        // 5 - TLS message header
        // 11 - MAC + padding
        if encrypted_message.buffer.len() < 5 + 11 {
            return Err(Error::new(
                ErrorKind::DecryptFailure,
                "Input message is too short".into(),
            ));
        }

        let stream_header_data = encrypted_message.buffer[0..5].to_vec();

        let decrypted_message = self.decrypt_tls(&encrypted_message.buffer)?;
        file_message(&format!("decrypted data: {:?}", decrypted_message));

        let stream_trailer_data = encrypted_message.buffer[(5 + decrypted_message.len())..].to_vec();

        // encrypted_message.buffer = decrypted_message;

        encrypted_message.buffer = stream_header_data;
        encrypted_message.buffer_type = SecurityBufferType::StreamHeader;

        let empty_buffer = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Empty)?;
        empty_buffer.buffer_type = SecurityBufferType::Data;
        empty_buffer.buffer = decrypted_message;

        // if let Ok(stream_header) = SecurityBuffer::find_buffer_mut(message,  SecurityBufferType::StreamHeader) {
        //     stream_header.buffer = stream_header_data;
        // } else {
        //     let empty_buffer = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Empty)?;
        //     empty_buffer.buffer_type = SecurityBufferType::StreamHeader;
        //     empty_buffer.buffer = stream_header_data;
        // }

        if let Ok(trailer) = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::StreamTrailer) {
            trailer.buffer = stream_trailer_data;
        } else {
            let empty_buffer = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Empty)?;
            empty_buffer.buffer_type = SecurityBufferType::StreamTrailer;
            empty_buffer.buffer = stream_trailer_data;
        }

        file_message("finish decrypt_message");

        Ok(DecryptionFlags::empty())
    }

    fn query_context_sizes(&mut self) -> Result<ContextSizes> {
        file_message("SSPI: query context sized");
        self.cred_ssp_context.sspi_context.query_context_sizes()
    }

    fn query_context_names(&mut self) -> Result<ContextNames> {
        file_message("SSPI: query context names");
        self.cred_ssp_context.sspi_context.query_context_names()
    }

    fn query_context_package_info(&mut self) -> Result<PackageInfo> {
        file_message("SSPI: query context package info");
        sspi::query_security_package_info(SecurityPackageType::CredSsp)
    }

    fn query_context_cert_trust_status(&mut self) -> Result<CertTrustStatus> {
        file_message("SSPI: query context cert trust status");
        // self.cred_ssp_context.sspi_context.query_context_cert_trust_status()
        Ok(CertTrustStatus {
            error_status: CertTrustErrorStatus::NO_ERROR,
            info_status: CertTrustInfoStatus::IS_CA_TRUSTED,
        })
    }

    fn query_context_remote_cert(&mut self) -> Result<CertContext> {
        file_message("query_context_remote_cert");
        if let Some(certificates) = self.tls_connection.peer_certificates() {
            file_message(&format!(
                "peer certificates present :) {:?} {}",
                certificates,
                certificates.len()
            ));
            let raw_server_certificate = certificates.get(0).map(|cert| &cert.0).ok_or_else(|| {
                Error::new(
                    ErrorKind::CertificateUnknown,
                    "Can not acquire server certificate".into(),
                )
            })?;

            let server_certificate: Certificate = picky_asn1_der::from_bytes(raw_server_certificate)?;

            Ok(CertContext {
                encoding_type: CertEncodingType::X509AsnEncoding,
                raw_cert: raw_server_certificate.clone(),
                cert: server_certificate,
            })
        } else {
            file_message("no peer certificates :(");
            Err(Error::new(
                ErrorKind::CertificateUnknown,
                "The server certificate is not present".into(),
            ))
        }
    }

    fn query_context_negotiation_package(&mut self) -> Result<PackageInfo> {
        self.cred_ssp_context.sspi_context.query_context_package_info()
    }

    fn query_context_connection_info(&mut self) -> Result<ConnectionInfo> {
        let protocol_version = self.tls_connection.protocol_version().ok_or_else(|| {
            file_message("no protocol version :(");
            Error::new(
                ErrorKind::InternalError,
                "Can not acquire connection protocol version".into(),
            )
        })?;

        let protocol = match self.tls_connection {
            Connection::Client(_) => match protocol_version {
                ProtocolVersion::SSLv2 => ConnectionProtocol::SP_PROT_SSL2_CLIENT,
                ProtocolVersion::TLSv1_0 => ConnectionProtocol::SP_PROT_TLS1_CLIENT,
                ProtocolVersion::TLSv1_1 => ConnectionProtocol::SP_PROT_TLS1_1_CLIENT,
                ProtocolVersion::TLSv1_2 => ConnectionProtocol::SP_PROT_TLS1_2_CLIENT,
                ProtocolVersion::TLSv1_3 => ConnectionProtocol::SP_PROT_TLS1_3_CLIENT,
                version => {
                    file_message(&format!("unsupported protocol version: {:?}", version));
                    return Err(Error::new(
                        ErrorKind::InternalError,
                        format!("Unsupported connection protocol was used: {:?}", version),
                    ));
                }
            },
            Connection::Server(_) => match protocol_version {
                ProtocolVersion::SSLv2 => ConnectionProtocol::SP_PROT_SSL2_SERVER,
                ProtocolVersion::TLSv1_0 => ConnectionProtocol::SP_PROT_TLS1_SERVER,
                ProtocolVersion::TLSv1_1 => ConnectionProtocol::SP_PROT_TLS1_1_SERVER,
                ProtocolVersion::TLSv1_2 => ConnectionProtocol::SP_PROT_TLS1_2_SERVER,
                ProtocolVersion::TLSv1_3 => ConnectionProtocol::SP_PROT_TLS1_3_SERVER,
                version => {
                    file_message(&format!("unsupported protocol version: {:?}", version));
                    return Err(Error::new(
                        ErrorKind::InternalError,
                        format!("Unsupported connection protocol was used: {:?}", version),
                    ));
                }
            },
        };

        let cipher = self.tls_connection.negotiated_cipher_suite().ok_or_else(|| {
            file_message("connection cipher is not negotiated");
            Error::new(ErrorKind::InternalError, "Connection cipher is not negotiated".into())
        })?;

        // let e = self.tls_connection.

        let hash_algo = cipher.hash_algorithm();
        // let hash = match hash_algo.id {

        // };

        Ok(ConnectionInfo {
            protocol,
            cipher: ConnectionCipher::CALG_AES_256,
            cipher_strength: 256,
            hash: ConnectionHash::CALG_SHA,
            hash_strength: hash_algo.output_len as u32,
            key_exchange: ConnectionKeyExchange::CALG_RSA_KEYX,
            exchange_strength: 2048,
        })
    }

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

    fn initialize_security_context_impl<'a>(
        &mut self,
        builder: &mut builders::FilledInitializeSecurityContext<'a, Self::CredentialsHandle>,
    ) -> Result<crate::InitializeSecurityContextResult> {
        file_message("sspi: init_sec -----------------------");
        let client_connection = match &mut self.tls_connection {
            Connection::Client(client_connection) => client_connection,
            Connection::Server(_) => {
                return Err(Error::new(
                    ErrorKind::InternalError,
                    "Error: Called initialize_security_context_impl on the server's context.".into(),
                ))
            }
        };

        let status = match &self.state {
            CredSspState::Tls => {
                file_message("sspi: init_sec: tls");

                file_message(&format!("sspi: init_sec: in buffers: {:?}", builder.input));
                // input token can not present on the first call
                if let Some(input_token) = builder
                    .input
                    .as_mut()
                    .map(|buffers| SecurityBuffer::find_buffer_mut(buffers, SecurityBufferType::Token).ok())
                    .flatten()
                {
                    file_message("sspi: init_sec: read tls");
                    let mut buffer = input_token.buffer.as_slice();
                    let bytes_read = client_connection.read_tls(&mut buffer)?;
                    file_message(&format!(
                        "sspi: init_sec: read tls: {} total. prev: {}",
                        bytes_read,
                        input_token.buffer.len()
                    ));
                } else {
                    file_message("input token buffer is not present");
                }

                file_message("before process_new_packets");
                let io_status = client_connection
                    .process_new_packets()
                    .map_err(|err| Error::new(ErrorKind::InternalError, err.to_string()))?;
                file_message(&format!("after process_new_packets: {:?}", io_status));

                let mut tls_buffer = Vec::new();
                file_message("before write tls");
                let bytes_written = client_connection.write_tls(&mut tls_buffer)?;
                file_message(&format!("after write tls: {}", bytes_written));

                if bytes_written == 0 {
                    self.state = CredSspState::NegoToken;
                    file_message("new state: CredSspState::NegoToken");

                    // delete the previous TLS message
                    builder.input = None;

                    return self.initialize_security_context_impl(builder);
                }

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token.buffer = tls_buffer;
                file_message(&format!("sspi: init_sec: out buffers: {:?}", builder.output));

                SecurityStatus::ContinueNeeded
            }
            CredSspState::NegoToken => {
                file_message("CredSspState::NegoToken");

                // decrypt and decode TsRequest from input buffers
                let mut ts_request = if let Some(input) = &builder.input {
                    let encrypted_ts_request = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;
                    file_message(&format!("encrypted ts request: {:?}", encrypted_ts_request));

                    let raw_ts_request = self.decrypt_tls(&encrypted_ts_request.buffer)?;
                    file_message(&format!("raw ts request: {:?}", encrypted_ts_request));

                    let ts_request = TsRequest::from_buffer(&raw_ts_request)?;
                    file_message(&format!("decoded ts request: {:?}", ts_request));
                    ts_request.check_error()?;

                    ts_request
                } else {
                    TsRequest::default()
                };

                self.cred_ssp_context.check_peer_version(ts_request.version)?;

                let mut input_token = vec![SecurityBuffer::new(
                    ts_request.nego_tokens.take().unwrap_or_default(),
                    SecurityBufferType::Token,
                )];

                // invoke inner sspi function
                let mut output_token = vec![SecurityBuffer::new(Vec::with_capacity(1024), SecurityBufferType::Token)];

                let mut inner_builder =
                    EmptyInitializeSecurityContext::<<SspiContext as SspiImpl>::CredentialsHandle>::new()
                        .with_credentials_handle(builder.credentials_handle.take().ok_or_else(|| {
                            Error::new(ErrorKind::InvalidParameter, "credentials handle is not present".into())
                        })?)
                        .with_context_requirements(ClientRequestFlags::empty())
                        .with_target_data_representation(DataRepresentation::Native);
                if let Some(target_name) = &builder.target_name {
                    inner_builder = inner_builder.with_target_name(target_name);
                }
                let mut inner_builder = inner_builder
                    .with_input(&mut input_token)
                    .with_output(&mut output_token);

                file_message(&format!(
                    "sspi-rs: sspi: init sec: before: {:?}",
                    self.cred_ssp_context.sspi_context
                ));
                let result = self
                    .cred_ssp_context
                    .sspi_context
                    .initialize_security_context_impl(&mut inner_builder)?;
                file_message("sspi-rs: sspi: init sec: after");

                // encode new TsRequest into output buffers
                ts_request.nego_tokens = Some(output_token.remove(0).buffer);

                if result.status == SecurityStatus::Ok {
                    let public_key = if let Some(certificates) = self.tls_connection.peer_certificates() {
                        file_message(&format!(
                            "peer certificates present :) {:?} {}",
                            certificates,
                            certificates.len()
                        ));
                        let raw_server_certificate = certificates.get(0).map(|cert| &cert.0).ok_or_else(|| {
                            Error::new(
                                ErrorKind::CertificateUnknown,
                                "Can not acquire server certificate".into(),
                            )
                        })?;

                        let server_certificate: Certificate = picky_asn1_der::from_bytes(raw_server_certificate)?;

                        let raw_public_key = match server_certificate
                            .tbs_certificate
                            .subject_public_key_info
                            .subject_public_key
                        {
                            picky_asn1_x509::PublicKey::Rsa(rsa_pk) => picky_asn1_der::to_vec(&rsa_pk.0)?,
                            picky_asn1_x509::PublicKey::Ec(_) => todo!(),
                            picky_asn1_x509::PublicKey::Ed(_) => todo!(),
                        };

                        file_message(&format!("encoded public key: {:?}", raw_public_key));

                        raw_public_key
                    } else {
                        file_message("no peer certificates :(");
                        return Err(Error::new(
                            ErrorKind::CertificateUnknown,
                            "The server certificate is not present".into(),
                        ));
                    };
                    file_message(&format!("pk: {:?}", public_key));

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

                    ts_request.client_nonce = self.nonce.clone();

                    if let Some(nego_tokens) = &ts_request.nego_tokens {
                        if nego_tokens.is_empty() {
                            ts_request.nego_tokens = None;
                        }
                    }

                    self.state = CredSspState::AuthInfo;
                    file_message("new state: CredSspState::AuthInfo");
                }

                let mut encoded_ts_request = Vec::new();
                ts_request.encode_ts_request(&mut encoded_ts_request)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token.buffer = self.encrypt_tls(&encoded_ts_request)?;

                file_message(&format!("sspi: init_sec: out buffers: {:?}", builder.output));

                SecurityStatus::ContinueNeeded
            }
            CredSspState::AuthInfo => {
                file_message("cur state: CredSspState::AuthInfo");

                // decrypt and decode TsRequest from input buffers
                let mut ts_request = if let Some(input) = &builder.input {
                    let encrypted_ts_request = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;
                    file_message(&format!("encrypted ts request: {:?}", encrypted_ts_request));

                    let raw_ts_request = self.decrypt_tls(&encrypted_ts_request.buffer)?;
                    file_message(&format!("raw ts request: {:?}", encrypted_ts_request));

                    let ts_request = TsRequest::from_buffer(&raw_ts_request)?;
                    file_message(&format!("decoded ts request: {:?}", ts_request));
                    ts_request.check_error()?;

                    ts_request
                } else {
                    TsRequest::default()
                };

                ts_request.nego_tokens = None;

                let pub_key_auth = ts_request
                    .pub_key_auth
                    .take()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Expected an encrypted public key".into()))?;
                let peer_version = self
                    .cred_ssp_context
                    .peer_version
                    .expect("An encrypt public key client function cannot be fired without any incoming TSRequest");

                file_message("start  server's pub key auth verification");
                self.cred_ssp_context.decrypt_public_key(
                    &self.raw_peer_public_key()?,
                    pub_key_auth.as_ref(),
                    EndpointType::Client,
                    &self.nonce,
                    peer_version,
                )?;
                file_message("server's pub key auth is VALID :)");

                // encrypt and send credentials
                file_message(&format!("{:?}", builder.credentials_handle));
                let credentials = builder
                    .credentials_handle
                    .take()
                    .map(|c| c.as_ref())
                    .flatten()
                    .ok_or_else(|| {
                        file_message("no credentials :(");
                        Error::new(ErrorKind::InvalidParameter, "credentials handle is not present".into())
                    })?;

                ts_request.auth_info = Some(
                    self.cred_ssp_context
                        .encrypt_ts_credentials(credentials, CredSspMode::WithCredentials)?,
                );

                file_message(&format!("the final ts request: {:?}", ts_request));

                // encode and encrypt TsRequest with credentials
                let mut encoded_ts_request = Vec::new();
                ts_request.encode_ts_request(&mut encoded_ts_request)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token.buffer = self.encrypt_tls(&encoded_ts_request)?;

                file_message(&format!("sspi: init_sec: out buffers: {:?}", builder.output));

                self.state = CredSspState::Final;
                file_message("new state: CredSspState::Final");

                SecurityStatus::Ok
            }
            CredSspState::Final => {
                file_message("cur state: CredSspState::Final");
                return Err(Error::new(
                    ErrorKind::InvalidParameter,
                    "Error: Initialize security context function has been called after authorization".into(),
                ));
            }
        };

        Ok(InitializeSecurityContextResult {
            status,
            flags: ClientResponseFlags::empty(),
            expiry: None,
        })
    }

    fn accept_security_context_impl<'a>(
        &'a mut self,
        _builder: builders::FilledAcceptSecurityContext<'a, Self::AuthenticationData, Self::CredentialsHandle>,
    ) -> Result<crate::AcceptSecurityContextResult> {
        match &self.state {
            CredSspState::Tls => todo!(),
            CredSspState::NegoToken => todo!(),
            CredSspState::AuthInfo => todo!(),
            CredSspState::Final => todo!(),
        }
    }
}

impl SspiEx for SspiCredSsp {
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) {
        self.auth_identity = Some(identity.into());
    }
}
