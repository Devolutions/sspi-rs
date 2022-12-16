use std::sync::Arc;

use lazy_static::lazy_static;
use rustls::{ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection};

use super::{CredSspContext, SspiContext};
use crate::internal::SspiImpl;
use crate::sspi::{self, PACKAGE_ID_NONE};
use crate::utils::file_message;
use crate::{
    builders, negotiate, ntlm, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers, CertTrustStatus,
    ClientResponseFlags, ContextNames, ContextSizes, DecryptionFlags, EncryptionFlags, Error, ErrorKind,
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
        })
    }
}

impl Sspi for SspiCredSsp {
    fn complete_auth_token(&mut self, _token: &mut [SecurityBuffer]) -> Result<SecurityStatus> {
        Ok(SecurityStatus::Ok)
    }

    fn encrypt_message(
        &mut self,
        flags: EncryptionFlags,
        message: &mut [SecurityBuffer],
        sequence_number: u32,
    ) -> Result<SecurityStatus> {
        self.cred_ssp_context
            .sspi_context
            .encrypt_message(flags, message, sequence_number)
    }

    fn decrypt_message(&mut self, message: &mut [SecurityBuffer], sequence_number: u32) -> Result<DecryptionFlags> {
        self.cred_ssp_context
            .sspi_context
            .decrypt_message(message, sequence_number)
    }

    fn query_context_sizes(&mut self) -> Result<ContextSizes> {
        self.cred_ssp_context.sspi_context.query_context_sizes()
    }

    fn query_context_names(&mut self) -> Result<ContextNames> {
        self.cred_ssp_context.sspi_context.query_context_names()
    }

    fn query_context_package_info(&mut self) -> Result<PackageInfo> {
        sspi::query_security_package_info(SecurityPackageType::CredSsp)
    }

    fn query_context_cert_trust_status(&mut self) -> Result<CertTrustStatus> {
        self.cred_ssp_context.sspi_context.query_context_cert_trust_status()
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
        _builder: builders::FilledAcquireCredentialsHandle<'a, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> Result<crate::AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
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
        let status = match &self.state {
            CredSspState::Tls => {
                file_message("sspi: init_sec: tls");
                let client_connection = match &mut self.tls_connection {
                    Connection::Client(client_connection) => client_connection,
                    Connection::Server(_) => {
                        return Err(Error::new(
                            ErrorKind::InternalError,
                            "Error: Called initialize_security_context_impl on the server's context.".into(),
                        ))
                    }
                };

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

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token.buffer = tls_buffer;
                file_message(&format!("sspi: init_sec: out buffers: {:?}", builder.output));

                // maybe replace with `bytes_written == 0` ? will see
                if !client_connection.is_handshaking() {
                    self.state = CredSspState::NegoToken;
                }

                SecurityStatus::ContinueNeeded
            }
            CredSspState::NegoToken => todo!(),
            CredSspState::AuthInfo => todo!(),
            CredSspState::Final => todo!(),
        };

        Ok(InitializeSecurityContextResult {
            status,
            flags: ClientResponseFlags::empty(),
            expiry: None,
        })
    }

    fn accept_security_context_impl<'a>(
        &'a mut self,
        builder: builders::FilledAcceptSecurityContext<'a, Self::AuthenticationData, Self::CredentialsHandle>,
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
