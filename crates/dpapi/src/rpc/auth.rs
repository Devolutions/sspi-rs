use sspi::builders::{AcquireCredentialsHandle, WithoutCredentialUse};
use sspi::credssp::SspiContext;
use sspi::{
    AcquireCredentialsHandleResult, BufferType, ClientRequestFlags, CredentialUse, Credentials, CredentialsBuffers,
    DataRepresentation, EncryptionFlags, SecurityBuffer, SecurityBufferFlags, SecurityBufferRef, SecurityStatus, Sspi,
};
use thiserror::Error;

use crate::rpc::pdu::{AuthenticationLevel, SecurityProvider, SecurityTrailer};

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("{0} security provider is not supported")]
    SecurityProviderNotSupported(&'static str),

    #[error("SSPI authorization error: {0}")]
    Sspi(#[from] sspi::Error),

    #[error(transparent)]
    IntConversion(#[from] std::num::TryFromIntError),
}

pub type AuthResult<T> = Result<T, AuthError>;

/// Performs RPC authentication using underlying SSPI provider.
///
/// Basically, this is a convenient wrapper over [SspiContext].
/// It allows to perform RPC authentication without going into details of SSPI configuration and
/// authentication parameters.
#[derive(Debug)]
pub struct AuthProvider {
    security_type: SecurityProvider,
    security_context: SspiContext,
    credentials_handle: Option<CredentialsBuffers>,
    is_finished: bool,
    target_name: String,
}

impl AuthProvider {
    /// Creates a new [AuthProvider].
    pub fn new(mut security_context: SspiContext, credentials: Credentials, target_host: &str) -> AuthResult<Self> {
        let security_type = match &security_context {
            SspiContext::Ntlm(_) => SecurityProvider::Winnt,
            SspiContext::Kerberos(_) => SecurityProvider::GssKerberos,
            SspiContext::Negotiate(_) => SecurityProvider::GssNegotiate,
            SspiContext::Pku2u(_) => Err(AuthError::SecurityProviderNotSupported("PKU2U"))?,
        };

        let builder = AcquireCredentialsHandle::<'_, _, _, WithoutCredentialUse>::new();
        let AcquireCredentialsHandleResult { credentials_handle, .. } = builder
            .with_auth_data(&credentials)
            .with_credential_use(CredentialUse::Outbound)
            .execute(&mut security_context)?;

        Ok(Self {
            security_type,
            security_context,
            is_finished: false,
            credentials_handle,
            target_name: format!("host/{}", target_host),
        })
    }

    /// Returns a `bool` value indicating whether authentication is complete.
    pub fn is_finished(&self) -> bool {
        self.is_finished
    }

    /// Returns an empty [SecurityTrailer] with correct parameters.
    pub fn empty_trailer(&mut self, pad_length: u8) -> AuthResult<SecurityTrailer> {
        Ok(SecurityTrailer {
            security_type: self.security_type,
            level: AuthenticationLevel::PktPrivacy,
            pad_length,
            context_id: 0,
            auth_value: vec![
                0;
                self.security_context
                    .query_context_sizes()?
                    .security_trailer
                    .try_into()?
            ],
        })
    }

    /// Encrypts input buffers using inner SSPI security context.
    ///
    /// This method is an equivalent to `GSS_WrapEx()`. More info: [Kerberos Binding of GSS_WrapEx()](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e94b3acd-8415-4d0d-9786-749d0c39d550).
    ///
    /// **Important**. `header`, `body`, `security_trailer_header`, `security_trailer_data` are parts of one RPC PDU:
    /// * `header`: RPC PDU header + header data from the RPC PDU body.
    /// * `body` contains data from the RPC PDU body that must be encrypted.
    /// * `security_trailer_header`: RPC PDU security trailer header data (i.e. security trailer without `auth_value`).
    /// * `security_trailer_data`: RPC PDU security trailer `auth_value`. Basically, it's a Kerberos Wrap Token.
    ///
    /// All encryption is performed in-place.
    #[instrument(ret, skip(self))]
    pub fn wrap_with_header_sign(
        &mut self,
        header: &mut [u8],
        body: &mut [u8],
        security_trailer_header: &mut [u8],
        security_trailer_data: &mut [u8],
    ) -> AuthResult<()> {
        let mut message = vec![
            SecurityBufferRef::data_buf(header).with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
            SecurityBufferRef::data_buf(body),
            SecurityBufferRef::data_buf(security_trailer_header)
                .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
            SecurityBufferRef::token_buf(security_trailer_data),
        ];

        self.security_context
            .encrypt_message(EncryptionFlags::empty(), &mut message, 0)?;

        Ok(())
    }

    /// Encrypts input buffers using inner SSPI security context.
    ///
    /// This method is an equivalent to `GSS_WrapEx()`. More info: [Kerberos Binding of GSS_WrapEx()](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e94b3acd-8415-4d0d-9786-749d0c39d550).
    ///
    /// **Important**. `body` and `security_trailer_data` are parts of one RPC PDU:
    /// * `body` contains data from the RPC PDU body that must be encrypted.
    /// * `security_trailer_data`: RPC PDU security trailer `auth_value`. Basically, it's a Kerberos Wrap Token.
    ///
    /// All encryption is performed in-place.
    pub fn wrap(&mut self, body: &mut [u8], security_trailer_data: &mut [u8]) -> AuthResult<()> {
        let mut message = vec![
            SecurityBufferRef::data_buf(body),
            SecurityBufferRef::token_buf(security_trailer_data),
        ];

        self.security_context
            .encrypt_message(EncryptionFlags::empty(), &mut message, 0)?;

        Ok(())
    }

    /// Decrypts input buffers using inner SSPI security context.
    ///
    /// This method is an equivalent to `GSS_UnwrapEx()`. More info: [Kerberos Binding of GSS_WrapEx()](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e94b3acd-8415-4d0d-9786-749d0c39d550) and [GSS_UnwrapEx() Call](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/9e3981a9-6564-4db6-a70e-4af4c07d03b3).
    ///
    /// **Important**. `header`, `body`, `security_trailer_header`, and `security_trailer_data` are parts of one RPC PDU:
    /// * `header`: RPC PDU header + header data from the RPC PDU body.
    /// * `body` contains data from the RPC PDU body that needs to be decrypted.
    /// * `security_trailer_header`: RPC PDU security trailer header data (i.e. security trailer without `auth_value`).
    /// * `security_trailer_data`: `auth_value` of the RPC PDU security trailer. Basically, it's a Kerberos Wrap Token.
    ///
    /// All decryption is performed in-place.
    #[instrument(ret, skip(self))]
    pub fn unwrap_with_header_sign(
        &mut self,
        header: &mut [u8],
        body: &mut [u8],
        security_trailer_header: &mut [u8],
        security_trailer_data: &mut [u8],
    ) -> AuthResult<Vec<u8>> {
        let mut message = vec![
            SecurityBufferRef::data_buf(header).with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
            SecurityBufferRef::data_buf(body),
            SecurityBufferRef::data_buf(security_trailer_header)
                .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
            SecurityBufferRef::token_buf(security_trailer_data),
        ];

        self.security_context.decrypt_message(&mut message, 0)?;

        Ok(message[1].data().to_vec())
    }

    /// Decrypts input buffers using inner SSPI security context.
    ///
    /// This method is an equivalent to `GSS_UnwrapEx()`. More info: [Kerberos Binding of GSS_WrapEx()](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e94b3acd-8415-4d0d-9786-749d0c39d550) and [GSS_UnwrapEx() Call](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/9e3981a9-6564-4db6-a70e-4af4c07d03b3).
    ///
    /// **Important**. `body` and `security_trailer_data` are parts of one RPC PDU:
    /// * `body` contains data from the RPC PDU body that needs to be decrypted.
    /// * `security_trailer_data`: `auth_value` of the RPC PDU security trailer. Basically, it's a Kerberos Wrap Token.
    ///
    /// All decryption is performed in-place.
    #[instrument(ret, skip(self))]
    pub fn unwrap(&mut self, body: &mut [u8], security_trailer_data: &mut [u8]) -> AuthResult<Vec<u8>> {
        let mut message = vec![
            SecurityBufferRef::data_buf(body),
            SecurityBufferRef::token_buf(security_trailer_data),
        ];

        self.security_context.decrypt_message(&mut message, 0)?;

        Ok(message[1].data().to_vec())
    }

    /// Performs one step in authorization process.
    ///
    /// The client should call this method until `self.is_finished()` is `true`.
    #[instrument(ret, fields(state = ?self.is_finished), skip(self))]
    pub fn initialize_security_context(&mut self, in_token: Vec<u8>) -> AuthResult<SecurityTrailer> {
        let mut input_token = [SecurityBuffer::new(in_token, BufferType::Token)];
        let mut output_token = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];
        let mut credentials_handle = self.credentials_handle.take();

        let mut builder = self
            .security_context
            .initialize_security_context()
            .with_credentials_handle(&mut credentials_handle)
            .with_context_requirements(
                // Warning: do not change these flags if you don't know what you are doing.
                // The absence or presence of some flags can break the RPC auth. For example,
                // if you enable the `ClientRequestFlags::USER_TO_USER`, then it will fail.
                ClientRequestFlags::MUTUAL_AUTH
                    | ClientRequestFlags::INTEGRITY
                    | ClientRequestFlags::DELEGATE
                    | ClientRequestFlags::USE_DCE_STYLE
                    | ClientRequestFlags::CONFIDENTIALITY,
            )
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(&self.target_name)
            .with_input(&mut input_token)
            .with_output(&mut output_token);
        let result = self.security_context.initialize_security_context_sync(&mut builder)?;
        self.is_finished = result.status == SecurityStatus::Ok;

        self.credentials_handle = credentials_handle;
        let auth_value = output_token.remove(0).buffer;

        Ok(SecurityTrailer {
            security_type: self.security_type,
            level: AuthenticationLevel::PktPrivacy,
            pad_length: 0,
            context_id: 0,
            auth_value,
        })
    }
}
