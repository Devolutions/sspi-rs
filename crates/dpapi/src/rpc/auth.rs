use sspi::builders::{AcquireCredentialsHandle, WithoutCredentialUse};
use sspi::credssp::SspiContext;
use sspi::{
    AcquireCredentialsHandleResult, BufferType, ClientRequestFlags, CredentialUse, Credentials, CredentialsBuffers,
    DataRepresentation, EncryptionFlags, SecurityBuffer, SecurityBufferRef, SecurityBufferFlags, Sspi, SecurityStatus,
};
use thiserror::Error;

use crate::rpc::pdu::{AuthenticationLevel, SecurityProvider, SecurityTrailer};

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("{0} security provider is not supported")]
    SecurityProviderNotSupported(&'static str),

    #[error("SSPI authorization error: {0}")]
    Sspi(#[from] sspi::Error),
}

pub type AuthResult<T> = Result<T, AuthError>;

#[derive(Debug)]
pub struct AuthProvider {
    security_type: SecurityProvider,
    security_context: SspiContext,
    credentials: Credentials,
    credentials_handle: Option<CredentialsBuffers>,
    is_finished: bool,
}

impl AuthProvider {
    pub fn new(security_context: SspiContext, credentials: Credentials) -> AuthResult<Self> {
        let security_type = match &security_context {
            SspiContext::Ntlm(_) => SecurityProvider::Winnt,
            SspiContext::Kerberos(_) => SecurityProvider::GssKerberos,
            SspiContext::Negotiate(_) => SecurityProvider::GssNegotiate,
            SspiContext::Pku2u(_) => Err(AuthError::SecurityProviderNotSupported("PKU2U"))?,
        };

        Ok(Self {
            security_type,
            security_context,
            is_finished: false,
            credentials,
            credentials_handle: None,
        })
    }

    pub fn is_finished(&self) -> bool {
        self.is_finished
    }

    pub fn get_empty_trailer(&mut self, pad_length: u8) -> AuthResult<SecurityTrailer> {
        // let header_len = self.security_context.query_context_stream_sizes()?.header;
        // TODO:
        let header_len = 76;

        Ok(SecurityTrailer {
            security_type: self.security_type,
            level: AuthenticationLevel::PktPrivacy,
            pad_length,
            context_id: 0,
            auth_value: vec![0; header_len],
        })
    }

    pub fn wrap(
        &mut self,
        header_data: &[u8],
        body_data: &[u8],
        security_trailer_data: &[u8],
        sign_header: bool,
    ) -> AuthResult<Vec<u8>> {
        let mut token = [0; 76];

        let mut header = header_data.to_vec();
        let mut body = body_data.to_vec();
        let mut trailer = security_trailer_data.to_vec();

        let mut message = if sign_header {
            vec![
                SecurityBufferRef::data_buf(&mut header).with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
                SecurityBufferRef::data_buf(&mut body),
                SecurityBufferRef::data_buf(&mut trailer)
                    .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
                SecurityBufferRef::token_buf(&mut token),
            ]
        } else {
            vec![
                SecurityBufferRef::data_buf(&mut header).with_flags(SecurityBufferFlags::SECBUFFER_READONLY),
                SecurityBufferRef::data_buf(&mut body),
                SecurityBufferRef::data_buf(&mut trailer).with_flags(SecurityBufferFlags::SECBUFFER_READONLY),
                SecurityBufferRef::token_buf(&mut token),
            ]
        };

        println!("message to wrap: {:?}", message);

        self.security_context
            .encrypt_message(EncryptionFlags::empty(), &mut message, 0)?;

        println!("output message: {:?}", message);

        Ok(message.iter().fold(Vec::new(), |mut result, buf| {
            result.extend_from_slice(buf.data());
            result
        }))
    }

    pub fn unwrap(
        &mut self,
        header_data: &[u8],
        body_data: &[u8],
        security_trailer_data: &[u8],
        signature_data: &[u8],
        sign_header: bool,
    ) -> AuthResult<Vec<u8>> {
        let mut header = header_data.to_vec();
        let mut body = body_data.to_vec();
        let mut trailer = security_trailer_data.to_vec();
        let mut signature = signature_data.to_vec();

        let mut message = if sign_header {
            vec![
                SecurityBufferRef::data_buf(&mut header).with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
                SecurityBufferRef::data_buf(&mut body),
                SecurityBufferRef::data_buf(&mut trailer)
                    .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
                SecurityBufferRef::token_buf(&mut signature),
            ]
        } else {
            vec![
                SecurityBufferRef::data_buf(&mut header).with_flags(SecurityBufferFlags::SECBUFFER_READONLY),
                SecurityBufferRef::data_buf(&mut body),
                SecurityBufferRef::data_buf(&mut trailer).with_flags(SecurityBufferFlags::SECBUFFER_READONLY),
                SecurityBufferRef::token_buf(&mut signature),
            ]
        };

        self.security_context.decrypt_message(&mut message, 0)?;

        Ok(message[1].data().to_vec())
    }

    pub fn acquire_credentials_handle(&mut self) -> AuthResult<()> {
        let builder = AcquireCredentialsHandle::<'_, _, _, WithoutCredentialUse>::new();
        let AcquireCredentialsHandleResult { credentials_handle, .. } = builder
            .with_auth_data(&self.credentials)
            .with_credential_use(CredentialUse::Outbound)
            .execute(&mut self.security_context)?;
        self.credentials_handle = credentials_handle;

        Ok(())
    }

    pub fn initialize_security_context(&mut self, in_token: &[u8]) -> AuthResult<SecurityTrailer> {
        let mut input_token = [SecurityBuffer::new(in_token.to_vec(), BufferType::Token)];
        let mut output_token = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];
        let mut credentials_handle = self.credentials_handle.take();

        let mut builder = self
            .security_context
            .initialize_security_context()
            .with_credentials_handle(&mut credentials_handle)
            .with_context_requirements(
                ClientRequestFlags::MUTUAL_AUTH
                    // | ClientRequestFlags::USE_SESSION_KEY
                    | ClientRequestFlags::INTEGRITY
                    | ClientRequestFlags::DELEGATE
                    | ClientRequestFlags::USE_DCE_STYLE
                    | ClientRequestFlags::CONFIDENTIALITY,
            )
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name("host/win-956cqossjtf.tbt.com")
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
