use sspi::credssp::SspiContext;
use sspi::Sspi;
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
}

impl AuthProvider {
    pub fn new(security_context: SspiContext) -> AuthResult<Self> {
        let security_type = match &security_context {
            SspiContext::Ntlm(_) => SecurityProvider::Winnt,
            SspiContext::Kerberos(_) => SecurityProvider::GssKerberos,
            SspiContext::Negotiate(_) => SecurityProvider::GssNegotiate,
            SspiContext::Pku2u(_) => Err(AuthError::SecurityProviderNotSupported("PKU2U"))?,
        };

        Ok(Self {
            security_type,
            security_context,
        })
    }

    pub fn get_empty_trailer(&mut self, pad_length: u8) -> AuthResult<SecurityTrailer> {
        let header_len = self.security_context.query_context_stream_sizes()?.header;

        Ok(SecurityTrailer {
            security_type: self.security_type,
            level: AuthenticationLevel::PktPrivacy,
            pad_length,
            context_id: 0,
            auth_value: vec![0; header_len.try_into().unwrap()],
        })
    }

    pub fn wrap(&self, header: &[u8], body: &[u8], security_trailer: &[u8], sign_header: bool) -> AuthResult<Vec<u8>> {
        // TODO: call Sspi::encrypt_message method

        Ok(vec![])
    }

    pub fn unwrap(
        &self,
        header: &[u8],
        body: &[u8],
        security_trailer: &[u8],
        signature: &[u8],
        sign_header: bool,
    ) -> AuthResult<Vec<u8>> {
        // TODO: call Sspi::encrypt_message method

        Ok(vec![])
    }
}
