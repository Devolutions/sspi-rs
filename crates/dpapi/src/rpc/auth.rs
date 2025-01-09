use crate::rpc::pdu::{AuthenticationLevel, SecurityProvider, SecurityTrailer};
use crate::DpapiResult;

pub struct AuthProvider {
    security_type: SecurityProvider,
}

impl AuthProvider {
    pub fn get_empty_trailer(&self, pad_length: u8) -> SecurityTrailer {
        // TODO: self.ctx.query_message_sizes().header
        let header_len = 0;

        SecurityTrailer {
            security_type: self.security_type,
            level: AuthenticationLevel::PktPrivacy,
            pad_length,
            context_id: 0,
            auth_value: vec![0; header_len],
        }
    }

    pub fn wrap(&self, header: &[u8], body: &[u8], security_trailer: &[u8], sign_header: bool) -> DpapiResult<Vec<u8>> {
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
    ) -> DpapiResult<Vec<u8>> {
        // TODO: call Sspi::encrypt_message method

        Ok(vec![])
    }
}
