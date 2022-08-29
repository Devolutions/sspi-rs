use picky_krb::constants::key_usages::{ACCEPTOR_SEAL, INITIATOR_SEAL};
use picky_krb::crypto::aes::AesSize;
use picky_krb::crypto::CipherSuite;

#[derive(Debug, Clone)]
pub struct EncryptionParams {
    pub encryption_type: Option<CipherSuite>,
    pub session_key: Option<Vec<u8>>,
    pub sub_session_key: Option<Vec<u8>>,
    pub sspi_encrypt_key_usage: i32,
    pub sspi_decrypt_key_usage: i32,
}

impl EncryptionParams {
    pub fn default_for_client() -> Self {
        Self {
            encryption_type: None,
            session_key: None,
            sub_session_key: None,
            sspi_encrypt_key_usage: INITIATOR_SEAL,
            sspi_decrypt_key_usage: ACCEPTOR_SEAL,
        }
    }

    pub fn default_for_server() -> Self {
        Self {
            encryption_type: None,
            session_key: None,
            sub_session_key: None,
            sspi_encrypt_key_usage: ACCEPTOR_SEAL,
            sspi_decrypt_key_usage: INITIATOR_SEAL,
        }
    }

    pub fn aes_size(&self) -> Option<AesSize> {
        self.encryption_type.as_ref().and_then(|e_type| match e_type {
            CipherSuite::Aes256CtsHmacSha196 => Some(AesSize::Aes256),
            CipherSuite::Aes128CtsHmacSha196 => Some(AesSize::Aes128),
            CipherSuite::Des3CbcSha1Kd => None,
        })
    }
}
