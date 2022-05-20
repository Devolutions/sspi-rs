use kerberos_crypto::AesSizes;
use picky_krb::constants::key_usages::{ACCEPTOR_SEAL, INITIATOR_SEAL};

use crate::sspi::kerberos::{AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96};

#[derive(Debug, Clone)]
pub struct EncryptionParams {
    pub encryption_type: Option<i32>,
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

    pub fn aes_sizes(&self) -> Option<AesSizes> {
        self.encryption_type.map(|e_type| match e_type {
            AES256_CTS_HMAC_SHA1_96 => AesSizes::Aes256,
            AES128_CTS_HMAC_SHA1_96 => AesSizes::Aes128,
            _ => AesSizes::Aes256,
        })
    }
}
