use picky_asn1_x509::Certificate;
use rsa::RsaPrivateKey;

use super::cert_utils::extract_client_p2p_cert_and_key;
use crate::Result;

#[derive(Debug, Clone)]
pub struct Pku2uConfig {
    pub p2p_certificate: Certificate,
    pub private_key: RsaPrivateKey,
}

impl Pku2uConfig {
    pub fn new(p2p_certificate: Certificate, private_key: RsaPrivateKey) -> Self {
        Self {
            p2p_certificate,
            private_key,
        }
    }

    #[cfg(target_os = "windows")]
    pub fn default_client_config() -> Result<Self> {
        let (p2p_certificate, private_key) = extract_client_p2p_cert_and_key()?;

        Ok(Self {
            p2p_certificate,
            private_key,
        })
    }
}
