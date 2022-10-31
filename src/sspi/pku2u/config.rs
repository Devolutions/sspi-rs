use picky_asn1_x509::Certificate;
use rsa::RsaPrivateKey;

use crate::negotiate::{NegotiatedProtocol, ProtocolConfig};
use crate::{Pku2u, Result};

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
        use super::cert_utils::extraction::extract_client_p2p_cert_and_key;

        let (p2p_certificate, private_key) = extract_client_p2p_cert_and_key()?;

        Ok(Self {
            p2p_certificate,
            private_key,
        })
    }
}

impl ProtocolConfig for Pku2uConfig {
    fn new_client(&self) -> Result<NegotiatedProtocol> {
        Ok(NegotiatedProtocol::Pku2u(Pku2u::new_client_from_config(Clone::clone(
            self,
        ))?))
    }

    fn clone(&self) -> Box<dyn ProtocolConfig> {
        Box::new(Clone::clone(self))
    }
}
