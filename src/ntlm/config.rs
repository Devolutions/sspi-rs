use crate::negotiate::ProtocolConfig;
use crate::{NegotiatedProtocol, Ntlm, Result};

#[derive(Debug, Clone, Default)]
pub struct NtlmConfig {
    pub workstation: Option<String>,
}

impl NtlmConfig {
    pub fn new(workstation: String) -> Self {
        Self {
            workstation: Some(workstation),
        }
    }
}

impl ProtocolConfig for NtlmConfig {
    fn new_client(&self) -> Result<NegotiatedProtocol> {
        Ok(NegotiatedProtocol::Ntlm(Ntlm::new(Clone::clone(self))))
    }

    fn clone(&self) -> Box<dyn ProtocolConfig + Send> {
        Box::new(Clone::clone(self))
    }
}
