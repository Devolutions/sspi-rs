use std::fmt::Debug;

use crate::{NegotiatedProtocol, Result};

pub trait ProtocolConfig: Debug + Send + Sync {
    fn new_instance(&self) -> Result<NegotiatedProtocol>;
    fn box_clone(&self) -> Box<dyn ProtocolConfig>;
}

#[derive(Debug)]
pub struct NegotiateConfig {
    pub protocol_config: Box<dyn ProtocolConfig>,
    pub package_list: Option<String>,
    /// Computer name, or "workstation name", of the client machine performing the authentication attempt
    ///
    /// This is also referred to as the "Source Workstation", i.e.: the name of the computer attempting to logon.
    pub client_computer_name: String,
}

impl NegotiateConfig {
    /// package_list format, "kerberos,ntlm,pku2u"
    pub fn new(
        protocol_config: Box<dyn ProtocolConfig>,
        package_list: Option<String>,
        client_computer_name: String,
    ) -> Self {
        Self {
            protocol_config,
            package_list,
            client_computer_name,
        }
    }

    pub fn from_protocol_config(protocol_config: Box<dyn ProtocolConfig + Send>, client_computer_name: String) -> Self {
        Self {
            protocol_config,
            package_list: None,
            client_computer_name,
        }
    }
}

impl Clone for NegotiateConfig {
    fn clone(&self) -> Self {
        Self {
            protocol_config: self.protocol_config.box_clone(),
            package_list: self.package_list.clone(),
            client_computer_name: self.client_computer_name.clone(),
        }
    }
}
