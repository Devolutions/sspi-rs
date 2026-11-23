use std::fmt::Debug;

use crate::{NegotiatedProtocol, Result};

pub trait ProtocolConfig: Debug + Send + Sync {
    fn new_instance(&self) -> Result<NegotiatedProtocol>;
    fn new_server_instance(&self) -> Result<NegotiatedProtocol> {
        self.new_instance()
    }
    fn box_clone(&self) -> Box<dyn ProtocolConfig>;
}

#[derive(Debug)]
#[non_exhaustive]
pub struct NegotiateConfig {
    pub protocol_config: Box<dyn ProtocolConfig>,
    pub package_list: Option<String>,
    /// Computer name, or "workstation name", of the client machine performing the authentication attempt
    ///
    /// This is also referred to as the "Source Workstation", i.e.: the name of the computer attempting to logon.
    pub client_computer_name: String,
    /// Requires the KDC certificate of a smart card logon to be verified.
    ///
    /// Applies to the Kerberos instances that Negotiate creates itself, such as the switch from NTLM to Kerberos
    /// for smart card credentials. See [`KerberosConfig::enforce_kdc_ca_cert`](crate::KerberosConfig::enforce_kdc_ca_cert).
    pub enforce_kdc_ca_cert: bool,
}

impl NegotiateConfig {
    /// Creates a new instance of [NegotiateConfig].
    ///
    /// `package_list` specifies allowed security packages for user authorization.
    /// Security packages are specified as a comma-separated list of package names in lowercase.
    /// If the security package is not allowed, then prepend '!' to its name. Examples:
    ///
    /// - "kerberos,ntlm" - allows both Kerberos and NTLM but not PKU2U.
    /// - "kerberos,!ntlm" - allows Kerberos but not NTLM and not PKU2U. Forces the use of Kerberos.
    /// - "!kerberos,ntlm" - allows NTLM but not Kerberos and not PKU2U. Forces the use of NTLM.
    /// - "!ntlm" - allows Kerberos and PKU2U but not NTLM.
    ///
    /// If `package_list` is None, then all packages are allowed and Kerberos is preferred.
    pub fn new(
        protocol_config: Box<dyn ProtocolConfig>,
        package_list: Option<String>,
        client_computer_name: String,
    ) -> Self {
        Self {
            protocol_config,
            package_list,
            client_computer_name,
            enforce_kdc_ca_cert: false,
        }
    }

    pub fn from_protocol_config(protocol_config: Box<dyn ProtocolConfig>, client_computer_name: String) -> Self {
        Self {
            protocol_config,
            package_list: None,
            client_computer_name,
            enforce_kdc_ca_cert: false,
        }
    }

    /// Sets [`NegotiateConfig::enforce_kdc_ca_cert`].
    #[must_use]
    pub fn with_enforce_kdc_ca_cert(mut self, enforce_kdc_ca_cert: bool) -> Self {
        self.enforce_kdc_ca_cert = enforce_kdc_ca_cert;
        self
    }
}

impl Clone for NegotiateConfig {
    fn clone(&self) -> Self {
        Self {
            protocol_config: self.protocol_config.box_clone(),
            package_list: self.package_list.clone(),
            client_computer_name: self.client_computer_name.clone(),
            enforce_kdc_ca_cert: self.enforce_kdc_ca_cert,
        }
    }
}
