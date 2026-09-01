use std::fmt::Debug;
use std::str::FromStr;

use url::Url;

use crate::kdc::detect_kdc_url;
use crate::kerberos::ServerProperties;
use crate::negotiate::{NegotiatedProtocol, ProtocolConfig};
use crate::{Kerberos, Result};

/// Strategy for resolving the KDC to use for Kerberos authentication.
#[derive(Clone, Debug)]
pub enum KdcResolution {
    /// Use IAKerb extension to proxy KDC communication through the server to the LocalKDC.
    IAKerb,
    /// KDC URL
    ///
    /// Depending on the scheme it is expected to be either:
    /// - a (Kerberos) KDC address (e.g.: tcp://domain:88, udp://domain:88), or
    /// - a KDC _Proxy_ URL (e.g.: <https://gateway.devolutions.net/jet/KdcProxy?token=…>)
    ///
    /// That is, when the scheme is `http` or `https`, the KDC Proxy Protocol ([KKDCP]) will be
    /// used on top of the Kerberos protocol, wrapping the messages.
    /// Otherwise, the scheme must be either `tcp` or `udp`, and the KDC protocol will be used
    /// in order to communicate with the KDC server directly.
    ///
    /// [KKDCP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/5bcebb8d-b747-4ee5-9453-428aec1c5c38
    KdcUrl(Option<Url>),
}

/// Kerberos client configuration.
#[derive(Clone, Debug)]
pub struct KerberosConfig {
    /// Strategy for resolving the KDC to use for Kerberos authentication.
    pub kdc_resolution: KdcResolution,
    /// Computer name, or "workstation name", of the client machine performing the authentication attempt
    ///
    /// This is also referred to as the "Source Workstation", i.e.: the name of the computer attempting to logon.
    pub client_computer_name: String,
}

impl ProtocolConfig for KerberosConfig {
    fn new_instance(&self) -> Result<NegotiatedProtocol> {
        Ok(NegotiatedProtocol::Kerberos(Kerberos::new_client_from_config(
            self.clone(),
        )?))
    }

    fn box_clone(&self) -> Box<dyn ProtocolConfig> {
        Box::new(self.clone())
    }
}

pub fn parse_kdc_url(kdc_url: &str) -> Option<Url> {
    if !kdc_url.contains("://") {
        Url::from_str(&format!("tcp://{kdc_url}")).ok()
    } else {
        Url::from_str(kdc_url).ok()
    }
}

impl KerberosConfig {
    pub fn new_with_kdc_url(kdc_url: &str, client_computer_name: String) -> Self {
        let kdc_url = parse_kdc_url(kdc_url);

        Self {
            kdc_resolution: KdcResolution::KdcUrl(kdc_url),
            client_computer_name,
        }
    }

    pub fn new_with_iakerb(client_computer_name: String) -> Self {
        Self {
            kdc_resolution: KdcResolution::IAKerb,
            client_computer_name,
        }
    }

    pub fn get_kdc_url(self, domain: &str) -> Option<Url> {
        match self.kdc_resolution {
            KdcResolution::IAKerb => None,
            KdcResolution::KdcUrl(kdc_url) => {
                if let Some(kdc_url) = kdc_url {
                    Some(kdc_url)
                } else {
                    detect_kdc_url(domain)
                }
            }
        }
    }
}

/// Kerberos server configuration.
#[derive(Clone, Debug)]
pub struct KerberosServerConfig {
    /// General Kerberos configuration.
    pub kerberos_config: KerberosConfig,
    /// Kerberos server specific parameters.
    pub server_properties: ServerProperties,
}

impl ProtocolConfig for KerberosServerConfig {
    fn new_instance(&self) -> Result<NegotiatedProtocol> {
        Ok(NegotiatedProtocol::Kerberos(Kerberos::new_server_from_config(
            self.kerberos_config.clone(),
            self.server_properties.clone(),
        )?))
    }

    fn box_clone(&self) -> Box<dyn ProtocolConfig> {
        Box::new(self.clone())
    }
}
