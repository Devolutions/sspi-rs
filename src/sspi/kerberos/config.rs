use std::fmt::Debug;
use std::str::FromStr;

use url::Url;

#[cfg(feature = "network_client")]
use super::network_client::reqwest_network_client::ReqwestNetworkClient;
use super::network_client::NetworkClient;
use crate::kdc::detect_kdc_url;
use crate::negotiate::{NegotiatedProtocol, ProtocolConfig};
use crate::{Kerberos, Result};

pub struct KerberosConfig {
    pub url: Option<Url>,
    pub network_client: Box<dyn NetworkClient>,
}

impl Debug for KerberosConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KerberosConfig")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl ProtocolConfig for KerberosConfig {
    fn new_client(&self) -> Result<NegotiatedProtocol> {
        Ok(NegotiatedProtocol::Kerberos(Kerberos::new_client_from_config(
            Clone::clone(self),
        )?))
    }

    fn clone(&self) -> Box<dyn ProtocolConfig> {
        Box::new(Clone::clone(self))
    }
}

pub fn parse_kdc_url(mut kdc: String) -> Option<Url> {
    if !kdc.contains("://") {
        kdc = format!("tcp://{}", kdc);
    }
    Url::from_str(&kdc).ok()
}

impl KerberosConfig {
    pub fn get_kdc_url(self, domain: &str) -> Option<Url> {
        if let Some(kdc_url) = self.url {
            Some(kdc_url)
        } else {
            detect_kdc_url(domain)
        }
    }

    pub fn new_with_network_client(network_client: Box<dyn NetworkClient>) -> Self {
        Self {
            url: None,
            network_client,
        }
    }

    #[cfg(feature = "network_client")]
    pub fn from_env() -> Self {
        let network_client = Box::new(ReqwestNetworkClient::new());
        Self::new_with_network_client(network_client)
    }

    pub fn from_kdc_url(url: &str, network_client: Box<dyn NetworkClient>) -> Self {
        let kdc_url = parse_kdc_url(url.to_owned());
        Self {
            url: kdc_url,
            network_client,
        }
    }

    #[cfg(not(feature = "network_client"))]
    pub fn from_env(network_client: Box<dyn NetworkClient>) -> Self {
        Self::new_with_network_client(network_client)
    }
}

impl Clone for KerberosConfig {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            network_client: self.network_client.clone(),
        }
    }
}
