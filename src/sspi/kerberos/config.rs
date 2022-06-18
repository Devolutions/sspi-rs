use std::env;
use std::fmt::Debug;
use std::str::FromStr;

use url::Url;

#[cfg(feature = "network_client")]
use super::network_client::reqwest_network_client::ReqwestNetworkClient;
use super::network_client::NetworkClient;
use super::SSPI_KDC_URL_ENV;

#[derive(Debug, Clone)]
pub enum KdcType {
    Kdc,
    KdcProxy,
}

#[derive(Debug)]
pub struct KerberosConfig {
    pub url: Url,
    pub kdc_type: KdcType,
    pub network_client: Box<dyn NetworkClient>,
}

pub fn parse_kdc_url(mut kdc: String) -> (Url, KdcType) {
    if !kdc.contains("://") {
        kdc = format!("tcp://{}", kdc);
    }
    let kdc_url = Url::from_str(&kdc).unwrap();
    let kdc_type = match kdc_url.scheme() {
        "tcp" => KdcType::Kdc,
        "udp" => KdcType::Kdc,
        "http" => KdcType::KdcProxy,
        "https" => KdcType::KdcProxy,
        _ => KdcType::Kdc,
    };
    (kdc_url, kdc_type)
}

impl KerberosConfig {
    pub fn get_kdc_env() -> Option<(Url, KdcType)> {
        Some(parse_kdc_url(
            env::var(SSPI_KDC_URL_ENV).expect("SSPI_KDC_URL environment variable must be set!"),
        ))
    }

    pub fn new_with_network_client(network_client: Box<dyn NetworkClient>) -> Self {
        if let Some((kdc_url, kdc_type)) = Self::get_kdc_env() {
            Self {
                url: kdc_url,
                kdc_type,
                network_client,
            }
        } else {
            panic!("{} environment variable is not set properly!", SSPI_KDC_URL_ENV);
        }
    }

    #[cfg(feature = "network_client")]
    pub fn from_env() -> Self {
        let network_client = Box::new(ReqwestNetworkClient::new());
        Self::new_with_network_client(network_client)
    }

    pub fn from_kdc_url(url: &str, network_client: Box<dyn NetworkClient>) -> Self {
        let (url, kdc_type) = parse_kdc_url(url.to_owned());

        Self {
            url,
            kdc_type,
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
            kdc_type: self.kdc_type.clone(),
            network_client: self.network_client.clone(),
        }
    }
}
