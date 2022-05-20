use std::env;
use std::fmt::Debug;
use std::str::FromStr;

use url::Url;

#[cfg(feature = "network_client")]
use super::network_client::reqwest_network_client::ReqwestNetworkClient;
use super::network_client::NetworkClient;
use super::{KDC_TYPE_ENV, SSPI_RS_KERBEROS_URL_ENV};

#[derive(Debug, Clone)]
pub enum KdcType {
    Kdc,
    KdcProxy,
}

impl From<String> for KdcType {
    fn from(data: String) -> Self {
        match data.as_str() {
            "KDC" => KdcType::Kdc,
            "KDC_PROXY" => KdcType::KdcProxy,
            kdc_type => panic!("Invalid kdc type {}. Expected KDC or KDC_PROCY", kdc_type),
        }
    }
}

#[derive(Debug)]
pub struct KerberosConfig {
    pub url: Url,
    pub kdc_type: KdcType,
    pub network_client: Box<dyn NetworkClient>,
}

impl KerberosConfig {
    #[cfg(feature = "network_client")]
    pub fn from_env() -> Self {
        Self {
            url: Url::from_str(&env::var(SSPI_RS_KERBEROS_URL_ENV).unwrap()).unwrap(),
            kdc_type: env::var(KDC_TYPE_ENV).unwrap().into(),
            network_client: Box::new(ReqwestNetworkClient::new()),
        }
    }

    #[cfg(not(feature = "network_client"))]
    pub fn from_env(network_client: Box<dyn NetworkClient>) -> Self {
        Self {
            url: Url::from_str(&env::var(SSPI_RS_KERBEROS_URL_ENV).unwrap()).unwrap(),
            kdc_type: env::var(KDC_TYPE_ENV).unwrap().into(),
            network_client,
        }
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
