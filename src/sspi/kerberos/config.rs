use std::fmt::Debug;

use url::Url;

use super::NetworkClient;

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

impl Clone for KerberosConfig {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            kdc_type: self.kdc_type.clone(),
            network_client: self.network_client.clone(),
        }
    }
}
