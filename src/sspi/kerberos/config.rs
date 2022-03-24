use url::Url;

use super::NetworkClient;

pub enum KdcType {
    Kdc,
    KdcProxy,
}

pub struct KerberosConfig {
    pub url: Url,
    pub kdc_type: KdcType,
    pub network_client: Box<dyn NetworkClient>,
}
