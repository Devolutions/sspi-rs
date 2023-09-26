use std::fmt::Debug;
use std::str::FromStr;

use url::Url;

use crate::kdc::detect_kdc_url;
use crate::negotiate::{NegotiatedProtocol, ProtocolConfig};
use crate::{Kerberos, Result};

pub struct KerberosConfig {
    pub url: Option<Url>,
    pub hostname: Option<String>,
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
    pub fn new(url: &str, hostname: String) -> Self {
        let kdc_url = parse_kdc_url(url.to_owned());

        Self {
            url: kdc_url,
            hostname: Some(hostname),
        }
    }

    pub fn get_kdc_url(self, domain: &str) -> Option<Url> {
        if let Some(kdc_url) = self.url {
            Some(kdc_url)
        } else {
            detect_kdc_url(domain)
        }
    }

    pub fn from_kdc_url(url: &str) -> Self {
        let kdc_url = parse_kdc_url(url.to_owned());

        Self {
            url: kdc_url,
            hostname: None,
        }
    }
}

impl Clone for KerberosConfig {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            hostname: self.hostname.clone(),
        }
    }
}
