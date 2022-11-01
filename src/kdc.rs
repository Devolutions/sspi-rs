cfg_if::cfg_if! {
    if #[cfg(windows)] {
        use winreg::RegKey;
        use winreg::enums::*;
    }
}

use std::env;
use std::str::FromStr;

use url::Url;

use crate::dns::detect_kdc_hosts_from_dns;

#[cfg(target_os = "windows")]
pub fn detect_kdc_hosts_from_system(domain: &str) -> Vec<String> {
    let domain_upper = domain.to_uppercase();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let domains_key_path = "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Domains";
    let domain_key_path = format!("{}\\{}", domains_key_path, &domain_upper);
    if let Ok(domain_key) = hklm.open_subkey(domain_key_path) {
        let kdc_names: Vec<String> = domain_key.get_value("KdcNames").unwrap_or_default();
        kdc_names.iter().map(|x| format!("tcp://{}:88", x)).collect()
    } else {
        Vec::new()
    }
}

#[cfg(not(target_os = "windows"))]
pub fn detect_kdc_hosts_from_system(_domain: &str) -> Vec<String> {
    Vec::new() // TODO: parse krb5.conf file
}

pub fn detect_kdc_hosts(domain: &str) -> Vec<String> {
    if let Ok(kdc_url) = env::var(&format!("SSPI_KDC_URL_{}", domain)) {
        return vec![kdc_url];
    }

    if let Ok(kdc_url) = env::var("SSPI_KDC_URL") {
        return vec![kdc_url];
    }

    let kdc_hosts = detect_kdc_hosts_from_system(domain);

    if !kdc_hosts.is_empty() {
        return kdc_hosts;
    }

    detect_kdc_hosts_from_dns(domain)
}

pub fn detect_kdc_host(domain: &str) -> Option<String> {
    let kdc_hosts = detect_kdc_hosts(domain);
    if !kdc_hosts.is_empty() {
        Some(kdc_hosts.get(0).unwrap().to_string())
    } else {
        None
    }
}

pub fn detect_kdc_url(domain: &str) -> Option<Url> {
    let kdc_host = detect_kdc_host(domain)?;
    Url::from_str(&kdc_host).ok()
}

#[cfg(test)]
mod tests {
    use super::detect_kdc_hosts;
    #[test]
    fn test_detect_kdc() {
        if let Ok(domain) = std::env::var("TEST_KERBEROS_REALM") {
            println!("Finding KDC for {} domain", &domain);
            let kdc_hosts = detect_kdc_hosts(&domain);
            if let Some(kdc_host) = kdc_hosts.get(0) {
                println!("KDC server: {}", kdc_host);
            } else {
                println!("No KDC server found!");
            }
        }
    }
}
