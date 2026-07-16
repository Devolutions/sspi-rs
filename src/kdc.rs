cfg_if::cfg_if! {
    if #[cfg(windows)] {
        use windows_registry::LOCAL_MACHINE;
    }
}

use std::env;
#[cfg(not(target_os = "windows"))]
use std::path::Path;
use std::str::FromStr;

use url::Url;

use crate::dns::detect_kdc_hosts_from_dns;
#[cfg(not(target_os = "windows"))]
use crate::krb::Krb5Conf;

#[cfg(target_os = "windows")]
#[instrument(level = "debug", ret)]
pub(crate) fn detect_kdc_hosts_from_system(domain: &str) -> Vec<String> {
    let domain_upper = domain.to_uppercase();
    let hklm = LOCAL_MACHINE;
    let domains_key_path = "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Domains";
    let domain_key_path = format!("{}\\{}", domains_key_path, &domain_upper);
    if let Ok(domain_key) = hklm.open(domain_key_path) {
        let kdc_names: Vec<String> = domain_key.get_multi_string("KdcNames").unwrap_or_default();
        kdc_names.iter().map(|x| format!("tcp://{x}:88")).collect()
    } else {
        Vec::new()
    }
}

#[cfg(not(target_os = "windows"))]
#[instrument(level = "debug", ret)]
pub(crate) fn detect_kdc_hosts_from_system(domain: &str) -> Vec<String> {
    // https://web.mit.edu/kerberos/krb5-current/doc/user/user_config/kerberos.html#environment-variables

    let krb5_config = env::var("KRB5_CONFIG").unwrap_or_else(|_| "/etc/krb5.conf:/usr/local/etc/krb5.conf".to_string());
    let krb5_conf_paths = krb5_config.split(':').map(Path::new).collect::<Vec<&Path>>();

    for krb5_conf_path in krb5_conf_paths {
        if krb5_conf_path.exists()
            && let Some(krb5_conf) = Krb5Conf::new_from_file(krb5_conf_path)
        {
            let kdcs = krb5_conf.get_all_values(vec!["realms", domain, "kdc"]);
            if !kdcs.is_empty() {
                return krb5_kdc_values_to_hosts(&kdcs);
            }
        }
    }

    Vec::new()
}

/// Maps krb5.conf `kdc = ` values to an ordered list of `tcp://` host URLs.
///
/// Per the MIT krb5 spec each `kdc = ` line names exactly one host (optionally `host:port`);
/// multiple KDCs for a realm are expressed as multiple `kdc = ` lines, which [`get_all_values`]
/// returns in order. See <https://web.mit.edu/kerberos/krb5-current/doc/admin/conf_files/krb5_conf.html>.
///
/// [`get_all_values`]: crate::krb::Krb5Conf::get_all_values
#[cfg(not(target_os = "windows"))]
fn krb5_kdc_values_to_hosts(kdcs: &[String]) -> Vec<String> {
    kdcs.iter().map(|host| format!("tcp://{host}")).collect()
}

#[instrument(ret, level = "debug")]
pub(crate) fn detect_kdc_hosts(domain: &str) -> Vec<String> {
    if let Ok(kdc_url) = env::var(format!("SSPI_KDC_URL_{domain}")) {
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
        Some(kdc_hosts.first().unwrap().to_string())
    } else {
        None
    }
}

pub fn detect_kdc_url(domain: &str) -> Option<Url> {
    detect_kdc_urls(domain).into_iter().next()
}

/// Resolves the ordered list of candidate KDC URLs for `domain`.
///
/// Same resolution order as [`detect_kdc_hosts`] (env → system store → DNS SRV), but returns every
/// candidate rather than just the first, so callers can fail over to the next KDC when one is
/// unreachable.
pub fn detect_kdc_urls(domain: &str) -> Vec<Url> {
    detect_kdc_hosts(domain)
        .iter()
        .filter_map(|host| Url::from_str(host).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::detect_kdc_hosts;
    #[test]
    fn test_detect_kdc() {
        if let Ok(domain) = std::env::var("TEST_KERBEROS_REALM") {
            println!("Finding KDC for {} domain", &domain);
            let kdc_hosts = detect_kdc_hosts(&domain);
            if let Some(kdc_host) = kdc_hosts.first() {
                println!("KDC server: {kdc_host}");
            } else {
                println!("No KDC server found!");
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn krb5_kdc_values_expand_to_one_host_each() {
        use super::krb5_kdc_values_to_hosts;

        // Single host.
        assert_eq!(
            krb5_kdc_values_to_hosts(&["dc1.example.com".to_owned()]),
            vec!["tcp://dc1.example.com".to_owned()]
        );

        // Multiple `kdc = ` lines preserve order.
        assert_eq!(
            krb5_kdc_values_to_hosts(&["dc1.example.com".to_owned(), "dc2.example.com".to_owned()]),
            vec!["tcp://dc1.example.com".to_owned(), "tcp://dc2.example.com".to_owned()]
        );

        // One host per line (MIT spec): a whitespace-separated line is not split.
        assert_eq!(
            krb5_kdc_values_to_hosts(&["dc1.example.com dc2.example.com".to_owned()]),
            vec!["tcp://dc1.example.com dc2.example.com".to_owned()]
        );

        // An explicit port is preserved.
        assert_eq!(
            krb5_kdc_values_to_hosts(&["dc1.example.com:8888".to_owned()]),
            vec!["tcp://dc1.example.com:8888".to_owned()]
        );

        // Nothing in, nothing out.
        assert!(krb5_kdc_values_to_hosts(&[]).is_empty());
    }
}
