#![allow(dead_code)]
#![allow(unused_imports)]

use rand::RngExt as _;
use rand::rngs::{StdRng, SysRng};
use rand_core::SeedableRng as _;

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        use windows::{
            core::*,
            Win32::NetworkManagement::Dns::*,
        };
        use windows_registry::LOCAL_MACHINE;
        use std::ptr::{null_mut};
        use core::ffi::{c_void};

        /// Queries SRV records for `name`, returning each record with its priority and weight.
        ///
        /// `DnsQuery_W` yields a linked list that may include non-SRV records (e.g. A records for
        /// the SRV targets), so we walk `pNext` and keep only SRV entries.
        pub(crate) fn dns_query_srv_records(name: &str) -> Vec<SrvRecord> {
            let mut records = Vec::new();

            let mut p_query_results: *mut DNS_RECORDA = null_mut();

            // SAFETY: FFI call with no outstanding preconditions.
            let dns_status = unsafe {
                DnsQuery_W(
                    &HSTRING::from(name),
                    DNS_TYPE_SRV,
                    DNS_QUERY_STANDARD,
                    None,
                    &mut p_query_results,
                    None
                )
            };

            match dns_status.ok() {
                Ok(()) => {
                    // UNTESTED: `DNS_RECORDA` and `DNS_RECORDW` share one layout (`PSTR` and `PWSTR` are both pointers),
                    // so the list `DnsQuery_W` types as `DNS_RECORDA` is reinterpreted as `DNS_RECORDW` once and the
                    // record types tell the truth for the rest of the walk.
                    // Nothing here runs under test, so when bumping the `windows` crate compare both struct definitions
                    // in `Win32::NetworkManagement::Dns` field by field.
                    // UNTESTED: `wPriority` and `wWeight` are read from the same `Srv` union member as `wPort`.
                    // A swapped field would mis-order KDCs on Windows without failing any test.
                    // When changing this code, check the field mapping against `DNS_SRV_DATAW`.
                    let mut p_record = p_query_results.cast::<DNS_RECORDW>();
                    while !p_record.is_null() {
                        // SAFETY: `p_record` is non-null and points to a valid record of the list `DnsQuery_W`
                        // returned.
                        let record = unsafe { *p_record };

                        if record.wType == DNS_TYPE_SRV.0 {
                            // SAFETY: `wType == DNS_TYPE_SRV` guarantees the `Srv` union member is active.
                            let srv = unsafe { record.Data.Srv };
                            // SAFETY: `pNameTarget` points to a valid, null-terminated UTF-16 string.
                            if let Ok(name_target) = unsafe { srv.pNameTarget.to_string() } {
                                records.push(SrvRecord {
                                    target: name_target,
                                    port: srv.wPort,
                                    priority: srv.wPriority,
                                    weight: srv.wWeight,
                                });
                            }
                        }

                        p_record = record.pNext;
                    }
                }
                Err(error) => error!(%error, "DnsQuery_W failed"),
            }

            // SAFETY: `DnsFree` tolerates a null pointer.
            unsafe {
                DnsFree(Some(p_query_results.cast::<c_void>()), DnsFreeRecordList);
            }

            records
        }

        pub(crate) struct DnsClientNrptRule {
            rule_name: String,
            namespace: String,
            name_servers: Vec<String>
        }

        pub(crate) fn get_dns_client_nrpt_rules() -> Vec<DnsClientNrptRule> {
            let mut rules: Vec<DnsClientNrptRule> = Vec::new();
            let hklm = LOCAL_MACHINE;
            let dns_policy_config_key_path = "System\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig";
            if let Ok(dns_policy_config_key) = hklm.open(dns_policy_config_key_path) {
                for rule_name in dns_policy_config_key.keys().unwrap() {
                    let dns_policy_rule_key_path = format!("{}\\{}", dns_policy_config_key_path, rule_name);
                    if let Ok(dns_policy_rule_key) = hklm.open(dns_policy_rule_key_path) {
                        let namespace: Option<String> = dns_policy_rule_key.get_string("Name").ok(); // REG_MULTI_SZ
                        let name_server_list: Option<String> = dns_policy_rule_key.get_string("GenericDNSServers").ok(); // REG_SZ
                        if let (Some(namespace), Some(name_server_list)) = (namespace, name_server_list) {
                            let name_servers: Vec<String> = name_server_list.split(';').map(|x| x.to_string()).collect();
                            rules.push(DnsClientNrptRule {
                                rule_name,
                                namespace,
                                name_servers,
                            });
                        }
                    }
                }
            }
            rules
        }

        pub(crate) fn get_default_name_servers() -> Vec<String> {
            let hklm = LOCAL_MACHINE;
            let tcpip_linkage_key_path = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Linkage";
            let tcpip_interfaces_key_path = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces";
            let dns_registered_adapters_key_path = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\DNSRegisteredAdapters";

            if let Ok(tcpip_linkage_key) = hklm.open(tcpip_linkage_key_path) {
                let bind_devices: Vec<String> = tcpip_linkage_key.get_multi_string("Bind").unwrap();
                let device_ids = bind_devices.iter().map(|x| x.strip_prefix("\\Device\\").unwrap());

                for device_id in device_ids {
                    let interface_key_path = format!("{}\\{}", tcpip_interfaces_key_path, device_id);
                    let dns_adapter_key_path = format!("{}\\{}", dns_registered_adapters_key_path, device_id);

                    if let (Ok(interface_key), Ok(dns_adapter_key)) = (hklm.open(interface_key_path), hklm.open(dns_adapter_key_path)) {
                        let name_server: Option<String> = interface_key.get_string("NameServer").ok().filter(|x: &String| !x.is_empty());
                        let dhcp_name_server: Option<String> = interface_key.get_string("DhcpNameServer").ok().filter(|x: &String| !x.is_empty());
                        let stale_adapter: u32 = dns_adapter_key.get_u32("StaleAdapter").unwrap_or(1);

                        if stale_adapter != 1
                            && let Some(name_server_list) = name_server.or(dhcp_name_server) {
                                let name_servers: Vec<String> = name_server_list.split(' ')
                                    .map(|c| c.trim().to_string()).filter(|x: &String| !x.is_empty()).collect();
                                return name_servers;
                            }
                    }
                }
            }
            Vec::new()
        }

        pub(crate) fn get_name_servers_for_domain(domain: &str) -> Vec<String> {
            let domain_namespace = if domain.starts_with('.') {
                domain.to_string()
            } else {
                format!(".{}", domain)
            };

            for nrpt_rule in get_dns_client_nrpt_rules() {
                if nrpt_rule.namespace.ends_with(&domain_namespace) {
                    return nrpt_rule.name_servers;
                }
            }

            get_default_name_servers()
        }

        pub(crate) fn detect_kdc_hosts_from_dns_windows(domain: &str) -> Vec<String> {
            detect_kdc_hosts_from_srv(domain, &mut dns_query_srv_records)
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(any(target_os="macos", target_os="ios"))] {
        use std::fmt;
        use std::time::Duration;
        use tokio::time::timeout;
        use futures::stream::{StreamExt};
        use async_dnssd::{query_record, QueryRecordResult, QueriedRecordFlags, Type};

        /// Why an SRV callback could not be turned into a usable record, kept for diagnostics.
        #[derive(Debug)]
        pub(crate) enum SrvRecordParseError {
            /// RDATA is shorter than the 6-byte fixed header (priority + weight + port).
            RdataTooShort,
            /// The target is the DNS root ("."), which per RFC 2782 means the service is not
            /// available, so there is no host to connect to.
            EmptyTarget,
            /// The target name is not a well-formed DNS name: a label runs past the end of the
            /// RDATA, a label exceeds the 63-byte limit, or the name is not root-terminated.
            MalformedTarget,
        }

        impl fmt::Display for SrvRecordParseError {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::RdataTooShort => f.write_str("RDATA shorter than the 6-byte SRV fixed fields"),
                    Self::EmptyTarget => f.write_str("SRV target names no host"),
                    Self::MalformedTarget => f.write_str("SRV target is not a well-formed DNS name"),
                }
            }
        }

        impl std::error::Error for SrvRecordParseError {}

        impl SrvRecord {
            /// Parses the wire RDATA of an SRV record (RFC 2782: priority, weight, port, target).
            fn from_rdata(rdata: &[u8]) -> Result<Self, SrvRecordParseError> {
                // An SRV record's RDATA is 2 (priority) + 2 (weight) + 2 (port) = 6 fixed
                // bytes, followed by the target as a DNS name. Fewer than 6 bytes cannot be
                // indexed for the fixed fields. In practice such a short RDATA only shows up
                // in the negative/removal callbacks handled by the caller, so this guard is
                // defensive.
                if rdata.len() < 6 {
                    return Err(SrvRecordParseError::RdataTooShort);
                }

                let priority = u16::from_be_bytes(rdata[0..2].try_into().map_err(|_| SrvRecordParseError::RdataTooShort)?);
                let weight = u16::from_be_bytes(rdata[2..4].try_into().map_err(|_| SrvRecordParseError::RdataTooShort)?);
                let port = u16::from_be_bytes(rdata[4..6].try_into().map_err(|_| SrvRecordParseError::RdataTooShort)?);
                // A malformed name (truncated label, oversized label, missing root terminator)
                // is rejected here rather than silently accepted as a partial hostname.
                let target = dns_decode_target_data_to_string(&rdata[6..])?;
                // An empty (root, ".") target per RFC 2782 explicitly means the service is not
                // available, so there is no usable endpoint. Reject it rather than emit a
                // "scheme://:port" URL with an empty host.
                if target.is_empty() {
                    return Err(SrvRecordParseError::EmptyTarget);
                }
                Ok(SrvRecord {
                    priority,
                    weight,
                    port,
                    target,
                })
            }
        }

        impl TryFrom<&QueryRecordResult> for SrvRecord {
            type Error = SrvRecordParseError;

            fn try_from(record: &QueryRecordResult) -> Result<Self, Self::Error> {
                Self::from_rdata(record.rdata.as_slice())
            }
        }

        /// Decodes a DNS name in wire format (length-prefixed labels ending in a root label)
        /// into a dotted string.
        ///
        /// The name must be well-formed: every label fully present and at most 63 bytes, ending
        /// with the root label (a zero length byte). A truncated label, an oversized label byte
        /// (>63, e.g. a compression pointer, which RFC 2782 forbids in an SRV target), or a name
        /// that runs off the end without a root terminator is rejected as `MalformedTarget`
        /// rather than returning the partial labels collected so far.
        pub(crate) fn dns_decode_target_data_to_string(v: &[u8]) -> Result<String, SrvRecordParseError> {
            const MAX_LABEL_LEN: usize = 63;

            let mut names = Vec::new();

            let mut i = 0;
            while i < v.len() {
                let size = usize::from(v[i]);
                if size == 0 {
                    // Root label: the name is complete and correctly terminated.
                    return Ok(names.join("."));
                }
                if size > MAX_LABEL_LEN || i + 1 + size > v.len() {
                    return Err(SrvRecordParseError::MalformedTarget);
                }
                names.push(String::from_utf8_lossy(&v[i+1..i+1+size]));
                i = i + 1 + size;
            }

            // Reached the end without a root label: the name is truncated.
            Err(SrvRecordParseError::MalformedTarget)
        }

        pub(crate) fn dns_query_srv_records(name: &str) -> Vec<SrvRecord> {
            const QUERY_TIMEOUT: u64 = 1000;

            async fn query_with_timeout(name: &str, query_timeout: u64) -> Vec<SrvRecord> {
                let mut dns_records: Vec<SrvRecord> = Vec::new();
                let mut query = query_record(name, Type::SRV);

                loop {
                    match timeout(Duration::from_millis(query_timeout), query.next()).await {
                        Ok(Some(Ok(dns_record))) => {
                            // A normal "no SRV records" outcome is a query timeout (the
                            // Err arm below): mDNSResponder simply never calls back. Some
                            // environments, however, have a resolver in the path (VPN,
                            // enterprise DNS filtering, a local stub) that answers the SRV
                            // query immediately with a negative/empty or non-SRV response.
                            // Such a callback carries the ADD flag cleared and/or RDATA too
                            // short to be an SRV record; parsing it blindly panics. Only ADD
                            // callbacks with a well-formed SRV RDATA are usable records; the
                            // rest are logged so the offending response can be diagnosed.
                            if !dns_record.flags.contains(QueriedRecordFlags::ADD) {
                                debug!(
                                    name,
                                    rr_type = ?dns_record.rr_type,
                                    rr_class = ?dns_record.rr_class,
                                    rdata_len = dns_record.rdata.len(),
                                    "Skipping DNS SRV callback without ADD flag (negative response or record removal)"
                                );
                            } else {
                                match SrvRecord::try_from(&dns_record) {
                                    Ok(srv_record) => dns_records.push(srv_record),
                                    Err(reason) => {
                                        warn!(
                                            name,
                                            %reason,
                                            rr_type = ?dns_record.rr_type,
                                            rr_class = ?dns_record.rr_class,
                                            rdata_len = dns_record.rdata.len(),
                                            "Ignoring malformed DNS SRV callback"
                                        );
                                    }
                                }
                            }
                            if !dns_record.flags.contains(QueriedRecordFlags::MORE_COMING) {
                                break;
                            }
                        }
                        Ok(None) => {
                            break
                        }
                        Ok(Some(Err(error))) => {
                            error!(%error, "IO error when reading DNS query");
                            break;
                        }
                        Err(error) => {
                            error!(%error, "Timeout when reading DNS query");
                            break;
                        }
                    }
                }

                dns_records
            }

            execute_future(query_with_timeout(name, QUERY_TIMEOUT))
        }

        pub(crate) fn detect_kdc_hosts_from_dns_apple(domain: &str) -> Vec<String> {
            detect_kdc_hosts_from_srv(domain, &mut dns_query_srv_records)
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature="dns_resolver")] {
        use hickory_resolver::TokioResolver;
        use hickory_resolver::system_conf::read_system_conf;
        use hickory_resolver::config::{ResolverConfig, NameServerConfig, ResolverOpts};
        use hickory_resolver::proto::xfer::Protocol;
        use hickory_resolver::name_server::GenericConnector;
        use hickory_proto::runtime::TokioRuntimeProvider;
        use std::env;
        use std::net::{IpAddr,SocketAddr};
        use std::str::FromStr;
        use url::Url;

        fn get_dns_name_server_from_url(url: &str) -> Option<NameServerConfig> {
            let url = if !url.contains("://") && !url.is_empty() {
                format!("udp://{url}")
            } else {
                url.to_string()
            };

            if let Ok(url) = Url::parse(&url)
                && let Some(url_host) = url.host_str() {
                    let url_port = url.port().unwrap_or(53);
                    let protocol = match url.scheme().to_lowercase().as_str() {
                        "tcp" => Protocol::Tcp,
                        "udp" => Protocol::Udp,
                        _ => Protocol::Udp,
                    };
                    if let Ok(ip_addr) = IpAddr::from_str(url_host) {
                        let socket_addr = SocketAddr::new(ip_addr, url_port);
                        return Some(NameServerConfig {
                            socket_addr,
                            protocol,
                            tls_dns_name: None,
                            trust_negative_responses: false,
                            http_endpoint: None,
                            bind_addr: None
                        });
                    }
                }

            None
        }

        fn get_dns_resolver_from_name_servers(name_servers: Vec<String>) -> TokioResolver {
            let mut resolver_config = ResolverConfig::new();

            for name_server_url in name_servers {
                if let Some(name_server) = get_dns_name_server_from_url(&name_server_url) {
                    resolver_config.add_name_server(name_server);
                }
            }

            let mut resolver_options = ResolverOpts::default();
            resolver_options.validate = false;

            TokioResolver::builder_with_config(resolver_config, GenericConnector::new(TokioRuntimeProvider::new()))
                .with_options(resolver_options)
                .build()
        }

        #[cfg(target_os="windows")]
        fn get_dns_resolver(domain: &str) -> Option<TokioResolver> {
            let name_servers = get_name_servers_for_domain(domain);
            Some(get_dns_resolver_from_name_servers(name_servers))
        }

        #[cfg(not(target_os="windows"))]
        fn get_dns_resolver(_domain: &str) -> Option<TokioResolver> {
            if let Ok(name_server_list) = env::var("SSPI_DNS_URL") {
                let name_servers: Vec<String> = name_server_list
                    .split(',').map(|c|c.trim()).filter(|x| !x.is_empty()).map(String::from).collect();
                Some(get_dns_resolver_from_name_servers(name_servers))
            } else if let Ok((resolver_config, resolver_options)) = read_system_conf() {
                Some(TokioResolver::builder_with_config(resolver_config, GenericConnector::new(TokioRuntimeProvider::new()))
                    .with_options(resolver_options)
                    .build())
            } else {
                None
            }
        }

        pub(crate) fn detect_kdc_hosts_from_dns_resolver(domain: &str) -> Vec<String> {
            let Some(resolver) = get_dns_resolver(domain) else {
                return Vec::new();
            };

            detect_kdc_hosts_from_srv(domain, &mut |name| {
                execute_future(resolver.srv_lookup(name))
                    .map(|records| {
                        records
                            .iter()
                            .map(|record| SrvRecord {
                                target: record.target().to_string(),
                                port: record.port(),
                                priority: record.priority(),
                                weight: record.weight(),
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            })
        }
    }
}

#[cfg(any(feature = "dns_resolver", target_os = "macos", target_os = "ios"))]
fn execute_future<Fut>(fut: Fut) -> Fut::Output
where
    Fut: IntoFuture + Send,
    Fut::Output: Send,
{
    use std::thread;

    use tokio::runtime::{Builder, Handle, Runtime, RuntimeFlavor};
    use tokio::task;

    fn new_runtime() -> Runtime {
        Builder::new_current_thread().enable_all().build().unwrap()
    }

    match Handle::try_current() {
        Ok(handle) => {
            match handle.runtime_flavor() {
                RuntimeFlavor::CurrentThread => thread::scope(|s| {
                    s.spawn(move || new_runtime().block_on(fut.into_future()))
                        .join()
                        .unwrap()
                }),
                // block_in_place can't be used in current_thread runtime
                _ => task::block_in_place(move || handle.block_on(fut.into_future())),
            }
        }
        Err(_) => new_runtime().block_on(fut.into_future()),
    }
}

/// A resolved SRV record, independent of the platform resolver that produced it.
#[derive(Clone, Debug)]
pub(crate) struct SrvRecord {
    target: String,
    port: u16,
    priority: u16,
    weight: u16,
}

/// Orders SRV records as [RFC 2782] "The format of the SRV RR" requires.
///
/// Records are ordered by ascending priority, and each priority group by repeated weighted draws.
/// `pick(max)` returns a number in `0..=max`; a larger value is clamped to `max`.
///
/// [RFC 2782]: https://www.rfc-editor.org/rfc/rfc2782
fn order_srv_records(mut records: Vec<SrvRecord>, pick: &mut dyn FnMut(u32) -> u32) -> Vec<SrvRecord> {
    // Weight-0 records go first in each priority group, so they are selected only when the draw is 0.
    // https://www.rfc-editor.org/rfc/rfc2782:
    // > To select a target to be contacted next, arrange all SRV RRs
    // > (that have not been ordered yet) in any order, except that all
    // > those with weight 0 are placed at the beginning of the list.
    records.sort_by_key(|record| (record.priority, record.weight != 0));

    let mut ordered = Vec::with_capacity(records.len());

    // https://www.rfc-editor.org/rfc/rfc2782:
    // > Compute the sum of the weights of those RRs, and with each RR
    // > associate the running sum in the selected order. Then choose a
    // > uniform random number between 0 and the sum computed
    // > (inclusive), and select the RR whose running sum value is the
    // > first in the selected order which is greater than or equal to
    // > the random number selected. The target host specified in the
    // > selected SRV RR is the next one to be contacted by the client.
    // > Remove this SRV RR from the set of the unordered SRV RRs and
    // > apply the described algorithm to the unordered SRV RRs to select
    // > the next target host.  Continue the ordering process until there
    // > are no unordered SRV RRs.  This process is repeated for each
    // > Priority.
    while let Some(first) = records.first() {
        let priority = first.priority;
        let group_len = records.partition_point(|record| record.priority == priority);
        let mut group: Vec<SrvRecord> = records.drain(..group_len).collect();

        while !group.is_empty() {
            ordered.push(group.remove(weighted_draw_index(&group, pick)));
        }
    }

    return ordered;

    /// Returns the index of the record that a weighted draw over `group` selects, as RFC 2782 describes.
    fn weighted_draw_index(group: &[SrvRecord], pick: &mut dyn FnMut(u32) -> u32) -> usize {
        let weight_sum: u32 = group.iter().map(|record| u32::from(record.weight)).sum();
        let draw = pick(weight_sum).min(weight_sum);

        // The selected record follows every record whose running sum is below `draw`.
        // INVARIANT: `draw <= weight_sum`, and `weight_sum` is the last running sum.
        // `take_while` therefore stops at or before the last record, so the index is in bounds.
        group
            .iter()
            .scan(0u32, |running_sum, record| {
                *running_sum += u32::from(record.weight);
                Some(*running_sum)
            })
            .take_while(|&running_sum| running_sum < draw)
            .count()
    }
}

/// Builds `scheme://host:port` KDC URLs from resolved SRV records, ordered by [`order_srv_records`].
///
/// DNS returns absolute names with a trailing dot (`dc.example.com.`); it is stripped so the result parses as a URL host.
fn srv_records_to_kdc_urls(scheme: &str, records: Vec<SrvRecord>) -> Vec<String> {
    // A failed seed only loses the weighted spread: every draw is then 0 and the records stay in priority order.
    // UNTESTED: the seed cannot be made to fail under test, so nothing checks that a failed seed does not panic.
    // The global thread RNG panics on a failed seed, and a panic here aborts a host process that reaches this code
    // through the FFI, so keep the seed fallible when changing this code.
    let mut rng = StdRng::try_from_rng(&mut SysRng).ok();

    order_srv_records(records, &mut |max| {
        rng.as_mut().map_or(0, |rng| rng.random_range(0..=max))
    })
    .into_iter()
    .map(|SrvRecord { target, port, .. }| format!("{scheme}://{}:{port}", target.trim_end_matches('.')))
    .collect()
}

/// Resolves KDC URLs for `domain` through `lookup`, which returns the SRV records of a DNS name.
///
/// The `_kerberos._udp` records are used only when there are no `_kerberos._tcp` records.
/// Active Directory publishes both sets for the same domain controllers, so using both would list every KDC twice.
fn detect_kdc_hosts_from_srv(domain: &str, lookup: &mut dyn FnMut(&str) -> Vec<SrvRecord>) -> Vec<String> {
    let tcp_records = lookup(&format!("_kerberos._tcp.{domain}"));
    if !tcp_records.is_empty() {
        return srv_records_to_kdc_urls("tcp", tcp_records);
    }

    srv_records_to_kdc_urls("udp", lookup(&format!("_kerberos._udp.{domain}")))
}

#[allow(unused_variables)]
#[instrument(level = "debug", ret)]
pub(crate) fn detect_kdc_hosts_from_dns(domain: &str) -> Vec<String> {
    cfg_if::cfg_if! {
        if #[cfg(windows)] {
            detect_kdc_hosts_from_dns_windows(domain)
        } else if #[cfg(any(target_os="macos", target_os="ios"))] {
            detect_kdc_hosts_from_dns_apple(domain)
        } else if #[cfg(feature="dns_resolver")] {
            detect_kdc_hosts_from_dns_resolver(domain)
        } else {
            Vec::new()
        }
    }
}

#[cfg(all(test, any(target_os = "macos", target_os = "ios")))]
mod apple_srv_tests {
    use super::{SrvRecord, SrvRecordParseError};
    use crate::Result;

    /// Builds SRV RDATA: priority, weight, port, then `target` as length-prefixed DNS labels
    /// terminated by the root label.
    fn srv_rdata(priority: u16, weight: u16, port: u16, target: &str) -> Result<Vec<u8>> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&priority.to_be_bytes());
        rdata.extend_from_slice(&weight.to_be_bytes());
        rdata.extend_from_slice(&port.to_be_bytes());
        for label in target.split('.').filter(|label| !label.is_empty()) {
            rdata.push(label.len().try_into()?);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0); // root label

        Ok(rdata)
    }

    #[test]
    fn parses_well_formed_srv_record() {
        let rdata = srv_rdata(1, 2, 88, "dc.example.com").expect("failed to build SRV rdata");
        let record = SrvRecord::from_rdata(&rdata).expect("valid SRV record should parse");
        assert_eq!(record.priority, 1);
        assert_eq!(record.weight, 2);
        assert_eq!(record.port, 88);
        assert_eq!(record.target, "dc.example.com");
    }

    #[test]
    fn rejects_empty_rdata() {
        // The original crash: an empty negative-response callback sliced as if it were SRV.
        assert!(matches!(
            SrvRecord::from_rdata(&[]),
            Err(SrvRecordParseError::RdataTooShort)
        ));
    }

    #[test]
    fn rejects_rdata_shorter_than_fixed_header() {
        assert!(matches!(
            SrvRecord::from_rdata(&[0, 1, 0]),
            Err(SrvRecordParseError::RdataTooShort)
        ));
    }

    #[test]
    fn rejects_six_byte_rdata_with_no_target() {
        // Exactly the 6 fixed bytes, not even a root label: a truncated name.
        assert!(matches!(
            SrvRecord::from_rdata(&[0, 1, 0, 2, 0, 88]),
            Err(SrvRecordParseError::MalformedTarget)
        ));
    }

    #[test]
    fn rejects_rfc2782_root_target() {
        // Target "." (a lone root label): RFC 2782 "service not available".
        assert!(matches!(
            SrvRecord::from_rdata(&[0, 1, 0, 2, 0, 88, 0]),
            Err(SrvRecordParseError::EmptyTarget)
        ));
    }

    #[test]
    fn rejects_truncated_label() {
        // "dc" then a label claiming 5 bytes with only 1 present, and no root terminator:
        // must not be silently accepted as the partial name "dc".
        let rdata = [0, 1, 0, 2, 0, 88, 2, b'd', b'c', 5, b'x'];
        assert!(matches!(
            SrvRecord::from_rdata(&rdata),
            Err(SrvRecordParseError::MalformedTarget)
        ));
    }

    #[test]
    fn rejects_name_without_root_terminator() {
        // A complete label but the name runs off the end without a root label.
        let rdata = [0, 1, 0, 2, 0, 88, 2, b'd', b'c'];
        assert!(matches!(
            SrvRecord::from_rdata(&rdata),
            Err(SrvRecordParseError::MalformedTarget)
        ));
    }

    #[test]
    fn rejects_oversized_label_length() {
        // A label length byte above the 63-byte limit (e.g. a compression pointer 0xC0),
        // which RFC 2782 forbids in an SRV target.
        let rdata = [0, 1, 0, 2, 0, 88, 0xC0, 0x0C];
        assert!(matches!(
            SrvRecord::from_rdata(&rdata),
            Err(SrvRecordParseError::MalformedTarget)
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::{SrvRecord, detect_kdc_hosts_from_srv, order_srv_records, srv_records_to_kdc_urls};

    fn record(target: &str, priority: u16, weight: u16) -> SrvRecord {
        SrvRecord {
            target: target.to_owned(),
            port: 88,
            priority,
            weight,
        }
    }

    fn targets(records: &[SrvRecord]) -> Vec<&str> {
        records.iter().map(|record| record.target.as_str()).collect()
    }

    // A backup KDC listed first by the resolver must not be tried before the primary.
    // oracle: spec RFC 2782 §"The format of the SRV RR" (Priority)
    #[test]
    fn lower_priority_value_is_tried_first() {
        let records = vec![
            record("backup.example.com", 20, 0),
            record("tertiary.example.com", 30, 0),
            record("primary.example.com", 10, 0),
        ];

        // A target within a priority is chosen by `pick`; each priority here has one record, so `pick` is irrelevant.
        let ordered = order_srv_records(records, &mut |_| 0);

        assert_eq!(
            targets(&ordered),
            ["primary.example.com", "backup.example.com", "tertiary.example.com"]
        );
    }

    // Weights 0, 1 and 3 have running sums 0, 1 and 4.
    // A draw of 2 selects the first record whose running sum reaches 2, the weight-3 record.
    // The remaining weights 0 and 1 have running sums 0 and 1, so a draw of 1 selects the weight-1 record.
    // Each draw is taken from `0..=sum of the remaining weights`.
    // oracle: spec RFC 2782 §"The format of the SRV RR" (Weight)
    #[test]
    fn equal_priority_records_are_selected_by_running_weight_sum() {
        let records = vec![
            record("zero.example.com", 10, 0),
            record("one.example.com", 10, 1),
            record("three.example.com", 10, 3),
        ];

        let mut script = [2, 1, 0].into_iter();
        let mut draw_maxima = Vec::new();
        let ordered = order_srv_records(records, &mut |max| {
            draw_maxima.push(max);
            script.next().expect("more draws than records")
        });

        assert_eq!(
            targets(&ordered),
            ["three.example.com", "one.example.com", "zero.example.com"]
        );
        assert_eq!(draw_maxima[..2], [4, 1]);
    }

    // Weights 0, 1 and 3 have running sums 0, 1 and 4.
    // A draw of 1 selects the weight-1 record, which is neither the first nor the last one.
    // oracle: spec RFC 2782 §"The format of the SRV RR" (Weight)
    #[test]
    fn draw_selects_a_record_in_the_middle_of_the_group() {
        let records = vec![
            record("zero.example.com", 10, 0),
            record("one.example.com", 10, 1),
            record("three.example.com", 10, 3),
        ];

        let ordered = order_srv_records(records, &mut |_| 1);

        assert_eq!(targets(&ordered)[0], "one.example.com");
    }

    // Weight-0 records are placed at the beginning of the list, so only a draw of 0 selects one.
    // That holds even when the resolver returned the weight-0 record after positively weighted ones.
    // oracle: spec RFC 2782 §"The format of the SRV RR" (Weight)
    #[test]
    fn weight_zero_record_is_selected_only_by_a_zero_draw() {
        let records = vec![
            record("three.example.com", 10, 3),
            record("zero.example.com", 10, 0),
            record("one.example.com", 10, 1),
        ];

        let ordered = order_srv_records(records, &mut |_| 0);

        assert_eq!(targets(&ordered)[0], "zero.example.com");
    }

    // With every weight 0, the only draw is 0 and every record must still be returned once.
    // oracle: spec RFC 2782 §"The format of the SRV RR" (Weight)
    #[test]
    fn all_zero_weights_keep_every_record() {
        let records = vec![
            record("a.example.com", 10, 0),
            record("b.example.com", 10, 0),
            record("c.example.com", 10, 0),
        ];

        let ordered = order_srv_records(records, &mut |max| {
            assert_eq!(max, 0, "the draw range is 0..=sum of weights");
            0
        });

        let mut ordered_targets = targets(&ordered);
        ordered_targets.sort_unstable();
        assert_eq!(ordered_targets, ["a.example.com", "b.example.com", "c.example.com"]);
    }

    // A draw is taken over the weights of one priority only, and a group is fully ordered before the next one starts.
    // The first draw of priority 10, with weights 1 and 3, is from `0..=4`.
    // The first draw of priority 20, with weights 5 and 7, is from `0..=12`.
    // Which record a draw selects is left open by the RFC, so only the first draw of each group and the grouping are
    // asserted.
    // oracle: spec RFC 2782 §"The format of the SRV RR" (Weight)
    #[test]
    fn weights_are_summed_within_one_priority_only() {
        let records = vec![
            record("p20-w7.example.com", 20, 7),
            record("p10-w3.example.com", 10, 3),
            record("p20-w5.example.com", 20, 5),
            record("p10-w1.example.com", 10, 1),
        ];

        let mut draw_maxima = Vec::new();
        let ordered = order_srv_records(records, &mut |max| {
            draw_maxima.push(max);
            0
        });

        assert_eq!(draw_maxima.len(), 4);
        assert_eq!([draw_maxima[0], draw_maxima[2]], [4, 12]);
        assert!(ordered[..2].iter().all(|record| record.priority == 10));
        assert!(ordered[2..].iter().all(|record| record.priority == 20));
    }

    // Two weights of `u16::MAX` sum past `u16::MAX`, so the draw range must be computed in a wider type.
    // oracle: spec RFC 2782 §"The format of the SRV RR" (Weight: 16-bit field, sum of weights)
    #[test]
    fn weight_sum_does_not_overflow_16_bits() {
        let records = vec![
            record("a.example.com", 10, u16::MAX),
            record("b.example.com", 10, u16::MAX),
        ];

        let mut draw_maxima = Vec::new();
        let ordered = order_srv_records(records, &mut |max| {
            draw_maxima.push(max);
            max
        });

        // The running sums are 65535 and 131070, so a draw of 131070 first reaches the sum at the second record.
        assert_eq!(draw_maxima[0], 2 * u32::from(u16::MAX));
        assert_eq!(targets(&ordered), ["b.example.com", "a.example.com"]);
    }

    // Distinct priorities make the order independent of the random draw.
    // oracle: mutant a swapped scheme, host or port in the URL, or a dropped record
    #[test]
    fn builds_scheme_host_port_in_priority_order() {
        let records = vec![
            SrvRecord {
                port: 8888,
                ..record("dc2.example.com", 20, 0)
            },
            record("dc1.example.com", 10, 0),
        ];
        assert_eq!(
            srv_records_to_kdc_urls("tcp", records),
            vec![
                "tcp://dc1.example.com:88".to_owned(),
                "tcp://dc2.example.com:8888".to_owned()
            ]
        );
    }

    // oracle: mutant a kept trailing dot, which leaves a URL host that does not parse
    #[test]
    fn strips_trailing_dot_from_absolute_names() {
        let records = vec![record("dc.example.com.", 0, 0)];
        assert_eq!(
            srv_records_to_kdc_urls("udp", records),
            vec!["udp://dc.example.com:88".to_owned()]
        );
    }

    // oracle: mutant a panic or a spurious URL on empty input
    #[test]
    fn empty_input_yields_empty() {
        assert!(srv_records_to_kdc_urls("tcp", Vec::new()).is_empty());
    }

    fn lookup_from<'a>(tcp: &'a [SrvRecord], udp: &'a [SrvRecord]) -> impl FnMut(&str) -> Vec<SrvRecord> + 'a {
        move |name| match name {
            "_kerberos._tcp.tbt.com" => tcp.to_vec(),
            "_kerberos._udp.tbt.com" => udp.to_vec(),
            other => panic!("unexpected DNS name {other}"),
        }
    }

    // AD publishes both record sets for the same DCs, so using both would list every KDC twice.
    // oracle: mutant tcp and udp candidates concatenated, which retries a dead KDC over the other transport
    #[test]
    fn udp_records_are_ignored_when_tcp_records_exist() {
        let tcp = [record("dc1.example.com", 0, 100)];
        let udp = [record("dc1.example.com", 0, 100), record("dc2.example.com", 0, 100)];

        let hosts = detect_kdc_hosts_from_srv("tbt.com", &mut lookup_from(&tcp, &udp));

        assert_eq!(hosts, ["tcp://dc1.example.com:88"]);
    }

    // oracle: mutant udp records dropped, which leaves a realm that publishes only udp records without a KDC
    #[test]
    fn udp_records_are_used_when_there_are_no_tcp_records() {
        let udp = [record("dc2.example.com", 0, 100)];

        let hosts = detect_kdc_hosts_from_srv("tbt.com", &mut lookup_from(&[], &udp));

        assert_eq!(hosts, ["udp://dc2.example.com:88"]);
    }

    // Whatever the draws, every record is returned once and a lower priority value never follows a higher one.
    // oracle: spec RFC 2782 §"The format of the SRV RR" (Priority)
    proptest::proptest! {
        #[test]
        fn ordering_is_a_priority_sorted_permutation(
            fields in proptest::collection::vec((0u16..4, proptest::num::u16::ANY), 0..12),
            draws in proptest::collection::vec(proptest::num::u32::ANY, 1..12),
        ) {
            let records: Vec<SrvRecord> = fields
                .iter()
                .enumerate()
                .map(|(index, &(priority, weight))| record(&format!("dc{index}.example.com"), priority, weight))
                .collect();

            let mut draws = draws.into_iter().cycle();
            let ordered = order_srv_records(records.clone(), &mut |max| draws.next().unwrap_or(0) % (max + 1));

            let mut expected_targets = targets(&records);
            let mut actual_targets = targets(&ordered);
            expected_targets.sort_unstable();
            actual_targets.sort_unstable();
            // Make sure we do not lost any targets in the ordering and did not introduce any duplicates or omissions.
            proptest::prop_assert_eq!(actual_targets, expected_targets);
            // Make sure the ordering respects the priority rules of SRV records.
            proptest::prop_assert!(ordered.windows(2).all(|pair| pair[0].priority <= pair[1].priority));
        }
    }
}
