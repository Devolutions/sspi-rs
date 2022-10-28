use byteorder::{LittleEndian, ReadBytesExt};
use picky_krb::crypto::CipherSuite;
use rand::rngs::OsRng;
use rand::Rng;

use crate::sspi::pku2u::AZURE_AD_DOMAIN;

pub fn string_to_utf16(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(|i| i.to_le_bytes().to_vec())
        .collect::<Vec<u8>>()
}

pub fn bytes_to_utf16_string(mut value: &[u8]) -> String {
    let mut value_u16 = vec![0x00; value.len() / 2];
    value
        .read_u16_into::<LittleEndian>(value_u16.as_mut())
        .expect("read_u16_into cannot fail at this point");

    String::from_utf16_lossy(value_u16.as_ref())
}

#[cfg(feature = "network_client")]
pub fn get_domain_from_fqdn(fqdm: &[u8]) -> Option<String> {
    let mut fqdm = bytes_to_utf16_string(fqdm);

    fqdm.find('@').map(|index| fqdm.split_off(index + 1))
}

pub fn is_azure_ad_domain(domain: &[u8]) -> bool {
    bytes_to_utf16_string(domain) == AZURE_AD_DOMAIN
}

pub fn utf16_bytes_to_utf8_string(data: &[u8]) -> String {
    debug_assert_eq!(data.len() % 2, 0);
    String::from_utf16_lossy(
        &data
            .chunks(2)
            .map(|c| u16::from_le_bytes(c.try_into().unwrap()))
            .collect::<Vec<u16>>(),
    )
}

#[cfg(feature = "network_client")]
pub fn resolve_kdc_host(domain: &str) -> Option<String> {
    use trust_dns_resolver::system_conf::read_system_conf;
    use trust_dns_resolver::Resolver;

    let (resolver_config, resolver_options) = read_system_conf().ok()?;
    let resolver = Resolver::new(resolver_config, resolver_options).ok()?;

    if let Ok(records) = resolver.srv_lookup(&format!("_kerberos._tcp.{}", domain)) {
        records
            .into_iter()
            .next()
            .map(|record| format!("tcp://{}:88", record.target()))
    } else if let Ok(records) = resolver.srv_lookup(&format!("_kerberos._udp.{}", domain)) {
        records
            .into_iter()
            .next()
            .map(|record| format!("udp://{}:88", record.target()))
    } else {
        None
    }
}

pub fn generate_random_key(cipher: &CipherSuite, rnd: &mut OsRng) -> Vec<u8> {
    let key_size = cipher.cipher().key_size();
    let mut key = Vec::with_capacity(key_size);

    for _ in 0..key_size {
        key.push(rnd.gen());
    }

    key
}

#[cfg(feature = "network_client")]
#[cfg(test)]
mod tests {
    use super::get_domain_from_fqdn;

    #[test]
    fn test_get_domain_from_fqdm() {
        // user1@example.com
        let fqdm = [
            117, 0, 115, 0, 101, 0, 114, 0, 49, 0, 64, 0, 101, 0, 120, 0, 97, 0, 109, 0, 112, 0, 108, 0, 101, 0, 46, 0,
            99, 0, 111, 0, 109, 0,
        ];

        let domain = get_domain_from_fqdn(&fqdm).unwrap();

        assert_eq!(&domain, "example.com");
    }
}
