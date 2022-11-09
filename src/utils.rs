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

pub fn is_azure_ad_domain(domain: &str) -> bool {
    domain == AZURE_AD_DOMAIN
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

pub fn generate_random_symmetric_key(cipher: &CipherSuite, rnd: &mut OsRng) -> Vec<u8> {
    let key_size = cipher.cipher().key_size();
    let mut key = Vec::with_capacity(key_size);

    for _ in 0..key_size {
        key.push(rnd.gen());
    }

    key
}
