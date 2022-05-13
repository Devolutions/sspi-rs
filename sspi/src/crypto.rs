mod rc4;

use std::io;

use crypto_mac::Mac;
use md4::{Digest, Md4};
use md5::Md5;
pub use rc4::Rc4;
use sha2::Sha256;

pub const HASH_SIZE: usize = 16;

const SHA256_SIZE: usize = 32;

pub fn compute_md4(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut context = Md4::new();
    let mut result = [0x00; HASH_SIZE];
    context.update(data);
    result.clone_from_slice(&context.finalize());

    result
}

pub fn compute_md5(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut context = Md5::new();
    let mut result = [0x00; HASH_SIZE];
    context.update(data);
    result.clone_from_slice(&context.finalize());

    result
}

pub fn compute_sha256(data: &[u8]) -> [u8; SHA256_SIZE] {
    let mut context = Sha256::new();
    let mut result = [0x00; SHA256_SIZE];
    context.update(data);
    result.clone_from_slice(&context.finalize());

    result
}

pub fn compute_hmac_md5(key: &[u8], input: &[u8]) -> io::Result<[u8; HASH_SIZE]> {
    use hmac::NewMac;
    let mut mac = hmac::Hmac::<Md5>::new_from_slice(key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to compute hmac md5: {}", e)))?;
    let mut result = [0x00; HASH_SIZE];
    mac.update(input);
    result.clone_from_slice(&mac.finalize().into_bytes());

    Ok(result)
}
