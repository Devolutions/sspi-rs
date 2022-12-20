use std::io::Write;

use picky_krb::constants::key_usages::INITIATOR_SIGN;
use picky_krb::crypto::aes::{checksum_sha_aes, AesSize};
use picky_krb::gss_api::MicToken;
use serde::Serialize;

use crate::kerberos::client::generators::get_mech_list;
use crate::kerberos::encryption_params::EncryptionParams;
use crate::{Error, ErrorKind, Result};

pub fn serialize_message<T: ?Sized + Serialize>(v: &T) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    // 4 bytes: length of the message
    data.write_all(&[0, 0, 0, 0])?;

    picky_asn1_der::to_writer(v, &mut data)?;

    let len = data.len() as u32 - 4;
    data[0..4].copy_from_slice(&len.to_be_bytes());

    Ok(data)
}

pub fn validate_mic_token(raw_token: &[u8], key_usage: i32, params: &EncryptionParams) -> Result<()> {
    let token = MicToken::decode(raw_token)?;

    let mut payload = picky_asn1_der::to_vec(&get_mech_list())?;
    payload.extend_from_slice(&token.header());

    // the sub-session key is always preferred over the session key
    let key = if let Some(key) = params.sub_session_key.as_ref() {
        key
    } else if let Some(key) = params.session_key.as_ref() {
        key
    } else {
        return Err(Error {
            error_type: ErrorKind::DecryptFailure,
            description: "unable to obtain decryption key".into(),
        });
    };

    let checksum = checksum_sha_aes(key, key_usage, &payload, &params.aes_size().unwrap_or(AesSize::Aes256))?;

    if checksum != token.checksum {
        return Err(Error {
            error_type: ErrorKind::MessageAltered,
            description: "bad checksum of the mic token".into(),
        });
    }

    Ok(())
}

pub fn generate_initiator_raw(mut payload: Vec<u8>, seq_number: u64, session_key: &[u8]) -> Result<Vec<u8>> {
    let mut mic_token = MicToken::with_initiator_flags().with_seq_number(seq_number);

    payload.extend_from_slice(&mic_token.header());

    mic_token.set_checksum(checksum_sha_aes(
        session_key,
        INITIATOR_SIGN,
        &payload,
        &AesSize::Aes256,
    )?);

    let mut mic_token_raw = Vec::new();
    mic_token.encode(&mut mic_token_raw)?;

    Ok(mic_token_raw)
}

pub fn unwrap_hostname(hostname: Option<&str>) -> Result<String> {
    if let Some(hostname) = hostname {
        Ok(hostname.into())
    } else {
        Err(Error::new(
            ErrorKind::InvalidParameter,
            "The hostname is not provided".into(),
        ))
    }
}
