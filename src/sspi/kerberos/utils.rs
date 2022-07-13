use std::convert::TryInto;
use std::io::Write;

use kerberos_crypto::{checksum_sha_aes, AesSizes};
use picky_krb::constants::key_usages::INITIATOR_SIGN;
use picky_krb::gss_api::MicToken;
use serde::Serialize;

use crate::sspi::kerberos::client::generators::get_mech_list;
use crate::sspi::kerberos::encryption_params::EncryptionParams;
use crate::sspi::{Error, ErrorKind, Result};

pub fn serialize_message<T: ?Sized + Serialize>(v: &T) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    // 4 bytes: length of the message
    data.write_all(&[0, 0, 0, 0])?;

    picky_asn1_der::to_writer(v, &mut data)?;

    let len = data.len() as u32 - 4;
    data[0..4].copy_from_slice(&len.to_be_bytes());

    Ok(data)
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

    let checksum = checksum_sha_aes(
        key,
        key_usage,
        &payload,
        &params.aes_sizes().unwrap_or(AesSizes::Aes256),
    );

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
        &AesSizes::Aes256,
    ));

    let mut mic_token_raw = Vec::new();
    mic_token.encode(&mut mic_token_raw)?;

    Ok(mic_token_raw)
}
