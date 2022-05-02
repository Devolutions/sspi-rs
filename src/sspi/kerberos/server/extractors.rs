use std::io::{Cursor, Read};

use kerberos_constants::key_usages::KEY_USAGE_AP_REP_ENC_PART;
use kerberos_crypto::new_kerberos_cipher;
use picky_asn1_der::{application_tag::ApplicationTag, Asn1RawDer};
use picky_krb::{data_types::EncApRepPart, messages::ApRep};

use crate::sspi::{
    kerberos::{client::AES256_CTS_HMAC_SHA1_96, negotiate::NegTokenTarg1, EncryptionParams},
    Error, ErrorKind, Result,
};

pub fn extract_ap_rep_from_neg_token_targ(token: &NegTokenTarg1) -> Result<ApRep> {
    let resp_token = &token.0.response_token.0.as_ref().unwrap().0 .0;

    let mut c = Cursor::new(resp_token);
    let _oid: ApplicationTag<Asn1RawDer, 0> = picky_asn1_der::from_reader(&mut c)
        .map_err(|e| Error::new(ErrorKind::InternalError, format!("{:?}", e)))?;

    let mut t = [0, 0];
    c.read_exact(&mut t).unwrap();

    Ok(picky_asn1_der::from_reader(&mut c)
        .map_err(|e| Error::new(ErrorKind::InternalError, format!("{:?}", e)))?)
}

pub fn extract_sub_session_key_from_ap_rep(
    ap_rep: &ApRep,
    session_key: &[u8],
    enc_params: &EncryptionParams,
) -> Result<Vec<u8>> {
    let cipher = new_kerberos_cipher(
        enc_params
            .encryption_type
            .unwrap_or(AES256_CTS_HMAC_SHA1_96),
    )
    .unwrap();

    let res = cipher
        .decrypt(
            session_key,
            KEY_USAGE_AP_REP_ENC_PART,
            &ap_rep.0.enc_part.cipher.0 .0,
        )
        .unwrap();

    let ap_rep_enc_part: EncApRepPart = picky_asn1_der::from_bytes(&res)
        .map_err(|e| Error::new(ErrorKind::InvalidToken, format!("{:?}", e)))?;

    Ok(ap_rep_enc_part
        .0
        .subkey
        .0
        .ok_or(Error::new(
            ErrorKind::InvalidToken,
            format!("Missing sub-key in ap_req"),
        ))?
        .0
        .key_value
        .0
         .0)
}
