use std::io::{Cursor, Read};

use kerberos_constants::key_usages::KEY_USAGE_AP_REP_ENC_PART;
use kerberos_crypto::new_kerberos_cipher;
use picky_asn1_der::{application_tag::ApplicationTag, Asn1RawDer};
use picky_krb::{data_types::EncApRepPart, messages::ApRep};

use crate::sspi::{
    kerberos::{client::AES256_CTS_HMAC_SHA1_96, negotiate::NegTokenTarg1},
    Error, ErrorKind,
};

pub fn extract_ap_rep_from_neg_token_targ(data: &[u8]) -> ApRep {
    let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(data).unwrap();
    let resp_token = neg_token_targ.0.response_token.0.unwrap().0 .0;

    let mut c = Cursor::new(resp_token);
    let _oid: ApplicationTag<Asn1RawDer, 0> = picky_asn1_der::from_reader(&mut c).unwrap();

    let mut t = [0, 0];
    c.read_exact(&mut t).unwrap();

    picky_asn1_der::from_reader(&mut c)
        .map_err(|e| Error::new(ErrorKind::DecryptFailure, format!("{:?}", e)))
        .unwrap()
}

pub fn extract_sub_session_key_from_ap_rep(ap_rep: &ApRep, session_key: &[u8]) -> Vec<u8> {
    let cipher = new_kerberos_cipher(AES256_CTS_HMAC_SHA1_96).unwrap();

    let res = cipher
        .decrypt(
            session_key,
            KEY_USAGE_AP_REP_ENC_PART,
            &ap_rep.0.enc_part.cipher.0 .0,
        )
        .unwrap();

    let ap_rep_enc_part: EncApRepPart = picky_asn1_der::from_bytes(&res).unwrap();

    ap_rep_enc_part.0.subkey.0.unwrap().0.key_value.0 .0
}
