use std::convert::{TryFrom, TryInto};

use oid::ObjectIdentifier;
use picky_asn1::wrapper::IntegerAsn1;
use picky_asn1_der::application_tag::ApplicationTag;
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::content_info::ContentValue;
use picky_asn1_x509::oids::PKINIT_DH_KEY_DATA;
use picky_asn1_x509::signed_data::SignedData;
use picky_krb::constants::key_usages::AS_REP_ENC;
use picky_krb::constants::types::PA_PK_AS_REP;
use picky_krb::messages::{AsRep, EncAsRepPart};
use picky_krb::pkinit::{DhRepInfo, KdcDhKeyInfo, PaPkAsRep};
use serde::Deserialize;

use super::generators::DH_NONCE_LEN;
use crate::kerberos::{EncryptionParams, DEFAULT_ENCRYPTION_TYPE};
use crate::{Error, ErrorKind, Result};

pub fn extract_krb_rep<'a, T: Deserialize<'a>>(mut data: &'a [u8]) -> Result<(T, &'a [u8])> {
    let _oid: ApplicationTag<Asn1RawDer, 0> =
        picky_asn1_der::from_reader(&mut data).map_err(|e| Error::new(ErrorKind::InvalidToken, format!("{:?}", e)))?;

    // let oid: ObjectIdentifierAsn1 = picky_asn1_der::from_bytes(&oid.0.0)?;

    // let mut token_id = [0, 0];
    // data.read_exact(&mut token_id)?;

    // if token_id != AS_REP_TOKEN_ID {
    //     return Err(Error::new(
    //         ErrorKind::InvalidToken,
    //         format!("Invalid token id: {:?}. Expected: {:?}", token_id, AS_REP_TOKEN_ID),
    //     ));
    // }

    Ok((picky_asn1_der::from_bytes(data)?, data))
}

pub fn extract_pa_pk_as_rep(as_rep: &AsRep) -> Result<PaPkAsRep> {
    Ok(picky_asn1_der::from_bytes(
        &as_rep
            .0
            .padata
            .0
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "pa-datas is not present in as rep".into()))?
            .iter()
            .find(|pa_data| &pa_data.padata_type.0 .0 == &PA_PK_AS_REP)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidToken,
                    "PA_PK_AS_REP is not present in pa-datas of the as rep".into(),
                )
            })?
            .padata_data
            .0
             .0,
    )?)
}

pub fn extract_server_nonce(dh_rep_info: &DhRepInfo) -> Result<[u8; DH_NONCE_LEN]> {
    let nonce = dh_rep_info
        .server_dh_nonce
        .0
        .as_ref()
        .map(|nonce| nonce.0 .0.clone())
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "DH server nonce is not present".into()))?;

    if nonce.len() != DH_NONCE_LEN {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!(
                "invalid server dh nonce length: {}. Expected: {}",
                nonce.len(),
                DH_NONCE_LEN
            ),
        ));
    }

    Ok(nonce.try_into().unwrap())
}

pub fn extract_server_dh_public_key(signed_data: &SignedData) -> Result<Vec<u8>> {
    let pkinit_dh_key_data = ObjectIdentifier::try_from(PKINIT_DH_KEY_DATA).unwrap();
    if signed_data.content_info.content_type.0 != pkinit_dh_key_data {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!(
                "Invalid content info identifier: {:?}. Expected: {:?}",
                signed_data.content_info.content_type.0, pkinit_dh_key_data
            ),
        ));
    }

    let dh_key_info_data = match &signed_data
        .content_info
        .content
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "content info is not present".into()))?
        .0
    {
        ContentValue::OctetString(data) => &data.0,
        _ => return Err(Error::new(ErrorKind::InvalidToken, "unexpected content info".into())),
    };

    let dh_key_info: KdcDhKeyInfo = picky_asn1_der::from_bytes(dh_key_info_data)?;

    if dh_key_info.nonce.0 != vec![0] {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!("DH key nonce must be 0. Got: {:?}", dh_key_info.nonce.0),
        ));
    }

    let key: IntegerAsn1 = picky_asn1_der::from_bytes(dh_key_info.subject_public_key.0.payload_view())?;

    Ok(key.as_unsigned_bytes_be().to_vec())
}

pub fn extract_session_key_from_as_rep(as_rep: &AsRep, key: &[u8], enc_params: &EncryptionParams) -> Result<Vec<u8>> {
    let cipher = enc_params
        .encryption_type
        .as_ref()
        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
        .cipher();

    let enc_data = cipher
        .decrypt(&key, AS_REP_ENC, &as_rep.0.enc_part.0.cipher.0 .0)?;
    println!("as rep decrypted!");

    let enc_as_rep_part: EncAsRepPart = picky_asn1_der::from_bytes(&enc_data)?;

    Ok(enc_as_rep_part.0.key.0.key_value.0.to_vec())
}

#[cfg(test)]
mod tests {
    use picky_krb::{messages::AsRep, crypto::{CipherSuite, diffie_hellman::{generate_key, DhNonce}}};

    use crate::kerberos::EncryptionParams;

    use super::{extract_krb_rep, extract_session_key_from_as_rep};

    #[test]
    fn as_rep_extraction() {
        let enc_type = CipherSuite::Aes256CtsHmacSha196;

        let as_rep: AsRep = picky_asn1_der::from_bytes(&[]).unwrap();

        let enc_params = EncryptionParams {
            encryption_type: Some(enc_type.clone()),
            session_key: None,
            sub_session_key: None,
            sspi_encrypt_key_usage: 0,
            sspi_decrypt_key_usage: 0,
        };

        let key = generate_key(
            &[],
            &[],
            &[],
            Some(DhNonce {
                client_nonce: &[142, 91, 149, 4, 44, 55, 103, 6, 75, 168, 207, 165, 162, 197, 172, 27, 2, 108, 166, 10, 240, 52, 179, 24, 56, 73, 137, 103, 160, 81, 236, 230],
                server_nonce: &[],
            }),
            enc_type.cipher().as_ref(),
        ).unwrap();

        println!("{:?}", extract_session_key_from_as_rep(&as_rep, &key, &enc_params).unwrap());
    }
}
