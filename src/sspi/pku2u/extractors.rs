use std::convert::{TryFrom, TryInto};

use oid::ObjectIdentifier;
use picky_asn1::wrapper::IntegerAsn1;
use picky_asn1_der::application_tag::ApplicationTag;
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::content_info::ContentValue;
use picky_asn1_x509::oids::PKINIT_DH_KEY_DATA;
use picky_asn1_x509::signed_data::SignedData;
use picky_krb::constants::key_usages::{AP_REQ_AUTHENTICATOR, AS_REP_ENC};
use picky_krb::constants::types::{PA_PK_AS_REP, PA_PK_AS_REQ};
use picky_krb::crypto::diffie_hellman::{compute_public_key, generate_key, generate_private_key, DhNonce};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::Authenticator;
use picky_krb::messages::{ApReq, AsRep, AsReq, EncAsRepPart};
use picky_krb::pkinit::{AuthPack, DhRepInfo, KdcDhKeyInfo, PaPkAsRep, PaPkAsReq};
use rand::rngs::OsRng;
use serde::Deserialize;

use super::generators::DH_NONCE_LEN;
use crate::kerberos::{EncryptionParams, DEFAULT_ENCRYPTION_TYPE};
use crate::{Error, ErrorKind, Result};

pub fn extract_krb_rep<'a, T: Deserialize<'a>>(mut data: &'a [u8]) -> Result<(T, &'a [u8])> {
    let _oid: ApplicationTag<Asn1RawDer, 0> = picky_asn1_der::from_reader(&mut data)?;

    Ok((picky_asn1_der::from_bytes(data)?, data))
}

pub fn extract_pa_pk_as_rep(as_rep: &AsRep) -> Result<PaPkAsRep> {
    Ok(picky_asn1_der::from_bytes(
        &as_rep
            .0
            .padata
            .0
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "pa-datas is not present in as-rep".into()))?
            .iter()
            .find(|pa_data| &pa_data.padata_type.0 .0 == &PA_PK_AS_REP)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidToken,
                    "PA_PK_AS_REP is not present in pa-datas of the as-rep".into(),
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

    let enc_data = cipher.decrypt(&key, AS_REP_ENC, &as_rep.0.enc_part.0.cipher.0 .0)?;

    let enc_as_rep_part: EncAsRepPart = picky_asn1_der::from_bytes(&enc_data)?;

    Ok(enc_as_rep_part.0.key.0.key_value.0.to_vec())
}

pub fn extract_pa_pk_as_req(as_req: &AsReq) -> Result<PaPkAsReq> {
    Ok(picky_asn1_der::from_bytes(
        &as_req
            .0
            .padata
            .0
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "pa-datas is not present in as rep".into()))?
            .iter()
            .find(|pa_data| &pa_data.padata_type.0 .0 == &PA_PK_AS_REQ)
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

pub fn compute_session_key_from_pa_pk_as_req(
    pa_pk_as_req: &PaPkAsReq,
    dh_server_nonce: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let signed_data: SignedData = picky_asn1_der::from_bytes(&pa_pk_as_req.signed_auth_pack.0)?;
    let content = signed_data
        .content_info
        .content
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidToken,
                "Content of the EncapsulatedContentInfo is not present".into(),
            )
        })?
        .0;
    let auth_pack: AuthPack = picky_asn1_der::from_bytes(match &content {
        ContentValue::OctetString(data) => &data.0,
        c => unimplemented!("wrong content value: {:?}", c),
    })?;

    let dh_client_public_info = &auth_pack
        .client_public_value
        .0
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "DH public key is not present".into()))?
        .0;

    let g = dh_client_public_info.key_info.key_info.g.0.clone();
    let p = dh_client_public_info.key_info.key_info.p.0.clone();
    let q = dh_client_public_info.key_info.key_info.q.0.clone();

    let dh_client_public: IntegerAsn1 = picky_asn1_der::from_bytes(&dh_client_public_info.key_value.0.inner()[1..])?;
    let dh_client_public = dh_client_public.0;

    let mut rng = OsRng::default();
    let dh_server_private = generate_private_key(&q, &mut rng);
    let dh_server_public = compute_public_key(&dh_server_private, &p, &g);

    let dh_client_nonce = auth_pack.client_dh_nonce.0.as_ref().unwrap().0 .0.clone();

    let session_key = generate_key(
        &dh_client_public,
        &dh_server_private,
        &p,
        Some(DhNonce {
            client_nonce: &dh_client_nonce,
            server_nonce: dh_server_nonce,
        }),
        CipherSuite::Aes256CtsHmacSha196.cipher().as_ref(),
    )?;

    Ok((session_key, dh_server_public))
}

pub fn extract_sub_session_key_from_ap_req(ap_req: &ApReq, session_key: &[u8]) -> Result<Vec<u8>> {
    let encrypted = &ap_req.0.authenticator.0.cipher.0 .0;
    let decrypted = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .decrypt(session_key, AP_REQ_AUTHENTICATOR, encrypted)?;

    let auth: Authenticator = picky_asn1_der::from_bytes(&decrypted)?;

    Ok(auth.0.subkey.0.unwrap().0.key_value.0 .0)
}
