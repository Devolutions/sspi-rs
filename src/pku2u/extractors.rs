use std::convert::TryInto;
use std::mem::size_of;

use picky_asn1_der::Asn1RawDer;
use picky_asn1_der::application_tag::ApplicationTag;
use picky_krb::constants::key_usages::AS_REP_ENC;
use picky_krb::constants::types::PA_PK_AS_REP;
use picky_krb::messages::{AsRep, EncAsRepPart};
use picky_krb::pkinit::{DhRepInfo, PaPkAsRep};
use serde::Deserialize;

use crate::kerberos::{DEFAULT_ENCRYPTION_TYPE, EncryptionParams};
use crate::pk_init::DH_NONCE_LEN;
use crate::{Error, ErrorKind, Result, Secret};

pub(super) fn extract_krb_rep<'a, T: Deserialize<'a>>(mut data: &'a [u8]) -> Result<(T, &'a [u8])> {
    let _oid: ApplicationTag<Asn1RawDer, 0> = picky_asn1_der::from_reader(&mut data)?;

    Ok((picky_asn1_der::from_bytes(data)?, data))
}

#[instrument(level = "trace", ret)]
pub fn extract_pa_pk_as_rep(as_rep: &AsRep) -> Result<PaPkAsRep> {
    Ok(picky_asn1_der::from_bytes(
        &as_rep
            .0
            .padata
            .0
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "pa-datas is not present in as-rep"))?
            .iter()
            .find(|pa_data| pa_data.padata_type.0.0 == PA_PK_AS_REP)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidToken,
                    "PA_PK_AS_REP is not present in pa-datas of the as-rep",
                )
            })?
            .padata_data
            .0
            .0,
    )?)
}

#[instrument(level = "trace", ret)]
pub fn extract_server_nonce(dh_rep_info: &DhRepInfo) -> Result<[u8; DH_NONCE_LEN]> {
    let nonce = dh_rep_info
        .server_dh_nonce
        .0
        .as_ref()
        .map(|nonce| nonce.0.0.clone())
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "DH server nonce is not present"))?;

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

#[instrument(level = "trace", ret)]
pub fn extract_session_key_from_as_rep(
    as_rep: &AsRep,
    key: &[u8],
    enc_params: &EncryptionParams,
) -> Result<Secret<Vec<u8>>> {
    Ok(decrypt_as_rep(as_rep, key, enc_params)?
        .0
        .key
        .0
        .key_value
        .0
        .to_vec()
        .into())
}

pub(super) fn extract_session_key_and_nonce_from_as_rep(
    as_rep: &AsRep,
    key: &[u8],
    enc_params: &EncryptionParams,
) -> Result<(Secret<Vec<u8>>, u32)> {
    let enc_as_rep_part = decrypt_as_rep(as_rep, key, enc_params)?;
    let nonce_bytes = enc_as_rep_part.0.nonce.0.as_unsigned_bytes_be();
    if nonce_bytes.len() > size_of::<u32>() {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "AS-REP nonce does not fit into a u32",
        ));
    }
    let mut nonce = [0; size_of::<u32>()];
    nonce[size_of::<u32>() - nonce_bytes.len()..].copy_from_slice(nonce_bytes);

    Ok((
        enc_as_rep_part.0.key.0.key_value.0.to_vec().into(),
        u32::from_be_bytes(nonce),
    ))
}

fn decrypt_as_rep(as_rep: &AsRep, key: &[u8], enc_params: &EncryptionParams) -> Result<EncAsRepPart> {
    let cipher = enc_params
        .encryption_type
        .as_ref()
        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
        .cipher();

    let enc_data = cipher.decrypt(key, AS_REP_ENC, &as_rep.0.enc_part.0.cipher.0.0)?;
    trace!(?enc_data, "Plain AsRep::EncData");

    Ok(picky_asn1_der::from_bytes(&enc_data)?)
}
