use picky_asn1::wrapper::Asn1SequenceOf;
use picky_krb::constants::key_usages::{AS_REP_ENC, KRB_PRIV_ENC_PART, TGS_REP_ENC_SESSION_KEY};
use picky_krb::constants::types::PA_ETYPE_INFO2_TYPE;
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{EncKrbPrivPart, EtypeInfo2, PaData};
use picky_krb::messages::{AsRep, EncAsRepPart, EncTgsRepPart, KrbError, KrbPriv, TgsRep};

use crate::kerberos::{EncryptionParams, DEFAULT_ENCRYPTION_TYPE};
use crate::{Error, ErrorKind, Result};

pub fn extract_salt_from_krb_error(error: &KrbError) -> Result<Option<String>> {
    trace!(?error, "KRB_ERROR");

    if let Some(e_data) = error.0.e_data.0.as_ref() {
        let pa_datas: Asn1SequenceOf<PaData> = picky_asn1_der::from_bytes(&e_data.0 .0)?;

        if let Some(pa_etype_info_2) = pa_datas
            .0
            .into_iter()
            .find(|pa_data| pa_data.padata_type.0 .0 == PA_ETYPE_INFO2_TYPE)
        {
            let etype_info_2: EtypeInfo2 = picky_asn1_der::from_bytes(&pa_etype_info_2.padata_data.0 .0)?;
            if let Some(params) = etype_info_2.0.get(0) {
                return Ok(params.salt.0.as_ref().map(|salt| salt.0.to_string()));
            }
        }
    }

    Ok(None)
}

#[instrument(level = "trace", ret)]
pub fn extract_session_key_from_as_rep(
    as_rep: &AsRep,
    salt: &str,
    password: &str,
    enc_params: &EncryptionParams,
) -> Result<Vec<u8>> {
    let cipher = enc_params
        .encryption_type
        .as_ref()
        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
        .cipher();

    let key = cipher.generate_key_from_password(password.as_bytes(), salt.as_bytes())?;

    let enc_data = cipher.decrypt(&key, AS_REP_ENC, &as_rep.0.enc_part.0.cipher.0 .0)?;

    let enc_as_rep_part: EncAsRepPart = picky_asn1_der::from_bytes(&enc_data)?;

    Ok(enc_as_rep_part.0.key.0.key_value.0.to_vec())
}

#[instrument(level = "trace", ret)]
pub fn extract_session_key_from_tgs_rep(
    tgs_rep: &TgsRep,
    session_key: &[u8],
    enc_params: &EncryptionParams,
) -> Result<Vec<u8>> {
    let cipher = enc_params
        .encryption_type
        .as_ref()
        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
        .cipher();

    let enc_data = cipher
        .decrypt(session_key, TGS_REP_ENC_SESSION_KEY, &tgs_rep.0.enc_part.0.cipher.0 .0)
        .map_err(|e| Error::new(ErrorKind::InternalError, format!("{:?}", e)))?;

    let enc_as_rep_part: EncTgsRepPart = picky_asn1_der::from_bytes(&enc_data)?;

    Ok(enc_as_rep_part.0.key.0.key_value.0.to_vec())
}

#[instrument(level = "trace", ret)]
pub fn extract_encryption_params_from_as_rep(as_rep: &AsRep) -> Result<(u8, String)> {
    match as_rep
        .0
        .padata
        .0
        .as_ref()
        .map(|v| {
            v.0 .0
                .iter()
                .find(|e| e.padata_type.0 .0 == PA_ETYPE_INFO2_TYPE)
                .map(|pa_data| pa_data.padata_data.0 .0.clone())
        })
        .unwrap_or_default()
    {
        Some(data) => {
            let pa_etype_info2: EtypeInfo2 = picky_asn1_der::from_bytes(&data)?;
            let pa_etype_info2 = pa_etype_info2
                .0
                .get(0)
                .ok_or_else(|| Error::new(ErrorKind::InternalError, "Missing EtypeInto2Entry in EtypeInfo2"))?;

            Ok((
                pa_etype_info2.etype.0 .0.first().copied().unwrap(),
                pa_etype_info2
                    .salt
                    .0
                    .as_ref()
                    .map(|salt| salt.0.to_string())
                    .ok_or_else(|| Error::new(ErrorKind::InternalError, "Missing salt in EtypeInto2Entry"))?,
            ))
        }
        None => {
            Ok((*as_rep.0.enc_part.0.etype.0.0.first().unwrap(), Default::default()))
        },
    }
}

pub fn extract_status_code_from_krb_priv_response(
    krb_priv: &KrbPriv,
    auth_key: &[u8],
    encryption_params: &EncryptionParams,
) -> Result<u16> {
    let encryption_type = encryption_params
        .encryption_type
        .clone()
        .unwrap_or(CipherSuite::try_from(
            *krb_priv
                .0
                .enc_part
                .0
                .etype
                .0
                 .0
                .first()
                .unwrap_or(&((&DEFAULT_ENCRYPTION_TYPE).into())) as usize,
        )?);

    let cipher = encryption_type.cipher();

    let enc_part: EncKrbPrivPart = picky_asn1_der::from_bytes(&cipher.decrypt(
        auth_key,
        KRB_PRIV_ENC_PART,
        &krb_priv.0.enc_part.0.cipher.0 .0,
    )?)?;
    let user_data = enc_part.0.user_data.0 .0;

    if user_data.len() < 2 {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "Invalid KRB_PRIV message: user-data first is too short (expected at least 2 bytes)",
        ));
    }

    Ok(u16::from_be_bytes(user_data[0..2].try_into().unwrap()))
}
