use kerberos_constants::key_usages::{
    KEY_USAGE_AS_REP_ENC_PART, KEY_USAGE_TGS_REP_ENC_PART_SESSION_KEY,
};
use kerberos_crypto::new_kerberos_cipher;
use picky_krb::{
    constants::types::PA_ETYPE_INFO2_TYPE,
    data_types::EtypeInfo2,
    messages::{AsRep, EncAsRepPart, EncTgsRepPart, TgsRep},
};

use crate::sspi::{Error, ErrorKind, Result, kerberos::{EncryptionParams, DEFAULT_ENCRYPTION_TYPE}};

pub fn extract_session_key_from_as_rep(
    as_rep: &AsRep,
    salt: &str,
    password: &str,
    enc_params: &EncryptionParams,
) -> Result<Vec<u8>> {
    let cipher = new_kerberos_cipher(enc_params.encryption_type.unwrap_or(DEFAULT_ENCRYPTION_TYPE)).unwrap();

    let key = cipher.generate_key_from_string(password, salt.as_bytes());

    let enc_data = cipher
        .decrypt(
            &key,
            KEY_USAGE_AS_REP_ENC_PART,
            &as_rep.0.enc_part.0.cipher.0 .0,
        )
        .map_err(|e| Error {
            error_type: ErrorKind::DecryptFailure,
            description: format!("{:?}", e),
        })?;

    let enc_as_rep_part: EncAsRepPart =
        picky_asn1_der::from_bytes(&enc_data).map_err(|e| Error {
            error_type: ErrorKind::DecryptFailure,
            description: format!("{:?}", e),
        })?;

    Ok(enc_as_rep_part.0.key.0.key_value.0.to_vec())
}

pub fn extract_session_key_from_tgs_rep(tgs_rep: &TgsRep, session_key: &[u8], enc_params: &EncryptionParams,) -> Result<Vec<u8>> {
    let cipher = new_kerberos_cipher(enc_params.encryption_type.unwrap_or(DEFAULT_ENCRYPTION_TYPE)).unwrap();

    let enc_data = cipher
        .decrypt(
            session_key,
            KEY_USAGE_TGS_REP_ENC_PART_SESSION_KEY,
            &tgs_rep.0.enc_part.0.cipher.0 .0,
        )
        .map_err(|e| Error {
            error_type: ErrorKind::DecryptFailure,
            description: format!("{:?}", e),
        })?;

    let enc_as_rep_part: EncTgsRepPart =
        picky_asn1_der::from_bytes(&enc_data).map_err(|e| Error {
            error_type: ErrorKind::DecryptFailure,
            description: format!("{:?}", e),
        })?;

    Ok(enc_as_rep_part.0.key.0.key_value.0.to_vec())
}

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
            let pa_etype_into2: EtypeInfo2 =
                picky_asn1_der::from_bytes(&data).map_err(|e| Error {
                    error_type: ErrorKind::DecryptFailure,
                    description: format!("{:?}", e),
                })?;
            let pa_etype_into2 = pa_etype_into2.0.get(0).ok_or(Error {
                error_type: ErrorKind::InvalidParameter,
                description: "Missing EtypeInto2Entry in EtypeInfo2".into(),
            })?;

            Ok((
                pa_etype_into2.etype.0 .0.get(0).copied().unwrap(),
                pa_etype_into2
                    .salt
                    .0
                    .as_ref()
                    .map(|salt| salt.0.to_string())
                    .ok_or(Error {
                        error_type: ErrorKind::InvalidParameter,
                        description: "Missing salt in EtypeInto2Entry".into(),
                    })?,
            ))
        }
        None => Err(Error {
            error_type: ErrorKind::NoPaData,
            description: format!(
                "Missing PaData: PA_ETYPE_INFO2 ({:0x?})",
                PA_ETYPE_INFO2_TYPE
            ),
        }),
    }
}
