use crate::{Error, ErrorKind, Result};
use oid::ObjectIdentifier;
use picky::oids;
use picky_krb::gss_api::ApplicationTag0;
use picky_krb::gss_api::GssApiNegInit;
use picky_krb::gss_api::KrbMessage;
use picky_krb::gss_api::MechTypeList;
use picky_krb::gss_api::NegTokenInit;
use picky_krb::messages::TgtReq;

/// Extract TGT request and mech types from the first token returned by the Kerberos client.
#[instrument(ret, level = "trace")]
pub(super) fn decode_initial_neg_init(data: &[u8]) -> crate::Result<(Option<TgtReq>, MechTypeList)> {
    let token: ApplicationTag0<GssApiNegInit> = picky_asn1_der::from_bytes(data)?;
    let NegTokenInit {
        mech_types,
        req_flags: _,
        mech_token,
        mech_list_mic: _,
    } = token.0.neg_token_init.0;

    let mech_types = mech_types
        .0
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidToken,
                "mech_types is missing in GssApiNegInit message",
            )
        })?
        .0;

    let tgt_req = if let Some(mech_token) = mech_token.0 {
        let encoded_tgt_req = mech_token.0 .0;
        let neg_token_init = KrbMessage::<TgtReq>::decode_application_krb_message(&encoded_tgt_req)?;

        let token_oid = &neg_token_init.0.krb5_oid.0;
        let krb5_u2u = oids::krb5_user_to_user();
        if *token_oid != krb5_u2u {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                format!(
                    "invalid oid inside mech_token: expected krb5 u2u ({:?}) but got {:?}",
                    krb5_u2u, token_oid
                ),
            ));
        }

        Some(neg_token_init.0.krb_msg)
    } else {
        None
    };

    Ok((tgt_req, mech_types))
}

/// Selects the preferred Kerberos oid.
///
/// 1.2.840.48018.1.2.2 (MS KRB5 - Microsoft Kerberos 5) is preferred over 1.2.840.113554.1.2.2 (KRB5 - Kerberos 5).
pub(super) fn select_mech_type(mech_list: &MechTypeList) -> crate::Result<ObjectIdentifier> {
    // TODO: Support more mech types if needed.

    let ntlm_oid = oids::ntlm_ssp();
    if mech_list.0.iter().any(|mech_type| mech_type.0 == ntlm_oid) {
        return Ok(ntlm_oid);
    }

    Err(Error::new(
        ErrorKind::InvalidToken,
        "invalid mech type list: NTLM protocol is not present",
    ))
}
