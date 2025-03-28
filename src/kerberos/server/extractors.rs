use std::io::Read;

use picky_asn1::wrapper::ObjectIdentifierAsn1;
use picky_asn1_der::application_tag::ApplicationTag;
use picky_asn1_der::Asn1RawDer;
use picky_krb::constants::key_usages::AP_REP_ENC;
use picky_krb::data_types::{EncApRepPart, Ticket};
use picky_krb::gss_api::NegTokenTarg1;
use picky_krb::messages::{ApRep, TgtRep};

use crate::kerberos::{EncryptionParams, DEFAULT_ENCRYPTION_TYPE};
use crate::{Error, ErrorKind, Result};

pub fn extract_ap_rep_from_neg_token_targ(token: &NegTokenTarg1) -> Result<ApRep> {
    let resp_token = &token
        .0
        .response_token
        .0
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "missing response token in NegTokenTarg"))?
        .0
         .0;

    let mut data = resp_token.as_slice();
    let _oid: ApplicationTag<Asn1RawDer, 0> = picky_asn1_der::from_reader(&mut data)?;

    let mut t = [0, 0];
    data.read_exact(&mut t)?;

    Ok(picky_asn1_der::from_reader(&mut data)?)
}

#[instrument(level = "trace", ret)]
pub fn extract_seq_number_from_ap_rep(
    ap_rep: &ApRep,
    session_key: &[u8],
    enc_params: &EncryptionParams,
) -> Result<Vec<u8>> {
    let cipher = enc_params
        .encryption_type
        .as_ref()
        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
        .cipher();

    let res = cipher
        .decrypt(session_key, AP_REP_ENC, &ap_rep.0.enc_part.cipher.0 .0)
        .map_err(|err| {
            Error::new(
                ErrorKind::DecryptFailure,
                format!("cannot decrypt ap_rep.enc_part: {:?}", err),
            )
        })?;

    let ap_rep_enc_part: EncApRepPart = picky_asn1_der::from_bytes(&res)?;

    Ok(ap_rep_enc_part
        .0
        .seq_number
        .0
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "missing sequence number in ap_rep"))?
        .0
         .0)
}

#[instrument(level = "trace", ret)]
pub fn extract_sub_session_key_from_ap_rep(
    ap_rep: &ApRep,
    session_key: &[u8],
    enc_params: &EncryptionParams,
) -> Result<Vec<u8>> {
    let cipher = enc_params
        .encryption_type
        .as_ref()
        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
        .cipher();

    let res = cipher
        .decrypt(session_key, AP_REP_ENC, &ap_rep.0.enc_part.cipher.0 .0)
        .map_err(|err| {
            Error::new(
                ErrorKind::DecryptFailure,
                format!("cannot decrypt ap_rep.enc_part: {:?}", err),
            )
        })?;

    let ap_rep_enc_part: EncApRepPart = picky_asn1_der::from_bytes(&res)?;

    Ok(ap_rep_enc_part
        .0
        .subkey
        .0
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "missing sub-key in ap_req"))?
        .0
        .key_value
        .0
         .0)
}

/// Extracts TGT Ticket from encoded [NegTokenTarg1].
///
/// Returned OID means the selected authentication mechanism by the target server. More info:
/// * [3.2.1. Syntax](https://datatracker.ietf.org/doc/html/rfc2478#section-3.2.1): `responseToken` field;
///
/// We use this oid to choose between the regular Kerberos 5 and Kerberos 5 User-to-User authentication.
#[instrument(level = "trace", ret)]
pub fn extract_tgt_ticket_with_oid(data: &[u8]) -> Result<Option<(Ticket, ObjectIdentifierAsn1)>> {
    if data.is_empty() {
        return Ok(None);
    }

    let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(data)?;

    if let Some(resp_token) = neg_token_targ.0.response_token.0.as_ref().map(|ticket| &ticket.0 .0) {
        let mut c = resp_token.as_slice();

        let oid: ApplicationTag<Asn1RawDer, 0> = picky_asn1_der::from_reader(&mut c)?;
        let oid: ObjectIdentifierAsn1 = picky_asn1_der::from_bytes(&oid.0 .0)?;

        let mut t = [0, 0];

        c.read_exact(&mut t)?;

        let tgt_rep: TgtRep = picky_asn1_der::from_reader(&mut c)?;

        Ok(Some((tgt_rep.ticket.0, oid)))
    } else {
        Ok(None)
    }
}
