use std::io::Read;

use picky_asn1_der::application_tag::ApplicationTag;
use picky_asn1_der::Asn1RawDer;
use picky_krb::constants::key_usages::AP_REP_ENC;
use picky_krb::data_types::{EncApRepPart, Ticket};
use picky_krb::gss_api::NegTokenTarg1;
use picky_krb::messages::{ApRep, TgtRep};

use crate::kerberos::DEFAULT_ENCRYPTION_TYPE;
use crate::sspi::kerberos::EncryptionParams;
use crate::sspi::{Error, ErrorKind, Result};

pub fn extract_ap_rep_from_neg_token_targ(token: &NegTokenTarg1) -> Result<ApRep> {
    let resp_token = &token
        .0
        .response_token
        .0
        .as_ref()
        .ok_or_else(|| Error {
            error_type: ErrorKind::InvalidToken,
            description: "Missing responce token in NegTokenTarg".to_owned(),
        })?
        .0
         .0;

    let mut data = resp_token.as_slice();
    let _oid: ApplicationTag<Asn1RawDer, 0> = picky_asn1_der::from_reader(&mut data)?;

    let mut t = [0, 0];
    data.read_exact(&mut t)?;

    Ok(picky_asn1_der::from_reader(&mut data)?)
}

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
        .map_err(|err| Error {
            error_type: ErrorKind::DecryptFailure,
            description: format!("Cannot decrypt ap_rep.enc_part: {:?}", err),
        })?;

    let ap_rep_enc_part: EncApRepPart = picky_asn1_der::from_bytes(&res)?;

    Ok(ap_rep_enc_part
        .0
        .subkey
        .0
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Missing sub-key in ap_req".to_owned()))?
        .0
        .key_value
        .0
         .0)
}

pub fn extract_tgt_ticket(data: &[u8]) -> Result<Option<Ticket>> {
    let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(data)?;

    if let Some(resp_token) = neg_token_targ.0.response_token.0.as_ref().map(|ticket| &ticket.0 .0) {
        let mut c = resp_token.as_slice();

        let _oid: ApplicationTag<Asn1RawDer, 0> = picky_asn1_der::from_reader(&mut c)?;

        let mut t = [0, 0];

        c.read_exact(&mut t)?;

        let tgt_rep: TgtRep = picky_asn1_der::from_reader(&mut c)?;

        Ok(Some(tgt_rep.ticket.0))
    } else {
        Ok(None)
    }
}
