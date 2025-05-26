use picky_asn1::wrapper::ExplicitContextTag1;
use picky_krb::constants::gss_api::AP_REQ_TOKEN_ID;
use picky_krb::constants::key_usages::{AP_REQ_AUTHENTICATOR, TICKET_REP};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{Authenticator, EncTicketPart};
use picky_krb::gss_api::{ApplicationTag0, GssApiNegInit, KrbMessage, NegTokenTarg};
use picky_krb::messages::{ApReq, TgtReq};

use crate::{Error, ErrorKind, Result};

/// Extract TGT request from token returned by the Kerberos client.
pub fn extract_tgt_req(data: &[u8]) -> Result<TgtReq> {
    let token: ApplicationTag0<GssApiNegInit> = picky_asn1_der::from_bytes(data)?;
    let encoded_tgt_req = token
        .0
        .neg_token_init
        .0
        .mech_token
        .0
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidToken,
                "mech_token is missing in GssApiNegInit message",
            )
        })?
        .0
         .0;
    let neg_token_init = KrbMessage::<TgtReq>::decode_application_krb_message(&encoded_tgt_req)?;

    Ok(neg_token_init.0.krb_msg)
}

/// Decodes incoming SPNEGO message and extracts [ApReq] Kerberos message.
pub fn decode_neg_ap_req(data: &[u8]) -> Result<ApReq> {
    let neg_token_targ: ExplicitContextTag1<NegTokenTarg> = picky_asn1_der::from_bytes(data)?;

    let krb_message = KrbMessage::<ApReq>::decode_application_krb_message(
        &neg_token_targ
            .0
            .response_token
            .0
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidToken,
                    "response_token is missing in NegTokenTarg message",
                )
            })?
            .0
             .0,
    )?
    .0;

    if krb_message.krb5_token_id != AP_REQ_TOKEN_ID {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!(
                "invalid kerberos token id: expected {:?} but got {:?}",
                AP_REQ_TOKEN_ID, krb_message.krb5_token_id
            ),
        ));
    }

    Ok(krb_message.krb_msg)
}

pub fn decrypt_ap_req_ticket(key: &[u8], ap_req: &ApReq) -> Result<EncTicketPart> {
    let ticket_enc_part = &ap_req.0.ticket.0 .0.enc_part.0;
    let cipher = CipherSuite::try_from(ticket_enc_part.etype.0 .0.as_slice())?.cipher();

    let encoded_enc_part = cipher.decrypt(key, TICKET_REP, &ticket_enc_part.cipher.0 .0)?;

    Ok(picky_asn1_der::from_bytes(&encoded_enc_part)?)
}

pub fn decrypt_ap_req_authenticator(session_key: &[u8], ap_req: &ApReq) -> Result<Authenticator> {
    let encrypted_authenticator = &ap_req.0.authenticator.0;
    let cipher = CipherSuite::try_from(encrypted_authenticator.etype.0 .0.as_slice())?.cipher();

    let encoded_authenticator =
        cipher.decrypt(session_key, AP_REQ_AUTHENTICATOR, &encrypted_authenticator.cipher.0 .0)?;

    Ok(picky_asn1_der::from_bytes(&encoded_authenticator)?)
}
