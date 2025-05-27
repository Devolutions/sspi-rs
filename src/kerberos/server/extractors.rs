use picky_asn1::wrapper::ExplicitContextTag1;
use picky_krb::constants::gss_api::{ACCEPT_COMPLETE, AP_REQ_TOKEN_ID};
use picky_krb::constants::key_usages::{AP_REQ_AUTHENTICATOR, TICKET_REP};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{Authenticator, EncTicketPart};
use picky_krb::gss_api::{
    ApplicationTag0, GssApiNegInit, KrbMessage, MechTypeList, NegTokenInit, NegTokenTarg, NegTokenTarg1,
};
use picky_krb::messages::{ApReq, TgtReq};

use crate::{Error, ErrorKind, Result};

/// Extract TGT request and mech types from the first token returned by the Kerberos client.
pub fn decode_initial_neg_init(data: &[u8]) -> Result<(TgtReq, MechTypeList)> {
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

    let encoded_tgt_req = mech_token
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

    Ok((neg_token_init.0.krb_msg, mech_types))
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

/// Decrypts the [ApReq] ticket and returns decoded encrypted part of the ticket.
pub fn decrypt_ap_req_ticket(key: &[u8], ap_req: &ApReq) -> Result<EncTicketPart> {
    let ticket_enc_part = &ap_req.0.ticket.0 .0.enc_part.0;
    let cipher = CipherSuite::try_from(ticket_enc_part.etype.0 .0.as_slice())?.cipher();

    let encoded_enc_part = cipher.decrypt(key, TICKET_REP, &ticket_enc_part.cipher.0 .0)?;

    Ok(picky_asn1_der::from_bytes(&encoded_enc_part)?)
}

/// Decrypts [ApReq] Authenticator and returns decoded authenticator.
pub fn decrypt_ap_req_authenticator(session_key: &[u8], ap_req: &ApReq) -> Result<Authenticator> {
    let encrypted_authenticator = &ap_req.0.authenticator.0;
    let cipher = CipherSuite::try_from(encrypted_authenticator.etype.0 .0.as_slice())?.cipher();

    let encoded_authenticator =
        cipher.decrypt(session_key, AP_REQ_AUTHENTICATOR, &encrypted_authenticator.cipher.0 .0)?;

    Ok(picky_asn1_der::from_bytes(&encoded_authenticator)?)
}

/// Validated client final [NegTokenTarg1] message and extract its MIC token.
///
/// **Note**: the input client message should be last message in the _authentication_ sequence.
pub fn extract_client_mic_token(data: &[u8]) -> Result<Vec<u8>> {
    let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(data)?;
    let NegTokenTarg {
        neg_result,
        supported_mech: _,
        response_token: _,
        mech_list_mic,
    } = neg_token_targ.0;

    let neg_result = neg_result
        .0
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "neg_result is missing in NegTokenTarg message"))?
        .0
         .0;
    if neg_result != ACCEPT_COMPLETE {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "invalid neg result: expected accept_complete",
        ));
    }

    Ok(mech_list_mic
        .0
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidToken,
                "mech_list_mic is missing in NegTokenTarg message",
            )
        })?
        .0
         .0)
}
