use picky_krb::constants::gss_api::AP_REQ_TOKEN_ID;
use picky_krb::constants::key_usages::{AP_REQ_AUTHENTICATOR, TICKET_REP};
use picky_krb::constants::types::{NT_ENTERPRISE, NT_PRINCIPAL};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{Authenticator, EncTicketPart, KerberosStringAsn1, PrincipalName};
use picky_krb::gss_api::KrbMessage;
use picky_krb::messages::ApReq;

use crate::{Error, ErrorKind, Result, Username};

/// Decodes incoming SPNEGO message and extracts [ApReq] Kerberos message.
pub(super) fn decode_neg_ap_req(data: &[u8]) -> Result<ApReq> {
    let krb_message = KrbMessage::<ApReq>::decode_application_krb_message(data)?.0;

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
pub(super) fn decrypt_ap_req_ticket(key: &[u8], ap_req: &ApReq) -> Result<EncTicketPart> {
    let ticket_enc_part = &ap_req.0.ticket.0 .0.enc_part.0;
    let cipher = CipherSuite::try_from(ticket_enc_part.etype.0 .0.as_slice())?.cipher();

    let encoded_enc_part = cipher.decrypt(key, TICKET_REP, &ticket_enc_part.cipher.0 .0)?;

    Ok(picky_asn1_der::from_bytes(&encoded_enc_part)?)
}

/// Decrypts [ApReq] Authenticator and returns decoded authenticator.
pub(super) fn decrypt_ap_req_authenticator(session_key: &[u8], ap_req: &ApReq) -> Result<Authenticator> {
    let encrypted_authenticator = &ap_req.0.authenticator.0;
    let cipher = CipherSuite::try_from(encrypted_authenticator.etype.0 .0.as_slice())?.cipher();

    let encoded_authenticator =
        cipher.decrypt(session_key, AP_REQ_AUTHENTICATOR, &encrypted_authenticator.cipher.0 .0)?;

    Ok(picky_asn1_der::from_bytes(&encoded_authenticator)?)
}

/// Constructs [Username] from the client's [PrincipalName] and realm.
pub(super) fn client_upn(cname: &PrincipalName, crealm: &KerberosStringAsn1) -> Result<Username> {
    let username = cname
        .name_string
        .0
         .0
        .first()
        .map(|name| name.to_string())
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "missing cname value in token"))?;

    let name_type = &cname.name_type.0 .0;
    if name_type == &[NT_PRINCIPAL] {
        Ok(Username::new_upn(
            &username,
            &crealm.0.to_string().to_ascii_lowercase(),
        )?)
    } else if name_type == &[NT_ENTERPRISE] {
        Ok(Username::parse(&username)?)
    } else {
        Err(Error::new(
            ErrorKind::InvalidToken,
            format!("unsupported principal name type: {:?}", name_type),
        ))
    }
}
