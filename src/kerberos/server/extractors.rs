use std::io::Read;

use picky_asn1_der::application_tag::ApplicationTag;
use picky_asn1_der::Asn1RawDer;
use picky_asn1::wrapper::ObjectIdentifierAsn1;
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
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Missing response token in NegTokenTarg"))?
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
                format!("Cannot decrypt ap_rep.enc_part: {:?}", err),
            )
        })?;

    let ap_rep_enc_part: EncApRepPart = picky_asn1_der::from_bytes(&res)?;

    Ok(ap_rep_enc_part
        .0
        .seq_number
        .0
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Missing sequence number in ap_rep"))?
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
                format!("Cannot decrypt ap_rep.enc_part: {:?}", err),
            )
        })?;

    let ap_rep_enc_part: EncApRepPart = picky_asn1_der::from_bytes(&res)?;

    Ok(ap_rep_enc_part
        .0
        .subkey
        .0
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Missing sub-key in ap_req"))?
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
pub fn extract_tgt_ticket_and_oid(data: &[u8]) -> Result<Option<(Ticket, ObjectIdentifierAsn1)>> {
    if data.is_empty() {
        return Ok(None);
    }

    let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(data)?;

    if let Some(resp_token) = neg_token_targ.0.response_token.0.as_ref().map(|ticket| &ticket.0 .0) {
        let mut c = resp_token.as_slice();

        let oid: ApplicationTag<Asn1RawDer, 0> = picky_asn1_der::from_reader(&mut c)?;
        let oid: ObjectIdentifierAsn1 = picky_asn1_der::from_bytes(&oid.0.0)?;

        let mut t = [0, 0];

        c.read_exact(&mut t)?;

        let tgt_rep: TgtRep = picky_asn1_der::from_reader(&mut c)?;

        Ok(Some((tgt_rep.ticket.0, oid)))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extforefkje() {
        let data = [161, 130, 4, 146, 48, 130, 4, 142, 160, 3, 10, 1, 1, 161, 11, 6, 9, 42, 134, 72, 130, 247, 18, 1, 2, 2, 162, 130, 4, 120, 4, 130, 4, 116, 96, 130, 4, 112, 6, 10, 42, 134, 72, 134, 247, 18, 1, 2, 2, 3, 4, 1, 48, 130, 4, 94, 160, 3, 2, 1, 5, 161, 3, 2, 1, 17, 162, 130, 4, 80, 97, 130, 4, 76, 48, 130, 4, 72, 160, 3, 2, 1, 5, 161, 13, 27, 11, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 162, 32, 48, 30, 160, 3, 2, 1, 2, 161, 23, 48, 21, 27, 6, 107, 114, 98, 116, 103, 116, 27, 11, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 163, 130, 4, 14, 48, 130, 4, 10, 160, 3, 2, 1, 18, 161, 3, 2, 1, 2, 162, 130, 3, 252, 4, 130, 3, 248, 58, 176, 96, 104, 148, 116, 168, 177, 48, 197, 115, 31, 233, 217, 105, 81, 140, 38, 30, 245, 3, 239, 15, 203, 160, 156, 134, 234, 132, 191, 71, 202, 222, 150, 103, 171, 92, 19, 221, 17, 179, 129, 3, 255, 79, 117, 96, 161, 111, 255, 62, 72, 85, 50, 133, 190, 217, 238, 115, 108, 74, 181, 4, 183, 174, 6, 13, 39, 157, 21, 179, 161, 38, 53, 173, 32, 179, 38, 31, 111, 235, 99, 4, 84, 73, 19, 131, 66, 70, 86, 143, 92, 176, 35, 222, 236, 86, 11, 218, 45, 67, 13, 75, 15, 70, 146, 109, 32, 230, 18, 73, 31, 136, 51, 36, 247, 91, 216, 147, 63, 53, 232, 52, 147, 108, 77, 95, 95, 24, 54, 56, 188, 50, 8, 28, 34, 173, 252, 124, 28, 83, 9, 186, 41, 94, 150, 73, 86, 24, 16, 54, 251, 57, 142, 11, 121, 241, 69, 245, 149, 245, 214, 198, 37, 119, 142, 219, 194, 2, 206, 206, 180, 158, 68, 168, 249, 236, 216, 49, 90, 165, 237, 232, 9, 189, 248, 231, 254, 121, 205, 205, 149, 131, 30, 46, 63, 48, 145, 68, 63, 146, 137, 77, 32, 182, 218, 225, 188, 226, 238, 82, 141, 180, 86, 90, 239, 101, 222, 8, 77, 102, 96, 102, 226, 45, 199, 31, 76, 163, 81, 169, 147, 168, 188, 112, 196, 135, 215, 159, 30, 74, 2, 133, 200, 145, 150, 60, 245, 124, 79, 250, 118, 6, 38, 91, 229, 40, 13, 51, 193, 1, 179, 37, 238, 58, 50, 172, 54, 24, 60, 250, 234, 13, 91, 77, 96, 143, 253, 1, 122, 141, 197, 143, 158, 38, 85, 60, 23, 149, 87, 27, 196, 153, 10, 122, 157, 246, 83, 225, 198, 161, 171, 201, 103, 126, 19, 156, 75, 143, 207, 166, 28, 76, 14, 185, 85, 98, 35, 103, 220, 152, 100, 20, 97, 187, 66, 107, 94, 56, 187, 77, 120, 82, 180, 244, 20, 129, 154, 251, 5, 99, 161, 220, 10, 238, 61, 2, 110, 72, 195, 81, 11, 11, 111, 219, 134, 142, 50, 9, 46, 224, 15, 206, 87, 24, 142, 157, 248, 107, 93, 133, 164, 75, 147, 111, 54, 154, 158, 157, 68, 158, 222, 20, 134, 249, 211, 36, 7, 229, 92, 130, 220, 29, 19, 82, 247, 236, 224, 7, 157, 70, 97, 70, 109, 205, 46, 44, 229, 186, 69, 127, 117, 201, 183, 151, 77, 25, 67, 38, 211, 184, 58, 7, 179, 234, 19, 37, 181, 63, 85, 12, 4, 8, 243, 248, 136, 134, 197, 28, 106, 99, 155, 17, 66, 223, 116, 123, 19, 88, 230, 99, 235, 56, 55, 135, 89, 57, 58, 125, 70, 67, 141, 106, 212, 9, 78, 0, 127, 213, 142, 8, 248, 78, 211, 241, 128, 127, 194, 240, 45, 253, 228, 210, 176, 229, 156, 0, 102, 105, 43, 64, 206, 83, 78, 130, 210, 238, 174, 206, 231, 47, 68, 225, 72, 234, 240, 90, 253, 246, 29, 173, 119, 117, 154, 253, 51, 14, 142, 112, 20, 86, 157, 15, 103, 44, 24, 83, 40, 38, 188, 135, 202, 60, 246, 32, 50, 51, 43, 148, 161, 58, 3, 212, 105, 169, 247, 125, 48, 35, 227, 186, 71, 158, 243, 198, 101, 9, 233, 169, 147, 66, 107, 65, 243, 211, 135, 236, 129, 116, 182, 77, 40, 32, 212, 28, 155, 140, 239, 48, 222, 163, 87, 100, 10, 149, 54, 126, 112, 180, 208, 225, 42, 182, 254, 79, 97, 85, 231, 109, 231, 111, 82, 56, 57, 34, 66, 23, 204, 83, 30, 187, 191, 9, 154, 29, 231, 12, 28, 62, 132, 221, 235, 106, 80, 220, 171, 207, 75, 44, 148, 78, 209, 252, 49, 138, 163, 159, 191, 96, 168, 149, 186, 115, 105, 229, 98, 181, 65, 191, 225, 46, 101, 235, 203, 204, 79, 168, 140, 216, 246, 73, 69, 104, 240, 239, 121, 227, 16, 134, 69, 150, 254, 18, 254, 223, 26, 154, 82, 26, 83, 21, 91, 1, 151, 221, 205, 114, 70, 140, 229, 219, 189, 100, 214, 255, 207, 91, 254, 74, 103, 199, 102, 170, 173, 137, 19, 47, 129, 151, 127, 144, 182, 202, 116, 115, 58, 214, 123, 18, 185, 81, 132, 29, 229, 80, 131, 118, 45, 185, 22, 87, 173, 173, 207, 204, 135, 13, 254, 244, 239, 28, 250, 233, 182, 140, 163, 234, 91, 25, 49, 182, 113, 182, 47, 213, 7, 203, 133, 227, 243, 75, 14, 250, 154, 83, 60, 23, 241, 253, 33, 106, 233, 235, 119, 71, 175, 49, 226, 125, 226, 156, 227, 132, 189, 29, 64, 151, 168, 39, 120, 199, 110, 233, 45, 132, 197, 250, 35, 67, 68, 139, 58, 245, 247, 74, 241, 70, 170, 174, 15, 56, 13, 130, 18, 195, 137, 90, 153, 166, 17, 152, 62, 12, 55, 51, 140, 22, 45, 171, 25, 172, 77, 14, 201, 160, 61, 56, 132, 216, 131, 93, 162, 132, 216, 186, 179, 60, 198, 247, 229, 249, 201, 43, 212, 227, 116, 29, 129, 9, 75, 99, 63, 218, 213, 214, 179, 204, 14, 48, 192, 232, 54, 197, 5, 235, 18, 106, 129, 85, 100, 2, 78, 213, 83, 255, 114, 85, 78, 250, 11, 235, 182, 221, 242, 255, 252, 51, 93, 254, 168, 35, 161, 111, 198, 77, 141, 118, 197, 155, 129, 191, 215, 193, 81, 47, 99, 1, 124, 120, 46, 148, 51, 133, 160, 21, 187, 196, 236, 59, 175, 138, 166, 247, 162, 168, 48, 122, 100, 146, 154, 251, 27, 131, 8, 249, 171, 237, 122, 212, 52, 195, 226, 75, 60, 248, 52, 124, 143, 121, 206, 69, 7, 24, 22, 16, 232, 178, 254, 197, 31, 132, 98, 71, 22, 217, 145, 34, 214, 214, 189, 164, 171, 200, 232, 234, 237, 99, 76, 216, 35, 137, 123, 207, 77, 59, 180, 170, 209, 93, 137, 89, 62, 192, 201, 20, 61, 102, 10, 255, 160, 11, 27, 254, 213, 14, 2];

        println!("{:?}", extract_tgt_ticket_and_oid(data.as_slice()).unwrap());
    }
}
