//! Functions for handling Kerberos messages on both client and server sides.

use std::fmt::Debug;

use oid::ObjectIdentifier;
use picky_asn1::wrapper::{ExplicitContextTag1, ObjectIdentifierAsn1, Optional};
use picky_asn1_der::Asn1RawDer;
use picky_krb::constants::gss_api::AP_REP_TOKEN_ID;
use picky_krb::data_types::{KrbResult, ResultExt};
use picky_krb::gss_api::{ApplicationTag0, IAKerbProxyMessage, KrbMessage};
use picky_krb::messages::{ApRep, IAKerbCookie, IAKerbHeader, KrbError};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{Error, ErrorKind, Result};

/// Decodes incoming [KrbMessage] message and extracts [ApReq] Kerberos message.
pub(super) fn decode_krb_message<T: DeserializeOwned>(data: &[u8], token_id: [u8; 2]) -> Result<T> {
    let krb_message = KrbMessage::<T>::decode_application_krb_message(data)?.0;

    if krb_message.krb5_token_id != token_id {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!(
                "invalid kerberos token id: expected {:?} but got {:?}",
                token_id, krb_message.krb5_token_id
            ),
        ));
    }

    Ok(krb_message.krb_msg)
}

/// Token id of the KRB-ERROR GSS token.
///
/// [RFC 4121, Section 4.1](https://www.rfc-editor.org/rfc/rfc4121#section-4.1)
pub(super) const KRB_ERROR_TOKEN_ID: [u8; 2] = [0x03, 0x00];

/// Decodes the reply of the acceptor to the AP-REQ: the GSS token with the AP-REP, or with a KRB-ERROR.
///
/// A KRB-ERROR is returned as the error that maps its code, so the caller sees why the acceptor refused.
pub(super) fn decode_ap_rep_message(data: &[u8]) -> Result<ApRep> {
    // The body is kept as raw DER, because its type depends on the token id.
    let krb_message = KrbMessage::<Asn1RawDer>::decode_application_krb_message(data)?.0;

    match krb_message.krb5_token_id {
        AP_REP_TOKEN_ID => Ok(picky_asn1_der::from_bytes(&krb_message.krb_msg.0)?),
        KRB_ERROR_TOKEN_ID => Err(picky_asn1_der::from_bytes::<KrbError>(&krb_message.krb_msg.0)?.into()),
        token_id => Err(Error::new(
            ErrorKind::InvalidToken,
            format!("invalid kerberos token id: expected {AP_REP_TOKEN_ID:?} but got {token_id:?}"),
        )),
    }
}

/// Decodes the reply of the acceptor to the AP-REQ without the GSS framing: an AP-REP, or a KRB-ERROR.
pub(super) fn decode_dce_ap_rep_message(data: &[u8]) -> Result<ApRep> {
    let mut deserializer = picky_asn1_der::Deserializer::new_from_bytes(data);

    Ok(<KrbResult<ApRep> as ResultExt<ApRep>>::deserialize(&mut deserializer)??)
}

pub(super) fn generate_krb_message<T: Serialize + Debug + PartialEq>(
    mech_id: ObjectIdentifier,
    krb5_token_id: [u8; 2],
    krb_msg: T,
) -> Result<Vec<u8>> {
    let krb_blob = ApplicationTag0(KrbMessage {
        krb5_oid: ObjectIdentifierAsn1::from(mech_id),
        krb5_token_id,
        krb_msg,
    });

    Ok(picky_asn1_der::to_vec(&krb_blob)?)
}

pub(super) fn generate_iakerb_proxy_message<T: Serialize + Debug + PartialEq>(
    cookie: IAKerbCookie,
    krb_msg: T,
) -> Result<Vec<u8>> {
    let iakerb_proxy_blob = ApplicationTag0(IAKerbProxyMessage {
        header: IAKerbHeader {
            // Although the IAKerb RFC specifies that the `target_realm` must be provided,
            // the Windows implementation does not use it.
            // The specification also states that the `target_realm` can be retrieved by sending
            // the `IAKerbProxyMessage` with empty `target_realm` and no Kerberos message. However,
            // the Windows implementation returns an error if the Kerberos message is absent.
            // Therefore, we leave the `target_realm` empty.
            //
            // [IAKERB Realm Retrieval](https://datatracker.ietf.org/doc/html/draft-ietf-kitten-iakerb-03#section-3.1)
            target_realm: ExplicitContextTag1::from(String::new()),
            cookie: Optional(cookie),
            flags: Optional(None),
        },
        krb_msg,
    });

    Ok(picky_asn1_der::to_vec(&iakerb_proxy_blob)?)
}

#[cfg(test)]
mod tests {
    use picky_asn1::date::GeneralizedTime;
    use picky_asn1::restricted_string::IA5String;
    use picky_asn1::wrapper::{
        Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag4, ExplicitContextTag5,
        ExplicitContextTag6, ExplicitContextTag9, ExplicitContextTag10, IntegerAsn1, Optional,
    };
    use picky_krb::constants::error_codes::KRB_AP_ERR_SKEW;
    use picky_krb::constants::gss_api::AP_REQ_TOKEN_ID;
    use picky_krb::data_types::{KerberosStringAsn1, KerberosTime, Microseconds, PrincipalName};
    use picky_krb::messages::{KrbError, KrbErrorInner};
    use time::OffsetDateTime;

    use super::{
        AP_REP_TOKEN_ID, KRB_ERROR_TOKEN_ID, decode_ap_rep_message, decode_dce_ap_rep_message, generate_krb_message,
    };
    use crate::kerberos::EncryptionParams;
    use crate::kerberos::client::generators::generate_ap_rep;
    use crate::{ErrorKind, Secret};

    fn krb_error(error_code: u32) -> KrbError {
        let string = |value: &str| KerberosStringAsn1::from(IA5String::from_string(value.to_owned()).unwrap());

        KrbError::from(KrbErrorInner {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![30])),
            ctime: Optional::from(None),
            cusec: Optional::from(None),
            stime: ExplicitContextTag4::from(KerberosTime::from(GeneralizedTime::from(OffsetDateTime::now_utc()))),
            susec: ExplicitContextTag5::from(Microseconds::from(vec![0])),
            error_code: ExplicitContextTag6::from(error_code),
            crealm: Optional::from(None),
            cname: Optional::from(None),
            realm: ExplicitContextTag9::from(string("EXAMPLE.COM")),
            sname: ExplicitContextTag10::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![2])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    string("TERMSRV"),
                    string("host.example.com"),
                ])),
            }),
            e_text: Optional::from(None),
            e_data: Optional::from(None),
        })
    }

    fn ap_rep() -> picky_krb::messages::ApRep {
        generate_ap_rep(
            &Secret::new(vec![0x22; 32]),
            vec![1],
            &EncryptionParams::default_for_client(),
        )
        .unwrap()
    }

    #[test]
    fn a_gss_token_with_an_ap_rep_is_decoded() {
        let ap_rep = ap_rep();
        let token = generate_krb_message(
            oid::ObjectIdentifier::try_from("1.2.840.113554.1.2.2").unwrap(),
            AP_REP_TOKEN_ID,
            ap_rep.clone(),
        )
        .unwrap();

        assert_eq!(decode_ap_rep_message(&token).unwrap(), ap_rep);
    }

    // RFC 4121 §4.1: the acceptor can answer with a KRB-ERROR token.
    // Its error code must reach the caller.
    #[test]
    fn a_gss_token_with_a_krb_error_is_reported_as_the_error() {
        let token = generate_krb_message(
            oid::ObjectIdentifier::try_from("1.2.840.113554.1.2.2").unwrap(),
            KRB_ERROR_TOKEN_ID,
            krb_error(KRB_AP_ERR_SKEW),
        )
        .unwrap();

        let error = decode_ap_rep_message(&token).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::TimeSkew, "{error}");
    }

    #[test]
    fn a_gss_token_of_another_type_is_rejected() {
        let token = generate_krb_message(
            oid::ObjectIdentifier::try_from("1.2.840.113554.1.2.2").unwrap(),
            AP_REQ_TOKEN_ID,
            ap_rep(),
        )
        .unwrap();

        let error = decode_ap_rep_message(&token).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::InvalidToken, "{error}");
    }

    #[test]
    fn a_dce_style_ap_rep_is_decoded() {
        let ap_rep = ap_rep();

        assert_eq!(
            decode_dce_ap_rep_message(&picky_asn1_der::to_vec(&ap_rep).unwrap()).unwrap(),
            ap_rep
        );
    }

    #[test]
    fn a_dce_style_krb_error_is_reported_as_the_error() {
        let message = picky_asn1_der::to_vec(&krb_error(KRB_AP_ERR_SKEW)).unwrap();

        let error = decode_dce_ap_rep_message(&message).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::TimeSkew, "{error}");
    }
}
