//! Requests that the AS exchange rejects.

mod common;

use std::time::Duration;

use common::{
    ENC_TKT_IN_SKEY, MAX_SKEW_SECS, REALM, USER, as_req, as_req_body, enc_timestamp, encrypted_data, etype_byte,
    etype_number, flags, kdc_config, ktime, padata_field, principal, raw_pa_data, realm, send_as, user_key,
    valid_enc_timestamp,
};
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag1, ExplicitContextTag3, ExplicitContextTag4, IntegerAsn1, Optional,
};
use picky_krb::constants::error_codes::{
    KDC_ERR_BAD_PVNO, KDC_ERR_BADOPTION, KDC_ERR_C_PRINCIPAL_UNKNOWN, KDC_ERR_CANNOT_POSTDATE, KDC_ERR_ETYPE_NOSUPP,
    KDC_ERR_NEVER_VALID, KDC_ERR_PREAUTH_FAILED, KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_S_PRINCIPAL_UNKNOWN,
    KDC_ERR_WRONG_REALM, KRB_AP_ERR_MSG_TYPE, KRB_AP_ERR_SKEW,
};
use picky_krb::constants::etypes::{DES3_CBC_SHA1_KD, RC4_HMA};
use picky_krb::constants::types::{NT_PRINCIPAL, NT_SRV_INST, PA_ENC_TIMESTAMP, PA_TGS_REQ_TYPE, TGS_REQ_MSG_TYPE};
use picky_krb::crypto::CipherSuite;
use picky_krb::messages::AsReq;
use rstest::rstest;
use time::OffsetDateTime;

fn valid_request() -> AsReq {
    as_req(Some(vec![valid_enc_timestamp()]), as_req_body())
}

// The error code of each rejected request.
// RFC 4120 §3.1.3 and §5.9.1 decide the cases marked `spec`.
// The other codes are the choice of this KDC.
#[rstest]
// oracle: spec RFC 4120 §3.1.3 - KDC_ERR_PREAUTH_REQUIRED when pre-authentication is required and absent.
#[case::no_padata(|r: &mut AsReq| r.0.padata = Optional::from(None), KDC_ERR_PREAUTH_REQUIRED)]
// oracle: spec RFC 4120 §3.1.3 - KDC_ERR_C_PRINCIPAL_UNKNOWN when the client is not in the database.
#[case::unknown_user(
    |r: &mut AsReq| r.0.req_body.0.cname = Optional::from(Some(ExplicitContextTag1::from(principal(NT_PRINCIPAL, &["nobody"])))),
    KDC_ERR_C_PRINCIPAL_UNKNOWN
)]
// oracle: mutant a client name type other than NT-PRINCIPAL and NT-ENTERPRISE is accepted
#[case::unknown_cname_type(
    |r: &mut AsReq| r.0.req_body.0.cname = Optional::from(Some(ExplicitContextTag1::from(principal(0x7f, &[USER])))),
    KDC_ERR_C_PRINCIPAL_UNKNOWN
)]
// oracle: mutant a request without cname is processed
#[case::missing_cname(|r: &mut AsReq| r.0.req_body.0.cname = Optional::from(None), KDC_ERR_C_PRINCIPAL_UNKNOWN)]
// oracle: mutant a request for another realm is processed or is answered with another code
#[case::wrong_realm(|r: &mut AsReq| r.0.req_body.0.realm.0 = realm("OTHER.COM"), KDC_ERR_WRONG_REALM)]
// oracle: mutant the AS issues a ticket for a service other than krbtgt
#[case::sname_is_not_krbtgt(
    |r: &mut AsReq| r.0.req_body.0.sname = Optional::from(Some(ExplicitContextTag3::from(principal(NT_SRV_INST, &["host", REALM])))),
    KDC_ERR_S_PRINCIPAL_UNKNOWN
)]
// oracle: mutant a request without sname is processed
#[case::missing_sname(|r: &mut AsReq| r.0.req_body.0.sname = Optional::from(None), KDC_ERR_S_PRINCIPAL_UNKNOWN)]
// oracle: spec RFC 4120 §3.1.3 - KDC_ERR_ETYPE_NOSUPP when no requested etype is supported.
#[case::only_unsupported_etype(
    |r: &mut AsReq| r.0.req_body.0.etype.0 = Asn1SequenceOf::from(vec![IntegerAsn1::from(etype_number(RC4_HMA))]),
    KDC_ERR_ETYPE_NOSUPP
)]
// oracle: spec RFC 4120 §5.9.1 - KDC_ERR_PREAUTH_FAILED, "Pre-authentication information was invalid".
#[case::undecodable_timestamp(
    |r: &mut AsReq| r.0.padata = padata_field(vec![raw_pa_data(&PA_ENC_TIMESTAMP, vec![0xde, 0xad])]),
    KDC_ERR_PREAUTH_FAILED
)]
// oracle: spec RFC 4120 §5.9.1 - KDC_ERR_ETYPE_NOSUPP, "KDC has no support for encryption type".
#[case::timestamp_with_unknown_etype(
    |r: &mut AsReq| r.0.padata = padata_field(vec![raw_pa_data(
        &PA_ENC_TIMESTAMP,
        picky_asn1_der::to_vec(&encrypted_data(99, vec![0; 32])).unwrap(),
    )]),
    KDC_ERR_ETYPE_NOSUPP
)]
// The cipher of this etype is not used by the KDC, and it must not be asked to decrypt untrusted data:
// the DES3 decryption of picky-krb panics on a short ciphertext.
// oracle: spec RFC 4120 §5.9.1 - KDC_ERR_ETYPE_NOSUPP, "KDC has no support for encryption type".
#[case::timestamp_with_unsupported_etype_and_short_cipher(
    |r: &mut AsReq| r.0.padata = padata_field(vec![raw_pa_data(
        &PA_ENC_TIMESTAMP,
        picky_asn1_der::to_vec(&encrypted_data(etype_byte(DES3_CBC_SHA1_KD), vec![0])).unwrap(),
    )]),
    KDC_ERR_ETYPE_NOSUPP
)]
// oracle: spec RFC 4120 §5.9.1 - KDC_ERR_PREAUTH_REQUIRED, "Additional pre-authentication required".
#[case::only_unrelated_padata(
    |r: &mut AsReq| r.0.padata = padata_field(vec![raw_pa_data(&PA_TGS_REQ_TYPE, vec![])]),
    KDC_ERR_PREAUTH_REQUIRED
)]
// oracle: spec RFC 4120 §5.9.1 - KDC_ERR_BAD_PVNO, "Requested protocol version number not supported".
#[case::wrong_protocol_version(|r: &mut AsReq| r.0.pvno.0 = IntegerAsn1::from(vec![4]), KDC_ERR_BAD_PVNO)]
// oracle: spec RFC 4120 §5.9.1 - KDC_ERR_BADOPTION, "KDC cannot accommodate requested option";
// the KDC accommodates none of forwarded, proxy, postdated, renew and validate, which need an existing ticket.
#[case::forwarded_option(|r: &mut AsReq| r.0.req_body.0.kdc_options.0 = flags(0x2000_0000), KDC_ERR_BADOPTION)]
// oracle: spec RFC 4120 §5.9.1 - KDC_ERR_BADOPTION, as for forwarded.
#[case::proxy_option(|r: &mut AsReq| r.0.req_body.0.kdc_options.0 = flags(0x0800_0000), KDC_ERR_BADOPTION)]
// oracle: spec RFC 4120 §5.9.1 - KDC_ERR_BADOPTION, as for forwarded.
#[case::postdated_option(|r: &mut AsReq| r.0.req_body.0.kdc_options.0 = flags(0x0200_0000), KDC_ERR_BADOPTION)]
// oracle: spec RFC 4120 §5.9.1 - KDC_ERR_BADOPTION, as for forwarded.
#[case::renew_option(|r: &mut AsReq| r.0.req_body.0.kdc_options.0 = flags(0x0000_0002), KDC_ERR_BADOPTION)]
// oracle: spec RFC 4120 §5.9.1 - KDC_ERR_BADOPTION, as for forwarded.
#[case::validate_option(|r: &mut AsReq| r.0.req_body.0.kdc_options.0 = flags(0x0000_0001), KDC_ERR_BADOPTION)]
// oracle: spec RFC 4120 §2.9.2 - the ENC-TKT-IN-SKEY option is honored only by the ticket-granting service.
#[case::enc_tkt_in_skey_option(|r: &mut AsReq| r.0.req_body.0.kdc_options.0 = flags(ENC_TKT_IN_SKEY), KDC_ERR_BADOPTION)]
// oracle: spec RFC 4120 §5.9.1 - KRB_AP_ERR_MSG_TYPE, "Invalid msg type".
#[case::wrong_message_type(|r: &mut AsReq| r.0.msg_type.0 = IntegerAsn1::from(vec![TGS_REQ_MSG_TYPE]), KRB_AP_ERR_MSG_TYPE)]
// oracle: spec RFC 4120 §3.1.3 - KDC_ERR_CANNOT_POSTDATE for a start time beyond the clock skew.
#[case::start_time_too_far_in_the_future(
    |r: &mut AsReq| r.0.req_body.0.from = Optional::from(Some(ExplicitContextTag4::from(ktime(OffsetDateTime::now_utc() + Duration::from_secs(3600))))),
    KDC_ERR_CANNOT_POSTDATE
)]
// oracle: spec RFC 4120 §3.1.3 - KDC_ERR_NEVER_VALID when the requested lifetime is not positive.
#[case::end_time_in_the_past(
    |r: &mut AsReq| r.0.req_body.0.till.0 = ktime(OffsetDateTime::now_utc() - Duration::from_secs(600)),
    KDC_ERR_NEVER_VALID
)]
fn error_code(#[case] mutate: fn(&mut AsReq), #[case] expected: u32) {
    let mut req = valid_request();
    mutate(&mut req);

    assert_eq!(send_as(&req, &kdc_config()).unwrap_err_code(), expected);
}

#[test]
fn timestamp_outside_the_allowed_skew_is_rejected() {
    // oracle: mutant a PA-ENC-TIMESTAMP outside the clock skew is accepted, or is rejected with another code
    let etype = CipherSuite::Aes256CtsHmacSha196;
    let stale = OffsetDateTime::now_utc() - Duration::from_secs(MAX_SKEW_SECS + 60);
    let req = as_req(
        Some(vec![enc_timestamp(&etype, &user_key(&etype), stale)]),
        as_req_body(),
    );

    assert_eq!(send_as(&req, &kdc_config()).unwrap_err_code(), KRB_AP_ERR_SKEW);
}
