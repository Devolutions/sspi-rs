//! Requests that the TGS exchange rejects.

mod common;

use std::time::Duration;

use common::{
    ENC_TKT_IN_SKEY, HOSTNAME, MAX_SKEW_SECS, REALM, Tgt, domain_user, encrypted_data, etype_byte, etype_number, flags,
    kdc_config, ktime, padata_field, principal, raw_pa_data, realm, send_tgs, tgs_req, tgs_req_body, u2u_request,
    valid_tgs_request,
};
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag11, IntegerAsn1, Optional,
};
use picky_krb::constants::error_codes::{
    KDC_ERR_BAD_PVNO, KDC_ERR_BADOPTION, KDC_ERR_CANNOT_POSTDATE, KDC_ERR_ETYPE_NOSUPP, KDC_ERR_NEVER_VALID,
    KDC_ERR_PREAUTH_FAILED, KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_S_PRINCIPAL_UNKNOWN, KDC_ERR_SERVER_NOMATCH,
    KDC_ERR_WRONG_REALM, KRB_AP_ERR_BADMATCH, KRB_AP_ERR_BADVERSION, KRB_AP_ERR_MODIFIED, KRB_AP_ERR_SKEW,
    KRB_AP_ERR_TKT_EXPIRED, KRB_AP_ERR_TKT_NYV, KRB_ERR_GENERIC,
};
use picky_krb::constants::etypes::{DES3_CBC_SHA1_KD, RC4_HMA};
use picky_krb::constants::types::{NT_PRINCIPAL, NT_SRV_INST, PA_ENC_TIMESTAMP, PA_TGS_REQ_TYPE};
use picky_krb::messages::TgsReq;
use rstest::rstest;
use time::OffsetDateTime;

// The error code of each rejected request.
// RFC 4120 §3.3.3 and §5.9.1 decide the cases marked `spec`.
// The other codes are the choice of this KDC.
#[rstest]
// oracle: mutant a request without any padata is processed
#[case::no_padata(|r: &mut TgsReq| r.0.padata = Optional::from(None), KDC_ERR_PREAUTH_REQUIRED)]
// oracle: mutant a request for another realm is processed or is answered with another code
#[case::wrong_realm(|r: &mut TgsReq| r.0.req_body.0.realm.0 = realm("OTHER.COM"), KDC_ERR_WRONG_REALM)]
// oracle: spec RFC 4120 §5.9.1 - KDC_ERR_BAD_PVNO, "Requested protocol version number not supported".
#[case::wrong_protocol_version(|r: &mut TgsReq| r.0.pvno.0 = IntegerAsn1::from(vec![4]), KDC_ERR_BAD_PVNO)]
// oracle: spec RFC 4120 §5.9.1 - KDC_ERR_BADOPTION, "KDC cannot accommodate requested option";
// the KDC accommodates none of forwarded, proxy, postdated, renew and validate, which need an existing ticket.
#[case::forwarded_option(|r: &mut TgsReq| r.0.req_body.0.kdc_options.0 = flags(0x2000_0000), KDC_ERR_BADOPTION)]
// oracle: spec RFC 4120 §5.9.1 - KDC_ERR_BADOPTION, as for forwarded.
#[case::proxy_option(|r: &mut TgsReq| r.0.req_body.0.kdc_options.0 = flags(0x0800_0000), KDC_ERR_BADOPTION)]
// oracle: spec RFC 4120 §5.9.1 - KDC_ERR_BADOPTION, as for forwarded.
#[case::postdated_option(|r: &mut TgsReq| r.0.req_body.0.kdc_options.0 = flags(0x0200_0000), KDC_ERR_BADOPTION)]
// oracle: spec RFC 4120 §5.9.1 - KDC_ERR_BADOPTION, as for forwarded.
#[case::renew_option(|r: &mut TgsReq| r.0.req_body.0.kdc_options.0 = flags(0x0000_0002), KDC_ERR_BADOPTION)]
// oracle: spec RFC 4120 §5.9.1 - KDC_ERR_BADOPTION, as for forwarded.
#[case::validate_option(|r: &mut TgsReq| r.0.req_body.0.kdc_options.0 = flags(0x0000_0001), KDC_ERR_BADOPTION)]
// oracle: spec RFC 4120 §3.7 - enc-tkt-in-skey requires the TGT of the service as the additional ticket.
#[case::enc_tkt_in_skey_without_additional_ticket(
    |r: &mut TgsReq| r.0.req_body.0.kdc_options.0 = flags(ENC_TKT_IN_SKEY),
    KDC_ERR_BADOPTION
)]
// oracle: mutant a request without sname is processed
#[case::missing_sname(|r: &mut TgsReq| r.0.req_body.0.sname = Optional::from(None), KDC_ERR_S_PRINCIPAL_UNKNOWN)]
// oracle: spec RFC 4120 §3.3.3 - KDC_ERR_ETYPE_NOSUPP when no requested etype is supported.
#[case::only_unsupported_etype(
    |r: &mut TgsReq| r.0.req_body.0.etype.0 = Asn1SequenceOf::from(vec![IntegerAsn1::from(etype_number(RC4_HMA))]),
    KDC_ERR_ETYPE_NOSUPP
)]
// oracle: spec RFC 4120 §3.3.3 - the start time rules of the AS exchange apply: KDC_ERR_CANNOT_POSTDATE
// for a start time beyond the clock skew.
#[case::start_time_too_far_in_the_future(
    |r: &mut TgsReq| r.0.req_body.0.from = Optional::from(Some(ExplicitContextTag4::from(ktime(OffsetDateTime::now_utc() + Duration::from_secs(3600))))),
    KDC_ERR_CANNOT_POSTDATE
)]
// oracle: spec RFC 4120 §3.3.3 - the lifetime rules of the AS exchange apply: KDC_ERR_NEVER_VALID.
#[case::end_time_in_the_past(
    |r: &mut TgsReq| r.0.req_body.0.till.0 = ktime(OffsetDateTime::now_utc() - Duration::from_secs(600)),
    KDC_ERR_NEVER_VALID
)]
// oracle: mutant an undecodable AP-REQ is ignored
#[case::undecodable_ap_req(
    |r: &mut TgsReq| r.0.padata = padata_field(vec![raw_pa_data(&PA_TGS_REQ_TYPE, vec![0xde, 0xad])]),
    KDC_ERR_PREAUTH_FAILED
)]
// oracle: mutant a request without PA-TGS-REQ is processed
#[case::padata_without_pa_tgs_req(
    |r: &mut TgsReq| r.0.padata = padata_field(vec![raw_pa_data(&PA_ENC_TIMESTAMP, vec![])]),
    KDC_ERR_PREAUTH_REQUIRED
)]
// oracle: mutant the KDC issues tickets for services other than TERMSRV
#[case::service_is_not_termsrv(
    |r: &mut TgsReq| r.0.req_body.0.sname = Optional::from(Some(ExplicitContextTag3::from(principal(NT_SRV_INST, &["HTTP", HOSTNAME])))),
    KDC_ERR_S_PRINCIPAL_UNKNOWN
)]
// oracle: mutant the KDC issues tickets for hosts other than its own
#[case::service_host_is_not_the_gateway(
    |r: &mut TgsReq| r.0.req_body.0.sname = Optional::from(Some(ExplicitContextTag3::from(principal(NT_SRV_INST, &["TERMSRV", "other.example.com"])))),
    KDC_ERR_S_PRINCIPAL_UNKNOWN
)]
fn error_code(#[case] mutate: fn(&mut TgsReq), #[case] expected: u32) {
    let mut req = valid_tgs_request(&Tgt::valid());
    mutate(&mut req);

    assert_eq!(send_tgs(&req, &kdc_config()).unwrap_err_code(), expected);
}

// The error code of each authenticator that does not match the TGT.
#[rstest]
// oracle: spec RFC 4120 §3.2.3 - KRB_AP_ERR_BADMATCH when the client name differs from the one in the ticket.
#[case::other_client_name(
    |t: &mut Tgt| t.auth_cname = principal(NT_PRINCIPAL, &["mallory"]),
    KRB_AP_ERR_BADMATCH
)]
// oracle: spec RFC 4120 §3.2.3 - KRB_AP_ERR_BADMATCH when the client realm differs from the one in the ticket.
#[case::other_client_realm(|t: &mut Tgt| t.auth_crealm = "OTHER.COM", KRB_AP_ERR_BADMATCH)]
// oracle: spec RFC 4120 §3.2.3 - KRB_AP_ERR_SKEW when the client time differs from the KDC time
// by more than the allowable clock skew.
#[case::client_time_too_old(
    |t: &mut Tgt| t.auth_ctime = OffsetDateTime::now_utc() - Duration::from_secs(MAX_SKEW_SECS + 60),
    KRB_AP_ERR_SKEW
)]
// oracle: spec RFC 4120 §3.2.3 - KRB_AP_ERR_SKEW, as above, for a client clock that is ahead.
#[case::client_time_too_new(
    |t: &mut Tgt| t.auth_ctime = OffsetDateTime::now_utc() + Duration::from_secs(MAX_SKEW_SECS + 60),
    KRB_AP_ERR_SKEW
)]
fn authenticator_error_code(#[case] mutate: fn(&mut Tgt), #[case] expected: u32) {
    let mut tgt = Tgt::valid();
    mutate(&mut tgt);

    assert_eq!(
        send_tgs(&valid_tgs_request(&tgt), &kdc_config()).unwrap_err_code(),
        expected
    );
}

// The error code of each TGT that is not valid.
// TicketFlags bit 7 (invalid) is `1 << (31 - 7)` (§5.3).
#[rstest]
// oracle: spec RFC 4120 §3.2.3 - KRB_AP_ERR_TKT_NYV when the start time (here the authentication time,
// as the ticket has no start time) is later than the current time by more than the clock skew.
#[case::auth_time_in_the_future(
    |t: &mut Tgt| t.auth_time = OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp() + 3600).unwrap(),
    KRB_AP_ERR_TKT_NYV
)]
// oracle: spec RFC 4120 §3.2.3 - KRB_AP_ERR_TKT_NYV, as above, for an explicit start time.
#[case::start_time_in_the_future(
    |t: &mut Tgt| t.start_time = Some(OffsetDateTime::now_utc() + Duration::from_secs(3600)),
    KRB_AP_ERR_TKT_NYV
)]
// oracle: spec RFC 4120 §3.2.3 - KRB_AP_ERR_TKT_NYV when the INVALID flag is set in the ticket.
#[case::invalid_flag(|t: &mut Tgt| t.ticket_flags = 1 << (31 - 7), KRB_AP_ERR_TKT_NYV)]
// oracle: spec RFC 4120 §5.9.1 - KRB_AP_ERR_BADVERSION, "Protocol version mismatch".
#[case::unknown_ticket_version(|t: &mut Tgt| t.tkt_vno = 4, KRB_AP_ERR_BADVERSION)]
// oracle: mutant a TGT of another realm is accepted, although the KDC has no cross-realm support
#[case::ticket_of_another_realm(|t: &mut Tgt| t.ticket_realm = "OTHER.COM", KDC_ERR_WRONG_REALM)]
fn tgt_error_code(#[case] mutate: fn(&mut Tgt), #[case] expected: u32) {
    let mut tgt = Tgt::valid();
    mutate(&mut tgt);

    assert_eq!(
        send_tgs(&valid_tgs_request(&tgt), &kdc_config()).unwrap_err_code(),
        expected
    );
}

#[test]
fn tgt_started_in_the_past_is_accepted() {
    // oracle: spec RFC 4120 §3.2.3 - only a start time later than now plus the skew makes the ticket not yet valid.
    let mut tgt = Tgt::valid();
    tgt.start_time = Some(OffsetDateTime::now_utc() - Duration::from_secs(600));

    send_tgs(&valid_tgs_request(&tgt), &kdc_config()).unwrap_ok();
}

// A TGT that is valid from about now is accepted, for example one that the client got just before this request.
#[rstest]
// oracle: spec RFC 4120 §3.2.3 - a ticket whose start time (here the authentication time) is now is valid.
#[case::auth_time_now(|t: &mut Tgt| t.auth_time = OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp()).unwrap())]
// oracle: spec RFC 4120 §3.2.3 - only a start time later than now plus the skew makes the ticket not yet valid.
#[case::auth_time_ahead_within_skew(|t: &mut Tgt| t.auth_time = OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp() + 100).unwrap())]
// oracle: spec RFC 4120 §3.2.3 - as above, for an explicit start time.
#[case::start_time_ahead_within_skew(|t: &mut Tgt| t.start_time = Some(OffsetDateTime::now_utc() + Duration::from_secs(100)))]
fn tgt_valid_from_about_now_is_accepted(#[case] mutate: fn(&mut Tgt)) {
    let mut tgt = Tgt::valid();
    mutate(&mut tgt);

    send_tgs(&valid_tgs_request(&tgt), &kdc_config()).unwrap_ok();
}

// The KDC does not use the ciphers of the etypes it does not support, and it must not be asked to decrypt
// untrusted data with them: the DES3 decryption of picky-krb panics on a short ciphertext.
#[rstest]
// oracle: spec RFC 4120 §5.9.1 - KDC_ERR_ETYPE_NOSUPP, "KDC has no support for encryption type".
#[case::ticket(|t: &mut Tgt| t.raw_ticket_enc_part = Some(encrypted_data(etype_byte(DES3_CBC_SHA1_KD), vec![0])))]
// oracle: spec RFC 4120 §5.9.1 - KDC_ERR_ETYPE_NOSUPP, "KDC has no support for encryption type".
#[case::authenticator(|t: &mut Tgt| t.raw_authenticator = Some(encrypted_data(etype_byte(DES3_CBC_SHA1_KD), vec![0])))]
fn data_encrypted_with_an_unsupported_etype_is_rejected(#[case] mutate: fn(&mut Tgt)) {
    let mut tgt = Tgt::valid();
    mutate(&mut tgt);

    assert_eq!(
        send_tgs(&valid_tgs_request(&tgt), &kdc_config()).unwrap_err_code(),
        KDC_ERR_ETYPE_NOSUPP
    );
}

// The error code of each additional ticket that is not a valid TGT of this realm.
#[rstest]
// oracle: mutant the additional ticket is not checked for expiry
#[case::expired(
    |t: &mut Tgt| t.end_time = OffsetDateTime::now_utc() - Duration::from_secs(MAX_SKEW_SECS + 60),
    KRB_AP_ERR_TKT_EXPIRED
)]
// oracle: mutant the additional ticket is not checked for the realm
#[case::other_realm(|t: &mut Tgt| t.ticket_realm = "OTHER.COM", KDC_ERR_WRONG_REALM)]
// oracle: mutant the additional ticket is not checked for validity
#[case::not_yet_valid(|t: &mut Tgt| t.ticket_flags = 1 << (31 - 7), KRB_AP_ERR_TKT_NYV)]
fn additional_ticket_error_code(#[case] mutate: fn(&mut Tgt), #[case] expected: u32) {
    let tgt = Tgt::valid();
    let mut additional = Tgt::valid();
    mutate(&mut additional);

    assert_eq!(
        send_tgs(&u2u_request(&tgt, &additional), &kdc_config()).unwrap_err_code(),
        expected
    );
}

#[test]
fn additional_ticket_of_another_client_than_the_service_user_is_rejected() {
    // oracle: spec RFC 4120 §3.3.3 - the client of the additional ticket must be the requested server;
    // the configured service user is that server.
    // §7.5.9 - KDC_ERR_SERVER_NOMATCH, "Requested server and ticket don't match".
    let mut config = kdc_config();
    config.service_user = Some(domain_user("service"));
    let tgt = Tgt::valid();
    // The client of this TGT is `user`.
    let additional = Tgt::valid();

    assert_eq!(
        send_tgs(&u2u_request(&tgt, &additional), &config).unwrap_err_code(),
        KDC_ERR_SERVER_NOMATCH
    );
}

#[test]
fn client_time_inside_the_allowed_skew_is_accepted() {
    // oracle: spec RFC 4120 §3.2.3 - only a difference beyond the allowable skew is an error.
    let mut tgt = Tgt::valid();
    tgt.auth_ctime = OffsetDateTime::now_utc() - Duration::from_secs(MAX_SKEW_SECS - 100);

    send_tgs(&valid_tgs_request(&tgt), &kdc_config()).unwrap_ok();
}

#[test]
fn tgt_encrypted_with_another_key_is_rejected() {
    // oracle: mutant a TGT that the krbtgt key does not decrypt is accepted
    let mut tgt = Tgt::valid();
    tgt.krbtgt_key = vec![0x99; 32];

    assert_eq!(
        send_tgs(&valid_tgs_request(&tgt), &kdc_config()).unwrap_err_code(),
        KRB_AP_ERR_MODIFIED
    );
}

#[test]
fn authenticator_encrypted_with_another_key_is_rejected() {
    // oracle: mutant an authenticator that the TGT session key does not decrypt is accepted
    let tgt = Tgt::valid();
    let req = tgs_req(Some(vec![tgt.pa_tgs_req(&[0x99; 32], None)]), tgs_req_body());

    assert_eq!(send_tgs(&req, &kdc_config()).unwrap_err_code(), KRB_AP_ERR_MODIFIED);
}

#[test]
fn additional_ticket_that_is_not_a_tgt_is_rejected() {
    // oracle: spec RFC 4120 §3.7 - the additional ticket for user-to-user is the TGT of the service.
    let tgt = Tgt::valid();
    let mut not_tgt = Tgt::valid().ticket();
    not_tgt.0.sname.0 = principal(NT_SRV_INST, &["host", REALM]);
    let mut body = tgs_req_body();
    body.kdc_options.0 = flags(ENC_TKT_IN_SKEY);
    body.additional_tickets = Optional::from(Some(ExplicitContextTag11::from(Asn1SequenceOf::from(vec![not_tgt]))));
    let req = tgs_req(Some(vec![tgt.pa_tgs_req(&tgt.session_key, None)]), body);

    assert_eq!(
        send_tgs(&req, &kdc_config()).unwrap_err_code(),
        KDC_ERR_S_PRINCIPAL_UNKNOWN
    );
}

#[test]
fn missing_ticket_decryption_key_is_an_internal_error() {
    // oracle: mutant a KDC without a service key issues a ticket anyway
    let mut config = kdc_config();
    config.ticket_decryption_key = None;

    assert_eq!(
        send_tgs(&valid_tgs_request(&Tgt::valid()), &config).unwrap_err_code(),
        KRB_ERR_GENERIC
    );
}
