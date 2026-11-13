//! TGS exchange behaviour observed through `handle_kdc_proxy_message`.

mod common;

use std::time::Duration;

use common::{
    ENC_TKT_IN_SKEY, HOSTNAME, MAX_SKEW_SECS, REALM, SERVICE_KEY, Tgt, decrypt_tgs_rep_part, decrypt_ticket,
    domain_user, etype_byte, etype_list, etype_number, flags, kdc_config, ktime, principal, realm, send_tgs, tgs_req,
    tgs_req_body, u2u_request, valid_tgs_request,
};
use picky_asn1::wrapper::{Asn1SequenceOf, ExplicitContextTag11, Optional};
use picky_krb::constants::error_codes::{KDC_ERR_BADOPTION, KDC_ERR_ETYPE_NOSUPP, KDC_ERR_NEVER_VALID};
use picky_krb::constants::etypes::{AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96, DES3_CBC_SHA1_KD};
use picky_krb::constants::key_usages::{TGS_REP_ENC_SESSION_KEY, TGS_REP_ENC_SUB_KEY};
use picky_krb::constants::types::NT_SRV_INST;
use picky_krb::crypto::CipherSuite;
use time::OffsetDateTime;

#[test]
fn tgs_req_returns_service_ticket_for_valid_tgt() {
    // oracle: spec RFC 4120 §3.3.3 - with no authenticator subkey the reply is encrypted in the TGT session key,
    // the service ticket in the service key, and the nonce is copied from the request.
    let tgt = Tgt::valid();

    let rep = send_tgs(&valid_tgs_request(&tgt), &kdc_config()).unwrap_ok();

    let part = decrypt_tgs_rep_part(&rep, &tgt.session_key, TGS_REP_ENC_SESSION_KEY);
    assert_eq!(part.nonce.0.0, [0x01, 0x02, 0x03, 0x04]);
    let ticket = decrypt_ticket(&rep.0.ticket.0, &SERVICE_KEY);
    assert_eq!(ticket.key.0.key_value.0.0, part.key.0.key_value.0.0);
}

#[test]
fn tgs_req_reply_uses_authenticator_subkey_when_present() {
    // oracle: spec RFC 4120 §3.3.3 - when the authenticator carries a subkey, the reply is encrypted in it.
    // Key usages: 8 for the session key and 9 for the subkey (§7.5.1).
    let tgt = Tgt::valid();
    let subkey = vec![0x44; 32];
    let req = tgs_req(
        Some(vec![tgt.pa_tgs_req(&tgt.session_key, Some(&subkey))]),
        tgs_req_body(),
    );

    let rep = send_tgs(&req, &kdc_config()).unwrap_ok();

    decrypt_tgs_rep_part(&rep, &subkey, TGS_REP_ENC_SUB_KEY);
}

#[test]
fn tgt_expired_beyond_the_allowed_skew_is_rejected() {
    // oracle: spec RFC 4120 §3.2.3 - KRB_AP_ERR_TKT_EXPIRED when the current time is later than the end time
    // by more than the allowable clock skew.
    let mut tgt = Tgt::valid();
    tgt.end_time = OffsetDateTime::now_utc() - Duration::from_secs(MAX_SKEW_SECS + 60);

    assert_eq!(
        send_tgs(&valid_tgs_request(&tgt), &kdc_config()).unwrap_err_code(),
        picky_krb::constants::error_codes::KRB_AP_ERR_TKT_EXPIRED
    );
}

#[test]
fn tgt_expired_within_the_allowed_skew_cannot_issue_a_ticket() {
    // oracle: spec RFC 4120 §3.2.3 - a TGT expired by no more than the allowable clock skew is not rejected as expired.
    // oracle: spec RFC 4120 §3.3.3 and §3.1.3 - the ticket ends no later than the TGT, so it would end before it
    // starts: KDC_ERR_NEVER_VALID.
    let mut tgt = Tgt::valid();
    tgt.end_time = OffsetDateTime::now_utc() - Duration::from_secs(MAX_SKEW_SECS - 100);

    assert_eq!(
        send_tgs(&valid_tgs_request(&tgt), &kdc_config()).unwrap_err_code(),
        KDC_ERR_NEVER_VALID
    );
}

#[test]
fn empty_additional_tickets_list_is_rejected() {
    // An empty additional-tickets sequence must get an error reply, not a panic.
    // oracle: spec RFC 4120 §3.7 - user-to-user needs the TGT of the service as the additional ticket,
    // and §5.9.1 - KDC_ERR_BADOPTION is "KDC cannot accommodate requested option".
    let tgt = Tgt::valid();
    let mut body = tgs_req_body();
    body.kdc_options.0 = flags(ENC_TKT_IN_SKEY);
    body.additional_tickets = Optional::from(Some(ExplicitContextTag11::from(Asn1SequenceOf::from(vec![]))));
    let req = tgs_req(Some(vec![tgt.pa_tgs_req(&tgt.session_key, None)]), body);

    assert_eq!(send_tgs(&req, &kdc_config()).unwrap_err_code(), KDC_ERR_BADOPTION);
}

#[test]
fn requested_options_are_not_copied_to_the_service_ticket_flags() {
    // oracle: mutant the client's KDCOptions (forwardable, renewable) are copied into the ticket flags
    // TicketFlags bits: forwardable(1), renewable(8), initial(9) (§5.3).
    // The KDC grants none of them, but accepts the request.
    // INITIAL is only set by the AS.
    let tgt = Tgt::valid();
    let mut body = tgs_req_body();
    body.kdc_options.0 = flags(0x4080_0000); // forwardable | renewable
    let req = tgs_req(Some(vec![tgt.pa_tgs_req(&tgt.session_key, None)]), body);

    let rep = send_tgs(&req, &kdc_config()).unwrap_ok();

    let ticket = decrypt_ticket(&rep.0.ticket.0, &SERVICE_KEY);
    let reply_flags = decrypt_tgs_rep_part(&rep, &tgt.session_key, TGS_REP_ENC_SESSION_KEY)
        .flags
        .0
        .0;
    for flags in [&ticket.flags.0.0, &reply_flags] {
        assert!(!flags.is_set(1), "forwardable");
        assert!(!flags.is_set(8), "renewable");
        assert!(!flags.is_set(9), "initial");
    }
    assert!(ticket.renew_till.0.is_none(), "renew-till");
}

#[test]
fn authentication_flags_of_the_tgt_are_carried_to_the_service_ticket() {
    // oracle: spec RFC 4120 §2.1 - "the INITIAL flag is clear, but the PRE-AUTHENT and HW-AUTHENT flags are
    // carried forward from the TGT".
    // TicketFlags bits: initial(9), pre-authent(10), hw-authent(11) (§5.3).
    let mut tgt = Tgt::valid();
    tgt.ticket_flags = (1 << (31 - 9)) | (1 << (31 - 10)) | (1 << (31 - 11));

    let rep = send_tgs(&valid_tgs_request(&tgt), &kdc_config()).unwrap_ok();

    let ticket_flags = decrypt_ticket(&rep.0.ticket.0, &SERVICE_KEY).flags.0.0;
    let reply_flags = decrypt_tgs_rep_part(&rep, &tgt.session_key, TGS_REP_ENC_SESSION_KEY)
        .flags
        .0
        .0;
    for flags in [ticket_flags, reply_flags] {
        assert!(!flags.is_set(9), "initial");
        assert!(flags.is_set(10), "pre-authent");
        assert!(flags.is_set(11), "hw-authent");
    }
}

#[test]
fn service_ticket_cannot_outlive_the_tgt() {
    // oracle: spec RFC 4120 §3.3.3 - the end time is the minimum of the request, the end time of the TGT,
    // and the local limits.
    // Here the TGT ends first, in 600 seconds.
    let mut tgt = Tgt::valid();
    tgt.end_time = OffsetDateTime::now_utc() + Duration::from_secs(600);

    let rep = send_tgs(&valid_tgs_request(&tgt), &kdc_config()).unwrap_ok();

    let ticket = decrypt_ticket(&rep.0.ticket.0, &SERVICE_KEY);
    let end = OffsetDateTime::try_from(ticket.endtime.0.0).unwrap();
    // The ticket times have a resolution of one second.
    assert!(
        end <= tgt.end_time && tgt.end_time - end < time::Duration::seconds(2),
        "{end}"
    );
}

#[test]
fn requested_lifetime_is_capped_at_one_hour() {
    // oracle: mutant the local lifetime limit (one hour) is not applied or is applied as a shorter time
    let mut tgt = Tgt::valid();
    tgt.end_time = OffsetDateTime::now_utc() + Duration::from_secs(24 * 3600);
    let mut body = tgs_req_body();
    body.till.0 = ktime(OffsetDateTime::now_utc() + Duration::from_secs(24 * 3600));
    let req = tgs_req(Some(vec![tgt.pa_tgs_req(&tgt.session_key, None)]), body);

    let rep = send_tgs(&req, &kdc_config()).unwrap_ok();

    let end = OffsetDateTime::try_from(decrypt_ticket(&rep.0.ticket.0, &SERVICE_KEY).endtime.0.0).unwrap();
    let remaining = end - OffsetDateTime::now_utc();
    assert!(
        (time::Duration::seconds(3590)..=time::Duration::seconds(3600)).contains(&remaining),
        "{remaining}"
    );
}

#[test]
fn requested_lifetime_below_the_limits_is_honored() {
    // oracle: spec RFC 4120 §3.3.3 - the end time is the minimum of the request, the end time of the TGT,
    // and the local limits.
    // Here the request ends first, in 1800 seconds.
    let tgt = Tgt::valid();
    let mut body = tgs_req_body();
    body.till.0 = ktime(OffsetDateTime::now_utc() + Duration::from_secs(1800));
    let req = tgs_req(Some(vec![tgt.pa_tgs_req(&tgt.session_key, None)]), body);

    let rep = send_tgs(&req, &kdc_config()).unwrap_ok();

    let end = OffsetDateTime::try_from(decrypt_ticket(&rep.0.ticket.0, &SERVICE_KEY).endtime.0.0).unwrap();
    let remaining = end - OffsetDateTime::now_utc();
    assert!(
        (time::Duration::seconds(1795)..=time::Duration::seconds(1800)).contains(&remaining),
        "{remaining}"
    );
}

#[test]
fn service_ticket_keeps_the_authentication_time_of_the_tgt() {
    // oracle: spec RFC 4120 §3.3.3 - the time of initial authentication of the new ticket is copied from the TGT.
    let tgt = Tgt::valid();

    let rep = send_tgs(&valid_tgs_request(&tgt), &kdc_config()).unwrap_ok();

    let ticket = decrypt_ticket(&rep.0.ticket.0, &SERVICE_KEY);
    assert_eq!(OffsetDateTime::try_from(ticket.auth_time.0.0).unwrap(), tgt.auth_time);
    let part = decrypt_tgs_rep_part(&rep, &tgt.session_key, TGS_REP_ENC_SESSION_KEY);
    assert_eq!(OffsetDateTime::try_from(part.auth_time.0.0).unwrap(), tgt.auth_time);
}

#[test]
fn service_ticket_starts_now_and_not_at_the_authentication_time_of_the_tgt() {
    // oracle: spec RFC 4120 §3.3.3 - an absent requested start time becomes the current time of the KDC.
    // The TGT was authenticated 30 minutes ago.
    let tgt = Tgt::valid();

    let rep = send_tgs(&valid_tgs_request(&tgt), &kdc_config()).unwrap_ok();

    let now = OffsetDateTime::now_utc();
    let ticket = decrypt_ticket(&rep.0.ticket.0, &SERVICE_KEY);
    let ticket_start = OffsetDateTime::try_from(ticket.starttime.0.expect("starttime is present").0.0).unwrap();
    assert!(
        (now - ticket_start).abs() < time::Duration::seconds(5),
        "{ticket_start}"
    );
    // oracle: spec RFC 4120 §5.4.2 - the reply repeats the start time of the ticket.
    let part = decrypt_tgs_rep_part(&rep, &tgt.session_key, TGS_REP_ENC_SESSION_KEY);
    let reply_start = OffsetDateTime::try_from(part.start_time.0.expect("start-time is present").0.0).unwrap();
    assert_eq!(reply_start, ticket_start);
}

#[test]
fn user_to_user_service_ticket_is_encrypted_with_the_additional_tgt_session_key() {
    // oracle: spec RFC 4120 §3.7 - with the additional TGT of the service, the issued ticket is encrypted
    // using a session key from that TGT instead of the service key.
    let tgt = Tgt::valid();
    let mut service_tgt = Tgt::valid();
    service_tgt.session_key = vec![0x55; 32];

    let rep = send_tgs(&u2u_request(&tgt, &service_tgt), &kdc_config()).unwrap_ok();

    decrypt_ticket(&rep.0.ticket.0, &service_tgt.session_key);
}

#[test]
fn additional_ticket_of_the_service_user_is_accepted() {
    // oracle: spec RFC 4120 §3.3.3 - the client of the additional ticket is the requested server;
    // the name is compared case-insensitively, like the other principal names.
    let mut config = kdc_config();
    config.service_user = Some(domain_user("USER"));
    let tgt = Tgt::valid();
    let mut service_tgt = Tgt::valid();
    service_tgt.session_key = vec![0x55; 32];

    let rep = send_tgs(&u2u_request(&tgt, &service_tgt), &config).unwrap_ok();

    decrypt_ticket(&rep.0.ticket.0, &service_tgt.session_key);
}

#[test]
fn user_to_user_does_not_need_the_service_key() {
    // oracle: mutant user-to-user issuance requires the service key of the KDC, which the verifier does not have
    let tgt = Tgt::valid();
    let mut service_tgt = Tgt::valid();
    service_tgt.session_key = vec![0x55; 32];
    let mut config = kdc_config();
    config.ticket_decryption_key = None;

    let rep = send_tgs(&u2u_request(&tgt, &service_tgt), &config).unwrap_ok();

    decrypt_ticket(&rep.0.ticket.0, &service_tgt.session_key);
}

#[test]
fn user_to_user_ticket_is_encrypted_with_the_etype_of_the_additional_tgt_session_key() {
    // oracle: spec RFC 4120 §3.7 - the issued ticket is encrypted using a session key from the additional TGT,
    // and §5.3 - the etype in the ticket names the key it is encrypted in (here AES128, etype 17, a 128-bit key).
    let tgt = Tgt::valid();
    let mut service_tgt = Tgt::valid();
    service_tgt.key_type = etype_byte(AES128_CTS_HMAC_SHA1_96);
    service_tgt.session_key = vec![0x55; 16];

    let rep = send_tgs(&u2u_request(&tgt, &service_tgt), &kdc_config()).unwrap_ok();

    assert_eq!(
        rep.0.ticket.0.0.enc_part.0.etype.0.0,
        etype_number(AES128_CTS_HMAC_SHA1_96)
    );
    decrypt_ticket(&rep.0.ticket.0, &service_tgt.session_key);
}

#[test]
fn reply_names_the_client_and_the_requested_service() {
    // oracle: spec RFC 4120 §3.3.3 - the client name and realm of the new ticket are copied from the TGT;
    // §5.4.2 - the reply repeats them, together with the requested service.
    let tgt = Tgt::valid();

    let rep = send_tgs(&valid_tgs_request(&tgt), &kdc_config()).unwrap_ok();

    let service = principal(NT_SRV_INST, &["TERMSRV", HOSTNAME]);
    assert_eq!(rep.0.crealm.0.to_string(), REALM);
    assert_eq!(rep.0.cname.0, tgt.cname);
    assert_eq!(rep.0.ticket.0.0.sname.0, service);
    let ticket = decrypt_ticket(&rep.0.ticket.0, &SERVICE_KEY);
    assert_eq!(ticket.cname.0, tgt.cname);
    assert_eq!(ticket.crealm.0.to_string(), REALM);
    let part = decrypt_tgs_rep_part(&rep, &tgt.session_key, TGS_REP_ENC_SESSION_KEY);
    assert_eq!(part.sname.0, service);
    assert_eq!(part.srealm.0.to_string(), REALM);
}

#[test]
fn client_realm_is_copied_from_the_tgt_and_not_from_the_request() {
    // oracle: spec RFC 4120 §3.3.3 - the client realm of the new ticket is copied from the TGT.
    // The realm of the request body is the realm of the server; it is matched case-insensitively.
    let tgt = Tgt::valid();
    let mut req = valid_tgs_request(&tgt);
    req.0.req_body.0.realm.0 = realm(&REALM.to_lowercase());

    let rep = send_tgs(&req, &kdc_config()).unwrap_ok();

    assert_eq!(rep.0.crealm.0.to_string(), REALM);
    let ticket = decrypt_ticket(&rep.0.ticket.0, &SERVICE_KEY);
    assert_eq!(ticket.crealm.0.to_string(), REALM);
}

#[test]
fn requested_etype_selects_the_new_session_key_and_not_the_reply_key() {
    // oracle: spec RFC 4120 §3.3.3 - the reply is encrypted in the key of the PA-TGS-REQ (here the AES256 TGT
    // session key); the etype list of the request is for the new session key (here AES128: etype 17, 128 bits,
    // RFC 3962 §7).
    let tgt = Tgt::valid();
    let mut body = tgs_req_body();
    body.etype.0 = etype_list(&[CipherSuite::Aes128CtsHmacSha196]);
    let req = tgs_req(Some(vec![tgt.pa_tgs_req(&tgt.session_key, None)]), body);

    let rep = send_tgs(&req, &kdc_config()).unwrap_ok();

    assert_eq!(rep.0.enc_part.0.etype.0.0, etype_number(AES256_CTS_HMAC_SHA1_96));
    let part = decrypt_tgs_rep_part(&rep, &tgt.session_key, TGS_REP_ENC_SESSION_KEY);
    assert_eq!(part.key.0.key_type.0.0, etype_number(AES128_CTS_HMAC_SHA1_96));
    assert_eq!(part.key.0.key_value.0.0.len(), 16);
}

#[test]
fn unsupported_subkey_etype_is_rejected() {
    // The reply is encrypted in the authenticator subkey, so a DES3 (etype 16) subkey is refused.
    // oracle: spec RFC 4120 §5.9.1 - KDC_ERR_ETYPE_NOSUPP, "KDC has no support for encryption type".
    let mut tgt = Tgt::valid();
    tgt.subkey_type = etype_byte(DES3_CBC_SHA1_KD);
    let req = tgs_req(
        Some(vec![tgt.pa_tgs_req(&tgt.session_key, Some(&[0x44; 24]))]),
        tgs_req_body(),
    );

    assert_eq!(send_tgs(&req, &kdc_config()).unwrap_err_code(), KDC_ERR_ETYPE_NOSUPP);
}
