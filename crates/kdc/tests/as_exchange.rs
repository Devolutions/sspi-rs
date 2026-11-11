//! AS exchange behaviour observed through `handle_kdc_proxy_message`.

mod common;

use common::{
    KRBTGT_KEY, REALM, Reply, SALT, USER, as_req, as_req_body, decrypt_as_rep_part, decrypt_ticket, enc_timestamp,
    etype_list, etype_number, exchange_raw, flags, kdc_config, ktime, parse_as_reply, principal, realm, send_as,
    user_key, valid_enc_timestamp,
};
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag3, ExplicitContextTag9, IntegerAsn1,
    OctetStringAsn1, Optional,
};
use picky_krb::constants::error_codes::{KDC_ERR_ETYPE_NOSUPP, KDC_ERR_PREAUTH_FAILED};
use picky_krb::constants::etypes::{AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96, RC4_HMA};
use picky_krb::constants::types::{
    NET_BIOS_ADDR_TYPE, NT_ENTERPRISE, NT_PRINCIPAL, NT_SRV_INST, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2_TYPE,
};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{EtypeInfo2Entry, HostAddress, PaData};
use time::OffsetDateTime;

#[test]
fn password_logon_returns_tgt_decryptable_with_user_key_and_krbtgt_key() {
    // oracle: spec RFC 4120 §3.1.3 - the reply is encrypted in the client key and the ticket in the krbtgt key,
    // and the ticket carries the session key of the reply; the nonce is copied from the request.
    let etype = CipherSuite::Aes256CtsHmacSha196;
    let req = as_req(Some(vec![valid_enc_timestamp()]), as_req_body());

    let rep = send_as(&req, &kdc_config()).unwrap_ok();

    let part = decrypt_as_rep_part(&rep, &user_key(&etype));
    assert_eq!(part.nonce.0.0, [0x01, 0x02, 0x03, 0x04]);
    let ticket = decrypt_ticket(&rep.0.ticket.0, &KRBTGT_KEY);
    assert_eq!(ticket.key.0.key_value.0.0, part.key.0.key_value.0.0);
}

#[test]
fn etype_list_is_searched_for_a_supported_etype() {
    // An unsupported etype (here RC4-HMAC, 23) listed before AES256 must not make the KDC reject the request.
    // oracle: spec RFC 4120 §3.1.3 - the KDC selects an etype it supports from the requested list.
    let mut body = as_req_body();
    body.etype.0 = Asn1SequenceOf::from(vec![
        IntegerAsn1::from(etype_number(RC4_HMA)),
        IntegerAsn1::from(etype_number(AES256_CTS_HMAC_SHA1_96)),
    ]);
    let req = as_req(Some(vec![valid_enc_timestamp()]), body);

    let rep = send_as(&req, &kdc_config()).unwrap_ok();

    assert_eq!(rep.0.enc_part.0.etype.0.0, etype_number(AES256_CTS_HMAC_SHA1_96));
}

#[test]
fn aes128_logon_returns_reply_encrypted_with_the_aes128_user_key() {
    // oracle: spec RFC 3962 §7 - aes128-cts-hmac-sha1-96 is etype 17.
    let etype = CipherSuite::Aes128CtsHmacSha196;
    let key = user_key(&etype);
    let mut body = as_req_body();
    body.etype.0 = etype_list(std::slice::from_ref(&etype));
    let req = as_req(Some(vec![enc_timestamp(&etype, &key, OffsetDateTime::now_utc())]), body);

    let rep = send_as(&req, &kdc_config()).unwrap_ok();

    assert_eq!(rep.0.enc_part.0.etype.0.0, etype_number(AES128_CTS_HMAC_SHA1_96));
    decrypt_as_rep_part(&rep, &key);
}

#[test]
fn enterprise_principal_name_is_matched_against_the_full_upn() {
    // oracle: mutant an NT-ENTERPRISE name is looked up by a part of the UPN or not at all
    let mut body = as_req_body();
    body.cname = Optional::from(Some(ExplicitContextTag1::from(principal(
        NT_ENTERPRISE,
        &["user@example.com"],
    ))));
    let req = as_req(Some(vec![valid_enc_timestamp()]), body);

    send_as(&req, &kdc_config()).unwrap_ok();
}

#[test]
fn reply_advertises_the_user_salt() {
    // oracle: spec RFC 4120 §5.2.7.5 - ETYPE-INFO2 carries the salt the client must use to derive its key.
    let req = as_req(Some(vec![valid_enc_timestamp()]), as_req_body());

    let rep = send_as(&req, &kdc_config()).unwrap_ok();

    let pa_data = &rep.0.padata.0.as_ref().expect("padata is present").0.0;
    let info2 = pa_data
        .iter()
        .find(|pa| pa.padata_type.0.0 == PA_ETYPE_INFO2_TYPE)
        .expect("ETYPE-INFO2 is present");
    let entries: Asn1SequenceOf<EtypeInfo2Entry> = picky_asn1_der::from_bytes(&info2.padata_data.0.0).unwrap();
    let salt = entries.0[0].salt.0.as_ref().expect("salt is present");
    assert_eq!(salt.0.to_string(), SALT);
}

#[test]
fn timestamp_encrypted_with_a_wrong_password_is_rejected() {
    // oracle: spec RFC 4120 §3.1.3 - KDC_ERR_PREAUTH_FAILED when the pre-authentication data is invalid,
    // which clients use to tell a wrong password from a damaged message.
    let etype = CipherSuite::Aes256CtsHmacSha196;
    let wrong_key = etype
        .cipher()
        .generate_key_from_password(b"wrong", SALT.as_bytes())
        .unwrap();
    let req = as_req(
        Some(vec![enc_timestamp(&etype, &wrong_key, OffsetDateTime::now_utc())]),
        as_req_body(),
    );

    assert_eq!(send_as(&req, &kdc_config()).unwrap_err_code(), KDC_ERR_PREAUTH_FAILED);
}

#[test]
fn issued_tgt_is_flagged_initial_and_pre_authenticated() {
    // oracle: spec RFC 4120 §3.1.3 - the AS sets INITIAL, and PRE-AUTHENT after a successful pre-authentication.
    // TicketFlags bits: initial(9), pre-authent(10) (§5.3).
    // The reply flags repeat the ticket flags (§5.4.2).
    let req = as_req(Some(vec![valid_enc_timestamp()]), as_req_body());

    let rep = send_as(&req, &kdc_config()).unwrap_ok();

    let ticket_flags = decrypt_ticket(&rep.0.ticket.0, &KRBTGT_KEY).flags.0.0;
    let reply_flags = decrypt_as_rep_part(&rep, &user_key(&CipherSuite::Aes256CtsHmacSha196))
        .flags
        .0
        .0;
    for flags in [ticket_flags, reply_flags] {
        assert!(flags.is_set(9), "initial");
        assert!(flags.is_set(10), "pre-authent");
    }
}

#[test]
fn requested_options_are_not_copied_to_the_ticket_flags() {
    // oracle: mutant the client's KDCOptions (forwardable, renewable) are copied into the ticket flags
    // TicketFlags bits: forwardable(1), renewable(8) (§5.3).
    // The KDC grants neither, but still accepts the request.
    let mut body = as_req_body();
    body.kdc_options.0 = flags(0x4080_0000); // forwardable | renewable
    let req = as_req(Some(vec![valid_enc_timestamp()]), body);

    let rep = send_as(&req, &kdc_config()).unwrap_ok();

    let ticket = decrypt_ticket(&rep.0.ticket.0, &KRBTGT_KEY);
    assert!(!ticket.flags.0.0.is_set(1), "forwardable");
    assert!(!ticket.flags.0.0.is_set(8), "renewable");
    assert!(ticket.renew_till.0.is_none(), "renew-till");
}

#[test]
fn reply_names_the_client_and_the_krbtgt_service() {
    // oracle: spec RFC 4120 §5.4.2 - KDC-REP carries the client realm and name, and EncKDCRepPart carries the
    // service realm and name, which for the AS exchange are the KDC realm and `krbtgt/REALM` (§7.3).
    let req = as_req(Some(vec![valid_enc_timestamp()]), as_req_body());

    let rep = send_as(&req, &kdc_config()).unwrap_ok();

    assert_eq!(rep.0.crealm.0.to_string(), REALM);
    assert_eq!(rep.0.cname.0, principal(NT_PRINCIPAL, &[USER]));
    let part = decrypt_as_rep_part(&rep, &user_key(&CipherSuite::Aes256CtsHmacSha196));
    assert_eq!(part.srealm.0.to_string(), REALM);
    assert_eq!(part.sname.0, principal(NT_SRV_INST, &["krbtgt", REALM]));
    let ticket = decrypt_ticket(&rep.0.ticket.0, &KRBTGT_KEY);
    assert_eq!(ticket.cname.0, rep.0.cname.0);
    assert_eq!(ticket.crealm.0.to_string(), REALM);
}

#[test]
fn realm_and_user_names_are_matched_case_insensitively() {
    // oracle: mutant the realm or the user name is compared case-sensitively
    // The KDC matches names the way Active Directory does.
    let mut body = as_req_body();
    body.realm.0 = realm("example.com");
    body.cname = Optional::from(Some(ExplicitContextTag1::from(principal(NT_PRINCIPAL, &["USER"]))));
    body.sname = Optional::from(Some(ExplicitContextTag3::from(principal(
        NT_SRV_INST,
        &["krbtgt", "example.com"],
    ))));
    let req = as_req(Some(vec![valid_enc_timestamp()]), body);

    send_as(&req, &kdc_config()).unwrap_ok();
}

#[test]
fn client_addresses_are_copied_to_the_reply() {
    // oracle: spec RFC 4120 §3.1.3 - the KDC copies the addresses of the request into the caddr of the reply.
    let address = HostAddress {
        addr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NET_BIOS_ADDR_TYPE])),
        address: ExplicitContextTag1::from(OctetStringAsn1::from(b"WORKSTATION".to_vec())),
    };
    let mut body = as_req_body();
    body.addresses = Optional::from(Some(ExplicitContextTag9::from(Asn1SequenceOf::from(vec![
        address.clone(),
    ]))));
    let req = as_req(Some(vec![valid_enc_timestamp()]), body);

    let rep = send_as(&req, &kdc_config()).unwrap_ok();

    let part = decrypt_as_rep_part(&rep, &user_key(&CipherSuite::Aes256CtsHmacSha196));
    assert_eq!(part.caddr.0.expect("caddr is present").0.0, [address]);
}

#[rstest::rstest]
#[case::aes128(CipherSuite::Aes128CtsHmacSha196, AES128_CTS_HMAC_SHA1_96, 16)]
#[case::aes256(CipherSuite::Aes256CtsHmacSha196, AES256_CTS_HMAC_SHA1_96, 32)]
fn session_key_has_the_type_and_length_of_the_etype(
    #[case] etype: CipherSuite,
    #[case] key_type: usize,
    #[case] key_len: usize,
) {
    // oracle: spec RFC 3962 §7 - aes128-cts-hmac-sha1-96 is etype 17 with a 128-bit key,
    // and aes256-cts-hmac-sha1-96 is etype 18 with a 256-bit key.
    let key = user_key(&etype);
    let mut body = as_req_body();
    body.etype.0 = etype_list(std::slice::from_ref(&etype));
    let req = as_req(Some(vec![enc_timestamp(&etype, &key, OffsetDateTime::now_utc())]), body);

    let rep = send_as(&req, &kdc_config()).unwrap_ok();

    let session_key = decrypt_as_rep_part(&rep, &key).key.0;
    assert_eq!(session_key.key_type.0.0, etype_number(key_type));
    assert_eq!(session_key.key_value.0.0.len(), key_len);
}

#[test]
fn error_for_an_unknown_user_names_the_kdc_and_leaks_no_salt() {
    // The request has no sname, so the error names the krbtgt service of the KDC realm.
    let mut body = as_req_body();
    body.cname = Optional::from(Some(ExplicitContextTag1::from(principal(NT_PRINCIPAL, &["nobody"]))));
    body.sname = Optional::from(None);
    let req = as_req(None, body);

    let Reply::Err(err) = send_as(&req, &kdc_config()) else {
        panic!("expected KRB-ERROR");
    };

    // oracle: spec RFC 4120 §5.9.1 - the realm and sname of a KRB-ERROR are the server's.
    assert_eq!(err.0.realm.0.to_string(), REALM);
    assert_eq!(err.0.sname.0, principal(NT_SRV_INST, &["krbtgt", REALM]));
    // oracle: mutant the ETYPE-INFO2 hint with the salt is sent for a principal the KDC does not know
    if let Some(e_data) = &err.0.e_data.0 {
        let method_data: Asn1SequenceOf<PaData> = picky_asn1_der::from_bytes(&e_data.0.0).unwrap();
        assert!(method_data.0.iter().all(|pa| pa.padata_type.0.0 != PA_ETYPE_INFO2_TYPE));
    }
    // oracle: spec RFC 4120 §5.9.1 - stime is the current time of the KDC.
    let stime = OffsetDateTime::try_from(err.0.stime.0.0).unwrap();
    assert!((OffsetDateTime::now_utc() - stime).abs() < time::Duration::seconds(5));
}

#[test]
fn kdc_options_with_an_impossible_unused_bits_count_are_answered() {
    // The first content byte of the kdc-options BIT STRING is the number of unused bits (0..=7, X.690 §8.6.2.2).
    // A larger value must get a reply, not a panic.
    // oracle: mutant the bit lookup panics on an unused-bits count above the payload size
    let mut raw = picky_asn1_der::to_vec(&as_req(Some(vec![valid_enc_timestamp()]), as_req_body())).unwrap();
    // DER of the 32 empty KDCOptions bits: BIT STRING, length 5, 0 unused bits, 4 zero bytes.
    let kdc_options = raw
        .windows(7)
        .position(|window| window == [0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00])
        .expect("kdc-options are encoded");
    raw[kdc_options + 2] = 0xff;

    // All option bits are zero, so a request that reaches the KDC logic is valid and gets an AS-REP.
    // A KRB-ERROR would also mean the request was not decoded and the bit lookup was never reached.
    parse_as_reply(&exchange_raw(&raw, &kdc_config())).unwrap_ok();
}

#[test]
fn reply_uses_the_etype_of_the_pre_authentication_key() {
    // The user key is derived for the etype of the PA-ENC-TIMESTAMP.
    // The reply must use that etype even when the request lists a more preferred one.
    // oracle: mutant the reply is encrypted with an etype that does not match the user key
    let etype = CipherSuite::Aes128CtsHmacSha196;
    let key = user_key(&etype);
    let mut body = as_req_body();
    body.etype.0 = etype_list(&[CipherSuite::Aes256CtsHmacSha196, etype.clone()]);
    let req = as_req(Some(vec![enc_timestamp(&etype, &key, OffsetDateTime::now_utc())]), body);

    let rep = send_as(&req, &kdc_config()).unwrap_ok();

    assert_eq!(rep.0.enc_part.0.etype.0.0, etype_number(AES128_CTS_HMAC_SHA1_96));
    decrypt_as_rep_part(&rep, &key);
}

#[test]
fn pre_authentication_etype_missing_from_the_request_list_is_rejected() {
    // oracle: mutant the reply is encrypted with an etype the client did not offer
    let etype = CipherSuite::Aes128CtsHmacSha196;
    let req = as_req(
        Some(vec![enc_timestamp(
            &etype,
            &user_key(&etype),
            OffsetDateTime::now_utc(),
        )]),
        as_req_body(), // offers AES256 only
    );

    assert_eq!(send_as(&req, &kdc_config()).unwrap_err_code(), KDC_ERR_ETYPE_NOSUPP);
}

#[test]
fn requested_lifetime_is_capped_at_one_hour() {
    // oracle: mutant the local lifetime limit (one hour) is not applied or is applied as a shorter time
    let mut body = as_req_body();
    body.till.0 = ktime(OffsetDateTime::now_utc() + std::time::Duration::from_secs(24 * 3600));
    let req = as_req(Some(vec![valid_enc_timestamp()]), body);

    let rep = send_as(&req, &kdc_config()).unwrap_ok();

    let part = decrypt_as_rep_part(&rep, &user_key(&CipherSuite::Aes256CtsHmacSha196));
    let remaining = OffsetDateTime::try_from(part.end_time.0.0).unwrap() - OffsetDateTime::now_utc();
    assert!(
        (time::Duration::seconds(3590)..=time::Duration::seconds(3600)).contains(&remaining),
        "{remaining}"
    );
}

#[test]
fn requested_lifetime_below_the_cap_is_honored() {
    // oracle: spec RFC 4120 §3.1.3 - the end time is the earlier of the requested time and the local limit.
    let mut body = as_req_body();
    body.till.0 = ktime(OffsetDateTime::now_utc() + std::time::Duration::from_secs(1800));
    let req = as_req(Some(vec![valid_enc_timestamp()]), body);

    let rep = send_as(&req, &kdc_config()).unwrap_ok();

    let part = decrypt_as_rep_part(&rep, &user_key(&CipherSuite::Aes256CtsHmacSha196));
    let remaining = OffsetDateTime::try_from(part.end_time.0.0).unwrap() - OffsetDateTime::now_utc();
    assert!(
        (time::Duration::seconds(1795)..=time::Duration::seconds(1800)).contains(&remaining),
        "{remaining}"
    );
}

#[test]
fn error_reply_carries_valid_microseconds_and_preauth_hints() {
    // oracle: spec RFC 4120 §5.2.4 - Microseconds ::= INTEGER (0..999999).
    let req = as_req(None, as_req_body());

    let Reply::Err(err) = send_as(&req, &kdc_config()) else {
        panic!("expected KRB-ERROR");
    };

    let susec = err.0.susec.0.0.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b));
    assert!(susec <= 999_999, "{susec}");
    // oracle: spec RFC 4120 §5.9.1 - the e-data of KDC_ERR_PREAUTH_REQUIRED is METHOD-DATA,
    // and §5.2.7.2, §5.2.7.5 - it names the encrypted timestamp and the ETYPE-INFO2 salt hint.
    let e_data = &err.0.e_data.0.as_ref().expect("e-data is present").0.0;
    let method_data: Asn1SequenceOf<PaData> = picky_asn1_der::from_bytes(e_data).unwrap();
    let types: Vec<&[u8]> = method_data.0.iter().map(|pa| pa.padata_type.0.0.as_slice()).collect();
    assert!(types.contains(&PA_ENC_TIMESTAMP.as_slice()), "{types:?}");
    assert!(types.contains(&PA_ETYPE_INFO2_TYPE.as_slice()), "{types:?}");
}
