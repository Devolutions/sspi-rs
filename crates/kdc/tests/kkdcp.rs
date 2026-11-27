//! KKDCP envelope handling of `handle_kdc_proxy_message`.

mod common;

use common::{HOSTNAME, REALM, as_req, as_req_body, exchange_raw, kdc_config, kkdcp_message, kstr};
use picky_asn1::wrapper::{ExplicitContextTag1, Optional};
use picky_krb::constants::error_codes::KRB_ERR_GENERIC;
use picky_krb::messages::{KdcProxyMessage, KrbError};

#[test]
fn message_shorter_than_the_length_prefix_is_an_error() {
    // oracle: spec RFC 4120 §7.2.2 - the Kerberos message is preceded by a 4-byte length,
    // so fewer bytes cannot hold a message.
    let msg = KdcProxyMessage::from_raw_kerb_message(&[0, 0, 1]).unwrap();

    kdc::handle_kdc_proxy_message(msg, &kdc_config(), HOSTNAME).unwrap_err();
}

#[rstest::rstest]
// oracle: spec RFC 4120 §7.2.2 - the 4-byte prefix is the length of the Kerberos message that follows,
// so a message shorter than that is truncated.
#[case::prefix_longer_than_message(1)]
// oracle: mutant bytes after the end of the Kerberos message are ignored
#[case::prefix_shorter_than_message(-1)]
fn length_prefix_that_does_not_match_the_message_is_an_error(#[case] error: i64) {
    let raw = picky_asn1_der::to_vec(&as_req(None, as_req_body())).unwrap();
    let prefix = u32::try_from(i64::try_from(raw.len()).unwrap() + error).unwrap();
    let msg = kkdcp_message(&raw, prefix);

    kdc::handle_kdc_proxy_message(msg, &kdc_config(), HOSTNAME).unwrap_err();
}

#[test]
fn garbage_message_is_answered_with_a_generic_krb_error() {
    // oracle: mutant a message that is neither an AS-REQ nor a TGS-REQ is dropped, or answered with another code
    let raw = exchange_raw(&[0xde, 0xad, 0xbe, 0xef], &kdc_config());

    let err: KrbError = picky_asn1_der::from_bytes(&raw).unwrap();
    assert_eq!(err.0.error_code.0, KRB_ERR_GENERIC);
}

#[test]
fn reply_echoes_target_domain_and_has_a_matching_length_prefix() {
    // oracle: spec RFC 4120 §7.2.2 - the reply is preceded by the 4-byte length of the Kerberos message.
    let req = as_req(None, as_req_body());
    let raw = picky_asn1_der::to_vec(&req).unwrap();
    let mut msg = kkdcp_message(&raw, u32::try_from(raw.len()).unwrap());
    msg.target_domain = Optional::from(Some(ExplicitContextTag1::from(kstr(REALM))));

    let reply = kdc::handle_kdc_proxy_message(msg, &kdc_config(), HOSTNAME).unwrap();

    // oracle: mutant the target-domain of the KKDCP request is dropped from the reply
    assert_eq!(reply.target_domain.0.unwrap().0.to_string(), REALM);
    let body = &reply.kerb_message.0.0;
    assert_eq!(
        usize::try_from(u32::from_be_bytes(body[..4].try_into().unwrap())).unwrap(),
        body.len() - 4
    );
}
