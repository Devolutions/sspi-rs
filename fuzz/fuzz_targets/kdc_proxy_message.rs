#![no_main]

use kdc::config::{DomainUser, KerberosServer};
use picky_krb::messages::KdcProxyMessage;

// The KDC must answer any bytes with a Kerberos message or a decoding error, and never panic.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let config = KerberosServer {
        realm: "EXAMPLE.COM".to_owned(),
        users: vec![DomainUser {
            username: "user@example.com".to_owned(),
            password: "password".to_owned().into(),
            salt: "EXAMPLE.COMuser".to_owned(),
        }],
        max_time_skew: 300,
        krbtgt_key: vec![0x11; 32].into(),
        ticket_decryption_key: Some(vec![0x22; 32].into()),
        service_user: None,
    };

    // Prefix the data with a correct length so that the fuzzer reaches the Kerberos message parsers.
    let mut framed = u32::try_from(data.len()).expect("fuzz input fits u32").to_be_bytes().to_vec();
    framed.extend_from_slice(data);

    if let Ok(message) = KdcProxyMessage::from_raw_kerb_message(&framed) {
        let _ = kdc::handle_kdc_proxy_message(message, &config, "gateway.example.com");
    }
});
