//! The acceptor acquires its own TGT with a password for Kerberos user-to-user authentication.
//! These tests follow the AS exchange of the acceptor only, so they stop after its TGT-REP.

use std::sync::{Arc, Mutex};

use picky_krb::constants::etypes::{AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96};
use picky_krb::constants::types::PA_ENC_TIMESTAMP;
use picky_krb::data_types::EncryptedData;
use picky_krb::messages::TgtRep;

use super::*;

/// What the KDC saw in the AS-REQs of the acceptor.
#[derive(Default)]
struct SeenAsRequests {
    /// The count of the AS-REQs.
    count: usize,
    /// The encryption type of the PA-ENC-TIMESTAMP of each AS-REQ that has it.
    timestamp_etypes: Vec<Vec<u8>>,
}

/// Lets the acceptor acquire its TGT from the KDC configured by `configure_kdc`.
fn acceptor_acquires_tgt(configure_kdc: impl FnOnce(KdcMock) -> KdcMock) -> SeenAsRequests {
    let KrbEnvironment {
        realm,
        credentials,
        keys,
        users,
        target_name,
        target_service_name,
    } = init_krb_environment();

    let seen = Arc::new(Mutex::new(SeenAsRequests::default()));
    let recorder = Arc::clone(&seen);
    let mut network = NetworkClientMock {
        kdc: configure_kdc(KdcMock::new(
            realm,
            keys,
            users,
            Validators {
                as_req: Box::new(move |as_req| {
                    let mut seen = recorder.lock().unwrap();
                    seen.count += 1;
                    let timestamp = as_req
                        .0
                        .padata
                        .0
                        .iter()
                        .flat_map(|pa_datas| pa_datas.0.iter())
                        .find(|pa_data| pa_data.padata_type.0.0 == PA_ENC_TIMESTAMP);
                    if let Some(timestamp) = timestamp {
                        let enc_data: EncryptedData = picky_asn1_der::from_bytes(&timestamp.padata_data.0.0).unwrap();
                        seen.timestamp_etypes.push(enc_data.etype.0.0);
                    }
                }),
                tgs_req: Box::new(|_| {}),
            },
        )),
    };

    let credentials = CredentialsBuffers::try_from(credentials).unwrap();
    let config = KerberosConfig {
        kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
        client_computer_name: CLIENT_COMPUTER_NAME.into(),
    };
    let mut client = SspiContext::Kerberos(Kerberos::new_client_from_config(config.clone()).unwrap());
    let mut server = SspiContext::Kerberos(
        Kerberos::new_server_from_config(
            config,
            ServerProperties {
                mech_types: MechTypeList::from(Vec::new()),
                max_time_skew: MAX_TIME_SKEW,
                ticket_decryption_key: None,
                service_name: target_service_name,
                additional_service_keys: Vec::new(),
                user: Some(credentials.clone()),
                client: None,
                authenticators_cache: Default::default(),
            },
        )
        .unwrap(),
    );
    let mut client_handle = Some(credentials.clone());
    let mut server_handle = Some(credentials);
    let client_flags = ClientRequestFlags::MUTUAL_AUTH | ClientRequestFlags::USE_SESSION_KEY;
    let server_flags = ServerRequestFlags::MUTUAL_AUTH | ServerRequestFlags::USE_SESSION_KEY;

    let (status, tgt_req) = initialize_security_context(
        &mut client,
        &mut client_handle,
        client_flags,
        &target_name,
        Vec::new(),
        &mut network,
    );
    assert_eq!(status, SecurityStatus::ContinueNeeded);
    let (status, tgt_rep) =
        accept_security_context(&mut server, &mut server_handle, server_flags, tgt_req, &mut network);
    assert_eq!(status, SecurityStatus::ContinueNeeded);
    KrbMessage::<TgtRep>::decode_application_krb_message(&tgt_rep).expect("the acceptor answers with a TGT-REP");

    let seen = seen.lock().unwrap();
    SeenAsRequests {
        count: seen.count,
        timestamp_etypes: seen.timestamp_etypes.clone(),
    }
}

/// [RFC 4120, section 3.1.3](https://www.rfc-editor.org/rfc/rfc4120#section-3.1.3):
/// a KDC does not require pre-authentication for every account, and answers the first AS-REQ with the AS-REP.
#[test]
fn the_acceptor_accepts_an_as_rep_to_the_request_without_pre_authentication() {
    let seen = acceptor_acquires_tgt(KdcMock::no_preauth_required);

    assert_eq!(seen.count, 1, "no second AS-REQ is needed");
    assert!(seen.timestamp_etypes.is_empty(), "no pre-authentication is sent");
}

/// [RFC 4120, section 5.2.7.5](https://www.rfc-editor.org/rfc/rfc4120#section-5.2.7.5):
/// the ETYPE-INFO2 entry of the pre-authentication error names the key type of the account.
#[test]
fn the_acceptor_encrypts_the_timestamp_with_the_key_type_of_the_hint() {
    let seen = acceptor_acquires_tgt(KdcMock::aes128_user_key);

    assert_eq!(
        seen.timestamp_etypes,
        [vec![u8::try_from(AES128_CTS_HMAC_SHA1_96).unwrap()]]
    );
    assert_ne!(AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96);
}
