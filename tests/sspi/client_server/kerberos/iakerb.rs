use std::collections::HashSet;

use picky_asn1::wrapper::{ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, OctetStringAsn1, Optional};
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::oids;
use picky_krb::constants::gss_api::{ACCEPT_INCOMPLETE, AUTHENTICATOR_CHECKSUM_TYPE};
use picky_krb::constants::key_usages::{AP_REQ_AUTHENTICATOR, KEY_USAGE_FINISHED, TICKET_REP};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{Authenticator, EncTicketPart};
use picky_krb::gss_api::{
    ApplicationTag0, GssApiNegInit, IAKerbProxyMessage, KrbMessage, MechType, MechTypeList, NegTokenTarg, NegTokenTarg1,
};
use picky_krb::messages::{ApReq, IAKerbHeader};
use picky_krb::pkinit::KrbFinished;
use sspi::credssp::SspiContext;
use sspi::kerberos::ServerProperties;
use sspi::{
    ClientRequestFlags, CredentialsBuffers, KdcResolution, Kerberos, KerberosConfig, Negotiate, NegotiateConfig,
    NegotiatedProtocol, SecurityStatus, ServerRequestFlags,
};

use crate::client_server::kerberos::kdc::{
    CLIENT_COMPUTER_NAME, KdcMock, MAX_TIME_SKEW, SERVER_COMPUTER_NAME, UserName, Validators,
};
use crate::client_server::kerberos::network_client::NetworkClientMock;
use crate::client_server::kerberos::{
    KrbEnvironment, accept_security_context, init_krb_environment, initialize_security_context,
};
use crate::client_server::{test_encryption, test_rpc_request_encryption, test_stream_buffer_encryption};

#[derive(Default)]
struct IakerbCookieTracker {
    last_issued_cookie: Option<Vec<u8>>,
    next_cookie_id: u8,
}

impl IakerbCookieTracker {
    fn proxy_round_trip(&mut self, kdc: &KdcMock, client_token: &[u8]) -> Vec<u8> {
        let message = IAKerbProxyMessage::<Asn1RawDer>::decode_application_iakerb_proxy_message(client_token)
            .expect("client token should be a valid IAKerb proxy message")
            .0;

        let received_cookie = message.header.cookie.0.map(|tag| tag.0.0);
        assert_eq!(
            received_cookie, self.last_issued_cookie,
            "client must echo back the cookie received in the previous IAKerb proxy reply"
        );

        let response = kdc.exchange(&message.krb_msg.0).unwrap();

        self.next_cookie_id += 1;
        let new_cookie = vec![self.next_cookie_id; 8];
        self.last_issued_cookie = Some(new_cookie.clone());

        let response = ApplicationTag0(IAKerbProxyMessage {
            header: IAKerbHeader {
                target_realm: ExplicitContextTag1::from(String::new()),
                cookie: Optional(Some(ExplicitContextTag2::from(OctetStringAsn1::from(new_cookie)))),
                flags: Optional(None),
            },
            krb_msg: Asn1RawDer(response),
        });

        picky_asn1_der::to_vec(&response).expect("failed to encode IAKerb proxy message")
    }
}

fn iakerb_flags() -> (ClientRequestFlags, ServerRequestFlags) {
    (
        ClientRequestFlags::MUTUAL_AUTH | ClientRequestFlags::INTEGRITY | ClientRequestFlags::CONFIDENTIALITY,
        ServerRequestFlags::MUTUAL_AUTH | ServerRequestFlags::INTEGRITY | ServerRequestFlags::CONFIDENTIALITY,
    )
}

fn verify_iakerb_checksum(ap_req_token: &[u8], service_key: &[u8], expected_transcript: &[u8]) {
    let ap_req = KrbMessage::<ApReq>::decode_application_krb_message(ap_req_token)
        .expect("AP-REQ decoding should not fail")
        .0
        .krb_msg;

    let ticket_enc_data = &ap_req.0.ticket.0.0.enc_part.0;
    let ticket_cipher = CipherSuite::try_from(ticket_enc_data.etype.0.0.as_slice())
        .expect("invalid ticket etype")
        .cipher();
    let ticket_data = ticket_cipher
        .decrypt(service_key, TICKET_REP, &ticket_enc_data.cipher.0.0)
        .expect("service ticket decryption should not fail");
    let ticket: EncTicketPart =
        picky_asn1_der::from_bytes(&ticket_data).expect("EncTicketPart decoding should not fail");
    let session_key = &ticket.0.key.0.key_value.0.0;

    let authenticator_enc_data = &ap_req.0.authenticator.0;
    let authenticator_cipher = CipherSuite::try_from(authenticator_enc_data.etype.0.0.as_slice())
        .expect("invalid authenticator etype")
        .cipher();
    let authenticator_data = authenticator_cipher
        .decrypt(session_key, AP_REQ_AUTHENTICATOR, &authenticator_enc_data.cipher.0.0)
        .expect("authenticator decryption should not fail");
    let authenticator: Authenticator =
        picky_asn1_der::from_bytes(&authenticator_data).expect("Authenticator decoding should not fail");

    let subkey = authenticator
        .0
        .subkey
        .0
        .expect("AP-REQ authenticator must carry a subkey")
        .0
        .key_value
        .0
        .0;

    let checksum = authenticator
        .0
        .cksum
        .0
        .expect("AP-REQ authenticator must carry a checksum");
    assert_eq!(checksum.0.cksumtype.0.0, AUTHENTICATOR_CHECKSUM_TYPE);

    let (_base_checksum, extensions) = checksum
        .0
        .checksum
        .0
        .0
        .split_first_chunk::<24>()
        .expect("authenticator checksum must be at least 24 bytes");

    const GSS_EXTS_FINISHED: u32 = 2;
    let mut rest = extensions;
    let finished_value = loop {
        let (ext_type_bytes, tail) = rest.split_first_chunk::<4>().expect("extension type must be present");
        let (ext_len_bytes, tail) = tail.split_first_chunk::<4>().expect("extension length must be present");
        let ext_type = u32::from_le_bytes(*ext_type_bytes);
        let ext_len = usize::try_from(u32::from_le_bytes(*ext_len_bytes)).expect("extension length fits in usize");
        let (value, tail) = tail.split_at(ext_len);
        if ext_type == GSS_EXTS_FINISHED {
            break value;
        }
        rest = tail;
    };

    let finished: KrbFinished =
        picky_asn1_der::from_bytes(finished_value).expect("KrbFinished decoding should not fail");
    let checksum_suite = CipherSuite::Aes256CtsHmacSha196.cipher().checksum_type();
    let expected_checksum = checksum_suite
        .hasher()
        .checksum(&subkey, KEY_USAGE_FINISHED, expected_transcript)
        .expect("checksum computation should not fail");

    assert_eq!(
        finished.gss_mic.0.checksum.0.0, expected_checksum,
        "IAKERB checksum does not match the expected checksum computed over the transcript of all IAKERB messages exchanged between the client and server"
    );
}

#[test]
fn iakerb_auth() {
    iakerb_auth_with_kdc(|kdc| kdc);
}

fn iakerb_auth_with_kdc(configure_kdc: fn(KdcMock) -> KdcMock) {
    let KrbEnvironment {
        realm,
        credentials,
        keys,
        users,
        target_name,
        target_service_name,
    } = init_krb_environment();

    let ticket_decryption_key = keys[&UserName(target_service_name.clone())].clone();

    let kdc = configure_kdc(KdcMock::new(
        realm,
        keys,
        users,
        Validators {
            as_req: Box::new(|_as_req| {
                // Nothing to validate in AsReq.
            }),
            tgs_req: Box::new(|tgs_req| {
                // Here, we should check that the Kerberos client does not negotiate Kerberos U2U auth and not enabled any unneeded flags.

                let kdc_options = tgs_req.0.req_body.kdc_options.0.0.as_bytes();
                // enc-tkt-in-skey must be disabled.
                assert_eq!(kdc_options[4], 0x00, "some unneeded KDC options are enabled");

                let additional_tickets = tgs_req
                    .0
                    .req_body
                    .0
                    .additional_tickets
                    .0
                    .as_ref()
                    .map(|additional_tickets| additional_tickets.0.0.as_slice());
                assert!(
                    matches!(additional_tickets, None | Some(&[])),
                    "TgsReq should not contain any additional tickets"
                );
            }),
        },
    ));

    let client_config = KerberosConfig::new_with_iakerb(CLIENT_COMPUTER_NAME.into());
    let mut kerberos_client = SspiContext::Kerberos(Kerberos::new_client_from_config(client_config).unwrap());

    let server_config = KerberosConfig {
        kdc_resolution: KdcResolution::IAKerb,
        client_computer_name: SERVER_COMPUTER_NAME.into(),
    };
    let server_properties = ServerProperties {
        mech_types: MechTypeList::from(Vec::new()),
        max_time_skew: MAX_TIME_SKEW,
        ticket_decryption_key: Some(ticket_decryption_key.clone().into()),
        service_name: target_service_name,
        additional_service_keys: Vec::new(),
        user: None,
        client: None,
        authenticators_cache: HashSet::new(),
    };
    let mut kerberos_server =
        SspiContext::Kerberos(Kerberos::new_server_from_config(server_config, server_properties).unwrap());

    let credentials = CredentialsBuffers::try_from(credentials).unwrap();
    let mut client_credentials_handle = Some(credentials.clone());
    let mut server_credentials_handle = Some(credentials);

    let (client_flags, server_flags) = iakerb_flags();

    let mut unused_network_client = NetworkClientMock { kdc: KdcMock::empty() };

    let mut iakerb_cookie_tracker = IakerbCookieTracker::default();
    let mut expected_iakerb_gss_transcript = Vec::new();
    let mut input_token = Vec::new();

    // Hop 0: no-preauth AS-REQ -> KRB-ERROR(PREAUTH_REQUIRED), cookie #1 issued.
    // Hop 1: preauth AS-REQ (echoing cookie #1) -> AS-REP, cookie #2 issued.
    // Hop 2: TGS-REQ (echoing cookie #2) -> TGS-REP, cookie #3 issued.
    for hop in 0..3 {
        let (status, token) = initialize_security_context(
            &mut kerberos_client,
            &mut client_credentials_handle,
            client_flags,
            &target_name,
            input_token,
            &mut unused_network_client,
        );
        assert_eq!(
            status,
            SecurityStatus::ContinueNeeded,
            "IAKerb hop {hop} should request another proxy round trip"
        );

        expected_iakerb_gss_transcript.extend_from_slice(&token);
        input_token = iakerb_cookie_tracker.proxy_round_trip(&kdc, &token);
        expected_iakerb_gss_transcript.extend_from_slice(&input_token);
    }

    let (status, ap_req_token) = initialize_security_context(
        &mut kerberos_client,
        &mut client_credentials_handle,
        client_flags,
        &target_name,
        input_token,
        &mut unused_network_client,
    );
    assert_eq!(status, SecurityStatus::ContinueNeeded);

    verify_iakerb_checksum(&ap_req_token, &ticket_decryption_key, &expected_iakerb_gss_transcript);

    let (server_status, ap_rep_token) = accept_security_context(
        &mut kerberos_server,
        &mut server_credentials_handle,
        server_flags,
        ap_req_token,
        &mut unused_network_client,
    );
    assert_eq!(server_status, SecurityStatus::Ok);

    let (status, final_token) = initialize_security_context(
        &mut kerberos_client,
        &mut client_credentials_handle,
        client_flags,
        &target_name,
        ap_rep_token,
        &mut unused_network_client,
    );
    assert_eq!(status, SecurityStatus::Ok);

    if !final_token.is_empty() {
        accept_security_context(
            &mut kerberos_server,
            &mut server_credentials_handle,
            server_flags,
            final_token,
            &mut unused_network_client,
        );
    }

    test_encryption(&mut kerberos_client, &mut kerberos_server);
    test_stream_buffer_encryption(&mut kerberos_client, &mut kerberos_server);
    test_rpc_request_encryption(&mut kerberos_client, &mut kerberos_server);
}

#[test]
fn spnego_iakerb() {
    let KrbEnvironment {
        realm,
        credentials,
        keys,
        users,
        target_name,
        target_service_name,
    } = init_krb_environment();

    let ticket_decryption_key = keys[&UserName(target_service_name.clone())].clone();

    let kdc = KdcMock::new(
        realm,
        keys,
        users,
        Validators {
            as_req: Box::new(|_as_req| {
                // Nothing to validate in AsReq.
            }),
            tgs_req: Box::new(|_tgs_req| {
                // Nothing to validate in TgsReq.
            }),
        },
    );

    let client_config = KerberosConfig::new_with_iakerb(CLIENT_COMPUTER_NAME.into());
    let mut spnego_client = SspiContext::Negotiate(
        Negotiate::new_client(NegotiateConfig::new(
            Box::new(client_config),
            Some(String::from("kerberos,!ntlm")),
            CLIENT_COMPUTER_NAME.into(),
        ))
        .unwrap(),
    );

    let server_config = KerberosConfig {
        kdc_resolution: KdcResolution::IAKerb,
        client_computer_name: CLIENT_COMPUTER_NAME.into(),
    };
    let server_properties = ServerProperties {
        mech_types: MechTypeList::from(Vec::new()),
        max_time_skew: MAX_TIME_SKEW,
        ticket_decryption_key: Some(ticket_decryption_key.into()),
        service_name: target_service_name,
        additional_service_keys: Vec::new(),
        user: None,
        client: None,
        authenticators_cache: HashSet::new(),
    };

    // We cannot use the SPNEGO server to handle the authentication, because it does not have support for IAKERB yet.
    // Instead, we use the Kerberos server only to handle the AP-REQ.
    let mut kerberos_server =
        SspiContext::Kerberos(Kerberos::new_server_from_config(server_config, server_properties).unwrap());

    let credentials = CredentialsBuffers::try_from(credentials).unwrap();
    let mut client_credentials_handle = Some(credentials.clone());
    let mut server_credentials_handle = Some(credentials);

    let (client_flags, server_flags) = iakerb_flags();

    let mut unused_network_client = NetworkClientMock { kdc: KdcMock::empty() };

    let mut iakerb_cookie_tracker = IakerbCookieTracker::default();
    let mut input_token = Vec::new();

    // Hop 0: SPNEGO NegTokenInit, IAKERB proxy round trip (AS-REQ without preauth)

    let (status, token) = initialize_security_context(
        &mut spnego_client,
        &mut client_credentials_handle,
        client_flags,
        &target_name,
        input_token,
        &mut unused_network_client,
    );
    assert_eq!(status, SecurityStatus::ContinueNeeded);

    let neg_token_init: ApplicationTag0<GssApiNegInit> =
        picky_asn1_der::from_bytes(&token).expect("first client token must be a NegTokenInit");
    assert_eq!(
        neg_token_init.0.oid.0,
        oids::spnego(),
        "first token must be wrapped in a SPNEGO envelope"
    );

    let mech_types = neg_token_init
        .0
        .neg_token_init
        .0
        .mech_types
        .0
        .expect("mech_types must be present")
        .0;
    assert!(
        mech_types.0.iter().any(|mech: &MechType| mech.0 == oids::iakerb5()),
        "client must advertise the IAKERB OID in the SPNEGO MechTypeList"
    );
    assert!(
        !mech_types
            .0
            .iter()
            .any(|mech: &MechType| mech.0 == oids::ms_krb5() || mech.0 == oids::krb5()),
        "client must not advertise plain Kerberos OIDs together with the IAKERB OID in the SPNEGO MechTypeList"
    );

    let mech_token = neg_token_init
        .0
        .neg_token_init
        .0
        .mech_token
        .0
        .expect("mech_token must be present")
        .0
        .0;

    // Simulate the server forwarding the IAKERB proxy message to the LocalKDC,
    // and wrap the reply back into a `NegTokenTarg`, selecting IAKERB as `supported_mech`.
    let response = iakerb_cookie_tracker.proxy_round_trip(&kdc, &mech_token);
    input_token = picky_asn1_der::to_vec(&NegTokenTarg1::from(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(ACCEPT_INCOMPLETE.to_vec())))),
        supported_mech: Optional::from(Some(ExplicitContextTag1::from(MechType::from(oids::iakerb5())))),
        response_token: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(response)))),
        mech_list_mic: Optional::from(None),
    }))
    .unwrap();

    // Hops 1-2: further IAKERB proxy round trips (AS-REQ with preauth, TGS-REQ)
    for _ in 0..2 {
        let (status, token) = initialize_security_context(
            &mut spnego_client,
            &mut client_credentials_handle,
            client_flags,
            &target_name,
            input_token,
            &mut unused_network_client,
        );
        assert_eq!(status, SecurityStatus::ContinueNeeded);

        let neg_token_targ: NegTokenTarg1 =
            picky_asn1_der::from_bytes(&token).expect("client token must be a NegTokenTarg");

        let mech_token = neg_token_targ
            .0
            .response_token
            .0
            .expect("response_token must be present")
            .0
            .0;

        let response = iakerb_cookie_tracker.proxy_round_trip(&kdc, &mech_token);
        input_token = picky_asn1_der::to_vec(&NegTokenTarg1::from(NegTokenTarg {
            neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(ACCEPT_INCOMPLETE.to_vec())))),
            supported_mech: Optional::from(None),
            response_token: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(response)))),
            mech_list_mic: Optional::from(None),
        }))
        .unwrap();
    }

    // Hop 3: final SPNEGO NegTokenTarg with AP-REQ, server accepts the context
    let (status, ap_req) = initialize_security_context(
        &mut spnego_client,
        &mut client_credentials_handle,
        client_flags,
        &target_name,
        input_token,
        &mut unused_network_client,
    );
    assert_eq!(status, SecurityStatus::ContinueNeeded);

    // Confirm the client has switched protocol to IAKERB.
    let SspiContext::Negotiate(negotiate) = &spnego_client else {
        panic!("client must be a Negotiate context");
    };
    match negotiate.negotiated_protocol() {
        NegotiatedProtocol::Kerberos(kerberos) => assert!(kerberos.is_iakerb(), "client must have switched to IAKERB"),
        other => panic!("expected Kerberos protocol, got {other:?}"),
    }

    // Unwrap the AP-REQ from the NegTokenTarg and feed it to the Kerberos server.
    let neg_token_targ: NegTokenTarg1 =
        picky_asn1_der::from_bytes(&ap_req).expect("client token must be a NegTokenTarg");
    let ap_req_bytes = neg_token_targ
        .0
        .response_token
        .0
        .expect("response_token must be present")
        .0
        .0;

    let (_, ap_rep) = accept_security_context(
        &mut kerberos_server,
        &mut server_credentials_handle,
        server_flags,
        ap_req_bytes,
        &mut unused_network_client,
    );

    // Wrap the AP-REP in a NegTokenTarg and feed it to the SPNEGO client.
    let neg_token_targ_ap_rep = ExplicitContextTag1(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(ACCEPT_INCOMPLETE.to_vec())))),
        supported_mech: Optional::from(None),
        response_token: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(ap_rep)))),
        mech_list_mic: Optional::from(None),
    });
    let neg_token_targ_ap_rep = picky_asn1_der::to_vec(&neg_token_targ_ap_rep).unwrap();

    let (status, _) = initialize_security_context(
        &mut spnego_client,
        &mut client_credentials_handle,
        client_flags,
        &target_name,
        neg_token_targ_ap_rep,
        &mut unused_network_client,
    );
    assert_eq!(status, SecurityStatus::Ok);

    test_encryption(&mut spnego_client, &mut kerberos_server);
    test_stream_buffer_encryption(&mut spnego_client, &mut kerberos_server);
    test_rpc_request_encryption(&mut spnego_client, &mut kerberos_server);
}

#[test]
fn iakerb_auth_without_as_rep_etype_info2_with_tgs_rep_enc_part_in_as_rep() {
    iakerb_auth_with_kdc(|kdc| kdc.omit_as_rep_etype_info2().tgs_rep_enc_part_in_as_rep());
}
