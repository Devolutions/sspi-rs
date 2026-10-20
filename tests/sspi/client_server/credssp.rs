use std::collections::HashSet;
use std::mem;
use std::sync::{Arc, Mutex};

use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, IntegerAsn1};
use picky_krb::constants::key_usages::TICKET_REP;
use picky_krb::constants::types::NT_SRV_HST;
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{EncTicketPart, KerberosStringAsn1, PrincipalName};
use picky_krb::gss_api::{ApplicationTag0, GssApiNegInit, MechTypeList, NegTokenTarg1};
use picky_krb::messages::TgsReq;
use sspi::credssp::{
    ClientMode, ClientState, CredSspClient, CredSspMode, CredSspServer, ServerMode, ServerState, TsRequest,
};
use sspi::kerberos::ServerProperties;
use sspi::network_client::NetworkClient;
use sspi::ntlm::NtlmConfig;
use sspi::rcg::NtlmRedirectionNames;
use sspi::{
    AuthIdentity, Credentials, CredentialsBuffers, ErrorKind, KdcResolution, KerberosConfig, KerberosServerConfig,
    NegotiateConfig, Secret, Username,
};
use url::Url;

use super::kerberos::kdc::{CLIENT_COMPUTER_NAME, KDC_URL, KdcMock, MAX_TIME_SKEW, UserName, Validators};
use super::kerberos::network_client::NetworkClientMock;
use super::kerberos::{KrbEnvironment, ap_req_authenticator, init_krb_environment};
use crate::client_server::TARGET_NAME;
use crate::client_server::kerberos::kdc::SERVER_COMPUTER_NAME;
use crate::common::CredentialsProxyImpl;

const PUBLIC_KEY: &[u8] = &[
    48, 130, 2, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 2, 15, 0, 48, 130, 2, 10, 2, 130,
    2, 1, 0, 153, 85, 210, 206, 231, 176, 16, 84, 146, 20, 255, 201, 74, 62, 122, 183, 157, 210, 202, 111, 17, 50, 30,
    181, 14, 13, 193, 242, 152, 41, 178, 93, 237, 151, 133, 122, 29, 233, 73, 139, 182, 23, 93, 149, 119, 56, 5, 156,
    180, 217, 84, 109, 88, 242, 117, 103, 167, 173, 81, 14, 171, 69, 18, 6, 149, 163, 35, 39, 128, 183, 73, 157, 200,
    229, 17, 156, 115, 197, 187, 141, 211, 156, 148, 207, 94, 14, 119, 210, 166, 59, 242, 214, 224, 159, 51, 41, 55,
    78, 250, 170, 175, 133, 213, 24, 173, 39, 234, 10, 216, 60, 238, 204, 157, 149, 186, 144, 203, 231, 241, 239, 41,
    118, 35, 14, 245, 183, 29, 229, 209, 198, 182, 174, 34, 66, 146, 20, 214, 109, 119, 19, 8, 207, 231, 222, 119, 155,
    192, 76, 15, 221, 210, 78, 132, 112, 33, 213, 87, 153, 25, 38, 190, 161, 178, 130, 108, 140, 75, 75, 22, 74, 28, 0,
    164, 72, 103, 14, 57, 202, 58, 91, 94, 235, 177, 68, 209, 252, 254, 173, 97, 101, 156, 128, 139, 58, 140, 226, 73,
    26, 232, 234, 178, 220, 193, 89, 196, 236, 89, 173, 235, 92, 39, 13, 1, 0, 93, 43, 252, 89, 236, 123, 140, 108,
    144, 215, 171, 46, 211, 144, 236, 202, 59, 87, 177, 225, 162, 70, 144, 109, 113, 237, 2, 152, 115, 52, 166, 112,
    249, 30, 53, 62, 239, 228, 226, 97, 56, 246, 27, 64, 43, 153, 195, 79, 176, 38, 178, 188, 192, 207, 0, 179, 255,
    17, 173, 250, 152, 140, 8, 198, 9, 2, 50, 151, 16, 176, 125, 175, 161, 118, 185, 166, 34, 217, 189, 160, 27, 145,
    91, 113, 71, 71, 220, 4, 195, 210, 242, 185, 14, 108, 61, 61, 5, 45, 27, 38, 56, 245, 49, 55, 196, 230, 22, 8, 155,
    27, 3, 79, 252, 108, 199, 189, 29, 98, 220, 118, 212, 5, 0, 129, 59, 110, 131, 188, 159, 249, 56, 37, 69, 106, 185,
    215, 38, 54, 36, 196, 28, 39, 81, 27, 255, 249, 155, 197, 237, 125, 92, 147, 108, 248, 238, 115, 101, 170, 27, 203,
    193, 180, 33, 146, 208, 216, 113, 174, 158, 84, 100, 32, 200, 49, 30, 28, 31, 112, 247, 68, 190, 181, 247, 54, 117,
    131, 215, 100, 13, 170, 52, 12, 137, 61, 253, 114, 120, 116, 124, 238, 3, 234, 95, 242, 208, 224, 96, 132, 150,
    152, 186, 81, 85, 50, 179, 216, 191, 125, 25, 148, 232, 235, 234, 193, 150, 186, 41, 18, 38, 220, 144, 104, 97,
    127, 215, 215, 49, 92, 81, 21, 232, 67, 145, 164, 179, 156, 220, 175, 154, 70, 144, 218, 31, 106, 84, 78, 218, 238,
    15, 29, 207, 34, 33, 68, 121, 213, 114, 203, 80, 32, 42, 224, 115, 86, 161, 42, 78, 246, 183, 203, 213, 198, 110,
    71, 22, 137, 164, 4, 163, 206, 239, 57, 197, 112, 179, 191, 160, 5, 2, 3, 1, 0, 1,
];

fn run_credssp(
    client: &mut CredSspClient,
    server: &mut CredSspServer<CredentialsProxyImpl<'_>>,
    auth_identity: &AuthIdentity,
    network_client: &mut dyn NetworkClient,
) {
    let mut ts_request = TsRequest::default();

    for _ in 0..5 {
        ts_request = match client
            .process(mem::take(&mut ts_request))
            .resolve_with_client(network_client)
            .unwrap()
        {
            ClientState::ReplyNeeded(ts_request) => ts_request,
            ClientState::FinalMessage(ts_request) => ts_request,
        };

        match server.process(ts_request).resolve_with_client(network_client).unwrap() {
            ServerState::ReplyNeeded(server_ts_request) => ts_request = server_ts_request,
            ServerState::Finished(received_auth_identity) => {
                assert_eq!(*auth_identity, received_auth_identity);
                return;
            }
        };
    }

    panic!("CredSSP authentication should not exceed 5 steps")
}

#[test]
fn credssp_ntlm() {
    let auth_identity = AuthIdentity {
        username: Username::parse("test_user").unwrap(),
        password: Secret::from("test_password".to_owned()),
    };
    let credentials = Credentials::AuthIdentity(auth_identity.clone());

    let mut client = CredSspClient::new(
        PUBLIC_KEY.to_vec(),
        credentials.clone(),
        CredSspMode::WithCredentials,
        ClientMode::Ntlm(NtlmConfig {
            client_computer_name: Some("DESKTOP-3D83IAN.example.com".to_owned()),
        }),
        TARGET_NAME.to_owned(),
    )
    .unwrap();

    let mut server = CredSspServer::new(
        PUBLIC_KEY.to_vec(),
        CredentialsProxyImpl::new(&auth_identity),
        ServerMode::Ntlm(NtlmConfig {
            client_computer_name: Some("DESKTOP-3D83IAN.example.com".to_owned()),
        }),
    )
    .unwrap();

    let mut network_client = NetworkClientMock { kdc: KdcMock::empty() };

    run_credssp(&mut client, &mut server, &auth_identity, &mut network_client);
}

#[test]
fn credssp_kerberos() {
    // CredSSP with Kerberos inside requires SPNEGO. We cannot use Kerberos inside CredSSP without SPNEGO.

    let KrbEnvironment {
        realm,
        credentials,
        keys,
        users,
        target_name,
        target_service_name,
    } = init_krb_environment();

    let identity_1 = credentials.to_auth_identity().unwrap();
    let mut identity_2 = identity_1.clone();
    identity_2.username = Username::new_upn(identity_1.username.account_name(), &realm.to_ascii_lowercase()).unwrap();

    let kdc = KdcMock::new(realm, keys, users, Validators::default());
    let mut network_client = NetworkClientMock { kdc };

    let client_config = KerberosConfig {
        kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
        client_computer_name: CLIENT_COMPUTER_NAME.into(),
    };

    let server_config = KerberosConfig {
        kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
        client_computer_name: SERVER_COMPUTER_NAME.into(),
    };
    let server_properties = ServerProperties {
        mech_types: MechTypeList::from(Vec::new()),
        max_time_skew: MAX_TIME_SKEW,
        ticket_decryption_key: None,
        service_name: target_service_name,
        additional_service_keys: Vec::new(),
        user: Some(CredentialsBuffers::try_from(credentials.clone()).unwrap()),
        client: None,
        authenticators_cache: HashSet::new(),
    };
    let kerberos_server_config = KerberosServerConfig {
        kerberos_config: server_config,
        server_properties,
    };

    let mut client = CredSspClient::new(
        PUBLIC_KEY.to_vec(),
        credentials,
        CredSspMode::WithCredentials,
        ClientMode::Negotiate(NegotiateConfig::new(
            Box::new(client_config.clone()),
            Some(String::from("kerberos,!ntlm")),
            CLIENT_COMPUTER_NAME.into(),
        )),
        target_name,
    )
    .unwrap();

    let mut server = CredSspServer::new(
        PUBLIC_KEY.to_vec(),
        CredentialsProxyImpl::new(&identity_2),
        ServerMode::Negotiate(NegotiateConfig::new(
            Box::new(kerberos_server_config),
            Some(String::from("kerberos,!ntlm")),
            SERVER_COMPUTER_NAME.into(),
        )),
    )
    .unwrap();

    run_credssp(&mut client, &mut server, &identity_1, &mut network_client);
}

const MS_KRB5_OID: &str = "1.2.840.48018.1.2.2";
const KRB5_OID: &str = "1.2.840.113554.1.2.2";

/// TGS-REQ seen by the KDC: service name components, `forwarded` KDC option, and U2U additional ticket.
type RecordedTgsReq = (Vec<String>, bool, bool);

fn host_principal(host: &str) -> UserName {
    UserName(PrincipalName {
        name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_HST])),
        name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
            KerberosStringAsn1::from(IA5String::from_string("HOST".to_owned()).unwrap()),
            KerberosStringAsn1::from(IA5String::from_string(host.to_owned()).unwrap()),
        ])),
    })
}

fn record_tgs_requests(requests: Arc<Mutex<Vec<RecordedTgsReq>>>) -> Validators {
    Validators {
        as_req: Box::new(|_| {}),
        tgs_req: Box::new(move |tgs_req: &TgsReq| {
            let body = &tgs_req.0.req_body.0;
            let sname = body
                .sname
                .0
                .as_ref()
                .unwrap()
                .0
                .name_string
                .0
                .0
                .iter()
                .map(|component| component.0.to_string())
                .collect();
            // RFC 4120 5.4.1: KDCOptions bit 2 is `forwarded`.
            let forwarded = body.kdc_options.0.0.is_set(2);
            let user_to_user = body.additional_tickets.0.is_some();

            requests.lock().unwrap().push((sname, forwarded, user_to_user));
        }),
    }
}

fn remote_guard_server(credentials: &Credentials, target_service_name: PrincipalName) -> KerberosServerConfig {
    KerberosServerConfig {
        kerberos_config: KerberosConfig {
            kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
            client_computer_name: SERVER_COMPUTER_NAME.into(),
        },
        server_properties: ServerProperties {
            mech_types: MechTypeList::from(Vec::new()),
            max_time_skew: MAX_TIME_SKEW,
            ticket_decryption_key: None,
            service_name: target_service_name,
            additional_service_keys: Vec::new(),
            user: Some(CredentialsBuffers::try_from(credentials.clone()).unwrap()),
            client: None,
            authenticators_cache: HashSet::new(),
        },
    }
}

fn remote_guard_client(credentials: Credentials, target_name: String) -> CredSspClient {
    CredSspClient::new(
        PUBLIC_KEY.to_vec(),
        credentials,
        CredSspMode::RemoteGuard,
        ClientMode::Negotiate(NegotiateConfig::new(
            Box::new(KerberosConfig {
                kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
                client_computer_name: CLIENT_COMPUTER_NAME.into(),
            }),
            // NTLM is enabled on purpose: remote credential guard must disable it.
            Some(String::from("kerberos,ntlm")),
            CLIENT_COMPUTER_NAME.into(),
        )),
        target_name,
    )
    .unwrap()
}

fn offered_mech_types(nego_token: &[u8]) -> Vec<String> {
    let token: ApplicationTag0<GssApiNegInit> = picky_asn1_der::from_bytes(nego_token).unwrap();

    token
        .0
        .neg_token_init
        .0
        .mech_types
        .0
        .unwrap()
        .0
        .0
        .iter()
        .map(|mech_type| -> String { (&mech_type.0).into() })
        .collect()
}

/// Runs a Remote Credential Guard exchange until the server rejects the delegated credentials, and returns the
/// client.
fn run_credssp_remote_guard_kerberos(ntlm: Option<Option<NtlmRedirectionNames>>) -> CredSspClient {
    let KrbEnvironment {
        realm,
        credentials,
        mut keys,
        users,
        target_name,
        target_service_name,
    } = init_krb_environment();

    let target_host = target_name.split_once('/').unwrap().1.to_owned();
    keys.insert(host_principal(&target_host), vec![0x5a; 32]);

    let identity = credentials.to_auth_identity().unwrap();
    let mut server_identity = identity.clone();
    server_identity.username =
        Username::new_upn(identity.username.account_name(), &realm.to_ascii_lowercase()).unwrap();

    let tgs_requests = Arc::new(Mutex::new(Vec::new()));
    let kdc = KdcMock::new(
        realm.clone(),
        keys,
        users,
        record_tgs_requests(Arc::clone(&tgs_requests)),
    );
    let network_client = NetworkClientMock { kdc };

    let mut client = remote_guard_client(credentials.clone(), target_name);
    if let Some(names) = ntlm {
        client.enable_remote_guard_ntlm(names).unwrap();
    }
    let mut server = CredSspServer::new(
        PUBLIC_KEY.to_vec(),
        CredentialsProxyImpl::new(&server_identity),
        ServerMode::Negotiate(NegotiateConfig::new(
            Box::new(remote_guard_server(&credentials, target_service_name)),
            Some(String::from("kerberos,!ntlm")),
            SERVER_COMPUTER_NAME.into(),
        )),
    )
    .unwrap();

    // The session is not available before the exchange is finished.
    assert_eq!(
        client.take_remote_guard_session().unwrap_err().error_type,
        ErrorKind::OutOfSequence
    );

    let mut ts_request = TsRequest::default();
    let mut sent_credentials = false;
    for step in 0..4 {
        ts_request = match client
            .process(mem::take(&mut ts_request))
            .resolve_with_client(&network_client)
            .unwrap()
        {
            ClientState::ReplyNeeded(ts_request) => ts_request,
            ClientState::FinalMessage(ts_request) => {
                sent_credentials = true;
                ts_request
            }
        };

        if step == 0 {
            assert_eq!(
                offered_mech_types(ts_request.nego_tokens.as_deref().unwrap()),
                [MS_KRB5_OID, KRB5_OID]
            );
        }

        match server.process(ts_request).resolve_with_client(&network_client) {
            Ok(ServerState::ReplyNeeded(server_ts_request)) => ts_request = server_ts_request,
            Ok(ServerState::Finished(_)) => panic!("the server cannot accept remote credential guard credentials"),
            Err(error) => {
                // The server decrypted `authInfo` with the CredSSP Kerberos context but does not implement
                // credential type 6 (TSRemoteGuardCreds).
                assert!(sent_credentials);
                assert_eq!(error.error.error_type, ErrorKind::InvalidToken);
                assert!(
                    error.error.description.contains("cred_type value: 6"),
                    "{}",
                    error.error.description
                );
                break;
            }
        }
    }
    assert!(sent_credentials);

    let tgs_requests = tgs_requests.lock().unwrap();
    let host = target_host;
    // CredSSP requests USE_SESSION_KEY, so the client authenticates with user-to-user Kerberos.
    assert!(tgs_requests.contains(&(vec!["TERMSRV".to_owned(), host.clone()], false, true)));
    // Ticket for the computer account of the target.
    assert!(tgs_requests.contains(&(vec!["HOST".to_owned(), host], false, false)));
    // Forwarded TGT of the client realm.
    assert!(tgs_requests.contains(&(vec!["krbtgt".to_owned(), realm], true, false)));
    drop(tgs_requests);

    // NTLM redirection cannot be enabled once the exchange started.
    assert_eq!(
        client.enable_remote_guard_ntlm(None).unwrap_err().error_type,
        ErrorKind::OutOfSequence
    );

    client
}

#[test]
fn credssp_kerberos_replay_and_sequence_flags_are_remote_guard_only() {
    for mode in [
        CredSspMode::WithCredentials,
        CredSspMode::CredentialLess,
        CredSspMode::RemoteGuard,
    ] {
        let KrbEnvironment {
            realm,
            credentials,
            keys,
            users,
            target_name,
            target_service_name,
        } = init_krb_environment();

        let tgt_key = keys
            .iter()
            .find(|(name, _)| {
                name.0
                    .name_string
                    .0
                    .0
                    .iter()
                    .map(|part| part.0.to_string())
                    .eq(["krbtgt".to_owned(), realm.clone()])
            })
            .unwrap()
            .1
            .clone();
        let u2u_ticket_key = Arc::new(Mutex::new(None));
        let captured_key = Arc::clone(&u2u_ticket_key);
        let validators = Validators {
            tgs_req: Box::new(move |request| {
                let tickets = &request.0.req_body.0.additional_tickets.0.as_ref().unwrap().0.0;
                assert_eq!(tickets.len(), 1);
                let encrypted = &tickets[0].0.enc_part.0;
                let plaintext = CipherSuite::try_from(encrypted.etype.0.0.as_slice())
                    .unwrap()
                    .cipher()
                    .decrypt(&tgt_key, TICKET_REP, &encrypted.cipher.0.0)
                    .unwrap();
                let ticket: EncTicketPart = picky_asn1_der::from_bytes(&plaintext).unwrap();
                *captured_key.lock().unwrap() = Some(ticket.0.key.0.key_value.0.0);
            }),
            ..Validators::default()
        };
        let network = NetworkClientMock {
            kdc: KdcMock::new(realm.clone(), keys, users, validators),
        };
        let mut server_identity = credentials.to_auth_identity().unwrap();
        server_identity.username =
            Username::new_upn(server_identity.username.account_name(), &realm.to_ascii_lowercase()).unwrap();
        let mut client = CredSspClient::new(
            PUBLIC_KEY.to_vec(),
            credentials.clone(),
            mode,
            ClientMode::Negotiate(NegotiateConfig::new(
                Box::new(KerberosConfig {
                    kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
                    client_computer_name: CLIENT_COMPUTER_NAME.into(),
                }),
                Some("kerberos,!ntlm".to_owned()),
                CLIENT_COMPUTER_NAME.into(),
            )),
            target_name,
        )
        .unwrap();
        let mut server = CredSspServer::new(
            PUBLIC_KEY.to_vec(),
            CredentialsProxyImpl::new(&server_identity),
            ServerMode::Negotiate(NegotiateConfig::new(
                Box::new(remote_guard_server(&credentials, target_service_name)),
                Some("kerberos,!ntlm".to_owned()),
                SERVER_COMPUTER_NAME.into(),
            )),
        )
        .unwrap();

        let ClientState::ReplyNeeded(tgt_request) = client
            .process(TsRequest::default())
            .resolve_with_client(&network)
            .unwrap()
        else {
            panic!("expected a TGT request")
        };
        let ServerState::ReplyNeeded(tgt_reply) = server.process(tgt_request).resolve_with_client(&network).unwrap()
        else {
            panic!("expected a TGT reply")
        };
        let ClientState::ReplyNeeded(ap_request) = client.process(tgt_reply).resolve_with_client(&network).unwrap()
        else {
            panic!("expected an AP-REQ")
        };
        let token: NegTokenTarg1 = picky_asn1_der::from_bytes(ap_request.nego_tokens.as_deref().unwrap()).unwrap();
        let kerberos_token = token.0.response_token.0.unwrap().0.0;
        let key = u2u_ticket_key.lock().unwrap();
        let authenticator = ap_req_authenticator(&kerberos_token, key.as_ref().unwrap());
        let checksum = authenticator.0.cksum.0.unwrap().0;
        assert_eq!(checksum.cksumtype.0.0, [0x00, 0x80, 0x03]);
        let bytes = checksum.checksum.0.0;
        assert_eq!(bytes.len(), 24);
        // RFC 4121 4.1.1.1: mutual, confidentiality, integrity, plus replay/sequence only for RCG.
        let expected: u32 = if mode == CredSspMode::RemoteGuard { 0x3e } else { 0x32 };
        assert_eq!(&bytes[20..24], &expected.to_le_bytes(), "{mode:?}");
    }
}

#[test]
fn credssp_remote_guard_kerberos() {
    let mut client = run_credssp_remote_guard_kerberos(None);

    let session: sspi::rcg::RemoteGuardSession = client.take_remote_guard_session().unwrap();
    let _: &sspi::remote_guard::RemoteGuardSession = &session;
    let _: &sspi::kerberos::remote_guard::RemoteGuardSession = &session;
    assert!(!session.ntlm_available());
    // The context is moved out exactly once.
    assert_eq!(
        client.take_remote_guard_session().unwrap_err().error_type,
        ErrorKind::ContextExpired
    );
    let (mut client, mut peer, _) = run_inspected_high_level(CredSspMode::RemoteGuard, None);
    let mut session = client.take_remote_guard_session().unwrap();
    check_remote_guard_auth_info(&peer, &mut session, false);
    check_live_handoff(&mut peer, &mut session);
}

#[test]
fn credssp_remote_guard_kerberos_with_ntlm_redirection() {
    for names in [
        None,
        Some(NtlmRedirectionNames {
            user: "user".to_owned(),
            domain: "EXAMPLE".to_owned(),
        }),
    ] {
        let mut client = run_credssp_remote_guard_kerberos(Some(names.clone()));

        // The initial authentication is still Kerberos-only, and the session holds the NTLM credential.
        let session = client.take_remote_guard_session().unwrap();
        assert!(session.ntlm_available());
        let (mut client, mut peer, _) = run_inspected_high_level(CredSspMode::RemoteGuard, Some(names.clone()));
        let mut session = client.take_remote_guard_session().unwrap();
        check_remote_guard_auth_info(&peer, &mut session, true);
        check_ntlm_redirection_names(&peer, &mut session, names.as_ref());
        check_live_handoff(&mut peer, &mut session);
    }
}

#[test]
fn credssp_remote_guard_never_offers_ntlm() {
    for ntlm in [
        None,
        Some(None),
        Some(Some(NtlmRedirectionNames {
            user: "redirected".to_owned(),
            domain: "SYNTHETIC".to_owned(),
        })),
    ] {
        let KrbEnvironment {
            realm,
            credentials,
            keys,
            users,
            target_name,
            ..
        } = init_krb_environment();

        let kdc = KdcMock::new(realm, keys, users, Validators::default());
        let network_client = NetworkClientMock { kdc };

        let auth_identity = credentials.to_auth_identity().unwrap();
        let mut client = remote_guard_client(credentials, target_name);
        if let Some(names) = ntlm {
            client.enable_remote_guard_ntlm(names).unwrap();
        }
        let mut server = CredSspServer::new(
            PUBLIC_KEY.to_vec(),
            CredentialsProxyImpl::new(&auth_identity),
            ServerMode::Negotiate(NegotiateConfig::new(
                Box::new(NtlmConfig {
                    client_computer_name: Some(SERVER_COMPUTER_NAME.to_owned()),
                }),
                Some("ntlm,!kerberos,!pku2u".to_owned()),
                SERVER_COMPUTER_NAME.to_owned(),
            )),
        )
        .unwrap();

        let ts_request = match client
            .process(TsRequest::default())
            .resolve_with_client(&network_client)
            .unwrap()
        {
            ClientState::ReplyNeeded(ts_request) => ts_request,
            ClientState::FinalMessage(_) => panic!("credentials must not be sent in the first message"),
        };
        assert!(ts_request.auth_info.is_none());
        assert_eq!(
            offered_mech_types(ts_request.nego_tokens.as_deref().unwrap()),
            [MS_KRB5_OID, KRB5_OID]
        );

        // An NTLM-only server has nothing to select.
        let error = server
            .process(ts_request)
            .resolve_with_client(&network_client)
            .unwrap_err();
        assert_eq!(error.error.error_type, ErrorKind::InvalidToken);
        assert_eq!(
            client.take_remote_guard_session().unwrap_err().error_type,
            ErrorKind::OutOfSequence
        );
    }
}

#[test]
fn credssp_remote_guard_requires_negotiate() {
    let KrbEnvironment {
        credentials,
        target_name,
        ..
    } = init_krb_environment();

    let error = CredSspClient::new(
        PUBLIC_KEY.to_vec(),
        credentials.clone(),
        CredSspMode::RemoteGuard,
        ClientMode::Ntlm(NtlmConfig::new(CLIENT_COMPUTER_NAME.into())),
        target_name.clone(),
    )
    .unwrap_err();
    assert_eq!(error.error_type, ErrorKind::UnsupportedFunction);

    let mut no_kerberos = CredSspClient::new(
        PUBLIC_KEY.to_vec(),
        credentials.clone(),
        CredSspMode::RemoteGuard,
        ClientMode::Negotiate(NegotiateConfig::new(
            Box::new(NtlmConfig::new(CLIENT_COMPUTER_NAME.into())),
            Some("ntlm,!kerberos".to_owned()),
            CLIENT_COMPUTER_NAME.into(),
        )),
        target_name.clone(),
    )
    .unwrap();
    let error = no_kerberos
        .process(TsRequest::default())
        .resolve_to_result()
        .unwrap_err();
    assert_eq!(error.error_type, ErrorKind::InvalidParameter);

    let mut client = CredSspClient::new(
        PUBLIC_KEY.to_vec(),
        credentials,
        CredSspMode::WithCredentials,
        ClientMode::Negotiate(NegotiateConfig::new(
            Box::new(KerberosConfig {
                kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
                client_computer_name: CLIENT_COMPUTER_NAME.into(),
            }),
            Some(String::from("kerberos,!ntlm")),
            CLIENT_COMPUTER_NAME.into(),
        )),
        target_name,
    )
    .unwrap();
    assert_eq!(
        client.take_remote_guard_session().unwrap_err().error_type,
        ErrorKind::UnsupportedFunction
    );
    assert_eq!(
        client.enable_remote_guard_ntlm(None).unwrap_err().error_type,
        ErrorKind::UnsupportedFunction
    );
}

#[test]
fn credssp_remote_guard_ntlm_requires_a_user_name() {
    let KrbEnvironment {
        credentials,
        target_name,
        ..
    } = init_krb_environment();

    let mut client = remote_guard_client(credentials, target_name);
    let error = client
        .enable_remote_guard_ntlm(Some(NtlmRedirectionNames {
            user: String::new(),
            domain: "EXAMPLE".to_owned(),
        }))
        .unwrap_err();
    assert_eq!(error.error_type, ErrorKind::InvalidParameter);
}

#[test]
fn credssp_negotiate_ntlm() {
    let auth_identity = AuthIdentity {
        username: Username::parse("test_user").unwrap(),
        password: Secret::from("test_password".to_owned()),
    };
    let credentials = Credentials::AuthIdentity(auth_identity.clone());

    let mut client = CredSspClient::new(
        PUBLIC_KEY.to_vec(),
        credentials.clone(),
        CredSspMode::WithCredentials,
        ClientMode::Negotiate(NegotiateConfig::new(
            Box::new(NtlmConfig {
                client_computer_name: Some("DESKTOP-3D83IAN.example.com".to_owned()),
            }),
            Some("ntlm,!kerberos,!pku2u".to_owned()),
            "DESKTOP-3D83IAN.example.com".to_owned(),
        )),
        TARGET_NAME.to_owned(),
    )
    .unwrap();

    let mut server = CredSspServer::new(
        PUBLIC_KEY.to_vec(),
        CredentialsProxyImpl::new(&auth_identity),
        ServerMode::Negotiate(NegotiateConfig::new(
            Box::new(NtlmConfig {
                client_computer_name: Some("DESKTOP-3D83IAN.example.com".to_owned()),
            }),
            Some("ntlm,!kerberos,!pku2u".to_owned()),
            "SERVER.example.com".to_owned(),
        )),
    )
    .unwrap();

    let mut network_client = NetworkClientMock { kdc: KdcMock::empty() };

    run_credssp(&mut client, &mut server, &auth_identity, &mut network_client);
}

/// A synthetic peer that retains the actual negotiated context after decoding authInfo.
/// Unlike CredSspServer, it can inspect type 6 without importing a Windows logon credential.
struct InspectingPeer {
    context: sspi::credssp::SspiContext,
    credentials: Credentials,
    handle: Option<CredentialsBuffers>,
    public_key: Vec<u8>,
    auth_info: Option<Vec<u8>>,
    offered: Vec<String>,
    binding_verified: bool,
    last_received_sequence: Option<u64>,
    last_sent_sequence: Option<u64>,
    ticket_key: Arc<Mutex<Vec<u8>>>,
    tgt_key: Vec<u8>,
    gss_flags: Option<u32>,
    request_body: Arc<Mutex<Vec<u8>>>,
}

impl InspectingPeer {
    fn new(credentials: Credentials, server: NegotiateConfig, public_key: Vec<u8>) -> Self {
        let identity = credentials.to_auth_identity().unwrap();
        let mut upn_identity = identity.clone();
        upn_identity.username = Username::new_upn(identity.username.account_name(), "example.com").unwrap();
        Self {
            context: sspi::credssp::SspiContext::Negotiate(
                sspi::Negotiate::new_server(server, vec![identity, upn_identity]).unwrap(),
            ),
            handle: None,
            credentials,
            public_key,
            auth_info: None,
            offered: Vec::new(),
            binding_verified: false,
            last_received_sequence: None,
            last_sent_sequence: None,
            ticket_key: Arc::new(Mutex::new(Vec::new())),
            tgt_key: Vec::new(),
            gss_flags: None,
            request_body: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn decrypt(&mut self, token: &[u8]) -> Vec<u8> {
        use sspi::{BufferType, SecurityBufferRef, Sspi as _};
        if token.starts_with(&[0x05, 0x04]) {
            self.last_received_sequence = Some(u64::from_be_bytes(token[8..16].try_into().unwrap()));
        }
        let mut token = token.to_vec();
        let (signature, data) = token.split_at_mut(16);
        let mut buffers = [
            SecurityBufferRef::token_buf(signature),
            SecurityBufferRef::data_buf(data),
        ];
        self.context.decrypt_message(&mut buffers).unwrap();
        SecurityBufferRef::find_buffer(&buffers, BufferType::Data)
            .unwrap()
            .data()
            .to_vec()
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        use sspi::{BufferType, EncryptionFlags, SecurityBufferRef, Sspi as _};
        let mut signature = [0; 1024];
        let mut data = plaintext.to_vec();
        let mut buffers = [
            SecurityBufferRef::token_buf(&mut signature),
            SecurityBufferRef::data_buf(&mut data),
        ];
        self.context
            .encrypt_message(EncryptionFlags::empty(), &mut buffers)
            .unwrap();
        let mut token = SecurityBufferRef::find_buffer(&buffers, BufferType::Token)
            .unwrap()
            .data()
            .to_vec();
        token.extend_from_slice(
            SecurityBufferRef::find_buffer(&buffers, BufferType::Data)
                .unwrap()
                .data(),
        );
        if token.starts_with(&[0x05, 0x04]) {
            self.last_sent_sequence = Some(u64::from_be_bytes(token[8..16].try_into().unwrap()));
        }
        token
    }

    fn process(&mut self, mut request: TsRequest, network: &NetworkClientMock) -> sspi::Result<Option<TsRequest>> {
        use sha2::{Digest as _, Sha256};
        use sspi::{
            BufferType, DataRepresentation, SecurityBuffer, SecurityStatus, ServerRequestFlags, Sspi as _, SspiEx as _,
            SspiImpl as _,
        };
        assert_eq!(request.version, 6);
        if let Some(auth_info) = request.auth_info.take() {
            assert!(self.binding_verified);
            assert!(self.auth_info.is_none());
            self.auth_info = Some(self.decrypt(&auth_info));
            return Ok(None);
        }
        if let Some(nego) = request.nego_tokens.take() {
            if self.offered.is_empty() {
                self.offered = offered_mech_types(&nego);
            }
            let kerberos_token = if let Ok(token) = picky_asn1_der::from_bytes::<NegTokenTarg1>(&nego) {
                token.0.response_token.0.map(|token| token.0.0)
            } else {
                picky_asn1_der::from_bytes::<ApplicationTag0<GssApiNegInit>>(&nego)
                    .unwrap()
                    .0
                    .neg_token_init
                    .0
                    .mech_token
                    .0
                    .map(|token| token.0.0)
            };
            if let Some(token) = kerberos_token
                && picky_krb::gss_api::KrbMessage::<picky_krb::messages::ApReq>::decode_application_krb_message(&token)
                    .is_ok()
            {
                let authenticator = ap_req_authenticator(&token, &self.ticket_key.lock().unwrap());
                let checksum = authenticator.0.cksum.0.unwrap().0.checksum.0.0;
                assert_eq!(checksum.len(), 24);
                self.gss_flags = Some(u32::from_le_bytes(checksum[20..24].try_into().unwrap()));
            }
            let mut input = [SecurityBuffer::new(nego, BufferType::Token)];
            let mut output = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
            let builder = self
                .context
                .accept_security_context()
                .with_credentials_handle(&mut self.handle)
                .with_context_requirements(ServerRequestFlags::empty())
                .with_target_data_representation(DataRepresentation::Native)
                .with_input(&mut input)
                .with_output(&mut output);
            let status = self
                .context
                .accept_security_context_impl(builder)?
                .resolve_with_client(network)?
                .status;
            if matches!(status, SecurityStatus::Ok | SecurityStatus::CompleteNeeded) {
                self.context.custom_set_auth_identity(self.credentials.clone())?;
                self.context.complete_auth_token(&mut [])?;
            }
            request.nego_tokens = (!output[0].buffer.is_empty()).then(|| mem::take(&mut output[0].buffer));
        }
        if let Some(binding) = request.pub_key_auth.take() {
            request.nego_tokens = None;
            let nonce = request.client_nonce.unwrap();
            let mut hash = Sha256::new();
            hash.update(b"CredSSP Client-To-Server Binding Hash\0");
            hash.update(nonce);
            hash.update(&self.public_key);
            assert_eq!(self.decrypt(&binding), hash.finalize().as_slice());
            self.binding_verified = true;
            let mut hash = Sha256::new();
            hash.update(b"CredSSP Server-To-Client Binding Hash\0");
            hash.update(nonce);
            hash.update(&self.public_key);
            request.pub_key_auth = Some(self.encrypt(&hash.finalize()));
        }
        Ok(Some(request))
    }
}

fn inspecting_environment() -> (
    Credentials,
    String,
    NetworkClientMock,
    InspectingPeer,
    Arc<Mutex<Vec<RecordedTgsReq>>>,
) {
    let KrbEnvironment {
        realm,
        credentials,
        mut keys,
        users,
        target_name,
        target_service_name,
    } = init_krb_environment();
    let host = target_name.split_once('/').unwrap().1;
    keys.insert(host_principal(host), vec![0x5a; 32]);
    let service_key = keys[&UserName(target_service_name.clone())].clone();
    let tgt_key = keys
        .iter()
        .find(|(name, _)| {
            name.0
                .name_string
                .0
                .0
                .iter()
                .map(|part| part.0.to_string())
                .eq(["krbtgt".to_owned(), realm.clone()])
        })
        .unwrap()
        .1
        .clone();
    let ticket_key = Arc::new(Mutex::new(service_key.clone()));
    let captured_key = Arc::clone(&ticket_key);
    let request_body = Arc::new(Mutex::new(Vec::new()));
    let captured_body = Arc::clone(&request_body);
    let decrypt_tgt = tgt_key.clone();
    let mut server = remote_guard_server(&credentials, target_service_name);
    server.server_properties.ticket_decryption_key = Some(service_key.into());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let record = record_tgs_requests(Arc::clone(&requests));
    let validators = Validators {
        tgs_req: Box::new(move |request| {
            (record.tgs_req)(request);
            *captured_body.lock().unwrap() = picky_asn1_der::to_vec(&request.0.req_body.0).unwrap();
            if let Some(tickets) = &request.0.req_body.0.additional_tickets.0 {
                let encrypted = &tickets.0.0[0].0.enc_part.0;
                let decrypted = CipherSuite::try_from(encrypted.etype.0.0.as_slice())
                    .unwrap()
                    .cipher()
                    .decrypt(&decrypt_tgt, TICKET_REP, &encrypted.cipher.0.0)
                    .unwrap();
                let ticket: EncTicketPart = picky_asn1_der::from_bytes(&decrypted).unwrap();
                *captured_key.lock().unwrap() = ticket.0.key.0.key_value.0.0;
            }
        }),
        ..Validators::default()
    };
    let network = NetworkClientMock {
        kdc: KdcMock::new(realm, keys, users, validators),
    };
    let mut peer = InspectingPeer::new(
        credentials.clone(),
        NegotiateConfig::new(
            Box::new(server),
            Some("kerberos,!ntlm".to_owned()),
            SERVER_COMPUTER_NAME.into(),
        ),
        PUBLIC_KEY.to_vec(),
    );
    peer.ticket_key = ticket_key;
    peer.tgt_key = tgt_key;
    peer.request_body = request_body;
    (credentials, target_name, network, peer, requests)
}

fn run_inspected_high_level(
    mode: CredSspMode,
    ntlm: Option<Option<NtlmRedirectionNames>>,
) -> (CredSspClient, InspectingPeer, Credentials) {
    let (credentials, target, network, mut peer, _) = inspecting_environment();
    let mut client = CredSspClient::new(
        PUBLIC_KEY.to_vec(),
        credentials.clone(),
        mode,
        ClientMode::Negotiate(NegotiateConfig::new(
            Box::new(KerberosConfig {
                kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
                client_computer_name: CLIENT_COMPUTER_NAME.into(),
            }),
            Some("kerberos,ntlm".to_owned()),
            CLIENT_COMPUTER_NAME.into(),
        )),
        target,
    )
    .unwrap();
    if let Some(names) = ntlm {
        client.enable_remote_guard_ntlm(names).unwrap();
    }
    let mut request = TsRequest::default();
    for _ in 0..6 {
        let result = client.process(request).resolve_with_client(&network).unwrap();
        let (outgoing, is_final) = match result {
            ClientState::ReplyNeeded(request) => (request, false),
            ClientState::FinalMessage(request) => (request, true),
        };
        assert_eq!(outgoing.auth_info.is_some(), is_final);
        if let Some(reply) = peer.process(outgoing, &network).unwrap() {
            request = reply;
        } else {
            assert!(is_final);
            assert_eq!(
                client
                    .process(TsRequest::default())
                    .resolve_with_client(&network)
                    .unwrap_err()
                    .error_type,
                ErrorKind::OutOfSequence
            );
            return (client, peer, credentials);
        }
    }
    panic!("synthetic CredSSP exchange did not finish")
}

#[test]
fn credssp_credential_less_sends_empty_type_one_auth_info() {
    let (mut client, peer, _) = run_inspected_high_level(CredSspMode::CredentialLess, None);
    assert_eq!(
        peer.auth_info.unwrap(),
        [
            0x30, 0x17, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x10, 0x04, 0x0e, 0x30, 0x0c, 0xa0, 0x02, 0x04, 0x00, 0xa1,
            0x02, 0x04, 0x00, 0xa2, 0x02, 0x04, 0x00,
        ]
    );
    assert_eq!(
        client.take_remote_guard_session().unwrap_err().error_type,
        ErrorKind::UnsupportedFunction
    );
}

#[test]
fn credssp_remote_guard_versioned_constructor_remains_kerberos_only() {
    for ntlm in [
        None,
        Some(None),
        Some(Some(NtlmRedirectionNames {
            user: "redirected".to_owned(),
            domain: "SYNTHETIC".to_owned(),
        })),
    ] {
        let (credentials, target, network, mut peer, _) = inspecting_environment();
        let mut client = CredSspClient::new_with_version(
            PUBLIC_KEY.to_vec(),
            credentials.clone(),
            CredSspMode::RemoteGuard,
            6,
            ClientMode::Negotiate(NegotiateConfig::new(
                Box::new(KerberosConfig {
                    kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
                    client_computer_name: CLIENT_COMPUTER_NAME.into(),
                }),
                Some("kerberos,ntlm".to_owned()),
                CLIENT_COMPUTER_NAME.into(),
            )),
            target.clone(),
        )
        .unwrap();
        if let Some(names) = ntlm {
            client.enable_remote_guard_ntlm(names).unwrap();
        }
        let ClientState::ReplyNeeded(first) = client
            .process(TsRequest::default())
            .resolve_with_client(&network)
            .unwrap()
        else {
            panic!("credentials must not be sent initially")
        };
        assert_eq!(
            offered_mech_types(first.nego_tokens.as_ref().unwrap()),
            [MS_KRB5_OID, KRB5_OID]
        );
        assert!(first.auth_info.is_none());
        assert!(peer.process(first, &network).unwrap().is_some());
        assert!(peer.auth_info.is_none());

        let mut no_kerberos = CredSspClient::new_with_version(
            PUBLIC_KEY.to_vec(),
            credentials,
            CredSspMode::RemoteGuard,
            6,
            ClientMode::Negotiate(NegotiateConfig::new(
                Box::new(NtlmConfig::new(CLIENT_COMPUTER_NAME.into())),
                Some("ntlm,!kerberos".to_owned()),
                CLIENT_COMPUTER_NAME.into(),
            )),
            target,
        )
        .unwrap();
        let error = no_kerberos
            .process(TsRequest::default())
            .resolve_to_result()
            .unwrap_err();
        assert_eq!(error.error_type, ErrorKind::InvalidParameter);
    }
}

#[derive(serde::Deserialize)]
struct GuardPackage {
    package_name: ExplicitContextTag0<picky_asn1::wrapper::OctetStringAsn1>,
    cred_buffer: ExplicitContextTag1<picky_asn1::wrapper::OctetStringAsn1>,
}

#[derive(serde::Deserialize)]
struct GuardCredentials {
    logon: ExplicitContextTag0<GuardPackage>,
    #[serde(default)]
    supplemental: picky_asn1::wrapper::Optional<Option<ExplicitContextTag1<Asn1SequenceOf<GuardPackage>>>>,
}

#[derive(Debug, PartialEq, serde::Deserialize)]
struct TestKrbCred {
    version: ExplicitContextTag0<IntegerAsn1>,
    message_type: ExplicitContextTag1<IntegerAsn1>,
    tickets: picky_asn1::wrapper::ExplicitContextTag2<Asn1SequenceOf<picky_krb::data_types::Ticket>>,
    encrypted: picky_asn1::wrapper::ExplicitContextTag3<picky_krb::data_types::EncryptedData>,
}

/// Reads a single DER value's content, for inspecting the already-encoded EncKrbCredPart.
fn der_content(input: &[u8], tag: u8) -> &[u8] {
    assert_eq!(input[0], tag);
    let (length, header) = if input[1] < 128 {
        (usize::from(input[1]), 2)
    } else {
        let n = usize::from(input[1] & 127);
        let length = input[2..2 + n]
            .iter()
            .fold(0usize, |length, byte| length * 256 + usize::from(*byte));
        (length, 2 + n)
    };
    &input[header..header + length]
}

fn check_remote_guard_auth_info(
    peer: &InspectingPeer,
    session: &mut sspi::rcg::RemoteGuardSession,
    ntlm_enabled: bool,
) {
    use picky_asn1_der::application_tag::ApplicationTag;
    use sspi::rcg::{ComputeTgsChecksumRequest, KeyReference};

    let encoded: picky_krb::credssp::TsCredentials =
        picky_asn1_der::from_bytes(peer.auth_info.as_ref().unwrap()).unwrap();
    assert_eq!(encoded.cred_type.0.0, [6]);
    let guard: GuardCredentials = picky_asn1_der::from_bytes(&encoded.credentials.0.0).unwrap();
    assert_eq!(guard.logon.0.package_name.0.0, b"K\0e\0r\0b\0e\0r\0o\0s\0");
    let logon = guard.logon.0.cred_buffer.0.0;
    let u32_at = |offset| u32::from_le_bytes(logon[offset..offset + 4].try_into().unwrap());
    let u64_at = |offset| u64::from_le_bytes(logon[offset..offset + 8].try_into().unwrap());
    assert_eq!(u32_at(0), 10);
    assert_eq!(u32_at(4), 2);
    let service_len = usize::try_from(u32_at(8)).unwrap();
    let tgt_len = usize::try_from(u32_at(12)).unwrap();
    let service_offset = usize::try_from(u64_at(16)).unwrap();
    let tgt_offset = usize::try_from(u64_at(24)).unwrap();
    assert_eq!(service_offset, 32);
    assert_eq!(tgt_offset, service_offset + service_len);
    assert_eq!(logon.len(), tgt_offset + tgt_len);
    let service: picky_krb::data_types::Ticket =
        picky_asn1_der::from_bytes(&logon[service_offset..tgt_offset]).unwrap();
    assert_eq!(service.0.tkt_vno.0.0, [5]);
    assert_eq!(service.0.sname.0.name_string.0.0[0].0.as_bytes(), b"HOST");
    let ticket = &service.0.enc_part.0;
    let ticket = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .decrypt(&[0x5a; 32], TICKET_REP, &ticket.cipher.0.0)
        .unwrap();
    let ticket: EncTicketPart = picky_asn1_der::from_bytes(&ticket).unwrap();
    let computer_key = ticket.0.key.0.key_value.0.0;
    let forwarded: ApplicationTag<TestKrbCred, 22> = picky_asn1_der::from_bytes(&logon[tgt_offset..]).unwrap();
    assert_eq!(forwarded.0.version.0.0, [5]);
    assert_eq!(forwarded.0.message_type.0.0, [22]);
    assert_eq!(forwarded.0.tickets.0.0.len(), 1);
    assert_eq!(forwarded.0.encrypted.0.etype.0.0, [18]);
    let protected = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .decrypt(&computer_key, 14, &forwarded.0.encrypted.0.cipher.0.0)
        .unwrap();
    let info = der_content(
        der_content(der_content(der_content(&protected, 0x7D), 0x30), 0xA0),
        0x30,
    );
    let first_info = der_content(info, 0x30);
    let key: picky_krb::data_types::EncryptionKey = picky_asn1_der::from_bytes(der_content(first_info, 0xA0)).unwrap();
    assert_eq!(key.key_type.0.0, [18]);
    let handle = key.key_value.0.0;
    assert_eq!(handle.len(), 32);
    let raw_tgt = &forwarded.0.tickets.0.0[0].0.enc_part.0;
    let plaintext = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .decrypt(&peer.tgt_key, TICKET_REP, &raw_tgt.cipher.0.0)
        .unwrap();
    let raw_tgt: EncTicketPart = picky_asn1_der::from_bytes(&plaintext).unwrap();
    let raw_key = raw_tgt.0.key.0.key_value.0.0;
    assert_ne!(handle, raw_key);
    assert!(!protected.windows(raw_key.len()).any(|bytes| bytes == raw_key));
    // The logon handle must resolve in exactly the handed-off session.
    let body = peer.request_body.lock().unwrap();
    let reference = KeyReference {
        encryption_type: 18,
        value: &handle,
    };
    let checksum = session
        .compute_tgs_checksum(ComputeTgsChecksumRequest {
            request_body: &body,
            key: reference,
            checksum_type: 16,
        })
        .unwrap();
    let checksum: picky_krb::data_types::Checksum = picky_asn1_der::from_bytes(&checksum).unwrap();
    assert_eq!(
        checksum.checksum.0.0,
        picky_krb::crypto::aes::checksum_sha_aes(&raw_key, 6, &body, &picky_krb::crypto::aes::AesSize::Aes256).unwrap()
    );
    assert_eq!(
        session
            .compute_tgs_checksum(ComputeTgsChecksumRequest {
                request_body: &body,
                key: KeyReference {
                    value: &raw_key,
                    ..reference
                },
                checksum_type: 16,
            })
            .unwrap_err()
            .error_type,
        ErrorKind::NoKerbKey
    );
    assert_eq!(session.ntlm_available(), ntlm_enabled);
    let supplemental = guard.supplemental.0;
    assert_eq!(supplemental.is_some(), ntlm_enabled);
    if let Some(supplemental) = supplemental {
        assert_eq!(supplemental.0.0.len(), 1);
        let credential = &supplemental.0.0[0];
        assert_eq!(credential.package_name.0.0, b"N\0T\0L\0M\0");
        let bytes = &credential.cred_buffer.0.0;
        assert_eq!(&bytes[..8], &[2, 0, 0xFF, 0xFF, 2, 0, 0, 0]);
        assert_eq!(&bytes[8..28], &[0; 20]);
        assert_eq!(&bytes[36..40], b"RGN1");
        let reference = sspi::rcg::NtlmCredentialReference {
            reserved1: 1,
            reserved2: 0,
            reserved3: 0,
            credential_key_type: 0,
            credential_key: &[0; 20],
            encrypted_secrets: &bytes[36..],
        };
        let result = session.compare_ntlm_credentials(&reference, &reference).unwrap();
        assert!(result.are_nt_owfs_equal);
        assert!(!result.are_lm_owfs_equal);
        assert!(!result.are_sha_owfs_equal);
        assert_eq!(
            session
                .compare_ntlm_credentials(
                    &reference,
                    &sspi::rcg::NtlmCredentialReference {
                        encrypted_secrets: &[0; 32],
                        ..reference
                    }
                )
                .unwrap_err()
                .error_type,
            ErrorKind::InvalidHandle
        );
    }
}

fn check_ntlm_redirection_names(
    peer: &InspectingPeer,
    session: &mut sspi::rcg::RemoteGuardSession,
    names: Option<&NtlmRedirectionNames>,
) {
    use hmac::{KeyInit as _, Mac as _};
    use md4::{Digest as _, Md4};
    use sspi::rcg::{Lm20GetNtlm3ChallengeResponseRequest, NtlmCredentialReference};

    let credentials: picky_krb::credssp::TsCredentials =
        picky_asn1_der::from_bytes(peer.auth_info.as_ref().unwrap()).unwrap();
    let guard: GuardCredentials = picky_asn1_der::from_bytes(&credentials.credentials.0.0).unwrap();
    let supplements = guard.supplemental.0.unwrap().0;
    let bytes = &supplements.0[0].cred_buffer.0.0;
    let (user, domain) = names
        .map(|names| (names.user.as_str(), names.domain.as_str()))
        .unwrap_or(("pw13", "EXAMPLE"));
    let user_and_domain = format!("{}{}", user.to_uppercase(), domain.to_uppercase())
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let user = user.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>();
    let domain = domain.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>();
    let wrong_name = "not-the-bound-name"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let server_name = [7, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0];
    let request = Lm20GetNtlm3ChallengeResponseRequest {
        credential: NtlmCredentialReference {
            reserved1: 1,
            reserved2: 0,
            reserved3: 0,
            credential_key_type: 0,
            credential_key: &[0; 20],
            encrypted_secrets: &bytes[36..],
        },
        user_name: &user,
        logon_domain_name: &domain,
        server_name: &server_name,
        challenge_to_client: [0x77; 8],
    };
    for invalid in [
        Lm20GetNtlm3ChallengeResponseRequest {
            user_name: &wrong_name,
            ..request
        },
        Lm20GetNtlm3ChallengeResponseRequest {
            logon_domain_name: &wrong_name,
            ..request
        },
    ] {
        assert_eq!(
            session
                .lm20_get_ntlm3_challenge_response(&invalid)
                .err()
                .unwrap()
                .error_type,
            ErrorKind::LogonDenied
        );
    }
    let response = session.lm20_get_ntlm3_challenge_response(&request).unwrap();
    assert_eq!(&response.ntlm3_response[16..24], &[1, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&response.ntlm3_response[24..32], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&response.ntlm3_response[32..40], &response.challenge_from_client);
    assert_eq!(&response.ntlm3_response[44..60], &server_name);
    assert_eq!(response.lm_session_key.as_ref(), &[0; 8]);

    let identity = peer.credentials.to_auth_identity().unwrap();
    let password = identity
        .password
        .as_ref()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let mut response_key = hmac::Hmac::<md5::Md5>::new_from_slice(&Md4::digest(&password)).unwrap();
    response_key.update(&user_and_domain);
    let response_key = response_key.finalize().into_bytes();
    let mut proof = hmac::Hmac::<md5::Md5>::new_from_slice(&response_key).unwrap();
    proof.update(&request.challenge_to_client);
    proof.update(&response.ntlm3_response[16..]);
    let expected_proof = proof.finalize().into_bytes();
    assert_eq!(response.ntlm3_response[..16], expected_proof[..]);
    let mut session_key = hmac::Hmac::<md5::Md5>::new_from_slice(&response_key).unwrap();
    session_key.update(&expected_proof);
    assert_eq!(
        response.user_session_key.as_ref().as_slice(),
        session_key.finalize().into_bytes().as_slice()
    );
    assert!(session.ntlm_available());
}

fn check_live_handoff(peer: &mut InspectingPeer, session: &mut sspi::rcg::RemoteGuardSession) {
    let sent = peer.last_received_sequence.unwrap();
    let received = peer.last_sent_sequence.unwrap();
    let request = session.wrap(b"rdpear request").unwrap();
    assert_eq!(u64::from_be_bytes(request[8..16].try_into().unwrap()), sent + 1);
    assert_eq!(peer.decrypt(&request), b"rdpear request");
    let response = peer.encrypt(b"rdpear response");
    assert_eq!(u64::from_be_bytes(response[8..16].try_into().unwrap()), received + 1);
    assert_eq!(session.unwrap(&response).unwrap().as_ref(), b"rdpear response");
    let next = session.wrap(b"next rdpear request").unwrap();
    assert_eq!(u64::from_be_bytes(next[8..16].try_into().unwrap()), sent + 2);
    assert_eq!(peer.decrypt(&next), b"next rdpear request");
}

#[cfg(feature = "tsssp")]
mod sspi_exchange {
    use std::io::{Read as _, Write as _};
    use std::sync::LazyLock;

    use picky::hash::HashAlgorithm;
    use picky::key::PrivateKey;
    use picky::signature::SignatureAlgorithm;
    use picky::x509::certificate::CertificateBuilder;
    use picky::x509::date::UtcDate;
    use picky::x509::name::DirectoryName;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use sspi::credssp::SspiContext;
    use sspi::credssp::sspi_cred_ssp::SspiCredSsp;
    use sspi::{
        BufferType, ClientRequestFlags, DataRepresentation, SecurityBuffer, SecurityStatus, Sspi as _, SspiEx as _,
        Utf16StringExt as _,
    };

    use super::*;

    static TLS_CONFIG: LazyLock<(Arc<rustls::ServerConfig>, Vec<u8>)> = LazyLock::new(|| {
        // This key and certificate exist only in memory for these tests.
        let key = PrivateKey::generate_rsa(2048).unwrap();
        let cert = CertificateBuilder::new()
            .validity(UtcDate::ymd(2020, 1, 1).unwrap(), UtcDate::ymd(2040, 1, 1).unwrap())
            .self_signed(DirectoryName::new_common_name("synthetic.example.com"), &key)
            .signature_hash_type(SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256))
            .build()
            .unwrap();
        let der = cert.to_der().unwrap();
        let cert: picky_asn1_x509::Certificate = picky_asn1_der::from_bytes(&der).unwrap();
        let picky_asn1_x509::PublicKey::Rsa(public_key) =
            cert.tbs_certificate.subject_public_key_info.subject_public_key
        else {
            panic!("expected RSA certificate")
        };
        let public_key = picky_asn1_der::to_vec(&public_key.0).unwrap();
        let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(der)],
                PrivatePkcs8KeyDer::from(key.to_pkcs8().unwrap()).into(),
            )
            .unwrap();
        (Arc::new(config), public_key)
    });

    enum IdentitySource {
        Acquire,
        CustomSet,
    }

    struct Exchange {
        client: SspiCredSsp,
        tls: rustls::ServerConnection,
        peer: InspectingPeer,
        network: NetworkClientMock,
        credentials: Option<CredentialsBuffers>,
        target: String,
        requests: Arc<Mutex<Vec<RecordedTgsReq>>>,
        input: Vec<u8>,
        final_output: bool,
    }

    impl Exchange {
        fn new(mode: CredSspMode, default_constructor: bool) -> Self {
            Self::with_identity_source(mode, default_constructor, IdentitySource::Acquire)
        }

        fn with_identity_source(mode: CredSspMode, default_constructor: bool, identity_source: IdentitySource) -> Self {
            Self::with_configuration(
                mode,
                default_constructor,
                identity_source,
                NegotiateConfig::new(
                    Box::new(KerberosConfig {
                        kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
                        client_computer_name: CLIENT_COMPUTER_NAME.into(),
                    }),
                    Some("kerberos,ntlm".to_owned()),
                    CLIENT_COMPUTER_NAME.into(),
                ),
            )
        }

        fn with_configuration(
            mode: CredSspMode,
            default_constructor: bool,
            identity_source: IdentitySource,
            config: NegotiateConfig,
        ) -> Self {
            let (credentials, target, network, mut peer, requests) = inspecting_environment();
            let context = SspiContext::Negotiate(sspi::Negotiate::new_client(config).unwrap());
            // Constructing the client installs the selected TLS crypto provider.
            let mut client = if default_constructor {
                SspiCredSsp::new_client(context).unwrap()
            } else {
                SspiCredSsp::new_client_with_mode(context, mode).unwrap()
            };
            let handle = match identity_source {
                IdentitySource::Acquire => {
                    client
                        .acquire_credentials_handle()
                        .with_credential_use(sspi::CredentialUse::Outbound)
                        .with_auth_data(&credentials)
                        .execute(&mut client)
                        .unwrap()
                        .credentials_handle
                }
                IdentitySource::CustomSet => {
                    // Do not acquire first: that would mask missing inner setter propagation.
                    let handle = Some(CredentialsBuffers::try_from(credentials.clone()).unwrap());
                    client.custom_set_auth_identity(credentials).unwrap();
                    handle
                }
            };
            peer.public_key = TLS_CONFIG.1.clone();
            Self {
                client,
                tls: rustls::ServerConnection::new(Arc::clone(&TLS_CONFIG.0)).unwrap(),
                peer,
                network,
                credentials: handle,
                target,
                requests,
                input: Vec::new(),
                final_output: false,
            }
        }

        fn initialize(
            &mut self,
            target: Option<&str>,
            flags: ClientRequestFlags,
        ) -> (sspi::Result<SecurityStatus>, Vec<u8>) {
            let mut input = [SecurityBuffer::new(self.input.clone(), BufferType::Token)];
            let mut output = [SecurityBuffer::new(b"unchanged output".to_vec(), BufferType::Token)];
            let mut builder = self
                .client
                .initialize_security_context()
                .with_credentials_handle(&mut self.credentials)
                .with_context_requirements(flags)
                .with_target_data_representation(DataRepresentation::Native)
                .with_output(&mut output);
            if !self.input.is_empty() {
                builder = builder.with_input(&mut input);
            }
            if let Some(target) = target {
                builder = builder.with_target_name(target);
            }
            let result = sspi::SspiImpl::initialize_security_context_impl(&mut self.client, &mut builder)
                .unwrap()
                .resolve_with_client(&self.network)
                .map(|result| result.status);
            (result, output[0].buffer.clone())
        }

        fn step(&mut self, omit_target: bool) -> sspi::Result<()> {
            let target = self.target.clone();
            let (result, output) =
                self.initialize((!omit_target).then_some(target.as_str()), ClientRequestFlags::empty());
            let status = result?;
            self.final_output = status == SecurityStatus::Ok;
            self.input.clear();
            self.tls.read_tls(&mut output.as_slice()).unwrap();
            let state = self.tls.process_new_packets().unwrap();
            if state.plaintext_bytes_to_read() != 0 {
                let mut plaintext = vec![0; state.plaintext_bytes_to_read()];
                self.tls.reader().read_exact(&mut plaintext).unwrap();
                let request = TsRequest::from_buffer(&plaintext).unwrap();
                assert_eq!(request.auth_info.is_some(), self.final_output);
                if let Some(response) = self.peer.process(request, &self.network)? {
                    let mut encoded = Vec::new();
                    response.encode_ts_request(&mut encoded).unwrap();
                    self.tls.writer().write_all(&encoded).unwrap();
                } else {
                    assert!(self.final_output);
                }
            }
            self.tls.write_tls(&mut self.input).unwrap();
            Ok(())
        }

        fn finish(&mut self, omit_later_target: bool) {
            for step in 0..12 {
                self.step(omit_later_target && step != 0).unwrap();
                if self.final_output {
                    assert!(self.peer.auth_info.is_some());
                    return;
                }
            }
            panic!("in-memory TLS/CredSSP exchange did not finish")
        }
    }

    #[test]
    fn credssp_sspi_default_client_preserves_ordinary_credential_delegation() {
        let mut exchange = Exchange::new(CredSspMode::WithCredentials, true);
        let CredentialsBuffers::AuthIdentity(expected) = exchange.credentials.clone().unwrap() else {
            panic!("expected password identity")
        };
        exchange.finish(false);
        let encoded: picky_krb::credssp::TsCredentials =
            picky_asn1_der::from_bytes(exchange.peer.auth_info.as_ref().unwrap()).unwrap();
        assert_eq!(encoded.cred_type.0.0, [1]);
        let password: picky_krb::credssp::TsPasswordCreds =
            picky_asn1_der::from_bytes(&encoded.credentials.0.0).unwrap();
        assert_eq!(password.domain_name.0.0, expected.domain.to_bytes_le());
        assert_eq!(password.user_name.0.0, expected.user.to_bytes_le());
        assert_eq!(password.password.0.0, expected.password.as_ref().0.to_bytes_le());
        assert!(exchange.peer.binding_verified);
        // Kerberos clears unsupported GSS ticket delegation; CredSSP delegates the password above.
        assert_eq!(exchange.peer.gss_flags, Some(0x02));
    }

    #[test]
    fn credssp_sspi_restricted_admin_allows_ntlm_without_delegating_credentials() {
        for mode in [CredSspMode::CredentialLess, CredSspMode::WithCredentials] {
            let mut exchange = Exchange::with_configuration(
                mode,
                false,
                IdentitySource::Acquire,
                NegotiateConfig::new(
                    Box::new(NtlmConfig::new(CLIENT_COMPUTER_NAME.to_owned())),
                    Some("ntlm,!kerberos,!pku2u".to_owned()),
                    CLIENT_COMPUTER_NAME.into(),
                ),
            );
            exchange.peer.context = SspiContext::Negotiate(
                sspi::Negotiate::new_server(
                    NegotiateConfig::new(
                        Box::new(NtlmConfig::new(SERVER_COMPUTER_NAME.to_owned())),
                        Some("ntlm,!kerberos,!pku2u".to_owned()),
                        SERVER_COMPUTER_NAME.to_owned(),
                    ),
                    vec![exchange.peer.credentials.to_auth_identity().unwrap()],
                )
                .unwrap(),
            );
            let CredentialsBuffers::AuthIdentity(expected) = exchange.credentials.clone().unwrap() else {
                panic!("expected password identity")
            };
            exchange.finish(false);
            assert!(exchange.peer.binding_verified);
            assert_eq!(exchange.peer.offered, ["1.3.6.1.4.1.311.2.2.10"]);
            assert_eq!(exchange.peer.gss_flags, None);
            let auth_info = exchange.peer.auth_info.as_ref().unwrap();
            if mode == CredSspMode::CredentialLess {
                assert_eq!(
                    auth_info,
                    &[
                        0x30, 0x17, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x10, 0x04, 0x0e, 0x30, 0x0c, 0xa0, 0x02, 0x04,
                        0x00, 0xa1, 0x02, 0x04, 0x00, 0xa2, 0x02, 0x04, 0x00,
                    ]
                );
            } else {
                let encoded: picky_krb::credssp::TsCredentials = picky_asn1_der::from_bytes(auth_info).unwrap();
                assert_eq!(encoded.cred_type.0.0, [1]);
                let password: picky_krb::credssp::TsPasswordCreds =
                    picky_asn1_der::from_bytes(&encoded.credentials.0.0).unwrap();
                assert_eq!(password.domain_name.0.0, expected.domain.to_bytes_le());
                assert_eq!(password.user_name.0.0, expected.user.to_bytes_le());
                assert_eq!(password.password.0.0, expected.password.as_ref().0.to_bytes_le());
            }
            assert!(exchange.requests.lock().unwrap().is_empty());
            assert_eq!(
                exchange.client.take_remote_guard_session().unwrap_err().error_type,
                ErrorKind::UnsupportedFunction
            );
        }
    }

    #[test]
    fn credssp_sspi_explicit_modes_select_matching_final_auth_info() {
        for mode in [CredSspMode::CredentialLess, CredSspMode::RemoteGuard] {
            let mut exchange = Exchange::new(mode, false);
            exchange.finish(true);
            if mode == CredSspMode::CredentialLess {
                assert_eq!(exchange.peer.offered, [MS_KRB5_OID, KRB5_OID, "1.3.6.1.4.1.311.2.2.10"]);
                assert_eq!(exchange.peer.gss_flags, Some(0x02));
                let credentials: picky_krb::credssp::TsCredentials =
                    picky_asn1_der::from_bytes(exchange.peer.auth_info.as_ref().unwrap()).unwrap();
                assert_eq!(credentials.cred_type.0.0, [1]);
                let password: picky_krb::credssp::TsPasswordCreds =
                    picky_asn1_der::from_bytes(&credentials.credentials.0.0).unwrap();
                assert_eq!(password.domain_name.0.0, Vec::<u8>::new());
                assert_eq!(password.user_name.0.0, Vec::<u8>::new());
                assert_eq!(password.password.0.0, Vec::<u8>::new());
            } else {
                assert_eq!(exchange.peer.offered, [MS_KRB5_OID, KRB5_OID]);
                assert_eq!(exchange.peer.gss_flags, Some(0x3e));
                let mut session = exchange.client.take_remote_guard_session().unwrap();
                check_remote_guard_auth_info(&exchange.peer, &mut session, false);
            }
        }
    }

    #[test]
    fn credssp_sspi_remote_guard_ntlm_option_does_not_enable_initial_ntlm() {
        for names in [
            None,
            Some(NtlmRedirectionNames {
                user: "redirected".to_owned(),
                domain: "SYNTHETIC".to_owned(),
            }),
        ] {
            let mut exchange = Exchange::new(CredSspMode::RemoteGuard, false);
            exchange.client.enable_remote_guard_ntlm(names.clone()).unwrap();
            exchange.finish(false);
            assert_eq!(exchange.peer.offered, [MS_KRB5_OID, KRB5_OID]);
            assert_eq!(exchange.peer.gss_flags, Some(0x3e));
            let mut session = exchange.client.take_remote_guard_session().unwrap();
            check_remote_guard_auth_info(&exchange.peer, &mut session, true);
            check_ntlm_redirection_names(&exchange.peer, &mut session, names.as_ref());
            check_live_handoff(&mut exchange.peer, &mut session);
        }
    }

    #[test]
    fn credssp_sspi_remote_guard_ntlm_uses_initialization_handle() {
        for names in [
            None,
            Some(NtlmRedirectionNames {
                user: "redirected".to_owned(),
                domain: "SYNTHETIC".to_owned(),
            }),
        ] {
            let mut exchange = Exchange::new(CredSspMode::RemoteGuard, false);
            let other_identity = Credentials::AuthIdentity(AuthIdentity {
                username: Username::new("other-user", Some("OTHER")).unwrap(),
                password: "not-the-authenticated-password".to_owned().into(),
            });
            let other_handle = exchange
                .client
                .acquire_credentials_handle()
                .with_credential_use(sspi::CredentialUse::Outbound)
                .with_auth_data(&other_identity)
                .execute(&mut exchange.client)
                .unwrap()
                .credentials_handle;
            assert_ne!(exchange.credentials, other_handle);

            exchange.client.enable_remote_guard_ntlm(names.clone()).unwrap();
            exchange.finish(false);
            assert!(exchange.peer.binding_verified);
            let mut session = exchange.client.take_remote_guard_session().unwrap();
            check_ntlm_redirection_names(&exchange.peer, &mut session, names.as_ref());
        }
    }

    #[test]
    fn credssp_sspi_custom_identity_on_fresh_context_preserves_remote_guard_ntlm_and_handoff() {
        for names in [
            None,
            Some(NtlmRedirectionNames {
                user: "redirected".to_owned(),
                domain: "SYNTHETIC".to_owned(),
            }),
        ] {
            let mut exchange =
                Exchange::with_identity_source(CredSspMode::RemoteGuard, false, IdentitySource::CustomSet);
            exchange.client.enable_remote_guard_ntlm(names.clone()).unwrap();
            exchange.finish(false);
            assert!(exchange.peer.binding_verified);
            assert_eq!(exchange.peer.offered, [MS_KRB5_OID, KRB5_OID]);
            assert_eq!(exchange.peer.gss_flags, Some(0x3e));
            let mut session = exchange.client.take_remote_guard_session().unwrap();
            check_remote_guard_auth_info(&exchange.peer, &mut session, true);
            check_ntlm_redirection_names(&exchange.peer, &mut session, names.as_ref());
            check_live_handoff(&mut exchange.peer, &mut session);
            assert_eq!(
                exchange.client.take_remote_guard_session().unwrap_err().error_type,
                ErrorKind::ContextExpired
            );
        }
    }

    #[test]
    fn credssp_sspi_remote_guard_rejects_ntlm_only_peer_without_auth_info() {
        for ntlm in [
            None,
            Some(None),
            Some(Some(NtlmRedirectionNames {
                user: "redirected".to_owned(),
                domain: "SYNTHETIC".to_owned(),
            })),
        ] {
            let mut exchange = Exchange::new(CredSspMode::RemoteGuard, false);
            if let Some(names) = ntlm {
                exchange.client.enable_remote_guard_ntlm(names).unwrap();
            }
            exchange.peer.context = SspiContext::Negotiate(
                sspi::Negotiate::new_server(
                    NegotiateConfig::new(
                        Box::new(NtlmConfig::new(SERVER_COMPUTER_NAME.to_owned())),
                        Some("ntlm,!kerberos,!pku2u".to_owned()),
                        SERVER_COMPUTER_NAME.to_owned(),
                    ),
                    vec![exchange.peer.credentials.to_auth_identity().unwrap()],
                )
                .unwrap(),
            );
            let mut error = None;
            for _ in 0..10 {
                if let Err(failure) = exchange.step(false) {
                    error = Some(failure);
                    break;
                }
                assert!(!exchange.final_output);
            }
            assert_eq!(error.unwrap().error_type, ErrorKind::InvalidToken);
            assert_eq!(exchange.peer.offered, [MS_KRB5_OID, KRB5_OID]);
            assert!(exchange.peer.auth_info.is_none());
            assert_eq!(
                exchange.client.take_remote_guard_session().unwrap_err().error_type,
                ErrorKind::OutOfSequence
            );
        }
    }

    #[test]
    fn credssp_sspi_target_is_bound_across_all_exchange_steps() {
        for mode in [
            CredSspMode::WithCredentials,
            CredSspMode::CredentialLess,
            CredSspMode::RemoteGuard,
        ] {
            let mut exchange = Exchange::new(mode, false);
            let target = exchange.target.clone();
            exchange.step(false).unwrap();
            let mut validated_steps = 0;
            for _ in 0..12 {
                for substituted in [
                    "TERMSRV/other.example.com".to_owned(),
                    format!("HOST/{}", target.split_once('/').unwrap().1),
                    target.replacen("TERMSRV", "termsrv", 1),
                    target.to_ascii_uppercase(),
                ] {
                    assert_ne!(substituted, target);
                    let before = exchange.requests.lock().unwrap().clone();
                    let (result, output) = exchange.initialize(Some(&substituted), ClientRequestFlags::empty());
                    assert_eq!(result.unwrap_err().error_type, ErrorKind::InvalidParameter);
                    assert_eq!(output, b"unchanged output");
                    assert_eq!(*exchange.requests.lock().unwrap(), before);
                }
                validated_steps += 1;
                if exchange.final_output {
                    for unchanged in [Some(target.as_str()), None] {
                        let (result, output) = exchange.initialize(unchanged, ClientRequestFlags::empty());
                        assert_eq!(result.unwrap_err().error_type, ErrorKind::OutOfSequence);
                        assert_eq!(output, b"unchanged output");
                    }
                    break;
                }
                // Alternating identical and omitted SPNs must preserve the original binding.
                exchange.step(validated_steps % 2 == 0).unwrap();
            }
            assert!(exchange.final_output);
            assert!(validated_steps >= 4);
            let host = target.split_once('/').unwrap().1.to_owned();
            let requests = exchange.requests.lock().unwrap();
            assert!(
                requests
                    .iter()
                    .any(|(names, _, _)| names == &["TERMSRV".to_owned(), host.clone()])
            );
            if mode == CredSspMode::RemoteGuard {
                assert!(requests.contains(&(vec!["HOST".to_owned(), host], false, false)));
                assert!(requests.contains(&(vec!["krbtgt".to_owned(), "EXAMPLE.COM".to_owned()], true, false)));
            }
        }
    }

    #[test]
    fn credssp_sspi_remote_guard_session_handoff_continues_live_sequence_numbers() {
        use sspi::{EncryptionFlags, SecurityBufferRef};

        let mut exchange = Exchange::new(CredSspMode::RemoteGuard, false);
        exchange.finish(false);
        let mut session = exchange.client.take_remote_guard_session().unwrap();
        check_remote_guard_auth_info(&exchange.peer, &mut session, false);
        check_live_handoff(&mut exchange.peer, &mut session);
        assert_eq!(
            exchange.client.take_remote_guard_session().unwrap_err().error_type,
            ErrorKind::ContextExpired
        );
        // Taking the inner Kerberos session must leave the outer TLS stream usable.
        let sizes = exchange.client.query_context_stream_sizes().unwrap();
        let mut header = vec![0; usize::try_from(sizes.header).unwrap()];
        let mut data = b"tls after handoff".to_vec();
        let mut trailer = vec![0; usize::try_from(sizes.trailer).unwrap()];
        let mut padding = [];
        let mut buffers = [
            SecurityBufferRef::stream_header_buf(&mut header),
            SecurityBufferRef::data_buf(&mut data),
            SecurityBufferRef::stream_trailer_buf(&mut trailer),
            SecurityBufferRef::padding_buf(&mut padding),
        ];
        exchange
            .client
            .encrypt_message(EncryptionFlags::empty(), &mut buffers)
            .unwrap();
        let tls = buffers
            .iter()
            .flat_map(|buffer| buffer.data().iter().copied())
            .collect::<Vec<_>>();
        exchange.tls.read_tls(&mut tls.as_slice()).unwrap();
        let state = exchange.tls.process_new_packets().unwrap();
        assert_eq!(state.plaintext_bytes_to_read(), b"tls after handoff".len());
        let mut received = [0; 17];
        exchange.tls.reader().read_exact(&mut received).unwrap();
        assert_eq!(&received, b"tls after handoff");
    }

    #[test]
    fn credssp_sspi_remote_guard_policy_and_handoff_obey_exchange_states() {
        for mode in [CredSspMode::CredentialLess, CredSspMode::RemoteGuard] {
            let mut exchange = Exchange::new(mode, false);
            for step in 0..12 {
                let before = exchange.requests.lock().unwrap().clone();
                let target = exchange.target.clone();
                let (result, output) = exchange.initialize(Some(&target), ClientRequestFlags::DELEGATE);
                assert_eq!(result.unwrap_err().error_type, ErrorKind::InvalidParameter);
                assert_eq!(output, b"unchanged output");
                assert_eq!(*exchange.requests.lock().unwrap(), before);
                if mode == CredSspMode::RemoteGuard {
                    if !exchange.final_output {
                        assert_eq!(
                            exchange.client.take_remote_guard_session().unwrap_err().error_type,
                            ErrorKind::OutOfSequence
                        );
                    }
                    if step != 0 {
                        assert_eq!(
                            exchange.client.enable_remote_guard_ntlm(None).unwrap_err().error_type,
                            ErrorKind::OutOfSequence
                        );
                    }
                } else {
                    assert_eq!(
                        exchange.client.take_remote_guard_session().unwrap_err().error_type,
                        ErrorKind::UnsupportedFunction
                    );
                }
                if exchange.final_output {
                    break;
                }
                exchange.step(step != 0).unwrap();
            }
            assert!(exchange.final_output);
            if mode == CredSspMode::RemoteGuard {
                let mut session = exchange.client.take_remote_guard_session().unwrap();
                check_live_handoff(&mut exchange.peer, &mut session);
                assert_eq!(
                    exchange.client.take_remote_guard_session().unwrap_err().error_type,
                    ErrorKind::ContextExpired
                );
            }
        }
    }
}
