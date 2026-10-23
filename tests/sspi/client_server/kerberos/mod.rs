#![allow(clippy::result_large_err)]

mod context_validator;
mod iakerb;
pub(super) mod kdc;
pub(super) mod network_client;

use std::collections::{HashMap, HashSet};
use std::panic;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, IntegerAsn1};
use picky_krb::constants::key_usages::{AP_REQ_AUTHENTICATOR, TICKET_REP};
use picky_krb::constants::types::{NT_PRINCIPAL, NT_SRV_INST};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{Authenticator, EncTicketPart, KerberosStringAsn1, PrincipalName};
use picky_krb::gss_api::{KrbMessage, MechTypeList};
use picky_krb::messages::ApReq;
use sspi::credssp::SspiContext;
use sspi::kerberos::ServerProperties;
use sspi::network_client::NetworkClient;
use sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, Credentials, CredentialsBuffers, DataRepresentation, ErrorKind,
    KdcResolution, Kerberos, KerberosConfig, KerberosServerConfig, Negotiate, NegotiateConfig, NegotiatedProtocol,
    SecurityBuffer, SecurityStatus, ServerRequestFlags, Sspi, SspiImpl, Username,
};
use time::OffsetDateTime;
use url::Url;

use crate::client_server::kerberos::context_validator::{
    EmptySspiContextValidator, SpnegoKerberosContextValidator, SpnegoKerberosNtlmFallbackValidator,
    SpnegoServerNtlmFallbackValidator, SspiContextValidator,
};
use crate::client_server::kerberos::kdc::{
    CLIENT_COMPUTER_NAME, KDC_URL, KdcMock, MAX_TIME_SKEW, PasswordCreds, SERVER_COMPUTER_NAME, UserName, Validators,
};
use crate::client_server::kerberos::network_client::{FailedNetworkClientMock, NetworkClientMock};
use crate::client_server::{test_encryption, test_rpc_request_encryption, test_stream_buffer_encryption};

/// Represents a Kerberos environment:
/// * user and services keys;
/// * user logon credentials;
/// * realm and target application service name;
///
/// It is used for simplifying tests environment preparation.
pub(super) struct KrbEnvironment {
    pub keys: HashMap<UserName, Vec<u8>>,
    pub users: HashMap<UserName, PasswordCreds>,
    pub credentials: Credentials,
    pub realm: String,
    pub target_name: String,
    pub target_service_name: PrincipalName,
}

/// Initializes a Kerberos environment. It includes:
/// * User logon credentials (password-based).
/// * Kerberos services keys.
/// * Target machine name.
pub(super) fn init_krb_environment() -> KrbEnvironment {
    let username = "pw13";
    let user_password = "qweQWE123!@#";
    let domain = "EXAMPLE";
    let realm = "EXAMPLE.COM";
    let mut salt = realm.to_string();
    salt.push_str(username);
    let krbtgt = "krbtgt";
    let termsrv = "TERMSRV";
    let target_machine_name = "DESKTOP-8F33RFH.example.com";
    let mut target_name = termsrv.to_string();
    target_name.push('/');
    target_name.push_str(target_machine_name);

    let tgt_service_key = vec![
        199, 133, 201, 239, 57, 139, 61, 128, 71, 236, 217, 130, 250, 148, 117, 193, 197, 86, 155, 11, 92, 124, 232,
        146, 3, 14, 158, 220, 113, 63, 110, 230,
    ];
    let application_service_key = vec![
        168, 29, 77, 196, 211, 88, 148, 180, 123, 188, 196, 182, 173, 30, 249, 191, 89, 35, 44, 56, 20, 217, 132, 131,
        89, 144, 33, 79, 16, 91, 126, 72,
    ];
    let keys = [
        (
            UserName(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string(krbtgt.into()).unwrap()),
                    KerberosStringAsn1::from(IA5String::from_string(domain.into()).unwrap()),
                ])),
            }),
            tgt_service_key.clone(),
        ),
        (
            UserName(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string(krbtgt.into()).unwrap()),
                    KerberosStringAsn1::from(IA5String::from_string(realm.to_string()).unwrap()),
                ])),
            }),
            tgt_service_key,
        ),
        (
            UserName(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string(termsrv.into()).unwrap()),
                    KerberosStringAsn1::from(IA5String::from_string(target_machine_name.into()).unwrap()),
                ])),
            }),
            application_service_key,
        ),
    ]
    .into_iter()
    .collect();
    let users = [(
        UserName(PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_PRINCIPAL])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![KerberosStringAsn1::from(
                IA5String::from_string(username.into()).unwrap(),
            )])),
        }),
        PasswordCreds {
            password: user_password.as_bytes().to_vec(),
            salt,
        },
    )]
    .into_iter()
    .collect();

    let credentials = Credentials::AuthIdentity(AuthIdentity {
        username: Username::new_down_level_logon_name(username, domain).unwrap(),
        password: user_password.to_owned().into(),
    });

    KrbEnvironment {
        keys,
        users,
        realm: realm.to_string(),
        credentials,
        target_name,
        target_service_name: PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                KerberosStringAsn1::from(IA5String::from_string("TERMSRV".into()).unwrap()),
                KerberosStringAsn1::from(IA5String::from_string("DESKTOP-8F33RFH.example.com".into()).unwrap()),
            ])),
        },
    }
}

/// Does all preparations and calls the [initialize_security_context_impl] function
/// on the provided Kerberos context.
pub(super) fn initialize_security_context(
    client: &mut SspiContext,
    credentials_handle: &mut Option<CredentialsBuffers>,
    flags: ClientRequestFlags,
    target_name: &str,
    in_token: Vec<u8>,
    network_client: &mut dyn NetworkClient,
) -> (SecurityStatus, Vec<u8>) {
    let mut input_token = [SecurityBuffer::new(in_token, BufferType::Token)];
    let mut output_token = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];

    let mut builder = client
        .initialize_security_context()
        .with_credentials_handle(credentials_handle)
        .with_context_requirements(flags)
        .with_target_data_representation(DataRepresentation::Native)
        .with_target_name(target_name)
        .with_input(&mut input_token)
        .with_output(&mut output_token);
    let result = client
        .initialize_security_context_impl(&mut builder)
        .expect("Kerberos initialize_security_context should not fail")
        .resolve_with_client(network_client)
        .expect("Kerberos initialize_security_context should not fail");

    (result.status, output_token.remove(0).buffer)
}

/// Does all preparations and calls the [accept_security_context] function
/// on the provided Kerberos context.
pub(super) fn accept_security_context(
    server: &mut SspiContext,
    credentials_handle: &mut Option<CredentialsBuffers>,
    flags: ServerRequestFlags,
    in_token: Vec<u8>,
    network_client: &mut dyn NetworkClient,
) -> (SecurityStatus, Vec<u8>) {
    let mut input_token = [SecurityBuffer::new(in_token, BufferType::Token)];
    let mut output_token = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];

    let builder = server
        .accept_security_context()
        .with_credentials_handle(credentials_handle)
        .with_context_requirements(flags)
        .with_target_data_representation(DataRepresentation::Native)
        .with_input(&mut input_token)
        .with_output(&mut output_token);
    let result = server
        .accept_security_context_impl(builder)
        .expect("Kerberos accept_security_context should not fail")
        .resolve_with_client(network_client)
        .expect("Kerberos accept_security_context should not fail");

    (result.status, output_token.remove(0).buffer)
}

#[expect(clippy::too_many_arguments, reason = "many arguments are acceptable in test helpers")]
fn run_kerberos(
    client: &mut SspiContext,
    client_credentials_handle: &mut Option<CredentialsBuffers>,
    client_flags: ClientRequestFlags,
    target_name: &str,

    server: &mut SspiContext,
    server_credentials_handle: &mut Option<CredentialsBuffers>,
    server_flags: ServerRequestFlags,

    network_client: &mut dyn NetworkClient,
    steps: usize,
    mut context_validator: impl SspiContextValidator,
) {
    let mut client_in_token = Vec::new();

    for step in 0..steps {
        let (client_status, token) = initialize_security_context(
            client,
            client_credentials_handle,
            client_flags,
            target_name,
            client_in_token,
            network_client,
        );

        context_validator.validate_client(step, client);

        if client_status == SecurityStatus::Ok {
            if !token.is_empty() {
                accept_security_context(server, server_credentials_handle, server_flags, token, network_client);
            }

            test_encryption(client, server);
            test_stream_buffer_encryption(client, server);
            test_rpc_request_encryption(client, server);
            return;
        }

        let (_, token) =
            accept_security_context(server, server_credentials_handle, server_flags, token, network_client);
        client_in_token = token;
    }

    panic!("Kerberos authentication should not exceed {steps} steps");
}

pub(super) fn ap_req_authenticator(token: &[u8], service_key: &[u8]) -> Authenticator {
    let ap_req = KrbMessage::<ApReq>::decode_application_krb_message(token)
        .expect("client token contains an AP-REQ")
        .0
        .krb_msg;
    let encrypted_ticket = &ap_req.0.ticket.0.0.enc_part.0;
    let ticket_cipher = CipherSuite::try_from(encrypted_ticket.etype.0.0.as_slice())
        .expect("supported ticket encryption type")
        .cipher();
    let ticket_data = ticket_cipher
        .decrypt(service_key, TICKET_REP, &encrypted_ticket.cipher.0.0)
        .expect("service decrypts the ticket");
    let ticket: EncTicketPart = picky_asn1_der::from_bytes(&ticket_data).expect("valid ticket");

    let encrypted_authenticator = &ap_req.0.authenticator.0;
    let authenticator_cipher = CipherSuite::try_from(encrypted_authenticator.etype.0.0.as_slice())
        .expect("supported authenticator encryption type")
        .cipher();
    let authenticator_data = authenticator_cipher
        .decrypt(
            &ticket.0.key.0.key_value.0.0,
            AP_REQ_AUTHENTICATOR,
            &encrypted_authenticator.cipher.0.0,
        )
        .expect("session key decrypts the authenticator");
    picky_asn1_der::from_bytes(&authenticator_data).expect("valid authenticator")
}

fn ap_req_authenticator_time(token: &[u8], service_key: &[u8]) -> OffsetDateTime {
    let authenticator = ap_req_authenticator(token, service_key);
    OffsetDateTime::try_from(authenticator.0.ctime.0.0).expect("valid authenticator time")
}

#[test]
fn kerberos_auth() {
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
            tgs_req: Box::new(|tgs_req| {
                // Here, we should check that the Kerberos client does not negotiated Kerberos U2U auth and not enabled any unneeded flags.

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
    );
    let mut network_client = NetworkClientMock { kdc };

    let client_config = KerberosConfig {
        kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
        client_computer_name: CLIENT_COMPUTER_NAME.into(),
    };
    let kerberos_client = Kerberos::new_client_from_config(client_config).unwrap();

    let server_config = KerberosConfig {
        kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
        client_computer_name: SERVER_COMPUTER_NAME.into(),
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
    let kerberos_server = Kerberos::new_server_from_config(server_config, server_properties).unwrap();

    let credentials = CredentialsBuffers::try_from(credentials).unwrap();
    let mut client_credentials_handle = Some(credentials.clone());
    let mut server_credentials_handle = Some(credentials);

    let client_flags = ClientRequestFlags::MUTUAL_AUTH
        | ClientRequestFlags::INTEGRITY
        | ClientRequestFlags::SEQUENCE_DETECT
        | ClientRequestFlags::REPLAY_DETECT
        | ClientRequestFlags::CONFIDENTIALITY;
    let server_flags = ServerRequestFlags::MUTUAL_AUTH
        | ServerRequestFlags::INTEGRITY
        | ServerRequestFlags::SEQUENCE_DETECT
        | ServerRequestFlags::REPLAY_DETECT
        | ServerRequestFlags::CONFIDENTIALITY;

    run_kerberos(
        &mut SspiContext::Kerberos(kerberos_client),
        &mut client_credentials_handle,
        client_flags,
        &target_name,
        &mut SspiContext::Kerberos(kerberos_server),
        &mut server_credentials_handle,
        server_flags,
        &mut network_client,
        2,
        EmptySspiContextValidator,
    );
}

/// Authenticates the test user against a [KdcMock] configured by `configure_kdc`.
fn kerberos_auth_with_kdc(configure_kdc: impl FnOnce(KdcMock) -> KdcMock) {
    kerberos_auth_with_environment_and_kdc(init_krb_environment(), configure_kdc);
}

fn kerberos_auth_with_environment_and_kdc(environment: KrbEnvironment, configure_kdc: impl FnOnce(KdcMock) -> KdcMock) {
    let KrbEnvironment {
        realm,
        credentials,
        keys,
        users,
        target_name,
        target_service_name,
    } = environment;

    let ticket_decryption_key = keys[&UserName(target_service_name.clone())].clone();

    let kdc = configure_kdc(KdcMock::new(
        realm,
        keys,
        users,
        Validators {
            as_req: Box::new(|_as_req| {}),
            tgs_req: Box::new(|_tgs_req| {}),
        },
    ));
    let mut network_client = NetworkClientMock { kdc };

    let client_config = KerberosConfig {
        kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
        client_computer_name: CLIENT_COMPUTER_NAME.into(),
    };
    let kerberos_client = Kerberos::new_client_from_config(client_config).unwrap();

    let server_config = KerberosConfig {
        kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
        client_computer_name: SERVER_COMPUTER_NAME.into(),
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
    let kerberos_server = Kerberos::new_server_from_config(server_config, server_properties).unwrap();

    let credentials = CredentialsBuffers::try_from(credentials).unwrap();
    let mut client_credentials_handle = Some(credentials.clone());
    let mut server_credentials_handle = Some(credentials);

    let client_flags = ClientRequestFlags::MUTUAL_AUTH
        | ClientRequestFlags::INTEGRITY
        | ClientRequestFlags::SEQUENCE_DETECT
        | ClientRequestFlags::REPLAY_DETECT
        | ClientRequestFlags::CONFIDENTIALITY;
    let server_flags = ServerRequestFlags::MUTUAL_AUTH
        | ServerRequestFlags::INTEGRITY
        | ServerRequestFlags::SEQUENCE_DETECT
        | ServerRequestFlags::REPLAY_DETECT
        | ServerRequestFlags::CONFIDENTIALITY;

    run_kerberos(
        &mut SspiContext::Kerberos(kerberos_client),
        &mut client_credentials_handle,
        client_flags,
        &target_name,
        &mut SspiContext::Kerberos(kerberos_server),
        &mut server_credentials_handle,
        server_flags,
        &mut network_client,
        2,
        EmptySspiContextValidator,
    );
}

/// MIT and Heimdal KDCs send PA-ETYPE-INFO2 only in the pre-authentication error.
/// The AS-REP key uses the same salt as the pre-authentication key.
#[test]
fn kerberos_auth_without_as_rep_etype_info2() {
    kerberos_auth_with_kdc(KdcMock::omit_as_rep_etype_info2);
}

/// MIT encodes the AS-REP enc-part as EncTGSRepPart, which clients may accept
/// under [RFC 4120 section 5.4.2: KRB_KDC_REP definition][kdc-rep].
///
/// [kdc-rep]: https://www.rfc-editor.org/rfc/rfc4120#section-5.4.2
#[test]
fn kerberos_auth_with_tgs_rep_enc_part_in_as_rep() {
    kerberos_auth_with_kdc(KdcMock::tgs_rep_enc_part_in_as_rep);
}

#[test]
fn kerberos_auth_recovers_from_kdc_clock_skew() {
    for clock_offset in [time::Duration::seconds(15), time::Duration::seconds(-15)] {
        let KrbEnvironment {
            realm,
            credentials,
            keys,
            users,
            target_name,
            target_service_name,
        } = init_krb_environment();
        let ticket_decryption_key = keys[&UserName(target_service_name.clone())].clone();
        let as_requests = Arc::new(AtomicUsize::new(0));
        let request_counter = Arc::clone(&as_requests);
        let kdc = KdcMock::new(
            realm,
            keys,
            users,
            Validators {
                as_req: Box::new(move |_| {
                    request_counter.fetch_add(1, Ordering::SeqCst);
                }),
                tgs_req: Box::new(|_| {}),
            },
        )
        .with_clock_offset(clock_offset);
        let mut network_client = NetworkClientMock { kdc };

        let client_config = KerberosConfig {
            kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
            client_computer_name: CLIENT_COMPUTER_NAME.into(),
        };
        let kerberos_client = Kerberos::new_client_from_config(client_config).unwrap();
        let server_config = KerberosConfig {
            kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
            client_computer_name: SERVER_COMPUTER_NAME.into(),
        };
        let server_properties = ServerProperties {
            mech_types: MechTypeList::from(Vec::new()),
            max_time_skew: std::time::Duration::from_secs(30),
            ticket_decryption_key: Some(ticket_decryption_key.clone().into()),
            service_name: target_service_name,
            additional_service_keys: Vec::new(),
            user: None,
            client: None,
            authenticators_cache: HashSet::new(),
        };
        let kerberos_server = Kerberos::new_server_from_config(server_config, server_properties).unwrap();

        let credentials = CredentialsBuffers::try_from(credentials).unwrap();
        let mut client_credentials_handle = Some(credentials.clone());
        let mut server_credentials_handle = Some(credentials);
        let mut client = SspiContext::Kerberos(kerberos_client);
        let mut server = SspiContext::Kerberos(kerberos_server);
        let client_flags = ClientRequestFlags::MUTUAL_AUTH | ClientRequestFlags::INTEGRITY;
        let server_flags = ServerRequestFlags::MUTUAL_AUTH | ServerRequestFlags::INTEGRITY;

        let before = OffsetDateTime::now_utc() + clock_offset;
        let (status, ap_req_token) = initialize_security_context(
            &mut client,
            &mut client_credentials_handle,
            client_flags,
            &target_name,
            Vec::new(),
            &mut network_client,
        );
        let after = OffsetDateTime::now_utc() + clock_offset;
        assert_eq!(status, SecurityStatus::ContinueNeeded);

        let ctime = ap_req_authenticator_time(&ap_req_token, &ticket_decryption_key);
        // KerberosTime stores whole seconds, so ctime can precede the sampled start by less than a second.
        assert!(
            (before - time::Duration::seconds(1)..=after).contains(&ctime),
            "AP authenticator time {ctime} should use the KDC clock offset {clock_offset} (observed {before}..{after})"
        );

        let (_, ap_rep_token) = accept_security_context(
            &mut server,
            &mut server_credentials_handle,
            server_flags,
            ap_req_token,
            &mut network_client,
        );
        let (status, final_token) = initialize_security_context(
            &mut client,
            &mut client_credentials_handle,
            client_flags,
            &target_name,
            ap_rep_token,
            &mut network_client,
        );
        assert_eq!(status, SecurityStatus::Ok);
        if !final_token.is_empty() {
            accept_security_context(
                &mut server,
                &mut server_credentials_handle,
                server_flags,
                final_token,
                &mut network_client,
            );
        }
        test_encryption(&mut client, &mut server);
        test_stream_buffer_encryption(&mut client, &mut server);
        test_rpc_request_encryption(&mut client, &mut server);
        assert_eq!(as_requests.load(Ordering::SeqCst), 3);
    }
}

#[test]
fn kerberos_skew_retry_is_bounded_and_does_not_retry_other_errors() {
    for (force_skew, expected_error, expected_requests) in
        [(true, ErrorKind::TimeSkew, 3), (false, ErrorKind::KdcInvalidRequest, 2)]
    {
        let KrbEnvironment {
            realm,
            credentials,
            keys,
            mut users,
            target_name,
            ..
        } = init_krb_environment();
        if !force_skew {
            for user in users.values_mut() {
                user.password = b"wrong password".to_vec();
            }
        }

        let as_requests = Arc::new(AtomicUsize::new(0));
        let request_counter = Arc::clone(&as_requests);
        let kdc = KdcMock::new(
            realm,
            keys,
            users,
            Validators {
                as_req: Box::new(move |_| {
                    request_counter.fetch_add(1, Ordering::SeqCst);
                }),
                tgs_req: Box::new(|_| {}),
            },
        );
        let kdc = if force_skew {
            kdc.with_clock_offset(time::Duration::seconds(15))
                .reject_valid_preauth_with_skew()
        } else {
            kdc
        };
        let network_client = NetworkClientMock { kdc };
        let mut client = SspiContext::Kerberos(
            Kerberos::new_client_from_config(KerberosConfig {
                kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
                client_computer_name: CLIENT_COMPUTER_NAME.into(),
            })
            .unwrap(),
        );
        let mut credentials_handle = Some(CredentialsBuffers::try_from(credentials).unwrap());
        let mut input_token = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut output_token = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut builder = client
            .initialize_security_context()
            .with_credentials_handle(&mut credentials_handle)
            .with_context_requirements(ClientRequestFlags::MUTUAL_AUTH)
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(&target_name)
            .with_input(&mut input_token)
            .with_output(&mut output_token);

        let err = client
            .initialize_security_context_impl(&mut builder)
            .unwrap()
            .resolve_with_client(&network_client)
            .unwrap_err();
        assert_eq!(err.error_type, expected_error);
        assert_eq!(as_requests.load(Ordering::SeqCst), expected_requests);
    }
}

#[test]
fn spnego_kerberos_u2u() {
    let KrbEnvironment {
        realm,
        credentials,
        keys,
        users,
        target_name,
        target_service_name,
    } = init_krb_environment();

    let ticket_decryption_key = keys[&UserName(target_service_name.clone())].clone();

    let identity_1 = credentials.to_auth_identity().unwrap();
    let mut identity_2 = identity_1.clone();
    identity_2.username = Username::new_upn(identity_1.username.account_name(), &realm.to_ascii_lowercase()).unwrap();

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
                //
                // Previously, we were able to validate the presence of the additional ticket and enc-tkt-in-skey flag.
                // But since we use a preflight Kerberos exchange to check if the Kerberos is possible,
                // we can no longer do that.
            }),
        },
    );
    let mut network_client = NetworkClientMock { kdc };

    let client_config = KerberosConfig {
        kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
        client_computer_name: CLIENT_COMPUTER_NAME.into(),
    };
    let spnego_client = Negotiate::new_client(NegotiateConfig::new(
        Box::new(client_config.clone()),
        Some(String::from("kerberos,!ntlm")),
        CLIENT_COMPUTER_NAME.into(),
    ))
    .unwrap();

    let credentials = CredentialsBuffers::try_from(credentials).unwrap();

    let server_config = KerberosConfig {
        kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
        client_computer_name: SERVER_COMPUTER_NAME.into(),
    };
    let server_properties = ServerProperties {
        mech_types: MechTypeList::from(Vec::new()),
        max_time_skew: MAX_TIME_SKEW,
        ticket_decryption_key: Some(ticket_decryption_key.into()),
        service_name: target_service_name,
        additional_service_keys: Vec::new(),
        user: Some(credentials.clone()),
        client: None,
        authenticators_cache: HashSet::new(),
    };
    let kerberos_server_config = KerberosServerConfig {
        kerberos_config: server_config,
        server_properties,
    };
    let spnego_server = Negotiate::new_server(
        NegotiateConfig::new(
            Box::new(kerberos_server_config),
            Some(String::from("kerberos,!ntlm")),
            SERVER_COMPUTER_NAME.into(),
        ),
        vec![identity_1, identity_2],
    )
    .unwrap();

    let mut client_credentials_handle = Some(credentials.clone());
    let mut server_credentials_handle = Some(credentials);

    let client_flags = ClientRequestFlags::MUTUAL_AUTH
        | ClientRequestFlags::INTEGRITY
        | ClientRequestFlags::USE_SESSION_KEY // Kerberos U2U auth
        | ClientRequestFlags::SEQUENCE_DETECT
        | ClientRequestFlags::REPLAY_DETECT
        | ClientRequestFlags::CONFIDENTIALITY;
    let server_flags = ServerRequestFlags::MUTUAL_AUTH
        | ServerRequestFlags::INTEGRITY
        | ServerRequestFlags::USE_SESSION_KEY // Kerberos U2U auth
        | ServerRequestFlags::SEQUENCE_DETECT
        | ServerRequestFlags::REPLAY_DETECT
        | ServerRequestFlags::CONFIDENTIALITY;

    run_kerberos(
        &mut SspiContext::Negotiate(spnego_client),
        &mut client_credentials_handle,
        client_flags,
        &target_name,
        &mut SspiContext::Negotiate(spnego_server),
        &mut server_credentials_handle,
        server_flags,
        &mut network_client,
        4,
        SpnegoKerberosContextValidator,
    );
}

fn run_spnego(
    client_flags: ClientRequestFlags,
    server_flags: ServerRequestFlags,
    steps: usize,
    get_network_client: impl Fn(KdcMock) -> Box<dyn NetworkClient>,
    client_package_list: Option<String>,
    server_package_list: Option<String>,
    context_validator: impl SspiContextValidator,
) -> (SspiContext, SspiContext) {
    let KrbEnvironment {
        realm,
        credentials,
        keys,
        users,
        target_name,
        target_service_name,
    } = init_krb_environment();

    let ticket_decryption_key = keys[&UserName(target_service_name.clone())].clone();

    let identity_1 = credentials.to_auth_identity().unwrap();
    let mut identity_2 = identity_1.clone();
    identity_2.username = Username::new_upn(identity_1.username.account_name(), &realm.to_ascii_lowercase()).unwrap();

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
    let mut network_client = get_network_client(kdc);

    let client_config = KerberosConfig {
        kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
        client_computer_name: CLIENT_COMPUTER_NAME.into(),
    };
    let mut spnego_client = SspiContext::Negotiate(
        Negotiate::new_client(NegotiateConfig::new(
            Box::new(client_config.clone()),
            client_package_list.clone(),
            CLIENT_COMPUTER_NAME.into(),
        ))
        .unwrap(),
    );

    let server_config = KerberosConfig {
        kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
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
    let kerberos_server_config = KerberosServerConfig {
        kerberos_config: server_config,
        server_properties,
    };
    let mut spnego_server = SspiContext::Negotiate(
        Negotiate::new_server(
            NegotiateConfig::new(
                Box::new(kerberos_server_config),
                server_package_list.clone(),
                SERVER_COMPUTER_NAME.into(),
            ),
            vec![identity_1, identity_2],
        )
        .unwrap(),
    );

    let credentials = CredentialsBuffers::try_from(credentials).unwrap();
    let mut client_credentials_handle = Some(credentials.clone());
    let mut server_credentials_handle = Some(credentials);

    run_kerberos(
        &mut spnego_client,
        &mut client_credentials_handle,
        client_flags,
        &target_name,
        &mut spnego_server,
        &mut server_credentials_handle,
        server_flags,
        &mut *network_client,
        steps,
        context_validator,
    );

    (spnego_client, spnego_server)
}

#[test]
fn spnego_kerberos_1() {
    let client_flags = ClientRequestFlags::MUTUAL_AUTH
        | ClientRequestFlags::INTEGRITY
        | ClientRequestFlags::SEQUENCE_DETECT
        | ClientRequestFlags::REPLAY_DETECT
        | ClientRequestFlags::CONFIDENTIALITY;
    let server_flags = ServerRequestFlags::MUTUAL_AUTH
        | ServerRequestFlags::INTEGRITY
        | ServerRequestFlags::SEQUENCE_DETECT
        | ServerRequestFlags::REPLAY_DETECT
        | ServerRequestFlags::CONFIDENTIALITY;
    let package_list = Some(String::from("kerberos,ntlm"));

    let (client, _server) = run_spnego(
        client_flags,
        server_flags,
        3,
        |kdc| Box::new(NetworkClientMock { kdc }),
        package_list.clone(),
        package_list,
        SpnegoKerberosContextValidator,
    );

    let SspiContext::Negotiate(negotiate) = client else {
        panic!("client must be a Negotiate context");
    };
    let negotiated_protocol = negotiate.negotiated_protocol();

    assert!(matches!(negotiated_protocol, NegotiatedProtocol::Kerberos(_)),);
}

#[test]
fn spnego_kerberos_dce_style() {
    let client_flags = ClientRequestFlags::MUTUAL_AUTH
        | ClientRequestFlags::INTEGRITY
        | ClientRequestFlags::USE_DCE_STYLE
        | ClientRequestFlags::SEQUENCE_DETECT
        | ClientRequestFlags::REPLAY_DETECT
        | ClientRequestFlags::CONFIDENTIALITY;
    let server_flags = ServerRequestFlags::MUTUAL_AUTH
        | ServerRequestFlags::INTEGRITY
        | ServerRequestFlags::USE_DCE_STYLE
        | ServerRequestFlags::SEQUENCE_DETECT
        | ServerRequestFlags::REPLAY_DETECT
        | ServerRequestFlags::CONFIDENTIALITY;
    let package_list = Some(String::from("kerberos,ntlm"));

    let (client, _server) = run_spnego(
        client_flags,
        server_flags,
        4,
        |kdc| Box::new(NetworkClientMock { kdc }),
        package_list.clone(),
        package_list,
        SpnegoKerberosContextValidator,
    );

    let SspiContext::Negotiate(negotiate) = client else {
        panic!("client must be a Negotiate context");
    };
    let negotiated_protocol = negotiate.negotiated_protocol();

    assert!(matches!(negotiated_protocol, NegotiatedProtocol::Kerberos(_)),);
}

#[test]
fn spnego_kerberos_ntlm_fallback() {
    let client_flags = ClientRequestFlags::MUTUAL_AUTH
        | ClientRequestFlags::INTEGRITY
        | ClientRequestFlags::SEQUENCE_DETECT
        | ClientRequestFlags::REPLAY_DETECT
        | ClientRequestFlags::CONFIDENTIALITY;
    let server_flags = ServerRequestFlags::MUTUAL_AUTH
        | ServerRequestFlags::INTEGRITY
        | ServerRequestFlags::SEQUENCE_DETECT
        | ServerRequestFlags::REPLAY_DETECT
        | ServerRequestFlags::CONFIDENTIALITY;
    let package_list = Some(String::from("kerberos,ntlm"));

    for kind in sspi::FALLBACK_ERROR_KINDS {
        let (client, _server) = run_spnego(
            client_flags,
            server_flags,
            4,
            |_| Box::new(FailedNetworkClientMock { kind }),
            package_list.clone(),
            package_list.clone(),
            SpnegoKerberosNtlmFallbackValidator,
        );

        let SspiContext::Negotiate(negotiate) = client else {
            panic!("client must be a Negotiate context");
        };
        let negotiated_protocol = negotiate.negotiated_protocol();

        assert!(
            matches!(negotiated_protocol, NegotiatedProtocol::Ntlm(_)),
            "Client should fallback to NTLM if Kerberos fails with {kind:?} error"
        );
    }
}

#[test]
fn spnego_kerberos_server_ntlm_fallback() {
    let client_flags = ClientRequestFlags::MUTUAL_AUTH
        | ClientRequestFlags::INTEGRITY
        | ClientRequestFlags::SEQUENCE_DETECT
        | ClientRequestFlags::REPLAY_DETECT
        | ClientRequestFlags::CONFIDENTIALITY;
    let server_flags = ServerRequestFlags::MUTUAL_AUTH
        | ServerRequestFlags::INTEGRITY
        | ServerRequestFlags::SEQUENCE_DETECT
        | ServerRequestFlags::REPLAY_DETECT
        | ServerRequestFlags::CONFIDENTIALITY;
    let client_package_list = Some(String::from("kerberos,ntlm"));
    let server_package_list = Some(String::from("!kerberos,ntlm"));

    let (client, _server) = run_spnego(
        client_flags,
        server_flags,
        4,
        |kdc| Box::new(NetworkClientMock { kdc }),
        client_package_list,
        server_package_list,
        SpnegoServerNtlmFallbackValidator,
    );

    let SspiContext::Negotiate(negotiate) = client else {
        panic!("client must be a Negotiate context");
    };
    let negotiated_protocol = negotiate.negotiated_protocol();

    assert!(matches!(negotiated_protocol, NegotiatedProtocol::Ntlm(_)),);
}

// This test ensures that the client falls back to NTLM when the SPN is an IP address, which is not supported by Kerberos.
#[test]
fn spnego_kerberos_ntlm_fallback_spn_ip_address() {
    let KrbEnvironment {
        realm,
        credentials,
        keys,
        users,
        target_name: _,
        target_service_name,
    } = init_krb_environment();

    let ticket_decryption_key = keys[&UserName(target_service_name.clone())].clone();

    let identity_1 = credentials.to_auth_identity().unwrap();
    let mut identity_2 = identity_1.clone();
    identity_2.username = Username::new_upn(identity_1.username.account_name(), &realm.to_ascii_lowercase()).unwrap();

    let kdc = KdcMock::new(
        realm,
        keys,
        users,
        Validators {
            as_req: Box::new(|_as_req| {
                panic!("AS_REQ should not be sent when the SPN is an IP address");
            }),
            tgs_req: Box::new(|_tgs_req| {
                panic!("TGS_REQ should not be sent when the SPN is an IP address");
            }),
        },
    );
    let mut network_client = NetworkClientMock { kdc };

    let client_config = KerberosConfig {
        kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
        client_computer_name: CLIENT_COMPUTER_NAME.into(),
    };
    let spnego_client = Negotiate::new_client(NegotiateConfig::new(
        Box::new(client_config.clone()),
        Some(String::from("kerberos,ntlm")),
        CLIENT_COMPUTER_NAME.into(),
    ))
    .unwrap();

    let credentials = CredentialsBuffers::try_from(credentials).unwrap();

    let server_config = KerberosConfig {
        kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
        client_computer_name: SERVER_COMPUTER_NAME.into(),
    };
    let server_properties = ServerProperties {
        mech_types: MechTypeList::from(Vec::new()),
        max_time_skew: MAX_TIME_SKEW,
        ticket_decryption_key: Some(ticket_decryption_key.into()),
        service_name: target_service_name,
        additional_service_keys: Vec::new(),
        user: Some(credentials.clone()),
        client: None,
        authenticators_cache: HashSet::new(),
    };
    let kerberos_server_config = KerberosServerConfig {
        kerberos_config: server_config,
        server_properties,
    };
    let spnego_server = Negotiate::new_server(
        NegotiateConfig::new(
            Box::new(kerberos_server_config),
            Some(String::from("kerberos,ntlm")),
            SERVER_COMPUTER_NAME.into(),
        ),
        vec![identity_1, identity_2],
    )
    .unwrap();

    let mut client_credentials_handle = Some(credentials.clone());
    let mut server_credentials_handle = Some(credentials);

    let client_flags = ClientRequestFlags::MUTUAL_AUTH
        | ClientRequestFlags::INTEGRITY
        | ClientRequestFlags::USE_SESSION_KEY
        | ClientRequestFlags::SEQUENCE_DETECT
        | ClientRequestFlags::REPLAY_DETECT
        | ClientRequestFlags::CONFIDENTIALITY;
    let server_flags = ServerRequestFlags::MUTUAL_AUTH
        | ServerRequestFlags::INTEGRITY
        | ServerRequestFlags::USE_SESSION_KEY
        | ServerRequestFlags::SEQUENCE_DETECT
        | ServerRequestFlags::REPLAY_DETECT
        | ServerRequestFlags::CONFIDENTIALITY;

    run_kerberos(
        &mut SspiContext::Negotiate(spnego_client),
        &mut client_credentials_handle,
        client_flags,
        // The client must fallback to NTLM when the SPN is an IP address.
        "TERMSRV/192.168.1.104",
        &mut SspiContext::Negotiate(spnego_server),
        &mut server_credentials_handle,
        server_flags,
        &mut network_client,
        3,
        SpnegoKerberosNtlmFallbackValidator,
    );
}

mod salt_regressions {
    use picky_krb::constants::key_usages::KRB_PRIV_ENC_PART;
    use picky_krb::data_types::EncKrbPrivPart;
    use picky_krb::messages::{ApMessage, AsReq, KrbPrivMessage, TgtRep, TgtReq};
    use sspi::builders::ChangePasswordBuilder;
    use sspi::generator::NetworkRequest;

    use super::kdc::SaltHint;
    use super::*;

    fn environment_with_preauth_salt(salt: &str) -> KrbEnvironment {
        let mut environment = init_krb_environment();
        for user in environment.users.values_mut() {
            user.salt = salt.to_owned();
        }
        environment
    }

    #[test]
    fn kerberos_auth_without_as_rep_etype_info2_with_tgs_rep_enc_part_in_as_rep() {
        kerberos_auth_with_kdc(|kdc| kdc.omit_as_rep_etype_info2().tgs_rep_enc_part_in_as_rep());
    }

    #[test]
    fn kerberos_auth_with_explicit_empty_as_rep_salt() {
        kerberos_auth_with_environment_and_kdc(environment_with_preauth_salt("preauth-only-salt"), |kdc| {
            kdc.with_as_rep_salt_hint(SaltHint::Explicit(String::new()))
                .with_as_rep_encryption_salt("")
        });
    }

    #[test]
    fn kerberos_auth_with_missing_as_rep_salt_field() {
        kerberos_auth_with_environment_and_kdc(environment_with_preauth_salt("preauth-only-salt"), |kdc| {
            kdc.with_as_rep_salt_hint(SaltHint::MissingField)
                .with_as_rep_encryption_salt("EXAMPLE.COMpw13")
        });
    }

    #[test]
    fn kerberos_auth_with_custom_as_rep_salt() {
        kerberos_auth_with_environment_and_kdc(environment_with_preauth_salt("preauth-only-salt"), |kdc| {
            kdc.with_as_rep_salt_hint(SaltHint::Explicit("reply-only-salt".to_owned()))
                .with_as_rep_encryption_salt("reply-only-salt")
        });
    }

    #[test]
    fn kerberos_auth_with_missing_preauth_salt_field() {
        // The down-level credentials request EXAMPLE; the KDC replies in EXAMPLE.COM.
        kerberos_auth_with_environment_and_kdc(environment_with_preauth_salt("EXAMPLEpw13"), |kdc| {
            kdc.with_preauth_salt_hint(SaltHint::MissingField)
                .omit_as_rep_etype_info2()
        });
    }

    #[test]
    fn kerberos_auth_with_explicit_empty_preauth_salt() {
        kerberos_auth_with_environment_and_kdc(environment_with_preauth_salt(""), |kdc| {
            kdc.with_preauth_salt_hint(SaltHint::Explicit(String::new()))
                .omit_as_rep_etype_info2()
        });
    }

    struct PasswordChangeRequestInspector {
        network: NetworkClientMock,
        service_key: Vec<u8>,
        as_requests: AtomicUsize,
        inspected_password_requests: AtomicUsize,
    }

    const NEW_PASSWORD: &str = "New password with exact bytes!42";
    const INSPECTED: &str = "password-change-request-inspected";

    impl NetworkClient for PasswordChangeRequestInspector {
        fn send(&self, request: &NetworkRequest) -> sspi::Result<Vec<u8>> {
            let data = &request.data[4..];
            if picky_asn1_der::from_bytes::<AsReq>(data).is_ok() {
                self.as_requests.fetch_add(1, Ordering::SeqCst);
                return self.network.send(request);
            }
            assert_eq!(self.as_requests.load(Ordering::SeqCst), 2);
            let message = KrbPrivMessage::deserialize(data).expect("actual outgoing password-change request");
            let ApMessage::ApReq(ap_req) = message.ap_message else {
                panic!("password change must carry an AP-REQ");
            };
            let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
            let ticket: EncTicketPart = picky_asn1_der::from_bytes(
                &cipher
                    .decrypt(
                        &self.service_key,
                        TICKET_REP,
                        &ap_req.0.ticket.0.0.enc_part.0.cipher.0.0,
                    )
                    .unwrap(),
            )
            .unwrap();
            let authenticator: Authenticator = picky_asn1_der::from_bytes(
                &cipher
                    .decrypt(
                        &ticket.0.key.0.key_value.0.0,
                        AP_REQ_AUTHENTICATOR,
                        &ap_req.0.authenticator.0.cipher.0.0,
                    )
                    .unwrap(),
            )
            .unwrap();
            let subkey = authenticator
                .0
                .subkey
                .0
                .expect("password-change authenticator carries a subkey");
            let private: EncKrbPrivPart = picky_asn1_der::from_bytes(
                &cipher
                    .decrypt(
                        &subkey.0.key_value.0.0,
                        KRB_PRIV_ENC_PART,
                        &message.krb_priv.0.enc_part.0.cipher.0.0,
                    )
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(private.0.user_data.0.0, NEW_PASSWORD.as_bytes());
            self.inspected_password_requests.fetch_add(1, Ordering::SeqCst);
            Err(sspi::Error::new(ErrorKind::InternalError, INSPECTED))
        }
    }

    #[test]
    fn kerberos_change_password_uses_negotiated_salt_without_as_rep_hint() {
        let mut environment = environment_with_preauth_salt("password-change-negotiated-salt");
        let service_name = PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(
                ["kadmin", "changepw"]
                    .map(|s| KerberosStringAsn1::from(IA5String::from_string(s.to_owned()).unwrap()))
                    .to_vec(),
            )),
        };
        let service_key = vec![0x69; 32];
        environment.keys.insert(UserName(service_name), service_key.clone());
        let network = PasswordChangeRequestInspector {
            network: NetworkClientMock {
                kdc: KdcMock::new(
                    environment.realm,
                    environment.keys,
                    environment.users,
                    Validators::default(),
                )
                .omit_as_rep_etype_info2(),
            },
            service_key,
            as_requests: AtomicUsize::new(0),
            inspected_password_requests: AtomicUsize::new(0),
        };
        let mut client = Kerberos::new_client_from_config(KerberosConfig {
            kdc_resolution: KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap())),
            client_computer_name: CLIENT_COMPUTER_NAME.into(),
        })
        .unwrap();
        // change_password uses the context's previously resolved realm. Initialize it
        // through the public context API, stopping at the mocked transport boundary.
        let mut handle = Some(CredentialsBuffers::try_from(environment.credentials).unwrap());
        let mut input = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut setup_output = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut initialize = client
            .initialize_security_context()
            .with_credentials_handle(&mut handle)
            .with_context_requirements(ClientRequestFlags::empty())
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(&environment.target_name)
            .with_input(&mut input)
            .with_output(&mut setup_output);
        let setup_error = SspiImpl::initialize_security_context_impl(&mut client, &mut initialize)
            .unwrap()
            .resolve_with_client(&FailedNetworkClientMock {
                kind: ErrorKind::NoAuthenticatingAuthority,
            })
            .unwrap_err();
        assert_eq!(setup_error.description, "error from mock network client");
        assert_eq!(network.as_requests.load(Ordering::SeqCst), 0);
        let mut output = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let change = ChangePasswordBuilder::new()
            .with_domain_name("EXAMPLE.COM")
            .with_account_name("pw13")
            .with_old_password("qweQWE123!@#")
            .with_new_password(NEW_PASSWORD)
            .with_output(&mut output)
            .build()
            .unwrap();
        let error = Sspi::change_password(&mut client, change)
            .unwrap()
            .resolve_with_client(&network)
            .unwrap_err();
        assert_eq!(error.error_type, ErrorKind::InternalError);
        assert_eq!(error.description, INSPECTED);
        assert_eq!(network.as_requests.load(Ordering::SeqCst), 2);
        assert_eq!(network.inspected_password_requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn kerberos_u2u_server_acquires_tgt_with_password_without_as_rep_hint() {
        let KrbEnvironment {
            realm,
            credentials,
            keys,
            users,
            target_name,
            target_service_name,
        } = environment_with_preauth_salt("u2u-negotiated-salt");
        let as_requests = Arc::new(AtomicUsize::new(0));
        let as_counter = Arc::clone(&as_requests);
        let mut network = NetworkClientMock {
            kdc: KdcMock::new(
                realm,
                keys,
                users,
                Validators {
                    as_req: Box::new(move |_| {
                        as_counter.fetch_add(1, Ordering::SeqCst);
                    }),
                    tgs_req: Box::new(|request| {
                        assert_ne!(request.0.req_body.0.kdc_options.0.0.as_bytes()[4] & 0x08, 0);
                        assert_eq!(request.0.req_body.0.additional_tickets.0.as_ref().unwrap().0.0.len(), 1);
                    }),
                },
            )
            .omit_as_rep_etype_info2(),
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
                    authenticators_cache: HashSet::new(),
                },
            )
            .unwrap(),
        );
        let mut client_handle = Some(credentials.clone());
        let mut server_handle = Some(credentials);
        let client_flags = ClientRequestFlags::MUTUAL_AUTH
            | ClientRequestFlags::INTEGRITY
            | ClientRequestFlags::CONFIDENTIALITY
            | ClientRequestFlags::USE_SESSION_KEY;
        let server_flags = ServerRequestFlags::MUTUAL_AUTH
            | ServerRequestFlags::INTEGRITY
            | ServerRequestFlags::CONFIDENTIALITY
            | ServerRequestFlags::USE_SESSION_KEY;
        let (status, request) = initialize_security_context(
            &mut client,
            &mut client_handle,
            client_flags,
            &target_name,
            Vec::new(),
            &mut network,
        );
        assert_eq!(status, SecurityStatus::ContinueNeeded);
        KrbMessage::<TgtReq>::decode_application_krb_message(&request).expect("initial U2U TGT_REQ");
        assert_eq!(as_requests.load(Ordering::SeqCst), 0);
        let (status, response) =
            accept_security_context(&mut server, &mut server_handle, server_flags, request, &mut network);
        assert_eq!(status, SecurityStatus::ContinueNeeded);
        assert_eq!(
            as_requests.load(Ordering::SeqCst),
            2,
            "password-backed acceptor acquires its TGT"
        );
        KrbMessage::<TgtRep>::decode_application_krb_message(&response).expect("acceptor emits TGT_REP");
        let (status, request) = initialize_security_context(
            &mut client,
            &mut client_handle,
            client_flags,
            &target_name,
            response,
            &mut network,
        );
        assert_eq!(status, SecurityStatus::ContinueNeeded);
        let (server_status, response) =
            accept_security_context(&mut server, &mut server_handle, server_flags, request, &mut network);
        assert_eq!(server_status, SecurityStatus::Ok);
        let (status, final_token) = initialize_security_context(
            &mut client,
            &mut client_handle,
            client_flags,
            &target_name,
            response,
            &mut network,
        );
        assert_eq!(status, SecurityStatus::Ok);
        if !final_token.is_empty() {
            accept_security_context(&mut server, &mut server_handle, server_flags, final_token, &mut network);
        }
        assert_eq!(as_requests.load(Ordering::SeqCst), 4);
        test_encryption(&mut client, &mut server);
        test_stream_buffer_encryption(&mut client, &mut server);
        test_rpc_request_encryption(&mut client, &mut server);
    }
}
