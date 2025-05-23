#![allow(clippy::result_large_err)]

pub mod kdc;
pub mod network_client;

use std::collections::HashMap;
use std::panic;

use kdc::Validators;
use picky::oids;
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, IntegerAsn1, ObjectIdentifierAsn1,
    OctetStringAsn1, Optional,
};
use picky_asn1_der::Asn1RawDer;
use picky_krb::constants::types::{NT_PRINCIPAL, NT_SRV_INST};
use picky_krb::data_types::{KerberosStringAsn1, PrincipalName};
use picky_krb::gss_api::{ApplicationTag0, GssApiNegInit, KrbMessage, MechType, NegTokenTarg, NegTokenTarg1};
use picky_krb::messages::TgtReq;
use rand::rngs::OsRng;
use rand::Rng;
use sspi::network_client::NetworkClient;
use sspi::{
    string_to_utf16, AuthIdentityBuffers, BufferType, ClientRequestFlags, CredentialsBuffers, DataRepresentation,
    Kerberos, KerberosConfig, SecurityBuffer, Sspi, SspiImpl,
};
use url::Url;

use crate::client_server::kerberos::kdc::{KdcMock, PasswordCreds, UserName};
use crate::client_server::kerberos::network_client::NetworkClientMock;

/// Represents a Kerberos environment:
/// * user and services keys;
/// * user logon credentials;
/// * realm and target application service name;
///
/// It is used for simplifying tests environment preparation.
struct KrbEnvironment {
    keys: HashMap<UserName, Vec<u8>>,
    users: HashMap<UserName, PasswordCreds>,
    credentials: CredentialsBuffers,
    realm: String,
    target_name: String,
}

/// Initializes a Kerberos environment. It includes:
/// * User logon credentials (password-based).
/// * Kerberos services keys.
/// * Target machine name.
fn init_krb_environment() -> KrbEnvironment {
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

    let credentials = CredentialsBuffers::AuthIdentity(AuthIdentityBuffers {
        user: string_to_utf16(username),
        domain: string_to_utf16(domain),
        password: string_to_utf16(user_password).into(),
    });

    KrbEnvironment {
        keys,
        users,
        realm: realm.to_string(),
        credentials,
        target_name,
    }
}

/// Does all preparations and calls the [initialize_security_context_impl] function
/// on the provided Kerberos context.
pub fn initialize_security_context(
    kerberos: &mut Kerberos,
    credentials_handle: &mut Option<CredentialsBuffers>,
    flags: ClientRequestFlags,
    target_name: &str,
    in_token: Vec<u8>,
    network_client: &mut dyn NetworkClient,
) -> Vec<u8> {
    let mut input_token = [SecurityBuffer::new(in_token, BufferType::Token)];
    let mut output_token = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];

    let mut builder = kerberos
        .initialize_security_context()
        .with_credentials_handle(credentials_handle)
        .with_context_requirements(flags)
        .with_target_data_representation(DataRepresentation::Native)
        .with_target_name(target_name)
        .with_input(&mut input_token)
        .with_output(&mut output_token);
    kerberos
        .initialize_security_context_impl(&mut builder)
        .expect("Kerberos initialize_security_context should not fail")
        .resolve_with_client(network_client)
        .expect("Kerberos initialize_security_context should not fail");

    output_token.remove(0).buffer
}

#[test]
fn kerberos_kdc_auth() {
    let KrbEnvironment {
        realm,
        credentials,
        keys,
        users,
        target_name,
    } = init_krb_environment();

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

                let kdc_options = tgs_req.0.req_body.kdc_options.0 .0.as_bytes();
                // enc-tkt-in-skey must be disabled.
                assert_eq!(kdc_options[4], 0x00, "some unneeded KDC options are enabled");

                let additional_tickets = tgs_req
                    .0
                    .req_body
                    .0
                    .additional_tickets
                    .0
                    .as_ref()
                    .map(|additional_tickets| additional_tickets.0 .0.as_slice());
                assert!(
                    matches!(additional_tickets, None | Some(&[])),
                    "TgsReq should not contain any additional tickets"
                );
            }),
        },
    );
    let mut network_client = NetworkClientMock { kdc };

    let kerberos_config = KerberosConfig {
        kdc_url: Some(Url::parse("tcp://192.168.1.103:88").unwrap()),
        client_computer_name: Some("DESKTOP-I7E8EFA.example.com".into()),
    };
    let mut kerberos_client = Kerberos::new_client_from_config(kerberos_config).unwrap();

    let mut credentials_handle = Some(credentials);
    let flags = ClientRequestFlags::MUTUAL_AUTH
        | ClientRequestFlags::INTEGRITY
        | ClientRequestFlags::SEQUENCE_DETECT
        | ClientRequestFlags::REPLAY_DETECT
        | ClientRequestFlags::CONFIDENTIALITY;

    initialize_security_context(
        &mut kerberos_client,
        &mut credentials_handle,
        flags,
        &target_name,
        Vec::new(),
        &mut network_client,
    );
    initialize_security_context(
        &mut kerberos_client,
        &mut credentials_handle,
        flags,
        &target_name,
        Vec::new(),
        &mut network_client,
    );
}

#[test]
fn kerberos_kdc_u2u_auth() {
    let KrbEnvironment {
        realm,
        credentials,
        keys,
        users,
        target_name,
    } = init_krb_environment();

    let kdc = KdcMock::new(
        realm,
        keys,
        users,
        Validators {
            as_req: Box::new(|_as_req| {
                // Nothing to validate in AsReq.
            }),
            tgs_req: Box::new(|tgs_req| {
                // Here, we should check that the Kerberos client successfully negotiated Kerberos U2U auth.

                let kdc_options = tgs_req.0.req_body.kdc_options.0 .0.as_bytes();
                // KDC options must have enc-tkt-in-skey enabled.
                assert_eq!(kdc_options[4], 0x08, "the enc-tkt-in-skey KDC option is not enabled");

                if let Some(tickets) = tgs_req.0.req_body.0.additional_tickets.0.as_ref() {
                    assert!(
                        !tickets.0 .0.is_empty(),
                        "TgsReq must have at least one additional ticket: TGT from the application service"
                    );
                } else {
                    panic!("TgsReq must have at least one additional ticket: TGT from the application service");
                }
            }),
        },
    );
    let mut network_client = NetworkClientMock { kdc };

    let kerberos_config = KerberosConfig {
        kdc_url: Some(Url::parse("tcp://192.168.1.103:88").unwrap()),
        client_computer_name: Some("DESKTOP-I7E8EFA.example.com".into()),
    };
    let mut kerberos_client = Kerberos::new_client_from_config(kerberos_config).unwrap();

    let mut credentials_handle = Some(credentials);
    let flags = ClientRequestFlags::MUTUAL_AUTH
        | ClientRequestFlags::INTEGRITY
        | ClientRequestFlags::USE_SESSION_KEY // Kerberos U2U auth
        | ClientRequestFlags::SEQUENCE_DETECT
        | ClientRequestFlags::REPLAY_DETECT
        | ClientRequestFlags::CONFIDENTIALITY;

    let token = initialize_security_context(
        &mut kerberos_client,
        &mut credentials_handle,
        flags,
        &target_name,
        Vec::new(),
        &mut network_client,
    );

    // Extract TGT request from token returned by the Kerberos client.
    let token: ApplicationTag0<GssApiNegInit> =
        picky_asn1_der::from_bytes(&token).expect("Kerberos client should return valid ASN1 data");
    let encoded_tgt_req = token
        .0
        .neg_token_init
        .0
        .mech_token
        .0
        .expect("GssApiNegInit mech_token should present")
        .0
         .0;
    let neg_token_init = KrbMessage::<TgtReq>::decode_application_krb_message(&encoded_tgt_req)
        .expect("neg_token_init contains invalid mech_token");
    let tgt_req = neg_token_init.0.krb_msg;

    // Generate TGT ticket.
    let tgt_rep = network_client
        .kdc
        .generate_tgt(tgt_req, OsRng.gen::<[u8; 32]>().as_slice());
    let neg_token_targ1 = NegTokenTarg1::from(NegTokenTarg {
        // accept-incomplete (1)
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(vec![10, 1, 1])))),
        supported_mech: Optional::from(Some(ExplicitContextTag1::from(MechType::from(oids::ms_krb5())))),
        response_token: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(
            picky_asn1_der::to_vec(&ApplicationTag0(KrbMessage {
                krb5_oid: ObjectIdentifierAsn1::from(oids::krb5_user_to_user()),
                // TGT rep
                krb5_token_id: [0x04, 0x01],
                krb_msg: tgt_rep,
            }))
            .expect("asn1 serialization should not fail"),
        )))),
        mech_list_mic: Optional::from(None),
    });

    initialize_security_context(
        &mut kerberos_client,
        &mut credentials_handle,
        flags,
        &target_name,
        picky_asn1_der::to_vec(&neg_token_targ1).expect("ASN1 serialization should not fail"),
        &mut network_client,
    );
}
