#![allow(clippy::result_large_err)]

pub mod kdc;
pub mod network_client;

use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, IntegerAsn1};
use picky_krb::constants::types::{NT_PRINCIPAL, NT_SRV_INST};
use picky_krb::data_types::{KerberosStringAsn1, PrincipalName};
use sspi::network_client::NetworkClient;
use sspi::{
    string_to_utf16, AuthIdentityBuffers, BufferType, ClientRequestFlags, CredentialsBuffers, DataRepresentation,
    Kerberos, KerberosConfig, SecurityBuffer, Sspi, SspiImpl,
};
use url::Url;

use crate::client_server::kerberos::kdc::{KdcMock, PasswordCreds, UserName};
use crate::client_server::kerberos::network_client::NetworkClientMock;

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
    let kdc = KdcMock::new(realm.to_string(), keys, users);
    let mut network_client = NetworkClientMock { kdc };

    let kerberos_config = KerberosConfig {
        kdc_url: Some(Url::parse("tcp://192.168.1.103:88").unwrap()),
        client_computer_name: Some("DESKTOP-I7E8EFA.example.com".into()),
    };
    let mut kerberos_client = Kerberos::new_client_from_config(kerberos_config).unwrap();

    let mut credentials_handle = Some(CredentialsBuffers::AuthIdentity(AuthIdentityBuffers {
        user: string_to_utf16(username),
        domain: string_to_utf16(domain),
        password: string_to_utf16(user_password).into(),
    }));
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
