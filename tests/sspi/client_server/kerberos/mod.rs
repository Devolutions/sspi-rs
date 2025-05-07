pub mod kdc;
pub mod network_client;
pub mod tests;

use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, IntegerAsn1};
use picky_krb::data_types::{KerberosStringAsn1, PrincipalName};
use sspi::network_client::NetworkClient;
use sspi::{
    string_to_utf16, AuthIdentityBuffers, BufferType, ClientRequestFlags, CredentialsBuffers, DataRepresentation,
    Kerberos, KerberosConfig, SecurityBuffer, Sspi, SspiImpl,
};
use url::Url;

use crate::client_server::kerberos::kdc::{KdcMock, PasswordCreds, UserName};
use crate::client_server::kerberos::network_client::NetworkClientMock;

pub fn initialize_security_context(
    kerberos: &mut Kerberos,
    credentials_handle: &mut Option<CredentialsBuffers>,
    target_name: &str,
    in_token: Vec<u8>,
    network_client: &mut dyn NetworkClient,
) -> Vec<u8> {
    let mut input_token = [SecurityBuffer::new(in_token, BufferType::Token)];
    let mut output_token = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];

    let mut builder = kerberos
        .initialize_security_context()
        .with_credentials_handle(credentials_handle)
        .with_context_requirements(
            ClientRequestFlags::MUTUAL_AUTH
                | ClientRequestFlags::INTEGRITY
                | ClientRequestFlags::SEQUENCE_DETECT
                | ClientRequestFlags::REPLAY_DETECT
                | ClientRequestFlags::CONFIDENTIALITY,
        )
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
fn regular_kerberos_auth() {
    let tgt_service_key = vec![
        199, 133, 201, 239, 57, 139, 61, 128, 71, 236, 217, 130, 250, 148, 117, 193, 197, 86, 155, 11, 92, 124, 232,
        146, 0, 14, 158, 220, 113, 63, 110, 230,
    ];
    let keys = [
        (
            UserName(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![2])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string("krbtgt".into()).unwrap()),
                    KerberosStringAsn1::from(IA5String::from_string("EXAMPLE".into()).unwrap()),
                ])),
            }),
            tgt_service_key.clone(),
        ),
        (
            UserName(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![2])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string("krbtgt".into()).unwrap()),
                    KerberosStringAsn1::from(IA5String::from_string("EXAMPLE.COM".into()).unwrap()),
                ])),
            }),
            tgt_service_key,
        ),
    ]
    .into_iter()
    .collect();
    let users = [(
        UserName(PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![1])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![KerberosStringAsn1::from(
                IA5String::from_string("pw13".into()).unwrap(),
            )])),
        }),
        PasswordCreds {
            password: b"qweQWE123!@#".to_vec(),
            salt: "EXAMPLE.COMpw13".into(),
        },
    )]
    .into_iter()
    .collect();
    let kdc = KdcMock::new("EXAMPLE.COM".into(), keys, users);
    let mut network_client = NetworkClientMock { kdc };

    let kerberos_config = KerberosConfig {
        kdc_url: Some(Url::parse("tcp://192.168.1.103:88").unwrap()),
        client_computer_name: Some("DESKTOP-I7E8EFA.example.com".into()),
    };
    let mut kerberos_client = Kerberos::new_client_from_config(kerberos_config).unwrap();

    let mut credentials_handle = Some(CredentialsBuffers::AuthIdentity(AuthIdentityBuffers {
        user: string_to_utf16("pw13"),
        domain: string_to_utf16("EXAMPLE"),
        password: string_to_utf16("qweQWE123!@#").into(),
    }));

    initialize_security_context(
        &mut kerberos_client,
        &mut credentials_handle,
        "TERMSRV/DESKTOP-8F33RFH.example.com",
        Vec::new(),
        &mut network_client,
    );
    let token = initialize_security_context(
        &mut kerberos_client,
        &mut credentials_handle,
        "TERMSRV/DESKTOP-8F33RFH.example.com",
        Vec::new(),
        &mut network_client,
    );
    println!("{:?}", token);
}
