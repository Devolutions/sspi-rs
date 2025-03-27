use std::mem;

use sspi::credssp::{ClientMode, ClientState, CredSspClient, CredSspMode, CredSspServer, ServerState, TsRequest};
use sspi::ntlm::NtlmConfig;
use sspi::{AuthIdentity, Credentials, Secret, Username};

use crate::common::CredentialsProxyImpl;

#[test]
fn run_credssp() {
    let auth_identity = AuthIdentity {
        username: Username::parse("test_user").unwrap(),
        password: Secret::from("test_password".to_owned()),
    };
    let credentials = Credentials::AuthIdentity(auth_identity.clone());
    let public_key = [
        48, 130, 2, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 2, 15, 0, 48, 130, 2, 10, 2,
        130, 2, 1, 0, 153, 85, 210, 206, 231, 176, 16, 84, 146, 20, 255, 201, 74, 62, 122, 183, 157, 210, 202, 111, 17,
        50, 30, 181, 14, 13, 193, 242, 152, 41, 178, 93, 237, 151, 133, 122, 29, 233, 73, 139, 182, 23, 93, 149, 119,
        56, 5, 156, 180, 217, 84, 109, 88, 242, 117, 103, 167, 173, 81, 14, 171, 69, 18, 6, 149, 163, 35, 39, 128, 183,
        73, 157, 200, 229, 17, 156, 115, 197, 187, 141, 211, 156, 148, 207, 94, 14, 119, 210, 166, 59, 242, 214, 224,
        159, 51, 41, 55, 78, 250, 170, 175, 133, 213, 24, 173, 39, 234, 10, 216, 60, 238, 204, 157, 149, 186, 144, 203,
        231, 241, 239, 41, 118, 35, 14, 245, 183, 29, 229, 209, 198, 182, 174, 34, 66, 146, 20, 214, 109, 119, 19, 8,
        207, 231, 222, 119, 155, 192, 76, 15, 221, 210, 78, 132, 112, 33, 213, 87, 153, 25, 38, 190, 161, 178, 130,
        108, 140, 75, 75, 22, 74, 28, 0, 164, 72, 103, 14, 57, 202, 58, 91, 94, 235, 177, 68, 209, 252, 254, 173, 97,
        101, 156, 128, 139, 58, 140, 226, 73, 26, 232, 234, 178, 220, 193, 89, 196, 236, 89, 173, 235, 92, 39, 13, 1,
        0, 93, 43, 252, 89, 236, 123, 140, 108, 144, 215, 171, 46, 211, 144, 236, 202, 59, 87, 177, 225, 162, 70, 144,
        109, 113, 237, 2, 152, 115, 52, 166, 112, 249, 30, 53, 62, 239, 228, 226, 97, 56, 246, 27, 64, 43, 153, 195,
        79, 176, 38, 178, 188, 192, 207, 0, 179, 255, 17, 173, 250, 152, 140, 8, 198, 9, 2, 50, 151, 16, 176, 125, 175,
        161, 118, 185, 166, 34, 217, 189, 160, 27, 145, 91, 113, 71, 71, 220, 4, 195, 210, 242, 185, 14, 108, 61, 61,
        5, 45, 27, 38, 56, 245, 49, 55, 196, 230, 22, 8, 155, 27, 3, 79, 252, 108, 199, 189, 29, 98, 220, 118, 212, 5,
        0, 129, 59, 110, 131, 188, 159, 249, 56, 37, 69, 106, 185, 215, 38, 54, 36, 196, 28, 39, 81, 27, 255, 249, 155,
        197, 237, 125, 92, 147, 108, 248, 238, 115, 101, 170, 27, 203, 193, 180, 33, 146, 208, 216, 113, 174, 158, 84,
        100, 32, 200, 49, 30, 28, 31, 112, 247, 68, 190, 181, 247, 54, 117, 131, 215, 100, 13, 170, 52, 12, 137, 61,
        253, 114, 120, 116, 124, 238, 3, 234, 95, 242, 208, 224, 96, 132, 150, 152, 186, 81, 85, 50, 179, 216, 191,
        125, 25, 148, 232, 235, 234, 193, 150, 186, 41, 18, 38, 220, 144, 104, 97, 127, 215, 215, 49, 92, 81, 21, 232,
        67, 145, 164, 179, 156, 220, 175, 154, 70, 144, 218, 31, 106, 84, 78, 218, 238, 15, 29, 207, 34, 33, 68, 121,
        213, 114, 203, 80, 32, 42, 224, 115, 86, 161, 42, 78, 246, 183, 203, 213, 198, 110, 71, 22, 137, 164, 4, 163,
        206, 239, 57, 197, 112, 179, 191, 160, 5, 2, 3, 1, 0, 1,
    ];

    let mut client = CredSspClient::new(
        public_key.to_vec(),
        credentials.clone(),
        CredSspMode::WithCredentials,
        ClientMode::Ntlm(NtlmConfig {
            client_computer_name: Some("DESKTOP-3D83IAN.example.com".to_owned()),
        }),
        "TERMSRV/DESKTOP-8F33RFH.example.com".to_owned(),
    )
    .unwrap();
    let mut server = CredSspServer::new(
        public_key.to_vec(),
        CredentialsProxyImpl::new(&auth_identity),
        ClientMode::Ntlm(NtlmConfig {
            client_computer_name: Some("DESKTOP-3D83IAN.example.com".to_owned()),
        }),
    )
    .unwrap();

    let mut ts_request = TsRequest::default();

    for _ in 0..3 {
        ts_request = match client
            .process(mem::take(&mut ts_request))
            .resolve_with_default_network_client()
            .unwrap()
        {
            ClientState::ReplyNeeded(ts_request) => ts_request,
            ClientState::FinalMessage(ts_request) => ts_request,
        };

        match server.process(ts_request).unwrap() {
            ServerState::ReplyNeeded(server_ts_request) => ts_request = server_ts_request,
            ServerState::Finished(received_auth_identity) => {
                assert_eq!(auth_identity, received_auth_identity);
                return;
            }
        };
    }

    panic!("CredSSP authentication should not exceed 3 steps")
}
