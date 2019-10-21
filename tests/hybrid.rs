#![cfg(windows)]

pub mod common;

use common::{
    check_messages_encryption, create_client_credentials_handle, create_server_credentials_handle,
    process_authentication_without_complete, set_identity_and_try_complete_authentication,
    try_complete_authentication, CredentialsProxyImpl, CREDENTIALS,
};
use sspi::{winapi, Ntlm};

#[test]
fn successful_ntlm_authentication_with_winapi_client_and_non_winapi_server() {
    let mut credentials_proxy = CredentialsProxyImpl::new(&*CREDENTIALS);

    let mut client = winapi::Ntlm::new();
    let client_credentials_handle =
        create_client_credentials_handle(&mut client, Some(&*CREDENTIALS)).unwrap();

    let mut server = Ntlm::new();
    let server_credentials_handle = create_server_credentials_handle(&mut server).unwrap();

    let (client_status, server_status) = process_authentication_without_complete(
        &mut client,
        client_credentials_handle,
        &mut server,
        server_credentials_handle,
    )
    .unwrap();
    try_complete_authentication(&mut client, client_status).unwrap();
    set_identity_and_try_complete_authentication(
        &mut server,
        server_status,
        &mut credentials_proxy,
    )
    .unwrap();

    check_messages_encryption(&mut client, &mut server).unwrap();
}
