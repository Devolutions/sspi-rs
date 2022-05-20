#![cfg(windows)]

pub mod common;

use common::{
    check_messages_encryption, create_client_credentials_handle, create_server_credentials_handle,
    process_authentication_without_complete, try_complete_authentication,
};
use sspi::winapi::{Ntlm, SecurityPackage};
use sspi::{enumerate_security_packages, AuthIdentity, SecurityPackageType, Sspi};

const NEGOTIATE_SECURITY_PACKAGE_NAME: &str = "Negotiate";

#[test]
fn successful_ntlm_authentication_without_client_auth_data() {
    let mut client = Ntlm::new();
    let client_credentials_handle = create_client_credentials_handle(&mut client, None).unwrap();

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
    try_complete_authentication(&mut server, server_status).unwrap();

    check_messages_encryption(&mut client, &mut server).unwrap();
}

#[test]
fn ntlm_authentication_fails_with_invalid_client_auth_data() {
    let credentials = AuthIdentity {
        username: whoami::username(),
        password: String::from("InvalidPassword"),
        domain: Some(whoami::hostname()),
    };

    let mut client = Ntlm::new();
    let client_credentials_handle = create_client_credentials_handle(&mut client, Some(&credentials)).unwrap();

    let mut server = Ntlm::new();
    let server_credentials_handle = create_server_credentials_handle(&mut server).unwrap();

    assert!(process_authentication_without_complete(
        &mut client,
        client_credentials_handle,
        &mut server,
        server_credentials_handle,
    )
    .is_err());
}

#[test]
fn successful_negotiate_authentication_without_client_auth_data() {
    let mut client = SecurityPackage::from_package_type(SecurityPackageType::Other(String::from(
        NEGOTIATE_SECURITY_PACKAGE_NAME,
    )));
    let client_credentials_handle = create_client_credentials_handle(&mut client, None).unwrap();

    let mut server = SecurityPackage::from_package_type(SecurityPackageType::Other(String::from(
        NEGOTIATE_SECURITY_PACKAGE_NAME,
    )));
    let server_credentials_handle = create_server_credentials_handle(&mut server).unwrap();

    let (client_status, server_status) = process_authentication_without_complete(
        &mut client,
        client_credentials_handle,
        &mut server,
        server_credentials_handle,
    )
    .unwrap();
    try_complete_authentication(&mut client, client_status).unwrap();
    try_complete_authentication(&mut server, server_status).unwrap();

    let package_info = client.query_context_package_info().unwrap();
    println!("Security package name: {:?}", package_info.name);

    check_messages_encryption(&mut client, &mut server).unwrap();
}

#[test]
fn enumerate_security_packages_returns_some_packages() {
    let packages = enumerate_security_packages().unwrap();

    assert!(!packages.is_empty());
}
