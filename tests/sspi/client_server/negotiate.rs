use sspi::builders::{AcquireCredentialsHandle, WithoutCredentialUse};
use sspi::credssp::SspiContext;
use sspi::ntlm::NtlmConfig;
use sspi::{
    AcquireCredentialsHandleResult, AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, Credentials,
    DataRepresentation, ErrorKind, InitializeSecurityContextResult, Negotiate, NegotiateConfig, Secret, SecurityBuffer,
    SecurityStatus, ServerRequestFlags, ServerResponseFlags, Sspi, Username,
};

use crate::client_server::{TARGET_NAME, test_encryption, test_rpc_request_encryption, test_stream_buffer_encryption};

const CLIENT_COMPUTER_NAME: &str = "DESKTOP-IHPPQ95.example.com";

fn run_spnego_ntlm(target_name: Option<&str>, username: &str, password: &str, mic_expected: bool) {
    let ntlm_config = NtlmConfig {
        client_computer_name: Some(CLIENT_COMPUTER_NAME.to_owned()),
    };
    let credentials = Credentials::AuthIdentity(AuthIdentity {
        username: Username::parse(username).unwrap(),
        password: Secret::from(password.to_owned()),
    });

    let mut client = SspiContext::Negotiate(
        Negotiate::new_client(NegotiateConfig::new(
            Box::new(ntlm_config.clone()),
            Some(String::from("ntlm,!kerberos")),
            CLIENT_COMPUTER_NAME.into(),
        ))
        .unwrap(),
    );
    let mut server = SspiContext::Negotiate(
        Negotiate::new_server(
            NegotiateConfig::new(
                Box::new(ntlm_config),
                Some(String::from("ntlm,!kerberos")),
                "WIN-956CQOSSJTF.example.com".into(),
            ),
            vec![credentials.to_auth_identity().unwrap()],
        )
        .unwrap(),
    );

    let builder = AcquireCredentialsHandle::<'_, _, _, WithoutCredentialUse>::new();
    let AcquireCredentialsHandleResult {
        credentials_handle: mut client_credentials_handle,
        ..
    } = builder
        .with_auth_data(&credentials)
        .with_credential_use(CredentialUse::Outbound)
        .execute(&mut client)
        .unwrap();

    let builder = AcquireCredentialsHandle::<'_, _, _, WithoutCredentialUse>::new();
    let AcquireCredentialsHandleResult {
        credentials_handle: mut server_credentials_handle,
        ..
    } = builder
        .with_auth_data(&credentials)
        .with_credential_use(CredentialUse::Inbound)
        .execute(&mut server)
        .unwrap();

    let mut input_token = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let mut output_token = [SecurityBuffer::new(Vec::new(), BufferType::Token)];

    for _ in 0..4 {
        let mut builder = client
            .initialize_security_context()
            .with_credentials_handle(&mut client_credentials_handle)
            .with_context_requirements(
                ClientRequestFlags::MUTUAL_AUTH
                    | ClientRequestFlags::USE_SESSION_KEY
                    | ClientRequestFlags::INTEGRITY
                    | ClientRequestFlags::CONFIDENTIALITY,
            )
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut input_token)
            .with_output(&mut output_token);
        builder.target_name = target_name;
        let InitializeSecurityContextResult { status, .. } =
            client.initialize_security_context_sync(&mut builder).unwrap();

        input_token[0].buffer.clear();

        if !output_token[0].buffer.is_empty() {
            let builder = server
                .accept_security_context()
                .with_credentials_handle(&mut server_credentials_handle)
                .with_context_requirements(ServerRequestFlags::empty())
                .with_target_data_representation(DataRepresentation::Native)
                .with_input(&mut output_token)
                .with_output(&mut input_token);
            server.accept_security_context_sync(builder).unwrap();

            output_token[0].buffer.clear();
        }

        if status == SecurityStatus::Ok {
            let negotiate_client = match &client {
                SspiContext::Negotiate(negotiate) => negotiate,
                _ => unreachable!(),
            };
            assert_eq!(negotiate_client.mic_needed(), mic_expected);

            let negotiate_server = match &server {
                SspiContext::Negotiate(negotiate) => negotiate,
                _ => unreachable!(),
            };
            assert_eq!(negotiate_server.mic_needed(), mic_expected);

            test_encryption(&mut client, &mut server);
            test_stream_buffer_encryption(&mut client, &mut server);
            test_rpc_request_encryption(&mut client, &mut server);

            return;
        }
    }

    panic!("SPNEGO authentication should not exceed 4 steps")
}

fn run_spnego_null_session(server_flags: ServerRequestFlags) -> Result<(SspiContext, SspiContext), ErrorKind> {
    run_spnego_null_session_steps(&[ClientRequestFlags::NULL_SESSION; 3], &[server_flags; 3])
}

fn run_spnego_null_session_steps(
    client_flags: &[ClientRequestFlags; 3],
    server_flags: &[ServerRequestFlags; 3],
) -> Result<(SspiContext, SspiContext), ErrorKind> {
    let ntlm_config = NtlmConfig {
        client_computer_name: Some(CLIENT_COMPUTER_NAME.to_owned()),
    };
    let anonymous_credentials = Credentials::AuthIdentity(AuthIdentity {
        username: Username::parse("").unwrap(),
        password: Secret::from(String::new()),
    });
    let negotiate_config = |hostname: &str| {
        NegotiateConfig::new(
            Box::new(ntlm_config.clone()),
            Some(String::from("ntlm,!kerberos")),
            hostname.into(),
        )
    };
    let mut client = SspiContext::Negotiate(Negotiate::new_client(negotiate_config(CLIENT_COMPUTER_NAME)).unwrap());
    let mut server = SspiContext::Negotiate(
        Negotiate::new_server(negotiate_config("WIN-956CQOSSJTF.example.com"), Vec::new()).unwrap(),
    );

    let AcquireCredentialsHandleResult {
        credentials_handle: mut client_credentials_handle,
        ..
    } = AcquireCredentialsHandle::<'_, _, _, WithoutCredentialUse>::new()
        .with_auth_data(&anonymous_credentials)
        .with_credential_use(CredentialUse::Outbound)
        .execute(&mut client)
        .unwrap();
    let AcquireCredentialsHandleResult {
        credentials_handle: mut server_credentials_handle,
        ..
    } = AcquireCredentialsHandle::<'_, _, _, WithoutCredentialUse>::new()
        .with_credential_use(CredentialUse::Inbound)
        .execute(&mut server)
        .unwrap();

    let mut server_token = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let mut client_token = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
    for step in 0..3 {
        let mut client_builder = client
            .initialize_security_context()
            .with_credentials_handle(&mut client_credentials_handle)
            .with_context_requirements(client_flags[step])
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut server_token)
            .with_output(&mut client_token);
        client_builder.target_name = Some(TARGET_NAME);
        let client_result = client
            .initialize_security_context_sync(&mut client_builder)
            .map_err(|error| error.error_type)?;
        server_token[0].buffer.clear();

        let server_builder = server
            .accept_security_context()
            .with_credentials_handle(&mut server_credentials_handle)
            .with_context_requirements(server_flags[step])
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut client_token)
            .with_output(&mut server_token);
        let server_result = match server.accept_security_context_sync(server_builder) {
            Ok(result) => result,
            Err(error) => return Err(error.error_type),
        };
        client_token[0].buffer.clear();

        if client_result.status == SecurityStatus::Ok {
            assert_eq!(server_result.status, SecurityStatus::Ok);
            assert!(client_result.flags.contains(sspi::ClientResponseFlags::NULL_SESSION));
            assert!(server_result.flags.contains(ServerResponseFlags::NULL_SESSION));
            return Ok((client, server));
        }
    }

    panic!("Negotiate NULL-session authentication should not exceed 3 steps")
}

#[test]
fn spnego_ntlm_client_server() {
    run_spnego_ntlm(Some(TARGET_NAME), "test_user@example.com", "test_password", true);
}

#[test]
fn spnego_ntlm_guest_logon() {
    run_spnego_ntlm(Some(TARGET_NAME), "/GUEST", "", false);
}

#[test]
fn spnego_ntlm_without_target_name() {
    run_spnego_ntlm(None, "test_user@example.com", "test_password", true);
}

#[test]
fn spnego_ntlm_null_session_is_explicitly_opted_in() {
    let (mut client, mut server) = run_spnego_null_session(ServerRequestFlags::ALLOW_NULL_SESSION).unwrap();
    super::test_null_session_security(&mut client);
    super::test_null_session_security(&mut server);
}

#[test]
fn spnego_ntlm_null_session_is_rejected_by_default() {
    assert_eq!(
        run_spnego_null_session(ServerRequestFlags::empty()).unwrap_err(),
        ErrorKind::LogonDenied
    );
}

#[test]
fn spnego_null_session_cannot_bypass_acceptor_security_policy() {
    for requirement in [
        ServerRequestFlags::INTEGRITY,
        ServerRequestFlags::CONFIDENTIALITY,
        ServerRequestFlags::REPLAY_DETECT,
        ServerRequestFlags::SEQUENCE_DETECT,
        ServerRequestFlags::MUTUAL_AUTH,
        ServerRequestFlags::DELEGATE,
        ServerRequestFlags::USE_SESSION_KEY,
        ServerRequestFlags::USE_DCE_STYLE,
    ] {
        assert_eq!(
            run_spnego_null_session(ServerRequestFlags::ALLOW_NULL_SESSION | requirement).unwrap_err(),
            ErrorKind::LogonDenied
        );
    }
}

#[test]
fn spnego_null_session_checks_requirements_on_subsequent_calls() {
    let allowed = ServerRequestFlags::ALLOW_NULL_SESSION;
    for changed in [
        ClientRequestFlags::empty(),
        ClientRequestFlags::NULL_SESSION | ClientRequestFlags::INTEGRITY,
    ] {
        assert_eq!(
            run_spnego_null_session_steps(&[ClientRequestFlags::NULL_SESSION, changed, changed], &[allowed; 3])
                .unwrap_err(),
            ErrorKind::InvalidParameter
        );
    }
    for changed in [
        ServerRequestFlags::empty(),
        allowed | ServerRequestFlags::CONFIDENTIALITY,
    ] {
        assert_eq!(
            run_spnego_null_session_steps(&[ClientRequestFlags::NULL_SESSION; 3], &[allowed, changed, changed])
                .unwrap_err(),
            ErrorKind::LogonDenied
        );
    }
}
