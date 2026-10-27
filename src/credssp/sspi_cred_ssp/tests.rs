use super::*;
use crate::ntlm::{Ntlm, NtlmConfig};
use crate::{AuthIdentity, Kerberos, KerberosConfig, Negotiate, NegotiateConfig, Username};

const COMPUTER: &str = "synthetic.example.com";
const TARGET: &str = "TERMSRV/server.example.com";
const SENTINEL: &[u8] = b"unchanged output";

fn negotiate(package_list: Option<&str>) -> SspiContext {
    SspiContext::Negotiate(
        Negotiate::new_client(NegotiateConfig::new(
            Box::new(KerberosConfig {
                kdc_resolution: crate::KdcResolution::KdcUrl(None),
                client_computer_name: COMPUTER.to_owned(),
            }),
            package_list.map(str::to_owned),
            COMPUTER.to_owned(),
        ))
        .unwrap(),
    )
}

fn client(mode: CredSspMode) -> SspiCredSsp {
    SspiCredSsp::new_client_with_mode(negotiate(Some("kerberos,ntlm")), mode).unwrap()
}

fn initialize(
    client: &mut SspiCredSsp,
    flags: ClientRequestFlags,
    target: Option<&str>,
) -> (Result<InitializeSecurityContextResult>, ClientRequestFlags, Vec<u8>) {
    let mut credentials = None;
    let mut output = [SecurityBuffer::new(SENTINEL.to_vec(), BufferType::Token)];
    let mut builder = client
        .initialize_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(flags)
        .with_target_data_representation(DataRepresentation::Native)
        .with_output(&mut output);
    if let Some(target) = target {
        builder = builder.with_target_name(target);
    }
    let builder_ref = &mut builder;
    let result = GeneratorInitSecurityContext::new(|mut yield_point| async move {
        client
            .initialize_security_context_impl(&mut yield_point, builder_ref)
            .await
    })
    .resolve_to_result();
    let flags = builder.context_requirements;
    (result, flags, output[0].buffer.clone())
}

#[test]
fn sspi_credssp_new_client_defaults_to_with_credentials() {
    let mut client = SspiCredSsp::new_client(negotiate(None)).unwrap();
    assert_eq!(client.cred_ssp_mode, CredSspMode::WithCredentials);
    let (result, flags, output) = initialize(&mut client, ClientRequestFlags::empty(), Some(TARGET));
    assert_eq!(result.unwrap().status, SecurityStatus::ContinueNeeded);
    assert_eq!(flags, ClientRequestFlags::DELEGATE | ClientRequestFlags::MUTUAL_AUTH);
    assert_eq!(output[0], 0x16);
    assert!(client.tls_connection.is_some());
}

#[test]
fn sspi_credssp_new_client_with_mode_accepts_credential_less_and_remote_guard() {
    for mode in [CredSspMode::CredentialLess, CredSspMode::RemoteGuard] {
        let client = client(mode);
        assert_eq!(client.cred_ssp_mode, mode);
        assert_eq!(client.state, CredSspState::Tls);
        assert!(client.target_name.is_none());
        assert!(client.tls_connection.is_none());
        let SspiContext::Negotiate(negotiate) = &client.cred_ssp_context.sspi_context else {
            panic!("expected Negotiate")
        };
        assert_eq!(negotiate.is_remote_guard(), mode == CredSspMode::RemoteGuard);
    }
}

#[test]
fn sspi_credssp_remote_guard_rejects_non_negotiate_contexts_before_tls() {
    let ntlm = SspiContext::Ntlm(Ntlm::with_config(NtlmConfig::new(COMPUTER.to_owned())));
    let kerberos = SspiContext::Kerberos(
        Kerberos::new_client_from_config(KerberosConfig {
            kdc_resolution: crate::KdcResolution::KdcUrl(None),
            client_computer_name: COMPUTER.to_owned(),
        })
        .unwrap(),
    );
    for context in [ntlm, kerberos] {
        assert_eq!(
            SspiCredSsp::new_client_with_mode(context, CredSspMode::RemoteGuard)
                .unwrap_err()
                .error_type,
            ErrorKind::UnsupportedFunction
        );
    }
    let server = Negotiate::new_server(
        NegotiateConfig::new(
            Box::new(NtlmConfig::new(COMPUTER.to_owned())),
            None,
            COMPUTER.to_owned(),
        ),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        SspiCredSsp::new_client_with_mode(SspiContext::Negotiate(server), CredSspMode::RemoteGuard)
            .unwrap_err()
            .error_type,
        ErrorKind::UnsupportedFunction
    );
}

#[test]
fn sspi_credssp_remote_guard_rejects_started_negotiate_before_tls() {
    let mut negotiate = Negotiate::new_client(NegotiateConfig::new(
        Box::new(NtlmConfig::new(COMPUTER.to_owned())),
        Some("kerberos,ntlm".to_owned()),
        COMPUTER.to_owned(),
    ))
    .unwrap();
    let mut credentials = Some(CredentialsBuffers::AuthIdentity(
        AuthIdentity {
            username: Username::parse("synthetic").unwrap(),
            password: "synthetic password".to_owned().into(),
        }
        .into(),
    ));
    let mut output = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let mut builder = negotiate
        .initialize_security_context()
        .with_credentials_handle(&mut credentials)
        .with_context_requirements(ClientRequestFlags::empty())
        .with_target_data_representation(DataRepresentation::Native)
        .with_target_name(TARGET)
        .with_output(&mut output);
    let result = SspiImpl::initialize_security_context_impl(&mut negotiate, &mut builder)
        .unwrap()
        .resolve_to_result()
        .unwrap();
    assert_eq!(result.status, SecurityStatus::ContinueNeeded);
    assert!(!output[0].buffer.is_empty());
    assert_eq!(
        SspiCredSsp::new_client_with_mode(SspiContext::Negotiate(negotiate), CredSspMode::RemoteGuard)
            .unwrap_err()
            .error_type,
        ErrorKind::OutOfSequence
    );
}

#[test]
fn sspi_credssp_remote_guard_rejects_kerberos_disabled_negotiate_before_tls() {
    assert_eq!(
        SspiCredSsp::new_client_with_mode(negotiate(Some("ntlm,!kerberos")), CredSspMode::RemoteGuard)
            .unwrap_err()
            .error_type,
        ErrorKind::InvalidParameter
    );
}

#[test]
fn sspi_credssp_no_delegate_modes_reject_delegate_before_tls_or_output() {
    for mode in [CredSspMode::CredentialLess, CredSspMode::RemoteGuard] {
        for state in [
            CredSspState::Tls,
            CredSspState::NegoToken,
            CredSspState::AuthInfo,
            CredSspState::Final,
        ] {
            let mut client = client(mode);
            client.state = state;
            let (result, flags, output) = initialize(&mut client, ClientRequestFlags::DELEGATE, Some(TARGET));
            assert_eq!(result.unwrap_err().error_type, ErrorKind::InvalidParameter);
            assert_eq!(flags, ClientRequestFlags::DELEGATE);
            assert_eq!(output, SENTINEL);
            assert!(client.target_name.is_none());
            assert!(client.tls_connection.is_none());
            assert_eq!(client.state, state);
        }
    }
}

#[test]
fn sspi_credssp_request_flags_are_mode_specific() {
    for mode in [
        CredSspMode::WithCredentials,
        CredSspMode::CredentialLess,
        CredSspMode::RemoteGuard,
    ] {
        let mut client = client(mode);
        let unrelated = ClientRequestFlags::ALLOCATE_MEMORY;
        let (result, flags, output) = initialize(&mut client, unrelated, Some(TARGET));
        assert_eq!(result.unwrap().status, SecurityStatus::ContinueNeeded);
        let expected = unrelated
            | ClientRequestFlags::MUTUAL_AUTH
            | match mode {
                CredSspMode::WithCredentials => ClientRequestFlags::DELEGATE,
                CredSspMode::CredentialLess => ClientRequestFlags::empty(),
                CredSspMode::RemoteGuard => {
                    ClientRequestFlags::USE_SESSION_KEY
                        | ClientRequestFlags::INTEGRITY
                        | ClientRequestFlags::CONFIDENTIALITY
                        | ClientRequestFlags::REPLAY_DETECT
                        | ClientRequestFlags::SEQUENCE_DETECT
                }
            };
        assert_eq!(flags, expected, "{mode:?}");
        assert_eq!(output[0], 0x16);
        assert_eq!(client.target_name.as_deref(), Some(TARGET));
    }
}

#[test]
fn sspi_credssp_ntlm_redirection_is_pre_start_and_remote_guard_only() {
    for mode in [CredSspMode::WithCredentials, CredSspMode::CredentialLess] {
        assert_eq!(
            client(mode).enable_remote_guard_ntlm(None).unwrap_err().error_type,
            ErrorKind::UnsupportedFunction
        );
    }
    let mut client = client(CredSspMode::RemoteGuard);
    assert_eq!(
        client
            .enable_remote_guard_ntlm(Some(rcg::NtlmRedirectionNames {
                user: String::new(),
                domain: "EXAMPLE".to_owned(),
            }))
            .unwrap_err()
            .error_type,
        ErrorKind::InvalidParameter
    );
    assert!(client.remote_guard_ntlm.is_none());
    client.enable_remote_guard_ntlm(None).unwrap();
    client
        .enable_remote_guard_ntlm(Some(rcg::NtlmRedirectionNames {
            user: "synthetic".to_owned(),
            domain: "EXAMPLE".to_owned(),
        }))
        .unwrap();
    assert!(client.remote_guard_ntlm.is_some());
    initialize(&mut client, ClientRequestFlags::empty(), Some(TARGET))
        .0
        .unwrap();
    assert_eq!(
        client.enable_remote_guard_ntlm(None).unwrap_err().error_type,
        ErrorKind::OutOfSequence
    );
    // Target capture alone closes the policy window, even if no TLS context exists.
    client.tls_connection = None;
    assert_eq!(
        client.enable_remote_guard_ntlm(None).unwrap_err().error_type,
        ErrorKind::OutOfSequence
    );
}

#[test]
fn sspi_credssp_session_handoff_rejects_non_remote_guard_and_nonfinal_states() {
    for mode in [CredSspMode::WithCredentials, CredSspMode::CredentialLess] {
        assert_eq!(
            client(mode).take_remote_guard_session().unwrap_err().error_type,
            ErrorKind::UnsupportedFunction
        );
    }
    let mut client = client(CredSspMode::RemoteGuard);
    for state in [CredSspState::Tls, CredSspState::NegoToken, CredSspState::AuthInfo] {
        client.state = state;
        assert_eq!(
            client.take_remote_guard_session().unwrap_err().error_type,
            ErrorKind::OutOfSequence
        );
        assert_eq!(client.state, state);
    }
}

#[test]
fn sspi_credssp_target_guards_precede_tls_output_and_final_state() {
    let mut client = client(CredSspMode::RemoteGuard);
    let (result, _, output) = initialize(&mut client, ClientRequestFlags::empty(), None);
    assert_eq!(result.unwrap_err().error_type, ErrorKind::NoCredentials);
    assert_eq!(output, SENTINEL);
    assert!(client.target_name.is_none());
    assert!(client.tls_connection.is_none());
    client.target_name = Some(TARGET.to_owned());
    for state in [
        CredSspState::Tls,
        CredSspState::NegoToken,
        CredSspState::AuthInfo,
        CredSspState::Final,
    ] {
        client.state = state;
        for target in [
            "TERMSRV/other.example.com",
            "HOST/server.example.com",
            "termsrv/server.example.com",
            "TERMSRV/SERVER.EXAMPLE.COM",
            "",
        ] {
            let (result, _, output) = initialize(&mut client, ClientRequestFlags::empty(), Some(target));
            assert_eq!(result.unwrap_err().error_type, ErrorKind::InvalidParameter);
            assert_eq!(output, SENTINEL);
            assert_eq!(client.target_name.as_deref(), Some(TARGET));
            assert_eq!(client.state, state);
            assert!(client.tls_connection.is_none());
        }
    }

    for target in [None, Some(TARGET)] {
        let (result, _, output) = initialize(&mut client, ClientRequestFlags::empty(), target);
        assert_eq!(result.unwrap_err().error_type, ErrorKind::OutOfSequence);
        assert_eq!(output, SENTINEL);
    }
}

#[test]
fn sspi_credssp_identity_changes_are_pre_start_only_for_remote_guard() {
    let original = Credentials::from(AuthIdentity {
        username: Username::parse("EXAMPLE\\original").unwrap(),
        password: "original synthetic password".to_owned().into(),
    });
    let replacement = Credentials::from(AuthIdentity {
        username: Username::parse("OTHER\\replacement").unwrap(),
        password: "different synthetic password".to_owned().into(),
    });
    let original_buffers = CredentialsBuffers::try_from(original.clone()).unwrap();
    let replacement_buffers = CredentialsBuffers::try_from(replacement.clone()).unwrap();
    for mode in [
        CredSspMode::RemoteGuard,
        CredSspMode::CredentialLess,
        CredSspMode::WithCredentials,
    ] {
        for (state, captured_target, has_tls) in [
            (CredSspState::Tls, true, false),
            (CredSspState::Tls, false, true),
            (CredSspState::Tls, true, true),
            (CredSspState::NegoToken, false, false),
            (CredSspState::AuthInfo, false, false),
            (CredSspState::Final, false, false),
        ] {
            for acquire in [false, true] {
                let mut client = client(mode);
                client.custom_set_auth_identity(original.clone()).unwrap();
                if mode == CredSspMode::RemoteGuard {
                    client
                        .enable_remote_guard_ntlm(Some(rcg::NtlmRedirectionNames {
                            user: "bound-original".to_owned(),
                            domain: "BOUND".to_owned(),
                        }))
                        .unwrap();
                }
                if has_tls {
                    let (result, _, _) = initialize(&mut client, ClientRequestFlags::empty(), Some(TARGET));
                    assert_eq!(result.unwrap().status, SecurityStatus::ContinueNeeded);
                }
                // Isolate each disjunct of the pre-start guard, including TLS without a captured SPN.
                client.state = state;
                client.target_name = captured_target.then(|| TARGET.to_owned());
                let policy = client.remote_guard_ntlm.as_ref().map(|policy| policy.names.clone());
                let nonce = client.nonce;
                assert_eq!(client.auth_identity.as_ref(), Some(&original_buffers));

                let result = if acquire {
                    client
                        .acquire_credentials_handle()
                        .with_credential_use(CredentialUse::Outbound)
                        .with_auth_data(&replacement)
                        .execute(&mut client)
                        .map(|_| ())
                } else {
                    client.custom_set_auth_identity(replacement.clone())
                };
                let expected = if mode == CredSspMode::RemoteGuard {
                    assert_eq!(result.unwrap_err().error_type, ErrorKind::OutOfSequence);
                    &original_buffers
                } else {
                    result.unwrap();
                    &replacement_buffers
                };
                assert_eq!(client.auth_identity.as_ref(), Some(expected));
                let SspiContext::Negotiate(negotiate) = &client.cred_ssp_context.sspi_context else {
                    panic!("expected Negotiate")
                };
                let negotiate::NegotiatedProtocol::Kerberos(kerberos) = negotiate.negotiated_protocol() else {
                    panic!("expected Kerberos")
                };
                assert_eq!(kerberos.auth_identity.as_ref(), Some(expected));
                assert_eq!(negotiate.is_remote_guard(), mode == CredSspMode::RemoteGuard);
                assert_eq!(client.cred_ssp_mode, mode);
                assert_eq!(client.state, state);
                assert_eq!(client.target_name.as_deref(), captured_target.then_some(TARGET));
                assert_eq!(client.tls_connection.is_some(), has_tls);
                assert_eq!(client.nonce, nonce);
                assert_eq!(
                    client.remote_guard_ntlm.as_ref().map(|policy| policy.names.clone()),
                    policy
                );
            }
        }
    }
}
