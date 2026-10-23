use picky::oids;
use picky_krb::gss_api::MechType;

use super::{Negotiate, NegotiateConfig, NegotiateState, NegotiatedProtocol};
use crate::ntlm::NtlmConfig;
use crate::{ErrorKind, KerberosConfig};

const COMPUTER_NAME: &str = "DESKTOP-3D83IAN.example.com";

fn client(protocol_config: NegotiateProtocolConfig, package_list: Option<&str>) -> Negotiate {
    let config = match protocol_config {
        NegotiateProtocolConfig::Kerberos => NegotiateConfig::new(
            Box::new(KerberosConfig {
                kdc_resolution: crate::KdcResolution::KdcUrl(None),
                client_computer_name: COMPUTER_NAME.to_owned(),
            }),
            package_list.map(str::to_owned),
            COMPUTER_NAME.to_owned(),
        ),
        NegotiateProtocolConfig::Ntlm => NegotiateConfig::new(
            Box::new(NtlmConfig::new(COMPUTER_NAME.to_owned())),
            package_list.map(str::to_owned),
            COMPUTER_NAME.to_owned(),
        ),
    };

    Negotiate::new_client(config).unwrap()
}

#[derive(Clone, Copy)]
enum NegotiateProtocolConfig {
    Kerberos,
    Ntlm,
}

fn remote_guard_client(protocol_config: NegotiateProtocolConfig) -> Negotiate {
    let mut negotiate = client(protocol_config, Some("kerberos,ntlm"));
    negotiate.enable_remote_guard().unwrap();
    negotiate
}

fn ntlm_mech() -> MechType {
    MechType::from(oids::ntlm_ssp())
}

#[test]
fn remote_guard_restricts_the_client_to_kerberos() {
    for protocol_config in [NegotiateProtocolConfig::Kerberos, NegotiateProtocolConfig::Ntlm] {
        let mut negotiate = remote_guard_client(protocol_config);

        assert!(negotiate.is_remote_guard());
        assert!(matches!(&negotiate.protocol, NegotiatedProtocol::Kerberos(kerberos) if kerberos.is_remote_guard()));
        assert!(negotiate.package_list.kerberos);
        assert!(!negotiate.package_list.ntlm);
        assert!(!negotiate.package_list.pku2u);

        assert!(!negotiate.can_downgrade_ntlm());
        assert!(!negotiate.fallback_to_ntlm());
        negotiate.check_target_name_for_ntlm_downgrade("TERMSRV/192.168.1.2");
        assert!(negotiate.protocol.is_kerberos());

        // Enabling it twice is harmless.
        negotiate.enable_remote_guard().unwrap();
        assert!(negotiate.protocol.is_kerberos());
    }
}

#[test]
fn remote_guard_cannot_be_enabled_for_incompatible_contexts() {
    let mut server = Negotiate::new_server(
        NegotiateConfig::new(
            Box::new(NtlmConfig::new(COMPUTER_NAME.to_owned())),
            None,
            COMPUTER_NAME.to_owned(),
        ),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        server.enable_remote_guard().unwrap_err().error_type,
        ErrorKind::UnsupportedFunction
    );
    assert!(!server.is_remote_guard());

    let mut no_kerberos = client(NegotiateProtocolConfig::Ntlm, Some("ntlm,!kerberos"));
    assert_eq!(
        no_kerberos.enable_remote_guard().unwrap_err().error_type,
        ErrorKind::InvalidParameter
    );
    assert!(!no_kerberos.is_remote_guard());
    assert!(no_kerberos.package_list.ntlm);

    for state in [
        NegotiateState::InProgress,
        NegotiateState::VerifyMic,
        NegotiateState::Ok,
    ] {
        let mut started = client(NegotiateProtocolConfig::Kerberos, None);
        started.state = state;
        assert_eq!(
            started.enable_remote_guard().unwrap_err().error_type,
            ErrorKind::OutOfSequence
        );
        assert!(!started.is_remote_guard());
        assert!(started.package_list.ntlm);
    }
}

#[test]
fn remote_guard_rejects_server_selected_ntlm() {
    let mut negotiate = remote_guard_client(NegotiateProtocolConfig::Kerberos);
    negotiate.mech_types =
        picky_asn1_der::to_vec(&super::generators::generate_mech_type_list(true, false, false).unwrap()).unwrap();

    let error = negotiate
        .negotiate_protocol_by_mech_type(&ntlm_mech(), None)
        .unwrap_err();
    assert_eq!(error.error_type, ErrorKind::InvalidToken);
    assert!(negotiate.protocol.is_kerberos());
    assert!(negotiate.package_list.kerberos);

    for mech in [oids::ms_krb5(), oids::krb5()] {
        negotiate
            .negotiate_protocol_by_mech_type(&MechType::from(mech), None)
            .unwrap();
        assert!(matches!(&negotiate.protocol, NegotiatedProtocol::Kerberos(kerberos) if kerberos.is_remote_guard()));
    }
}

#[test]
fn ntlm_selection_is_unchanged_without_remote_guard() {
    let mut negotiate = client(NegotiateProtocolConfig::Kerberos, None);
    negotiate.mech_types =
        picky_asn1_der::to_vec(&super::generators::generate_mech_type_list(true, false, true).unwrap()).unwrap();
    assert!(negotiate.can_downgrade_ntlm());

    negotiate.negotiate_protocol_by_mech_type(&ntlm_mech(), None).unwrap();
    assert!(matches!(negotiate.protocol, NegotiatedProtocol::Ntlm(_)));
    assert!(!negotiate.package_list.kerberos);
    assert!(negotiate.mic_needed);

    // The MIC requirement of remote credential guard does not apply.
    negotiate.mic_verified = false;
    negotiate.check_remote_guard_mic().unwrap();
}

#[test]
fn remote_guard_requires_a_verified_mech_list_mic() {
    let mut negotiate = remote_guard_client(NegotiateProtocolConfig::Kerberos);

    assert_eq!(
        negotiate.check_remote_guard_mic().unwrap_err().error_type,
        ErrorKind::MessageAltered
    );

    // A missing MIC is not a verified MIC.
    negotiate.verify_mic_token(None).unwrap();
    assert_eq!(
        negotiate.check_remote_guard_mic().unwrap_err().error_type,
        ErrorKind::MessageAltered
    );

    negotiate.mic_verified = true;
    negotiate.check_remote_guard_mic().unwrap();
}

#[test]
fn remote_guard_session_requires_an_established_remote_guard_context() {
    let mut regular = client(NegotiateProtocolConfig::Kerberos, None);
    regular.state = NegotiateState::Ok;
    assert_eq!(
        regular.take_remote_guard_session().unwrap_err().error_type,
        ErrorKind::UnsupportedFunction
    );

    let mut negotiate = remote_guard_client(NegotiateProtocolConfig::Kerberos);
    for state in [
        NegotiateState::Initial,
        NegotiateState::InProgress,
        NegotiateState::VerifyMic,
    ] {
        negotiate.state = state;
        assert_eq!(
            negotiate.take_remote_guard_session().unwrap_err().error_type,
            ErrorKind::OutOfSequence
        );
    }

    // The Negotiate exchange finished, but the Kerberos context did not.
    negotiate.state = NegotiateState::Ok;
    assert_eq!(
        negotiate.take_remote_guard_session().unwrap_err().error_type,
        ErrorKind::OutOfSequence
    );
}
