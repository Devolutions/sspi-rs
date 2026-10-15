use oid::ObjectIdentifier;
use picky::oids;
use picky_krb::gss_api::{ApplicationTag0, GssApiNegInit, MechTypeList, NegTokenInit};

use crate::ntlm::NtlmConfig;
use crate::{CredentialsBuffers, Error, ErrorKind, Negotiate, NegotiatedProtocol, Ntlm};

/// Extract TGT request and mech types from the first token returned by the Kerberos client.
#[instrument(ret, level = "trace")]
pub(super) fn decode_initial_neg_init(data: &[u8]) -> crate::Result<(Option<Vec<u8>>, MechTypeList)> {
    let token: ApplicationTag0<GssApiNegInit> = picky_asn1_der::from_bytes(data)?;
    let NegTokenInit {
        mech_types,
        req_flags: _,
        mech_token,
        mech_list_mic: _,
    } = token.0.neg_token_init.0;

    let mech_types = mech_types
        .0
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidToken,
                "mech_types is missing in GssApiNegInit message",
            )
        })?
        .0;

    let token = mech_token.0.map(|token| token.0.0);

    Ok((token, mech_types))
}

/// Selects the preferred authentication protocol OID based on the provided protocols list, allowed protocols,
/// and available protocols.
///
/// The Kerberos protocol will be selected only if it is allowed in the package list, its OID is present in the mech types,
/// and the internal protocol is configured to Kerberos. We cannot _just_ configure it from env vars as we do it for
/// the client-side Kerberos because the server-side Kerberos requires many configuration fields.
///
/// 1.2.840.48018.1.2.2 (MS KRB5 - Microsoft Kerberos 5) is preferred over 1.2.840.113554.1.2.2 (KRB5 - Kerberos 5).
///
/// 1.2.840.113554.1.2.2.3 (KRB5 U2U) is selected when it is the client's first choice and the acceptor can complete
/// U2U.
/// The client's `mechToken` belongs to its first choice (here a `TGT-REQ`), and selecting another mechanism drops it.
/// FreeRDP offers `[krb5-u2u, krb5, ntlm]`, which used to select `krb5`.
pub(super) fn negotiate_mech_type(
    mech_list: &MechTypeList,
    negotiate: &mut Negotiate,
) -> crate::Result<(ObjectIdentifier, usize)> {
    // U2U needs a password or a keytab for the acceptor's own TGT (`ServerProperties::user`).
    // Without them the exchange fails after the mechanism is committed and cannot be recovered.
    if mech_list
        .0
        .first()
        .is_some_and(|mech_type| mech_type.0 == oids::krb5_user_to_user())
        && negotiate.package_list.kerberos
        && let NegotiatedProtocol::Kerberos(kerberos) = &negotiate.protocol
        && kerberos.server.as_ref().is_some_and(|server| {
            matches!(
                server.user,
                Some(CredentialsBuffers::AuthIdentity(_) | CredentialsBuffers::Keytab(_))
            )
        })
    {
        return Ok((oids::krb5_user_to_user(), 0));
    }

    let ms_krb5 = oids::ms_krb5();
    if let Some(mech_index) = mech_list.0.iter().position(|mech_type| mech_type.0 == ms_krb5)
        && negotiate.package_list.kerberos
        && negotiate.protocol.is_kerberos()
    {
        return Ok((ms_krb5, mech_index));
    }

    let krb5 = oids::krb5();
    if let Some(mech_index) = mech_list.0.iter().position(|mech_type| mech_type.0 == krb5)
        && negotiate.package_list.kerberos
        && negotiate.protocol.is_kerberos()
    {
        return Ok((krb5, mech_index));
    }

    let ntlm_oid = oids::ntlm_ssp();
    if let Some(mech_index) = mech_list.0.iter().position(|mech_type| mech_type.0 == ntlm_oid)
        && negotiate.package_list.ntlm
    {
        if let NegotiatedProtocol::Kerberos(kerberos) = &mut negotiate.protocol {
            // Negotiate is configured to use Kerberos, but only NTLM is possible (fallback to NTLM).
            negotiate.protocol = NegotiatedProtocol::Ntlm(Ntlm::with_config(NtlmConfig {
                client_computer_name: Some(kerberos.config.client_computer_name.clone()),
            }));
        }

        return Ok((ntlm_oid, mech_index));
    }

    Err(Error::new(
        ErrorKind::InvalidToken,
        "no supported authentication protocols found in mech list",
    ))
}

#[cfg(test)]
mod tests {
    use picky_krb::gss_api::MechType;
    use url::Url;

    use super::*;
    use crate::auth_identity::AuthIdentityBuffers;
    use crate::generator::GeneratorState;
    use crate::kerberos::KerberosState;
    use crate::kerberos::test_data::{TGT_REQ_TOKEN_WITH_REALM, fake_server};
    use crate::negotiate::generators::generate_neg_token_init;
    use crate::negotiate::{NegotiateMode, NegotiateState, PackageListConfig};
    use crate::{
        AcceptSecurityContextResult, BufferType, DataRepresentation, SecurityBuffer, SecurityStatus,
        ServerRequestFlags, Sspi, SspiImpl,
    };

    fn mech_list(oids: &[ObjectIdentifier]) -> MechTypeList {
        MechTypeList::from(oids.iter().cloned().map(MechType::from).collect::<Vec<_>>())
    }

    /// Kerberos acceptor. `with_user` gives it the credentials for U2U.
    fn kerberos_acceptor(with_user: bool, kerberos: bool) -> Negotiate {
        let mut protocol = fake_server();
        if with_user {
            protocol
                .server
                .as_mut()
                .expect("fake_server has server properties")
                .user = Some(CredentialsBuffers::AuthIdentity(AuthIdentityBuffers::default()));
        }

        Negotiate {
            state: NegotiateState::default(),
            protocol: NegotiatedProtocol::Kerberos(protocol),
            package_list: PackageListConfig {
                ntlm: true,
                kerberos,
                pku2u: false,
            },
            auth_identity: None,
            client_computer_name: "acceptor".to_owned(),
            mode: NegotiateMode::Server(Vec::new()),
            mech_types: Vec::new(),
            mic_verified: false,
            mic_needed: true,
            authorizes_externally: false,
        }
    }

    /// The list FreeRDP offers.
    fn winpr_mech_list() -> MechTypeList {
        mech_list(&[oids::krb5_user_to_user(), oids::krb5(), oids::ntlm_ssp()])
    }

    #[test]
    fn u2u_is_selected_when_it_is_the_clients_first_choice() {
        let mut negotiate = kerberos_acceptor(true, true);

        let (oid, index) = negotiate_mech_type(&winpr_mech_list(), &mut negotiate).unwrap();

        assert_eq!(oid, oids::krb5_user_to_user());
        assert_eq!(index, 0, "the client's optimistic token belongs to its first choice");
    }

    #[test]
    fn u2u_is_not_selected_by_an_acceptor_that_cannot_complete_it() {
        let mut negotiate = kerberos_acceptor(false, true);

        let (oid, index) = negotiate_mech_type(&winpr_mech_list(), &mut negotiate).unwrap();

        assert_eq!(oid, oids::krb5());
        assert_eq!(index, 1);
    }

    #[test]
    fn u2u_is_not_selected_when_kerberos_is_disabled() {
        let mut negotiate = kerberos_acceptor(true, false);

        let (oid, index) = negotiate_mech_type(&winpr_mech_list(), &mut negotiate).unwrap();

        assert_eq!(oid, oids::ntlm_ssp());
        assert_eq!(index, 2);
    }

    /// U2U in any other position changes nothing.
    #[test]
    fn u2u_offered_after_another_mechanism_changes_nothing() {
        let mut negotiate = kerberos_acceptor(true, true);

        let list = mech_list(&[oids::ms_krb5(), oids::krb5(), oids::krb5_user_to_user()]);
        let (oid, index) = negotiate_mech_type(&list, &mut negotiate).unwrap();
        assert_eq!((oid, index), (oids::ms_krb5(), 0));

        let list = mech_list(&[oids::krb5(), oids::krb5_user_to_user()]);
        let (oid, index) = negotiate_mech_type(&list, &mut negotiate).unwrap();
        assert_eq!((oid, index), (oids::krb5(), 0));
    }

    #[test]
    fn ms_krb5_is_still_preferred_over_krb5() {
        let mut negotiate = kerberos_acceptor(true, true);
        let list = mech_list(&[oids::krb5(), oids::ms_krb5(), oids::ntlm_ssp()]);

        let (oid, index) = negotiate_mech_type(&list, &mut negotiate).unwrap();

        assert_eq!((oid, index), (oids::ms_krb5(), 1));
    }

    /// Sends a FreeRDP-style first token to the acceptor.
    ///
    /// Returns `None` when the acceptor went to the KDC for its own TGT, and the outcome otherwise.
    fn accept_first_token(negotiate: &mut Negotiate) -> Option<crate::Result<AcceptSecurityContextResult>> {
        let NegotiatedProtocol::Kerberos(kerberos) = &mut negotiate.protocol else {
            panic!("a Kerberos acceptor is expected");
        };
        kerberos.state = KerberosState::TgtExchange;
        kerberos.kdc_url = Some(Url::parse("tcp://192.168.1.103:88").unwrap());
        negotiate.state = NegotiateState::Initial;

        let token = picky_asn1_der::to_vec(
            &generate_neg_token_init(winpr_mech_list(), Some(TGT_REQ_TOKEN_WITH_REALM.to_vec())).unwrap(),
        )
        .unwrap();

        let mut credentials_handle = None;
        let mut input = [SecurityBuffer::new(token, BufferType::Token)];
        let mut output = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let builder = negotiate
            .accept_security_context()
            .with_credentials_handle(&mut credentials_handle)
            .with_context_requirements(ServerRequestFlags::USE_SESSION_KEY)
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut input)
            .with_output(&mut output);
        let mut generator = SspiImpl::accept_security_context_impl(negotiate, builder).unwrap();

        match generator.start() {
            GeneratorState::Suspended(_) => None,
            GeneratorState::Completed(result) => Some(result),
        }
    }

    #[test]
    fn a_freerdp_first_token_is_answered_with_the_acceptors_own_tgt_request() {
        let mut negotiate = kerberos_acceptor(true, true);

        let outcome = accept_first_token(&mut negotiate);

        assert!(outcome.is_none(), "{outcome:?}");
    }

    #[test]
    fn a_freerdp_first_token_does_not_reach_the_kdc_without_u2u_credentials() {
        let mut negotiate = kerberos_acceptor(false, true);

        let outcome = accept_first_token(&mut negotiate);

        // The acceptor drops the `mechToken` and answers with its own choice of mechanism instead of failing.
        let result = outcome.expect("the acceptor must not reach the KDC").unwrap();
        assert_eq!(result.status, SecurityStatus::ContinueNeeded);
    }
}
