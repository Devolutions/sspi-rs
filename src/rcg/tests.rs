//! Remote Credential Guard tests.
//!
//! All keys, tickets and KDC replies are synthetic. The sequence numbers of
//! `context_continues_native_credssp_sequence_into_rdpear` are the sequence numbers observed in a capture of a
//! native Windows Remote Credential Guard connection, but the token contents are not native.

use md5::{Digest as _, Md5};
use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag8,
    ExplicitContextTag9, ExplicitContextTag10, GeneralizedTimeAsn1, OctetStringAsn1, Optional,
};
use picky_krb::constants::error_codes::KDC_ERR_S_PRINCIPAL_UNKNOWN;
use picky_krb::constants::key_usages::KRB_CRED_ENC_PART;
use picky_krb::constants::types::{KRB_CRED_MSG_TYPE, NT_PRINCIPAL, NT_SRV_HST, NT_SRV_INST};
use picky_krb::credssp::{TsCredentials, TsRemoteGuardCreds};
use picky_krb::crypto::aes::{AesSize, checksum_sha_aes};
use picky_krb::data_types::{
    Authenticator, AuthenticatorInner, AuthorizationData, AuthorizationDataInner, Checksum, EncApRepPart,
    EncApRepPartInner, EncKrbCredPart, EncryptedData, KerberosFlags, KerberosStringAsn1, KerberosTime, LastReqInner,
    TicketInner,
};
use picky_krb::messages::{
    ApRep, ApRepInner, ApReq, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, KdcRep, KdcReqBody, KrbCred, KrbError,
    KrbErrorInner, TgsRep, TgsReq,
};
use rand_core::SeedableRng as _;
use time::OffsetDateTime;
use url::Url;

use super::key_store::KeyRole;
use super::logon::{
    KERB_LOGON_FLAG_REDIRECTED, KERB_TICKET_LOGON_HEADER_LEN, KERB_TICKET_LOGON_MESSAGE_TYPE, TgsReply,
    build_kerb_ticket_logon, build_ts_credentials, process_tgs_rep,
};
use super::ntlm::{NtlmCredential, compute_ntlm3_response, current_filetime, nt_owf};
use super::wrap::{MAX_SEQUENCE_NUMBER, SEAL_OVERHEAD, Sender};
use super::*;
use crate::generator::{Generator, GeneratorState, NetworkRequest};
use crate::kerberos::client::generators::nonce_to_asn1;
use crate::kerberos::test_data::{fake_client, fake_server};
use crate::private::Sealed;
use crate::{
    AuthIdentityBuffers, CredentialsBuffers, EncryptionFlags, Sspi as _, SspiEx as _, Utf16String, ZeroizedUtf16String,
};

const REALM: &str = "EXAMPLE.COM";
const USER: &str = "alice";
const TARGET: &str = "TERMSRV/server.example.com";
const HOST: &str = "server.example.com";
const KDC_URL: &str = "tcp://kdc.example.com:88";

const AES256: i32 = 18;
const AES128: i32 = 17;
const RC4: u8 = 23;

const HOME_TGT_KEY: [u8; 32] = [0x11; 32];
const SERVICE_TGT_KEY: [u8; 32] = [0x22; 32];
const CONTEXT_KEY: [u8; 32] = [0x33; 32];
const FORWARDED_TGT_KEY: [u8; 32] = [0x44; 32];
const COMPUTER_TICKET_KEY: [u8; 32] = [0x55; 32];
const SERVICE_KEY: [u8; 32] = [0x66; 32];
const SERVER_SUBKEY: [u8; 32] = [0x77; 32];
const NEW_TICKET_KEY: [u8; 32] = [0x88; 32];

/// First byte of the (fake) encrypted part of each ticket, used to tell the tickets apart.
const HOME_TGT_MARKER: u8 = 0xA1;
const SERVICE_TGT_MARKER: u8 = 0xA2;
const COMPUTER_TICKET_MARKER: u8 = 0xB1;
const FORWARDED_TGT_MARKER: u8 = 0xB2;

/// Key usages (RFC 4120 7.5.1).
const USAGE_TGS_REQ_CHECKSUM: i32 = 6;
const USAGE_TGS_REQ_AUTHENTICATOR: i32 = 7;
const USAGE_TGS_REP_SESSION_KEY: i32 = 8;
const USAGE_TGS_REP_SUB_KEY: i32 = 9;
const USAGE_AP_REQ_AUTHENTICATOR: i32 = 11;
const USAGE_AP_REP: i32 = 12;

const AES256_SUITE: CipherSuite = CipherSuite::Aes256CtsHmacSha196;

fn kind<T>(result: crate::Result<T>) -> ErrorKind {
    match result {
        Ok(_) => panic!("the operation unexpectedly succeeded"),
        Err(error) => error.error_type,
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn fixed_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
}

fn kerberos_time(time: OffsetDateTime) -> KerberosTime {
    KerberosTime::from(GeneralizedTime::from(time))
}

fn kerberos_string(value: &str) -> KerberosStringAsn1 {
    KerberosStringAsn1::from(IA5String::from_string(value.to_owned()).unwrap())
}

fn realm(name: &str) -> Realm {
    Realm::from(IA5String::from_string(name.to_owned()).unwrap())
}

fn principal(name_type: u8, names: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![name_type])),
        name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(
            names.iter().map(|name| kerberos_string(name)).collect::<Vec<_>>(),
        )),
    }
}

fn user() -> PrincipalName {
    principal(NT_PRINCIPAL, &[USER])
}

fn krbtgt() -> PrincipalName {
    principal(NT_SRV_INST, &["krbtgt", REALM])
}

fn computer() -> PrincipalName {
    principal(NT_SRV_HST, &["HOST", HOST])
}

fn binding() -> ClientBinding {
    ClientBinding {
        name: user(),
        realm: REALM.to_owned(),
    }
}

fn encryption_key(etype: u8, value: &[u8]) -> EncryptionKey {
    EncryptionKey {
        key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![etype])),
        key_value: ExplicitContextTag1::from(OctetStringAsn1::from(value.to_vec())),
    }
}

fn encrypted_data(etype: u8, cipher: Vec<u8>) -> EncryptedData {
    EncryptedData {
        etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![etype])),
        kvno: Optional::from(None),
        cipher: ExplicitContextTag2::from(OctetStringAsn1::from(cipher)),
    }
}

fn encrypt_der(key: &[u8], usage: i32, plaintext: &[u8]) -> Vec<u8> {
    let cipher = AES256_SUITE.cipher().encrypt(key, usage, plaintext).unwrap();
    picky_asn1_der::to_vec(&encrypted_data(18, cipher)).unwrap()
}

fn decrypt_der(key: &[u8], usage: i32, encrypted: &[u8]) -> Vec<u8> {
    let encrypted: EncryptedData = picky_asn1_der::from_bytes(encrypted).unwrap();
    assert_eq!(encrypted.etype.0, IntegerAsn1::from(vec![18]));
    AES256_SUITE
        .cipher()
        .decrypt(key, usage, &encrypted.cipher.0.0)
        .unwrap()
}

fn ticket(sname: PrincipalName, marker: u8) -> Ticket {
    Ticket::from(TicketInner {
        tkt_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
        realm: ExplicitContextTag1::from(realm(REALM)),
        sname: ExplicitContextTag2::from(sname),
        enc_part: ExplicitContextTag3::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
            kvno: Optional::from(Some(ExplicitContextTag1::from(IntegerAsn1::from(vec![2])))),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(vec![marker; 48])),
        }),
    })
}

fn ticket_marker(ticket: &Ticket) -> u8 {
    ticket.0.enc_part.0.cipher.0.0[0]
}

fn captured_tgt(key: [u8; 32], marker: u8) -> CapturedTgt {
    CapturedTgt::new(
        REALM.to_owned(),
        ticket(krbtgt(), marker),
        AES256_SUITE,
        Secret::new(key.to_vec()),
    )
    .unwrap()
}

fn state_with_tgts() -> RemoteGuardState {
    RemoteGuardState {
        home_tgt: Some(captured_tgt(HOME_TGT_KEY, HOME_TGT_MARKER)),
        service_tgt: Some(captured_tgt(SERVICE_TGT_KEY, SERVICE_TGT_MARKER)),
        binding: Some(binding()),
        ..RemoteGuardState::default()
    }
}

fn context_subkey() -> EncryptionKey {
    encryption_key(18, &CONTEXT_KEY)
}

fn established_state(next_send_seq: u64, next_recv_seq: u64) -> RemoteGuardState {
    let mut state = state_with_tgts();
    state
        .establish_context(Some(&context_subkey()), next_send_seq, next_recv_seq)
        .unwrap();
    state
}

fn state_sequence_numbers(state: &RemoteGuardState) -> (u64, u64) {
    state.context.as_ref().unwrap().sequence_numbers()
}

fn session(next_send_seq: u64, next_recv_seq: u64) -> RemoteGuardSession {
    let mut state = established_state(next_send_seq, next_recv_seq);
    state.mark_logon_built();
    state.into_session(Duration::ZERO).unwrap()
}

struct KeyedSession {
    session: RemoteGuardSession,
    tgt_handle: Vec<u8>,
    service_handle: Vec<u8>,
}

fn session_with_keys() -> KeyedSession {
    session_with_keys_at(1000, 2000)
}

fn session_with_keys_at(next_send_seq: u64, next_recv_seq: u64) -> KeyedSession {
    let mut state = established_state(next_send_seq, next_recv_seq);
    let mut rng = StdRng::seed_from_u64(7);
    let tgt_handle = state
        .key_store
        .insert(
            AES256_SUITE,
            Secret::new(FORWARDED_TGT_KEY.to_vec()),
            KeyRole::TicketGranting,
            &mut rng,
        )
        .unwrap();
    let service_handle = state
        .key_store
        .insert(
            AES256_SUITE,
            Secret::new(SERVICE_KEY.to_vec()),
            KeyRole::Service,
            &mut rng,
        )
        .unwrap();
    state.mark_logon_built();

    KeyedSession {
        session: state.into_session(Duration::ZERO).unwrap(),
        tgt_handle,
        service_handle,
    }
}

fn key_ref(value: &[u8]) -> KeyReference<'_> {
    KeyReference {
        encryption_type: AES256,
        value,
    }
}

/// A token sealed by the server (acceptor) with the context key.
fn server_seal(seq_number: u64, plaintext: &[u8]) -> Vec<u8> {
    wrap::seal(&AES256_SUITE, &CONTEXT_KEY, Sender::Acceptor, seq_number, plaintext).unwrap()
}

/// Unseals, as the server, a token sealed by the client (initiator).
fn server_unseal(seq_number: u64, token: &[u8]) -> Vec<u8> {
    wrap::unseal(&AES256_SUITE, &CONTEXT_KEY, Sender::Initiator, seq_number, token)
        .unwrap()
        .to_vec()
}

fn kerberos_encrypt(kerberos: &mut Kerberos, plaintext: &[u8]) -> crate::Result<Vec<u8>> {
    let mut token = [0; 1024];
    let mut data = plaintext.to_vec();
    let mut message = [
        SecurityBufferRef::token_buf(token.as_mut_slice()),
        SecurityBufferRef::data_buf(data.as_mut_slice()),
    ];

    kerberos.encrypt_message(EncryptionFlags::empty(), &mut message)?;

    let mut wrapped = message[0].data().to_vec();
    wrapped.extend_from_slice(message[1].data());
    Ok(wrapped)
}

fn kerberos_decrypt(kerberos: &mut Kerberos, token: &[u8]) -> crate::Result<Vec<u8>> {
    let (header, body) = token.split_at(SEAL_OVERHEAD);
    let mut header = header.to_vec();
    let mut body = body.to_vec();
    let mut message = [
        SecurityBufferRef::token_buf(header.as_mut_slice()),
        SecurityBufferRef::data_buf(body.as_mut_slice()),
    ];

    kerberos.decrypt_message(&mut message)?;

    Ok(message[1].data().to_vec())
}

fn rcg_client() -> Kerberos {
    let mut kerberos = fake_client();
    kerberos.realm = Some(REALM.to_owned());
    kerberos.config.kdc_resolution = crate::KdcResolution::KdcUrl(Some(Url::parse(KDC_URL).unwrap()));
    kerberos.remote_guard = Some(Box::new(established_state(1000, 2000)));
    kerberos
}

fn rcg_state(kerberos: &Kerberos) -> &RemoteGuardState {
    kerberos.remote_guard.as_deref().unwrap()
}

fn kdc_req_body() -> Vec<u8> {
    picky_asn1_der::to_vec(&KdcReqBody {
        kdc_options: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(vec![
            0x40, 0x81, 0x00, 0x00,
        ]))),
        cname: Optional::from(None),
        realm: ExplicitContextTag2::from(realm(REALM)),
        sname: Optional::from(Some(ExplicitContextTag3::from(principal(
            NT_SRV_INST,
            &["cifs", "fs.example.com"],
        )))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(fixed_time()))),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(IntegerAsn1::from(vec![0x12, 0x34])),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![IntegerAsn1::from(vec![18])])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    })
    .unwrap()
}

fn authorization_data() -> Vec<u8> {
    picky_asn1_der::to_vec(&AuthorizationData::from(vec![AuthorizationDataInner {
        ad_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![1])),
        ad_data: ExplicitContextTag1::from(OctetStringAsn1::from(vec![0x30, 0x00])),
    }]))
    .unwrap()
}

fn gss_checksum() -> Vec<u8> {
    picky_asn1_der::to_vec(&Checksum {
        cksumtype: ExplicitContextTag0::from(IntegerAsn1::from(vec![0x00, 0x80, 0x03])),
        checksum: ExplicitContextTag1::from(OctetStringAsn1::from(vec![0x10; 24])),
    })
    .unwrap()
}

fn enc_kdc_rep_part(key: EncryptionKey, nonce: IntegerAsn1, flags: &[u8], sname: PrincipalName) -> EncKdcRepPart {
    let time = kerberos_time(fixed_time());

    EncKdcRepPart {
        key: ExplicitContextTag0::from(key),
        last_req: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![LastReqInner {
            lr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0])),
            lr_value: ExplicitContextTag1::from(time.clone()),
        }])),
        nonce: ExplicitContextTag2::from(nonce),
        key_expiration: Optional::from(None),
        flags: ExplicitContextTag4::from(KerberosFlags::from(BitString::with_bytes(flags.to_vec()))),
        auth_time: ExplicitContextTag5::from(time.clone()),
        start_time: Optional::from(Some(ExplicitContextTag6::from(time))),
        end_time: ExplicitContextTag7::from(kerberos_time(fixed_time() + Duration::hours(10))),
        renew_till: Optional::from(None),
        srealm: ExplicitContextTag9::from(realm(REALM)),
        sname: ExplicitContextTag10::from(sname),
        caddr: Optional::from(None),
        encrypted_pa_data: Optional::from(None),
    }
}

fn enc_ap_rep_part() -> Vec<u8> {
    picky_asn1_der::to_vec(&EncApRepPart::from(EncApRepPartInner {
        ctime: ExplicitContextTag0::from(kerberos_time(fixed_time())),
        cusec: ExplicitContextTag1::from(IntegerAsn1::from(vec![0x01, 0x02])),
        subkey: Optional::from(Some(ExplicitContextTag2::from(encryption_key(18, &[0x99; 32])))),
        seq_number: Optional::from(Some(ExplicitContextTag3::from(IntegerAsn1::from(vec![0x05])))),
    }))
    .unwrap()
}

/// A synthetic `KRB_AP_REP` template for an RDPEAR `PackApReply` request.
fn ap_rep_template(pvno: Vec<u8>, msg_type: Vec<u8>, enc_part: EncryptedData) -> Vec<u8> {
    picky_asn1_der::to_vec(&ApRep::from(ApRepInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(pvno)),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(msg_type)),
        enc_part: ExplicitContextTag2::from(enc_part),
    }))
    .unwrap()
}

fn valid_ap_rep_template() -> Vec<u8> {
    ap_rep_template(vec![5], vec![15], encrypted_data(0, Vec::new()))
}

#[test]
fn context_continues_native_credssp_sequence_into_rdpear() {
    // Sequence numbers of a native connection: the server's SPNEGO mechListMIC uses 39321546, its pubKeyAuth
    // follows, and its first RDPEAR token uses 39321548. The capture has 164 RDPEAR request/response pairs:
    // server 39321548..=39321711, client 137625793..=137625956.
    const CLIENT_FIRST_SEQ: u64 = 137_625_790;
    const SERVER_FIRST_SEQ: u64 = 39_321_546;
    const RDPEAR_PAIRS: u64 = 164;

    let mut kerberos = fake_client();
    kerberos.remote_guard = Some(Box::new(established_state(CLIENT_FIRST_SEQ, SERVER_FIRST_SEQ)));

    // SPNEGO mechListMIC exchange.
    let client_mic = kerberos.generate_mic_token(b"mech types", Sealed).unwrap();
    assert_eq!(&client_mic[..8], &[0x04, 0x04, 0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(&client_mic[8..16], &CLIENT_FIRST_SEQ.to_be_bytes());
    wrap::verify_mic(
        &AES256_SUITE,
        &CONTEXT_KEY,
        Sender::Initiator,
        CLIENT_FIRST_SEQ,
        b"mech types",
        &client_mic,
    )
    .unwrap();

    let server_mic = wrap::mic(
        &AES256_SUITE,
        &CONTEXT_KEY,
        Sender::Acceptor,
        SERVER_FIRST_SEQ,
        b"mech types",
    )
    .unwrap();
    assert_eq!(server_mic[2], 0x05);
    kerberos.verify_mic_token(&server_mic, b"mech types", Sealed).unwrap();

    // CredSSP pubKeyAuth exchange.
    let client_pub_key_auth = kerberos_encrypt(&mut kerberos, b"client public key").unwrap();
    assert_eq!(
        &client_pub_key_auth[..8],
        &[0x05, 0x04, 0x06, 0xFF, 0x00, 0x00, 0x00, 0x1C]
    );
    assert_eq!(
        server_unseal(CLIENT_FIRST_SEQ + 1, &client_pub_key_auth),
        b"client public key"
    );

    let server_pub_key_auth = server_seal(SERVER_FIRST_SEQ + 1, b"server public key");
    assert_eq!(
        &server_pub_key_auth[..8],
        &[0x05, 0x04, 0x07, 0xFF, 0x00, 0x00, 0x00, 0x1C]
    );
    assert_eq!(
        kerberos_decrypt(&mut kerberos, &server_pub_key_auth).unwrap(),
        b"server public key"
    );

    // CredSSP authInfo.
    let auth_info = kerberos_encrypt(&mut kerberos, b"ts credentials").unwrap();
    assert_eq!(server_unseal(CLIENT_FIRST_SEQ + 2, &auth_info), b"ts credentials");
    kerberos.remote_guard.as_deref_mut().unwrap().mark_logon_built();

    let mut session = kerberos.take_remote_guard_session().unwrap();
    assert_eq!(session.sequence_numbers(), (137_625_793, 39_321_548));

    for i in 0..RDPEAR_PAIRS {
        let request = format!("rdpear request {i}");
        let request_token = server_seal(39_321_548 + i, request.as_bytes());
        assert_eq!(
            session.unwrap(&request_token).unwrap().as_ref().as_slice(),
            request.as_bytes()
        );

        let response = format!("rdpear response {i}");
        let response_token = session.wrap(response.as_bytes()).unwrap();
        assert_eq!(&response_token[..8], &[0x05, 0x04, 0x06, 0xFF, 0x00, 0x00, 0x00, 0x1C]);
        assert_eq!(&response_token[8..16], &(137_625_793 + i).to_be_bytes());
        assert_eq!(server_unseal(137_625_793 + i, &response_token), response.as_bytes());
    }
    assert_eq!(session.sequence_numbers(), (137_625_957, 39_321_712));

    // The Kerberos context no longer protects messages and does not expose the key.
    assert_eq!(
        kind(kerberos_encrypt(&mut kerberos, b"after")),
        ErrorKind::ContextExpired
    );
    assert_eq!(
        kind(kerberos_decrypt(&mut kerberos, &server_seal(39_321_712, b"after"))),
        ErrorKind::ContextExpired
    );
    assert_eq!(
        kind(kerberos.generate_mic_token(b"after", Sealed)),
        ErrorKind::ContextExpired
    );
    assert_eq!(
        kind(kerberos.query_context_session_key()),
        ErrorKind::UnsupportedFunction
    );
    assert!(kerberos.encryption_params.session_key.is_none());
    assert!(kerberos.encryption_params.sub_session_key.is_none());
    assert_eq!(kind(kerberos.take_remote_guard_session()), ErrorKind::ContextExpired);
}

#[test]
fn session_unwrap_accepts_any_rotation_count() {
    let mut session = session(10, 20);

    for (offset, rrc) in [0_u16, 1, 28, 60, 1000].into_iter().enumerate() {
        let seq_number = 20 + u64::try_from(offset).unwrap();
        let token = server_seal(seq_number, b"rotated message");

        // Re-rotate the token from RRC 28 to `rrc`.
        let (header, rotated) = token.split_at(16);
        let mut unrotated = rotated.to_vec();
        unrotated.rotate_left(28);
        let len = unrotated.len();
        unrotated.rotate_right(usize::from(rrc) % len);

        let mut rerotated = header.to_vec();
        rerotated[6..8].copy_from_slice(&rrc.to_be_bytes());
        rerotated.extend_from_slice(&unrotated);

        assert_eq!(
            session.unwrap(&rerotated).unwrap().as_ref().as_slice(),
            b"rotated message"
        );
    }
}

fn assert_session_poisoned(session: &mut RemoteGuardSession, sequence_numbers: (u64, u64)) {
    assert!(session.is_poisoned());
    assert!(!session.has_protection_key());
    assert_eq!(session.key_store.len(), 0);
    assert_eq!(session.server_subkeys.len(), 0);
    assert!(session.ntlm.is_none());
    assert_eq!(session.sequence_numbers(), sequence_numbers);
    assert_eq!(kind(session.wrap(b"later")), ErrorKind::ContextExpired);
    assert_eq!(
        kind(session.unwrap(&server_seal(sequence_numbers.1, b"later"))),
        ErrorKind::ContextExpired
    );
    // Rejected calls do not consume sequence numbers.
    assert_eq!(session.sequence_numbers(), sequence_numbers);
}

#[test]
fn session_unwrap_failures_disable_the_session() {
    let valid = server_seal(20, b"message");

    let mut tampered = valid.clone();
    *tampered.last_mut().unwrap() ^= 0x01;

    let mut tampered_header = valid.clone();
    tampered_header[15] ^= 0x01;

    let mut bad_flags = valid.clone();
    bad_flags[2] = 0x05;

    let mut no_acceptor_subkey = valid.clone();
    no_acceptor_subkey[2] = 0x03;

    let wrong_key = wrap::seal(&AES256_SUITE, &SERVICE_KEY, Sender::Acceptor, 20, b"message").unwrap();
    let reflected = wrap::seal(&AES256_SUITE, &CONTEXT_KEY, Sender::Initiator, 20, b"message").unwrap();
    let mic_token = wrap::mic(&AES256_SUITE, &CONTEXT_KEY, Sender::Acceptor, 20, b"message").unwrap();

    let cases: Vec<(&str, Vec<u8>, ErrorKind)> = vec![
        (
            "skipped sequence number",
            server_seal(21, b"message"),
            ErrorKind::OutOfSequence,
        ),
        (
            "old sequence number",
            server_seal(19, b"message"),
            ErrorKind::OutOfSequence,
        ),
        ("tampered ciphertext", tampered, ErrorKind::MessageAltered),
        ("tampered header", tampered_header, ErrorKind::OutOfSequence),
        ("not sealed", bad_flags, ErrorKind::MessageAltered),
        ("acceptor subkey flag", no_acceptor_subkey, ErrorKind::MessageAltered),
        ("wrong key", wrong_key, ErrorKind::MessageAltered),
        ("reflected initiator token", reflected, ErrorKind::MessageAltered),
        ("MIC token", mic_token, ErrorKind::InvalidToken),
        (
            "truncated",
            valid[..SEAL_OVERHEAD - 1].to_vec(),
            ErrorKind::InvalidToken,
        ),
        ("empty", Vec::new(), ErrorKind::InvalidToken),
        ("oversized", vec![0; MAX_WRAP_TOKEN_LEN + 1], ErrorKind::InvalidToken),
    ];

    for (name, token, expected) in cases {
        let mut session = session(10, 20);
        let error = session
            .unwrap(&token)
            .err()
            .unwrap_or_else(|| panic!("{name}: accepted"));
        assert_eq!(error.error_type, expected, "{name}");
        assert_session_poisoned(&mut session, (10, 20));
    }
}

#[test]
fn session_rejects_replayed_token() {
    let mut session = session(10, 20);
    let token = server_seal(20, b"first");

    assert_eq!(session.unwrap(&token).unwrap().as_ref().as_slice(), b"first");
    assert_eq!(kind(session.unwrap(&token)), ErrorKind::OutOfSequence);
    assert_session_poisoned(&mut session, (10, 21));
}

#[test]
fn session_rejects_oversized_message_without_consuming_a_sequence_number() {
    let mut session = session(10, 20);

    let oversized = vec![0; MAX_WRAP_TOKEN_LEN - SEAL_OVERHEAD + 1];
    assert_eq!(kind(session.wrap(&oversized)), ErrorKind::InvalidParameter);
    assert!(!session.is_poisoned());
    assert_eq!(session.sequence_numbers(), (10, 20));

    let token = session.wrap(b"small").unwrap();
    assert_eq!(server_unseal(10, &token), b"small");
}

#[test]
fn session_sequence_numbers_do_not_wrap() {
    let mut session = session(MAX_SEQUENCE_NUMBER, MAX_SEQUENCE_NUMBER);

    let token = session.wrap(b"last").unwrap();
    assert_eq!(server_unseal(MAX_SEQUENCE_NUMBER, &token), b"last");
    assert_eq!(kind(session.wrap(b"one too many")), ErrorKind::OutOfSequence);
    assert!(session.is_poisoned());

    let mut session = self::session(0, MAX_SEQUENCE_NUMBER);
    session.unwrap(&server_seal(MAX_SEQUENCE_NUMBER, b"last")).unwrap();
    assert_eq!(
        kind(session.unwrap(&server_seal(MAX_SEQUENCE_NUMBER, b"replay"))),
        ErrorKind::OutOfSequence
    );
    assert!(session.is_poisoned());
}

#[test]
fn session_protection_failures_discard_all_secrets() {
    let alice = vec![USER.to_owned()];

    for send_failure in [false, true] {
        let next_send_seq = if send_failure { MAX_SEQUENCE_NUMBER } else { 1000 };
        let KeyedSession {
            mut session,
            service_handle,
            ..
        } = session_with_keys_at(next_send_seq, 2000);
        session.ntlm = Some(ntlm_credential(1));
        session
            .create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
                sub_key: Some(key_ref(&SERVER_SUBKEY)),
                ..authenticator_request(&service_handle, &alice)
            })
            .unwrap();

        assert!(session.has_protection_key());
        assert_eq!(session.key_store.len(), 2);
        assert_eq!(session.server_subkeys.len(), 1);
        assert!(session.ntlm_available());

        let next_send_seq = if send_failure {
            let token = session.wrap(b"last").unwrap();
            assert_eq!(server_unseal(MAX_SEQUENCE_NUMBER, &token), b"last");
            assert_eq!(kind(session.wrap(b"exhausted")), ErrorKind::OutOfSequence);
            MAX_SEQUENCE_NUMBER + 1
        } else {
            let mut token = server_seal(2000, b"tampered");
            *token.last_mut().unwrap() ^= 1;
            assert_eq!(kind(session.unwrap(&token)), ErrorKind::MessageAltered);
            next_send_seq
        };

        assert_session_poisoned(&mut session, (next_send_seq, 2000));
    }
}

#[test]
fn poisoned_session_rejects_all_kerberos_operations() {
    let KeyedSession {
        mut session,
        tgt_handle,
        service_handle,
    } = session_with_keys();
    let alice = vec![USER.to_owned()];
    let body = kdc_req_body();
    let auth_data = authorization_data();
    let reply_body = enc_ap_rep_part();
    let reply = valid_ap_rep_template();
    let encrypted_ap_reply = encrypt_der(&SERVICE_KEY, USAGE_AP_REP, &reply_body);
    let reply_part = EncTgsRepPart::from(tgs_reply_part(encryption_key(18, &NEW_TICKET_KEY), computer()));
    let encrypted_tgs_reply = encrypted_reply(&FORWARDED_TGT_KEY, USAGE_TGS_REP_SESSION_KEY, &reply_part);
    let encrypted_subkey_reply = encrypted_reply(&SERVER_SUBKEY, USAGE_TGS_REP_SUB_KEY, &reply_part);

    session
        .create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
            sub_key: Some(key_ref(&SERVER_SUBKEY)),
            ..authenticator_request(&service_handle, &alice)
        })
        .unwrap();
    assert_eq!(kind(session.unwrap(&[])), ErrorKind::InvalidToken);

    for malformed in [false, true] {
        let body = if malformed { &[] } else { body.as_slice() };
        let auth_data = if malformed { &[] } else { auth_data.as_slice() };
        let reply_body = if malformed { &[] } else { reply_body.as_slice() };
        let reply = if malformed { &[] } else { reply.as_slice() };
        let encrypted_ap_reply = if malformed { &[] } else { encrypted_ap_reply.as_slice() };
        let encrypted_tgs_reply = if malformed { &[] } else { encrypted_tgs_reply.as_slice() };
        let encrypted_subkey_reply = if malformed {
            &[]
        } else {
            encrypted_subkey_reply.as_slice()
        };

        for (name, result) in [
            (
                "TGS checksum",
                kind(session.compute_tgs_checksum(checksum_request(body, &tgt_handle))),
            ),
            (
                "AP-REQ authenticator",
                kind(session.create_ap_req_authenticator(authenticator_request(&service_handle, &alice))),
            ),
            (
                "TGS-REQ authenticator",
                kind(session.create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
                    key_usage: 7,
                    ..authenticator_request(&tgt_handle, &alice)
                })),
            ),
            (
                "AP-REP decryption",
                kind(session.decrypt_ap_reply(DecryptApReplyRequest {
                    encrypted_reply: encrypted_ap_reply,
                    key: key_ref(&service_handle),
                })),
            ),
            (
                "AP-REP encryption",
                kind(session.pack_ap_reply(PackApReplyRequest {
                    reply,
                    reply_body,
                    session_key: key_ref(&service_handle),
                })),
            ),
        ] {
            assert_eq!(result, ErrorKind::ContextExpired, "{name}");
        }

        for (key, auth_data_usage, reply_usage, encrypted_reply) in [
            (key_ref(&tgt_handle), 4, 8, encrypted_tgs_reply),
            (key_ref(&SERVER_SUBKEY), 5, 9, encrypted_subkey_reply),
        ] {
            assert_eq!(
                kind(session.build_encrypted_auth_data(BuildEncryptedAuthDataRequest {
                    key_usage: auth_data_usage,
                    key,
                    plain_auth_data: auth_data,
                })),
                ErrorKind::ContextExpired
            );
            assert_eq!(
                kind(session.unpack_kdc_reply_body(UnpackKdcReplyBodyRequest {
                    encrypted_data: encrypted_reply,
                    key,
                    strengthen_key: malformed.then_some(key_ref(&SERVER_SUBKEY)),
                    key_usage: reply_usage,
                })),
                ErrorKind::ContextExpired
            );
        }
    }
    assert_session_poisoned(&mut session, (1000, 2000));
}

#[test]
fn session_debug_output_is_redacted() {
    let keyed = session_with_keys();
    let debug = format!("{:?}", keyed.session);

    assert_eq!(
        debug,
        "RemoteGuardSession { poisoned: false, key_store: KeyStore { len: 2 }, ntlm: false, .. }"
    );

    let reference = format!("{:?}", key_ref(&keyed.tgt_handle));
    assert_eq!(reference, "KeyReference { encryption_type: 18, value_len: 32 }");
}

#[test]
fn establish_context_checks_preconditions_without_poisoning() {
    let mut state = state_with_tgts();
    state.poison();
    assert_eq!(
        kind(state.establish_context(Some(&context_subkey()), 0, 0)),
        ErrorKind::ContextExpired
    );

    let mut state = established_state(1, 2);
    assert_eq!(
        kind(state.establish_context(Some(&context_subkey()), 3, 4)),
        ErrorKind::OutOfSequence
    );
    assert!(!state.poisoned);
    assert_eq!(state_sequence_numbers(&state), (1, 2));

    let removals: [fn(&mut RemoteGuardState); 3] = [
        |state| state.binding = None,
        |state| state.home_tgt = None,
        |state| state.service_tgt = None,
    ];
    for remove in removals {
        let mut state = state_with_tgts();
        remove(&mut state);
        assert_eq!(
            kind(state.establish_context(Some(&context_subkey()), 0, 0)),
            ErrorKind::InternalError
        );
        assert!(!state.poisoned);
    }

    let mut state = state_with_tgts();
    assert_eq!(kind(state.establish_context(None, 0, 0)), ErrorKind::InvalidToken);
    assert_eq!(
        kind(state.establish_context(Some(&encryption_key(RC4, &[0x33; 16])), 0, 0)),
        ErrorKind::AlgorithmMismatch
    );
    assert_eq!(
        kind(state.establish_context(Some(&encryption_key(18, &[0x33; 16])), 0, 0)),
        ErrorKind::InvalidParameter
    );
    assert!(!state.poisoned);
    assert!(state.context.is_none());

    state
        .establish_context(Some(&encryption_key(17, &[0x33; 16])), 5, 6)
        .unwrap();
    assert_eq!(state_sequence_numbers(&state), (5, 6));

    let token = state.generate_mic(b"aes128").unwrap();
    assert_eq!(&token[..3], &[0x04, 0x04, 0x04]);
    assert_eq!(&token[8..16], &5_u64.to_be_bytes());
    wrap::verify_mic(
        &CipherSuite::Aes128CtsHmacSha196,
        &[0x33; 16],
        Sender::Initiator,
        5,
        b"aes128",
        &token,
    )
    .unwrap();

    let server_mic = wrap::mic(
        &CipherSuite::Aes128CtsHmacSha196,
        &[0x33; 16],
        Sender::Acceptor,
        6,
        b"aes128",
    )
    .unwrap();
    assert_eq!(
        kind(state.verify_mic(&server_mic, b"altered")),
        ErrorKind::MessageAltered
    );
    assert!(state.poisoned);
    assert!(state.context.is_none() && state.home_tgt.is_none() && state.service_tgt.is_none());
    assert_eq!(
        kind(state.verify_mic(&server_mic, b"aes128")),
        ErrorKind::ContextExpired
    );
}

#[test]
fn remote_guard_mic_sequence_error_reports_stage_and_numbers_and_drops_secrets() {
    const EXPECTED: u64 = 39_321_546;
    let message = b"mech types";

    for received in [EXPECTED - 1, EXPECTED + 1, u64::MAX] {
        let mut kerberos = fake_client();
        let mut state = established_state(137_625_790, EXPECTED);
        state.ntlm = Some(ntlm_credential(1));
        kerberos.remote_guard = Some(Box::new(state));

        let mut token = wrap::mic(
            &AES256_SUITE,
            &CONTEXT_KEY,
            Sender::Acceptor,
            received.min(MAX_SEQUENCE_NUMBER),
            message,
        )
        .unwrap();
        // Only the out-of-range case needs an unauthenticated sequence header.
        token[8..16].copy_from_slice(&received.to_be_bytes());

        let error = kerberos.verify_mic_token(&token, message, Sealed).unwrap_err();
        assert_eq!(error.error_type, ErrorKind::OutOfSequence);
        assert_eq!(
            error.description,
            format!(
                "SPNEGO mechListMIC verification failed: MIC token sequence number mismatch: \
                 expected {EXPECTED}, received {received} (unauthenticated header)"
            )
        );

        let state = rcg_state(&kerberos);
        assert!(state.poisoned);
        assert!(state.context.is_none());
        assert!(state.home_tgt.is_none() && state.service_tgt.is_none());
        assert!(state.ntlm.is_none());
        assert_eq!(state.key_store.len(), 0);
        assert_eq!(
            kind(kerberos.verify_mic_token(&token, message, Sealed)),
            ErrorKind::ContextExpired
        );
    }
}

#[test]
fn remote_guard_mic_advances_once_and_rejects_replay() {
    const FIRST: u64 = 39_321_546;
    let message = b"mech types";
    let mut kerberos = fake_client();
    kerberos.remote_guard = Some(Box::new(established_state(137_625_790, FIRST)));
    let token = wrap::mic(&AES256_SUITE, &CONTEXT_KEY, Sender::Acceptor, FIRST, message).unwrap();

    kerberos.verify_mic_token(&token, message, Sealed).unwrap();
    assert_eq!(state_sequence_numbers(rcg_state(&kerberos)), (137_625_790, FIRST + 1));

    let error = kerberos.verify_mic_token(&token, message, Sealed).unwrap_err();
    assert_eq!(error.error_type, ErrorKind::OutOfSequence);
    assert_eq!(
        error.description,
        "SPNEGO mechListMIC verification failed: MIC token sequence number mismatch: \
         expected 39321547, received 39321546 (unauthenticated header)"
    );
    assert!(rcg_state(&kerberos).poisoned);
    assert!(rcg_state(&kerberos).context.is_none());
}

#[test]
fn protection_requires_an_established_context() {
    let mut state = state_with_tgts();

    assert_eq!(kind(state.generate_mic(b"data")), ErrorKind::OutOfSequence);
    assert_eq!(kind(state.verify_mic(&[0; 28], b"data")), ErrorKind::OutOfSequence);
    assert!(!state.poisoned);
}

#[test]
fn into_session_requires_a_complete_state() {
    let mut state = established_state(1, 2);
    state.mark_logon_built();
    state.poison();
    assert_eq!(kind(state.into_session(Duration::ZERO)), ErrorKind::ContextExpired);

    let state = established_state(1, 2);
    assert_eq!(kind(state.into_session(Duration::ZERO)), ErrorKind::OutOfSequence);

    let mut state = state_with_tgts();
    state.mark_logon_built();
    assert_eq!(kind(state.into_session(Duration::ZERO)), ErrorKind::OutOfSequence);

    let mut state = established_state(1, 2);
    state.binding = None;
    state.mark_logon_built();
    assert_eq!(kind(state.into_session(Duration::ZERO)), ErrorKind::InternalError);
}

#[test]
fn state_clone_is_poisoned_and_empty() {
    let state = established_state(1, 2);
    let clone = state.clone();

    assert!(clone.poisoned);
    assert!(clone.context.is_none());
    assert!(clone.binding.is_none());
    assert!(clone.home_tgt.is_none());
    assert!(clone.service_tgt.is_none());

    let mut kerberos = rcg_client();
    let mut cloned_kerberos = kerberos.clone();
    assert_eq!(
        kind(kerberos_encrypt(&mut cloned_kerberos, b"data")),
        ErrorKind::ContextExpired
    );
    kerberos_encrypt(&mut kerberos, b"data").unwrap();
}

#[test]
fn mark_logon_built_drops_the_captured_tickets() {
    let mut state = established_state(1, 2);
    assert!(!state.is_logon_built());

    state.mark_logon_built();

    assert!(state.is_logon_built());
    assert!(state.home_tgt.is_none());
    assert!(state.service_tgt.is_none());
    assert!(state.context.is_some());
}

#[test]
fn state_debug_output_is_redacted() {
    let state = established_state(1, 2);

    assert_eq!(
        format!("{state:?}"),
        "RemoteGuardState { poisoned: false, home_tgt: true, service_tgt: true, context: true, \
         key_store: KeyStore { len: 0 }, ntlm: false, logon_built: false, .. }"
    );
}

#[test]
fn kerberos_encrypt_message_checks_buffers_without_consuming_a_sequence_number() {
    let mut kerberos = rcg_client();

    let mut token = [0; 1024];
    let mut data = b"data".to_vec();
    let mut signed = b"signed".to_vec();
    let mut message = [
        SecurityBufferRef::token_buf(token.as_mut_slice()),
        SecurityBufferRef::data_buf(data.as_mut_slice()),
        SecurityBufferRef::data_buf(signed.as_mut_slice())
            .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
    ];
    assert_eq!(
        kind(kerberos.encrypt_message(EncryptionFlags::empty(), &mut message)),
        ErrorKind::UnsupportedFunction
    );

    let mut token = [0; 1024];
    let mut data = b"data".to_vec();
    let mut other = b"other".to_vec();
    let mut message = [
        SecurityBufferRef::token_buf(token.as_mut_slice()),
        SecurityBufferRef::data_buf(data.as_mut_slice()),
        SecurityBufferRef::data_buf(other.as_mut_slice()),
    ];
    assert_eq!(
        kind(kerberos.encrypt_message(EncryptionFlags::empty(), &mut message)),
        ErrorKind::UnsupportedFunction
    );

    let mut token = [0; SEAL_OVERHEAD - 1];
    let mut data = b"data".to_vec();
    let mut message = [
        SecurityBufferRef::token_buf(token.as_mut_slice()),
        SecurityBufferRef::data_buf(data.as_mut_slice()),
    ];
    assert_eq!(
        kind(kerberos.encrypt_message(EncryptionFlags::empty(), &mut message)),
        ErrorKind::BufferTooSmall
    );

    let mut token = [0; 1024];
    let mut message = [SecurityBufferRef::token_buf(token.as_mut_slice())];
    assert_eq!(
        kind(kerberos.encrypt_message(EncryptionFlags::empty(), &mut message)),
        ErrorKind::InvalidToken
    );

    assert!(!rcg_state(&kerberos).poisoned);
    assert_eq!(state_sequence_numbers(rcg_state(&kerberos)), (1000, 2000));

    let wrapped = kerberos_encrypt(&mut kerberos, b"data").unwrap();
    assert_eq!(server_unseal(1000, &wrapped), b"data");
}

#[test]
fn kerberos_decrypt_message_supports_stream_buffers() {
    let mut kerberos = rcg_client();

    let mut stream = server_seal(2000, b"streamed");
    let mut message = [
        SecurityBufferRef::stream_buf(stream.as_mut_slice()),
        SecurityBufferRef::data_buf(&mut []),
    ];
    kerberos.decrypt_message(&mut message).unwrap();
    assert_eq!(message[1].data(), b"streamed");

    // Without a Data buffer the plaintext cannot be returned after the sequence number was consumed.
    let mut stream = server_seal(2001, b"lost");
    let mut message = [SecurityBufferRef::stream_buf(stream.as_mut_slice())];
    assert!(kerberos.decrypt_message(&mut message).is_err());
    assert!(rcg_state(&kerberos).poisoned);
    assert_eq!(
        kind(kerberos_decrypt(&mut kerberos, &server_seal(2002, b"later"))),
        ErrorKind::ContextExpired
    );
}

#[test]
fn kerberos_security_trailer_has_no_extra_count() {
    let mut kerberos = rcg_client();
    kerberos.encryption_params.ec = 16;

    let sizes = kerberos.query_context_sizes().unwrap();
    assert_eq!(sizes.security_trailer, u32::try_from(SEAL_OVERHEAD).unwrap());
}

#[test]
fn take_remote_guard_session_fails_closed() {
    let mut kerberos = fake_client();
    assert_eq!(
        kind(kerberos.take_remote_guard_session()),
        ErrorKind::UnsupportedFunction
    );
    assert!(kerberos.encryption_params.session_key.is_some());

    let mut kerberos = rcg_client();
    kerberos.state = KerberosState::Client(Box::new(KerberosClientState::ApExchange));
    assert_eq!(kind(kerberos.take_remote_guard_session()), ErrorKind::OutOfSequence);
    assert!(!rcg_state(&kerberos).poisoned);
    assert!(rcg_state(&kerberos).context.is_some());

    // The logon credentials were not built: the session is not handed out and the context is disabled.
    let mut kerberos = rcg_client();
    assert_eq!(kind(kerberos.take_remote_guard_session()), ErrorKind::OutOfSequence);
    assert!(kerberos.encryption_params.session_key.is_none());
    assert!(kerberos.encryption_params.sub_session_key.is_none());
    assert_eq!(
        kind(kerberos_encrypt(&mut kerberos, b"data")),
        ErrorKind::ContextExpired
    );
    assert_eq!(kind(kerberos.take_remote_guard_session()), ErrorKind::ContextExpired);
}

#[test]
fn enable_remote_guard_is_restricted_to_new_clients() {
    let mut server = fake_server();
    assert_eq!(kind(server.enable_remote_guard()), ErrorKind::UnsupportedFunction);
    assert!(!server.is_remote_guard());

    let mut established = fake_client();
    assert_eq!(kind(established.enable_remote_guard()), ErrorKind::OutOfSequence);
    assert!(!established.is_remote_guard());

    let mut client = fake_client();
    client.state = KerberosState::Client(Box::new(KerberosClientState::TgtExchange));
    client.enable_remote_guard().unwrap();
    client.enable_remote_guard().unwrap();
    assert!(client.is_remote_guard());
    assert!(!rcg_state(&client).poisoned);
    assert!(rcg_state(&client).context.is_none());

    let mut iakerb = fake_client();
    iakerb.state = KerberosState::Client(Box::new(KerberosClientState::TgtExchange));
    iakerb.config.kdc_resolution = crate::KdcResolution::IAKerb;
    assert_eq!(kind(iakerb.enable_remote_guard()), ErrorKind::UnsupportedFunction);
    assert!(!iakerb.is_remote_guard());
    assert!(iakerb.is_iakerb());
}

#[test]
fn integer_to_i32_accepts_only_int32_values() {
    assert_eq!(integer_to_i32(&IntegerAsn1::from(vec![0x12])).unwrap(), 18);
    assert_eq!(integer_to_i32(&IntegerAsn1::from(vec![0xFF])).unwrap(), -1);
    assert_eq!(
        integer_to_i32(&IntegerAsn1::from(vec![0x7F, 0xFF, 0xFF, 0xFF])).unwrap(),
        i32::MAX
    );
    assert_eq!(
        integer_to_i32(&IntegerAsn1::from(vec![0x80, 0x00, 0x00, 0x00])).unwrap(),
        i32::MIN
    );
    // Redundant sign bytes.
    assert_eq!(
        integer_to_i32(&IntegerAsn1::from(vec![0xFF, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00])).unwrap(),
        i32::MIN
    );
    assert_eq!(integer_to_i32(&IntegerAsn1::from(vec![0x00, 0x00, 0x05])).unwrap(), 5);

    for out_of_range in [
        vec![0x00, 0x80, 0x00, 0x00, 0x00],
        vec![0xFF, 0x7F, 0xFF, 0xFF, 0xFF],
        vec![0x00; 9],
    ] {
        assert_eq!(
            kind(integer_to_i32(&IntegerAsn1::from(out_of_range))),
            ErrorKind::InvalidToken
        );
    }
}

#[test]
fn cipher_suite_helpers_accept_only_aes() {
    assert_eq!(aes_cipher_suite(AES256).unwrap(), CipherSuite::Aes256CtsHmacSha196);
    assert_eq!(aes_cipher_suite(AES128).unwrap(), CipherSuite::Aes128CtsHmacSha196);
    for etype in [i32::from(RC4), 16, 0, -1, 1000, i32::MAX] {
        assert_eq!(kind(aes_cipher_suite(etype)), ErrorKind::AlgorithmMismatch);
    }

    assert_eq!(etype_of(&CipherSuite::Aes256CtsHmacSha196), AES256);
    assert_eq!(etype_of(&CipherSuite::Aes128CtsHmacSha196), AES128);
}

#[test]
fn captured_tgt_requires_an_aes_key_of_the_right_length() {
    assert!(
        CapturedTgt::new(
            REALM.to_owned(),
            ticket(krbtgt(), HOME_TGT_MARKER),
            CipherSuite::Aes128CtsHmacSha196,
            Secret::new(vec![0x11; 16]),
        )
        .is_ok()
    );
    assert_eq!(
        kind(CapturedTgt::new(
            REALM.to_owned(),
            ticket(krbtgt(), HOME_TGT_MARKER),
            AES256_SUITE,
            Secret::new(vec![0x11; 16]),
        )),
        ErrorKind::AlgorithmMismatch
    );
    assert!(
        CapturedTgt::new(
            REALM.to_owned(),
            ticket(krbtgt(), HOME_TGT_MARKER),
            CipherSuite::Des3CbcSha1Kd,
            Secret::new(vec![0x11; 24]),
        )
        .is_err()
    );
}

/// Operation failures are reported to the server; they neither disable nor advance message protection.
fn assert_protection_untouched(session: &mut RemoteGuardSession) {
    assert!(!session.is_poisoned());
    assert_eq!(session.sequence_numbers(), (1000, 2000));
}

fn checksum_request<'a>(request_body: &'a [u8], key: &'a [u8]) -> ComputeTgsChecksumRequest<'a> {
    ComputeTgsChecksumRequest {
        request_body,
        key: key_ref(key),
        checksum_type: 16,
    }
}

fn authenticator_request<'a>(key: &'a [u8], client_name: &'a [String]) -> CreateApReqAuthenticatorRequest<'a> {
    CreateApReqAuthenticatorRequest {
        encryption_key: key_ref(key),
        sequence_number: 0,
        client_name,
        client_realm: REALM,
        skew_time: 0,
        sub_key: None,
        auth_data: None,
        gss_checksum: None,
        key_usage: 11,
    }
}

fn decrypt_authenticator(key: &[u8], usage: i32, authenticator: &ApReqAuthenticator) -> AuthenticatorInner {
    let plaintext = decrypt_der(key, usage, &authenticator.authenticator);
    picky_asn1_der::from_bytes::<Authenticator>(&plaintext).unwrap().0
}

#[test]
fn compute_tgs_checksum_uses_the_referenced_tgt_key() {
    let KeyedSession {
        mut session,
        tgt_handle,
        ..
    } = session_with_keys();
    let body = kdc_req_body();

    let checksum = session
        .compute_tgs_checksum(checksum_request(&body, &tgt_handle))
        .unwrap();

    let checksum: Checksum = picky_asn1_der::from_bytes(&checksum).unwrap();
    assert_eq!(checksum.cksumtype.0, IntegerAsn1::from(vec![16]));
    assert_eq!(
        checksum.checksum.0.0,
        checksum_sha_aes(&FORWARDED_TGT_KEY, USAGE_TGS_REQ_CHECKSUM, &body, &AesSize::Aes256).unwrap()
    );
    assert_protection_untouched(&mut session);
}

#[test]
fn compute_tgs_checksum_supports_rsa_md5_with_aes_ticket_keys() {
    let KeyedSession {
        mut session,
        tgt_handle,
        ..
    } = session_with_keys();
    let aes128_handle = session
        .key_store
        .insert(
            CipherSuite::Aes128CtsHmacSha196,
            Secret::new(vec![0x99; 16]),
            KeyRole::TicketGranting,
            &mut StdRng::seed_from_u64(8),
        )
        .unwrap();
    let body = kdc_req_body();
    let mut changed_body: KdcReqBody = picky_asn1_der::from_bytes(&body).unwrap();
    changed_body.nonce = ExplicitContextTag7::from(IntegerAsn1::from(vec![0x12, 0x35]));
    let changed_body = picky_asn1_der::to_vec(&changed_body).unwrap();
    assert_ne!(Md5::digest(&body), Md5::digest(&changed_body));

    for key in [
        key_ref(&tgt_handle),
        KeyReference {
            encryption_type: AES128,
            value: &aes128_handle,
        },
    ] {
        for request_body in [&body, &changed_body] {
            let encoded = session
                .compute_tgs_checksum(ComputeTgsChecksumRequest {
                    request_body,
                    key,
                    checksum_type: 7,
                })
                .unwrap();
            let checksum: Checksum = picky_asn1_der::from_bytes(&encoded).unwrap();
            assert_eq!(checksum.cksumtype.0, IntegerAsn1::from(vec![7]));
            assert_eq!(checksum.checksum.0.0, Md5::digest(request_body).to_vec());
        }
    }
    assert_protection_untouched(&mut session);
}

#[test]
fn compute_tgs_checksum_rsa_md5_preserves_input_and_key_authorization() {
    let KeyedSession {
        mut session,
        tgt_handle,
        service_handle,
    } = session_with_keys();
    let body = kdc_req_body();
    let oversized = vec![0; MAX_OPERATION_INPUT_LEN + 1];
    let base = ComputeTgsChecksumRequest {
        checksum_type: 7,
        ..checksum_request(&body, &tgt_handle)
    };

    for (request_body, expected) in [
        (&[][..], ErrorKind::InvalidParameter),
        (oversized.as_slice(), ErrorKind::InvalidParameter),
        (&[0x30, 0x03, 0x02][..], ErrorKind::InvalidToken),
    ] {
        assert_eq!(
            kind(session.compute_tgs_checksum(ComputeTgsChecksumRequest { request_body, ..base })),
            expected
        );
    }
    for key in [key_ref(&service_handle), key_ref(&FORWARDED_TGT_KEY), key_ref(&[0; 32])] {
        assert_eq!(
            kind(session.compute_tgs_checksum(ComputeTgsChecksumRequest { key, ..base })),
            ErrorKind::NoKerbKey
        );
    }
    assert_eq!(
        kind(session.compute_tgs_checksum(ComputeTgsChecksumRequest {
            key: KeyReference {
                encryption_type: AES128,
                value: &tgt_handle,
            },
            ..base
        })),
        ErrorKind::AlgorithmMismatch
    );
    for checksum_type in [0, 1, 8, 15, -138, i32::MAX] {
        assert_eq!(
            kind(session.compute_tgs_checksum(ComputeTgsChecksumRequest { checksum_type, ..base })),
            ErrorKind::AlgorithmMismatch
        );
    }
    assert_protection_untouched(&mut session);
}

#[test]
fn create_ap_req_authenticator_preserves_rsa_md5_tgs_checksum() {
    let KeyedSession {
        mut session,
        tgt_handle,
        ..
    } = session_with_keys();
    let body = kdc_req_body();
    let checksum = session
        .compute_tgs_checksum(ComputeTgsChecksumRequest {
            checksum_type: 7,
            ..checksum_request(&body, &tgt_handle)
        })
        .unwrap();
    let alice = vec![USER.to_owned()];
    let authenticator = session
        .create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
            key_usage: 7,
            gss_checksum: Some(&checksum),
            ..authenticator_request(&tgt_handle, &alice)
        })
        .unwrap();
    let inner = decrypt_authenticator(&FORWARDED_TGT_KEY, USAGE_TGS_REQ_AUTHENTICATOR, &authenticator);
    let checksum = inner.cksum.0.unwrap().0;
    assert_eq!(checksum.cksumtype.0, IntegerAsn1::from(vec![7]));
    assert_eq!(checksum.checksum.0.0, Md5::digest(&body).to_vec());
    assert_eq!(inner.crealm.0, realm(REALM));
    assert_eq!(inner.cname.0, user());
    assert_protection_untouched(&mut session);
}

#[test]
fn compute_tgs_checksum_rejects_invalid_requests() {
    let KeyedSession {
        mut session,
        tgt_handle,
        service_handle,
    } = session_with_keys();
    let body = kdc_req_body();
    let oversized = vec![0x30; MAX_OPERATION_INPUT_LEN + 1];

    let cases = [
        (
            "empty body",
            checksum_request(&[], &tgt_handle),
            ErrorKind::InvalidParameter,
        ),
        (
            "oversized body",
            checksum_request(&oversized, &tgt_handle),
            ErrorKind::InvalidParameter,
        ),
        (
            "invalid body",
            checksum_request(&[0x30, 0x03, 0x02], &tgt_handle),
            ErrorKind::InvalidToken,
        ),
        (
            "service key",
            checksum_request(&body, &service_handle),
            ErrorKind::NoKerbKey,
        ),
        (
            "raw key",
            checksum_request(&body, &FORWARDED_TGT_KEY),
            ErrorKind::NoKerbKey,
        ),
        (
            "encryption type",
            ComputeTgsChecksumRequest {
                key: KeyReference {
                    encryption_type: AES128,
                    value: &tgt_handle,
                },
                ..checksum_request(&body, &tgt_handle)
            },
            ErrorKind::AlgorithmMismatch,
        ),
        (
            "checksum type",
            ComputeTgsChecksumRequest {
                checksum_type: 15,
                ..checksum_request(&body, &tgt_handle)
            },
            ErrorKind::AlgorithmMismatch,
        ),
    ];

    for (name, request, expected) in cases {
        assert_eq!(kind(session.compute_tgs_checksum(request)), expected, "{name}");
    }
    assert_protection_untouched(&mut session);

    let token = session.wrap(b"still usable").unwrap();
    assert_eq!(server_unseal(1000, &token), b"still usable");
}

#[test]
fn create_ap_req_authenticator_encrypts_with_the_referenced_key() {
    let KeyedSession {
        mut session,
        tgt_handle,
        service_handle,
    } = session_with_keys();
    // The client identity is compared case-insensitively.
    let client_name = vec![USER.to_ascii_uppercase()];
    let auth_data = authorization_data();
    let gss_checksum = gss_checksum();

    let authenticator = session
        .create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
            sequence_number: 0x1234_5678,
            client_realm: "example.com",
            skew_time: -10_000_000,
            sub_key: Some(key_ref(&SERVER_SUBKEY)),
            auth_data: Some(&auth_data),
            gss_checksum: Some(&gss_checksum),
            ..authenticator_request(&service_handle, &client_name)
        })
        .unwrap();

    let inner = decrypt_authenticator(&SERVICE_KEY, USAGE_AP_REQ_AUTHENTICATOR, &authenticator);
    assert_eq!(inner.authenticator_vno.0, IntegerAsn1::from(vec![5]));
    assert_eq!(inner.crealm.0, realm(REALM));
    assert_eq!(inner.cname.0, user());
    assert_eq!(
        inner.cksum.0.unwrap().0,
        picky_asn1_der::from_bytes::<Checksum>(&gss_checksum).unwrap()
    );
    assert_eq!(inner.subkey.0.unwrap().0, encryption_key(18, &SERVER_SUBKEY));
    assert_eq!(integer_to_i32(&inner.seq_number.0.unwrap().0).unwrap(), 0x1234_5678);
    assert_eq!(
        inner.authorization_data.0.unwrap().0,
        picky_asn1_der::from_bytes::<AuthorizationData>(&auth_data).unwrap()
    );

    let cusec = integer_to_i32(&inner.cusec.0).unwrap();
    assert!((0..1_000_000).contains(&cusec));
    assert_eq!(authenticator.authenticator_time % 10_000_000 / 10, i64::from(cusec));
    let now = (OffsetDateTime::now_utc().unix_timestamp() + 11_644_473_600) * 10_000_000;
    assert!((authenticator.authenticator_time - now).abs() < 600 * 10_000_000);

    assert!(format!("{authenticator:?}").starts_with("ApReqAuthenticator { authenticator_time: "));
    assert_eq!(session.server_subkeys.len(), 1);

    // PA-TGS-REQ authenticator with the TGT key, without sequence number or subkey.
    let authenticator = session
        .create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
            key_usage: 7,
            ..authenticator_request(&tgt_handle, &client_name)
        })
        .unwrap();

    let inner = decrypt_authenticator(&FORWARDED_TGT_KEY, USAGE_TGS_REQ_AUTHENTICATOR, &authenticator);
    assert!(inner.seq_number.0.is_none());
    assert!(inner.subkey.0.is_none());
    assert!(inner.cksum.0.is_none());
    assert!(inner.authorization_data.0.is_none());
    assert_eq!(session.server_subkeys.len(), 1);
    assert_protection_untouched(&mut session);
}

#[test]
fn create_ap_req_authenticator_rejects_invalid_requests() {
    let KeyedSession {
        mut session,
        tgt_handle,
        service_handle,
    } = session_with_keys();
    let alice = vec![USER.to_owned()];
    let bob = vec!["bob".to_owned()];
    let two_components = vec![USER.to_owned(), "extra".to_owned()];
    let short_subkey = [0x77; 16];
    let base = authenticator_request(&service_handle, &alice);

    let cases = [
        (
            "AS-REQ usage",
            CreateApReqAuthenticatorRequest { key_usage: 1, ..base },
            ErrorKind::UnsupportedFunction,
        ),
        (
            "AP-REP usage",
            CreateApReqAuthenticatorRequest { key_usage: 12, ..base },
            ErrorKind::UnsupportedFunction,
        ),
        (
            "TGT key for an AP-REQ",
            authenticator_request(&tgt_handle, &alice),
            ErrorKind::NoKerbKey,
        ),
        (
            "service key for a TGS-REQ",
            CreateApReqAuthenticatorRequest { key_usage: 7, ..base },
            ErrorKind::NoKerbKey,
        ),
        (
            "unretained raw key",
            authenticator_request(&NEW_TICKET_KEY, &alice),
            ErrorKind::NoKerbKey,
        ),
        (
            "other client",
            authenticator_request(&service_handle, &bob),
            ErrorKind::NoCredentials,
        ),
        (
            "other client name",
            authenticator_request(&service_handle, &two_components),
            ErrorKind::NoCredentials,
        ),
        (
            "other realm",
            CreateApReqAuthenticatorRequest {
                client_realm: "OTHER.COM",
                ..base
            },
            ErrorKind::NoCredentials,
        ),
        (
            "skew time too large",
            CreateApReqAuthenticatorRequest {
                skew_time: 864_000_000_001,
                ..base
            },
            ErrorKind::TimeSkew,
        ),
        (
            "skew time too small",
            CreateApReqAuthenticatorRequest {
                skew_time: i64::MIN,
                ..base
            },
            ErrorKind::TimeSkew,
        ),
        (
            "RC4 subkey",
            CreateApReqAuthenticatorRequest {
                sub_key: Some(KeyReference {
                    encryption_type: i32::from(RC4),
                    value: &short_subkey,
                }),
                ..base
            },
            ErrorKind::AlgorithmMismatch,
        ),
        (
            "short subkey",
            CreateApReqAuthenticatorRequest {
                sub_key: Some(key_ref(&short_subkey)),
                ..base
            },
            ErrorKind::InvalidParameter,
        ),
        (
            "key handle as subkey",
            CreateApReqAuthenticatorRequest {
                sub_key: Some(key_ref(&tgt_handle)),
                ..base
            },
            ErrorKind::InvalidParameter,
        ),
        (
            "invalid authorization data",
            CreateApReqAuthenticatorRequest {
                sub_key: Some(key_ref(&SERVER_SUBKEY)),
                auth_data: Some(&[0x30, 0x05]),
                ..base
            },
            ErrorKind::InvalidToken,
        ),
        (
            "empty authorization data",
            CreateApReqAuthenticatorRequest {
                auth_data: Some(&[]),
                ..base
            },
            ErrorKind::InvalidParameter,
        ),
        (
            "invalid checksum",
            CreateApReqAuthenticatorRequest {
                sub_key: Some(key_ref(&SERVER_SUBKEY)),
                gss_checksum: Some(&[0x04, 0x00]),
                ..base
            },
            ErrorKind::InvalidToken,
        ),
    ];

    for (name, request, expected) in cases {
        assert_eq!(kind(session.create_ap_req_authenticator(request)), expected, "{name}");
    }

    // Subkeys of rejected requests are not remembered.
    assert_eq!(session.server_subkeys.len(), 0);
    assert_protection_untouched(&mut session);
}

fn independent_filetime(time: OffsetDateTime) -> i64 {
    (time.unix_timestamp() + 11_644_473_600) * 10_000_000 + i64::from(time.microsecond()) * 10
}

fn check_authenticator_clock(skews: &[i64], offsets: &[Duration]) {
    for &offset in offsets {
        for &skew in skews {
            for usage in [7, 11] {
                let KeyedSession {
                    mut session,
                    tgt_handle,
                    service_handle,
                } = session_with_keys();
                session.clock_offset = offset;
                let alice = vec![USER.to_owned()];
                let (handle, raw_key) = if usage == 7 {
                    (&tgt_handle, &FORWARDED_TGT_KEY)
                } else {
                    (&service_handle, &SERVICE_KEY)
                };
                let before = OffsetDateTime::now_utc();
                let output = session
                    .create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
                        key_usage: usage,
                        skew_time: skew,
                        ..authenticator_request(handle, &alice)
                    })
                    .unwrap();
                let after = OffsetDateTime::now_utc();
                let shift = Duration::nanoseconds_i128(i128::from(skew) * 100);
                let lower = independent_filetime(before + shift);
                let upper = independent_filetime(after + shift);
                assert!(
                    lower <= output.authenticator_time && output.authenticator_time <= upper,
                    "usage={usage}, skew={skew}, offset={offset}: {lower} <= {} <= {upper}",
                    output.authenticator_time
                );
                let inner = decrypt_authenticator(raw_key, i32::try_from(usage).unwrap(), &output);
                let cusec = integer_to_i32(&inner.cusec.0).unwrap();
                assert!((0..1_000_000).contains(&cusec));
                let seconds = OffsetDateTime::try_from(inner.ctime.0.0).unwrap().unix_timestamp();
                assert_eq!(
                    output.authenticator_time,
                    (seconds + 11_644_473_600) * 10_000_000 + i64::from(cusec) * 10
                );
                assert_eq!(output.authenticator_time % 10, 0);
                assert_eq!(inner.crealm.0, realm(REALM));
                assert_eq!(inner.cname.0, user());
                assert_eq!(session.clock_offset, offset);
                assert_eq!(session.server_subkeys.len(), 0);
                assert_protection_untouched(&mut session);
            }
        }
    }
}

#[test]
fn create_ap_req_authenticator_applies_zero_skew_to_client_utc() {
    check_authenticator_clock(&[0], &[Duration::ZERO]);
}

#[test]
fn create_ap_req_authenticator_applies_positive_skew_in_100ns_ticks() {
    check_authenticator_clock(&[10_000_000, 12_345_670, 12_345_679, 1], &[Duration::ZERO]);
}

#[test]
fn create_ap_req_authenticator_applies_negative_skew_in_100ns_ticks() {
    check_authenticator_clock(&[-10_000_000, -12_345_670, -12_345_679, -1], &[Duration::ZERO]);
}

#[test]
fn create_ap_req_authenticator_accepts_both_skew_time_bounds() {
    check_authenticator_clock(&[-864_000_000_000, 864_000_000_000], &[Duration::ZERO]);
}

#[test]
fn create_ap_req_authenticator_does_not_reapply_kdc_clock_offset() {
    check_authenticator_clock(
        &[0, -12_345_670, 12_345_670],
        &[Duration::hours(-2), Duration::hours(2)],
    );
}

#[test]
fn create_ap_req_authenticator_keeps_filetime_ctime_and_cusec_consistent() {
    check_authenticator_clock(&[-10_000_001, -9_999_999, 9_999_999, 10_000_001], &[Duration::ZERO]);
}

#[test]
fn create_ap_req_authenticator_rejects_adjacent_out_of_range_skew_and_i64_extremes() {
    let alice = vec![USER.to_owned()];
    let KeyedSession {
        mut session,
        tgt_handle,
        service_handle,
    } = session_with_keys();
    for skew_time in [-864_000_000_001, 864_000_000_001, i64::MIN, i64::MAX] {
        for (key_usage, key) in [(7, &tgt_handle), (11, &service_handle)] {
            assert_eq!(
                kind(session.create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
                    key_usage,
                    skew_time,
                    sub_key: Some(key_ref(&SERVER_SUBKEY)),
                    ..authenticator_request(key, &alice)
                })),
                ErrorKind::TimeSkew
            );
            assert_eq!(session.key_store.len(), 2);
            assert_eq!(session.server_subkeys.len(), 0);
            assert_protection_untouched(&mut session);
        }
    }
    let output = session
        .create_ap_req_authenticator(authenticator_request(&service_handle, &alice))
        .unwrap();
    assert_eq!(decrypt_authenticator(&SERVICE_KEY, 11, &output).cname.0, user());
}

#[test]
fn build_encrypted_auth_data_uses_session_key_or_remembered_subkey() {
    let KeyedSession {
        mut session,
        tgt_handle,
        service_handle,
    } = session_with_keys();
    let alice = vec![USER.to_owned()];
    let auth_data = authorization_data();

    let encrypted = session
        .build_encrypted_auth_data(BuildEncryptedAuthDataRequest {
            key_usage: 4,
            key: key_ref(&tgt_handle),
            plain_auth_data: &auth_data,
        })
        .unwrap();
    assert_eq!(decrypt_der(&FORWARDED_TGT_KEY, 4, &encrypted), auth_data);

    let subkey_request = BuildEncryptedAuthDataRequest {
        key_usage: 5,
        key: key_ref(&SERVER_SUBKEY),
        plain_auth_data: &auth_data,
    };
    assert_eq!(
        kind(session.build_encrypted_auth_data(subkey_request)),
        ErrorKind::NoKerbKey
    );

    session
        .create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
            sub_key: Some(key_ref(&SERVER_SUBKEY)),
            ..authenticator_request(&service_handle, &alice)
        })
        .unwrap();

    let encrypted = session.build_encrypted_auth_data(subkey_request).unwrap();
    assert_eq!(decrypt_der(&SERVER_SUBKEY, 5, &encrypted), auth_data);

    let cases = [
        (
            "subkey with another encryption type",
            BuildEncryptedAuthDataRequest {
                key: KeyReference {
                    encryption_type: AES128,
                    value: &SERVER_SUBKEY,
                },
                ..subkey_request
            },
            ErrorKind::NoKerbKey,
        ),
        (
            "service key",
            BuildEncryptedAuthDataRequest {
                key_usage: 4,
                key: key_ref(&service_handle),
                plain_auth_data: &auth_data,
            },
            ErrorKind::NoKerbKey,
        ),
        (
            "raw TGT key",
            BuildEncryptedAuthDataRequest {
                key_usage: 4,
                key: key_ref(&FORWARDED_TGT_KEY),
                plain_auth_data: &auth_data,
            },
            ErrorKind::NoKerbKey,
        ),
        (
            "key handle as subkey",
            BuildEncryptedAuthDataRequest {
                key: key_ref(&tgt_handle),
                ..subkey_request
            },
            ErrorKind::NoKerbKey,
        ),
        (
            "key usage",
            BuildEncryptedAuthDataRequest {
                key_usage: 3,
                ..subkey_request
            },
            ErrorKind::UnsupportedFunction,
        ),
        (
            "invalid authorization data",
            BuildEncryptedAuthDataRequest {
                plain_auth_data: &[0x30, 0x05],
                ..subkey_request
            },
            ErrorKind::InvalidToken,
        ),
    ];

    for (name, request, expected) in cases {
        assert_eq!(kind(session.build_encrypted_auth_data(request)), expected, "{name}");
    }
    assert_protection_untouched(&mut session);
}

#[test]
fn server_subkeys_are_bounded() {
    let KeyedSession {
        mut session,
        service_handle,
        ..
    } = session_with_keys();
    let alice = vec![USER.to_owned()];
    let auth_data = authorization_data();

    let remember = |session: &mut RemoteGuardSession, subkey: [u8; 32]| {
        session
            .create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
                sub_key: Some(key_ref(&subkey)),
                ..authenticator_request(&service_handle, &alice)
            })
            .unwrap();
    };

    for i in 1..=64 {
        remember(&mut session, [i; 32]);
    }
    assert_eq!(session.server_subkeys.len(), 64);

    // A duplicate is not stored twice and does not refresh the entry.
    remember(&mut session, [1; 32]);
    assert_eq!(session.server_subkeys.len(), 64);

    remember(&mut session, [0xF0; 32]);
    assert_eq!(session.server_subkeys.len(), 64);

    let encrypt_with = |session: &mut RemoteGuardSession, subkey: [u8; 32]| {
        session.build_encrypted_auth_data(BuildEncryptedAuthDataRequest {
            key_usage: 5,
            key: key_ref(&subkey),
            plain_auth_data: &auth_data,
        })
    };

    assert_eq!(kind(encrypt_with(&mut session, [1; 32])), ErrorKind::NoKerbKey);
    for subkey in [[2; 32], [0xF0; 32]] {
        let encrypted = encrypt_with(&mut session, subkey).unwrap();
        assert_eq!(decrypt_der(&subkey, 5, &encrypted), auth_data);
    }
}

#[test]
fn create_ap_req_authenticator_rejects_tgs_raw_subkeys_before_output_or_retention() {
    let KeyedSession {
        mut session,
        tgt_handle,
        service_handle,
    } = session_with_keys();
    let alice = vec![USER.to_owned()];
    let auth_data = authorization_data();
    let checksum = gss_checksum();
    let base = CreateApReqAuthenticatorRequest {
        key_usage: 7,
        auth_data: Some(&auth_data),
        gss_checksum: Some(&checksum),
        ..authenticator_request(&tgt_handle, &alice)
    };

    // All Some values are refused before subkey or optional DER parsing.
    for sub_key in [
        key_ref(&SERVER_SUBKEY),
        KeyReference {
            encryption_type: AES128,
            value: &[0x99; 16],
        },
        KeyReference {
            encryption_type: i32::from(RC4),
            value: &[],
        },
        key_ref(&tgt_handle),
    ] {
        for (auth_data, gss_checksum) in [
            (Some(auth_data.as_slice()), Some(checksum.as_slice())),
            (Some(&[0xFF][..]), Some(&[0xFF][..])),
        ] {
            assert_eq!(
                kind(session.create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
                    sub_key: Some(sub_key),
                    auth_data,
                    gss_checksum,
                    ..base
                })),
                ErrorKind::UnsupportedFunction
            );
        }
    }
    assert_eq!(session.server_subkeys.len(), 0);
    assert_eq!(session.key_store.len(), 2);
    assert_eq!(
        kind(session.build_encrypted_auth_data(BuildEncryptedAuthDataRequest {
            key_usage: 5,
            key: key_ref(&SERVER_SUBKEY),
            plain_auth_data: &auth_data,
        })),
        ErrorKind::NoKerbKey
    );
    let reply = service_reply(&SERVER_SUBKEY);
    assert_eq!(
        kind(session.unpack_kdc_reply_body(UnpackKdcReplyBodyRequest {
            key_usage: 9,
            ..unpack_request(&reply, &SERVER_SUBKEY)
        })),
        ErrorKind::NoKerbKey
    );

    // Ownership, identity and skew checks still take precedence over subkey policy.
    let bob = vec!["bob".to_owned()];
    for (request, expected) in [
        (
            CreateApReqAuthenticatorRequest {
                encryption_key: key_ref(&FORWARDED_TGT_KEY),
                ..base
            },
            ErrorKind::NoKerbKey,
        ),
        (
            CreateApReqAuthenticatorRequest {
                client_name: &bob,
                ..base
            },
            ErrorKind::NoCredentials,
        ),
        (
            CreateApReqAuthenticatorRequest {
                skew_time: i64::MAX,
                ..base
            },
            ErrorKind::TimeSkew,
        ),
    ] {
        assert_eq!(
            kind(session.create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
                sub_key: Some(key_ref(&SERVER_SUBKEY)),
                ..request
            })),
            expected
        );
    }

    session
        .create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
            sub_key: Some(key_ref(&SERVER_SUBKEY)),
            ..authenticator_request(&service_handle, &alice)
        })
        .unwrap();
    assert_eq!(
        kind(session.create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
            sub_key: Some(key_ref(&SERVER_SUBKEY)),
            ..base
        })),
        ErrorKind::UnsupportedFunction
    );
    assert_eq!(session.server_subkeys.len(), 1);
    assert_protection_untouched(&mut session);
}

#[test]
fn create_ap_req_authenticator_supports_tgs_without_a_subkey() {
    let KeyedSession {
        mut session,
        tgt_handle,
        ..
    } = session_with_keys();
    let alice = vec![USER.to_owned()];
    let auth_data = authorization_data();
    let checksum = gss_checksum();
    let output = session
        .create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
            key_usage: 7,
            auth_data: Some(&auth_data),
            gss_checksum: Some(&checksum),
            ..authenticator_request(&tgt_handle, &alice)
        })
        .unwrap();
    let inner = decrypt_authenticator(&FORWARDED_TGT_KEY, 7, &output);
    assert_eq!(inner.crealm.0, realm(REALM));
    assert_eq!(inner.cname.0, user());
    assert_eq!(
        inner.authorization_data.0.unwrap().0,
        picky_asn1_der::from_bytes::<AuthorizationData>(&auth_data).unwrap()
    );
    assert_eq!(
        inner.cksum.0.unwrap().0,
        picky_asn1_der::from_bytes::<Checksum>(&checksum).unwrap()
    );
    assert!(inner.subkey.0.is_none());
    assert!(inner.seq_number.0.is_none());
    assert_eq!(session.server_subkeys.len(), 0);
    assert_protection_untouched(&mut session);
}

#[test]
fn create_ap_req_authenticator_keeps_service_subkeys_usable_for_safe_followup_operations() {
    let KeyedSession {
        mut session,
        service_handle,
        ..
    } = session_with_keys();
    let alice = vec![USER.to_owned()];
    let auth_data = authorization_data();
    for (encryption_type, subkey, suite) in [
        (AES128, vec![0x99; 16], CipherSuite::Aes128CtsHmacSha196),
        (AES256, SERVER_SUBKEY.to_vec(), AES256_SUITE),
    ] {
        let reference = KeyReference {
            encryption_type,
            value: &subkey,
        };
        let output = session
            .create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
                sub_key: Some(reference),
                ..authenticator_request(&service_handle, &alice)
            })
            .unwrap();
        let inner = decrypt_authenticator(&SERVICE_KEY, 11, &output);
        assert_eq!(
            inner.subkey.0.unwrap().0,
            encryption_key(u8::try_from(encryption_type).unwrap(), &subkey)
        );
        let encrypted = session
            .build_encrypted_auth_data(BuildEncryptedAuthDataRequest {
                key_usage: 5,
                key: reference,
                plain_auth_data: &auth_data,
            })
            .unwrap();
        let encrypted: EncryptedData = picky_asn1_der::from_bytes(&encrypted).unwrap();
        assert_eq!(
            suite.cipher().decrypt(&subkey, 5, &encrypted.cipher.0.0).unwrap(),
            auth_data
        );
        let part = EncTgsRepPart::from(tgs_reply_part(encryption_key(18, &NEW_TICKET_KEY), computer()));
        let cipher = suite
            .cipher()
            .encrypt(&subkey, 9, &picky_asn1_der::to_vec(&part).unwrap())
            .unwrap();
        let encrypted = picky_asn1_der::to_vec(&encrypted_data(u8::from(&suite), cipher)).unwrap();
        let unpacked = session
            .unpack_kdc_reply_body(UnpackKdcReplyBodyRequest {
                key: reference,
                key_usage: 9,
                ..unpack_request(&encrypted, &subkey)
            })
            .unwrap();
        assert_eq!(unpacked, picky_asn1_der::to_vec(&part).unwrap());
    }
    assert_eq!(session.server_subkeys.len(), 2);
    assert_protection_untouched(&mut session);
}

fn tgs_reply_part(key: EncryptionKey, sname: PrincipalName) -> EncKdcRepPart {
    enc_kdc_rep_part(
        key,
        IntegerAsn1::from(vec![0x12, 0x34]),
        &[0x40, 0x81, 0x00, 0x00],
        sname,
    )
}

fn encrypted_reply<T: serde::Serialize>(key: &[u8], usage: i32, part: &T) -> Vec<u8> {
    encrypt_der(key, usage, &picky_asn1_der::to_vec(part).unwrap())
}

fn unpack_request<'a>(encrypted_data: &'a [u8], key: &'a [u8]) -> UnpackKdcReplyBodyRequest<'a> {
    UnpackKdcReplyBodyRequest {
        encrypted_data,
        key: key_ref(key),
        strengthen_key: None,
        key_usage: 8,
    }
}

fn service_reply(key: &[u8]) -> Vec<u8> {
    encrypted_reply(
        key,
        USAGE_TGS_REP_SESSION_KEY,
        &EncTgsRepPart::from(tgs_reply_part(encryption_key(18, &NEW_TICKET_KEY), computer())),
    )
}

#[test]
fn unpack_kdc_reply_body_replaces_the_ticket_key_with_a_handle() {
    let KeyedSession {
        mut session,
        tgt_handle,
        ..
    } = session_with_keys();
    let alice = vec![USER.to_owned()];
    let part = tgs_reply_part(
        encryption_key(18, &NEW_TICKET_KEY),
        principal(NT_SRV_INST, &["krbtgt", "OTHER.EXAMPLE.COM"]),
    );
    let encrypted = encrypted_reply(
        &FORWARDED_TGT_KEY,
        USAGE_TGS_REP_SESSION_KEY,
        &EncTgsRepPart::from(part.clone()),
    );

    let unpacked = session
        .unpack_kdc_reply_body(unpack_request(&encrypted, &tgt_handle))
        .unwrap();

    assert_eq!(unpacked[0], 0x7A);
    assert!(!contains(&unpacked, &NEW_TICKET_KEY));
    let unpacked: EncTgsRepPart = picky_asn1_der::from_bytes(&unpacked).unwrap();
    let handle = unpacked.0.key.0.key_value.0.0.clone();
    assert_eq!(handle.len(), 32);
    assert_ne!(handle, NEW_TICKET_KEY);

    let mut expected = part;
    expected.key.0.key_value = ExplicitContextTag1::from(OctetStringAsn1::from(handle.clone()));
    assert_eq!(unpacked.0, expected);
    assert_eq!(session.key_store.len(), 3);

    // The referral key is usable only through its TGT handle.
    let body = kdc_req_body();
    let checksum = session.compute_tgs_checksum(checksum_request(&body, &handle)).unwrap();
    let checksum: Checksum = picky_asn1_der::from_bytes(&checksum).unwrap();
    assert_eq!(
        checksum.checksum.0.0,
        checksum_sha_aes(&NEW_TICKET_KEY, 6, &body, &AesSize::Aes256).unwrap()
    );
    assert_eq!(
        kind(session.create_ap_req_authenticator(authenticator_request(&handle, &alice))),
        ErrorKind::NoKerbKey
    );
    assert_protection_untouched(&mut session);
}

#[test]
fn unpack_kdc_reply_body_keeps_the_tgt_role_and_the_as_rep_tag() {
    let KeyedSession {
        mut session,
        tgt_handle,
        ..
    } = session_with_keys();
    let alice = vec![USER.to_owned()];
    let part = tgs_reply_part(
        encryption_key(18, &NEW_TICKET_KEY),
        principal(NT_SRV_INST, &["KRBTGT", "OTHER.EXAMPLE.COM"]),
    );
    let encrypted = encrypted_reply(&FORWARDED_TGT_KEY, USAGE_TGS_REP_SESSION_KEY, &EncAsRepPart::from(part));

    let unpacked = session
        .unpack_kdc_reply_body(unpack_request(&encrypted, &tgt_handle))
        .unwrap();

    assert_eq!(unpacked[0], 0x79);
    assert!(!contains(&unpacked, &NEW_TICKET_KEY));
    let unpacked: EncAsRepPart = picky_asn1_der::from_bytes(&unpacked).unwrap();
    let handle = unpacked.0.key.0.key_value.0.0.clone();

    let body = kdc_req_body();
    let checksum = session.compute_tgs_checksum(checksum_request(&body, &handle)).unwrap();
    let checksum: Checksum = picky_asn1_der::from_bytes(&checksum).unwrap();
    assert_eq!(
        checksum.checksum.0.0,
        checksum_sha_aes(&NEW_TICKET_KEY, USAGE_TGS_REQ_CHECKSUM, &body, &AesSize::Aes256).unwrap()
    );
    assert_eq!(
        kind(session.create_ap_req_authenticator(authenticator_request(&handle, &alice))),
        ErrorKind::NoKerbKey
    );
}

#[test]
fn unpack_kdc_reply_body_with_a_remembered_subkey() {
    let KeyedSession {
        mut session,
        service_handle,
        ..
    } = session_with_keys();
    let alice = vec![USER.to_owned()];
    let aes128_ticket_key = [0x88; 16];

    session
        .create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
            sub_key: Some(key_ref(&SERVER_SUBKEY)),
            ..authenticator_request(&service_handle, &alice)
        })
        .unwrap();

    let encrypted = encrypted_reply(
        &SERVER_SUBKEY,
        USAGE_TGS_REP_SUB_KEY,
        &EncTgsRepPart::from(tgs_reply_part(encryption_key(17, &aes128_ticket_key), computer())),
    );
    let unpacked = session
        .unpack_kdc_reply_body(UnpackKdcReplyBodyRequest {
            key_usage: 9,
            ..unpack_request(&encrypted, &SERVER_SUBKEY)
        })
        .unwrap();

    let unpacked: EncTgsRepPart = picky_asn1_der::from_bytes(&unpacked).unwrap();
    assert_eq!(unpacked.0.key.0.key_type.0, IntegerAsn1::from(vec![17]));
    let handle = unpacked.0.key.0.key_value.0.0.clone();
    assert_eq!(handle.len(), 16);
    assert_eq!(handle, aes128_ticket_key);

    let authenticator = session
        .create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
            encryption_key: KeyReference {
                encryption_type: AES128,
                value: &handle,
            },
            ..authenticator_request(&handle, &alice)
        })
        .unwrap();
    let encrypted: EncryptedData = picky_asn1_der::from_bytes(&authenticator.authenticator).unwrap();
    assert_eq!(encrypted.etype.0, IntegerAsn1::from(vec![17]));
    CipherSuite::Aes128CtsHmacSha196
        .cipher()
        .decrypt(&aes128_ticket_key, USAGE_AP_REQ_AUTHENTICATOR, &encrypted.cipher.0.0)
        .unwrap();
}

#[test]
fn unpack_kdc_reply_body_rejects_invalid_requests() {
    let KeyedSession {
        mut session,
        tgt_handle,
        service_handle,
    } = session_with_keys();

    let reply_with_key = |key: EncryptionKey| {
        encrypted_reply(
            &FORWARDED_TGT_KEY,
            USAGE_TGS_REP_SESSION_KEY,
            &EncTgsRepPart::from(tgs_reply_part(key, computer())),
        )
    };
    let valid = service_reply(&FORWARDED_TGT_KEY);
    let rc4_ticket_key = reply_with_key(encryption_key(RC4, &[0x88; 16]));
    let short_ticket_key = reply_with_key(encryption_key(18, &[0x88; 16]));
    let wrong_key = service_reply(&SERVICE_KEY);
    let wrong_usage = encrypted_reply(
        &FORWARDED_TGT_KEY,
        USAGE_TGS_REP_SUB_KEY,
        &EncTgsRepPart::from(tgs_reply_part(encryption_key(18, &NEW_TICKET_KEY), computer())),
    );
    let not_a_reply = encrypt_der(&FORWARDED_TGT_KEY, USAGE_TGS_REP_SESSION_KEY, &enc_ap_rep_part());
    let aes128_etype = {
        let cipher = AES256_SUITE
            .cipher()
            .encrypt(&FORWARDED_TGT_KEY, USAGE_TGS_REP_SESSION_KEY, b"reply")
            .unwrap();
        picky_asn1_der::to_vec(&encrypted_data(17, cipher)).unwrap()
    };
    let base = unpack_request(&valid, &tgt_handle);

    let cases = [
        (
            "strengthen key",
            UnpackKdcReplyBodyRequest {
                strengthen_key: Some(key_ref(&tgt_handle)),
                ..base
            },
            ErrorKind::UnsupportedFunction,
        ),
        (
            "AS-REP usage",
            UnpackKdcReplyBodyRequest { key_usage: 3, ..base },
            ErrorKind::UnsupportedFunction,
        ),
        (
            "service key",
            unpack_request(&valid, &service_handle),
            ErrorKind::NoKerbKey,
        ),
        (
            "raw key",
            unpack_request(&valid, &FORWARDED_TGT_KEY),
            ErrorKind::NoKerbKey,
        ),
        (
            "unknown subkey",
            UnpackKdcReplyBodyRequest {
                key_usage: 9,
                ..unpack_request(&valid, &SERVER_SUBKEY)
            },
            ErrorKind::NoKerbKey,
        ),
        ("empty", unpack_request(&[], &tgt_handle), ErrorKind::InvalidParameter),
        (
            "invalid encrypted data",
            unpack_request(&[0x30, 0x01], &tgt_handle),
            ErrorKind::InvalidToken,
        ),
        (
            "encryption type",
            unpack_request(&aes128_etype, &tgt_handle),
            ErrorKind::AlgorithmMismatch,
        ),
        (
            "wrong key",
            unpack_request(&wrong_key, &tgt_handle),
            ErrorKind::DecryptFailure,
        ),
        (
            "wrong key usage",
            unpack_request(&wrong_usage, &tgt_handle),
            ErrorKind::DecryptFailure,
        ),
        (
            "not a KDC reply",
            unpack_request(&not_a_reply, &tgt_handle),
            ErrorKind::InvalidToken,
        ),
        (
            "RC4 ticket key",
            unpack_request(&rc4_ticket_key, &tgt_handle),
            ErrorKind::AlgorithmMismatch,
        ),
        (
            "short ticket key",
            unpack_request(&short_ticket_key, &tgt_handle),
            ErrorKind::InvalidParameter,
        ),
    ];

    for (name, request, expected) in cases {
        assert_eq!(kind(session.unpack_kdc_reply_body(request)), expected, "{name}");
    }

    for (encryption_type, length) in [(17, 0), (17, 15), (17, 17), (18, 0), (18, 31), (18, 33)] {
        let encrypted = reply_with_key(encryption_key(encryption_type, &vec![0x88; length]));
        assert_eq!(
            kind(session.unpack_kdc_reply_body(unpack_request(&encrypted, &tgt_handle))),
            ErrorKind::InvalidParameter
        );
        assert_eq!(session.key_store.len(), 2);
    }

    assert_eq!(session.key_store.len(), 2);
    assert_protection_untouched(&mut session);
}

#[test]
fn key_handles_are_bound_to_their_session() {
    let mut first = session_with_keys();
    let encrypted = service_reply(&FORWARDED_TGT_KEY);
    let unpacked = first
        .session
        .unpack_kdc_reply_body(unpack_request(&encrypted, &first.tgt_handle))
        .unwrap();
    let unpacked: EncTgsRepPart = picky_asn1_der::from_bytes(&unpacked).unwrap();
    let handle = unpacked.0.key.0.key_value.0.0;

    let mut second = session(1000, 2000);
    let alice = vec![USER.to_owned()];
    let body = kdc_req_body();

    assert_eq!(
        kind(second.create_ap_req_authenticator(authenticator_request(&handle, &alice))),
        ErrorKind::NoKerbKey
    );
    assert_eq!(
        kind(second.compute_tgs_checksum(checksum_request(&body, &first.tgt_handle))),
        ErrorKind::NoKerbKey
    );
}

fn check_service_key_preservation(suite: CipherSuite, as_rep: bool) {
    let KeyedSession {
        mut session,
        tgt_handle,
        ..
    } = session_with_keys();
    let raw_key = vec![0x98; suite.cipher().key_size()];
    let part = tgs_reply_part(encryption_key(u8::from(&suite), &raw_key), computer());
    let expected = if as_rep {
        picky_asn1_der::to_vec(&EncAsRepPart::from(part.clone())).unwrap()
    } else {
        picky_asn1_der::to_vec(&EncTgsRepPart::from(part.clone())).unwrap()
    };
    let encrypted = encrypt_der(&FORWARDED_TGT_KEY, 8, &expected);
    let output = session
        .unpack_kdc_reply_body(unpack_request(&encrypted, &tgt_handle))
        .unwrap();
    assert_eq!(output, expected);
    assert_eq!(output[0], if as_rep { 0x79 } else { 0x7A });
    assert_eq!(session.key_store.len(), 3);
    check_service_operations(
        &mut session,
        KeyReference {
            encryption_type: i32::from(u8::from(&suite)),
            value: &raw_key,
        },
        &suite,
        &raw_key,
    );
    assert_protection_untouched(&mut session);
}

fn check_service_operations(
    session: &mut RemoteGuardSession,
    reference: KeyReference<'_>,
    suite: &CipherSuite,
    raw_key: &[u8],
) {
    let alice = vec!["ALICE".to_owned()];
    let authenticator = session
        .create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
            encryption_key: reference,
            client_realm: "example.com",
            sequence_number: 42,
            ..authenticator_request(reference.value, &alice)
        })
        .unwrap();
    let encrypted: EncryptedData = picky_asn1_der::from_bytes(&authenticator.authenticator).unwrap();
    assert_eq!(integer_to_i32(&encrypted.etype.0).unwrap(), reference.encryption_type);
    let decrypted = suite.cipher().decrypt(raw_key, 11, &encrypted.cipher.0.0).unwrap();
    let inner = picky_asn1_der::from_bytes::<Authenticator>(&decrypted).unwrap().0;
    assert_eq!(inner.cname.0, user());
    assert_eq!(inner.crealm.0, realm(REALM));
    assert_eq!(integer_to_i32(&inner.seq_number.0.unwrap().0).unwrap(), 42);
    assert!(inner.subkey.0.is_none());

    let body = enc_ap_rep_part();
    let template = valid_ap_rep_template();
    let packed = session
        .pack_ap_reply(PackApReplyRequest {
            reply: &template,
            reply_body: &body,
            session_key: reference,
        })
        .unwrap();
    let packed: ApRep = picky_asn1_der::from_bytes(&packed).unwrap();
    assert_eq!(integer_to_i32(&packed.0.pvno.0).unwrap(), 5);
    assert_eq!(integer_to_i32(&packed.0.msg_type.0).unwrap(), 15);
    assert!(packed.0.enc_part.0.kvno.0.is_none());
    assert_eq!(
        integer_to_i32(&packed.0.enc_part.0.etype.0).unwrap(),
        reference.encryption_type
    );
    assert_eq!(
        suite
            .cipher()
            .decrypt(raw_key, 12, &packed.0.enc_part.0.cipher.0.0)
            .unwrap(),
        body
    );

    // Construct the inbound reply independently rather than round-tripping the packer.
    let cipher = suite.cipher().encrypt(raw_key, 12, &body).unwrap();
    let inbound = picky_asn1_der::to_vec(&encrypted_data(u8::from(suite), cipher)).unwrap();
    assert_eq!(
        session
            .decrypt_ap_reply(DecryptApReplyRequest {
                encrypted_reply: &inbound,
                key: reference,
            })
            .unwrap()
            .as_ref(),
        &body
    );
}

#[test]
fn unpack_kdc_reply_body_preserves_aes128_service_key_in_enc_as_rep() {
    check_service_key_preservation(CipherSuite::Aes128CtsHmacSha196, true);
}

#[test]
fn unpack_kdc_reply_body_preserves_aes128_service_key_in_enc_tgs_rep() {
    check_service_key_preservation(CipherSuite::Aes128CtsHmacSha196, false);
}

#[test]
fn unpack_kdc_reply_body_preserves_aes256_service_key_in_enc_as_rep() {
    check_service_key_preservation(AES256_SUITE, true);
}

#[test]
fn unpack_kdc_reply_body_preserves_aes256_service_key_in_enc_tgs_rep() {
    check_service_key_preservation(AES256_SUITE, false);
}

#[test]
fn unpack_kdc_reply_body_hides_tgt_and_referral_keys_for_both_aes_sizes_and_tags() {
    for suite in [CipherSuite::Aes128CtsHmacSha196, AES256_SUITE] {
        for as_rep in [false, true] {
            for (names, key_usage) in [
                vec!["krbtgt", REALM],
                vec!["KrBtGt", "OTHER.EXAMPLE.COM"],
                vec!["KRBTGT"],
            ]
            .into_iter()
            .flat_map(|names| [8, 9].map(move |usage| (names.clone(), usage)))
            {
                let KeyedSession {
                    mut session,
                    service_handle,
                    ..
                } = session_with_keys();
                let raw_key = vec![0xA9; suite.cipher().key_size()];
                let etype = i32::from(u8::from(&suite));
                // Exercise AES128 as the input/decryption key as well as the returned key.
                let input_key = vec![0xB9; suite.cipher().key_size()];
                let input_reference = if key_usage == 8 {
                    session
                        .key_store
                        .insert(
                            suite.clone(),
                            Secret::new(input_key.clone()),
                            KeyRole::TicketGranting,
                            &mut StdRng::seed_from_u64(56),
                        )
                        .unwrap()
                } else {
                    let alice = vec![USER.to_owned()];
                    session
                        .create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
                            sub_key: Some(KeyReference {
                                encryption_type: etype,
                                value: &input_key,
                            }),
                            ..authenticator_request(&service_handle, &alice)
                        })
                        .unwrap();
                    input_key.clone()
                };
                let part = tgs_reply_part(
                    encryption_key(u8::from(&suite), &raw_key),
                    principal(NT_SRV_INST, &names),
                );
                let plaintext = if as_rep {
                    picky_asn1_der::to_vec(&EncAsRepPart::from(part.clone())).unwrap()
                } else {
                    picky_asn1_der::to_vec(&EncTgsRepPart::from(part.clone())).unwrap()
                };
                let cipher = suite.cipher().encrypt(&input_key, key_usage, &plaintext).unwrap();
                let encrypted = picky_asn1_der::to_vec(&encrypted_data(u8::from(&suite), cipher)).unwrap();
                let output = session
                    .unpack_kdc_reply_body(UnpackKdcReplyBodyRequest {
                        key_usage: u32::try_from(key_usage).unwrap(),
                        key: KeyReference {
                            encryption_type: etype,
                            value: &input_reference,
                        },
                        ..unpack_request(&encrypted, &input_reference)
                    })
                    .unwrap();
                assert!(!contains(&output, &raw_key));
                assert_eq!(output[0], if as_rep { 0x79 } else { 0x7A });
                let decoded = if as_rep {
                    picky_asn1_der::from_bytes::<EncAsRepPart>(&output).unwrap().0
                } else {
                    picky_asn1_der::from_bytes::<EncTgsRepPart>(&output).unwrap().0
                };
                let handle = decoded.key.0.key_value.0.0.clone();
                assert_eq!(handle.len(), raw_key.len());
                let mut expected = part;
                expected.key.0.key_value.0.0 = handle.clone();
                assert_eq!(decoded, expected);
                let body = kdc_req_body();
                let checksum = session
                    .compute_tgs_checksum(ComputeTgsChecksumRequest {
                        request_body: &body,
                        key: KeyReference {
                            encryption_type: etype,
                            value: &handle,
                        },
                        checksum_type: if etype == AES128 { 15 } else { 16 },
                    })
                    .unwrap();
                let checksum: Checksum = picky_asn1_der::from_bytes(&checksum).unwrap();
                assert_eq!(
                    checksum.checksum.0.0,
                    checksum_sha_aes(&raw_key, 6, &body, &wrap::aes_size(&suite).unwrap()).unwrap()
                );
                assert_eq!(
                    kind(session.compute_tgs_checksum(ComputeTgsChecksumRequest {
                        request_body: &body,
                        key: KeyReference {
                            encryption_type: etype,
                            value: &raw_key,
                        },
                        checksum_type: 7,
                    })),
                    ErrorKind::NoKerbKey
                );
                assert_protection_untouched(&mut session);
            }
        }
    }
}

#[test]
fn unpack_kdc_reply_body_classifies_only_exact_first_krbtgt_component_as_tgt() {
    for names in [
        vec!["krbtgtx", REALM],
        vec!["xkrbtgt", REALM],
        vec!["cifs", "krbtgt"],
        vec![],
    ] {
        let KeyedSession {
            mut session,
            tgt_handle,
            ..
        } = session_with_keys();
        let part = EncTgsRepPart::from(tgs_reply_part(
            encryption_key(18, &NEW_TICKET_KEY),
            principal(NT_SRV_INST, &names),
        ));
        let encrypted = encrypted_reply(&FORWARDED_TGT_KEY, 8, &part);
        let output = session
            .unpack_kdc_reply_body(unpack_request(&encrypted, &tgt_handle))
            .unwrap();
        assert_eq!(output, picky_asn1_der::to_vec(&part).unwrap());
        check_service_operations(&mut session, key_ref(&NEW_TICKET_KEY), &AES256_SUITE, &NEW_TICKET_KEY);
    }
}

#[test]
fn service_key_handles_and_retained_bytes_support_service_operations() {
    let KeyedSession {
        mut session,
        service_handle,
        ..
    } = session_with_keys();
    for reference in [key_ref(&service_handle), key_ref(&SERVICE_KEY)] {
        check_service_operations(&mut session, reference, &AES256_SUITE, &SERVICE_KEY);
    }
    assert_protection_untouched(&mut session);
}

#[test]
fn service_operations_reject_unretained_foreign_and_tgt_key_bytes() {
    let mut session = session_with_keys().session;
    let mut foreign = session_with_keys();
    let encrypted = service_reply(&FORWARDED_TGT_KEY);
    foreign
        .session
        .unpack_kdc_reply_body(unpack_request(&encrypted, &foreign.tgt_handle))
        .unwrap();
    let alice = vec![USER.to_owned()];
    let body = enc_ap_rep_part();
    let template = valid_ap_rep_template();
    for raw_key in [&NEW_TICKET_KEY, &FORWARDED_TGT_KEY, &[0xFE; 32]] {
        assert_eq!(
            kind(session.create_ap_req_authenticator(authenticator_request(raw_key, &alice))),
            ErrorKind::NoKerbKey
        );
        let encrypted = encrypt_der(raw_key, 12, &body);
        assert_eq!(
            kind(session.decrypt_ap_reply(DecryptApReplyRequest {
                encrypted_reply: &encrypted,
                key: key_ref(raw_key),
            })),
            ErrorKind::NoKerbKey
        );
        assert_eq!(
            kind(session.pack_ap_reply(PackApReplyRequest {
                reply: &template,
                reply_body: &body,
                session_key: key_ref(raw_key),
            })),
            ErrorKind::NoKerbKey
        );
    }
    assert_protection_untouched(&mut session);
}

#[test]
fn service_key_references_preserve_enctype_and_role_authorization() {
    let KeyedSession {
        mut session,
        service_handle,
        tgt_handle,
    } = session_with_keys();
    let alice = vec![USER.to_owned()];
    let body = kdc_req_body();
    let ap_body = enc_ap_rep_part();
    let template = valid_ap_rep_template();
    let auth_data = authorization_data();
    for reference in [&service_handle[..], &SERVICE_KEY[..]] {
        let wrong_type = KeyReference {
            encryption_type: AES128,
            value: reference,
        };
        assert_eq!(
            kind(session.create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
                encryption_key: wrong_type,
                ..authenticator_request(reference, &alice)
            })),
            ErrorKind::AlgorithmMismatch
        );
        assert_eq!(
            kind(session.pack_ap_reply(PackApReplyRequest {
                reply: &template,
                reply_body: &ap_body,
                session_key: wrong_type,
            })),
            ErrorKind::AlgorithmMismatch
        );
        let encrypted = encrypt_der(&SERVICE_KEY, 12, &ap_body);
        assert_eq!(
            kind(session.decrypt_ap_reply(DecryptApReplyRequest {
                encrypted_reply: &encrypted,
                key: wrong_type,
            })),
            ErrorKind::AlgorithmMismatch
        );
        assert_eq!(
            kind(session.compute_tgs_checksum(checksum_request(&body, reference))),
            ErrorKind::NoKerbKey
        );
        assert_eq!(
            kind(session.build_encrypted_auth_data(BuildEncryptedAuthDataRequest {
                key_usage: 4,
                key: key_ref(reference),
                plain_auth_data: &auth_data,
            })),
            ErrorKind::NoKerbKey
        );
        assert_eq!(
            kind(session.create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
                key_usage: 7,
                ..authenticator_request(reference, &alice)
            })),
            ErrorKind::NoKerbKey
        );
        for names in [
            vec![],
            vec!["bob".to_owned()],
            vec![USER.to_owned(), "extra".to_owned()],
        ] {
            assert_eq!(
                kind(session.create_ap_req_authenticator(authenticator_request(reference, &names))),
                ErrorKind::NoCredentials
            );
        }
        assert_eq!(
            kind(session.create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
                client_realm: "OTHER.COM",
                ..authenticator_request(reference, &alice)
            })),
            ErrorKind::NoCredentials
        );
    }
    for reference in [&tgt_handle[..], &FORWARDED_TGT_KEY[..]] {
        assert_eq!(
            kind(session.pack_ap_reply(PackApReplyRequest {
                reply: &template,
                reply_body: &ap_body,
                session_key: key_ref(reference),
            })),
            ErrorKind::NoKerbKey
        );
    }
    assert_protection_untouched(&mut session);
}

#[test]
fn unpack_kdc_reply_body_preserves_key_store_capacity_and_failed_insert_atomicity() {
    let KeyedSession {
        mut session,
        tgt_handle,
        ..
    } = session_with_keys();
    let mut last_key = Vec::new();
    for n in 2..key_store::MAX_KEYS {
        let mut raw_key = vec![0xA5; 32];
        raw_key[..8].copy_from_slice(&n.to_le_bytes());
        let reply = EncTgsRepPart::from(tgs_reply_part(encryption_key(18, &raw_key), computer()));
        let encrypted = encrypted_reply(&FORWARDED_TGT_KEY, 8, &reply);
        let output = session
            .unpack_kdc_reply_body(unpack_request(&encrypted, &tgt_handle))
            .unwrap();
        assert_eq!(output, picky_asn1_der::to_vec(&reply).unwrap());
        assert_eq!(session.key_store.len(), n + 1);
        last_key = raw_key;
    }
    let failed = service_reply(&FORWARDED_TGT_KEY);
    assert_eq!(
        kind(session.unpack_kdc_reply_body(unpack_request(&failed, &tgt_handle))),
        ErrorKind::InsufficientMemory
    );
    assert_eq!(session.key_store.len(), key_store::MAX_KEYS);
    let alice = vec![USER.to_owned()];
    assert_eq!(
        kind(session.create_ap_req_authenticator(authenticator_request(&NEW_TICKET_KEY, &alice))),
        ErrorKind::NoKerbKey
    );
    check_service_operations(&mut session, key_ref(&last_key), &AES256_SUITE, &last_key);
    let body = kdc_req_body();
    session
        .compute_tgs_checksum(checksum_request(&body, &tgt_handle))
        .unwrap();
    assert_protection_untouched(&mut session);
}

#[test]
fn unpack_kdc_reply_body_preserves_input_authorization_before_retention() {
    let KeyedSession {
        mut session,
        tgt_handle,
        service_handle,
    } = session_with_keys();
    let encrypted = service_reply(&FORWARDED_TGT_KEY);
    for key in [&SERVICE_KEY[..], &service_handle, &FORWARDED_TGT_KEY] {
        assert_eq!(
            kind(session.unpack_kdc_reply_body(unpack_request(&encrypted, key))),
            ErrorKind::NoKerbKey
        );
        assert_eq!(session.key_store.len(), 2);
    }
    session
        .unpack_kdc_reply_body(unpack_request(&encrypted, &tgt_handle))
        .unwrap();
    assert_eq!(session.key_store.len(), 3);
    check_service_operations(&mut session, key_ref(&NEW_TICKET_KEY), &AES256_SUITE, &NEW_TICKET_KEY);
}

#[test]
fn unpack_kdc_reply_body_checks_exact_input_size_boundary() {
    let KeyedSession {
        mut session,
        tgt_handle,
        ..
    } = session_with_keys();
    let mut wrapper = encrypted_data(18, vec![0; MAX_OPERATION_INPUT_LEN]);
    let overhead = picky_asn1_der::to_vec(&wrapper).unwrap().len() - MAX_OPERATION_INPUT_LEN;
    wrapper.cipher.0.0.truncate(MAX_OPERATION_INPUT_LEN - overhead);
    let missing = MAX_OPERATION_INPUT_LEN - picky_asn1_der::to_vec(&wrapper).unwrap().len();
    wrapper.cipher.0.0.resize(wrapper.cipher.0.0.len() + missing, 0);
    let boundary = picky_asn1_der::to_vec(&wrapper).unwrap();
    assert_eq!(boundary.len(), MAX_OPERATION_INPUT_LEN);
    for (input, expected) in [
        (&[][..], ErrorKind::InvalidParameter),
        (boundary.as_slice(), ErrorKind::DecryptFailure),
        (
            vec![0; MAX_OPERATION_INPUT_LEN + 1].as_slice(),
            ErrorKind::InvalidParameter,
        ),
    ] {
        assert_eq!(
            kind(session.unpack_kdc_reply_body(unpack_request(input, &tgt_handle))),
            expected
        );
        assert_eq!(session.key_store.len(), 2);
    }
    assert_protection_untouched(&mut session);
}

#[test]
fn build_encrypted_auth_data_checks_exact_input_size_boundary() {
    let KeyedSession {
        mut session,
        tgt_handle,
        ..
    } = session_with_keys();
    let mut data: AuthorizationData = picky_asn1_der::from_bytes(&authorization_data()).unwrap();
    data.0[0].ad_data.0.0 = vec![0x42; MAX_OPERATION_INPUT_LEN];
    let overhead = picky_asn1_der::to_vec(&data).unwrap().len() - MAX_OPERATION_INPUT_LEN;
    data.0[0].ad_data.0.0.truncate(MAX_OPERATION_INPUT_LEN - overhead);
    let missing = MAX_OPERATION_INPUT_LEN - picky_asn1_der::to_vec(&data).unwrap().len();
    let length = data.0[0].ad_data.0.0.len() + missing;
    data.0[0].ad_data.0.0.resize(length, 0x42);
    let boundary = picky_asn1_der::to_vec(&data).unwrap();
    assert_eq!(boundary.len(), MAX_OPERATION_INPUT_LEN);
    let encrypted = session
        .build_encrypted_auth_data(BuildEncryptedAuthDataRequest {
            key_usage: 4,
            key: key_ref(&tgt_handle),
            plain_auth_data: &boundary,
        })
        .unwrap();
    assert_eq!(decrypt_der(&FORWARDED_TGT_KEY, 4, &encrypted), boundary);
    for input in [&[][..], vec![0; MAX_OPERATION_INPUT_LEN + 1].as_slice()] {
        assert_eq!(
            kind(session.build_encrypted_auth_data(BuildEncryptedAuthDataRequest {
                key_usage: 4,
                key: key_ref(&tgt_handle),
                plain_auth_data: input,
            })),
            ErrorKind::InvalidParameter
        );
    }
    assert_protection_untouched(&mut session);
}

#[test]
fn poisoned_session_rejects_retained_raw_service_keys() {
    let mut session = session_with_keys().session;
    assert_eq!(
        kind(session.unwrap(&server_seal(2001, b"wrong sequence"))),
        ErrorKind::OutOfSequence
    );
    assert!(session.is_poisoned());
    assert_eq!(session.key_store.len(), 0);
    let alice = vec![USER.to_owned()];
    let body = enc_ap_rep_part();
    let template = valid_ap_rep_template();
    let encrypted = encrypt_der(&SERVICE_KEY, 12, &body);
    assert_eq!(
        kind(session.create_ap_req_authenticator(authenticator_request(&SERVICE_KEY, &alice))),
        ErrorKind::ContextExpired
    );
    assert_eq!(
        kind(session.pack_ap_reply(PackApReplyRequest {
            reply: &template,
            reply_body: &body,
            session_key: key_ref(&SERVICE_KEY),
        })),
        ErrorKind::ContextExpired
    );
    assert_eq!(
        kind(session.decrypt_ap_reply(DecryptApReplyRequest {
            encrypted_reply: &encrypted,
            key: key_ref(&SERVICE_KEY),
        })),
        ErrorKind::ContextExpired
    );
}

#[test]
fn pack_and_decrypt_ap_reply_use_the_service_key() {
    let KeyedSession {
        mut session,
        service_handle,
        ..
    } = session_with_keys();
    let body = enc_ap_rep_part();
    let template = valid_ap_rep_template();

    let packed = session
        .pack_ap_reply(PackApReplyRequest {
            reply: &template,
            reply_body: &body,
            session_key: key_ref(&service_handle),
        })
        .unwrap();

    let reply: ApRep = picky_asn1_der::from_bytes(&packed).unwrap();
    assert_eq!(reply.0.pvno.0, IntegerAsn1::from(vec![5]));
    assert_eq!(reply.0.msg_type.0, IntegerAsn1::from(vec![15]));
    let enc_part = picky_asn1_der::to_vec(&reply.0.enc_part.0).unwrap();
    assert_eq!(decrypt_der(&SERVICE_KEY, USAGE_AP_REP, &enc_part), body);

    let decrypted = session
        .decrypt_ap_reply(DecryptApReplyRequest {
            encrypted_reply: &enc_part,
            key: key_ref(&service_handle),
        })
        .unwrap();
    assert_eq!(decrypted.as_ref(), &body);

    let server_reply = encrypt_der(&SERVICE_KEY, USAGE_AP_REP, &body);
    let decrypted = session
        .decrypt_ap_reply(DecryptApReplyRequest {
            encrypted_reply: &server_reply,
            key: key_ref(&service_handle),
        })
        .unwrap();
    assert_eq!(decrypted.as_ref(), &body);
    assert_protection_untouched(&mut session);
}

#[test]
fn ap_reply_operations_reject_invalid_requests() {
    let KeyedSession {
        mut session,
        tgt_handle,
        service_handle,
    } = session_with_keys();
    let body = enc_ap_rep_part();
    let template = valid_ap_rep_template();
    let auth_data = authorization_data();

    let pack_cases = [
        ("TGT key", &body[..], &tgt_handle[..], ErrorKind::NoKerbKey),
        (
            "unretained raw key",
            &body[..],
            &NEW_TICKET_KEY[..],
            ErrorKind::NoKerbKey,
        ),
        (
            "not an AP-REP part",
            &auth_data[..],
            &service_handle[..],
            ErrorKind::InvalidToken,
        ),
        ("empty", &[][..], &service_handle[..], ErrorKind::InvalidParameter),
    ];
    for (name, reply_body, key, expected) in pack_cases {
        let request = PackApReplyRequest {
            reply: &template,
            reply_body,
            session_key: key_ref(key),
        };
        assert_eq!(kind(session.pack_ap_reply(request)), expected, "{name}");
    }

    let encrypted = encrypt_der(&SERVICE_KEY, USAGE_AP_REP, &body);
    let wrong_usage = encrypt_der(&SERVICE_KEY, USAGE_AP_REQ_AUTHENTICATOR, &body);
    let not_a_reply = encrypt_der(&SERVICE_KEY, USAGE_AP_REP, &auth_data);

    let decrypt_cases = [
        ("TGT key", &encrypted[..], &tgt_handle[..], ErrorKind::NoKerbKey),
        (
            "unretained raw key",
            &encrypted[..],
            &NEW_TICKET_KEY[..],
            ErrorKind::NoKerbKey,
        ),
        (
            "wrong key usage",
            &wrong_usage[..],
            &service_handle[..],
            ErrorKind::DecryptFailure,
        ),
        (
            "not an AP-REP part",
            &not_a_reply[..],
            &service_handle[..],
            ErrorKind::InvalidToken,
        ),
        ("empty", &[][..], &service_handle[..], ErrorKind::InvalidParameter),
    ];
    for (name, encrypted_reply, key, expected) in decrypt_cases {
        let request = DecryptApReplyRequest {
            encrypted_reply,
            key: key_ref(key),
        };
        assert_eq!(kind(session.decrypt_ap_reply(request)), expected, "{name}");
    }

    assert_protection_untouched(&mut session);
}

#[test]
fn pack_ap_reply_updates_only_the_template_encrypted_part() {
    let KeyedSession {
        mut session,
        service_handle,
        ..
    } = session_with_keys();
    let body = enc_ap_rep_part();

    let placeholders = [
        ("empty placeholder", encrypted_data(0, Vec::new())),
        ("stale placeholder", encrypted_data(17, vec![0xAB; 40])),
        (
            "placeholder with kvno",
            EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
                kvno: Optional::from(Some(ExplicitContextTag1::from(IntegerAsn1::from(vec![2])))),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(vec![0xCD; 8])),
            },
        ),
        (
            "signed etype and maximum kvno",
            EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![0x80, 0, 0, 0])),
                kvno: Optional::from(Some(ExplicitContextTag1::from(IntegerAsn1::from(vec![
                    0, 0xFF, 0xFF, 0xFF, 0xFF,
                ])))),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(Vec::new())),
            },
        ),
    ];
    for (name, placeholder) in placeholders {
        let template = ap_rep_template(vec![5], vec![15], placeholder);

        let packed = session
            .pack_ap_reply(PackApReplyRequest {
                reply: &template,
                reply_body: &body,
                session_key: key_ref(&service_handle),
            })
            .unwrap();

        let mut reply: ApRep = picky_asn1_der::from_bytes(&packed).unwrap();
        let enc_part = reply.0.enc_part.0.clone();
        assert_eq!(enc_part.etype.0, IntegerAsn1::from(vec![18]), "{name}");
        assert!(enc_part.kvno.0.is_none(), "{name}");
        assert_eq!(
            decrypt_der(&SERVICE_KEY, USAGE_AP_REP, &picky_asn1_der::to_vec(&enc_part).unwrap()),
            body,
            "{name}"
        );

        // Restoring the placeholder gives back the template: nothing else was changed.
        let template_reply: ApRep = picky_asn1_der::from_bytes(&template).unwrap();
        reply.0.enc_part = template_reply.0.enc_part;
        assert_eq!(picky_asn1_der::to_vec(&reply).unwrap(), template, "{name}");
    }

    assert_protection_untouched(&mut session);
}

#[test]
fn pack_ap_reply_rejects_invalid_templates() {
    let KeyedSession {
        mut session,
        service_handle,
        ..
    } = session_with_keys();
    let body = enc_ap_rep_part();
    let valid = valid_ap_rep_template();
    assert!(valid[1] < 0x80, "the template uses a short-form length");

    let as_ap_req = {
        let mut template = valid.clone();
        template[0] = 0x6E;
        template
    };
    let long_form_length = [&[valid[0], 0x81][..], &valid[1..]].concat();
    let trailing_data = [&valid[..], &[0x00][..]].concat();
    let wrong_pvno = ap_rep_template(vec![4], vec![15], encrypted_data(0, Vec::new()));
    let non_minimal_pvno = ap_rep_template(vec![0, 5], vec![15], encrypted_data(0, Vec::new()));
    let wrong_msg_type = ap_rep_template(vec![5], vec![14], encrypted_data(0, Vec::new()));
    let non_minimal_msg_type = ap_rep_template(vec![5], vec![0, 15], encrypted_data(0, Vec::new()));
    let krb_error_msg_type = ap_rep_template(vec![5], vec![30], encrypted_data(0, Vec::new()));
    let oversized = vec![0x30; MAX_OPERATION_INPUT_LEN + 1];

    let cases = [
        ("empty", &[][..], ErrorKind::InvalidParameter),
        ("oversized", &oversized[..], ErrorKind::InvalidParameter),
        ("garbage", &[0xFF, 0x00, 0x01][..], ErrorKind::InvalidToken),
        ("EncAPRepPart instead of KRB_AP_REP", &body[..], ErrorKind::InvalidToken),
        ("AP-REQ application tag", &as_ap_req[..], ErrorKind::InvalidToken),
        ("long-form length", &long_form_length[..], ErrorKind::InvalidToken),
        ("trailing data", &trailing_data[..], ErrorKind::InvalidToken),
        ("wrong pvno", &wrong_pvno[..], ErrorKind::InvalidToken),
        ("non-minimal pvno", &non_minimal_pvno[..], ErrorKind::InvalidToken),
        ("AP-REQ msg-type", &wrong_msg_type[..], ErrorKind::InvalidToken),
        (
            "non-minimal msg-type",
            &non_minimal_msg_type[..],
            ErrorKind::InvalidToken,
        ),
        ("KRB-ERROR msg-type", &krb_error_msg_type[..], ErrorKind::InvalidToken),
    ];
    for (name, reply, expected) in cases {
        let request = PackApReplyRequest {
            reply,
            reply_body: &body,
            session_key: key_ref(&service_handle),
        };
        assert_eq!(kind(session.pack_ap_reply(request)), expected, "{name}");
    }

    assert_protection_untouched(&mut session);
}

#[test]
fn pack_ap_reply_rejects_invalid_encrypted_part_integers() {
    let KeyedSession {
        mut session,
        service_handle,
        ..
    } = session_with_keys();
    let body = enc_ap_rep_part();

    let cases = [
        ("empty etype", vec![], None),
        ("non-minimal positive etype", vec![0, 18], None),
        ("non-minimal negative etype", vec![0xFF, 0xFF], None),
        ("etype above Int32 maximum", vec![0, 0x80, 0, 0, 0], None),
        ("etype below Int32 minimum", vec![0xFF, 0x7F, 0xFF, 0xFF, 0xFF], None),
        ("empty kvno", vec![0], Some(vec![])),
        ("non-minimal kvno", vec![0], Some(vec![0, 2])),
        ("negative kvno", vec![0], Some(vec![0xFF])),
        ("kvno above UInt32 maximum", vec![0], Some(vec![1, 0, 0, 0, 0])),
    ];
    for (name, etype, kvno) in cases {
        let template = ap_rep_template(
            vec![5],
            vec![15],
            EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1::from(etype)),
                kvno: Optional::from(kvno.map(|value| ExplicitContextTag1::from(IntegerAsn1::from(value)))),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(Vec::new())),
            },
        );
        let result = session.pack_ap_reply(PackApReplyRequest {
            reply: &template,
            reply_body: &body,
            session_key: key_ref(&service_handle),
        });
        assert!(result.is_err(), "{name}");
        assert_eq!(kind(result), ErrorKind::InvalidToken, "{name}");
    }

    assert_protection_untouched(&mut session);
}

#[test]
fn kerb_ticket_logon_uses_the_64_bit_self_relative_layout() {
    let logon = build_kerb_ticket_logon(&[1, 2, 3], &[4, 5]).unwrap();

    #[rustfmt::skip]
    let expected = [
        10, 0, 0, 0, // MessageType: KerbTicketLogon
        2, 0, 0, 0, // Flags: KERB_LOGON_FLAG_REDIRECTED
        3, 0, 0, 0, // ServiceTicketLength
        2, 0, 0, 0, // TicketGrantingTicketLength
        32, 0, 0, 0, 0, 0, 0, 0, // ServiceTicket
        35, 0, 0, 0, 0, 0, 0, 0, // TicketGrantingTicket
        1, 2, 3,
        4, 5,
    ];
    assert_eq!(logon, expected);
    assert_eq!(KERB_TICKET_LOGON_HEADER_LEN, 32);
}

#[test]
fn ts_credentials_carry_a_kerberos_remote_guard_package_credential() {
    let credentials = build_ts_credentials(&[0xAA, 0xBB], None).unwrap();

    let credentials: TsCredentials = picky_asn1_der::from_bytes(&credentials).unwrap();
    assert_eq!(credentials.cred_type.0, IntegerAsn1::from(vec![6]));

    let remote_guard: TsRemoteGuardCreds = picky_asn1_der::from_bytes(&credentials.credentials.0.0).unwrap();
    assert!(remote_guard.supplemental_creds.0.is_none());
    assert_eq!(
        remote_guard.logon_cred.0.package_name.0.0,
        b"K\0e\0r\0b\0e\0r\0o\0s\0".to_vec()
    );
    assert_eq!(remote_guard.logon_cred.0.cred_buffer.0.0, vec![0xAA, 0xBB]);
}

const TGS_NONCE: u32 = 0x1234_5678;

struct ReplySpec {
    crealm: &'static str,
    cname: PrincipalName,
    etype: u8,
    encryption_key: [u8; 32],
    usage: i32,
    plaintext: Option<Vec<u8>>,
    as_rep_tag: bool,
    nonce: IntegerAsn1,
    part_sname: PrincipalName,
    ticket_sname: PrincipalName,
    reply_key: EncryptionKey,
}

impl ReplySpec {
    fn new() -> Self {
        Self {
            crealm: REALM,
            cname: user(),
            etype: 18,
            encryption_key: SERVICE_TGT_KEY,
            usage: USAGE_TGS_REP_SESSION_KEY,
            plaintext: None,
            as_rep_tag: false,
            nonce: nonce_to_asn1(TGS_NONCE),
            part_sname: computer(),
            ticket_sname: computer(),
            reply_key: encryption_key(18, &COMPUTER_TICKET_KEY),
        }
    }

    fn build(self) -> TgsRep {
        let part = enc_kdc_rep_part(self.reply_key, self.nonce, &[0x40, 0x81, 0x00, 0x00], self.part_sname);
        let plaintext = self.plaintext.unwrap_or_else(|| {
            if self.as_rep_tag {
                picky_asn1_der::to_vec(&EncAsRepPart::from(part)).unwrap()
            } else {
                picky_asn1_der::to_vec(&EncTgsRepPart::from(part)).unwrap()
            }
        });
        let cipher = AES256_SUITE
            .cipher()
            .encrypt(&self.encryption_key, self.usage, &plaintext)
            .unwrap();

        TgsRep::from(KdcRep {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![13])),
            padata: Optional::from(None),
            crealm: ExplicitContextTag3::from(realm(self.crealm)),
            cname: ExplicitContextTag4::from(self.cname),
            ticket: ExplicitContextTag5::from(ticket(self.ticket_sname, COMPUTER_TICKET_MARKER)),
            enc_part: ExplicitContextTag6::from(encrypted_data(self.etype, cipher)),
        })
    }
}

fn process(spec: ReplySpec) -> crate::Result<TgsReply> {
    process_tgs_rep(
        spec.build(),
        &captured_tgt(SERVICE_TGT_KEY, SERVICE_TGT_MARKER),
        &binding(),
        &computer(),
        TGS_NONCE,
    )
}

#[test]
fn process_tgs_rep_accepts_a_matching_reply() {
    let reply = process(ReplySpec::new()).unwrap();

    assert_eq!(ticket_marker(&reply.ticket), COMPUTER_TICKET_MARKER);
    assert_eq!(reply.cipher_suite, AES256_SUITE);
    assert_eq!(reply.session_key.as_ref(), &COMPUTER_TICKET_KEY);
    assert!(reply.part.key.0.key_value.0.0.is_empty());

    // Names and realms are compared case-insensitively, and the EncASRepPart tag is accepted.
    let reply = process(ReplySpec {
        crealm: "example.com",
        cname: principal(NT_PRINCIPAL, &["ALICE"]),
        part_sname: principal(NT_SRV_HST, &["host", "SERVER.EXAMPLE.COM"]),
        as_rep_tag: true,
        reply_key: encryption_key(17, &[0x55; 16]),
        ..ReplySpec::new()
    })
    .unwrap();
    assert_eq!(reply.cipher_suite, CipherSuite::Aes128CtsHmacSha196);
    assert_eq!(reply.session_key.as_ref(), &[0x55; 16]);
}

#[test]
fn process_tgs_rep_rejects_mismatching_replies() {
    let cases = [
        (
            "client realm",
            ReplySpec {
                crealm: "OTHER.COM",
                ..ReplySpec::new()
            },
            ErrorKind::InvalidToken,
        ),
        (
            "client name",
            ReplySpec {
                cname: principal(NT_PRINCIPAL, &["bob"]),
                ..ReplySpec::new()
            },
            ErrorKind::InvalidToken,
        ),
        (
            "encryption type",
            ReplySpec {
                etype: 17,
                ..ReplySpec::new()
            },
            ErrorKind::AlgorithmMismatch,
        ),
        (
            "wrong key",
            ReplySpec {
                encryption_key: HOME_TGT_KEY,
                ..ReplySpec::new()
            },
            ErrorKind::DecryptFailure,
        ),
        (
            "wrong key usage",
            ReplySpec {
                usage: USAGE_TGS_REP_SUB_KEY,
                ..ReplySpec::new()
            },
            ErrorKind::DecryptFailure,
        ),
        (
            "not a KDC reply",
            ReplySpec {
                plaintext: Some(enc_ap_rep_part()),
                ..ReplySpec::new()
            },
            ErrorKind::InvalidToken,
        ),
        (
            "nonce",
            ReplySpec {
                nonce: nonce_to_asn1(TGS_NONCE + 1),
                ..ReplySpec::new()
            },
            ErrorKind::InvalidToken,
        ),
        (
            "reply service name",
            ReplySpec {
                part_sname: krbtgt(),
                ..ReplySpec::new()
            },
            ErrorKind::InvalidToken,
        ),
        (
            "ticket service name",
            ReplySpec {
                ticket_sname: principal(NT_SRV_HST, &["HOST", "other.example.com"]),
                ..ReplySpec::new()
            },
            ErrorKind::InvalidToken,
        ),
        (
            "RC4 session key",
            ReplySpec {
                reply_key: encryption_key(RC4, &[0x55; 16]),
                ..ReplySpec::new()
            },
            ErrorKind::AlgorithmMismatch,
        ),
        (
            "short session key",
            ReplySpec {
                reply_key: encryption_key(18, &[0x55; 16]),
                ..ReplySpec::new()
            },
            ErrorKind::InvalidToken,
        ),
    ];

    for (name, spec, expected) in cases {
        assert_eq!(kind(process(spec)), expected, "{name}");
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KdcBehavior {
    Normal,
    NotForwarded,
    WrongNonce,
    Garbage,
    UnknownPrincipal,
    Unreachable,
}

/// A KDC that checks the TGS-REQs of the logon credential construction and answers them.
struct FakeKdc {
    behavior: KdcBehavior,
    requests: usize,
}

impl FakeKdc {
    fn new(behavior: KdcBehavior) -> Self {
        Self { behavior, requests: 0 }
    }

    fn respond(&mut self, request: &NetworkRequest) -> crate::Result<Vec<u8>> {
        assert_eq!(request.url, Url::parse(KDC_URL).unwrap());
        let (length, message) = request.data.split_at(4);
        assert_eq!(
            usize::try_from(u32::from_be_bytes(length.try_into().unwrap())).unwrap(),
            message.len()
        );

        let index = self.requests;
        self.requests += 1;

        match self.behavior {
            KdcBehavior::Unreachable => {
                return Err(Error::new(
                    ErrorKind::NoAuthenticatingAuthority,
                    "the KDC is unreachable",
                ));
            }
            KdcBehavior::Garbage => return Ok(vec![0, 0, 0, 2, 0x30, 0x00]),
            KdcBehavior::UnknownPrincipal => return Ok(with_length_prefix(&krb_error(KDC_ERR_S_PRINCIPAL_UNKNOWN))),
            _ => {}
        }

        let tgs_req: TgsReq = picky_asn1_der::from_bytes(message).unwrap();
        let tgs_req = tgs_req.0;
        let body = &tgs_req.req_body.0;
        let pa_data = &tgs_req.padata.0.as_ref().unwrap().0.0[0];
        assert_eq!(pa_data.padata_type.0, IntegerAsn1::from(vec![1]));
        let ap_req: ApReq = picky_asn1_der::from_bytes(&pa_data.padata_data.0.0).unwrap();

        let sname = body.sname.0.as_ref().unwrap().0.clone();
        let forwardable = body.kdc_options.0.0.is_set(1);
        let forwarded = body.kdc_options.0.0.is_set(2);
        let (tgt_key, reply_marker, reply_key, flags) = match ticket_marker(&ap_req.0.ticket.0) {
            SERVICE_TGT_MARKER => {
                assert_eq!(index, 0);
                assert_eq!(sname, computer());
                assert!(forwardable && !forwarded);
                (SERVICE_TGT_KEY, COMPUTER_TICKET_MARKER, COMPUTER_TICKET_KEY, 0x40)
            }
            HOME_TGT_MARKER => {
                assert_eq!(index, 1);
                assert_eq!(sname, krbtgt());
                assert!(forwardable && forwarded);
                let flags = if self.behavior == KdcBehavior::NotForwarded {
                    0x40
                } else {
                    0x60
                };
                (HOME_TGT_KEY, FORWARDED_TGT_MARKER, FORWARDED_TGT_KEY, flags)
            }
            marker => panic!("unexpected TGT {marker:#x}"),
        };

        assert_eq!(body.realm.0, realm(REALM));
        assert_eq!(
            body.etype.0.0,
            vec![IntegerAsn1::from(vec![18]), IntegerAsn1::from(vec![17])]
        );

        let authenticator = AES256_SUITE
            .cipher()
            .decrypt(
                &tgt_key,
                USAGE_TGS_REQ_AUTHENTICATOR,
                &ap_req.0.authenticator.0.cipher.0.0,
            )
            .unwrap();
        let authenticator = picky_asn1_der::from_bytes::<Authenticator>(&authenticator).unwrap().0;
        assert_eq!(authenticator.crealm.0, realm(REALM));
        assert_eq!(authenticator.cname.0, user());
        let checksum = authenticator.cksum.0.unwrap().0;
        assert_eq!(checksum.cksumtype.0, IntegerAsn1::from(vec![16]));
        assert_eq!(
            checksum.checksum.0.0,
            checksum_sha_aes(
                &tgt_key,
                USAGE_TGS_REQ_CHECKSUM,
                &picky_asn1_der::to_vec(body).unwrap(),
                &AesSize::Aes256
            )
            .unwrap()
        );

        let mut nonce = body.nonce.0.clone();
        if self.behavior == KdcBehavior::WrongNonce {
            nonce = nonce_to_asn1(u32::try_from(integer_to_i32(&nonce).unwrap()).unwrap() ^ 1);
        }

        let part = enc_kdc_rep_part(encryption_key(18, &reply_key), nonce, &[flags, 0, 0, 0], sname.clone());
        let cipher = AES256_SUITE
            .cipher()
            .encrypt(
                &tgt_key,
                USAGE_TGS_REP_SESSION_KEY,
                &picky_asn1_der::to_vec(&EncTgsRepPart::from(part)).unwrap(),
            )
            .unwrap();
        let tgs_rep = TgsRep::from(KdcRep {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![13])),
            padata: Optional::from(None),
            crealm: ExplicitContextTag3::from(realm(REALM)),
            cname: ExplicitContextTag4::from(user()),
            ticket: ExplicitContextTag5::from(ticket(sname, reply_marker)),
            enc_part: ExplicitContextTag6::from(encrypted_data(18, cipher)),
        });

        Ok(with_length_prefix(&picky_asn1_der::to_vec(&tgs_rep).unwrap()))
    }
}

fn with_length_prefix(message: &[u8]) -> Vec<u8> {
    let mut data = u32::try_from(message.len()).unwrap().to_be_bytes().to_vec();
    data.extend_from_slice(message);
    data
}

fn krb_error(error_code: u32) -> Vec<u8> {
    picky_asn1_der::to_vec(&KrbError::from(KrbErrorInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![30])),
        ctime: Optional::from(None),
        cusec: Optional::from(None),
        stime: ExplicitContextTag4::from(kerberos_time(fixed_time())),
        susec: ExplicitContextTag5::from(IntegerAsn1::from(vec![0])),
        error_code: ExplicitContextTag6::from(error_code),
        crealm: Optional::from(None),
        cname: Optional::from(None),
        realm: ExplicitContextTag9::from(realm(REALM)),
        sname: ExplicitContextTag10::from(computer()),
        e_text: Optional::from(None),
        e_data: Optional::from(None),
    }))
    .unwrap()
}

type CredentialsGenerator<'a> =
    Generator<'a, NetworkRequest, crate::Result<Vec<u8>>, crate::Result<Zeroizing<Vec<u8>>>>;

fn build_credentials(kerberos: &mut Kerberos, target: &str, kdc: &mut FakeKdc) -> crate::Result<Zeroizing<Vec<u8>>> {
    build_credentials_with_ntlm(kerberos, target, kdc, None)
}

fn build_credentials_with_ntlm(
    kerberos: &mut Kerberos,
    target: &str,
    kdc: &mut FakeKdc,
    ntlm: Option<NtlmRedirectionPolicy>,
) -> crate::Result<Zeroizing<Vec<u8>>> {
    let target = target.to_owned();
    let mut generator: CredentialsGenerator<'_> = Generator::new(move |mut yield_point| async move {
        kerberos
            .build_remote_guard_credentials(&mut yield_point, &target, ntlm.as_ref())
            .await
    });

    let mut state = generator.start();
    loop {
        match state {
            GeneratorState::Suspended(request) => state = generator.resume(kdc.respond(&request)),
            GeneratorState::Completed(result) => return result,
        }
    }
}

struct DecodedCredentials {
    service_ticket: Ticket,
    krb_cred: KrbCred,
}

fn decode_credentials(credentials: &[u8]) -> DecodedCredentials {
    let credentials: TsCredentials = picky_asn1_der::from_bytes(credentials).unwrap();
    assert_eq!(credentials.cred_type.0, IntegerAsn1::from(vec![6]));
    let remote_guard: TsRemoteGuardCreds = picky_asn1_der::from_bytes(&credentials.credentials.0.0).unwrap();
    let logon = remote_guard.logon_cred.0.cred_buffer.0.0;

    let u32_at = |offset: usize| u32::from_le_bytes(logon[offset..offset + 4].try_into().unwrap());
    let u64_at = |offset: usize| u64::from_le_bytes(logon[offset..offset + 8].try_into().unwrap());
    assert_eq!(u32_at(0), KERB_TICKET_LOGON_MESSAGE_TYPE);
    assert_eq!(u32_at(4), KERB_LOGON_FLAG_REDIRECTED);
    let service_ticket_len = usize::try_from(u32_at(8)).unwrap();
    let krb_cred_len = usize::try_from(u32_at(12)).unwrap();
    let service_ticket_offset = usize::try_from(u64_at(16)).unwrap();
    let krb_cred_offset = usize::try_from(u64_at(24)).unwrap();
    assert_eq!(service_ticket_offset, KERB_TICKET_LOGON_HEADER_LEN);
    assert_eq!(krb_cred_offset, service_ticket_offset + service_ticket_len);
    assert_eq!(logon.len(), krb_cred_offset + krb_cred_len);

    DecodedCredentials {
        service_ticket: picky_asn1_der::from_bytes(&logon[service_ticket_offset..krb_cred_offset]).unwrap(),
        krb_cred: picky_asn1_der::from_bytes(&logon[krb_cred_offset..]).unwrap(),
    }
}

#[test]
fn remote_guard_credentials_delegate_a_forwarded_tgt_to_the_computer_account() {
    let mut kerberos = rcg_client();
    let mut kdc = FakeKdc::new(KdcBehavior::Normal);

    let credentials = build_credentials(&mut kerberos, TARGET, &mut kdc).unwrap();

    assert_eq!(kdc.requests, 2);
    for key in [
        HOME_TGT_KEY,
        SERVICE_TGT_KEY,
        CONTEXT_KEY,
        FORWARDED_TGT_KEY,
        COMPUTER_TICKET_KEY,
    ] {
        assert!(!contains(&credentials, &key));
    }

    let DecodedCredentials {
        service_ticket,
        krb_cred,
    } = decode_credentials(&credentials);
    assert_eq!(ticket_marker(&service_ticket), COMPUTER_TICKET_MARKER);
    assert_eq!(service_ticket.0.sname.0, computer());

    let krb_cred = krb_cred.0;
    assert_eq!(krb_cred.pvno.0, IntegerAsn1::from(vec![5]));
    assert_eq!(krb_cred.msg_type.0, IntegerAsn1::from(vec![KRB_CRED_MSG_TYPE]));
    assert_eq!(krb_cred.tickets.0.0.len(), 1);
    assert_eq!(ticket_marker(&krb_cred.tickets.0.0[0]), FORWARDED_TGT_MARKER);
    assert_eq!(krb_cred.enc_part.0.etype.0, IntegerAsn1::from(vec![18]));

    let enc_part = AES256_SUITE
        .cipher()
        .decrypt(&COMPUTER_TICKET_KEY, KRB_CRED_ENC_PART, &krb_cred.enc_part.0.cipher.0.0)
        .unwrap();
    let enc_part: EncKrbCredPart = picky_asn1_der::from_bytes(&enc_part).unwrap();
    let info = &enc_part.0.ticket_info.0.0[0];
    assert_eq!(enc_part.0.ticket_info.0.0.len(), 1);
    assert_eq!(info.key.0.key_type.0, IntegerAsn1::from(vec![18]));
    let handle = info.key.0.key_value.0.0.clone();
    assert_eq!(handle.len(), 32);
    assert_ne!(handle, FORWARDED_TGT_KEY);
    assert_eq!(info.prealm.0.as_ref().unwrap().0, realm(REALM));
    assert_eq!(info.pname.0.as_ref().unwrap().0, user());
    assert_eq!(info.srealm.0.as_ref().unwrap().0, realm(REALM));
    assert_eq!(info.sname.0.as_ref().unwrap().0, krbtgt());
    assert!(info.flags.0.as_ref().unwrap().0.0.is_set(2));

    let state = rcg_state(&kerberos);
    assert!(state.is_logon_built());
    assert!(state.home_tgt.is_none() && state.service_tgt.is_none());
    assert_eq!(state.key_store.len(), 1);

    // The delegated TGT key stays in the session and can only be used through its handle.
    let mut session = kerberos.take_remote_guard_session().unwrap();
    assert_eq!(session.sequence_numbers(), (1000, 2000));
    let body = kdc_req_body();
    let checksum = session.compute_tgs_checksum(checksum_request(&body, &handle)).unwrap();
    let checksum: Checksum = picky_asn1_der::from_bytes(&checksum).unwrap();
    assert_eq!(
        checksum.checksum.0.0,
        checksum_sha_aes(&FORWARDED_TGT_KEY, USAGE_TGS_REQ_CHECKSUM, &body, &AesSize::Aes256).unwrap()
    );
}

fn assert_build_poisoned(kerberos: &mut Kerberos) {
    let state = rcg_state(kerberos);
    assert!(state.poisoned);
    assert!(state.home_tgt.is_none() && state.service_tgt.is_none());
    assert!(state.context.is_none());
    assert_eq!(state.key_store.len(), 0);
    assert_eq!(kind(kerberos.take_remote_guard_session()), ErrorKind::ContextExpired);
}

#[test]
fn remote_guard_credentials_fail_closed_on_kdc_failures() {
    let cases = [
        (KdcBehavior::NotForwarded, ErrorKind::NoCredentials, 2),
        (KdcBehavior::WrongNonce, ErrorKind::InvalidToken, 1),
        (KdcBehavior::UnknownPrincipal, ErrorKind::UnknownCredentials, 1),
        (KdcBehavior::Unreachable, ErrorKind::NoAuthenticatingAuthority, 1),
    ];

    for (behavior, expected, requests) in cases {
        let mut kerberos = rcg_client();
        let mut kdc = FakeKdc::new(behavior);

        assert_eq!(kind(build_credentials(&mut kerberos, TARGET, &mut kdc)), expected);
        assert_eq!(kdc.requests, requests);
        assert_build_poisoned(&mut kerberos);
    }

    let mut kerberos = rcg_client();
    let mut kdc = FakeKdc::new(KdcBehavior::Garbage);
    assert!(build_credentials(&mut kerberos, TARGET, &mut kdc).is_err());
    assert_eq!(kdc.requests, 1);
    assert_build_poisoned(&mut kerberos);
}

#[test]
fn remote_guard_credentials_check_the_context_state() {
    // Invalid target name: no request is sent.
    let mut kerberos = rcg_client();
    let mut kdc = FakeKdc::new(KdcBehavior::Normal);
    assert_eq!(
        kind(build_credentials(&mut kerberos, "server.example.com", &mut kdc)),
        ErrorKind::InvalidParameter
    );
    assert_eq!(kdc.requests, 0);
    assert_build_poisoned(&mut kerberos);

    // Authentication not complete.
    let mut kerberos = rcg_client();
    kerberos.state = KerberosState::Client(Box::new(KerberosClientState::ApExchange));
    assert_eq!(
        kind(build_credentials(&mut kerberos, TARGET, &mut kdc)),
        ErrorKind::OutOfSequence
    );
    assert!(rcg_state(&kerberos).poisoned);

    // Missing captured ticket.
    let mut kerberos = rcg_client();
    kerberos.remote_guard.as_deref_mut().unwrap().service_tgt = None;
    assert_eq!(
        kind(build_credentials(&mut kerberos, TARGET, &mut kdc)),
        ErrorKind::InternalError
    );
    assert_build_poisoned(&mut kerberos);

    // Remote Credential Guard not enabled.
    let mut kerberos = rcg_client();
    kerberos.remote_guard = None;
    assert_eq!(
        kind(build_credentials(&mut kerberos, TARGET, &mut kdc)),
        ErrorKind::InternalError
    );
    assert!(kerberos.remote_guard.is_none());
    assert_eq!(kdc.requests, 0);

    // Credentials are built only once.
    let mut kerberos = rcg_client();
    let mut kdc = FakeKdc::new(KdcBehavior::Normal);
    build_credentials(&mut kerberos, TARGET, &mut kdc).unwrap();
    assert_eq!(
        kind(build_credentials(&mut kerberos, TARGET, &mut kdc)),
        ErrorKind::OutOfSequence
    );
    assert_eq!(kdc.requests, 2);
    assert_build_poisoned(&mut kerberos);
}

// NTLM supplemental credential.
//
// The known answers are the NTLMv2 example of MS-NLMP 4.2.4. All other material is synthetic.

const NTLM_USER: &str = "User";
const NTLM_DOMAIN: &str = "Domain";
const NTLM_PASSWORD: &str = "Password";
const NTLM_SERVER_CHALLENGE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const NTLM_CLIENT_CHALLENGE: [u8; 8] = [0xaa; 8];
/// NTOWFv1 of "Password".
const NTLM_NT_OWF: [u8; 16] = [
    0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca, 0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f, 0xd8, 0x52,
];
const NTLM_NT_PROOF_STR: [u8; 16] = [
    0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96, 0xaa, 0xbc, 0x92, 0x7b, 0xeb, 0xef, 0x6a, 0x1c,
];
const NTLM_SESSION_BASE_KEY: [u8; 16] = [
    0x8d, 0xe4, 0x0c, 0xca, 0xdb, 0xc1, 0x4a, 0x82, 0xf1, 0x5c, 0xb0, 0xad, 0x0d, 0xe9, 0x5c, 0xa3,
];
const NTLM_LMV2_RESPONSE: [u8; 16] = [
    0x86, 0xc3, 0x50, 0x97, 0xac, 0x9c, 0xec, 0x10, 0x25, 0x54, 0x76, 0x4a, 0x57, 0xcc, 0xcc, 0x19,
];
/// Offset of the handle in the supplemental credential.
const NTLM_HANDLE_OFFSET: usize = 36;

fn utf16(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

fn utf16le(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn av_pair(id: u16, value: &[u8]) -> Vec<u8> {
    let mut pair = id.to_le_bytes().to_vec();
    pair.extend_from_slice(&u16::try_from(value.len()).unwrap().to_le_bytes());
    pair.extend_from_slice(value);
    pair
}

/// The `ServerName` of the MS-NLMP 4.2.4 example.
fn ms_nlmp_server_name() -> Vec<u8> {
    let mut server_name = av_pair(2, &utf16le(NTLM_DOMAIN));
    server_name.extend(av_pair(1, &utf16le("Server")));
    server_name.extend(av_pair(0, &[]));
    server_name
}

fn server_name_with_timestamp(timestamp: u64) -> Vec<u8> {
    let mut server_name = av_pair(2, &utf16le(NTLM_DOMAIN));
    server_name.extend(av_pair(7, &timestamp.to_le_bytes()));
    server_name.extend(av_pair(0, &[]));
    server_name
}

fn ntlm_credential(seed: u64) -> NtlmCredential {
    NtlmCredential::new(
        nt_owf(&utf16(NTLM_PASSWORD)).unwrap(),
        &Utf16String::from_str(NTLM_USER),
        &Utf16String::from_str(NTLM_DOMAIN),
        &mut StdRng::seed_from_u64(seed),
    )
}

/// Returns a session holding an NTLM credential, and the supplemental credential sent for it.
fn ntlm_session(seed: u64) -> (RemoteGuardSession, Vec<u8>) {
    let mut state = established_state(1000, 2000);
    let credential = ntlm_credential(seed);
    let supplemental = credential.supplemental_credential();
    state.ntlm = Some(credential);
    state.mark_logon_built();

    (state.into_session(Duration::ZERO).unwrap(), supplemental)
}

fn ntlm_reference(handle: &[u8]) -> NtlmCredentialReference<'_> {
    NtlmCredentialReference {
        reserved1: 1,
        reserved2: 0,
        reserved3: 0,
        credential_key_type: 0,
        credential_key: &[0; CREDENTIAL_KEY_LEN],
        encrypted_secrets: handle,
    }
}

#[test]
fn ntlm_credential_reference_debug_redacts_untrusted_credential_bytes() {
    let key = [0xA7; CREDENTIAL_KEY_LEN];
    let handle = [0xB9; NTLM_CREDENTIAL_HANDLE_LEN];
    let credential = NtlmCredentialReference {
        credential_key: &key,
        ..ntlm_reference(&handle)
    };

    assert_eq!(
        format!("{credential:?}"),
        "NtlmCredentialReference { reserved1: 1, reserved2: 0, reserved3: 0, \
         credential_key_type: 0, encrypted_secrets_len: 36, .. }"
    );
}

#[test]
fn ntlm_challenge_request_debug_redacts_identity_and_challenge_bytes() {
    let handle = [0xB9; NTLM_CREDENTIAL_HANDLE_LEN];
    let credential = ntlm_reference(&handle);
    let request = Lm20GetNtlm3ChallengeResponseRequest {
        credential,
        user_name: b"u\0s\0e\0r\0",
        logon_domain_name: b"D\0O\0M\0A\0I\0N\0",
        server_name: b"s\0e\0r\0v\0e\0r\0",
        challenge_to_client: [0xDB; 8],
    };

    assert_eq!(
        format!("{request:?}"),
        format!(
            "Lm20GetNtlm3ChallengeResponseRequest {{ credential: {credential:?}, \
             user_name_len: 8, logon_domain_name_len: 12, server_name_len: 12, .. }}"
        )
    );
}

struct NtlmRequestBuffers {
    user: Vec<u8>,
    domain: Vec<u8>,
    server_name: Vec<u8>,
}

impl NtlmRequestBuffers {
    fn new(server_name: Vec<u8>) -> Self {
        Self {
            user: utf16le(NTLM_USER),
            domain: utf16le(NTLM_DOMAIN),
            server_name,
        }
    }

    fn request<'a>(&'a self, credential: NtlmCredentialReference<'a>) -> Lm20GetNtlm3ChallengeResponseRequest<'a> {
        Lm20GetNtlm3ChallengeResponseRequest {
            credential,
            user_name: &self.user,
            logon_domain_name: &self.domain,
            server_name: &self.server_name,
            challenge_to_client: NTLM_SERVER_CHALLENGE,
        }
    }
}

fn assert_response_eq(actual: &Ntlm3ChallengeResponse, expected: &Ntlm3ChallengeResponse) {
    assert_eq!(actual.ntlm3_response, expected.ntlm3_response);
    assert_eq!(actual.lm3_response, expected.lm3_response);
    assert_eq!(actual.challenge_from_client, expected.challenge_from_client);
    assert_eq!(actual.user_session_key.as_ref(), expected.user_session_key.as_ref());
    assert_eq!(actual.lm_session_key.as_ref(), expected.lm_session_key.as_ref());
}

/// Recomputes the response of a session from its own client challenge and time.
fn expected_ntlm_response(
    response: &Ntlm3ChallengeResponse,
    user: &str,
    domain: &str,
    server_name: &[u8],
) -> Ntlm3ChallengeResponse {
    let time = u64::from_le_bytes(response.ntlm3_response[24..32].try_into().unwrap());
    compute_ntlm3_response(
        &NTLM_NT_OWF,
        &Utf16String::from_str(user),
        &Utf16String::from_str(domain),
        server_name,
        &NTLM_SERVER_CHALLENGE,
        &response.challenge_from_client,
        time,
    )
    .unwrap()
}

#[test]
fn ntlm_v2_response_matches_the_ms_nlmp_example() {
    let nt_owf = nt_owf(&utf16(NTLM_PASSWORD)).unwrap();
    assert_eq!(nt_owf.as_ref(), &NTLM_NT_OWF);

    let server_name = ms_nlmp_server_name();
    let response = compute_ntlm3_response(
        nt_owf.as_ref(),
        &Utf16String::from_str(NTLM_USER),
        &Utf16String::from_str(NTLM_DOMAIN),
        &server_name,
        &NTLM_SERVER_CHALLENGE,
        &NTLM_CLIENT_CHALLENGE,
        0,
    )
    .unwrap();

    let mut temp = vec![1, 1, 0, 0, 0, 0, 0, 0];
    temp.extend_from_slice(&[0; 8]);
    temp.extend_from_slice(&NTLM_CLIENT_CHALLENGE);
    temp.extend_from_slice(&[0; 4]);
    temp.extend_from_slice(&server_name);
    temp.extend_from_slice(&[0; 4]);

    assert_eq!(response.ntlm3_response[..16], NTLM_NT_PROOF_STR);
    assert_eq!(response.ntlm3_response[16..], temp);
    assert_eq!(response.user_session_key.as_ref(), &NTLM_SESSION_BASE_KEY);
    assert_eq!(response.lm3_response, NTLM_LMV2_RESPONSE);
    assert_eq!(response.challenge_from_client, NTLM_CLIENT_CHALLENGE);
    assert_eq!(response.lm_session_key.as_ref(), &[0; 8]);
}

#[test]
fn ntlm_owf_accepts_an_nt_hash_password() {
    for hash in [
        "$NTLM$:a4f49c406510bdcab6824ee7c30fd852",
        "$NTLM$:A4F49C406510BDCAB6824EE7C30FD852",
    ] {
        assert_eq!(nt_owf(&utf16(hash)).unwrap().as_ref(), &NTLM_NT_OWF);
    }

    for hash in [
        "$NTLM$:",
        "$NTLM$:a4f49c406510bdcab6824ee7c30fd8",
        "$NTLM$:a4f49c406510bdcab6824ee7c30fd85200",
        "$NTLM$:g4f49c406510bdcab6824ee7c30fd852",
        "$NTLM$:+4f49c406510bdcab6824ee7c30fd852",
    ] {
        assert_eq!(kind(nt_owf(&utf16(hash))), ErrorKind::InvalidParameter, "{hash}");
    }

    // Without the exact prefix, the value is a password.
    assert_ne!(
        nt_owf(&utf16("$ntlm$:a4f49c406510bdcab6824ee7c30fd852"))
            .unwrap()
            .as_ref(),
        &NTLM_NT_OWF
    );
}

#[test]
fn ntlm_supplemental_credential_carries_only_an_opaque_handle() {
    let credential = ntlm_credential(1);
    let supplemental = credential.supplemental_credential();

    let u32_at = |offset: usize| u32::from_le_bytes(supplemental[offset..offset + 4].try_into().unwrap());
    assert_eq!(supplemental.len(), NTLM_HANDLE_OFFSET + NTLM_CREDENTIAL_HANDLE_LEN);
    assert_eq!(u32_at(0), 0xFFFF_0002);
    assert_eq!(u32_at(4), 0x2);
    assert_eq!(supplemental[8..28], [0; CREDENTIAL_KEY_LEN]);
    assert_eq!(u32_at(28), DOMAIN_USER_CREDENTIAL_KEY_TYPE);
    assert_eq!(usize::try_from(u32_at(32)).unwrap(), NTLM_CREDENTIAL_HANDLE_LEN);
    assert_eq!(&supplemental[NTLM_HANDLE_OFFSET..NTLM_HANDLE_OFFSET + 4], b"RGN1");
    assert!(!contains(&supplemental, &NTLM_NT_OWF));

    // Each credential has its own handle.
    let other = ntlm_credential(2).supplemental_credential();
    assert_ne!(supplemental[NTLM_HANDLE_OFFSET..], other[NTLM_HANDLE_OFFSET..]);

    let debug = format!("{credential:?}");
    assert!(!debug.contains("USER") && !debug.contains("RGN1") && !debug.contains("164"));
}

#[test]
fn ts_credentials_carry_the_ntlm_supplemental_credential() {
    let supplemental = ntlm_credential(1).supplemental_credential();
    let credentials = build_ts_credentials(&[0xAA, 0xBB], Some(&supplemental)).unwrap();

    let credentials: TsCredentials = picky_asn1_der::from_bytes(&credentials).unwrap();
    assert_eq!(credentials.cred_type.0, IntegerAsn1::from(vec![6]));

    let remote_guard: TsRemoteGuardCreds = picky_asn1_der::from_bytes(&credentials.credentials.0.0).unwrap();
    assert_eq!(remote_guard.logon_cred.0.cred_buffer.0.0, vec![0xAA, 0xBB]);
    let supplemental_creds = remote_guard.supplemental_creds.0.unwrap().0.0;
    assert_eq!(supplemental_creds.len(), 1);
    assert_eq!(supplemental_creds[0].package_name.0.0, b"N\0T\0L\0M\0".to_vec());
    assert_eq!(supplemental_creds[0].cred_buffer.0.0, supplemental);
}

#[test]
fn ntlm_response_uses_the_server_timestamp() {
    let (mut session, supplemental) = ntlm_session(1);
    let handle = &supplemental[NTLM_HANDLE_OFFSET..];
    let timestamp = 0x01D9_0000_1234_5678;
    let buffers = NtlmRequestBuffers::new(server_name_with_timestamp(timestamp));

    let first = session
        .lm20_get_ntlm3_challenge_response(&buffers.request(ntlm_reference(handle)))
        .unwrap();
    let second = session
        .lm20_get_ntlm3_challenge_response(&buffers.request(ntlm_reference(handle)))
        .unwrap();

    assert_eq!(first.ntlm3_response[24..32], timestamp.to_le_bytes());
    assert_response_eq(
        &first,
        &expected_ntlm_response(&first, NTLM_USER, NTLM_DOMAIN, &buffers.server_name),
    );
    assert_response_eq(
        &second,
        &expected_ntlm_response(&second, NTLM_USER, NTLM_DOMAIN, &buffers.server_name),
    );
    // A new client challenge for each response.
    assert_ne!(first.challenge_from_client, second.challenge_from_client);
    assert_eq!(first.lm_session_key.as_ref(), &[0; 8]);

    let debug = format!("{first:?}");
    assert!(debug.contains("ntlm3_response_len"));
    assert!(!debug.contains("user_session_key") && !debug.contains("lm3_response:"));

    // Operations do not consume sequence numbers.
    assert_eq!(session.sequence_numbers(), (1000, 2000));
}

#[test]
fn ntlm_response_uses_the_current_time_without_a_server_timestamp() {
    let (mut session, supplemental) = ntlm_session(1);
    let buffers = NtlmRequestBuffers::new(ms_nlmp_server_name());

    let before = current_filetime(Duration::ZERO).unwrap();
    let response = session
        .lm20_get_ntlm3_challenge_response(&buffers.request(ntlm_reference(&supplemental[NTLM_HANDLE_OFFSET..])))
        .unwrap();
    let after = current_filetime(Duration::ZERO).unwrap();

    let time = u64::from_le_bytes(response.ntlm3_response[24..32].try_into().unwrap());
    assert!(before <= time && time <= after);
    assert_response_eq(
        &response,
        &expected_ntlm_response(&response, NTLM_USER, NTLM_DOMAIN, &buffers.server_name),
    );
}

#[test]
fn ntlm_response_preserves_kdc_clock_offset_without_server_timestamp() {
    for offset in [Duration::hours(-2), Duration::hours(2)] {
        let (mut session, supplemental) = ntlm_session(1);
        session.clock_offset = offset;
        let handle = session
            .key_store
            .insert(
                AES256_SUITE,
                Secret::new(SERVICE_KEY.to_vec()),
                KeyRole::Service,
                &mut StdRng::seed_from_u64(55),
            )
            .unwrap();
        let alice = vec![USER.to_owned()];
        let before_authenticator = OffsetDateTime::now_utc();
        let authenticator = session
            .create_ap_req_authenticator(CreateApReqAuthenticatorRequest {
                skew_time: 12_345_670,
                ..authenticator_request(&handle, &alice)
            })
            .unwrap();
        let after_authenticator = OffsetDateTime::now_utc();
        let skew = Duration::nanoseconds(1_234_567_000);
        assert!(
            independent_filetime(before_authenticator + skew) <= authenticator.authenticator_time
                && authenticator.authenticator_time <= independent_filetime(after_authenticator + skew)
        );
        assert_eq!(decrypt_authenticator(&SERVICE_KEY, 11, &authenticator).cname.0, user());
        assert_eq!(session.clock_offset, offset);
        let buffers = NtlmRequestBuffers::new(ms_nlmp_server_name());
        let before = OffsetDateTime::now_utc();
        let response = session
            .lm20_get_ntlm3_challenge_response(&buffers.request(ntlm_reference(&supplemental[NTLM_HANDLE_OFFSET..])))
            .unwrap();
        let after = OffsetDateTime::now_utc();
        let timestamp = i64::from_le_bytes(response.ntlm3_response[24..32].try_into().unwrap());
        // NTLM retains 100ns precision, unlike the microsecond-truncated authenticator.
        let ticks = |time: OffsetDateTime| {
            (time.unix_timestamp() + 11_644_473_600) * 10_000_000 + i64::from(time.nanosecond()) / 100
        };
        assert!(ticks(before + offset) <= timestamp && timestamp <= ticks(after + offset));
        assert_response_eq(
            &response,
            &expected_ntlm_response(&response, NTLM_USER, NTLM_DOMAIN, &buffers.server_name),
        );
        assert_eq!(session.clock_offset, offset);
        assert_protection_untouched(&mut session);
    }
}

#[test]
fn ntlm_response_uses_server_timestamp_even_with_kdc_clock_offset() {
    for offset in [Duration::hours(-2), Duration::hours(2)] {
        let (mut session, supplemental) = ntlm_session(1);
        session.clock_offset = offset;
        let timestamp = 0x01D9_0000_1234_5678u64;
        let buffers = NtlmRequestBuffers::new(server_name_with_timestamp(timestamp));
        let response = session
            .lm20_get_ntlm3_challenge_response(&buffers.request(ntlm_reference(&supplemental[NTLM_HANDLE_OFFSET..])))
            .unwrap();
        assert_eq!(response.ntlm3_response[24..32], timestamp.to_le_bytes());
        assert_response_eq(
            &response,
            &expected_ntlm_response(&response, NTLM_USER, NTLM_DOMAIN, &buffers.server_name),
        );
        assert_eq!(session.clock_offset, offset);
        assert_protection_untouched(&mut session);
    }
}

#[test]
fn ntlm_response_names_match_ignoring_case() {
    let (mut session, supplemental) = ntlm_session(1);
    let reference = ntlm_reference(&supplemental[NTLM_HANDLE_OFFSET..]);
    let server_name = ms_nlmp_server_name();

    let mut buffers = NtlmRequestBuffers::new(server_name.clone());
    buffers.user = utf16le("uSER");
    buffers.domain = utf16le("DOMAIN");
    let response = session
        .lm20_get_ntlm3_challenge_response(&buffers.request(reference))
        .unwrap();
    // The domain name is used as given in the request.
    assert_response_eq(
        &response,
        &expected_ntlm_response(&response, "uSER", "DOMAIN", &server_name),
    );

    for (user, domain) in [
        ("Other", NTLM_DOMAIN),
        (NTLM_USER, "Other"),
        (NTLM_USER, ""),
        ("", NTLM_DOMAIN),
    ] {
        let mut buffers = NtlmRequestBuffers::new(server_name.clone());
        buffers.user = utf16le(user);
        buffers.domain = utf16le(domain);
        assert_eq!(
            kind(session.lm20_get_ntlm3_challenge_response(&buffers.request(reference))),
            ErrorKind::LogonDenied,
            "{user}\\{domain}"
        );
    }

    // Invalid UTF-16: odd length and lone surrogate.
    for invalid in [vec![0x55], vec![0x00, 0xD8]] {
        let mut buffers = NtlmRequestBuffers::new(server_name.clone());
        buffers.user = invalid.clone();
        assert_eq!(
            kind(session.lm20_get_ntlm3_challenge_response(&buffers.request(reference))),
            ErrorKind::InvalidParameter
        );

        let mut buffers = NtlmRequestBuffers::new(server_name.clone());
        buffers.domain = invalid;
        assert_eq!(
            kind(session.lm20_get_ntlm3_challenge_response(&buffers.request(reference))),
            ErrorKind::InvalidParameter
        );
    }
}

#[test]
fn ntlm_response_rejects_malformed_server_names() {
    let (mut session, supplemental) = ntlm_session(1);
    let reference = ntlm_reference(&supplemental[NTLM_HANDLE_OFFSET..]);
    let eol = av_pair(0, &[]);

    let mut trailing = ms_nlmp_server_name();
    trailing.push(0);
    let mut eol_with_value = av_pair(1, &utf16le("Server"));
    eol_with_value.extend(av_pair(0, &[0, 0]));
    let mut duplicate_timestamp = av_pair(7, &[0; 8]);
    duplicate_timestamp.extend(server_name_with_timestamp(1));
    let mut short_timestamp = av_pair(7, &[0; 4]);
    short_timestamp.extend_from_slice(&eol);
    let mut truncated_pair = vec![1, 0, 8, 0, 0x53, 0];
    truncated_pair.extend_from_slice(&eol);

    let cases = [
        ("empty", Vec::new()),
        ("plain host name", utf16le("server.example.com")),
        ("missing EOL", av_pair(1, &utf16le("Server"))),
        ("truncated header", vec![0, 0, 0]),
        ("truncated value", truncated_pair),
        ("trailing bytes", trailing),
        ("EOL with a value", eol_with_value),
        ("short timestamp", short_timestamp),
        ("duplicate timestamp", duplicate_timestamp),
    ];
    for (name, server_name) in cases {
        let buffers = NtlmRequestBuffers::new(server_name);
        assert_eq!(
            kind(session.lm20_get_ntlm3_challenge_response(&buffers.request(reference))),
            ErrorKind::InvalidToken,
            "{name}"
        );
    }

    // Largest ServerName.
    let mut longest = av_pair(1, &vec![0x41; MAX_NTLM_SERVER_NAME_LEN - 8]);
    longest.extend_from_slice(&eol);
    assert_eq!(longest.len(), MAX_NTLM_SERVER_NAME_LEN);
    let buffers = NtlmRequestBuffers::new(longest);
    let response = session
        .lm20_get_ntlm3_challenge_response(&buffers.request(reference))
        .unwrap();
    assert_eq!(response.ntlm3_response.len(), usize::from(u16::MAX));

    let mut too_long = av_pair(1, &vec![0x41; MAX_NTLM_SERVER_NAME_LEN - 7]);
    too_long.extend_from_slice(&eol);
    let buffers = NtlmRequestBuffers::new(too_long);
    assert_eq!(
        kind(session.lm20_get_ntlm3_challenge_response(&buffers.request(reference))),
        ErrorKind::InvalidParameter
    );

    // Failures do not affect the session.
    assert!(session.ntlm_available());
    assert!(session.wrap(b"rdpear").is_ok());
}

#[test]
fn ntlm_reference_accepts_native_n_only_import_metadata() {
    let (session, supplemental) = ntlm_session(1);

    assert_eq!(&supplemental[4..8], &0x2_u32.to_le_bytes());
    assert_eq!(&supplemental[28..32], &DOMAIN_USER_CREDENTIAL_KEY_TYPE.to_le_bytes());

    // C-clear import does not copy the supplemental credential-key type into the primary credential.
    let native_reference = NtlmCredentialReference {
        reserved1: 1,
        reserved2: 0,
        reserved3: 0,
        credential_key_type: 0,
        credential_key: &[0; CREDENTIAL_KEY_LEN],
        encrypted_secrets: &supplemental[NTLM_HANDLE_OFFSET..],
    };

    assert_eq!(
        session
            .compare_ntlm_credentials(&native_reference, &native_reference)
            .unwrap(),
        NtlmCredentialComparison {
            are_nt_owfs_equal: true,
            are_lm_owfs_equal: false,
            are_sha_owfs_equal: false,
        }
    );
}

#[test]
fn ntlm_reference_ignores_unused_credential_key_metadata() {
    let (mut session, supplemental) = ntlm_session(1);
    let reference = ntlm_reference(&supplemental[NTLM_HANDLE_OFFSET..]);
    let buffers = NtlmRequestBuffers::new(ms_nlmp_server_name());

    // The live Windows callback supplies type 2 and a nonzero key despite C-clear import.
    for credential_key_type in [2, 0, 1, 3, 4, 0x8000_0002, u32::MAX] {
        for key in [[0xA7; CREDENTIAL_KEY_LEN], [0; CREDENTIAL_KEY_LEN]] {
            let native_reference = NtlmCredentialReference {
                credential_key_type,
                credential_key: &key,
                ..reference
            };
            let response = session
                .lm20_get_ntlm3_challenge_response(&buffers.request(native_reference))
                .unwrap();
            assert_response_eq(
                &response,
                &expected_ntlm_response(&response, NTLM_USER, NTLM_DOMAIN, &buffers.server_name),
            );
            for (first, second) in [(&reference, &native_reference), (&native_reference, &reference)] {
                assert_eq!(
                    session.compare_ntlm_credentials(first, second).unwrap(),
                    NtlmCredentialComparison {
                        are_nt_owfs_equal: true,
                        are_lm_owfs_equal: false,
                        are_sha_owfs_equal: false,
                    }
                );
            }
        }
    }
    assert_protection_untouched(&mut session);
}

#[test]
fn ntlm_operations_reject_foreign_and_tampered_references() {
    let (mut session, supplemental) = ntlm_session(1);
    let (_, other_supplemental) = ntlm_session(2);
    let handle = &supplemental[NTLM_HANDLE_OFFSET..];
    let buffers = NtlmRequestBuffers::new(ms_nlmp_server_name());

    let mut tampered = handle.to_vec();
    tampered[NTLM_CREDENTIAL_HANDLE_LEN - 1] ^= 1;
    let mut extended = handle.to_vec();
    extended.push(0);
    let other_handle = &other_supplemental[NTLM_HANDLE_OFFSET..];
    let truncated = &handle[..NTLM_CREDENTIAL_HANDLE_LEN - 1];
    let key = [0xA7; CREDENTIAL_KEY_LEN];
    let valid = NtlmCredentialReference {
        credential_key_type: DOMAIN_USER_CREDENTIAL_KEY_TYPE,
        credential_key: &key,
        ..ntlm_reference(handle)
    };

    let mut references = vec![
        NtlmCredentialReference {
            encrypted_secrets: other_handle,
            ..valid
        },
        NtlmCredentialReference {
            encrypted_secrets: &tampered,
            ..valid
        },
        NtlmCredentialReference {
            encrypted_secrets: &extended,
            ..valid
        },
        NtlmCredentialReference {
            encrypted_secrets: truncated,
            ..valid
        },
        NtlmCredentialReference {
            encrypted_secrets: &[],
            ..valid
        },
    ];
    references.push(NtlmCredentialReference { reserved1: 0, ..valid });
    references.push(NtlmCredentialReference { reserved1: 2, ..valid });
    references.push(NtlmCredentialReference { reserved2: 1, ..valid });
    references.push(NtlmCredentialReference {
        reserved2: 0xFF,
        ..valid
    });
    references.push(NtlmCredentialReference { reserved3: 1, ..valid });
    references.push(NtlmCredentialReference { reserved3: 2, ..valid });

    for reference in references {
        assert_eq!(
            kind(session.lm20_get_ntlm3_challenge_response(&buffers.request(reference))),
            ErrorKind::InvalidHandle,
            "{reference:?}"
        );
        assert_eq!(
            kind(session.compare_ntlm_credentials(&reference, &valid)),
            ErrorKind::InvalidHandle
        );
        assert_eq!(
            kind(session.compare_ntlm_credentials(&valid, &reference)),
            ErrorKind::InvalidHandle
        );
    }

    // Failures do not affect the session.
    assert!(session.ntlm_available());
    assert_eq!(session.wrap(b"rdpear").map(|token| token.is_empty()).ok(), Some(false));
}

#[test]
fn ntlm_compare_credentials_matches_the_session_credential() {
    let (session, supplemental) = ntlm_session(1);
    let reference = ntlm_reference(&supplemental[NTLM_HANDLE_OFFSET..]);

    assert_eq!(
        session.compare_ntlm_credentials(&reference, &reference).unwrap(),
        NtlmCredentialComparison {
            are_nt_owfs_equal: true,
            are_lm_owfs_equal: false,
            are_sha_owfs_equal: false,
        }
    );
}

#[test]
fn ntlm_operations_require_a_delegated_credential() {
    let mut session = session(1000, 2000);
    let handle = [0; NTLM_CREDENTIAL_HANDLE_LEN];
    let reference = ntlm_reference(&handle);
    let buffers = NtlmRequestBuffers::new(ms_nlmp_server_name());

    assert!(!session.ntlm_available());
    assert_eq!(
        kind(session.lm20_get_ntlm3_challenge_response(&buffers.request(reference))),
        ErrorKind::NoCredentials
    );
    assert_eq!(
        kind(session.compare_ntlm_credentials(&reference, &reference)),
        ErrorKind::NoCredentials
    );
}

#[test]
fn ntlm_credential_is_dropped_when_the_session_fails() {
    let (mut session, supplemental) = ntlm_session(1);
    let reference = ntlm_reference(&supplemental[NTLM_HANDLE_OFFSET..]);
    let buffers = NtlmRequestBuffers::new(ms_nlmp_server_name());
    assert!(session.ntlm_available());
    assert!(format!("{session:?}").contains("ntlm: true"));

    assert!(session.unwrap(&[0x05, 0x04, 0x07, 0xFF]).is_err());

    assert!(session.is_poisoned());
    assert!(session.ntlm.is_none());
    assert!(!session.ntlm_available());
    assert_eq!(
        kind(session.lm20_get_ntlm3_challenge_response(&buffers.request(reference))),
        ErrorKind::ContextExpired
    );
    assert_eq!(
        kind(session.compare_ntlm_credentials(&reference, &reference)),
        ErrorKind::ContextExpired
    );

    // Poisoning the context state also drops the credential.
    let mut state = established_state(1000, 2000);
    state.ntlm = Some(ntlm_credential(1));
    state.poison();
    assert!(state.ntlm.is_none());
    assert!(format!("{state:?}").contains("ntlm: false"));
}

#[test]
fn ntlm_redirection_policy_requires_a_user_name() {
    let names = |user: &str| {
        Some(NtlmRedirectionNames {
            user: user.to_owned(),
            domain: NTLM_DOMAIN.to_owned(),
        })
    };

    assert_eq!(kind(NtlmRedirectionPolicy::new(names(""))), ErrorKind::InvalidParameter);
    assert!(NtlmRedirectionPolicy::new(names(NTLM_USER)).is_ok());
    assert!(NtlmRedirectionPolicy::new(None).is_ok());
}

fn decode_ntlm_supplemental_credential(credentials: &[u8]) -> Option<Vec<u8>> {
    let credentials: TsCredentials = picky_asn1_der::from_bytes(credentials).unwrap();
    let remote_guard: TsRemoteGuardCreds = picky_asn1_der::from_bytes(&credentials.credentials.0.0).unwrap();
    let supplemental_creds = remote_guard.supplemental_creds.0?.0.0;
    assert_eq!(supplemental_creds.len(), 1);
    assert_eq!(supplemental_creds[0].package_name.0.0, utf16le("NTLM"));

    Some(supplemental_creds[0].cred_buffer.0.0.clone())
}

fn rcg_client_with_password(password: &str) -> Kerberos {
    let mut kerberos = rcg_client();
    kerberos.auth_identity = Some(CredentialsBuffers::AuthIdentity(AuthIdentityBuffers {
        user: Utf16String::from_str("fake_user"),
        domain: Utf16String::from_str("FAKE_DOMAIN"),
        password: Secret::new(ZeroizedUtf16String(Utf16String::from_str(password))),
    }));
    kerberos
}

#[test]
fn remote_guard_credentials_delegate_an_ntlm_supplemental_credential() {
    let mut kerberos = rcg_client_with_password(NTLM_PASSWORD);
    let mut kdc = FakeKdc::new(KdcBehavior::Normal);
    let policy = NtlmRedirectionPolicy::new(None).unwrap();

    let credentials = build_credentials_with_ntlm(&mut kerberos, TARGET, &mut kdc, Some(policy)).unwrap();

    assert!(!contains(&credentials, &NTLM_NT_OWF));
    let supplemental = decode_ntlm_supplemental_credential(&credentials).unwrap();
    assert_eq!(supplemental.len(), NTLM_HANDLE_OFFSET + NTLM_CREDENTIAL_HANDLE_LEN);
    // The Kerberos logon credential is unchanged.
    assert_eq!(
        ticket_marker(&decode_credentials(&credentials).service_ticket),
        COMPUTER_TICKET_MARKER
    );

    // The session answers requests for the client identity with the delegated handle.
    let mut session = kerberos.take_remote_guard_session().unwrap();
    assert!(session.ntlm_available());
    let mut buffers = NtlmRequestBuffers::new(ms_nlmp_server_name());
    buffers.user = utf16le("FAKE_USER");
    buffers.domain = utf16le("fake_domain");
    let response = session
        .lm20_get_ntlm3_challenge_response(&buffers.request(ntlm_reference(&supplemental[NTLM_HANDLE_OFFSET..])))
        .unwrap();
    assert_response_eq(
        &response,
        &expected_ntlm_response(&response, "FAKE_USER", "fake_domain", &buffers.server_name),
    );
}

#[test]
fn remote_guard_credentials_bind_ntlm_to_the_configured_names() {
    let mut kerberos = rcg_client_with_password(NTLM_PASSWORD);
    let mut kdc = FakeKdc::new(KdcBehavior::Normal);
    let policy = NtlmRedirectionPolicy::new(Some(NtlmRedirectionNames {
        user: NTLM_USER.to_owned(),
        domain: NTLM_DOMAIN.to_owned(),
    }))
    .unwrap();

    let credentials = build_credentials_with_ntlm(&mut kerberos, TARGET, &mut kdc, Some(policy)).unwrap();
    let supplemental = decode_ntlm_supplemental_credential(&credentials).unwrap();
    let reference = ntlm_reference(&supplemental[NTLM_HANDLE_OFFSET..]);
    let mut session = kerberos.take_remote_guard_session().unwrap();

    let buffers = NtlmRequestBuffers::new(ms_nlmp_server_name());
    session
        .lm20_get_ntlm3_challenge_response(&buffers.request(reference))
        .unwrap();

    let mut buffers = NtlmRequestBuffers::new(ms_nlmp_server_name());
    buffers.user = utf16le("fake_user");
    buffers.domain = utf16le("FAKE_DOMAIN");
    assert_eq!(
        kind(session.lm20_get_ntlm3_challenge_response(&buffers.request(reference))),
        ErrorKind::LogonDenied
    );
}

#[test]
fn remote_guard_credentials_omit_ntlm_without_an_nt_owf() {
    let policy = || Some(NtlmRedirectionPolicy::new(None).unwrap());

    let mut cases = vec![
        (
            "NTLM redirection disabled",
            rcg_client_with_password(NTLM_PASSWORD),
            None,
        ),
        ("empty password", rcg_client_with_password(""), policy()),
    ];
    let mut no_identity = rcg_client();
    no_identity.auth_identity = None;
    cases.push(("no password identity", no_identity, policy()));

    for (name, mut kerberos, policy) in cases {
        let mut kdc = FakeKdc::new(KdcBehavior::Normal);
        let credentials = build_credentials_with_ntlm(&mut kerberos, TARGET, &mut kdc, policy).unwrap();

        assert_eq!(decode_ntlm_supplemental_credential(&credentials), None, "{name}");
        let mut session = kerberos.take_remote_guard_session().unwrap();
        assert!(!session.ntlm_available(), "{name}");
        assert!(session.wrap(b"rdpear").is_ok(), "{name}");
    }
}

#[test]
fn remote_guard_credentials_fail_closed_on_an_invalid_nt_hash() {
    let mut kerberos = rcg_client_with_password("$NTLM$:not-a-hash");
    let mut kdc = FakeKdc::new(KdcBehavior::Normal);
    let policy = NtlmRedirectionPolicy::new(None).unwrap();

    assert_eq!(
        kind(build_credentials_with_ntlm(
            &mut kerberos,
            TARGET,
            &mut kdc,
            Some(policy)
        )),
        ErrorKind::InvalidParameter
    );
    assert!(rcg_state(&kerberos).ntlm.is_none());
    assert_build_poisoned(&mut kerberos);
}
