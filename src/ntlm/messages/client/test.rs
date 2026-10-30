use super::*;
use crate::Utf16StringExt;
use crate::ntlm::messages::test::*;
use crate::ntlm::*;

#[test]
fn write_negotiate_writes_correct_signature() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Negotiate;

    let mut buff = Vec::new();
    write_negotiate(&mut context, &mut buff).unwrap();

    assert_eq!(NTLM_SIGNATURE, buff[SIGNATURE_START..MESSAGE_TYPE_START]);
}

#[test]
fn write_negotiate_writes_correct_message_type() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Negotiate;

    let mut buff = Vec::new();
    write_negotiate(&mut context, &mut buff).unwrap();

    assert_eq!(NEGOTIATE_MESSAGE_TYPE, buff[MESSAGE_TYPE_START..NEGOTIATE_FLAGS_START]);
}

#[test]
fn write_negotiate_writes_flags() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Negotiate;

    let mut buff = Vec::new();
    write_negotiate(&mut context, &mut buff).unwrap();

    assert_eq!(
        LOCAL_NEGOTIATE_FLAGS.to_le_bytes(),
        buff[NEGOTIATE_FLAGS_START..NEGOTIATE_DOMAIN_NAME_START]
    );
    assert_eq!(NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap(), context.flags);
}

#[test]
fn write_negotiate_writes_domain_name() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Negotiate;

    let mut buff = Vec::new();
    write_negotiate(&mut context, &mut buff).unwrap();

    assert_eq!(
        LOCAL_NEGOTIATE_DOMAIN,
        buff[NEGOTIATE_DOMAIN_NAME_START..NEGOTIATE_WORKSTATION_START]
    );
}

#[test]
fn write_negotiate_writes_workstation() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Negotiate;

    let mut buff = Vec::new();
    write_negotiate(&mut context, &mut buff).unwrap();

    assert_eq!(
        LOCAL_NEGOTIATE_WORKSTATION,
        buff[NEGOTIATE_WORKSTATION_START..NEGOTIATE_VERSION_START]
    );
}

#[test]
fn write_negotiate_writes_version() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Negotiate;

    let mut buff = Vec::new();
    write_negotiate(&mut context, &mut buff).unwrap();

    assert_eq!(
        LOCAL_NEGOTIATE_VERSION,
        buff[NEGOTIATE_VERSION_START..NEGOTIATE_VERSION_START + NTLM_VERSION_SIZE]
    );
}

#[test]
fn write_negotiate_writes_buffer_to_context() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Negotiate;

    let mut buff = Vec::new();
    write_negotiate(&mut context, &mut buff).unwrap();

    assert_eq!((*LOCAL_NEGOTIATE_MESSAGE).as_ref(), buff.as_slice());
}

#[test]
fn write_negotiate_changes_context_state_on_success() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Negotiate;

    let expected_state = NtlmState::Challenge;

    let mut buff = Vec::new();
    write_negotiate(&mut context, &mut buff).unwrap();

    assert_eq!(expected_state, context.state);
}

#[test]
fn write_negotiate_failed_on_incorrect_state() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Challenge;

    let mut buff = Vec::new();
    assert!(write_negotiate(&mut context, &mut buff).is_err());
}

#[test]
fn read_challenge_does_not_fail_with_correct_header() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Challenge;
    context.negotiate_message = Some(NegotiateMessage::new(LOCAL_NEGOTIATE_MESSAGE.to_vec()));
    context.flags = NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap();

    let buff = *LOCAL_CHALLENGE_MESSAGE;
    read_challenge(&mut context, buff.as_ref()).unwrap();
}

#[test]
fn read_challenge_fails_with_incorrect_signature() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Challenge;
    context.negotiate_message = Some(NegotiateMessage::new(LOCAL_NEGOTIATE_MESSAGE.to_vec()));
    context.flags = NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap();

    let mut buff = LOCAL_CHALLENGE_MESSAGE.to_vec();
    buff[1] += 1;
    assert!(read_challenge(&mut context, buff.as_slice()).is_err());
}

#[test]
fn read_challenge_fails_with_incorrect_message_type() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Challenge;
    context.negotiate_message = Some(NegotiateMessage::new(LOCAL_NEGOTIATE_MESSAGE.to_vec()));
    context.flags = NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap();

    let mut buff = LOCAL_CHALLENGE_MESSAGE.to_vec();
    buff[8] = 3;
    assert!(read_challenge(&mut context, buff.as_slice()).is_err());
}

#[test]
fn read_challenge_reads_correct_flags() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Challenge;
    context.negotiate_message = Some(NegotiateMessage::new(LOCAL_NEGOTIATE_MESSAGE.to_vec()));
    context.flags = NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap();

    let buff = *LOCAL_CHALLENGE_MESSAGE;
    read_challenge(&mut context, buff.as_ref()).unwrap();

    assert_eq!(
        LOCAL_CHALLENGE_FLAGS.to_le_bytes(),
        buff[CHALLENGE_FLAGS_START..CHALLENGE_SERVER_CHALLENGE_START]
    );
    assert_eq!(NegotiateFlags::from_bits(LOCAL_CHALLENGE_FLAGS).unwrap(), context.flags);
}

#[test]
fn read_challenge_reads_correct_target_info() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Challenge;
    context.negotiate_message = Some(NegotiateMessage::new(LOCAL_NEGOTIATE_MESSAGE.to_vec()));
    context.flags = NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap();

    let buff = *LOCAL_CHALLENGE_MESSAGE;
    read_challenge(&mut context, buff.as_ref()).unwrap();

    assert_eq!(
        LOCAL_CHALLENGE_TARGET_INFO_BUFFER.as_ref(),
        context.challenge_message.unwrap().target_info.as_slice()
    );
}

#[test]
fn read_challenge_reads_correct_server_challenge() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Challenge;
    context.negotiate_message = Some(NegotiateMessage::new(LOCAL_NEGOTIATE_MESSAGE.to_vec()));
    context.flags = NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap();

    let buff = *LOCAL_CHALLENGE_MESSAGE;
    read_challenge(&mut context, buff.as_ref()).unwrap();

    assert_eq!(
        LOCAL_CHALLENGE_SERVER_CHALLENGE,
        context.challenge_message.unwrap().server_challenge
    );
}

#[test]
fn read_challenge_reads_correct_timestamp() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Challenge;
    context.negotiate_message = Some(NegotiateMessage::new(LOCAL_NEGOTIATE_MESSAGE.to_vec()));
    context.flags = NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap();

    let buff = *LOCAL_CHALLENGE_MESSAGE;
    read_challenge(&mut context, buff.as_ref()).unwrap();

    assert_eq!(LOCAL_CHALLENGE_TIMESTAMP, context.challenge_message.unwrap().timestamp);
}

#[test]
fn read_challenge_writes_buffer_to_context() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Challenge;
    context.negotiate_message = Some(NegotiateMessage::new(LOCAL_NEGOTIATE_MESSAGE.to_vec()));
    context.flags = NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap();

    let buff = *LOCAL_CHALLENGE_MESSAGE;
    read_challenge(&mut context, buff.as_ref()).unwrap();

    assert_eq!(
        (*LOCAL_CHALLENGE_MESSAGE).as_ref(),
        context.challenge_message.unwrap().message.as_slice()
    );
}

#[test]
fn read_challenge_fails_on_incorrect_state() {
    let mut context = Ntlm::new();
    context.set_version(LOCAL_NEGOTIATE_VERSION);
    context.state = NtlmState::Authenticate;
    context.negotiate_message = Some(NegotiateMessage::new(LOCAL_NEGOTIATE_MESSAGE.to_vec()));
    context.flags = NegotiateFlags::from_bits(LOCAL_NEGOTIATE_FLAGS).unwrap();

    let buff = *LOCAL_CHALLENGE_MESSAGE;
    assert!(read_challenge(&mut context, buff.as_ref()).is_err());
}

#[test]
fn write_authenticate_writes_correct_header() {
    let mut context = Ntlm::new();
    context.set_version(NTLM_VERSION);
    context.state = NtlmState::Authenticate;
    context.negotiate_message = Some(NegotiateMessage::new(vec![0x01, 0x02, 0x03]));
    context.challenge_message = Some(ChallengeMessage::new(
        vec![0x04, 0x05, 0x06],
        Vec::new(),
        [0x00; CHALLENGE_SIZE],
        0,
    ));
    let mut buff = Vec::new();
    let expected = [0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00];

    write_authenticate(&mut context, &TEST_CREDENTIALS, &mut buff).unwrap();

    assert_eq!(
        buff[SIGNATURE_START..AUTHENTICATE_LM_CHALLENGE_RESPONSE_START],
        expected
    );
}

#[test]
fn write_authenticate_changes_context_state_on_success() {
    let mut context = Ntlm::new();
    context.set_version(NTLM_VERSION);
    let mut buff = Vec::new();
    context.negotiate_message = Some(NegotiateMessage::new(vec![0x01, 0x02, 0x03]));
    context.challenge_message = Some(ChallengeMessage::new(
        vec![0x04, 0x05, 0x06],
        Vec::new(),
        [0x00; CHALLENGE_SIZE],
        0,
    ));
    context.state = NtlmState::Authenticate;
    let expected_state = NtlmState::Final;

    write_authenticate(&mut context, &TEST_CREDENTIALS, &mut buff).unwrap();

    assert_eq!(context.state, expected_state);
}

#[test]
fn write_anonymous_authenticate_uses_the_null_session_wire_format() {
    const ANONYMOUS_PAYLOAD_OFFSET: usize = 72;
    let mut context = Ntlm::new();
    context.set_version(NTLM_VERSION);
    context.state = NtlmState::Authenticate;
    context.null_session = true;
    context.negotiate_message = Some(NegotiateMessage::new(vec![0x01, 0x02, 0x03]));
    context.challenge_message = Some(ChallengeMessage::new(
        vec![0x04, 0x05, 0x06],
        Vec::new(),
        [0x00; CHALLENGE_SIZE],
        0,
    ));

    let mut buffer = Vec::new();
    write_anonymous_authenticate(&mut context, &mut buffer).unwrap();

    assert_eq!(buffer.len(), ANONYMOUS_PAYLOAD_OFFSET + 1);
    assert_eq!(&buffer[12..20], &[1, 0, 1, 0, 72, 0, 0, 0]);
    assert_eq!(&buffer[20..28], &[0; 8]); // Length, maximum length, and offset are zero.
    assert_eq!(&buffer[28..32], &[0; 4]); // Empty domain.
    assert_eq!(&buffer[36..40], &[0; 4]); // Empty username.
    assert_eq!(buffer[ANONYMOUS_PAYLOAD_OFFSET], 0); // Z(1) LM response.
    assert!(context.flags.contains(NegotiateFlags::NTLM_SSP_NEGOTIATE_ANONYMOUS));
    assert!(!context.flags.intersects(
        NegotiateFlags::NTLM_SSP_NEGOTIATE_SIGN
            | NegotiateFlags::NTLM_SSP_NEGOTIATE_SEAL
            | NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH
    ));
    assert!(context.authenticate_message.is_none());
    assert!(context.session_key.is_none());
}

#[test]
fn write_authenticate_correct_writes_domain_name() {
    let expected = [0x0c, 0x00, 0x0c, 0x00, 0x58, 0x00, 0x00, 0x00];
    let expected_buffer = [0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00];

    let mut context = Ntlm::new();
    context.set_version(NTLM_VERSION);
    context.state = NtlmState::Authenticate;
    context.negotiate_message = Some(NegotiateMessage::new(vec![0x01, 0x02, 0x03]));
    context.challenge_message = Some(ChallengeMessage::new(
        vec![0x04, 0x05, 0x06],
        vec![
            0x2, 0x0, 0x8, 0x0, 0x48, 0x4f, 0x53, 0x54, 0x4e, 0x41, 0x4d, 0x45, 0x1, 0x0, 0x8, 0x0, 0x48, 0x4f, 0x53,
            0x54, 0x4e, 0x41, 0x4d, 0x45, 0x4, 0x0, 0x8, 0x0, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x3, 0x0,
            0x8, 0x0, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x7, 0x0, 0x8, 0x0, 0x33, 0x57, 0xbd, 0xb1, 0x7,
            0x8b, 0xcf, 0x1, 0x6, 0x0, 0x4, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ],
        SERVER_CHALLENGE,
        TIMESTAMP,
    ));
    context.flags = NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH;

    let mut buff = Vec::new();
    write_authenticate(&mut context, &TEST_CREDENTIALS, &mut buff).unwrap();

    assert_eq!(
        buff[AUTHENTICATE_DOMAIN_NAME_START..AUTHENTICATE_USER_NAME_START],
        expected
    );
    assert_eq!(
        buff[AUTHENTICATE_OFFSET_WITH_MIC..AUTHENTICATE_OFFSET_WITH_MIC + TEST_CREDENTIALS.domain.as_bytes_le().len()],
        expected_buffer[..]
    );
}

#[test]
fn write_authenticate_correct_writes_user_name() {
    let expected = [0x08, 0x00, 0x08, 0x00, 0x64, 0x00, 0x00, 0x00];
    let expected_buffer = [0x55, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00];

    let mut context = Ntlm::new();
    context.set_version(NTLM_VERSION);
    context.state = NtlmState::Authenticate;
    context.negotiate_message = Some(NegotiateMessage::new(vec![0x01, 0x02, 0x03]));
    context.challenge_message = Some(ChallengeMessage::new(
        vec![0x04, 0x05, 0x06],
        vec![
            0x2, 0x0, 0x8, 0x0, 0x48, 0x4f, 0x53, 0x54, 0x4e, 0x41, 0x4d, 0x45, 0x1, 0x0, 0x8, 0x0, 0x48, 0x4f, 0x53,
            0x54, 0x4e, 0x41, 0x4d, 0x45, 0x4, 0x0, 0x8, 0x0, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x3, 0x0,
            0x8, 0x0, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x7, 0x0, 0x8, 0x0, 0x33, 0x57, 0xbd, 0xb1, 0x7,
            0x8b, 0xcf, 0x1, 0x6, 0x0, 0x4, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ],
        SERVER_CHALLENGE,
        TIMESTAMP,
    ));
    context.flags = NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH;

    let mut buff = Vec::new();
    write_authenticate(&mut context, &TEST_CREDENTIALS, &mut buff).unwrap();

    assert_eq!(
        buff[AUTHENTICATE_USER_NAME_START..AUTHENTICATE_WORKSTATION_START],
        expected
    );
    let offset = AUTHENTICATE_OFFSET_WITH_MIC + TEST_CREDENTIALS.domain.as_bytes_le().len();
    assert_eq!(
        buff[offset..offset + TEST_CREDENTIALS.user.as_bytes_le().len()],
        expected_buffer[..]
    );
}

#[test]
fn write_authenticate_fails_on_incorrect_state() {
    let mut context = Ntlm::new();
    context.set_version(NTLM_VERSION);
    context.state = NtlmState::Final;
    context.negotiate_message = Some(NegotiateMessage::new(vec![0x01, 0x02, 0x03]));
    context.challenge_message = Some(ChallengeMessage::new(
        vec![0x04, 0x05, 0x06],
        vec![
            0x2, 0x0, 0x8, 0x0, 0x48, 0x4f, 0x53, 0x54, 0x4e, 0x41, 0x4d, 0x45, 0x1, 0x0, 0x8, 0x0, 0x48, 0x4f, 0x53,
            0x54, 0x4e, 0x41, 0x4d, 0x45, 0x4, 0x0, 0x8, 0x0, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x3, 0x0,
            0x8, 0x0, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x7, 0x0, 0x8, 0x0, 0x33, 0x57, 0xbd, 0xb1, 0x7,
            0x8b, 0xcf, 0x1, 0x6, 0x0, 0x4, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ],
        SERVER_CHALLENGE,
        TIMESTAMP,
    ));
    context.flags = NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH;

    let mut buff = Vec::new();
    assert!(write_authenticate(&mut context, &TEST_CREDENTIALS, &mut buff).is_err());
}

#[test]
fn anonymous_negotiate_sets_always_sign_without_session_security() {
    let mut context = Ntlm::new();
    context.state = NtlmState::Negotiate;
    context.null_session = true;
    let mut message = Vec::new();
    write_negotiate(&mut context, &mut message).unwrap();
    let flags = NegotiateFlags::from_bits_retain(u32::from_le_bytes(message[12..16].try_into().unwrap()));
    assert!(flags.contains(NegotiateFlags::NTLM_SSP_NEGOTIATE_ALWAYS_SIGN));
    assert!(flags.contains(NegotiateFlags::NTLM_SSP_NEGOTIATE_ANONYMOUS));
    assert!(!flags.intersects(
        NegotiateFlags::NTLM_SSP_NEGOTIATE_SIGN
            | NegotiateFlags::NTLM_SSP_NEGOTIATE_SEAL
            | NegotiateFlags::NTLM_SSP_NEGOTIATE_KEY_EXCH
    ));
}

#[test]
fn anonymous_version_messages_place_workstation_in_authenticate() {
    let mut context = Ntlm::with_config(NtlmConfig {
        client_computer_name: Some("CLIENT.example.com".into()),
    });
    context.state = NtlmState::Negotiate;
    context.null_session = true;
    let mut negotiate = Vec::new();
    write_negotiate(&mut context, &mut negotiate).unwrap();
    assert_eq!(&negotiate[16..20], &[0; 4]); // DomainNameLen / MaxLen.
    assert_eq!(&negotiate[24..28], &[0; 4]); // WorkstationLen / MaxLen (3.1.5.1.1).
    context.state = NtlmState::Authenticate;
    context.challenge_message = Some(ChallengeMessage::new(vec![], vec![], [0; CHALLENGE_SIZE], 0));
    let mut authenticate = Vec::new();
    write_anonymous_authenticate(&mut context, &mut authenticate).unwrap();
    assert_eq!(&authenticate[20..28], &[0; 8]);
    assert_eq!(&authenticate[44..52], &[12, 0, 12, 0, 72, 0, 0, 0]);
    assert_eq!(
        &authenticate[72..84],
        &[b'C', 0, b'L', 0, b'I', 0, b'E', 0, b'N', 0, b'T', 0]
    );
    assert_eq!(&authenticate[12..20], &[1, 0, 1, 0, 84, 0, 0, 0]);
    assert_eq!(authenticate[84], 0);
}
