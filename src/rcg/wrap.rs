//! Strict [RFC 4121] per-message token processing for the Remote Credential Guard protection context.
//!
//! The regular Kerberos `encrypt_message`/`decrypt_message` paths stay lenient for compatibility with
//! existing users. The Remote Credential Guard context instead requires sealed tokens, exact flags,
//! exact sequence numbers, and a verified encrypted header copy, because the same context later
//! protects the RDPEAR channel (MS-RDPEAR [2.2 Message Syntax]).
//!
//! [RFC 4121]: https://www.rfc-editor.org/rfc/rfc4121
//! [2.2 Message Syntax]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/

use picky_krb::crypto::CipherSuite;
use picky_krb::crypto::aes::{AesSize, checksum_sha_aes};
use zeroize::Zeroizing;

use crate::{Error, ErrorKind, Result};

const WRAP_TOKEN_ID: [u8; 2] = [0x05, 0x04];
const MIC_TOKEN_ID: [u8; 2] = [0x04, 0x04];
const TOKEN_HEADER_LEN: usize = 16;
const FILLER: u8 = 0xFF;

const FLAG_SENT_BY_ACCEPTOR: u8 = 0x01;
const FLAG_SEALED: u8 = 0x02;
const FLAG_ACCEPTOR_SUBKEY: u8 = 0x04;

/// Right rotation count emitted on sealed tokens.
///
/// MS-KILE [3.4.5.4.1 Kerberos Binding of GSS_WrapEx()] uses 28 when encryption is requested, which
/// also matches the Windows RDPEAR tokens.
///
/// [3.4.5.4.1 Kerberos Binding of GSS_WrapEx()]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e94b3acd-8415-4d0d-9786-749d0c39d550
const SEAL_RRC: u16 = 28;

const AES_CONFOUNDER_LEN: usize = 16;
const AES_HMAC_LEN: usize = 12;

/// Size of a sealed token without any payload: header, confounder, encrypted header copy, and HMAC.
pub(crate) const SEAL_OVERHEAD: usize = TOKEN_HEADER_LEN + AES_CONFOUNDER_LEN + TOKEN_HEADER_LEN + AES_HMAC_LEN;

const MIC_TOKEN_LEN: usize = TOKEN_HEADER_LEN + AES_HMAC_LEN;

/// Upper bound on the size of a Remote Credential Guard wrap token.
pub const MAX_TOKEN_LEN: usize = 4 * 1024 * 1024;

/// Largest sequence number used by the Remote Credential Guard context.
///
/// Kerberos AP-REQ and AP-REP sequence numbers are `UInt32` (RFC 4120 [5.5.1 KRB_AP_REQ Definition]).
/// Wrapping past `u32::MAX` is not attempted, because peer behavior at that boundary is unverified.
///
/// [5.5.1 KRB_AP_REQ Definition]: https://www.rfc-editor.org/rfc/rfc4120#section-5.5.1
pub(crate) const MAX_SEQUENCE_NUMBER: u64 = 0xFFFF_FFFF;

const KEY_USAGE_ACCEPTOR_SEAL: i32 = 22;
const KEY_USAGE_ACCEPTOR_SIGN: i32 = 23;
const KEY_USAGE_INITIATOR_SEAL: i32 = 24;
const KEY_USAGE_INITIATOR_SIGN: i32 = 25;

/// The party that produced a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sender {
    Initiator,
    Acceptor,
}

impl Sender {
    fn seal_usage(self) -> i32 {
        match self {
            Sender::Initiator => KEY_USAGE_INITIATOR_SEAL,
            Sender::Acceptor => KEY_USAGE_ACCEPTOR_SEAL,
        }
    }

    fn sign_usage(self) -> i32 {
        match self {
            Sender::Initiator => KEY_USAGE_INITIATOR_SIGN,
            Sender::Acceptor => KEY_USAGE_ACCEPTOR_SIGN,
        }
    }

    /// Token flags for this sender when the acceptor subkey protects the context.
    ///
    /// Windows RDPEAR tokens use 0x07 from the server and 0x06 from the client.
    fn flags(self) -> u8 {
        match self {
            Sender::Initiator => FLAG_ACCEPTOR_SUBKEY,
            Sender::Acceptor => FLAG_SENT_BY_ACCEPTOR | FLAG_ACCEPTOR_SUBKEY,
        }
    }
}

/// Returns the AES size for the cipher suites accepted by the Remote Credential Guard context.
pub(crate) fn aes_size(cipher_suite: &CipherSuite) -> Result<AesSize> {
    match cipher_suite {
        CipherSuite::Aes256CtsHmacSha196 => Ok(AesSize::Aes256),
        CipherSuite::Aes128CtsHmacSha196 => Ok(AesSize::Aes128),
        _ => Err(Error::new(
            ErrorKind::AlgorithmMismatch,
            "remote credential guard requires an AES Kerberos encryption type",
        )),
    }
}

fn header(token_id: [u8; 2], flags: u8, ec: u16, rrc: u16, seq_number: u64) -> [u8; TOKEN_HEADER_LEN] {
    let mut header = [0; TOKEN_HEADER_LEN];
    header[0..2].copy_from_slice(&token_id);
    header[2] = flags;
    header[3] = FILLER;
    header[4..6].copy_from_slice(&ec.to_be_bytes());
    header[6..8].copy_from_slice(&rrc.to_be_bytes());
    header[8..16].copy_from_slice(&seq_number.to_be_bytes());
    header
}

fn check_sequence_number(seq_number: u64) -> Result<()> {
    if seq_number > MAX_SEQUENCE_NUMBER {
        return Err(Error::new(
            ErrorKind::OutOfSequence,
            "remote credential guard sequence number space is exhausted",
        ));
    }

    Ok(())
}

/// Compares two byte strings without data-dependent early exits.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));

    std::hint::black_box(diff) == 0
}

/// Produces a sealed wrap token (RFC 4121 [4.2.4 Encryption and Checksum Operations]).
///
/// The token uses EC=0 and RRC=28, like the Windows RDPEAR tokens.
///
/// [4.2.4 Encryption and Checksum Operations]: https://www.rfc-editor.org/rfc/rfc4121#section-4.2.4
pub(crate) fn seal(
    cipher_suite: &CipherSuite,
    key: &[u8],
    sender: Sender,
    seq_number: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    aes_size(cipher_suite)?;
    check_sequence_number(seq_number)?;

    let flags = sender.flags() | FLAG_SEALED;
    // The encrypted header copy carries RRC=0 (RFC 4121 4.2.4).
    let inner_header = header(WRAP_TOKEN_ID, flags, 0, 0, seq_number);

    let mut payload = Zeroizing::new(Vec::with_capacity(plaintext.len() + TOKEN_HEADER_LEN));
    payload.extend_from_slice(plaintext);
    payload.extend_from_slice(&inner_header);

    let mut encrypted = cipher_suite.cipher().encrypt(key, sender.seal_usage(), &payload)?;
    let rotation = usize::from(SEAL_RRC) % encrypted.len();
    encrypted.rotate_right(rotation);

    let mut token = Vec::with_capacity(TOKEN_HEADER_LEN + encrypted.len());
    token.extend_from_slice(&header(WRAP_TOKEN_ID, flags, 0, SEAL_RRC, seq_number));
    token.extend_from_slice(&encrypted);

    Ok(token)
}

/// Verifies and decrypts a sealed wrap token.
///
/// Requirements:
/// - the token is sealed and has exactly the flags expected from `sender`;
/// - the sequence number equals `expected_seq_number`;
/// - the HMAC is valid (checked in constant time);
/// - the decrypted header copy equals the outer header with RRC zeroed (RFC 4121 4.2.4).
///
/// Any RRC value is accepted, including values not smaller than the token body length (RFC 4121 4.2.5).
pub(crate) fn unseal(
    cipher_suite: &CipherSuite,
    key: &[u8],
    sender: Sender,
    expected_seq_number: u64,
    token: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    aes_size(cipher_suite)?;
    check_sequence_number(expected_seq_number)?;

    if token.len() > MAX_TOKEN_LEN {
        return Err(Error::new(ErrorKind::InvalidToken, "wrap token is too large"));
    }
    if token.len() < SEAL_OVERHEAD {
        return Err(Error::new(ErrorKind::InvalidToken, "wrap token is too short"));
    }

    let (outer_header, body) = token.split_at(TOKEN_HEADER_LEN);

    if outer_header[0..2] != WRAP_TOKEN_ID {
        return Err(Error::new(ErrorKind::InvalidToken, "invalid wrap token id"));
    }
    if outer_header[3] != FILLER {
        return Err(Error::new(ErrorKind::InvalidToken, "invalid wrap token filler"));
    }
    if outer_header[2] != sender.flags() | FLAG_SEALED {
        return Err(Error::new(
            ErrorKind::MessageAltered,
            format!("unexpected wrap token flags: 0x{:02x}", outer_header[2]),
        ));
    }

    let ec = usize::from(u16::from_be_bytes([outer_header[4], outer_header[5]]));
    let rrc = usize::from(u16::from_be_bytes([outer_header[6], outer_header[7]]));
    let mut seq_number_bytes = [0; 8];
    seq_number_bytes.copy_from_slice(&outer_header[8..16]);
    let seq_number = u64::from_be_bytes(seq_number_bytes);

    if seq_number != expected_seq_number {
        return Err(Error::new(
            ErrorKind::OutOfSequence,
            "wrap token sequence number does not match the expected value",
        ));
    }

    let mut body = body.to_vec();
    let rotation = rrc % body.len();
    body.rotate_left(rotation);

    let cipher = cipher_suite.cipher();
    let decrypted = cipher.decrypt_no_checksum(key, sender.seal_usage(), &body)?;
    let plaintext = Zeroizing::new(decrypted.plaintext);
    let mut checksum_input = Zeroizing::new(decrypted.confounder);
    checksum_input.extend_from_slice(&plaintext);
    let expected_checksum = cipher.encryption_checksum(key, sender.seal_usage(), &checksum_input)?;

    if !constant_time_eq(&expected_checksum, &decrypted.checksum) {
        return Err(Error::new(
            ErrorKind::MessageAltered,
            "wrap token integrity check failed",
        ));
    }

    if plaintext.len() < TOKEN_HEADER_LEN + ec {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "wrap token is shorter than its extra count",
        ));
    }

    let data_len = plaintext.len() - TOKEN_HEADER_LEN - ec;
    let inner_header = &plaintext[plaintext.len() - TOKEN_HEADER_LEN..];
    let mut expected_inner_header = [0; TOKEN_HEADER_LEN];
    expected_inner_header.copy_from_slice(outer_header);
    expected_inner_header[6] = 0;
    expected_inner_header[7] = 0;

    if inner_header != expected_inner_header {
        return Err(Error::new(
            ErrorKind::MessageAltered,
            "encrypted wrap token header does not match the token header",
        ));
    }

    Ok(Zeroizing::new(plaintext[..data_len].to_vec()))
}

/// Produces a MIC token (RFC 4121 [4.2.6.1 MIC Tokens]).
///
/// [4.2.6.1 MIC Tokens]: https://www.rfc-editor.org/rfc/rfc4121#section-4.2.6.1
pub(crate) fn mic(
    cipher_suite: &CipherSuite,
    key: &[u8],
    sender: Sender,
    seq_number: u64,
    message: &[u8],
) -> Result<Vec<u8>> {
    let aes_size = aes_size(cipher_suite)?;
    check_sequence_number(seq_number)?;

    let header = mic_header(sender.flags(), seq_number);
    let mut payload = message.to_vec();
    payload.extend_from_slice(&header);

    let mut token = header.to_vec();
    token.extend_from_slice(&checksum_sha_aes(key, sender.sign_usage(), &payload, &aes_size)?);

    Ok(token)
}

fn mic_header(flags: u8, seq_number: u64) -> [u8; TOKEN_HEADER_LEN] {
    let mut header = [FILLER; TOKEN_HEADER_LEN];
    header[0..2].copy_from_slice(&MIC_TOKEN_ID);
    header[2] = flags;
    header[8..16].copy_from_slice(&seq_number.to_be_bytes());
    header
}

/// Verifies a MIC token with exact flags and sequence number.
///
/// A sequence mismatch reports the expected and received values without authenticating the received header.
pub(crate) fn verify_mic(
    cipher_suite: &CipherSuite,
    key: &[u8],
    sender: Sender,
    expected_seq_number: u64,
    message: &[u8],
    token: &[u8],
) -> Result<()> {
    let aes_size = aes_size(cipher_suite)?;
    check_sequence_number(expected_seq_number)?;

    if token.len() != MIC_TOKEN_LEN {
        return Err(Error::new(ErrorKind::InvalidToken, "invalid MIC token length"));
    }

    let (token_header, checksum) = token.split_at(TOKEN_HEADER_LEN);

    if token_header[0..2] != MIC_TOKEN_ID || token_header[3..8] != [FILLER; 5] {
        return Err(Error::new(ErrorKind::InvalidToken, "invalid MIC token header"));
    }
    if token_header[2] != sender.flags() {
        return Err(Error::new(
            ErrorKind::MessageAltered,
            format!("unexpected MIC token flags: 0x{:02x}", token_header[2]),
        ));
    }

    let mut seq_number_bytes = [0; 8];
    seq_number_bytes.copy_from_slice(&token_header[8..16]);
    let seq_number = u64::from_be_bytes(seq_number_bytes);
    if seq_number != expected_seq_number {
        return Err(Error::new(
            ErrorKind::OutOfSequence,
            format!(
                "MIC token sequence number mismatch: expected {expected_seq_number}, received {seq_number} \
                 (unauthenticated header)"
            ),
        ));
    }

    let mut payload = message.to_vec();
    payload.extend_from_slice(token_header);
    let expected_checksum = checksum_sha_aes(key, sender.sign_usage(), &payload, &aes_size)?;

    if !constant_time_eq(&expected_checksum, checksum) {
        return Err(Error::new(
            ErrorKind::MessageAltered,
            "MIC token integrity check failed",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AES256_KEY: [u8; 32] = [0x11; 32];
    const AES128_KEY: [u8; 16] = [0x22; 16];

    fn set_rrc(token: &mut [u8], rrc: u16) {
        // Re-rotates the body for a different RRC while keeping the header consistent.
        let current = usize::from(u16::from_be_bytes([token[6], token[7]]));
        let body = &mut token[TOKEN_HEADER_LEN..];
        let len = body.len();
        body.rotate_left(current % len);
        body.rotate_right(usize::from(rrc) % len);
        token[6..8].copy_from_slice(&rrc.to_be_bytes());
    }

    #[test]
    fn seal_matches_native_header_layout() {
        let token = seal(
            &CipherSuite::Aes256CtsHmacSha196,
            &AES256_KEY,
            Sender::Initiator,
            7,
            b"abc",
        )
        .unwrap();

        assert_eq!(&token[..8], &[0x05, 0x04, 0x06, 0xFF, 0x00, 0x00, 0x00, 28]);
        assert_eq!(&token[8..16], &7u64.to_be_bytes());
        assert_eq!(token.len(), SEAL_OVERHEAD + 3);

        let token = seal(
            &CipherSuite::Aes256CtsHmacSha196,
            &AES256_KEY,
            Sender::Acceptor,
            7,
            b"abc",
        )
        .unwrap();
        assert_eq!(token[2], 0x07);
    }

    #[test]
    fn seal_unseal_round_trip_for_both_aes_sizes() {
        for (suite, key) in [
            (CipherSuite::Aes256CtsHmacSha196, AES256_KEY.as_slice()),
            (CipherSuite::Aes128CtsHmacSha196, AES128_KEY.as_slice()),
        ] {
            for plaintext in [&b""[..], b"x", &[0x5A; 1000]] {
                let token = seal(&suite, key, Sender::Acceptor, 39_321_548, plaintext).unwrap();
                let decrypted = unseal(&suite, key, Sender::Acceptor, 39_321_548, &token).unwrap();
                assert_eq!(decrypted.as_slice(), plaintext);
            }
        }
    }

    #[test]
    fn unseal_accepts_any_rrc() {
        let suite = CipherSuite::Aes256CtsHmacSha196;
        let token = seal(&suite, &AES256_KEY, Sender::Acceptor, 1, b"payload").unwrap();
        let body_len = u16::try_from(token.len() - TOKEN_HEADER_LEN).unwrap();

        for rrc in [0, 12, 28, body_len, body_len + 5, u16::MAX] {
            let mut token = token.clone();
            set_rrc(&mut token, rrc);
            let decrypted = unseal(&suite, &AES256_KEY, Sender::Acceptor, 1, &token).unwrap();
            assert_eq!(decrypted.as_slice(), b"payload");
        }
    }

    #[test]
    fn unseal_rejects_wrong_sequence_number() {
        let suite = CipherSuite::Aes256CtsHmacSha196;
        let token = seal(&suite, &AES256_KEY, Sender::Acceptor, 10, b"payload").unwrap();

        for expected in [9, 11] {
            let err = unseal(&suite, &AES256_KEY, Sender::Acceptor, expected, &token).unwrap_err();
            assert_eq!(err.error_type, ErrorKind::OutOfSequence);
        }
    }

    #[test]
    fn unseal_rejects_wrong_direction_and_flags() {
        let suite = CipherSuite::Aes256CtsHmacSha196;
        let initiator_token = seal(&suite, &AES256_KEY, Sender::Initiator, 3, b"payload").unwrap();

        // A reflected client token must not be accepted as a server token.
        let err = unseal(&suite, &AES256_KEY, Sender::Acceptor, 3, &initiator_token).unwrap_err();
        assert_eq!(err.error_type, ErrorKind::MessageAltered);

        let mut token = seal(&suite, &AES256_KEY, Sender::Acceptor, 3, b"payload").unwrap();
        // Clearing the AcceptorSubkey flag is rejected even though the outer header is not authenticated directly.
        token[2] = FLAG_SENT_BY_ACCEPTOR | FLAG_SEALED;
        let err = unseal(&suite, &AES256_KEY, Sender::Acceptor, 3, &token).unwrap_err();
        assert_eq!(err.error_type, ErrorKind::MessageAltered);

        // An integrity-only token is rejected.
        token[2] = FLAG_SENT_BY_ACCEPTOR | FLAG_ACCEPTOR_SUBKEY;
        let err = unseal(&suite, &AES256_KEY, Sender::Acceptor, 3, &token).unwrap_err();
        assert_eq!(err.error_type, ErrorKind::MessageAltered);
    }

    #[test]
    fn unseal_rejects_tampering() {
        let suite = CipherSuite::Aes256CtsHmacSha196;
        let token = seal(&suite, &AES256_KEY, Sender::Acceptor, 3, b"payload").unwrap();

        for index in TOKEN_HEADER_LEN..token.len() {
            let mut tampered = token.clone();
            tampered[index] ^= 0x01;
            let err = unseal(&suite, &AES256_KEY, Sender::Acceptor, 3, &tampered).unwrap_err();
            assert_eq!(err.error_type, ErrorKind::MessageAltered, "byte {index}");
        }

        let err = unseal(&suite, &[0x12; 32], Sender::Acceptor, 3, &token).unwrap_err();
        assert_eq!(err.error_type, ErrorKind::MessageAltered);
    }

    #[test]
    fn unseal_rejects_outer_header_substitution() {
        let suite = CipherSuite::Aes256CtsHmacSha196;
        let token = seal(&suite, &AES256_KEY, Sender::Acceptor, 3, b"payload").unwrap();

        // Changing the outer sequence number fails the encrypted header comparison.
        let mut tampered = token.clone();
        tampered[15] = 4;
        let err = unseal(&suite, &AES256_KEY, Sender::Acceptor, 4, &tampered).unwrap_err();
        assert_eq!(err.error_type, ErrorKind::MessageAltered);

        // Claiming a non-zero extra count fails the encrypted header comparison.
        let mut tampered = token;
        tampered[5] = 1;
        let err = unseal(&suite, &AES256_KEY, Sender::Acceptor, 3, &tampered).unwrap_err();
        assert_eq!(err.error_type, ErrorKind::MessageAltered);
    }

    #[test]
    fn unseal_rejects_malformed_tokens() {
        let suite = CipherSuite::Aes256CtsHmacSha196;

        let err = unseal(&suite, &AES256_KEY, Sender::Acceptor, 0, &[0; SEAL_OVERHEAD - 1]).unwrap_err();
        assert_eq!(err.error_type, ErrorKind::InvalidToken);

        let err = unseal(&suite, &AES256_KEY, Sender::Acceptor, 0, &vec![0; MAX_TOKEN_LEN + 1]).unwrap_err();
        assert_eq!(err.error_type, ErrorKind::InvalidToken);

        let mut token = seal(&suite, &AES256_KEY, Sender::Acceptor, 0, b"x").unwrap();
        token[3] = 0;
        let err = unseal(&suite, &AES256_KEY, Sender::Acceptor, 0, &token).unwrap_err();
        assert_eq!(err.error_type, ErrorKind::InvalidToken);
    }

    #[test]
    fn rejects_non_aes_and_exhausted_sequence_numbers() {
        let err = seal(&CipherSuite::Des3CbcSha1Kd, &[0; 24], Sender::Initiator, 0, b"x").unwrap_err();
        assert_eq!(err.error_type, ErrorKind::AlgorithmMismatch);

        let err = seal(
            &CipherSuite::Aes256CtsHmacSha196,
            &AES256_KEY,
            Sender::Initiator,
            MAX_SEQUENCE_NUMBER + 1,
            b"x",
        )
        .unwrap_err();
        assert_eq!(err.error_type, ErrorKind::OutOfSequence);
    }

    #[test]
    fn mic_round_trip_and_failures() {
        let suite = CipherSuite::Aes256CtsHmacSha196;
        let token = mic(&suite, &AES256_KEY, Sender::Acceptor, 39_321_546, b"mech list").unwrap();
        assert_eq!(&token[..3], &[0x04, 0x04, 0x05]);

        verify_mic(&suite, &AES256_KEY, Sender::Acceptor, 39_321_546, b"mech list", &token).unwrap();

        let err = verify_mic(&suite, &AES256_KEY, Sender::Acceptor, 39_321_547, b"mech list", &token).unwrap_err();
        assert_eq!(err.error_type, ErrorKind::OutOfSequence);

        let err = verify_mic(&suite, &AES256_KEY, Sender::Acceptor, 39_321_546, b"mech lisT", &token).unwrap_err();
        assert_eq!(err.error_type, ErrorKind::MessageAltered);

        let initiator_token = mic(&suite, &AES256_KEY, Sender::Initiator, 39_321_546, b"mech list").unwrap();
        let err = verify_mic(
            &suite,
            &AES256_KEY,
            Sender::Acceptor,
            39_321_546,
            b"mech list",
            &initiator_token,
        )
        .unwrap_err();
        assert_eq!(err.error_type, ErrorKind::MessageAltered);
    }

    #[test]
    fn constant_time_eq_compares_lengths_and_content() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
