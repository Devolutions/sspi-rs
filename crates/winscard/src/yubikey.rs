//! YubiKey-specific behaviour of the emulated smart card.
//!
//! The Windows inbox PIV minidriver (`msclmd.dll`) supports only RSA keys, so smart cards with EC keys
//! have to be served by the YubiKey Smart Card Minidriver (`ykmd.dll`). This minidriver is selected by
//! the exact ATR value and expects several YubiKey extensions of the PIV card edge on top of the
//! standard PIV commands. All values in this module are taken from the APDU traffic of a real YubiKey.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use des::TdesEde3;
use des::cipher::{Array, BlockCipherEncrypt, KeyInit};
use secret::Secret;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::scard_context::encode_container_name;
use crate::{WinScardResult, tlv_tags};

/// Returns the firmware version of the YubiKey.
pub(crate) const INS_GET_VERSION: u8 = 0xFD;
/// Returns the serial number of the YubiKey.
pub(crate) const INS_GET_SERIAL: u8 = 0xF8;
/// Returns the metadata of the key stored in the specified slot.
pub(crate) const INS_GET_METADATA: u8 = 0xF7;

/// The YubiKey admin data object.
pub(crate) const ADMIN_DATA_TAG: [u8; 3] = [0x5F, 0xFF, 0x00];
/// The object that keeps the Windows container map.
pub(crate) const CONTAINER_MAP_TAG: [u8; 3] = [0x5F, 0xFF, 0x10];
/// The Printed Information object. The YubiKey tooling uses it to keep the protected management key.
pub(crate) const PRINTED_INFORMATION_TAG: [u8; 3] = [0x5F, 0xC1, 0x09];

/// The slot of the card management key.
pub(crate) const MANAGEMENT_KEY_SLOT: u8 = 0x9B;
/// The 3DES algorithm identifier of the card management key.
pub(crate) const MANAGEMENT_KEY_ALGORITHM: u8 = 0x03;
/// The block size of the 3DES cipher: it is the size of the management key authentication challenges.
pub(crate) const MANAGEMENT_CHALLENGE_SIZE: usize = 8;

/// The minimal part of the PIV AID the YubiKey accepts in the SELECT command: the RID.
pub(crate) const PIV_AID_MIN_SIZE: usize = 5;

/// The firmware version we report. The firmware version 5 or higher makes the minidriver use the
/// [INS_GET_SERIAL] command instead of selecting the OTP application.
const FIRMWARE_VERSION: [u8; 3] = [5, 4, 3];

const MANAGEMENT_KEY_SIZE: usize = 24;
/// The Printed Information object: the data object, protected data and management key tags with their lengths, and the key.
const PRINTED_INFORMATION_SIZE: usize = 6 + MANAGEMENT_KEY_SIZE;
const CERT_FINGERPRINT_SIZE: usize = 20;

// Fields of the container map record.
const PIV_AUTHENTICATION_SLOT: u8 = 0x9A;
/// The key specification the minidriver derives from the certificate of a P-256 key.
const KEY_SPEC_P256: u8 = 6;
const KEY_SIZE_BITS_P256: u16 = 256;
/// The record is valid and is the default container.
const CONTAINER_FLAGS: u8 = 3;
const USER_PIN_ID: u8 = 1;
const NO_ASSOCIATED_ECDH_CONTAINER: u8 = 0xFF;

/// `1` is the algorithm tag, `2` is the PIN and touch policy tag, and `5` is the tag that says if the key is the default one.
/// The metadata describes the non-default 3DES key with no touch requirement.
const MANAGEMENT_KEY_METADATA: [u8; 10] = [0x01, 0x01, 0x03, 0x02, 0x02, 0x00, 0x01, 0x05, 0x01, 0x00];

/// The admin data flag says that the management key is kept in the protected object.
const ADMIN_DATA: [u8; 7] = [tlv_tags::DATA, 0x05, 0x80, 0x03, 0x81, 0x01, 0x03];

/// State of the YubiKey extensions of the emulated smart card.
#[derive(Debug, Clone)]
pub(crate) struct YubiKey {
    serial: [u8; 4],
    /// The encoded container name: see [encode_container_name].
    container_name: Vec<u8>,
    cert_fingerprint: [u8; CERT_FINGERPRINT_SIZE],
    /// The minidriver authenticates itself using this key.
    ///
    /// It only gates card modifications, which the emulated smart card does not support.
    /// It is derived from the card ID, which anyone can read from the CHUID object without the PIN.
    /// So, unlike the card private key, it does not protect anything.
    management_key: Secret<[u8; MANAGEMENT_KEY_SIZE]>,
    challenge_counter: u64,
    /// The plain value of the challenge the card is waiting the response for.
    pending_challenge: Option<Secret<[u8; MANAGEMENT_CHALLENGE_SIZE]>>,
}

impl YubiKey {
    pub(crate) fn new(card_id: Uuid, certificate: &[u8]) -> WinScardResult<Self> {
        let mut serial = [0; 4];
        serial.copy_from_slice(&card_id.as_bytes()[..4]);
        // The serial number is a positive integer.
        serial[0] &= 0x7F;

        let mut cert_fingerprint = [0; CERT_FINGERPRINT_SIZE];
        cert_fingerprint.copy_from_slice(&Sha256::digest(certificate)[..CERT_FINGERPRINT_SIZE]);

        let mut management_key = [0; MANAGEMENT_KEY_SIZE];
        management_key.copy_from_slice(&Sha256::digest(card_id.as_bytes())[..MANAGEMENT_KEY_SIZE]);

        Ok(Self {
            serial,
            container_name: encode_container_name(&card_id.to_string())?,
            cert_fingerprint,
            management_key: Secret::new(management_key),
            challenge_counter: 0,
            pending_challenge: None,
        })
    }

    pub(crate) fn set_container_name(&mut self, container_name: &str) -> WinScardResult<()> {
        self.container_name = encode_container_name(container_name)?;

        Ok(())
    }

    pub(crate) fn version(&self) -> &[u8] {
        &FIRMWARE_VERSION
    }

    pub(crate) fn serial(&self) -> &[u8] {
        &self.serial
    }

    /// Returns the metadata of the key in the specified slot.
    ///
    /// The minidriver asks only for the management key metadata, and for the metadata of the
    /// `0x96` slot that exists only on the YubiKey Bio devices.
    pub(crate) fn metadata(&self, slot: u8) -> Option<&[u8]> {
        (slot == MANAGEMENT_KEY_SLOT).then_some(MANAGEMENT_KEY_METADATA.as_slice())
    }

    pub(crate) fn admin_data(&self) -> &[u8] {
        &ADMIN_DATA
    }

    /// Returns the Printed Information object that contains the protected management key.
    pub(crate) fn printed_information(&self) -> Secret<[u8; PRINTED_INFORMATION_SIZE]> {
        const MANAGEMENT_KEY_TAG: u8 = 0x89;
        const PROTECTED_DATA_TAG: u8 = 0x88;

        let key_size = u8::try_from(MANAGEMENT_KEY_SIZE).expect("management key size fits u8");

        let mut object = [0; PRINTED_INFORMATION_SIZE];
        object[..6].copy_from_slice(&[
            tlv_tags::DATA,
            key_size + 4,
            PROTECTED_DATA_TAG,
            key_size + 2,
            MANAGEMENT_KEY_TAG,
            key_size,
        ]);
        object[6..].copy_from_slice(self.management_key.as_ref());

        Secret::new(object)
    }

    /// Returns the object with the container map: the only record describes the PIV Authentication key.
    ///
    /// The minidriver compares this record with the certificate it reads from the card. If the key specification,
    /// key size, or fingerprint do not match, then it skips the container and the card looks empty.
    pub(crate) fn container_map(&self) -> Vec<u8> {
        const CONTAINER_MAP_RECORD_TAG: u8 = 0x81;

        let mut record = self.container_name.clone();

        record.push(PIV_AUTHENTICATION_SLOT);
        record.push(KEY_SPEC_P256);
        record.extend_from_slice(&KEY_SIZE_BITS_P256.to_le_bytes());
        record.push(CONTAINER_FLAGS);
        record.push(USER_PIN_ID);
        record.push(NO_ASSOCIATED_ECDH_CONTAINER);
        record.extend_from_slice(&self.cert_fingerprint);

        let record_size = u8::try_from(record.len()).expect("container map record size fits u8");

        let mut object = vec![tlv_tags::DATA, record_size + 2, CONTAINER_MAP_RECORD_TAG, record_size];
        object.extend_from_slice(&record);

        object
    }

    /// Starts the management key authentication and returns the encrypted challenge.
    ///
    /// The challenge does not have to be unpredictable: see [YubiKey::management_key].
    pub(crate) fn start_management_authentication(&mut self) -> [u8; MANAGEMENT_CHALLENGE_SIZE] {
        self.challenge_counter = self.challenge_counter.wrapping_add(1);

        let mut challenge = [0; MANAGEMENT_CHALLENGE_SIZE];
        let digest = Sha256::new()
            .chain_update(self.management_key.as_ref())
            .chain_update(self.challenge_counter.to_le_bytes())
            .finalize();
        challenge.copy_from_slice(&digest[..MANAGEMENT_CHALLENGE_SIZE]);

        self.pending_challenge = Some(Secret::new(challenge));

        self.encrypt_block(challenge)
    }

    /// Finishes the management key authentication.
    ///
    /// `decrypted_challenge` is the challenge decrypted by the caller, and `caller_challenge` is the challenge
    /// the caller authenticates the card with. Returns the encrypted `caller_challenge` on success.
    pub(crate) fn finish_management_authentication(
        &mut self,
        decrypted_challenge: &[u8],
        caller_challenge: &[u8],
    ) -> Option<[u8; MANAGEMENT_CHALLENGE_SIZE]> {
        let expected_challenge = self.pending_challenge.take()?;
        if decrypted_challenge != expected_challenge.as_ref() {
            return None;
        }

        let caller_challenge = caller_challenge.try_into().ok()?;

        Some(self.encrypt_block(caller_challenge))
    }

    fn encrypt_block(&self, block: [u8; MANAGEMENT_CHALLENGE_SIZE]) -> [u8; MANAGEMENT_CHALLENGE_SIZE] {
        let cipher = TdesEde3::new(&Array::from(*self.management_key.as_ref()));

        let mut block = Array::from(block);
        cipher.encrypt_block(&mut block);

        block.into()
    }
}
