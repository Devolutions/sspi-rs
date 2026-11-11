use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};

use crypto_bigint::BoxedUint;
use iso7816::{Aid, Command, Instruction};
use iso7816_tlv::ber::{Tag, Tlv, Value};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::pkcs8::DecodePrivateKey as _;
use picky::key::{KeyKind, PrivateKey};
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use secret::{Secret, SecretPrivateKey};
use sha1::Sha1;
use uuid::Uuid;

use crate::card_capability_container::build_ccc;
use crate::chuid::{CHUID_LENGTH, build_chuid};
use crate::piv_cert::{build_auth_cert, build_yubikey_auth_cert};
use crate::scard_context::{
    DEFAULT_CARD_NAME, MICROSOFT_DEFAULT_CSP, MICROSOFT_DEFAULT_KSP, MICROSOFT_SCARD_DRIVER_LOCATION,
    YUBIKEY_CARD_NAME, YUBIKEY_SCARD_DRIVER_LOCATION,
};
use crate::winscard::{AttributeId, ControlCode, Protocol, ReaderAction, ShareMode, TransmitOutData, WinScard};
use crate::yubikey::{self, YubiKey};
use crate::{Error, ErrorKind, Response, Status, WinScardResult, tlv_tags, winscard};

/// [NIST.SP.800-73-4, part 1, section 2.2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=16).
pub const PIV_AID: Aid = Aid::new_truncatable(&[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00], 9);
/// The max amount of data one APDU response can transmit.
pub const CHUNK_SIZE: usize = 256;
/// NIST.SP.800-73-4, part 1, section 4.3, Table 3
pub const CARD_AUTH_CERT_TAG: [u8; 3] = [0x5F, 0xC1, 0x01];
// NIST.SP.800-73-4, part 1, section 4.3, Table 3
const CHUID_TAG: &[u8] = &[0x5F, 0xC1, 0x02];
/// NIST.SP.800-73-4, part 1, section 4.3, Table 3
pub const PIV_CERT_TAG: [u8; 3] = [0x5F, 0xC1, 0x05];
// NIST.SP.800-73-4, part 1, section 4.3, Table 3
const CARD_CAPABILITY_CONTAINER_TAG: &[u8] = &[0x5F, 0xC1, 0x07];
/// NIST.SP.800-73-4, part 1, section 4.3, Table 3
pub const DIGITAL_SIGNATURE_CERT_TAG: [u8; 3] = [0x5F, 0xC1, 0x0A];
/// NIST.SP.800-73-4, part 1, section 4.3, Table 3
pub const KEY_MANAGEMENT_CERT_TAG: [u8; 3] = [0x5F, 0xC1, 0x0B];
// NIST.SP.800-73-4 part 2, section 2.4.3
const PIN_LENGTH_RANGE_LOW_BOUND: usize = 6;
// NIST.SP.800-73-4 part 2, section 2.4.3
const PIN_LENGTH_RANGE_HIGH_BOUND: usize = 8;
/// Supported connection protocol in emulated smart cards.
///
/// We are always using the T1 protocol as the original Windows TPM smart card does
pub const SUPPORTED_CONNECTION_PROTOCOL: Protocol = Protocol::T1;
// Only one supported control code.
// `#define CM_IOCTL_GET_FEATURE_REQUEST SCARD_CTL_CODE(3400)`
// Request features described in the *PC/SC 2.0 Specification Part 10*
const IO_CTL: u32 = 0x00313520;

/// The original winscard ATR is not suitable because it contains AID bytes.
/// So we need to construct our own. Read more about our constructed ATR string:
/// <https://smartcard-atr.apdu.fr/parse?ATR=3B+8D+01+80+FB+A0+00+00+03+08+00+00+10+00+01+00+4D>
#[rustfmt::skip]
pub const ATR: [u8; 17] = [
    // TS. Direct Convention
    0x3b,
    // T0. Y(1): b1000, K: 13 (historical bytes)
    0x8d,
    // TD. Y(i+1) = b0000, Protocol T=1
    0x01,
    // Historical bytes
    0x80,
    // Tag: 15, Len: 11.
    0xfb,
    // PIV AID
    0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
    // TCK (Checksum)
    0x4d,
];

/// ATR of the YubiKey 5.
///
/// The Windows inbox PIV minidriver supports only RSA keys, so emulated smart cards with EC keys report this ATR
/// to be served by the YubiKey Smart Card Minidriver. The minidriver is registered for this exact value.
#[rustfmt::skip]
pub const YUBIKEY_ATR: [u8; 23] = [
    0x3b, 0xfd, 0x13, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x15, 0x80, 0x73, 0xc0,
    0x21, 0xc0, 0x57, 0x59, 0x75, 0x62, 0x69, 0x4b, 0x65, 0x79, 0x40,
];

/// How the emulated smart card presents itself to the Windows smart card stack.
///
/// All values depend on the card private key and must stay consistent: Windows selects the
/// smart card minidriver by the ATR, and the card name and provider must fit this minidriver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CardIdentity {
    /// Answer to reset.
    pub atr: &'static [u8],
    /// Smart card name.
    pub name: &'static str,
    /// Name of the provider that serves the smart card key.
    pub provider_name: &'static str,
    /// Null-terminated file name of the smart card minidriver.
    pub card_module: &'static str,
}

/// Returns the identity of the emulated smart card with the provided private key.
///
/// Fails if the emulated smart card does not support such a key.
pub fn card_identity(private_key: &PrivateKey) -> WinScardResult<CardIdentity> {
    Ok(match parse_ec_key(private_key)? {
        Some(_) => EC_CARD_IDENTITY,
        None => RSA_CARD_IDENTITY,
    })
}

const RSA_CARD_IDENTITY: CardIdentity = CardIdentity {
    atr: &ATR,
    name: DEFAULT_CARD_NAME,
    provider_name: MICROSOFT_DEFAULT_CSP,
    card_module: MICROSOFT_SCARD_DRIVER_LOCATION,
};

/// The legacy CSP and the inbox PIV minidriver cannot work with EC keys.
const EC_CARD_IDENTITY: CardIdentity = CardIdentity {
    atr: &YUBIKEY_ATR,
    name: YUBIKEY_CARD_NAME,
    provider_name: MICROSOFT_DEFAULT_KSP,
    card_module: YUBIKEY_SCARD_DRIVER_LOCATION,
};

/// Checks that the emulated smart card supports the provided key and returns the parsed EC key if it is an EC one.
fn parse_ec_key(private_key: &PrivateKey) -> WinScardResult<Option<p256::SecretKey>> {
    match private_key.kind() {
        KeyKind::Rsa => Ok(None),
        KeyKind::Ec => {
            let pkcs8 = Secret::new(private_key.to_pkcs8()?);

            // The PKCS#8 decoder checks that the key is on the P-256 curve.
            let secret_key = p256::SecretKey::from_pkcs8_der(pkcs8.as_ref()).map_err(|_| {
                Error::new(
                    ErrorKind::UnsupportedFeature,
                    "only the P-256 curve is supported for EC smart card keys",
                )
            })?;

            Ok(Some(secret_key))
        }
        _ => Err(Error::new(
            ErrorKind::UnsupportedFeature,
            "only RSA and EC smart card keys are supported",
        )),
    }
}

/// Private key of the emulated smart card.
///
/// The key type determines the PIV cryptographic algorithm identifier the smart card accepts in the GENERAL AUTHENTICATE command.
///
/// [NIST.SP.800-73-4, part 1, Table 5. Cryptographic Mechanism Identifiers](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=34)
#[derive(Debug, Clone)]
enum CardKey {
    /// RSA key. The `0x07` (RSA 2048) algorithm.
    Rsa,
    /// ECC P-256 key. The `0x11` (ECC: Curve P-256) algorithm.
    ///
    /// Smart cards with such a key emulate the YubiKey: see [YUBIKEY_ATR].
    EcP256 {
        secret_key: p256::SecretKey,
        yubikey: YubiKey,
    },
}

impl CardKey {
    // NIST.SP.800-73-4, part 1, Table 5
    const RSA_ALGORITHM: u8 = 0x07;
    // NIST.SP.800-73-4, part 1, Table 5
    const ECC_P256_ALGORITHM: u8 = 0x11;

    fn new(private_key: &PrivateKey, card_id: Uuid, auth_cert_der: &[u8]) -> WinScardResult<Self> {
        Ok(match parse_ec_key(private_key)? {
            Some(secret_key) => Self::EcP256 {
                secret_key,
                yubikey: YubiKey::new(card_id, auth_cert_der)?,
            },
            None => Self::Rsa,
        })
    }

    fn identity(&self) -> CardIdentity {
        match self {
            Self::Rsa => RSA_CARD_IDENTITY,
            Self::EcP256 { .. } => EC_CARD_IDENTITY,
        }
    }

    fn algorithm(&self) -> u8 {
        match self {
            Self::Rsa => Self::RSA_ALGORITHM,
            Self::EcP256 { .. } => Self::ECC_P256_ALGORITHM,
        }
    }

    fn yubikey(&self) -> Option<&YubiKey> {
        match self {
            Self::Rsa => None,
            Self::EcP256 { yubikey, .. } => Some(yubikey),
        }
    }

    fn yubikey_mut(&mut self) -> Option<&mut YubiKey> {
        match self {
            Self::Rsa => None,
            Self::EcP256 { yubikey, .. } => Some(yubikey),
        }
    }
}

/// Emulated smart card.
///
/// Currently, we support one key container per smart card.
#[derive(Debug, Clone)]
pub struct SmartCard<'a> {
    reader_name: Cow<'a, str>,
    chuid: [u8; CHUID_LENGTH],
    ccc: Vec<u8>,
    pin: Secret<Vec<u8>>,
    auth_cert: Vec<u8>,
    auth_pk: SecretPrivateKey,
    key: CardKey,
    state: SCardState,
    // We don't need to track actual transactions for the emulated smart card.
    // We are using this flag to track incorrect smart card usage.
    transaction: bool,
    pending_command: Option<Command<1024>>,
    pending_response: Option<Secret<Vec<u8>>>,
    // We keep it just for compatibility reasons with WinSCard API.
    // Usually, the mstsc.exe doesn't use scard attributes for connection establishing.
    attributes: BTreeMap<AttributeId, Cow<'a, [u8]>>,
}

impl SmartCard<'_> {
    /// Creates a smart card instance based on the provided data.
    pub fn new(
        reader_name: Cow<'_, str>,
        card_id: Uuid,
        pin: Vec<u8>,
        auth_cert_der: Vec<u8>,
        auth_pk: PrivateKey,
    ) -> WinScardResult<SmartCard<'_>> {
        let chuid = build_chuid(card_id)?;
        let key = CardKey::new(&auth_pk, card_id, &auth_cert_der)?;
        let auth_cert = match key {
            CardKey::Rsa => build_auth_cert(auth_cert_der)?,
            CardKey::EcP256 { .. } => build_yubikey_auth_cert(auth_cert_der),
        };

        Ok(SmartCard {
            reader_name,
            chuid,
            ccc: build_ccc(),
            pin: SmartCard::validate_and_pad_pin(pin)?.into(),
            auth_cert,
            auth_pk: auth_pk.into(),
            key,
            state: SCardState::Ready,
            transaction: false,
            pending_command: None,
            pending_response: None,
            attributes: BTreeMap::new(),
        })
    }

    /// Sets the name of the key container this smart card reports to the smart card minidriver.
    ///
    /// Fails if the name does not fit the container map record.
    pub fn with_container_name(mut self, container_name: &str) -> WinScardResult<Self> {
        if let Some(yubikey) = self.key.yubikey_mut() {
            yubikey.set_container_name(container_name)?;
        }

        Ok(self)
    }

    fn validate_and_pad_pin(pin: Vec<u8>) -> WinScardResult<Vec<u8>> {
        // All PIN requirements can be found here: NIST.SP.800-73-4 part 2, section 2.4.3
        if !(PIN_LENGTH_RANGE_LOW_BOUND..=PIN_LENGTH_RANGE_HIGH_BOUND).contains(&pin.len()) {
            return Err(Error::new(
                ErrorKind::InvalidValue,
                "PIN should be no shorter than 6 bytes and no longer than 8",
            ));
        }
        if pin.iter().any(|byte| !byte.is_ascii_digit()) {
            return Err(Error::new(
                ErrorKind::InvalidValue,
                "PIN should consist only of ASCII values representing decimal digits (0-9)",
            ));
        };

        Ok(Self::pad_pin(pin))
    }

    fn pad_pin(mut pin: Vec<u8>) -> Vec<u8> {
        if pin.len() < PIN_LENGTH_RANGE_HIGH_BOUND {
            // NIST.SP.800-73-4 part 2, section 2.4.3
            const PIN_PAD_VALUE: u8 = 0xFF;
            pin.resize(PIN_LENGTH_RANGE_HIGH_BOUND, PIN_PAD_VALUE);
        }

        pin
    }

    /// This functions handles one APDU command.
    #[instrument(level = "debug", fields(state = ?self.state, data_len = data.len()), skip_all, err)]
    pub fn handle_command(&mut self, data: &[u8]) -> WinScardResult<Response> {
        // The command data of a VERIFY command is the PIN, so the raw bytes are traced only.
        trace!(?data, "APDU command");

        let cmd = Command::<1024>::try_from(data).map_err(|error| {
            error!(?error, "APDU command parsing error");
            Error::new(
                ErrorKind::InternalError,
                format!("error: an error happened while parsing an APDU command: {error:?}"),
            )
        })?;
        let cmd = if let Some(mut chained) = self.pending_command.take() {
            chained.extend_from_command(&cmd).map_err(|_| {
                Error::new(
                    ErrorKind::InternalError,
                    "error: an error happened while trying to build a chained APDU command",
                )
            })?;
            chained
        } else {
            cmd
        };

        if cmd.class().chain().not_the_last() {
            self.pending_command = Some(cmd);
            return Ok(Status::OK.into());
        }
        if self.state == SCardState::Ready && cmd.instruction() != Instruction::Select {
            // if the application wasn't selected, only the SELECT command can be used
            return Ok(if self.key.yubikey().is_some() {
                // The YubiKey has no PIV-specific instructions until the PIV application is selected.
                Status::InstructionNotSupported.into()
            } else {
                Status::NotFound.into()
            });
        } else if self.state == SCardState::PivAppSelected
            && cmd.instruction() == Instruction::GeneralAuthenticate
            && !(self.key.yubikey().is_some() && is_management_authentication(&cmd))
        {
            // GENERAL AUTHENTICATE can only be used if the smart card has already been unlocked using the PIN code
            return Ok(Status::SecurityStatusNotSatisfied.into());
        }
        let instruction = cmd.instruction();
        let response = match instruction {
            Instruction::Select => self.select(cmd),
            Instruction::GetData => self.get_data(cmd),
            Instruction::Verify => self.verify(cmd),
            Instruction::GeneralAuthenticate => match self.key.yubikey_mut() {
                Some(yubikey) if is_management_authentication(&cmd) => Self::management_authenticate(yubikey, cmd),
                _ => self.general_authenticate(cmd),
            },
            Instruction::GetResponse => self.get_response(),
            instruction => {
                if let (Instruction::Unknown(instruction), Some(yubikey)) = (instruction, self.key.yubikey()) {
                    return Ok(Self::yubikey_command(yubikey, instruction, cmd));
                }

                error!(?instruction, "unimplemented instruction");
                Ok(Status::InstructionNotSupported.into())
            }
        }?;

        // The response data can be a signature or other card data, so only its length is logged.
        debug!(?instruction, status = ?response.status, data_len = response.data.as_ref().map(Vec::len), "APDU command handled");
        trace!(data = ?response.data, "APDU response data");

        Ok(response)
    }

    #[instrument(level = "debug", fields(state = ?self.state), skip_all, err)]
    fn select(&mut self, cmd: Command<1024>) -> WinScardResult<Response> {
        // NIST.SP.800-73-4, Part 2, Section 3.1.1
        // PIV SELECT command
        //      CLA - 0x00
        //      INS - 0xA4
        //      P1  - 0x04
        //      P2  - 0x00

        // ISO/IEC 7816-4, Section 7.1.1, Table 39
        const APPLICATION_IDENTIFIER: u8 = 0x04;
        // ISO/IEC 7816-4, Section 7.1.1, Table 40
        const FIRST_OR_ONLY_OCCURRENCE: u8 = 0x00;

        // The YubiKey accepts the shortened AID, and the YubiKey Smart Card Minidriver uses it.
        let is_short_aid = self.key.yubikey().is_some()
            && cmd.data().len() >= yubikey::PIV_AID_MIN_SIZE
            && PIV_AID.starts_with(cmd.data());

        if cmd.p1 != APPLICATION_IDENTIFIER
            || cmd.p2 != FIRST_OR_ONLY_OCCURRENCE
            || !(PIV_AID.matches(cmd.data()) || is_short_aid)
        {
            return Ok(Status::NotFound.into());
        }
        let data = Tlv::new(
            Tag::try_from(tlv_tags::APPLICATION_PROPERTY_TEMPLATE)?,
            Value::Constructed(vec![
                Tlv::new(
                    Tag::try_from(tlv_tags::APPLICATION_IDENTIFIER)?,
                    // application portion + version portion of the PIV AID
                    // NIST.SP.800-73-4 Part 1, section 2.2
                    Value::Primitive(vec![0x00, 0x00, 0x10, 0x00, 0x01, 0x00]),
                )?,
                Tlv::new(
                    Tag::try_from(tlv_tags::COEXISTING_TAG_ALLOCATION_AUTHORITY)?,
                    Value::Constructed(vec![Tlv::new(
                        Tag::try_from(tlv_tags::APPLICATION_IDENTIFIER)?,
                        Value::Primitive(PIV_AID.to_vec()),
                    )?]),
                )?,
            ]),
        )?;
        self.state = SCardState::PivAppSelected;
        Ok(Response::new(Status::OK, Some(data.to_vec())))
    }

    #[instrument(level = "debug", fields(state = ?self.state), skip_all, err)]
    fn verify(&mut self, cmd: Command<1024>) -> WinScardResult<Response> {
        // NIST.SP.800-73-4, Part 2, Section 3.2.1
        // PIV VERIFY command
        //      CLA  - 0x00
        //      INS  - 0x20
        //      P1   - 0x00 | 0xFF
        //      P2   - 0x80
        //      Data - PIN
        //
        // If P1 is 0xFF, the Data field should be empty

        // ISO/IEC 7816-4, Section 7.5.1
        const NO_IDENTIFIER: u8 = 0x00;
        // NIST.SP.800-73-4, Part 2, Section 3.2.1
        const RESET_SECURITY_STATUS: u8 = 0xFF;
        // ISO/IEC 7816-4, Section 7.5.1, Table 65
        const SPECIFIC_REFERENCE_DATA: u8 = 0x80;

        if cmd.p1 == RESET_SECURITY_STATUS && !cmd.data().is_empty() {
            return Ok(Status::IncorrectP1orP2.into());
        }
        if cmd.p2 != SPECIFIC_REFERENCE_DATA {
            return Ok(Status::KeyReferenceNotFound.into());
        }
        match cmd.p1 {
            NO_IDENTIFIER => {
                // PIN was already verified -> return OK
                if self.state != SCardState::PinVerified {
                    if !cmd.data().is_empty()
                        && !(PIN_LENGTH_RANGE_LOW_BOUND..=PIN_LENGTH_RANGE_HIGH_BOUND).contains(&cmd.data().len())
                    {
                        // Incorrect PIN length -> do not proceed and return an error
                        return Ok(Status::IncorrectDataField.into());
                    }
                    // Retrieve the number of further allowed retries if the data field is absent
                    // Otherwise just compare the provided PIN with the stored one
                    if cmd.data().is_empty() || cmd.data() != self.pin.as_ref().as_slice() {
                        return Ok(Status::VerificationFailedWithRetries.into());
                    } else {
                        // data field is present and the provided PIN is correct -> change state and return OK
                        self.state = SCardState::PinVerified;
                    }
                }
            }
            RESET_SECURITY_STATUS => {
                // p1 is 0xFF and the data field is absent -> reset the security status and return OK
                self.state = SCardState::PivAppSelected;
            }
            _ => return Ok(Status::IncorrectP1orP2.into()),
        };
        Ok(Status::OK.into())
    }

    #[instrument(level = "debug", fields(state = ?self.state), skip_all, err)]
    fn get_data(&mut self, cmd: Command<1024>) -> WinScardResult<Response> {
        // NIST.SP.800-73-4, Part 2, Section 3.1.2
        // PIV GET DATA command
        //      CLA  - 0x00
        //      INS  - 0xCB
        //      P1   - 0x3F
        //      P2   - 0xFF
        //      Data - a single BER-TLV tag of the data object to be retrieved
        //
        // Our PIV smart card only supports:
        //      5FC102 - Card Holder Unique Identifier
        //      5FC105 - X.509 Certificate for PIV Authentication

        // ISO/IEC 7816-4, Section 7.4.1
        const FIRST_BYTE_OF_CURRENT_DF: u8 = 0x3F;
        const SECOND_BYTE_OF_CURRENT_DF: u8 = 0xFF;

        if cmd.p1 != FIRST_BYTE_OF_CURRENT_DF || cmd.p2 != SECOND_BYTE_OF_CURRENT_DF {
            return Ok(Status::IncorrectP1orP2.into());
        }
        let request = Tlv::from_bytes(cmd.data())?;
        if request.tag() != &Tag::try_from(tlv_tags::TAG_LIST)? {
            return Ok(Status::NotFound.into());
        }

        if let (Some(yubikey), Value::Primitive(tag)) = (self.key.yubikey(), request.value()) {
            match <[u8; 3]>::try_from(tag.as_slice()) {
                Ok(yubikey::ADMIN_DATA_TAG) => {
                    return Ok(Response::new(Status::OK, Some(yubikey.admin_data().to_vec())));
                }
                Ok(yubikey::CONTAINER_MAP_TAG) => return Ok(Response::new(Status::OK, Some(yubikey.container_map()))),
                Ok(yubikey::PRINTED_INFORMATION_TAG) => {
                    return Ok(if self.state == SCardState::PinVerified {
                        Response::new(Status::OK, Some(yubikey.printed_information().as_ref().to_vec()))
                    } else {
                        Status::SecurityStatusNotSatisfied.into()
                    });
                }
                // The minidriver lists the card keys by reading the certificate slots. The key is
                // kept only in the PIV Authentication slot: a duplicate of the key in another slot
                // would become one more key container.
                Ok(CARD_AUTH_CERT_TAG | KEY_MANAGEMENT_CERT_TAG | DIGITAL_SIGNATURE_CERT_TAG) => {
                    return Ok(Status::NotFound.into());
                }
                _ => {}
            }
        }

        match request.value() {
            Value::Primitive(tag) => match tag.as_slice() {
                CHUID_TAG => Ok(Response::new(Status::OK, Some(self.chuid.to_vec()))),
                [a, b, c]
                    if matches!(
                        [*a, *b, *c],
                        PIV_CERT_TAG | CARD_AUTH_CERT_TAG | KEY_MANAGEMENT_CERT_TAG | DIGITAL_SIGNATURE_CERT_TAG
                    ) =>
                {
                    // certificate is almost certainly longer than 256 bytes, so we can just set a pending response and call the GET RESPONSE handler
                    self.pending_response = Some(self.auth_cert.clone().into());
                    self.get_response()
                }
                CARD_CAPABILITY_CONTAINER_TAG => Ok(Response::new(Status::OK, Some(self.ccc.clone()))),
                _ => Ok(Status::NotFound.into()),
            },
            Value::Constructed(_) => Ok(Status::NotFound.into()),
        }
    }

    #[instrument(level = "debug", fields(state = ?self.state), skip_all, err)]
    fn get_response(&mut self) -> WinScardResult<Response> {
        // ISO/IEC 7816-4, Section 7.6.1
        // The smart card uses the standard (short) APDU response form, so the maximum amount of data transferred in one response is 256 bytes
        match self.get_next_response_chunk() {
            Some((chunk, bytes_left)) => {
                let status = if bytes_left == 0 {
                    self.pending_response = None;
                    Status::OK
                } else if bytes_left < CHUNK_SIZE {
                    // conversion is safe as we know that bytes_left isn't bigger than 256
                    Status::MoreAvailable(bytes_left.try_into().unwrap())
                } else {
                    // 0 indicates that we have 256 or more bytes left to be read
                    Status::MoreAvailable(0)
                };
                Ok(Response::new(status, Some(chunk)))
            }
            None => Ok(Status::NotFound.into()),
        }
    }

    #[instrument(level = "debug", fields(state = ?self.state), skip_all, err)]
    fn general_authenticate(&mut self, cmd: Command<1024>) -> WinScardResult<Response> {
        // NIST.SP.800-73-4, Part 2, Section 3.2.4
        // PIV GENERAL AUTHENTICATE command
        //      CLA  - 0x00 | 0x10 (command chaining)
        //      INS  - 0x87
        //      P1   - 0x07 - RSA 2048 | 0x11 - ECC P-256
        //      P2   - 0x9A - PIV Authentication Key, 0x9C - PIV Digital Signature Key or 0x9D - Key Management Key
        //      Data - Dynamic Authentication Template with Challenge (or Exponentiation) inside
        //
        // There are many possible P1 and P2 values in this command, but our smart card supports only the algorithm of its key
        // (RSA 2048 or ECC P-256) and data signing using the PIV Authentication Key or PIV Digital Signature Key.
        // The EC key can also be used in the ECDH key agreement. The Key Management Key reference is accepted for that purpose.

        // NIST.SP.800-73-4, Part 1, Table 4b
        const PIV_AUTHENTICATION_KEY: u8 = 0x9A;
        const PIV_DIGITAL_SIGNATURE_KEY: u8 = 0x9C;
        const PIV_KEY_MANAGEMENT_KEY: u8 = 0x9D;

        // We accept the PIV Authentication Key and the Digital Signature Key references. The EC key accepts the Key Management Key too.
        let key_reference_is_supported = match self.key {
            CardKey::Rsa => matches!(cmd.p2, PIV_DIGITAL_SIGNATURE_KEY | PIV_AUTHENTICATION_KEY),
            CardKey::EcP256 { .. } => matches!(
                cmd.p2,
                PIV_DIGITAL_SIGNATURE_KEY | PIV_AUTHENTICATION_KEY | PIV_KEY_MANAGEMENT_KEY
            ),
        };
        if cmd.p1 != self.key.algorithm() || !key_reference_is_supported {
            return Err(Error::new(
                ErrorKind::UnsupportedFeature,
                format!(
                    "provided algorithm or key reference isn't supported: got algorithm {:x}, expected {:x}; got key reference {:x}, expected 0x9a, 0x9c or 0x9d (0x9d is supported only by EC keys)",
                    cmd.p1,
                    self.key.algorithm(),
                    cmd.p2
                ),
            ));
        }
        let request = Tlv::from_bytes(cmd.data())?;
        if request.tag() != &Tag::try_from(tlv_tags::DYNAMIC_AUTHENTICATION_TEMPLATE)?
            || !request.value().is_constructed()
        {
            // wrong TLV request structure
            return Err(Error::new(
                ErrorKind::InvalidValue,
                "TLV structure is invalid: wrong top-level tag structure".to_string(),
            ));
        }
        let inner_tlv = match request.value() {
            // we already know that the value is constructed at this point
            Value::Primitive(_) => unreachable!(),
            Value::Constructed(tlv_vec) => tlv_vec,
        };
        // to avoid constructing the tag on each iteration
        let challenge_tag = Tag::try_from(tlv_tags::DAT_CHALLENGE)?;
        let challenge = inner_tlv.iter().find(|&tlv| tlv.tag() == &challenge_tag);
        // The ECDH key agreement request carries the other party public key instead of the challenge.
        let exponentiation_tag = Tag::try_from(tlv_tags::DAT_EXPONENTIATION)?;
        let exponentiation = inner_tlv.iter().find(|&tlv| tlv.tag() == &exponentiation_tag);

        let (challenge, key_agreement) = match (challenge, exponentiation, &self.key) {
            (Some(challenge), _, _) => (challenge, false),
            (None, Some(exponentiation), CardKey::EcP256 { .. }) => (exponentiation, true),
            (None, _, _) => {
                return Err(Error::new(
                    ErrorKind::InvalidValue,
                    "TLV structure is invalid: no challenge field is present in the request".to_string(),
                ));
            }
        };
        // Signature creation is described in NIST.SP.800-73-4, Part 2, Appendix A, Sections A.1-3 and Section A.4.1
        let challenge = match challenge.value() {
            Value::Primitive(challenge) => challenge,
            Value::Constructed(_) => {
                // this tag must contain a primitive value
                return Err(Error::new(
                    ErrorKind::InvalidValue,
                    "TLV structure is invalid: challenge field contains constructed value".to_string(),
                ));
            }
        };

        let signed_challenge = match &self.key {
            CardKey::Rsa => Secret::new(self.sign_padded(challenge)?),
            CardKey::EcP256 { secret_key, .. } if key_agreement => {
                // NIST.SP.800-73-4, Part 2, Section 3.2.4 and Appendix A.4.2: the response is the x-coordinate of the shared point.
                // The other party public key must be an uncompressed point: `0x04 || X || Y`.
                let public_key = match challenge.split_first() {
                    Some((0x04, _)) if challenge.len() == 65 => p256::PublicKey::from_sec1_bytes(challenge).ok(),
                    _ => None,
                };
                let Some(public_key) = public_key else {
                    return Ok(Status::IncorrectDataField.into());
                };

                Secret::new(secret_key.diffie_hellman(&public_key).raw_secret_bytes().to_vec())
            }
            // NIST.SP.800-73-4, Part 2, Appendix A.4.2: the challenge is the hash that is signed as is.
            CardKey::EcP256 { secret_key, .. } => match ecdsa_sign_prehash(secret_key, challenge) {
                Ok(signature) => Secret::new(signature),
                Err(_) => return Ok(Status::IncorrectDataField.into()),
            },
        };
        let response = Tlv::new(
            Tag::try_from(tlv_tags::DYNAMIC_AUTHENTICATION_TEMPLATE)?,
            Value::Constructed(vec![Tlv::new(
                Tag::try_from(tlv_tags::DAT_RESPONSE)?,
                Value::Primitive(signed_challenge.as_ref().clone()),
            )?]),
        )?
        .to_vec();
        self.pending_response = Some(response.into());
        self.get_response()
    }

    /// Handles the mutual authentication with the management key.
    ///
    /// NIST.SP.800-73-4, Part 2, Appendix A.3:
    /// * The caller requests a witness: an empty `0x80` tag.
    /// * The card returns the encrypted witness in the `0x80` tag.
    /// * The caller sends the decrypted witness in the `0x80` tag and its own challenge in the `0x81` tag.
    /// * The card returns the encrypted challenge in the `0x82` tag.
    #[instrument(level = "debug", skip_all, err)]
    fn management_authenticate(yubikey: &mut YubiKey, cmd: Command<1024>) -> WinScardResult<Response> {
        let request = Tlv::from_bytes(cmd.data())?;
        let Value::Constructed(fields) = request.value() else {
            return Ok(Status::IncorrectDataField.into());
        };
        if request.tag() != &Tag::try_from(tlv_tags::DYNAMIC_AUTHENTICATION_TEMPLATE)? {
            return Ok(Status::IncorrectDataField.into());
        }

        let field_value = |tag: u8| -> WinScardResult<Option<&[u8]>> {
            let tag = Tag::try_from(tag)?;

            Ok(fields
                .iter()
                .find(|tlv| tlv.tag() == &tag)
                .and_then(|tlv| match tlv.value() {
                    Value::Primitive(value) => Some(value.as_slice()),
                    Value::Constructed(_) => None,
                }))
        };
        let witness = field_value(tlv_tags::DAT_WITNESS)?;
        let challenge = field_value(tlv_tags::DAT_CHALLENGE)?;

        let (response_tag, response_value) = match (witness, challenge) {
            (Some([]), None) => (tlv_tags::DAT_WITNESS, yubikey.start_management_authentication()),
            (Some(witness), Some(challenge)) if challenge.len() == yubikey::MANAGEMENT_CHALLENGE_SIZE => {
                let Some(response) = yubikey.finish_management_authentication(witness, challenge) else {
                    return Ok(Status::SecurityStatusNotSatisfied.into());
                };

                (tlv_tags::DAT_RESPONSE, response)
            }
            _ => return Ok(Status::IncorrectDataField.into()),
        };

        let response = Tlv::new(
            Tag::try_from(tlv_tags::DYNAMIC_AUTHENTICATION_TEMPLATE)?,
            Value::Constructed(vec![Tlv::new(
                Tag::try_from(response_tag)?,
                Value::Primitive(response_value.to_vec()),
            )?]),
        )?;

        Ok(Response::new(Status::OK, Some(response.to_vec())))
    }

    /// Handles the commands that exist only on the YubiKey.
    fn yubikey_command(yubikey: &YubiKey, instruction: u8, cmd: Command<1024>) -> Response {
        match instruction {
            yubikey::INS_GET_VERSION => Response::new(Status::OK, Some(yubikey.version().to_vec())),
            yubikey::INS_GET_SERIAL => Response::new(Status::OK, Some(yubikey.serial().to_vec())),
            yubikey::INS_GET_METADATA => match yubikey.metadata(cmd.p2) {
                Some(metadata) => Response::new(Status::OK, Some(metadata.to_vec())),
                None => Status::KeyReferenceNotFound.into(),
            },
            _ => {
                error!(instruction, "unimplemented YubiKey instruction");

                Status::InstructionNotSupported.into()
            }
        }
    }

    fn sign_padded(&self, data: impl AsRef<[u8]>) -> WinScardResult<Vec<u8>> {
        let rsa_private_key = RsaPrivateKey::try_from(self.auth_pk.as_ref())?;
        // According to the specification, the PIV smart card accepts already padded digest.
        // So, it's safe to use the `rsa_decrypt_and_check` function here.
        let signature = rsa::hazmat::rsa_decrypt_and_check(
            &rsa_private_key,
            None::<&mut crate::dummy_rng::Dummy>,
            &BoxedUint::from_be_slice_vartime(data.as_ref()),
        )?;

        let mut signature = signature.to_be_bytes_trimmed_vartime().into_vec();

        while signature.len() < rsa_private_key.size() {
            signature.insert(0, 0);
        }

        Ok(signature)
    }

    /// Signs the provided data using the smart card private key.
    /// *Warning 1*. The input data should be a *SHA1* hash of the actually you want to sign.
    pub fn sign_hashed(&self, data: impl AsRef<[u8]>) -> WinScardResult<Vec<u8>> {
        let rsa_private_key = RsaPrivateKey::try_from(self.auth_pk.as_ref())?;
        let signature = rsa_private_key.sign(Pkcs1v15Sign::new::<Sha1>(), data.as_ref())?;

        Ok(signature)
    }

    /// Signs the provided hash using the EC smart card private key.
    ///
    /// *Warning*. The input data should be the hash (SHA-256 for the P-256 curve) of the actual data you want to sign.
    /// The hash is signed as is. The output is the DER-encoded `ECDSA-Sig-Value`.
    ///
    /// [RFC 5480, ECDSA-Sig-Value](https://www.rfc-editor.org/rfc/rfc5480#section-2.2.3)
    pub fn sign_ecdsa_hashed(&self, data: impl AsRef<[u8]>) -> WinScardResult<Vec<u8>> {
        match &self.key {
            CardKey::EcP256 { secret_key, .. } => ecdsa_sign_prehash(secret_key, data.as_ref()),
            CardKey::Rsa => Err(Error::new(
                ErrorKind::UnsupportedFeature,
                "the smart card key is not an EC key",
            )),
        }
    }

    /// Verifies the PIN code. This method alters the scard state.
    pub fn verify_pin(&mut self, pin: &[u8]) -> WinScardResult<()> {
        if *self.pin.as_ref() != Self::pad_pin(pin.into()) {
            return Err(Error::new(
                ErrorKind::InvalidValue,
                "PIN verification error: Invalid PIN",
            ));
        }

        self.state = SCardState::PinVerified;

        Ok(())
    }

    fn get_next_response_chunk(&mut self) -> Option<(Vec<u8>, usize)> {
        let vec: &mut Vec<u8> = self.pending_response.as_mut()?.as_mut();
        if vec.is_empty() {
            return None;
        }
        let next_chunk_length = CHUNK_SIZE.min(vec.len());
        let chunk = vec.drain(0..next_chunk_length).collect::<Vec<u8>>();
        Some((chunk, vec.len()))
    }
}

#[derive(Debug, Clone, PartialEq)]
enum SCardState {
    Ready,
    PivAppSelected,
    PinVerified,
}

impl WinScard for SmartCard<'_> {
    fn status(&self) -> WinScardResult<winscard::Status<'_>> {
        Ok(winscard::Status {
            readers: vec![self.reader_name.clone()],
            // The original winscard always returns SCARD_SPECIFIC for a working inserted card
            state: winscard::State::Specific,
            // We are always using the T1 protocol as the original Windows TPM smart card does
            protocol: SUPPORTED_CONNECTION_PROTOCOL,
            atr: self.key.identity().atr.to_vec().into(),
        })
    }

    fn control(&mut self, code: ControlCode, _input: &[u8]) -> WinScardResult<()> {
        if code != IO_CTL {
            return Err(Error::new(
                ErrorKind::InvalidValue,
                format!("unsupported control code: {code:?}"),
            ));
        }

        Ok(())
    }

    fn control_with_output(&mut self, code: ControlCode, input: &[u8], _output: &mut [u8]) -> WinScardResult<usize> {
        self.control(code, input)?;

        Ok(0)
    }

    fn transmit(&mut self, input_apdu: &[u8]) -> WinScardResult<TransmitOutData> {
        let Response { status, data } = self.handle_command(input_apdu)?;

        let mut output_apdu = data.unwrap_or_default();
        let status_data: [u8; 2] = status.into();
        output_apdu.extend_from_slice(&status_data);

        Ok(TransmitOutData {
            output_apdu,
            receive_pci: None,
        })
    }

    fn begin_transaction(&mut self) -> WinScardResult<()> {
        if self.transaction {
            return Err(Error::new(
                ErrorKind::InternalError,
                "the transaction already in progress",
            ));
        }
        self.transaction = true;
        Ok(())
    }

    fn end_transaction(&mut self, _disposition: ReaderAction) -> WinScardResult<()> {
        if !self.transaction {
            return Err(Error::new(ErrorKind::NotTransacted, "the transaction is not started"));
        }
        self.transaction = false;
        Ok(())
    }

    fn reconnect(&mut self, _: ShareMode, _: Option<Protocol>, _: ReaderAction) -> WinScardResult<Protocol> {
        // Because it's an emulated smart card, we do nothing and return success.
        Ok(SUPPORTED_CONNECTION_PROTOCOL)
    }

    fn get_attribute(&self, attribute_id: AttributeId) -> WinScardResult<Cow<'_, [u8]>> {
        let data = self.attributes.get(&attribute_id).map(AsRef::as_ref).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidParameter,
                format!("The {attribute_id:?} attribute id is not present"),
            )
        })?;

        Ok(Cow::Borrowed(data))
    }

    fn set_attribute(&mut self, attribute_id: AttributeId, attribute_data: &[u8]) -> WinScardResult<()> {
        self.attributes
            .insert(attribute_id, Cow::Owned(attribute_data.to_vec()));

        Ok(())
    }

    fn disconnect(&mut self, _disposition: ReaderAction) -> WinScardResult<()> {
        // We don't need any actions during the disconnection in emulated smart cards.
        // It's enough just to drop the card object.

        Ok(())
    }
}

/// Returns `true` if the GENERAL AUTHENTICATE command authenticates with the YubiKey management key.
fn is_management_authentication(cmd: &Command<1024>) -> bool {
    cmd.p1 == yubikey::MANAGEMENT_KEY_ALGORITHM && cmd.p2 == yubikey::MANAGEMENT_KEY_SLOT
}

/// Signs the prehashed data using ECDSA and returns the DER-encoded `ECDSA-Sig-Value`.
///
/// The signature is deterministic ([RFC 6979](https://www.rfc-editor.org/rfc/rfc6979)), so no random number generator is needed.
///
/// [RFC 5480, ECDSA-Sig-Value](https://www.rfc-editor.org/rfc/rfc5480#section-2.2.3)
fn ecdsa_sign_prehash(secret_key: &p256::SecretKey, prehash: &[u8]) -> WinScardResult<Vec<u8>> {
    // The ECDSA implementation panics on the empty hash.
    if prehash.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidValue,
            "invalid data to sign: the hash is empty",
        ));
    }

    let signature: p256::ecdsa::Signature = SigningKey::from(secret_key)
        .sign_prehash(prehash)
        .map_err(|_| Error::new(ErrorKind::InvalidValue, "invalid data to sign: unsuitable hash length"))?;

    Ok(signature.to_der().as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
    use crypto_bigint::{Odd, Resize};
    use picky::hash::HashAlgorithm;
    use picky::signature::SignatureAlgorithm;
    use proptest::prelude::*;
    use proptest::{collection, option, prop_compose};
    use rand::RngExt as _;
    use rand::distr::Uniform;
    use rsa::BoxedUint;
    use rsa::traits::PublicKeyParts;

    use super::*;
    use crate::ber_tlv::ber_tlv_length_encoding;

    fn arb_status() -> impl Strategy<Value = Status> {
        prop_oneof![
            Just(Status::NotFound),
            Just(Status::OK),
            Just(Status::VerificationFailedWithRetries),
            any::<u8>().prop_map(Status::MoreAvailable),
            Just(Status::KeyReferenceNotFound),
            Just(Status::SecurityStatusNotSatisfied),
            Just(Status::IncorrectP1orP2),
            Just(Status::IncorrectDataField),
            Just(Status::InstructionNotSupported)
        ]
    }

    prop_compose! {
        fn arb_response()(status in arb_status(), data in option::of(collection::vec(any::<u8>(), 0..256))) -> Response {
            Response::new(status, data)
        }
    }

    proptest! {
        #[test]
        fn response_is_encoded_correctly(arb_response in arb_response()) {
            let data = arb_response.data.clone();
            let status: [u8; 2] = arb_response.status.clone().into();
            let expected_result = if let Some(mut bytes) = data {
                bytes.extend(status);
                bytes
            } else {
                Vec::from(status)
            };
            assert_eq!(expected_result, Vec::from(arb_response));
        }
    }

    fn new_scard() -> SmartCard<'static> {
        let rsa_2048_private_key = crate::test_keys::RSA_2048_PRIVATE_KEY;
        let auth_pk = PrivateKey::from_pem_str(rsa_2048_private_key).unwrap();
        let certificate_stub = vec![0xff; 1024];
        let pin = vec![0x39; 6];
        SmartCard::new(
            Cow::Borrowed("Reader 0"),
            // The tests do not care about the card identifier, so any fixed value suits them.
            Uuid::from_u128(1),
            pin,
            certificate_stub,
            auth_pk,
        )
        .unwrap()
    }

    // Helper function that calls the GET RESPONSE handler until there is no more data to read
    fn get_all_available_data(mut response: Response, scard: &mut SmartCard<'_>) -> Vec<u8> {
        let mut complete_response = vec![];
        while let Status::MoreAvailable(bytes_left) = response.status {
            complete_response.extend_from_slice(&response.data.expect("Data should be present"));
            let apdu_get_response = vec![0x00, 0xC0, 0x00, 0x00, bytes_left];
            response = scard
                .handle_command(&apdu_get_response)
                .expect("Can't retrieve all available data");
        }
        assert_eq!(response.status, Status::OK);
        complete_response.extend_from_slice(&response.data.expect("The last chunk of data isn't present"));
        complete_response
    }

    #[test]
    fn invalid_apdu_command() {
        // Verify that smart card correctly handles invalid APDU commands
        let mut scard = new_scard();

        let bad_apdu_command = vec![0x00; 2048];
        let response = scard.handle_command(&bad_apdu_command);
        assert!(response.is_err_and(|err| err.error_kind == ErrorKind::InternalError));
    }

    #[test]
    fn wrong_command_order() {
        // Verify that the smart card prohibits using any commands besides SELECT when no app was selected
        let mut scard = new_scard();

        let mut apdu_verify_cmd = vec![0x00, 0x20, 0x00, 0x80, 0x08];
        // add pin
        apdu_verify_cmd.extend_from_slice(&[0xA9; 8]);
        let response = scard.handle_command(&apdu_verify_cmd);
        assert!(response.is_ok_and(|resp| resp.status == Status::NotFound));
    }

    #[test]
    fn invalid_select_command() {
        // Verify that the SELECT handler correctly responds if called with an invalid AID
        let mut scard = new_scard();

        let bad_aid = vec![0xff; 11];

        let mut apdu_select_cmd = vec![0x00, 0xA4, 0x04, 0x00, 0x0B];
        apdu_select_cmd.extend_from_slice(&bad_aid);
        let response = scard.handle_command(&apdu_select_cmd);
        assert!(response.is_ok_and(|resp| resp.status == Status::NotFound));
    }

    #[test]
    fn select_command() {
        // Verify that the SELECT command works as expected and returns expected output
        let mut scard = new_scard();

        let mut expected_response = vec![
            0x61, 0x17, 0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x0D, 0x4F, 0x0B,
        ];
        expected_response.extend_from_slice(&PIV_AID);

        let mut apdu_select_cmd = vec![0x00, 0xA4, 0x04, 0x00, 0x0B];
        apdu_select_cmd.extend_from_slice(&PIV_AID);
        let response = scard.handle_command(&apdu_select_cmd);
        assert!(response.is_ok_and(
            |resp| resp.status == Status::OK && resp.data.expect("Data should be present") == expected_response
        ));
    }

    #[test]
    fn unsupported_command() {
        // Verify that smart card correctly handles unsupported commands
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // RESET RETRY COUNTER APDU command
        let apdu_reset_retry_cmd = vec![0x00, 0x2C, 0x00, 0x80, 0x00];
        let response = scard.handle_command(&apdu_reset_retry_cmd);
        assert!(response.is_ok_and(|resp| resp.status == Status::InstructionNotSupported));
    }

    #[test]
    fn invalid_verify_commands() {
        // Verify that the VERIFY command handler correctly handles badly structured or malformed requests
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // p1 can only be 0x00 or 0xFF
        let apdu_verify_bad_p1 = vec![0x00, 0x20, 0xAA, 0x80, 0x00];
        let response = scard.handle_command(&apdu_verify_bad_p1);
        assert!(response.is_ok_and(|resp| resp.status == Status::IncorrectP1orP2));

        // if p1 is 0xFF, the data field should be empty
        let apdu_verify_bad_p1_data = vec![0x00, 0x20, 0xFF, 0x80, 0x02, 0xFF, 0xFF];
        let response = scard.handle_command(&apdu_verify_bad_p1_data);
        assert!(response.is_ok_and(|resp| resp.status == Status::IncorrectP1orP2));

        // p2 should always be 0x80
        let apdu_verify_bad_p2 = vec![0x00, 0x20, 0x00, 0x81, 0x02, 0xFF, 0xFF];
        let response = scard.handle_command(&apdu_verify_bad_p2);
        assert!(response.is_ok_and(|resp| resp.status == Status::KeyReferenceNotFound));

        // PIN should be no shorter than six bytes and no longer than 8
        let apdu_verify_bad_pin = vec![0x00, 0x20, 0x00, 0x80, 0x02, 0xAA, 0xAA];
        let response = scard.handle_command(&apdu_verify_bad_pin);
        assert!(response.is_ok_and(|resp| resp.status == Status::IncorrectDataField));
    }

    #[test]
    fn verify_command() {
        // Verify that the VERIFY command handler correctly handles all supported types of requests
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // retrieve number of allowed retries by omitting the data field
        let apdu_verify_no_data = vec![0x00, 0x20, 0x00, 0x80, 0x00];
        let response = scard.handle_command(&apdu_verify_no_data);
        assert!(response.is_ok_and(|resp| resp.status == Status::VerificationFailedWithRetries));

        // VERIFY command with the wrong PIN code
        let mut apdu_verify_wrong_pin = vec![0x00, 0x20, 0x00, 0x80, 0x08];
        apdu_verify_wrong_pin.extend_from_slice(&[0xCC; 8]);
        let response = scard.handle_command(&apdu_verify_wrong_pin);
        assert!(response.is_ok_and(|resp| resp.status == Status::VerificationFailedWithRetries));

        // VERIFY command with the correct PIN code
        let mut apdu_verify_correct_pin = vec![0x00, 0x20, 0x00, 0x80, 0x08];
        apdu_verify_correct_pin.extend_from_slice(&[0x39; 6]);
        // 0xFF padding
        apdu_verify_correct_pin.extend_from_slice(&[0xFF; 2]);
        let response = scard.handle_command(&apdu_verify_correct_pin);
        assert!(response.is_ok_and(|resp| resp.status == Status::OK));
        assert_eq!(scard.state, SCardState::PinVerified);

        // Reset the security status
        let apdu_verify_reset = vec![0x00, 0x20, 0xFF, 0x80, 0x00];
        let response = scard.handle_command(&apdu_verify_reset);
        assert!(response.is_ok_and(|resp| resp.status == Status::OK));
        assert_eq!(scard.state, SCardState::PivAppSelected);
    }

    #[test]
    fn get_response_command() {
        // Verify that the GET RESPONSE handler correctly sends the data
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;
        let mut rng = rand::rng();

        // get a random Vec<u8> of length 513
        let uniform = Uniform::new(0, 255).unwrap();
        let data: Vec<u8> = (0..513).map(|_| rng.sample(uniform)).collect();
        // we will have to make 3 calls to get this data
        scard.pending_response = Some(data.clone().into());

        let mut received_result = vec![];
        // 0 means any valid number in range 0..=256
        // We set this to 0 on the first call so that the smart card returns whatever it got
        let bytes_left = 0;
        let mut apdu_get_response = vec![0x00, 0xC0, 0x00, 0x00, bytes_left];

        let response = scard.handle_command(&apdu_get_response);
        assert!(
            response
                .as_ref()
                .is_ok_and(|resp| resp.status == Status::MoreAvailable(0)
                    && resp.data.is_some()
                    && resp.data.as_ref().unwrap() == &data[0..256])
        );
        received_result.extend_from_slice(&response.unwrap().data.unwrap());

        let response = scard.handle_command(&apdu_get_response);
        assert!(
            response
                .as_ref()
                .is_ok_and(|resp| resp.status == Status::MoreAvailable(1)
                    && resp.data.is_some()
                    && resp.data.as_ref().unwrap() == &data[256..512])
        );
        received_result.extend_from_slice(&response.unwrap().data.unwrap());

        // set the Le field to 1 so that we get the last remaining byte
        apdu_get_response[4] = 1;
        let response = scard.handle_command(&apdu_get_response);
        assert!(response.as_ref().is_ok_and(|resp| resp.status == Status::OK
            && resp.data.is_some()
            && resp.data.as_ref().unwrap() == &data[512..]));
        received_result.extend_from_slice(&response.unwrap().data.unwrap());

        assert_eq!(received_result, data);
    }

    #[test]
    fn invalid_get_data_command() {
        // Verify that the GET DATA handler correctly handles invalid requests
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // p1 should always be 0x3F; p2 should always be 0xFF
        let apdu_get_data_bad_p1_p2 = vec![0x00, 0xCB, 0x10, 0x21, 0x00];
        let response = scard.handle_command(&apdu_get_data_bad_p1_p2);
        assert!(response.is_ok_and(|resp| resp.status == Status::IncorrectP1orP2));

        // bad object tag in the data field
        let apdu_get_data_bad_tag = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x08];
        let response = scard.handle_command(&apdu_get_data_bad_tag);
        assert!(response.is_ok_and(|resp| resp.status == Status::NotFound));
    }

    #[test]
    fn get_data_command() {
        // Verify that the GET DATA handler correctly handles all supported requests and returns correct data
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // get CHUID
        let apdu_get_data_chuid = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x02];
        let response = scard.handle_command(&apdu_get_data_chuid);
        assert!(
            response.is_ok_and(|resp| resp.status == Status::OK && resp.data.expect("Expected CHUID") == scard.chuid)
        );

        // get PIV authentication certificate
        let apdu_get_data_chuid = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05];
        let response = scard.handle_command(&apdu_get_data_chuid);
        // verify the contents
        assert!(response.is_ok_and(|resp| {
            // as the certificate is larger than 256 bytes, we have to call the GET RESPONSE function a few times
            let complete_response = get_all_available_data(resp, &mut scard);
            complete_response == scard.auth_cert
        }));
    }

    #[test]
    fn general_authenticate_no_pin() {
        // Verify that the GENERAL AUTHENTICATE handler can't be used without unlocking the smart card first
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        let apdu_general_authenticate = vec![0x00, 0x87, 0x07, 0x9A, 0x00];
        let response = scard.handle_command(&apdu_general_authenticate);
        assert!(response.is_ok_and(|resp| resp.status == Status::SecurityStatusNotSatisfied));
    }

    #[test]
    fn invalid_general_authenticate_command() {
        // Verify that the GENERAL AUTHENTICATE handler correctly handles invalid requests
        let mut scard = new_scard();
        scard.state = SCardState::PinVerified;

        // p1 should always be 0x07; p2 should always be 0x9A
        let apdu_general_authenticate = vec![0x00, 0x87, 0xFF, 0xCC, 0x00];
        let response = scard.handle_command(&apdu_general_authenticate);
        assert!(response.is_err_and(|err| err.error_kind == ErrorKind::UnsupportedFeature));
    }

    #[test]
    fn general_authenticate_command() {
        // Verify that the GENERAL AUTHENTICATE handler correctly encrypts the provided data
        let mut scard = new_scard();
        scard.state = SCardState::PinVerified;

        let data = "My message".as_bytes();

        let rsa_pk = RsaPrivateKey::try_from(scard.auth_pk.as_ref()).expect("Can't convert the private key");
        // sign the data using the PKCS1-v1.5 padding scheme
        let signature_algorithm = SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA3_512);
        let signed_data = signature_algorithm
            .sign(data, scard.auth_pk.as_ref())
            .expect("Error while signing the data");
        // extract the padded hash by decrypting the signature using the public key
        // we need to extract the padded hash to calculate the signature ourselves
        let padded_hash = modpow(
            &BoxedUint::from_be_slice_vartime(&signed_data),
            rsa_pk.e(),
            Odd::new(rsa_pk.n().clone().get()).into_option().unwrap(),
        );
        let padded_hash = padded_hash.to_be_bytes_trimmed_vartime().into_vec();

        // the hash is bigger than 127, so we have to use BER-TLV encoding
        let encoded_hash_length = ber_tlv_length_encoding(padded_hash.len());
        // encoded_hash_length + tag + hash
        let dat_tag_data_length = ber_tlv_length_encoding(1 + encoded_hash_length.len() + padded_hash.len());

        // use command chaining to send the data that is bigger than 255 bytes
        let mut apdu_general_authenticate = vec![0x10, 0x87, 0x07, 0x9A, 0xFF, 0x7C];
        apdu_general_authenticate.extend_from_slice(&dat_tag_data_length);
        apdu_general_authenticate.extend_from_slice(&[0x81]);
        apdu_general_authenticate.extend_from_slice(&encoded_hash_length);
        apdu_general_authenticate.extend_from_slice(&padded_hash[..248]);

        let response = scard.handle_command(&apdu_general_authenticate);
        assert!(response.is_ok_and(|resp| resp.status == Status::OK));

        // send the remaining data and end command chaining by setting the CLA byte to 0x00
        let mut apdu_general_authenticate = vec![0x00, 0x87, 0x07, 0x9A, 0x07];
        apdu_general_authenticate.extend_from_slice(&padded_hash[248..]);
        // Le
        apdu_general_authenticate.extend_from_slice(&[0x00]);

        let response = scard
            .handle_command(&apdu_general_authenticate)
            .expect("Shouldn't have failed");

        let complete_response = get_all_available_data(response, &mut scard);
        let parsed_response =
            Tlv::from_bytes(&complete_response).expect("Couldn't parse a TLV object sent from the smart card");

        // verify the structure of the response and extract the signed hash
        assert_eq!(
            parsed_response.tag(),
            &Tag::try_from(tlv_tags::DYNAMIC_AUTHENTICATION_TEMPLATE).expect("Couldn't construct a TLV tag")
        );
        let response_tag = match parsed_response.value() {
            Value::Constructed(data) => data
                .iter()
                .find(|tlv_object| {
                    tlv_object.tag() == &Tag::try_from(tlv_tags::DAT_RESPONSE).expect("Couldn't construct a TLV tag")
                })
                .expect("The inner TLV object should contain a Response tag"),
            Value::Primitive(_) => panic!("Dynamic Authentication Template should contain constructed value"),
        };
        let signed_hash = match response_tag.value() {
            Value::Constructed(_) => panic!("Response tag should contain a primitive value"),
            Value::Primitive(signed_hash) => signed_hash,
        };
        // verify that the returned signature can be verified using the corresponding public key
        assert!(
            signature_algorithm
                .verify(
                    &scard
                        .auth_pk
                        .as_ref()
                        .to_public_key()
                        .expect("Error while creating public key from a private key"),
                    data,
                    signed_hash
                )
                .is_ok()
        );
    }

    fn modpow(public_key: &BoxedUint, private_key: &BoxedUint, p: Odd<BoxedUint>) -> BoxedUint {
        let p = BoxedMontyParams::new_vartime(p);
        pow_mod_params(public_key, private_key, &p)
    }

    // Copied from `rsa` crate: https://github.com/RustCrypto/RSA/blob/eb1cca7b7ea42445dc874c1c1ce38873e4adade7/src/algorithms/rsa.rs#L232-L241
    fn pow_mod_params(base: &BoxedUint, exp: &BoxedUint, n_params: &BoxedMontyParams) -> BoxedUint {
        let base = reduce_vartime(base, n_params);
        base.pow(exp).retrieve()
    }

    fn reduce_vartime(n: &BoxedUint, p: &BoxedMontyParams) -> BoxedMontyForm {
        let modulus = p.modulus().as_nz_ref().clone();
        let n_reduced = n.rem_vartime(&modulus).resize_unchecked(p.bits_precision());
        BoxedMontyForm::new(n_reduced, p)
    }

    mod ec {
        use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
        use p256::ecdsa::{Signature, VerifyingKey};

        use super::*;
        use crate::test_keys::{EC_P256_PRIVATE_KEY, EC_P256_PUBLIC_POINT, EC_P384_PRIVATE_KEY, ED25519_PRIVATE_KEY};

        fn new_ec_scard() -> SmartCard<'static> {
            let auth_pk = PrivateKey::from_pem_str(EC_P256_PRIVATE_KEY).unwrap();

            let mut scard = SmartCard::new(
                Cow::Borrowed("Reader 0"),
                Uuid::from_u128(1),
                vec![0x39; 6],
                vec![0xff; 1024],
                auth_pk,
            )
            .unwrap();
            scard.state = SCardState::PinVerified;

            scard
        }

        /// The GENERAL AUTHENTICATE command the Windows smart card minidriver sends: the empty response tag goes first.
        ///
        /// The command layout is taken from the real YubiKey (P-256) RDP smart card logon capture.
        fn general_authenticate_apdu(p1: u8, p2: u8, tag: u8, value: &[u8]) -> Vec<u8> {
            let mut template = vec![0x82, 0x00, tag, u8::try_from(value.len()).unwrap()];
            template.extend_from_slice(value);

            let mut apdu = vec![0x00, 0x87, p1, p2, u8::try_from(template.len() + 2).unwrap(), 0x7c];
            apdu.push(u8::try_from(template.len()).unwrap());
            apdu.extend_from_slice(&template);
            apdu.push(0x00);

            apdu
        }

        /// Sends the command and returns the value of the response (0x82) tag of the Dynamic Authentication Template.
        fn response_value(scard: &mut SmartCard<'_>, apdu: &[u8]) -> Vec<u8> {
            let response = scard.handle_command(apdu).expect("the command must be handled");
            let data = get_all_available_data(response, scard);
            let template = Tlv::from_bytes(&data).expect("the response must be a TLV object");

            assert_eq!(
                template.tag(),
                &Tag::try_from(tlv_tags::DYNAMIC_AUTHENTICATION_TEMPLATE).unwrap()
            );
            let Value::Constructed(inner) = template.value() else {
                panic!("the Dynamic Authentication Template must be constructed");
            };
            assert_eq!(1, inner.len());
            assert_eq!(inner[0].tag(), &Tag::try_from(tlv_tags::DAT_RESPONSE).unwrap());
            let Value::Primitive(value) = inner[0].value() else {
                panic!("the response tag must be primitive");
            };

            value.clone()
        }

        /// Parses the DER `ECDSA-Sig-Value` and checks it is encoded minimally.
        fn parse_der_signature(der: &[u8]) -> Signature {
            assert_eq!(0x30, der[0]);
            assert_eq!(usize::from(der[1]), der.len() - 2);

            let mut rest = &der[2..];
            let mut integers = Vec::new();
            for _ in 0..2 {
                assert_eq!(0x02, rest[0]);
                let len = usize::from(rest[1]);
                let integer = &rest[2..2 + len];
                // Minimal two's complement non-negative integer.
                if integer.len() > 1 && integer[0] == 0 {
                    assert!(integer[1] & 0x80 != 0, "redundant leading zero");
                }
                assert!(integer[0] & 0x80 == 0, "negative integer");

                let integer = integer.strip_prefix(&[0]).unwrap_or(integer);
                let mut padded = [0_u8; 32];
                padded[32 - integer.len()..].copy_from_slice(integer);
                integers.push(padded);
                rest = &rest[2 + len..];
            }
            assert!(rest.is_empty());

            Signature::from_scalars(integers[0], integers[1]).expect("valid signature scalars")
        }

        #[test]
        fn ec_key_is_detected() {
            let scard = new_ec_scard();

            assert!(matches!(scard.key, CardKey::EcP256 { .. }));
            assert_eq!(0x11, scard.key.algorithm());
            assert_eq!(0x07, new_scard().key.algorithm());
        }

        #[test]
        fn unsupported_keys_are_rejected() {
            for key in [EC_P384_PRIVATE_KEY, ED25519_PRIVATE_KEY] {
                let auth_pk = PrivateKey::from_pem_str(key).unwrap();

                let error = SmartCard::new(
                    Cow::Borrowed("Reader 0"),
                    Uuid::from_u128(1),
                    vec![0x39; 6],
                    vec![0xff; 16],
                    auth_pk,
                )
                .unwrap_err();

                assert_eq!(ErrorKind::UnsupportedFeature, error.error_kind);
            }
        }

        #[test]
        fn general_authenticate_signs_the_challenge_hash() {
            let mut scard = new_ec_scard();
            let hash = [0x42_u8; 32];

            // The same command as the Windows minidriver sends.
            let apdu = general_authenticate_apdu(0x11, 0x9a, 0x81, &hash);
            assert_eq!(
                &[0x00, 0x87, 0x11, 0x9a, 0x26, 0x7c, 0x24, 0x82, 0x00, 0x81, 0x20],
                &apdu[..11]
            );

            let signature = parse_der_signature(&response_value(&mut scard, &apdu));

            VerifyingKey::from_sec1_bytes(&EC_P256_PUBLIC_POINT)
                .unwrap()
                .verify_prehash(&hash, &signature)
                .expect("the signature must be valid");
        }

        #[test]
        fn general_authenticate_signature_is_deterministic() {
            let mut scard = new_ec_scard();
            let apdu = general_authenticate_apdu(0x11, 0x9c, 0x81, &[0x24; 32]);

            assert_eq!(response_value(&mut scard, &apdu), response_value(&mut scard, &apdu));
        }

        #[test]
        fn der_signature_encoding_is_minimal_for_any_hash() {
            let scard = new_ec_scard();
            let verifying_key = VerifyingKey::from_sec1_bytes(&EC_P256_PUBLIC_POINT).unwrap();

            // A lot of different hashes give `r` and `s` values with the high bit set and with leading zero bytes.
            for seed in 0..=u8::MAX {
                let hash = (0..32)
                    .map(|i| seed.wrapping_mul(31).wrapping_add(i))
                    .collect::<Vec<_>>();

                let der = scard.sign_ecdsa_hashed(&hash).unwrap();
                let signature = parse_der_signature(&der);

                verifying_key.verify_prehash(&hash, &signature).unwrap();
            }
        }

        #[test]
        fn general_authenticate_ecdh_returns_the_shared_secret_x_coordinate() {
            let mut scard = new_ec_scard();

            // The other party (the server) ephemeral key pair.
            let other_secret = p256::SecretKey::from_slice(&[0x55; 32]).unwrap();
            let other_point = other_secret.public_key().to_sec1_bytes();
            assert_eq!(65, other_point.len());

            let apdu = general_authenticate_apdu(0x11, 0x9a, 0x85, &other_point);
            assert_eq!(
                &[0x00, 0x87, 0x11, 0x9a, 0x47, 0x7c, 0x45, 0x82, 0x00, 0x85, 0x41, 0x04],
                &apdu[..12]
            );

            let shared_secret = response_value(&mut scard, &apdu);

            let card_public_key = p256::PublicKey::from_sec1_bytes(&EC_P256_PUBLIC_POINT).unwrap();
            let expected = other_secret.diffie_hellman(&card_public_key);
            assert_eq!(32, shared_secret.len());
            assert_eq!(expected.raw_secret_bytes().as_slice(), shared_secret.as_slice());
        }

        #[test]
        fn general_authenticate_ecdh_rejects_an_invalid_point() {
            let mut scard = new_ec_scard();

            // A compressed (but otherwise valid) point of the other party.
            let other_point = p256::SecretKey::from_slice(&[0x55; 32])
                .unwrap()
                .public_key()
                .to_sec1_bytes();
            let mut compressed_point = vec![0x02 + (other_point[64] & 1)];
            compressed_point.extend_from_slice(&other_point[1..33]);

            // Not on the curve, the unsupported point encodings and a truncated point.
            for point in [&[0x04_u8; 65][..], &[0x07; 33], &[0x01, 0x02], &compressed_point] {
                let apdu = general_authenticate_apdu(0x11, 0x9a, 0x85, point);
                let response = scard.handle_command(&apdu).expect("the command must be handled");

                assert_eq!(Status::IncorrectDataField, response.status, "point: {point:02x?}");
            }
        }

        #[test]
        fn general_authenticate_requires_the_key_algorithm() {
            let mut ec_scard = new_ec_scard();
            // RSA algorithm identifier on the EC card.
            let apdu = general_authenticate_apdu(0x07, 0x9a, 0x81, &[0; 32]);
            ec_scard.handle_command(&apdu).unwrap_err();
            // ECC algorithm identifier on the RSA card.
            let mut rsa_scard = new_scard();
            rsa_scard.state = SCardState::PinVerified;
            let apdu = general_authenticate_apdu(0x11, 0x9a, 0x81, &[0; 32]);
            rsa_scard.handle_command(&apdu).unwrap_err();
        }

        #[test]
        fn general_authenticate_key_references() {
            let mut ec_scard = new_ec_scard();
            for key_reference in [0x9a, 0x9c, 0x9d] {
                let apdu = general_authenticate_apdu(0x11, key_reference, 0x81, &[0; 32]);
                ec_scard
                    .handle_command(&apdu)
                    .expect("the EC key reference must be supported");
            }
            let apdu = general_authenticate_apdu(0x11, 0x9e, 0x81, &[0; 32]);
            ec_scard.handle_command(&apdu).unwrap_err();

            // The key management key is not supported for RSA (the old behavior).
            let mut rsa_scard = new_scard();
            rsa_scard.state = SCardState::PinVerified;
            let apdu = general_authenticate_apdu(0x07, 0x9d, 0x81, &[0; 32]);
            rsa_scard.handle_command(&apdu).unwrap_err();
        }

        #[test]
        fn general_authenticate_challenge_with_a_wrong_length_is_rejected() {
            let mut scard = new_ec_scard();
            let apdu = general_authenticate_apdu(0x11, 0x9a, 0x81, &[]);

            let response = scard.handle_command(&apdu).expect("the command must be handled");
            assert_eq!(Status::IncorrectDataField, response.status);
        }

        #[test]
        fn ecdh_request_is_not_accepted_by_rsa_card() {
            let mut scard = new_scard();
            scard.state = SCardState::PinVerified;
            let apdu = general_authenticate_apdu(0x07, 0x9a, 0x85, &[0x04; 65]);

            scard.handle_command(&apdu).unwrap_err();
        }

        #[test]
        fn rsa_card_cannot_sign_with_ecdsa() {
            new_scard().sign_ecdsa_hashed([0; 32]).unwrap_err();
        }

        #[test]
        fn ec_card_cannot_sign_with_rsa() {
            new_ec_scard().sign_hashed([0; 20]).unwrap_err();
        }

        // The expected values below are taken from the APDU traffic of a real YubiKey 5.
        mod yubikey_extensions {
            use des::TdesEde3;
            use des::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
            use sha2::{Digest, Sha256};

            use super::*;

            const AUTHENTICATION_REQUEST: [u8; 10] = [0x00, 0x87, 0x03, 0x9B, 0x04, 0x7C, 0x02, 0x80, 0x00, 0x00];
            const SHORT_AID_SELECT: [u8; 11] = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00];
            const PRINTED_INFORMATION_TAG: [u8; 3] = [0x5F, 0xC1, 0x09];

            fn get_data(scard: &mut SmartCard<'_>, tag: [u8; 3]) -> Response {
                scard
                    .handle_command(&[0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, tag[0], tag[1], tag[2], 0x00])
                    .unwrap()
            }

            fn management_key(scard: &mut SmartCard<'_>) -> TdesEde3 {
                let object = get_data(scard, PRINTED_INFORMATION_TAG).data.unwrap();
                assert_eq!([0x53, 0x1C, 0x88, 0x1A, 0x89, 0x18], object[..6]);

                TdesEde3::new_from_slice(&object[6..]).unwrap()
            }

            fn authentication_response(witness: &[u8], challenge: &[u8]) -> Vec<u8> {
                let mut command = vec![0x00, 0x87, 0x03, 0x9B, 0x16, 0x7C, 0x14, 0x80, 0x08];
                command.extend_from_slice(witness);
                command.extend_from_slice(&[0x81, 0x08]);
                command.extend_from_slice(challenge);
                command.push(0x00);

                command
            }

            #[test]
            fn ec_card_reports_the_yubikey_atr() {
                assert_eq!(YUBIKEY_ATR, new_ec_scard().status().unwrap().atr.as_ref());
            }

            #[test]
            fn rsa_card_keeps_the_piv_atr() {
                assert_eq!(ATR, new_scard().status().unwrap().atr.as_ref());
            }

            #[test]
            fn ec_card_returns_firmware_version_and_serial() {
                let mut scard = new_ec_scard();

                let version = scard.handle_command(&[0x00, 0xFD, 0x00, 0x00, 0x00]).unwrap();
                assert_eq!(Status::OK, version.status);
                assert_eq!(vec![5, 4, 3], version.data.unwrap());

                let serial = scard.handle_command(&[0x00, 0xF8, 0x00, 0x00, 0x00]).unwrap();
                assert_eq!(Status::OK, serial.status);
                assert_eq!(4, serial.data.unwrap().len());
            }

            #[test]
            fn rsa_card_has_no_yubikey_instructions() {
                let mut scard = new_scard();
                scard.state = SCardState::PivAppSelected;

                let response = scard.handle_command(&[0x00, 0xFD, 0x00, 0x00, 0x00]).unwrap();

                assert_eq!(Status::InstructionNotSupported, response.status);
            }

            #[test]
            fn ec_card_metadata_describes_only_the_management_key() {
                let mut scard = new_ec_scard();

                let metadata = scard.handle_command(&[0x00, 0xF7, 0x00, 0x9B, 0x00]).unwrap();
                assert_eq!(Status::OK, metadata.status);
                assert_eq!(
                    vec![0x01, 0x01, 0x03, 0x02, 0x02, 0x00, 0x01, 0x05, 0x01, 0x00],
                    metadata.data.unwrap()
                );

                let bio = scard.handle_command(&[0x00, 0xF7, 0x00, 0x96, 0x00]).unwrap();
                assert_eq!(Status::KeyReferenceNotFound, bio.status);
            }

            #[test]
            fn ec_card_admin_data_matches_the_real_card() {
                let response = get_data(&mut new_ec_scard(), [0x5F, 0xFF, 0x00]);

                assert_eq!(vec![0x53, 0x05, 0x80, 0x03, 0x81, 0x01, 0x03], response.data.unwrap());
            }

            #[test]
            fn ec_card_container_map_matches_the_real_card_layout() {
                let mut scard = new_ec_scard().with_container_name("test-container").unwrap();

                let object = get_data(&mut scard, [0x5F, 0xFF, 0x10]).data.unwrap();

                assert_eq!(111, object.len());
                assert_eq!([0x53, 0x6D, 0x81, 0x6B], object[..4]);

                let record = &object[4..];
                let name = "test-container"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>();
                assert_eq!(name, record[..name.len()]);
                assert!(record[name.len()..80].iter().all(|byte| *byte == 0));
                // Slot, key spec, key size, flags, PIN id, and no associated ECDH container.
                assert_eq!([0x9A, 0x06, 0x00, 0x01, 0x03, 0x01, 0xFF], record[80..87]);
                // The fingerprint is the beginning of the SHA-256 hash of the certificate.
                assert_eq!(Sha256::digest([0xff; 1024])[..20], record[87..]);
            }

            #[test]
            fn too_long_container_name_is_rejected() {
                let error = new_ec_scard().with_container_name(&"a".repeat(40)).unwrap_err();

                assert_eq!(ErrorKind::InvalidParameter, error.error_kind);
            }

            #[test]
            fn card_identity_follows_the_key() {
                let ec_key = PrivateKey::from_pem_str(EC_P256_PRIVATE_KEY).unwrap();
                let identity = card_identity(&ec_key).unwrap();
                assert_eq!(YUBIKEY_ATR, identity.atr);
                assert_eq!("YubiKey Smart Card", identity.name);
                assert_eq!("Microsoft Smart Card Key Storage Provider", identity.provider_name);
                assert_eq!("ykmd.dll\0", identity.card_module);

                let rsa_key = PrivateKey::from_pem_str(crate::test_keys::RSA_2048_PRIVATE_KEY).unwrap();
                let identity = card_identity(&rsa_key).unwrap();
                assert_eq!(ATR, identity.atr);
                assert_eq!("Sspi-rs emulated smart card", identity.name);
                assert_eq!("Microsoft Base Smart Card Crypto Provider", identity.provider_name);
                assert_eq!("msclmd.dll\0", identity.card_module);
            }

            #[test]
            fn unsupported_curve_has_no_card_identity() {
                let key = PrivateKey::from_pem_str(EC_P384_PRIVATE_KEY).unwrap();

                let error = card_identity(&key).unwrap_err();

                assert_eq!(ErrorKind::UnsupportedFeature, error.error_kind);
            }

            #[test]
            fn ec_card_certificate_uses_ber_tlv_lengths() {
                let mut scard = new_ec_scard();

                let object = get_all_available_data(get_data(&mut scard, PIV_CERT_TAG), &mut scard);

                // `new_ec_scard` uses a 1024-byte certificate. The real card returns the same structure:
                // `53 82 LL LL 70 82 LL LL <certificate> 71 01 00 FE 00`.
                assert_eq!([0x53, 0x82, 0x04, 0x09, 0x70, 0x82, 0x04, 0x00], object[..8]);
                assert_eq!([0xff; 1024], object[8..1032]);
                assert_eq!([0x71, 0x01, 0x00, 0xFE, 0x00], object[1032..]);
            }

            #[test]
            fn rsa_card_certificate_keeps_the_simple_tlv_length() {
                let mut scard = new_scard();
                scard.state = SCardState::PivAppSelected;

                let object = get_all_available_data(get_data(&mut scard, PIV_CERT_TAG), &mut scard);

                // The Windows inbox PIV minidriver works with this encoding.
                assert_eq!([0x70, 0xFF, 0x04, 0x00], object[4..8]);
            }

            #[test]
            fn ec_card_keeps_the_key_only_in_the_authentication_slot() {
                let mut scard = new_ec_scard();

                assert_eq!(Status::MoreAvailable(0), get_data(&mut scard, PIV_CERT_TAG).status);
                for tag in [DIGITAL_SIGNATURE_CERT_TAG, KEY_MANAGEMENT_CERT_TAG, CARD_AUTH_CERT_TAG] {
                    assert_eq!(Status::NotFound, get_data(&mut scard, tag).status);
                }
            }

            #[test]
            fn ec_card_hides_the_management_key_until_the_pin_is_verified() {
                let mut scard = new_ec_scard();
                scard.state = SCardState::PivAppSelected;

                let response = get_data(&mut scard, PRINTED_INFORMATION_TAG);

                assert_eq!(Status::SecurityStatusNotSatisfied, response.status);
                assert!(response.data.is_none());
            }

            #[test]
            fn ec_card_requires_the_piv_application_selection() {
                let mut scard = new_ec_scard();
                scard.state = SCardState::Ready;

                let response = scard.handle_command(&[0x00, 0x20, 0x00, 0x80, 0x00]).unwrap();
                assert_eq!(Status::InstructionNotSupported, response.status);

                // The minidriver selects the application using the shortened AID.
                let response = scard.handle_command(&SHORT_AID_SELECT).unwrap();
                assert_eq!(Status::OK, response.status);
                assert_eq!(SCardState::PivAppSelected, scard.state);
            }

            #[test]
            fn rsa_card_does_not_accept_the_shortened_aid() {
                let response = new_scard().handle_command(&SHORT_AID_SELECT).unwrap();

                assert_eq!(Status::NotFound, response.status);
            }

            #[test]
            fn management_key_mutual_authentication() {
                let mut scard = new_ec_scard();
                let cipher = management_key(&mut scard);

                // Step 1: the card returns the encrypted witness.
                let response = scard.handle_command(&AUTHENTICATION_REQUEST).unwrap();
                assert_eq!(Status::OK, response.status);
                let witness = response.data.unwrap();
                assert_eq!([0x7C, 0x0A, 0x80, 0x08], witness[..4]);

                let mut decrypted = Array::try_from(&witness[4..]).unwrap();
                cipher.decrypt_block(&mut decrypted);

                // Step 2: the caller proves it knows the key and challenges the card.
                let challenge = [1, 2, 3, 4, 5, 6, 7, 8];
                let response = scard
                    .handle_command(&authentication_response(&decrypted, &challenge))
                    .unwrap();
                assert_eq!(Status::OK, response.status);
                let card_response = response.data.unwrap();
                assert_eq!([0x7C, 0x0A, 0x82, 0x08], card_response[..4]);

                let mut expected = Array::from(challenge);
                cipher.encrypt_block(&mut expected);
                assert_eq!(expected.as_slice(), &card_response[4..]);
            }

            #[test]
            fn management_key_authentication_rejects_wrong_witness() {
                let mut scard = new_ec_scard();

                scard.handle_command(&AUTHENTICATION_REQUEST).unwrap();
                let response = scard
                    .handle_command(&authentication_response(&[0; 8], &[0; 8]))
                    .unwrap();

                assert_eq!(Status::SecurityStatusNotSatisfied, response.status);
            }

            #[test]
            fn ec_card_signs_the_way_the_minidriver_requests() {
                let mut command = vec![0x00, 0x87, 0x11, 0x9A, 0x26, 0x7C, 0x24, 0x82, 0x00, 0x81, 0x20];
                command.extend_from_slice(&[0xA5; 32]);
                command.push(0x00);

                let response = new_ec_scard().handle_command(&command).unwrap();

                assert_eq!(Status::OK, response.status);
                let data = response.data.unwrap();
                assert_eq!(0x7C, data[0]);
                assert_eq!(0x82, data[2]);
            }
        }
    }
}
