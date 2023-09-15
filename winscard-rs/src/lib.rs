#![cfg_attr(not(feature = "std"), no_std)]

mod helpers;

extern crate alloc;

mod scard_context;
pub mod winscard;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
use core::{fmt, result};

use helpers::{build_auth_cert, build_chuid, tlv_tags};
use iso7816::{Aid, Command, Instruction};
use iso7816_tlv::ber::{Tag, Tlv, Value};
use iso7816_tlv::TlvError;
use picky::key::{KeyError, PrivateKey};
pub use scard_context::{Reader, ScardContext};
use tracing::error;

pub const PIV_AID: Aid = Aid::new_truncatable(&[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00], 9);
const CHUNK_SIZE: usize = 256;

pub type Result<T> = result::Result<T, Error>;

pub struct SmartCard {
    // chuid will always have a fixed length when excluding optional fields and asymmetric signature
    chuid: [u8; 61],
    pin: Vec<u8>,
    auth_cert: Vec<u8>,
    auth_pk: PrivateKey,
    state: SCardState,
    pending_command: Option<Command<1024>>,
    pending_response: Option<(Vec<u8>, usize)>,
}

impl SmartCard {
    pub fn new(pin: Vec<u8>, auth_cert_der: Vec<u8>, auth_pk_pem: &str) -> Result<Self> {
        let chuid = build_chuid();
        let auth_cert = build_auth_cert(auth_cert_der)?;
        let auth_pk = PrivateKey::from_pem_str(auth_pk_pem)?;
        if !(6..=8).contains(&pin.len()) {
            return Err(Error::new(
                ErrorKind::InvalidPin,
                "PIN should be no shorter than 6 bytes and no longer than 8",
            ));
        }
        Ok(SmartCard {
            chuid,
            pin,
            auth_cert,
            auth_pk,
            state: SCardState::Ready,
            pending_command: None,
            pending_response: None,
        })
    }

    pub fn handle_command(&mut self, data: Vec<u8>) -> Result<Response> {
        let cmd = Command::<1024>::try_from(&data).map_err(|e| {
            error!("APDU command parsing error: {:?}", e);
            Error::new(
                ErrorKind::MalformedRequest,
                format!("Error: an error happened while parsing an APDU command: {:?}", e),
            )
        })?;
        let cmd = if let Some(mut chained) = self.pending_command.take() {
                chained.extend_from_command(&cmd).map_err(|_| {
                    Error::new(
                        ErrorKind::MalformedRequest,
                        "Error: an error happened while trying to build a chained APDU command",
                    )
                })?;
            chained
                } else {
            cmd
        };
        if cmd.class().chain().not_the_last() {
            self.pending_command = Some(cmd);
            return Ok(Response::new(Status::OK, None));
        }
        if self.state == SCardState::Ready && cmd.instruction() != Instruction::Select {
            // if the application wasn't selected, only the SELECT command can be used
            return Ok(Response::new(Status::NotFound, None));
        } else if self.state == SCardState::PivAppSelected && cmd.instruction() == Instruction::GeneralAuthenticate {
            // GENERAL AUTHENTICATE can only be used if the smart card has already been unlocked using the PIN code
            return Ok(Response::new(Status::SecurityStatusNotSatisfied, None));
        }
        match cmd.instruction() {
            Instruction::Select => self.select(cmd),
            Instruction::GetData => self.get_data(cmd),
            Instruction::Verify => self.verify(cmd),
            Instruction::GeneralAuthenticate => self.general_authenticate(cmd),
            Instruction::GetResponse => self.get_response(),
            _ => {
                error!("unimplemented instruction {:?}", cmd.instruction());
                Ok(Response::new(Status::InstructionNotSupported, None))
            }
        }
    }

    fn select(&self, cmd: Command<1024>) -> Result<Response> {
        if cmd.p1 != 0x04 || cmd.p2 != 0x00 || !PIV_AID.matches(cmd.data()) {
            return Ok(Response::new(Status::NotFound, None));
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
        Ok(Response::new(Status::OK, Some(data.to_vec())))
    }

    fn verify(&mut self, cmd: Command<1024>) -> Result<Response> {
        if (cmd.p1 != 0x00 && cmd.p1 != 0xFF) || (cmd.p1 == 0xFF && !cmd.data().is_empty()) {
            return Ok(Response::new(Status::IncorrectP1orP2, None));
        }
        if cmd.p2 != 0x80 {
            return Ok(Response::new(Status::KeyReferenceNotFound, None));
        }
        match cmd.p1 {
            0x00 => {
                // PIN was already verified -> return OK
                if self.state != SCardState::PinVerified {
                    if !cmd.data().is_empty() && !(6..=8).contains(&cmd.data().len()) {
                        // Incorrect PIN length -> do not proceed and return an error
                        return Ok(Response::new(Status::IncorrectDataField, None));
                    }
                    // Retrieve the number of further allowed retries if the data field is absent
                    // Otherwise just compare the provided PIN with the stored one
                    if cmd.data().is_empty() || cmd.data() != self.pin.as_slice() {
                        return Ok(Response::new(Status::VerificationFailedWithRetries, None));
                    } else {
                        // data field is present and the provided PIN is correct -> change state and return OK
                        self.state = SCardState::PinVerified;
                    }
                }
            }
            0xFF => {
                // p1 is 0xFF and the data field is absent -> reset the security status and return OK
                self.state = SCardState::PivAppSelected;
            }
            _ => unreachable!(),
        };
        Ok(Response::new(Status::OK, None))
    }

    fn get_data(&mut self, cmd: Command<1024>) -> Result<Response> {
        if cmd.p1 != 0x3F || cmd.p2 != 0xFF {
            return Ok(Response::new(Status::IncorrectP1orP2, None));
        }
        let request = Tlv::from_bytes(cmd.data())?;
        if request.tag() != &Tag::try_from(tlv_tags::TAG_LIST)? {
            return Ok(Response::new(Status::NotFound, None));
        }
        match request.value() {
            Value::Primitive(tag) => match tag.as_slice() {
                [0x5F, 0xC1, 0x02] => Ok(Response::new(Status::OK, Some(self.chuid.to_vec()))),
                [0x5F, 0xC1, 0x05] => {
                    // certificate is almost certainly longer than 256 bytes, so we can just set a pending response and call the GET RESPONSE handler
                    self.pending_response = Some((self.auth_cert.clone(), 0));
                    self.get_response()
                }
                _ => Ok(Response::new(Status::NotFound, None)),
            },
            Value::Constructed(_) => Ok(Response::new(Status::NotFound, None)),
        }
    }

    fn get_response(&mut self) -> Result<Response> {
        match self.get_next_response_chunk() {
            Some((chunk, bytes_left)) => {
                let chunk = chunk.to_vec();
                let status = if bytes_left == 0 {
                    self.pending_response = None;
                    Status::OK
                } else if bytes_left < CHUNK_SIZE {
                    // conversion is safe as we know that bytes_left isn't bigger than 256
                    Status::MoreAvailable(bytes_left as u8)
                } else {
                    // 0 indicates that we have 256 or more bytes left to be read
                    Status::MoreAvailable(0)
                };
                Ok(Response::new(status, Some(chunk)))
            }
            None => Ok(Response::new(Status::NotFound, None)),
        }
    }

    fn general_authenticate(&mut self, cmd: Command<1024>) -> Result<Response> {
        if cmd.p1 != 0x07 || cmd.p2 != 0x9A {
            return Err(Error::new(
                ErrorKind::UnsupportedFeature,
                format!("Provided algorithm or key reference isn't supported: got algorithm {}, expected 0x07; got key reference {}, expected 0x9A", cmd.p1, cmd.p2)
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
        let challenge = inner_tlv
            .iter()
            .find(|&tlv| tlv.tag() == &challenge_tag)
            .ok_or(Error::new(
                ErrorKind::InvalidValue,
                "TLV structure is invalid: no challenge field is present in the request".to_string(),
            ))?;
        let challenge = match challenge.value() {
            Value::Primitive(challenge) => challenge.clone(),
            Value::Constructed(_) => {
                // this tag must contain a primitive value
                return Err(Error::new(
                    ErrorKind::InvalidValue,
                    "TLV structure is invalid: challenge field contains constructed value".to_string(),
                ));
            }
        };
        let signed_challenge = self.auth_pk.sign_hashed_rsa(challenge)?;
        let response = Tlv::new(
            Tag::try_from(tlv_tags::DYNAMIC_AUTHENTICATION_TEMPLATE)?,
            Value::Constructed(vec![Tlv::new(
                Tag::try_from(tlv_tags::DAT_RESPONSE)?,
                Value::Primitive(signed_challenge),
            )?]),
        )?
        .to_vec();
        self.pending_response = Some((response, 0));
        self.get_response()
    }

    fn get_next_response_chunk(&mut self) -> Option<(&[u8], usize)> {
        if let Some((ref vec, ref mut current_index)) = self.pending_response {
            if *current_index == vec.len() {
                return None;
            }
            let next_index = *current_index + CHUNK_SIZE.min(vec.len() - *current_index);
            let chunk = &vec[*current_index..next_index];
            let bytes_left = if next_index != vec.len() {
                // update the index if there is still data left
                *current_index = next_index;
                vec.len() - next_index
            } else {
                0
            };
            Some((chunk, bytes_left))
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct Response {
    status: Status,
    data: Option<Vec<u8>>,
}

impl Response {
    pub fn new(status: Status, data: Option<Vec<u8>>) -> Self {
        Response { status, data }
    }
}

impl From<Response> for Vec<u8> {
    fn from(value: Response) -> Self {
        let status_as_bytes: [u8; 2] = value.status.into();
        let vec_capacity = status_as_bytes.len() + value.data.as_ref().map(|data| data.len()).unwrap_or(0);
        let mut encoded: Vec<u8> = Vec::with_capacity(vec_capacity);
        if let Some(bytes) = value.data {
            encoded.extend(bytes);
        }
        encoded.extend(status_as_bytes);
        encoded
    }
}

#[derive(Debug)]
pub struct Error {
    pub error_kind: ErrorKind,
    pub description: String,
}

impl Error {
    pub fn new(error_kind: ErrorKind, description: impl Into<String>) -> Self {
        Error {
            error_kind,
            description: description.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.error_kind, self.description)?;
        Ok(())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<KeyError> for Error {
    fn from(value: KeyError) -> Self {
        Error::new(
            ErrorKind::KeyError,
            format!("Error while parsing a PEM-encoded private key: {}", value),
        )
    }
}

impl From<TlvError> for Error {
    fn from(value: TlvError) -> Self {
        Error::new(
            ErrorKind::TlvError,
            format!(
                "Error while trying to build or parse a TLV-encoded value or tag: {}",
                value
            ),
        )
    }
}

#[derive(Debug, PartialEq)]
#[repr(u32)]
pub enum ErrorKind {
    BrokenPipe = 0x00000109,
    BadSeek = 0x80100029,
    Canceled = 0x80100002,
    CantDispose = 0x8010000E,
    CardUnsupported = 0x8010001C,
    CertificateUnavailable = 0x8010002D,
    CommDataLost = 0x8010002F,
    DirNotFound = 0x80100023,
    DuplicateReader = 0x8010001B,
    FileNotFound = 0x80100024,
    IccCreateOrder = 0x80100021,
    IccInstallation = 0x80100020,
    InsufficientBuffer = 0x80100008,
    InvalidAtr = 0x80100015,
    InvalidChv = 0x8010002A,
    InvalidHandle = 0x80100003,
    InvalidParameter = 0x80100004,
    InvalidTarget = 0x80100005,
    InvalidValue = 0x80100011,
    NoAccess = 0x80100027,
    NoDir = 0x80100025,
    NoFile = 0x80100026,
    NoKeyContainer = 0x80100030,
    NoMemory = 0x80100006,
    NoPinCache = 0x80100033,
    NoReadersAvailable = 0x8010002E,
    NoService = 0x8010001D,
    NoSmartCard = 0x8010000C,
    NoSuchCertificate = 0x8010002C,
    NotReady = 0x80100010,
    NotTransacted = 0x80100016,
    PciTooSmall = 0x80100019,
    PinCacheExpired = 0x80100032,
    ProtoMismatch = 0x8010000F,
    ReadOnlyCard = 0x80100034,
    ReaderUnavailable = 0x80100017,
    ReaderUnsupported = 0x8010001A,
    ServerTooBusy = 0x80100031,
    ServiceStopped = 0x8010001E,
    SharingViolation = 0x8010000B,
    SystemCanceled = 0x80100012,
    Timeout = 0x8010000A,
    Unexpected = 0x8010001F,
    UnknownCard = 0x8010000D,
    UnknownReader = 0x80100009,
    UnknownResMng = 0x8010002B,
    UnsupportedFeature = 0x80100022,
    WriteTooMany = 0x80100028,
    CommError = 0x80100013,
    InternalError = 0x80100001,
    UnknownError = 0x80100014,
    WaitedTooLong = 0x80100007,
    Shutdown = 0x80100018,
    Success = 0,
    CanceledByUser = 0x8010006E,
    CacheItemNotFound = 0x80100070,
    CacheItemStale = 0x80100071,
    CacheItemTooBig = 0x80100072,
    CardNotAuthenticated = 0x8010006F,
    ChvBlocked = 0x8010006C,
    Eof = 0x8010006D,
    RemovedCard = 0x80100069,
    ResetCard = 0x80100068,
    SecurityViolation = 0x8010006A,
    UnpoweredCard = 0x80100067,
    UnresponsiveCard = 0x80100066,
    UnsupportedCard = 0x80100065,
    WrongChv = 0x8010006B,
}

#[derive(Debug, PartialEq)]
pub enum SCardState {
    Ready,
    PivAppSelected,
    PinVerified,
    TransactionInProgress,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    NotFound,
    OK,
    // number of allowed retries is always 9
    VerificationFailedWithRetries,
    MoreAvailable(u8),
    KeyReferenceNotFound,
    SecurityStatusNotSatisfied,
    IncorrectP1orP2,
    IncorrectDataField,
    InstructionNotSupported,
}

impl From<Status> for [u8; 2] {
    fn from(value: Status) -> Self {
        match value {
            Status::NotFound => [0x6A, 0x82],
            Status::OK => [0x90, 0x00],
            Status::VerificationFailedWithRetries => [0x63, 0xC9],
            Status::MoreAvailable(bytes_left) => [0x61, bytes_left],
            Status::KeyReferenceNotFound => [0x6A, 0x88],
            Status::SecurityStatusNotSatisfied => [0x69, 0x82],
            Status::IncorrectP1orP2 => [0x6A, 0x86],
            Status::IncorrectDataField => [0x6A, 0x80],
            Status::InstructionNotSupported => [0x6D, 0x00],
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    pub use super::*;

    #[cfg(feature = "proptest")]
    mod proptests {
        use proptest::prelude::*;
        use proptest::{collection, option, prop_compose};

        use super::*;

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
    }

    fn new_scard() -> SmartCard {
        let rsa_2048_private_key = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAiJ/d1/2d1CQYlJfZ02TOH7F/5U53a6IZc8QwTQEsBQbVGfQO
RN/+b09NzJJZmtyuLdBAXLzP8lEzKcfgn4JNl5G7DuKOxRreE5tq8uA+j2SQCw7m
Sm6todEOvkWG5Dov3Q9QnlPbvqp871pfbRsfKwOo2RxJIjbjpM5FQnlqOd+3gu2I
TF8dt+/PY+wl1w6kPTUZg/mzElY95WSnOE9bFlHcVL//Sl3caW85AB0lLUbd96b/
7PMO6IWJQyvS0ssG0emcyQYllvvSCFSpVWA/e1EGzKrwbtG1Xn9je5L4mIKiSw/p
gbjnYE9g+pibLJNobBBLkzGdo/KzyCQbMWirkQIDAQABAoIBAEbAm28mXNymkMAq
31g1BPWuwy/p8bggqxOjjuvh5nz369XT6KvMYAQeyohdZd/n1p/ND/e2o+22FUvW
wcF5Bluu0XNE6nCymD0JKFp8vIkfp+TCI4p6RJrfG8Z3VQLOC0lsi/BiNxNHUQnX
AEINYJey/nboygrY6AzJ8V4aaGNtbtnz7tfyALJHUK0qRa+AmyLCzaZR5RSbDgB5
srCX9J5OCxH2s5tVSfqg48Z0RIiBcDFPYbJDakZWLRNLD8ByW3e0jEFDA1vQPsaj
CsyY4E6UZwYNZemC60zW0e8BYJYnOAhcmwaYnaxvL5xy0aW5pUGr+FgnO4NrNr33
pKT2eFECgYEA2LJdjjFGdTsuW8esbTn+9hGyNnUR9gxYGdNhcINhPHMhoR8GkakC
5sLOlpgCDpdzHDduW2GjhIAUnXt50yZNpkXQuSWdjucbYGc2G5ySc8eHaP+5tHAr
svyZBchE+Kf4p2nNoXoQxsgxY2Qgz/ctUgCR7SnbgRW0cHDH7HIXlJ0CgYEAoWeY
rt2q8PFW3sEWy1RK0dxD+7UnuN76x5rd0IUxi2HS5F4tyfiDy3LgVs0XJqF9IN6K
IQ7pX/0C1g91NbUl8pAnu+k7R/CiynqGAmQumkMscIRO4VoR+v3+Hta9NV6sy/0U
fDfQSK9AnrFXGCpHPLC+YrmgbVnKqJ526vBxboUCgYEAvx4pJ0TMWI62p1nm+HrD
JLGc1SzRh4mBll15PeuRsef1DA66E3PVzEKaQ/WTMt1eN8+ntE7cEfuIsxB49MJ+
j5xZp0HGwYeQ/Khq71VbUWP0SKXqWnrn/7eLGq90LT6wLq9BHh7zdu6PqJJh4iml
vgIkseBN6X6EIvtFSIOjyn0CgYBRvEiRpSd/xHedbmLArPsGs2ip+t8Wu7R7iG1z
vz+Lugo2I4tEkFkNmisJSerDYVwgXRHOE+MS/OmGxWUxwX5qC55ThpTCpZWKu+lJ
JLqE3CeRAy9+50HbvOwHae9/K2aOFqddEFaluDodIulcD2zrywVesWoQdjwuj7Dg
4MpQkQKBgA4vlTf+n8kpOJWls2YMyZaauY48xcNzDdhpBGFCjVm+aiKX5dyIjAQK
9LX8/iVau8ZRM+qSLpuEP+o8qGR11TbGZrLH/wITc7r9cWnaGDsozmPAnxMcu1zz
9IRTY9zr9QWzxGiSqr834q5IZIQ/5uDBW/857MP0bpMl6cTdxzg0
-----END RSA PRIVATE KEY-----";
        let certificate_stub = vec![0xff; 1024];
        let pin = vec![0xA9; 8];
        SmartCard::new(pin, certificate_stub, rsa_2048_private_key).unwrap()
    }

    #[test]
    fn scard_invalid_apdu_command() {
        let mut scard = new_scard();
        let bad_apdu_command = vec![0x00; 2048];
        let response = scard.handle_command(bad_apdu_command);
        assert!(response.is_err_and(|err| err.error_kind == ErrorKind::InternalError
            && err
                .description
                .contains("Error: an error happened while parsing an APDU command")));
    }

    #[test]
    fn scard_wrong_command_order() {
        // Try to issue a verify command when no app was selected
        let mut scard = new_scard();
        let mut apdu_verify_cmd = vec![0x00, 0x20, 0x00, 0x80, 0x08];
        // add pin
        apdu_verify_cmd.extend_from_slice(&[0xA9; 8]);
        let response = scard.handle_command(apdu_verify_cmd);
        assert!(response.is_ok_and(|resp| resp.status == Status::NotFound));
    }

    #[test]
    fn scard_invalid_select_command() {
        // Try to issue a SELECT command with unsupported AID
        let mut scard = new_scard();
        let mut apdu_select_cmd = vec![0x00, 0xA4, 0x04, 0x00, 0x0B];
        let bad_aid = vec![0xff; 11];
        apdu_select_cmd.extend_from_slice(&bad_aid);
        let response = scard.handle_command(apdu_select_cmd);
        assert!(response.is_ok_and(|resp| resp.status == Status::NotFound));
    }

    #[test]
    fn scard_select_command() {
        // Verify that the SELECT command works as expected and returns expected output
        let mut expected_response = vec![
            0x61, 0x17, 0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x0D, 0x4F, 0x0B,
        ];
        expected_response.extend_from_slice(&PIV_AID);

        let mut scard = new_scard();
        let mut apdu_select_cmd = vec![0x00, 0xA4, 0x04, 0x00, 0x0B];
        apdu_select_cmd.extend_from_slice(&PIV_AID);
        let response = scard.handle_command(apdu_select_cmd);
        assert!(response.is_ok_and(
            |resp| resp.status == Status::OK && resp.data.expect("Data should be present") == expected_response
        ));
    }

    #[test]
    fn scard_unsupported_command() {
        // Try to issue an RESET RETRY COUNTER command that the app doesn't support
        let mut scard = new_scard();
        // we set this manually to avoid issuing a SELECT command every time
        scard.state = SCardState::PivAppSelected;
        let apdu_reset_retry_cmd = vec![0x00, 0x2C, 0x00, 0x80, 0x00];
        let response = scard.handle_command(apdu_reset_retry_cmd);
        assert!(response.is_ok_and(|resp| resp.status == Status::InstructionNotSupported));
    }

    #[test]
    fn scard_invalid_verify_commands() {
        // Verify that the VERIFY command handler correctly handles badly structured or malformed requests
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // p1 can only be 0x00 or 0xFF
        let apdu_verify_bad_p1 = vec![0x00, 0x20, 0xAA, 0x80, 0x00];
        let response = scard.handle_command(apdu_verify_bad_p1);
        assert!(response.is_ok_and(|resp| resp.status == Status::IncorrectP1orP2));

        // if p1 is 0xFF, the data field should be empty
        let apdu_verify_bad_p1_data = vec![0x00, 0x20, 0xFF, 0x80, 0x02, 0xFF, 0xFF];
        let response = scard.handle_command(apdu_verify_bad_p1_data);
        assert!(response.is_ok_and(|resp| resp.status == Status::IncorrectP1orP2));

        // p2 should always be 0x80
        let apdu_verify_bad_p2 = vec![0x00, 0x20, 0x00, 0x81, 0x02, 0xFF, 0xFF];
        let response = scard.handle_command(apdu_verify_bad_p2);
        assert!(response.is_ok_and(|resp| resp.status == Status::KeyReferenceNotFound));

        // PIN should be no shorter than six bytes and no longer than 8
        let apdu_verify_bad_pin = vec![0x00, 0x20, 0x00, 0x80, 0x02, 0xAA, 0xAA];
        let response = scard.handle_command(apdu_verify_bad_pin);
        assert!(response.is_ok_and(|resp| resp.status == Status::IncorrectDataField));
    }

    #[test]
    fn scard_verify_command() {
        // Verify that the VERIFY command handler correctly handles all supported types of requests
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // retrieve number of allowed retries by omitting the data field
        let apdu_verify_no_data = vec![0x00, 0x20, 0x00, 0x80, 0x00];
        let response = scard.handle_command(apdu_verify_no_data);
        assert!(response.is_ok_and(|resp| resp.status == Status::VerificationFailedWithRetries));

        // VERIFY command with the wrong PIN code
        let mut apdu_verify_wrong_pin = vec![0x00, 0x20, 0x00, 0x80, 0x08];
        apdu_verify_wrong_pin.extend_from_slice(&[0xCC; 8]);
        let response = scard.handle_command(apdu_verify_wrong_pin);
        assert!(response.is_ok_and(|resp| resp.status == Status::VerificationFailedWithRetries));

        // VERIFY command with the correct PIN code
        let mut apdu_verify_correct_pin = vec![0x00, 0x20, 0x00, 0x80, 0x08];
        apdu_verify_correct_pin.extend_from_slice(&[0xA9; 8]);
        let response = scard.handle_command(apdu_verify_correct_pin);
        assert!(response.is_ok_and(|resp| resp.status == Status::OK));
        assert_eq!(scard.state, SCardState::PinVerified);

        // Reset the security status
        let apdu_verify_reset = vec![0x00, 0x20, 0xFF, 0x80, 0x00];
        let response = scard.handle_command(apdu_verify_reset);
        assert!(response.is_ok_and(|resp| resp.status == Status::OK));
        assert_eq!(scard.state, SCardState::PivAppSelected);
    }

    #[test]
    fn scard_invalid_get_data_command() {
        // Verify that the GET DATA handler correctly handles invalid requests
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // p1 should always be 0x3F; p2 should always be 0xFF
        let apdu_get_data_bad_p1_p2 = vec![0x00, 0xCB, 0x10, 0x21, 0x00];
        let response = scard.handle_command(apdu_get_data_bad_p1_p2);
        assert!(response.is_ok_and(|resp| resp.status == Status::IncorrectP1orP2));

        // bad object tag in the data field
        let apdu_get_data_bad_tag = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x08];
        let response = scard.handle_command(apdu_get_data_bad_tag);
        assert!(response.is_ok_and(|resp| resp.status == Status::NotFound));
    }

    #[test]
    fn scard_get_data_command() {
        // Verify that the GET DATA handler correctly handles all supported requests and returns correct data
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // get CHUID
        let apdu_get_data_chuid = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x02];
        let response = scard.handle_command(apdu_get_data_chuid);
        assert!(
            response.is_ok_and(|resp| resp.status == Status::OK && resp.data.expect("Expected CHUID") == scard.chuid)
        );

        // get PIV authentication certificate
        let apdu_get_data_chuid = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05];
        let response = scard.handle_command(apdu_get_data_chuid);
        // verify the contents
        assert!(response.is_ok_and(|mut resp| {
            // as the certificate is larger than 256 bytes, we have to call the GET RESPONSE function a few times
            let mut complete_response = vec![];
            while let Status::MoreAvailable(bytes_left) = resp.status {
                complete_response.extend_from_slice(&resp.data.expect("Data should be present"));
                let apdu_get_response = vec![0x00, 0xC0, 0x00, 0x00, bytes_left];
                resp = scard
                    .handle_command(apdu_get_response)
                    .expect("Can't retrieve all available data");
            }
            assert_eq!(resp.status, Status::OK);
            // append the last chunk of data
            complete_response.extend_from_slice(&resp.data.expect("Can't get the last chunk of data"));
            complete_response == scard.auth_cert
        }));
    }
}
