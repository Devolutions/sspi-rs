#![cfg_attr(not(feature = "std"), no_std)]

mod helpers;

extern crate alloc;

mod scard_context;
pub mod winscard;

use alloc::string::String;
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
        let cmd = match self.pending_command.as_mut() {
            Some(chained) => {
                chained.extend_from_command(&cmd).map_err(|_| {
                    Error::new(
                        ErrorKind::MalformedRequest,
                        "Error: an error happened while trying to build a chained APDU command",
                    )
                })?;
                if cmd.class().chain().not_the_last() {
                    return Ok(Response::new(Status::OK, None));
                } else {
                    self.pending_command.take().unwrap()
                }
            }
            None => cmd,
        };
        if self.state == SCardState::Ready && cmd.instruction() != Instruction::Select {
            // if the application wasn't selected, only the SELECT command can be used
            return Ok(Response::new(Status::NotFound, None));
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
        unimplemented!();
    }

    fn get_data(&mut self, cmd: Command<1024>) -> Result<Response> {
        unimplemented!();
    }

    fn get_response(&mut self) -> Result<Response> {
        unimplemented!();
    }

    fn general_authenticate(&self, cmd: Command<1024>) -> Result<Response> {
        unimplemented!();
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

#[derive(Debug)]
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

#[derive(PartialEq)]
pub enum SCardState {
    Ready,
    PivAppSelected,
    PinVerified,
    TransactionInProgress,
}

#[derive(Debug, Clone)]
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
}
