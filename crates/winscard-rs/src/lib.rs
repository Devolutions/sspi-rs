#![cfg_attr(not(feature = "std"), no_std)]

mod ber_tlv;
mod card_capability_container;
mod chuid;
mod compression;
mod piv_cert;
mod scard;
mod scard_context;
pub mod tlv_tags;
pub mod winscard;

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::{fmt, result};

pub use ber_tlv::ber_tlv_length_encoding;
use iso7816_tlv::TlvError;
use picky::key::KeyError;
pub use scard::{SmartCard, PIV_AID};
pub use scard_context::{Reader, ScardContext};

pub type WinScardResult<T> = result::Result<T, Error>;

#[derive(Debug)]
pub struct Response {
    pub status: Status,
    pub data: Option<Vec<u8>>,
}

impl Response {
    pub fn new(status: Status, data: Option<Vec<u8>>) -> Self {
        Response { status, data }
    }
}

impl From<Status> for Response {
    fn from(value: Status) -> Self {
        Response::new(value, None)
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
            ErrorKind::InternalError,
            format!("error: an unexpected KeyError happened: {}", value),
        )
    }
}

impl From<TlvError> for Error {
    fn from(value: TlvError) -> Self {
        Error::new(
            ErrorKind::InternalError,
            format!("error: an unexpected TlvError happened: {}", value),
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

impl From<ErrorKind> for u32 {
    fn from(value: ErrorKind) -> Self {
        value as u32
    }
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

// ISO/IEC 7816-4, Section 5.1.3, Tables 5-6
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
