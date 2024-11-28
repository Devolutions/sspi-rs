use std::io::Error as IoError;
use std::num::TryFromIntError;

use num_derive::{FromPrimitive, ToPrimitive};
use uuid::Error as UuidError;

#[derive(Debug, Copy, Clone, Eq, PartialEq, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum ErrorKind {
    Success = 0,
    NteBadFlags = 0x80090009,
    NteInvalidParameter = 0x80090027,
    NteInternalError = 0x8009002D,

    IoError = 1,
    UuidError = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub description: String,
}

impl Error {
    pub fn new(kind: ErrorKind, description: impl Into<String>) -> Self {
        Self {
            kind,
            description: description.into(),
        }
    }
}

pub type DpapiResult<T> = Result<T, Error>;

impl From<IoError> for Error {
    fn from(err: IoError) -> Self {
        Self {
            kind: ErrorKind::IoError,
            description: err.to_string(),
        }
    }
}

impl From<UuidError> for Error {
    fn from(err: UuidError) -> Self {
        Self {
            kind: ErrorKind::UuidError,
            description: err.to_string(),
        }
    }
}

impl From<TryFromIntError> for Error {
    fn from(err: TryFromIntError) -> Self {
        Self {
            kind: ErrorKind::NteInternalError,
            description: err.to_string(),
        }
    }
}
