use alloc::string::String;
use alloc::vec::Vec;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("UUID error: {0}")]
    Uuid(#[from] uuid::Error),

    #[error(transparent)]
    IntConversion(#[from] core::num::TryFromIntError),

    #[error(transparent)]
    Bind(#[from] crate::rpc::BindError),

    #[error("provided buf contains invalid UTF-8 data")]
    Utf8(#[from] alloc::string::FromUtf8Error),

    #[error(transparent)]
    Pdu(#[from] crate::rpc::PduError),

    #[error(transparent)]
    Command(#[from] crate::rpc::CommandError),

    #[error(transparent)]
    Epm(#[from] crate::rpc::EpmError),

    #[error(transparent)]
    Gkdi(#[from] crate::gkdi::GkdiError),

    #[error("{0}")]
    FromUtf16(String),

    #[error("invalid {name} magic bytes")]
    InvalidMagic {
        name: &'static str,
        expected: &'static [u8],
        actual: Vec<u8>,
    },

    #[error("invalid {name} length: expected at least {expected} bytes but got {actual}")]
    InvalidLength {
        name: &'static str,
        expected: usize,
        actual: usize,
    },
}

impl From<alloc::string::FromUtf16Error> for Error {
    fn from(err: alloc::string::FromUtf16Error) -> Self {
        use crate::alloc::string::ToString;

        Self::FromUtf16(err.to_string())
    }
}

pub type Result<T> = core::result::Result<T, Error>;
