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
}

pub type Result<T> = core::result::Result<T, Error>;
