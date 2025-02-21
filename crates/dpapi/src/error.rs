use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
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

    #[error("invalid {name} url: {url}")]
    InvalidUrl {
        name: &'static str,
        url: String,
        error: url::ParseError,
    },

    #[error(transparent)]
    Gkdi(#[from] crate::gkdi::GkdiError),

    #[error(transparent)]
    Blob(#[from] crate::blob::BlobError),

    #[error(transparent)]
    Rpc(#[from] crate::rpc::RpcError),

    #[error(transparent)]
    Sid(#[from] crate::sid::SidError),

    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),

    #[error(transparent)]
    RpcClient(#[from] crate::rpc::client::RpcClientError),

    #[error(transparent)]
    Command(#[from] crate::rpc::verification::CommandError),

    #[error(transparent)]
    Auth(#[from] crate::rpc::auth::AuthError),

    #[error(transparent)]
    Epm(#[from] crate::epm::EpmError),

    #[error(transparent)]
    Client(#[from] crate::client::ClientError),

    #[error("IO error")]
    Io(#[from] std::io::Error),

    #[error("UUID error: {0}")]
    Uuid(#[from] uuid::Error),

    #[error(transparent)]
    IntConversion(#[from] std::num::TryFromIntError),

    #[error("provided buf contains invalid UTF-8 data")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("{description}: {value}: {error}")]
    ParseInt {
        description: &'static str,
        value: String,
        error: std::num::ParseIntError,
    },

    #[error(transparent)]
    Asn1(#[from] picky_asn1_der::Asn1DerError),

    #[error(transparent)]
    CharSet(#[from] picky_asn1::restricted_string::CharSetError),

    #[error("{0}")]
    FromUtf16(String),
}

impl From<std::string::FromUtf16Error> for Error {
    fn from(err: std::string::FromUtf16Error) -> Self {
        Self::FromUtf16(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
