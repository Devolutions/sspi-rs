use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error")]
    Io(#[from] std::io::Error),

    #[error("UUID error: {0}")]
    Uuid(#[from] uuid::Error),

    #[error(transparent)]
    IntConversion(#[from] std::num::TryFromIntError),

    #[error("provided buf contains invalid UTF-8 data")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("invalid context result code value: {0}")]
    InvalidContextResultCode(u16),

    #[error("invalid integer representation value: {0}")]
    InvalidIntRepr(u8),

    #[error("invalid character representation value: {0}")]
    InvalidCharacterRepr(u8),

    #[error("invalid floating point representation value: {0}")]
    InvalidFloatingPointRepr(u8),

    #[error("invalid packet type value: {0}")]
    InvalidPacketType(u8),

    #[error("invalid packet flags value: {0}")]
    InvalidPacketFlags(u8),

    #[error("invalid security provider value: {0}")]
    InvalidSecurityProvider(u8),

    #[error("invalid authentication level value: {0}")]
    InvalidAuthenticationLevel(u8),

    #[error("invalid fault flags value: {0}")]
    InvalidFaultFlags(u8),

    #[error("{0:?} PDU is not supported")]
    PduNotSupported(crate::rpc::pdu::PacketType),

    #[error("invalid fragment (PDU) length: {0}")]
    InvalidFragLength(u16),
}

pub type DpapiResult<T> = Result<T, Error>;
