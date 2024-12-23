use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0:?}")]
    Io(#[from] std::io::Error),

    #[error("UUID error: {0:?}")]
    Uuid(#[from] uuid::Error),

    #[error("Integer conversion error: {0:?}")]
    IntegerConversion(#[from] std::num::TryFromIntError),

    #[error("Provided buf contains invalid UTF-8 data: {0:?}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("Invalid context result code value: {0}")]
    InvalidContextResultCode(u16),

    #[error("Invalid integer representation value: {0}")]
    InvalidIntegerRepresentation(u8),

    #[error("Invalid character representation value: {0}")]
    InvalidCharacterRepresentation(u8),

    #[error("Invalid floating point representation value: {0}")]
    InvalidFloatingPointRepresentation(u8),

    #[error("Invalid packet type value: {0}")]
    InvalidPacketType(u8),

    #[error("Invalid packet flags value: {0}")]
    InvalidPacketFlags(u8),

    #[error("Invalid security provider value: {0}")]
    InvalidSecurityProvider(u8),

    #[error("Invalid authentication level value: {0}")]
    InvalidAuthenticationLevel(u8),

    #[error("Invalid fault flags value: {0}")]
    InvalidFaultFlags(u8),

    #[error("{0:?} PDU is not supported")]
    PduNotSupported(crate::rpc::pdu::PacketType),
}

pub type DpapiResult<T> = Result<T, Error>;
