use std::fmt;
use std::mem::take;

use crate::{Error, ErrorKind, SecurityBufferType};

/// A special security buffer type is used for the data decryption. Basically, it's almost the same
/// as [SecurityBuffer] but for decryption.
///
/// [DecryptMessage](https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--general)
/// "The encrypted message is decrypted in place, overwriting the original contents of its buffer."
///
/// So, the already defined [SecurityBuffer] is not suitable for decryption because it uses [Vec] inside.
/// We use reference in the [DecryptionBuffer] structure to avoid data cloning as much as possible.
/// Decryption input buffers can be very large. Even up to 32 KiB if we are using this crate as a CREDSSP security package.
pub enum DecryptBuffer<'data> {
    Data(&'data mut [u8]),
    Token(&'data mut [u8]),
    StreamHeader(&'data mut [u8]),
    StreamTrailer(&'data mut [u8]),
    Stream(&'data mut [u8]),
    Extra(&'data mut [u8]),
    Missing(usize),
    Empty,
}

impl<'data> DecryptBuffer<'data> {
    /// Created a [DecryptBuffer] from based on provided [SecurityBufferType].
    ///
    /// Inner buffers will be empty.
    pub fn with_security_buffer_type(security_buffer_type: SecurityBufferType) -> crate::Result<Self> {
        match security_buffer_type {
            SecurityBufferType::Empty => Ok(DecryptBuffer::Empty),
            SecurityBufferType::Data => Ok(DecryptBuffer::Data(&mut [])),
            SecurityBufferType::Token => Ok(DecryptBuffer::Token(&mut [])),
            SecurityBufferType::Missing => Ok(DecryptBuffer::Missing(0)),
            SecurityBufferType::Extra => Ok(DecryptBuffer::Extra(&mut [])),
            SecurityBufferType::StreamTrailer => Ok(DecryptBuffer::StreamTrailer(&mut [])),
            SecurityBufferType::StreamHeader => Ok(DecryptBuffer::StreamHeader(&mut [])),
            SecurityBufferType::Stream => Ok(DecryptBuffer::Stream(&mut [])),
            _ => Err(Error::new(ErrorKind::UnsupportedFunction, "")),
        }
    }

    /// Creates a new [DecryptBuffer] with the provided buffer data saving the old buffer type.
    ///
    /// *Attention*: the buffer type must not be [SecurityBufferType::Missing].
    pub fn with_data(self, data: &'data mut [u8]) -> crate::Result<Self> {
        Ok(match self {
            DecryptBuffer::Data(_) => DecryptBuffer::Data(data),
            DecryptBuffer::Token(_) => DecryptBuffer::Token(data),
            DecryptBuffer::StreamHeader(_) => DecryptBuffer::StreamHeader(data),
            DecryptBuffer::StreamTrailer(_) => DecryptBuffer::StreamTrailer(data),
            DecryptBuffer::Stream(_) => DecryptBuffer::Stream(data),
            DecryptBuffer::Extra(_) => DecryptBuffer::Extra(data),
            DecryptBuffer::Missing(_) => {
                return Err(Error::new(
                    ErrorKind::InternalError,
                    "The missing buffer type does not hold any buffers inside.",
                ))
            }
            DecryptBuffer::Empty => DecryptBuffer::Empty,
        })
    }

    /// Sets the buffer data.
    ///
    /// *Attention*: the buffer type must not be [SecurityBufferType::Missing].
    pub fn set_data(&mut self, buf: &'data mut [u8]) -> crate::Result<()> {
        match self {
            DecryptBuffer::Data(data) => *data = buf,
            DecryptBuffer::Token(data) => *data = buf,
            DecryptBuffer::StreamHeader(data) => *data = buf,
            DecryptBuffer::StreamTrailer(data) => *data = buf,
            DecryptBuffer::Stream(data) => *data = buf,
            DecryptBuffer::Extra(data) => *data = buf,
            DecryptBuffer::Missing(_) => {
                return Err(Error::new(
                    ErrorKind::InternalError,
                    "The missing buffer type does not hold any buffers inside.",
                ))
            }
            DecryptBuffer::Empty => {}
        };
        Ok(())
    }

    /// Determines the [SecurityBufferType] of the decrypt buffer.
    pub fn security_buffer_type(&self) -> SecurityBufferType {
        match self {
            DecryptBuffer::Data(_) => SecurityBufferType::Data,
            DecryptBuffer::Token(_) => SecurityBufferType::Token,
            DecryptBuffer::StreamHeader(_) => SecurityBufferType::StreamHeader,
            DecryptBuffer::StreamTrailer(_) => SecurityBufferType::StreamTrailer,
            DecryptBuffer::Stream(_) => SecurityBufferType::Stream,
            DecryptBuffer::Extra(_) => SecurityBufferType::Extra,
            DecryptBuffer::Missing(_) => SecurityBufferType::Missing,
            DecryptBuffer::Empty => SecurityBufferType::Empty,
        }
    }

    /// Returns the immutable reference to the [DecryptBuffer] with specified buffer type.
    ///
    /// If a slice contains more than one buffer with a specified buffer type, then the first one will be returned.
    pub fn find_buffer<'a>(
        buffers: &'a [DecryptBuffer<'data>],
        buffer_type: SecurityBufferType,
    ) -> crate::Result<&'a DecryptBuffer<'data>> {
        buffers
            .iter()
            .find(|b| b.security_buffer_type() == buffer_type)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidToken,
                    format!("No buffer was provided with type {:?}", buffer_type),
                )
            })
    }

    /// Returns the mutable reference to the [DecryptBuffer] with specified buffer type.
    ///
    /// If a slice contains more than one buffer with a specified buffer type, then the first one will be returned.
    pub fn find_buffer_mut<'a>(
        buffers: &'a mut [DecryptBuffer<'data>],
        buffer_type: SecurityBufferType,
    ) -> crate::Result<&'a mut DecryptBuffer<'data>> {
        buffers
            .iter_mut()
            .find(|b| b.security_buffer_type() == buffer_type)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidToken,
                    format!("No buffer was provided with type {:?}", buffer_type),
                )
            })
    }

    /// Returns the immutable reference to the inner buffer data.
    pub fn buf_data<'a>(buffers: &'a [DecryptBuffer<'a>], buffer_type: SecurityBufferType) -> crate::Result<&'a [u8]> {
        Ok(DecryptBuffer::find_buffer(buffers, buffer_type)?.data())
    }

    /// Returns the immutable reference to the inner data.
    pub fn data(&self) -> &[u8] {
        match self {
            DecryptBuffer::Data(data) => data,
            DecryptBuffer::Token(data) => data,
            DecryptBuffer::StreamHeader(data) => data,
            DecryptBuffer::StreamTrailer(data) => data,
            DecryptBuffer::Stream(data) => data,
            DecryptBuffer::Extra(data) => data,
            DecryptBuffer::Missing(_) => &[],
            DecryptBuffer::Empty => &[],
        }
    }

    /// Calculates the buffer data length.
    pub fn buf_len(&self) -> usize {
        match self {
            DecryptBuffer::Data(data) => data.len(),
            DecryptBuffer::Token(data) => data.len(),
            DecryptBuffer::StreamHeader(data) => data.len(),
            DecryptBuffer::StreamTrailer(data) => data.len(),
            DecryptBuffer::Stream(data) => data.len(),
            DecryptBuffer::Extra(data) => data.len(),
            DecryptBuffer::Missing(needed_bytes_amount) => *needed_bytes_amount,
            DecryptBuffer::Empty => 0,
        }
    }

    /// Returns the mutable reference to the inner buffer data leaving the empty buffer on its place.
    pub fn take_buf_data_mut<'a>(
        buffers: &'a mut [DecryptBuffer<'data>],
        buffer_type: SecurityBufferType,
    ) -> crate::Result<&'data mut [u8]> {
        Ok(DecryptBuffer::find_buffer_mut(buffers, buffer_type)?.take_data())
    }

    /// Returns the mutable reference to the inner data leaving the empty buffer on its place.
    pub fn take_data(&mut self) -> &'data mut [u8] {
        match self {
            DecryptBuffer::Data(data) => take(data),
            DecryptBuffer::Token(data) => take(data),
            DecryptBuffer::StreamHeader(data) => take(data),
            DecryptBuffer::StreamTrailer(data) => take(data),
            DecryptBuffer::Stream(data) => take(data),
            DecryptBuffer::Extra(data) => take(data),
            DecryptBuffer::Missing(_) => &mut [],
            DecryptBuffer::Empty => &mut [],
        }
    }
}

impl fmt::Debug for DecryptBuffer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecryptBuffer {{ ")?;
        match self {
            DecryptBuffer::Data(data) => write_buffer(data, "Data", f)?,
            DecryptBuffer::Token(data) => write_buffer(data, "Token", f)?,
            DecryptBuffer::StreamHeader(data) => write_buffer(data, "StreamHeader", f)?,
            DecryptBuffer::StreamTrailer(data) => write_buffer(data, "StreamTrailer", f)?,
            DecryptBuffer::Stream(data) => write_buffer(data, "Stream", f)?,
            DecryptBuffer::Extra(data) => write_buffer(data, "Extra", f)?,
            DecryptBuffer::Missing(needed_bytes_amount) => write!(f, "Missing({})", *needed_bytes_amount)?,
            DecryptBuffer::Empty => f.write_str("Empty")?,
        };
        write!(f, " }}")
    }
}

fn write_buffer(buf: &[u8], buf_name: &str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}: ", buf_name)?;
    f.write_str("0x")?;
    buf.iter().try_for_each(|byte| write!(f, "{byte:02X}"))
}
