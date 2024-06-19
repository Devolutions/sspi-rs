use std::fmt;
use std::mem::take;

use crate::{Error, ErrorKind, Result, SecurityBufferType};

/// A special security buffer type is used for the data decryption. Basically, it's almost the same
/// as [OwnedSecurityBuffer] but for decryption.
///
/// [DecryptMessage](https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--general)
/// "The encrypted message is decrypted in place, overwriting the original contents of its buffer."
///
/// So, the already defined [SecurityBuffer] is not suitable for decryption because it uses [Vec] inside.
/// We use reference in the [SecurityBuffer] structure to avoid data cloning as much as possible.
/// Decryption input buffers can be very large. Even up to 32 KiB if we are using this crate as a TSSSP(CREDSSP)
/// security package.
pub enum SecurityBuffer<'data> {
    Data(&'data mut [u8]),
    Token(&'data mut [u8]),
    StreamHeader(&'data mut [u8]),
    StreamTrailer(&'data mut [u8]),
    Stream(&'data mut [u8]),
    Extra(&'data mut [u8]),
    Missing(usize),
    Empty,
}

impl<'data> SecurityBuffer<'data> {
    /// Created a [SecurityBuffer] from based on provided [SecurityBufferType].
    ///
    /// Inner buffers will be empty.
    pub fn with_security_buffer_type(security_buffer_type: SecurityBufferType) -> Result<Self> {
        match security_buffer_type {
            SecurityBufferType::Empty => Ok(SecurityBuffer::Empty),
            SecurityBufferType::Data => Ok(SecurityBuffer::Data(&mut [])),
            SecurityBufferType::Token => Ok(SecurityBuffer::Token(&mut [])),
            SecurityBufferType::Missing => Ok(SecurityBuffer::Missing(0)),
            SecurityBufferType::Extra => Ok(SecurityBuffer::Extra(&mut [])),
            SecurityBufferType::StreamTrailer => Ok(SecurityBuffer::StreamTrailer(&mut [])),
            SecurityBufferType::StreamHeader => Ok(SecurityBuffer::StreamHeader(&mut [])),
            SecurityBufferType::Stream => Ok(SecurityBuffer::Stream(&mut [])),
            _ => Err(Error::new(ErrorKind::UnsupportedFunction, "")),
        }
    }

    /// Creates a new [SecurityBuffer] with the provided buffer data saving the old buffer type.
    ///
    /// *Attention*: the buffer type must not be [SecurityBufferType::Missing].
    pub fn with_data(self, data: &'data mut [u8]) -> Result<Self> {
        Ok(match self {
            SecurityBuffer::Data(_) => SecurityBuffer::Data(data),
            SecurityBuffer::Token(_) => SecurityBuffer::Token(data),
            SecurityBuffer::StreamHeader(_) => SecurityBuffer::StreamHeader(data),
            SecurityBuffer::StreamTrailer(_) => SecurityBuffer::StreamTrailer(data),
            SecurityBuffer::Stream(_) => SecurityBuffer::Stream(data),
            SecurityBuffer::Extra(_) => SecurityBuffer::Extra(data),
            SecurityBuffer::Missing(_) => {
                return Err(Error::new(
                    ErrorKind::InternalError,
                    "The missing buffer type does not hold any buffers inside.",
                ))
            }
            SecurityBuffer::Empty => SecurityBuffer::Empty,
        })
    }

    /// Sets the buffer data.
    ///
    /// *Attention*: the buffer type must not be [SecurityBufferType::Missing].
    pub fn set_data(&mut self, buf: &'data mut [u8]) -> Result<()> {
        match self {
            SecurityBuffer::Data(data) => *data = buf,
            SecurityBuffer::Token(data) => *data = buf,
            SecurityBuffer::StreamHeader(data) => *data = buf,
            SecurityBuffer::StreamTrailer(data) => *data = buf,
            SecurityBuffer::Stream(data) => *data = buf,
            SecurityBuffer::Extra(data) => *data = buf,
            SecurityBuffer::Missing(_) => {
                return Err(Error::new(
                    ErrorKind::InternalError,
                    "The missing buffer type does not hold any buffers inside.",
                ))
            }
            SecurityBuffer::Empty => {}
        };
        Ok(())
    }

    /// Determines the [SecurityBufferType] of the decrypt buffer.
    pub fn security_buffer_type(&self) -> SecurityBufferType {
        match self {
            SecurityBuffer::Data(_) => SecurityBufferType::Data,
            SecurityBuffer::Token(_) => SecurityBufferType::Token,
            SecurityBuffer::StreamHeader(_) => SecurityBufferType::StreamHeader,
            SecurityBuffer::StreamTrailer(_) => SecurityBufferType::StreamTrailer,
            SecurityBuffer::Stream(_) => SecurityBufferType::Stream,
            SecurityBuffer::Extra(_) => SecurityBufferType::Extra,
            SecurityBuffer::Missing(_) => SecurityBufferType::Missing,
            SecurityBuffer::Empty => SecurityBufferType::Empty,
        }
    }

    /// Returns the immutable reference to the [SecurityBuffer] with specified buffer type.
    ///
    /// If a slice contains more than one buffer with a specified buffer type, then the first one will be returned.
    pub fn find_buffer<'a>(
        buffers: &'a [SecurityBuffer<'data>],
        buffer_type: SecurityBufferType,
    ) -> Result<&'a SecurityBuffer<'data>> {
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

    /// Returns the mutable reference to the [SecurityBuffer] with specified buffer type.
    ///
    /// If a slice contains more than one buffer with a specified buffer type, then the first one will be returned.
    pub fn find_buffer_mut<'a>(
        buffers: &'a mut [SecurityBuffer<'data>],
        buffer_type: SecurityBufferType,
    ) -> Result<&'a mut SecurityBuffer<'data>> {
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
    pub fn buf_data<'a>(buffers: &'a [SecurityBuffer<'a>], buffer_type: SecurityBufferType) -> Result<&'a [u8]> {
        Ok(SecurityBuffer::find_buffer(buffers, buffer_type)?.data())
    }

    /// Returns the immutable reference to the inner data.
    ///
    /// Some buffer types can not hold the data, so the empty slice will be returned.
    pub fn data(&self) -> &[u8] {
        match self {
            SecurityBuffer::Data(data) => data,
            SecurityBuffer::Token(data) => data,
            SecurityBuffer::StreamHeader(data) => data,
            SecurityBuffer::StreamTrailer(data) => data,
            SecurityBuffer::Stream(data) => data,
            SecurityBuffer::Extra(data) => data,
            SecurityBuffer::Missing(_) => &[],
            SecurityBuffer::Empty => &[],
        }
    }

    /// Calculates the buffer data length.
    pub fn buf_len(&self) -> usize {
        match self {
            SecurityBuffer::Data(data) => data.len(),
            SecurityBuffer::Token(data) => data.len(),
            SecurityBuffer::StreamHeader(data) => data.len(),
            SecurityBuffer::StreamTrailer(data) => data.len(),
            SecurityBuffer::Stream(data) => data.len(),
            SecurityBuffer::Extra(data) => data.len(),
            SecurityBuffer::Missing(needed_bytes_amount) => *needed_bytes_amount,
            SecurityBuffer::Empty => 0,
        }
    }

    /// Returns the mutable reference to the inner buffer data leaving the empty buffer on its place.
    pub fn take_buf_data_mut<'a>(
        buffers: &'a mut [SecurityBuffer<'data>],
        buffer_type: SecurityBufferType,
    ) -> Result<&'data mut [u8]> {
        Ok(SecurityBuffer::find_buffer_mut(buffers, buffer_type)?.take_data())
    }

    /// Returns the mutable reference to the inner data leaving the empty buffer on its place.
    ///
    /// Some buffer types can not hold the data, so the empty slice will be returned.
    pub fn take_data(&mut self) -> &'data mut [u8] {
        match self {
            SecurityBuffer::Data(data) => take(data),
            SecurityBuffer::Token(data) => take(data),
            SecurityBuffer::StreamHeader(data) => take(data),
            SecurityBuffer::StreamTrailer(data) => take(data),
            SecurityBuffer::Stream(data) => take(data),
            SecurityBuffer::Extra(data) => take(data),
            SecurityBuffer::Missing(_) => &mut [],
            SecurityBuffer::Empty => &mut [],
        }
    }

    /// Writes the provided data into the inner buffer.
    ///
    /// Returns error if the inner buffer is not big enough. If the inner buffer is larger than
    /// provided data, then it'll be shrunk to the size of the data.
    pub fn write_data(&mut self, data: &[u8]) -> Result<()> {
        let data_len = data.len();

        if self.buf_len() < data_len {
            return Err(Error::new(
                ErrorKind::BufferTooSmall,
                "provided data can not fit in the destination buffer",
            ));
        }

        let mut buf = self.take_data();
        buf = &mut buf[0..data_len];
        buf.copy_from_slice(data);

        self.set_data(buf)
    }
}

impl fmt::Debug for SecurityBuffer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecryptBuffer {{ ")?;
        match self {
            SecurityBuffer::Data(data) => write_buffer(data, "Data", f)?,
            SecurityBuffer::Token(data) => write_buffer(data, "Token", f)?,
            SecurityBuffer::StreamHeader(data) => write_buffer(data, "StreamHeader", f)?,
            SecurityBuffer::StreamTrailer(data) => write_buffer(data, "StreamTrailer", f)?,
            SecurityBuffer::Stream(data) => write_buffer(data, "Stream", f)?,
            SecurityBuffer::Extra(data) => write_buffer(data, "Extra", f)?,
            SecurityBuffer::Missing(needed_bytes_amount) => write!(f, "Missing({})", *needed_bytes_amount)?,
            SecurityBuffer::Empty => f.write_str("Empty")?,
        };
        write!(f, " }}")
    }
}

fn write_buffer(buf: &[u8], buf_name: &str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}: ", buf_name)?;
    f.write_str("0x")?;
    buf.iter().try_for_each(|byte| write!(f, "{byte:02X}"))
}
