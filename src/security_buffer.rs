use std::fmt;
use std::mem::take;

use crate::{BufferType, Error, ErrorKind, OwnedSecurityBufferType, Result, SecurityBufferFlags};

/// A security buffer type with a mutable reference to the buffer data.
///
/// Basically, it is a security buffer but without buffer flags.
#[non_exhaustive]
pub enum SecurityBufferType<'data> {
    Data(&'data mut [u8]),
    Token(&'data mut [u8]),
    StreamHeader(&'data mut [u8]),
    StreamTrailer(&'data mut [u8]),
    Stream(&'data mut [u8]),
    Extra(&'data mut [u8]),
    Padding(&'data mut [u8]),
    Missing(usize),
    Empty,
}

/// A special security buffer type is used for the data decryption. Basically, it's almost the same
/// as `OwnedSecurityBuffer` but for decryption.
///
/// [DecryptMessage](https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--general)
/// "The encrypted message is decrypted in place, overwriting the original contents of its buffer."
///
/// So, the already defined `OwnedSecurityBuffer` is not suitable for decryption because it uses [Vec] inside.
/// We use reference in the [SecurityBuffer] structure to avoid data cloning as much as possible.
/// Decryption/encryption input buffers can be very large. Even up to 32 KiB if we are using this crate as a TSSSP(CREDSSP)
/// security package.
pub struct SecurityBuffer<'data> {
    buffer_type: SecurityBufferType<'data>,
    buffer_flags: SecurityBufferFlags,
}

impl<'data> SecurityBuffer<'data> {
    /// Creates a [SecurityBuffer] with a `Data` buffer type and empty buffer flags.
    pub fn data_buf(data: &mut [u8]) -> SecurityBuffer {
        SecurityBuffer {
            buffer_type: SecurityBufferType::Data(data),
            buffer_flags: Default::default(),
        }
    }

    /// Creates a [SecurityBuffer] with a `Token` buffer type and empty buffer flags.
    pub fn token_buf(data: &mut [u8]) -> SecurityBuffer {
        SecurityBuffer {
            buffer_type: SecurityBufferType::Token(data),
            buffer_flags: Default::default(),
        }
    }

    /// Creates a [SecurityBuffer] with a `StreamHeader` buffer type and empty buffer flags.
    pub fn stream_header_buf(data: &mut [u8]) -> SecurityBuffer {
        SecurityBuffer {
            buffer_type: SecurityBufferType::StreamHeader(data),
            buffer_flags: Default::default(),
        }
    }

    /// Creates a [SecurityBuffer] with a `StreamTrailer` buffer type and empty buffer flags.
    pub fn stream_trailer_buf(data: &mut [u8]) -> SecurityBuffer {
        SecurityBuffer {
            buffer_type: SecurityBufferType::StreamTrailer(data),
            buffer_flags: Default::default(),
        }
    }

    /// Creates a [SecurityBuffer] with a `Stream` buffer type and empty buffer flags.
    pub fn stream_buf(data: &mut [u8]) -> SecurityBuffer {
        SecurityBuffer {
            buffer_type: SecurityBufferType::Stream(data),
            buffer_flags: Default::default(),
        }
    }

    /// Creates a [SecurityBuffer] with a `Extra` buffer type and empty buffer flags.
    pub fn extra_buf(data: &mut [u8]) -> SecurityBuffer {
        SecurityBuffer {
            buffer_type: SecurityBufferType::Extra(data),
            buffer_flags: Default::default(),
        }
    }

    /// Creates a [SecurityBuffer] with a `Padding` buffer type and empty buffer flags.
    pub fn padding_buf(data: &mut [u8]) -> SecurityBuffer {
        SecurityBuffer {
            buffer_type: SecurityBufferType::Padding(data),
            buffer_flags: Default::default(),
        }
    }

    /// Creates a [SecurityBuffer] with a `Missing` buffer type and empty buffer flags.
    pub fn missing_buf<'a>(count: usize) -> SecurityBuffer<'a> {
        SecurityBuffer {
            buffer_type: SecurityBufferType::Missing(count),
            buffer_flags: Default::default(),
        }
    }

    /// Set buffer flags.
    pub fn with_flags(self, buffer_flags: SecurityBufferFlags) -> Self {
        let Self {
            buffer_type,
            buffer_flags: _,
        } = self;

        Self {
            buffer_type,
            buffer_flags,
        }
    }

    /// Creates a [SecurityBuffer] from based on provided [BufferType].
    ///
    /// Inner buffers will be empty.
    pub fn with_security_buffer_type(security_buffer_type: BufferType) -> Result<Self> {
        Ok(Self {
            buffer_type: match security_buffer_type {
                BufferType::Empty => SecurityBufferType::Empty,
                BufferType::Data => SecurityBufferType::Data(&mut []),
                BufferType::Token => SecurityBufferType::Token(&mut []),
                BufferType::Missing => SecurityBufferType::Missing(0),
                BufferType::Extra => SecurityBufferType::Extra(&mut []),
                BufferType::Padding => SecurityBufferType::Padding(&mut []),
                BufferType::StreamTrailer => SecurityBufferType::StreamTrailer(&mut []),
                BufferType::StreamHeader => SecurityBufferType::StreamHeader(&mut []),
                BufferType::Stream => SecurityBufferType::Stream(&mut []),
                _ => return Err(Error::new(ErrorKind::UnsupportedFunction, "")),
            },
            buffer_flags: SecurityBufferFlags::NONE,
        })
    }

    /// Created a [SecurityBuffer] from based on provided [BufferType].
    ///
    /// Inner buffers will be empty.
    pub fn with_owned_security_buffer_type(security_buffer_type: OwnedSecurityBufferType) -> Result<Self> {
        Ok(Self {
            buffer_type: match security_buffer_type.buffer_type {
                BufferType::Empty => SecurityBufferType::Empty,
                BufferType::Data => SecurityBufferType::Data(&mut []),
                BufferType::Token => SecurityBufferType::Token(&mut []),
                BufferType::Missing => SecurityBufferType::Missing(0),
                BufferType::Extra => SecurityBufferType::Extra(&mut []),
                BufferType::Padding => SecurityBufferType::Padding(&mut []),
                BufferType::StreamTrailer => SecurityBufferType::StreamTrailer(&mut []),
                BufferType::StreamHeader => SecurityBufferType::StreamHeader(&mut []),
                BufferType::Stream => SecurityBufferType::Stream(&mut []),
                _ => return Err(Error::new(ErrorKind::UnsupportedFunction, "")),
            },
            buffer_flags: security_buffer_type.buffer_flags,
        })
    }

    /// Creates a new [SecurityBuffer] with the provided buffer data saving the old buffer type.
    ///
    /// *Attention*: the buffer type must not be [BufferType::Missing].
    pub fn with_data(self, data: &'data mut [u8]) -> Result<Self> {
        Ok(Self {
            buffer_type: match &self.buffer_type {
                SecurityBufferType::Data(_) => SecurityBufferType::Data(data),
                SecurityBufferType::Token(_) => SecurityBufferType::Token(data),
                SecurityBufferType::StreamHeader(_) => SecurityBufferType::StreamHeader(data),
                SecurityBufferType::StreamTrailer(_) => SecurityBufferType::StreamTrailer(data),
                SecurityBufferType::Stream(_) => SecurityBufferType::Stream(data),
                SecurityBufferType::Extra(_) => SecurityBufferType::Extra(data),
                SecurityBufferType::Padding(_) => SecurityBufferType::Padding(data),
                SecurityBufferType::Missing(_) => {
                    return Err(Error::new(
                        ErrorKind::InternalError,
                        "the missing buffer type does not hold any buffers inside",
                    ))
                }
                SecurityBufferType::Empty => SecurityBufferType::Empty,
            },
            buffer_flags: self.buffer_flags,
        })
    }

    /// Sets the buffer data.
    ///
    /// *Attention*: the buffer type must not be [BufferType::Missing].
    pub fn set_data(&mut self, buf: &'data mut [u8]) -> Result<()> {
        match &mut self.buffer_type {
            SecurityBufferType::Data(data) => *data = buf,
            SecurityBufferType::Token(data) => *data = buf,
            SecurityBufferType::StreamHeader(data) => *data = buf,
            SecurityBufferType::StreamTrailer(data) => *data = buf,
            SecurityBufferType::Stream(data) => *data = buf,
            SecurityBufferType::Extra(data) => *data = buf,
            SecurityBufferType::Padding(data) => *data = buf,
            SecurityBufferType::Missing(_) => {
                return Err(Error::new(
                    ErrorKind::InternalError,
                    "the missing buffer type does not hold any buffers inside",
                ))
            }
            SecurityBufferType::Empty => {}
        };
        Ok(())
    }

    /// Determines the [BufferType] of security buffer.
    pub fn buffer_type(&self) -> BufferType {
        match &self.buffer_type {
            SecurityBufferType::Data(_) => BufferType::Data,
            SecurityBufferType::Token(_) => BufferType::Token,
            SecurityBufferType::StreamHeader(_) => BufferType::StreamHeader,
            SecurityBufferType::StreamTrailer(_) => BufferType::StreamTrailer,
            SecurityBufferType::Stream(_) => BufferType::Stream,
            SecurityBufferType::Extra(_) => BufferType::Extra,
            SecurityBufferType::Padding(_) => BufferType::Padding,
            SecurityBufferType::Missing(_) => BufferType::Missing,
            SecurityBufferType::Empty => BufferType::Empty,
        }
    }

    pub fn buffer_flags(&self) -> SecurityBufferFlags {
        self.buffer_flags
    }

    pub fn owned_security_buffer_type(&self) -> OwnedSecurityBufferType {
        let buffer_type = match &self.buffer_type {
            SecurityBufferType::Data(_) => BufferType::Data,
            SecurityBufferType::Token(_) => BufferType::Token,
            SecurityBufferType::StreamHeader(_) => BufferType::StreamHeader,
            SecurityBufferType::StreamTrailer(_) => BufferType::StreamTrailer,
            SecurityBufferType::Stream(_) => BufferType::Stream,
            SecurityBufferType::Extra(_) => BufferType::Extra,
            SecurityBufferType::Padding(_) => BufferType::Padding,
            SecurityBufferType::Missing(_) => BufferType::Missing,
            SecurityBufferType::Empty => BufferType::Empty,
        };

        OwnedSecurityBufferType {
            buffer_type,
            buffer_flags: self.buffer_flags,
        }
    }

    /// Returns the immutable reference to the [SecurityBuffer] with specified buffer type.
    ///
    /// If a slice contains more than one buffer with a specified buffer type, then the first one will be returned.
    pub fn find_buffer<'a>(
        buffers: &'a [SecurityBuffer<'data>],
        buffer_type: BufferType,
    ) -> Result<&'a SecurityBuffer<'data>> {
        buffers.iter().find(|b| b.buffer_type() == buffer_type).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidToken,
                format!("no buffer was provided with type {:?}", buffer_type),
            )
        })
    }

    /// Returns the vector of immutable references to the [SecurityBuffer] with specified buffer type.
    pub fn buffers_with_type<'a>(
        buffers: &'a [SecurityBuffer<'data>],
        buffer_type: BufferType,
    ) -> Vec<&'a SecurityBuffer<'data>> {
        buffers.iter().filter(|b| b.buffer_type() == buffer_type).collect()
    }

    /// Returns the vector of immutable references to the [SecurityBuffer] with specified buffer type.
    pub fn buffers_with_type_mut<'a>(
        buffers: &'a mut [SecurityBuffer<'data>],
        buffer_type: BufferType,
    ) -> Vec<&'a mut SecurityBuffer<'data>> {
        buffers.iter_mut().filter(|b| b.buffer_type() == buffer_type).collect()
    }

    /// Returns the vector of immutable references to the [SecurityBuffer] with specified buffer type and flags.
    pub fn buffers_with_type_and_flags<'a>(
        buffers: &'a [SecurityBuffer<'data>],
        buffer_type: BufferType,
        buffer_flags: SecurityBufferFlags,
    ) -> Vec<&'a SecurityBuffer<'data>> {
        buffers
            .iter()
            .filter(|b| b.buffer_type() == buffer_type && b.buffer_flags() == buffer_flags)
            .collect()
    }

    /// Returns the vector of immutable references to the [SecurityBuffer] with specified buffer type and flags.
    pub fn buffers_with_type_and_flags_mut<'a>(
        buffers: &'a mut [SecurityBuffer<'data>],
        buffer_type: BufferType,
        buffer_flags: SecurityBufferFlags,
    ) -> Vec<&'a mut SecurityBuffer<'data>> {
        buffers
            .iter_mut()
            .filter(|b| b.buffer_type() == buffer_type && b.buffer_flags() == buffer_flags)
            .collect()
    }

    /// Returns the mutable reference to the [SecurityBuffer] with specified buffer type.
    ///
    /// If a slice contains more than one buffer with a specified buffer type, then the first one will be returned.
    pub fn find_buffer_mut<'a>(
        buffers: &'a mut [SecurityBuffer<'data>],
        buffer_type: BufferType,
    ) -> Result<&'a mut SecurityBuffer<'data>> {
        buffers
            .iter_mut()
            .find(|b| b.buffer_type() == buffer_type)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidToken,
                    format!("no buffer was provided with type {:?}", buffer_type),
                )
            })
    }

    /// Returns the immutable reference to the inner buffer data.
    pub fn buf_data<'a>(buffers: &'a [SecurityBuffer<'a>], buffer_type: BufferType) -> Result<&'a [u8]> {
        Ok(SecurityBuffer::find_buffer(buffers, buffer_type)?.data())
    }

    /// Returns the immutable reference to the inner data.
    ///
    /// Some buffer types can not hold the data, so the empty slice will be returned.
    pub fn data(&self) -> &[u8] {
        match &self.buffer_type {
            SecurityBufferType::Data(data) => data,
            SecurityBufferType::Token(data) => data,
            SecurityBufferType::StreamHeader(data) => data,
            SecurityBufferType::StreamTrailer(data) => data,
            SecurityBufferType::Stream(data) => data,
            SecurityBufferType::Extra(data) => data,
            SecurityBufferType::Padding(data) => data,
            SecurityBufferType::Missing(_) => &[],
            SecurityBufferType::Empty => &[],
        }
    }

    /// Calculates the buffer data length.
    pub fn buf_len(&self) -> usize {
        match &self.buffer_type {
            SecurityBufferType::Data(data) => data.len(),
            SecurityBufferType::Token(data) => data.len(),
            SecurityBufferType::StreamHeader(data) => data.len(),
            SecurityBufferType::StreamTrailer(data) => data.len(),
            SecurityBufferType::Stream(data) => data.len(),
            SecurityBufferType::Extra(data) => data.len(),
            SecurityBufferType::Padding(data) => data.len(),
            SecurityBufferType::Missing(needed_bytes_amount) => *needed_bytes_amount,
            SecurityBufferType::Empty => 0,
        }
    }

    /// Returns the mutable reference to the inner buffer data leaving the empty buffer on its place.
    pub fn take_buf_data_mut<'a>(
        buffers: &'a mut [SecurityBuffer<'data>],
        buffer_type: BufferType,
    ) -> Result<&'data mut [u8]> {
        Ok(SecurityBuffer::find_buffer_mut(buffers, buffer_type)?.take_data())
    }

    /// Returns the mutable reference to the inner data leaving the empty buffer on its place.
    ///
    /// Some buffer types can not hold the data, so the empty slice will be returned.
    pub fn take_data(&mut self) -> &'data mut [u8] {
        match &mut self.buffer_type {
            SecurityBufferType::Data(data) => take(data),
            SecurityBufferType::Token(data) => take(data),
            SecurityBufferType::StreamHeader(data) => take(data),
            SecurityBufferType::StreamTrailer(data) => take(data),
            SecurityBufferType::Stream(data) => take(data),
            SecurityBufferType::Extra(data) => take(data),
            SecurityBufferType::Padding(data) => take(data),
            SecurityBufferType::Missing(_) => &mut [],
            SecurityBufferType::Empty => &mut [],
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
        write!(f, "SecurityBuffer {{ ")?;
        f.write_fmt(format_args!("{:?},", self.buffer_flags))?;
        match &self.buffer_type {
            SecurityBufferType::Data(data) => write_buffer(data, "Data", f)?,
            SecurityBufferType::Token(data) => write_buffer(data, "Token", f)?,
            SecurityBufferType::StreamHeader(data) => write_buffer(data, "StreamHeader", f)?,
            SecurityBufferType::StreamTrailer(data) => write_buffer(data, "StreamTrailer", f)?,
            SecurityBufferType::Stream(data) => write_buffer(data, "Stream", f)?,
            SecurityBufferType::Extra(data) => write_buffer(data, "Extra", f)?,
            SecurityBufferType::Padding(data) => write_buffer(data, "Padding", f)?,
            SecurityBufferType::Missing(needed_bytes_amount) => write!(f, "Missing({})", *needed_bytes_amount)?,
            SecurityBufferType::Empty => f.write_str("Empty")?,
        };
        write!(f, " }}")
    }
}

fn write_buffer(buf: &[u8], buf_name: &str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}: ", buf_name)?;
    f.write_str("0x")?;
    buf.iter().try_for_each(|byte| write!(f, "{byte:02X}"))
}
