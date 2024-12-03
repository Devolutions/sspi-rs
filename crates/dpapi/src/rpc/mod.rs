pub mod bind;
pub mod pdu;
pub mod request;

use std::io::{ErrorKind as IoErrorKind, Read, Write};

use uuid::Uuid;

use crate::{DpapiResult, Error};

pub trait Encode {
    fn encode(&self, writer: impl Write) -> DpapiResult<()>;
}

pub trait EncodeExt: Encode {
    fn encode_to_vec(&self) -> DpapiResult<Vec<u8>> {
        let mut buf = Vec::new();

        self.encode(&mut buf)?;

        Ok(buf)
    }
}

impl<T: Encode> EncodeExt for T {}

pub trait Decode: Sized {
    fn decode(reader: impl Read) -> DpapiResult<Self>;
}

impl Encode for Uuid {
    fn encode(&self, writer: impl Write) -> DpapiResult<()> {
        write_buf(&self.to_bytes_le(), writer)?;

        Ok(())
    }
}

impl Decode for Uuid {
    fn decode(reader: impl Read) -> DpapiResult<Self> {
        let mut uuid_buf = [0; 16];
        read_buf(&mut uuid_buf, reader)?;

        Ok(Uuid::from_slice_le(&uuid_buf)?)
    }
}

pub fn write_padding<const ALIGNMENT: usize>(buf_len: usize, mut writer: impl Write) -> DpapiResult<()> {
    let padding_len = (ALIGNMENT - (buf_len % ALIGNMENT)) % ALIGNMENT;
    let padding_buf = vec![0; padding_len];

    write_buf(&padding_buf, writer)?;

    Ok(())
}

pub fn read_padding<const ALIGNMENT: usize>(buf_len: usize, mut reader: impl Read) -> DpapiResult<()> {
    let padding_len = (ALIGNMENT - (buf_len % ALIGNMENT)) % ALIGNMENT;
    let mut padding_buf = vec![0; padding_len];

    reader.read_exact(&mut padding_buf)?;

    Ok(())
}

pub fn read_to_end(mut reader: impl Read) -> DpapiResult<Vec<u8>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;

    Ok(buf)
}

pub fn write_buf(mut data: &[u8], mut writer: impl Write) -> DpapiResult<()> {
    while !data.is_empty() {
        let bytes_written = writer.write(data)?;
        data = &data[bytes_written..];

        if bytes_written == 0 {
            return Err(Error::Io(IoErrorKind::WriteZero.into()));
        }
    }

    Ok(())
}

pub fn read_buf(mut buf: &mut [u8], mut reader: impl Read) -> DpapiResult<()> {
    while !buf.is_empty() {
        let bytes_read = reader.read(buf)?;
        buf = &mut buf[bytes_read..];

        if bytes_read == 0 {
            return Err(Error::Io(IoErrorKind::UnexpectedEof.into()));
        }
    }

    Ok(())
}

pub fn read_c_str_utf16_le(len: usize, mut reader: impl Read) -> DpapiResult<String> {
    use byteorder::{LittleEndian, ReadBytesExt};

    use crate::utils::utf16_bytes_to_utf8_string;

    let mut buf = vec![0; len - 2 /* UTF16 null terminator */];
    reader.read_exact(buf.as_mut_slice())?;

    // Read UTF16 null terminator.
    reader.read_u16::<LittleEndian>()?;

    utf16_bytes_to_utf8_string(&buf)
}
