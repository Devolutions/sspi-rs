#[macro_use]
mod macros;

pub mod bind;
pub mod pdu;
pub mod request;

use std::io::{ErrorKind as IoErrorKind, Read, Write};

use uuid::Uuid;

use crate::{DpapiResult, Error};

trait Encode {
    fn encode(&self, writer: impl Write) -> DpapiResult<()>;
    fn encode_to_vec(&self) -> DpapiResult<Vec<u8>> {
        let mut buf = Vec::new();

        self.encode(&mut buf)?;

        Ok(buf)
    }
}

trait Decode: Sized {
    fn decode(reader: impl Read) -> DpapiResult<Self>;
}

fn write_padding<const ALIGNMENT: usize>(buf_len: usize, writer: impl Write) -> DpapiResult<()> {
    let padding_len = (ALIGNMENT - (buf_len % ALIGNMENT)) % ALIGNMENT;
    let padding_buf = vec![0; padding_len];

    write_buf(&padding_buf, writer)?;

    Ok(())
}

fn read_padding<const ALIGNMENT: usize>(buf_len: usize, mut reader: impl Read) -> DpapiResult<()> {
    let padding_len = (ALIGNMENT - (buf_len % ALIGNMENT)) % ALIGNMENT;
    let mut padding_buf = vec![0; padding_len];

    reader.read_exact(&mut padding_buf)?;

    Ok(())
}

fn read_uuid(reader: impl Read) -> DpapiResult<Uuid> {
    let mut uuid_buf = [0; 16];
    read_buf(&mut uuid_buf, reader)?;

    Ok(Uuid::from_slice_le(&uuid_buf)?)
}

fn read_to_end(mut reader: impl Read) -> DpapiResult<Vec<u8>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;

    Ok(buf)
}

fn write_buf(mut data: &[u8], mut writer: impl Write) -> DpapiResult<()> {
    while !data.is_empty() {
        let bytes_written = writer.write(data)?;
        data = &data[bytes_written..];

        if bytes_written == 0 {
            return Err(Error::Io(IoErrorKind::WriteZero.into()));
        }
    }

    Ok(())
}

fn read_buf(mut buf: &mut [u8], mut reader: impl Read) -> DpapiResult<()> {
    while !buf.is_empty() {
        let bytes_read = reader.read(buf)?;
        buf = &mut buf[bytes_read..];

        if bytes_read == 0 {
            return Err(Error::Io(IoErrorKind::UnexpectedEof.into()));
        }
    }

    Ok(())
}
