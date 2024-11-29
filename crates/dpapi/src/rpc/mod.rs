#[macro_use]
mod macros;

mod bind;
mod pdu;
mod request;

use std::io::{Read, Write};

use uuid::Uuid;

use crate::DpapiResult;

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

fn write_padding<const ALIGNMENT: usize>(buf_len: usize, mut writer: impl Write) -> DpapiResult<()> {
    let padding_len = (ALIGNMENT - (buf_len % ALIGNMENT)) % ALIGNMENT;
    let padding_buf = vec![0; padding_len];

    writer.write(padding_buf.as_ref())?;

    Ok(())
}

fn read_padding<const ALIGNMENT: usize>(buf_len: usize, mut reader: impl Read) -> DpapiResult<()> {
    let padding_len = (ALIGNMENT - (buf_len % ALIGNMENT)) % ALIGNMENT;
    let mut padding_buf = vec![0; padding_len];

    reader.read_exact(&mut padding_buf)?;

    Ok(())
}

fn read_uuid(mut reader: impl Read) -> DpapiResult<Uuid> {
    let mut uuid_buf = [0; 16];
    reader.read(&mut uuid_buf)?;

    Ok(Uuid::from_slice_le(&uuid_buf)?)
}

fn read_to_end(mut reader: impl Read) -> DpapiResult<Vec<u8>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;

    Ok(buf)
}
