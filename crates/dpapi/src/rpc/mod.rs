#[macro_use]
mod macros;

mod bind;
mod pdu;

use std::io::{Read, Write};

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

fn write_padding<const Alignment: usize>(buf_len: usize, mut writer: impl Write) -> DpapiResult<()> {
    let padding_len = (Alignment - (buf_len % Alignment)) % Alignment;
    let padding_buf = vec![0; padding_len];

    writer.write(padding_buf.as_ref())?;

    Ok(())
}

fn read_padding<const Alignment: usize>(buf_len: usize, mut reader: impl Read) -> DpapiResult<()> {
    let padding_len = (Alignment - (buf_len % Alignment)) % Alignment;
    let mut padding_buf = vec![0; padding_len];

    reader.read_exact(&mut padding_buf)?;

    Ok(())
}
