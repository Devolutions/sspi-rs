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
