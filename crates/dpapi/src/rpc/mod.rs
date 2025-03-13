pub mod auth;
pub mod client;

use std::io::{ErrorKind as IoErrorKind, Read, Write};

pub use auth::AuthProvider;
pub use client::{bind_time_feature_negotiation, RpcClient, NDR, NDR64};

use crate::{Error, Result};

pub fn write_buf(mut data: &[u8], mut writer: impl Write) -> Result<()> {
    while !data.is_empty() {
        let bytes_written = writer.write(data)?;
        data = &data[bytes_written..];

        if bytes_written == 0 {
            return Err(Error::Io(IoErrorKind::WriteZero.into()));
        }
    }

    Ok(())
}

pub fn read_to_end(mut reader: impl Read) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;

    Ok(buf)
}
