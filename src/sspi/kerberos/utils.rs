use std::{
    convert::TryInto,
    io::{Cursor, Write},
};

use picky_krb::data_types::KrbResult;
use serde::{Deserialize, Serialize};

use crate::{Error, ErrorKind, Result};

pub fn serialize_message<T: ?Sized + Serialize>(v: &T) -> Vec<u8> {
    let mut writer = Cursor::new(Vec::new());
    writer.write_all(&[0, 0, 0, 0]).unwrap();

    picky_asn1_der::to_writer(v, &mut writer).unwrap();

    let mut data = writer.into_inner();
    let len = data.len() as u32 - 4;
    data[0..4].copy_from_slice(&len.to_be_bytes());

    data
}

pub fn utf16_bytes_to_string(data: &[u8]) -> String {
    assert_eq!(data.len() % 2, 0);
    String::from_utf16_lossy(
        &data
            .chunks(2)
            .map(|c| u16::from_le_bytes(c.try_into().unwrap()))
            .collect::<Vec<u16>>(),
    )
}

pub fn unwrap_krb_response<'a, T: Deserialize<'a>>(data: &'a [u8]) -> Result<T> {
    match KrbResult::from_bytes(data).map_err(|e| Error {
        error_type: ErrorKind::InvalidToken,
        description: format!("{:?}", e),
    })? {
        KrbResult::Ok(as_rep) => Ok(as_rep),
        KrbResult::Err(krb_error) => Err(Error {
            error_type: ErrorKind::InvalidToken,
            description: krb_error.0.to_string(),
        }),
    }
}
