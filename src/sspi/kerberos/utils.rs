use std::io::{Cursor, Write};

use serde::Serialize;

pub fn serialize_message<T: ?Sized + Serialize>(v: &T) -> Vec<u8> {
    let mut writer = Cursor::new(Vec::new());
    writer.write_all(&[0, 0, 0, 0]).unwrap();

    picky_asn1_der::to_writer(v, &mut writer).unwrap();

    let mut data = writer.into_inner();
    let len = data.len() as u32 - 4;
    data[0..4].copy_from_slice(&len.to_be_bytes());

    data
}
