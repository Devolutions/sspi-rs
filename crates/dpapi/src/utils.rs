use crate::DpapiResult;

pub fn utf16_bytes_to_utf8_string(data: &[u8]) -> DpapiResult<String> {
    debug_assert_eq!(data.len() % 2, 0);

    Ok(String::from_utf16(
        &data
            .chunks(2)
            .map(|c| u16::from_le_bytes(c.try_into().unwrap()))
            .collect::<Vec<u16>>(),
    )?)
}
