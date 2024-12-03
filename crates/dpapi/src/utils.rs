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

pub fn encode_utf16_le(data: &str) -> Vec<u8> {
    data.encode_utf16()
        .into_iter()
        .chain(std::iter::once(0))
        .flat_map(|v| v.to_le_bytes())
        .collect::<Vec<_>>()
}
