use crate::{DpapiResult, Error};

/// Decodes a UTF-16–encoded byte slice into a [String].
///
/// The input `data` slice should has the size multiple of two (`data.len() % 2 == 0`).
/// Otherwise, the function will return an error.
///
/// *Note*: this function does not expect a NULL-char at the end of the byte slice.
pub fn from_utf16_le(data: &[u8]) -> DpapiResult<String> {
    if data.len() % 2 != 0 {
        return Err(Error::FromUtf16(
            "invalid UTF-16: byte slice should has the size multiple of two".into(),
        ));
    }

    Ok(String::from_utf16(
        &data
            .chunks(2)
            .map(|c| u16::from_le_bytes(c.try_into().unwrap()))
            .collect::<Vec<u16>>(),
    )?)
}

/// Encodes str into a UTF-16 encoded byte array.
///
/// *Note*: this function automatically appends a NULL-char.
pub fn encode_utf16_le(data: &str) -> Vec<u8> {
    data.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(|v| v.to_le_bytes())
        .collect::<Vec<_>>()
}
