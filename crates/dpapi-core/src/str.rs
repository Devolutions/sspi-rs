use alloc::string::String;
use alloc::vec::Vec;

use ironrdp_core::{DecodeError, DecodeResult, InvalidFieldErr, ReadCursor, WriteCursor, ensure_size};

use crate::{Error, Result};

/// Decodes a UTF-16–encoded byte slice into a [String].
///
/// The input `data` slice should has the size multiple of two (`data.len() % 2 == 0`).
/// Otherwise, the function will return an error.
///
/// *Note*: this function does not expect a NULL-char at the end of the byte slice.
pub fn from_utf16_le(data: &[u8]) -> Result<String> {
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
/// *Panic*: panics when cursor's internal buffer doesn't have enough space.
pub fn encode_utf16_le(data: &str, dst: &mut WriteCursor) {
    data.encode_utf16()
        .chain(core::iter::once(0))
        .for_each(|v| dst.write_u16(v));
}

/// Calculates the size in bytes of the UTF16 encoded representation of
/// the string slice.
///
/// *Note*: this function automatically counts a NULL-char.
pub fn str_utf16_len(data: &str) -> usize {
    data.encode_utf16().chain(core::iter::once(0)).count() * 2
}

/// Reads UTF-16 C-str from [ReadCursor].
pub fn read_c_str_utf16_le(len: usize, src: &mut ReadCursor<'_>) -> DecodeResult<String> {
    use crate::Error;
    use crate::str::from_utf16_le;

    if len < 2 {
        return Err(
            DecodeError::invalid_field("", "C UTF-16 str", "expected at least 2 bytes").with_source(
                Error::InvalidLength {
                    name: "UTF-16 string",
                    expected: 2,
                    actual: len,
                },
            ),
        );
    }

    ensure_size!(ctx: "UTF16-le C str", in: src, size: len);
    let buf = src.read_slice(len - 2 /* UTF16 null terminator */);

    // Read UTF16 null terminator.
    src.read_u16();

    Ok(from_utf16_le(buf)?)
}
