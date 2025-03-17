use alloc::string::String;
use alloc::vec::Vec;

use uuid::Uuid;

use crate::{NeedsContext, ReadCursor, Result};

/// PDU that can be decoded from a binary input.
pub trait Decode: Sized {
    /// Decodes a PDU from a binary input.
    fn decode(src: &[u8]) -> Result<Self> {
        let mut cursor = ReadCursor::new(src);
        Self::decode_cursor(&mut cursor)
    }

    /// Decodes a PDU from a cursor.
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self>;
}

impl Decode for Uuid {
    fn decode_cursor(src: &mut ReadCursor) -> Result<Self> {
        ensure_size!(in: src, size: 16);

        Ok(Uuid::from_slice_le(src.read_slice(16))?)
    }
}

impl Decode for (u8, u8) {
    fn decode_cursor(src: &mut ReadCursor) -> Result<Self> {
        ensure_size!(name: "(u8, u8)", in: src, size: 2);

        Ok((src.read_u8(), src.read_u8()))
    }
}

/// PDU that can be decoded from a binary input and provided context.
pub trait DecodeWithContext: Sized + NeedsContext {
    /// Decodes PDU from a binary input with provided context.
    fn decode_with_context(src: &[u8], ctx: Self::Context<'_>) -> Result<Self> {
        let mut cursor = ReadCursor::new(src);
        Self::decode_cursor_with_context(&mut cursor, ctx)
    }

    /// Decodes PDU from a [`ReadCursor`] with provided context.
    fn decode_cursor_with_context(src: &mut ReadCursor<'_>, ctx: Self::Context<'_>) -> Result<Self>;
}

impl<T: Decode> DecodeWithContext for Vec<T> {
    fn decode_cursor_with_context(src: &mut ReadCursor<'_>, ctx: Self::Context<'_>) -> Result<Self> {
        (0..ctx).map(|_| T::decode_cursor(src)).collect()
    }
}

/// Fixed size of the srtructure.
pub trait FixedPartSize {
    /// Size of the fixed part of frame.
    const FIXED_PART_SIZE: usize;
}

/// Finds the precise byte count required to decode the frame from a possibly partial input.
/// Incorrectly reading too few or too many bytes will lead to program malfunctions.
pub trait FindLength: FixedPartSize {
    /// Try to find the length of this frame given the first bytes.
    fn find_frame_length(bytes: &[u8]) -> Result<Option<usize>>;
}

pub fn read_c_str_utf16_le(len: usize, src: &mut ReadCursor<'_>) -> Result<String> {
    use crate::Error;
    use crate::str::from_utf16_le;

    if len < 2 {
        return Err(Error::InvalidLength {
            name: "UTF-16 string",
            expected: 2,
            actual: len,
        });
    }

    ensure_size!(name: "UTF16-le C str", in: src, size: len);
    let buf = src.read_slice(len - 2 /* UTF16 null terminator */);

    // Read UTF16 null terminator.
    src.read_u16();

    from_utf16_le(buf)
}
