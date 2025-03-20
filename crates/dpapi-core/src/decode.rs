use alloc::string::String;

use ironrdp_core::{DecodeError, DecodeResult, InvalidFieldErr, ReadCursor, ensure_size};
use uuid::Uuid;

use crate::NeedsContext;

pub trait DecodeOwnedExt: Sized {
    fn decode_owned(src: &mut ReadCursor<'_>) -> DecodeResult<Self>;
}

impl DecodeOwnedExt for Uuid {
    fn decode_owned(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        ensure_size!(in: src, size: Uuid::FIXED_PART_SIZE);

        Uuid::from_slice_le(src.read_slice(Self::FIXED_PART_SIZE))
            .map_err(|err| DecodeError::invalid_field("", "uuid", "invalid data").with_source(err))
    }
}

/// PDU that can be decoded from a binary input and provided context.
pub trait DecodeWithContextOwned: Sized + NeedsContext {
    /// Decodes PDU from a [`ReadCursor`] with provided context.
    fn decode_with_context_owned(src: &mut ReadCursor<'_>, ctx: Self::Context<'_>) -> DecodeResult<Self>;
}

/// Fixed size of the srtructure.
pub trait FixedPartSize {
    /// Size of the fixed part of frame.
    const FIXED_PART_SIZE: usize;
}

impl FixedPartSize for Uuid {
    const FIXED_PART_SIZE: usize = 16;
}

/// Finds the precise byte count required to decode the frame from a possibly partial input.
/// Incorrectly reading too few or too many bytes will lead to program malfunctions.
pub trait FindLength: FixedPartSize {
    /// Try to find the length of this frame given the first bytes.
    fn find_frame_length(bytes: &[u8]) -> DecodeResult<Option<usize>>;
}

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
