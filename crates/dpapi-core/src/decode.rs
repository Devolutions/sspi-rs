use crate::{ReadCursor, Result};

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

/// Finds the precise byte count required to decode the frame from a possibly partial input.
/// Incorrectly reading too few or too many bytes will lead to program malfunctions.
pub trait FindLength {
    /// Size of the fixed part of frame.
    const FIXED_PART_SIZE: usize;

    /// Try to find the length of this frame given the first bytes.
    fn find_frame_length(bytes: &[u8]) -> Result<Option<usize>>;
}
