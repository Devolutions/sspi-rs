use alloc::vec::Vec;

use crate::{Result, WriteBuf, WriteCursor};

/// PDU that can be encoded into its binary form.
///
/// This trait is object-safe and may be used in a dynamic context.
pub trait Encode {
    /// Encodes this PDU in-place into the provided buffer and returns the number of bytes written.
    fn encode(&self, dst: &mut [u8]) -> Result<usize> {
        let mut cursor = WriteCursor::new(dst);
        self.encode_cursor(&mut cursor)?;

        Ok(cursor.pos())
    }

    /// Encodes this PDU in-place using the provided [`WriteCursor`].
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()>;

    /// Same as [`Encode::encode`] but resizes the buffer when it is too small to fit the PDU.
    fn encode_buf(&self, buf: &mut WriteBuf) -> Result<usize> {
        let frame_length = self.frame_length();
        let dst = buf.unfilled_to(frame_length);
        let written = self.encode(dst)?;
        debug_assert_eq!(written, frame_length);
        buf.advance(written);

        Ok(written)
    }

    /// Same as [`Encode::encode`] but allocates and returns a new buffer each time.
    fn encode_vec(&self) -> Result<Vec<u8>> {
        let frame_length = self.frame_length();
        let mut buf = ::alloc::vec![0; frame_length];
        let written = self.encode(&mut buf)?;
        debug_assert_eq!(written, frame_length);

        Ok(buf)
    }

    /// Computes size in bytes required for encoding of this PDU.
    fn frame_length(&self) -> usize;
}
