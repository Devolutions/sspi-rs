use ironrdp_core::{DecodeResult, EncodeResult, ReadCursor, WriteCursor, ensure_size};

/// Use this when handling padding.
pub struct Padding<const ALIGNMENT: usize>;

impl<const ALIGNMENT: usize> Padding<ALIGNMENT> {
    pub fn write(len: usize, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        let padding_len = Self::padding(len);
        ensure_size!(ctx: "Padding", in: dst, size: padding_len);

        dst.advance(padding_len);

        Ok(())
    }

    pub fn read(len: usize, src: &mut ReadCursor<'_>) -> DecodeResult<()> {
        let padding_len = Self::padding(len);
        ensure_size!(ctx: "Padding", in: src, size: padding_len);

        src.advance(padding_len);

        Ok(())
    }

    pub fn padding(len: usize) -> usize {
        (ALIGNMENT - (len % ALIGNMENT)) % ALIGNMENT
    }
}
