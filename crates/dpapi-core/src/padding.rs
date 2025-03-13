use alloc::vec;

use crate::{ReadCursor, Result, WriteCursor};

/// Use this when handling padding.
pub struct Padding<const ALIGNMENT: usize>;

impl<const ALIGNMENT: usize> Padding<ALIGNMENT> {
    pub fn write(len: usize, dst: &mut WriteCursor<'_>) {
        dst.write_slice(&vec![0; Self::padding(len)]);
    }

    pub fn read(len: usize, src: &mut ReadCursor<'_>) -> Result<()> {
        let padding_len = Self::padding(len);
        ensure_size!(name: "Padding", in: src, size: padding_len);

        src.advance(padding_len);

        Ok(())
    }

    pub fn padding(len: usize) -> usize {
        (ALIGNMENT - (len % ALIGNMENT)) % ALIGNMENT
    }
}
