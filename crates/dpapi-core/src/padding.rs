use alloc::vec;

use crate::cursor::{ReadCursor, WriteCursor};

/// Use this when handling padding.
pub struct Padding<const ALIGNMENT: usize>;

impl<const ALIGNMENT: usize> Padding<ALIGNMENT> {
    pub fn write(len: usize, dst: &mut WriteCursor<'_>) {
        let padding_len = (ALIGNMENT - (len % ALIGNMENT)) % ALIGNMENT;

        dst.write_slice(&vec![0; padding_len]);
    }

    pub fn read(len: usize, src: &mut ReadCursor<'_>) {
        let padding_len = (ALIGNMENT - (len % ALIGNMENT)) % ALIGNMENT;

        src.advance(padding_len);
    }
}
