use alloc::vec::Vec;

use ironrdp_core::{Encode, EncodeResult, WriteBuf, WriteCursor, ensure_size};
use uuid::Uuid;

use crate::FixedPartSize;

pub trait EncodeExt {
    fn encode_ext(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()>;

    fn size_ext(&self) -> usize;
}

impl EncodeExt for Uuid {
    fn encode_ext(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size_ext());

        dst.write_slice(&self.to_bytes_le());

        Ok(())
    }

    fn size_ext(&self) -> usize {
        Uuid::FIXED_PART_SIZE
    }
}

impl<T: EncodeExt> EncodeExt for Vec<T> {
    fn encode_ext(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        for item in self.iter() {
            item.encode_ext(dst)?;
        }

        Ok(())
    }

    fn size_ext(&self) -> usize {
        self.iter().map(|item| item.size_ext()).sum()
    }
}

impl<T: EncodeExt> EncodeExt for Option<T> {
    fn encode_ext(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        if let Some(obj) = self {
            obj.encode_ext(dst)?;
        }

        Ok(())
    }

    fn size_ext(&self) -> usize {
        self.as_ref().map(|item| item.size_ext()).unwrap_or_default()
    }
}

pub fn encode_buf<T>(pdu: &T, buf: &mut WriteBuf) -> EncodeResult<usize>
where
    T: EncodeExt + ?Sized,
{
    let pdu_size = pdu.size_ext();

    let mut dst = WriteCursor::new(buf.unfilled_to(pdu_size));
    pdu.encode_ext(&mut dst)?;

    let written = dst.pos();

    debug_assert_eq!(written, pdu_size);
    buf.advance(written);

    Ok(written)
}

pub trait EncodeVec {
    fn encode_vec(&self) -> EncodeResult<Vec<u8>>;
}

impl<T: Encode> EncodeVec for T {
    fn encode_vec(&self) -> EncodeResult<Vec<u8>> {
        let mut buf = WriteBuf::new();
        ironrdp_core::encode_buf(self, &mut buf)?;

        Ok(buf.into_inner())
    }
}
