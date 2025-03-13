use alloc::vec::Vec;

use uuid::Uuid;

use crate::rpc::{PacketFlags, PduHeader};
use crate::{Decode, DecodeWithContext, Encode, NeedsContext, ReadCursor, Result, WriteCursor, StaticName};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub alloc_hint: u32,
    pub context_id: u16,
    pub opnum: u16,
    pub obj: Option<Uuid>,
    pub stub_data: Vec<u8>,
}

impl StaticName for Request {
    const NAME: &'static str = "Request";
}

impl Encode for Request {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        ensure_size!(in: dst, size: self.frame_length());

        dst.write_u32(self.alloc_hint);
        dst.write_u16(self.context_id);
        dst.write_u16(self.opnum);
        self.obj.encode_cursor(dst)?;
        dst.write_slice(&self.stub_data);

        Ok(())
    }

    fn frame_length(&self) -> usize {
        4 /* alloc_hint */ + 2 /* context_id */ + 2 /* opnum */ + self.obj.frame_length() + self.stub_data.len()
    }
}

impl NeedsContext for Request {
    type Context<'ctx> = &'ctx PduHeader;
}

impl DecodeWithContext for Request {
    fn decode_cursor_with_context(src: &mut ReadCursor<'_>, pdu_header: Self::Context<'_>) -> Result<Self> {
        Ok(Self {
            alloc_hint: src.read_u32(),
            context_id: src.read_u16(),
            opnum: src.read_u16(),
            obj: if pdu_header.packet_flags.contains(PacketFlags::PfcObjectUuid) {
                Some(Uuid::decode_cursor(src)?)
            } else {
                None
            },
            stub_data: src.read_remaining().to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub alloc_hint: u32,
    pub context_id: u16,
    pub cancel_count: u8,
    pub stub_data: Vec<u8>,
}

impl StaticName for Response {
    const NAME: &'static str = "Response";
}

impl Encode for Response {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        ensure_size!(in: dst, size: self.frame_length());

        dst.write_u32(self.alloc_hint);
        dst.write_u16(self.context_id);
        dst.write_u8(self.cancel_count);
        // Reserved.
        dst.write_u8(0);

        dst.write_slice(&self.stub_data);

        Ok(())
    }

    fn frame_length(&self) -> usize {
        4 /* alloc_hint */ + 2 /* context_id */ + 1 /* cancel_count */ + 1 /* reserved */ + self.stub_data.len()
    }
}

impl Decode for Response {
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self> {
        Ok(Self {
            alloc_hint: src.read_u32(),
            context_id: src.read_u16(),
            cancel_count: {
                let cancel_count = src.read_u8();

                // Reserved
                src.read_u8();

                cancel_count
            },
            stub_data: src.read_remaining().to_vec(),
        })
    }
}
