use std::io::{Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use uuid::Uuid;

use super::{read_to_end, read_uuid, Decode, Encode};
use crate::rpc::pdu::{PacketFlags, PduHeader};
use crate::{DpapiResult, Error, ErrorKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub alloc_hint: u32,
    pub context_id: u16,
    pub opnum: u16,
    pub obj: Option<Uuid>,
    pub stub_data: Vec<u8>,
}

impl Encode for Request {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        writer.write_u32::<LittleEndian>(self.alloc_hint)?;
        writer.write_u16::<LittleEndian>(self.context_id)?;
        writer.write_u16::<LittleEndian>(self.opnum)?;
        if let Some(obj) = self.obj.as_ref() {
            writer.write(&obj.to_bytes_le())?;
        }
        // TODO
        writer.write(&self.stub_data)?;

        Ok(())
    }
}

impl Request {
    pub fn decode(pdu_header: &PduHeader, mut reader: impl Read) -> DpapiResult<Self> {
        Ok(Self {
            alloc_hint: reader.read_u32::<LittleEndian>()?,
            context_id: reader.read_u16::<LittleEndian>()?,
            opnum: reader.read_u16::<LittleEndian>()?,
            obj: if pdu_header.packet_flags.contains(PacketFlags::PfcObjectUuid) {
                Some(read_uuid(&mut reader)?)
            } else {
                None
            },
            stub_data: read_to_end(reader)?,
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

impl Encode for Response {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        writer.write_u32::<LittleEndian>(self.alloc_hint)?;
        writer.write_u16::<LittleEndian>(self.context_id)?;
        writer.write_u8(self.cancel_count)?;
        // Reserved.
        writer.write_u8(0)?;

        // TODO
        writer.write(&self.stub_data)?;

        Ok(())
    }
}

impl Decode for Response {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        Ok(Self {
            alloc_hint: reader.read_u32::<LittleEndian>()?,
            context_id: reader.read_u16::<LittleEndian>()?,
            cancel_count: {
                let cancel_count = reader.read_u8()?;

                // Reserved
                reader.read_u8()?;

                cancel_count
            },
            stub_data: read_to_end(reader)?,
        })
    }
}
