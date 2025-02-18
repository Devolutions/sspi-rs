use std::io::{Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use uuid::Uuid;

use super::{read_to_end, write_buf, Decode, Encode};
use crate::rpc::pdu::{PacketFlags, PduHeader};
use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub alloc_hint: u32,
    pub context_id: u16,
    pub opnum: u16,
    pub obj: Option<Uuid>,
    pub stub_data: Vec<u8>,
}

impl Encode for Request {
    fn encode(&self, mut writer: impl Write) -> Result<()> {
        writer.write_u32::<LittleEndian>(self.alloc_hint)?;
        writer.write_u16::<LittleEndian>(self.context_id)?;
        writer.write_u16::<LittleEndian>(self.opnum)?;
        if let Some(obj) = self.obj.as_ref() {
            obj.encode(&mut writer)?;
        }
        write_buf(&self.stub_data, writer)?;

        Ok(())
    }
}

impl Request {
    pub fn decode(pdu_header: &PduHeader, mut reader: impl Read) -> Result<Self> {
        Ok(Self {
            alloc_hint: reader.read_u32::<LittleEndian>()?,
            context_id: reader.read_u16::<LittleEndian>()?,
            opnum: reader.read_u16::<LittleEndian>()?,
            obj: if pdu_header.packet_flags.contains(PacketFlags::PfcObjectUuid) {
                Some(Uuid::decode(&mut reader)?)
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
    fn encode(&self, mut writer: impl Write) -> Result<()> {
        writer.write_u32::<LittleEndian>(self.alloc_hint)?;
        writer.write_u16::<LittleEndian>(self.context_id)?;
        writer.write_u8(self.cancel_count)?;
        // Reserved.
        writer.write_u8(0)?;

        write_buf(&self.stub_data, writer)?;

        Ok(())
    }
}

impl Decode for Response {
    fn decode(mut reader: impl Read) -> Result<Self> {
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
