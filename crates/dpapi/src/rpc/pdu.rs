use std::io::{Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use uuid::Uuid;

use super::{Decode, Encode};
use crate::{DpapiResult, Error, ErrorKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, FromPrimitive)]
#[repr(u8)]
pub enum IntegerRepresentation {
    BigEndian = 0,
    #[default]
    LittleEndian = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, FromPrimitive)]
#[repr(u8)]
pub enum CharacterRepresentation {
    #[default]
    Ascii = 0,
    Ebcdic = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, FromPrimitive)]
#[repr(u8)]
pub enum FloatingPointRepresentation {
    #[default]
    Ieee = 0,
    Vax = 1,
    Cray = 2,
    Ibm = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Request = 0,
    Ping = 1,
    Response = 2,
    Fault = 3,
    Working = 4,
    Nocall = 5,
    Reject = 6,
    Ack = 7,
    ClCancel = 8,
    Fack = 9,
    CancelAck = 10,
    Bind = 11,
    BindAck = 12,
    BindNak = 13,
    AlterAontext = 14,
    AlterAontextResp = 15,
    Shutdown = 17,
    CoCancel = 18,
    Orphaned = 19,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketFlags {
    None = 0x00,
    PfcFirstFrag = 0x01,
    PfcLastFrag = 0x02,
    // PfcPendingCancel = 0x04,
    PfcSupportHeaderSign = 0x04, // MS-RPCE extension used in Bind/AlterContext
    PfcReserved1 = 0x08,
    PfcConcMpx = 0x10,
    PfcDidNotExecute = 0x20,
    PfcMaybe = 0x40,
    PfcObjectUuid = 0x80,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DataRepresentation {
    pub byte_order: IntegerRepresentation,
    pub character: CharacterRepresentation,
    pub floating_point: FloatingPointRepresentation,
}

impl Encode for DataRepresentation {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        let first_octet = (self.byte_order as u8) << 4 | self.character as u8;
        writer.write_u8(first_octet)?;
        writer.write_u8(self.floating_point as u8)?;

        // Padding
        writer.write_u16::<LittleEndian>(0)?;

        Ok(())
    }
}

impl Decode for DataRepresentation {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let first_octet = reader.read_u8()?;

        Ok(Self {
            byte_order: IntegerRepresentation::from_u8((first_octet & 0b11110000) >> 4)
                .ok_or_else(|| Error::new(ErrorKind::NteInvalidParameter, "Invalid IntegerRepresentation value"))?,
            character: CharacterRepresentation::from_u8(first_octet & 0b00001111)
                .ok_or_else(|| Error::new(ErrorKind::NteInvalidParameter, "Invalid CharacterRepresentation value"))?,
            floating_point: FloatingPointRepresentation::from_u8(reader.read_u8()?).ok_or_else(|| {
                Error::new(
                    ErrorKind::NteInvalidParameter,
                    "Invalid FloatingPointRepresentation value",
                )
            })?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    test_encoding_decoding! {
        DataRepresentation,
        DataRepresentation::default(),
        [0x10, 0, 0, 0]
    }
}
