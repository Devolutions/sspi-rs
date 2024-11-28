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

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
#[repr(u8)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
#[repr(u8)]
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
                .ok_or_else(|| Error::new(ErrorKind::NteInvalidParameter, "invalid IntegerRepresentation value"))?,
            character: CharacterRepresentation::from_u8(first_octet & 0b00001111)
                .ok_or_else(|| Error::new(ErrorKind::NteInvalidParameter, "invalid CharacterRepresentation value"))?,
            floating_point: FloatingPointRepresentation::from_u8(reader.read_u8()?).ok_or_else(|| {
                Error::new(
                    ErrorKind::NteInvalidParameter,
                    "invalid FloatingPointRepresentation value",
                )
            })?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduHeader {
    pub version: u8,
    pub version_minor: u8,
    pub packet_type: PacketType,
    pub packet_flags: PacketFlags,
    pub data_rep: DataRepresentation,
    pub frag_len: u16,
    pub auth_len: u16,
    pub call_id: u32,
}

impl Encode for PduHeader {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        writer.write_u8(self.version)?;
        writer.write_u8(self.version_minor)?;
        writer.write_u8(self.packet_type as u8)?;
        writer.write_u8(self.packet_flags as u8)?;
        self.data_rep.encode(&mut writer)?;
        writer.write_u16::<LittleEndian>(self.frag_len)?;
        writer.write_u16::<LittleEndian>(self.auth_len)?;
        writer.write_u32::<LittleEndian>(self.call_id)?;

        Ok(())
    }
}

impl Decode for PduHeader {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        Ok(Self {
            version: reader.read_u8()?,
            version_minor: reader.read_u8()?,
            packet_type: PacketType::from_u8(reader.read_u8()?)
                .ok_or_else(|| Error::new(ErrorKind::NteInvalidParameter, "invalid PacketType value"))?,
            packet_flags: PacketFlags::from_u8(reader.read_u8()?)
                .ok_or_else(|| Error::new(ErrorKind::NteInvalidParameter, "invalid PacketFlags value"))?,
            data_rep: DataRepresentation::decode(&mut reader)?,
            frag_len: reader.read_u16::<LittleEndian>()?,
            auth_len: reader.read_u16::<LittleEndian>()?,
            call_id: reader.read_u32::<LittleEndian>()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
#[repr(u8)]
pub enum SecurityProvider {
    RpcCAuthnNone = 0x00,
    RpcCAuthnGssNegotiate = 0x09,
    RpcCAuthnWinnt = 0x0a,
    RpcCAuthnGssSchannel = 0x0e,
    RpcCAuthnGssKerberos = 0x10,
    RpcCAuthnNetlogon = 0x44,
    RpcCAuthnDefault = 0xff,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
#[repr(u8)]
pub enum AuthenticationLevel {
    RpcCAuthnLevelDefault = 0x00,
    RpcCAuthnLevelNone = 0x01,
    RpcCAuthnLevelConnect = 0x02,
    RpcCAuthnLevelCall = 0x03,
    RpcCAuthnLevelPkt = 0x04,
    RpcCAuthnLevelPktIntegrity = 0x05,
    RpcCAuthnLevelPktPrivacy = 0x06,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityTrailer {
    security_type: SecurityProvider,
    level: AuthenticationLevel,
    pad_length: u8,
    context_id: u32,
    auth_value: Vec<u8>,
}

impl Encode for SecurityTrailer {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        writer.write_u8(self.security_type as u8)?;
        writer.write_u8(self.level as u8)?;
        writer.write_u8(self.pad_length)?;
        writer.write_u8(0)?; // Auth-Rsrvd
        writer.write_u32::<LittleEndian>(self.context_id)?;
        // TODO: check written bytes.
        writer.write(&self.auth_value)?;

        Ok(())
    }
}

impl Decode for SecurityTrailer {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        Ok(Self {
            security_type: SecurityProvider::from_u8(reader.read_u8()?)
                .ok_or_else(|| Error::new(ErrorKind::NteInvalidParameter, "invalid SecurityProvider value"))?,
            level: AuthenticationLevel::from_u8(reader.read_u8()?)
                .ok_or_else(|| Error::new(ErrorKind::NteInvalidParameter, "invalid AuthenticationLevel value"))?,
            pad_length: reader.read_u8()?,
            context_id: {
                // Skip Auth-Rsrvd.
                reader.read_u8()?;

                reader.read_u32::<LittleEndian>()?
            },
            auth_value: {
                let mut buf = Vec::new();
                reader.read_to_end(&mut buf)?;

                buf
            },
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

    test_encoding_decoding! {
        SecurityTrailer,
        SecurityTrailer {
            security_type: SecurityProvider::RpcCAuthnGssKerberos,
            level: AuthenticationLevel::RpcCAuthnLevelPktPrivacy,
            pad_length: 0,
            context_id: 0,
            auth_value: vec![111, 129, 135, 48, 129, 132, 160, 3, 2, 1, 5, 161, 3, 2, 1, 15, 162, 120, 48, 118, 160, 3, 2, 1, 18, 162, 111, 4, 109, 119, 103, 226, 62, 224, 40, 10, 92, 235, 148, 195, 168, 140, 247, 167, 45, 22, 189, 35, 181, 182, 57, 109, 10, 207, 215, 253, 118, 167, 212, 69, 43, 39, 201, 54, 64, 99, 241, 39, 189, 178, 98, 111, 37, 181, 177, 174, 239, 217, 11, 149, 100, 143, 41, 205, 36, 175, 207, 83, 14, 69, 197, 91, 154, 186, 114, 47, 121, 9, 37, 33, 107, 120, 161, 209, 114, 38, 201, 202, 210, 13, 59, 9, 29, 146, 85, 134, 67, 107, 99, 129, 40, 249, 200, 138, 117, 235, 104, 139, 93, 199, 167, 84, 119, 12, 90, 55, 27, 109],
        },
        [16, 6, 0, 0, 0, 0, 0, 0, 111, 129, 135, 48, 129, 132, 160, 3, 2, 1, 5, 161, 3, 2, 1, 15, 162, 120, 48, 118, 160, 3, 2, 1, 18, 162, 111, 4, 109, 119, 103, 226, 62, 224, 40, 10, 92, 235, 148, 195, 168, 140, 247, 167, 45, 22, 189, 35, 181, 182, 57, 109, 10, 207, 215, 253, 118, 167, 212, 69, 43, 39, 201, 54, 64, 99, 241, 39, 189, 178, 98, 111, 37, 181, 177, 174, 239, 217, 11, 149, 100, 143, 41, 205, 36, 175, 207, 83, 14, 69, 197, 91, 154, 186, 114, 47, 121, 9, 37, 33, 107, 120, 161, 209, 114, 38, 201, 202, 210, 13, 59, 9, 29, 146, 85, 134, 67, 107, 99, 129, 40, 249, 200, 138, 117, 235, 104, 139, 93, 199, 167, 84, 119, 12, 90, 55, 27, 109]
    }
}
