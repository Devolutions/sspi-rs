use std::io::{Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use super::{read_to_end, Decode, Encode};
use crate::rpc::bind::{AlterContext, AlterContextResponse, Bind, BindAck, BindNak, ContextElement};
use crate::rpc::request::{Request, Response};
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
    AlterContext = 14,
    AlterContextResponse = 15,
    Shutdown = 17,
    CoCancel = 18,
    Orphaned = 19,
}

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
    pub struct PacketFlags: u8 {
        const None = 0x00;
        const PfcFirstFrag = 0x01;
        const PfcLastFrag = 0x02;
        // PfcPendingCancel = 0x04,
        const PfcSupportHeaderSign = 0x04; // MS-RPCE extension used in Bind/AlterContext
        const PfcReserved1 = 0x08;
        const PfcConcMpx = 0x10;
        const PfcDidNotExecute = 0x20;
        const PfcMaybe = 0x40;
        const PfcObjectUuid = 0x80;
    }
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

        let data_representation = Self {
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
        };

        // Padding.
        reader.read_u16::<LittleEndian>()?;

        Ok(data_representation)
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
        writer.write_u8(self.packet_flags.bits())?;
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
            packet_flags: PacketFlags::from_bits(reader.read_u8()?)
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
            auth_value: read_to_end(reader)?,
        })
    }
}

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
    pub struct FaultFlags: u8 {
        const None = 0x00;
        const ExtendedErrorPresent = 0x01;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    pub alloc_hint: u32,
    pub context_id: u16,
    pub cancel_count: u8,
    // Extension of MS-RPCE.
    pub flags: FaultFlags,
    pub status: u32,
    pub stub_data: Vec<u8>,
}

impl Encode for Fault {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        writer.write_u32::<LittleEndian>(self.alloc_hint)?;
        writer.write_u16::<LittleEndian>(self.context_id)?;
        writer.write_u8(self.cancel_count)?;
        writer.write_u8(self.flags.bits())?;
        writer.write_u32::<LittleEndian>(self.status)?;
        // alignment padding
        writer.write_u32::<LittleEndian>(0)?;
        // TODO: check written bytes.
        writer.write(&self.stub_data)?;

        Ok(())
    }
}

impl Decode for Fault {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        Ok(Self {
            alloc_hint: reader.read_u32::<LittleEndian>()?,
            context_id: reader.read_u16::<LittleEndian>()?,
            cancel_count: reader.read_u8()?,
            flags: FaultFlags::from_bits(reader.read_u8()?)
                .ok_or_else(|| Error::new(ErrorKind::NteInvalidParameter, "invalid FaultFlags value"))?,
            status: reader.read_u32::<LittleEndian>()?,
            stub_data: read_to_end(reader)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PduData {
    Bind(Bind),
    BindAck(BindAck),
    BindNak(BindNak),
    AlterContext(AlterContext),
    AlterContextResponse(AlterContextResponse),
    Request(Request),
    Response(Response),
    Fault(Fault),
}

impl PduData {
    pub fn decode(pdu_header: &PduHeader, data_len: usize, mut reader: impl Read) -> DpapiResult<Self> {
        // TODO: optimize it.
        let mut buf = vec![0; data_len];
        reader.read(&mut buf)?;

        match pdu_header.packet_type {
            PacketType::Bind => Ok(PduData::Bind(Bind::decode(&buf as &[u8])?)),
            PacketType::BindAck => Ok(PduData::BindAck(BindAck::decode(&buf as &[u8])?)),
            PacketType::BindNak => Ok(PduData::BindNak(BindNak::decode(&buf as &[u8])?)),
            PacketType::AlterContext => Ok(PduData::AlterContext(AlterContext::decode(&buf as &[u8])?)),
            PacketType::AlterContextResponse => Ok(PduData::AlterContextResponse(AlterContextResponse::decode(
                &buf as &[u8],
            )?)),
            PacketType::Request => Ok(PduData::Request(Request::decode(pdu_header, &buf as &[u8])?)),
            PacketType::Response => Ok(PduData::Response(Response::decode(&buf as &[u8])?)),
            PacketType::Fault => Ok(PduData::Fault(Fault::decode(&buf as &[u8])?)),
            _ => Err(Error::new(
                ErrorKind::NteInternalError,
                format!("unsupported packet type: {:?}", pdu_header.packet_type),
            )),
        }
    }
}

impl Encode for PduData {
    fn encode(&self, writer: impl Write) -> DpapiResult<()> {
        match self {
            PduData::Bind(bind) => bind.encode(writer),
            PduData::BindAck(bind_ack) => bind_ack.encode(writer),
            PduData::BindNak(bind_nak) => bind_nak.encode(writer),
            PduData::AlterContext(alter_context) => alter_context.encode(writer),
            PduData::AlterContextResponse(alter_context_response) => alter_context_response.encode(writer),
            PduData::Request(request) => request.encode(writer),
            PduData::Response(response) => response.encode(writer),
            PduData::Fault(fault) => fault.encode(writer),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdu {
    pub header: PduHeader,
    pub data: PduData,
    pub security_trailer: SecurityTrailer,
}

impl Encode for Pdu {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        self.header.encode(&mut writer)?;
        self.data.encode(&mut writer)?;
        self.security_trailer.encode(writer)?;

        Ok(())
    }
}

impl Decode for Pdu {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let header = PduHeader::decode(&mut reader)?;
        let data = PduData::decode(
            &header,
            (header.frag_len - header.auth_len - 8 /* security trailer header */ - 16/* PDU header len */).into(),
            &mut reader,
        )?;
        let security_trailer = SecurityTrailer::decode(reader)?;

        Ok(Self {
            header,
            data,
            security_trailer,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use uuid::Uuid;

    use super::*;
    use crate::rpc::bind::{BindAck, ContextElement, ContextResult, ContextResultCode, SyntaxId};
    use crate::rpc::request::{Request, Response};

    test_encoding_decoding! {
        data_rep,
        DataRepresentation,
        DataRepresentation::default(),
        [0x10, 0, 0, 0]
    }

    test_encoding_decoding! {
        sec_trailer,
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

    test_encoding_decoding! {
        pdu_bind,
        Pdu,
        Pdu {
            header: PduHeader {
                version: 5,
                version_minor: 0,
                packet_type: PacketType::Bind,
                packet_flags: PacketFlags::PfcSupportHeaderSign | PacketFlags::PfcLastFrag | PacketFlags::PfcFirstFrag,
                data_rep: DataRepresentation {
                    byte_order: IntegerRepresentation::LittleEndian,
                    character: CharacterRepresentation::Ascii,
                    floating_point: FloatingPointRepresentation::Ieee,
                },
                frag_len: 1624,
                auth_len: 1500,
                call_id: 1,
            },
            data: PduData::Bind(Bind {
                max_xmit_frag: 5840,
                max_recv_frag: 5840,
                assoc_group: 0,
                contexts: vec![
                    ContextElement {
                        context_id: 0,
                        abstract_syntax: SyntaxId {
                            uuid: Uuid::from_str("b9785960-524f-11df-8b6d-83dcded72085").unwrap(),
                            version: 1,
                            version_minor: 0,
                        },
                        transfer_syntaxes: vec![
                            SyntaxId {
                                uuid: Uuid::from_str("71710533-beba-4937-8319-b5dbef9ccc36").unwrap(),
                                version: 1,
                                version_minor: 0,
                            }
                        ]
                    },
                    ContextElement {
                        context_id: 1,
                        abstract_syntax: SyntaxId {
                            uuid: Uuid::from_str("b9785960-524f-11df-8b6d-83dcded72085").unwrap(),
                            version: 1,
                            version_minor: 0,
                        },
                        transfer_syntaxes: vec![
                            SyntaxId {
                                uuid: Uuid::from_str("6cb71c2c-9812-4540-0000-000000000000").unwrap(),
                                version: 1,
                                version_minor: 0,
                            }
                        ]
                    },
                ],
            }),
            security_trailer: SecurityTrailer {
                security_type: SecurityProvider::RpcCAuthnGssKerberos,
                level: AuthenticationLevel::RpcCAuthnLevelPktPrivacy,
                pad_length: 0,
                context_id: 0,
                auth_value: vec![110, 130, 5, 216, 48, 130, 5, 212, 160, 3, 2, 1, 5, 161, 3, 2, 1, 14, 162, 7, 3, 5, 0, 32, 0, 0, 0, 163, 130, 4, 122, 97, 130, 4, 118, 48, 130, 4, 114, 160, 3, 2, 1, 5, 161, 9, 27, 7, 84, 66, 84, 46, 67, 79, 77, 162, 42, 48, 40, 160, 3, 2, 1, 2, 161, 33, 48, 31, 27, 4, 104, 111, 115, 116, 27, 23, 119, 105, 110, 45, 57, 53, 54, 99, 113, 111, 115, 115, 106, 116, 102, 46, 116, 98, 116, 46, 99, 111, 109, 163, 130, 4, 50, 48, 130, 4, 46, 160, 3, 2, 1, 18, 161, 3, 2, 1, 9, 162, 130, 4, 32, 4, 130, 4, 28, 44, 103, 214, 219, 239, 134, 71, 190, 93, 33, 211, 36, 190, 6, 172, 121, 2, 89, 207, 145, 220, 145, 172, 231, 91, 117, 132, 111, 90, 170, 93, 68, 125, 232, 140, 82, 149, 113, 166, 160, 177, 128, 211, 60, 148, 255, 76, 218, 44, 251, 207, 172, 107, 5, 100, 116, 150, 169, 166, 9, 243, 215, 68, 138, 147, 181, 172, 57, 147, 162, 119, 199, 59, 114, 24, 246, 77, 200, 11, 70, 50, 177, 82, 16, 66, 204, 205, 184, 46, 235, 136, 252, 175, 19, 54, 232, 224, 42, 167, 220, 22, 230, 36, 196, 53, 64, 242, 190, 202, 121, 185, 201, 34, 254, 147, 167, 94, 244, 59, 7, 50, 175, 224, 79, 20, 81, 165, 16, 10, 139, 62, 188, 123, 240, 61, 227, 185, 45, 183, 229, 204, 78, 87, 196, 197, 234, 229, 130, 158, 133, 212, 167, 240, 86, 39, 192, 130, 213, 211, 136, 250, 130, 143, 151, 0, 242, 199, 20, 5, 218, 217, 222, 115, 183, 135, 28, 162, 0, 206, 176, 200, 131, 43, 121, 200, 78, 64, 202, 103, 223, 65, 195, 173, 108, 127, 210, 56, 103, 73, 27, 111, 57, 221, 127, 168, 81, 65, 65, 48, 231, 188, 175, 218, 158, 56, 220, 28, 51, 18, 78, 65, 9, 117, 136, 225, 226, 155, 211, 182, 155, 116, 29, 12, 235, 39, 120, 61, 238, 228, 78, 78, 29, 178, 197, 255, 52, 185, 164, 93, 132, 148, 163, 18, 168, 33, 44, 134, 83, 29, 249, 125, 166, 9, 211, 185, 82, 34, 99, 148, 121, 5, 114, 121, 41, 237, 194, 95, 80, 109, 247, 67, 238, 79, 200, 238, 178, 171, 47, 139, 138, 11, 26, 108, 22, 209, 244, 74, 6, 17, 164, 91, 111, 118, 100, 139, 205, 38, 213, 121, 250, 105, 51, 79, 228, 85, 111, 255, 26, 253, 154, 168, 212, 164, 22, 152, 185, 219, 58, 205, 182, 239, 137, 180, 82, 235, 101, 23, 93, 224, 96, 190, 43, 11, 183, 88, 237, 137, 193, 232, 156, 146, 174, 202, 44, 39, 49, 111, 198, 3, 44, 201, 32, 103, 132, 89, 10, 94, 203, 184, 64, 222, 78, 213, 92, 99, 74, 36, 229, 181, 181, 194, 62, 89, 102, 10, 98, 47, 241, 137, 250, 255, 219, 151, 85, 145, 205, 7, 34, 127, 226, 95, 200, 46, 36, 17, 243, 26, 38, 130, 139, 167, 215, 248, 100, 188, 6, 116, 142, 149, 249, 213, 198, 117, 43, 155, 240, 53, 202, 154, 253, 60, 78, 131, 30, 53, 59, 239, 67, 192, 197, 112, 100, 93, 255, 141, 85, 67, 172, 12, 167, 0, 13, 188, 129, 67, 127, 145, 220, 87, 22, 210, 46, 194, 105, 142, 151, 239, 192, 137, 218, 176, 178, 100, 62, 229, 212, 215, 195, 160, 29, 14, 177, 139, 124, 62, 142, 182, 34, 86, 149, 18, 106, 107, 215, 34, 130, 75, 181, 147, 5, 244, 131, 18, 25, 81, 63, 243, 228, 110, 188, 37, 142, 244, 25, 11, 210, 75, 26, 58, 37, 17, 46, 43, 179, 68, 0, 128, 84, 65, 169, 180, 244, 47, 114, 9, 96, 248, 216, 27, 157, 209, 39, 252, 25, 61, 203, 232, 148, 172, 157, 1, 48, 35, 24, 149, 87, 0, 154, 185, 121, 29, 233, 191, 234, 241, 109, 98, 30, 221, 214, 82, 238, 90, 212, 107, 205, 91, 222, 55, 181, 48, 156, 197, 78, 157, 139, 235, 169, 24, 243, 88, 230, 248, 87, 238, 146, 162, 45, 99, 222, 148, 133, 169, 41, 129, 46, 223, 223, 43, 251, 56, 5, 195, 101, 79, 15, 122, 137, 119, 192, 109, 211, 56, 33, 101, 49, 243, 82, 92, 93, 112, 115, 91, 202, 166, 57, 203, 165, 206, 134, 5, 10, 67, 157, 231, 38, 184, 188, 160, 206, 222, 183, 207, 212, 239, 167, 45, 121, 230, 184, 55, 147, 79, 5, 148, 176, 170, 74, 84, 17, 230, 112, 247, 198, 248, 70, 223, 205, 183, 133, 40, 7, 243, 102, 236, 53, 69, 67, 73, 50, 138, 50, 36, 199, 25, 146, 141, 162, 178, 93, 110, 156, 202, 72, 232, 51, 29, 156, 254, 42, 94, 113, 105, 138, 3, 45, 89, 58, 145, 99, 87, 246, 65, 118, 229, 216, 220, 169, 127, 206, 169, 142, 95, 155, 28, 43, 128, 13, 76, 5, 138, 15, 76, 239, 59, 248, 230, 97, 240, 3, 172, 68, 191, 165, 101, 68, 233, 66, 3, 218, 174, 118, 118, 81, 56, 127, 53, 156, 74, 150, 188, 12, 47, 11, 251, 197, 169, 70, 110, 67, 209, 139, 45, 200, 57, 206, 205, 22, 75, 53, 87, 63, 34, 207, 81, 153, 183, 54, 251, 107, 193, 139, 66, 237, 104, 5, 33, 38, 93, 190, 136, 235, 164, 58, 115, 109, 177, 34, 15, 208, 193, 175, 21, 5, 128, 255, 161, 158, 100, 4, 99, 30, 237, 212, 167, 208, 170, 31, 20, 137, 217, 213, 244, 100, 6, 110, 139, 131, 67, 44, 100, 24, 246, 35, 135, 139, 135, 221, 254, 168, 247, 177, 9, 200, 13, 92, 163, 162, 253, 192, 153, 10, 118, 71, 66, 65, 132, 227, 136, 104, 11, 103, 164, 63, 190, 181, 135, 140, 162, 237, 223, 52, 53, 211, 156, 28, 171, 224, 69, 40, 77, 196, 54, 99, 220, 214, 128, 5, 177, 177, 188, 78, 180, 83, 219, 160, 122, 140, 79, 244, 53, 57, 92, 94, 186, 17, 148, 52, 99, 202, 1, 121, 199, 28, 121, 175, 89, 251, 144, 39, 117, 252, 84, 253, 109, 68, 121, 82, 235, 176, 76, 83, 119, 16, 186, 94, 145, 11, 42, 60, 137, 18, 217, 69, 150, 69, 244, 232, 31, 76, 183, 58, 140, 111, 57, 149, 40, 26, 177, 79, 222, 235, 18, 227, 170, 47, 39, 177, 96, 106, 15, 170, 96, 36, 32, 147, 189, 227, 195, 40, 255, 180, 223, 9, 169, 68, 170, 149, 62, 72, 131, 193, 152, 7, 243, 75, 73, 97, 132, 115, 90, 80, 21, 214, 19, 182, 153, 198, 139, 68, 249, 21, 148, 89, 39, 108, 149, 5, 129, 96, 26, 21, 144, 236, 179, 160, 213, 108, 237, 111, 188, 51, 164, 130, 1, 63, 48, 130, 1, 59, 160, 3, 2, 1, 18, 162, 130, 1, 50, 4, 130, 1, 46, 132, 58, 70, 180, 118, 76, 164, 13, 174, 223, 44, 210, 119, 10, 168, 231, 247, 137, 253, 0, 147, 51, 147, 79, 64, 225, 162, 243, 64, 198, 106, 116, 122, 159, 132, 137, 232, 183, 137, 33, 162, 232, 196, 68, 112, 126, 64, 155, 62, 200, 181, 67, 40, 221, 74, 128, 117, 140, 57, 200, 172, 159, 121, 52, 122, 50, 39, 240, 175, 114, 10, 88, 171, 54, 116, 167, 7, 124, 93, 163, 59, 179, 206, 210, 91, 126, 205, 57, 115, 78, 180, 28, 107, 61, 141, 6, 140, 62, 77, 85, 238, 185, 48, 140, 110, 207, 21, 19, 215, 208, 77, 240, 165, 86, 2, 229, 151, 16, 91, 105, 6, 94, 158, 76, 182, 8, 244, 219, 144, 3, 186, 128, 170, 213, 97, 69, 240, 124, 236, 93, 147, 248, 221, 9, 43, 164, 185, 248, 67, 205, 74, 138, 9, 38, 149, 13, 198, 28, 40, 27, 84, 11, 17, 216, 24, 158, 156, 247, 65, 97, 65, 24, 187, 83, 92, 147, 203, 255, 213, 15, 109, 70, 251, 65, 36, 237, 175, 239, 41, 141, 249, 223, 134, 52, 53, 45, 193, 159, 184, 133, 93, 114, 189, 62, 16, 153, 182, 134, 210, 232, 230, 224, 31, 87, 142, 243, 63, 220, 180, 223, 196, 21, 52, 70, 254, 208, 122, 5, 169, 160, 148, 100, 219, 162, 142, 128, 131, 201, 197, 111, 208, 225, 174, 58, 77, 146, 16, 72, 221, 17, 132, 154, 11, 34, 102, 199, 154, 25, 111, 228, 229, 86, 208, 103, 90, 93, 239, 143, 131, 17, 122, 68, 45, 135, 227, 213, 105, 238, 55, 56, 254, 133, 76, 167, 163, 44, 163, 19, 29, 76, 244, 42, 72, 96, 219, 91, 235, 28, 9, 103, 117, 237]
            },
        },
        [5, 0, 11, 7, 16, 0, 0, 0, 88, 6, 220, 5, 1, 0, 0, 0, 208, 22, 208, 22, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0, 96, 89, 120, 185, 79, 82, 223, 17, 139, 109, 131, 220, 222, 215, 32, 133, 1, 0, 0, 0, 51, 5, 113, 113, 186, 190, 55, 73, 131, 25, 181, 219, 239, 156, 204, 54, 1, 0, 0, 0, 1, 0, 1, 0, 96, 89, 120, 185, 79, 82, 223, 17, 139, 109, 131, 220, 222, 215, 32, 133, 1, 0, 0, 0, 44, 28, 183, 108, 18, 152, 64, 69, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 16, 6, 0, 0, 0, 0, 0, 0, 110, 130, 5, 216, 48, 130, 5, 212, 160, 3, 2, 1, 5, 161, 3, 2, 1, 14, 162, 7, 3, 5, 0, 32, 0, 0, 0, 163, 130, 4, 122, 97, 130, 4, 118, 48, 130, 4, 114, 160, 3, 2, 1, 5, 161, 9, 27, 7, 84, 66, 84, 46, 67, 79, 77, 162, 42, 48, 40, 160, 3, 2, 1, 2, 161, 33, 48, 31, 27, 4, 104, 111, 115, 116, 27, 23, 119, 105, 110, 45, 57, 53, 54, 99, 113, 111, 115, 115, 106, 116, 102, 46, 116, 98, 116, 46, 99, 111, 109, 163, 130, 4, 50, 48, 130, 4, 46, 160, 3, 2, 1, 18, 161, 3, 2, 1, 9, 162, 130, 4, 32, 4, 130, 4, 28, 44, 103, 214, 219, 239, 134, 71, 190, 93, 33, 211, 36, 190, 6, 172, 121, 2, 89, 207, 145, 220, 145, 172, 231, 91, 117, 132, 111, 90, 170, 93, 68, 125, 232, 140, 82, 149, 113, 166, 160, 177, 128, 211, 60, 148, 255, 76, 218, 44, 251, 207, 172, 107, 5, 100, 116, 150, 169, 166, 9, 243, 215, 68, 138, 147, 181, 172, 57, 147, 162, 119, 199, 59, 114, 24, 246, 77, 200, 11, 70, 50, 177, 82, 16, 66, 204, 205, 184, 46, 235, 136, 252, 175, 19, 54, 232, 224, 42, 167, 220, 22, 230, 36, 196, 53, 64, 242, 190, 202, 121, 185, 201, 34, 254, 147, 167, 94, 244, 59, 7, 50, 175, 224, 79, 20, 81, 165, 16, 10, 139, 62, 188, 123, 240, 61, 227, 185, 45, 183, 229, 204, 78, 87, 196, 197, 234, 229, 130, 158, 133, 212, 167, 240, 86, 39, 192, 130, 213, 211, 136, 250, 130, 143, 151, 0, 242, 199, 20, 5, 218, 217, 222, 115, 183, 135, 28, 162, 0, 206, 176, 200, 131, 43, 121, 200, 78, 64, 202, 103, 223, 65, 195, 173, 108, 127, 210, 56, 103, 73, 27, 111, 57, 221, 127, 168, 81, 65, 65, 48, 231, 188, 175, 218, 158, 56, 220, 28, 51, 18, 78, 65, 9, 117, 136, 225, 226, 155, 211, 182, 155, 116, 29, 12, 235, 39, 120, 61, 238, 228, 78, 78, 29, 178, 197, 255, 52, 185, 164, 93, 132, 148, 163, 18, 168, 33, 44, 134, 83, 29, 249, 125, 166, 9, 211, 185, 82, 34, 99, 148, 121, 5, 114, 121, 41, 237, 194, 95, 80, 109, 247, 67, 238, 79, 200, 238, 178, 171, 47, 139, 138, 11, 26, 108, 22, 209, 244, 74, 6, 17, 164, 91, 111, 118, 100, 139, 205, 38, 213, 121, 250, 105, 51, 79, 228, 85, 111, 255, 26, 253, 154, 168, 212, 164, 22, 152, 185, 219, 58, 205, 182, 239, 137, 180, 82, 235, 101, 23, 93, 224, 96, 190, 43, 11, 183, 88, 237, 137, 193, 232, 156, 146, 174, 202, 44, 39, 49, 111, 198, 3, 44, 201, 32, 103, 132, 89, 10, 94, 203, 184, 64, 222, 78, 213, 92, 99, 74, 36, 229, 181, 181, 194, 62, 89, 102, 10, 98, 47, 241, 137, 250, 255, 219, 151, 85, 145, 205, 7, 34, 127, 226, 95, 200, 46, 36, 17, 243, 26, 38, 130, 139, 167, 215, 248, 100, 188, 6, 116, 142, 149, 249, 213, 198, 117, 43, 155, 240, 53, 202, 154, 253, 60, 78, 131, 30, 53, 59, 239, 67, 192, 197, 112, 100, 93, 255, 141, 85, 67, 172, 12, 167, 0, 13, 188, 129, 67, 127, 145, 220, 87, 22, 210, 46, 194, 105, 142, 151, 239, 192, 137, 218, 176, 178, 100, 62, 229, 212, 215, 195, 160, 29, 14, 177, 139, 124, 62, 142, 182, 34, 86, 149, 18, 106, 107, 215, 34, 130, 75, 181, 147, 5, 244, 131, 18, 25, 81, 63, 243, 228, 110, 188, 37, 142, 244, 25, 11, 210, 75, 26, 58, 37, 17, 46, 43, 179, 68, 0, 128, 84, 65, 169, 180, 244, 47, 114, 9, 96, 248, 216, 27, 157, 209, 39, 252, 25, 61, 203, 232, 148, 172, 157, 1, 48, 35, 24, 149, 87, 0, 154, 185, 121, 29, 233, 191, 234, 241, 109, 98, 30, 221, 214, 82, 238, 90, 212, 107, 205, 91, 222, 55, 181, 48, 156, 197, 78, 157, 139, 235, 169, 24, 243, 88, 230, 248, 87, 238, 146, 162, 45, 99, 222, 148, 133, 169, 41, 129, 46, 223, 223, 43, 251, 56, 5, 195, 101, 79, 15, 122, 137, 119, 192, 109, 211, 56, 33, 101, 49, 243, 82, 92, 93, 112, 115, 91, 202, 166, 57, 203, 165, 206, 134, 5, 10, 67, 157, 231, 38, 184, 188, 160, 206, 222, 183, 207, 212, 239, 167, 45, 121, 230, 184, 55, 147, 79, 5, 148, 176, 170, 74, 84, 17, 230, 112, 247, 198, 248, 70, 223, 205, 183, 133, 40, 7, 243, 102, 236, 53, 69, 67, 73, 50, 138, 50, 36, 199, 25, 146, 141, 162, 178, 93, 110, 156, 202, 72, 232, 51, 29, 156, 254, 42, 94, 113, 105, 138, 3, 45, 89, 58, 145, 99, 87, 246, 65, 118, 229, 216, 220, 169, 127, 206, 169, 142, 95, 155, 28, 43, 128, 13, 76, 5, 138, 15, 76, 239, 59, 248, 230, 97, 240, 3, 172, 68, 191, 165, 101, 68, 233, 66, 3, 218, 174, 118, 118, 81, 56, 127, 53, 156, 74, 150, 188, 12, 47, 11, 251, 197, 169, 70, 110, 67, 209, 139, 45, 200, 57, 206, 205, 22, 75, 53, 87, 63, 34, 207, 81, 153, 183, 54, 251, 107, 193, 139, 66, 237, 104, 5, 33, 38, 93, 190, 136, 235, 164, 58, 115, 109, 177, 34, 15, 208, 193, 175, 21, 5, 128, 255, 161, 158, 100, 4, 99, 30, 237, 212, 167, 208, 170, 31, 20, 137, 217, 213, 244, 100, 6, 110, 139, 131, 67, 44, 100, 24, 246, 35, 135, 139, 135, 221, 254, 168, 247, 177, 9, 200, 13, 92, 163, 162, 253, 192, 153, 10, 118, 71, 66, 65, 132, 227, 136, 104, 11, 103, 164, 63, 190, 181, 135, 140, 162, 237, 223, 52, 53, 211, 156, 28, 171, 224, 69, 40, 77, 196, 54, 99, 220, 214, 128, 5, 177, 177, 188, 78, 180, 83, 219, 160, 122, 140, 79, 244, 53, 57, 92, 94, 186, 17, 148, 52, 99, 202, 1, 121, 199, 28, 121, 175, 89, 251, 144, 39, 117, 252, 84, 253, 109, 68, 121, 82, 235, 176, 76, 83, 119, 16, 186, 94, 145, 11, 42, 60, 137, 18, 217, 69, 150, 69, 244, 232, 31, 76, 183, 58, 140, 111, 57, 149, 40, 26, 177, 79, 222, 235, 18, 227, 170, 47, 39, 177, 96, 106, 15, 170, 96, 36, 32, 147, 189, 227, 195, 40, 255, 180, 223, 9, 169, 68, 170, 149, 62, 72, 131, 193, 152, 7, 243, 75, 73, 97, 132, 115, 90, 80, 21, 214, 19, 182, 153, 198, 139, 68, 249, 21, 148, 89, 39, 108, 149, 5, 129, 96, 26, 21, 144, 236, 179, 160, 213, 108, 237, 111, 188, 51, 164, 130, 1, 63, 48, 130, 1, 59, 160, 3, 2, 1, 18, 162, 130, 1, 50, 4, 130, 1, 46, 132, 58, 70, 180, 118, 76, 164, 13, 174, 223, 44, 210, 119, 10, 168, 231, 247, 137, 253, 0, 147, 51, 147, 79, 64, 225, 162, 243, 64, 198, 106, 116, 122, 159, 132, 137, 232, 183, 137, 33, 162, 232, 196, 68, 112, 126, 64, 155, 62, 200, 181, 67, 40, 221, 74, 128, 117, 140, 57, 200, 172, 159, 121, 52, 122, 50, 39, 240, 175, 114, 10, 88, 171, 54, 116, 167, 7, 124, 93, 163, 59, 179, 206, 210, 91, 126, 205, 57, 115, 78, 180, 28, 107, 61, 141, 6, 140, 62, 77, 85, 238, 185, 48, 140, 110, 207, 21, 19, 215, 208, 77, 240, 165, 86, 2, 229, 151, 16, 91, 105, 6, 94, 158, 76, 182, 8, 244, 219, 144, 3, 186, 128, 170, 213, 97, 69, 240, 124, 236, 93, 147, 248, 221, 9, 43, 164, 185, 248, 67, 205, 74, 138, 9, 38, 149, 13, 198, 28, 40, 27, 84, 11, 17, 216, 24, 158, 156, 247, 65, 97, 65, 24, 187, 83, 92, 147, 203, 255, 213, 15, 109, 70, 251, 65, 36, 237, 175, 239, 41, 141, 249, 223, 134, 52, 53, 45, 193, 159, 184, 133, 93, 114, 189, 62, 16, 153, 182, 134, 210, 232, 230, 224, 31, 87, 142, 243, 63, 220, 180, 223, 196, 21, 52, 70, 254, 208, 122, 5, 169, 160, 148, 100, 219, 162, 142, 128, 131, 201, 197, 111, 208, 225, 174, 58, 77, 146, 16, 72, 221, 17, 132, 154, 11, 34, 102, 199, 154, 25, 111, 228, 229, 86, 208, 103, 90, 93, 239, 143, 131, 17, 122, 68, 45, 135, 227, 213, 105, 238, 55, 56, 254, 133, 76, 167, 163, 44, 163, 19, 29, 76, 244, 42, 72, 96, 219, 91, 235, 28, 9, 103, 117, 237]
    }

    test_encoding_decoding! {
        pdu_bind_ack,
        Pdu,
        Pdu {
            header: PduHeader {
                version: 5,
                version_minor: 0,
                packet_type: PacketType::BindAck,
                packet_flags: PacketFlags::PfcSupportHeaderSign | PacketFlags::PfcLastFrag | PacketFlags::PfcFirstFrag,
                data_rep: DataRepresentation {
                    byte_order: IntegerRepresentation::LittleEndian,
                    character: CharacterRepresentation::Ascii,
                    floating_point: FloatingPointRepresentation::Ieee,
                },
                frag_len: 230,
                auth_len: 138,
                call_id: 1,
            },
            data: PduData::BindAck(BindAck {
                max_xmit_frag: 5840,
                max_recv_frag: 5840,
                assoc_group: 0x00007320,
                sec_addr: String::from("49668"),
                results: vec![
                    ContextResult {
                        result: ContextResultCode::Acceptance,
                        reason: 0,
                        syntax: Uuid::from_str("71710533-beba-4937-8319-b5dbef9ccc36").unwrap(),
                        syntax_version: 1,
                    },
                    ContextResult {
                        result: ContextResultCode::NegotiateAck,
                        reason: 0,
                        syntax: Uuid::from_str("00000000-0000-0000-0000-000000000000").unwrap(),
                        syntax_version: 0,
                    },
                ],
            }),
            security_trailer: SecurityTrailer {
                security_type: SecurityProvider::RpcCAuthnGssKerberos,
                level: AuthenticationLevel::RpcCAuthnLevelPktPrivacy,
                pad_length: 0,
                context_id: 0,
                auth_value: vec![111, 129, 135, 48, 129, 132, 160, 3, 2, 1, 5, 161, 3, 2, 1, 15, 162, 120, 48, 118, 160, 3, 2, 1, 18, 162, 111, 4, 109, 119, 103, 226, 62, 224, 40, 10, 92, 235, 148, 195, 168, 140, 247, 167, 45, 22, 189, 35, 181, 182, 57, 109, 10, 207, 215, 253, 118, 167, 212, 69, 43, 39, 201, 54, 64, 99, 241, 39, 189, 178, 98, 111, 37, 181, 177, 174, 239, 217, 11, 149, 100, 143, 41, 205, 36, 175, 207, 83, 14, 69, 197, 91, 154, 186, 114, 47, 121, 9, 37, 33, 107, 120, 161, 209, 114, 38, 201, 202, 210, 13, 59, 9, 29, 146, 85, 134, 67, 107, 99, 129, 40, 249, 200, 138, 117, 235, 104, 139, 93, 199, 167, 84, 119, 12, 90, 55, 27, 109]
            },
        },
        [5, 0, 12, 7, 16, 0, 0, 0, 230, 0, 138, 0, 1, 0, 0, 0, 208, 22, 208, 22, 32, 115, 0, 0, 6, 0, 52, 57, 54, 54, 56, 0, 2, 0, 0, 0, 0, 0, 0, 0, 51, 5, 113, 113, 186, 190, 55, 73, 131, 25, 181, 219, 239, 156, 204, 54, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 6, 0, 0, 0, 0, 0, 0, 111, 129, 135, 48, 129, 132, 160, 3, 2, 1, 5, 161, 3, 2, 1, 15, 162, 120, 48, 118, 160, 3, 2, 1, 18, 162, 111, 4, 109, 119, 103, 226, 62, 224, 40, 10, 92, 235, 148, 195, 168, 140, 247, 167, 45, 22, 189, 35, 181, 182, 57, 109, 10, 207, 215, 253, 118, 167, 212, 69, 43, 39, 201, 54, 64, 99, 241, 39, 189, 178, 98, 111, 37, 181, 177, 174, 239, 217, 11, 149, 100, 143, 41, 205, 36, 175, 207, 83, 14, 69, 197, 91, 154, 186, 114, 47, 121, 9, 37, 33, 107, 120, 161, 209, 114, 38, 201, 202, 210, 13, 59, 9, 29, 146, 85, 134, 67, 107, 99, 129, 40, 249, 200, 138, 117, 235, 104, 139, 93, 199, 167, 84, 119, 12, 90, 55, 27, 109]
    }

    test_encoding_decoding! {
        pdu_alter_context,
        Pdu,
        Pdu {
            header: PduHeader {
                version: 5,
                version_minor: 0,
                packet_type: PacketType::AlterContext,
                packet_flags: PacketFlags::PfcSupportHeaderSign | PacketFlags::PfcLastFrag | PacketFlags::PfcFirstFrag,
                data_rep: DataRepresentation {
                    byte_order: IntegerRepresentation::LittleEndian,
                    character: CharacterRepresentation::Ascii,
                    floating_point: FloatingPointRepresentation::Ieee,
                },
                frag_len: 173,
                auth_len: 93,
                call_id: 1,
            },
            data: PduData::AlterContext(AlterContext(Bind {
                max_xmit_frag: 5840,
                max_recv_frag: 5840,
                assoc_group: 0,
                contexts: vec![
                    ContextElement {
                        context_id: 0,
                        abstract_syntax: SyntaxId {
                            uuid: Uuid::from_str("b9785960-524f-11df-8b6d-83dcded72085").unwrap(),
                            version: 1,
                            version_minor: 0,
                        },
                        transfer_syntaxes: vec![
                            SyntaxId {
                                uuid: Uuid::from_str("71710533-beba-4937-8319-b5dbef9ccc36").unwrap(),
                                version: 1,
                                version_minor: 0,
                            }
                        ]
                    },
                ],
            })),
            security_trailer: SecurityTrailer {
                security_type: SecurityProvider::RpcCAuthnGssKerberos,
                level: AuthenticationLevel::RpcCAuthnLevelPktPrivacy,
                pad_length: 0,
                context_id: 0,
                auth_value: vec![111, 91, 48, 89, 160, 3, 2, 1, 5, 161, 3, 2, 1, 15, 162, 77, 48, 75, 160, 3, 2, 1, 18, 162, 68, 4, 66, 169, 200, 55, 118, 91, 23, 32, 40, 237, 31, 41, 10, 235, 96, 11, 206, 91, 184, 138, 167, 37, 44, 224, 129, 132, 69, 220, 201, 123, 20, 243, 60, 251, 187, 228, 62, 104, 246, 170, 121, 102, 22, 16, 1, 222, 154, 38, 2, 94, 168, 232, 219, 6, 47, 32, 21, 238, 30, 254, 203, 201, 245, 242, 109, 43, 132]
            },
        },
        [5, 0, 14, 7, 16, 0, 0, 0, 173, 0, 93, 0, 1, 0, 0, 0, 208, 22, 208, 22, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 96, 89, 120, 185, 79, 82, 223, 17, 139, 109, 131, 220, 222, 215, 32, 133, 1, 0, 0, 0, 51, 5, 113, 113, 186, 190, 55, 73, 131, 25, 181, 219, 239, 156, 204, 54, 1, 0, 0, 0, 16, 6, 0, 0, 0, 0, 0, 0, 111, 91, 48, 89, 160, 3, 2, 1, 5, 161, 3, 2, 1, 15, 162, 77, 48, 75, 160, 3, 2, 1, 18, 162, 68, 4, 66, 169, 200, 55, 118, 91, 23, 32, 40, 237, 31, 41, 10, 235, 96, 11, 206, 91, 184, 138, 167, 37, 44, 224, 129, 132, 69, 220, 201, 123, 20, 243, 60, 251, 187, 228, 62, 104, 246, 170, 121, 102, 22, 16, 1, 222, 154, 38, 2, 94, 168, 232, 219, 6, 47, 32, 21, 238, 30, 254, 203, 201, 245, 242, 109, 43, 132]
    }

    test_encoding_decoding! {
        pdu_alter_context_response,
        Pdu,
        Pdu {
            header: PduHeader {
                version: 5,
                version_minor: 0,
                packet_type: PacketType::AlterContextResponse,
                packet_flags: PacketFlags::PfcSupportHeaderSign | PacketFlags::PfcLastFrag | PacketFlags::PfcFirstFrag,
                data_rep: DataRepresentation {
                    byte_order: IntegerRepresentation::LittleEndian,
                    character: CharacterRepresentation::Ascii,
                    floating_point: FloatingPointRepresentation::Ieee,
                },
                frag_len: 64,
                auth_len: 0,
                call_id: 1,
            },
            data: PduData::AlterContextResponse(AlterContextResponse(BindAck {
                max_xmit_frag: 5840,
                max_recv_frag: 5840,
                assoc_group: 0x00007320,
                sec_addr: String::new(),
                results: vec![
                    ContextResult {
                        result: ContextResultCode::Acceptance,
                        reason: 0,
                        syntax: Uuid::from_str("71710533-beba-4937-8319-b5dbef9ccc36").unwrap(),
                        syntax_version: 1,
                    },
                ],
            })),
            security_trailer: SecurityTrailer {
                security_type: SecurityProvider::RpcCAuthnGssKerberos,
                level: AuthenticationLevel::RpcCAuthnLevelPktPrivacy,
                pad_length: 0,
                context_id: 0,
                auth_value: Vec::new(),
            },
        },
        [5, 0, 15, 7, 16, 0, 0, 0, 64, 0, 0, 0, 1, 0, 0, 0, 208, 22, 208, 22, 32, 115, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 51, 5, 113, 113, 186, 190, 55, 73, 131, 25, 181, 219, 239, 156, 204, 54, 1, 0, 0, 0, 16, 6, 0, 0, 0, 0, 0, 0]
    }

    test_encoding_decoding! {
        pdu_request,
        Pdu,
        Pdu {
            header: PduHeader {
                version: 5,
                version_minor: 0,
                packet_type: PacketType::Request,
                packet_flags: PacketFlags::PfcLastFrag | PacketFlags::PfcFirstFrag,
                data_rep: DataRepresentation {
                    byte_order: IntegerRepresentation::LittleEndian,
                    character: CharacterRepresentation::Ascii,
                    floating_point: FloatingPointRepresentation::Ieee,
                },
                frag_len: 332,
                auth_len: 76,
                call_id: 1,
            },
            data: PduData::Request(Request {
                alloc_hint: 224,
                context_id: 0,
                opnum: 0,
                obj: None,
                stub_data: vec![70, 145, 235, 30, 109, 26, 31, 173, 254, 42, 137, 229, 243, 197, 44, 158, 238, 241, 41, 183, 81, 67, 57, 200, 254, 191, 147, 127, 205, 26, 3, 40, 255, 194, 91, 96, 55, 224, 130, 204, 168, 191, 33, 234, 237, 111, 175, 214, 140, 82, 127, 41, 174, 170, 228, 93, 51, 220, 223, 202, 204, 131, 102, 248, 202, 155, 5, 129, 117, 2, 229, 154, 46, 85, 137, 43, 189, 80, 105, 195, 207, 206, 50, 225, 121, 213, 208, 156, 244, 102, 76, 112, 244, 57, 173, 67, 116, 129, 185, 143, 232, 121, 52, 62, 241, 0, 14, 31, 208, 226, 155, 175, 16, 174, 156, 17, 53, 0, 163, 190, 217, 253, 107, 13, 206, 7, 225, 139, 156, 203, 149, 7, 247, 94, 222, 106, 236, 20, 57, 137, 82, 83, 240, 38, 131, 217, 130, 188, 85, 50, 55, 154, 150, 64, 148, 170, 48, 56, 219, 253, 162, 223, 243, 244, 116, 25, 228, 155, 93, 106, 187, 240, 80, 24, 0, 146, 192, 248, 239, 98, 144, 160, 17, 70, 74, 18, 17, 117, 215, 151, 189, 241, 77, 32, 193, 180, 71, 172, 118, 69, 103, 165, 79, 159, 190, 42, 51, 243, 86, 224, 148, 94, 89, 138, 70, 16, 158, 43, 179, 125, 70, 252, 89, 109],
            }),
            security_trailer: SecurityTrailer {
                security_type: SecurityProvider::RpcCAuthnGssNegotiate,
                level: AuthenticationLevel::RpcCAuthnLevelPktPrivacy,
                pad_length: 8,
                context_id: 0,
                auth_value: vec![5, 4, 6, 255, 0, 16, 0, 28, 0, 0, 0, 0, 79, 12, 105, 32, 144, 245, 113, 202, 80, 221, 101, 212, 65, 96, 235, 157, 134, 111, 198, 10, 115, 62, 240, 22, 254, 69, 248, 210, 242, 96, 170, 195, 58, 55, 129, 156, 207, 68, 71, 29, 72, 179, 60, 55, 242, 152, 3, 186, 10, 255, 63, 87, 127, 71, 33, 237, 173, 182, 94, 104, 149, 226, 47, 85],
            },
        },
        [5, 0, 0, 3, 16, 0, 0, 0, 76, 1, 76, 0, 1, 0, 0, 0, 224, 0, 0, 0, 0, 0, 0, 0, 70, 145, 235, 30, 109, 26, 31, 173, 254, 42, 137, 229, 243, 197, 44, 158, 238, 241, 41, 183, 81, 67, 57, 200, 254, 191, 147, 127, 205, 26, 3, 40, 255, 194, 91, 96, 55, 224, 130, 204, 168, 191, 33, 234, 237, 111, 175, 214, 140, 82, 127, 41, 174, 170, 228, 93, 51, 220, 223, 202, 204, 131, 102, 248, 202, 155, 5, 129, 117, 2, 229, 154, 46, 85, 137, 43, 189, 80, 105, 195, 207, 206, 50, 225, 121, 213, 208, 156, 244, 102, 76, 112, 244, 57, 173, 67, 116, 129, 185, 143, 232, 121, 52, 62, 241, 0, 14, 31, 208, 226, 155, 175, 16, 174, 156, 17, 53, 0, 163, 190, 217, 253, 107, 13, 206, 7, 225, 139, 156, 203, 149, 7, 247, 94, 222, 106, 236, 20, 57, 137, 82, 83, 240, 38, 131, 217, 130, 188, 85, 50, 55, 154, 150, 64, 148, 170, 48, 56, 219, 253, 162, 223, 243, 244, 116, 25, 228, 155, 93, 106, 187, 240, 80, 24, 0, 146, 192, 248, 239, 98, 144, 160, 17, 70, 74, 18, 17, 117, 215, 151, 189, 241, 77, 32, 193, 180, 71, 172, 118, 69, 103, 165, 79, 159, 190, 42, 51, 243, 86, 224, 148, 94, 89, 138, 70, 16, 158, 43, 179, 125, 70, 252, 89, 109, 9, 6, 8, 0, 0, 0, 0, 0, 5, 4, 6, 255, 0, 16, 0, 28, 0, 0, 0, 0, 79, 12, 105, 32, 144, 245, 113, 202, 80, 221, 101, 212, 65, 96, 235, 157, 134, 111, 198, 10, 115, 62, 240, 22, 254, 69, 248, 210, 242, 96, 170, 195, 58, 55, 129, 156, 207, 68, 71, 29, 72, 179, 60, 55, 242, 152, 3, 186, 10, 255, 63, 87, 127, 71, 33, 237, 173, 182, 94, 104, 149, 226, 47, 85]
    }

    test_encoding_decoding! {
        pdu_response,
        Pdu,
        Pdu {
            header: PduHeader {
                version: 5,
                version_minor: 0,
                packet_type: PacketType::Response,
                packet_flags: PacketFlags::PfcLastFrag | PacketFlags::PfcFirstFrag,
                data_rep: DataRepresentation {
                    byte_order: IntegerRepresentation::LittleEndian,
                    character: CharacterRepresentation::Ascii,
                    floating_point: FloatingPointRepresentation::Ieee,
                },
                frag_len: 988,
                auth_len: 76,
                call_id: 1,
            },
            data: PduData::Response(Response {
                alloc_hint: 868,
                context_id: 0,
                cancel_count: 0,
                stub_data: vec![140, 22, 170, 99, 118, 14, 170, 89, 139, 87, 80, 46, 170, 201, 100, 178, 117, 90, 91, 192, 162, 184, 19, 212, 23, 128, 138, 18, 254, 148, 164, 176, 99, 3, 173, 76, 201, 138, 131, 120, 250, 252, 185, 253, 65, 241, 2, 186, 42, 19, 121, 1, 56, 123, 222, 239, 124, 245, 220, 6, 164, 22, 214, 134, 144, 90, 18, 29, 229, 134, 221, 54, 240, 230, 26, 15, 183, 249, 98, 170, 169, 13, 141, 38, 170, 51, 82, 88, 193, 175, 211, 154, 234, 11, 120, 56, 240, 19, 15, 136, 13, 165, 63, 206, 201, 2, 9, 53, 183, 29, 88, 92, 143, 244, 110, 255, 33, 255, 9, 164, 168, 238, 77, 141, 6, 49, 232, 211, 232, 67, 105, 186, 181, 12, 147, 155, 165, 12, 73, 47, 8, 63, 114, 12, 1, 119, 37, 88, 209, 138, 30, 193, 104, 26, 204, 45, 221, 177, 79, 4, 80, 120, 16, 48, 168, 28, 112, 192, 173, 111, 216, 0, 229, 10, 241, 0, 179, 123, 144, 120, 181, 45, 149, 22, 121, 85, 167, 150, 73, 171, 76, 123, 5, 51, 58, 235, 34, 173, 73, 96, 1, 231, 83, 68, 203, 207, 59, 172, 137, 103, 1, 47, 188, 188, 72, 162, 133, 233, 185, 129, 155, 35, 73, 16, 197, 86, 236, 182, 255, 170, 26, 28, 107, 235, 192, 25, 233, 58, 230, 85, 181, 124, 234, 193, 229, 193, 13, 228, 61, 90, 160, 247, 223, 86, 113, 113, 233, 164, 118, 29, 108, 140, 188, 74, 59, 94, 73, 241, 159, 3, 113, 28, 212, 36, 111, 141, 154, 108, 79, 109, 134, 117, 54, 188, 18, 219, 148, 76, 2, 102, 5, 150, 51, 29, 121, 251, 142, 73, 0, 169, 202, 237, 139, 213, 78, 61, 152, 81, 120, 35, 96, 5, 105, 156, 72, 85, 252, 158, 1, 103, 55, 143, 39, 64, 16, 225, 118, 137, 22, 239, 139, 203, 140, 120, 196, 170, 15, 247, 249, 173, 206, 49, 156, 75, 167, 89, 138, 238, 6, 61, 254, 124, 56, 187, 179, 236, 94, 108, 119, 151, 255, 148, 20, 57, 141, 125, 38, 56, 235, 77, 239, 74, 97, 67, 217, 43, 231, 154, 164, 168, 131, 90, 140, 173, 247, 93, 215, 67, 111, 162, 255, 42, 161, 7, 37, 216, 94, 246, 125, 27, 45, 198, 172, 118, 137, 6, 216, 65, 106, 142, 54, 200, 151, 220, 174, 145, 45, 145, 16, 70, 202, 204, 202, 244, 91, 50, 0, 36, 147, 175, 167, 20, 47, 228, 211, 2, 12, 56, 72, 107, 161, 6, 55, 209, 89, 45, 176, 95, 140, 212, 175, 99, 203, 43, 102, 59, 188, 43, 57, 178, 155, 166, 213, 125, 4, 68, 252, 236, 202, 188, 235, 35, 17, 249, 247, 133, 93, 49, 158, 87, 195, 167, 201, 40, 168, 18, 239, 164, 176, 52, 45, 137, 9, 243, 47, 80, 147, 49, 56, 176, 212, 198, 127, 46, 50, 108, 135, 76, 27, 34, 242, 99, 199, 36, 93, 22, 41, 65, 157, 80, 69, 68, 109, 160, 141, 197, 104, 127, 151, 200, 37, 200, 4, 168, 185, 206, 19, 240, 126, 191, 73, 169, 223, 222, 118, 240, 123, 176, 140, 184, 117, 180, 116, 194, 231, 223, 126, 134, 67, 223, 11, 52, 233, 59, 188, 121, 131, 65, 235, 134, 141, 55, 115, 84, 29, 125, 12, 108, 128, 123, 4, 253, 70, 37, 161, 15, 23, 198, 135, 37, 234, 123, 123, 107, 161, 237, 38, 116, 13, 116, 2, 99, 181, 75, 10, 18, 253, 115, 56, 250, 239, 17, 153, 89, 8, 199, 121, 67, 223, 178, 18, 115, 6, 22, 183, 105, 238, 77, 167, 54, 59, 171, 149, 228, 107, 235, 183, 59, 224, 211, 227, 7, 198, 165, 27, 206, 9, 249, 49, 229, 19, 158, 195, 80, 162, 185, 187, 6, 12, 105, 75, 209, 197, 133, 232, 143, 178, 56, 247, 210, 254, 96, 227, 94, 103, 170, 146, 149, 234, 138, 229, 84, 227, 191, 133, 168, 2, 158, 38, 17, 147, 0, 169, 84, 197, 61, 230, 69, 62, 204, 224, 85, 78, 106, 161, 171, 100, 77, 118, 217, 162, 198, 130, 211, 94, 189, 87, 163, 235, 44, 121, 156, 211, 82, 203, 196, 238, 113, 190, 225, 155, 209, 9, 141, 97, 155, 187, 222, 153, 224, 41, 107, 85, 198, 26, 170, 41, 20, 246, 170, 120, 87, 224, 40, 241, 118, 87, 195, 240, 45, 119, 19, 31, 48, 88, 134, 196, 129, 13, 23, 246, 89, 53, 175, 210, 14, 225, 198, 192, 159, 201, 51, 131, 42, 115, 220, 41, 11, 92, 22, 35, 148, 150, 224, 49, 14, 105, 92, 89, 67, 73, 230, 6, 236, 200, 210, 171, 170, 179, 201, 225, 37, 209, 67, 17, 59, 65, 44, 27, 75, 29, 133, 43, 121, 171, 206, 138, 112, 65, 206, 2, 96, 29, 250, 87, 170, 131, 178, 248, 130, 249, 228, 87, 37, 47, 79, 220, 166, 70, 254, 118, 165, 223, 62, 6, 17, 242, 61, 210, 255, 137, 9, 229, 155, 39, 171, 33, 2, 238, 93, 198, 146, 131, 236, 116, 236, 179, 184, 102, 59],
            }),
            security_trailer: SecurityTrailer {
                security_type: SecurityProvider::RpcCAuthnGssNegotiate,
                level: AuthenticationLevel::RpcCAuthnLevelPktPrivacy,
                pad_length: 12,
                context_id: 0,
                auth_value: vec![5, 4, 7, 255, 0, 16, 0, 28, 0, 0, 0, 0, 51, 128, 170, 35, 94, 238, 241, 97, 204, 124, 66, 162, 119, 57, 190, 117, 249, 25, 174, 246, 194, 102, 133, 211, 241, 188, 128, 195, 227, 189, 65, 195, 40, 30, 231, 115, 38, 58, 165, 66, 11, 106, 157, 183, 70, 85, 36, 135, 69, 247, 93, 97, 111, 229, 75, 25, 99, 208, 247, 253, 227, 122, 252, 85],
            },
        },
        [5, 0, 2, 3, 16, 0, 0, 0, 220, 3, 76, 0, 1, 0, 0, 0, 100, 3, 0, 0, 0, 0, 0, 0, 140, 22, 170, 99, 118, 14, 170, 89, 139, 87, 80, 46, 170, 201, 100, 178, 117, 90, 91, 192, 162, 184, 19, 212, 23, 128, 138, 18, 254, 148, 164, 176, 99, 3, 173, 76, 201, 138, 131, 120, 250, 252, 185, 253, 65, 241, 2, 186, 42, 19, 121, 1, 56, 123, 222, 239, 124, 245, 220, 6, 164, 22, 214, 134, 144, 90, 18, 29, 229, 134, 221, 54, 240, 230, 26, 15, 183, 249, 98, 170, 169, 13, 141, 38, 170, 51, 82, 88, 193, 175, 211, 154, 234, 11, 120, 56, 240, 19, 15, 136, 13, 165, 63, 206, 201, 2, 9, 53, 183, 29, 88, 92, 143, 244, 110, 255, 33, 255, 9, 164, 168, 238, 77, 141, 6, 49, 232, 211, 232, 67, 105, 186, 181, 12, 147, 155, 165, 12, 73, 47, 8, 63, 114, 12, 1, 119, 37, 88, 209, 138, 30, 193, 104, 26, 204, 45, 221, 177, 79, 4, 80, 120, 16, 48, 168, 28, 112, 192, 173, 111, 216, 0, 229, 10, 241, 0, 179, 123, 144, 120, 181, 45, 149, 22, 121, 85, 167, 150, 73, 171, 76, 123, 5, 51, 58, 235, 34, 173, 73, 96, 1, 231, 83, 68, 203, 207, 59, 172, 137, 103, 1, 47, 188, 188, 72, 162, 133, 233, 185, 129, 155, 35, 73, 16, 197, 86, 236, 182, 255, 170, 26, 28, 107, 235, 192, 25, 233, 58, 230, 85, 181, 124, 234, 193, 229, 193, 13, 228, 61, 90, 160, 247, 223, 86, 113, 113, 233, 164, 118, 29, 108, 140, 188, 74, 59, 94, 73, 241, 159, 3, 113, 28, 212, 36, 111, 141, 154, 108, 79, 109, 134, 117, 54, 188, 18, 219, 148, 76, 2, 102, 5, 150, 51, 29, 121, 251, 142, 73, 0, 169, 202, 237, 139, 213, 78, 61, 152, 81, 120, 35, 96, 5, 105, 156, 72, 85, 252, 158, 1, 103, 55, 143, 39, 64, 16, 225, 118, 137, 22, 239, 139, 203, 140, 120, 196, 170, 15, 247, 249, 173, 206, 49, 156, 75, 167, 89, 138, 238, 6, 61, 254, 124, 56, 187, 179, 236, 94, 108, 119, 151, 255, 148, 20, 57, 141, 125, 38, 56, 235, 77, 239, 74, 97, 67, 217, 43, 231, 154, 164, 168, 131, 90, 140, 173, 247, 93, 215, 67, 111, 162, 255, 42, 161, 7, 37, 216, 94, 246, 125, 27, 45, 198, 172, 118, 137, 6, 216, 65, 106, 142, 54, 200, 151, 220, 174, 145, 45, 145, 16, 70, 202, 204, 202, 244, 91, 50, 0, 36, 147, 175, 167, 20, 47, 228, 211, 2, 12, 56, 72, 107, 161, 6, 55, 209, 89, 45, 176, 95, 140, 212, 175, 99, 203, 43, 102, 59, 188, 43, 57, 178, 155, 166, 213, 125, 4, 68, 252, 236, 202, 188, 235, 35, 17, 249, 247, 133, 93, 49, 158, 87, 195, 167, 201, 40, 168, 18, 239, 164, 176, 52, 45, 137, 9, 243, 47, 80, 147, 49, 56, 176, 212, 198, 127, 46, 50, 108, 135, 76, 27, 34, 242, 99, 199, 36, 93, 22, 41, 65, 157, 80, 69, 68, 109, 160, 141, 197, 104, 127, 151, 200, 37, 200, 4, 168, 185, 206, 19, 240, 126, 191, 73, 169, 223, 222, 118, 240, 123, 176, 140, 184, 117, 180, 116, 194, 231, 223, 126, 134, 67, 223, 11, 52, 233, 59, 188, 121, 131, 65, 235, 134, 141, 55, 115, 84, 29, 125, 12, 108, 128, 123, 4, 253, 70, 37, 161, 15, 23, 198, 135, 37, 234, 123, 123, 107, 161, 237, 38, 116, 13, 116, 2, 99, 181, 75, 10, 18, 253, 115, 56, 250, 239, 17, 153, 89, 8, 199, 121, 67, 223, 178, 18, 115, 6, 22, 183, 105, 238, 77, 167, 54, 59, 171, 149, 228, 107, 235, 183, 59, 224, 211, 227, 7, 198, 165, 27, 206, 9, 249, 49, 229, 19, 158, 195, 80, 162, 185, 187, 6, 12, 105, 75, 209, 197, 133, 232, 143, 178, 56, 247, 210, 254, 96, 227, 94, 103, 170, 146, 149, 234, 138, 229, 84, 227, 191, 133, 168, 2, 158, 38, 17, 147, 0, 169, 84, 197, 61, 230, 69, 62, 204, 224, 85, 78, 106, 161, 171, 100, 77, 118, 217, 162, 198, 130, 211, 94, 189, 87, 163, 235, 44, 121, 156, 211, 82, 203, 196, 238, 113, 190, 225, 155, 209, 9, 141, 97, 155, 187, 222, 153, 224, 41, 107, 85, 198, 26, 170, 41, 20, 246, 170, 120, 87, 224, 40, 241, 118, 87, 195, 240, 45, 119, 19, 31, 48, 88, 134, 196, 129, 13, 23, 246, 89, 53, 175, 210, 14, 225, 198, 192, 159, 201, 51, 131, 42, 115, 220, 41, 11, 92, 22, 35, 148, 150, 224, 49, 14, 105, 92, 89, 67, 73, 230, 6, 236, 200, 210, 171, 170, 179, 201, 225, 37, 209, 67, 17, 59, 65, 44, 27, 75, 29, 133, 43, 121, 171, 206, 138, 112, 65, 206, 2, 96, 29, 250, 87, 170, 131, 178, 248, 130, 249, 228, 87, 37, 47, 79, 220, 166, 70, 254, 118, 165, 223, 62, 6, 17, 242, 61, 210, 255, 137, 9, 229, 155, 39, 171, 33, 2, 238, 93, 198, 146, 131, 236, 116, 236, 179, 184, 102, 59, 9, 6, 12, 0, 0, 0, 0, 0, 5, 4, 7, 255, 0, 16, 0, 28, 0, 0, 0, 0, 51, 128, 170, 35, 94, 238, 241, 97, 204, 124, 66, 162, 119, 57, 190, 117, 249, 25, 174, 246, 194, 102, 133, 211, 241, 188, 128, 195, 227, 189, 65, 195, 40, 30, 231, 115, 38, 58, 165, 66, 11, 106, 157, 183, 70, 85, 36, 135, 69, 247, 93, 97, 111, 229, 75, 25, 99, 208, 247, 253, 227, 122, 252, 85]
    }
}