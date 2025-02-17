use std::io::{Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use thiserror::Error;

use super::{read_to_end, read_vec, write_buf, Decode, Encode};
use crate::rpc::bind::{AlterContext, AlterContextResponse, Bind, BindAck, BindNak};
use crate::rpc::request::{Request, Response};
use crate::DpapiResult;

#[derive(Error, Debug)]
pub enum PduError {
    #[error("invalid integer representation value: {0}")]
    InvalidIntRepr(u8),

    #[error("invalid character representation value: {0}")]
    InvalidCharacterRepr(u8),

    #[error("invalid floating point representation value: {0}")]
    InvalidFloatingPointRepr(u8),

    #[error("invalid packet type value: {0}")]
    InvalidPacketType(u8),

    #[error("invalid packet flags value: {0}")]
    InvalidPacketFlags(u8),

    #[error("invalid security provider value: {0}")]
    InvalidSecurityProvider(u8),

    #[error("invalid authentication level value: {0}")]
    InvalidAuthenticationLevel(u8),

    #[error("invalid fault flags value: {0}")]
    InvalidFaultFlags(u8),

    #[error("{0:?} PDU is not supported")]
    PduNotSupported(PacketType),

    #[error("invalid fragment (PDU) length: {0}")]
    InvalidFragLength(u16),

    #[error("RPC failed: {0}")]
    RpcFail(&'static str),
}

pub type PduResult<T> = Result<T, PduError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, FromPrimitive)]
#[repr(u8)]
pub enum IntRepr {
    BigEndian = 0,
    #[default]
    LittleEndian = 1,
}

impl IntRepr {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, FromPrimitive)]
#[repr(u8)]
pub enum CharacterRepr {
    #[default]
    Ascii = 0,
    Ebcdic = 1,
}

impl CharacterRepr {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, FromPrimitive)]
#[repr(u8)]
pub enum FloatingPointRepr {
    #[default]
    Ieee = 0,
    Vax = 1,
    Cray = 2,
    Ibm = 3,
}

impl FloatingPointRepr {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
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

impl PacketType {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
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
pub struct DataRepr {
    pub byte_order: IntRepr,
    pub character: CharacterRepr,
    pub floating_point: FloatingPointRepr,
}

impl Encode for DataRepr {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        let first_octet = (self.byte_order.as_u8()) << 4 | self.character.as_u8();
        writer.write_u8(first_octet)?;
        writer.write_u8(self.floating_point.as_u8())?;

        // Padding
        writer.write_u16::<LittleEndian>(0)?;

        Ok(())
    }
}

impl Decode for DataRepr {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let first_octet = reader.read_u8()?;

        let integer_representation = (first_octet & 0b11110000) >> 4;
        let character_representation = first_octet & 0b00001111;
        let floating_representation = reader.read_u8()?;

        let data_representation = Self {
            byte_order: IntRepr::from_u8(integer_representation)
                .ok_or(PduError::InvalidIntRepr(integer_representation))?,
            character: CharacterRepr::from_u8(character_representation)
                .ok_or(PduError::InvalidCharacterRepr(character_representation))?,
            floating_point: FloatingPointRepr::from_u8(floating_representation)
                .ok_or(PduError::InvalidFloatingPointRepr(floating_representation))?,
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
    pub data_rep: DataRepr,
    pub frag_len: u16,
    pub auth_len: u16,
    pub call_id: u32,
}

impl PduHeader {
    /// Length of the encoded [PduHeader].
    pub const LENGTH: usize = 16;
}

impl Encode for PduHeader {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        writer.write_u8(self.version)?;
        writer.write_u8(self.version_minor)?;
        writer.write_u8(self.packet_type.as_u8())?;
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
            packet_type: {
                let packet_type = reader.read_u8()?;
                PacketType::from_u8(packet_type).ok_or(PduError::InvalidPacketType(packet_type))?
            },
            packet_flags: {
                let packet_flags = reader.read_u8()?;
                PacketFlags::from_bits(packet_flags).ok_or(PduError::InvalidPacketFlags(packet_flags))?
            },
            data_rep: DataRepr::decode(&mut reader)?,
            frag_len: reader.read_u16::<LittleEndian>()?,
            auth_len: reader.read_u16::<LittleEndian>()?,
            call_id: reader.read_u32::<LittleEndian>()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
#[repr(u8)]
pub enum SecurityProvider {
    None = 0x00,
    GssNegotiate = 0x09,
    Winnt = 0x0a,
    GssSchannel = 0x0e,
    GssKerberos = 0x10,
    Netlogon = 0x44,
    Default = 0xff,
}

impl SecurityProvider {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
#[repr(u8)]
pub enum AuthenticationLevel {
    Default = 0x00,
    None = 0x01,
    Connect = 0x02,
    Call = 0x03,
    Pkt = 0x04,
    PktIntegrity = 0x05,
    PktPrivacy = 0x06,
}

impl AuthenticationLevel {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityTrailer {
    pub security_type: SecurityProvider,
    pub level: AuthenticationLevel,
    pub pad_length: u8,
    pub context_id: u32,
    pub auth_value: Vec<u8>,
}

impl SecurityTrailer {
    // `SecurityTrailer` size but without `auth_value`.
    pub const HEADER_LEN: usize = 8;
}

impl Encode for SecurityTrailer {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        writer.write_u8(self.security_type.as_u8())?;
        writer.write_u8(self.level.as_u8())?;
        writer.write_u8(self.pad_length)?;
        writer.write_u8(0)?; // Auth-Rsrvd
        writer.write_u32::<LittleEndian>(self.context_id)?;
        write_buf(&self.auth_value, writer)?;

        Ok(())
    }
}

impl Decode for SecurityTrailer {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let security_provider = reader.read_u8()?;
        let authentication_level = reader.read_u8()?;

        Ok(Self {
            security_type: SecurityProvider::from_u8(security_provider)
                .ok_or(PduError::InvalidSecurityProvider(security_provider))?,
            level: AuthenticationLevel::from_u8(authentication_level)
                .ok_or(PduError::InvalidAuthenticationLevel(authentication_level))?,
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
        write_buf(&self.stub_data, writer)?;

        Ok(())
    }
}

impl Decode for Fault {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        Ok(Self {
            alloc_hint: reader.read_u32::<LittleEndian>()?,
            context_id: reader.read_u16::<LittleEndian>()?,
            cancel_count: reader.read_u8()?,
            flags: {
                let fault_flags = reader.read_u8()?;
                FaultFlags::from_bits(fault_flags).ok_or(PduError::InvalidFaultFlags(fault_flags))?
            },
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
    /// Returns [BindAck] extracted from the inner data.
    ///
    /// Returns an error if the inner data is not `BindAck` or `AlterContextResponse`.
    pub fn bind_ack(self) -> PduResult<BindAck> {
        match self {
            PduData::BindAck(bind_ack) => Ok(bind_ack),
            PduData::AlterContextResponse(alter_context) => Ok(alter_context.0),
            _ => Err(PduError::RpcFail("BindAcknowledge PDU is expected")),
        }
    }

    /// Checks if the [PduData] contains any error PDU inside. Returns an error if so.
    pub fn into_error(self) -> PduResult<Self> {
        if let PduData::Fault(_) = self {
            Err(PduError::RpcFail("got unexpected Fault PDU"))
        } else if let PduData::BindNak(_) = self {
            Err(PduError::RpcFail("got unexpected BindAcknowledge PDU"))
        } else {
            Ok(self)
        }
    }

    pub fn decode(pdu_header: &PduHeader, data_len: usize, reader: impl Read) -> DpapiResult<Self> {
        let buf = read_vec(data_len, reader)?;

        match pdu_header.packet_type {
            PacketType::Bind => Ok(PduData::Bind(Bind::decode(buf.as_slice())?)),
            PacketType::BindAck => Ok(PduData::BindAck(BindAck::decode(buf.as_slice())?)),
            PacketType::BindNak => Ok(PduData::BindNak(BindNak::decode(buf.as_slice())?)),
            PacketType::AlterContext => Ok(PduData::AlterContext(AlterContext::decode(buf.as_slice())?)),
            PacketType::AlterContextResponse => Ok(PduData::AlterContextResponse(AlterContextResponse::decode(
                buf.as_slice(),
            )?)),
            PacketType::Request => Ok(PduData::Request(Request::decode(pdu_header, buf.as_slice())?)),
            PacketType::Response => Ok(PduData::Response(Response::decode(buf.as_slice())?)),
            PacketType::Fault => Ok(PduData::Fault(Fault::decode(buf.as_slice())?)),
            packet_type => Err(PduError::PduNotSupported(packet_type))?,
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
    pub security_trailer: Option<SecurityTrailer>,
}

impl Pdu {
    /// Tries to extract PDU Response from the inner data.
    ///
    /// Return an error if the PDU is any type then `Response`.
    pub fn try_into_response(self) -> PduResult<Response> {
        if let PduData::Response(response) = self.data {
            Ok(response)
        } else {
            Err(PduError::RpcFail("got unexpected PDU: expected Response PDU"))
        }
    }
}

impl Encode for Pdu {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        self.header.encode(&mut writer)?;
        self.data.encode(&mut writer)?;

        if let Some(security_trailer) = self.security_trailer.as_ref() {
            security_trailer.encode(writer)?;
        }

        Ok(())
    }
}

impl Decode for Pdu {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let header = PduHeader::decode(&mut reader)?;

        let security_trailer_len = if header.auth_len > 0 {
            SecurityTrailer::HEADER_LEN
        } else {
            0
        } + usize::from(header.auth_len);

        let data = PduData::decode(
            &header,
            usize::from(header.frag_len)
                .checked_sub(security_trailer_len + PduHeader::LENGTH)
                .ok_or(PduError::InvalidFragLength(header.frag_len))?,
            &mut reader,
        )?;

        let security_trailer = if header.auth_len > 0 {
            Some(SecurityTrailer::decode(reader)?)
        } else {
            None
        };

        Ok(Self {
            header,
            data,
            security_trailer,
        })
    }
}
