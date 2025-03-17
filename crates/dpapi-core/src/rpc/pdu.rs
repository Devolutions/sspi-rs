use alloc::vec::Vec;

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use thiserror::Error;

use crate::rpc::{AlterContext, AlterContextResponse, Bind, BindAck, BindNak, Request, Response};
use crate::{Decode, DecodeWithContext, Encode, FindLength, NeedsContext, ReadCursor, Result, StaticName, WriteCursor, Padding};

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

pub type PduResult<T> = core::result::Result<T, PduError>;

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

impl DataRepr {
    pub const SIZE: usize = 1 /* first octet */ + 1 /* floating point */ + 2 /* padding */;
}

impl StaticName for DataRepr {
    const NAME: &'static str = "DataRepr";
}

impl Encode for DataRepr {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        ensure_size!(in: dst, size: self.frame_length());

        let first_octet = ((self.byte_order.as_u8()) << 4) | self.character.as_u8();
        dst.write_u8(first_octet);
        dst.write_u8(self.floating_point.as_u8());

        Padding::<4>::write(2, dst)?;

        Ok(())
    }

    fn frame_length(&self) -> usize {
        Self::SIZE
    }
}

impl Decode for DataRepr {
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self> {
        ensure_size!(in: src, size: Self::SIZE);

        let first_octet = src.read_u8();

        let integer_representation = (first_octet & 0b11110000) >> 4;
        let character_representation = first_octet & 0b00001111;
        let floating_representation = src.read_u8();

        let data_representation = Self {
            byte_order: IntRepr::from_u8(integer_representation)
                .ok_or(PduError::InvalidIntRepr(integer_representation))?,
            character: CharacterRepr::from_u8(character_representation)
                .ok_or(PduError::InvalidCharacterRepr(character_representation))?,
            floating_point: FloatingPointRepr::from_u8(floating_representation)
                .ok_or(PduError::InvalidFloatingPointRepr(floating_representation))?,
        };

        // Padding.
        src.read_u16();

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
    pub const SIZE: usize = 16;
}

impl StaticName for PduHeader {
    const NAME: &'static str = "PduHeader";
}

impl Encode for PduHeader {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        ensure_size!(in: dst, size: self.frame_length());

        dst.write_u8(self.version);
        dst.write_u8(self.version_minor);
        dst.write_u8(self.packet_type.as_u8());
        dst.write_u8(self.packet_flags.bits());
        self.data_rep.encode_cursor(dst)?;
        dst.write_u16(self.frag_len);
        dst.write_u16(self.auth_len);
        dst.write_u32(self.call_id);

        Ok(())
    }

    fn frame_length(&self) -> usize {
        Self::SIZE
    }
}

impl Decode for PduHeader {
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self> {
        ensure_size!(in: src, size: Self::SIZE);

        Ok(Self {
            version: src.read_u8(),
            version_minor: src.read_u8(),
            packet_type: {
                let packet_type = src.read_u8();
                PacketType::from_u8(packet_type).ok_or(PduError::InvalidPacketType(packet_type))?
            },
            packet_flags: {
                let packet_flags = src.read_u8();
                PacketFlags::from_bits(packet_flags).ok_or(PduError::InvalidPacketFlags(packet_flags))?
            },
            data_rep: DataRepr::decode_cursor(src)?,
            frag_len: src.read_u16(),
            auth_len: src.read_u16(),
            call_id: src.read_u32(),
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

impl StaticName for SecurityTrailer {
    const NAME: &'static str = "SecurityTrailer";
}

impl Encode for SecurityTrailer {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        ensure_size!(in: dst, size: self.frame_length());

        dst.write_u8(self.security_type.as_u8());
        dst.write_u8(self.level.as_u8());
        dst.write_u8(self.pad_length);
        dst.write_u8(0); // Auth-Rsrvd
        dst.write_u32(self.context_id);
        dst.write_slice(&self.auth_value);

        Ok(())
    }

    fn frame_length(&self) -> usize {
        Self::HEADER_LEN + self.auth_value.len()
    }
}

impl Decode for SecurityTrailer {
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self> {
        ensure_size!(in: src, size: Self::HEADER_LEN);

        let security_provider = src.read_u8();
        let authentication_level = src.read_u8();

        Ok(Self {
            security_type: SecurityProvider::from_u8(security_provider)
                .ok_or(PduError::InvalidSecurityProvider(security_provider))?,
            level: AuthenticationLevel::from_u8(authentication_level)
                .ok_or(PduError::InvalidAuthenticationLevel(authentication_level))?,
            pad_length: src.read_u8(),
            context_id: {
                // Skip Auth-Rsrvd.
                src.read_u8();

                src.read_u32()
            },
            auth_value: src.read_remaining().to_vec(),
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

impl Fault {
    const FIXED_PART_SIZE: usize = 4 /* alloc_hint */ + 2 /* context_id */ + 1 /* cancel_count */ + 1 /* flags */ + 4 /* status */ + 4 /* padding */;
}

impl StaticName for Fault {
    const NAME: &'static str = "Fault";
}

impl Encode for Fault {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        ensure_size!(in: dst, size: self.frame_length());

        dst.write_u32(self.alloc_hint);
        dst.write_u16(self.context_id);
        dst.write_u8(self.cancel_count);
        dst.write_u8(self.flags.bits());
        dst.write_u32(self.status);
        // alignment padding
        dst.write_u32(0);
        dst.write_slice(&self.stub_data);

        Ok(())
    }

    fn frame_length(&self) -> usize {
        Self::FIXED_PART_SIZE + self.stub_data.len()
    }
}

impl Decode for Fault {
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self> {
        ensure_size!(in: src, size: Self::FIXED_PART_SIZE);

        Ok(Self {
            alloc_hint: src.read_u32(),
            context_id: src.read_u16(),
            cancel_count: src.read_u8(),
            flags: {
                let fault_flags = src.read_u8();
                FaultFlags::from_bits(fault_flags).ok_or(PduError::InvalidFaultFlags(fault_flags))?
            },
            status: src.read_u32(),
            stub_data: {
                // alignment padding
                src.read_u32();

                src.read_remaining().to_vec()
            },
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
}

impl NeedsContext for PduData {
    type Context<'ctx> = &'ctx PduHeader;
}

impl StaticName for PduData {
    const NAME: &'static str = "PduData";
}

impl DecodeWithContext for PduData {
    fn decode_cursor_with_context(src: &mut ReadCursor<'_>, pdu_header: Self::Context<'_>) -> Result<Self> {
        let security_trailer_len = if pdu_header.auth_len > 0 {
            SecurityTrailer::HEADER_LEN
        } else {
            0
        } + usize::from(pdu_header.auth_len);

        let data_len = usize::from(pdu_header.frag_len)
            .checked_sub(security_trailer_len + PduHeader::SIZE)
            .ok_or(PduError::InvalidFragLength(pdu_header.frag_len))?;

        ensure_size!(in: src, size: data_len);
        let buf = src.read_slice(data_len);

        match pdu_header.packet_type {
            PacketType::Bind => Ok(PduData::Bind(Bind::decode(buf)?)),
            PacketType::BindAck => Ok(PduData::BindAck(BindAck::decode(buf)?)),
            PacketType::BindNak => Ok(PduData::BindNak(BindNak::decode(buf)?)),
            PacketType::AlterContext => Ok(PduData::AlterContext(AlterContext::decode(buf)?)),
            PacketType::AlterContextResponse => Ok(PduData::AlterContextResponse(AlterContextResponse::decode(buf)?)),
            PacketType::Request => Ok(PduData::Request(Request::decode_with_context(buf, pdu_header)?)),
            PacketType::Response => Ok(PduData::Response(Response::decode(buf)?)),
            PacketType::Fault => Ok(PduData::Fault(Fault::decode(buf)?)),
            packet_type => Err(PduError::PduNotSupported(packet_type))?,
        }
    }
}

impl Encode for PduData {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        ensure_size!(in: dst, size: self.frame_length());

        match self {
            PduData::Bind(bind) => bind.encode_cursor(dst),
            PduData::BindAck(bind_ack) => bind_ack.encode_cursor(dst),
            PduData::BindNak(bind_nak) => bind_nak.encode_cursor(dst),
            PduData::AlterContext(alter_context) => alter_context.encode_cursor(dst),
            PduData::AlterContextResponse(alter_context_response) => alter_context_response.encode_cursor(dst),
            PduData::Request(request) => request.encode_cursor(dst),
            PduData::Response(response) => response.encode_cursor(dst),
            PduData::Fault(fault) => fault.encode_cursor(dst),
        }
    }

    fn frame_length(&self) -> usize {
        match self {
            PduData::Bind(bind) => bind.frame_length(),
            PduData::BindAck(bind_ack) => bind_ack.frame_length(),
            PduData::BindNak(bind_nak) => bind_nak.frame_length(),
            PduData::AlterContext(alter_context) => alter_context.frame_length(),
            PduData::AlterContextResponse(alter_context_response) => alter_context_response.frame_length(),
            PduData::Request(request) => request.frame_length(),
            PduData::Response(response) => response.frame_length(),
            PduData::Fault(fault) => fault.frame_length(),
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

impl StaticName for Pdu {
    const NAME: &'static str = "Pdu";
}

impl Encode for Pdu {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        ensure_size!(in: dst, size: self.frame_length());

        self.header.encode_cursor(dst)?;
        self.data.encode_cursor(dst)?;
        self.security_trailer.encode_cursor(dst)?;

        Ok(())
    }

    fn frame_length(&self) -> usize {
        self.header.frame_length() + self.data.frame_length() + self.security_trailer.frame_length()
    }
}

impl Decode for Pdu {
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self> {
        let header = PduHeader::decode_cursor(src)?;
        let data = PduData::decode_cursor_with_context(src, &header)?;
        let security_trailer = if header.auth_len > 0 {
            Some(SecurityTrailer::decode_cursor(src)?)
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

impl FindLength for Pdu {
    const FIXED_PART_SIZE: usize = PduHeader::SIZE;

    fn find_frame_length(bytes: &[u8]) -> Result<Option<usize>> {
        if bytes.len() < Self::FIXED_PART_SIZE {
            return Ok(None);
        }

        let pdu_header = PduHeader::decode(&bytes[0..Self::FIXED_PART_SIZE])?;

        Ok(Some(usize::from(pdu_header.frag_len)))
    }
}
