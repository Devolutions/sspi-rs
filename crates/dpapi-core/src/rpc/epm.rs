use alloc::vec;
use alloc::vec::Vec;

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use thiserror::Error;
use uuid::{Uuid, uuid};

use crate::rpc::SyntaxId;
use crate::{
    Decode, DecodeWithContext, Encode, NeedsContext, Padding, ReadCursor, Result, StaticName, WriteBuf, WriteCursor,
};

#[derive(Debug, Error)]
pub enum EpmError {
    #[error("invalid floor protocol: {0}")]
    InvalidFloorProtocol(u8),

    #[error("invalid floor value: {0}")]
    InvalidFloorValue(&'static str),

    #[error("unsupported floor protocol: {0:?}")]
    UnsupportedFloor(FloorProtocol),
}

pub const EPM: SyntaxId = SyntaxId {
    uuid: uuid!("e1af8308-5d1f-11c9-91a4-08002b14a0fa"),
    version: 3,
    version_minor: 0,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
#[repr(u8)]
pub enum FloorProtocol {
    Osi = 0x00,
    DnaSessionControl = 0x02,
    DnaSessionControlV3 = 0x03,
    DnaNspTransport = 0x04,
    Tp4 = 0x05,
    Clns = 0x06,
    Tcp = 0x07,
    Udp = 0x08,
    Ip = 0x09,
    RpcConnectionless = 0x0a,
    RpcConnectionOriented = 0x0b,
    UuidId = 0x0d,
    NamedPipes = 0x10,
    NetBios = 0x11,
    NetBeui = 0x12,
    NetWareSpx = 0x13,
    NetWareIpx = 0x14,
    AppleTalkStream = 0x16,
    AppleTalkDataram = 0x17,
    AppleTalk = 0x18,
    NetBios2 = 0x19,
    VinesSpp = 0x1a,
    VinesIpc = 0x1b,
    StreetTalk = 0x1c,
    UnixDomainSocket = 0x20,
    Null = 0x21,
    NetBios3 = 0x22,
}

impl FloorProtocol {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

pub struct BaseFloor {
    pub protocol: FloorProtocol,
    pub lhs: Vec<u8>,
    pub rhs: Vec<u8>,
}

impl BaseFloor {
    const FIXED_PART_SIZE: usize = 2 /* lhs + protocol byte length */ + 1 /* protocol byte */;
}

impl BaseFloor {
    pub fn new(protocol: FloorProtocol, lhs: Vec<u8>, rhs: Vec<u8>) -> Self {
        Self { protocol, lhs, rhs }
    }
}

impl StaticName for BaseFloor {
    const NAME: &'static str = "BaseFloor";
}

impl Encode for BaseFloor {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        ensure_size!(in: dst, size: self.frame_length());

        dst.write_u16((self.lhs.len() + 1/* protocol byte */).try_into()?);
        dst.write_u8(self.protocol.as_u8());
        dst.write_slice(&self.lhs);

        dst.write_u16(self.rhs.len().try_into()?);
        dst.write_slice(&self.rhs);

        Ok(())
    }

    fn frame_length(&self) -> usize {
        Self::FIXED_PART_SIZE + self.lhs.len() + 2 /* rhs len */ + self.rhs.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpFloor {
    pub port: u16,
}

impl Encode for TcpFloor {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        BaseFloor::new(FloorProtocol::Tcp, Vec::new(), self.port.to_be_bytes().to_vec()).encode_cursor(dst)
    }

    fn frame_length(&self) -> usize {
        BaseFloor::new(FloorProtocol::Tcp, Vec::new(), self.port.to_be_bytes().to_vec()).frame_length()
    }
}

impl StaticName for TcpFloor {
    const NAME: &'static str = "TcpFloor";
}

impl NeedsContext for TcpFloor {
    type Context<'ctx> = usize;
}

impl DecodeWithContext for TcpFloor {
    fn decode_cursor_with_context(src: &mut ReadCursor<'_>, ctx: Self::Context<'_>) -> Result<Self> {
        ensure_size!(in: src, size: ctx);

        let _lhs = src.read_slice(ctx);

        ensure_size!(in: src, size: 2);
        let rhs_len = usize::from(src.read_u16());

        ensure_size!(in: src, size: rhs_len);
        let rhs = src.read_slice(rhs_len).to_vec();

        if rhs.len() != 2 {
            Err(EpmError::InvalidFloorValue(
                "invalid TcpFloor rhs value length: expected exactly 2 bytes",
            ))?;
        }

        Ok(Self {
            port: u16::from_be_bytes(rhs.try_into().unwrap()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpFloor {
    pub addr: u32,
}

impl StaticName for IpFloor {
    const NAME: &'static str = "IpFloor";
}

impl NeedsContext for IpFloor {
    type Context<'ctx> = usize;
}

impl Encode for IpFloor {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        BaseFloor::new(FloorProtocol::Ip, Vec::new(), self.addr.to_be_bytes().to_vec()).encode_cursor(dst)
    }

    fn frame_length(&self) -> usize {
        BaseFloor::new(FloorProtocol::Ip, Vec::new(), self.addr.to_be_bytes().to_vec()).frame_length()
    }
}

impl DecodeWithContext for IpFloor {
    fn decode_cursor_with_context(src: &mut ReadCursor<'_>, ctx: Self::Context<'_>) -> Result<Self> {
        ensure_size!(in: src, size: ctx);

        let _lhs = src.read_slice(ctx);

        ensure_size!(in: src, size: 2);
        let rhs_len = usize::from(src.read_u16());

        ensure_size!(in: src, size: rhs_len);
        let rhs = src.read_slice(rhs_len).to_vec();

        if rhs.len() != 4 {
            Err(EpmError::InvalidFloorValue(
                "invalid IpFloor rhs value length: expected exactly 4 bytes",
            ))?;
        }

        Ok(Self {
            addr: u32::from_be_bytes(rhs.try_into().unwrap()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcConnectionOrientedFloor {
    pub version_minor: u16,
}

impl StaticName for RpcConnectionOrientedFloor {
    const NAME: &'static str = "RpcConnectionOrientedFloor";
}

impl NeedsContext for RpcConnectionOrientedFloor {
    type Context<'ctx> = usize;
}

impl Encode for RpcConnectionOrientedFloor {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        BaseFloor::new(
            FloorProtocol::RpcConnectionOriented,
            Vec::new(),
            self.version_minor.to_le_bytes().to_vec(),
        )
        .encode_cursor(dst)
    }

    fn frame_length(&self) -> usize {
        BaseFloor::new(
            FloorProtocol::RpcConnectionOriented,
            Vec::new(),
            self.version_minor.to_le_bytes().to_vec(),
        )
        .frame_length()
    }
}

impl DecodeWithContext for RpcConnectionOrientedFloor {
    fn decode_cursor_with_context(src: &mut ReadCursor<'_>, ctx: Self::Context<'_>) -> Result<Self> {
        ensure_size!(in: src, size: ctx);

        let _lhs = src.read_slice(ctx);

        ensure_size!(in: src, size: 2);
        let rhs_len = usize::from(src.read_u16());

        ensure_size!(in: src, size: rhs_len);
        let rhs = src.read_slice(rhs_len).to_vec();

        if rhs.len() != 2 {
            Err(EpmError::InvalidFloorValue(
                "invalid RpcConnectionOrientedFloor rhs value length: expected exactly 2 bytes",
            ))?;
        }

        Ok(Self {
            version_minor: u16::from_be_bytes(rhs.try_into().unwrap()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UuidFloor {
    pub uuid: Uuid,
    pub version: u16,
    pub version_minor: u16,
}

impl StaticName for UuidFloor {
    const NAME: &'static str = "UuidFloor";
}

impl NeedsContext for UuidFloor {
    type Context<'ctx> = usize;
}

impl Encode for UuidFloor {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        let mut lhs = self.uuid.to_bytes_le().to_vec();
        lhs.extend_from_slice(&self.version.to_le_bytes());

        BaseFloor::new(FloorProtocol::UuidId, lhs, self.version_minor.to_le_bytes().to_vec()).encode_cursor(dst)
    }

    fn frame_length(&self) -> usize {
        let mut lhs = self.uuid.to_bytes_le().to_vec();
        lhs.extend_from_slice(&self.version.to_le_bytes());

        BaseFloor::new(FloorProtocol::UuidId, lhs, self.version_minor.to_le_bytes().to_vec()).frame_length()
    }
}

impl DecodeWithContext for UuidFloor {
    fn decode_cursor_with_context(src: &mut ReadCursor<'_>, ctx: Self::Context<'_>) -> Result<Self> {
        ensure_size!(in: src, size: ctx);

        let lhs = src.read_slice(ctx);

        ensure_size!(in: src, size: 2);
        let rhs_len = usize::from(src.read_u16());

        ensure_size!(in: src, size: rhs_len);
        let rhs = src.read_slice(rhs_len).to_vec();

        if lhs.len() != 18 {
            Err(EpmError::InvalidFloorValue(
                "invalid UuidFloor lhs value length: expected exactly 18 bytes",
            ))?;
        }

        if rhs.len() != 2 {
            Err(EpmError::InvalidFloorValue(
                "invalid UuidFloor rhs value length: expected exactly 2 bytes",
            ))?;
        }

        Ok(Self {
            uuid: Uuid::from_slice_le(&lhs[0..16])?,
            version: u16::from_le_bytes(lhs[16..].try_into().unwrap()),
            version_minor: u16::from_le_bytes(rhs.try_into().unwrap()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Floor {
    Tcp(TcpFloor),
    Ip(IpFloor),
    RpcConnectionOriented(RpcConnectionOrientedFloor),
    Uuid(UuidFloor),
}

impl StaticName for Floor {
    const NAME: &'static str = "Floor";
}

impl Encode for Floor {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        match self {
            Floor::Tcp(tcp_floor) => tcp_floor.encode_cursor(dst),
            Floor::Ip(ip_floor) => ip_floor.encode_cursor(dst),
            Floor::RpcConnectionOriented(rpc_connection_oriented_floor) => {
                rpc_connection_oriented_floor.encode_cursor(dst)
            }
            Floor::Uuid(uuid_floor) => uuid_floor.encode_cursor(dst),
        }
    }

    fn frame_length(&self) -> usize {
        match self {
            Floor::Tcp(tcp_floor) => tcp_floor.frame_length(),
            Floor::Ip(ip_floor) => ip_floor.frame_length(),
            Floor::RpcConnectionOriented(rpc_connection_oriented_floor) => rpc_connection_oriented_floor.frame_length(),
            Floor::Uuid(uuid_floor) => uuid_floor.frame_length(),
        }
    }
}

impl Decode for Floor {
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self> {
        ensure_size!(in: src, size: BaseFloor::FIXED_PART_SIZE);

        let lhs_len = usize::from(src.read_u16() - 1);

        let protocol_value = src.read_u8();
        let protocol = FloorProtocol::from_u8(protocol_value).ok_or(EpmError::InvalidFloorProtocol(protocol_value))?;

        Ok(match protocol {
            FloorProtocol::Tcp => Floor::Tcp(TcpFloor::decode_cursor_with_context(src, lhs_len)?),
            FloorProtocol::Ip => Floor::Ip(IpFloor::decode_cursor_with_context(src, lhs_len)?),
            FloorProtocol::RpcConnectionOriented => {
                Floor::RpcConnectionOriented(RpcConnectionOrientedFloor::decode_cursor_with_context(src, lhs_len)?)
            }
            FloorProtocol::UuidId => Floor::Uuid(UuidFloor::decode_cursor_with_context(src, lhs_len)?),
            protocol => Err(EpmError::UnsupportedFloor(protocol))?,
        })
    }
}

pub type Tower = Vec<Floor>;

pub fn build_tcpip_tower(service: SyntaxId, data_rep: SyntaxId, port: u16, addr: u32) -> Tower {
    vec![
        Floor::Uuid(UuidFloor {
            uuid: service.uuid,
            version: service.version,
            version_minor: service.version_minor,
        }),
        Floor::Uuid(UuidFloor {
            uuid: data_rep.uuid,
            version: data_rep.version,
            version_minor: data_rep.version_minor,
        }),
        Floor::RpcConnectionOriented(RpcConnectionOrientedFloor { version_minor: 0 }),
        Floor::Tcp(TcpFloor { port }),
        Floor::Ip(IpFloor { addr }),
    ]
}

pub type EntryHandle = (u32, Uuid);
const EMPTY_ENTRY_HANDLE: &[u8; 20] = &[0; 20];

impl StaticName for Option<EntryHandle> {
    const NAME: &'static str = "Option<EntryHandle>";
}

impl Encode for Option<EntryHandle> {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        ensure_size!(in: dst, size: self.frame_length());

        if let Some(entry_handle) = self {
            dst.write_u32(entry_handle.0);
            entry_handle.1.encode_cursor(dst)?;
        } else {
            dst.write_slice(EMPTY_ENTRY_HANDLE);
        }

        Ok(())
    }

    fn frame_length(&self) -> usize {
        EMPTY_ENTRY_HANDLE.len()
    }
}

impl Decode for Option<EntryHandle> {
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self> {
        ensure_size!(in: src, size: EMPTY_ENTRY_HANDLE.len());

        let entry_handle_buf = src.read_slice(EMPTY_ENTRY_HANDLE.len());

        Ok(if entry_handle_buf != EMPTY_ENTRY_HANDLE {
            Some((
                u32::from_le_bytes(entry_handle_buf[0..4].try_into().unwrap()),
                Uuid::from_slice_le(&entry_handle_buf[4..])?,
            ))
        } else {
            None
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EptMap {
    pub obj: Option<Uuid>,
    pub tower: Tower,
    pub entry_handle: Option<EntryHandle>,
    pub max_towers: u32,
}

impl EptMap {
    pub const OPNUM: u16 = 3;
    const FIXED_PART_SIZE: usize = 8 /* obj with a referent id of 1 */ + 16 /* obj */ + 8 /* Tower referent id 2 */ + 8 /* encoded tower len */ + 4 /* encoded tower length */ + 2 /* tower amount */;
    const TOWER_REFERENT_ID_1: &[u8] = &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    const TOWER_REFERENT_ID_2: &[u8] = &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
}

impl StaticName for EptMap {
    const NAME: &'static str = "EptMap";
}

impl Encode for EptMap {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        ensure_size!(in: dst, size: self.frame_length());

        // obj with a referent id of 1
        dst.write_slice(Self::TOWER_REFERENT_ID_1);

        if let Some(uuid) = self.obj {
            uuid.encode_cursor(dst)?;
        } else {
            dst.write_slice(&[0; 16]);
        }

        // Tower referent id 2
        dst.write_slice(Self::TOWER_REFERENT_ID_2);

        let mut encoded_tower = WriteBuf::new();
        encoded_tower.write_u16(u16::try_from(self.tower.len())?);
        self.tower.encode_buf(&mut encoded_tower)?;

        dst.write_u64(u64::try_from(encoded_tower.filled_len())?);
        dst.write_u32(u32::try_from(encoded_tower.filled_len())?);

        dst.write_slice(encoded_tower.filled());

        Padding::<8>::write(encoded_tower.filled_len() + 4, dst)?;

        self.entry_handle.encode_cursor(dst)?;
        dst.write_u32(self.max_towers);

        Ok(())
    }

    fn frame_length(&self) -> usize {
        let encoded_tower_length = self.tower.frame_length();
        let padding_len = Padding::<8>::padding(encoded_tower_length + 2 /* tower amount */ + 4);

        Self::FIXED_PART_SIZE + encoded_tower_length + padding_len + self.entry_handle.frame_length() + 4 /* max_towers */
    }
}

impl Decode for EptMap {
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self> {
        ensure_size!(in: src, size: Self::FIXED_PART_SIZE);

        // obj with a referent id of 1
        src.read_u64();

        let obj = src.read_slice(16);

        let obj = if obj != [0; 16] {
            Some(Uuid::from_slice_le(obj)?)
        } else {
            None
        };

        // Tower referent id 2
        src.read_u64();

        let tower_length = src.read_u64();
        src.read_u32();

        let floor_length = usize::from(src.read_u16());
        let tower = (0..floor_length)
            .map(|_| Floor::decode_cursor(src))
            .collect::<Result<Vec<Floor>>>()?;

        Padding::<8>::read((tower_length + 4).try_into()?, src)?;

        let entry_handle = Option::decode_cursor(src)?;
        ensure_size!(in: src, size: 4);
        let max_towers = src.read_u32();

        Ok(Self {
            obj,
            tower,
            entry_handle,
            max_towers,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EptMapResult {
    pub entry_handle: Option<EntryHandle>,
    pub towers: Vec<Tower>,
    pub status: u32,
}

impl StaticName for EptMapResult {
    const NAME: &'static str = "EptMapResult";
}

impl Encode for EptMapResult {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        ensure_size!(in: dst, size: self.frame_length());

        self.entry_handle.encode_cursor(dst)?;

        dst.write_u32(u32::try_from(self.towers.len())?);
        // max_tower_count
        dst.write_u64(u64::try_from(self.towers.len())?);

        // Tower pointer offset
        dst.write_u64(0);

        dst.write_u64(u64::try_from(self.towers.len())?);

        for idx in 0..self.towers.len() {
            dst.write_u64((idx + 3).try_into()?);
        }

        for tower in &self.towers {
            let mut encoded_tower = WriteBuf::new();

            encoded_tower.write_u16(u16::try_from(tower.len())?);
            tower.encode_buf(&mut encoded_tower)?;

            dst.write_u64(u64::try_from(encoded_tower.filled_len())?);
            dst.write_u32(u32::try_from(encoded_tower.filled_len())?);
            dst.write_slice(encoded_tower.filled());

            Padding::<4>::write(encoded_tower.filled_len(), dst)?;
        }

        dst.write_u32(self.status);

        Ok(())
    }

    fn frame_length(&self) -> usize {
        self.entry_handle.frame_length() + 4 /* towers len */ + 8 /* towers len */ + 8 /* tower pointer offset */
        + 8 /* towers len */ + self.towers.len() * 8 + self.towers.iter().map(|tower| {
            let encoded_tower_length = 2 /* tower len */ + tower.frame_length() + 8 /* encoded tower len */ + 4 /* encoded tower len */;
            let padding_len = Padding::<4>::padding(encoded_tower_length);

            encoded_tower_length + padding_len
        }).sum::<usize>() + 4 /* status */
    }
}

impl Decode for EptMapResult {
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self> {
        let entry_handle = Option::decode_cursor(src)?;

        ensure_size!(in: src, size: 4 /* num towers */ + 8 /* max towers cound */ + 8 /* tower offset */ + 8 /* tower count */);
        // num towers
        src.read_u32();
        // max tower count
        src.read_u64();
        // tower offset
        src.read_u64();

        let tower_count = usize::try_from(src.read_u64())?;
        ensure_size!(in: src, size: tower_count * 8);
        // Ignore referent ids
        for _ in 0..tower_count {
            src.read_u64();
        }

        let towers = (0..tower_count)
            .map(|_| {
                ensure_size!(in: src, size: 8 /* tower length */ + 4 + 2 /* floor length */);

                let tower_length = src.read_u64();

                src.read_u32();

                let floor_length = src.read_u16();
                let tower = (0..floor_length)
                    .map(|_| Floor::decode_cursor(src))
                    .collect::<Result<Vec<Floor>>>()?;

                Padding::<8>::read((tower_length + 4).try_into()?, src)?;

                Ok(tower)
            })
            .collect::<Result<Vec<Tower>>>()?;

        ensure_size!(in: src, size: 4);
        let status = src.read_u32();

        Ok(Self {
            entry_handle,
            towers,
            status,
        })
    }
}
