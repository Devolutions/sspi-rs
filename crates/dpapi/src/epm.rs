use std::io::{Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use thiserror::Error;
use uuid::{uuid, Uuid};

use crate::Result;
use crate::rpc::{read_buf, read_padding, read_vec, write_buf, write_padding, Decode, Encode};
use crate::rpc::bind::SyntaxId;

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
    pub fn new(protocol: FloorProtocol, lhs: Vec<u8>, rhs: Vec<u8>) -> Self {
        Self { protocol, lhs, rhs }
    }
}

impl Encode for BaseFloor {
    fn encode(&self, mut writer: impl Write) -> Result<()> {
        writer.write_u16::<LittleEndian>((self.lhs.len() + 1/* protocol byte */).try_into()?)?;
        writer.write_u8(self.protocol.as_u8())?;
        write_buf(&self.lhs, &mut writer)?;

        writer.write_u16::<LittleEndian>(self.rhs.len().try_into()?)?;
        write_buf(&self.rhs, &mut writer)?;

        Ok(())
    }
}

impl Decode for BaseFloor {
    fn decode(mut reader: impl Read) -> Result<Self> {
        let lhs_len = reader.read_u16::<LittleEndian>()?;

        let protocol_value = reader.read_u8()?;
        let protocol = FloorProtocol::from_u8(protocol_value).ok_or(EpmError::InvalidFloorProtocol(protocol_value))?;

        let lhs = read_vec(usize::from(lhs_len - 1), &mut reader)?;

        let rhs_len = reader.read_u16::<LittleEndian>()?;
        let rhs = read_vec(usize::from(rhs_len), &mut reader)?;

        Ok(Self { protocol, lhs, rhs })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpFloor {
    pub port: u16,
}

impl Encode for TcpFloor {
    fn encode(&self, writer: impl Write) -> Result<()> {
        BaseFloor::new(FloorProtocol::Tcp, Vec::new(), self.port.to_be_bytes().to_vec()).encode(writer)
    }
}

impl TcpFloor {
    fn decode(_lhs: &[u8], rhs: &[u8]) -> Result<Self> {
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

impl Encode for IpFloor {
    fn encode(&self, writer: impl Write) -> Result<()> {
        BaseFloor::new(FloorProtocol::Ip, Vec::new(), self.addr.to_be_bytes().to_vec()).encode(writer)
    }
}

impl IpFloor {
    fn decode(_lhs: &[u8], rhs: &[u8]) -> Result<Self> {
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

impl Encode for RpcConnectionOrientedFloor {
    fn encode(&self, writer: impl Write) -> Result<()> {
        BaseFloor::new(
            FloorProtocol::RpcConnectionOriented,
            Vec::new(),
            self.version_minor.to_le_bytes().to_vec(),
        )
        .encode(writer)
    }
}

impl RpcConnectionOrientedFloor {
    fn decode(_lhs: &[u8], rhs: &[u8]) -> Result<Self> {
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

impl Encode for UuidFloor {
    fn encode(&self, writer: impl Write) -> Result<()> {
        let mut lhs = self.uuid.to_bytes_le().to_vec();
        lhs.extend_from_slice(&self.version.to_le_bytes());

        BaseFloor::new(FloorProtocol::UuidId, lhs, self.version_minor.to_le_bytes().to_vec()).encode(writer)
    }
}

impl UuidFloor {
    fn decode(lhs: &[u8], rhs: &[u8]) -> Result<Self> {
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

impl Encode for Floor {
    fn encode(&self, writer: impl Write) -> Result<()> {
        match self {
            Floor::Tcp(tcp_floor) => tcp_floor.encode(writer),
            Floor::Ip(ip_floor) => ip_floor.encode(writer),
            Floor::RpcConnectionOriented(rpc_connection_oriented_floor) => rpc_connection_oriented_floor.encode(writer),
            Floor::Uuid(uuid_floor) => uuid_floor.encode(writer),
        }
    }
}

impl Decode for Floor {
    fn decode(reader: impl Read) -> Result<Self> {
        let BaseFloor { protocol, lhs, rhs } = BaseFloor::decode(reader)?;

        Ok(match protocol {
            FloorProtocol::Tcp => Floor::Tcp(TcpFloor::decode(&lhs, &rhs)?),
            FloorProtocol::Ip => Floor::Ip(IpFloor::decode(&lhs, &rhs)?),
            FloorProtocol::RpcConnectionOriented => {
                Floor::RpcConnectionOriented(RpcConnectionOrientedFloor::decode(&lhs, &rhs)?)
            }
            FloorProtocol::UuidId => Floor::Uuid(UuidFloor::decode(&lhs, &rhs)?),
            protocol => Err(EpmError::UnsupportedFloor(protocol))?,
        })
    }
}

pub type Tower = Vec<Floor>;

impl Encode for Tower {
    fn encode(&self, mut writer: impl Write) -> Result<()> {
        for floor in self {
            floor.encode(&mut writer)?;
        }

        Ok(())
    }
}

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

impl Encode for Option<EntryHandle> {
    fn encode(&self, mut writer: impl Write) -> Result<()> {
        if let Some(entry_handle) = self {
            writer.write_u32::<LittleEndian>(entry_handle.0)?;
            entry_handle.1.encode(writer)?;
        } else {
            write_buf(&[0; 20], &mut writer)?;
        }

        Ok(())
    }
}

impl Decode for Option<EntryHandle> {
    fn decode(mut reader: impl Read) -> Result<Self> {
        let mut entry_handle_buf = [0; 20];
        read_buf(&mut reader, &mut entry_handle_buf)?;

        Ok(if entry_handle_buf != [0; 20] {
            Some((
                u32::from_le_bytes(entry_handle_buf[0..4].try_into()?),
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
}

impl Encode for EptMap {
    fn encode(&self, mut writer: impl Write) -> Result<()> {
        // obj with a referent id of 1
        write_buf(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], &mut writer)?;

        if let Some(uuid) = self.obj {
            uuid.encode(&mut writer)?;
        } else {
            write_buf(&[0; 16], &mut writer)?;
        }

        // Tower referent id 2
        write_buf(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], &mut writer)?;

        let mut encoded_tower = u16::try_from(self.tower.len())?.to_le_bytes().to_vec();
        self.tower.encode(&mut encoded_tower)?;

        writer.write_u64::<LittleEndian>(u64::try_from(encoded_tower.len())?)?;
        writer.write_u32::<LittleEndian>(u32::try_from(encoded_tower.len())?)?;

        write_buf(&encoded_tower, &mut writer)?;
        write_padding::<8>(encoded_tower.len() + 4, &mut writer)?;

        self.entry_handle.encode(&mut writer)?;
        writer.write_u32::<LittleEndian>(self.max_towers)?;

        Ok(())
    }
}

impl Decode for EptMap {
    fn decode(mut reader: impl Read) -> Result<Self> {
        // obj with a referent id of 1
        reader.read_u64::<LittleEndian>()?;

        let mut obj = [0; 16];
        read_buf(&mut reader, &mut obj)?;

        let obj = if obj != [0; 16] {
            Some(Uuid::from_slice_le(&obj)?)
        } else {
            None
        };

        // Tower referent id 2
        reader.read_u64::<LittleEndian>()?;

        let tower_length = reader.read_u64::<LittleEndian>()?;
        reader.read_u32::<LittleEndian>()?;

        let floor_length = usize::from(reader.read_u16::<LittleEndian>()?);
        let tower = (0..floor_length)
            .map(|_| Floor::decode(&mut reader))
            .collect::<Result<Vec<Floor>>>()?;

        read_padding::<8>((tower_length + 4).try_into()?, &mut reader)?;

        let entry_handle = Option::decode(&mut reader)?;
        let max_towers = reader.read_u32::<LittleEndian>()?;

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

impl Encode for EptMapResult {
    fn encode(&self, mut writer: impl Write) -> Result<()> {
        self.entry_handle.encode(&mut writer)?;

        writer.write_u32::<LittleEndian>(u32::try_from(self.towers.len())?)?;
        // max_tower_count
        writer.write_u64::<LittleEndian>(u64::try_from(self.towers.len())?)?;

        // Tower pointer offset
        writer.write_u64::<LittleEndian>(0)?;

        writer.write_u64::<LittleEndian>(u64::try_from(self.towers.len())?)?;

        for idx in 0..self.towers.len() {
            writer.write_u64::<LittleEndian>((idx + 3).try_into()?)?;
        }

        for tower in &self.towers {
            let mut encoded_tower = u16::try_from(tower.len())?.to_le_bytes().to_vec();
            tower.encode(&mut encoded_tower)?;

            writer.write_u64::<LittleEndian>(u64::try_from(encoded_tower.len())?)?;
            writer.write_u32::<LittleEndian>(u32::try_from(encoded_tower.len())?)?;
            write_buf(&encoded_tower, &mut writer)?;
            write_padding::<4>(encoded_tower.len(), &mut writer)?;
        }

        writer.write_u32::<LittleEndian>(self.status)?;

        Ok(())
    }
}

impl Decode for EptMapResult {
    fn decode(mut reader: impl Read) -> Result<Self> {
        let entry_handle = Option::decode(&mut reader)?;

        // num towers
        reader.read_u32::<LittleEndian>()?;
        // mac tower count
        reader.read_u64::<LittleEndian>()?;
        // tower offset
        reader.read_u64::<LittleEndian>()?;

        let tower_count = usize::try_from(reader.read_u64::<LittleEndian>()?)?;
        // Ignore referent ids
        for _ in 0..tower_count {
            reader.read_u64::<LittleEndian>()?;
        }

        let towers = (0..tower_count)
            .map(|_| {
                let tower_length = reader.read_u64::<LittleEndian>()?;

                reader.read_u32::<LittleEndian>()?;

                let floor_length = reader.read_u16::<LittleEndian>()?;
                let tower = (0..floor_length)
                    .map(|_| Floor::decode(&mut reader))
                    .collect::<Result<Vec<Floor>>>()?;

                read_padding::<8>((tower_length + 4).try_into()?, &mut reader)?;

                Ok(tower)
            })
            .collect::<Result<Vec<Tower>>>()?;

        let status = reader.read_u32::<LittleEndian>()?;

        Ok(Self {
            entry_handle,
            towers,
            status,
        })
    }
}
