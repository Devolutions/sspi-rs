use std::io::{Read, Write};

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use thiserror::Error;

use crate::Result;
use crate::rpc::{Encode, Decode, write_buf, read_vec};

#[derive(Debug, Error)]
pub enum EpmError {
    #[error("invalid floor protocol: {0}")]
    InvalidFloorProtocol(u8),
}

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

pub struct Floor {
    pub protocol: FloorProtocol,
    lhs: Vec<u8>,
    rhs: Vec<u8>,
}

impl Encode for Floor {
    fn encode(&self, mut writer: impl Write) -> Result<()> {
        writer.write_u16::<LittleEndian>((self.lhs.len() + 1 /* protocol byte */).try_into()?)?;
        writer.write_u8(self.protocol.as_u8())?;
        write_buf(&self.lhs, &mut writer)?;

        writer.write_u16::<LittleEndian>(self.rhs.len().try_into()?)?;
        write_buf(&self.rhs, &mut writer)?;

        Ok(())
    }
}

impl Decode for Floor {
    fn decode(mut reader: impl Read) -> Result<Self> {
        let lhs_len = reader.read_u16::<LittleEndian>()?;

        let protocol_value = reader.read_u8()?;
        let protocol = FloorProtocol::from_u8(protocol_value)
            .ok_or(EpmError::InvalidFloorProtocol(protocol_value))?;

        let mut lhs = read_vec(usize::from(lhs_len - 1), &mut reader)?;

        let rhs_len = reader.read_u16::<LittleEndian>()?;
        let mut rhs = read_vec(usize::from(rhs_len), &mut reader)?;

        todo!()
    }
}
