use std::io::{Read, Write};

use bitflags::bitflags;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use thiserror::Error;

use crate::rpc::bind::SyntaxId;
use crate::rpc::pdu::{DataRepr, PacketType};
use crate::rpc::{read_vec, write_buf, Decode, Encode, EncodeExt};
use crate::DpapiResult;

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("invalid RPC command type: {0}")]
    InvalidCommandType(u16),

    #[error("invalid RPC command flags: {0}")]
    InvalidCommandFlags(u16),

    #[error("invalid RPC bitmask command value length: expected exactly 4 bytes but got {0} bytes")]
    InvalidCommandBitmaskValueLength(usize),

    #[error("invalid packet RPC type value in RPC command: {0}")]
    InvalidPacketType(u8),

    #[error("invalid VerificationTrailer signature")]
    InvalidVerificationTrailerSignature { expected: &'static [u8], actual: Vec<u8> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
#[repr(u16)]
pub enum CommandType {
    Bitmask1 = 0x0001,
    Pcontext = 0x0002,
    Header2 = 0x0003,
}

impl CommandType {
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
    pub struct CommandFlags: u16 {
        const None = 0;
        const SecVtCommandEnd = 0x4000;
        const SecVtMustProcessCommand = 0x8000;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Bitmask1(CommandBitmask),
    Pcontext(CommandPContext),
    Header2(CommandHeader2),
}

impl Command {
    pub fn flags(&self) -> CommandFlags {
        match self {
            Command::Bitmask1(command) => command.flags,
            Command::Pcontext(command) => command.flags,
            Command::Header2(command) => command.flags,
        }
    }

    pub fn command_type(&self) -> CommandType {
        match self {
            Command::Bitmask1(_) => CommandType::Bitmask1,
            Command::Pcontext(_) => CommandType::Pcontext,
            Command::Header2(_) => CommandType::Header2,
        }
    }
}

impl Encode for Command {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        writer.write_u16::<LittleEndian>(self.command_type().as_u16() | self.flags().bits())?;

        match self {
            Command::Bitmask1(command) => command.encode_value(writer),
            Command::Pcontext(command) => command.encode_value(writer),
            Command::Header2(command) => command.encode_value(writer),
        }
    }
}

impl Decode for Command {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let cmd_field = reader.read_u16::<LittleEndian>()?;

        let command_type = cmd_field & 0x3fff;
        let command_flags = cmd_field & 0xc000;

        let command = CommandType::from_u16(command_type).ok_or(CommandError::InvalidCommandType(command_type))?;
        let flags = CommandFlags::from_bits(command_flags).ok_or(CommandError::InvalidCommandFlags(command_flags))?;

        let value_len = reader.read_u16::<LittleEndian>()?;
        let value = read_vec(usize::from(value_len), reader)?;

        Ok(match command {
            CommandType::Bitmask1 => Self::Bitmask1(CommandBitmask::from_flags_and_value(flags, &value)?),
            CommandType::Pcontext => Self::Pcontext(CommandPContext::from_flags_and_value(flags, &value)?),
            CommandType::Header2 => Self::Header2(CommandHeader2::from_flags_and_value(flags, &value)?),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandBitmask {
    pub bits: u32,
    pub flags: CommandFlags,
}

impl CommandBitmask {
    fn from_flags_and_value(flags: CommandFlags, value: &[u8]) -> DpapiResult<Self> {
        if value.len() != 4 {
            Err(CommandError::InvalidCommandBitmaskValueLength(value.len()))?;
        }

        let bits: [u8; 4] = value.try_into().expect("length should be checked");

        Ok(Self {
            flags,
            bits: u32::from_le_bytes(bits),
        })
    }

    fn encode_value(&self, mut writer: impl Write) -> DpapiResult<()> {
        writer.write_u16::<LittleEndian>(4)?;
        write_buf(self.bits.to_le_bytes().as_slice(), writer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPContext {
    pub flags: CommandFlags,
    pub interface_id: SyntaxId,
    pub transfer_syntax: SyntaxId,
}

impl CommandPContext {
    fn from_flags_and_value(flags: CommandFlags, value: &[u8]) -> DpapiResult<Self> {
        let mut reader = value;
        let interface_id = SyntaxId::decode(&mut reader)?;
        let transfer_syntax = SyntaxId::decode(&mut reader)?;

        Ok(Self {
            flags,
            interface_id,
            transfer_syntax,
        })
    }

    fn encode_value(&self, mut writer: impl Write) -> DpapiResult<()> {
        let mut value = self.interface_id.encode_to_vec()?;
        self.transfer_syntax.encode(&mut value)?;

        writer.write_u16::<LittleEndian>(value.len().try_into()?)?;
        write_buf(&value, writer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandHeader2 {
    pub flags: CommandFlags,
    pub packet_type: PacketType,
    pub data_rep: DataRepr,
    pub call_id: u32,
    pub context_id: u16,
    pub opnum: u16,
}

impl CommandHeader2 {
    fn from_flags_and_value(flags: CommandFlags, value: &[u8]) -> DpapiResult<Self> {
        let mut reader = value;

        Ok(Self {
            flags,
            packet_type: {
                let packet_type = reader.read_u8()?;
                reader.read_u8()?;
                reader.read_u8()?;
                reader.read_u8()?;

                PacketType::from_u8(packet_type).ok_or(CommandError::InvalidPacketType(packet_type))?
            },
            data_rep: DataRepr::decode(&mut reader)?,
            call_id: reader.read_u32::<LittleEndian>()?,
            context_id: reader.read_u16::<LittleEndian>()?,
            opnum: reader.read_u16::<LittleEndian>()?,
        })
    }

    fn encode_value(&self, mut writer: impl Write) -> DpapiResult<()> {
        let mut value = vec![self.packet_type as u8];
        // Reserved
        value.extend_from_slice(&[0, 0, 0]);
        self.data_rep.encode(&mut value)?;
        value.write_u32::<LittleEndian>(self.call_id)?;
        value.write_u16::<LittleEndian>(self.context_id)?;
        value.write_u16::<LittleEndian>(self.opnum)?;

        writer.write_u16::<LittleEndian>(value.len().try_into()?)?;
        write_buf(&value, writer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationTrailer {
    pub commands: Vec<Command>,
}

impl VerificationTrailer {
    const SIGNATURE: &[u8] = &[138, 227, 19, 113, 2, 244, 54, 113];
}

impl Encode for VerificationTrailer {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        write_buf(VerificationTrailer::SIGNATURE, &mut writer)?;

        for command in &self.commands {
            command.encode(&mut writer)?;
        }

        Ok(())
    }
}

impl Decode for VerificationTrailer {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let signature = read_vec(VerificationTrailer::SIGNATURE.len(), &mut reader)?;

        if signature != VerificationTrailer::SIGNATURE {
            Err(CommandError::InvalidVerificationTrailerSignature {
                expected: VerificationTrailer::SIGNATURE,
                actual: signature,
            })?;
        }

        let mut commands = Vec::new();
        loop {
            let command = Command::decode(&mut reader)?;
            let flags = command.flags();

            commands.push(command);

            if flags.contains(CommandFlags::SecVtCommandEnd) {
                break;
            }
        }

        Ok(Self { commands })
    }
}
