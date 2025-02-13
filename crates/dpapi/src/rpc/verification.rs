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
    SecVtCommandBitmask1 = 0x0001,
    SecVtCommandPcontext = 0x0002,
    SecVtCommandHeader2 = 0x0003,
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
pub struct CommandBase {
    pub command: CommandType,
    pub flags: CommandFlags,
    pub value: Vec<u8>,
}

impl Encode for CommandBase {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        writer.write_u16::<LittleEndian>(self.command as u16 | self.flags.bits())?;
        writer.write_u16::<LittleEndian>(self.value.len().try_into()?)?;
        write_buf(&self.value, writer)?;

        Ok(())
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
            Command::Bitmask1(command) => command.flags(),
            Command::Pcontext(command) => command.flags(),
            Command::Header2(command) => command.flags(),
        }
    }
}

impl Encode for Command {
    fn encode(&self, writer: impl Write) -> DpapiResult<()> {
        match self {
            Command::Bitmask1(command) => command.encode(writer),
            Command::Pcontext(command) => command.encode(writer),
            Command::Header2(command) => command.encode(writer),
        }
    }
}

impl Decode for Command {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let cmd_field = reader.read_u16::<LittleEndian>()?;

        let command_type = cmd_field & 0x3fff;
        let command_flags = cmd_field & 0xc000;

        let command =
            CommandType::from_u16(command_type).ok_or(CommandError::InvalidCommandType(command_type))?;
        let flags =
            CommandFlags::from_bits(command_flags).ok_or(CommandError::InvalidCommandFlags(command_flags))?;

        let value_len = reader.read_u16::<LittleEndian>()?;
        let value = read_vec(usize::from(value_len), reader)?;

        Ok(match command {
            CommandType::SecVtCommandBitmask1 => Self::Bitmask1(CommandBitmask::from_flags_and_value(flags, &value)?),
            CommandType::SecVtCommandPcontext => Self::Pcontext(CommandPContext::from_flags_and_value(flags, &value)?),
            CommandType::SecVtCommandHeader2 => Self::Header2(CommandHeader2::from_flags_and_value(flags, &value)?),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandBitmask {
    pub bits: u32,
    pub flags: CommandFlags,
}

impl CommandBitmask {
    pub fn flags(&self) -> CommandFlags {
        self.flags
    }

    pub fn from_flags_and_value(flags: CommandFlags, value: &[u8]) -> DpapiResult<Self> {
        if value.len() != 4 {
            Err(CommandError::InvalidCommandBitmaskValueLength(value.len()))?;
        }

        let bits: [u8; 4] = value.try_into().expect("length should be checked");

        Ok(Self {
            flags,
            bits: u32::from_le_bytes(bits),
        })
    }
}

impl Encode for CommandBitmask {
    fn encode(&self, writer: impl Write) -> DpapiResult<()> {
        CommandBase {
            command: CommandType::SecVtCommandBitmask1,
            flags: self.flags,
            value: self.bits.to_le_bytes().to_vec(),
        }
        .encode(writer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPContext {
    pub flags: CommandFlags,
    pub interface_id: SyntaxId,
    pub transfer_syntax: SyntaxId,
}

impl CommandPContext {
    pub fn flags(&self) -> CommandFlags {
        self.flags
    }

    pub fn from_flags_and_value(flags: CommandFlags, value: &[u8]) -> DpapiResult<Self> {
        let mut reader = value;
        let interface_id = SyntaxId::decode(&mut reader)?;
        let transfer_syntax = SyntaxId::decode(&mut reader)?;

        Ok(Self {
            flags,
            interface_id,
            transfer_syntax,
        })
    }
}

impl Encode for CommandPContext {
    fn encode(&self, writer: impl Write) -> DpapiResult<()> {
        CommandBase {
            command: CommandType::SecVtCommandPcontext,
            flags: self.flags,
            value: {
                let mut value = self.interface_id.encode_to_vec()?;
                self.transfer_syntax.encode(&mut value)?;
                value
            },
        }
        .encode(writer)
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
    pub fn flags(&self) -> CommandFlags {
        self.flags
    }

    pub fn from_flags_and_value(flags: CommandFlags, value: &[u8]) -> DpapiResult<Self> {
        let mut reader = value;

        Ok(Self {
            flags,
            packet_type: {
                let packet_type = reader.read_u8()?;
                PacketType::from_u8(packet_type).ok_or(CommandError::InvalidPacketType(packet_type))?
            },
            data_rep: DataRepr::decode(&mut reader)?,
            call_id: reader.read_u32::<LittleEndian>()?,
            context_id: reader.read_u16::<LittleEndian>()?,
            opnum: reader.read_u16::<LittleEndian>()?,
        })
    }
}

impl Encode for CommandHeader2 {
    fn encode(&self, writer: impl Write) -> DpapiResult<()> {
        let mut value = vec![self.packet_type as u8];
        // Reserved
        value.extend_from_slice(&[0, 0, 0]);
        self.data_rep.encode(&mut value)?;
        value.write_u32::<LittleEndian>(self.call_id)?;
        value.write_u16::<LittleEndian>(self.context_id)?;
        value.write_u16::<LittleEndian>(self.opnum)?;

        CommandBase {
            command: CommandType::SecVtCommandHeader2,
            flags: self.flags,
            value,
        }
        .encode(writer)
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
            commands.push(command.clone());

            if command.flags().contains(CommandFlags::SecVtCommandEnd) {
                break;
            }
        }

        Ok(Self { commands })
    }
}
