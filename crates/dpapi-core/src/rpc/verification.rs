use alloc::vec::Vec;

use bitflags::bitflags;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use thiserror::Error;

use crate::rpc::{DataRepr, PacketType, SyntaxId};
use crate::{Decode, Encode, ReadCursor, Result, WriteBuf, WriteCursor, StaticName};

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

    fn value_length(&self) -> usize {
        match self {
            Command::Bitmask1(command) => command.value_length(),
            Command::Pcontext(command) => command.value_length(),
            Command::Header2(command) => command.value_length(),
        }
    }
}

impl StaticName for Command {
    const NAME: &'static str = "Command";
}

impl Encode for Command {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        ensure_size!(in: dst, size: self.frame_length());

        dst.write_u16(self.command_type().as_u16() | self.flags().bits());

        match self {
            Command::Bitmask1(command) => command.encode_value(dst),
            Command::Pcontext(command) => command.encode_value(dst),
            Command::Header2(command) => command.encode_value(dst),
        }
    }

    fn frame_length(&self) -> usize {
        2 /* command_type + command_flags */ + self.value_length()
    }
}

impl Decode for Command {
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self> {
        let cmd_field = src.read_u16();

        let command_type = cmd_field & 0x3fff;
        let command_flags = cmd_field & 0xc000;

        let command = CommandType::from_u16(command_type).ok_or(CommandError::InvalidCommandType(command_type))?;
        let flags = CommandFlags::from_bits(command_flags).ok_or(CommandError::InvalidCommandFlags(command_flags))?;

        let value_len = src.read_u16();
        let value = src.read_slice(usize::from(value_len));

        Ok(match command {
            CommandType::Bitmask1 => Self::Bitmask1(CommandBitmask::from_flags_and_value(flags, value)?),
            CommandType::Pcontext => Self::Pcontext(CommandPContext::from_flags_and_value(flags, value)?),
            CommandType::Header2 => Self::Header2(CommandHeader2::from_flags_and_value(flags, value)?),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandBitmask {
    pub bits: u32,
    pub flags: CommandFlags,
}

impl StaticName for CommandBitmask {
    const NAME: &'static str = "CommandBitmask";
}

impl CommandBitmask {
    fn value_length(&self) -> usize {
        4 /* bits */ + 2 /* value length */
    }

    fn from_flags_and_value(flags: CommandFlags, value: &[u8]) -> Result<Self> {
        if value.len() != 4 {
            Err(CommandError::InvalidCommandBitmaskValueLength(value.len()))?;
        }

        let bits: [u8; 4] = value.try_into().expect("length is checked above");

        Ok(Self {
            flags,
            bits: u32::from_le_bytes(bits),
        })
    }

    fn encode_value(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        ensure_size!(in: dst, size: self.value_length());

        dst.write_u16(4);
        dst.write_slice(self.bits.to_le_bytes().as_slice());

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPContext {
    pub flags: CommandFlags,
    pub interface_id: SyntaxId,
    pub transfer_syntax: SyntaxId,
}

impl StaticName for CommandPContext {
    const NAME: &'static str = "CommandPContext";
}

impl CommandPContext {
    fn value_length(&self) -> usize {
        self.interface_id.frame_length() + self.transfer_syntax.frame_length() + 2 /* value length */
    }

    fn from_flags_and_value(flags: CommandFlags, value: &[u8]) -> Result<Self> {
        let mut src = ReadCursor::new(value);

        let interface_id = SyntaxId::decode_cursor(&mut src)?;
        let transfer_syntax = SyntaxId::decode_cursor(&mut src)?;

        Ok(Self {
            flags,
            interface_id,
            transfer_syntax,
        })
    }

    fn encode_value(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        ensure_size!(in: dst, size: self.value_length());

        let mut buf = WriteBuf::new();

        self.interface_id.encode_buf(&mut buf)?;
        self.transfer_syntax.encode_buf(&mut buf)?;

        dst.write_u16(buf.filled_len().try_into()?);
        dst.write_slice(buf.filled());

        Ok(())
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

impl StaticName for CommandHeader2 {
    const NAME: &'static str = "CommandHeader2";
}

impl CommandHeader2 {
    fn value_length(&self) -> usize {
        4 /* packet_type + reserved */ + self.data_rep.frame_length() + 4 /* call_id */ + 2 /* context_id */ + 2 /* opnum */ + 2 /* value length */
    }

    fn from_flags_and_value(flags: CommandFlags, value: &[u8]) -> Result<Self> {
        let mut src = ReadCursor::new(value);

        Ok(Self {
            flags,
            packet_type: {
                let packet_type = src.read_u8();
                src.read_u8();
                src.read_u8();
                src.read_u8();

                PacketType::from_u8(packet_type).ok_or(CommandError::InvalidPacketType(packet_type))?
            },
            data_rep: DataRepr::decode_cursor(&mut src)?,
            call_id: src.read_u32(),
            context_id: src.read_u16(),
            opnum: src.read_u16(),
        })
    }

    fn encode_value(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        ensure_size!(in: dst, size: self.value_length());

        let mut buf = WriteBuf::new();

        buf.write_u8(self.packet_type.as_u8());
        // Reserved
        buf.write_slice(&[0, 0, 0]);
        self.data_rep.encode_buf(&mut buf)?;

        buf.write_u32(self.call_id);
        buf.write_u16(self.context_id);
        buf.write_u16(self.opnum);

        dst.write_u16(buf.filled_len().try_into()?);
        dst.write_slice(buf.filled());

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationTrailer {
    pub commands: Vec<Command>,
}

impl VerificationTrailer {
    const SIGNATURE: &[u8] = &[138, 227, 19, 113, 2, 244, 54, 113];
}

impl StaticName for VerificationTrailer {
    const NAME: &'static str = "VerificationTrailer";
}

impl Encode for VerificationTrailer {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        ensure_size!(in: dst, size: self.frame_length());

        dst.write_slice(Self::SIGNATURE);

        self.commands.encode_cursor(dst)?;

        Ok(())
    }

    fn frame_length(&self) -> usize {
        Self::SIGNATURE.len() + self.commands.frame_length()
    }
}

impl Decode for VerificationTrailer {
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self> {
        let signature = src.read_slice(VerificationTrailer::SIGNATURE.len());

        if signature != VerificationTrailer::SIGNATURE {
            Err(CommandError::InvalidVerificationTrailerSignature {
                expected: VerificationTrailer::SIGNATURE,
                actual: signature.to_vec(),
            })?;
        }

        let mut commands = Vec::new();
        loop {
            let command = Command::decode_cursor(src)?;
            let flags = command.flags();

            commands.push(command);

            if flags.contains(CommandFlags::SecVtCommandEnd) {
                break;
            }
        }

        Ok(Self { commands })
    }
}
