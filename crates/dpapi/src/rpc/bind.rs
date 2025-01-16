use std::io::{Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use thiserror::Error;
use uuid::Uuid;

use crate::rpc::{read_padding, read_vec, write_buf, write_padding, Decode, Encode};
use crate::DpapiResult;

#[derive(Debug, Error)]
pub enum BindError {
    #[error("invalid context result code value: {0}")]
    InvalidContextResultCode(u16),
}

/// [BindTimeFeatureNegotiationBitmask](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/cef529cc-77b5-4794-85dc-91e1467e80f0)
///
/// The bind time feature negotiation bitmask is an array of eight octets, each of which is interpreted as a bitmask.
/// **Bitmask**: Currently, only the two least significant bits in the first element of the array are defined.
///
/// ```not_rust
/// typedef struct {
///    unsigned char Bitmask[8];
/// } BindTimeFeatureNegotiationBitmask;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum BindTimeFeatureNegotiationBitmask {
    None = 0x0,
    /// Client supports security context multiplexing, as specified in section [3.3.1.5.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/c8b3c80f-b2ba-4a78-bf36-dabba4278194).
    SecurityContextMultiplexingSupported = 0x01,
    /// Client supports keeping the connection open after sending the orphaned PDU, as specified in section [3.3.1.5.10](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/44d6f02e-55f3-4814-973e-cf0bc3287c44).
    KeepConnectionOnOrphanSupported = 0x02,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxId {
    pub uuid: Uuid,
    pub version: u16,
    pub version_minor: u16,
}

impl Encode for SyntaxId {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        self.uuid.encode(&mut writer)?;
        writer.write_u16::<LittleEndian>(self.version)?;
        writer.write_u16::<LittleEndian>(self.version_minor)?;

        Ok(())
    }
}

impl Decode for SyntaxId {
    fn decode(mut reader: impl Read) -> DpapiResult<SyntaxId> {
        Ok(Self {
            uuid: Uuid::decode(&mut reader)?,
            version: reader.read_u16::<LittleEndian>()?,
            version_minor: reader.read_u16::<LittleEndian>()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextElement {
    pub context_id: u16,
    pub abstract_syntax: SyntaxId,
    pub transfer_syntaxes: Vec<SyntaxId>,
}

impl Encode for ContextElement {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        writer.write_u16::<LittleEndian>(self.context_id)?;
        writer.write_u16::<LittleEndian>(self.transfer_syntaxes.len().try_into()?)?;

        self.abstract_syntax.encode(&mut writer)?;

        for transfer_syntax in &self.transfer_syntaxes {
            transfer_syntax.encode(&mut writer)?;
        }

        Ok(())
    }
}

impl Decode for ContextElement {
    fn decode(mut reader: impl Read) -> DpapiResult<ContextElement> {
        let context_id = reader.read_u16::<LittleEndian>()?;
        let transfer_syntaxes_count = usize::from(reader.read_u16::<LittleEndian>()?);
        let abstract_syntax = SyntaxId::decode(&mut reader)?;

        let transfer_syntaxes = (0..transfer_syntaxes_count)
            .map(|_| SyntaxId::decode(&mut reader))
            .collect::<DpapiResult<_>>()?;

        Ok(Self {
            context_id,
            abstract_syntax,
            transfer_syntaxes,
        })
    }
}

/// [`p_cont_def_result_t` Enumerator](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/8df5c4d4-364d-468c-81fe-ec94c1b40917)
///
/// These extensions specify a new member, `negotiate_ack`, which is added to the `p_cont_def_result_t` enumeration
/// (specified in C706 section 12.6), with the numeric value of `3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ContextResultCode {
    Acceptance = 0,
    UserRejection = 1,
    ProviderRejection = 2,
    NegotiateAck = 3, // MS-RPCE extension
}

impl ContextResultCode {
    pub fn as_u16(&self) -> u16 {
        *self as u16
    }
}

impl TryFrom<u16> for ContextResultCode {
    type Error = BindError;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Acceptance),
            1 => Ok(Self::UserRejection),
            2 => Ok(Self::ProviderRejection),
            3 => Ok(Self::NegotiateAck),
            v => Err(BindError::InvalidContextResultCode(v)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextResult {
    pub result: ContextResultCode,
    pub reason: u16,
    pub syntax: Uuid,
    pub syntax_version: u32,
}

impl Encode for ContextResult {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        writer.write_u16::<LittleEndian>(self.result.as_u16())?;
        writer.write_u16::<LittleEndian>(self.reason)?;
        self.syntax.encode(&mut writer)?;
        writer.write_u32::<LittleEndian>(self.syntax_version)?;

        Ok(())
    }
}

impl Decode for ContextResult {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        Ok(Self {
            result: reader.read_u16::<LittleEndian>()?.try_into()?,
            reason: reader.read_u16::<LittleEndian>()?,
            syntax: Uuid::decode(&mut reader)?,
            syntax_version: reader.read_u32::<LittleEndian>()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bind {
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group: u32,
    pub contexts: Vec<ContextElement>,
}

impl Encode for Bind {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        writer.write_u16::<LittleEndian>(self.max_xmit_frag)?;
        writer.write_u16::<LittleEndian>(self.max_recv_frag)?;
        writer.write_u32::<LittleEndian>(self.assoc_group)?;
        writer.write_u32::<LittleEndian>(self.contexts.len().try_into()?)?;

        for context in &self.contexts {
            context.encode(&mut writer)?;
        }

        Ok(())
    }
}

impl Decode for Bind {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let max_xmit_frag = reader.read_u16::<LittleEndian>()?;
        let max_recv_frag = reader.read_u16::<LittleEndian>()?;
        let assoc_group = reader.read_u32::<LittleEndian>()?;

        let contexts_count = reader.read_u32::<LittleEndian>()?;
        let contexts = (0..contexts_count)
            .map(|_| ContextElement::decode(&mut reader))
            .collect::<DpapiResult<_>>()?;

        Ok(Self {
            max_xmit_frag,
            max_recv_frag,
            assoc_group,
            contexts,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindAck {
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group: u32,
    pub sec_addr: String,
    pub results: Vec<ContextResult>,
}

impl Encode for BindAck {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        writer.write_u16::<LittleEndian>(self.max_xmit_frag)?;
        writer.write_u16::<LittleEndian>(self.max_recv_frag)?;
        writer.write_u32::<LittleEndian>(self.assoc_group)?;

        let sec_addr_len = if !self.sec_addr.is_empty() {
            let sec_addr_len = self.sec_addr.len() + 1;
            writer.write_u16::<LittleEndian>(sec_addr_len.try_into()?)?;

            write_buf(self.sec_addr.as_bytes(), &mut writer)?;
            writer.write_u8(0)?;

            sec_addr_len
        } else {
            writer.write_u16::<LittleEndian>(0)?;

            0
        } + 2;

        write_padding::<4>(sec_addr_len, &mut writer)?;

        writer.write_u32::<LittleEndian>(self.results.len().try_into()?)?;
        for result in &self.results {
            result.encode(&mut writer)?;
        }

        Ok(())
    }
}

impl Decode for BindAck {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        Ok(Self {
            max_xmit_frag: reader.read_u16::<LittleEndian>()?,
            max_recv_frag: reader.read_u16::<LittleEndian>()?,
            assoc_group: reader.read_u32::<LittleEndian>()?,
            sec_addr: {
                let sec_addr_len = usize::from(reader.read_u16::<LittleEndian>()?);
                let sec_addr = if sec_addr_len > 0 {
                    let buf = read_vec(sec_addr_len - 1 /* null byte */, &mut reader)?;

                    // Read null-terminator byte.
                    reader.read_u8()?;

                    String::from_utf8(buf)?
                } else {
                    String::new()
                };

                read_padding::<4>(sec_addr_len + 2 /* len */, &mut reader)?;

                sec_addr
            },
            results: {
                let results_count = reader.read_u32::<LittleEndian>()?;
                (0..results_count)
                    .map(|_| ContextResult::decode(&mut reader))
                    .collect::<DpapiResult<_>>()?
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindNak {
    pub reason: u16,
    pub versions: Vec<(u8, u8)>,
}

impl Encode for BindNak {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        writer.write_u16::<LittleEndian>(self.reason)?;

        writer.write_u8(self.versions.len().try_into()?)?;
        for version in &self.versions {
            writer.write_u8(version.0)?;
            writer.write_u8(version.1)?;
        }

        let versions_buf_len = 1 /* len */ + 2 /* version size */ * self.versions.len();
        write_padding::<4>(versions_buf_len, &mut writer)
    }
}

impl Decode for BindNak {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        Ok(Self {
            reason: reader.read_u16::<LittleEndian>()?,
            versions: {
                let versions_count = reader.read_u8()?;
                let versions = (0..versions_count)
                    .map(|_| Ok((reader.read_u8()?, reader.read_u8()?)))
                    .collect::<DpapiResult<Vec<_>>>()?;

                let versions_buf_len = 1 /* len */ + 2 /* version size */ * versions.len();
                read_padding::<4>(versions_buf_len, reader)?;

                versions
            },
        })
    }
}

// `AlterContext` has the same layout as `Bind`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlterContext(pub Bind);

impl Encode for AlterContext {
    fn encode(&self, writer: impl Write) -> DpapiResult<()> {
        self.0.encode(writer)
    }
}

impl Decode for AlterContext {
    fn decode(reader: impl Read) -> DpapiResult<Self> {
        Ok(Self(Bind::decode(reader)?))
    }
}

// `AlterContextResponse` has the same layout as `BindAck`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlterContextResponse(pub BindAck);

impl Encode for AlterContextResponse {
    fn encode(&self, writer: impl Write) -> DpapiResult<()> {
        self.0.encode(writer)
    }
}

impl Decode for AlterContextResponse {
    fn decode(reader: impl Read) -> DpapiResult<Self> {
        Ok(Self(BindAck::decode(reader)?))
    }
}
