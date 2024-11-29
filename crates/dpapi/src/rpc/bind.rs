use std::io::{Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use uuid::Uuid;

use super::{Decode, Encode};
use crate::{DpapiResult, Error, ErrorKind};

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
        writer.write(&self.uuid.to_bytes_le())?;
        writer.write_u16::<LittleEndian>(self.version)?;
        writer.write_u16::<LittleEndian>(self.version_minor)?;

        Ok(())
    }
}

impl Decode for SyntaxId {
    fn decode(mut reader: impl Read) -> DpapiResult<SyntaxId> {
        let mut uuid_buf = [0; 16];
        reader.read(&mut uuid_buf)?;
        let uuid = Uuid::from_slice_le(&uuid_buf)?;

        let version = reader.read_u16::<LittleEndian>()?;
        let version_minor = reader.read_u16::<LittleEndian>()?;

        Ok(Self {
            uuid,
            version,
            version_minor,
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
            .into_iter()
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

impl From<ContextResultCode> for u16 {
    fn from(code: ContextResultCode) -> Self {
        code as u16
    }
}

impl TryFrom<u16> for ContextResultCode {
    type Error = Error;

    fn try_from(v: u16) -> DpapiResult<Self> {
        match v {
            0 => Ok(Self::Acceptance),
            1 => Ok(Self::UserRejection),
            2 => Ok(Self::ProviderRejection),
            3 => Ok(Self::NegotiateAck),
            v => Err(Error::new(
                ErrorKind::NteInvalidParameter,
                format!("invalid ContextResultCode value: {}", v),
            )),
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
        writer.write_u16::<LittleEndian>(self.result.into())?;
        writer.write_u16::<LittleEndian>(self.reason)?;
        writer.write(&self.syntax.to_bytes_le())?;
        writer.write_u32::<LittleEndian>(self.syntax_version)?;

        Ok(())
    }
}

impl Decode for ContextResult {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        Ok(Self {
            result: reader.read_u16::<LittleEndian>()?.try_into()?,
            reason: reader.read_u16::<LittleEndian>()?,
            syntax: {
                let mut uuid_buf = [0; 16];
                reader.read(&mut uuid_buf)?;
                Uuid::from_slice_le(&uuid_buf)?
            },
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
            .into_iter()
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

            writer.write(self.sec_addr.as_bytes())?;
            writer.write_u8(0)?;

            sec_addr_len
        } else {
            writer.write_u16::<LittleEndian>(0)?;

            0
        } + 2;

        let padding_len = (4 - (sec_addr_len % 4)) % 4;
        let padding_buf = vec![0; padding_len];
        // TODO: check written bytes.
        writer.write(&padding_buf)?;

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
                    let mut buf = vec![0; sec_addr_len - 1 /* null byte */];

                    reader.read_exact(buf.as_mut_slice())?;
                    // Read null-terminator byte.
                    reader.read_u8()?;

                    String::from_utf8(buf)?
                } else {
                    String::new()
                };

                let sec_addr_len = sec_addr_len + 2;
                let padding_len = (4 - (sec_addr_len % 4)) % 4;
                let mut padding_buf = vec![0; padding_len];
                reader.read_exact(padding_buf.as_mut_slice())?;

                sec_addr
            },
            results: {
                let results_count = reader.read_u32::<LittleEndian>()?;
                (0..results_count)
                    .into_iter()
                    .map(|_| ContextResult::decode(&mut reader))
                    .collect::<DpapiResult<_>>()?
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    test_encoding_decoding! {
        syntax_id,
        SyntaxId,
        SyntaxId {
            uuid: Uuid::from_str("b9785960-524f-11df-8b6d-83dcded72085").expect("valid uuid"),
            version: 1,
            version_minor: 0,
        },
        [96, 89, 120, 185, 79, 82, 223, 17, 139, 109, 131, 220, 222, 215, 32, 133, 1, 0, 0, 0]
    }

    test_encoding_decoding! {
        context_element,
        ContextElement,
        ContextElement {
            context_id: 0,
            abstract_syntax: SyntaxId {
                uuid: Uuid::from_str("b9785960-524f-11df-8b6d-83dcded72085").expect("valid uuid"),
                version: 1,
                version_minor: 0,
            },
            transfer_syntaxes: vec![
                SyntaxId {
                    uuid: Uuid::from_str("71710533-beba-4937-8319-b5dbef9ccc36").expect("valid uuid"),
                    version: 1,
                    version_minor: 0,
                }
            ],
        },
        [0, 0, 1, 0, 96, 89, 120, 185, 79, 82, 223, 17, 139, 109, 131, 220, 222, 215, 32, 133, 1, 0, 0, 0, 51, 5, 113, 113, 186, 190, 55, 73, 131, 25, 181, 219, 239, 156, 204, 54, 1, 0, 0, 0]
    }

    test_encoding_decoding! {
        context_result,
        ContextResult,
        ContextResult {
            result: ContextResultCode::Acceptance,
            reason: 0,
            syntax: Uuid::from_str("71710533-beba-4937-8319-b5dbef9ccc36").unwrap(),
            syntax_version: 1,
        },
        [0, 0, 0, 0, 51, 5, 113, 113, 186, 190, 55, 73, 131, 25, 181, 219, 239, 156, 204, 54, 1, 0, 0, 0]
    }
}
