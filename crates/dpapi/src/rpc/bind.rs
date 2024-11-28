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
#[repr(u64)]
pub enum BindTimeFeatureNegotiationBitmask {
    None = 0x0,
    /// Client supports security context multiplexing, as specified in section [3.3.1.5.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/c8b3c80f-b2ba-4a78-bf36-dabba4278194).
    SecurityContextMultiplexingSupported = 0x01,
    /// Client supports keeping the connection open after sending the orphaned PDU, as specified in section [3.3.1.5.10](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/44d6f02e-55f3-4814-973e-cf0bc3287c44).
    KeepConnectionOnOrphanSupported = 0x02,
}

#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone, PartialEq)]
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

#[cfg(test)]
mod tests {
    #![allow(non_snake_case)]

    use std::str::FromStr;

    use super::*;

    macro_rules! test_encoding_decoding {
        ($name:ident, $expected:expr, $data:expr) => {
            paste::paste! {
                #[test]
                fn [<$name _encoding_decoding>]() {
                    let data = $data;

                    let parsed = $name::decode(data.as_ref()).unwrap();
                    let encoded = parsed.encode_to_vec().unwrap();

                    assert_eq!($expected, parsed);
                    assert_eq!(data.as_ref(), &encoded);
                }
            }
        };
    }

    test_encoding_decoding! {
        SyntaxId,
        SyntaxId {
            uuid: Uuid::from_str("b9785960-524f-11df-8b6d-83dcded72085").expect("valid uuid"),
            version: 1,
            version_minor: 0,
        },
        [96, 89, 120, 185, 79, 82, 223, 17, 139, 109, 131, 220, 222, 215, 32, 133, 1, 0, 0, 0]
    }

    test_encoding_decoding! {
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
}
