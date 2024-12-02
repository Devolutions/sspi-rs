use std::io::{Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use uuid::Uuid;

use crate::rpc::{read_padding, read_uuid, write_padding, Decode, Encode};
use crate::{DpapiResult, Error, ErrorKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetKey {
    pub target_sd: Vec<u8>,
    pub root_key_id: Option<Uuid>,
    pub l0_key_id: i32,
    pub l1_key_id: i32,
    pub l2_key_id: i32,
}

impl Encode for GetKey {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        let target_sd_len = self.target_sd.len().try_into()?;
        // cbTargetSD
        writer.write_u64::<LittleEndian>(target_sd_len)?;
        // pbTargetSD - pointer header includes the length + padding
        writer.write_u64::<LittleEndian>(target_sd_len)?;

        // TODO
        writer.write(&self.target_sd)?;

        write_padding::<8>(target_sd_len.try_into()?, &mut writer)?;

        let root_key_bytes = if let Some(root_key_id) = self.root_key_id.as_ref() {
            // TODO
            writer.write(&[0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00])?;
            writer.write(root_key_id.to_bytes_le().as_ref())?;
        } else {
            writer.write_u64::<LittleEndian>(0)?;
        };

        writer.write_i32::<LittleEndian>(self.l0_key_id)?;
        writer.write_i32::<LittleEndian>(self.l1_key_id)?;
        writer.write_i32::<LittleEndian>(self.l2_key_id)?;

        Ok(())
    }
}

impl Decode for GetKey {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let target_sd_len = reader.read_u64::<LittleEndian>()?;
        let _offset = reader.read_u64::<LittleEndian>()?;

        let mut target_sd = vec![0; target_sd_len.try_into()?];
        // TODO
        reader.read_exact(&mut target_sd)?;

        read_padding::<8>(target_sd_len.try_into()?, &mut reader)?;

        let root_key_id = if reader.read_u64::<LittleEndian>()? != 0 {
            Some(read_uuid(&mut reader)?)
        } else {
            None
        };

        let l0_key_id = reader.read_i32::<LittleEndian>()?;
        let l1_key_id = reader.read_i32::<LittleEndian>()?;
        let l2_key_id = reader.read_i32::<LittleEndian>()?;

        Ok(Self {
            target_sd,
            root_key_id,
            l0_key_id,
            l1_key_id,
            l2_key_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    test_encoding_decoding! {
        get_key,
        GetKey,
        GetKey {
            target_sd: vec![1, 2, 3, 4],
            root_key_id: Some(Uuid::from_str("73294420-917f-416a-9ec3-86082afafb9e").unwrap()),
            l0_key_id: -1,
            l1_key_id: 1,
            l2_key_id: 31,
        },
        [0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x44, 0x29, 0x73, 0x7f, 0x91, 0x6a, 0x41, 0x9e, 0xc3, 0x86, 0x08, 0x2a, 0xfa, 0xfb, 0x9e, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00]
    }
}
