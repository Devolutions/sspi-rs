use std::fmt;
use std::io::{Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_bigint_dig::BigUint;
use uuid::Uuid;

use crate::rpc::{read_padding, read_uuid, write_padding, Decode, Encode};
use crate::utils::utf16_bytes_to_utf8_string;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl fmt::Display for HashAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashAlg::Sha1 => write!(f, "SHA1"),
            HashAlg::Sha256 => write!(f, "SHA256"),
            HashAlg::Sha384 => write!(f, "SHA384"),
            HashAlg::Sha512 => write!(f, "SHA512"),
        }
    }
}

impl TryFrom<&str> for HashAlg {
    type Error = Error;

    fn try_from(data: &str) -> Result<Self, Self::Error> {
        match data {
            "SHA1" => Ok(HashAlg::Sha1),
            "SHA256" => Ok(HashAlg::Sha256),
            "SHA384" => Ok(HashAlg::Sha384),
            "SHA512" => Ok(HashAlg::Sha512),
            _ => Err(Error::new(
                ErrorKind::NteInvalidParameter,
                format!("invalid hash alg name: {}", data),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParameters {
    hash_alg: HashAlg,
}

impl KdfParameters {
    const MAGIC_IDENTIFIER_1: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
    const MAGIC_IDENTIFIER_2: &[u8] = &[0x00, 0x00, 0x00, 0x00];
}

impl Encode for KdfParameters {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        let encoded_hash_alg = self
            .hash_alg
            .to_string()
            .encode_utf16()
            .into_iter()
            .chain(std::iter::once(0))
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>();

        writer.write(KdfParameters::MAGIC_IDENTIFIER_1)?;
        writer.write_u32::<LittleEndian>(encoded_hash_alg.len().try_into()?)?;
        // TODO
        writer.write(KdfParameters::MAGIC_IDENTIFIER_2)?;
        writer.write(&encoded_hash_alg)?;

        Ok(())
    }
}

impl Decode for KdfParameters {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let mut buf = [0; 8];
        reader.read_exact(&mut buf)?;

        if buf != KdfParameters::MAGIC_IDENTIFIER_1 {
            return Err(Error::new(
                ErrorKind::NteInvalidParameter,
                "invalid KdfParameters::MAGIC_IDENTIFIER_1",
            ));
        }

        let hash_name_len: usize = reader.read_u32::<LittleEndian>()?.try_into()?;

        let mut buf = [0; 4];
        reader.read_exact(&mut buf)?;

        if buf != KdfParameters::MAGIC_IDENTIFIER_2 {
            return Err(Error::new(
                ErrorKind::NteInvalidParameter,
                "invalid KdfParameters::MAGIC_IDENTIFIER_2",
            ));
        }

        let mut buf = vec![0; hash_name_len - 2 /* UTF16 null terminator char */];
        reader.read_exact(&mut buf)?;
        // Skip UTF16 null terminator char.
        reader.read_u16::<LittleEndian>()?;

        Ok(Self {
            hash_alg: utf16_bytes_to_utf8_string(&buf)?.as_str().try_into()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfcdhParameters {
    pub key_length: u32,
    pub field_order: BigUint,
    pub generator: BigUint,
}

impl FfcdhParameters {
    const MAGIC: &[u8] = &[0x44, 0x48, 0x50, 0x4d];
}

impl Encode for FfcdhParameters {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        writer.write_u32::<LittleEndian>(12 + self.key_length * 2)?;
        // TODO
        writer.write(FfcdhParameters::MAGIC)?;
        writer.write_u32::<LittleEndian>(self.key_length)?;

        let key_len = self.key_length.try_into()?;

        let mut field_order = self.field_order.to_bytes_be();
        while field_order.len() < key_len {
            field_order.insert(0, 0);
        }
        // TODO
        writer.write(&field_order)?;

        let mut generator = self.generator.to_bytes_be();
        while generator.len() < key_len {
            generator.insert(0, 0);
        }
        // TODO
        writer.write(&generator)?;

        Ok(())
    }
}

impl Decode for FfcdhParameters {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let _total_len = reader.read_u32::<LittleEndian>()?;

        let mut magic = [0; 4];
        // TODO
        reader.read_exact(&mut magic)?;
        if magic != FfcdhParameters::MAGIC {
            return Err(Error::new(
                ErrorKind::NteInvalidParameter,
                "invalid FfcdhParameters::MAGIC",
            ));
        }

        let key_length = reader.read_u32::<LittleEndian>()?;

        let mut field_order = vec![0; key_length.try_into()?];
        // TODO
        reader.read_exact(&mut field_order)?;
        let field_order = BigUint::from_bytes_be(&field_order);

        let mut generator = vec![0; key_length.try_into()?];
        // TODO
        reader.read_exact(&mut generator)?;
        let generator = BigUint::from_bytes_be(&generator);

        Ok(Self {
            key_length,
            field_order,
            generator,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfcdhKey {
    key_length: u32,
    field_order: BigUint,
    generator: BigUint,
    public_key: BigUint,
}

impl FfcdhKey {
    const MAGIC: &[u8] = &[0x44, 0x48, 0x50, 0x42];
}

impl Encode for FfcdhKey {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        // TODO
        writer.write(FfcdhKey::MAGIC)?;

        writer.write_u32::<LittleEndian>(self.key_length)?;

        let key_len = self.key_length.try_into()?;

        let mut field_order = self.field_order.to_bytes_be();
        while field_order.len() < key_len {
            field_order.insert(0, 0);
        }
        // TODO
        writer.write(&field_order)?;

        let mut generator = self.generator.to_bytes_be();
        while generator.len() < key_len {
            generator.insert(0, 0);
        }
        // TODO
        writer.write(&generator)?;

        let mut public_key = self.public_key.to_bytes_be();
        while public_key.len() < key_len {
            public_key.insert(0, 0);
        }
        // TODO
        writer.write(&public_key)?;

        Ok(())
    }
}

impl Decode for FfcdhKey {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let mut magic = [0; 4];
        // TODO
        reader.read_exact(&mut magic)?;
        if magic != FfcdhKey::MAGIC {
            return Err(Error::new(ErrorKind::NteInvalidParameter, "invalid FfcdhKey::MAGIC"));
        }

        let key_length = reader.read_u32::<LittleEndian>()?;

        let mut field_order = vec![0; key_length.try_into()?];
        // TODO
        reader.read_exact(&mut field_order)?;
        let field_order = BigUint::from_bytes_be(&field_order);

        let mut generator = vec![0; key_length.try_into()?];
        // TODO
        reader.read_exact(&mut generator)?;
        let generator = BigUint::from_bytes_be(&generator);

        let mut public_key = vec![0; key_length.try_into()?];
        // TODO
        reader.read_exact(&mut public_key)?;
        let public_key = BigUint::from_bytes_be(&public_key);

        Ok(Self {
            key_length,
            field_order,
            generator,
            public_key,
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

    test_encoding_decoding! {
        kdf_parameters,
        KdfParameters,
        KdfParameters {
            hash_alg: HashAlg::Sha512,
        },
        [0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53, 0x00, 0x48, 0x00, 0x41, 0x00, 0x35, 0x00, 0x31, 0x00, 0x32, 0x00, 0x00, 0x00]
    }

    test_encoding_decoding! {
        ffcdh_parameters,
        FfcdhParameters,
        FfcdhParameters {
            key_length: 256,
            field_order: BigUint::from_bytes_be(&[135, 168, 230, 29, 180, 182, 102, 60, 255, 187, 209, 156, 101, 25, 89, 153, 140, 238, 246, 8, 102, 13, 208, 242, 93, 44, 238, 212, 67, 94, 59, 0, 224, 13, 248, 241, 214, 25, 87, 212, 250, 247, 223, 69, 97, 178, 170, 48, 22, 195, 217, 17, 52, 9, 111, 170, 59, 244, 41, 109, 131, 14, 154, 124, 32, 158, 12, 100, 151, 81, 122, 189, 90, 138, 157, 48, 107, 207, 103, 237, 145, 249, 230, 114, 91, 71, 88, 192, 34, 224, 177, 239, 66, 117, 191, 123, 108, 91, 252, 17, 212, 95, 144, 136, 185, 65, 245, 78, 177, 229, 155, 184, 188, 57, 160, 191, 18, 48, 127, 92, 79, 219, 112, 197, 129, 178, 63, 118, 182, 58, 202, 225, 202, 166, 183, 144, 45, 82, 82, 103, 53, 72, 138, 14, 241, 60, 109, 154, 81, 191, 164, 171, 58, 216, 52, 119, 150, 82, 77, 142, 246, 161, 103, 181, 164, 24, 37, 217, 103, 225, 68, 229, 20, 5, 100, 37, 28, 202, 203, 131, 230, 180, 134, 246, 179, 202, 63, 121, 113, 80, 96, 38, 192, 184, 87, 246, 137, 150, 40, 86, 222, 212, 1, 10, 189, 11, 230, 33, 195, 163, 150, 10, 84, 231, 16, 195, 117, 242, 99, 117, 215, 1, 65, 3, 164, 181, 67, 48, 193, 152, 175, 18, 97, 22, 210, 39, 110, 17, 113, 95, 105, 56, 119, 250, 215, 239, 9, 202, 219, 9, 74, 233, 30, 26, 21, 151]),
            generator: BigUint::from_bytes_be(&[63, 179, 44, 155, 115, 19, 77, 11, 46, 119, 80, 102, 96, 237, 189, 72, 76, 167, 177, 143, 33, 239, 32, 84, 7, 244, 121, 58, 26, 11, 161, 37, 16, 219, 193, 80, 119, 190, 70, 63, 255, 79, 237, 74, 172, 11, 181, 85, 190, 58, 108, 27, 12, 107, 71, 177, 188, 55, 115, 191, 126, 140, 111, 98, 144, 18, 40, 248, 194, 140, 187, 24, 165, 90, 227, 19, 65, 0, 10, 101, 1, 150, 249, 49, 199, 122, 87, 242, 221, 244, 99, 229, 233, 236, 20, 75, 119, 125, 230, 42, 170, 184, 168, 98, 138, 195, 118, 210, 130, 214, 237, 56, 100, 230, 121, 130, 66, 142, 188, 131, 29, 20, 52, 143, 111, 47, 145, 147, 181, 4, 90, 242, 118, 113, 100, 225, 223, 201, 103, 193, 251, 63, 46, 85, 164, 189, 27, 255, 232, 59, 156, 128, 208, 82, 185, 133, 209, 130, 234, 10, 219, 42, 59, 115, 19, 211, 254, 20, 200, 72, 75, 30, 5, 37, 136, 185, 183, 210, 187, 210, 223, 1, 97, 153, 236, 208, 110, 21, 87, 205, 9, 21, 179, 53, 59, 187, 100, 224, 236, 55, 127, 208, 40, 55, 13, 249, 43, 82, 199, 137, 20, 40, 205, 198, 126, 182, 24, 75, 82, 61, 29, 178, 70, 195, 47, 99, 7, 132, 144, 240, 14, 248, 214, 71, 209, 72, 212, 121, 84, 81, 94, 35, 39, 207, 239, 152, 197, 130, 102, 75, 76, 15, 108, 196, 22, 89]),
        },
        [12, 2, 0, 0, 68, 72, 80, 77, 0, 1, 0, 0, 135, 168, 230, 29, 180, 182, 102, 60, 255, 187, 209, 156, 101, 25, 89, 153, 140, 238, 246, 8, 102, 13, 208, 242, 93, 44, 238, 212, 67, 94, 59, 0, 224, 13, 248, 241, 214, 25, 87, 212, 250, 247, 223, 69, 97, 178, 170, 48, 22, 195, 217, 17, 52, 9, 111, 170, 59, 244, 41, 109, 131, 14, 154, 124, 32, 158, 12, 100, 151, 81, 122, 189, 90, 138, 157, 48, 107, 207, 103, 237, 145, 249, 230, 114, 91, 71, 88, 192, 34, 224, 177, 239, 66, 117, 191, 123, 108, 91, 252, 17, 212, 95, 144, 136, 185, 65, 245, 78, 177, 229, 155, 184, 188, 57, 160, 191, 18, 48, 127, 92, 79, 219, 112, 197, 129, 178, 63, 118, 182, 58, 202, 225, 202, 166, 183, 144, 45, 82, 82, 103, 53, 72, 138, 14, 241, 60, 109, 154, 81, 191, 164, 171, 58, 216, 52, 119, 150, 82, 77, 142, 246, 161, 103, 181, 164, 24, 37, 217, 103, 225, 68, 229, 20, 5, 100, 37, 28, 202, 203, 131, 230, 180, 134, 246, 179, 202, 63, 121, 113, 80, 96, 38, 192, 184, 87, 246, 137, 150, 40, 86, 222, 212, 1, 10, 189, 11, 230, 33, 195, 163, 150, 10, 84, 231, 16, 195, 117, 242, 99, 117, 215, 1, 65, 3, 164, 181, 67, 48, 193, 152, 175, 18, 97, 22, 210, 39, 110, 17, 113, 95, 105, 56, 119, 250, 215, 239, 9, 202, 219, 9, 74, 233, 30, 26, 21, 151, 63, 179, 44, 155, 115, 19, 77, 11, 46, 119, 80, 102, 96, 237, 189, 72, 76, 167, 177, 143, 33, 239, 32, 84, 7, 244, 121, 58, 26, 11, 161, 37, 16, 219, 193, 80, 119, 190, 70, 63, 255, 79, 237, 74, 172, 11, 181, 85, 190, 58, 108, 27, 12, 107, 71, 177, 188, 55, 115, 191, 126, 140, 111, 98, 144, 18, 40, 248, 194, 140, 187, 24, 165, 90, 227, 19, 65, 0, 10, 101, 1, 150, 249, 49, 199, 122, 87, 242, 221, 244, 99, 229, 233, 236, 20, 75, 119, 125, 230, 42, 170, 184, 168, 98, 138, 195, 118, 210, 130, 214, 237, 56, 100, 230, 121, 130, 66, 142, 188, 131, 29, 20, 52, 143, 111, 47, 145, 147, 181, 4, 90, 242, 118, 113, 100, 225, 223, 201, 103, 193, 251, 63, 46, 85, 164, 189, 27, 255, 232, 59, 156, 128, 208, 82, 185, 133, 209, 130, 234, 10, 219, 42, 59, 115, 19, 211, 254, 20, 200, 72, 75, 30, 5, 37, 136, 185, 183, 210, 187, 210, 223, 1, 97, 153, 236, 208, 110, 21, 87, 205, 9, 21, 179, 53, 59, 187, 100, 224, 236, 55, 127, 208, 40, 55, 13, 249, 43, 82, 199, 137, 20, 40, 205, 198, 126, 182, 24, 75, 82, 61, 29, 178, 70, 195, 47, 99, 7, 132, 144, 240, 14, 248, 214, 71, 209, 72, 212, 121, 84, 81, 94, 35, 39, 207, 239, 152, 197, 130, 102, 75, 76, 15, 108, 196, 22, 89]
    }

    test_encoding_decoding! {
        ffcdh_key,
        FfcdhKey,
        FfcdhKey {
            key_length: 256,
            field_order: BigUint::from_bytes_be(&[135, 168, 230, 29, 180, 182, 102, 60, 255, 187, 209, 156, 101, 25, 89, 153, 140, 238, 246, 8, 102, 13, 208, 242, 93, 44, 238, 212, 67, 94, 59, 0, 224, 13, 248, 241, 214, 25, 87, 212, 250, 247, 223, 69, 97, 178, 170, 48, 22, 195, 217, 17, 52, 9, 111, 170, 59, 244, 41, 109, 131, 14, 154, 124, 32, 158, 12, 100, 151, 81, 122, 189, 90, 138, 157, 48, 107, 207, 103, 237, 145, 249, 230, 114, 91, 71, 88, 192, 34, 224, 177, 239, 66, 117, 191, 123, 108, 91, 252, 17, 212, 95, 144, 136, 185, 65, 245, 78, 177, 229, 155, 184, 188, 57, 160, 191, 18, 48, 127, 92, 79, 219, 112, 197, 129, 178, 63, 118, 182, 58, 202, 225, 202, 166, 183, 144, 45, 82, 82, 103, 53, 72, 138, 14, 241, 60, 109, 154, 81, 191, 164, 171, 58, 216, 52, 119, 150, 82, 77, 142, 246, 161, 103, 181, 164, 24, 37, 217, 103, 225, 68, 229, 20, 5, 100, 37, 28, 202, 203, 131, 230, 180, 134, 246, 179, 202, 63, 121, 113, 80, 96, 38, 192, 184, 87, 246, 137, 150, 40, 86, 222, 212, 1, 10, 189, 11, 230, 33, 195, 163, 150, 10, 84, 231, 16, 195, 117, 242, 99, 117, 215, 1, 65, 3, 164, 181, 67, 48, 193, 152, 175, 18, 97, 22, 210, 39, 110, 17, 113, 95, 105, 56, 119, 250, 215, 239, 9, 202, 219, 9, 74, 233, 30, 26, 21, 151]),
            generator: BigUint::from_bytes_be(&[63, 179, 44, 155, 115, 19, 77, 11, 46, 119, 80, 102, 96, 237, 189, 72, 76, 167, 177, 143, 33, 239, 32, 84, 7, 244, 121, 58, 26, 11, 161, 37, 16, 219, 193, 80, 119, 190, 70, 63, 255, 79, 237, 74, 172, 11, 181, 85, 190, 58, 108, 27, 12, 107, 71, 177, 188, 55, 115, 191, 126, 140, 111, 98, 144, 18, 40, 248, 194, 140, 187, 24, 165, 90, 227, 19, 65, 0, 10, 101, 1, 150, 249, 49, 199, 122, 87, 242, 221, 244, 99, 229, 233, 236, 20, 75, 119, 125, 230, 42, 170, 184, 168, 98, 138, 195, 118, 210, 130, 214, 237, 56, 100, 230, 121, 130, 66, 142, 188, 131, 29, 20, 52, 143, 111, 47, 145, 147, 181, 4, 90, 242, 118, 113, 100, 225, 223, 201, 103, 193, 251, 63, 46, 85, 164, 189, 27, 255, 232, 59, 156, 128, 208, 82, 185, 133, 209, 130, 234, 10, 219, 42, 59, 115, 19, 211, 254, 20, 200, 72, 75, 30, 5, 37, 136, 185, 183, 210, 187, 210, 223, 1, 97, 153, 236, 208, 110, 21, 87, 205, 9, 21, 179, 53, 59, 187, 100, 224, 236, 55, 127, 208, 40, 55, 13, 249, 43, 82, 199, 137, 20, 40, 205, 198, 126, 182, 24, 75, 82, 61, 29, 178, 70, 195, 47, 99, 7, 132, 144, 240, 14, 248, 214, 71, 209, 72, 212, 121, 84, 81, 94, 35, 39, 207, 239, 152, 197, 130, 102, 75, 76, 15, 108, 196, 22, 89]),
            public_key: BigUint::from_bytes_be(&[45, 48, 255, 175, 224, 178, 34, 113, 55, 121, 103, 94, 57, 230, 149, 227, 2, 8, 211, 56, 135, 63, 75, 228, 67, 79, 182, 168, 130, 79, 28, 56, 65, 78, 255, 48, 67, 5, 243, 1, 170, 131, 242, 24, 216, 174, 93, 89, 249, 12, 215, 25, 248, 12, 146, 191, 38, 9, 239, 136, 197, 113, 125, 222, 79, 184, 149, 180, 198, 185, 10, 161, 28, 53, 69, 19, 173, 197, 112, 73, 23, 172, 239, 88, 66, 170, 206, 185, 238, 228, 152, 153, 163, 198, 94, 147, 212, 117, 120, 83, 30, 158, 8, 70, 1, 73, 134, 237, 77, 162, 147, 56, 224, 231, 179, 30, 110, 19, 55, 253, 176, 115, 101, 171, 146, 59, 227, 37, 145, 200, 156, 20, 33, 186, 8, 34, 118, 162, 125, 114, 229, 11, 202, 36, 115, 124, 83, 60, 251, 141, 83, 244, 164, 213, 197, 199, 2, 130, 173, 22, 120, 61, 63, 196, 111, 60, 184, 58, 17, 34, 166, 237, 250, 238, 19, 150, 192, 123, 172, 162, 70, 227, 90, 165, 58, 139, 124, 87, 199, 135, 30, 146, 142, 203, 133, 133, 54, 26, 54, 229, 134, 122, 117, 207, 31, 184, 148, 68, 232, 89, 132, 91, 246, 40, 87, 225, 14, 74, 23, 81, 228, 241, 146, 171, 106, 211, 196, 222, 192, 142, 81, 207, 169, 185, 24, 161, 88, 75, 138, 97, 111, 92, 43, 214, 190, 140, 12, 124, 177, 67, 125, 237, 147, 195, 41, 40]),
        },
        [68, 72, 80, 66, 0, 1, 0, 0, 135, 168, 230, 29, 180, 182, 102, 60, 255, 187, 209, 156, 101, 25, 89, 153, 140, 238, 246, 8, 102, 13, 208, 242, 93, 44, 238, 212, 67, 94, 59, 0, 224, 13, 248, 241, 214, 25, 87, 212, 250, 247, 223, 69, 97, 178, 170, 48, 22, 195, 217, 17, 52, 9, 111, 170, 59, 244, 41, 109, 131, 14, 154, 124, 32, 158, 12, 100, 151, 81, 122, 189, 90, 138, 157, 48, 107, 207, 103, 237, 145, 249, 230, 114, 91, 71, 88, 192, 34, 224, 177, 239, 66, 117, 191, 123, 108, 91, 252, 17, 212, 95, 144, 136, 185, 65, 245, 78, 177, 229, 155, 184, 188, 57, 160, 191, 18, 48, 127, 92, 79, 219, 112, 197, 129, 178, 63, 118, 182, 58, 202, 225, 202, 166, 183, 144, 45, 82, 82, 103, 53, 72, 138, 14, 241, 60, 109, 154, 81, 191, 164, 171, 58, 216, 52, 119, 150, 82, 77, 142, 246, 161, 103, 181, 164, 24, 37, 217, 103, 225, 68, 229, 20, 5, 100, 37, 28, 202, 203, 131, 230, 180, 134, 246, 179, 202, 63, 121, 113, 80, 96, 38, 192, 184, 87, 246, 137, 150, 40, 86, 222, 212, 1, 10, 189, 11, 230, 33, 195, 163, 150, 10, 84, 231, 16, 195, 117, 242, 99, 117, 215, 1, 65, 3, 164, 181, 67, 48, 193, 152, 175, 18, 97, 22, 210, 39, 110, 17, 113, 95, 105, 56, 119, 250, 215, 239, 9, 202, 219, 9, 74, 233, 30, 26, 21, 151, 63, 179, 44, 155, 115, 19, 77, 11, 46, 119, 80, 102, 96, 237, 189, 72, 76, 167, 177, 143, 33, 239, 32, 84, 7, 244, 121, 58, 26, 11, 161, 37, 16, 219, 193, 80, 119, 190, 70, 63, 255, 79, 237, 74, 172, 11, 181, 85, 190, 58, 108, 27, 12, 107, 71, 177, 188, 55, 115, 191, 126, 140, 111, 98, 144, 18, 40, 248, 194, 140, 187, 24, 165, 90, 227, 19, 65, 0, 10, 101, 1, 150, 249, 49, 199, 122, 87, 242, 221, 244, 99, 229, 233, 236, 20, 75, 119, 125, 230, 42, 170, 184, 168, 98, 138, 195, 118, 210, 130, 214, 237, 56, 100, 230, 121, 130, 66, 142, 188, 131, 29, 20, 52, 143, 111, 47, 145, 147, 181, 4, 90, 242, 118, 113, 100, 225, 223, 201, 103, 193, 251, 63, 46, 85, 164, 189, 27, 255, 232, 59, 156, 128, 208, 82, 185, 133, 209, 130, 234, 10, 219, 42, 59, 115, 19, 211, 254, 20, 200, 72, 75, 30, 5, 37, 136, 185, 183, 210, 187, 210, 223, 1, 97, 153, 236, 208, 110, 21, 87, 205, 9, 21, 179, 53, 59, 187, 100, 224, 236, 55, 127, 208, 40, 55, 13, 249, 43, 82, 199, 137, 20, 40, 205, 198, 126, 182, 24, 75, 82, 61, 29, 178, 70, 195, 47, 99, 7, 132, 144, 240, 14, 248, 214, 71, 209, 72, 212, 121, 84, 81, 94, 35, 39, 207, 239, 152, 197, 130, 102, 75, 76, 15, 108, 196, 22, 89, 45, 48, 255, 175, 224, 178, 34, 113, 55, 121, 103, 94, 57, 230, 149, 227, 2, 8, 211, 56, 135, 63, 75, 228, 67, 79, 182, 168, 130, 79, 28, 56, 65, 78, 255, 48, 67, 5, 243, 1, 170, 131, 242, 24, 216, 174, 93, 89, 249, 12, 215, 25, 248, 12, 146, 191, 38, 9, 239, 136, 197, 113, 125, 222, 79, 184, 149, 180, 198, 185, 10, 161, 28, 53, 69, 19, 173, 197, 112, 73, 23, 172, 239, 88, 66, 170, 206, 185, 238, 228, 152, 153, 163, 198, 94, 147, 212, 117, 120, 83, 30, 158, 8, 70, 1, 73, 134, 237, 77, 162, 147, 56, 224, 231, 179, 30, 110, 19, 55, 253, 176, 115, 101, 171, 146, 59, 227, 37, 145, 200, 156, 20, 33, 186, 8, 34, 118, 162, 125, 114, 229, 11, 202, 36, 115, 124, 83, 60, 251, 141, 83, 244, 164, 213, 197, 199, 2, 130, 173, 22, 120, 61, 63, 196, 111, 60, 184, 58, 17, 34, 166, 237, 250, 238, 19, 150, 192, 123, 172, 162, 70, 227, 90, 165, 58, 139, 124, 87, 199, 135, 30, 146, 142, 203, 133, 133, 54, 26, 54, 229, 134, 122, 117, 207, 31, 184, 148, 68, 232, 89, 132, 91, 246, 40, 87, 225, 14, 74, 23, 81, 228, 241, 146, 171, 106, 211, 196, 222, 192, 142, 81, 207, 169, 185, 24, 161, 88, 75, 138, 97, 111, 92, 43, 214, 190, 140, 12, 124, 177, 67, 125, 237, 147, 195, 41, 40]
    }
}
