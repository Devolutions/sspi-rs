use std::fmt;
use std::io::{Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_bigint_dig::BigUint;
use uuid::Uuid;

use crate::rpc::{read_buf, read_c_str_utf16_le, read_padding, read_uuid, write_padding, Decode, Encode};
use crate::utils::{encode_utf16_le, utf16_bytes_to_utf8_string};
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

        if let Some(root_key_id) = self.root_key_id.as_ref() {
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
        let encoded_hash_alg = encode_utf16_le(&self.hash_alg.to_string());

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EllipticCurve {
    P256,
    P384,
    P521,
}

impl From<EllipticCurve> for &[u8] {
    fn from(curve: EllipticCurve) -> Self {
        match curve {
            EllipticCurve::P256 => b"ECK1",
            EllipticCurve::P384 => b"ECK3",
            EllipticCurve::P521 => b"ECK5",
        }
    }
}

impl TryFrom<&[u8]> for EllipticCurve {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value {
            b"ECK1" => Ok(EllipticCurve::P256),
            b"ECK3" => Ok(EllipticCurve::P384),
            b"ECK5" => Ok(EllipticCurve::P521),
            _ => Err(Error::new(ErrorKind::NteInvalidParameter, "invalid elliptic curve")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdhKey {
    pub curve: EllipticCurve,
    pub key_length: u32,
    pub x: BigUint,
    pub y: BigUint,
}

impl Encode for EcdhKey {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        // TODO
        writer.write(self.curve.into())?;

        writer.write_u32::<LittleEndian>(self.key_length)?;

        let key_len: usize = self.key_length.try_into()?;

        let mut x = self.x.to_bytes_be();
        while x.len() < key_len {
            x.insert(0, 0);
        }
        // TODO
        writer.write(&x)?;

        let mut y = self.y.to_bytes_be();
        while y.len() < key_len {
            y.insert(0, 0);
        }
        // TODO
        writer.write(&y)?;

        Ok(())
    }
}

impl Decode for EcdhKey {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let mut buf = [0; 4];
        reader.read_exact(&mut buf)?;
        let curve = EllipticCurve::try_from(buf.as_ref())?;

        let key_length = reader.read_u32::<LittleEndian>()?;

        let mut x = vec![0; key_length.try_into()?];
        // TODO
        reader.read_exact(&mut x)?;
        let x = BigUint::from_bytes_be(&x);

        let mut y = vec![0; key_length.try_into()?];
        // TODO
        reader.read_exact(&mut y)?;
        println!("{:?}", y);
        let y = BigUint::from_bytes_be(&y);
        println!("y: {y}");

        Ok(Self {
            curve,
            key_length,
            x,
            y,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupKeyEnvelope {
    pub flags: u32,
    pub l0: u32,
    pub l1: u32,
    pub l2: u32,
    pub root_key_identifier: Uuid,
    pub kdf_alg: String,
    pub kdf_parameters: Vec<u8>,
    pub secret_algorithm: String,
    pub secret_parameters: Vec<u8>,
    pub private_key_length: u32,
    pub public_key_length: u32,
    pub domain_name: String,
    pub forest_name: String,
    pub l1_key: Vec<u8>,
    pub l2_key: Vec<u8>,
}

impl GroupKeyEnvelope {
    const MAGIC: &[u8] = &[0x4B, 0x44, 0x53, 0x4B];
}

impl Encode for GroupKeyEnvelope {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        // version is always 1
        writer.write_u32::<LittleEndian>(1)?;

        // TODO
        writer.write(GroupKeyEnvelope::MAGIC)?;
        writer.write_u32::<LittleEndian>(self.flags)?;
        writer.write_u32::<LittleEndian>(self.l0)?;
        writer.write_u32::<LittleEndian>(self.l1)?;
        writer.write_u32::<LittleEndian>(self.l2)?;
        writer.write(&self.root_key_identifier.to_bytes_le())?;

        let encoded_kdf_alg = encode_utf16_le(&self.kdf_alg);
        let encoded_secret_alg = encode_utf16_le(&self.secret_algorithm);
        let encoded_domain_name = encode_utf16_le(&self.domain_name);
        let encoded_forest_name = encode_utf16_le(&self.forest_name);

        writer.write_u32::<LittleEndian>(encoded_kdf_alg.len().try_into()?)?;
        writer.write_u32::<LittleEndian>(self.kdf_parameters.len().try_into()?)?;
        writer.write_u32::<LittleEndian>(encoded_secret_alg.len().try_into()?)?;
        writer.write_u32::<LittleEndian>(self.secret_parameters.len().try_into()?)?;
        writer.write_u32::<LittleEndian>(self.private_key_length)?;
        writer.write_u32::<LittleEndian>(self.public_key_length)?;
        writer.write_u32::<LittleEndian>(self.l1_key.len().try_into()?)?;
        writer.write_u32::<LittleEndian>(self.l2_key.len().try_into()?)?;
        writer.write_u32::<LittleEndian>(encoded_domain_name.len().try_into()?)?;
        writer.write_u32::<LittleEndian>(encoded_forest_name.len().try_into()?)?;
        // TODO
        writer.write(&encoded_kdf_alg)?;
        writer.write(&self.kdf_parameters)?;
        writer.write(&encoded_secret_alg)?;
        writer.write(&self.secret_parameters)?;
        writer.write(&encoded_domain_name)?;
        writer.write(&encoded_forest_name)?;
        writer.write(&self.l1_key)?;
        writer.write(&self.l2_key)?;

        Ok(())
    }
}

impl Decode for GroupKeyEnvelope {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let version = reader.read_u32::<LittleEndian>()?;

        if version != 1 {
            return Err(Error::new(
                ErrorKind::NteInvalidParameter,
                "invalid GroupKeyEnvelope version",
            ));
        }

        let mut buf = [0; 4];
        // TODO
        reader.read_exact(&mut buf)?;

        if buf != GroupKeyEnvelope::MAGIC {
            return Err(Error::new(
                ErrorKind::NteInvalidParameter,
                "invalid GroupKeyEnvelope magic",
            ));
        }

        let flags = reader.read_u32::<LittleEndian>()?;
        let l0 = reader.read_u32::<LittleEndian>()?;
        let l1 = reader.read_u32::<LittleEndian>()?;
        let l2 = reader.read_u32::<LittleEndian>()?;
        let root_key_identifier = read_uuid(&mut reader)?;

        let kdf_alg_len = reader.read_u32::<LittleEndian>()?;
        let kdf_parameters_len = reader.read_u32::<LittleEndian>()?;
        let secret_alg_len = reader.read_u32::<LittleEndian>()?;
        let secret_parameters_len = reader.read_u32::<LittleEndian>()?;
        let private_key_length = reader.read_u32::<LittleEndian>()?;
        let public_key_length = reader.read_u32::<LittleEndian>()?;
        let l1_key_len = reader.read_u32::<LittleEndian>()?;
        let l2_key_len = reader.read_u32::<LittleEndian>()?;
        let domain_len = reader.read_u32::<LittleEndian>()?;
        let forest_len = reader.read_u32::<LittleEndian>()?;

        let kdf_alg = read_c_str_utf16_le(kdf_alg_len.try_into()?, &mut reader)?;
        let kdf_parameters = read_buf(kdf_parameters_len.try_into()?, &mut reader)?;

        let secret_algorithm = read_c_str_utf16_le(secret_alg_len.try_into()?, &mut reader)?;
        let secret_parameters = read_buf(secret_parameters_len.try_into()?, &mut reader)?;

        let domain_name = read_c_str_utf16_le(domain_len.try_into()?, &mut reader)?;
        let forest_name = read_c_str_utf16_le(forest_len.try_into()?, &mut reader)?;

        let l1_key = read_buf(l1_key_len.try_into()?, &mut reader)?;
        let l2_key = read_buf(l2_key_len.try_into()?, &mut reader)?;

        Ok(Self {
            flags,
            l0,
            l1,
            l2,
            root_key_identifier,
            kdf_alg,
            kdf_parameters,
            secret_algorithm,
            secret_parameters,
            private_key_length,
            public_key_length,
            domain_name,
            forest_name,
            l1_key,
            l2_key,
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

    test_encoding_decoding! {
        ecdh_key,
        EcdhKey,
        EcdhKey {
            curve: EllipticCurve::P256,
            key_length: 32,
            x: BigUint::from_bytes_be(&[55, 207, 128, 106, 197, 198, 140, 63, 65, 0, 159, 14, 21, 210, 20, 185, 6, 206, 148, 114, 80, 216, 60, 7, 162, 43, 89, 58, 4, 185, 244, 146]),
            y: BigUint::from_bytes_be(&[12, 96, 47, 29, 213, 226, 140, 169, 155, 108, 148, 93, 27, 55, 236, 228, 100, 7, 103, 201, 181, 118, 34, 92, 72, 181, 88, 110, 92, 34, 255, 192]),
        },
        [69, 67, 75, 49, 32, 0, 0, 0, 55, 207, 128, 106, 197, 198, 140, 63, 65, 0, 159, 14, 21, 210, 20, 185, 6, 206, 148, 114, 80, 216, 60, 7, 162, 43, 89, 58, 4, 185, 244, 146, 12, 96, 47, 29, 213, 226, 140, 169, 155, 108, 148, 93, 27, 55, 236, 228, 100, 7, 103, 201, 181, 118, 34, 92, 72, 181, 88, 110, 92, 34, 255, 192]
    }

    test_encoding_decoding! {
        group_key_envelope,
        GroupKeyEnvelope,
        GroupKeyEnvelope {
            flags: 2,
            l0: 361,
            l1: 17,
            l2: 8,
            root_key_identifier: Uuid::from_str("d778c271-9025-9a82-f6dc-b8960b8ad8c5").unwrap(),
            kdf_alg: "SP800_108_CTR_HMAC".into(),
            kdf_parameters: vec![0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53, 0x00, 0x48, 0x00, 0x41, 0x00, 0x35, 0x00, 0x31, 0x00, 0x32, 0x00, 0x00, 0x00],
            secret_algorithm: "DH".into(),
            secret_parameters: vec![12, 2, 0, 0, 68, 72, 80, 77, 0, 1, 0, 0, 135, 168, 230, 29, 180, 182, 102, 60, 255, 187, 209, 156, 101, 25, 89, 153, 140, 238, 246, 8, 102, 13, 208, 242, 93, 44, 238, 212, 67, 94, 59, 0, 224, 13, 248, 241, 214, 25, 87, 212, 250, 247, 223, 69, 97, 178, 170, 48, 22, 195, 217, 17, 52, 9, 111, 170, 59, 244, 41, 109, 131, 14, 154, 124, 32, 158, 12, 100, 151, 81, 122, 189, 90, 138, 157, 48, 107, 207, 103, 237, 145, 249, 230, 114, 91, 71, 88, 192, 34, 224, 177, 239, 66, 117, 191, 123, 108, 91, 252, 17, 212, 95, 144, 136, 185, 65, 245, 78, 177, 229, 155, 184, 188, 57, 160, 191, 18, 48, 127, 92, 79, 219, 112, 197, 129, 178, 63, 118, 182, 58, 202, 225, 202, 166, 183, 144, 45, 82, 82, 103, 53, 72, 138, 14, 241, 60, 109, 154, 81, 191, 164, 171, 58, 216, 52, 119, 150, 82, 77, 142, 246, 161, 103, 181, 164, 24, 37, 217, 103, 225, 68, 229, 20, 5, 100, 37, 28, 202, 203, 131, 230, 180, 134, 246, 179, 202, 63, 121, 113, 80, 96, 38, 192, 184, 87, 246, 137, 150, 40, 86, 222, 212, 1, 10, 189, 11, 230, 33, 195, 163, 150, 10, 84, 231, 16, 195, 117, 242, 99, 117, 215, 1, 65, 3, 164, 181, 67, 48, 193, 152, 175, 18, 97, 22, 210, 39, 110, 17, 113, 95, 105, 56, 119, 250, 215, 239, 9, 202, 219, 9, 74, 233, 30, 26, 21, 151, 63, 179, 44, 155, 115, 19, 77, 11, 46, 119, 80, 102, 96, 237, 189, 72, 76, 167, 177, 143, 33, 239, 32, 84, 7, 244, 121, 58, 26, 11, 161, 37, 16, 219, 193, 80, 119, 190, 70, 63, 255, 79, 237, 74, 172, 11, 181, 85, 190, 58, 108, 27, 12, 107, 71, 177, 188, 55, 115, 191, 126, 140, 111, 98, 144, 18, 40, 248, 194, 140, 187, 24, 165, 90, 227, 19, 65, 0, 10, 101, 1, 150, 249, 49, 199, 122, 87, 242, 221, 244, 99, 229, 233, 236, 20, 75, 119, 125, 230, 42, 170, 184, 168, 98, 138, 195, 118, 210, 130, 214, 237, 56, 100, 230, 121, 130, 66, 142, 188, 131, 29, 20, 52, 143, 111, 47, 145, 147, 181, 4, 90, 242, 118, 113, 100, 225, 223, 201, 103, 193, 251, 63, 46, 85, 164, 189, 27, 255, 232, 59, 156, 128, 208, 82, 185, 133, 209, 130, 234, 10, 219, 42, 59, 115, 19, 211, 254, 20, 200, 72, 75, 30, 5, 37, 136, 185, 183, 210, 187, 210, 223, 1, 97, 153, 236, 208, 110, 21, 87, 205, 9, 21, 179, 53, 59, 187, 100, 224, 236, 55, 127, 208, 40, 55, 13, 249, 43, 82, 199, 137, 20, 40, 205, 198, 126, 182, 24, 75, 82, 61, 29, 178, 70, 195, 47, 99, 7, 132, 144, 240, 14, 248, 214, 71, 209, 72, 212, 121, 84, 81, 94, 35, 39, 207, 239, 152, 197, 130, 102, 75, 76, 15, 108, 196, 22, 89],
            private_key_length: 512,
            public_key_length: 2048,
            domain_name: "domain.test".into(),
            forest_name: "domain.test".into(),
            l1_key: vec![0x9C, 0x8F, 0x03, 0x85, 0xD7, 0x46, 0x06, 0x2A, 0xFB, 0x90, 0xBA, 0x9D, 0x02, 0x3A, 0x3A, 0x5C, 0x24, 0x2E, 0xB5, 0x33, 0x43, 0x41, 0xBE, 0xFA, 0xDC, 0x49, 0xE2, 0x7A, 0x90, 0x8F, 0xC3, 0x39, 0x3B, 0xAC, 0x40, 0x14, 0x56, 0xA8, 0x65, 0x61, 0x04, 0xC8, 0x72, 0xD0, 0xC9, 0x96, 0xAA, 0x25, 0x9A, 0x95, 0x4B, 0xF5, 0xA3, 0x8B, 0x8D, 0x6E, 0xC7, 0xCD, 0xBA, 0xC1, 0x35, 0x9E, 0x5A, 0x09],
            l2_key: vec![0x1B, 0xAC, 0x68, 0xA1, 0xA7, 0xC8, 0xB9, 0xAC, 0x94, 0x4C, 0x8E, 0xB1, 0xEA, 0x39, 0x6C, 0xC3, 0x66, 0x68, 0x5E, 0x17, 0xA4, 0x11, 0x0A, 0x1F, 0xB5, 0x5E, 0x7C, 0x44, 0x11, 0xA6, 0xFA, 0xA5, 0x8F, 0x8E, 0x5B, 0xE1, 0x25, 0x24, 0xFA, 0xBB, 0xC3, 0x44, 0xC5, 0x9B, 0xEA, 0xF9, 0xB3, 0xEC, 0xE2, 0x18, 0xEA, 0x8E, 0x4F, 0x81, 0x1B, 0x6C, 0xAF, 0xEA, 0x4B, 0x77, 0xE7, 0xEF, 0x0A, 0xED],
        },
        [1, 0, 0, 0, 75, 68, 83, 75, 2, 0, 0, 0, 105, 1, 0, 0, 17, 0, 0, 0, 8, 0, 0, 0, 113, 194, 120, 215, 37, 144, 130, 154, 246, 220, 184, 150, 11, 138, 216, 197, 38, 0, 0, 0, 30, 0, 0, 0, 6, 0, 0, 0, 12, 2, 0, 0, 0, 2, 0, 0, 0, 8, 0, 0, 64, 0, 0, 0, 64, 0, 0, 0, 24, 0, 0, 0, 24, 0, 0, 0, 83, 0, 80, 0, 56, 0, 48, 0, 48, 0, 95, 0, 49, 0, 48, 0, 56, 0, 95, 0, 67, 0, 84, 0, 82, 0, 95, 0, 72, 0, 77, 0, 65, 0, 67, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 83, 0, 72, 0, 65, 0, 53, 0, 49, 0, 50, 0, 0, 0, 68, 0, 72, 0, 0, 0, 12, 2, 0, 0, 68, 72, 80, 77, 0, 1, 0, 0, 135, 168, 230, 29, 180, 182, 102, 60, 255, 187, 209, 156, 101, 25, 89, 153, 140, 238, 246, 8, 102, 13, 208, 242, 93, 44, 238, 212, 67, 94, 59, 0, 224, 13, 248, 241, 214, 25, 87, 212, 250, 247, 223, 69, 97, 178, 170, 48, 22, 195, 217, 17, 52, 9, 111, 170, 59, 244, 41, 109, 131, 14, 154, 124, 32, 158, 12, 100, 151, 81, 122, 189, 90, 138, 157, 48, 107, 207, 103, 237, 145, 249, 230, 114, 91, 71, 88, 192, 34, 224, 177, 239, 66, 117, 191, 123, 108, 91, 252, 17, 212, 95, 144, 136, 185, 65, 245, 78, 177, 229, 155, 184, 188, 57, 160, 191, 18, 48, 127, 92, 79, 219, 112, 197, 129, 178, 63, 118, 182, 58, 202, 225, 202, 166, 183, 144, 45, 82, 82, 103, 53, 72, 138, 14, 241, 60, 109, 154, 81, 191, 164, 171, 58, 216, 52, 119, 150, 82, 77, 142, 246, 161, 103, 181, 164, 24, 37, 217, 103, 225, 68, 229, 20, 5, 100, 37, 28, 202, 203, 131, 230, 180, 134, 246, 179, 202, 63, 121, 113, 80, 96, 38, 192, 184, 87, 246, 137, 150, 40, 86, 222, 212, 1, 10, 189, 11, 230, 33, 195, 163, 150, 10, 84, 231, 16, 195, 117, 242, 99, 117, 215, 1, 65, 3, 164, 181, 67, 48, 193, 152, 175, 18, 97, 22, 210, 39, 110, 17, 113, 95, 105, 56, 119, 250, 215, 239, 9, 202, 219, 9, 74, 233, 30, 26, 21, 151, 63, 179, 44, 155, 115, 19, 77, 11, 46, 119, 80, 102, 96, 237, 189, 72, 76, 167, 177, 143, 33, 239, 32, 84, 7, 244, 121, 58, 26, 11, 161, 37, 16, 219, 193, 80, 119, 190, 70, 63, 255, 79, 237, 74, 172, 11, 181, 85, 190, 58, 108, 27, 12, 107, 71, 177, 188, 55, 115, 191, 126, 140, 111, 98, 144, 18, 40, 248, 194, 140, 187, 24, 165, 90, 227, 19, 65, 0, 10, 101, 1, 150, 249, 49, 199, 122, 87, 242, 221, 244, 99, 229, 233, 236, 20, 75, 119, 125, 230, 42, 170, 184, 168, 98, 138, 195, 118, 210, 130, 214, 237, 56, 100, 230, 121, 130, 66, 142, 188, 131, 29, 20, 52, 143, 111, 47, 145, 147, 181, 4, 90, 242, 118, 113, 100, 225, 223, 201, 103, 193, 251, 63, 46, 85, 164, 189, 27, 255, 232, 59, 156, 128, 208, 82, 185, 133, 209, 130, 234, 10, 219, 42, 59, 115, 19, 211, 254, 20, 200, 72, 75, 30, 5, 37, 136, 185, 183, 210, 187, 210, 223, 1, 97, 153, 236, 208, 110, 21, 87, 205, 9, 21, 179, 53, 59, 187, 100, 224, 236, 55, 127, 208, 40, 55, 13, 249, 43, 82, 199, 137, 20, 40, 205, 198, 126, 182, 24, 75, 82, 61, 29, 178, 70, 195, 47, 99, 7, 132, 144, 240, 14, 248, 214, 71, 209, 72, 212, 121, 84, 81, 94, 35, 39, 207, 239, 152, 197, 130, 102, 75, 76, 15, 108, 196, 22, 89, 100, 0, 111, 0, 109, 0, 97, 0, 105, 0, 110, 0, 46, 0, 116, 0, 101, 0, 115, 0, 116, 0, 0, 0, 100, 0, 111, 0, 109, 0, 97, 0, 105, 0, 110, 0, 46, 0, 116, 0, 101, 0, 115, 0, 116, 0, 0, 0, 156, 143, 3, 133, 215, 70, 6, 42, 251, 144, 186, 157, 2, 58, 58, 92, 36, 46, 181, 51, 67, 65, 190, 250, 220, 73, 226, 122, 144, 143, 195, 57, 59, 172, 64, 20, 86, 168, 101, 97, 4, 200, 114, 208, 201, 150, 170, 37, 154, 149, 75, 245, 163, 139, 141, 110, 199, 205, 186, 193, 53, 158, 90, 9, 27, 172, 104, 161, 167, 200, 185, 172, 148, 76, 142, 177, 234, 57, 108, 195, 102, 104, 94, 23, 164, 17, 10, 31, 181, 94, 124, 68, 17, 166, 250, 165, 143, 142, 91, 225, 37, 36, 250, 187, 195, 68, 197, 155, 234, 249, 179, 236, 226, 24, 234, 142, 79, 129, 27, 108, 175, 234, 75, 119, 231, 239, 10, 237]
    }
}
