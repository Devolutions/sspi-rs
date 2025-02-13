use std::fmt;
use std::io::{Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_bigint_dig::BigUint;
use rand::rngs::OsRng;
use rand::Rng;
use thiserror::Error;
use uuid::{uuid, Uuid};

use crate::blob::KeyIdentifier;
use crate::crypto::{
    compute_kek, compute_kek_from_public_key, compute_l2_key, compute_public_key, kdf, KDS_SERVICE_LABEL,
};
use crate::rpc::bind::SyntaxId;
use crate::rpc::{read_buf, read_c_str_utf16_le, read_padding, read_vec, write_buf, write_padding, Decode, Encode};
use crate::str::{encode_utf16_le, from_utf16_le};
use crate::{Error, Result};

pub const ISD_KEY: SyntaxId = SyntaxId {
    uuid: uuid!("b9785960-524f-11df-8b6d-83dcded72085"),
    version: 1,
    version_minor: 0,
};

#[derive(Debug, Error)]
pub enum GkdiError {
    #[error("invalid hash algorithm name: {0}")]
    InvalidHashName(String),

    #[error("invalid {name} version: expected {expected} but got {actual}")]
    InvalidVersion {
        name: &'static str,
        expected: u32,
        actual: u32,
    },

    #[error("invalid elliptic curve id")]
    InvalidEllipticCurveId(Vec<u8>),

    #[error("invalid kdf algorithm name: expected {expected} but got {actual}")]
    InvalidKdfAlgName { expected: &'static str, actual: String },

    #[error("current user is not authorized to retrieve the KEK information")]
    IsNotAuthorized,

    #[error("l0 index does not match requested l0 index")]
    InvalidL0Index,
}

pub type GkdiResult<T> = std::result::Result<T, GkdiError>;

const KDF_ALGORITHM_NAME: &str = "SP800_108_CTR_HMAC";

/// GetKey RPC Request
///
/// This can be used to build the stub data for the GetKey RPC request.
/// The syntax for this function is defined in []`MS-GKDI 3.1.4.1 GetKey (Opnum 0)`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/4cac87a3-521e-4918-a272-240f8fabed39)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetKey {
    /// The the security descriptor for which the group key is being requested.
    pub target_sd: Vec<u8>,
    /// This parameter represents the root key identifier of the requested key. It can be set to NULL.
    pub root_key_id: Option<Uuid>,
    /// This parameter represents the L0 index of the requested group key.
    /// It MUST be a signed 32-bit integer greater than or equal to -1.
    pub l0_key_id: i32,
    /// This parameter represents the L1 index of the requested group key.
    /// It MUST be a signed 32-bit integer between -1 and 31 (inclusive).
    pub l1_key_id: i32,
    /// This parameter represents the L2 index of the requested group key.
    /// It MUST be a 32-bit integer between -1 and 31 (inclusive).
    pub l2_key_id: i32,
}

impl Encode for GetKey {
    fn encode(&self, mut writer: impl Write) -> Result<()> {
        let target_sd_len = self.target_sd.len().try_into()?;
        // cbTargetSD
        writer.write_u64::<LittleEndian>(target_sd_len)?;
        // pbTargetSD - pointer header includes the length + padding
        writer.write_u64::<LittleEndian>(target_sd_len)?;

        write_buf(&self.target_sd, &mut writer)?;

        write_padding::<8>(target_sd_len.try_into()?, &mut writer)?;

        if let Some(root_key_id) = self.root_key_id.as_ref() {
            write_buf(&[0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00], &mut writer)?;
            write_buf(root_key_id.to_bytes_le().as_ref(), &mut writer)?;
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
    fn decode(mut reader: impl Read) -> Result<Self> {
        let target_sd_len = reader.read_u64::<LittleEndian>()?;
        let _offset = reader.read_u64::<LittleEndian>()?;

        let target_sd = read_vec(target_sd_len.try_into()?, &mut reader)?;

        read_padding::<8>(target_sd_len.try_into()?, &mut reader)?;

        let root_key_id = if reader.read_u64::<LittleEndian>()? != 0 {
            Some(Uuid::decode(&mut reader)?)
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

/// Supported hash algorithms.
///
/// It contains hash algorithms that are listed in the documentation:
/// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/9946aeff-a914-45e9-b9e5-6cb5b4059187
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    type Error = GkdiError;

    fn try_from(data: &str) -> GkdiResult<Self> {
        match data {
            "SHA1" => Ok(HashAlg::Sha1),
            "SHA256" => Ok(HashAlg::Sha256),
            "SHA384" => Ok(HashAlg::Sha384),
            "SHA512" => Ok(HashAlg::Sha512),
            _ => Err(GkdiError::InvalidHashName(data.to_owned())),
        }
    }
}

/// [KDF Parameters](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/9946aeff-a914-45e9-b9e5-6cb5b4059187)
///
/// The following specifies the format and field descriptions for the key derivation function (KDF) parameters structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParameters {
    pub hash_alg: HashAlg,
}

impl KdfParameters {
    // The following magic identifiers are specified in the Microsoft documentation:
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/9946aeff-a914-45e9-b9e5-6cb5b4059187
    const MAGIC_IDENTIFIER_1: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
    const MAGIC_IDENTIFIER_2: &[u8] = &[0x00, 0x00, 0x00, 0x00];
}

impl Encode for KdfParameters {
    fn encode(&self, mut writer: impl Write) -> Result<()> {
        let encoded_hash_alg = encode_utf16_le(&self.hash_alg.to_string());

        write_buf(KdfParameters::MAGIC_IDENTIFIER_1, &mut writer)?;
        writer.write_u32::<LittleEndian>(encoded_hash_alg.len().try_into()?)?;
        write_buf(KdfParameters::MAGIC_IDENTIFIER_2, &mut writer)?;
        write_buf(&encoded_hash_alg, &mut writer)?;

        Ok(())
    }
}

impl Decode for KdfParameters {
    fn decode(mut reader: impl Read) -> Result<Self> {
        let mut magic_identifier_1 = [0; 8];
        read_buf(&mut reader, &mut magic_identifier_1)?;

        if magic_identifier_1 != Self::MAGIC_IDENTIFIER_1 {
            return Err(Error::InvalidMagic {
                name: "KdfParameters::MAGIC_IDENTIFIER_1",
                expected: Self::MAGIC_IDENTIFIER_1,
                actual: magic_identifier_1.to_vec(),
            });
        }

        let hash_name_len: usize = reader.read_u32::<LittleEndian>()?.try_into()?;

        let mut magic_identifier_2 = [0; 4];
        read_buf(&mut reader, &mut magic_identifier_2)?;

        if magic_identifier_2 != Self::MAGIC_IDENTIFIER_2 {
            return Err(Error::InvalidMagic {
                name: "KdfParameters::MAGIC_IDENTIFIER_1",
                expected: Self::MAGIC_IDENTIFIER_2,
                actual: magic_identifier_2.to_vec(),
            });
        }

        // The smallest possible hash algorithm name is "SHA1\0", 10 bytes long in UTF-16 encoding.
        if hash_name_len < 10 {
            Err(Error::InvalidLength {
                name: "KdfParameters hash id",
                expected: 10,
                actual: hash_name_len,
            })?;
        }

        let buf = read_vec(hash_name_len - 2 /* UTF-16 null terminator char */, &mut reader)?;
        // Skip UTF-16 null terminator char.
        reader.read_u16::<LittleEndian>()?;

        Ok(Self {
            hash_alg: from_utf16_le(&buf)?.as_str().try_into()?,
        })
    }
}

/// [FFC DH Parameters](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/e15ae269-ee21-446a-a480-de3ea243db5f)
///
/// This structure specifies field parameters for use in deriving finite field cryptography (FFC) Diffie-Hellman (DH)
/// ([SP800-56A](https://csrc.nist.gov/pubs/sp/800/56/a/r1/final) section 5.7.1) keys,
/// as specified in section [3.1.4.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/5d373568-dd68-499b-bd06-a3ce16ca7117).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfcdhParameters {
    /// A 32-bit unsigned integer. This field MUST be the length, in bytes, of the public key.
    /// This field is encoded using little-endian format.
    pub key_length: u32,
    /// This is the large prime field order, and is a domain parameter for the FFC DH algorithm ([SP800-56A] section 5.7.1).
    /// It MUST be encoded in big-endian format. The length of this field, in bytes,
    /// MUST be equal to the value of the Key length field.
    pub field_order: BigUint,
    /// The generator of the subgroup, a domain parameter for the FFC DH algorithm ([SP800-56A] section 5.7.1).
    /// It MUST be encoded in big-endian format. The length of this field, in bytes,
    /// MUST be equal to the value of the Key length field.
    pub generator: BigUint,
}

impl FfcdhParameters {
    // The following magic value is defined in the Microsoft documentation:
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/e15ae269-ee21-446a-a480-de3ea243db5f
    const MAGIC: &[u8] = &[0x44, 0x48, 0x50, 0x4d];
}

impl Encode for FfcdhParameters {
    fn encode(&self, mut writer: impl Write) -> Result<()> {
        // Calculate total structure length and write it.
        //
        // Length (4 bytes):  A 32-bit unsigned integer. This field MUST be the length, in bytes, of the entire structure. This field is encoded using little-endian format:
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/e15ae269-ee21-446a-a480-de3ea243db5f
        writer.write_u32::<LittleEndian>(12 + self.key_length * 2)?;

        write_buf(FfcdhParameters::MAGIC, &mut writer)?;
        writer.write_u32::<LittleEndian>(self.key_length)?;

        let key_len = self.key_length.try_into()?;

        let mut field_order = self.field_order.to_bytes_be();
        field_order.resize(key_len, 0);
        write_buf(&field_order, &mut writer)?;

        let mut generator = self.generator.to_bytes_be();
        generator.resize(key_len, 0);
        write_buf(&generator, &mut writer)?;

        Ok(())
    }
}

impl Decode for FfcdhParameters {
    fn decode(mut reader: impl Read) -> Result<Self> {
        let _total_len = reader.read_u32::<LittleEndian>()?;

        let mut magic = [0; 4];
        read_buf(&mut reader, &mut magic)?;

        if magic != Self::MAGIC {
            return Err(Error::InvalidMagic {
                name: "FfcdhParameters",
                expected: Self::MAGIC,
                actual: magic.to_vec(),
            });
        }

        let key_length = reader.read_u32::<LittleEndian>()?;

        let field_order = BigUint::from_bytes_be(&read_vec(key_length.try_into()?, &mut reader)?);

        let generator = BigUint::from_bytes_be(&read_vec(key_length.try_into()?, &mut reader)?);

        Ok(Self {
            key_length,
            field_order,
            generator,
        })
    }
}

/// [FFC DH Key](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/f8770f01-036d-4bf6-a4cf-1bd0e3913404)
///
/// The following specifies the format and field descriptions for the FFC DH Key structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfcdhKey {
    /// A 32-bit unsigned integer. The value in this field MUST be equal to the length, in bytes,
    /// of the Public key field. This parameter is encoded using little-endian format.
    pub key_length: u32,
    /// This is the large prime field order, and is a domain parameter for the FFC DH algorithm ([SP800-56A](https://csrc.nist.gov/pubs/sp/800/56/a/r1/final) section 5.7.1).
    /// It MUST be encoded in big-endian format. The length of this field, in bytes,
    /// MUST be equal to the value in the Key length field.
    pub field_order: BigUint,
    /// The generator of the subgroup, a domain parameter for the FFC DH algorithm ([SP800-56A](https://csrc.nist.gov/pubs/sp/800/56/a/r1/final) section 5.7.1).
    /// It MUST be encoded in big-endian format. The length of this field, in bytes,
    /// MUST be equal to the value in the Key length field.
    pub generator: BigUint,
    /// The public key for the FFC DH algorithm ([SP800-56A](https://csrc.nist.gov/pubs/sp/800/56/a/r1/final) section 5.7.1).
    /// It MUST be encoded in big-endian format. The length of this field, in bytes,
    /// MUST be equal to the value of the Key length field.
    pub public_key: BigUint,
}

impl FfcdhKey {
    // The following magic value is defined in the Microsoft documentation:
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/f8770f01-036d-4bf6-a4cf-1bd0e3913404
    const MAGIC: &[u8] = &[0x44, 0x48, 0x50, 0x42];
}

impl Encode for FfcdhKey {
    fn encode(&self, mut writer: impl Write) -> Result<()> {
        write_buf(FfcdhKey::MAGIC, &mut writer)?;

        writer.write_u32::<LittleEndian>(self.key_length)?;

        let key_len = self.key_length.try_into()?;

        let mut field_order = self.field_order.to_bytes_be();
        field_order.resize(key_len, 0);
        write_buf(&field_order, &mut writer)?;

        let mut generator = self.generator.to_bytes_be();
        generator.resize(key_len, 0);
        write_buf(&generator, &mut writer)?;

        let mut public_key = self.public_key.to_bytes_be();
        public_key.resize(key_len, 0);
        write_buf(&public_key, &mut writer)?;

        Ok(())
    }
}

impl Decode for FfcdhKey {
    fn decode(mut reader: impl Read) -> Result<Self> {
        let mut magic = [0; 4];
        read_buf(&mut reader, &mut magic)?;

        if magic != FfcdhKey::MAGIC {
            return Err(Error::InvalidMagic {
                name: "FfcdhKey",
                expected: Self::MAGIC,
                actual: magic.to_vec(),
            });
        }

        let key_length = reader.read_u32::<LittleEndian>()?;

        Ok(Self {
            key_length,
            field_order: BigUint::from_bytes_be(&read_vec(key_length.try_into()?, &mut reader)?),
            generator: BigUint::from_bytes_be(&read_vec(key_length.try_into()?, &mut reader)?),
            public_key: BigUint::from_bytes_be(&read_vec(key_length.try_into()?, &mut reader)?),
        })
    }
}

/// Supported elliptic curves.
///
/// It contains elliptic curves that are listed in the documentation:
/// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/24876a37-9a92-4187-9052-222bb6f85d4a
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
    type Error = GkdiError;

    fn try_from(value: &[u8]) -> GkdiResult<Self> {
        match value {
            b"ECK1" => Ok(EllipticCurve::P256),
            b"ECK3" => Ok(EllipticCurve::P384),
            b"ECK5" => Ok(EllipticCurve::P521),
            _ => Err(GkdiError::InvalidEllipticCurveId(value.to_vec())),
        }
    }
}

/// [ECDH Key](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/24876a37-9a92-4187-9052-222bb6f85d4a)
///
/// The following specifies the format and field descriptions for the Elliptic Curve Diffie-Hellman (ECDH) Key structure [RFC5114](https://www.rfc-editor.org/info/rfc5114).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdhKey {
    /// Represents the ECDH field parameters.
    pub curve: EllipticCurve,
    /// A 32-bit unsigned integer. This field MUST be the length, in bytes, of the public key.
    /// This field is encoded using little-endian format.
    pub key_length: u32,
    /// The x coordinate of the point P that represents the ECDH [RFC5114](https://www.rfc-editor.org/info/rfc5114) public key.
    /// It MUST be encoded in big-endian format. The length of this field, in bytes,
    /// MUST be equal to the value in the Key length field.
    pub x: BigUint,
    /// The y coordinate of the point P that represents the ECDH public key.
    /// It MUST be encoded in big-endian format. The length of this field, in bytes,
    /// MUST be equal to the value in the Key length field.
    pub y: BigUint,
}

impl Encode for EcdhKey {
    fn encode(&self, mut writer: impl Write) -> Result<()> {
        write_buf(self.curve.into(), &mut writer)?;

        writer.write_u32::<LittleEndian>(self.key_length)?;

        let key_len: usize = self.key_length.try_into()?;

        let mut x = self.x.to_bytes_be();
        x.resize(key_len, 0);
        write_buf(&x, &mut writer)?;

        let mut y = self.y.to_bytes_be();
        y.resize(key_len, 0);
        write_buf(&y, &mut writer)?;

        Ok(())
    }
}

impl Decode for EcdhKey {
    fn decode(mut reader: impl Read) -> Result<Self> {
        let mut curve_id = [0; 4];
        read_buf(&mut reader, &mut curve_id)?;
        let curve = EllipticCurve::try_from(curve_id.as_ref())?;

        let key_length = reader.read_u32::<LittleEndian>()?;

        Ok(Self {
            curve,
            key_length,
            x: BigUint::from_bytes_be(&read_vec(key_length.try_into()?, &mut reader)?),
            y: BigUint::from_bytes_be(&read_vec(key_length.try_into()?, &mut reader)?),
        })
    }
}

/// [Group Key Envelope](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/192c061c-e740-4aa0-ab1d-6954fb3e58f7)
///
/// The following specifies the format and field descriptions for the Group Key Envelope structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupKeyEnvelope {
    /// A 32-bit unsigned integer. Bit 31 (LSB) MUST be set to 1 when this structure is being used to
    /// transport a public key, otherwise set to 0. Bit 30 MUST be set to 1 when the key being transported
    /// by this structure might be used for encryption and decryption, otherwise it should only be used for decryption.
    /// This field is encoded using little-endian format.
    pub flags: u32,
    /// This field MUST be the L0 index of the key being enveloped. This field is encoded using little-endian format.
    pub l0: i32,
    /// This field MUST be the L1 index of the key being enveloped, and therefore MUST be a number between 0 and 31, inclusive.
    /// This field is encoded using little-endian format.
    pub l1: i32,
    /// This field MUST be the L2 index of the key being enveloped, and therefore MUST be a number between 0 and 31, inclusive.
    /// This field is encoded using little-endian format.
    pub l2: i32,
    /// A GUID containing the root key identifier of the key being enveloped.
    pub root_key_identifier: Uuid,
    /// This field MUST be the ADM element KDF algorithm name associated with the ADM element root key,
    /// whose identifier is in the Root key identifier field.
    pub kdf_alg: String,
    /// This field MUST contain the KDF parameters associated with the ADM element root key,
    /// whose identifier is in the Root key identifier field.
    pub kdf_parameters: Vec<u8>,
    /// This field MUST be the ADM element Secret agreement algorithm name associated with the ADM element root key,
    /// whose identifier is in the Root key identifier field.
    pub secret_algorithm: String,
    /// This field MUST contain the ADM element Secret agreement algorithm associated with the ADM element root key,
    /// whose identifier is in the Root key identifier field.
    pub secret_parameters: Vec<u8>,
    /// A 32-bit unsigned integer. This field MUST be the private key length associated with the root key,
    /// whose identifier is in the Root key identifier field. This field is encoded using little-endian format.
    pub private_key_length: u32,
    /// A 32-bit unsigned integer. This field MUST be the public key length associated with the root key,
    /// whose identifier is in the Root key identifier field. This field is encoded using little-endian format.
    pub public_key_length: u32,
    /// This field MUST be the domain name of the server in DNS format.
    pub domain_name: String,
    /// This field MUST be the forest name of the server in DNS format.
    pub forest_name: String,
    /// An L1 seed key ADM element in binary form.
    pub l1_key: Vec<u8>,
    /// The L2 seed key ADM element or the group public key ADM element with group key identifier in binary form.
    pub l2_key: Vec<u8>,
}

impl GroupKeyEnvelope {
    // The following magic value is defined in the Microsoft documentation:
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/192c061c-e740-4aa0-ab1d-6954fb3e58f7
    const MAGIC: &[u8] = &[0x4B, 0x44, 0x53, 0x4B];
    const VERSION: u32 = 1;

    pub fn is_public_key(&self) -> bool {
        self.flags & 1 != 0
    }

    pub fn new_kek(&self) -> Result<(Vec<u8>, KeyIdentifier)> {
        if self.kdf_alg != KDF_ALGORITHM_NAME {
            Err(GkdiError::InvalidKdfAlgName {
                expected: KDF_ALGORITHM_NAME,
                actual: self.kdf_alg.clone(),
            })?;
        }

        let kdf_parameters = KdfParameters::decode(self.kdf_parameters.as_slice())?;
        let hash_alg = kdf_parameters.hash_alg;

        let mut rand = OsRng;

        let (kek, key_info) = if self.is_public_key() {
            // the L2 key is the peer's public key

            let mut private_key = vec![self.private_key_length.div_ceil(8).try_into()?];
            rand.fill(private_key.as_mut_slice());

            let kek = compute_kek(hash_alg, &self.secret_algorithm, &private_key, &self.l2_key)?;
            let key_info = compute_public_key(&self.secret_algorithm, &private_key, &self.l2_key)?;

            (kek, key_info)
        } else {
            let key_info = rand.gen::<[u8; 32]>();
            let kek = kdf(hash_alg, &self.l2_key, KDS_SERVICE_LABEL, &key_info, 32)?;

            (kek, key_info.to_vec())
        };

        Ok((
            kek,
            KeyIdentifier {
                version: 1,
                flags: self.flags,

                l0: self.l0,
                l1: self.l1,
                l2: self.l2,
                root_key_identifier: self.root_key_identifier,

                key_info,
                domain_name: self.domain_name.clone(),
                forest_name: self.forest_name.clone(),
            },
        ))
    }

    pub fn get_kek(&self, key_identifier: &KeyIdentifier) -> Result<Vec<u8>> {
        if self.is_public_key() {
            Err(GkdiError::IsNotAuthorized)?;
        }

        if self.l0 != key_identifier.l0 {
            Err(GkdiError::InvalidL0Index)?;
        }

        if self.kdf_alg != KDF_ALGORITHM_NAME {
            Err(GkdiError::InvalidKdfAlgName {
                expected: KDF_ALGORITHM_NAME,
                actual: self.kdf_alg.clone(),
            })?;
        }

        let kdf_parameters = KdfParameters::decode(self.kdf_parameters.as_slice())?;
        let hash_alg = kdf_parameters.hash_alg;
        let l2_key = compute_l2_key(hash_alg, key_identifier.l1, key_identifier.l2, self)?;

        if key_identifier.is_public_key() {
            Ok(compute_kek_from_public_key(
                hash_alg,
                &l2_key,
                &self.secret_algorithm,
                &key_identifier.key_info,
                self.private_key_length.div_ceil(8).try_into()?,
            )?)
        } else {
            Ok(kdf(hash_alg, &l2_key, KDS_SERVICE_LABEL, &key_identifier.key_info, 32)?)
        }
    }
}

impl Encode for GroupKeyEnvelope {
    fn encode(&self, mut writer: impl Write) -> Result<()> {
        writer.write_u32::<LittleEndian>(Self::VERSION)?;

        write_buf(GroupKeyEnvelope::MAGIC, &mut writer)?;
        writer.write_u32::<LittleEndian>(self.flags)?;
        writer.write_i32::<LittleEndian>(self.l0)?;
        writer.write_i32::<LittleEndian>(self.l1)?;
        writer.write_i32::<LittleEndian>(self.l2)?;
        self.root_key_identifier.encode(&mut writer)?;

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

        write_buf(&encoded_kdf_alg, &mut writer)?;
        write_buf(&self.kdf_parameters, &mut writer)?;
        write_buf(&encoded_secret_alg, &mut writer)?;
        write_buf(&self.secret_parameters, &mut writer)?;
        write_buf(&encoded_domain_name, &mut writer)?;
        write_buf(&encoded_forest_name, &mut writer)?;
        write_buf(&self.l1_key, &mut writer)?;
        write_buf(&self.l2_key, &mut writer)?;

        Ok(())
    }
}

impl Decode for GroupKeyEnvelope {
    fn decode(mut reader: impl Read) -> Result<Self> {
        let version = reader.read_u32::<LittleEndian>()?;

        if version != Self::VERSION {
            Err(GkdiError::InvalidVersion {
                name: "GroupKeyEnvelope",
                expected: Self::VERSION,
                actual: version,
            })?;
        }

        let mut magic = [0; 4];
        read_buf(&mut reader, &mut magic)?;

        if magic != Self::MAGIC {
            return Err(Error::InvalidMagic {
                name: "GroupKeyEnvelope",
                expected: Self::MAGIC,
                actual: magic.to_vec(),
            });
        }

        let flags = reader.read_u32::<LittleEndian>()?;
        let l0 = reader.read_i32::<LittleEndian>()?;
        let l1 = reader.read_i32::<LittleEndian>()?;
        let l2 = reader.read_i32::<LittleEndian>()?;
        let root_key_identifier = Uuid::decode(&mut reader)?;

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
        let kdf_parameters = read_vec(kdf_parameters_len.try_into()?, &mut reader)?;

        let secret_algorithm = read_c_str_utf16_le(secret_alg_len.try_into()?, &mut reader)?;
        let secret_parameters = read_vec(secret_parameters_len.try_into()?, &mut reader)?;

        let domain_name = read_c_str_utf16_le(domain_len.try_into()?, &mut reader)?;
        let forest_name = read_c_str_utf16_le(forest_len.try_into()?, &mut reader)?;

        let l1_key = read_vec(l1_key_len.try_into()?, &mut reader)?;
        let l2_key = read_vec(l2_key_len.try_into()?, &mut reader)?;

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
