use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use num_bigint_dig::BigUint;
use thiserror::Error;
use uuid::Uuid;

use crate::str::{encode_utf16_le, from_utf16_le};
use crate::{Decode, Encode, Error, Padding, ReadCursor, Result, WriteCursor, read_c_str_utf16_le};

pub const KDF_ALGORITHM_NAME: &str = "SP800_108_CTR_HMAC";

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

    #[error("bad GetKey response: {0}")]
    BadResponse(&'static str),

    #[error("bad GetKey hresult: {0:x?}")]
    BadHresult(u32),
}

pub type GkdiResult<T> = core::result::Result<T, GkdiError>;

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

impl GetKey {
    pub const OPNUM: u16 = 0;
}

impl Encode for GetKey {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        let target_sd_len = self.target_sd.len().try_into()?;
        // cbTargetSD
        dst.write_u64(target_sd_len);
        // pbTargetSD - pointer header includes the length + padding
        dst.write_u64(target_sd_len);

        dst.write_slice(&self.target_sd);

        Padding::<8>::write(self.target_sd.len(), dst);

        if let Some(root_key_id) = self.root_key_id.as_ref() {
            dst.write_slice(&[0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]);
            root_key_id.encode_cursor(dst)?;
        } else {
            dst.write_u64(0);
        };

        dst.write_i32(self.l0_key_id);
        dst.write_i32(self.l1_key_id);
        dst.write_i32(self.l2_key_id);

        Ok(())
    }

    fn frame_length(&self) -> usize {
        8 /* cbTargetSD */ + 8 /* pbTartetSD */ + self.target_sd.len() + Padding::<8>::padding(self.target_sd.len())
        + if let Some(root_key_id) = self.root_key_id.as_ref() { 8 + root_key_id.frame_length() } else { 8 }
        + 4 /* l0 */ + 4 /* l1 */ + 4 /* l2 */
    }
}

impl Decode for GetKey {
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self> {
        let target_sd_len = src.read_u64();
        let _offset = src.read_u64();

        let target_sd = src.read_slice(target_sd_len.try_into()?).to_vec();

        Padding::<8>::read(target_sd_len.try_into()?, src);

        let root_key_id = if src.read_u64() != 0 {
            Some(Uuid::decode_cursor(src)?)
        } else {
            None
        };

        let l0_key_id = src.read_i32();
        let l1_key_id = src.read_i32();
        let l2_key_id = src.read_i32();

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
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        let encoded_hash_alg = encode_utf16_le(&self.hash_alg.to_string());

        dst.write_slice(Self::MAGIC_IDENTIFIER_1);
        dst.write_u32(encoded_hash_alg.len().try_into()?);
        dst.write_slice(Self::MAGIC_IDENTIFIER_2);
        dst.write_slice(&encoded_hash_alg);

        Ok(())
    }

    fn frame_length(&self) -> usize {
        let encoded_hash_alg = encode_utf16_le(&self.hash_alg.to_string());

        Self::MAGIC_IDENTIFIER_1.len() + 4 /* encoded_hash_alg len */ + Self::MAGIC_IDENTIFIER_2.len() + encoded_hash_alg.len()
    }
}

impl Decode for KdfParameters {
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self> {
        let magic_identifier_1 = src.read_slice(Self::MAGIC_IDENTIFIER_1.len());

        if magic_identifier_1 != Self::MAGIC_IDENTIFIER_1 {
            return Err(Error::InvalidMagic {
                name: "KdfParameters::MAGIC_IDENTIFIER_1",
                expected: Self::MAGIC_IDENTIFIER_1,
                actual: magic_identifier_1.to_vec(),
            });
        }

        let hash_name_len: usize = src.read_u32().try_into()?;

        let magic_identifier_2 = src.read_slice(Self::MAGIC_IDENTIFIER_2.len());

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

        let buf = src.read_slice(hash_name_len - 2 /* UTF-16 null terminator char */);
        // Skip UTF-16 null terminator char.
        src.read_u16();

        Ok(Self {
            hash_alg: from_utf16_le(buf)?.as_str().try_into()?,
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
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        // Calculate total structure length and write it.
        //
        // Length (4 bytes):  A 32-bit unsigned integer. This field MUST be the length, in bytes, of the entire structure. This field is encoded using little-endian format:
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/e15ae269-ee21-446a-a480-de3ea243db5f
        dst.write_u32(12 + self.key_length * 2);

        dst.write_slice(Self::MAGIC);
        dst.write_u32(self.key_length);

        let key_len = self.key_length.try_into()?;

        let mut field_order = self.field_order.to_bytes_be();
        field_order.resize(key_len, 0);
        dst.write_slice(&field_order);

        let mut generator = self.generator.to_bytes_be();
        generator.resize(key_len, 0);
        dst.write_slice(&generator);

        Ok(())
    }

    fn frame_length(&self) -> usize {
        4 /* structure length */ + Self::MAGIC.len() + 4 /* key length */ + usize::try_from(self.key_length).unwrap() * 2
    }
}

impl Decode for FfcdhParameters {
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self> {
        let _total_len = src.read_u32();

        let magic = src.read_slice(Self::MAGIC.len());

        if magic != Self::MAGIC {
            return Err(Error::InvalidMagic {
                name: "FfcdhParameters",
                expected: Self::MAGIC,
                actual: magic.to_vec(),
            });
        }

        let key_length = src.read_u32();

        let field_order = BigUint::from_bytes_be(src.read_slice(key_length.try_into()?));

        let generator = BigUint::from_bytes_be(src.read_slice(key_length.try_into()?));

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
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        dst.write_slice(Self::MAGIC);

        dst.write_u32(self.key_length);

        let key_len = self.key_length.try_into()?;

        let mut field_order = self.field_order.to_bytes_be();
        field_order.resize(key_len, 0);
        dst.write_slice(&field_order);

        let mut generator = self.generator.to_bytes_be();
        generator.resize(key_len, 0);
        dst.write_slice(&generator);

        let mut public_key = self.public_key.to_bytes_be();
        public_key.resize(key_len, 0);
        dst.write_slice(&public_key);

        Ok(())
    }

    fn frame_length(&self) -> usize {
        Self::MAGIC.len() + 4 /* key length */ + usize::try_from(self.key_length).unwrap() * 3
    }
}

impl Decode for FfcdhKey {
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self> {
        let magic = src.read_slice(Self::MAGIC.len());

        if magic != FfcdhKey::MAGIC {
            return Err(Error::InvalidMagic {
                name: "FfcdhKey",
                expected: Self::MAGIC,
                actual: magic.to_vec(),
            });
        }

        let key_length = src.read_u32();

        Ok(Self {
            key_length,
            field_order: BigUint::from_bytes_be(src.read_slice(key_length.try_into()?)),
            generator: BigUint::from_bytes_be(src.read_slice(key_length.try_into()?)),
            public_key: BigUint::from_bytes_be(src.read_slice(key_length.try_into()?)),
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
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        dst.write_slice(self.curve.into());

        dst.write_u32(self.key_length);

        let key_len: usize = self.key_length.try_into()?;

        let mut x = self.x.to_bytes_be();
        x.resize(key_len, 0);
        dst.write_slice(&x);

        let mut y = self.y.to_bytes_be();
        y.resize(key_len, 0);
        dst.write_slice(&y);

        Ok(())
    }

    fn frame_length(&self) -> usize {
        let encoded_curve: &[u8] = self.curve.into();

        encoded_curve.len() + 4 /* key_length */ + 2 * usize::try_from(self.key_length).unwrap()
    }
}

impl Decode for EcdhKey {
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self> {
        let curve_id = src.read_slice(4);
        let curve = EllipticCurve::try_from(curve_id)?;

        let key_length = src.read_u32();

        Ok(Self {
            curve,
            key_length,
            x: BigUint::from_bytes_be(src.read_slice(key_length.try_into()?)),
            y: BigUint::from_bytes_be(src.read_slice(key_length.try_into()?)),
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
}

impl Encode for GroupKeyEnvelope {
    fn encode_cursor(&self, dst: &mut WriteCursor<'_>) -> Result<()> {
        dst.write_u32(Self::VERSION);

        dst.write_slice(Self::MAGIC);
        dst.write_u32(self.flags);
        dst.write_i32(self.l0);
        dst.write_i32(self.l1);
        dst.write_i32(self.l2);
        self.root_key_identifier.encode_cursor(dst)?;

        let encoded_kdf_alg = encode_utf16_le(&self.kdf_alg);
        let encoded_secret_alg = encode_utf16_le(&self.secret_algorithm);
        let encoded_domain_name = encode_utf16_le(&self.domain_name);
        let encoded_forest_name = encode_utf16_le(&self.forest_name);

        dst.write_u32(encoded_kdf_alg.len().try_into()?);
        dst.write_u32(self.kdf_parameters.len().try_into()?);
        dst.write_u32(encoded_secret_alg.len().try_into()?);
        dst.write_u32(self.secret_parameters.len().try_into()?);
        dst.write_u32(self.private_key_length);
        dst.write_u32(self.public_key_length);
        dst.write_u32(self.l1_key.len().try_into()?);
        dst.write_u32(self.l2_key.len().try_into()?);
        dst.write_u32(encoded_domain_name.len().try_into()?);
        dst.write_u32(encoded_forest_name.len().try_into()?);

        dst.write_slice(&encoded_kdf_alg);
        dst.write_slice(&self.kdf_parameters);
        dst.write_slice(&encoded_secret_alg);
        dst.write_slice(&self.secret_parameters);
        dst.write_slice(&encoded_domain_name);
        dst.write_slice(&encoded_forest_name);
        dst.write_slice(&self.l1_key);
        dst.write_slice(&self.l2_key);

        Ok(())
    }

    fn frame_length(&self) -> usize {
        let encoded_kdf_alg = encode_utf16_le(&self.kdf_alg);
        let encoded_secret_alg = encode_utf16_le(&self.secret_algorithm);
        let encoded_domain_name = encode_utf16_le(&self.domain_name);
        let encoded_forest_name = encode_utf16_le(&self.forest_name);

        4 /* version */ + Self::MAGIC.len() + 4 /* flags */ + 4 /* l0 */ + 4 /* l1 */ + 4 /* l2 */
        + self.root_key_identifier.frame_length()
        + 4 /* encoded_kdf_alg */
        + 4 /* kdf_parameters */
        + 4 /* encoded_secret_alg */
        + 4 /* secret_parameters */
        + 4 /* private_key_length */
        + 4 /* public_key_length */
        + 4 /* l1_key */
        + 4 /* l2_key */
        + 4 /* encoded_domain_name */
        + 4 /* encoded_forest_name */
        + encoded_kdf_alg.len()
        + self.kdf_parameters.len()
        + encoded_secret_alg.len()
        + self.secret_parameters.len()
        + encoded_domain_name.len()
        + encoded_forest_name.len()
        + self.l1_key.len()
        + self.l2_key.len()
    }
}

impl Decode for GroupKeyEnvelope {
    fn decode_cursor(src: &mut ReadCursor<'_>) -> Result<Self> {
        let version = src.read_u32();

        if version != Self::VERSION {
            Err(GkdiError::InvalidVersion {
                name: "GroupKeyEnvelope",
                expected: Self::VERSION,
                actual: version,
            })?;
        }

        let magic = src.read_slice(Self::MAGIC.len());

        if magic != Self::MAGIC {
            return Err(Error::InvalidMagic {
                name: "GroupKeyEnvelope",
                expected: Self::MAGIC,
                actual: magic.to_vec(),
            });
        }

        let flags = src.read_u32();
        let l0 = src.read_i32();
        let l1 = src.read_i32();
        let l2 = src.read_i32();
        let root_key_identifier = Uuid::decode_cursor(src)?;

        let kdf_alg_len = src.read_u32();
        let kdf_parameters_len = src.read_u32();
        let secret_alg_len = src.read_u32();
        let secret_parameters_len = src.read_u32();
        let private_key_length = src.read_u32();
        let public_key_length = src.read_u32();
        let l1_key_len = src.read_u32();
        let l2_key_len = src.read_u32();
        let domain_len = src.read_u32();
        let forest_len = src.read_u32();

        let kdf_alg = read_c_str_utf16_le(kdf_alg_len.try_into()?, src)?;
        let kdf_parameters = src.read_slice(kdf_parameters_len.try_into()?).to_vec();

        let secret_algorithm = read_c_str_utf16_le(secret_alg_len.try_into()?, src)?;
        let secret_parameters = src.read_slice(secret_parameters_len.try_into()?).to_vec();

        let domain_name = read_c_str_utf16_le(domain_len.try_into()?, src)?;
        let forest_name = read_c_str_utf16_le(forest_len.try_into()?, src)?;

        let l1_key = src.read_slice(l1_key_len.try_into()?).to_vec();
        let l2_key = src.read_slice(l2_key_len.try_into()?).to_vec();

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
