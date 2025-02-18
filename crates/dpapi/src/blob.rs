use std::io::{Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use picky_asn1::restricted_string::Utf8String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ImplicitContextTag0, ObjectIdentifierAsn1, OctetStringAsn1, Optional,
    Utf8StringAsn1,
};
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::cmsversion::CmsVersion;
use picky_asn1_x509::enveloped_data::{
    ContentEncryptionAlgorithmIdentifier, ContentInfo, ContentType, EncryptedContent, EncryptedContentInfo,
    EncryptedKey, EnvelopedData, GeneralProtectionDescriptor, KekIdentifier, KekRecipientInfo,
    KeyEncryptionAlgorithmIdentifier, OtherKeyAttribute, ProtectionDescriptor, RecipientInfo, RecipientInfos,
};
use picky_asn1_x509::oids;
use thiserror::Error;
use uuid::Uuid;

use crate::rpc::{read_buf, read_to_end, read_vec, write_buf, Decode, Encode, EncodeExt};
use crate::sid::{ace_to_bytes, sd_to_bytes};
use crate::str::{encode_utf16_le, from_utf16_le};
use crate::{Error, Result};

#[derive(Debug, Error)]
pub enum BlobError {
    #[error("unsupported protection descriptor: {0}")]
    UnsupportedProtectionDescriptor(String),

    #[error("invalid {name}: expected {expected} but got {actual}")]
    InvalidOid {
        name: &'static str,
        expected: String,
        actual: String,
    },

    #[error("invalid {name} version: expected {expected:?} but got {actual:?}")]
    InvalidCmsVersion {
        name: &'static str,
        expected: CmsVersion,
        actual: CmsVersion,
    },

    #[error("bad recipient infos amount: expected {expected} but got {actual}")]
    RecipientInfosAmount { expected: usize, actual: usize },

    #[error("missing {0} value")]
    MissingValue(&'static str),
}

/// Key Identifier
///
/// This contains the key identifier info that can be used by MS-GKDI GetKey to retrieve the group key seed values.
/// This structure is not defined publicly by Microsoft but it closely matches the [GroupKeyEnvelope] structure.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyIdentifier {
    /// The version of the structure.
    pub version: u32,
    /// Flags describing the values inside the structure.
    pub flags: u32,

    /// The L0 index of the key.
    pub l0: i32,
    /// The L1 index of the key.
    pub l1: i32,
    /// The L2 index of the key.
    pub l2: i32,
    /// A GUID that identifies a root key.
    pub root_key_identifier: Uuid,

    /// Key info.
    pub key_info: Vec<u8>,
    /// The domain name of the server in DNS format.
    pub domain_name: String,
    /// The forest name of the server in DNS format.
    pub forest_name: String,
}

impl KeyIdentifier {
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/192c061c-e740-4aa0-ab1d-6954fb3e58f7
    const MAGIC: [u8; 4] = [0x4b, 0x44, 0x53, 0x4b];

    pub fn is_public_key(&self) -> bool {
        self.flags & 1 != 0
    }
}

impl Encode for KeyIdentifier {
    fn encode(&self, mut writer: impl Write) -> Result<()> {
        let domain_name = encode_utf16_le(&self.domain_name);
        let forest_name = encode_utf16_le(&self.forest_name);

        writer.write_u32::<LittleEndian>(self.version)?;
        write_buf(&KeyIdentifier::MAGIC, &mut writer)?;
        writer.write_u32::<LittleEndian>(self.flags)?;

        writer.write_i32::<LittleEndian>(self.l0)?;
        writer.write_i32::<LittleEndian>(self.l1)?;
        writer.write_i32::<LittleEndian>(self.l2)?;

        self.root_key_identifier.encode(&mut writer)?;

        writer.write_u32::<LittleEndian>(self.key_info.len().try_into()?)?;
        writer.write_u32::<LittleEndian>(domain_name.len().try_into()?)?;
        writer.write_u32::<LittleEndian>(forest_name.len().try_into()?)?;

        write_buf(&self.key_info, &mut writer)?;
        write_buf(&domain_name, &mut writer)?;
        write_buf(&forest_name, &mut writer)?;

        Ok(())
    }
}

impl Decode for KeyIdentifier {
    fn decode(mut reader: impl Read) -> Result<Self> {
        let version = reader.read_u32::<LittleEndian>()?;

        let mut magic = [0; 4];
        read_buf(&mut reader, &mut magic)?;

        if magic != Self::MAGIC {
            return Err(Error::InvalidMagic {
                name: "KeyIdentifier",
                expected: Self::MAGIC.as_slice(),
                actual: magic.to_vec(),
            });
        }

        let flags = reader.read_u32::<LittleEndian>()?;

        let l0 = reader.read_i32::<LittleEndian>()?;
        let l1 = reader.read_i32::<LittleEndian>()?;
        let l2 = reader.read_i32::<LittleEndian>()?;
        let root_key_identifier = Uuid::decode(&mut reader)?;

        let key_info_len = reader.read_u32::<LittleEndian>()?;

        let domain_len = reader.read_u32::<LittleEndian>()?.try_into()?;
        if domain_len <= 2 {
            return Err(Error::InvalidLength {
                name: "KeyIdentifier domain name",
                expected: 2,
                actual: domain_len,
            });
        }
        let domain_len = domain_len - 2 /* UTF16 null terminator */;

        let forest_len = reader.read_u32::<LittleEndian>()?.try_into()?;
        if forest_len <= 2 {
            return Err(Error::InvalidLength {
                name: "KeyIdentifier forest name",
                expected: 2,
                actual: forest_len,
            });
        }
        let forest_len = forest_len - 2 /* UTF16 null terminator */;

        let key_info = read_vec(key_info_len.try_into()?, &mut reader)?;

        let domain_name = read_vec(domain_len, &mut reader)?;
        // Read UTF16 null terminator.
        reader.read_u16::<LittleEndian>()?;

        let forest_name = read_vec(forest_len, &mut reader)?;
        // Read UTF16 null terminator.
        reader.read_u16::<LittleEndian>()?;

        Ok(Self {
            version,
            flags,
            l0,
            l1,
            l2,
            root_key_identifier,
            key_info,
            domain_name: from_utf16_le(&domain_name)?,
            forest_name: from_utf16_le(&forest_name)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ProtectionDescriptorType {
    #[default]
    Sid,
    KeyFile,
    Sddl,
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidProtectionDescriptor {
    pub sid: String,
}

impl SidProtectionDescriptor {
    pub fn get_target_sd(&self) -> Result<Vec<u8>> {
        // Build the target security descriptor from the SID passed in. This SD
        // contains an ACE per target user with a mask of 0x3 and a final ACE of
        // the current user with a mask of 0x2. When viewing this over the wire
        // the current user is set as S-1-1-0 (World) and the owner/group is
        // S-1-5-18 (SYSTEM).
        sd_to_bytes(
            "S-1-5-18",
            "S-1-5-18",
            None,
            Some(&[ace_to_bytes(&self.sid, 3)?, ace_to_bytes("S-1-1-0", 2)?]),
        )
    }

    pub fn encode_asn1(&self) -> Result<Vec<u8>> {
        Ok(picky_asn1_der::to_vec(&GeneralProtectionDescriptor {
            descriptor_type: ObjectIdentifierAsn1::from(oids::sid_protection_descriptor()),
            descriptors: Asn1SequenceOf::from(vec![Asn1SequenceOf::from(vec![ProtectionDescriptor {
                descriptor_type: Utf8StringAsn1::from(Utf8String::from_string("SID".to_owned())?),
                descriptor_value: Utf8StringAsn1::from(Utf8String::from_string(self.sid.clone())?),
            }])]),
        })?)
    }

    pub fn decode_asn1(data: &[u8]) -> Result<Self> {
        let general_protection_descriptor: GeneralProtectionDescriptor = picky_asn1_der::from_bytes(data)?;

        if general_protection_descriptor.descriptor_type.0 != oids::sid_protection_descriptor() {
            Err(BlobError::UnsupportedProtectionDescriptor(
                general_protection_descriptor.descriptor_type.0.into(),
            ))?;
        }

        let ProtectionDescriptor {
            descriptor_type,
            descriptor_value,
        } = general_protection_descriptor
            .descriptors
            .0
            .first()
            .ok_or(BlobError::MissingValue("protection descriptor"))?
            .0
            .first()
            .ok_or(BlobError::MissingValue("protection descriptor"))?;

        if descriptor_type.0.as_utf8() != "SID" {
            Err(BlobError::UnsupportedProtectionDescriptor(
                descriptor_type.0.as_utf8().to_owned(),
            ))?;
        }

        Ok(Self {
            sid: descriptor_value.0.as_utf8().to_owned(),
        })
    }
}

/// Represents DPAPI blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpapiBlob {
    /// The key identifier for the KEK.
    pub key_identifier: KeyIdentifier,
    /// The protection descriptor that protects the key.
    pub protection_descriptor: SidProtectionDescriptor,
    /// The encrypted CEK.
    pub enc_cek: Vec<u8>,
    /// CEK encryption algorithm.
    pub enc_cek_algorithm_id: KeyEncryptionAlgorithmIdentifier,
    /// The encrypted content.
    pub enc_content: Vec<u8>,
    /// Content encryption algorithm.
    pub enc_content_algorithm_id: ContentEncryptionAlgorithmIdentifier,
}

impl DpapiBlob {
    // blob_in_envelope:
    // * `true` to store the encrypted blob in the EnvelopedData structure (NCryptProtectSecret general).
    // * `false` to append the encrypted blob after the EnvelopedData structure (LAPS style).
    pub fn encode(&self, blob_in_envelope: bool, mut writer: impl Write) -> Result<()> {
        picky_asn1_der::to_writer(
            &ContentInfo {
                content_type: ObjectIdentifierAsn1::from(oids::enveloped_data()),
                content: ExplicitContextTag0::from(Asn1RawDer(picky_asn1_der::to_vec(&EnvelopedData {
                    version: CmsVersion::V2,
                    originator_info: Optional::from(None),
                    recipient_infos: RecipientInfos::from(vec![RecipientInfo::Kek(KekRecipientInfo {
                        version: CmsVersion::V4,
                        kek_id: KekIdentifier {
                            key_identifier: OctetStringAsn1::from(self.key_identifier.encode_to_vec()?),
                            date: Optional::from(None),
                            other: Optional::from(Some(OtherKeyAttribute {
                                key_attr_id: ObjectIdentifierAsn1::from(oids::protection_descriptor_type()),
                                key_attr: Some(Asn1RawDer(self.protection_descriptor.encode_asn1()?)),
                            })),
                        },
                        key_encryption_algorithm: self.enc_cek_algorithm_id.clone(),
                        encrypted_key: EncryptedKey::from(self.enc_cek.clone()),
                    })]),
                    encrypted_content_info: EncryptedContentInfo {
                        content_type: ContentType::from(oids::content_info_type_data()),
                        content_encryption_algorithm: self.enc_content_algorithm_id.clone(),
                        encrypted_content: Optional::from(if blob_in_envelope {
                            Some(ImplicitContextTag0::from(EncryptedContent::from(
                                self.enc_content.clone(),
                            )))
                        } else {
                            None
                        }),
                    },
                    unprotected_attrs: Optional::from(None),
                })?)),
            },
            &mut writer,
        )?;

        if !blob_in_envelope {
            write_buf(&self.enc_content, &mut writer)?;
        }

        Ok(())
    }
}

impl Decode for DpapiBlob {
    fn decode(mut reader: impl Read) -> Result<Self> {
        let content_info: ContentInfo = picky_asn1_der::from_reader(&mut reader)?;

        if content_info.content_type.0 != oids::enveloped_data() {
            let expected_content_type: String = oids::enveloped_data().into();
            let actual_content_type: String = content_info.content_type.0.into();

            Err(BlobError::InvalidOid {
                name: "blob content type",
                expected: expected_content_type,
                actual: actual_content_type,
            })?;
        }

        let enveloped_data: EnvelopedData = picky_asn1_der::from_bytes(&content_info.content.0 .0)?;

        if enveloped_data.version != CmsVersion::V2 {
            Err(BlobError::InvalidCmsVersion {
                name: "enveloped data",
                expected: CmsVersion::V2,
                actual: enveloped_data.version,
            })?;
        }

        if enveloped_data.recipient_infos.0.len() != 1 {
            Err(BlobError::RecipientInfosAmount {
                expected: 1,
                actual: enveloped_data.recipient_infos.0.len(),
            })?;
        }

        let RecipientInfo::Kek(kek_info) = enveloped_data.recipient_infos.0.first().unwrap();

        if kek_info.version != CmsVersion::V4 {
            Err(BlobError::InvalidCmsVersion {
                name: "KEK info",
                expected: CmsVersion::V4,
                actual: kek_info.version,
            })?;
        }

        let key_identifier = KeyIdentifier::decode(&kek_info.kek_id.key_identifier.0 as &[u8])?;

        let protection_descriptor = if let Some(OtherKeyAttribute { key_attr_id, key_attr }) = &kek_info.kek_id.other.0
        {
            if key_attr_id.0 != oids::protection_descriptor_type() {
                let expected_descriptor: String = oids::protection_descriptor_type().into();
                let actual_descriptor: String = (&key_attr_id.0).into();

                Err(BlobError::InvalidOid {
                    name: "KEK recipient info OtherAttribute OID",
                    expected: expected_descriptor,
                    actual: actual_descriptor,
                })?;
            }

            if let Some(encoded_protection_descriptor) = key_attr {
                SidProtectionDescriptor::decode_asn1(&encoded_protection_descriptor.0)?
            } else {
                Err(BlobError::MissingValue("KEK recipient info OtherAttribute"))?
            }
        } else {
            Err(BlobError::MissingValue("KEK recipient info protection descriptor"))?
        };

        let enc_content = if let Some(enc_content) = enveloped_data.encrypted_content_info.encrypted_content.0 {
            // Some DPAPI blobs don't include the content in the PKCS7 payload but
            // just append it after the blob.
            if enc_content.0 .0.is_empty() {
                read_to_end(reader)?
            } else {
                enc_content.0 .0
            }
        } else {
            read_to_end(reader)?
        };
        let enc_content_algorithm_id = enveloped_data.encrypted_content_info.content_encryption_algorithm;

        let KekRecipientInfo {
            encrypted_key,
            key_encryption_algorithm,
            version: _,
            kek_id: _,
        } = kek_info;

        Ok(Self {
            key_identifier,
            protection_descriptor,
            enc_cek: encrypted_key.0.clone(),
            enc_cek_algorithm_id: key_encryption_algorithm.clone(),
            enc_content,
            enc_content_algorithm_id,
        })
    }
}
