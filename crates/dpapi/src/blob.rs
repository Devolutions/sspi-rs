use std::io::{Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use picky_asn1::restricted_string::Utf8String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ImplicitContextTag0, ObjectIdentifierAsn1, OctetStringAsn1, Optional,
    Utf8StringAsn1,
};
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::cmsversion::CmsVersion;
use picky_asn1_x509::content_info::{ContentValue, EncapsulatedContentInfo};
use picky_asn1_x509::enveloped_data::{
    ContentEncryptionAlgorithmIdentifier, ContentType, EncryptedContent, EncryptedContentInfo, EncryptedKey,
    EnvelopedData, GeneralProtectionDescriptor, KekIdentifier, KekRecipientInfo, KeyEncryptionAlgorithmIdentifier,
    OtherKeyAttribute, ProtectionDescriptor, RecipientInfo, RecipientInfos,
};
use picky_asn1_x509::oids;
use uuid::Uuid;

use crate::rpc::{read_to_end, read_uuid, Decode, Encode};
use crate::sid_utils::{ace_to_bytes, sd_to_bytes};
use crate::{DpapiResult, Error, ErrorKind};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyIdentifier {
    pub version: u32,
    pub flags: u32,

    pub l0: u32,
    pub l1: u32,
    pub l2: u32,
    pub root_key_identifier: Uuid,

    pub key_info: Vec<u8>,
    pub domain_name: String,
    pub forest_name: String,
}

impl KeyIdentifier {
    const MAGIC: [u8; 4] = [0x4b, 0x44, 0x53, 0x4b];
}

impl Encode for KeyIdentifier {
    fn encode(&self, mut writer: impl Write) -> DpapiResult<()> {
        let domain_name = self
            .domain_name
            .encode_utf16()
            .into_iter()
            .chain(std::iter::once(0))
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>();
        let forest_name = self
            .forest_name
            .encode_utf16()
            .into_iter()
            .chain(std::iter::once(0))
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>();

        writer.write_u32::<LittleEndian>(self.version)?;
        // TODO
        writer.write(&KeyIdentifier::MAGIC)?;
        writer.write_u32::<LittleEndian>(self.flags)?;

        writer.write_u32::<LittleEndian>(self.l0)?;
        writer.write_u32::<LittleEndian>(self.l1)?;
        writer.write_u32::<LittleEndian>(self.l2)?;

        writer.write(&self.root_key_identifier.to_bytes_le())?;

        writer.write_u32::<LittleEndian>(self.key_info.len().try_into()?)?;
        writer.write_u32::<LittleEndian>(domain_name.len().try_into()?)?;
        writer.write_u32::<LittleEndian>(forest_name.len().try_into()?)?;

        // TODO
        writer.write(&self.key_info)?;
        writer.write(&domain_name)?;
        writer.write(&forest_name)?;

        Ok(())
    }
}

impl Decode for KeyIdentifier {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let version = reader.read_u32::<LittleEndian>()?;

        let mut magic = [0; 4];
        reader.read_exact(&mut magic)?;

        if magic != KeyIdentifier::MAGIC {
            return Err(Error::new(
                ErrorKind::NteInvalidParameter,
                "invalid KeyIdentifier magic bytes",
            ));
        }

        let flags = reader.read_u32::<LittleEndian>()?;

        let l0 = reader.read_u32::<LittleEndian>()?;
        let l1 = reader.read_u32::<LittleEndian>()?;
        let l2 = reader.read_u32::<LittleEndian>()?;
        let root_key_identifier = read_uuid(&mut reader)?;

        let key_info_len = reader.read_u32::<LittleEndian>()? - 2 /* UTF16 null terminator */;
        let domain_len = reader.read_u32::<LittleEndian>()? - 2 /* UTF16 null terminator */;
        let forest_len = reader.read_u32::<LittleEndian>()? - 2 /* UTF16 null terminator */;

        let mut key_info = vec![0; key_info_len.try_into()?];
        reader.read_exact(key_info.as_mut_slice())?;

        let mut domain_name = vec![0; domain_len.try_into()?];
        reader.read_exact(domain_name.as_mut_slice())?;

        let mut forest_name = vec![0; forest_len.try_into()?];
        reader.read_exact(forest_name.as_mut_slice())?;

        Ok(Self {
            version,
            flags,
            l0,
            l1,
            l2,
            root_key_identifier,
            key_info,
            domain_name: utf16_bytes_to_utf8_string(&domain_name)?,
            forest_name: utf16_bytes_to_utf8_string(&forest_name)?,
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
    pub fn get_target_sd(&self) -> DpapiResult<Vec<u8>> {
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

    pub fn encode_asn1(&self) -> DpapiResult<Vec<u8>> {
        Ok(picky_asn1_der::to_vec(&GeneralProtectionDescriptor {
            descriptor_type: ObjectIdentifierAsn1::from(oids::sid_protection_descriptor()),
            descriptors: Asn1SequenceOf::from(vec![Asn1SequenceOf::from(vec![ProtectionDescriptor {
                descriptor_type: Utf8StringAsn1::from(Utf8String::from_string("SID".to_owned())?),
                descriptor_value: Utf8StringAsn1::from(Utf8String::from_string(self.sid.clone())?),
            }])]),
        })?)
    }

    pub fn decode_asn1(data: &[u8]) -> DpapiResult<Self> {
        let general_protection_descriptor: GeneralProtectionDescriptor = picky_asn1_der::from_bytes(data)?;

        if general_protection_descriptor.descriptor_type.0 != oids::sid_protection_descriptor() {
            return Err(Error::new(
                ErrorKind::NteInvalidParameter,
                "invalid protection descriptor type: expected sid",
            ));
        }

        let ProtectionDescriptor {
            descriptor_type,
            descriptor_value,
        } = general_protection_descriptor
            .descriptors
            .0
            .get(0)
            .ok_or_else(|| Error::new(ErrorKind::NteInvalidParameter, "invalid protection descriptor data"))?
            .0
            .get(0)
            .ok_or_else(|| Error::new(ErrorKind::NteInvalidParameter, "invalid protection descriptor data"))?;

        if descriptor_type.0.as_utf8() != "SID" {
            return Err(Error::new(
                ErrorKind::NteInvalidParameter,
                "invalid protection descriptor data",
            ));
        }

        Ok(Self {
            sid: descriptor_value.0.as_utf8().to_owned(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpapiBlob {
    pub key_identifier: KeyIdentifier,
    pub protection_descriptor: SidProtectionDescriptor,
    pub enc_cek: Vec<u8>,
    pub enc_cek_algorithm_id: KeyEncryptionAlgorithmIdentifier,
    pub enc_content: Vec<u8>,
    pub enc_content_algorithm_id: ContentEncryptionAlgorithmIdentifier,
}

impl DpapiBlob {
    // blob_in_envelope: true to store the encrypted blob in the
    // EnvelopedData structure (NCryptProtectSecret general), `false` to
    // append the encrypted blob after the EnvelopedData structure
    // (LAPS style).
    fn encode(&self, blob_in_envelope: bool, mut writer: impl Write) -> DpapiResult<()> {
        picky_asn1_der::to_writer(
            &EncapsulatedContentInfo {
                content_type: ObjectIdentifierAsn1::from(oids::enveloped_data()),
                content: Some(ExplicitContextTag0::from(ContentValue::Data(OctetStringAsn1::from(
                    picky_asn1_der::to_vec(&EnvelopedData {
                        version: CmsVersion::V2,
                        originator_info: Optional::from(None),
                        recipient_infos: RecipientInfos::from(vec![RecipientInfo::Kek(KekRecipientInfo {
                            version: CmsVersion::V2,
                            kek_id: KekIdentifier {
                                key_identifier: OctetStringAsn1::from(self.key_identifier.encode_to_vec()?),
                                date: Optional::from(None),
                                other: Optional::from(Some(OtherKeyAttribute {
                                    key_attr_id: ObjectIdentifierAsn1::from(oids::microsoft_software()),
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
                    })?,
                )))),
            },
            &mut writer,
        )?;

        if !blob_in_envelope {
            // TODO
            writer.write(&self.enc_content)?;
        }

        Ok(())
    }
}

impl Decode for DpapiBlob {
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let content_info: EncapsulatedContentInfo = picky_asn1_der::from_reader(&mut reader)?;

        if content_info.content_type.0 != oids::enveloped_data() {
            return Err(Error::new(
                ErrorKind::NteInvalidParameter,
                "invalid content type: expected enveloped data",
            ));
        }

        let enveloped_data: EnvelopedData = if let Some(content) = content_info.content.as_ref() {
            let enveloped_data = if let ContentValue::Data(data) = &content.0 {
                &data.0
            } else {
                return Err(Error::new(
                    ErrorKind::NteInvalidParameter,
                    "invalid content value: expected ContentValue::Data",
                ));
            };

            picky_asn1_der::from_bytes(enveloped_data)?
        } else {
            return Err(Error::new(
                ErrorKind::NteInvalidParameter,
                "missing enveloped_data in content info",
            ));
        };

        if enveloped_data.version != CmsVersion::V2 {
            return Err(Error::new(
                ErrorKind::NteInvalidParameter,
                "invalid enveloped data version: expected CmsVersion::V2",
            ));
        }

        if enveloped_data.recipient_infos.0.len() != 1 {
            return Err(Error::new(
                ErrorKind::NteInvalidParameter,
                "invalid enveloped data recipient infos: expected exactly one recipient info",
            ));
        }

        let recipient_info = enveloped_data.recipient_infos.0.get(0).unwrap();
        let kek_info = match recipient_info {
            RecipientInfo::Kek(kek_recipient_info) => kek_recipient_info,
        };

        if kek_info.version != CmsVersion::V4 {
            return Err(Error::new(
                ErrorKind::NteInvalidParameter,
                "invalid recipient version: expected CmsVersion::V4",
            ));
        }

        let key_identifier = KeyIdentifier::decode(&kek_info.kek_id.key_identifier.0 as &[u8])?;

        let protection_descriptor = if let Some(OtherKeyAttribute { key_attr_id, key_attr }) = &kek_info.kek_id.other.0
        {
            if key_attr_id.0 != oids::microsoft_software() {
                return Err(Error::new(
                    ErrorKind::NteInvalidParameter,
                    "invalid kek recipient info other attribute oid",
                ));
            }

            if let Some(encoded_protection_descriptor) = key_attr {
                SidProtectionDescriptor::decode_asn1(&encoded_protection_descriptor.0)?
            } else {
                return Err(Error::new(
                    ErrorKind::NteInvalidParameter,
                    "invalid kek recipient info other attribute: missing value",
                ));
            }
        } else {
            return Err(Error::new(
                ErrorKind::NteInvalidParameter,
                "invalid kek recipient info: missing protection descriptor",
            ));
        };

        let enc_content = if let Some(enc_content) = enveloped_data.encrypted_content_info.encrypted_content.0 {
            // Some DPAPI blobs don't include the content in the PKCS7 payload but
            // just append after the blob.
            if enc_content.0 .0.is_empty() {
                read_to_end(reader)?
            } else {
                enc_content.0 .0
            }
        } else {
            return Err(Error::new(
                ErrorKind::NteInvalidParameter,
                "invalid enveloped data: missing encrypted content info",
            ));
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

pub fn utf16_bytes_to_utf8_string(data: &[u8]) -> DpapiResult<String> {
    debug_assert_eq!(data.len() % 2, 0);

    Ok(String::from_utf16(
        &data
            .chunks(2)
            .map(|c| u16::from_le_bytes(c.try_into().unwrap()))
            .collect::<Vec<u16>>(),
    )?)
}
