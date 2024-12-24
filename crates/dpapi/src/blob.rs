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
use uuid::Uuid;

use crate::rpc::{read_buf, read_to_end, write_buf, Decode, Encode, EncodeExt};
use crate::sid_utils::{ace_to_bytes, sd_to_bytes};
use crate::utils::{encode_utf16_le, utf16_bytes_to_utf8_string};
use crate::{DpapiResult, Error};

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
        let domain_name = encode_utf16_le(&self.domain_name);
        let forest_name = encode_utf16_le(&self.forest_name);

        writer.write_u32::<LittleEndian>(self.version)?;
        write_buf(&KeyIdentifier::MAGIC, &mut writer)?;
        writer.write_u32::<LittleEndian>(self.flags)?;

        writer.write_u32::<LittleEndian>(self.l0)?;
        writer.write_u32::<LittleEndian>(self.l1)?;
        writer.write_u32::<LittleEndian>(self.l2)?;

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
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let version = reader.read_u32::<LittleEndian>()?;

        let mut magic = [0; 4];
        read_buf(&mut magic, &mut reader)?;

        if magic != Self::MAGIC {
            return Err(Error::InvalidMagicBytes(
                "KeyIdentifier",
                Self::MAGIC.as_slice(),
                magic.to_vec(),
            ));
        }

        let flags = reader.read_u32::<LittleEndian>()?;

        let l0 = reader.read_u32::<LittleEndian>()?;
        let l1 = reader.read_u32::<LittleEndian>()?;
        let l2 = reader.read_u32::<LittleEndian>()?;
        let root_key_identifier = Uuid::decode(&mut reader)?;

        let key_info_len = reader.read_u32::<LittleEndian>()?;
        let domain_len = reader.read_u32::<LittleEndian>()? - 2 /* UTF16 null terminator */;
        let forest_len = reader.read_u32::<LittleEndian>()? - 2 /* UTF16 null terminator */;

        let mut key_info = vec![0; key_info_len.try_into()?];
        read_buf(key_info.as_mut_slice(), &mut reader)?;

        let mut domain_name = vec![0; domain_len.try_into()?];
        read_buf(domain_name.as_mut_slice(), &mut reader)?;
        // Read UTF16 null terminator.
        reader.read_u16::<LittleEndian>()?;

        let mut forest_name = vec![0; forest_len.try_into()?];
        read_buf(forest_name.as_mut_slice(), &mut reader)?;
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
            return Err(Error::UnsupportedProtectionDescriptor(
                general_protection_descriptor.descriptor_type.0.into(),
            ));
        }

        let ProtectionDescriptor {
            descriptor_type,
            descriptor_value,
        } = general_protection_descriptor
            .descriptors
            .0
            .get(0)
            .ok_or_else(|| Error::InvalidProtectionDescriptor("missing ASN1 sequence".into()))?
            .0
            .get(0)
            .ok_or_else(|| Error::InvalidProtectionDescriptor("missing ASN1 sequence".into()))?;

        if descriptor_type.0.as_utf8() != "SID" {
            return Err(Error::UnsupportedProtectionDescriptor(
                descriptor_type.0.as_utf8().to_owned(),
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
    fn decode(mut reader: impl Read) -> DpapiResult<Self> {
        let content_info: ContentInfo = picky_asn1_der::from_reader(&mut reader)?;

        if content_info.content_type.0 != oids::enveloped_data() {
            let expected_content_type: String = oids::enveloped_data().into();
            let actual_content_type: String = content_info.content_type.0.into();

            return Err(Error::InvalidValue(
                "content info type",
                format!("expected {expected_content_type} but got {actual_content_type}"),
            ));
        }

        let enveloped_data: EnvelopedData = picky_asn1_der::from_bytes(&content_info.content.0 .0)?;

        if enveloped_data.version != CmsVersion::V2 {
            return Err(Error::InvalidValue(
                "enveloped data CMS version",
                format!("expected {:?} but got {:?}", CmsVersion::V2, enveloped_data.version,),
            ));
        }

        if enveloped_data.recipient_infos.0.len() != 1 {
            return Err(Error::InvalidValue(
                "recipient infos",
                format!(
                    "expected exactly 1 recipient info but got {}",
                    enveloped_data.recipient_infos.0.len(),
                ),
            ));
        }

        let recipient_info = enveloped_data.recipient_infos.0.get(0).unwrap();
        let kek_info = match recipient_info {
            RecipientInfo::Kek(kek_recipient_info) => kek_recipient_info,
        };

        if kek_info.version != CmsVersion::V4 {
            return Err(Error::InvalidValue(
                "KEK info CMS version",
                format!("expected {:?} but got {:?}", CmsVersion::V4, enveloped_data.version,),
            ));
        }

        let key_identifier = KeyIdentifier::decode(&kek_info.kek_id.key_identifier.0 as &[u8])?;

        let protection_descriptor = if let Some(OtherKeyAttribute { key_attr_id, key_attr }) = &kek_info.kek_id.other.0
        {
            if key_attr_id.0 != oids::protection_descriptor_type() {
                let expected_descriptor: String = oids::protection_descriptor_type().into();
                let actual_descriptor: String = (&key_attr_id.0).into();

                return Err(Error::InvalidValue(
                    "KEK recipient info OtherAttribute OID",
                    format!("expected {expected_descriptor} but got {actual_descriptor}"),
                ));
            }

            if let Some(encoded_protection_descriptor) = key_attr {
                SidProtectionDescriptor::decode_asn1(&encoded_protection_descriptor.0)?
            } else {
                return Err(Error::MissingValue("KEK recipient info OtherAttribute"));
            }
        } else {
            return Err(Error::MissingValue("KEK recipient info protection descriptor"));
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use picky_asn1_x509::{AesAuthEncParams, AesMode, AesParameters};

    use super::*;

    const DPAPI_BLOB_DATA: &[u8] = &[
        48, 130, 4, 77, 6, 9, 42, 134, 72, 134, 247, 13, 1, 7, 3, 160, 130, 4, 62, 48, 130, 4, 58, 2, 1, 2, 49, 130, 4,
        6, 162, 130, 4, 2, 2, 1, 4, 48, 130, 3, 196, 4, 130, 3, 108, 1, 0, 0, 0, 75, 68, 83, 75, 3, 0, 0, 0, 105, 1, 0,
        0, 16, 0, 0, 0, 3, 0, 0, 0, 113, 194, 120, 215, 37, 144, 130, 154, 246, 220, 184, 150, 11, 138, 216, 197, 8, 3,
        0, 0, 24, 0, 0, 0, 24, 0, 0, 0, 68, 72, 80, 66, 0, 1, 0, 0, 135, 168, 230, 29, 180, 182, 102, 60, 255, 187,
        209, 156, 101, 25, 89, 153, 140, 238, 246, 8, 102, 13, 208, 242, 93, 44, 238, 212, 67, 94, 59, 0, 224, 13, 248,
        241, 214, 25, 87, 212, 250, 247, 223, 69, 97, 178, 170, 48, 22, 195, 217, 17, 52, 9, 111, 170, 59, 244, 41,
        109, 131, 14, 154, 124, 32, 158, 12, 100, 151, 81, 122, 189, 90, 138, 157, 48, 107, 207, 103, 237, 145, 249,
        230, 114, 91, 71, 88, 192, 34, 224, 177, 239, 66, 117, 191, 123, 108, 91, 252, 17, 212, 95, 144, 136, 185, 65,
        245, 78, 177, 229, 155, 184, 188, 57, 160, 191, 18, 48, 127, 92, 79, 219, 112, 197, 129, 178, 63, 118, 182, 58,
        202, 225, 202, 166, 183, 144, 45, 82, 82, 103, 53, 72, 138, 14, 241, 60, 109, 154, 81, 191, 164, 171, 58, 216,
        52, 119, 150, 82, 77, 142, 246, 161, 103, 181, 164, 24, 37, 217, 103, 225, 68, 229, 20, 5, 100, 37, 28, 202,
        203, 131, 230, 180, 134, 246, 179, 202, 63, 121, 113, 80, 96, 38, 192, 184, 87, 246, 137, 150, 40, 86, 222,
        212, 1, 10, 189, 11, 230, 33, 195, 163, 150, 10, 84, 231, 16, 195, 117, 242, 99, 117, 215, 1, 65, 3, 164, 181,
        67, 48, 193, 152, 175, 18, 97, 22, 210, 39, 110, 17, 113, 95, 105, 56, 119, 250, 215, 239, 9, 202, 219, 9, 74,
        233, 30, 26, 21, 151, 63, 179, 44, 155, 115, 19, 77, 11, 46, 119, 80, 102, 96, 237, 189, 72, 76, 167, 177, 143,
        33, 239, 32, 84, 7, 244, 121, 58, 26, 11, 161, 37, 16, 219, 193, 80, 119, 190, 70, 63, 255, 79, 237, 74, 172,
        11, 181, 85, 190, 58, 108, 27, 12, 107, 71, 177, 188, 55, 115, 191, 126, 140, 111, 98, 144, 18, 40, 248, 194,
        140, 187, 24, 165, 90, 227, 19, 65, 0, 10, 101, 1, 150, 249, 49, 199, 122, 87, 242, 221, 244, 99, 229, 233,
        236, 20, 75, 119, 125, 230, 42, 170, 184, 168, 98, 138, 195, 118, 210, 130, 214, 237, 56, 100, 230, 121, 130,
        66, 142, 188, 131, 29, 20, 52, 143, 111, 47, 145, 147, 181, 4, 90, 242, 118, 113, 100, 225, 223, 201, 103, 193,
        251, 63, 46, 85, 164, 189, 27, 255, 232, 59, 156, 128, 208, 82, 185, 133, 209, 130, 234, 10, 219, 42, 59, 115,
        19, 211, 254, 20, 200, 72, 75, 30, 5, 37, 136, 185, 183, 210, 187, 210, 223, 1, 97, 153, 236, 208, 110, 21, 87,
        205, 9, 21, 179, 53, 59, 187, 100, 224, 236, 55, 127, 208, 40, 55, 13, 249, 43, 82, 199, 137, 20, 40, 205, 198,
        126, 182, 24, 75, 82, 61, 29, 178, 70, 195, 47, 99, 7, 132, 144, 240, 14, 248, 214, 71, 209, 72, 212, 121, 84,
        81, 94, 35, 39, 207, 239, 152, 197, 130, 102, 75, 76, 15, 108, 196, 22, 89, 45, 48, 255, 175, 224, 178, 34,
        113, 55, 121, 103, 94, 57, 230, 149, 227, 2, 8, 211, 56, 135, 63, 75, 228, 67, 79, 182, 168, 130, 79, 28, 56,
        65, 78, 255, 48, 67, 5, 243, 1, 170, 131, 242, 24, 216, 174, 93, 89, 249, 12, 215, 25, 248, 12, 146, 191, 38,
        9, 239, 136, 197, 113, 125, 222, 79, 184, 149, 180, 198, 185, 10, 161, 28, 53, 69, 19, 173, 197, 112, 73, 23,
        172, 239, 88, 66, 170, 206, 185, 238, 228, 152, 153, 163, 198, 94, 147, 212, 117, 120, 83, 30, 158, 8, 70, 1,
        73, 134, 237, 77, 162, 147, 56, 224, 231, 179, 30, 110, 19, 55, 253, 176, 115, 101, 171, 146, 59, 227, 37, 145,
        200, 156, 20, 33, 186, 8, 34, 118, 162, 125, 114, 229, 11, 202, 36, 115, 124, 83, 60, 251, 141, 83, 244, 164,
        213, 197, 199, 2, 130, 173, 22, 120, 61, 63, 196, 111, 60, 184, 58, 17, 34, 166, 237, 250, 238, 19, 150, 192,
        123, 172, 162, 70, 227, 90, 165, 58, 139, 124, 87, 199, 135, 30, 146, 142, 203, 133, 133, 54, 26, 54, 229, 134,
        122, 117, 207, 31, 184, 148, 68, 232, 89, 132, 91, 246, 40, 87, 225, 14, 74, 23, 81, 228, 241, 146, 171, 106,
        211, 196, 222, 192, 142, 81, 207, 169, 185, 24, 161, 88, 75, 138, 97, 111, 92, 43, 214, 190, 140, 12, 124, 177,
        67, 125, 237, 147, 195, 41, 40, 100, 0, 111, 0, 109, 0, 97, 0, 105, 0, 110, 0, 46, 0, 116, 0, 101, 0, 115, 0,
        116, 0, 0, 0, 100, 0, 111, 0, 109, 0, 97, 0, 105, 0, 110, 0, 46, 0, 116, 0, 101, 0, 115, 0, 116, 0, 0, 0, 48,
        82, 6, 9, 43, 6, 1, 4, 1, 130, 55, 74, 1, 48, 69, 6, 10, 43, 6, 1, 4, 1, 130, 55, 74, 1, 1, 48, 55, 48, 53, 48,
        51, 12, 3, 83, 73, 68, 12, 44, 83, 45, 49, 45, 53, 45, 50, 49, 45, 51, 51, 51, 55, 51, 51, 55, 57, 55, 51, 45,
        51, 50, 57, 55, 48, 55, 56, 48, 50, 56, 45, 52, 51, 55, 51, 56, 54, 48, 54, 54, 45, 53, 49, 50, 48, 11, 6, 9,
        96, 134, 72, 1, 101, 3, 4, 1, 45, 4, 40, 137, 127, 196, 63, 116, 142, 253, 9, 87, 39, 221, 233, 143, 78, 26,
        111, 251, 157, 65, 99, 211, 159, 179, 116, 208, 73, 199, 61, 137, 105, 12, 126, 250, 69, 230, 190, 17, 158, 13,
        107, 48, 43, 6, 9, 42, 134, 72, 134, 247, 13, 1, 7, 1, 48, 30, 6, 9, 96, 134, 72, 1, 101, 3, 4, 1, 46, 48, 17,
        4, 12, 158, 91, 46, 23, 194, 63, 4, 252, 53, 37, 225, 24, 2, 1, 16, 228, 205, 246, 84, 114, 42, 73, 213, 95,
        83, 8, 85, 14, 196, 232, 170, 198, 208, 190, 73, 81, 22, 246, 19, 42, 77, 89, 23, 159, 215, 19, 142, 201, 75,
        83, 110, 37, 17, 213, 202, 13, 55, 141, 236, 60, 66, 61, 85, 197, 10, 96, 220, 65, 143, 144, 23, 130, 72, 70,
        224, 43, 98, 4, 200, 179, 39, 60, 159, 196, 67, 55, 99, 148, 71, 59, 249, 123, 220, 85, 128, 9, 81, 173, 249,
        35, 141, 138, 2, 255, 224, 56, 205, 77, 123, 22, 1, 47, 122, 232, 184, 121, 3, 224, 80, 0, 216, 227, 16, 222,
        27, 45, 28, 163, 68, 178, 242, 103, 58, 61, 90, 92, 77, 228, 99, 38, 75, 149, 100, 235, 158, 176, 76, 82, 113,
        28, 51, 197, 167, 169, 116, 13, 102, 84, 136, 85, 182,
    ];

    fn testing_blob() -> DpapiBlob {
        DpapiBlob {
            key_identifier: KeyIdentifier {
                version: 1,
                flags: 3,
                l0: 361,
                l1: 16,
                l2: 3,
                root_key_identifier: Uuid::from_str("d778c271-9025-9a82-f6dc-b8960b8ad8c5").unwrap(),
                key_info: vec![
                    68, 72, 80, 66, 0, 1, 0, 0, 135, 168, 230, 29, 180, 182, 102, 60, 255, 187, 209, 156, 101, 25, 89,
                    153, 140, 238, 246, 8, 102, 13, 208, 242, 93, 44, 238, 212, 67, 94, 59, 0, 224, 13, 248, 241, 214,
                    25, 87, 212, 250, 247, 223, 69, 97, 178, 170, 48, 22, 195, 217, 17, 52, 9, 111, 170, 59, 244, 41,
                    109, 131, 14, 154, 124, 32, 158, 12, 100, 151, 81, 122, 189, 90, 138, 157, 48, 107, 207, 103, 237,
                    145, 249, 230, 114, 91, 71, 88, 192, 34, 224, 177, 239, 66, 117, 191, 123, 108, 91, 252, 17, 212,
                    95, 144, 136, 185, 65, 245, 78, 177, 229, 155, 184, 188, 57, 160, 191, 18, 48, 127, 92, 79, 219,
                    112, 197, 129, 178, 63, 118, 182, 58, 202, 225, 202, 166, 183, 144, 45, 82, 82, 103, 53, 72, 138,
                    14, 241, 60, 109, 154, 81, 191, 164, 171, 58, 216, 52, 119, 150, 82, 77, 142, 246, 161, 103, 181,
                    164, 24, 37, 217, 103, 225, 68, 229, 20, 5, 100, 37, 28, 202, 203, 131, 230, 180, 134, 246, 179,
                    202, 63, 121, 113, 80, 96, 38, 192, 184, 87, 246, 137, 150, 40, 86, 222, 212, 1, 10, 189, 11, 230,
                    33, 195, 163, 150, 10, 84, 231, 16, 195, 117, 242, 99, 117, 215, 1, 65, 3, 164, 181, 67, 48, 193,
                    152, 175, 18, 97, 22, 210, 39, 110, 17, 113, 95, 105, 56, 119, 250, 215, 239, 9, 202, 219, 9, 74,
                    233, 30, 26, 21, 151, 63, 179, 44, 155, 115, 19, 77, 11, 46, 119, 80, 102, 96, 237, 189, 72, 76,
                    167, 177, 143, 33, 239, 32, 84, 7, 244, 121, 58, 26, 11, 161, 37, 16, 219, 193, 80, 119, 190, 70,
                    63, 255, 79, 237, 74, 172, 11, 181, 85, 190, 58, 108, 27, 12, 107, 71, 177, 188, 55, 115, 191, 126,
                    140, 111, 98, 144, 18, 40, 248, 194, 140, 187, 24, 165, 90, 227, 19, 65, 0, 10, 101, 1, 150, 249,
                    49, 199, 122, 87, 242, 221, 244, 99, 229, 233, 236, 20, 75, 119, 125, 230, 42, 170, 184, 168, 98,
                    138, 195, 118, 210, 130, 214, 237, 56, 100, 230, 121, 130, 66, 142, 188, 131, 29, 20, 52, 143, 111,
                    47, 145, 147, 181, 4, 90, 242, 118, 113, 100, 225, 223, 201, 103, 193, 251, 63, 46, 85, 164, 189,
                    27, 255, 232, 59, 156, 128, 208, 82, 185, 133, 209, 130, 234, 10, 219, 42, 59, 115, 19, 211, 254,
                    20, 200, 72, 75, 30, 5, 37, 136, 185, 183, 210, 187, 210, 223, 1, 97, 153, 236, 208, 110, 21, 87,
                    205, 9, 21, 179, 53, 59, 187, 100, 224, 236, 55, 127, 208, 40, 55, 13, 249, 43, 82, 199, 137, 20,
                    40, 205, 198, 126, 182, 24, 75, 82, 61, 29, 178, 70, 195, 47, 99, 7, 132, 144, 240, 14, 248, 214,
                    71, 209, 72, 212, 121, 84, 81, 94, 35, 39, 207, 239, 152, 197, 130, 102, 75, 76, 15, 108, 196, 22,
                    89, 45, 48, 255, 175, 224, 178, 34, 113, 55, 121, 103, 94, 57, 230, 149, 227, 2, 8, 211, 56, 135,
                    63, 75, 228, 67, 79, 182, 168, 130, 79, 28, 56, 65, 78, 255, 48, 67, 5, 243, 1, 170, 131, 242, 24,
                    216, 174, 93, 89, 249, 12, 215, 25, 248, 12, 146, 191, 38, 9, 239, 136, 197, 113, 125, 222, 79,
                    184, 149, 180, 198, 185, 10, 161, 28, 53, 69, 19, 173, 197, 112, 73, 23, 172, 239, 88, 66, 170,
                    206, 185, 238, 228, 152, 153, 163, 198, 94, 147, 212, 117, 120, 83, 30, 158, 8, 70, 1, 73, 134,
                    237, 77, 162, 147, 56, 224, 231, 179, 30, 110, 19, 55, 253, 176, 115, 101, 171, 146, 59, 227, 37,
                    145, 200, 156, 20, 33, 186, 8, 34, 118, 162, 125, 114, 229, 11, 202, 36, 115, 124, 83, 60, 251,
                    141, 83, 244, 164, 213, 197, 199, 2, 130, 173, 22, 120, 61, 63, 196, 111, 60, 184, 58, 17, 34, 166,
                    237, 250, 238, 19, 150, 192, 123, 172, 162, 70, 227, 90, 165, 58, 139, 124, 87, 199, 135, 30, 146,
                    142, 203, 133, 133, 54, 26, 54, 229, 134, 122, 117, 207, 31, 184, 148, 68, 232, 89, 132, 91, 246,
                    40, 87, 225, 14, 74, 23, 81, 228, 241, 146, 171, 106, 211, 196, 222, 192, 142, 81, 207, 169, 185,
                    24, 161, 88, 75, 138, 97, 111, 92, 43, 214, 190, 140, 12, 124, 177, 67, 125, 237, 147, 195, 41, 40,
                ],
                domain_name: "domain.test".into(),
                forest_name: "domain.test".into(),
            },
            protection_descriptor: SidProtectionDescriptor {
                sid: "S-1-5-21-3337337973-3297078028-437386066-512".into(),
            },
            enc_cek: vec![
                137, 127, 196, 63, 116, 142, 253, 9, 87, 39, 221, 233, 143, 78, 26, 111, 251, 157, 65, 99, 211, 159,
                179, 116, 208, 73, 199, 61, 137, 105, 12, 126, 250, 69, 230, 190, 17, 158, 13, 107,
            ],
            enc_cek_algorithm_id: KeyEncryptionAlgorithmIdentifier::new_aes256_empty(AesMode::Wrap),
            enc_content: vec![
                228, 205, 246, 84, 114, 42, 73, 213, 95, 83, 8, 85, 14, 196, 232, 170, 198, 208, 190, 73, 81, 22, 246,
                19, 42, 77, 89, 23, 159, 215, 19, 142, 201, 75, 83, 110, 37, 17, 213, 202, 13, 55, 141, 236, 60, 66,
                61, 85, 197, 10, 96, 220, 65, 143, 144, 23, 130, 72, 70, 224, 43, 98, 4, 200, 179, 39, 60, 159, 196,
                67, 55, 99, 148, 71, 59, 249, 123, 220, 85, 128, 9, 81, 173, 249, 35, 141, 138, 2, 255, 224, 56, 205,
                77, 123, 22, 1, 47, 122, 232, 184, 121, 3, 224, 80, 0, 216, 227, 16, 222, 27, 45, 28, 163, 68, 178,
                242, 103, 58, 61, 90, 92, 77, 228, 99, 38, 75, 149, 100, 235, 158, 176, 76, 82, 113, 28, 51, 197, 167,
                169, 116, 13, 102, 84, 136, 85, 182,
            ],
            enc_content_algorithm_id: ContentEncryptionAlgorithmIdentifier::new_aes256(
                AesMode::Gcm,
                AesParameters::AuthenticatedEncryptionParameters(AesAuthEncParams::new(
                    vec![158, 91, 46, 23, 194, 63, 4, 252, 53, 37, 225, 24],
                    16,
                )),
            ),
        }
    }

    #[test]
    fn dpapi_blob_decoding() {
        let blob = DpapiBlob::decode(DPAPI_BLOB_DATA).unwrap();

        assert_eq!(testing_blob(), blob);
    }

    #[test]
    fn dpapi_blob_encoding() {
        let blob = testing_blob();

        let mut buf = Vec::new();
        blob.encode(false, &mut buf).unwrap();

        assert_eq!(DPAPI_BLOB_DATA.as_ref(), &buf);
    }
}
