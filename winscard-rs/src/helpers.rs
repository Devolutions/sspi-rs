use alloc::format;
use alloc::vec::Vec;

use chrono::{Duration, Utc};
use iso7816_tlv::simple::{Tag, Tlv};
use uuid::Uuid;

use crate::Result;

// The CHUID has to be encoded manually because for some weird reason all nested tags use the SIMPLE-TLV encoding.
// This makes it impossible to encode this particular object using iso7816_tlv crate (or any other BER-TLV crate out there)
pub(crate) fn build_chuid() -> [u8; 61] {
    // We do this by hand, because iso7816_tlv uses Vecs when constructing a new TLV value
    // By avoiding using Tlv::new(), we can avoid allocating a new Vec for each TLV value and use slices instead
    let mut chuid = Vec::with_capacity(61);
    chuid.extend_from_slice(&[tlv_tags::DATA, 0x3B]);
    chuid.extend_from_slice(&[tlv_tags::FASC_N, 0x19]);
    // The FASC-N number is encoded using the BCD 4-Bit decimal format with odd parity as per https://www.idmanagement.gov/docs/pacs-tig-scepacs.pdf
    // The unencoded value is (whitespaces were added for readability): SS 9999 FS 9999 FS 999999 FS 0 FS 1 FS 0000000000 3 0000 1 ES LRC
    // The Agency Code is set to 9999 as stated in section 6.4
    // The system code and credential number can both be set to any number
    chuid.extend_from_slice(&[
        0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83, 0x68, 0x58, 0x21, 0x08, 0x42, 0x10,
        0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3, 0xeb,
    ]);
    chuid.extend_from_slice(&[tlv_tags::GUID, 0x10]);
    // Section 3.4.1 of https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf
    let uuid = Uuid::new_v4();
    chuid.extend_from_slice(uuid.as_bytes());
    chuid.extend_from_slice(&[tlv_tags::EXPIRATION_DATE, 0x8]);
    // Section 3.1.2 of https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf
    let year_from_today = Utc::now() + Duration::weeks(48);
    chuid.extend_from_slice(format!("{}", year_from_today.format("%Y%m%d")).as_bytes());
    chuid.extend_from_slice(&[tlv_tags::ISSUER_SIGNATURE, 0x0]);
    chuid.extend_from_slice(&[tlv_tags::ERROR_DETECTION_CODE, 0x0]);
    // won't fail, as chuid is of fixed length
    chuid.try_into().unwrap()
}

// The X.509 Certificate for PIV Authentication has to be encoded manually because for some weird reason all nested tags use the SIMPLE-TLV encoding.
// This makes it impossible to encode this particular object using iso7816_tlv crate (or any other BER-TLV crate out there)
pub(crate) fn build_auth_cert(auth_cert: Vec<u8>) -> Result<Vec<u8>> {
    // SIMPLE-TLV encoding
    // We do use Tlv::new() here to avoid calculating SIMPLE-TLV length ourselves (as a certificate is most certainly > 254 bytes in length)
    let certificate = Tlv::new(Tag::try_from(tlv_tags::CERTIFICATE)?, auth_cert)?.to_vec();
    // 0x00 indicates that the certificate is uncompressed
    // NIST.SP.800-73-4, Part 1, Appendix A, table 39
    let cert_info = &[tlv_tags::CERT_INFO, 0x01, 0x00];
    // NIST.SP.800-73-4, Part 1, Appendix A, table 10
    let edc = &[tlv_tags::ERROR_DETECTION_CODE, 0x00];
    let data_value_len = certificate.len() + cert_info.len() + edc.len();
    // BER-TLV encoding of the data_value_len
    let encoded_data_value_len = ber_tlv_length_encoding(data_value_len);
    let mut result: Vec<u8> = Vec::with_capacity(1 + encoded_data_value_len.len() + data_value_len);
    result.extend_from_slice(&[tlv_tags::DATA]);
    result.extend_from_slice(&encoded_data_value_len);
    result.extend_from_slice(&certificate);
    result.extend_from_slice(cert_info);
    result.extend_from_slice(edc);
    Ok(result)
}

fn ber_tlv_length_encoding(length: usize) -> Vec<u8> {
    // ISO/IEC 7816-4, Section 5.2.2.2
    if length <= 0x7F {
        // length consists of 1 byte
        Vec::from([length as u8])
    } else {
        // if the length is > 0x7F, it consists of N consecutive bytes, where N is the first 7 lower bits of the first byte in the sequence
        let mut result: Vec<u8> = length.to_be_bytes().iter().skip_while(|&x| *x == 0).cloned().collect();
        // add the first byte that indicates how many consecutive bytes represent the object's actual length
        result.insert(0, 0x80 | result.len() as u8);
        result
    }
}

pub mod tlv_tags {
    pub const DATA: u8 = 0x53;
    pub const FASC_N: u8 = 0x30;
    pub const GUID: u8 = 0x34;
    pub const EXPIRATION_DATE: u8 = 0x35;
    pub const ISSUER_SIGNATURE: u8 = 0x3E;
    pub const ERROR_DETECTION_CODE: u8 = 0xFE;
    pub const APPLICATION_PROPERTY_TEMPLATE: u8 = 0x61;
    pub const APPLICATION_IDENTIFIER: u8 = 0x4F;
    pub const COEXISTING_TAG_ALLOCATION_AUTHORITY: u8 = 0x79;
    pub const TAG_LIST: u8 = 0x5C;
    pub const CERTIFICATE: u8 = 0x70;
    pub const CERT_INFO: u8 = 0x71;
    pub const DYNAMIC_AUTHENTICATION_TEMPLATE: u8 = 0x7C;
    pub const DAT_CHALLENGE: u8 = 0x81;
    pub const DAT_RESPONSE: u8 = 0x82;
}
