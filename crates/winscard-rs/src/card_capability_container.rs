use alloc::vec::Vec;

use crate::{WinScardResult, tlv_tags};

pub fn build_ccc() -> Vec<u8> {
    let mut ccc = Vec::new();

    ccc.extend_from_slice(&[tlv_tags::DATA, 0x33]);

    // Card Identifier
    ccc.extend_from_slice(&[0xf0, 21, 160, 0, 0, 1, 22, 255, 2, 62, 243, 197, 122, 122, 55, 197, 117, 56, 169, 61, 186, 177, 253]);
    // Capability Container version number
    ccc.extend_from_slice(&[0xf1, 0x01, 0x21]);
    // Capability Grammar version number
    ccc.extend_from_slice(&[0xf2, 0x01, 0x21]);
    // Applications CardURL
    ccc.extend_from_slice(&[0xf3, 0x00]);
    // PKCS#15
    ccc.extend_from_slice(&[0xf4, 0x01, 0x00]);
    // Registered Data Model number
    ccc.extend_from_slice(&[0xf5, 0x01, 0x10]);
    // Access Control Rule Table
    ccc.extend_from_slice(&[0xf6, 0x00]);
    // Card APDUs
    ccc.extend_from_slice(&[0xf7, 0x00]);
    // Redirection Tag
    ccc.extend_from_slice(&[0xfa, 0x00]);
    // Capability Tuples (CTs)
    ccc.extend_from_slice(&[0xfb, 0x00]);
    // Status Tuples (STs)
    ccc.extend_from_slice(&[0xfc, 0x00]);
    // Next CCC
    ccc.extend_from_slice(&[0xfd, 0x00]);
    // Error Detection Code
    ccc.extend_from_slice(&[0xfe, 0x00]);

    ccc
}

#[cfg(test)]
mod tests {
    use super::build_ccc;

    #[test]
    fn test() {
        let expected = [0x53, 0x33, 0xf0, 0x15, 160, 0, 0, 1, 22, 255, 2, 62, 243, 197, 122, 122, 55, 197, 117, 56, 169, 61, 186, 177, 253, 0xf1, 0x01, 0x21,
                       0xf2, 0x01, 0x21, 0xf3, 0x00, 0xf4, 0x01, 0x00, 0xf5, 0x01, 0x10, 0xf6, 0x00, 0xf7,
                       0x00, 0xfa, 0x00, 0xfb, 0x00, 0xfc, 0x00, 0xfd, 0x00, 0xfe, 0x00];
        let actual = build_ccc();

        assert_eq!(&actual, &expected);
    }
}
