use alloc::vec::Vec;

pub fn ber_tlv_length_encoding(length: usize) -> Vec<u8> {
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
