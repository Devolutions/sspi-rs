use std::slice::from_raw_parts;

use libc::c_char;

pub fn into_raw_ptr<T>(value: T) -> *mut T {
    Box::into_raw(Box::new(value))
}

pub unsafe fn c_w_str_to_string(s: *const u16) -> String {
    let mut len = 0;

    while unsafe { *(s.add(len)) } != 0 {
        len += 1;
    }

    String::from_utf16_lossy(unsafe { from_raw_parts(s, len) })
}

pub unsafe fn raw_str_into_bytes(raw_buffer: *const c_char, len: usize) -> Vec<u8> {
    unsafe { from_raw_parts(raw_buffer, len) }
        .iter()
        .map(|c| *c as u8)
        .collect()
}

pub fn str_to_w_buff(data: &str) -> Vec<u16> {
    data.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(feature = "scard")]
pub fn str_encode_utf16(data: &str) -> Vec<u8> {
    data.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}
