use std::slice::from_raw_parts;

use libc::c_char;

pub fn into_raw_ptr<T>(value: T) -> *mut T {
    Box::into_raw(Box::new(value))
}

pub unsafe fn c_w_str_to_string(s: *const u16) -> String {
    let mut len = 0;

    while *(s.add(len)) != 0 {
        len += 1;
    }

    String::from_utf16_lossy(from_raw_parts(s, len))
}

pub unsafe fn raw_str_into_bytes(raw_buffer: *const c_char, len: usize) -> Vec<u8> {
    from_raw_parts(raw_buffer, len).iter().map(|c| *c as u8).collect()
}
