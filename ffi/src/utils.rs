use std::slice::from_raw_parts;

use libc::c_char;
use sspi::CredentialsBuffers;

use crate::credentials_attributes::CredentialsAttributes;
use crate::sec_handle::CredentialsHandle;
use crate::sspi_data_types::SecWChar;

pub fn into_raw_ptr<T>(value: T) -> *mut T {
    Box::into_raw(Box::new(value))
}

pub unsafe fn c_w_str_to_string(s: *const SecWChar) -> String {
    let mut len = 0;

    while *(s.add(len)) != 0 {
        len += 1;
    }

    String::from_utf16_lossy(from_raw_parts(s, len))
}

pub unsafe fn raw_str_into_bytes(raw_buffer: *const c_char, len: usize) -> Vec<u8> {
    from_raw_parts(raw_buffer, len).iter().map(|c| *c as u8).collect()
}

pub unsafe fn transform_credentials_handle<'a>(
    credentials_handle: *mut CredentialsHandle,
) -> Option<(CredentialsBuffers, &'a str, &'a CredentialsAttributes)> {
    if credentials_handle.is_null() {
        None
    } else {
        let cred_handle = credentials_handle.as_mut().unwrap();
        Some((
            cred_handle.credentials.clone(),
            cred_handle.security_package_name.as_str(),
            &cred_handle.attributes,
        ))
    }
}

// when encoding an UTF-16 character using two code units, the 16-bit values are chosen from the UTF-16 surrogate range 0xD800–0xDFFF,
// and thus only \0 is encoded by two consecutive null bytes
#[cfg(feature = "tsssp")]
pub fn raw_wide_str_trim_nulls(raw_str: &mut Vec<u8>) {
    let mut len = raw_str.len();
    while len > 2 && raw_str[len - 2..] == [0, 0] {
        raw_str.truncate(len - 2);
        len = raw_str.len();
    }
}
