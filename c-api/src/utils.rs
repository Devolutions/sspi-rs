use std::slice::from_raw_parts;

use libc::{c_char, c_ushort};
use sspi::AuthIdentityBuffers;

use crate::sec_handle::CredentialsHandle;
use crate::sspi_data_types::{SecChar, SecWChar};

pub fn into_raw_ptr<T>(value: T) -> *mut T {
    Box::into_raw(Box::new(value))
}

pub fn vec_into_raw_ptr<T>(v: Vec<T>) -> *mut T {
    Box::into_raw(v.into_boxed_slice()) as *mut T
}

pub unsafe fn raw_w_str_to_bytes(raw_buffer: *const c_ushort, len: usize) -> Vec<u8> {
    from_raw_parts(raw_buffer, len)
        .iter()
        .flat_map(|w_char| w_char.to_le_bytes())
        .collect()
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

pub unsafe fn c_str_into_string(s: *const SecChar) -> String {
    let mut len = 0;

    while *(s.add(len)) != 0 {
        len += 1;
    }

    String::from_utf8(from_raw_parts(s as *const u8, len).to_vec()).unwrap()
}

pub unsafe fn transform_credentials_handle<'a>(
    credentials_handle: *mut CredentialsHandle,
) -> (Option<AuthIdentityBuffers>, Option<&'a str>) {
    if credentials_handle.is_null() {
        (None, None)
    } else {
        let cred_handle = credentials_handle.as_mut().unwrap();
        (
            Some(cred_handle.credentials.clone()),
            Some(cred_handle.security_package_name.as_str()),
        )
    }
}

#[macro_export]
macro_rules! try_execute {
    ($x:expr) => {{
        match $x {
            Ok(value) => value,
            Err(err) => {
                return err.error_type.to_u32().unwrap();
            }
        }
    }};
}
