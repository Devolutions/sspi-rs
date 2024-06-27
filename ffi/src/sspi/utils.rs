use sspi::{CredentialsBuffers, Error, ErrorKind, Result};

use super::credentials_attributes::CredentialsAttributes;
use super::sec_handle::CredentialsHandle;

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

// When encoding a UTF-16 character using two code units, the 16-bit values are chosen from
// the UTF-16 surrogate range 0xD800–0xDFFF, and thus only \0 is encoded by two consecutive null bytes.
#[cfg(any(feature = "tsssp", feature = "scard"))]
pub fn raw_wide_str_trim_nulls(raw_str: &mut Vec<u8>) {
    let mut len = raw_str.len();
    while len > 2 && raw_str[len - 2..] == [0, 0] {
        raw_str.truncate(len - 2);
        len = raw_str.len();
    }
}

pub fn hostname() -> Result<String> {
    whoami::fallible::hostname().map_err(|err| {
        Error::new(
            ErrorKind::InternalError,
            format!("can not query the system hostname: {:?}", err),
        )
    })
}
