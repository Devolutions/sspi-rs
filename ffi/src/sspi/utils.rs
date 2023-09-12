use sspi::CredentialsBuffers;

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
