use sspi::{CredentialsBuffers, Result};

use super::credentials_attributes::CredentialsAttributes;
use super::sec_handle::CredentialsHandle;

/// Transforms a passed pointer to the credentials handle into a triplet of [CredentialsBuffers],
/// security package name, and [CredentialsAttributes].
///
/// # Safety:
///
/// The caller have to ensure that either the pointer is null or the pointer is [convertible to a reference](https://doc.rust-lang.org/std/ptr/index.html#pointer-to-reference-conversion).
pub unsafe fn transform_credentials_handle<'a>(
    credentials_handle: *mut CredentialsHandle,
) -> Option<(CredentialsBuffers, &'a str, &'a CredentialsAttributes)> {
    // SAFETY: `credentials_handle` is not null. We've checked this above.
    unsafe { credentials_handle.as_mut() }.map(|cred_handle| {
        (
            cred_handle.credentials.clone(),
            cred_handle.security_package_name.as_str(),
            &cred_handle.attributes,
        )
    })
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
    // We run tests with Miri. Miri is the Rust's mid-level intermediate representation interpreter.
    // It is unable to execute system calls. Thus, Miri cannot execute `whoami::fallible::hostname()`.
    // So, we decided to keep hardcoded hostname.
    #[cfg(miri)]
    {
        Ok("test-vm".into())
    }
    #[cfg(not(miri))]
    {
        use sspi::{Error, ErrorKind};

        whoami::fallible::hostname().map_err(|err| {
            Error::new(
                ErrorKind::InternalError,
                format!("can not query the system hostname: {:?}", err),
            )
        })
    }
}
