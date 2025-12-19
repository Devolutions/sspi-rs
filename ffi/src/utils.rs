use std::slice::from_raw_parts;
use std::string::FromUtf16Error;

use libc::c_char;

pub(crate) fn into_raw_ptr<T>(value: T) -> *mut T {
    Box::into_raw(Box::new(value))
}

/// *Note*: the resulting [String] will contain a null-terminator char at the end.
///
/// # Safety
///
/// Behavior is undefined is any of the following conditions are violated:
///
/// * `s` must be a [valid], null-terminated C string.
pub(crate) unsafe fn c_w_str_to_string(s: *const u16) -> Result<String, FromUtf16Error> {
    // SAFETY: `s` is a valid, null-terminated C string.
    let len = unsafe { w_str_len(s) };

    // SAFETY: `s` is a valid, null-terminated C string.
    String::from_utf16(unsafe { from_raw_parts(s, len) })
}

/// The returned length includes the null terminator char.
///
/// # Safety
///
/// Behavior is undefined is any of the following conditions are violated:
///
/// * `s` must be a [valid], null-terminated C string.
pub(crate) unsafe fn w_str_len(s: *const u16) -> usize {
    let mut len = 0;

    while {
        // SAFETY: `s` is a valid, null-terminated C string.
        let s = unsafe { s.add(len) };
        // SAFETY: `s` is a valid, null-terminated C string.
        unsafe { *s }
    } != 0
    {
        len += 1;
    }

    len
}

/// Converts raw credentials string into [Vec] of bytes.
///
/// Credentials are often represented as strings. For example, username, domain, password.
/// It is OK for Windows SSPI to accept `null` or empty credential strings. The `AcquireCredentialsHandle`
/// function will return successful status code is we pass the `null` username value. Thus, this function
/// will return an empty [Vec] in such a case. It is done on purpose to follow the Windows SSPI behavior.
///
/// # Safety
///
/// * the `raw_buffer` pointer can be null.
/// * if `raw_buffer` is not null, then it must be valid for reads for `len` many bytes, and it must be properly aligned.
/// * The total size `len` of the slice must be no larger than `isize::MAX`, and adding that size to `data`
///   must not "wrap around" the address space.
pub(crate) unsafe fn credentials_str_into_bytes(raw_buffer: *const c_char, len: usize) -> Vec<u8> {
    if !raw_buffer.is_null() {
        // SAFETY:
        // - `raw_buffer` is guaranteed to be non-null due to the prior check.
        // - `raw_buffer` is valid for reads for `len` many bytes.
        unsafe { from_raw_parts(raw_buffer as *const u8, len) }.to_vec()
    } else {
        Vec::new()
    }
}

#[cfg(any(feature = "scard", feature = "tsssp"))]
pub(crate) fn str_encode_utf16(data: &str) -> Vec<u8> {
    data.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}
