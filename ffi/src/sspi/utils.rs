use sspi::Result;

use super::sec_handle::SecHandle;

/// Logs the address and the raw `dw_lower`/`dw_upper` values of a credentials or context handle.
///
/// Used to trace handle lifetimes across SSPI calls (which handle the caller allocated, which one it
/// passed back, and whether it reused a freed one).
///
/// # Safety
///
/// The caller have to ensure that either the pointer is null or the pointer is [convertible to a reference](https://doc.rust-lang.org/std/ptr/index.html#pointer-to-reference-conversion).
pub unsafe fn log_sec_handle(label: &str, sec_handle: *const SecHandle) {
    // SAFETY: `sec_handle` is either null or it is convertible to a reference.
    let handle = unsafe { sec_handle.as_ref() };

    debug!(handle_addr = ?sec_handle, handle_value = ?handle, "{label}");
}

pub fn hostname() -> Result<String> {
    // We run tests with Miri. Miri is the Rust's mid-level intermediate representation interpreter.
    // It is unable to execute system calls. Thus, Miri cannot execute `whoami::hostname()`.
    // So, we decided to keep hardcoded hostname.
    #[cfg(miri)]
    {
        Ok("test-vm".into())
    }
    #[cfg(not(miri))]
    {
        use sspi::{Error, ErrorKind};

        whoami::hostname().map_err(|err| {
            Error::new(
                ErrorKind::InternalError,
                format!("can not query the system hostname: {err:?}"),
            )
        })
    }
}
