#![cfg(not(target_os = "windows"))]

use std::borrow::Cow;
use std::env;
use std::ffi::CString;

use libc::{dlopen, dlsym};
use winscard::{Error, ErrorKind, WinScardResult};

use crate::winscard::pcsc_lite::functions::PcscLiteApiFunctionTable;

pub mod functions;

/// `hContext` returned by `SCardEstablishContext()`.
///
/// https://pcsclite.apdu.fr/api/pcsclite_8h.html#a22530ffaff18b5d3e32260a5f1ce4abd
pub type ScardContext = i32;

/// Pointer to the [ScardContext].
pub type LpScardContext = *mut ScardContext;

/// `hCard` returned by `SCardConnect()`.
///
/// https://pcsclite.apdu.fr/api/pcsclite_8h.html#af328aca3e11de737ecd771bcf1f75fb5
pub type ScardHandle = i32;

/// Pointer to the [ScardHandle].
pub type LpScardHandle = *mut ScardHandle;

/// Path to the `pcsc-lite` library.
///
/// The user can use this environment variable to customize the `pcsc-lite` library loading.
const PCSC_LITE_LIB_PATH_ENV: &str = "PCSC_LITE_LIB_PATH";

pub fn initialize_pcsc_lite_api() -> WinScardResult<PcscLiteApiFunctionTable> {
    let pcsc_lite_path = if let Ok(lib_path) = env::var(PCSC_LITE_LIB_PATH_ENV) {
        Cow::Owned(lib_path)
    } else {
        Cow::Borrowed("libpcsclite")
    };
    // SAFE: Rust string cannot contain `0` bytes.
    let pcsc_lite_path = CString::new(pcsc_lite_path.as_ref()).expect("CString creation should not fail");

    let handle = unsafe { dlopen(pcsc_lite_path.as_ptr(), 0) };
    if handle.is_null() {
        return Err(Error::new(ErrorKind::InternalError, "Can not load pcsc-lite library"));
    }

    macro_rules! load_fn {
        ($func_name:literal) => {{
            let fn_name = CString::new($func_name).expect("CString creation should not fail");
            unsafe { std::mem::transmute(dlsym(handle, fn_name.as_ptr())) }
        }};
    }

    Ok(PcscLiteApiFunctionTable {
        SCardEstablishContext: load_fn!("SCardEstablishContext"),
        SCardReleaseContext: load_fn!("SCardReleaseContext"),
        SCardConnect: load_fn!("SCardConnect"),
        SCardReconnect: load_fn!("SCardReconnect"),
        SCardDisconnect: load_fn!("SCardDisconnect"),
        SCardBeginTransaction: load_fn!("SCardBeginTransaction"),
        SCardEndTransaction: load_fn!("SCardEndTransaction"),
        SCardStatus: load_fn!("SCardStatus"),
        SCardGetStatusChange: load_fn!("SCardGetStatusChange"),
        SCardControl: load_fn!("SCardControl"),
        SCardGetAttrib: load_fn!("SCardGetAttrib"),
        SCardSetAttrib: load_fn!("SCardSetAttrib"),
        SCardTransmit: load_fn!("SCardTransmit"),
        SCardListReaders: load_fn!("SCardListReaders"),
        SCardFreeMemory: load_fn!("SCardFreeMemory"),
        SCardListReaderGroups: load_fn!("SCardListReaderGroups"),
        SCardCancel: load_fn!("SCardCancel"),
        SCardIsValidContext: load_fn!("SCardIsValidContext"),
    })
}
