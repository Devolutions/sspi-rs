#![cfg(not(target_os = "windows"))]

use core::ffi::{c_long, c_ulong};
use std::borrow::Cow;
use std::env;
use std::ffi::CString;

use libc::{dlopen, dlsym, RTLD_LOCAL, RTLD_LAZY};
use winscard::{Error, ErrorKind, WinScardResult};

use crate::winscard::pcsc_lite::functions::PcscLiteApiFunctionTable;

pub mod functions;

pub type ScardStatus = c_long;

pub type Dword = c_ulong;

pub type LpDword = *mut Dword;

/// `hContext` returned by `SCardEstablishContext()`.
///
/// https://pcsclite.apdu.fr/api/pcsclite_8h.html#a22530ffaff18b5d3e32260a5f1ce4abd
pub type ScardContext = c_long;

/// Pointer to the [ScardContext].
pub type LpScardContext = *mut ScardContext;

/// `hCard` returned by `SCardConnect()`.
///
/// https://pcsclite.apdu.fr/api/pcsclite_8h.html#af328aca3e11de737ecd771bcf1f75fb5
pub type ScardHandle = c_long;

/// Pointer to the [ScardHandle].
pub type LpScardHandle = *mut ScardHandle;

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
    pub struct State: Dword {
        const Absent = 0x0002;
        const Present = 0x0004;
        const Swallowed = 0x0008;
        const Powered = 0x0010;
        const Negotiable = 0x0020;
        const Specific = 0x0040;
    }
}

impl From<State> for winscard::winscard::State {
    fn from(value: State) -> Self {
        if let Ok(s) = Self::try_from(value.bits() as u32) {
            s
        } else {
            Self::Specific
        }
    }
}

/// Path to the `pcsc-lite` library.
///
/// The user can use this environment variable to customize the `pcsc-lite` library loading.
const PCSC_LITE_LIB_PATH_ENV: &str = "PCSC_LITE_LIB_PATH";

pub fn initialize_pcsc_lite_api() -> WinScardResult<PcscLiteApiFunctionTable> {
    let pcsc_lite_path = if let Ok(lib_path) = env::var(PCSC_LITE_LIB_PATH_ENV) {
        Cow::Owned(lib_path)
    } else {
        Cow::Borrowed("libpcsclite.so.1")
    };
    let pcsc_lite_path = CString::new(pcsc_lite_path.as_ref())?;

    // SAFETY: The library path is type checked.
    let handle = unsafe { dlopen(pcsc_lite_path.as_ptr(), RTLD_LOCAL | RTLD_LAZY) };
    if handle.is_null() {
        return Err(Error::new(ErrorKind::InternalError, format!("Can not load pcsc-lite library: {}", pcsc_lite_path.to_str().unwrap())));
    }

    macro_rules! load_fn {
        ($func_name:literal) => {{
            let fn_name = CString::new($func_name).expect("CString creation should not fail");
            // SAFETY: The `handle` is initialized and checked above. The function name should be correct
            // because it's hardcoded in the code.
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

#[cfg(test)]
pub mod tests {
    use super::{ScardContext, ScardHandle};

    #[test]
    fn load_api_table() {
        use std::mem::size_of;

        super::initialize_pcsc_lite_api().unwrap();
        println!("{} {}", size_of::<ScardContext>(), size_of::<ScardHandle>())
    }
}
