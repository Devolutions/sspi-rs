#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

#[cfg(target_os = "windows")]
compile_error!("The pcsc-lite-rs crate should be used only on Linux/MacOS. Use windows/windows-sys crated to interact with Windows API.");

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
