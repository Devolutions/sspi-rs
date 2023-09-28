use ffi_types::winscard::{ScardContext, ScardHandle};
use winscard::winscard::{WinScard, WinScardContext};

pub fn scard_handle_to_winscard(handle: ScardHandle) -> *mut Box<dyn WinScard> {
    handle as *mut Box<dyn WinScard>
}
pub fn scard_context_to_winscard_context(handle: ScardContext) -> *mut Box<dyn WinScardContext> {
    handle as *mut Box<dyn WinScardContext>
}
