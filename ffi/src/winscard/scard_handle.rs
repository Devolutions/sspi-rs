use ffi_types::winscard::ScardHandle;
use winscard::winscard::WinScard;

pub fn scard_handle_to_winscard(handle: ScardHandle) -> *mut Box<dyn WinScard> {
    handle as *mut Box<dyn WinScard>
}