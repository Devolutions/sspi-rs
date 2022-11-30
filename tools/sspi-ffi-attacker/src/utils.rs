use std::{slice::from_raw_parts};

use libc::{c_void, dlopen, RTLD_LOCAL, RTLD_LAZY, dlsym};

use crate::types::SEC_WCHAR;

pub unsafe fn load_library(path_to_dll: &str) -> *mut c_void {
    let lp_file_name = path_to_dll.as_ptr() as *const _;
    // let lp_file_name = path_to_dll.as_ptr();
    // let sspi_handle = LoadLibraryA(lp_file_name);
    let sspi_handle = dlopen(lp_file_name, RTLD_LOCAL | RTLD_LAZY);

    if sspi_handle.is_null() {
        panic!("Can not load library: {}", path_to_dll);
    }

    sspi_handle
}

pub unsafe fn get_library_fn(library: *mut c_void, fn_name: &str) -> *mut c_void {
    let fn_addr = dlsym(library, fn_name.as_ptr() as *const _);

    if fn_addr.is_null() {
        panic!("Can not find {} symbol in the loaded library", fn_name);
    }

    fn_addr
}

pub unsafe fn c_w_str_to_string(s: *const SEC_WCHAR) -> String {
    let mut len = 0;

    while *(s.add(len)) != 0 {
        len += 1;
    }

    String::from_utf16_lossy(from_raw_parts(s, len))
}
