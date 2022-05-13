use libc::{c_char, c_long, c_ulong, c_ushort, c_void};

pub type SecChar = c_char;

pub type LpStr = *const SecChar;

pub type SecWChar = c_ushort;

pub type LpcWStr = *const SecWChar;

pub type SecurityStatus = u32;

#[repr(C)]
pub struct SecurityInteger {
    pub low_part: c_ulong,
    pub high_part: c_long,
}

pub type PTimeStamp = *mut SecurityInteger;

#[repr(C)]
pub struct SecurityString {
    pub length: c_ushort,
    pub maximum_length: c_ushort,
    pub buffer: *mut c_ushort,
}

pub type PSecurityString = *mut SecurityString;

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct SecPkgContextSizes {
    pub cb_max_token: c_ulong,
    pub cb_max_signature: c_ulong,
    pub cb_block_size: c_ulong,
    pub cb_security_trailer: c_ulong,
}

#[cfg(not(target_os = "windows"))]
#[repr(C)]
pub struct SecPkgContextSizes {
    pub cb_max_token: c_uint,
    pub cb_max_signature: c_uint,
    pub cb_block_size: c_uint,
    pub cb_security_trailer: c_uint,
}

pub type SecGetKeyFn = extern "system" fn(*mut c_void, *mut c_void, u32, *mut *mut c_void, *mut i32);
