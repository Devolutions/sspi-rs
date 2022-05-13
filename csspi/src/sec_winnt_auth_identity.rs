use libc::{c_char, c_uint, c_ulong, c_ushort};

#[repr(C)]
pub struct SecWinntAuthIdentityW {
    pub user: *const c_ushort,
    pub user_length: c_ulong,
    pub domain: *const c_ushort,
    pub domain_length: c_ulong,
    pub password: *const c_ushort,
    pub password_length: c_ulong,
    pub flags: c_ulong,
}

#[repr(C)]
pub struct SecWinntAuthIdentityA {
    pub user: *const c_char,
    pub user_length: c_uint,
    pub domain: *const c_char,
    pub domain_length: c_uint,
    pub password: *const c_char,
    pub password_length: c_uint,
    pub flags: c_uint,
}
