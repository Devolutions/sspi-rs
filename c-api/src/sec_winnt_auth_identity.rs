use std::ptr::drop_in_place;

use libc::{c_char, c_uint, c_ulong, c_ushort, c_void};
#[cfg(windows)]
use symbol_rename_macro::rename_symbol;

use crate::check_null;
use crate::sspi_data_types::{SecWChar, SecurityStatus};
use crate::utils::{c_w_str_to_string, into_raw_ptr};

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

#[allow(clippy::missing_safety_doc)]
#[cfg_attr(windows, rename_symbol(to = "Rust_SspiEncodeStringsAsAuthIdentity"))]
#[no_mangle]
pub unsafe extern "system" fn SspiEncodeStringsAsAuthIdentity(
    psz_user_name: *const SecWChar,
    psz_domain_name: *const SecWChar,
    psz_packed_credentials_string: *const SecWChar,
    pp_auth_identity: *mut *mut c_void,
) -> SecurityStatus {
    check_null!(pp_auth_identity);
    check_null!(psz_user_name);
    check_null!(psz_domain_name);
    check_null!(psz_packed_credentials_string);

    let user = c_w_str_to_string(psz_user_name);
    let domain = c_w_str_to_string(psz_domain_name);
    let password = c_w_str_to_string(psz_packed_credentials_string);

    let auth_identity = SecWinntAuthIdentityW {
        user: psz_user_name,
        user_length: user.len().try_into().unwrap(),
        domain: psz_domain_name,
        domain_length: domain.len().try_into().unwrap(),
        password: psz_packed_credentials_string,
        password_length: password.len().try_into().unwrap(),
        flags: 0,
    };

    *pp_auth_identity = into_raw_ptr(auth_identity) as *mut c_void;

    0
}

#[allow(clippy::missing_safety_doc)]
#[cfg_attr(windows, rename_symbol(to = "Rust_SspiFreeAuthIdentity"))]
#[no_mangle]
pub unsafe extern "system" fn SspiFreeAuthIdentity(auth_data: *mut c_void) -> SecurityStatus {
    if auth_data.is_null() {
        return 0;
    }

    let auth_data = auth_data.cast::<SecWinntAuthIdentityW>();

    drop_in_place((*auth_data).user as *mut c_ushort);
    drop_in_place((*auth_data).domain as *mut c_ushort);
    drop_in_place((*auth_data).password as *mut c_ushort);

    drop_in_place(auth_data);

    0
}

#[cfg(test)]
mod tests {
    use std::ptr::null;
    use std::slice::from_raw_parts;

    use libc::c_void;
    use num_traits::ToPrimitive;
    use sspi::ErrorKind;

    use super::{SecWinntAuthIdentityW, SspiEncodeStringsAsAuthIdentity};
    use crate::sec_winnt_auth_identity::SspiFreeAuthIdentity;

    fn get_user_credentials() -> ([u16; 5], [u16; 5], [u16; 7]) {
        // (user, pass, domain)
        (
            [0x75, 0x73, 0x65, 0x72, 0],
            [0x70, 0x61, 0x73, 0x73, 0],
            [0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0],
        )
    }

    #[test]
    fn sspi_encode_strings_as_auth_identity() {
        let (username, password, domain) = get_user_credentials();
        let mut identity = null::<c_void>() as *mut c_void;

        unsafe {
            let status =
                SspiEncodeStringsAsAuthIdentity(username.as_ptr(), domain.as_ptr(), password.as_ptr(), &mut identity);

            assert_eq!(status, 0);
            assert!(!identity.is_null());

            let identity = identity.cast::<SecWinntAuthIdentityW>();

            assert_eq!(
                "user",
                String::from_utf16_lossy(from_raw_parts((*identity).user, (*identity).user_length as usize))
            );
            assert_eq!(
                "pass",
                String::from_utf16_lossy(from_raw_parts(
                    (*identity).password,
                    (*identity).password_length as usize
                ))
            );
            assert_eq!(
                "domain",
                String::from_utf16_lossy(from_raw_parts((*identity).domain, (*identity).domain_length as usize))
            );
        }
    }

    #[test]
    fn sspi_encode_strings_as_auth_identity_on_null() {
        let mut identity = null::<c_void>() as *mut c_void;

        unsafe {
            let status = SspiEncodeStringsAsAuthIdentity(null(), null(), null(), &mut identity);

            assert_eq!(status, ErrorKind::InvalidParameter.to_u32().unwrap());
            assert!(identity.is_null());
        }
    }

    #[test]
    fn sspi_encode_strings_as_auth_identity_on_empty_creds() {
        let username = [0];
        let password = [0];
        let domain = [0];
        let mut identity = null::<c_void>() as *mut c_void;

        unsafe {
            let status =
                SspiEncodeStringsAsAuthIdentity(username.as_ptr(), domain.as_ptr(), password.as_ptr(), &mut identity);

            assert_eq!(status, 0);
            assert!(!identity.is_null());

            let identity = identity.cast::<SecWinntAuthIdentityW>();

            assert_eq!(
                "",
                String::from_utf16_lossy(from_raw_parts((*identity).user, (*identity).user_length as usize))
            );
            assert_eq!(
                "",
                String::from_utf16_lossy(from_raw_parts(
                    (*identity).password,
                    (*identity).password_length as usize
                ))
            );
            assert_eq!(
                "",
                String::from_utf16_lossy(from_raw_parts((*identity).domain, (*identity).domain_length as usize))
            );
        }
    }

    #[test]
    fn sspi_free_auth_identity() {
        let (username, password, domain) = get_user_credentials();
        let mut identity = null::<c_void>() as *mut c_void;

        unsafe {
            SspiEncodeStringsAsAuthIdentity(username.as_ptr(), domain.as_ptr(), password.as_ptr(), &mut identity);

            let status = SspiFreeAuthIdentity(identity);

            assert_eq!(status, 0);
        }
    }

    #[test]
    fn sspi_free_auth_identity_on_null() {
        unsafe {
            let status = SspiFreeAuthIdentity(null::<c_void>() as *mut _);

            assert_eq!(status, 0);
        }
    }
}
