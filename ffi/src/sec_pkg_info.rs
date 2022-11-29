use std::ffi::CStr;
use std::mem::size_of;

use libc::{c_char, c_uint, c_ulong, c_ushort, malloc, memcpy};
use sspi::{enumerate_security_packages, PackageInfo, KERBEROS_VERSION};
#[cfg(windows)]
use symbol_rename_macro::rename_symbol;

use crate::sspi_data_types::{SecChar, SecWChar, SecurityStatus};
use crate::utils::{c_w_str_to_string, into_raw_ptr, vec_into_raw_ptr};

#[derive(Debug)]
#[repr(C)]
pub struct SecPkgInfoW {
    pub f_capabilities: c_ulong,
    pub w_version: c_ushort,
    pub w_rpc_id: c_ushort,
    pub cb_max_token: c_ulong,
    pub name: *mut SecWChar,
    pub comment: *mut SecWChar,
}

pub type PSecPkgInfoW = *mut SecPkgInfoW;

#[allow(clippy::useless_conversion)]
impl From<PackageInfo> for &mut SecPkgInfoW {
    fn from(pkg_info: PackageInfo) -> Self {
        let mut name = pkg_info.name.to_string().encode_utf16().collect::<Vec<_>>();
        name.push(0);

        let mut comment = pkg_info.comment.encode_utf16().collect::<Vec<_>>();
        comment.push(0);

        let pkg_name = pkg_info.name.to_string().encode_utf16().collect::<Vec<_>>();
        let name_bytes_len = pkg_name.len() * 2;

        let pkg_comment = pkg_info.comment.encode_utf16().collect::<Vec<_>>();
        let comment_bytes_len = pkg_comment.len() * 2;

        let pkg_info_w_size = size_of::<SecPkgInfoW>();

        unsafe {
            let size = pkg_info_w_size + name_bytes_len + comment_bytes_len;
            let raw_pkg_info = malloc(size);

            let pkg_info_w = (raw_pkg_info as *mut SecPkgInfoW).as_mut().unwrap();

            pkg_info_w.f_capabilities = pkg_info.capabilities.bits() as c_ulong;
            pkg_info_w.w_version = KERBEROS_VERSION as c_ushort;
            pkg_info_w.w_rpc_id = pkg_info.rpc_id;

            let a: c_ulong = pkg_info.max_token_len.try_into().unwrap();
            pkg_info_w.cb_max_token = a;

            let name_ptr = raw_pkg_info.add(pkg_info_w_size);
            memcpy(name_ptr, pkg_name.as_ptr() as *const _, name_bytes_len);
            pkg_info_w.name = name_ptr as *mut _;

            let comment_ptr = name_ptr.add(name_bytes_len);
            memcpy(comment_ptr, pkg_comment.as_ptr() as *const _, comment_bytes_len);
            pkg_info_w.comment = comment_ptr as *mut _;

            (raw_pkg_info as *mut SecPkgInfoW).as_mut().unwrap()
        }
    }
}

#[repr(C)]
pub struct SecPkgInfoA {
    pub f_capabilities: c_uint,
    pub w_version: c_ushort,
    pub w_rpc_id: c_ushort,
    pub cb_max_token: c_uint,
    pub name: *mut SecChar,
    pub comment: *mut SecChar,
}

pub type PSecPkgInfoA = *mut SecPkgInfoA;

#[derive(Debug)]
#[repr(C)]
pub struct SecNegoInfoW {
    pub package_info: *mut SecPkgInfoW,
    pub nego_state: c_ulong,
}

#[derive(Debug)]
#[repr(C)]
pub struct SecNegoInfoA {
    pub package_info: *mut SecPkgInfoA,
    pub nego_state: c_uint,
}

impl From<PackageInfo> for SecPkgInfoA {
    fn from(data: PackageInfo) -> Self {
        let mut name = data.name.to_string().as_bytes().to_vec();
        name.push(0);

        let mut comment = data.comment.as_bytes().to_vec();
        comment.push(0);

        SecPkgInfoA {
            f_capabilities: data.capabilities.bits() as c_uint,
            w_version: KERBEROS_VERSION as c_ushort,
            w_rpc_id: data.rpc_id,
            cb_max_token: data.max_token_len,
            name: vec_into_raw_ptr(name) as *mut c_char,
            comment: vec_into_raw_ptr(comment) as *mut c_char,
        }
    }
}

#[cfg_attr(feature = "debug_mode", instrument(skip_all))]
#[cfg_attr(windows, rename_symbol(to = "Rust_EnumerateSecurityPackagesA"))]
#[no_mangle]
pub unsafe extern "system" fn EnumerateSecurityPackagesA(
    pc_packages: *mut c_ulong,
    pp_package_info: *mut PSecPkgInfoA,
) -> SecurityStatus {
    catch_panic! {
        check_null!(pc_packages);
        check_null!(pp_package_info);

        let packages = try_execute!(enumerate_security_packages());

        *pc_packages = packages.len() as c_ulong;

        *pp_package_info = vec_into_raw_ptr(packages.into_iter().map(SecPkgInfoA::from).collect::<Vec<_>>());

        0
    }
}

pub type EnumerateSecurityPackagesFnA = unsafe extern "system" fn(*mut c_ulong, *mut PSecPkgInfoA) -> SecurityStatus;

#[cfg_attr(feature = "debug_mode", instrument(skip_all))]
#[cfg_attr(windows, rename_symbol(to = "Rust_EnumerateSecurityPackagesW"))]
#[no_mangle]
pub unsafe extern "system" fn EnumerateSecurityPackagesW(
    pc_packages: *mut c_ulong,
    pp_package_info: *mut *mut SecPkgInfoW,
) -> SecurityStatus {
    catch_panic! {
        check_null!(pc_packages);
        check_null!(pp_package_info);

        let packages = try_execute!(enumerate_security_packages());

        *pc_packages = packages.len() as c_ulong;

        let mut size = size_of::<SecPkgInfoW>() * packages.len();
        let mut names = Vec::with_capacity(packages.len());
        let mut comments = Vec::with_capacity(packages.len());

        for package in &packages {
            let mut name = package.name.to_string().encode_utf16().collect::<Vec<_>>();
            name.push(0);
            let mut comment = package.comment.encode_utf16().collect::<Vec<_>>();
            comment.push(0);

            size += (name.len() + comment.len()) * 2;

            names.push(name);
            comments.push(comment);
        }

        let raw_packages = malloc(size);

        let mut package_ptr = raw_packages as *mut SecPkgInfoW;
        let mut data_ptr = raw_packages.add(size_of::<SecPkgInfoW>() * packages.len()) as *mut SecWChar;
        for (i, pkg_info) in packages.iter().enumerate() {
            let pkg_info_w = package_ptr.as_mut().unwrap();

            pkg_info_w.f_capabilities = pkg_info.capabilities.bits() as c_ulong;
            pkg_info_w.w_version = KERBEROS_VERSION as c_ushort;
            pkg_info_w.w_rpc_id = pkg_info.rpc_id;
            pkg_info_w.cb_max_token = pkg_info.max_token_len.try_into().unwrap();

            memcpy(data_ptr as *mut _, names[i].as_ptr() as *const _, names[i].len() * 2);
            pkg_info_w.name = data_ptr as *mut _;
            data_ptr = data_ptr.add(names[i].len());

            memcpy(data_ptr as *mut _, comments[i].as_ptr() as *const _, comments[i].len() * 2);
            pkg_info_w.comment = data_ptr as *mut _;
            data_ptr = data_ptr.add(comments[i].len());

            package_ptr = package_ptr.add(1);
        }

        *pp_package_info = raw_packages as *mut _;

        0
    }
}

pub type EnumerateSecurityPackagesFnW = unsafe extern "system" fn(*mut c_ulong, *mut PSecPkgInfoW) -> SecurityStatus;

#[cfg_attr(feature = "debug_mode", instrument(skip_all))]
#[cfg_attr(windows, rename_symbol(to = "Rust_QuerySecurityPackageInfoA"))]
#[no_mangle]
pub unsafe extern "system" fn QuerySecurityPackageInfoA(
    p_package_name: *const SecChar,
    pp_package_info: *mut PSecPkgInfoA,
) -> SecurityStatus {
    catch_panic! {
        check_null!(p_package_name);
        check_null!(pp_package_info);

        let pkg_name = try_execute!(CStr::from_ptr(p_package_name).to_str(), ErrorKind::InvalidParameter);

        *pp_package_info = try_execute!(enumerate_security_packages())
            .into_iter()
            .find(|pkg| pkg.name.as_ref() == pkg_name)
            .map(|pkg_info| into_raw_ptr(SecPkgInfoA::from(pkg_info)))
            .unwrap();

        0
    }
}

pub type QuerySecurityPackageInfoFnA = unsafe extern "system" fn(*const SecChar, *mut PSecPkgInfoA) -> SecurityStatus;

#[cfg_attr(feature = "debug_mode", instrument(skip_all))]
#[cfg_attr(windows, rename_symbol(to = "Rust_QuerySecurityPackageInfoW"))]
#[no_mangle]
pub unsafe extern "system" fn QuerySecurityPackageInfoW(
    p_package_name: *const SecWChar,
    pp_package_info: *mut PSecPkgInfoW,
) -> SecurityStatus {
    catch_panic! {
        check_null!(p_package_name);
        check_null!(pp_package_info);

        let pkg_name = c_w_str_to_string(p_package_name);

        let pkg_info: &mut SecPkgInfoW = try_execute!(enumerate_security_packages())
            .into_iter()
            .find(|pkg| pkg.name.to_string() == pkg_name)
            .unwrap()
            .into();
        *pp_package_info = pkg_info;

        0
    }
}

pub type QuerySecurityPackageInfoFnW = unsafe extern "system" fn(*const SecWChar, *mut PSecPkgInfoW) -> SecurityStatus;

#[cfg(test)]
mod tests {
    use std::ptr::null;

    use super::{EnumerateSecurityPackagesA, EnumerateSecurityPackagesW, SecPkgInfoA, SecPkgInfoW};

    #[test]
    fn enumerate_security_packages_a() {
        let mut packages_amount = 0;
        let mut packages = null::<SecPkgInfoA>() as *mut _;

        unsafe {
            let status = EnumerateSecurityPackagesA(&mut packages_amount, &mut packages);

            assert_eq!(status, 0);
            assert_eq!(packages_amount, 3);
            assert!(!packages.is_null());

            for i in 0..(packages_amount as usize) {
                let _ = packages.add(i).as_mut().unwrap();
            }
        }
    }

    #[test]
    fn enumerate_security_packages_w() {
        let mut packages_amount = 0;
        let mut packages = null::<SecPkgInfoW>() as *mut _;

        unsafe {
            let status = EnumerateSecurityPackagesW(&mut packages_amount, &mut packages);

            assert_eq!(status, 0);
            assert_eq!(packages_amount, 3);
            assert!(!packages.is_null());

            for i in 0..(packages_amount as usize) {
                let _ = packages.add(i).as_mut().unwrap();
            }
        }
    }
}
