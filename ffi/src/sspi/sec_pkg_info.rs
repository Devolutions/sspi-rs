use std::ffi::CStr;
use std::mem::size_of;
use std::ptr::copy_nonoverlapping;

use sspi::{enumerate_security_packages, PackageInfo, KERBEROS_VERSION};
#[cfg(windows)]
use symbol_rename_macro::rename_symbol;

use super::sspi_data_types::{SecChar, SecWChar, SecurityStatus};
use crate::utils::{c_w_str_to_string, str_to_w_buff};

#[derive(Debug)]
#[repr(C)]
pub struct SecPkgInfoW {
    pub f_capabilities: u32,
    pub w_version: u16,
    pub w_rpc_id: u16,
    pub cb_max_token: u32,
    pub name: *mut SecWChar,
    pub comment: *mut SecWChar,
}

pub type PSecPkgInfoW = *mut SecPkgInfoW;

#[allow(clippy::useless_conversion)]
impl From<PackageInfo> for &mut SecPkgInfoW {
    fn from(pkg_info: PackageInfo) -> Self {
        let pkg_name = str_to_w_buff(pkg_info.name.as_ref());
        let name_bytes_len = pkg_name.len() * 2;

        let pkg_comment = str_to_w_buff(&pkg_info.comment);
        let comment_bytes_len = pkg_comment.len() * 2;

        let pkg_info_w_size = size_of::<SecPkgInfoW>();
        let size = pkg_info_w_size + name_bytes_len + comment_bytes_len;

        let raw_pkg_info;
        let pkg_info_w;
        unsafe {
            raw_pkg_info = libc::malloc(size);
            pkg_info_w = (raw_pkg_info as *mut SecPkgInfoW).as_mut().unwrap();
        }

        pkg_info_w.f_capabilities = pkg_info.capabilities.bits();
        pkg_info_w.w_version = KERBEROS_VERSION as u16;
        pkg_info_w.w_rpc_id = pkg_info.rpc_id;
        pkg_info_w.cb_max_token = pkg_info.max_token_len.try_into().unwrap();

        let name_ptr;
        unsafe {
            name_ptr = raw_pkg_info.add(pkg_info_w_size);
            copy_nonoverlapping(pkg_name.as_ptr() as *const _, name_ptr, name_bytes_len);
        }
        pkg_info_w.name = name_ptr as *mut _;

        let comment_ptr;
        unsafe {
            comment_ptr = name_ptr.add(name_bytes_len);
            copy_nonoverlapping(pkg_comment.as_ptr() as *const _, comment_ptr, comment_bytes_len);
        }
        pkg_info_w.comment = comment_ptr as *mut _;

        unsafe { (raw_pkg_info as *mut SecPkgInfoW).as_mut().unwrap() }
    }
}

#[repr(C)]
pub struct SecPkgInfoA {
    pub f_capabilities: u32,
    pub w_version: u16,
    pub w_rpc_id: u16,
    pub cb_max_token: u32,
    pub name: *mut SecChar,
    pub comment: *mut SecChar,
}

pub type PSecPkgInfoA = *mut SecPkgInfoA;

impl From<PackageInfo> for &mut SecPkgInfoA {
    fn from(pkg_info: PackageInfo) -> Self {
        let mut pkg_name = pkg_info.name.to_string().as_bytes().to_vec();
        // We need to add the null-terminator during the conversion from Rust to C string.
        pkg_name.push(0);
        let name_bytes_len = pkg_name.len();

        let mut pkg_comment = pkg_info.comment.as_bytes().to_vec();
        // We need to add the null-terminator during the conversion from Rust to C string.
        pkg_comment.push(0);
        let comment_bytes_len = pkg_comment.len();

        let pkg_info_a_size = size_of::<SecPkgInfoA>();

        let size = pkg_info_a_size + name_bytes_len + comment_bytes_len;

        let raw_pkg_info;
        let pkg_info_a;

        unsafe {
            raw_pkg_info = libc::malloc(size);

            // FIXME(safety): it is illegal to construct a reference to uninitialized data
            // Useful references:
            // - https://doc.rust-lang.org/nomicon/unchecked-uninit.html
            // - https://doc.rust-lang.org/core/mem/union.MaybeUninit.html#initializing-a-struct-field-by-field
            // NOTE: this is not the only place that needs to be fixed. An audit is required.
            pkg_info_a = (raw_pkg_info as *mut SecPkgInfoA).as_mut().unwrap();
        }

        pkg_info_a.f_capabilities = pkg_info.capabilities.bits();
        pkg_info_a.w_version = KERBEROS_VERSION as u16;
        pkg_info_a.w_rpc_id = pkg_info.rpc_id;
        pkg_info_a.cb_max_token = pkg_info.max_token_len;

        let name_ptr;
        unsafe {
            name_ptr = raw_pkg_info.add(pkg_info_a_size);
            copy_nonoverlapping(pkg_name.as_ptr() as *const _, name_ptr, name_bytes_len);
        }
        pkg_info_a.name = name_ptr as *mut _;

        let comment_ptr;
        unsafe {
            comment_ptr = name_ptr.add(name_bytes_len);
            copy_nonoverlapping(pkg_comment.as_ptr() as *const _, comment_ptr, comment_bytes_len);
        }
        pkg_info_a.comment = comment_ptr as *mut _;

        unsafe { (raw_pkg_info as *mut SecPkgInfoA).as_mut().unwrap() }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct SecNegoInfoW {
    pub package_info: *mut SecPkgInfoW,
    pub nego_state: u32,
}

#[derive(Debug)]
#[repr(C)]
pub struct SecNegoInfoA {
    pub package_info: *mut SecPkgInfoA,
    pub nego_state: u32,
}

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_EnumerateSecurityPackagesA"))]
#[no_mangle]
pub unsafe extern "system" fn EnumerateSecurityPackagesA(
    pc_packages: *mut u32,
    pp_package_info: *mut PSecPkgInfoA,
) -> SecurityStatus {
    catch_panic! {
        check_null!(pc_packages);
        check_null!(pp_package_info);

        let packages = try_execute!(enumerate_security_packages());

        *pc_packages = packages.len() as u32;

        let mut size = size_of::<SecPkgInfoA>() * packages.len();

        for package in &packages {
            size += package.name.as_ref().as_bytes().len() + 1 /* null byte */ + package.comment.as_bytes().len() + 1 /* null byte */;
        }

        let raw_packages = libc::malloc(size);

        let mut package_ptr = raw_packages as *mut SecPkgInfoA;
        let mut data_ptr = raw_packages.add(size_of::<SecPkgInfoA>() * packages.len()) as *mut SecChar;
        for pkg_info in packages {
            let pkg_info_a = package_ptr.as_mut().unwrap();

            pkg_info_a.f_capabilities = pkg_info.capabilities.bits();
            pkg_info_a.w_version = KERBEROS_VERSION as u16;
            pkg_info_a.w_rpc_id = pkg_info.rpc_id;
            pkg_info_a.cb_max_token = pkg_info.max_token_len;

            let mut name = pkg_info.name.as_ref().as_bytes().to_vec();
            // We need to add the null-terminator during the conversion from Rust to C string.
            name.push(0);
            copy_nonoverlapping(name.as_ptr(), data_ptr as *mut _, name.len());
            pkg_info_a.name = data_ptr as *mut _;
            data_ptr = data_ptr.add(name.len());

            let mut comment = pkg_info.comment.as_bytes().to_vec();
            // We need to add the null-terminator during the conversion from Rust to C string.
            comment.push(0);
            copy_nonoverlapping(comment.as_ptr(), data_ptr as *mut _, comment.len());
            pkg_info_a.comment = data_ptr as *mut _;
            data_ptr = data_ptr.add(comment.len());

            package_ptr = package_ptr.add(1);
        }

        *pp_package_info = raw_packages as *mut _;

        0
    }
}

pub type EnumerateSecurityPackagesFnA = unsafe extern "system" fn(*mut u32, *mut PSecPkgInfoA) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_EnumerateSecurityPackagesW"))]
#[no_mangle]
pub unsafe extern "system" fn EnumerateSecurityPackagesW(
    pc_packages: *mut u32,
    pp_package_info: *mut *mut SecPkgInfoW,
) -> SecurityStatus {
    catch_panic! {
        check_null!(pc_packages);
        check_null!(pp_package_info);

        let packages = try_execute!(enumerate_security_packages());

        *pc_packages = packages.len() as u32;

        let mut size = size_of::<SecPkgInfoW>() * packages.len();
        let mut names = Vec::with_capacity(packages.len());
        let mut comments = Vec::with_capacity(packages.len());

        for package in &packages {
            let name = str_to_w_buff(package.name.as_ref());
            let comment = str_to_w_buff(&package.comment);

            size += (name.len() + comment.len()) * 2;

            names.push(name);
            comments.push(comment);
        }

        let raw_packages = libc::malloc(size);

        let mut package_ptr = raw_packages as *mut SecPkgInfoW;
        let mut data_ptr = raw_packages.add(size_of::<SecPkgInfoW>() * packages.len()) as *mut SecWChar;
        for (i, pkg_info) in packages.iter().enumerate() {
            let pkg_info_w = package_ptr.as_mut().unwrap();

            pkg_info_w.f_capabilities = pkg_info.capabilities.bits();
            pkg_info_w.w_version = KERBEROS_VERSION as u16;
            pkg_info_w.w_rpc_id = pkg_info.rpc_id;
            pkg_info_w.cb_max_token = pkg_info.max_token_len;

            copy_nonoverlapping(names[i].as_ptr(), data_ptr, names[i].len());
            pkg_info_w.name = data_ptr as *mut _;
            data_ptr = data_ptr.add(names[i].len());

            copy_nonoverlapping(comments[i].as_ptr(), data_ptr, comments[i].len());
            pkg_info_w.comment = data_ptr as *mut _;
            data_ptr = data_ptr.add(comments[i].len());

            package_ptr = package_ptr.add(1);
        }

        *pp_package_info = raw_packages as *mut _;

        0
    }
}

pub type EnumerateSecurityPackagesFnW = unsafe extern "system" fn(*mut u32, *mut PSecPkgInfoW) -> SecurityStatus;

#[instrument(skip_all)]
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

        let pkg_info: &mut SecPkgInfoA = try_execute!(enumerate_security_packages())
            .into_iter()
            .find(|pkg| pkg.name.as_ref() == pkg_name)
            .unwrap()
            .into();
        *pp_package_info = pkg_info;

        0
    }
}

pub type QuerySecurityPackageInfoFnA = unsafe extern "system" fn(*const SecChar, *mut PSecPkgInfoA) -> SecurityStatus;

#[instrument(skip_all)]
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
    use std::ptr::null_mut;

    use super::{EnumerateSecurityPackagesA, EnumerateSecurityPackagesW, SecPkgInfoA, SecPkgInfoW};
    use crate::sspi::common::FreeContextBuffer;

    #[test]
    fn enumerate_security_packages_a() {
        cfg_if::cfg_if!(
            if #[cfg(feature = "tsssp")] {
                let expected_packages_amount = 5;
            } else {
                let expected_packages_amount = 4;
            }
        );

        let mut packages_amount = 0;
        let mut packages = null_mut::<SecPkgInfoA>();

        unsafe {
            let status = EnumerateSecurityPackagesA(&mut packages_amount, &mut packages);

            assert_eq!(status, 0);
            assert_eq!(packages_amount, expected_packages_amount);
            assert!(!packages.is_null());

            for i in 0..(packages_amount as usize) {
                let _ = packages.add(i).as_mut().unwrap();
            }

            let status = FreeContextBuffer(packages as *mut _);
            assert_eq!(status, 0);
        }
    }

    #[test]
    fn enumerate_security_packages_w() {
        cfg_if::cfg_if!(
            if #[cfg(feature = "tsssp")] {
                let expected_packages_amount = 5;
            } else {
                let expected_packages_amount = 4;
            }
        );

        let mut packages_amount = 0;
        let mut packages = null_mut::<SecPkgInfoW>();

        unsafe {
            let status = EnumerateSecurityPackagesW(&mut packages_amount, &mut packages);

            assert_eq!(status, 0);
            assert_eq!(packages_amount, expected_packages_amount);
            assert!(!packages.is_null());

            for i in 0..(packages_amount as usize) {
                let _ = packages.add(i).as_mut().unwrap();
            }

            let status = FreeContextBuffer(packages as *mut _);
            assert_eq!(status, 0);
        }
    }
}
