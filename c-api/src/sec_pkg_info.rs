use libc::{c_uint, c_ulong, c_ushort};
use sspi::{enumerate_security_packages, PackageInfo, KERBEROS_VERSION};

use crate::sspi_data_types::{SecChar, SecWChar, SecurityStatus};
use crate::utils::{c_str_into_string, c_w_str_to_string, into_raw_ptr, vec_into_raw_ptr};

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
impl From<PackageInfo> for SecPkgInfoW {
    fn from(data: PackageInfo) -> Self {
        SecPkgInfoW {
            f_capabilities: data.capabilities.bits() as c_ulong,
            w_version: KERBEROS_VERSION as c_ushort,
            w_rpc_id: data.rpc_id,
            cb_max_token: data.max_token_len.try_into().unwrap(),
            name: vec_into_raw_ptr(data.name.to_string().encode_utf16().collect::<Vec<_>>()),
            comment: vec_into_raw_ptr(data.comment.encode_utf16().collect::<Vec<_>>()),
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

impl From<PackageInfo> for SecPkgInfoA {
    fn from(data: PackageInfo) -> Self {
        SecPkgInfoA {
            f_capabilities: data.capabilities.bits() as c_uint,
            w_version: KERBEROS_VERSION as c_ushort,
            w_rpc_id: data.rpc_id,
            cb_max_token: data.max_token_len,
            name: vec_into_raw_ptr(data.name.to_string().as_bytes().to_vec()) as *mut i8,
            comment: vec_into_raw_ptr(data.comment.as_bytes().to_vec()) as *mut i8,
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn EnumerateSecurityPackagesA(
    pc_packages: *mut c_ulong,
    pp_package_info: *mut PSecPkgInfoA,
) -> SecurityStatus {
    let packages = enumerate_security_packages().unwrap();

    *pc_packages = packages.len() as c_ulong;

    *pp_package_info = *vec_into_raw_ptr(
        packages
            .into_iter()
            .map(|package| into_raw_ptr(SecPkgInfoA::from(package)))
            .collect::<Vec<_>>(),
    );

    0
}
pub type EnumerateSecurityPackagesFnA = unsafe extern "system" fn(*mut c_ulong, *mut PSecPkgInfoA) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "system" fn EnumerateSecurityPackagesW(
    pc_packages: *mut c_ulong,
    pp_package_info: *mut *mut SecPkgInfoW,
) -> SecurityStatus {
    let packages = enumerate_security_packages().unwrap();

    *pc_packages = packages.len() as c_ulong;

    *pp_package_info = *vec_into_raw_ptr(
        packages
            .into_iter()
            .map(|package| into_raw_ptr(SecPkgInfoW::from(package)))
            .collect::<Vec<_>>(),
    );

    0
}
pub type EnumerateSecurityPackagesFnW = unsafe extern "system" fn(*mut c_ulong, *mut PSecPkgInfoW) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "system" fn QuerySecurityPackageInfoA(
    p_package_name: *const SecChar,
    pp_package_info: *mut PSecPkgInfoA,
) -> SecurityStatus {
    let pkg_name = c_str_into_string(p_package_name);

    *pp_package_info = enumerate_security_packages()
        .unwrap()
        .into_iter()
        .find(|pkg| pkg.name.to_string() == pkg_name)
        .map(|pkg_info| into_raw_ptr(SecPkgInfoA::from(pkg_info)))
        .unwrap();

    0
}
pub type QuerySecurityPackageInfoFnA = unsafe extern "system" fn(*const SecChar, *mut PSecPkgInfoA) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "system" fn QuerySecurityPackageInfoW(
    p_package_name: *const SecWChar,
    pp_package_info: *mut PSecPkgInfoW,
) -> SecurityStatus {
    let pkg_name = c_w_str_to_string(p_package_name);

    *pp_package_info = enumerate_security_packages()
        .unwrap()
        .into_iter()
        .find(|pkg| pkg.name.to_string() == pkg_name)
        .map(|pkg_info| into_raw_ptr(SecPkgInfoW::from(pkg_info)))
        .unwrap();

    0
}
pub type QuerySecurityPackageInfoFnW = unsafe extern "system" fn(*const SecWChar, *mut PSecPkgInfoW) -> SecurityStatus;
