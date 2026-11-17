use std::ffi::CStr;
use std::ptr::null_mut;

use num_traits::ToPrimitive;
use sspi::{ErrorKind, PackageCapabilities, U16CString};

use super::{
    EnumerateSecurityPackagesA, EnumerateSecurityPackagesW, PSecPkgInfoA, PSecPkgInfoW, QuerySecurityPackageInfoA,
    QuerySecurityPackageInfoW, SecPkgInfoA, SecPkgInfoW,
};
use crate::sspi::common::FreeContextBuffer;

const PACKAGE_ID_NONE: u16 = 0xFFFF;

/// Expected package info values: `(package name, comment, max token length)`.
const NTLM_PACKAGE_INFO: (&str, &str, u32) = ("NTLM", "NTLM Security Package", 0xb48);
const KERBEROS_PACKAGE_INFO: (&str, &str, u32) = ("Kerberos", "Kerberos Security Package", 0xbb80);
#[cfg(feature = "tsssp")]
const CREDSSP_PACKAGE_INFO: (&str, &str, u32) = ("CREDSSP", "CredSsp security package", 0xbb81);

const EXPECTED_PACKAGES_AMOUNT: u32 = if cfg!(feature = "tsssp") { 5 } else { 4 };

const PACKAGE_INFOS: &[(&str, &str, u32)] = &[
    NTLM_PACKAGE_INFO,
    KERBEROS_PACKAGE_INFO,
    #[cfg(feature = "tsssp")]
    CREDSSP_PACKAGE_INFO,
];

#[test]
fn enumerate_security_packages_a() {
    let mut packages_amount = 0;
    let mut packages = null_mut::<SecPkgInfoA>();

    let status = unsafe { EnumerateSecurityPackagesA(&mut packages_amount, &mut packages) };

    assert_eq!(status, 0);
    assert_eq!(packages_amount, EXPECTED_PACKAGES_AMOUNT);
    assert!(!packages.is_null());

    for i in 0..packages_amount.try_into().expect("packages_amount is a valid usize") {
        let pkg_info = unsafe { packages.add(i) };
        let pkg_info = unsafe { pkg_info.as_mut() }.expect("pkg_info is not null");

        assert!(!pkg_info.name.is_null());
        let name = unsafe { CStr::from_ptr(pkg_info.name) }
            .to_str()
            .expect("package name must be valid UTF-8");
        assert!(!name.is_empty());

        assert!(!pkg_info.comment.is_null());
        let comment = unsafe { CStr::from_ptr(pkg_info.comment) }
            .to_str()
            .expect("package comment must be valid UTF-8");
        assert!(!comment.is_empty());
    }

    let pv_context_buffer = packages.cast();
    let status = unsafe { FreeContextBuffer(pv_context_buffer) };
    assert_eq!(status, 0);
}

#[test]
fn enumerate_security_packages_w() {
    let mut packages_amount = 0;
    let mut packages = null_mut::<SecPkgInfoW>();

    let status = unsafe { EnumerateSecurityPackagesW(&mut packages_amount, &mut packages) };

    assert_eq!(status, 0);
    assert_eq!(packages_amount, EXPECTED_PACKAGES_AMOUNT);
    assert!(!packages.is_null());

    for i in 0..packages_amount.try_into().expect("packages_amount is a valid usize") {
        let pkg_info = unsafe { packages.add(i) };
        let pkg_info = unsafe { pkg_info.as_mut() }.expect("pkg_info is not null");

        assert!(!pkg_info.name.is_null());
        let name = unsafe { U16CString::from_ptr_str(pkg_info.name) }
            .to_string()
            .expect("package name must be valid UTF-16");
        assert!(!name.is_empty());

        assert!(!pkg_info.comment.is_null());
        let comment = unsafe { U16CString::from_ptr_str(pkg_info.comment) }
            .to_string()
            .expect("package comment must be valid UTF-16");
        assert!(!comment.is_empty());
    }

    let pv_context_buffer = packages.cast();
    let status = unsafe { FreeContextBuffer(pv_context_buffer) };
    assert_eq!(status, 0);
}

/// Asserts that `QuerySecurityPackageInfoA` returns the expected package info and that the
/// returned buffer can be freed with `FreeContextBuffer`.
fn check_query_security_package_info_a(package_name: &str, comment: &str, max_token_len: u32) {
    let c_package_name = format!("{package_name}\0");
    let mut package_info: PSecPkgInfoA = null_mut::<SecPkgInfoA>();

    let status = unsafe { QuerySecurityPackageInfoA(c_package_name.as_ptr().cast(), &mut package_info) };
    assert_eq!(status, 0);

    let package_info_ref = unsafe { package_info.as_ref() }.expect("package_info is not null");

    assert_eq!(package_info_ref.f_capabilities, PackageCapabilities::empty().bits());
    assert_eq!(package_info_ref.w_rpc_id, PACKAGE_ID_NONE);
    assert_eq!(package_info_ref.cb_max_token, max_token_len);
    assert_eq!(
        unsafe { CStr::from_ptr(package_info_ref.name) }
            .to_str()
            .expect("package name must be valid UTF-8"),
        package_name
    );
    assert_eq!(
        unsafe { CStr::from_ptr(package_info_ref.comment) }
            .to_str()
            .expect("package comment must be valid UTF-8"),
        comment
    );

    let status = unsafe { FreeContextBuffer(package_info.cast()) };
    assert_eq!(status, 0);
}

/// Asserts that `QuerySecurityPackageInfoW` returns the expected package info and that the
/// returned buffer can be freed with `FreeContextBuffer`.
fn check_query_security_package_info_w(package_name: &str, comment: &str, max_token_len: u32) {
    let c_package_name = format!("{package_name}\0").encode_utf16().collect::<Vec<_>>();
    let mut package_info: PSecPkgInfoW = null_mut::<SecPkgInfoW>();

    let status = unsafe { QuerySecurityPackageInfoW(c_package_name.as_ptr(), &mut package_info) };
    assert_eq!(status, 0);

    let package_info_ref = unsafe { package_info.as_ref() }.expect("package_info is not null");

    assert_eq!(package_info_ref.f_capabilities, PackageCapabilities::empty().bits());
    assert_eq!(package_info_ref.w_rpc_id, PACKAGE_ID_NONE);
    assert_eq!(package_info_ref.cb_max_token, max_token_len);
    assert_eq!(
        unsafe { U16CString::from_ptr_str(package_info_ref.name) }
            .to_string()
            .expect("package name must be valid UTF-16"),
        package_name
    );
    assert_eq!(
        unsafe { U16CString::from_ptr_str(package_info_ref.comment) }
            .to_string()
            .expect("package comment must be valid UTF-16"),
        comment
    );

    let status = unsafe { FreeContextBuffer(package_info.cast()) };
    assert_eq!(status, 0);
}

#[test]
fn query_security_package_info_a() {
    for &(name, comment, max_token_len) in PACKAGE_INFOS {
        check_query_security_package_info_a(name, comment, max_token_len);
    }
}

#[test]
fn query_security_package_info_w() {
    for &(name, comment, max_token_len) in PACKAGE_INFOS {
        check_query_security_package_info_w(name, comment, max_token_len);
    }
}

#[test]
fn query_security_package_info_unknown_package() {
    let package_name_a = "PKG\0";
    let mut package_info_a: PSecPkgInfoA = null_mut::<SecPkgInfoA>();

    let status = unsafe { QuerySecurityPackageInfoA(package_name_a.as_ptr().cast(), &mut package_info_a) };

    assert_eq!(
        status,
        ErrorKind::SecurityPackageNotFound
            .to_u32()
            .expect("ErrorKind is castable to u32")
    );
    assert!(package_info_a.is_null());

    let package_name_w = "PKG\0".encode_utf16().collect::<Vec<_>>();
    let mut package_info_w: PSecPkgInfoW = null_mut::<SecPkgInfoW>();

    let status = unsafe { QuerySecurityPackageInfoW(package_name_w.as_ptr(), &mut package_info_w) };

    assert_eq!(
        status,
        ErrorKind::SecurityPackageNotFound
            .to_u32()
            .expect("ErrorKind is castable to u32")
    );
    assert!(package_info_w.is_null());
}
