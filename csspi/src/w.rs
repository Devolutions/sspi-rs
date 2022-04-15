use std::ptr::null;

use libc::{c_ulong, c_ushort, c_void};
use sspi::{enumerate_security_packages, PackageInfo, KERBEROS_VERSION};

use crate::{
    common::{
        PCredHandle, PCtxtHandle, PSecBufferDesc, PSecurityBuffer, PSecurityString, PTimeStamp,
        SecurityStatus, SEC_GET_KEY_FN,
    },
    into_raw_ptr, p_ctxt_handle_to_kerberos,
};

#[repr(C)]
pub struct SecPkgInfoW {
    pub fCapabilities: c_ulong,
    pub wVersion: c_ushort,
    pub wRPCID: c_ushort,
    pub cbMaxToken: c_ulong,
    pub Name: *mut SEC_WCHAR,
    pub Comment: *mut SEC_WCHAR,
}

pub type PSecPkgInfoW = *mut SecPkgInfoW;

impl From<PackageInfo> for SecPkgInfoW {
    fn from(data: PackageInfo) -> Self {
        let mut v = data.name.to_string().encode_utf16().collect::<Vec<_>>();
        let Name = v.as_mut_ptr();
        into_raw_ptr(v);

        let mut v = data.comment.encode_utf16().collect::<Vec<_>>();
        let Comment = v.as_mut_ptr();
        into_raw_ptr(v);

        SecPkgInfoW {
            fCapabilities: data.capabilities.bits() as c_ulong,
            wVersion: KERBEROS_VERSION as c_ushort,
            wRPCID: data.rpc_id,
            cbMaxToken: data.max_token_len,
            Name,
            // Comment: Box::into_raw(Box::new(data.comment.encode_utf16().collect::<Vec<_>>()))
            //     as *mut _ as *mut SEC_WCHAR,
            Comment,
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn helper(p_info: PSecPkgInfoW) {
    let packages = enumerate_security_packages().unwrap();

    *p_info =
    // into_raw_ptr(
        SecPkgInfoW::from(packages[0].clone())
    // )
    ;
}
pub type HELPER_FN = unsafe extern "C" fn(PSecPkgInfoW);

pub type LPCWSTR = *const SEC_WCHAR;

pub type SEC_WCHAR = c_ushort;

#[no_mangle]
pub unsafe extern "C" fn EnumerateSecurityPackagesW(
    pcPackages: *mut c_ulong,
    ppPackageInfo: *mut *mut SecPkgInfoW,
) -> SecurityStatus {
    let packages = enumerate_security_packages().unwrap();

    *pcPackages = packages.len() as c_ulong;

    let mut ptrs = packages
            .into_iter()
            .map(|package| into_raw_ptr(SecPkgInfoW::from(package)))
            .collect::<Vec<_>>();
    let ptr = ptrs.as_mut_ptr();
    into_raw_ptr(ptrs);

    *ppPackageInfo = *ptr;

    0
}
pub type ENUMERATE_SECURITY_PACKAGES_FN_W =
    unsafe extern "C" fn(*mut c_ulong, *mut PSecPkgInfoW) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn QueryCredentialsAttributesW(
    phCredential: PCredHandle,
    ulAttribute: c_ulong,
    pBuffer: *mut c_void,
) -> SecurityStatus {
    0
}
pub type QUERY_CREDENTIALS_ATTRIBUTES_FN_W =
    extern "C" fn(PCredHandle, c_ulong, *mut c_void) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn AcquireCredentialsHandleW(
    pszPrincipal: LPCWSTR,
    pszPackage: LPCWSTR,
    fCredentialUse: c_ulong,
    pvLogonId: *const c_void,
    pAuthData: *const c_void,
    pGetKeyFn: SEC_GET_KEY_FN,
    pvGetKeyArgument: *const c_void,
    phCredential: PCredHandle,
    ptsExpiry: PTimeStamp,
) -> SecurityStatus {
    0
}
pub type ACQUIRE_CREDENTIALS_HANDLE_FN_W = extern "C" fn(
    LPCWSTR,
    LPCWSTR,
    c_ulong,
    *const c_void,
    *const c_void,
    SEC_GET_KEY_FN,
    *const c_void,
    PCredHandle,
    PTimeStamp,
) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn InitializeSecurityContextW(
    phCredential: PCredHandle,
    phContext: PCtxtHandle,
    pTargetName: PSecurityString,
    fContextReq: c_ulong,
    Reserved1: c_ulong,
    TargetDataRep: c_ulong,
    pInput: PSecBufferDesc,
    Reserved2: c_ulong,
    phNewContext: PCtxtHandle,
    pOutput: PSecBufferDesc,
    pfContextAttr: *mut c_ulong,
    ptsExpiry: PTimeStamp,
) -> SecurityStatus {
    0
}
pub type INITIALIZE_SECURITY_CONTEXT_FN_W = extern "C" fn(
    PCredHandle,
    PCtxtHandle,
    PSecurityString,
    c_ulong,
    c_ulong,
    c_ulong,
    PSecBufferDesc,
    c_ulong,
    PCtxtHandle,
    PSecBufferDesc,
    *mut c_ulong,
    PTimeStamp,
) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn QueryContextAttributesW(
    phContext: PCtxtHandle,
    ulAttribute: c_ulong,
    pBuffer: *mut c_void,
) -> SecurityStatus {
    0
}
pub type QUERY_CONTEXT_ATTRIBUTES_FN_W =
    extern "C" fn(PCtxtHandle, c_ulong, *mut c_void) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn QuerySecurityPackageInfoW(
    pPackageName: PSecurityString,
    ppPackageInfo: *mut PSecPkgInfoW,
) -> SecurityStatus {
    0
}
pub type QUERY_SECURITY_PACKAGE_INFO_FN_W =
    extern "C" fn(PSecurityString, *mut PSecPkgInfoW) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn ImportSecurityContextW(
    pszPackage: PSecurityString,
    pPackedContext: PSecurityBuffer,
    Token: *mut c_void,
    phContext: PCtxtHandle,
) -> SecurityStatus {
    0
}
pub type IMPORT_SECURITY_CONTEXT_FN_W =
    extern "C" fn(PSecurityString, PSecurityBuffer, *mut c_void, PCtxtHandle) -> SecurityStatus;

// no docs?
#[no_mangle]
pub extern "C" fn AddCredentialsW() -> SecurityStatus {
    0
}
pub type ADD_CREDENTIALS_FN_W = extern "C" fn() -> SecurityStatus;

#[no_mangle]
pub extern "C" fn SetContextAttributesW(
    phContext: PCtxtHandle,
    ulAttribute: c_ulong,
    pBuffer: *mut c_void,
    cbBuffer: c_ulong,
) -> SecurityStatus {
    0
}
pub type SET_CONTEXT_ATTRIBUTES_FN_W =
    extern "C" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn SetCredentialsAttributesW(
    phContext: PCtxtHandle,
    ulAttribute: c_ulong,
    pBuffer: *mut c_void,
    cbBuffer: c_ulong,
) -> SecurityStatus {
    0
}
pub type SET_CREDENTIALS_ATTRIBUTES_FN_W =
    extern "C" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn ChangeAccountPasswordW(
    pszPackageName: *mut SEC_WCHAR,
    pszDomainName: *mut SEC_WCHAR,
    pszAccountName: *mut SEC_WCHAR,
    pszOldPassword: *mut SEC_WCHAR,
    pszNewPassword: *mut SEC_WCHAR,
    bImpersonating: bool,
    dwReserved: c_ulong,
    pOutput: PSecBufferDesc,
) -> SecurityStatus {
    0
}
pub type CHANGE_PASSWORD_FN_W = extern "C" fn(
    *mut SEC_WCHAR,
    *mut SEC_WCHAR,
    *mut SEC_WCHAR,
    *mut SEC_WCHAR,
    *mut SEC_WCHAR,
    bool,
    c_ulong,
    PSecBufferDesc,
) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn QueryContextAttributesExW(
    phContext: PCtxtHandle,
    ulAttribute: c_ulong,
    pBuffer: *mut c_void,
    cbBuffer: c_ulong,
) -> SecurityStatus {
    0
}
pub type QUERY_CONTEXT_ATTRIBUTES_EX_FN_W =
    extern "C" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn QueryCredentialsAttributesExW(
    phCredential: PCredHandle,
    ulAttribute: c_ulong,
    pBuffer: *mut c_void,
    cBuffers: c_ulong,
) -> SecurityStatus {
    0
}
pub type QUERY_CREDENTIALS_ATTRIBUTES_EX_FN_W =
    extern "C" fn(PCredHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;
