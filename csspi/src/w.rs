use std::{ptr::null, slice::from_raw_parts};

use libc::{c_ulong, c_ulonglong, c_ushort, c_void};
use num_traits::{FromPrimitive, ToPrimitive};
use sspi::{
    enumerate_security_packages, AuthIdentityBuffers, ClientRequestFlags, DataRepresentation,
    PackageInfo, SecurityBuffer, SecurityBufferType, Sspi, KERBEROS_VERSION,
};

use crate::{
    common::{
        CredSspCred, PCredHandle, PCtxtHandle, PSecBuffer, PSecBufferDesc, PSecurityString,
        PTimeStamp, SecBufferDesc, SecurityStatus, SEC_GET_KEY_FN,
    },
    into_raw_ptr, p_ctxt_handle_to_kerberos, p_sec_buffers_to_security_buffers,
    p_sec_string_to_string, security_buffers_to_raw,
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
            Comment,
        }
    }
}

#[repr(C)]
pub struct SecWinntAuthIdentityW {
    User: *const c_ushort,
    UserLength: c_ulong,
    Domain: *const c_ushort,
    DomainLength: c_ulong,
    Password: *const c_ushort,
    PasswordLength: c_ulong,
    Flags: c_ulong,
}
pub type PSecWinntAuthIdentityW = *mut SecWinntAuthIdentityW;

pub type LPCWSTR = *const SEC_WCHAR;

pub type SEC_WCHAR = c_ushort;

unsafe fn raw_w_str_to_bytes(raw_buffer: *const c_ushort, len: usize) -> Vec<u8> {
    from_raw_parts(raw_buffer, len)
        .iter()
        .flat_map(|w_char| w_char.to_le_bytes())
        .collect()
}

pub(crate) unsafe fn c_w_str_to_string(s: *const SEC_WCHAR) -> String {
    let mut len = 0;

    while *(s.add(len)) != 0 {
        len += 1;
    }

    String::from_utf16_lossy(&from_raw_parts(s, len + 1))
}

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
    unimplemented!("QueryCredentialsAttributesW")
}
pub type QUERY_CREDENTIALS_ATTRIBUTES_FN_W =
    extern "C" fn(PCredHandle, c_ulong, *mut c_void) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "C" fn AcquireCredentialsHandleW(
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
    let auth_data = pAuthData.cast::<SecWinntAuthIdentityW>();

    let creds = AuthIdentityBuffers {
        user: raw_w_str_to_bytes((*auth_data).User, (*auth_data).UserLength as usize),
        domain: raw_w_str_to_bytes((*auth_data).Domain, (*auth_data).DomainLength as usize),
        password: raw_w_str_to_bytes((*auth_data).Password, (*auth_data).PasswordLength as usize),
    };

    (*phCredential).dwLower = into_raw_ptr(creds) as c_ulonglong;

    0
}
pub type ACQUIRE_CREDENTIALS_HANDLE_FN_W = unsafe extern "C" fn(
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
pub unsafe extern "C" fn InitializeSecurityContextW(
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
    let auth_data = ((*phCredential).dwLower as *mut AuthIdentityBuffers);

    let mut auth_data = if auth_data == null::<AuthIdentityBuffers>() as *mut _ {
        None
    } else {
        Some(auth_data.as_mut().unwrap().clone())
    };

    let kerberos_ptr = p_ctxt_handle_to_kerberos(phContext);
    let kerberos = kerberos_ptr.as_mut().unwrap();

    let mut input_tokens = if pInput == null::<SecBufferDesc>() as *mut _ {
        Vec::new()
    } else {
        p_sec_buffers_to_security_buffers(from_raw_parts(
            (*pInput).pBuffers,
            (*pInput).cBuffers as usize,
        ))
    };

    let len = (*pOutput).cBuffers as usize;
    let raw_buffers = from_raw_parts((*pOutput).pBuffers, len);
    let mut o = p_sec_buffers_to_security_buffers(raw_buffers);
    o.iter_mut().for_each(|s| s.buffer.clear());

    let result_status = kerberos
        .initialize_security_context()
        .with_credentials_handle(&mut auth_data)
        .with_context_requirements(ClientRequestFlags::from_bits(fContextReq).unwrap())
        .with_target_data_representation(DataRepresentation::from_u32(TargetDataRep).unwrap())
        .with_input(&mut input_tokens)
        .with_output(&mut o)
        .execute();
    
    let res = result_status
        .unwrap()
        .status;

    let output_tokens = o;

    (*pOutput).cBuffers = output_tokens.len() as c_ulong;

    (*pOutput).pBuffers = security_buffers_to_raw(output_tokens);

    (*phNewContext).dwLower = kerberos_ptr as c_ulonglong;

    res.to_i32().unwrap()
}
pub type INITIALIZE_SECURITY_CONTEXT_FN_W = unsafe extern "C" fn(
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
    unimplemented!("QueryContextAttributesW")
}
pub type QUERY_CONTEXT_ATTRIBUTES_FN_W =
    extern "C" fn(PCtxtHandle, c_ulong, *mut c_void) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "C" fn QuerySecurityPackageInfoW(
    // pPackageName: PSecurityString,
    pPackageName: *const SEC_WCHAR,
    ppPackageInfo: *mut PSecPkgInfoW,
) -> SecurityStatus {
    // let pkg_name = p_sec_string_to_string(pPackageName);
    let pkg_name = c_w_str_to_string(pPackageName);

    *ppPackageInfo = enumerate_security_packages()
        .unwrap()
        .into_iter()
        .find(|pkg| pkg.name.to_string() == pkg_name)
        .map(|pkg_info| into_raw_ptr(SecPkgInfoW::from(pkg_info)))
        .unwrap();

    0
}
pub type QUERY_SECURITY_PACKAGE_INFO_FN_W =
    unsafe extern "C" fn(*const SEC_WCHAR, *mut PSecPkgInfoW) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn ImportSecurityContextW(
    pszPackage: PSecurityString,
    pPackedContext: PSecBuffer,
    Token: *mut c_void,
    phContext: PCtxtHandle,
) -> SecurityStatus {
    unimplemented!("ImportSecurityContextW")
}
pub type IMPORT_SECURITY_CONTEXT_FN_W =
    extern "C" fn(PSecurityString, PSecBuffer, *mut c_void, PCtxtHandle) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn AddCredentialsW(
    phCredential: PCredHandle,
    s1: *mut SEC_WCHAR,
    s2: *mut SEC_WCHAR,
    n1: c_ulong,
    p1: *mut c_void,
    f: SEC_GET_KEY_FN,
    p2: *mut c_void,
    t: PTimeStamp,
) -> SecurityStatus {
    unimplemented!("AddCredentialsW")
}
pub type ADD_CREDENTIALS_FN_W = extern "C" fn(
    PCredHandle,
    *mut SEC_WCHAR,
    *mut SEC_WCHAR,
    c_ulong,
    *mut c_void,
    SEC_GET_KEY_FN,
    *mut c_void,
    PTimeStamp,
) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn SetContextAttributesW(
    phContext: PCtxtHandle,
    ulAttribute: c_ulong,
    pBuffer: *mut c_void,
    cbBuffer: c_ulong,
) -> SecurityStatus {
    unimplemented!("SetContextAttributesW")
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
    unimplemented!("SetCredentialsAttributesW")
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
    unimplemented!("ChangeAccountPasswordW")
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
    unimplemented!("QueryContextAttributesExW")
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
    unimplemented!("QueryCredentialsAttributesExW")
}
pub type QUERY_CREDENTIALS_ATTRIBUTES_EX_FN_W =
    extern "C" fn(PCredHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;
