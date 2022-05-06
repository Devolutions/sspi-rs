use std::{ptr::null, slice::from_raw_parts};

use libc::{c_char, c_uint, c_ulong, c_ulonglong, c_ushort, c_void};
use num_traits::{FromPrimitive, ToPrimitive};
use sspi::{
    enumerate_security_packages, AuthIdentityBuffers, ClientRequestFlags, DataRepresentation,
    ErrorKind, PackageInfo, Sspi, KERBEROS_VERSION,
};

use crate::{
    common::{
        PCredHandle, PCtxtHandle, PSecBuffer, PSecBufferDesc, PSecurityString, PTimeStamp,
        SecBufferDesc, SecGetKeyFn, SecPkgContextSizes, SecurityStatus,
    },
    into_raw_ptr, p_ctxt_handle_to_kerberos, p_sec_buffers_to_security_buffers,
    security_buffers_to_raw, vec_into_raw_ptr,
};

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

#[repr(C)]
pub struct SecWinntAuthIdentityA {
    user: *const c_char,
    user_length: c_uint,
    domain: *const c_char,
    domain_length: c_uint,
    password: *const c_char,
    password_length: c_uint,
    flags: c_uint,
}

pub type LpStr = *const SecChar;

pub type SecChar = c_char;

unsafe fn raw_str_into_bytes(raw_buffer: *const c_char, len: usize) -> Vec<u8> {
    from_raw_parts(raw_buffer, len)
        .iter()
        .map(|c| *c as u8)
        .collect()
}

unsafe fn c_str_into_string(s: *const SecChar) -> String {
    let mut len = 0;

    while *(s.add(len)) != 0 {
        len += 1;
    }

    String::from_utf8(from_raw_parts(s as *const u8, len + 1).to_vec()).unwrap()
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
pub type EnumerateSecurityPackagesFnA =
    unsafe extern "system" fn(*mut c_ulong, *mut PSecPkgInfoA) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn QueryCredentialsAttributesA(
    _ph_credential: PCredHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QueryCredentialsAttributesFnA =
    extern "system" fn(PCredHandle, c_ulong, *mut c_void) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "system" fn AcquireCredentialsHandleA(
    _psz_principal: LpStr,
    _psz_package: LpStr,
    _f_aredential_use: c_ulong,
    _pv_logon_id: *const c_void,
    p_auth_data: *const c_void,
    _p_get_key_fn: SecGetKeyFn,
    _pv_get_key_argument: *const c_void,
    ph_credential: PCredHandle,
    _pts_expiry: PTimeStamp,
) -> SecurityStatus {
    let auth_data = p_auth_data.cast::<SecWinntAuthIdentityA>();

    let creds = AuthIdentityBuffers {
        user: raw_str_into_bytes((*auth_data).user, (*auth_data).user_length as usize * 2),
        domain: raw_str_into_bytes((*auth_data).domain, (*auth_data).domain_length as usize * 2),
        password: raw_str_into_bytes(
            (*auth_data).password,
            (*auth_data).password_length as usize * 2,
        ),
    };

    (*ph_credential).dw_lower = into_raw_ptr(creds) as c_ulonglong;

    0
}
pub type AcquireCredentialsHandleFnA = unsafe extern "system" fn(
    LpStr,
    LpStr,
    c_ulong,
    *const c_void,
    *const c_void,
    SecGetKeyFn,
    *const c_void,
    PCredHandle,
    PTimeStamp,
) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "system" fn InitializeSecurityContextA(
    ph_credential: PCredHandle,
    ph_context: PCtxtHandle,
    _p_target_name: PSecurityString,
    f_context_req: c_ulong,
    _reserved1: c_ulong,
    target_data_rep: c_ulong,
    p_input: PSecBufferDesc,
    _reserved2: c_ulong,
    ph_new_context: PCtxtHandle,
    p_output: PSecBufferDesc,
    _pf_context_attr: *mut c_ulong,
    _pts_expiry: PTimeStamp,
) -> SecurityStatus {
    let auth_data = (*ph_credential).dw_lower as *mut AuthIdentityBuffers;

    let mut auth_data = if auth_data == null::<AuthIdentityBuffers>() as *mut _ {
        None
    } else {
        Some(auth_data.as_mut().unwrap().clone())
    };

    let kerberos_ptr = p_ctxt_handle_to_kerberos(ph_context);
    let kerberos = kerberos_ptr.as_mut().unwrap();

    let mut input_tokens = if p_input == null::<SecBufferDesc>() as *mut _ {
        Vec::new()
    } else {
        p_sec_buffers_to_security_buffers(from_raw_parts(
            (*p_input).p_buffers,
            (*p_input).c_buffers as usize,
        ))
    };

    let len = (*p_output).c_buffers as usize;
    let raw_buffers = from_raw_parts((*p_output).p_buffers, len);
    let mut output_tokens = p_sec_buffers_to_security_buffers(raw_buffers);
    output_tokens.iter_mut().for_each(|s| s.buffer.clear());

    let result_status = kerberos
        .initialize_security_context()
        .with_credentials_handle(&mut auth_data)
        .with_context_requirements(
            ClientRequestFlags::from_bits(f_context_req.try_into().unwrap()).unwrap(),
        )
        .with_target_data_representation(
            DataRepresentation::from_u32(target_data_rep.try_into().unwrap()).unwrap(),
        )
        .with_input(&mut input_tokens)
        .with_output(&mut output_tokens)
        .execute();

    (*p_output).c_buffers = output_tokens.len() as u32;
    (*p_output).p_buffers = security_buffers_to_raw(output_tokens);
    (*ph_new_context).dw_lower = kerberos_ptr as c_ulonglong;

    result_status.map_or_else(
        |err| err.error_type.to_u32().unwrap(),
        |result| result.status.to_u32().unwrap(),
    )
}
pub type InitializeSecurityContextFnA = unsafe extern "system" fn(
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
pub unsafe extern "system" fn QueryContextAttributesA(
    ph_context: PCtxtHandle,
    ul_attribute: c_ulong,
    p_buffer: *mut c_void,
) -> SecurityStatus {
    match ul_attribute {
        0 => {
            let kerberos = p_ctxt_handle_to_kerberos(ph_context).as_mut().unwrap();
            let sizes = p_buffer as *mut SecPkgContextSizes;

            let pkg_sizes = kerberos.query_context_sizes().unwrap();

            (*sizes).cb_max_token = pkg_sizes.max_token;
            (*sizes).cb_max_signature = pkg_sizes.max_signature;
            (*sizes).cb_block_size = pkg_sizes.block;
            (*sizes).cb_security_trailer = pkg_sizes.security_trailer;

            0
        }
        _ => ErrorKind::UnsupportedFunction.to_u32().unwrap(),
    }
}
pub type QueryContextAttributesFnA =
    unsafe extern "system" fn(PCtxtHandle, c_ulong, *mut c_void) -> SecurityStatus;

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
pub type QuerySecurityPackageInfoFnA =
    unsafe extern "system" fn(*const SecChar, *mut PSecPkgInfoA) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn ImportSecurityContextA(
    _psz_package: PSecurityString,
    _p_packed_context: PSecBuffer,
    _token: *mut c_void,
    _ph_context: PCtxtHandle,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type ImportSecurityContextFnA =
    extern "system" fn(PSecurityString, PSecBuffer, *mut c_void, PCtxtHandle) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn AddCredentialsA(
    _ph_credential: PCredHandle,
    _s1: *mut SecChar,
    _s2: *mut SecChar,
    _n1: c_ulong,
    _p1: *mut c_void,
    _f: SecGetKeyFn,
    _p2: *mut c_void,
    _t: PTimeStamp,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type AddCredentialsFnA = extern "system" fn(
    PCredHandle,
    *mut SecChar,
    *mut SecChar,
    c_ulong,
    *mut c_void,
    SecGetKeyFn,
    *mut c_void,
    PTimeStamp,
) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn SetContextAttributesA(
    _ph_context: PCtxtHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _cb_buffer: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type SetContextAttributesFnA =
    extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn SetCredentialsAttributesA(
    _ph_context: PCtxtHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _cb_buffer: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type SetCredentialsAttributesFnA =
    extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn ChangeAccountPasswordA(
    _psz_package_name: *mut SecChar,
    _psz_domain_name: *mut SecChar,
    _psz_account_name: *mut SecChar,
    _psz_old_password: *mut SecChar,
    _psz_new_password: *mut SecChar,
    _b_impersonating: bool,
    _dw_reserved: c_ulong,
    _p_output: PSecBufferDesc,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type ChangeAccountPasswordFnA = extern "system" fn(
    *mut SecChar,
    *mut SecChar,
    *mut SecChar,
    *mut SecChar,
    *mut SecChar,
    bool,
    c_ulong,
    PSecBufferDesc,
) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn QueryContextAttributesExA(
    _ph_context: PCtxtHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _cb_buffer: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QueryContextAttributesExFnA =
    extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn QueryCredentialsAttributesExA(
    _ph_credential: PCredHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _c_buffers: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QueryCredentialsAttributesExFnA =
    extern "system" fn(PCredHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;
