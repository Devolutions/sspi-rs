use std::{ptr::null, slice::from_raw_parts};

use libc::{c_ulong, c_ulonglong, c_ushort, c_void};
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
pub struct SecPkgInfoW {
    pub f_capabilities: c_ulong,
    pub w_version: c_ushort,
    pub w_rpc_id: c_ushort,
    pub cb_max_token: c_ulong,
    pub name: *mut SecWChar,
    pub comment: *mut SecWChar,
}

pub type PSecPkgInfoW = *mut SecPkgInfoW;

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
pub struct SecWinntAuthIdentityW {
    user: *const c_ushort,
    user_length: c_ulong,
    domain: *const c_ushort,
    domain_length: c_ulong,
    password: *const c_ushort,
    password_length: c_ulong,
    flags: c_ulong,
}

pub type LpcWStr = *const SecWChar;

pub type SecWChar = c_ushort;

unsafe fn raw_w_str_to_bytes(raw_buffer: *const c_ushort, len: usize) -> Vec<u8> {
    from_raw_parts(raw_buffer, len)
        .iter()
        .flat_map(|w_char| w_char.to_le_bytes())
        .collect()
}

unsafe fn c_w_str_to_string(s: *const SecWChar) -> String {
    let mut len = 0;

    while *(s.add(len)) != 0 {
        len += 1;
    }

    String::from_utf16_lossy(from_raw_parts(s, len + 1))
}

#[no_mangle]
pub unsafe extern "C" fn EnumerateSecurityPackagesW(
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
pub type EnumerateSecurityPackagesFnW =
    unsafe extern "C" fn(*mut c_ulong, *mut PSecPkgInfoW) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn QueryCredentialsAttributesW(
    _ph_credential: PCredHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QueryCredentialsAttributesFnW =
    extern "C" fn(PCredHandle, c_ulong, *mut c_void) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "C" fn AcquireCredentialsHandleW(
    _psz_principal: LpcWStr,
    _psz_package: LpcWStr,
    _f_credential_use: c_ulong,
    _pv_logon_id: *const c_void,
    p_auth_data: *const c_void,
    _p_get_key_fn: SecGetKeyFn,
    _pv_get_key_argument: *const c_void,
    ph_credential: PCredHandle,
    _pts_expiry: PTimeStamp,
) -> SecurityStatus {
    let auth_data = p_auth_data.cast::<SecWinntAuthIdentityW>();

    let creds = AuthIdentityBuffers {
        user: raw_w_str_to_bytes((*auth_data).user, (*auth_data).user_length as usize),
        domain: raw_w_str_to_bytes((*auth_data).domain, (*auth_data).domain_length as usize),
        password: raw_w_str_to_bytes((*auth_data).password, (*auth_data).password_length as usize),
    };

    (*ph_credential).dw_lower = into_raw_ptr(creds) as c_ulonglong;

    0
}
pub type AcquireCredentialsHandleFnW = unsafe extern "C" fn(
    LpcWStr,
    LpcWStr,
    c_ulong,
    *const c_void,
    *const c_void,
    SecGetKeyFn,
    *const c_void,
    PCredHandle,
    PTimeStamp,
) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "C" fn InitializeSecurityContextW(
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

    let raw_buffers = from_raw_parts((*p_output).p_buffers, (*p_output).c_buffers as usize);
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

    (*p_output).c_buffers = output_tokens.len().try_into().unwrap();
    (*p_output).p_buffers = security_buffers_to_raw(output_tokens);
    (*ph_new_context).dw_lower = kerberos_ptr as c_ulonglong;

    result_status.map_or_else(
        |err| err.error_type.to_u32().unwrap(),
        |result| result.status.to_u32().unwrap(),
    )
}
pub type InitializeSecurityContextFnW = unsafe extern "C" fn(
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
pub unsafe extern "C" fn QueryContextAttributesW(
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
pub type QueryContextAttributesFnW =
    unsafe extern "C" fn(PCtxtHandle, c_ulong, *mut c_void) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "C" fn QuerySecurityPackageInfoW(
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
pub type QuerySecurityPackageInfoFnW =
    unsafe extern "C" fn(*const SecWChar, *mut PSecPkgInfoW) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn ImportSecurityContextW(
    _psz_package: PSecurityString,
    _p_packed_context: PSecBuffer,
    _token: *mut c_void,
    _ph_context: PCtxtHandle,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type ImportSecurityContextFnW =
    extern "C" fn(PSecurityString, PSecBuffer, *mut c_void, PCtxtHandle) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn AddCredentialsW(
    _ph_credential: PCredHandle,
    _s1: *mut SecWChar,
    _s2: *mut SecWChar,
    _n1: c_ulong,
    _p1: *mut c_void,
    _f: SecGetKeyFn,
    _p2: *mut c_void,
    _t: PTimeStamp,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type AddCredentialsFnW = extern "C" fn(
    PCredHandle,
    *mut SecWChar,
    *mut SecWChar,
    c_ulong,
    *mut c_void,
    SecGetKeyFn,
    *mut c_void,
    PTimeStamp,
) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn SetContextAttributesW(
    _ph_context: PCtxtHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _cb_buffer: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type SetContextAttributesFnW =
    extern "C" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn SetCredentialsAttributesW(
    _ph_context: PCtxtHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _cb_buffer: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type SetCredentialsAttributesFnW =
    extern "C" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn ChangeAccountPasswordW(
    _psz_package_name: *mut SecWChar,
    _psz_domain_name: *mut SecWChar,
    _psz_account_name: *mut SecWChar,
    _psz_old_password: *mut SecWChar,
    _psz_new_password: *mut SecWChar,
    _b_impersonating: bool,
    _dw_reserved: c_ulong,
    _p_output: PSecBufferDesc,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type ChangeAccountPasswordFnW = extern "C" fn(
    *mut SecWChar,
    *mut SecWChar,
    *mut SecWChar,
    *mut SecWChar,
    *mut SecWChar,
    bool,
    c_ulong,
    PSecBufferDesc,
) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn QueryContextAttributesExW(
    _ph_context: PCtxtHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _cb_buffer: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QueryContextAttributesExFnW =
    extern "C" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn QueryCredentialsAttributesExW(
    _ph_aredential: PCredHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _c_buffers: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QueryCredentialsAttributesExFnW =
    extern "C" fn(PCredHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;
