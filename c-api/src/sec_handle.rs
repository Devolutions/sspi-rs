use std::ffi::CStr;
use std::ptr::null;
use std::slice::from_raw_parts;

use libc::{c_ulong, c_ulonglong, c_void};
use num_traits::{FromPrimitive, ToPrimitive};
use sspi::kerberos::config::KerberosConfig;
use sspi::{AuthIdentityBuffers, ClientRequestFlags, DataRepresentation, ErrorKind, Kerberos, Sspi};

use crate::sec_buffer::{
    p_sec_buffers_to_security_buffers, security_buffers_to_raw, PSecBuffer, PSecBufferDesc, SecBufferDesc,
};
use crate::sec_winnt_auth_identity::{SecWinntAuthIdentityA, SecWinntAuthIdentityW};
use crate::sspi_data_types::{
    LpStr, LpcWStr, PSecurityString, PTimeStamp, SecChar, SecGetKeyFn, SecPkgContextSizes, SecWChar, SecurityStatus,
};
use crate::utils::{c_w_str_to_string, into_raw_ptr, raw_str_into_bytes, raw_w_str_to_bytes};

#[repr(C)]
pub struct SecHandle {
    pub dw_lower: c_ulonglong,
    pub dw_upper: c_ulonglong,
}

pub type PCredHandle = *mut SecHandle;
pub type PCtxtHandle = *mut SecHandle;

pub(crate) unsafe fn p_ctxt_handle_to_kerberos(mut context: PCtxtHandle) -> *mut Kerberos {
    if context == null::<SecHandle>() as *mut _ {
        context = into_raw_ptr(SecHandle {
            dw_lower: 0,
            dw_upper: 0,
        });
    }
    if (*context).dw_lower == 0 {
        (*context).dw_lower =
            into_raw_ptr(Kerberos::new_client_from_config(KerberosConfig::from_env()).unwrap()) as c_ulonglong;
    }
    (*context).dw_lower as *mut Kerberos
}

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
        password: raw_str_into_bytes((*auth_data).password, (*auth_data).password_length as usize * 2),
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
pub unsafe extern "system" fn AcquireCredentialsHandleW(
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
pub type AcquireCredentialsHandleFnW = unsafe extern "system" fn(
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
pub extern "system" fn QueryCredentialsAttributesA(
    _ph_credential: PCredHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QueryCredentialsAttributesFnA = extern "system" fn(PCredHandle, c_ulong, *mut c_void) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn QueryCredentialsAttributesW(
    _ph_credential: PCredHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QueryCredentialsAttributesFnW = extern "system" fn(PCredHandle, c_ulong, *mut c_void) -> SecurityStatus;

#[allow(clippy::useless_conversion)]
#[no_mangle]
pub unsafe extern "system" fn InitializeSecurityContextA(
    ph_credential: PCredHandle,
    ph_context: PCtxtHandle,
    p_target_name: *const SecChar,
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

    let service_principal = CStr::from_ptr(p_target_name).to_str().unwrap();

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
        p_sec_buffers_to_security_buffers(from_raw_parts((*p_input).p_buffers, (*p_input).c_buffers as usize))
    };

    let len = (*p_output).c_buffers as usize;
    let raw_buffers = from_raw_parts((*p_output).p_buffers, len);
    let mut output_tokens = p_sec_buffers_to_security_buffers(raw_buffers);
    output_tokens.iter_mut().for_each(|s| s.buffer.clear());

    let result_status = kerberos
        .initialize_security_context()
        .with_credentials_handle(&mut auth_data)
        .with_context_requirements(ClientRequestFlags::from_bits(f_context_req.try_into().unwrap()).unwrap())
        .with_target_data_representation(DataRepresentation::from_u32(target_data_rep.try_into().unwrap()).unwrap())
        .with_target_name(service_principal)
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
    *const SecChar,
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

#[allow(clippy::useless_conversion)]
#[no_mangle]
pub unsafe extern "system" fn InitializeSecurityContextW(
    ph_credential: PCredHandle,
    ph_context: PCtxtHandle,
    p_target_name: *const SecWChar,
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

    let service_principal = c_w_str_to_string(p_target_name);

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
        p_sec_buffers_to_security_buffers(from_raw_parts((*p_input).p_buffers, (*p_input).c_buffers as usize))
    };

    let raw_buffers = from_raw_parts((*p_output).p_buffers, (*p_output).c_buffers as usize);
    let mut output_tokens = p_sec_buffers_to_security_buffers(raw_buffers);
    output_tokens.iter_mut().for_each(|s| s.buffer.clear());

    let result_status = kerberos
        .initialize_security_context()
        .with_credentials_handle(&mut auth_data)
        .with_context_requirements(ClientRequestFlags::from_bits(f_context_req.try_into().unwrap()).unwrap())
        .with_target_data_representation(DataRepresentation::from_u32(target_data_rep.try_into().unwrap()).unwrap())
        .with_target_name(&service_principal)
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
pub type InitializeSecurityContextFnW = unsafe extern "system" fn(
    PCredHandle,
    PCtxtHandle,
    *const SecWChar,
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
pub type QueryContextAttributesFnA = unsafe extern "system" fn(PCtxtHandle, c_ulong, *mut c_void) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "system" fn QueryContextAttributesW(
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
pub type QueryContextAttributesFnW = unsafe extern "system" fn(PCtxtHandle, c_ulong, *mut c_void) -> SecurityStatus;

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
pub extern "system" fn ImportSecurityContextW(
    _psz_package: PSecurityString,
    _p_packed_context: PSecBuffer,
    _token: *mut c_void,
    _ph_context: PCtxtHandle,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type ImportSecurityContextFnW =
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
pub extern "system" fn AddCredentialsW(
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
pub type AddCredentialsFnW = extern "system" fn(
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
pub extern "system" fn SetContextAttributesA(
    _ph_context: PCtxtHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _cb_buffer: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type SetContextAttributesFnA = extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn SetContextAttributesW(
    _ph_context: PCtxtHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _cb_buffer: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type SetContextAttributesFnW = extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn SetCredentialsAttributesA(
    _ph_context: PCtxtHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _cb_buffer: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type SetCredentialsAttributesFnA = extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn SetCredentialsAttributesW(
    _ph_context: PCtxtHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _cb_buffer: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type SetCredentialsAttributesFnW = extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

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
pub extern "system" fn ChangeAccountPasswordW(
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
pub type ChangeAccountPasswordFnW = extern "system" fn(
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
pub extern "system" fn QueryContextAttributesExA(
    _ph_context: PCtxtHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _cb_buffer: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QueryContextAttributesExFnA = extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn QueryContextAttributesExW(
    _ph_context: PCtxtHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _cb_buffer: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QueryContextAttributesExFnW = extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

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

#[no_mangle]
pub extern "system" fn QueryCredentialsAttributesExW(
    _ph_aredential: PCredHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _c_buffers: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QueryCredentialsAttributesExFnW =
    extern "system" fn(PCredHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;
