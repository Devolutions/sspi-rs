use std::{
    ptr::{drop_in_place, null},
    slice::from_raw_parts,
};

#[cfg(not(target_os = "windows"))]
use libc::c_uint;
use libc::{c_char, c_long, c_ulong, c_ulonglong, c_ushort, c_void};
use num_traits::cast::{FromPrimitive, ToPrimitive};
use sspi::{
    AuthIdentityBuffers, DataRepresentation, DecryptionFlags, EncryptionFlags, ErrorKind,
    SecurityBuffer, SecurityBufferType, ServerRequestFlags, Sspi,
};

use crate::{
    copy_to_c_sec_buffer, p_ctxt_handle_to_kerberos, p_sec_buffers_to_security_buffers,
    security_buffers_to_raw,
};

pub type SecurityStatus = u32;

#[repr(C)]
pub struct SecHandle {
    pub dw_lower: c_ulonglong,
    pub dw_upper: c_ulonglong,
}

pub type PCredHandle = *mut SecHandle;
pub type PCtxtHandle = *mut SecHandle;

#[repr(C)]
pub struct SecurityInteger {
    pub low_part: c_ulong,
    pub high_part: c_long,
}

pub type PTimeStamp = *mut SecurityInteger;

#[repr(C)]
pub struct SecurityString {
    pub length: c_ushort,
    pub maximum_length: c_ushort,
    pub buffer: *mut c_ushort,
}

pub type PSecurityString = *mut SecurityString;

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct SecBuffer {
    pub cb_buffer: c_ulong,
    pub buffer_type: c_ulong,
    pub pv_buffer: *mut c_char,
}

#[cfg(not(target_os = "windows"))]
#[repr(C)]
pub struct SecBuffer {
    pub cb_buffer: c_uint,
    pub buffer_type: c_uint,
    pub pv_buffer: *mut c_char,
}

pub type PSecBuffer = *mut SecBuffer;

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct SecBufferDesc {
    pub ul_version: c_ulong,
    pub c_buffers: c_ulong,
    pub p_buffers: PSecBuffer,
}

#[cfg(not(target_os = "windows"))]
#[repr(C)]
pub struct SecBufferDesc {
    pub ul_version: c_uint,
    pub c_buffers: c_uint,
    pub p_buffers: PSecBuffer,
}

pub type PSecBufferDesc = *mut SecBufferDesc;

#[cfg(target_os = "windows")]
#[repr(C)]
pub struct SecPkgContextSizes {
    pub cb_max_token: c_ulong,
    pub cb_max_signature: c_ulong,
    pub cb_block_size: c_ulong,
    pub cb_security_trailer: c_ulong,
}

#[cfg(not(target_os = "windows"))]
#[repr(C)]
pub struct SecPkgContextSizes {
    pub cb_max_token: c_uint,
    pub cb_max_signature: c_uint,
    pub cb_block_size: c_uint,
    pub cb_security_trailer: c_uint,
}

pub type SecGetKeyFn =
    extern "system" fn(*mut c_void, *mut c_void, u32, *mut *mut c_void, *mut i32);

#[no_mangle]
pub unsafe extern "system" fn FreeCredentialsHandle(ph_credential: PCredHandle) -> SecurityStatus {
    drop_in_place((*ph_credential).dw_lower as *mut AuthIdentityBuffers);
    drop_in_place(ph_credential);

    0
}
pub type FreeCredentialsHandleFn = unsafe extern "system" fn(PCredHandle) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "system" fn AcceptSecurityContext(
    ph_credential: PCredHandle,
    ph_context: PCtxtHandle,
    p_input: PSecBufferDesc,
    f_context_req: c_ulong,
    target_data_rep: c_ulong,
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

    let kerberos = p_ctxt_handle_to_kerberos(ph_context).as_mut().unwrap();

    let raw_buffers = from_raw_parts((*p_input).p_buffers, (*p_input).c_buffers as usize);
    let mut input_tokens = p_sec_buffers_to_security_buffers(raw_buffers);

    let mut output_token = vec![SecurityBuffer::new(
        Vec::with_capacity(1024),
        SecurityBufferType::Token,
    )];

    let result_status = kerberos
        .accept_security_context()
        .with_credentials_handle(&mut auth_data)
        .with_context_requirements(
            ServerRequestFlags::from_bits(f_context_req.try_into().unwrap()).unwrap(),
        )
        .with_target_data_representation(
            DataRepresentation::from_u32(target_data_rep.try_into().unwrap()).unwrap(),
        )
        .with_input(&mut input_tokens)
        .with_output(&mut output_token)
        .execute()
        .unwrap()
        .status;

    (*p_output).c_buffers = output_token.len().try_into().unwrap();
    (*p_output).p_buffers = security_buffers_to_raw(output_token);
    (*ph_new_context).dw_lower = (*ph_context).dw_lower;

    result_status.to_u32().unwrap()
}
pub type AcceptSecurityContextFn = unsafe extern "system" fn(
    PCredHandle,
    PCtxtHandle,
    PSecBufferDesc,
    c_ulong,
    c_ulong,
    PCtxtHandle,
    PSecBufferDesc,
    *mut c_ulong,
    PTimeStamp,
) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "system" fn CompleteAuthToken(
    ph_context: PCtxtHandle,
    p_token: PSecBufferDesc,
) -> SecurityStatus {
    let kerberos = p_ctxt_handle_to_kerberos(ph_context).as_mut().unwrap();

    let raw_buffers = from_raw_parts((*p_token).p_buffers, (*p_token).c_buffers as usize);
    let mut buffers = p_sec_buffers_to_security_buffers(raw_buffers);

    kerberos.complete_auth_token(&mut buffers).map_or_else(
        |err| err.error_type.to_u32().unwrap(),
        |result| result.to_u32().unwrap(),
    )
}
pub type CompleteAuthTokenFn =
    unsafe extern "system" fn(PCtxtHandle, PSecBufferDesc) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "system" fn DeleteSecurityContext(ph_context: PCtxtHandle) -> SecurityStatus {
    drop_in_place(p_ctxt_handle_to_kerberos(ph_context));
    drop_in_place(ph_context);

    0
}
pub type DeleteSecurityContextFn = unsafe extern "system" fn(PCtxtHandle) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn ApplyControlToken(
    _ph_context: PCtxtHandle,
    _p_input: PSecBufferDesc,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type ApplyControlTokenFn = extern "system" fn(PCtxtHandle, PSecBufferDesc) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn ImpersonateSecurityContext(_ph_context: PCtxtHandle) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type ImpersonateSecurityContextFn = extern "system" fn(PCtxtHandle) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn RevertSecurityContext(_ph_context: PCtxtHandle) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type RevertSecurityContextFn = extern "system" fn(PCtxtHandle) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn MakeSignature(
    _ph_context: PCtxtHandle,
    _f_qop: c_ulong,
    _p_message: PSecBufferDesc,
    _message_seq_no: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type MakeSignatureFn =
    extern "system" fn(PCtxtHandle, c_ulong, PSecBufferDesc, c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn VerifySignature(
    _ph_context: PCtxtHandle,
    _message: PSecBufferDesc,
    _message_seq_no: c_ulong,
    _pf_qop: *mut c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type VerifySignatureFn =
    extern "system" fn(PCtxtHandle, PSecBufferDesc, c_ulong, *mut c_ulong) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "system" fn FreeContextBuffer(pv_context_buffer: *mut c_void) -> SecurityStatus {
    drop_in_place(pv_context_buffer);
    0
}
pub type FreeContextBufferFn = unsafe extern "system" fn(*mut c_void) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn ExportSecurityContext(
    _ph_context: PCtxtHandle,
    _f_flags: c_ulong,
    _p_packed_context: PSecBuffer,
    _p_token: *mut *mut c_void,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type ExportSecurityContextFn =
    extern "system" fn(PCtxtHandle, c_ulong, PSecBuffer, *mut *mut c_void) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn QuerySecurityContextToken(
    _ph_context: PCtxtHandle,
    _token: *mut *mut c_void,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QuerySecurityContextTokenFn =
    extern "system" fn(PCtxtHandle, *mut *mut c_void) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "system" fn EncryptMessage(
    ph_context: PCtxtHandle,
    f_qop: c_ulong,
    p_message: PSecBufferDesc,
    message_seq_no: c_ulong,
) -> SecurityStatus {
    let kerberos = p_ctxt_handle_to_kerberos(ph_context).as_mut().unwrap();

    let len = (*p_message).c_buffers as usize;
    let raw_buffers = from_raw_parts((*p_message).p_buffers, len);
    let mut message = p_sec_buffers_to_security_buffers(raw_buffers);

    let result_status = match kerberos.encrypt_message(
        EncryptionFlags::from_bits(f_qop.try_into().unwrap()).unwrap(),
        &mut message,
        message_seq_no.try_into().unwrap(),
    ) {
        Ok(status) => status.to_u32().unwrap(),
        Err(error) => error.error_type.to_u32().unwrap(),
    };

    copy_to_c_sec_buffer(&message, (*p_message).p_buffers);

    result_status
}
pub type EncryptMessageFn =
    unsafe extern "system" fn(PCtxtHandle, c_ulong, PSecBufferDesc, c_ulong) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "system" fn DecryptMessage(
    ph_context: PCtxtHandle,
    p_message: PSecBufferDesc,
    message_seq_no: c_ulong,
    pf_qop: *mut c_ulong,
) -> SecurityStatus {
    let kerberos = p_ctxt_handle_to_kerberos(ph_context).as_mut().unwrap();

    let len = (*p_message).c_buffers as usize;
    let raw_buffers = from_raw_parts((*p_message).p_buffers, len);
    let mut message = p_sec_buffers_to_security_buffers(raw_buffers);

    let (decryption_flags, status) =
        match kerberos.decrypt_message(&mut message, message_seq_no.try_into().unwrap()) {
            Ok(flags) => (flags, 0),
            Err(error) => (DecryptionFlags::empty(), error.error_type.to_u32().unwrap()),
        };

    copy_to_c_sec_buffer(&message, (*p_message).p_buffers);
    *pf_qop = decryption_flags.bits().try_into().unwrap();

    status
}
pub type DecryptMessageFn =
    unsafe extern "system" fn(PCtxtHandle, PSecBufferDesc, c_ulong, *mut c_ulong) -> SecurityStatus;
