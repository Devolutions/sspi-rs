use std::ptr::{drop_in_place, null};
use std::slice::from_raw_parts;

use libc::{c_ulong, c_void};
use num_traits::cast::{FromPrimitive, ToPrimitive};
use sspi::{
    AuthIdentityBuffers, DataRepresentation, DecryptionFlags, EncryptionFlags, ErrorKind, SecurityBuffer,
    SecurityBufferType, ServerRequestFlags, Sspi,
};

use crate::sec_buffer::{
    copy_to_c_sec_buffer, p_sec_buffers_to_security_buffers, security_buffers_to_raw, PSecBuffer, PSecBufferDesc,
};
use crate::sec_handle::{p_ctxt_handle_to_security_package, PCredHandle, PCtxtHandle};
use crate::sspi_data_types::{PTimeStamp, SecurityStatus};
use crate::utils::into_raw_ptr;

#[no_mangle]
pub unsafe extern "system" fn FreeCredentialsHandle(ph_credential: PCredHandle) -> SecurityStatus {
    drop_in_place((*ph_credential).dw_lower as *mut AuthIdentityBuffers);
    drop_in_place(ph_credential);

    0
}
pub type FreeCredentialsHandleFn = unsafe extern "system" fn(PCredHandle) -> SecurityStatus;

#[allow(clippy::useless_conversion)]
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

    let mut kerberos = p_ctxt_handle_to_security_package(ph_context);

    let raw_buffers = from_raw_parts((*p_input).p_buffers, (*p_input).c_buffers as usize);
    let mut input_tokens = p_sec_buffers_to_security_buffers(raw_buffers);

    let mut output_token = vec![SecurityBuffer::new(Vec::with_capacity(1024), SecurityBufferType::Token)];

    let result_status = kerberos
        .accept_security_context()
        .with_credentials_handle(&mut auth_data)
        .with_context_requirements(ServerRequestFlags::from_bits(f_context_req.try_into().unwrap()).unwrap())
        .with_target_data_representation(DataRepresentation::from_u32(target_data_rep.try_into().unwrap()).unwrap())
        .with_input(&mut input_tokens)
        .with_output(&mut output_token)
        .execute()
        .unwrap()
        .status;

    (*p_output).c_buffers = output_token.len().try_into().unwrap();
    (*p_output).p_buffers = security_buffers_to_raw(output_token);
    (*ph_new_context).dw_lower = (*ph_context).dw_lower;

    into_raw_ptr(kerberos);

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
pub unsafe extern "system" fn CompleteAuthToken(ph_context: PCtxtHandle, p_token: PSecBufferDesc) -> SecurityStatus {
    let mut kerberos = p_ctxt_handle_to_security_package(ph_context);

    let raw_buffers = from_raw_parts((*p_token).p_buffers, (*p_token).c_buffers as usize);
    let mut buffers = p_sec_buffers_to_security_buffers(raw_buffers);

    let result = kerberos.complete_auth_token(&mut buffers).map_or_else(
        |err| err.error_type.to_u32().unwrap(),
        |result| result.to_u32().unwrap(),
    );

    into_raw_ptr(kerberos);

    result
}
pub type CompleteAuthTokenFn = unsafe extern "system" fn(PCtxtHandle, PSecBufferDesc) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "system" fn DeleteSecurityContext(ph_context: PCtxtHandle) -> SecurityStatus {
    let _ = p_ctxt_handle_to_security_package(ph_context);
    drop_in_place(ph_context);

    0
}
pub type DeleteSecurityContextFn = unsafe extern "system" fn(PCtxtHandle) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn ApplyControlToken(_ph_context: PCtxtHandle, _p_input: PSecBufferDesc) -> SecurityStatus {
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
pub type MakeSignatureFn = extern "system" fn(PCtxtHandle, c_ulong, PSecBufferDesc, c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "system" fn VerifySignature(
    _ph_context: PCtxtHandle,
    _message: PSecBufferDesc,
    _message_seq_no: c_ulong,
    _pf_qop: *mut c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type VerifySignatureFn = extern "system" fn(PCtxtHandle, PSecBufferDesc, c_ulong, *mut c_ulong) -> SecurityStatus;

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
pub extern "system" fn QuerySecurityContextToken(_ph_context: PCtxtHandle, _token: *mut *mut c_void) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QuerySecurityContextTokenFn = extern "system" fn(PCtxtHandle, *mut *mut c_void) -> SecurityStatus;

#[allow(clippy::useless_conversion)]
#[no_mangle]
pub unsafe extern "system" fn EncryptMessage(
    ph_context: PCtxtHandle,
    f_qop: c_ulong,
    p_message: PSecBufferDesc,
    message_seq_no: c_ulong,
) -> SecurityStatus {
    let mut kerberos = p_ctxt_handle_to_security_package(ph_context);

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

    into_raw_ptr(kerberos);

    result_status
}
pub type EncryptMessageFn = unsafe extern "system" fn(PCtxtHandle, c_ulong, PSecBufferDesc, c_ulong) -> SecurityStatus;

#[allow(clippy::useless_conversion)]
#[no_mangle]
pub unsafe extern "system" fn DecryptMessage(
    ph_context: PCtxtHandle,
    p_message: PSecBufferDesc,
    message_seq_no: c_ulong,
    pf_qop: *mut c_ulong,
) -> SecurityStatus {
    let mut kerberos = p_ctxt_handle_to_security_package(ph_context);

    let len = (*p_message).c_buffers as usize;
    let raw_buffers = from_raw_parts((*p_message).p_buffers, len);
    let mut message = p_sec_buffers_to_security_buffers(raw_buffers);

    let (decryption_flags, status) = match kerberos.decrypt_message(&mut message, message_seq_no.try_into().unwrap()) {
        Ok(flags) => (flags, 0),
        Err(error) => (DecryptionFlags::empty(), error.error_type.to_u32().unwrap()),
    };

    copy_to_c_sec_buffer(&message, (*p_message).p_buffers);
    *pf_qop = decryption_flags.bits().try_into().unwrap();

    into_raw_ptr(kerberos);

    status
}
pub type DecryptMessageFn =
    unsafe extern "system" fn(PCtxtHandle, PSecBufferDesc, c_ulong, *mut c_ulong) -> SecurityStatus;
