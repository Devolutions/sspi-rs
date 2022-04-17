use std::{ptr::null, slice::from_raw_parts};

use libc::{c_char, c_int, c_long, c_ulong, c_ulonglong, c_ushort, c_void, free};
use num_traits::cast::{FromPrimitive, ToPrimitive};
use sspi::{
    AuthIdentity, AuthIdentityBuffers, ClientRequestFlags, CredentialUse, DataRepresentation,
    EncryptionFlags, SecurityBuffer, SecurityBufferType, ServerRequestFlags, Sspi,
};

use crate::{
    p_ctxt_handle_to_kerberos, p_sec_buffers_to_security_buffers, security_buffers_to_raw,
};

pub type SecurityStatus = i32;

#[repr(C)]
pub struct SecHandle {
    pub dwLower: c_ulonglong,
    pub dwUpper: c_ulonglong,
}

pub type PCredHandle = *mut SecHandle;
pub type PCtxtHandle = *mut SecHandle;

#[repr(C)]
pub struct SecurityInteger {
    pub LowPart: c_ulong,
    pub HighPart: c_long,
}

pub type PTimeStamp = *mut SecurityInteger;

#[repr(C)]
pub struct SecurityString {
    pub Length: c_ushort,
    pub MaximumLength: c_ushort,
    pub Buffer: *mut c_ushort,
}

pub type PSecurityString = *mut SecurityString;

#[repr(C)]
pub struct SecBuffer {
    pub cbBuffer: c_ulong,
    pub BufferType: c_ulong,
    pub pvBuffer: *mut c_char,
}

pub type PSecBuffer = *mut SecBuffer;

#[repr(C)]
pub struct SecBufferDesc {
    pub ulVersion: c_ulong,
    pub cBuffers: c_ulong,
    pub pBuffers: PSecBuffer,
}

pub type PSecBufferDesc = *mut SecBufferDesc;

pub type SEC_GET_KEY_FN = fn(*mut c_void, *mut c_void, u32, *mut *mut c_void, *mut i32);

pub type CredSspCredType = c_int;

#[repr(C)]
pub struct CredSspCred {
    pub Type: CredSspCredType,
    pub pSchannelCred: *mut c_void,
    pub pSpnegoCred: *mut c_void,
}

#[no_mangle]
pub extern "C" fn FreeCredentialsHandle(phCredential: PCredHandle) -> SecurityStatus {
    0
}
pub type FREE_CREDENTIALS_HANDLE_FN = extern "C" fn(PCredHandle) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "C" fn AcceptSecurityContext(
    phCredential: PCredHandle,
    phContext: PCtxtHandle,
    pInput: PSecBufferDesc,
    fContextReq: c_ulong,
    TargetDataRep: c_ulong,
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

    let kerberos = p_ctxt_handle_to_kerberos(phContext).as_mut().unwrap();

    let len = (*pInput).cBuffers as usize;

    let raw_buffers = from_raw_parts((*pInput).pBuffers, len);
    let mut input_tokens = p_sec_buffers_to_security_buffers(raw_buffers);

    let mut output_token = vec![SecurityBuffer::new(
        Vec::with_capacity(1024),
        SecurityBufferType::Token,
    )];

    let result_status = kerberos
        .accept_security_context()
        .with_credentials_handle(&mut auth_data)
        .with_context_requirements(ServerRequestFlags::from_bits(fContextReq).unwrap())
        .with_target_data_representation(DataRepresentation::from_u32(TargetDataRep).unwrap())
        .with_input(&mut input_tokens)
        .with_output(&mut output_token)
        .execute()
        .unwrap()
        .status;

    (*pOutput).cBuffers = output_token.len() as c_ulong;

    (*pOutput).pBuffers = security_buffers_to_raw(output_token);

    (*phNewContext).dwLower = (*phContext).dwLower;

    result_status.to_i32().unwrap()
}
pub type ACCEPT_SECURITY_CONTEXT_FN = unsafe extern "C" fn(
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
pub unsafe extern "C" fn CompleteAuthToken(
    phContext: PCtxtHandle,
    pToken: PSecBufferDesc,
) -> SecurityStatus {
    let kerberos = p_ctxt_handle_to_kerberos(phContext).as_mut().unwrap();

    let len = (*pToken).cBuffers as usize;

    let raw_buffers = from_raw_parts((*pToken).pBuffers, len);
    let mut buffers = p_sec_buffers_to_security_buffers(raw_buffers);

    match kerberos.complete_auth_token(&mut buffers) {
        Ok(status) => status.to_i32().unwrap(),
        Err(err) => err.error_type.to_i32().unwrap(),
    }
}
pub type COMPLETE_AUTH_TOKEN_FN =
    unsafe extern "C" fn(PCtxtHandle, PSecBufferDesc) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "C" fn DeleteSecurityContext(phContext: PCtxtHandle) -> SecurityStatus {
    // free(p_ctxt_handle_to_kerberos(phContext) as *mut c_void);

    (*phContext).dwLower = 0;
    (*phContext).dwUpper = 0;

    0
}
pub type DELETE_SECURITY_CONTEXT_FN = unsafe extern "C" fn(PCtxtHandle) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn ApplyControlToken(
    phContext: PCtxtHandle,
    pInput: PSecBufferDesc,
) -> SecurityStatus {
    unimplemented!("ApplyControlToken")
}
pub type APPLY_CONTROL_TOKEN_FN = extern "C" fn(PCtxtHandle, PSecBufferDesc) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn ImpersonateSecurityContext(phContext: PCtxtHandle) -> SecurityStatus {
    unimplemented!("ImpersonateSecurityContext")
}
pub type IMPERSONATE_SECURITY_CONTEXT_FN = extern "C" fn(PCtxtHandle) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn RevertSecurityContext(phContext: PCtxtHandle) -> SecurityStatus {
    unimplemented!("RevertSecurityContext")
}
pub type REVERT_SECURITY_CONTEXT_FN = extern "C" fn(PCtxtHandle) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn MakeSignature(
    phContext: PCtxtHandle,
    fQOP: c_ulong,
    pMessage: PSecBufferDesc,
    MessageSeqNo: c_ulong,
) -> SecurityStatus {
    unimplemented!("MakeSignature")
}
pub type MAKE_SIGNATURE_FN =
    extern "C" fn(PCtxtHandle, c_ulong, PSecBufferDesc, c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn VerifySignature(
    phContext: PCtxtHandle,
    message: PSecBufferDesc,
    MessageSeqNo: c_ulong,
    pfQOP: *mut c_ulong,
) -> SecurityStatus {
    unimplemented!("VerifySignature")
}
pub type VERIFY_SIGNATURE_FN =
    extern "C" fn(PCtxtHandle, PSecBufferDesc, c_ulong, *mut c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn FreeContextBuffer(pvContextBuffer: *mut c_void) -> SecurityStatus {
    // free(pvContextBuffer);
    0
}
pub type FREE_CONTEXT_BUFFER_FN = extern "C" fn(*mut c_void) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn ExportSecurityContext(
    phContext: PCtxtHandle,
    fFlags: c_ulong,
    pPackedContext: PSecBuffer,
    pToken: *mut *mut c_void,
) -> SecurityStatus {
    unimplemented!("ExportSecurityContext")
}
pub type EXPORT_SECURITY_CONTEXT_FN =
    extern "C" fn(PCtxtHandle, c_ulong, PSecBuffer, *mut *mut c_void) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn QuerySecurityContextToken(
    phContext: PCtxtHandle,
    Token: *mut *mut c_void,
) -> SecurityStatus {
    unimplemented!("QuerySecurityContextToken")
}
pub type QUERY_SECURITY_CONTEXT_TOKEN_FN =
    extern "C" fn(PCtxtHandle, *mut *mut c_void) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "C" fn EncryptMessage(
    phContext: PCtxtHandle,
    fQOP: c_ulong,
    pMessage: PSecBufferDesc,
    MessageSeqNo: c_ulong,
) -> SecurityStatus {
    let kerberos = p_ctxt_handle_to_kerberos(phContext).as_mut().unwrap();

    let len = (*pMessage).cBuffers as usize;
    let raw_buffers = from_raw_parts((*pMessage).pBuffers, len);
    let mut message = p_sec_buffers_to_security_buffers(raw_buffers);

    let mut output_tokens = vec![SecurityBuffer::new(
        Vec::with_capacity(1024),
        SecurityBufferType::Token,
    )];

    let result_status = kerberos
        .encrypt_message(
            EncryptionFlags::from_bits(fQOP).unwrap(),
            &mut message,
            MessageSeqNo,
        )
        .unwrap();

    (*pMessage).cBuffers = message.len() as c_ulong;
    (*pMessage).pBuffers = security_buffers_to_raw(message);

    result_status.to_i32().unwrap()
}
pub type ENCRYPT_MESSAGE_FN =
    unsafe extern "C" fn(PCtxtHandle, c_ulong, PSecBufferDesc, c_ulong) -> SecurityStatus;

#[no_mangle]
pub unsafe extern "C" fn DecryptMessage(
    phContext: PCtxtHandle,
    pMessage: PSecBufferDesc,
    MessageSeqNo: c_ulong,
    pfQOP: *mut c_ulong,
) -> SecurityStatus {
    let kerberos = p_ctxt_handle_to_kerberos(phContext).as_mut().unwrap();

    let len = (*pMessage).cBuffers as usize;
    let raw_buffers = from_raw_parts((*pMessage).pBuffers, len);
    let mut message = p_sec_buffers_to_security_buffers(raw_buffers);

    let mut output_tokens = vec![SecurityBuffer::new(
        Vec::with_capacity(1024),
        SecurityBufferType::Token,
    )];

    let decryption_flags = kerberos
        .decrypt_message(&mut message, MessageSeqNo)
        .unwrap();

    (*pMessage).cBuffers = message.len() as c_ulong;
    (*pMessage).pBuffers = security_buffers_to_raw(message);
    *pfQOP = decryption_flags.bits();

    0
}
pub type DECRYPT_MESSAGE_FN =
    unsafe extern "C" fn(PCtxtHandle, PSecBufferDesc, c_ulong, *mut c_ulong) -> SecurityStatus;
