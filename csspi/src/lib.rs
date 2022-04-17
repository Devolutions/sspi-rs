pub(crate) mod a;
pub(crate) mod common;
pub(crate) mod w;

use std::{ptr::null, slice::from_raw_parts};

use libc::{c_char, c_ulong, c_ulonglong, c_void};
use num_traits::{FromPrimitive, ToPrimitive};
use sspi::{Kerberos, SecurityBuffer, SecurityBufferType, KERBEROS_VERSION};

use crate::{
    common::{
        AcceptSecurityContext, ApplyControlToken, CompleteAuthToken, DecryptMessage,
        DeleteSecurityContext, EncryptMessage, ExportSecurityContext, FreeContextBuffer,
        FreeCredentialsHandle, ImpersonateSecurityContext, MakeSignature, PCtxtHandle, PSecBuffer,
        PSecurityString, QuerySecurityContextToken, RevertSecurityContext, SecBuffer, SecHandle,
        VerifySignature, ACCEPT_SECURITY_CONTEXT_FN, APPLY_CONTROL_TOKEN_FN,
        COMPLETE_AUTH_TOKEN_FN, DECRYPT_MESSAGE_FN, DELETE_SECURITY_CONTEXT_FN, ENCRYPT_MESSAGE_FN,
        EXPORT_SECURITY_CONTEXT_FN, FREE_CONTEXT_BUFFER_FN, FREE_CREDENTIALS_HANDLE_FN,
        IMPERSONATE_SECURITY_CONTEXT_FN, MAKE_SIGNATURE_FN, QUERY_SECURITY_CONTEXT_TOKEN_FN,
        REVERT_SECURITY_CONTEXT_FN, VERIFY_SIGNATURE_FN,
    },
    w::{
        AcquireCredentialsHandleW, AddCredentialsW, ChangeAccountPasswordW,
        EnumerateSecurityPackagesW, ImportSecurityContextW, InitializeSecurityContextW,
        QueryContextAttributesExW, QueryContextAttributesW, QueryCredentialsAttributesExW,
        QueryCredentialsAttributesW, QuerySecurityPackageInfoW, SetContextAttributesW,
        SetCredentialsAttributesW, ACQUIRE_CREDENTIALS_HANDLE_FN_W, ADD_CREDENTIALS_FN_W,
        CHANGE_PASSWORD_FN_W, ENUMERATE_SECURITY_PACKAGES_FN_W, IMPORT_SECURITY_CONTEXT_FN_W,
        INITIALIZE_SECURITY_CONTEXT_FN_W, QUERY_CONTEXT_ATTRIBUTES_EX_FN_W,
        QUERY_CONTEXT_ATTRIBUTES_FN_W, QUERY_CREDENTIALS_ATTRIBUTES_EX_FN_W,
        QUERY_CREDENTIALS_ATTRIBUTES_FN_W, QUERY_SECURITY_PACKAGE_INFO_FN_W,
        SET_CONTEXT_ATTRIBUTES_FN_W, SET_CREDENTIALS_ATTRIBUTES_FN_W,
    },
};

pub(crate) unsafe fn p_ctxt_handle_to_kerberos(mut context: PCtxtHandle) -> *mut Kerberos {
    if context == null::<SecHandle>() as *mut _ {
        context = into_raw_ptr(SecHandle {
            dwLower: 0,
            dwUpper: 0,
        });
    }
    if (*context).dwLower == 0 {
        (*context).dwLower = into_raw_ptr(Kerberos::new_client_from_env()) as c_ulonglong;
    }
    (*context).dwLower as *mut Kerberos
}

pub(crate) fn into_raw_ptr<T>(value: T) -> *mut T {
    Box::into_raw(Box::new(value))
}

pub(crate) unsafe fn p_sec_buffers_to_security_buffers(
    raw_buffers: &[SecBuffer],
) -> Vec<SecurityBuffer> {
    raw_buffers
        .iter()
        .map(|raw_buffer| SecurityBuffer {
            buffer: from_raw_parts(raw_buffer.pvBuffer, raw_buffer.cbBuffer as usize)
                .into_iter()
                .map(|v| *v as u8)
                .collect(),
            buffer_type: SecurityBufferType::from_u32(raw_buffer.BufferType).unwrap(),
        })
        .collect()
}

pub(crate) unsafe fn security_buffers_to_raw(buffers: Vec<SecurityBuffer>) -> PSecBuffer {
    let mut sec_buffers = buffers
        .into_iter()
        .map(|mut buffer| {
            let cbBuffer = buffer.buffer.len() as c_ulong;
            let BufferType = buffer.buffer_type.to_u32().unwrap();

            let pvBuffer = buffer.buffer.as_mut_ptr() as *mut i8;
            into_raw_ptr(buffer.buffer);

            SecBuffer {
                cbBuffer,
                BufferType,
                pvBuffer,
            }
        })
        .collect::<Vec<_>>();

    let ptr = sec_buffers.as_mut_ptr();
    into_raw_ptr(sec_buffers);

    ptr
}

pub(crate) unsafe fn p_sec_string_to_string(s: PSecurityString) -> String {
    println!("================> ofimrefomerfmeromerfjov");
    let mut len = (*s).Length as usize;
    let max_len = (*s).MaximumLength as usize;

    if len > max_len {
        len = max_len;
    }

    String::from_utf16_lossy(&from_raw_parts((*s).Buffer, len))
}

#[repr(C)]
pub struct SecurityFunctionTableW {
    dwVersion: c_ulong,
    EnumerateSecurityPackagesW: ENUMERATE_SECURITY_PACKAGES_FN_W,
    QueryCredentialsAttributesW: QUERY_CREDENTIALS_ATTRIBUTES_FN_W,
    AcquireCredentialsHandleW: ACQUIRE_CREDENTIALS_HANDLE_FN_W,
    FreeCredentialsHandle: FREE_CREDENTIALS_HANDLE_FN,
    Reserved2: *const c_void,
    InitializeSecurityContextW: INITIALIZE_SECURITY_CONTEXT_FN_W,
    AcceptSecurityContext: ACCEPT_SECURITY_CONTEXT_FN,
    CompleteAuthToken: COMPLETE_AUTH_TOKEN_FN,
    DeleteSecurityContext: DELETE_SECURITY_CONTEXT_FN,
    ApplyControlToken: APPLY_CONTROL_TOKEN_FN,
    QueryContextAttributesW: QUERY_CONTEXT_ATTRIBUTES_FN_W,
    ImpersonateSecurityContext: IMPERSONATE_SECURITY_CONTEXT_FN,
    RevertSecurityContext: REVERT_SECURITY_CONTEXT_FN,
    MakeSignature: MAKE_SIGNATURE_FN,
    VerifySignature: VERIFY_SIGNATURE_FN,
    FreeContextBuffer: FREE_CONTEXT_BUFFER_FN,
    QuerySecurityPackageInfoW: QUERY_SECURITY_PACKAGE_INFO_FN_W,
    Reserved3: *const c_void,
    Reserved4: *const c_void,
    ExportSecurityContext: EXPORT_SECURITY_CONTEXT_FN,
    ImportSecurityContextW: IMPORT_SECURITY_CONTEXT_FN_W,
    AddCredentialsW: ADD_CREDENTIALS_FN_W,
    Reserved8: *const c_void,
    QuerySecurityContextToken: QUERY_SECURITY_CONTEXT_TOKEN_FN,
    EncryptMessage: ENCRYPT_MESSAGE_FN,
    DecryptMessage: DECRYPT_MESSAGE_FN,
    SetContextAttributesW: SET_CONTEXT_ATTRIBUTES_FN_W,
    SetCredentialsAttributesW: SET_CREDENTIALS_ATTRIBUTES_FN_W,
    ChangeAccountPasswordW: CHANGE_PASSWORD_FN_W,
    Reserved9: *const c_void,
    QueryContextAttributesExW: QUERY_CONTEXT_ATTRIBUTES_EX_FN_W,
    QueryCredentialsAttributesExW: QUERY_CREDENTIALS_ATTRIBUTES_EX_FN_W,
}

pub type PSecurityFunctionTableW = *mut SecurityFunctionTableW;

#[no_mangle]
pub extern "C" fn InitSecurityInterfaceW() -> PSecurityFunctionTableW {
    println!("init table");
    into_raw_ptr(SecurityFunctionTableW {
        // helper,
        dwVersion: KERBEROS_VERSION as c_ulong,
        EnumerateSecurityPackagesW,
        QueryCredentialsAttributesW,
        AcquireCredentialsHandleW,
        FreeCredentialsHandle,
        Reserved2: null(),
        InitializeSecurityContextW,
        AcceptSecurityContext,
        CompleteAuthToken,
        DeleteSecurityContext,
        ApplyControlToken,
        QueryContextAttributesW,
        ImpersonateSecurityContext,
        RevertSecurityContext,
        MakeSignature,
        VerifySignature,
        FreeContextBuffer,
        QuerySecurityPackageInfoW,
        Reserved3: null(),
        Reserved4: null(),
        ExportSecurityContext,
        ImportSecurityContextW,
        AddCredentialsW,
        Reserved8: null(),
        QuerySecurityContextToken,
        EncryptMessage,
        DecryptMessage,
        SetContextAttributesW,
        SetCredentialsAttributesW,
        ChangeAccountPasswordW,
        Reserved9: null(),
        QueryContextAttributesExW,
        QueryCredentialsAttributesExW,
    })
}
