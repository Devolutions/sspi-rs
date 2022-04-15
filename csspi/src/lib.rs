pub(crate) mod a;
pub(crate) mod common;
pub(crate) mod w;

use std::ptr::null;

use libc::{c_ulong, c_void};
use sspi::{Kerberos, KERBEROS_VERSION};

use crate::{
    common::{
        AcceptSecurityContext, ApplyControlToken, CompleteAuthToken, DecryptMessage,
        DeleteSecurityContext, EncryptMessage, ExportSecurityContext, FreeContextBuffer,
        FreeCredentialsHandle, ImpersonateSecurityContext, MakeSignature, PCtxtHandle,
        QuerySecurityContextToken, RevertSecurityContext, VerifySignature,
        ACCEPT_SECURITY_CONTEXT_FN, APPLY_CONTROL_TOKEN_FN, COMPLETE_AUTH_TOKEN_FN,
        DECRYPT_MESSAGE_FN, DELETE_SECURITY_CONTEXT_FN, ENCRYPT_MESSAGE_FN,
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
        SET_CONTEXT_ATTRIBUTES_FN_W, SET_CREDENTIALS_ATTRIBUTES_FN_W, HELPER_FN, helper,
    },
};

#[no_mangle]
pub extern "C" fn rust_function() {
    println!("year, you can call rust functions from C code :)");
}

#[no_mangle]
pub extern "C" fn test_2() -> i32 {
    43
}

pub type Test2 = extern "C" fn() -> i32;

#[repr(C)]
pub struct FunctionTable {
    test: Test2,
}

#[repr(C)]
pub struct ConstTable {
    a: i32,
    b: i32,
}

#[no_mangle]
pub extern "C" fn init() -> FunctionTable {
    FunctionTable { test: test_2 }
}

#[no_mangle]
pub extern "C" fn init_const() -> ConstTable {
    ConstTable { a: 5, b: 18 }
}

pub(crate) unsafe fn p_ctxt_handle_to_kerberos(context: PCtxtHandle) -> *mut Kerberos {
    let ptr = (*context).dwLower as *mut c_void;
    if (ptr.is_null()) {
        let ptr = Box::into_raw(Box::new(Kerberos::new_client_from_env())) as c_ulong;
        (*context).dwLower = ptr;
        ptr as *mut Kerberos
    } else {
        ptr as *mut Kerberos
    }
}

pub(crate) fn into_raw_ptr<T>(value: T) -> *mut T {
    Box::into_raw(Box::new(value))
}

#[repr(C)]
pub struct SecurityFunctionTableW {
    helper: HELPER_FN,
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

#[no_mangle]
pub extern "C" fn InitSecurityInterfaceW() -> SecurityFunctionTableW {
    SecurityFunctionTableW {
        helper,
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
    }
}
