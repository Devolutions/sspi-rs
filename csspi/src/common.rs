use libc::{c_char, c_long, c_ulong, c_ushort, c_void};

pub type SecurityStatus = i32;

#[repr(C)]
pub struct SecHandle {
    pub dwLower: c_ulong,
    pub dwUpper: c_ulong,
}

pub type PCredHandle = *mut SecHandle;
pub type PCtxtHandle = *mut SecHandle;

#[repr(C)]
pub struct SecurityInteger {
    pub LowPart: c_ulong,
    pub HighPart: c_long,
}

pub type PTimeStamp = *const SecurityInteger;

#[repr(C)]
pub struct SecurityString {
    pub Length: c_ushort,
    pub MaximumLength: c_ushort,
    pub Buffer: *mut c_ushort,
}

pub type PSecurityString = *const SecurityString;

#[repr(C)]
pub struct SecurityBuffer {
    pub cbBuffer: c_ulong,
    pub BufferType: c_ulong,
    pub pvBuffer: *mut c_char,
}

pub type PSecurityBuffer = *mut SecurityBuffer;

#[repr(C)]
pub struct SecBufferDesc {
    pub ulVersion: c_ulong,
    pub cBuffers: c_ulong,
    pub pBuffers: PSecurityBuffer,
}

pub type PSecBufferDesc = *mut SecBufferDesc;

pub type SEC_GET_KEY_FN = fn(*mut c_void, *mut c_void, u32, *mut *mut c_void, *mut i32);

#[no_mangle]
pub extern "C" fn FreeCredentialsHandle(phCredential: PCredHandle) -> SecurityStatus {
    0
}
pub type FREE_CREDENTIALS_HANDLE_FN = extern "C" fn(PCredHandle) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn AcceptSecurityContext(
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
    0
}
pub type ACCEPT_SECURITY_CONTEXT_FN = extern "C" fn(
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
pub extern "C" fn CompleteAuthToken(
    phContext: PCtxtHandle,
    pToken: PSecBufferDesc,
) -> SecurityStatus {
    0
}
pub type COMPLETE_AUTH_TOKEN_FN = extern "C" fn(PCtxtHandle, PSecBufferDesc) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn DeleteSecurityContext(phContext: PCtxtHandle) -> SecurityStatus {
    0
}
pub type DELETE_SECURITY_CONTEXT_FN = extern "C" fn(PCtxtHandle) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn ApplyControlToken(
    phContext: PCtxtHandle,
    pInput: PSecBufferDesc,
) -> SecurityStatus {
    0
}
pub type APPLY_CONTROL_TOKEN_FN = extern "C" fn(PCtxtHandle, PSecBufferDesc) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn ImpersonateSecurityContext(phContext: PCtxtHandle) -> SecurityStatus {
    0
}
pub type IMPERSONATE_SECURITY_CONTEXT_FN = extern "C" fn(PCtxtHandle) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn RevertSecurityContext(phContext: PCtxtHandle) -> SecurityStatus {
    0
}
pub type REVERT_SECURITY_CONTEXT_FN = extern "C" fn(PCtxtHandle) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn MakeSignature(
    phContext: PCtxtHandle,
    fQOP: c_ulong,
    pMessage: PSecBufferDesc,
    MessageSeqNo: c_ulong,
) -> SecurityStatus {
    0
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
    0
}
pub type VERIFY_SIGNATURE_FN =
    extern "C" fn(PCtxtHandle, PSecBufferDesc, c_ulong, *mut c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn FreeContextBuffer(pvContextBuffer: *mut c_void) -> SecurityStatus {
    0
}
pub type FREE_CONTEXT_BUFFER_FN = extern "C" fn(*mut c_void) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn ExportSecurityContext(
    phContext: PCtxtHandle,
    fFlags: c_ulong,
    pPackedContext: PSecurityBuffer,
    pToken: *mut *mut c_void,
) -> SecurityStatus {
    0
}
pub type EXPORT_SECURITY_CONTEXT_FN =
    extern "C" fn(PCtxtHandle, c_ulong, PSecurityBuffer, *mut *mut c_void) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn QuerySecurityContextToken(
    phContext: PCtxtHandle,
    Token: *mut *mut c_void,
) -> SecurityStatus {
    0
}
pub type QUERY_SECURITY_CONTEXT_TOKEN_FN =
    extern "C" fn(PCtxtHandle, *mut *mut c_void) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn EncryptMessage(
    phContext: PCtxtHandle,
    fQOP: c_ulong,
    pMessage: PSecBufferDesc,
    MessageSeqNo: c_ulong,
) -> SecurityStatus {
    0
}
pub type ENCRYPT_MESSAGE_FN =
    extern "C" fn(PCtxtHandle, c_ulong, PSecBufferDesc, c_ulong) -> SecurityStatus;

#[no_mangle]
pub extern "C" fn DecryptMessage(
    phContext: PCtxtHandle,
    pMessage: PSecBufferDesc,
    MessageSeqNo: c_ulong,
    pfQOP: *mut c_ulong,
) -> SecurityStatus {
    0
}
pub type DECRYPT_MESSAGE_FN =
    extern "C" fn(PCtxtHandle, PSecBufferDesc, c_ulong, *mut c_ulong) -> SecurityStatus;
