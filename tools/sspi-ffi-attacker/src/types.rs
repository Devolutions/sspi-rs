#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use libc::{c_char, c_long, c_uint, c_ulong, c_ushort, c_void};

pub type SEC_GET_KEY_FN = *mut c_void;

#[repr(C)]
pub struct SECURITY_INTEGER {
    pub low_part: c_ulong,
    pub high_part: c_long,
}

pub type PTimeStamp = *mut SECURITY_INTEGER;

#[cfg(target_os = "windows")]
#[derive(Debug)]
#[repr(C)]
pub struct SecBuffer {
    pub cb_buffer: c_ulong,
    pub buffer_type: c_ulong,
    pub pv_buffer: *mut c_char,
}

#[cfg(not(target_os = "windows"))]
#[derive(Debug)]
#[repr(C)]
pub struct SecBuffer {
    pub cb_buffer: c_uint,
    pub buffer_type: c_uint,
    pub pv_buffer: *mut c_char,
}

type PSecBuffer = *mut SecBuffer;

#[derive(Debug)]
#[cfg(target_os = "windows")]
#[repr(C)]
pub struct SecBufferDesc {
    pub ul_version: c_ulong,
    pub c_buffers: c_ulong,
    pub p_buffers: PSecBuffer,
}

#[derive(Debug)]
#[cfg(not(target_os = "windows"))]
#[repr(C)]
pub struct SecBufferDesc {
    pub ul_version: c_uint,
    pub c_buffers: c_uint,
    pub p_buffers: PSecBuffer,
}

pub type PSecBufferDesc = *mut SecBufferDesc;

pub type ULONG_PTR = usize;

#[derive(Debug)]
#[repr(C)]
pub struct SecHandle {
    pub dwLower: ULONG_PTR,
    pub dwUpper: ULONG_PTR,
}
pub type PSecHandle = *mut SecHandle;
pub type PCredHandle = PSecHandle;
pub type CtxtHandle = SecHandle;
pub type PCtxtHandle = *mut CtxtHandle;

#[derive(Debug)]
#[repr(C)]
pub struct SecPkgInfoA {
    pub fCapabilities: c_uint,
    pub wVersion: c_ushort,
    pub wRPCID: c_ushort,
    pub cbMaxToken: c_uint,
    pub Name: *mut SEC_CHAR,
    pub Comment: *mut SEC_CHAR,
}
pub type PSecPkgInfoA = *mut SecPkgInfoA;

#[derive(Debug)]
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

pub type SEC_CHAR = c_char;
pub type WCHAR = u16;
pub type SEC_WCHAR = WCHAR;
pub type LPSTR = *mut SEC_CHAR;
pub type LPWSTR = *mut WCHAR;
pub type SECURITY_STATUS = u32;

pub type EnumerateSecurityPackagesFnW = unsafe extern "system" fn(*mut c_ulong, *mut PSecPkgInfoW) -> SECURITY_STATUS;
pub type EnumerateSecurityPackagesFnA = unsafe extern "system" fn(*mut c_ulong, *mut PSecPkgInfoA) -> SECURITY_STATUS;

pub type QueryCredentialsAttributesFnW = extern "system" fn(PCredHandle, c_ulong, *mut c_void) -> SECURITY_STATUS;
pub type QueryCredentialsAttributesFnA = extern "system" fn(PCredHandle, c_ulong, *mut c_void) -> SECURITY_STATUS;

pub type AcquireCredentialsHandleFnW = unsafe extern "system" fn(
    LPWSTR,
    LPWSTR,
    c_ulong,
    *const c_void,
    *const c_void,
    SEC_GET_KEY_FN,
    *const c_void,
    PCredHandle,
    PTimeStamp,
) -> SECURITY_STATUS;
pub type AcquireCredentialsHandleFnA = unsafe extern "system" fn(
    LPSTR,
    LPSTR,
    c_ulong,
    *const c_void,
    *const c_void,
    SEC_GET_KEY_FN,
    *const c_void,
    PCredHandle,
    PTimeStamp,
) -> SECURITY_STATUS;

pub type FreeCredentialsHandleFn = unsafe extern "system" fn(PCredHandle) -> SECURITY_STATUS;

pub type InitializeSecurityContextFnW = unsafe extern "system" fn(
    PCredHandle,
    PCtxtHandle,
    *const SEC_WCHAR,
    c_ulong,
    c_ulong,
    c_ulong,
    PSecBufferDesc,
    c_ulong,
    PCtxtHandle,
    PSecBufferDesc,
    *mut c_ulong,
    PTimeStamp,
) -> SECURITY_STATUS;
pub type InitializeSecurityContextFnA = unsafe extern "system" fn(
    PCredHandle,
    PCtxtHandle,
    *const SEC_CHAR,
    c_ulong,
    c_ulong,
    c_ulong,
    PSecBufferDesc,
    c_ulong,
    PCtxtHandle,
    PSecBufferDesc,
    *mut c_ulong,
    PTimeStamp,
) -> SECURITY_STATUS;

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
) -> SECURITY_STATUS;

pub type CompleteAuthTokenFn = unsafe extern "system" fn(PCtxtHandle, PSecBufferDesc) -> SECURITY_STATUS;

pub type DeleteSecurityContextFn = unsafe extern "system" fn(PCtxtHandle) -> SECURITY_STATUS;

pub type ApplyControlTokenFn = extern "system" fn(PCtxtHandle, PSecBufferDesc) -> SECURITY_STATUS;

pub type QueryContextAttributesFnW = unsafe extern "system" fn(PCtxtHandle, c_ulong, *mut c_void) -> SECURITY_STATUS;
pub type QueryContextAttributesFnA = unsafe extern "system" fn(PCtxtHandle, c_ulong, *mut c_void) -> SECURITY_STATUS;

pub type ImpersonateSecurityContextFn = extern "system" fn(PCtxtHandle) -> SECURITY_STATUS;

pub type RevertSecurityContextFn = extern "system" fn(PCtxtHandle) -> SECURITY_STATUS;

pub type MakeSignatureFn = extern "system" fn(PCtxtHandle, c_ulong, PSecBufferDesc, c_ulong) -> SECURITY_STATUS;

pub type VerifySignatureFn = extern "system" fn(PCtxtHandle, PSecBufferDesc, c_ulong, *mut c_ulong) -> SECURITY_STATUS;

pub type FreeContextBufferFn = unsafe extern "system" fn(*mut c_void) -> SECURITY_STATUS;

pub type QuerySecurityPackageInfoFnW =
    unsafe extern "system" fn(*const SEC_WCHAR, *mut PSecPkgInfoW) -> SECURITY_STATUS;
pub type QuerySecurityPackageInfoFnA = unsafe extern "system" fn(*const SEC_CHAR, *mut PSecPkgInfoA) -> SECURITY_STATUS;

pub type ExportSecurityContextFn =
    extern "system" fn(PCtxtHandle, c_ulong, PSecBuffer, *mut *mut c_void) -> SECURITY_STATUS;

pub type ImportSecurityContextFnW = extern "system" fn(LPWSTR, PSecBuffer, *mut c_void, PCtxtHandle) -> SECURITY_STATUS;
pub type ImportSecurityContextFnA = extern "system" fn(LPSTR, PSecBuffer, *mut c_void, PCtxtHandle) -> SECURITY_STATUS;

pub type AddCredentialsFnW = extern "system" fn(
    PCredHandle,
    *mut SEC_WCHAR,
    *mut SEC_WCHAR,
    c_ulong,
    *mut c_void,
    SEC_GET_KEY_FN,
    *mut c_void,
    PTimeStamp,
) -> SECURITY_STATUS;
pub type AddCredentialsFnA = extern "system" fn(
    PCredHandle,
    *mut SEC_CHAR,
    *mut SEC_CHAR,
    c_ulong,
    *mut c_void,
    SEC_GET_KEY_FN,
    *mut c_void,
    PTimeStamp,
) -> SECURITY_STATUS;

pub type QuerySecurityContextTokenFn = extern "system" fn(PCtxtHandle, *mut *mut c_void) -> SECURITY_STATUS;

pub type EncryptMessageFn = unsafe extern "system" fn(PCtxtHandle, c_ulong, PSecBufferDesc, c_ulong) -> SECURITY_STATUS;

pub type DecryptMessageFn =
    unsafe extern "system" fn(PCtxtHandle, PSecBufferDesc, c_ulong, *mut c_ulong) -> SECURITY_STATUS;

pub type SetContextAttributesFnW = extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SECURITY_STATUS;
pub type SetContextAttributesFnA = extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SECURITY_STATUS;

pub type SetCredentialsAttributesFnW =
    unsafe extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SECURITY_STATUS;
pub type SetCredentialsAttributesFnA =
    unsafe extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SECURITY_STATUS;

pub type ChangeAccountPasswordFnW = unsafe extern "system" fn(
    *mut SEC_WCHAR,
    *mut SEC_WCHAR,
    *mut SEC_WCHAR,
    *mut SEC_WCHAR,
    *mut SEC_WCHAR,
    bool,
    c_ulong,
    PSecBufferDesc,
) -> SECURITY_STATUS;
pub type ChangeAccountPasswordFnA = unsafe extern "system" fn(
    *mut SEC_CHAR,
    *mut SEC_CHAR,
    *mut SEC_CHAR,
    *mut SEC_CHAR,
    *mut SEC_CHAR,
    bool,
    c_ulong,
    PSecBufferDesc,
) -> SECURITY_STATUS;

pub type QueryContextAttributesExFnW =
    extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SECURITY_STATUS;
pub type QueryContextAttributesExFnA =
    extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SECURITY_STATUS;

pub type QueryCredentialsAttributesExFnW =
    extern "system" fn(PCredHandle, c_ulong, *mut c_void, c_ulong) -> SECURITY_STATUS;
pub type QueryCredentialsAttributesExFnA =
    extern "system" fn(PCredHandle, c_ulong, *mut c_void, c_ulong) -> SECURITY_STATUS;

pub type SspiEncodeStringsAsAuthIdentityFn =
    extern "system" fn(*const SEC_WCHAR, *const SEC_WCHAR, *const SEC_WCHAR, *mut *mut c_void) -> SECURITY_STATUS;

pub type SspiFreeAuthIdentityFn = extern "system" fn(*mut c_void) -> SECURITY_STATUS;

#[repr(C)]
pub struct SecWinntAuthIdentityA {
    pub user: *const c_char,
    pub user_length: u32,
    pub domain: *const c_char,
    pub domain_length: u32,
    pub password: *const c_char,
    pub password_length: u32,
    pub flags: u32,
}

#[repr(C)]
pub struct SecWinntAuthIdentityW {
    pub user: *const c_ushort,
    pub user_length: u32,
    pub domain: *const c_ushort,
    pub domain_length: u32,
    pub password: *const c_ushort,
    pub password_length: u32,
    pub flags: u32,
}

#[repr(C)]
pub struct SecurityFunctionTableA {
    pub dwVersion: c_ulong,
    pub EnumerateSecurityPackagesA: EnumerateSecurityPackagesFnA,
    pub QueryCredentialsAttributesA: QueryCredentialsAttributesFnA,
    pub AcquireCredentialsHandleA: AcquireCredentialsHandleFnA,
    pub FreeCredentialsHandle: FreeCredentialsHandleFn,
    pub Reserved2: *const c_void,
    pub InitializeSecurityContextA: InitializeSecurityContextFnA,
    pub AcceptSecurityContext: AcceptSecurityContextFn,
    pub CompleteAuthToken: CompleteAuthTokenFn,
    pub DeleteSecurityContext: DeleteSecurityContextFn,
    pub ApplyControlToken: ApplyControlTokenFn,
    pub QueryContextAttributesA: QueryContextAttributesFnA,
    pub ImpersonateSecurityContext: ImpersonateSecurityContextFn,
    pub RevertSecurityContext: RevertSecurityContextFn,
    pub MakeSignature: MakeSignatureFn,
    pub VerifySignature: VerifySignatureFn,
    pub FreeContextBuffer: FreeContextBufferFn,
    pub QuerySecurityPackageInfoA: QuerySecurityPackageInfoFnA,
    pub Reserved3: *const c_void,
    pub Reserved4: *const c_void,
    pub ExportSecurityContext: ExportSecurityContextFn,
    pub ImportSecurityContextA: ImportSecurityContextFnA,
    pub AddCredentialsA: AddCredentialsFnA,
    pub Reserved8: *const c_void,
    pub QuerySecurityContextToken: QuerySecurityContextTokenFn,
    pub EncryptMessage: EncryptMessageFn,
    pub DecryptMessage: DecryptMessageFn,
    pub SetContextAttributesA: SetContextAttributesFnA,
    pub SetCredentialsAttributesA: SetCredentialsAttributesFnA,
    pub ChangeAccountPasswordA: ChangeAccountPasswordFnA,
    pub Reserved9: *const c_void,
    pub QueryContextAttributesExA: QueryContextAttributesExFnA,
    pub QueryCredentialsAttributesExA: QueryCredentialsAttributesExFnA,
}

pub type PSecurityFunctionTableA = *mut SecurityFunctionTableA;

pub type InitSecurityInterfaceA = extern "system" fn() -> PSecurityFunctionTableA;

#[repr(C)]
pub struct SecurityFunctionTableW {
    pub dwVersion: c_ulong,
    pub EnumerateSecurityPackagesW: EnumerateSecurityPackagesFnW,
    pub QueryCredentialsAttributesW: QueryCredentialsAttributesFnW,
    pub AcquireCredentialsHandleW: AcquireCredentialsHandleFnW,
    pub FreeCredentialsHandle: FreeCredentialsHandleFn,
    pub Reserved2: *const c_void,
    pub InitializeSecurityContextW: InitializeSecurityContextFnW,
    pub AcceptSecurityContext: AcceptSecurityContextFn,
    pub CompleteAuthToken: CompleteAuthTokenFn,
    pub DeleteSecurityContext: DeleteSecurityContextFn,
    pub ApplyControlToken: ApplyControlTokenFn,
    pub QueryContextAttributesW: QueryContextAttributesFnW,
    pub ImpersonateSecurityContext: ImpersonateSecurityContextFn,
    pub RevertSecurityContext: RevertSecurityContextFn,
    pub MakeSignature: MakeSignatureFn,
    pub VerifySignature: VerifySignatureFn,
    pub FreeContextBuffer: FreeContextBufferFn,
    pub QuerySecurityPackageInfoW: QuerySecurityPackageInfoFnW,
    pub Reserved3: *const c_void,
    pub Reserved4: *const c_void,
    pub ExportSecurityContext: ExportSecurityContextFn,
    pub ImportSecurityContextW: ImportSecurityContextFnW,
    pub AddCredentialsW: AddCredentialsFnW,
    pub Reserved8: *const c_void,
    pub QuerySecurityContextToken: QuerySecurityContextTokenFn,
    pub EncryptMessage: EncryptMessageFn,
    pub DecryptMessage: DecryptMessageFn,
    pub SetContextAttributesW: SetContextAttributesFnW,
    pub SetCredentialsAttributesW: SetCredentialsAttributesFnW,
    pub ChangeAccountPasswordW: ChangeAccountPasswordFnW,
    pub Reserved9: *const c_void,
    pub QueryContextAttributesExW: QueryContextAttributesExFnW,
    pub QueryCredentialsAttributesExW: QueryCredentialsAttributesExFnW,
}

pub type PSecurityFunctionTableW = *mut SecurityFunctionTableW;

pub type InitSecurityInterfaceW = extern "system" fn() -> PSecurityFunctionTableW;
