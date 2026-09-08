use core::ffi::c_void;

use super::{
    LpStr, LpcWStr, PCredHandle, PCtxtHandle, PSecBuffer, PSecBufferDesc, PSecPkgInfoA, PSecPkgInfoW, PSecurityString,
    PTimeStamp, SecChar, SecGetKeyFn, SecWChar, SecurityInteger, SecurityStatus,
};

pub type FreeCredentialsHandleFn = unsafe extern "system" fn(PCredHandle) -> SecurityStatus;
pub type AcceptSecurityContextFn = unsafe extern "system" fn(
    PCredHandle,
    PCtxtHandle,
    PSecBufferDesc,
    u32,
    u32,
    PCtxtHandle,
    PSecBufferDesc,
    *mut u32,
    *mut SecurityInteger,
) -> SecurityStatus;
pub type CompleteAuthTokenFn = unsafe extern "system" fn(PCtxtHandle, PSecBufferDesc) -> SecurityStatus;
pub type DeleteSecurityContextFn = unsafe extern "system" fn(PCtxtHandle) -> SecurityStatus;
pub type ApplyControlTokenFn = extern "system" fn(PCtxtHandle, PSecBufferDesc) -> SecurityStatus;
pub type ImpersonateSecurityContextFn = extern "system" fn(PCtxtHandle) -> SecurityStatus;
pub type RevertSecurityContextFn = extern "system" fn(PCtxtHandle) -> SecurityStatus;
pub type MakeSignatureFn = extern "system" fn(PCtxtHandle, u32, PSecBufferDesc, u32) -> SecurityStatus;
pub type VerifySignatureFn = extern "system" fn(PCtxtHandle, PSecBufferDesc, u32, *mut u32) -> SecurityStatus;
pub type FreeContextBufferFn = unsafe extern "system" fn(*mut c_void) -> SecurityStatus;
pub type ExportSecurityContextFn = extern "system" fn(PCtxtHandle, u32, PSecBuffer, *mut *mut c_void) -> SecurityStatus;
pub type QuerySecurityContextTokenFn = extern "system" fn(PCtxtHandle, *mut *mut c_void) -> SecurityStatus;
pub type EncryptMessageFn = unsafe extern "system" fn(PCtxtHandle, u32, PSecBufferDesc, u32) -> SecurityStatus;
pub type DecryptMessageFn = unsafe extern "system" fn(PCtxtHandle, PSecBufferDesc, u32, *mut u32) -> SecurityStatus;

pub type AcquireCredentialsHandleFnA = unsafe extern "system" fn(
    LpStr,
    LpStr,
    u32,
    *const c_void,
    *const c_void,
    SecGetKeyFn,
    *const c_void,
    PCredHandle,
    PTimeStamp,
) -> SecurityStatus;
pub type AcquireCredentialsHandleFnW = unsafe extern "system" fn(
    LpcWStr,
    LpcWStr,
    u32,
    *const c_void,
    *const c_void,
    SecGetKeyFn,
    *const c_void,
    PCredHandle,
    PTimeStamp,
) -> SecurityStatus;
pub type QueryCredentialsAttributesFnA = extern "system" fn(PCredHandle, u32, *mut c_void) -> SecurityStatus;
pub type QueryCredentialsAttributesFnW = extern "system" fn(PCredHandle, u32, *mut c_void) -> SecurityStatus;
pub type InitializeSecurityContextFnA = unsafe extern "system" fn(
    PCredHandle,
    PCtxtHandle,
    *const SecChar,
    u32,
    u32,
    u32,
    PSecBufferDesc,
    u32,
    PCtxtHandle,
    PSecBufferDesc,
    *mut u32,
    PTimeStamp,
) -> SecurityStatus;
pub type InitializeSecurityContextFnW = unsafe extern "system" fn(
    PCredHandle,
    PCtxtHandle,
    *const SecWChar,
    u32,
    u32,
    u32,
    PSecBufferDesc,
    u32,
    PCtxtHandle,
    PSecBufferDesc,
    *mut u32,
    PTimeStamp,
) -> SecurityStatus;
pub type QueryContextAttributesFnA = unsafe extern "system" fn(PCtxtHandle, u32, *mut c_void) -> SecurityStatus;
pub type QueryContextAttributesFnW = unsafe extern "system" fn(PCtxtHandle, u32, *mut c_void) -> SecurityStatus;
pub type EnumerateSecurityPackagesFnA = unsafe extern "system" fn(*mut u32, *mut PSecPkgInfoA) -> SecurityStatus;
pub type EnumerateSecurityPackagesFnW = unsafe extern "system" fn(*mut u32, *mut PSecPkgInfoW) -> SecurityStatus;
pub type QuerySecurityPackageInfoFnA = unsafe extern "system" fn(*const SecChar, *mut PSecPkgInfoA) -> SecurityStatus;
pub type QuerySecurityPackageInfoFnW = unsafe extern "system" fn(*const SecWChar, *mut PSecPkgInfoW) -> SecurityStatus;
pub type ImportSecurityContextFnA =
    extern "system" fn(PSecurityString, PSecBuffer, *mut c_void, PCtxtHandle) -> SecurityStatus;
pub type ImportSecurityContextFnW =
    extern "system" fn(PSecurityString, PSecBuffer, *mut c_void, PCtxtHandle) -> SecurityStatus;
pub type AddCredentialsFnA = extern "system" fn(
    PCredHandle,
    *mut SecChar,
    *mut SecChar,
    u32,
    *mut c_void,
    SecGetKeyFn,
    *mut c_void,
    PTimeStamp,
) -> SecurityStatus;
pub type AddCredentialsFnW = extern "system" fn(
    PCredHandle,
    *mut SecWChar,
    *mut SecWChar,
    u32,
    *mut c_void,
    SecGetKeyFn,
    *mut c_void,
    PTimeStamp,
) -> SecurityStatus;
pub type SetContextAttributesFnA = extern "system" fn(PCtxtHandle, u32, *mut c_void, u32) -> SecurityStatus;
pub type SetContextAttributesFnW = extern "system" fn(PCtxtHandle, u32, *mut c_void, u32) -> SecurityStatus;
pub type SetCredentialsAttributesFnA = unsafe extern "system" fn(PCtxtHandle, u32, *mut c_void, u32) -> SecurityStatus;
pub type SetCredentialsAttributesFnW = unsafe extern "system" fn(PCtxtHandle, u32, *mut c_void, u32) -> SecurityStatus;
pub type ChangeAccountPasswordFnA = unsafe extern "system" fn(
    *mut SecChar,
    *mut SecChar,
    *mut SecChar,
    *mut SecChar,
    *mut SecChar,
    bool,
    u32,
    PSecBufferDesc,
) -> SecurityStatus;
pub type ChangeAccountPasswordFnW = unsafe extern "system" fn(
    *mut SecWChar,
    *mut SecWChar,
    *mut SecWChar,
    *mut SecWChar,
    *mut SecWChar,
    bool,
    u32,
    PSecBufferDesc,
) -> SecurityStatus;
pub type QueryContextAttributesExFnA = extern "system" fn(PCtxtHandle, u32, *mut c_void, u32) -> SecurityStatus;
pub type QueryContextAttributesExFnW = extern "system" fn(PCtxtHandle, u32, *mut c_void, u32) -> SecurityStatus;
pub type QueryCredentialsAttributesExFnA = extern "system" fn(PCredHandle, u32, *mut c_void, u32) -> SecurityStatus;
pub type QueryCredentialsAttributesExFnW = extern "system" fn(PCredHandle, u32, *mut c_void, u32) -> SecurityStatus;

#[repr(C)]
pub struct SecurityFunctionTableA {
    pub dwVersion: u32,
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
    pub Reserved3: EncryptMessageFn,
    pub Reserved4: DecryptMessageFn,
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

#[repr(C)]
pub struct SecurityFunctionTableW {
    pub dwVersion: u32,
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
    pub Reserved3: EncryptMessageFn,
    pub Reserved4: DecryptMessageFn,
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
