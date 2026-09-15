#![allow(non_snake_case)]

use std::ptr::null;

pub use ffi_types::sspi::{
    AcceptSecurityContextFn, ApplyControlTokenFn, CompleteAuthTokenFn, DecryptMessageFn, DeleteSecurityContextFn,
    EncryptMessageFn, ExportSecurityContextFn, FreeContextBufferFn, FreeCredentialsHandleFn,
    ImpersonateSecurityContextFn, MakeSignatureFn, PSecurityFunctionTableA, PSecurityFunctionTableW,
    QuerySecurityContextTokenFn, RevertSecurityContextFn, SecurityFunctionTableA, SecurityFunctionTableW,
    VerifySignatureFn,
};
use sspi::KERBEROS_VERSION;
#[cfg(windows)]
use symbol_rename_macro::rename_symbol;

use super::common::{
    AcceptSecurityContext, ApplyControlToken, CompleteAuthToken, DecryptMessage, DeleteSecurityContext, EncryptMessage,
    ExportSecurityContext, FreeContextBuffer, FreeCredentialsHandle, ImpersonateSecurityContext, MakeSignature,
    QuerySecurityContextToken, RevertSecurityContext, VerifySignature,
};
use super::sec_handle::{
    AcquireCredentialsHandleA, AcquireCredentialsHandleW, AddCredentialsA, AddCredentialsW, ChangeAccountPasswordA,
    ChangeAccountPasswordW, ImportSecurityContextA, ImportSecurityContextW, InitializeSecurityContextA,
    InitializeSecurityContextW, QueryContextAttributesA, QueryContextAttributesExA, QueryContextAttributesExW,
    QueryContextAttributesW, QueryCredentialsAttributesA, QueryCredentialsAttributesExA, QueryCredentialsAttributesExW,
    QueryCredentialsAttributesW, SetContextAttributesA, SetContextAttributesW, SetCredentialsAttributesA,
    SetCredentialsAttributesW,
};
use super::sec_pkg_info::{
    EnumerateSecurityPackagesA, EnumerateSecurityPackagesW, QuerySecurityPackageInfoA, QuerySecurityPackageInfoW,
};
use crate::utils::into_raw_ptr;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_InitSecurityInterfaceA"))]
#[unsafe(no_mangle)]
pub extern "system" fn InitSecurityInterfaceA() -> PSecurityFunctionTableA {
    crate::logging::setup_logger();

    into_raw_ptr(SecurityFunctionTableA {
        dwVersion: u32::from(KERBEROS_VERSION),
        EnumerateSecurityPackagesA,
        QueryCredentialsAttributesA,
        AcquireCredentialsHandleA,
        FreeCredentialsHandle,
        Reserved2: null(),
        InitializeSecurityContextA,
        AcceptSecurityContext,
        CompleteAuthToken,
        DeleteSecurityContext,
        ApplyControlToken,
        QueryContextAttributesA,
        ImpersonateSecurityContext,
        RevertSecurityContext,
        MakeSignature,
        VerifySignature,
        FreeContextBuffer,
        QuerySecurityPackageInfoA,
        Reserved3: EncryptMessage,
        Reserved4: DecryptMessage,
        ExportSecurityContext,
        ImportSecurityContextA,
        AddCredentialsA,
        Reserved8: null(),
        QuerySecurityContextToken,
        EncryptMessage,
        DecryptMessage,
        SetContextAttributesA,
        SetCredentialsAttributesA,
        ChangeAccountPasswordA,
        Reserved9: null(),
        QueryContextAttributesExA,
        QueryCredentialsAttributesExA,
    })
}

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_InitSecurityInterfaceW"))]
#[unsafe(no_mangle)]
pub extern "system" fn InitSecurityInterfaceW() -> PSecurityFunctionTableW {
    crate::logging::setup_logger();

    into_raw_ptr(SecurityFunctionTableW {
        dwVersion: u32::from(KERBEROS_VERSION),
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
        Reserved3: EncryptMessage,
        Reserved4: DecryptMessage,
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
