#![allow(non_snake_case)]

pub(crate) mod a;
pub(crate) mod common;
pub(crate) mod w;

use std::{
    ptr::null,
    slice::{from_raw_parts, from_raw_parts_mut},
};

use libc::{c_ulong, c_ulonglong, c_void};
use num_traits::{FromPrimitive, ToPrimitive};
use sspi::{Kerberos, SecurityBuffer, SecurityBufferType, KERBEROS_VERSION};

use crate::{
    a::{
        AcquireCredentialsHandleA, AcquireCredentialsHandleFnA, AddCredentialsA, AddCredentialsFnA,
        ChangeAccountPasswordA, ChangeAccountPasswordFnA, EnumerateSecurityPackagesA,
        EnumerateSecurityPackagesFnA, ImportSecurityContextA, ImportSecurityContextFnA,
        InitializeSecurityContextA, InitializeSecurityContextFnA, QueryContextAttributesA,
        QueryContextAttributesExA, QueryContextAttributesExFnA, QueryContextAttributesFnA,
        QueryCredentialsAttributesA, QueryCredentialsAttributesExA,
        QueryCredentialsAttributesExFnA, QueryCredentialsAttributesFnA, QuerySecurityPackageInfoA,
        QuerySecurityPackageInfoFnA, SetContextAttributesA, SetContextAttributesFnA,
        SetCredentialsAttributesA, SetCredentialsAttributesFnA,
    },
    common::{
        AcceptSecurityContext, AcceptSecurityContextFn, ApplyControlToken, ApplyControlTokenFn,
        CompleteAuthToken, CompleteAuthTokenFn, DecryptMessage, DecryptMessageFn,
        DeleteSecurityContext, DeleteSecurityContextFn, EncryptMessage, EncryptMessageFn,
        ExportSecurityContext, ExportSecurityContextFn, FreeContextBuffer, FreeContextBufferFn,
        FreeCredentialsHandle, FreeCredentialsHandleFn, ImpersonateSecurityContext,
        ImpersonateSecurityContextFn, MakeSignature, MakeSignatureFn, PCtxtHandle, PSecBuffer,
        QuerySecurityContextToken, QuerySecurityContextTokenFn, RevertSecurityContext,
        RevertSecurityContextFn, SecBuffer, SecHandle, VerifySignature, VerifySignatureFn,
    },
    w::{
        AcquireCredentialsHandleFnW, AcquireCredentialsHandleW, AddCredentialsFnW, AddCredentialsW,
        ChangeAccountPasswordFnW, ChangeAccountPasswordW, EnumerateSecurityPackagesFnW,
        EnumerateSecurityPackagesW, ImportSecurityContextFnW, ImportSecurityContextW,
        InitializeSecurityContextFnW, InitializeSecurityContextW, QueryContextAttributesExFnW,
        QueryContextAttributesExW, QueryContextAttributesFnW, QueryContextAttributesW,
        QueryCredentialsAttributesExFnW, QueryCredentialsAttributesExW,
        QueryCredentialsAttributesFnW, QueryCredentialsAttributesW, QuerySecurityPackageInfoFnW,
        QuerySecurityPackageInfoW, SetContextAttributesFnW, SetContextAttributesW,
        SetCredentialsAttributesFnW, SetCredentialsAttributesW,
    },
};

pub(crate) unsafe fn p_ctxt_handle_to_kerberos(mut context: PCtxtHandle) -> *mut Kerberos {
    if context == null::<SecHandle>() as *mut _ {
        context = into_raw_ptr(SecHandle {
            dw_lower: 0,
            dw_upper: 0,
        });
    }
    if (*context).dw_lower == 0 {
        (*context).dw_lower = into_raw_ptr(Kerberos::new_client_from_env()) as c_ulonglong;
    }
    (*context).dw_lower as *mut Kerberos
}

pub(crate) fn into_raw_ptr<T>(value: T) -> *mut T {
    Box::into_raw(Box::new(value))
}

pub(crate) fn vec_into_raw_ptr<T>(v: Vec<T>) -> *mut T {
    Box::into_raw(v.into_boxed_slice()) as *mut T
}

pub(crate) unsafe fn p_sec_buffers_to_security_buffers(
    raw_buffers: &[SecBuffer],
) -> Vec<SecurityBuffer> {
    raw_buffers
        .iter()
        .map(|raw_buffer| SecurityBuffer {
            buffer: from_raw_parts(raw_buffer.pv_buffer, raw_buffer.cb_buffer as usize)
                .iter()
                .map(|v| *v as u8)
                .collect(),
            buffer_type: SecurityBufferType::from_u32(raw_buffer.buffer_type.try_into().unwrap())
                .unwrap(),
        })
        .collect()
}

pub(crate) unsafe fn security_buffers_to_raw(buffers: Vec<SecurityBuffer>) -> PSecBuffer {
    vec_into_raw_ptr(
        buffers
            .into_iter()
            .map(|buffer| SecBuffer {
                cb_buffer: buffer.buffer.len().try_into().unwrap(),
                buffer_type: buffer.buffer_type.to_u32().unwrap(),
                pv_buffer: vec_into_raw_ptr(buffer.buffer) as *mut i8,
            })
            .collect::<Vec<_>>(),
    )
}

pub(crate) unsafe fn copy_to_c_sec_buffer(
    from_buffers: &Vec<SecurityBuffer>,
    to_buffers: PSecBuffer,
) {
    let to_buffers = from_raw_parts_mut(to_buffers as *mut SecBuffer, from_buffers.len());
    for i in 0..from_buffers.len() {
        let buffer = &from_buffers[i];
        let len = buffer.buffer.len();

        to_buffers[i].cb_buffer = buffer.buffer.len().try_into().unwrap();
        let to_buffer = from_raw_parts_mut(to_buffers[i].pv_buffer, len);
        to_buffer.copy_from_slice(from_raw_parts(buffer.buffer.as_ptr() as *const i8, len));
    }
}

#[repr(C)]
pub struct SecurityFunctionTableA {
    dwVersion: c_ulong,
    EnumerateSecurityPackagesA: EnumerateSecurityPackagesFnA,
    QueryCredentialsAttributesA: QueryCredentialsAttributesFnA,
    AcquireCredentialsHandleA: AcquireCredentialsHandleFnA,
    FreeCredentialsHandle: FreeCredentialsHandleFn,
    Reserved2: *const c_void,
    InitializeSecurityContextA: InitializeSecurityContextFnA,
    AcceptSecurityContext: AcceptSecurityContextFn,
    CompleteAuthToken: CompleteAuthTokenFn,
    DeleteSecurityContext: DeleteSecurityContextFn,
    ApplyControlToken: ApplyControlTokenFn,
    QueryContextAttributesA: QueryContextAttributesFnA,
    ImpersonateSecurityContext: ImpersonateSecurityContextFn,
    RevertSecurityContext: RevertSecurityContextFn,
    MakeSignature: MakeSignatureFn,
    VerifySignature: VerifySignatureFn,
    FreeContextBuffer: FreeContextBufferFn,
    QuerySecurityPackageInfoA: QuerySecurityPackageInfoFnA,
    Reserved3: *const c_void,
    Reserved4: *const c_void,
    ExportSecurityContext: ExportSecurityContextFn,
    ImportSecurityContextA: ImportSecurityContextFnA,
    AddCredentialsA: AddCredentialsFnA,
    Reserved8: *const c_void,
    QuerySecurityContextToken: QuerySecurityContextTokenFn,
    EncryptMessage: EncryptMessageFn,
    DecryptMessage: DecryptMessageFn,
    SetContextAttributesA: SetContextAttributesFnA,
    SetCredentialsAttributesA: SetCredentialsAttributesFnA,
    ChangeAccountPasswordA: ChangeAccountPasswordFnA,
    Reserved9: *const c_void,
    QueryContextAttributesExA: QueryContextAttributesExFnA,
    QueryCredentialsAttributesExA: QueryCredentialsAttributesExFnA,
}

pub type PSecurityFunctionTableA = *mut SecurityFunctionTableA;

#[repr(C)]
pub struct SecurityFunctionTableW {
    dwVersion: c_ulong,
    EnumerateSecurityPackagesW: EnumerateSecurityPackagesFnW,
    QueryCredentialsAttributesW: QueryCredentialsAttributesFnW,
    AcquireCredentialsHandleW: AcquireCredentialsHandleFnW,
    FreeCredentialsHandle: FreeCredentialsHandleFn,
    Reserved2: *const c_void,
    InitializeSecurityContextW: InitializeSecurityContextFnW,
    AcceptSecurityContext: AcceptSecurityContextFn,
    CompleteAuthToken: CompleteAuthTokenFn,
    DeleteSecurityContext: DeleteSecurityContextFn,
    ApplyControlToken: ApplyControlTokenFn,
    QueryContextAttributesW: QueryContextAttributesFnW,
    ImpersonateSecurityContext: ImpersonateSecurityContextFn,
    RevertSecurityContext: RevertSecurityContextFn,
    MakeSignature: MakeSignatureFn,
    VerifySignature: VerifySignatureFn,
    FreeContextBuffer: FreeContextBufferFn,
    QuerySecurityPackageInfoW: QuerySecurityPackageInfoFnW,
    Reserved3: *const c_void,
    Reserved4: *const c_void,
    ExportSecurityContext: ExportSecurityContextFn,
    ImportSecurityContextW: ImportSecurityContextFnW,
    AddCredentialsW: AddCredentialsFnW,
    Reserved8: *const c_void,
    QuerySecurityContextToken: QuerySecurityContextTokenFn,
    EncryptMessage: EncryptMessageFn,
    DecryptMessage: DecryptMessageFn,
    SetContextAttributesW: SetContextAttributesFnW,
    SetCredentialsAttributesW: SetCredentialsAttributesFnW,
    ChangeAccountPasswordW: ChangeAccountPasswordFnW,
    Reserved9: *const c_void,
    QueryContextAttributesExW: QueryContextAttributesExFnW,
    QueryCredentialsAttributesExW: QueryCredentialsAttributesExFnW,
}

pub type PSecurityFunctionTableW = *mut SecurityFunctionTableW;

#[no_mangle]
pub extern "C" fn InitSecurityInterfaceA() -> PSecurityFunctionTableA {
    into_raw_ptr(SecurityFunctionTableA {
        dwVersion: KERBEROS_VERSION as c_ulong,
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
        Reserved3: null(),
        Reserved4: null(),
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

#[no_mangle]
pub extern "C" fn InitSecurityInterfaceW() -> PSecurityFunctionTableW {
    into_raw_ptr(SecurityFunctionTableW {
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

#[cfg(test)]
mod tests {
    use crate::vec_into_raw_ptr;

    #[test]
    fn test_vec() {
        let v = vec![1, 2, 3, 4];

        println!("v  : {:?}", v);

        unsafe {
            let ptr = vec_into_raw_ptr(v);
            *ptr = 5;

            let arr = std::slice::from_raw_parts(ptr, 4);
            println!("arr: {:?}", arr);

            libc::free(ptr as *mut libc::c_void);
        }
    }
}
