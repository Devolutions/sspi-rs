#[macro_use]
mod macros;

use std::ffi::CStr;
use std::slice::{from_raw_parts, from_raw_parts_mut};

use dpapi::{n_crypt_protect_secret, n_crypt_unprotect_secret};
use ffi_types::common::{Dword, LpByte, LpCByte, LpCStr, LpCUuid};
use uuid::Uuid;

// https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptprotectsecret#return-value
const ERROR_SUCCESS: u32 = 0;
const NTE_INVALID_PARAMETER: u32 = 0x80090027;
const NTE_INTERNAL_ERROR: u32 = 0x8009002d;
const NTE_NO_MEMORY: u32 = 0x8009000e;

#[instrument(skip_all)]
#[no_mangle]
pub unsafe extern "system" fn DpapiProtectSecret(
    secret: LpCByte,
    secret_len: Dword,
    sid: LpCStr,
    root_key: LpCUuid,
    server: LpCStr,
    username: LpCStr,
    password: LpCStr,
    computer_name: LpCStr,
    blob: *mut LpByte,
) -> u32 {
    check_null!(secret);
    check_null!(sid);
    check_null!(server);
    check_null!(username);
    check_null!(password);
    check_null!(blob);

    let secret =
        unsafe { from_raw_parts(secret, try_execute!(secret_len.try_into(), NTE_INVALID_PARAMETER)) }.to_owned();
    let sid = try_execute!(
        unsafe { CStr::from_ptr(sid as *const _) }.to_str(),
        NTE_INVALID_PARAMETER
    )
    .to_owned();
    let root_key = if !root_key.is_null() {
        let id = unsafe { *root_key };
        let root_key = Uuid::from_fields(id.data1, id.data2, id.data3, &id.data4);

        Some(root_key)
    } else {
        None
    };
    let server = try_execute!(
        unsafe { CStr::from_ptr(server as *const _) }.to_str(),
        NTE_INVALID_PARAMETER
    );
    let username = try_execute!(
        unsafe { CStr::from_ptr(username as *const _) }.to_str(),
        NTE_INVALID_PARAMETER
    );
    let password = try_execute!(
        unsafe { CStr::from_ptr(password as *const _) }.to_str(),
        NTE_INVALID_PARAMETER
    )
    .to_owned();
    let computer_name = if !computer_name.is_null() {
        Some(
            try_execute!(
                unsafe { CStr::from_ptr(computer_name as *const _) }.to_str(),
                NTE_INVALID_PARAMETER
            )
            .to_owned(),
        )
    } else {
        None
    };

    let blob_data = try_execute!(
        n_crypt_protect_secret(
            secret.into(),
            sid,
            root_key,
            server,
            username,
            password.into(),
            computer_name
        ),
        NTE_INTERNAL_ERROR
    );

    if blob_data.is_empty() {
        error!("Output DPAPI blob is empty");
        return NTE_INTERNAL_ERROR;
    }

    // SAFETY: Memory allocation should be safe. Moreover, we check for the null value below.
    let blob_buf = unsafe { libc::malloc(blob_data.len()) as *mut u8 };
    if blob_buf.is_null() {
        error!("Failed to allocate memory for the output DPAPI blob: blob buf pointer is NULL");
        return NTE_NO_MEMORY;
    }

    let buf = unsafe { from_raw_parts_mut(blob_buf, blob_data.len()) };
    buf.copy_from_slice(blob_data.as_ref());

    unsafe { *blob = blob_buf };

    ERROR_SUCCESS
}

#[instrument(skip_all)]
#[no_mangle]
pub unsafe extern "system" fn DpapiUnprotectSecret(
    blob: LpCByte,
    blob_len: Dword,
    server: LpCStr,
    username: LpCStr,
    password: LpCStr,
    computer_name: LpCStr,
    secret: *mut LpByte,
) -> u32 {
    check_null!(blob);
    check_null!(server);
    check_null!(username);
    check_null!(password);

    let blob = unsafe { from_raw_parts(blob, try_execute!(blob_len.try_into(), NTE_INVALID_PARAMETER)) };
    let server = try_execute!(
        unsafe { CStr::from_ptr(server as *const _) }.to_str(),
        NTE_INVALID_PARAMETER
    );
    let username = try_execute!(
        unsafe { CStr::from_ptr(username as *const _) }.to_str(),
        NTE_INVALID_PARAMETER
    );
    let password = try_execute!(
        unsafe { CStr::from_ptr(password as *const _) }.to_str(),
        NTE_INVALID_PARAMETER
    )
    .to_owned();
    let computer_name = if !computer_name.is_null() {
        Some(
            try_execute!(
                unsafe { CStr::from_ptr(computer_name as *const _) }.to_str(),
                NTE_INVALID_PARAMETER
            )
            .to_owned(),
        )
    } else {
        None
    };

    let secret_data = try_execute!(
        n_crypt_unprotect_secret(blob, server, username, password.into(), computer_name),
        NTE_INTERNAL_ERROR
    );

    if secret_data.as_ref().is_empty() {
        error!("Decrypted secret is empty");
        return NTE_INTERNAL_ERROR;
    }

    // SAFETY: Memory allocation should be safe. Moreover, we check for the null value below.
    let secret_buf = unsafe { libc::malloc(secret_data.as_ref().len()) as *mut u8 };
    if secret_buf.is_null() {
        error!("Failed to allocate memory for the output DPAPI blob: blob buf pointer is NULL");
        return NTE_NO_MEMORY;
    }

    let buf = unsafe { from_raw_parts_mut(secret_buf, secret_data.as_ref().len()) };
    buf.copy_from_slice(secret_data.as_ref());

    unsafe { *secret = secret_buf };

    ERROR_SUCCESS
}

#[instrument(skip_all)]
#[no_mangle]
pub extern "system" fn DpapiFree(blob: LpByte) -> u32 {
    check_null!(blob);

    // SAFETY: blob pointer is not NULL (checked above).
    unsafe {
        libc::free(blob as _);
    }

    ERROR_SUCCESS
}
