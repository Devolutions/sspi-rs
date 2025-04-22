#[macro_use]
mod macros;
mod api;
mod session_token;

use std::ffi::CStr;
use std::slice::{from_raw_parts, from_raw_parts_mut};

use dpapi::CryptProtectSecretArgs;
use dpapi_native_transport::NativeTransport;
use dpapi_transport::ProxyOptions;
use ffi_types::common::{Dword, LpByte, LpCByte, LpCStr, LpCUuid, LpDword};
use tokio::runtime::Builder;
use url::Url;
use uuid::Uuid;

use self::api::{n_crypt_protect_secret, n_crypt_unprotect_secret};

// https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptprotectsecret#return-value
const ERROR_SUCCESS: u32 = 0;
const NTE_INVALID_PARAMETER: u32 = 0x80090027;
const NTE_INTERNAL_ERROR: u32 = 0x8009002d;
const NTE_NO_MEMORY: u32 = 0x8009000e;

/// Type that represents a function for obtaining the session token.
///
/// We need it because we don't know the destination address in advance.
///
/// Parameters:
/// * `LpCUuid` is the session id.
/// * `LpCStr` is the destination of the proxied connection.
/// * `Lpbyte` is the session token buffer. It must be preallocated.
/// * `LpDword` is the session token buffer length.
type GetSessionTokenFn = unsafe extern "system" fn(LpCUuid, LpCStr, LpByte, LpDword) -> u32;

/// Encrypts the secret using the DPAPI.
///
/// This function simulated the `NCryptProtectSecret` function. Encryption requires making RPCs call to the domain.
///
/// # Safety
///
/// Input parameters must meet the following requirements:
///
/// * `secret` must be a valid pointer to the secret buffer. This parameter **cannot be NULL**.
/// * `secret_len` is a length of the `secret` buffer.
/// * `sid` must be a valid pointer to the UTF-8 SID string (with a null-terminator character). This parameter **cannot be NULL**.
/// * `root_key` is a pointer to the root key UUID. This parameter is optional and can be NULL.
/// * `server` must be a valid pointer to the UTF-8 string (with a null-terminator character) containing target server hostname.
///   Do not use IP address. This parameter **cannot be NULL**.
/// * `username` must be a valid pointer to the UTF-8 string (with a null-terminator character) containing username.
///   This parameter **cannot be NULL**. The username can be specified in FQDN (DOMAIN\username) or UPN (username@domain) format
/// * `password` must be a valid pointer to the UTF-8 string (with a null-terminator character) containing user's password.
///   This parameter **cannot be NULL**.
/// * `computer_name` must be a valid pointer to the UTF-8 string (with a null-terminator character) containing client's computer name.
///   This parameter can be NULL. If it's NULL, the current computer name will be used.
/// * `blob` is a pointer to the output buffer containing DPAPI blob. This parameter **cannot be NULL**.
///   The caller is responsible for freeing the memory using the [DpapiFree] function.
/// * `blob_len` is a length of the output `blob` buffer. This parameter **cannot be NULL**.
///
/// MSDN:
/// * [NCryptProtectSecret function (`ncryptprotect.h`)](https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptprotectsecret).
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
    proxy_url: LpCStr,
    get_session_token_fn: Option<GetSessionTokenFn>,
    blob: *mut LpByte,
    blob_len: *mut Dword,
) -> u32 {
    catch_panic! {
        check_null!(secret);
        check_null!(sid);
        check_null!(server);
        check_null!(username);
        check_null!(password);
        check_null!(blob);
        check_null!(blob_len);

        try_execute!(sspi::install_default_crypto_provider_if_necessary().map_err(|_| "failed to initialize default crypto provider"), NTE_INTERNAL_ERROR);

        let secret =
            // SAFETY: The `secret` pointer is not NULL (checked above). Other guarantees should be upheld by the caller.
            unsafe { from_raw_parts(secret, try_execute!(secret_len.try_into(), NTE_INVALID_PARAMETER)) }.to_owned();
        let sid = try_execute!(
            // SAFETY: The `sid` pointer is not NULL (checked above). Other guarantees should be upheld by the caller.
            unsafe { CStr::from_ptr(sid as *const _) }.to_str(),
            NTE_INVALID_PARAMETER
        )
        .to_owned();
        let root_key_id = if !root_key.is_null() {
            // SAFETY: The `root_key` pointer is not NULL (checked above).
            let id = unsafe { *root_key };
            let root_key = Uuid::from_fields(id.data1, id.data2, id.data3, &id.data4);

            Some(root_key)
        } else {
            None
        };
        let server = try_execute!(
            // SAFETY: The `server` pointer is not NULL (checked above). Other guarantees should be upheld by the caller.
            unsafe { CStr::from_ptr(server as *const _) }.to_str(),
            NTE_INVALID_PARAMETER
        );
        let username = try_execute!(
            // SAFETY: The `username` pointer is not NULL (checked above). Other guarantees should be upheld by the caller.
            unsafe { CStr::from_ptr(username as *const _) }.to_str(),
            NTE_INVALID_PARAMETER
        );
        let password = try_execute!(
            // SAFETY: The `password` pointer is not NULL (checked above). Other guarantees should be upheld by the caller.
            unsafe { CStr::from_ptr(password as *const _) }.to_str(),
            NTE_INVALID_PARAMETER
        )
        .to_owned();
        let client_computer_name = if !computer_name.is_null() {
            Some(
                try_execute!(
                    // SAFETY: The `computer_name` pointer is not NULL (checked above). Other guarantees should be upheld by the caller.
                    unsafe { CStr::from_ptr(computer_name as *const _) }.to_str(),
                    NTE_INVALID_PARAMETER
                )
                .to_owned(),
            )
        } else {
            None
        };

        let proxy = if let (false, Some(get_session_token_fn)) = (proxy_url.is_null(), get_session_token_fn) {
            info!("Proxy parameters are not empty. Proceeding with tunnelled connection.");

            let proxy_url = try_execute!(
                // SAFETY: The `proxy_url` pointer is not NULL (checked above). Other guarantees should be upheld by the caller.
                unsafe { CStr::from_ptr(proxy_url as *const _) }.to_str(),
                NTE_INVALID_PARAMETER
            );

            Some(ProxyOptions {
                proxy: try_execute!(Url::parse(proxy_url), NTE_INVALID_PARAMETER),
                // SAFETY:
                // The C function pointer must be safe to call. It's a user's responsibility to uphold its correctness.
                get_session_token: unsafe {
                    session_token::session_token_fn(get_session_token_fn)
                },
            })
        } else {
            info!("Proxy parameters are empty. Proceeding with direct connection.");

            None
        };
        let mut network_client = dpapi::network_client::SyncNetworkClient::new();

        let runtime  = try_execute!(Builder::new_current_thread().build(), NTE_INTERNAL_ERROR);
        let blob_data = try_execute!(
            runtime.block_on(n_crypt_protect_secret::<NativeTransport>(
                CryptProtectSecretArgs {
                    data: secret.into(),
                    sid,
                    root_key_id,
                    server,
                    proxy,
                    username,
                    password: password.into(),
                    client_computer_name,
                    network_client: &mut network_client,
                }
            )),
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

        // SAFETY: The `blob_buf` pointer is not NULL (checked above). The slice construction is safe because `blob_buf`
        // points to allocated, properly aligned, and not-empty bytes range.
        let buf = unsafe { from_raw_parts_mut(blob_buf, blob_data.len()) };
        buf.copy_from_slice(blob_data.as_ref());

        // SAFETY: The `blob` pointer is not NULL (checked above).
        unsafe {
            *blob = blob_buf;
            *blob_len = try_execute!(blob_data.len().try_into(), NTE_INTERNAL_ERROR);
        }

        ERROR_SUCCESS
    }
}

/// Decrypt the DPAPI blob.
///
/// This function simulated the `NCryptUnprotectSecret` function. Decryption requires making RPC calls to the domain.
///
/// # Safety
///
/// Input parameters must meet the following requirements:
///
/// * `blob` must be a valid pointer to the DPAPI blob buffer. This parameter **cannot be NULL**.
/// * `blob_len` is a length of the `blob` buffer.
/// * `server` must be a valid pointer to the UTF-8 string (with a null-terminator character) containing target server hostname.
///   Do not use IP address. This parameter **cannot be NULL**.
/// * `username` must be a valid pointer to the UTF-8 string (with a null-terminator character) containing username.
///   This parameter **cannot be NULL**. The username can be specified in FQDN (DOMAIN\username) or UPN (username@domain) format
/// * `password` must be a valid pointer to the UTF-8 string (with a null-terminator character) containing user's password.
///   This parameter **cannot be NULL**.
/// * `computer_name` must be a valid pointer to the UTF-8 string (with a null-terminator character) containing client's computer name.
///   This parameter can be NULL. If it's NULL, the current computer name will be used.
/// * `secret` is a pointer to the output buffer containing decrypted secret. This parameter **cannot be NULL**.
///   The caller is responsible for freeing the memory using the [DpapiFree] function.
/// * `secret_len` is a length of the output `secret` buffer. This parameter **cannot be NULL**.
///
/// MSDN:
/// * [NCryptUnprotectSecret function (ncryptprotect.h)](https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptunprotectsecret).
#[instrument(skip_all)]
#[no_mangle]
pub unsafe extern "system" fn DpapiUnprotectSecret(
    blob: LpCByte,
    blob_len: Dword,
    server: LpCStr,
    username: LpCStr,
    password: LpCStr,
    computer_name: LpCStr,
    proxy_url: LpCStr,
    get_session_token_fn: Option<GetSessionTokenFn>,
    secret: *mut LpByte,
    secret_len: *mut Dword,
) -> u32 {
    catch_panic! {
        check_null!(blob);
        check_null!(server);
        check_null!(username);
        check_null!(password);
        check_null!(secret);

        try_execute!(sspi::install_default_crypto_provider_if_necessary().map_err(|_| "failed to initialize default crypto provider"), NTE_INTERNAL_ERROR);

        // SAFETY: The `blob` pointer is not NULL (checked above). Other guarantees should be upheld by the caller.
        let blob = unsafe { from_raw_parts(blob, try_execute!(blob_len.try_into(), NTE_INVALID_PARAMETER)) };
        let server = try_execute!(
            // SAFETY: The `server` pointer is not NULL (checked above). Other guarantees should be upheld by the caller.
            unsafe { CStr::from_ptr(server as *const _) }.to_str(),
            NTE_INVALID_PARAMETER
        );
        let username = try_execute!(
            // SAFETY: The `username` pointer is not NULL (checked above). Other guarantees should be upheld by the caller.
            unsafe { CStr::from_ptr(username as *const _) }.to_str(),
            NTE_INVALID_PARAMETER
        );
        let password = try_execute!(
            // SAFETY: The `password` pointer is not NULL (checked above). Other guarantees should be upheld by the caller.
            unsafe { CStr::from_ptr(password as *const _) }.to_str(),
            NTE_INVALID_PARAMETER
        )
        .to_owned();
        let computer_name = if !computer_name.is_null() {
            Some(
                try_execute!(
                    // SAFETY: The `computer_name` pointer is not NULL (checked above). Other guarantees should be upheld by the caller.
                    unsafe { CStr::from_ptr(computer_name as *const _) }.to_str(),
                    NTE_INVALID_PARAMETER
                )
                .to_owned(),
            )
        } else {
            None
        };

        let proxy = if let (false, Some(get_session_token_fn)) = (proxy_url.is_null(), get_session_token_fn) {
            info!("Proxy parameters are not empty. Proceeding  with tunnelled connection.");

            let proxy_url = try_execute!(
                // SAFETY: The `proxy_url` pointer is not NULL (checked above). Other guarantees should be upheld by the caller.
                unsafe { CStr::from_ptr(proxy_url as *const _) }.to_str(),
                NTE_INVALID_PARAMETER
            );

            Some(ProxyOptions {
                proxy: try_execute!(Url::parse(proxy_url), NTE_INVALID_PARAMETER),
                // SAFETY:
                // The C function pointer must be safe to call. It's a user's responsibility to uphold its correctness.
                get_session_token: unsafe {
                    session_token::session_token_fn(get_session_token_fn)
                },
            })
        } else {
            info!("Proxy parameters are empty. Proceeding  with direct connection.");

            None
        };
        let mut network_client = dpapi::network_client::SyncNetworkClient::new();

        let runtime  = try_execute!(Builder::new_current_thread().build(), NTE_INTERNAL_ERROR);
        let secret_data = try_execute!(
            runtime.block_on(n_crypt_unprotect_secret::<NativeTransport>(blob, server, proxy, username, password.into(), computer_name, &mut network_client)),
            NTE_INTERNAL_ERROR
        );

        if secret_data.as_ref().is_empty() {
            error!("Decrypted secret is empty.");
            return NTE_INTERNAL_ERROR;
        }

        // SAFETY: Memory allocation should be safe. Moreover, we check for the null value below.
        let secret_buf = unsafe { libc::malloc(secret_data.as_ref().len()) as *mut u8 };
        if secret_buf.is_null() {
            error!("Failed to allocate memory for the output DPAPI blob: blob buf pointer is NULL.");
            return NTE_NO_MEMORY;
        }

        // SAFETY: The `secret_buf` pointer is not NULL (checked above). The slice construction is safe because `secret_buf`
        // points to allocated, properly aligned, and not-empty bytes range.
        let buf = unsafe { from_raw_parts_mut(secret_buf, secret_data.as_ref().len()) };
        buf.copy_from_slice(secret_data.as_ref());

        // SAFETY: The `secret` pointer is not NULL (checked above).
        unsafe {
            *secret = secret_buf;
            *secret_len = try_execute!(secret_data.as_ref().len().try_into(), NTE_INTERNAL_ERROR);
        }

        ERROR_SUCCESS
    }
}

/// Frees the memory allocated by [DpapiProtectSecret] and [DpapiUnprotectSecret] functions.
///
/// # Safety
///
/// The `data` parameter must be a valid pointer to the memory allocated by the [DpapiProtectSecret] or
/// [DpapiUnprotectSecret] functions and **cannot be NULL**.
#[instrument(skip_all)]
#[no_mangle]
pub unsafe extern "system" fn DpapiFree(buf: LpCByte) -> u32 {
    catch_panic! {
        check_null!(buf);

        // SAFETY: The user should uphold that the passed pointer is a memory allocated by an out DPAPI functions.
        unsafe {
            libc::free(buf as _);
        }

        ERROR_SUCCESS
    }
}

#[cfg(test)]
mod tests {
    //! This tests simulate `DpapiProtectSecret`, `DpapiUnprotectSecret`, and `DpapiFree` function calls.
    //! It's better to run them using Miri: https://github.com/rust-lang/miri.
    //! cargo +nightly miri test
    //!
    //! Note: this tests aim to check only the FFI functions implementation.
    //! Checking the correctness of DPAPI functions is not a goal of these tests.

    use std::ptr::{null, null_mut};

    use super::*;

    #[test]
    fn test_dpapi_protect_secret() {
        let secret = b"secret-to-encrypt";
        let secret_len = secret.len() as u32;
        let sid = "S-1-5-21-1485435871-894665558-560847465-1104\0";
        let server = "win-956cqossjtf.tbt.com\0";
        let username = "t2@tbt.com\0";
        let password = "qqqQQQ111!!!\0";
        let mut blob: LpByte = null_mut();
        let mut blob_len = 0;

        let result = unsafe {
            DpapiProtectSecret(
                secret.as_ptr(),
                secret_len,
                sid.as_ptr(),
                null(),
                server.as_ptr(),
                username.as_ptr(),
                password.as_ptr(),
                null(),
                null(),
                None,
                &mut blob,
                &mut blob_len,
            )
        };

        assert_eq!(result, ERROR_SUCCESS);
        assert!(!blob.is_null());
        assert!(blob_len > 0);

        let mut decrypted_secret: LpByte = null_mut();
        let mut secret_len = 0;

        let result = unsafe {
            DpapiUnprotectSecret(
                blob,
                blob_len,
                server.as_ptr(),
                username.as_ptr(),
                password.as_ptr(),
                null(),
                null(),
                None,
                &mut decrypted_secret,
                &mut secret_len,
            )
        };

        assert_eq!(result, ERROR_SUCCESS);
        assert!(!decrypted_secret.is_null());
        assert!(secret_len > 0);

        unsafe {
            DpapiFree(blob);
            DpapiFree(decrypted_secret);
        }
    }

    #[test]
    fn test_dpapi_protect_secret_proxied() {
        let secret = b"secret-to-encrypt";
        let secret_len = secret.len() as u32;
        let sid = "S-1-5-21-1485435871-894665558-560847465-1104\0";
        let server = "win-956cqossjtf.tbt.com\0";
        let username = "t2@tbt.com\0";
        let password = "qqqQQQ111!!!\0";
        let proxy_url = "ws://dg.tbt.com:7171/\0";
        let mut blob: LpByte = null_mut();
        let mut blob_len = 0;

        let result = unsafe {
            DpapiProtectSecret(
                secret.as_ptr(),
                secret_len,
                sid.as_ptr(),
                null(),
                server.as_ptr(),
                username.as_ptr(),
                password.as_ptr(),
                null(),
                proxy_url.as_ptr(),
                Some(api::get_session_token),
                &mut blob,
                &mut blob_len,
            )
        };

        assert_eq!(result, ERROR_SUCCESS);
        assert!(!blob.is_null());
        assert!(blob_len > 0);

        let mut decrypted_secret: LpByte = null_mut();
        let mut secret_len = 0;

        let result = unsafe {
            DpapiUnprotectSecret(
                blob,
                blob_len,
                server.as_ptr(),
                username.as_ptr(),
                password.as_ptr(),
                null(),
                proxy_url.as_ptr(),
                Some(api::get_session_token),
                &mut decrypted_secret,
                &mut secret_len,
            )
        };

        assert_eq!(result, ERROR_SUCCESS);
        assert!(!decrypted_secret.is_null());
        assert!(secret_len > 0);

        unsafe {
            DpapiFree(blob);
            DpapiFree(decrypted_secret);
        }
    }
}
