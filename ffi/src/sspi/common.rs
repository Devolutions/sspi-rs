use std::slice::{from_raw_parts, from_raw_parts_mut};

use libc::{c_ulonglong, c_void};
use num_traits::cast::{FromPrimitive, ToPrimitive};
use sspi::{
    BufferType, DataRepresentation, DecryptionFlags, EncryptionFlags, Error, ErrorKind, SecurityBuffer,
    SecurityBufferRef, SecurityBufferType, ServerRequestFlags, Sspi,
};
#[cfg(windows)]
use symbol_rename_macro::rename_symbol;

use super::credentials_attributes::CredentialsAttributes;
use super::sec_buffer::{
    copy_to_c_sec_buffer, p_sec_buffers_to_security_buffers, PSecBuffer, PSecBufferDesc, SecBuffer,
};
use super::sec_handle::{p_ctxt_handle_to_sspi_context, CredentialsHandle, PCredHandle, PCtxtHandle};
use super::sspi_data_types::{PTimeStamp, SecurityStatus};
use super::utils::transform_credentials_handle;
use crate::sspi::sec_handle::SspiHandle;
use crate::utils::into_raw_ptr;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_FreeCredentialsHandle"))]
#[no_mangle]
pub unsafe extern "system" fn FreeCredentialsHandle(ph_credential: PCredHandle) -> SecurityStatus {
    check_null!(ph_credential);

    // SAFETY: `ph_credentials` is not null. We've checked for this above.
    let cred_handle = unsafe { (*ph_credential).dw_lower as *mut CredentialsHandle };
    check_null!(cred_handle);

    // SAFETY: `cred_handle` is not null. We've checked for this above.
    // We create and allocate credentials handles using `Box::into_raw`. Thus,
    // it is safe to deallocate them using `Box::from_raw`.
    // The user have to ensure that the credentials handle was created by us.
    let _cred_handle = unsafe { Box::from_raw(cred_handle) };

    0
}

pub type FreeCredentialsHandleFn = unsafe extern "system" fn(PCredHandle) -> SecurityStatus;

#[instrument(skip_all)]
#[allow(clippy::useless_conversion)]
#[cfg_attr(windows, rename_symbol(to = "Rust_AcceptSecurityContext"))]
#[no_mangle]
pub unsafe extern "system" fn AcceptSecurityContext(
    ph_credential: PCredHandle,
    mut ph_context: PCtxtHandle,
    p_input: PSecBufferDesc,
    f_context_req: u32,
    target_data_rep: u32,
    ph_new_context: PCtxtHandle,
    p_output: PSecBufferDesc,
    pf_context_attr: *mut u32,
    _pts_expiry: PTimeStamp,
) -> SecurityStatus {
    catch_panic! {
        // ph_context can be null on the first call
        check_null!(ph_new_context);
        check_null!(ph_credential);
        check_null!(p_input);
        check_null!(p_output);
        check_null!(pf_context_attr);

        // SAFETY: `ph_credentials` is not null. We've checked for this above.
        let credentials_handle = unsafe { (*ph_credential).dw_lower as *mut CredentialsHandle };

        // SAFETY: It's safe to call the function, because it has internal null check and proper error handling.
        let (auth_data, security_package_name, attributes) = unsafe {
            match transform_credentials_handle(credentials_handle) {
                Some(data) => data,
                None => return ErrorKind::InvalidHandle.to_u32().unwrap(),
            }
        };

        // SAFETY: It's safe to call the function, because:
        // *`ph_context` can be null;
        // * the value behind `ph_context` must be initialized by ourself: the user does not have to create the [CtxHandle] values ​​themselves.
        // * other parameters are type checked.
        let mut sspi_context_ptr = try_execute!(unsafe { p_ctxt_handle_to_sspi_context(
            &mut ph_context,
            Some(security_package_name),
            attributes,
        )});

        // SAFETY: It's safe to call the `as_mut` function, because `sspi_context_ptr` is a local pointer,
        // which is initialized by the `p_ctx_handle_to_sspi_context` function. Thus, the value behind this pointer is valid.
        let sspi_context = unsafe { sspi_context_ptr.as_mut() };

        // SAFETY: `p_input` is not null. We've checked for this above. Additionally, we check `p_buffers` for null.
        // All other guarantees must be provided by user.
        let mut input_tokens = try_execute!(unsafe {
                if (*p_input).p_buffers.is_null() {
                    Err(Error::new(ErrorKind::InvalidParameter, "p_buffers cannot be null"))
                } else {
                    Ok(p_sec_buffers_to_security_buffers(from_raw_parts((*p_input).p_buffers, (*p_input).c_buffers as usize)))
                }
        });

        let mut output_tokens = vec![SecurityBuffer::new(Vec::with_capacity(1024), BufferType::Token)];

        let result_status = sspi_context.accept_security_context()
            .with_credentials_handle(&mut Some(auth_data))
            .with_context_requirements(ServerRequestFlags::from_bits(f_context_req.try_into().unwrap()).unwrap())
            .with_target_data_representation(DataRepresentation::from_u32(target_data_rep.try_into().unwrap()).unwrap())
            .with_input(&mut input_tokens)
            .with_output(&mut output_tokens)
            .execute(sspi_context);

        // SAFETY: `p_output` is not null. We've checked this above.
        try_execute!(unsafe { copy_to_c_sec_buffer((*p_output).p_buffers, &output_tokens, false) });

        // SAFETY: `ph_new_context` and `pf_context_attr` are not null. We've checked this above.
        let ph_new_context = unsafe { ph_new_context.as_mut() }.expect("ph_new_context should not be null");

        ph_new_context.dw_lower = sspi_context_ptr.as_ptr() as c_ulonglong;
        ph_new_context.dw_upper = into_raw_ptr(security_package_name.to_owned()) as c_ulonglong;
        unsafe {
            *pf_context_attr = f_context_req;
        }

        let result = try_execute!(result_status);
        result.status.to_u32().unwrap()
    }
}

pub type AcceptSecurityContextFn = unsafe extern "system" fn(
    PCredHandle,
    PCtxtHandle,
    PSecBufferDesc,
    u32,
    u32,
    PCtxtHandle,
    PSecBufferDesc,
    *mut u32,
    PTimeStamp,
) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_CompleteAuthToken"))]
#[no_mangle]
pub unsafe extern "system" fn CompleteAuthToken(
    mut ph_context: PCtxtHandle,
    p_token: PSecBufferDesc,
) -> SecurityStatus {
    catch_panic! {
        check_null!(ph_context);
        check_null!(p_token);

        // SAFETY: `p_token` is not null. We've checked this above.
        unsafe { check_null!((*p_token).p_buffers); }

        // SAFETY: It's safe to call the function, because:
        // *`ph_context` can be null;
        // * the value behind `ph_context` must be initialized by ourself: the user does not have to create the [CtxHandle] values ​​themselves.
        // * other parameters are type checked.
        let mut sspi_context_ptr = try_execute!(unsafe { p_ctxt_handle_to_sspi_context(
            &mut ph_context,
            None,
            &CredentialsAttributes::default()
        )});

        // SAFETY: It's safe to call the `as_mut` function, because `sspi_context_ptr` is a local pointer,
        // which is initialized by the `p_ctx_handle_to_sspi_context` function. Thus, the value behind this pointer is valid.
        let sspi_context = unsafe { sspi_context_ptr.as_mut() };

        // SAFETY: This function is safe to call because `p_buffers` is not null. We've checked this above.
        let raw_buffers = unsafe { from_raw_parts((*p_token).p_buffers, (*p_token).c_buffers as usize) };
        // SAFETY: This function is safe to call because `raw_buffers` is type checked. All other guarantees must be provided by user.
        let mut buffers = unsafe { p_sec_buffers_to_security_buffers(raw_buffers) };

        sspi_context.complete_auth_token(&mut buffers).map_or_else(
            |err| err.error_type.to_u32().unwrap(),
            |result| result.to_u32().unwrap(),
        )
    }
}

pub type CompleteAuthTokenFn = unsafe extern "system" fn(PCtxtHandle, PSecBufferDesc) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_DeleteSecurityContext"))]
#[no_mangle]
pub unsafe extern "system" fn DeleteSecurityContext(mut ph_context: PCtxtHandle) -> SecurityStatus {
    catch_panic!(
        check_null!(ph_context);

        // SAFETY: It's safe to call the function, because:
        // * the value behind `ph_context` must be initialized by ourself: the user does not have to create the [CtxHandle] values ​​themselves.
        // * other parameters are type checked.
        let mut sspi_context_ptr = try_execute!(unsafe { p_ctxt_handle_to_sspi_context(
            &mut ph_context,
            None,
            &CredentialsAttributes::default()
        )});

        // SAFETY: It's safe to constructs a box from a raw pointer because:
        // * the `sspi_context_ptr` is not null;
        // * the value behind `sspi_context_ptr` must be initialized by ourself: the user does not have to create the [CtxHandle] values ​​themselves.
        let _context: Box<SspiHandle> = unsafe {
            Box::from_raw(sspi_context_ptr.as_mut())
        };

        // SAFETY: `ph_context` is not null. We've checked for it above.
        let dw_upper = unsafe { (*ph_context).dw_upper };
        if dw_upper != 0 {
            // SAFETY: It's safe to constructs a box from a raw pointer because:
            // * the `dw_upper` is not equal to zero;
            // * the value behind `dw_upper` pointer must be initialized by ourself: the user does not have to create the [CtxHandle] values ​​themselves.
            let _name: Box<String> = unsafe { Box::from_raw(dw_upper as *mut String) };
        }

        0
    )
}

pub type DeleteSecurityContextFn = unsafe extern "system" fn(PCtxtHandle) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_ApplyControlToken"))]
#[no_mangle]
pub extern "system" fn ApplyControlToken(_ph_context: PCtxtHandle, _p_input: PSecBufferDesc) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type ApplyControlTokenFn = extern "system" fn(PCtxtHandle, PSecBufferDesc) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_ImpersonateSecurityContext"))]
#[no_mangle]
pub extern "system" fn ImpersonateSecurityContext(_ph_context: PCtxtHandle) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type ImpersonateSecurityContextFn = extern "system" fn(PCtxtHandle) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_RevertSecurityContext"))]
#[no_mangle]
pub extern "system" fn RevertSecurityContext(_ph_context: PCtxtHandle) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type RevertSecurityContextFn = extern "system" fn(PCtxtHandle) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_MakeSignature"))]
#[no_mangle]
pub extern "system" fn MakeSignature(
    _ph_context: PCtxtHandle,
    _f_qop: u32,
    _p_message: PSecBufferDesc,
    _message_seq_no: u32,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type MakeSignatureFn = extern "system" fn(PCtxtHandle, u32, PSecBufferDesc, u32) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_VerifySignature"))]
#[no_mangle]
pub extern "system" fn VerifySignature(
    _ph_context: PCtxtHandle,
    _message: PSecBufferDesc,
    _message_seq_no: u32,
    _pf_qop: *mut u32,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type VerifySignatureFn = extern "system" fn(PCtxtHandle, PSecBufferDesc, u32, *mut u32) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_FreeContextBuffer"))]
#[no_mangle]
pub unsafe extern "system" fn FreeContextBuffer(pv_context_buffer: *mut c_void) -> SecurityStatus {
    // NOTE: see https://github.com/Devolutions/sspi-rs/pull/141 for rationale behind libc usage.
    // SAFETY: Memory deallocation is safe.
    // The user must call this function to free buffers allocated by ourself. On our side, we always use `malloc`
    // to allocate buffers in in FFI.
    unsafe {
        libc::free(pv_context_buffer);
    }

    0
}

pub type FreeContextBufferFn = unsafe extern "system" fn(*mut c_void) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_ExportSecurityContext"))]
#[no_mangle]
pub extern "system" fn ExportSecurityContext(
    _ph_context: PCtxtHandle,
    _f_flags: u32,
    _p_packed_context: PSecBuffer,
    _p_token: *mut *mut c_void,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type ExportSecurityContextFn = extern "system" fn(PCtxtHandle, u32, PSecBuffer, *mut *mut c_void) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QuerySecurityContextToken"))]
#[no_mangle]
pub extern "system" fn QuerySecurityContextToken(_ph_context: PCtxtHandle, _token: *mut *mut c_void) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type QuerySecurityContextTokenFn = extern "system" fn(PCtxtHandle, *mut *mut c_void) -> SecurityStatus;

#[allow(clippy::useless_conversion)]
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_EncryptMessage"))]
#[no_mangle]
pub unsafe extern "system" fn EncryptMessage(
    mut ph_context: PCtxtHandle,
    f_qop: u32,
    p_message: PSecBufferDesc,
    message_seq_no: u32,
) -> SecurityStatus {
    catch_panic! {
        check_null!(ph_context);
        check_null!(p_message);

        // SAFETY: `p_message` is not null. We've checked this above.
        unsafe { check_null!((*p_message).p_buffers); }

        // SAFETY: It's safe to call the function, because:
        // *`ph_context` can be null;
        // * the value behind `ph_context` must be initialized by ourself: the user does not have to create the [CtxHandle] values ​​themselves.
        // * other parameters are type checked.
        let mut sspi_context_ptr = try_execute!(unsafe { p_ctxt_handle_to_sspi_context(
            &mut ph_context,
            None,
            &CredentialsAttributes::default()
        )});

        // SAFETY: It's safe to call the `as_mut` function, because `sspi_context_ptr` is a local pointer,
        // which is initialized by the `p_ctx_handle_to_sspi_context` function. Thus, the value behind this pointer is valid.
        let sspi_context = unsafe { sspi_context_ptr.as_mut() };

        // SAFETY: `p_message` is not null. We've checked this above.
        let len = unsafe { (*p_message).c_buffers as usize };

        // SAFETY: `p_message` is not null. We've checked this above. Moreover, we've checked `p_buffers` for null above.
        let raw_buffers = unsafe {
            from_raw_parts((*p_message).p_buffers, len)
        };

        // SAFETY: The user must provide guarantees about the correctness of buffers in `raw_buffers'.
        let mut message = try_execute!(unsafe { p_sec_buffers_to_decrypt_buffers(raw_buffers)});

        let result_status = sspi_context.encrypt_message(
            EncryptionFlags::from_bits(f_qop.try_into().unwrap()).unwrap(),
            &mut message,
            message_seq_no.try_into().unwrap(),
        );

        // SAFETY: `p_message` and `p_buffers` are not null. We've checked this above.
        // All other guarantees must be provided by user.
        try_execute!(unsafe { copy_decrypted_buffers((*p_message).p_buffers, message) });

        let result = try_execute!(result_status);
        result.to_u32().unwrap()
    }
}

pub type EncryptMessageFn = unsafe extern "system" fn(PCtxtHandle, u32, PSecBufferDesc, u32) -> SecurityStatus;

#[allow(clippy::useless_conversion)]
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_DecryptMessage"))]
#[no_mangle]
pub unsafe extern "system" fn DecryptMessage(
    mut ph_context: PCtxtHandle,
    p_message: PSecBufferDesc,
    message_seq_no: u32,
    pf_qop: *mut u32,
) -> SecurityStatus {
    catch_panic! {
        check_null!(ph_context);
        check_null!(p_message);

        // SAFETY: `p_message` is not null. We've checked this above.
        unsafe { check_null!((*p_message).p_buffers); }

        // SAFETY: It's safe to call the function, because:
        // *`ph_context` can be null;
        // * the value behind `ph_context` must be initialized by ourself: the user does not have to create the [CtxHandle] values ​​themselves.
        // * other parameters are type checked.
        let mut sspi_context_ptr = try_execute!(unsafe { p_ctxt_handle_to_sspi_context(
            &mut ph_context,
            None,
            &CredentialsAttributes::default()
        )});

        // SAFETY: It's safe to call the `as_mut` function, because `sspi_context_ptr` is a local pointer,
        // which is initialized by the `p_ctx_handle_to_sspi_context` function. Thus, the value behind this pointer is valid.
        let sspi_context = unsafe { sspi_context_ptr.as_mut() };

        // SAFETY: `p_message` is not null. We've checked this above.
        let len = unsafe { (*p_message).c_buffers as usize };
        // SAFETY: `p_message` and `p_buffers` is not null. We've checked this above.
        let raw_buffers = unsafe { from_raw_parts((*p_message).p_buffers, len) };
        // SAFETY: The user must provide guarantees about the correctness of buffers in `raw_buffers'.
        let mut message = try_execute!(unsafe { p_sec_buffers_to_decrypt_buffers(raw_buffers) });

        let (decryption_flags, result_status) =
            match sspi_context.decrypt_message(&mut message, message_seq_no.try_into().unwrap()) {
                Ok(flags) => (flags, Ok(())),
                Err(error) => (DecryptionFlags::empty(), Err(error)),
            };

        // SAFETY: `p_message` and `p_buffers` is not null. We've checked this above.
        // All other guarantees must be provided by user.
        try_execute!(unsafe { copy_decrypted_buffers((*p_message).p_buffers, message) });
        // `pf_qop` can be null if this library is used as a CredSsp security package
        if !pf_qop.is_null() {
            let flags = try_execute!(decryption_flags.bits().try_into(), ErrorKind::InternalError);
            // SAFETY: `pf_qop` is not null. We've checked this above.
            unsafe { *pf_qop = flags };
        }

        try_execute!(result_status);

        0
    }
}

/// Creates a vector of [SecurityBufferRef]s from the input C buffers.
///
/// *Attention*: after this function call, no one should touch [raw_buffers]. Otherwise, we can get UB.
/// It's because this function creates exclusive (mutable) Rust references to the input buffers.
#[allow(clippy::useless_conversion)]
unsafe fn p_sec_buffers_to_decrypt_buffers(raw_buffers: &[SecBuffer]) -> sspi::Result<Vec<SecurityBufferRef>> {
    let mut buffers = Vec::with_capacity(raw_buffers.len());

    for raw_buffer in raw_buffers {
        let buf =
            SecurityBufferRef::with_owned_security_buffer_type(SecurityBufferType::try_from(raw_buffer.buffer_type)?)?;

        buffers.push(if BufferType::Missing == buf.buffer_type() {
            // https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbuffer
            // SECBUFFER_MISSING: ...The pvBuffer member is ignored in this type.
            SecurityBufferRef::missing_buf(raw_buffer.cb_buffer.try_into()?)
        } else {
            let data = if raw_buffer.pv_buffer.is_null() || raw_buffer.cb_buffer == 0 {
                &mut []
            } else {
                // SAFETY: the safety contract [raw_buffers] must be upheld by the caller.
                unsafe { from_raw_parts_mut(raw_buffer.pv_buffer as *mut u8, raw_buffer.cb_buffer.try_into()?) }
            };
            buf.with_data(data)?
        })
    }

    Ok(buffers)
}

/// Copies Rust-security-buffers into C-security-buffers.
///
/// This function accepts owned [from_buffers] to avoid UB and other errors. Rust-buffers should
/// not be used after the data is copied into C-buffers.
unsafe fn copy_decrypted_buffers(to_buffers: PSecBuffer, from_buffers: Vec<SecurityBufferRef>) -> sspi::Result<()> {
    // SAFETY: the safety contract [to_buffers] must be upheld by the caller.
    let to_buffers = unsafe { from_raw_parts_mut(to_buffers, from_buffers.len()) };

    for (to_buffer, mut from_buffer) in to_buffers.iter_mut().zip(from_buffers.into_iter()) {
        // The `SECBUFFER_STREAM` buffer is only used for the data passing during the decryption
        // when the caller doesn't know the exact `SECBUFFER_TOKEN` and `SECBUFFER_DATA` lengths.
        // After the decryption, the pointer and length of the SECBUFFER_STREAM are unchanged.
        // So, we don't need to copy any data and we skip it.
        //
        // The `SECBUFFER_STREAM` usage example: https://learn.microsoft.com/en-us/windows/win32/secauthn/sspi-kerberos-interoperability-with-gssapi
        if from_buffer.buffer_type() == BufferType::Stream {
            continue;
        }

        let from_buffer_len = from_buffer.buf_len();

        to_buffer.buffer_type = from_buffer.owned_security_buffer_type().into();
        to_buffer.cb_buffer = from_buffer_len.try_into()?;

        if from_buffer.buffer_type() != BufferType::Missing {
            // We don't need to copy the actual content of the buffer because [from_buffer] is created
            // from the C-input-buffer and all decryption is performed in-place.
            to_buffer.pv_buffer = from_buffer.take_data().as_mut_ptr() as *mut _;
        }
    }

    Ok(())
}

pub type DecryptMessageFn = unsafe extern "system" fn(PCtxtHandle, PSecBufferDesc, u32, *mut u32) -> SecurityStatus;

#[cfg(test)]
mod tests {
    use std::ptr::null_mut;
    use std::slice::from_raw_parts;

    use libc::c_ulonglong;
    use sspi::credssp::SspiContext;
    use sspi::{EncryptionFlags, Kerberos, SecurityBufferRef, Sspi};

    use crate::sspi::sec_buffer::{SecBuffer, SecBufferDesc};
    use crate::sspi::sec_handle::{SecHandle, SspiHandle};
    use crate::utils::into_raw_ptr;

    fn kerberos_sec_handle(kerberos: Kerberos) -> SecHandle {
        SecHandle {
            dw_lower: {
                let sspi_context = SspiHandle::new(SspiContext::Kerberos(kerberos));
                into_raw_ptr(sspi_context) as c_ulonglong
            },
            dw_upper: into_raw_ptr(sspi::kerberos::PACKAGE_INFO.name.to_string()) as c_ulonglong,
        }
    }

    #[test]
    fn kerberos_stream_buffer_decryption() {
        // This test simulates decryption when the `SECBUFFER_STREAM` buffer is used.
        // The expected behavior is the same as for the original Windows SSPI.
        //
        // MSDN code example: https://learn.microsoft.com/en-us/windows/win32/secauthn/sspi-kerberos-interoperability-with-gssapi
        let plain_message = b"some plain message";

        let kerberos_client = sspi::kerberos::test_data::fake_client();
        let mut kerberos_server = sspi::kerberos::test_data::fake_server();

        let mut token = [0; 1024];
        let mut data = plain_message.to_vec();
        let mut message = vec![
            SecurityBufferRef::token_buf(token.as_mut_slice()),
            SecurityBufferRef::data_buf(data.as_mut_slice()),
        ];

        kerberos_server
            .encrypt_message(EncryptionFlags::empty(), &mut message, 0)
            .unwrap();

        let mut kerberos_client_context = kerberos_sec_handle(kerberos_client);

        let mut stream_buffer_data = message[0].data().to_vec();
        stream_buffer_data.extend_from_slice(message[1].data());
        let stream_buffer_data_len = stream_buffer_data.len().try_into().unwrap();
        let mut buffers = [
            SecBuffer {
                cb_buffer: stream_buffer_data_len,
                buffer_type: 10,
                pv_buffer: stream_buffer_data.as_mut_ptr() as *mut _,
            },
            SecBuffer {
                cb_buffer: 0,
                buffer_type: 1,
                pv_buffer: null_mut(),
            },
        ];
        let mut message = SecBufferDesc {
            ul_version: 0,
            c_buffers: 2,
            p_buffers: buffers.as_mut_ptr(),
        };

        let status = unsafe { super::DecryptMessage(&mut kerberos_client_context, &mut message, 0, null_mut()) };
        assert_eq!(status, 0);

        let status = unsafe { super::DeleteSecurityContext(&mut kerberos_client_context) };
        assert_eq!(status, 0);

        // Check SECBUFFER_STREAM
        assert_eq!(buffers[0].buffer_type, 10);
        assert_eq!(buffers[0].cb_buffer, stream_buffer_data_len);

        // Check SECBUFFER_DATA
        assert_eq!(buffers[1].buffer_type, 1);
        assert_eq!(buffers[1].cb_buffer, u32::try_from(plain_message.len()).unwrap());
        // Check that the decrypted data is the same as the initial message
        assert_eq!(
            unsafe {
                from_raw_parts(
                    buffers[1].pv_buffer as *const u8,
                    buffers[1].cb_buffer.try_into().unwrap(),
                )
            },
            plain_message
        );
    }

    /// This test simulates initialize security context function call. It's better to run it using Miri
    /// https://github.com/rust-lang/miri
    /// cargo +nightly miri test
    #[test]
    fn kerberos_encryption_decryption() {
        let plain_message = b"some plain message";

        let kerberos_client = sspi::kerberos::test_data::fake_client();
        let kerberos_server = sspi::kerberos::test_data::fake_server();

        let mut kerberos_server_context = kerberos_sec_handle(kerberos_server);

        let mut token = [0_u8; 1024];
        let mut data = plain_message.to_vec();
        let mut buffers = [
            SecBuffer {
                cb_buffer: token.len().try_into().unwrap(),
                buffer_type: 2, // Token
                pv_buffer: token.as_mut_ptr() as *mut _,
            },
            SecBuffer {
                cb_buffer: data.len().try_into().unwrap(),
                buffer_type: 1, // Data
                pv_buffer: data.as_mut_ptr() as *mut _,
            },
        ];
        let mut message = SecBufferDesc {
            ul_version: 0,
            c_buffers: 2,
            p_buffers: buffers.as_mut_ptr(),
        };

        let status = unsafe { super::EncryptMessage(&mut kerberos_server_context, 0, &mut message, 0) };
        assert_eq!(status, 0);

        let status = unsafe { super::DeleteSecurityContext(&mut kerberos_server_context) };
        assert_eq!(status, 0);

        let mut kerberos_client_context = kerberos_sec_handle(kerberos_client);

        let mut token =
            unsafe { from_raw_parts(buffers[0].pv_buffer as *const u8, buffers[0].cb_buffer as usize) }.to_vec();
        let mut data =
            unsafe { from_raw_parts(buffers[1].pv_buffer as *const u8, buffers[1].cb_buffer as usize) }.to_vec();
        let mut buffers = [
            SecBuffer {
                cb_buffer: token.len().try_into().unwrap(),
                buffer_type: 2, // Token
                pv_buffer: token.as_mut_ptr() as *mut _,
            },
            SecBuffer {
                cb_buffer: data.len().try_into().unwrap(),
                buffer_type: 1, // Data
                pv_buffer: data.as_mut_ptr() as *mut _,
            },
        ];
        let mut message = SecBufferDesc {
            ul_version: 0,
            c_buffers: 2,
            p_buffers: buffers.as_mut_ptr(),
        };

        let status = unsafe { super::DecryptMessage(&mut kerberos_client_context, &mut message, 0, null_mut()) };
        assert_eq!(status, 0);

        let status = unsafe { super::DeleteSecurityContext(&mut kerberos_client_context) };
        assert_eq!(status, 0);

        // Check that the decrypted data is the same as the initial message
        assert_eq!(
            unsafe { from_raw_parts(buffers[1].pv_buffer as *const u8, buffers[1].cb_buffer as usize,) },
            plain_message
        );
    }
}
