use std::slice::from_raw_parts;

use libc::{c_ulong, c_ulonglong, c_void};
use num_traits::cast::{FromPrimitive, ToPrimitive};
use sspi::credssp::SspiContext;
use sspi::{
    DataRepresentation, DecryptionFlags, EncryptionFlags, ErrorKind, SecurityBuffer, SecurityBufferType,
    ServerRequestFlags, Sspi,
};
#[cfg(windows)]
use symbol_rename_macro::rename_symbol;

use crate::credentials_attributes::CredentialsAttributes;
use crate::sec_buffer::{copy_to_c_sec_buffer, p_sec_buffers_to_security_buffers, PSecBuffer, PSecBufferDesc};
use crate::sec_handle::{p_ctxt_handle_to_sspi_context, CredentialsHandle, PCredHandle, PCtxtHandle};
use crate::sspi_data_types::{PTimeStamp, SecurityStatus};
use crate::utils::{into_raw_ptr, transform_credentials_handle};

#[cfg_attr(feature = "debug_mode", instrument(skip_all))]
#[cfg_attr(windows, rename_symbol(to = "Rust_FreeCredentialsHandle"))]
#[no_mangle]
pub unsafe extern "system" fn FreeCredentialsHandle(ph_credential: PCredHandle) -> SecurityStatus {
    check_null!(ph_credential);

    let cred_handle = (*ph_credential).dw_lower as *mut CredentialsHandle;
    check_null!(cred_handle);

    let _cred_handle = Box::from_raw(cred_handle);

    0
}

pub type FreeCredentialsHandleFn = unsafe extern "system" fn(PCredHandle) -> SecurityStatus;

#[cfg_attr(feature = "debug_mode", instrument(skip_all))]
#[allow(clippy::useless_conversion)]
#[cfg_attr(windows, rename_symbol(to = "Rust_AcceptSecurityContext"))]
#[no_mangle]
pub unsafe extern "system" fn AcceptSecurityContext(
    ph_credential: PCredHandle,
    mut ph_context: PCtxtHandle,
    p_input: PSecBufferDesc,
    f_context_req: c_ulong,
    target_data_rep: c_ulong,
    ph_new_context: PCtxtHandle,
    p_output: PSecBufferDesc,
    pf_context_attr: *mut c_ulong,
    _pts_expiry: PTimeStamp,
) -> SecurityStatus {
    catch_panic! {
        // ph_context can be null on the first call
        check_null!(ph_new_context);
        check_null!(ph_credential);
        check_null!(p_input);
        check_null!(p_output);
        check_null!(pf_context_attr);

        let credentials_handle = (*ph_credential).dw_lower as *mut CredentialsHandle;

        let (auth_data, security_package_name, attributes) = match transform_credentials_handle(credentials_handle) {
            Some(data) => data,
            None => return ErrorKind::InvalidHandle.to_u32().unwrap(),
        };

        let sspi_context_ptr = try_execute!(p_ctxt_handle_to_sspi_context(
            &mut ph_context,
            Some(security_package_name),
            attributes,
        ));

        let sspi_context = sspi_context_ptr
            .as_mut()
            .expect("security context pointer cannot be null");

        let mut input_tokens =
            p_sec_buffers_to_security_buffers(from_raw_parts((*p_input).p_buffers, (*p_input).c_buffers as usize));

        let mut output_tokens = vec![SecurityBuffer::new(Vec::with_capacity(1024), SecurityBufferType::Token)];

        let result_status = sspi_context
            .accept_security_context()
            .with_credentials_handle(&mut Some(auth_data))
            .with_context_requirements(ServerRequestFlags::from_bits(f_context_req.try_into().unwrap()).unwrap())
            .with_target_data_representation(DataRepresentation::from_u32(target_data_rep.try_into().unwrap()).unwrap())
            .with_input(&mut input_tokens)
            .with_output(&mut output_tokens)
            .execute();

        copy_to_c_sec_buffer((*p_output).p_buffers, &output_tokens, false);

        (*ph_new_context).dw_lower = sspi_context_ptr as c_ulonglong;
        (*ph_new_context).dw_upper = into_raw_ptr(security_package_name.to_owned()) as c_ulonglong;

        *pf_context_attr = f_context_req;

        let result = try_execute!(result_status);
        result.status.to_u32().unwrap()
    }
}

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
) -> SecurityStatus;

#[cfg_attr(feature = "debug_mode", instrument(skip_all))]
#[cfg_attr(windows, rename_symbol(to = "Rust_CompleteAuthToken"))]
#[no_mangle]
pub unsafe extern "system" fn CompleteAuthToken(
    mut ph_context: PCtxtHandle,
    p_token: PSecBufferDesc,
) -> SecurityStatus {
    catch_panic! {
        check_null!(ph_context);
        check_null!(p_token);

        let sspi_context = try_execute!(p_ctxt_handle_to_sspi_context(
            &mut ph_context,
            None,
            &CredentialsAttributes::default()
        ))
        .as_mut()
        .expect("security context pointer cannot be null");

        let raw_buffers = from_raw_parts((*p_token).p_buffers, (*p_token).c_buffers as usize);
        let mut buffers = p_sec_buffers_to_security_buffers(raw_buffers);

        sspi_context.complete_auth_token(&mut buffers).map_or_else(
            |err| err.error_type.to_u32().unwrap(),
            |result| result.to_u32().unwrap(),
        )
    }
}

pub type CompleteAuthTokenFn = unsafe extern "system" fn(PCtxtHandle, PSecBufferDesc) -> SecurityStatus;

#[cfg_attr(feature = "debug_mode", instrument(skip_all))]
#[cfg_attr(windows, rename_symbol(to = "Rust_DeleteSecurityContext"))]
#[no_mangle]
pub unsafe extern "system" fn DeleteSecurityContext(mut ph_context: PCtxtHandle) -> SecurityStatus {
    catch_panic!(
        check_null!(ph_context);

        let _context: Box<SspiContext> = Box::from_raw(try_execute!(p_ctxt_handle_to_sspi_context(
            &mut ph_context,
            None,
            &CredentialsAttributes::default()
        )));

        if (*ph_context).dw_upper != 0 {
            let _name: Box<String> = Box::from_raw((*ph_context).dw_upper as *mut String);
        }

        0
    )
}

pub type DeleteSecurityContextFn = unsafe extern "system" fn(PCtxtHandle) -> SecurityStatus;

#[cfg_attr(feature = "debug_mode", instrument(skip_all))]
#[cfg_attr(windows, rename_symbol(to = "Rust_ApplyControlToken"))]
#[no_mangle]
pub extern "system" fn ApplyControlToken(_ph_context: PCtxtHandle, _p_input: PSecBufferDesc) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type ApplyControlTokenFn = extern "system" fn(PCtxtHandle, PSecBufferDesc) -> SecurityStatus;

#[cfg_attr(feature = "debug_mode", instrument(skip_all))]
#[cfg_attr(windows, rename_symbol(to = "Rust_ImpersonateSecurityContext"))]
#[no_mangle]
pub extern "system" fn ImpersonateSecurityContext(_ph_context: PCtxtHandle) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type ImpersonateSecurityContextFn = extern "system" fn(PCtxtHandle) -> SecurityStatus;

#[cfg_attr(feature = "debug_mode", instrument(skip_all))]
#[cfg_attr(windows, rename_symbol(to = "Rust_RevertSecurityContext"))]
#[no_mangle]
pub extern "system" fn RevertSecurityContext(_ph_context: PCtxtHandle) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type RevertSecurityContextFn = extern "system" fn(PCtxtHandle) -> SecurityStatus;

#[cfg_attr(feature = "debug_mode", instrument(skip_all))]
#[cfg_attr(windows, rename_symbol(to = "Rust_MakeSignature"))]
#[no_mangle]
pub extern "system" fn MakeSignature(
    _ph_context: PCtxtHandle,
    _f_qop: c_ulong,
    _p_message: PSecBufferDesc,
    _message_seq_no: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type MakeSignatureFn = extern "system" fn(PCtxtHandle, c_ulong, PSecBufferDesc, c_ulong) -> SecurityStatus;

#[cfg_attr(feature = "debug_mode", instrument(skip_all))]
#[cfg_attr(windows, rename_symbol(to = "Rust_VerifySignature"))]
#[no_mangle]
pub extern "system" fn VerifySignature(
    _ph_context: PCtxtHandle,
    _message: PSecBufferDesc,
    _message_seq_no: c_ulong,
    _pf_qop: *mut c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type VerifySignatureFn = extern "system" fn(PCtxtHandle, PSecBufferDesc, c_ulong, *mut c_ulong) -> SecurityStatus;

#[cfg_attr(feature = "debug_mode", instrument(skip_all))]
#[cfg_attr(windows, rename_symbol(to = "Rust_FreeContextBuffer"))]
#[no_mangle]
pub unsafe extern "system" fn FreeContextBuffer(pv_context_buffer: *mut c_void) -> SecurityStatus {
    let _ = Box::from_raw(pv_context_buffer as *mut _);

    0
}

pub type FreeContextBufferFn = unsafe extern "system" fn(*mut c_void) -> SecurityStatus;

#[cfg_attr(feature = "debug_mode", instrument(skip_all))]
#[cfg_attr(windows, rename_symbol(to = "Rust_ExportSecurityContext"))]
#[no_mangle]
pub extern "system" fn ExportSecurityContext(
    _ph_context: PCtxtHandle,
    _f_flags: c_ulong,
    _p_packed_context: PSecBuffer,
    _p_token: *mut *mut c_void,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type ExportSecurityContextFn =
    extern "system" fn(PCtxtHandle, c_ulong, PSecBuffer, *mut *mut c_void) -> SecurityStatus;

#[cfg_attr(feature = "debug_mode", instrument(skip_all))]
#[cfg_attr(windows, rename_symbol(to = "Rust_QuerySecurityContextToken"))]
#[no_mangle]
pub extern "system" fn QuerySecurityContextToken(_ph_context: PCtxtHandle, _token: *mut *mut c_void) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type QuerySecurityContextTokenFn = extern "system" fn(PCtxtHandle, *mut *mut c_void) -> SecurityStatus;

#[allow(clippy::useless_conversion)]
#[cfg_attr(feature = "debug_mode", instrument(skip_all))]
#[cfg_attr(windows, rename_symbol(to = "Rust_EncryptMessage"))]
#[no_mangle]
pub unsafe extern "system" fn EncryptMessage(
    mut ph_context: PCtxtHandle,
    f_qop: c_ulong,
    p_message: PSecBufferDesc,
    message_seq_no: c_ulong,
) -> SecurityStatus {
    catch_panic! {
        check_null!(ph_context);
        check_null!(p_message);

        let sspi_context = try_execute!(p_ctxt_handle_to_sspi_context(
            &mut ph_context,
            None,
            &CredentialsAttributes::default()
        ))
        .as_mut()
        .expect("security context pointer cannot be null");

        let len = (*p_message).c_buffers as usize;
        let raw_buffers = from_raw_parts((*p_message).p_buffers, len);
        let mut message = p_sec_buffers_to_security_buffers(raw_buffers);

        let result_status = sspi_context.encrypt_message(
            EncryptionFlags::from_bits(f_qop.try_into().unwrap()).unwrap(),
            &mut message,
            message_seq_no.try_into().unwrap(),
        );

        copy_to_c_sec_buffer((*p_message).p_buffers, &message, false);

        let result = try_execute!(result_status);
        result.to_u32().unwrap()
    }
}

pub type EncryptMessageFn = unsafe extern "system" fn(PCtxtHandle, c_ulong, PSecBufferDesc, c_ulong) -> SecurityStatus;

#[allow(clippy::useless_conversion)]
#[cfg_attr(feature = "debug_mode", instrument(skip_all))]
#[cfg_attr(windows, rename_symbol(to = "Rust_DecryptMessage"))]
#[no_mangle]
pub unsafe extern "system" fn DecryptMessage(
    mut ph_context: PCtxtHandle,
    p_message: PSecBufferDesc,
    message_seq_no: c_ulong,
    pf_qop: *mut c_ulong,
) -> SecurityStatus {
    catch_panic! {
        check_null!(ph_context);
        check_null!(p_message);

        let sspi_context = try_execute!(p_ctxt_handle_to_sspi_context(
            &mut ph_context,
            None,
            &CredentialsAttributes::default()
        ))
        .as_mut()
        .expect("security context pointer cannot be null");

        let len = (*p_message).c_buffers as usize;
        let raw_buffers = from_raw_parts((*p_message).p_buffers, len);
        let mut message = p_sec_buffers_to_security_buffers(raw_buffers);

        let (decryption_flags, result_status) =
            match sspi_context.decrypt_message(&mut message, message_seq_no.try_into().unwrap()) {
                Ok(flags) => (flags, Ok(())),
                Err(error) => (DecryptionFlags::empty(), Err(error)),
            };

        copy_to_c_sec_buffer((*p_message).p_buffers, &message, false);
        // `pf_qop` can be null if this library is used as a CredSsp security package
        if !pf_qop.is_null() {
            *pf_qop = decryption_flags.bits().try_into().unwrap();
        }

        try_execute!(result_status);

        0
    }
}

pub type DecryptMessageFn =
    unsafe extern "system" fn(PCtxtHandle, PSecBufferDesc, c_ulong, *mut c_ulong) -> SecurityStatus;
