use std::ffi::CStr;
use std::slice::{from_raw_parts, from_raw_parts_mut};

use ffi_types::winscard::{
    LpOpenCardNameA, LpOpenCardNameExA, LpOpenCardNameExW, LpOpenCardNameW, LpScardHandle, LpScardIoRequest,
    ScardContext, ScardHandle, ScardStatus,
};
use ffi_types::{LpByte, LpCByte, LpCStr, LpCVoid, LpCWStr, LpDword, LpStr, LpVoid, LpWStr};
use num_traits::FromPrimitive;
#[cfg(target_os = "windows")]
use symbol_rename_macro::rename_symbol;
use winscard::winscard::{AttributeId, Protocol, ScardConnectData, ShareMode};
use winscard::{Error, ErrorKind, WinScardResult};

use super::buf_alloc::{build_buf_request_type, build_buf_request_type_wide, save_out_buf, save_out_buf_wide};
use crate::utils::{c_w_str_to_string, into_raw_ptr};
use crate::winscard::scard_handle::{
    copy_io_request_to_scard_io_request, raw_scard_handle_to_scard_handle, scard_context_to_winscard_context,
    scard_handle_to_winscard, scard_io_request_to_io_request, WinScardContextHandle, WinScardHandle,
};

unsafe fn connect(
    context: ScardContext,
    reader_name: &str,
    dw_share_mode: u32,
    dw_preferred_protocols: u32,
    ph_card: LpScardHandle,
    pdw_active_protocol: LpDword,
) -> WinScardResult<()> {
    if ph_card.is_null() {
        return Err(Error::new(ErrorKind::InvalidParameter, "ph_card cannot be null"));
    }
    if pdw_active_protocol.is_null() {
        return Err(Error::new(
            ErrorKind::InvalidParameter,
            "pdw_active_protocol cannot be null",
        ));
    }

    let share_mode = dw_share_mode.try_into()?;
    let protocol = Protocol::from_bits(dw_preferred_protocols);

    // SAFETY: The user should provide a valid context handle. If it's equal to zero, then
    // the `scard_context_to_winscard_context` will return an error.
    let scard_context = unsafe { scard_context_to_winscard_context(context)? };
    let ScardConnectData { handle, protocol } = scard_context.connect(reader_name, share_mode, protocol)?;

    let scard = WinScardHandle::new(handle, context);

    let raw_card_handle = into_raw_ptr(scard) as ScardHandle;

    // SAFETY: The user should provide a valid context handle. The `context` can't be a zero, because
    // the `scard_context_to_winscard_context` function didn't return an error.
    let context = unsafe { (context as *mut WinScardContextHandle).as_mut() }.unwrap();
    context.add_scard(raw_card_handle)?;

    // SAFETY: We've checked for null above.
    unsafe {
        *ph_card = raw_card_handle;
        *pdw_active_protocol = protocol.bits();
    }

    Ok(())
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardConnectA"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardConnectA(
    context: ScardContext,
    sz_reader: LpCStr,
    dw_share_mode: u32,
    dw_preferred_protocols: u32,
    ph_card: LpScardHandle,
    pdw_active_protocol: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(sz_reader);
    check_null!(ph_card);
    check_null!(pdw_active_protocol);

    let reader_name = try_execute!(
        // SAFETY: The `sz_reader` parameter is not null (checked above).
        unsafe { CStr::from_ptr(sz_reader as *const i8) }.to_str(),
        ErrorKind::InvalidParameter
    );

    try_execute!(
        // SAFETY: All parameters are validated and/or type checked.
        unsafe {
            connect(
                context,
                reader_name,
                dw_share_mode,
                dw_preferred_protocols,
                ph_card,
                pdw_active_protocol,
            )
        }
    );

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardConnectW"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardConnectW(
    context: ScardContext,
    sz_reader: LpCWStr,
    dw_share_mode: u32,
    dw_preferred_protocols: u32,
    ph_card: LpScardHandle,
    pdw_active_protocol: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(sz_reader);
    check_null!(ph_card);
    check_null!(pdw_active_protocol);

    // SAFETY: The `sz_reader` parameter is not null (checked above).
    let reader_name = unsafe { c_w_str_to_string(sz_reader) };

    try_execute!(
        // SAFETY: All parameters are validated and/or type checked.
        unsafe {
            connect(
                context,
                &reader_name,
                dw_share_mode,
                dw_preferred_protocols,
                ph_card,
                pdw_active_protocol,
            )
        }
    );

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardReconnect"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardReconnect(
    handle: ScardHandle,
    dw_share_mode: u32,
    dw_preferred_protocols: u32,
    dw_initialization: u32,
    pdw_active_protocol: LpDword,
) -> ScardStatus {
    check_handle!(handle);
    check_null!(pdw_active_protocol);

    let share_mode = try_execute!(ShareMode::try_from(dw_share_mode));
    let protocol = Protocol::from_bits(dw_preferred_protocols);
    let initialization = try_execute!(dw_initialization.try_into(), ErrorKind::InvalidParameter);

    let scard = try_execute!(
        // SAFETY: The `handle` is not equal to zero (checked above).
        unsafe { scard_handle_to_winscard(handle) }
    );
    let active_protocol = try_execute!(scard.reconnect(share_mode, protocol, initialization));

    // SAFETY: `pdw_active_protocol` is checked above, so it is guaranteed not NULL.
    unsafe {
        *pdw_active_protocol = active_protocol.bits();
    }

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardDisconnect"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardDisconnect(handle: ScardHandle, dw_disposition: u32) -> ScardStatus {
    check_handle!(handle);

    // SAFETY: The `handle` is not equal to zero (checked above).
    let mut scard = unsafe { Box::from_raw(handle as *mut WinScardHandle) };
    try_execute!(scard
        .scard_mut()
        .disconnect(try_execute!(dw_disposition.try_into(), ErrorKind::InvalidParameter)));

    if let Some(context) = scard.context() {
        if context.remove_scard(handle) {
            info!(?handle, "Successfully disconnected");
        } else {
            warn!("ScardHandle does not belong to the specified context")
        }
    }

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardBeginTransaction"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardBeginTransaction(handle: ScardHandle) -> ScardStatus {
    check_handle!(handle);

    // SAFETY: The `handle` is not equal to zero (checked above).
    let scard = try_execute!(unsafe { scard_handle_to_winscard(handle) });

    try_execute!(scard.begin_transaction());

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardEndTransaction"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardEndTransaction(handle: ScardHandle, dw_disposition: u32) -> ScardStatus {
    check_handle!(handle);

    // SAFETY: The `handle` is not equal to zero (checked above).
    let scard = try_execute!(unsafe { scard_handle_to_winscard(handle) });

    try_execute!(scard.end_transaction(try_execute!(dw_disposition.try_into())));

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardCancelTransaction"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardCancelTransaction(_handle: ScardHandle) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardState"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardState(
    _handle: ScardHandle,
    _pdw_state: LpDword,
    _pdw_protocol: LpDword,
    _pb_atr: LpByte,
    _pcb_atr_len: LpDword,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardStatusA"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardStatusA(
    handle: ScardHandle,
    msz_reader_names: LpStr,
    pcch_reader_len: LpDword,
    pdw_state: LpDword,
    pdw_protocol: LpDword,
    pb_atr: LpByte,
    pcb_atr_len: LpDword,
) -> ScardStatus {
    check_handle!(handle);
    check_null!(msz_reader_names);
    check_null!(pcch_reader_len);
    check_null!(pdw_state);
    check_null!(pdw_protocol);
    // pb_atr can be null.
    // it's not specified in a docs, but `msclmd.dll` can invoke this function with pb_atr = 0.
    check_null!(pcb_atr_len);

    // SAFETY: The `handle` is not null. All other guarantees should be provided by the user.
    let scard = try_execute!(unsafe { raw_scard_handle_to_scard_handle(handle) });
    // SAFETY: The `msz_reader_names` and `pcch_reader_len` parameters are not null (cheked above).
    let readers_buf_type = try_execute!(unsafe { build_buf_request_type(msz_reader_names, pcch_reader_len) });
    // SAFETY: It's safe to call this function because the `pb_atr` parameter is allowed to be null
    // and the `pcb_atr_len` parameter cannot be null (checked above).
    let atr_buf_type = try_execute!(unsafe { build_buf_request_type(pb_atr, pcb_atr_len) });

    let status = try_execute!(scard.status(readers_buf_type, atr_buf_type));

    // SAFETY: It's safe to deref because `pdw_state` and `pdw_protocol` parameters are not null (checked above).
    unsafe {
        *pdw_state = status.state.into();
        *pdw_protocol = status.protocol.bits();
    }

    // SAFETY: The `msz_reader_names` and `pcch_reader_len` parameters are not null (cheked above).
    try_execute!(unsafe { save_out_buf(status.readers, msz_reader_names, pcch_reader_len) });

    // SAFETY: `pb_atr` can be null. `pcb_atr_len` can not be null and checked above.
    try_execute!(unsafe { save_out_buf(status.atr, pb_atr, pcb_atr_len) });

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardStatusW"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardStatusW(
    handle: ScardHandle,
    msz_reader_names: LpWStr,
    pcch_reader_len: LpDword,
    pdw_state: LpDword,
    pdw_protocol: LpDword,
    pb_atr: LpByte,
    pcb_atr_len: LpDword,
) -> ScardStatus {
    check_handle!(handle);
    check_null!(msz_reader_names);
    check_null!(pcch_reader_len);
    check_null!(pdw_state);
    check_null!(pdw_protocol);
    // pb_atr can be null.
    // it's not specified in a docs, but `msclmd.dll` can invoke this function with pb_atr = 0.
    check_null!(pcb_atr_len);

    // SAFETY: The `handle` is not null. All other guarantees should be provided by the user.
    let scard = try_execute!(unsafe { raw_scard_handle_to_scard_handle(handle) });
    // SAFETY: The `msz_reader_names` and `pcch_reader_len` parameters are not null (cheked above).
    let readers_buf_type = try_execute!(unsafe { build_buf_request_type_wide(msz_reader_names, pcch_reader_len) });
    // SAFETY: It's safe to call this function because the `pb_atr` parameter is allowed to be null
    // and the `pcb_atr_len` parameter cannot be null (checked above).
    let atr_buf_type = try_execute!(unsafe { build_buf_request_type(pb_atr, pcb_atr_len) });

    let status = try_execute!(scard.status_wide(readers_buf_type, atr_buf_type));

    // SAFETY: It's safe to deref because `pdw_state` and `pdw_protocol` parameters are not null (checked above).
    unsafe {
        *pdw_state = status.state.into();
        *pdw_protocol = status.protocol.bits();
    }

    // SAFETY: The `msz_reader_names` and `pcch_reader_len` parameters are not null (cheked above).
    try_execute!(unsafe { save_out_buf_wide(status.readers, msz_reader_names, pcch_reader_len) });

    // SAFETY: `pb_atr` can be null. `pcb_atr_len` can not be null and checked above.
    try_execute!(unsafe { save_out_buf(status.atr, pb_atr, pcb_atr_len) });

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardTransmit"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardTransmit(
    handle: ScardHandle,
    pio_send_pci: LpScardIoRequest,
    pb_send_buffer: LpCByte,
    cb_send_length: u32,
    pio_recv_pci: LpScardIoRequest,
    pb_recv_buffer: LpByte,
    pcb_recv_length: LpDword,
) -> ScardStatus {
    check_handle!(handle);
    check_null!(pio_send_pci);
    check_null!(pb_send_buffer);
    check_null!(pcb_recv_length);

    // SAFETY: The `handle` is not null. All other guarantees should be provided by the user.
    let scard = try_execute!(unsafe { scard_handle_to_winscard(handle) });

    // SAFETY: The `pio_send_pci` parameter cannot be null (checked above).
    let io_request = try_execute!(unsafe { scard_io_request_to_io_request(pio_send_pci) });
    // SAFETY: The `pb_send_buffer` parameter cannot be null (checked above).
    let input_apdu = unsafe {
        from_raw_parts(
            pb_send_buffer,
            try_execute!(cb_send_length.try_into(), ErrorKind::InsufficientBuffer),
        )
    };

    let out_data = try_execute!(scard.transmit(io_request, input_apdu));

    let out_apdu_len = out_data.output_apdu.len();
    if out_apdu_len
        > try_execute!(
            // SAFETY: The `pcb_recv_length` parameter cannot be null (checked above). So, it's safe to deref.
            unsafe { *pcb_recv_length }.try_into(),
            ErrorKind::InsufficientBuffer
        )
        || pb_recv_buffer.is_null()
    {
        return ErrorKind::InsufficientBuffer.into();
    }

    // SAFETY: The `pb_recv_buffer` parameter cannot be null (checked above).
    let recv_buffer = unsafe { from_raw_parts_mut(pb_recv_buffer, out_apdu_len) };
    recv_buffer.copy_from_slice(&out_data.output_apdu);

    if !pio_recv_pci.is_null() && out_data.receive_pci.is_some() {
        try_execute!(
            // SAFETY: The `pio_recv_pci` parameter cannot be null (checked above).
            unsafe {
                copy_io_request_to_scard_io_request(
                    out_data
                        .receive_pci
                        .as_ref()
                        .expect("Should not panic: the receive_pci value is checked above"),
                    pio_recv_pci,
                )
            }
        );
    }

    // SAFETY: The `pcb_recv_length` parameter cannot be null (checked above).
    unsafe {
        *pcb_recv_length = try_execute!(out_apdu_len.try_into(), ErrorKind::InsufficientBuffer);
    }

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetTransmitCount"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardGetTransmitCount(_handle: ScardHandle, pc_transmit_count: LpDword) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardControl"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardControl(
    handle: ScardHandle,
    dw_control_code: u32,
    lp_in_buffer: LpCVoid,
    cb_in_buffer_size: u32,
    lp_out_buffer: LpVoid,
    cb_out_buffer_size: u32,
    lp_bytes_returned: LpDword,
) -> ScardStatus {
    check_handle!(handle);

    let scard = try_execute!(
        // SAFETY: The `handle` is not equal to zero (checked above).
        unsafe { scard_handle_to_winscard(handle) }
    );

    let in_buffer = if !lp_in_buffer.is_null() {
        // SAFETY: The `lp_in_buffer` parameter cannot be null (checked above).
        unsafe {
            from_raw_parts(
                lp_in_buffer as *const u8,
                try_execute!(cb_in_buffer_size.try_into(), ErrorKind::InsufficientBuffer),
            )
        }
    } else {
        &[]
    };

    if !lp_out_buffer.is_null() {
        // SAFETY: The `lp_out_buffer` parameter cannot be null (checked above).
        let lp_out_buffer = unsafe {
            from_raw_parts_mut(
                lp_out_buffer as *mut u8,
                try_execute!(cb_out_buffer_size.try_into(), ErrorKind::InvalidParameter),
            )
        };

        let out_bytes_count = try_execute!(scard.control_with_output(dw_control_code, in_buffer, lp_out_buffer));
        if !lp_bytes_returned.is_null() {
            // SAFETY: The `lp_bytes_returned` parameter cannot be null (checked above).
            unsafe {
                *lp_bytes_returned = try_execute!(out_bytes_count.try_into(), ErrorKind::InternalError);
            }
        }
    } else {
        try_execute!(scard.control(dw_control_code, in_buffer));
    }

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetAttrib"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardGetAttrib(
    handle: ScardHandle,
    dw_attr_id: u32,
    pb_attr: LpByte,
    pcb_attr_len: LpDword,
) -> ScardStatus {
    check_handle!(handle);
    check_null!(pcb_attr_len);

    let attr_id = try_execute!(AttributeId::from_u32(dw_attr_id).ok_or_else(|| Error::new(
        ErrorKind::InvalidParameter,
        format!("invalid attribute id: {}", dw_attr_id)
    )));

    // SAFETY: The `handle` is not null. All other guarantees should be provided by the user.
    let scard = try_execute!(unsafe { raw_scard_handle_to_scard_handle(handle) });
    // SAFETY: It's safe to call this function because the `pb_atr` parameter is allowed to be null
    // and the `pcb_atr_len` parameter cannot be null (checked above).
    let buffer_type = try_execute!(unsafe { build_buf_request_type(pb_attr, pcb_attr_len) });

    let out_buf = try_execute!(scard.get_attribute(attr_id, buffer_type));

    // SAFETY: It's safe to call this function because the `pb_atr` parameter is allowed to be null
    // and the `pcb_atr_len` parameter cannot be null (checked above).
    try_execute!(unsafe { save_out_buf(out_buf, pb_attr, pcb_attr_len) });

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardSetAttrib"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardSetAttrib(
    _handle: ScardHandle,
    _dw_attr_id: u32,
    _pb_attr: LpCByte,
    _cb_attrLen: u32,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardUIDlgSelectCardA"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardUIDlgSelectCardA(_p: LpOpenCardNameExA) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardUIDlgSelectCardW"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardUIDlgSelectCardW(_p: LpOpenCardNameExW) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_GetOpenCardNameA"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn GetOpenCardNameA(_p: LpOpenCardNameA) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_GetOpenCardNameW"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn GetOpenCardNameW(_p: LpOpenCardNameW) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}
