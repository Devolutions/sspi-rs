use std::ffi::CStr;
use std::slice::{from_raw_parts, from_raw_parts_mut};

use ffi_types::winscard::{
    LpOpenCardNameA, LpOpenCardNameExA, LpOpenCardNameExW, LpOpenCardNameW, LpScardHandle, LpScardIoRequest,
    ScardContext, ScardHandle, ScardStatus,
};
use ffi_types::{LpByte, LpCByte, LpCStr, LpCVoid, LpCWStr, LpDword, LpStr, LpVoid, LpWStr};
#[cfg(target_os = "windows")]
use symbol_rename_macro::rename_symbol;
use winscard::winscard::Protocol;
use winscard::{ErrorKind, WinScardResult};

use super::buf_alloc::{copy_buff, write_multistring_a, write_multistring_w};
use crate::utils::{c_w_str_to_string, into_raw_ptr};
use crate::winscard::scard_handle::{
    copy_io_request_to_scard_io_request, scard_context_to_winscard_context, scard_handle_to_winscard,
    scard_io_request_to_io_request, WinScardContextHandle, WinScardHandle,
};

unsafe fn connect(
    context: ScardContext,
    reader_name: &str,
    dw_share_mode: u32,
    dw_preferred_protocols: u32,
    ph_card: LpScardHandle,
    pdw_active_protocol: LpDword,
) -> WinScardResult<()> {
    let share_mode = dw_share_mode.try_into()?;
    let protocol = Protocol::from_bits(dw_preferred_protocols);

    let scard_context = unsafe { scard_context_to_winscard_context(context)? };
    let scard = scard_context.connect(reader_name, share_mode, protocol)?;
    let protocol = scard.handle.status()?.protocol.bits();

    let scard = WinScardHandle::new(scard.handle, context);

    let raw_card_handle = into_raw_ptr(scard) as ScardHandle;

    let context = unsafe { (context as *mut WinScardContextHandle).as_mut() }.unwrap();
    context.add_scard(raw_card_handle)?;

    unsafe {
        *ph_card = raw_card_handle;
        *pdw_active_protocol = protocol;
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
        unsafe { CStr::from_ptr(sz_reader as *const i8) }.to_str(),
        ErrorKind::InvalidParameter
    );

    try_execute!(unsafe {
        connect(
            context,
            reader_name,
            dw_share_mode,
            dw_preferred_protocols,
            ph_card,
            pdw_active_protocol,
        )
    });

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

    let reader_name = unsafe { c_w_str_to_string(sz_reader) };

    try_execute!(unsafe {
        connect(
            context,
            &reader_name,
            dw_share_mode,
            dw_preferred_protocols,
            ph_card,
            pdw_active_protocol,
        )
    });

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardReconnect"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardReconnect(
    _handle: ScardHandle,
    _dw_share_mode: u32,
    _dw_preferred_protocols: u32,
    _dw_initialization: u32,
    _pdw_active_protocol: LpDword,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardDisconnect"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardDisconnect(handle: ScardHandle, _dw_disposition: u32) -> ScardStatus {
    check_handle!(handle);

    let scard = unsafe { Box::from_raw(handle as *mut WinScardHandle) };
    if let Some(context) = unsafe { (scard.context() as *mut WinScardContextHandle).as_mut() } {
        if context.remove_scard(handle) {
            info!(?handle, "Successfully disconnected!");
        } else {
            warn!("ScardHandle does not belong to the specified context.")
        }
    }

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardBeginTransaction"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardBeginTransaction(handle: ScardHandle) -> ScardStatus {
    check_handle!(handle);
    let scard = try_execute!(unsafe { scard_handle_to_winscard(handle) });

    try_execute!(scard.begin_transaction());

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardEndTransaction"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardEndTransaction(handle: ScardHandle, dw_disposition: u32) -> ScardStatus {
    check_handle!(handle);
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

    let scard = unsafe { (handle as *mut WinScardHandle).as_ref().unwrap() };
    let status = try_execute!(scard.scard().status());
    check_handle!(scard.context());

    let readers = status.readers.iter().map(|reader| reader.as_ref()).collect::<Vec<_>>();
    let context = unsafe { (scard.context() as *mut WinScardContextHandle).as_mut() }.unwrap();
    try_execute!(unsafe { write_multistring_a(context, &readers, msz_reader_names, pcch_reader_len) });
    unsafe {
        *pdw_state = status.state.into();
        *pdw_protocol = status.protocol.bits();
    }

    if !pb_atr.is_null() {
        try_execute!(unsafe { copy_buff(context, pb_atr, pcb_atr_len, status.atr.as_ref()) });
    }

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

    let scard = unsafe { (handle as *mut WinScardHandle).as_ref() }.unwrap();
    let status = try_execute!(scard.scard().status());
    check_handle!(scard.context());

    let readers = status.readers.iter().map(|reader| reader.as_ref()).collect::<Vec<_>>();
    let context = unsafe { (scard.context() as *mut WinScardContextHandle).as_mut() }.unwrap();
    try_execute!(unsafe { write_multistring_w(context, &readers, msz_reader_names, pcch_reader_len) });
    unsafe {
        *pdw_state = status.state.into();
        *pdw_protocol = status.protocol.bits();
    }

    if !pb_atr.is_null() {
        try_execute!(unsafe { copy_buff(context, pb_atr, pcb_atr_len, status.atr.as_ref()) });
    }

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
    let scard = try_execute!(unsafe { scard_handle_to_winscard(handle) });

    let io_request = try_execute!(unsafe { scard_io_request_to_io_request(pio_send_pci) });
    let input_apdu = unsafe {
        from_raw_parts(
            pb_send_buffer,
            try_execute!(cb_send_length.try_into(), ErrorKind::InsufficientBuffer),
        )
    };

    let out_data = try_execute!(scard.transmit(io_request, input_apdu));

    let out_apdu_len = out_data.output_apdu.len();
    if out_apdu_len > try_execute!(unsafe { *pcb_recv_length }.try_into(), ErrorKind::InsufficientBuffer)
        || pb_recv_buffer.is_null()
    {
        return ErrorKind::InsufficientBuffer.into();
    }

    let recv_buffer = unsafe { from_raw_parts_mut(pb_recv_buffer, out_apdu_len) };
    recv_buffer.copy_from_slice(&out_data.output_apdu);

    if !pio_recv_pci.is_null() && out_data.receive_pci.is_some() {
        try_execute!(unsafe {
            copy_io_request_to_scard_io_request(out_data.receive_pci.as_ref().unwrap(), pio_recv_pci)
        });
    }

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
    let scard = try_execute!(unsafe { scard_handle_to_winscard(handle) });

    let in_buffer = if !lp_in_buffer.is_null() {
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
        let lp_out_buffer = unsafe {
            from_raw_parts_mut(
                lp_out_buffer as *mut u8,
                try_execute!(cb_out_buffer_size.try_into(), ErrorKind::InvalidParameter),
            )
        };

        let out_bytes_count = try_execute!(scard.control_with_output(dw_control_code, in_buffer, lp_out_buffer));
        if !lp_bytes_returned.is_null() {
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
pub extern "system" fn SCardGetAttrib(
    _handle: ScardHandle,
    _dw_attr_id: u32,
    _pb_attr: LpByte,
    _pcb_attrLen: LpDword,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
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
