use std::slice::{from_raw_parts, from_raw_parts_mut};

use ffi_types::winscard::{
    LpOpenCardNameA, LpOpenCardNameExA, LpOpenCardNameExW, LpOpenCardNameW, LpScardHandle, LpScardIoRequest,
    ScardContext, ScardHandle, ScardStatus,
};
use ffi_types::{LpByte, LpCByte, LpCStr, LpCVoid, LpCWStr, LpDword, LpStr, LpVoid, LpWStr};
use symbol_rename_macro::rename_symbol;
use winscard::winscard::WinScard;
use winscard::ErrorKind;

use crate::winscard::scard_handle::{
    copy_io_request_to_scard_io_request, scard_handle_to_winscard, scard_io_request_to_io_request,
};

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardConnectA"))]
#[no_mangle]
pub extern "system" fn SCardConnectA(
    _context: ScardContext,
    _sz_reader: LpCStr,
    _dw_share_mode: u32,
    _dw_preferred_protocols: u32,
    _ph_card: LpScardHandle,
    _pdw_active_protocol: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardConnectW"))]
#[no_mangle]
pub extern "system" fn SCardConnectW(
    _context: ScardContext,
    _sz_reader: LpCWStr,
    _dw_share_mode: u32,
    _dw_preferred_protocols: u32,
    _ph_card: LpScardHandle,
    _pdw_active_protocol: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardReconnect"))]
#[no_mangle]
pub extern "system" fn SCardReconnect(
    _handle: ScardHandle,
    _dw_share_mode: u32,
    _dw_preferred_protocols: u32,
    _dw_initialization: u32,
    _pdw_active_protocol: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardDisconnect"))]
#[no_mangle]
pub extern "system" fn SCardDisconnect(_handle: ScardHandle, _dw_disposition: u32) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardBeginTransaction"))]
#[no_mangle]
pub unsafe extern "system" fn SCardBeginTransaction(handle: ScardHandle) -> ScardStatus {
    check_handle!(handle);
    let scard = &mut *scard_handle_to_winscard(handle);

    try_execute!(scard.begin_transaction());

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardEndTransaction"))]
#[no_mangle]
pub unsafe extern "system" fn SCardEndTransaction(handle: ScardHandle, _dw_disposition: u32) -> ScardStatus {
    check_handle!(handle);
    let scard = &mut *scard_handle_to_winscard(handle);

    try_execute!(scard.end_transaction());

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardCancelTransaction"))]
#[no_mangle]
pub extern "system" fn SCardCancelTransaction(_handle: ScardHandle) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardState"))]
#[no_mangle]
pub extern "system" fn SCardState(
    _handle: ScardHandle,
    _pdw_state: LpDword,
    _pdw_protocol: LpDword,
    _pb_atr: LpByte,
    _pcb_atr_len: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardStatusA"))]
#[no_mangle]
pub extern "system" fn SCardStatusA(
    _handle: ScardHandle,
    _msz_reader_names: LpStr,
    _pcch_reader_len: LpDword,
    _pdw_state: LpDword,
    _pdw_protocol: LpDword,
    _pb_atr: LpByte,
    _pcb_atr_len: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardStatusW"))]
#[no_mangle]
pub extern "system" fn SCardStatusW(
    _handle: ScardHandle,
    _msz_reader_names: LpWStr,
    _pcch_reader_len: LpDword,
    _pdw_state: LpDword,
    _pdw_protocol: LpDword,
    _pb_atr: LpByte,
    _pcb_atr_len: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardTransmit"))]
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
    let scard = &mut *scard_handle_to_winscard(handle);

    let io_request = scard_io_request_to_io_request(pio_send_pci);
    let input_apdu = from_raw_parts(pb_send_buffer, cb_send_length.try_into().unwrap());
    let out_data = try_execute!(scard.transmit(io_request, input_apdu));

    let out_apdu_len = out_data.output_apdu.len();

    if out_apdu_len > (*pcb_recv_length).try_into().unwrap() || pb_recv_buffer.is_null() {
        return ErrorKind::InsufficientBuffer.into();
    }

    let recv_buffer = from_raw_parts_mut(pb_recv_buffer, out_apdu_len);
    recv_buffer.copy_from_slice(&out_data.output_apdu);

    if !pio_recv_pci.is_null() && out_data.receive_pci.is_some() {
        try_execute!(copy_io_request_to_scard_io_request(
            out_data.receive_pci.as_ref().unwrap(),
            pio_recv_pci
        ));
    }

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetTransmitCount"))]
#[no_mangle]
pub extern "system" fn SCardGetTransmitCount(_handle: ScardHandle, pc_transmit_count: LpDword) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardControl"))]
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
    let scard = &mut *scard_handle_to_winscard(handle);

    let in_buffer = from_raw_parts(lp_in_buffer as *const u8, cb_in_buffer_size.try_into().unwrap());
    let out_buffer = try_execute!(scard.control(try_execute!(dw_control_code.try_into()), in_buffer));
    let out_buffer_len = out_buffer.len().try_into().unwrap();

    if out_buffer_len > cb_out_buffer_size {
        return ErrorKind::InsufficientBuffer.into();
    }

    let lp_out_buffer = from_raw_parts_mut(lp_out_buffer as *mut u8, out_buffer.len());
    lp_out_buffer.copy_from_slice(&out_buffer);
    *lp_bytes_returned = out_buffer_len;

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetAttrib"))]
#[no_mangle]
pub extern "system" fn SCardGetAttrib(
    _handle: ScardHandle,
    _dw_attr_id: u32,
    _pb_attr: LpByte,
    _pcb_attrLen: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardSetAttrib"))]
#[no_mangle]
pub extern "system" fn SCardSetAttrib(
    _handle: ScardHandle,
    _dw_attr_id: u32,
    _pb_attr: LpCByte,
    _cb_attrLen: u32,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardUIDlgSelectCardA"))]
#[no_mangle]
pub extern "system" fn SCardUIDlgSelectCardA(_p: LpOpenCardNameExA) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardUIDlgSelectCardW"))]
#[no_mangle]
pub extern "system" fn SCardUIDlgSelectCardW(_p: LpOpenCardNameExW) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_GetOpenCardNameA"))]
#[no_mangle]
pub extern "system" fn GetOpenCardNameA(_p: LpOpenCardNameA) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_GetOpenCardNameW"))]
#[no_mangle]
pub extern "system" fn GetOpenCardNameW(_p: LpOpenCardNameW) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardDlgExtendedError"))]
#[no_mangle]
pub extern "system" fn SCardDlgExtendedError() -> i32 {
    todo!()
}
