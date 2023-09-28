use ffi_types::winscard::{
    LpOpenCardNameA, LpOpenCardNameExA, LpOpenCardNameExW, LpOpenCardNameW, LpScardHandle, LpScardIoRequest,
    ScardContext, ScardHandle, ScardStatus,
};
use ffi_types::{LpByte, LpCByte, LpCStr, LpCVoid, LpCWStr, LpDword, LpStr, LpVoid, LpWStr};
use symbol_rename_macro::rename_symbol;
use winscard::ErrorKind;
use winscard::winscard::WinScard;
use crate::winscard::scard_handle::scard_handle_to_winscard;

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
pub extern "system" fn SCardTransmit(
    _handle: ScardHandle,
    _pio_send_pci: LpScardIoRequest,
    _pb_send_buffer: LpCByte,
    _cb_send_length: u32,
    _pio_recv_pci: LpScardIoRequest,
    _pb_recv_buffer: LpByte,
    _pcb_recv_length: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetTransmitCount"))]
#[no_mangle]
pub extern "system" fn SCardGetTransmitCount(_handle: ScardHandle, pc_transmit_count: LpDword) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardControl"))]
#[no_mangle]
pub extern "system" fn SCardControl(
    _handle: ScardHandle,
    _dw_control_code: u32,
    _lp_in_buffer: LpCVoid,
    _cb_in_buffer_size: u32,
    _lp_out_buffer: LpVoid,
    _cb_out_buffer_size: u32,
    _lp_bytes_returned: LpDword,
) -> ScardStatus {
    todo!()
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
