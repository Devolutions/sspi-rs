use std::ffi::CStr;
use std::slice::from_raw_parts_mut;

use ffi_types::winscard::{
    LpScardAtrMask, LpScardContext, LpScardReaderStateA, LpScardReaderStateW, ScardContext, ScardStatus,
};
use ffi_types::{Handle, LpByte, LpCByte, LpCGuid, LpCStr, LpCVoid, LpCWStr, LpDword, LpGuid, LpStr, LpUuid, LpWStr};
use libc::c_void;
use symbol_rename_macro::rename_symbol;
use winscard::winscard::WinScardContext;
use winscard::{Error, ErrorKind, WinScardResult};

use crate::utils::c_w_str_to_string;
use crate::winscard::scard_handle::scard_context_to_winscard_context;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardEstablishContext"))]
#[no_mangle]
pub extern "system" fn SCardEstablishContext(
    _dw_scope: u32,
    _r1: *const c_void,
    _r2: *const c_void,
    _context: LpScardContext,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardReleaseContext"))]
#[no_mangle]
pub extern "system" fn SCardReleaseContext(_context: ScardContext) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIsValidContext"))]
#[no_mangle]
pub unsafe extern "system" fn SCardIsValidContext(context: ScardContext) -> ScardStatus {
    if context == 0 {
        return ErrorKind::InvalidHandle.into();
    }

    let context = &mut *scard_context_to_winscard_context(context);
    if context.is_valid() {
        ErrorKind::Success
    } else {
        ErrorKind::InvalidHandle
    }
    .into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListReaderGroupsA"))]
#[no_mangle]
pub extern "system" fn SCardListReaderGroupsA(
    _context: ScardContext,
    _gmsz_groups: LpStr,
    _pcch_groups: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListReaderGroupsW"))]
#[no_mangle]
pub extern "system" fn SCardListReaderGroupsW(
    _context: ScardContext,
    _gmsz_groups: LpWStr,
    _pcch_groups: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListReadersA"))]
#[no_mangle]
pub extern "system" fn SCardListReadersA(
    _context: ScardContext,
    _msz_groups: LpCStr,
    _msz_readers: LpStr,
    _pcch_readers: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListReadersW"))]
#[no_mangle]
pub extern "system" fn SCardListReadersW(
    _context: ScardContext,
    _msz_groups: LpCWStr,
    _msz_readers: LpWStr,
    _pcch_readers: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListCardsA"))]
#[no_mangle]
pub extern "system" fn SCardListCardsA(
    _context: ScardContext,
    _pb_atr: LpCByte,
    _rgquid_nterfaces: LpCGuid,
    _cguid_interface_count: u32,
    _msz_cards: *mut u8,
    _pcch_cards: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListCardsW"))]
#[no_mangle]
pub extern "system" fn SCardListCardsW(
    _context: ScardContext,
    _pb_atr: LpCByte,
    _rgquid_nterfaces: LpCGuid,
    _cguid_interface_count: u32,
    _msz_cards: *mut u16,
    _pcch_cards: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListInterfacesA"))]
#[no_mangle]
pub extern "system" fn SCardListInterfacesA(
    _context: ScardContext,
    _sz_scard: LpCStr,
    _pguid_interfaces: LpGuid,
    _pcguid_interfaces: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListInterfacesW"))]
#[no_mangle]
pub extern "system" fn SCardListInterfacesW(
    _context: ScardContext,
    _sz_scard: LpCWStr,
    _pguid_interfaces: LpGuid,
    _pcguid_interfaces: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetProviderIdA"))]
#[no_mangle]
pub extern "system" fn SCardGetProviderIdA(
    _context: ScardContext,
    _sz_card: LpCStr,
    _pguid_provider_id: LpGuid,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetProviderIdW"))]
#[no_mangle]
pub extern "system" fn SCardGetProviderIdW(
    _context: ScardContext,
    _sz_card: LpCWStr,
    _pguid_provider_id: LpGuid,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetCardTypeProviderNameA"))]
#[no_mangle]
pub extern "system" fn SCardGetCardTypeProviderNameA(
    _context: ScardContext,
    _sz_card_name: LpCStr,
    _dw_provide_id: u32,
    _szProvider: *mut u8,
    _pcch_provider: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetCardTypeProviderNameW"))]
#[no_mangle]
pub extern "system" fn SCardGetCardTypeProviderNameW(
    _context: ScardContext,
    _sz_card_name: LpCWStr,
    _dw_provide_id: u32,
    _szProvider: *mut u16,
    _pcch_provider: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceReaderGroupA"))]
#[no_mangle]
pub extern "system" fn SCardIntroduceReaderGroupA(_context: ScardContext, _sz_group_name: LpCStr) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceReaderGroupW"))]
#[no_mangle]
pub extern "system" fn SCardIntroduceReaderGroupW(_context: ScardContext, _sz_group_name: LpCWStr) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetReaderGroupA"))]
#[no_mangle]
pub extern "system" fn SCardForgetReaderGroupA(_context: ScardContext, _sz_group_name: LpCStr) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetReaderGroupW"))]
#[no_mangle]
pub extern "system" fn SCardForgetReaderGroupW(_context: ScardContext, _sz_group_name: LpCWStr) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceReaderA"))]
#[no_mangle]
pub extern "system" fn SCardIntroduceReaderA(
    _context: ScardContext,
    _sz_reader_name: LpCStr,
    _sz_device_name: LpCStr,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceReaderW"))]
#[no_mangle]
pub extern "system" fn SCardIntroduceReaderW(
    _context: ScardContext,
    _sz_reader_name: LpCWStr,
    _sz_device_name: LpCWStr,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetReaderA"))]
#[no_mangle]
pub extern "system" fn SCardForgetReaderA(_context: ScardContext, _sz_reader_name: LpCStr) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetReaderW"))]
#[no_mangle]
pub extern "system" fn SCardForgetReaderW(_context: ScardContext, _sz_reader_name: LpCWStr) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardAddReaderToGroupA"))]
#[no_mangle]
pub extern "system" fn SCardAddReaderToGroupA(
    _context: ScardContext,
    _sz_reader_name: LpCStr,
    _sz_group_name: LpCStr,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardAddReaderToGroupW"))]
#[no_mangle]
pub extern "system" fn SCardAddReaderToGroupW(
    _context: ScardContext,
    _sz_reader_name: LpCWStr,
    _sz_group_name: LpCWStr,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardRemoveReaderFromGroupA"))]
#[no_mangle]
pub extern "system" fn SCardRemoveReaderFromGroupA(
    _context: ScardContext,
    _sz_reader_name: LpCStr,
    _sz_group_name: LpCStr,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardRemoveReaderFromGroupW"))]
#[no_mangle]
pub extern "system" fn SCardRemoveReaderFromGroupW(
    _context: ScardContext,
    _sz_reader_name: LpCWStr,
    _sz_group_name: LpCWStr,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceCardTypeA"))]
#[no_mangle]
pub extern "system" fn SCardIntroduceCardTypeA(
    _context: ScardContext,
    _sz_card_name: LpCStr,
    _pguid_primary_provider: LpCGuid,
    _rgguid_interfaces: LpCGuid,
    _dw_interface_count: u32,
    _pb_atr: LpCByte,
    _pb_atr_mask: LpCByte,
    _cb_atr_len: u32,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceCardTypeW"))]
#[no_mangle]
pub extern "system" fn SCardIntroduceCardTypeW(
    _context: ScardContext,
    _sz_card_name: LpCWStr,
    _pguid_primary_provider: LpCGuid,
    _rgguid_interfaces: LpCGuid,
    _dw_interface_count: u32,
    _pb_atr: LpCByte,
    _pb_atr_mask: LpCByte,
    _cb_atr_len: u32,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardSetCardTypeProviderNameA"))]
#[no_mangle]
pub extern "system" fn SCardSetCardTypeProviderNameA(
    _context: ScardContext,
    _sz_card_name: LpCStr,
    _dw_provider_id: u32,
    _sz_provider: LpCStr,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardSetCardTypeProviderNameW"))]
#[no_mangle]
pub extern "system" fn SCardSetCardTypeProviderNameW(
    _context: ScardContext,
    _sz_card_name: LpCWStr,
    _dw_provider_id: u32,
    _sz_provider: LpCWStr,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetCardTypeA"))]
#[no_mangle]
pub extern "system" fn SCardForgetCardTypeA(_context: ScardContext, _sz_card_name: LpCStr) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetCardTypeW"))]
#[no_mangle]
pub extern "system" fn SCardForgetCardTypeW(_context: ScardContext, _sz_card_name: LpCWStr) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardFreeMemory"))]
#[no_mangle]
pub extern "system" fn SCardFreeMemory(_context: ScardContext, _pv_mem: LpCVoid) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardAccessStartedEvent"))]
#[no_mangle]
pub extern "system" fn SCardAccessStartedEvent() -> Handle {
    // This value has been extracted from the original winscard SCardAccessStartedEvent call.
    0x0000000000000eb0 as Handle
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardReleaseStartedEvent"))]
#[no_mangle]
pub extern "system" fn SCardReleaseStartedEvent() {}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardLocateCardsA"))]
#[no_mangle]
pub extern "system" fn SCardLocateCardsA(
    _context: ScardContext,
    _msz_cards: LpCStr,
    _rg_reader_states: LpScardReaderStateA,
    _c_readers: u32,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardLocateCardsW"))]
#[no_mangle]
pub extern "system" fn SCardLocateCardsW(
    _context: ScardContext,
    _msz_cards: LpCWStr,
    _rg_reader_states: LpScardReaderStateW,
    _c_readers: u32,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardLocateCardsByATRA"))]
#[no_mangle]
pub extern "system" fn SCardLocateCardsByATRA(
    _context: ScardContext,
    _rg_atr_masks: LpScardAtrMask,
    _c_atrs: u32,
    _rg_reader_states: LpScardReaderStateA,
    _c_readers: u32,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardLocateCardsByATRW"))]
#[no_mangle]
pub extern "system" fn SCardLocateCardsByATRW(
    _context: ScardContext,
    _rg_atr_masks: LpScardAtrMask,
    _c_atrs: u32,
    _rg_reader_states: LpScardReaderStateW,
    _c_readers: u32,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetStatusChangeA"))]
#[no_mangle]
pub extern "system" fn SCardGetStatusChangeA(
    _context: ScardContext,
    _dw_timeout: u32,
    _rg_reader_states: LpScardReaderStateA,
    _c_readers: u32,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetStatusChangeW"))]
#[no_mangle]
pub extern "system" fn SCardGetStatusChangeW(
    _context: ScardContext,
    _dw_timeout: u32,
    _rg_reader_states: LpScardReaderStateW,
    _c_readers: u32,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardCancel"))]
#[no_mangle]
pub extern "system" fn SCardCancel(_context: ScardContext) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardReadCacheA"))]
#[no_mangle]
pub extern "system" fn SCardReadCacheA(
    _context: ScardContext,
    _card_identifier: LpUuid,
    _freshness_counter: u32,
    _lookup_lame: LpStr,
    _data: LpByte,
    _data_len: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardReadCacheW"))]
#[no_mangle]
pub extern "system" fn SCardReadCacheW(
    _context: ScardContext,
    _card_identifier: LpUuid,
    _freshness_counter: u32,
    _lookup_lame: LpWStr,
    _data: LpByte,
    _data_len: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardWriteCacheA"))]
#[no_mangle]
pub extern "system" fn SCardWriteCacheA(
    _context: ScardContext,
    _card_identifier: LpUuid,
    _freshness_counter: u32,
    _lookup_lame: LpStr,
    _data: LpByte,
    _data_len: u32,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardWriteCacheW"))]
#[no_mangle]
pub extern "system" fn SCardWriteCacheW(
    _context: ScardContext,
    _card_identifier: LpUuid,
    _freshness_counter: u32,
    _lookup_lame: LpWStr,
    _data: LpByte,
    _data_len: u32,
) -> ScardStatus {
    todo!()
}

unsafe fn get_reader_icon(
    context: &dyn WinScardContext,
    reader_name: &str,
    pb_icon: LpByte,
    pcb_icon: LpDword,
) -> WinScardResult<()> {
    let icon = context.reader_icon(&reader_name)?;
    let icon_buffer_len = icon.as_ref().len();
    let pcb_icon_len = (*pcb_icon).try_into().unwrap();

    if icon_buffer_len > pcb_icon_len {
        return Err(Error::new(
            ErrorKind::InsufficientBuffer,
            format!(
                "Icon buffer is too small. Expected at least {} but got {}",
                icon_buffer_len, pcb_icon_len
            ),
        ));
    }

    *pcb_icon = icon_buffer_len.try_into().unwrap();

    let icon_buffer = from_raw_parts_mut(pb_icon, icon_buffer_len);
    icon_buffer.copy_from_slice(icon.as_ref());

    Ok(())
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetReaderIconA"))]
#[no_mangle]
pub unsafe extern "system" fn SCardGetReaderIconA(
    context: ScardContext,
    sz_reader_name: LpCStr,
    pb_icon: LpByte,
    pcb_icon: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(sz_reader_name);
    check_null!(pb_icon);

    let context = &mut *scard_context_to_winscard_context(context);
    let reader_name = try_execute!(
        CStr::from_ptr(sz_reader_name as *const i8).to_str(),
        ErrorKind::InvalidParameter
    );
    debug!(reader_name);

    try_execute!(get_reader_icon(context.as_ref(), &reader_name, pb_icon, pcb_icon));

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetReaderIconW"))]
#[no_mangle]
pub unsafe extern "system" fn SCardGetReaderIconW(
    context: ScardContext,
    sz_reader_name: LpCWStr,
    pb_icon: LpByte,
    pcb_icon: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(sz_reader_name);
    check_null!(pb_icon);

    let context = &mut *scard_context_to_winscard_context(context);
    let reader_name = c_w_str_to_string(sz_reader_name);
    debug!(reader_name);

    try_execute!(get_reader_icon(context.as_ref(), &reader_name, pb_icon, pcb_icon));

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetDeviceTypeIdA"))]
#[no_mangle]
pub unsafe extern "system" fn SCardGetDeviceTypeIdA(
    context: ScardContext,
    sz_reader_name: LpCStr,
    pdw_device_type_id: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(sz_reader_name);
    check_null!(pdw_device_type_id);

    let context = &mut *scard_context_to_winscard_context(context);
    let reader_name = try_execute!(
        CStr::from_ptr(sz_reader_name as *const i8).to_str(),
        ErrorKind::InvalidParameter
    );
    debug!(reader_name);

    let type_id = try_execute!(context.device_type_id(&reader_name));
    *pdw_device_type_id = type_id.into();

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetDeviceTypeIdW"))]
#[no_mangle]
pub unsafe extern "system" fn SCardGetDeviceTypeIdW(
    context: ScardContext,
    sz_reader_name: LpCWStr,
    pdw_device_type_id: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(sz_reader_name);
    check_null!(pdw_device_type_id);

    let context = &mut *scard_context_to_winscard_context(context);
    let reader_name = c_w_str_to_string(sz_reader_name);
    debug!(reader_name);

    let type_id = try_execute!(context.device_type_id(&reader_name));
    *pdw_device_type_id = type_id.into();

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetReaderDeviceInstanceIdA"))]
#[no_mangle]
pub extern "system" fn SCardGetReaderDeviceInstanceIdA(
    _context: ScardContext,
    _sz_reader_name: LpCStr,
    _sz_device_instance_id: LpStr,
    _pcch_device_instance_id: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetReaderDeviceInstanceIdW"))]
#[no_mangle]
pub extern "system" fn SCardGetReaderDeviceInstanceIdW(
    _context: ScardContext,
    _sz_reader_name: LpCWStr,
    _sz_device_instance_id: LpWStr,
    _pcch_device_instance_id: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListReadersWithDeviceInstanceIdA"))]
#[no_mangle]
pub extern "system" fn SCardListReadersWithDeviceInstanceIdA(
    _context: ScardContext,
    _sz_device_instance_id: LpCStr,
    _msz_readers: LpStr,
    _pcch_readers: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListReadersWithDeviceInstanceIdW"))]
#[no_mangle]
pub extern "system" fn SCardListReadersWithDeviceInstanceIdW(
    _context: ScardContext,
    _sz_device_instance_id: LpCWStr,
    _msz_readers: LpWStr,
    _pcch_readers: LpDword,
) -> ScardStatus {
    todo!()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardAudit"))]
#[no_mangle]
pub extern "system" fn SCardAudit(_context: ScardContext, _dw_event: u32) -> ScardStatus {
    todo!()
}
