use std::borrow::Cow;
use std::ffi::CStr;
use std::slice::from_raw_parts_mut;

use ffi_types::winscard::{
    LpScardAtrMask, LpScardContext, LpScardReaderStateA, LpScardReaderStateW, ScardContext, ScardStatus,
};
use ffi_types::{Handle, LpByte, LpCByte, LpCGuid, LpCStr, LpCVoid, LpCWStr, LpDword, LpGuid, LpStr, LpUuid, LpWStr};
use libc::c_void;
use symbol_rename_macro::rename_symbol;
use winscard::winscard::WinScardContext;
use winscard::{ErrorKind, ScardContext as PivCardContext, SmartCardInfo, WinScardResult, ATR};

use super::buff_alloc::copy_w_buff;
use crate::utils::{c_w_str_to_string, into_raw_ptr};
use crate::winscard::buff_alloc::copy_buff;
use crate::winscard::scard_handle::{
    scard_context_to_winscard_context, WinScardContextHandle,
};

use super::buff_alloc::{write_multistring_a, write_multistring_w};

// const SCARD_STATE_UNAWARE: u32 = 0x00000000;
const SCARD_STATE_CHANGED: u32 = 0x00000002;
const SCARD_STATE_INUSE: u32 = 0x00000100;
const SCARD_STATE_PRESENT: u32 = 0x00000020;
// Undocumented constant that appears in all API captures
const SCARD_STATE_UNNAMED_CONSTANT: u32 = 0x00010000;

// https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardgetcardtypeprovidernamew
// `dwProviderId` function parameter::
// The function retrieves the name of the smart card's primary service provider as a GUID string.
const SCARD_PROVIDER_PRIMARY: u32 = 1;
// The function retrieves the name of the cryptographic service provider.
const SCARD_PROVIDER_CSP: u32 = 2;
// The function retrieves the name of the smart card key storage provider (KSP).
const SCARD_PROVIDER_KSP: u32 = 3;
// The function retrieves the name of the card module.
const SCARD_PROVIDER_CARD_MODULE: u32 = 0x80000001;

const MICROSOFT_DEFAULT_CSP: &str = "Microsoft Base Smart Card Crypto Provider";
const MICROSOFT_DEFAULT_KSP: &str = "Microsoft Smart Card Key Storage Provider";
const MICROSOFT_SCARD_DRIVER_LOCATION: &str = "C:\\Windows\\System32\\msclmd.dll";

const DEFAULT_CARD_NAME: &str = "Cool card";

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardEstablishContext"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardEstablishContext(
    _dw_scope: u32,
    _r1: *const c_void,
    _r2: *const c_void,
    context: LpScardContext,
) -> ScardStatus {
    crate::logging::setup_logger();
    check_null!(context);

    let scard_info = try_execute!(SmartCardInfo::try_from_env());
    // We have only one available reader
    let scard_context: Box<dyn WinScardContext> = Box::new(try_execute!(PivCardContext::new(scard_info)));

    let scard_context = WinScardContextHandle {
        scard_context,
        scards: Vec::new(),
        allocations: Vec::new(),
    };

    let raw_ptr = into_raw_ptr(scard_context) as ScardContext;
    info!(new_established_context = ?raw_ptr);
    *context = raw_ptr;

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardReleaseContext"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardReleaseContext(context: ScardContext) -> ScardStatus {
    check_handle!(context);

    let _ = Box::from_raw(context as *mut WinScardContextHandle);

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIsValidContext"))]
#[no_mangle]
pub unsafe extern "system" fn SCardIsValidContext(context: ScardContext) -> ScardStatus {
    let context = try_execute!(scard_context_to_winscard_context(context));

    if context.is_valid() {
        ErrorKind::Success.into()
    } else {
        ErrorKind::InvalidHandle.into()
    }
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListReaderGroupsA"))]
#[no_mangle]
pub extern "system" fn SCardListReaderGroupsA(
    _context: ScardContext,
    _gmsz_groups: LpStr,
    _pcch_groups: LpDword,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListReaderGroupsW"))]
#[no_mangle]
pub extern "system" fn SCardListReaderGroupsW(
    _context: ScardContext,
    _gmsz_groups: LpWStr,
    _pcch_groups: LpDword,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListReadersA"))]
#[no_mangle]
pub unsafe extern "system" fn SCardListReadersA(
    context: ScardContext,
    _msz_groups: LpCStr,
    msz_readers: LpStr,
    pcch_readers: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(msz_readers);
    check_null!(pcch_readers);

    let context = (context as *mut WinScardContextHandle).as_mut().unwrap();
    let readers = context.scard_context.list_readers();
    let readers = readers.iter().map(|reader| reader.to_string()).collect::<Vec<_>>();
    let readers = readers.iter().map(|reader| reader.as_ref()).collect::<Vec<_>>();

    try_execute!(write_multistring_a(context, &readers, msz_readers, pcch_readers));

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListReadersW"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardListReadersW(
    context: ScardContext,
    _msz_groups: LpCWStr,
    msz_readers: LpWStr,
    pcch_readers: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(msz_readers);
    check_null!(pcch_readers);

    let context = (context as *mut WinScardContextHandle).as_mut().unwrap();
    let readers = context.scard_context.list_readers();
    let readers = readers.iter().map(|reader| reader.to_string()).collect::<Vec<_>>();
    let readers = readers.iter().map(|reader| reader.as_ref()).collect::<Vec<_>>();

    try_execute!(write_multistring_w(context, &readers, msz_readers, pcch_readers));

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListCardsA"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardListCardsA(
    context: ScardContext,
    _pb_atr: LpCByte,
    _rgquid_nterfaces: LpCGuid,
    _cguid_interface_count: u32,
    msz_cards: *mut u8,
    pcch_cards: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(msz_cards);
    check_null!(pcch_cards);

    let context = (context as *mut WinScardContextHandle).as_mut().unwrap();
    // we have only one smart card with only one default name
    try_execute!(write_multistring_a(
        context,
        &[DEFAULT_CARD_NAME],
        msz_cards,
        pcch_cards
    ));

    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListCardsW"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardListCardsW(
    context: ScardContext,
    _pb_atr: LpCByte,
    _rgquid_nterfaces: LpCGuid,
    _cguid_interface_count: u32,
    msz_cards: *mut u16,
    pcch_cards: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(msz_cards);
    check_null!(pcch_cards);

    let context = (context as *mut WinScardContextHandle).as_mut().unwrap();
    // we have only one smart card with only one default name
    try_execute!(write_multistring_w(
        context,
        &[DEFAULT_CARD_NAME],
        msz_cards,
        pcch_cards
    ));

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListInterfacesA"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardListInterfacesA(
    _context: ScardContext,
    _sz_scard: LpCStr,
    _pguid_interfaces: LpGuid,
    _pcguid_interfaces: LpDword,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListInterfacesW"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardListInterfacesW(
    _context: ScardContext,
    _sz_scard: LpCWStr,
    _pguid_interfaces: LpGuid,
    _pcguid_interfaces: LpDword,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetProviderIdA"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardGetProviderIdA(
    _context: ScardContext,
    _sz_card: LpCStr,
    _pguid_provider_id: LpGuid,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetProviderIdW"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardGetProviderIdW(
    _context: ScardContext,
    _sz_card: LpCWStr,
    _pguid_provider_id: LpGuid,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetCardTypeProviderNameA"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardGetCardTypeProviderNameA(
    context: ScardContext,
    _sz_card_name: LpCStr,
    dw_provide_id: u32,
    szProvider: *mut u8,
    pcch_provider: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(szProvider);
    check_null!(pcch_provider);

    let provider = match dw_provide_id {
        SCARD_PROVIDER_PRIMARY => {
            error!("Unsupported dw_provider_id: SCARD_PROVIDER_PRIMARY");
            return ErrorKind::UnsupportedFeature.into();
        }
        SCARD_PROVIDER_CSP => MICROSOFT_DEFAULT_CSP,
        SCARD_PROVIDER_KSP => MICROSOFT_DEFAULT_KSP,
        SCARD_PROVIDER_CARD_MODULE => MICROSOFT_SCARD_DRIVER_LOCATION,
        _ => {
            error!(?dw_provide_id, "Unsupported dw_provider_id.");
            return ErrorKind::InvalidParameter.into();
        }
    };

    let context = (context as *mut WinScardContextHandle).as_mut().unwrap();
    try_execute!(copy_buff(context, szProvider, pcch_provider, provider.as_bytes()));

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetCardTypeProviderNameW"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardGetCardTypeProviderNameW(
    context: ScardContext,
    _sz_card_name: LpCWStr,
    dw_provide_id: u32,
    szProvider: *mut u16,
    pcch_provider: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(szProvider);
    check_null!(pcch_provider);

    let provider = match dw_provide_id {
        SCARD_PROVIDER_PRIMARY => {
            error!("Unsupported dw_provider_id: SCARD_PROVIDER_PRIMARY");
            return ErrorKind::UnsupportedFeature.into();
        }
        SCARD_PROVIDER_CSP => MICROSOFT_DEFAULT_CSP,
        SCARD_PROVIDER_KSP => MICROSOFT_DEFAULT_KSP,
        SCARD_PROVIDER_CARD_MODULE => MICROSOFT_SCARD_DRIVER_LOCATION,
        _ => {
            error!(?dw_provide_id, "Unsupported dw_provider_id.");
            return ErrorKind::InvalidParameter.into();
        }
    };
    let encoded: Vec<u16> = provider.encode_utf16().chain(core::iter::once(0)).collect();

    let context = (context as *mut WinScardContextHandle).as_mut().unwrap();
    try_execute!(copy_w_buff(context, szProvider, pcch_provider, &encoded));

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceReaderGroupA"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardIntroduceReaderGroupA(_context: ScardContext, _sz_group_name: LpCStr) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceReaderGroupW"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardIntroduceReaderGroupW(_context: ScardContext, _sz_group_name: LpCWStr) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetReaderGroupA"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardForgetReaderGroupA(_context: ScardContext, _sz_group_name: LpCStr) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetReaderGroupW"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardForgetReaderGroupW(_context: ScardContext, _sz_group_name: LpCWStr) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceReaderA"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardIntroduceReaderA(
    _context: ScardContext,
    _sz_reader_name: LpCStr,
    _sz_device_name: LpCStr,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceReaderW"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardIntroduceReaderW(
    _context: ScardContext,
    _sz_reader_name: LpCWStr,
    _sz_device_name: LpCWStr,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetReaderA"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardForgetReaderA(_context: ScardContext, _sz_reader_name: LpCStr) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetReaderW"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardForgetReaderW(_context: ScardContext, _sz_reader_name: LpCWStr) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardAddReaderToGroupA"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardAddReaderToGroupA(
    _context: ScardContext,
    _sz_reader_name: LpCStr,
    _sz_group_name: LpCStr,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardAddReaderToGroupW"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardAddReaderToGroupW(
    _context: ScardContext,
    _sz_reader_name: LpCWStr,
    _sz_group_name: LpCWStr,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardRemoveReaderFromGroupA"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardRemoveReaderFromGroupA(
    _context: ScardContext,
    _sz_reader_name: LpCStr,
    _sz_group_name: LpCStr,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardRemoveReaderFromGroupW"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardRemoveReaderFromGroupW(
    _context: ScardContext,
    _sz_reader_name: LpCWStr,
    _sz_group_name: LpCWStr,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceCardTypeA"))]
#[instrument(ret)]
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
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceCardTypeW"))]
#[instrument(ret)]
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
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardSetCardTypeProviderNameA"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardSetCardTypeProviderNameA(
    _context: ScardContext,
    _sz_card_name: LpCStr,
    _dw_provider_id: u32,
    _sz_provider: LpCStr,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardSetCardTypeProviderNameW"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardSetCardTypeProviderNameW(
    _context: ScardContext,
    _sz_card_name: LpCWStr,
    _dw_provider_id: u32,
    _sz_provider: LpCWStr,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetCardTypeA"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardForgetCardTypeA(_context: ScardContext, _sz_card_name: LpCStr) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetCardTypeW"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardForgetCardTypeW(_context: ScardContext, _sz_card_name: LpCWStr) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardFreeMemory"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardFreeMemory(context: ScardContext, pv_mem: LpCVoid) -> ScardStatus {
    if let Some(context) = (context as *mut WinScardContextHandle).as_mut() {
        if context.free_buffer(pv_mem) {
            info!("Allocated buffer successfully freed.");
        } else {
            warn!(?pv_mem, "Attempt to free unknown buffer");
        }

        ErrorKind::Success.into()
    } else {
        ErrorKind::InvalidHandle.into()
    }
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardAccessStartedEvent"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardAccessStartedEvent() -> Handle {
    // This value has been extracted from the original winscard SCardAccessStartedEvent call.
    0x0000000000000eb0 as Handle
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardReleaseStartedEvent"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardReleaseStartedEvent() {}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardLocateCardsA"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardLocateCardsA(
    _context: ScardContext,
    _msz_cards: LpCStr,
    _rg_reader_states: LpScardReaderStateA,
    _c_readers: u32,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardLocateCardsW"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardLocateCardsW(
    _context: ScardContext,
    _msz_cards: LpCWStr,
    _rg_reader_states: LpScardReaderStateW,
    _c_readers: u32,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardLocateCardsByATRA"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardLocateCardsByATRA(
    _context: ScardContext,
    _rg_atr_masks: LpScardAtrMask,
    _c_atrs: u32,
    _rg_reader_states: LpScardReaderStateA,
    _c_readers: u32,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardLocateCardsByATRW"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardLocateCardsByATRW(
    _context: ScardContext,
    _rg_atr_masks: LpScardAtrMask,
    _c_atrs: u32,
    _rg_reader_states: LpScardReaderStateW,
    _c_readers: u32,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetStatusChangeA"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardGetStatusChangeA(
    context: ScardContext,
    _dw_timeout: u32,
    rg_reader_states: LpScardReaderStateA,
    c_readers: u32,
) -> ScardStatus {
    check_handle!(context);
    check_null!(rg_reader_states);

    let context = try_execute!(scard_context_to_winscard_context(context));
    let supported_readers = context.list_readers();

    let reader_states = from_raw_parts_mut(rg_reader_states, c_readers.try_into().unwrap());

    for reader_state in reader_states {
        let reader = try_execute!(
            CStr::from_ptr(reader_state.sz_reader as *const i8).to_str(),
            ErrorKind::InvalidParameter
        );

        if supported_readers.contains(&Cow::Borrowed(&reader)) {
            reader_state.dw_event_state =
                SCARD_STATE_UNNAMED_CONSTANT | SCARD_STATE_INUSE | SCARD_STATE_PRESENT | SCARD_STATE_CHANGED;
            reader_state.cb_atr = ATR.len().try_into().unwrap();
            reader_state.rgb_atr[0..ATR.len()].copy_from_slice(ATR.as_slice());
        } else if reader == "\\\\?PnP?\\Notification" {
            reader_state.dw_event_state = SCARD_STATE_UNNAMED_CONSTANT;
        } else {
            error!(?reader, "Unsupported reader");
        }
    }

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetStatusChangeW"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardGetStatusChangeW(
    context: ScardContext,
    _dw_timeout: u32,
    rg_reader_states: LpScardReaderStateW,
    c_readers: u32,
) -> ScardStatus {
    check_handle!(context);
    check_null!(rg_reader_states);

    let context = try_execute!(scard_context_to_winscard_context(context));
    let supported_readers = context.list_readers();

    let reader_states = from_raw_parts_mut(rg_reader_states, c_readers.try_into().unwrap());
    for reader_state in reader_states {
        let reader = c_w_str_to_string(reader_state.sz_reader);
        if supported_readers.contains(&Cow::Borrowed(&reader)) {
            reader_state.dw_event_state =
                SCARD_STATE_UNNAMED_CONSTANT | SCARD_STATE_INUSE | SCARD_STATE_PRESENT | SCARD_STATE_CHANGED;
            reader_state.cb_atr = ATR.len().try_into().unwrap();
            reader_state.rgb_atr[0..ATR.len()].copy_from_slice(ATR.as_slice());
        } else if reader == "\\\\?PnP?\\Notification" {
            reader_state.dw_event_state = SCARD_STATE_UNNAMED_CONSTANT;
        } else {
            error!(?reader, "Unsupported reader");
        }
    }

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardCancel"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardCancel(_context: ScardContext) -> ScardStatus {
    // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardcancel
    // The SCardCancel function terminates all outstanding actions within a specific resource manager context.
    //
    // We do not have such actions in an emulated scard context
    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardReadCacheA"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardReadCacheA(
    context: ScardContext,
    _card_identifier: LpUuid,
    _freshness_counter: u32,
    lookup_name: LpStr,
    data: LpByte,
    data_len: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(lookup_name);
    check_null!(data_len);

    let context = (context as *mut WinScardContextHandle).as_mut().unwrap();
    let lookup_name = try_execute!(
        CStr::from_ptr(lookup_name as *const i8).to_str(),
        ErrorKind::InvalidParameter
    );

    if let Some(cached_value) = context.scard_context.read_cache(&lookup_name) {
        let cached_value = cached_value.to_vec();
        try_execute!(copy_buff(context, data, data_len, &cached_value));

        ErrorKind::Success.into()
    } else {
        warn!(cache = ?ErrorKind::CacheItemNotFound);
        ErrorKind::CacheItemNotFound.into()
    }
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardReadCacheW"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardReadCacheW(
    context: ScardContext,
    _card_identifier: LpUuid,
    _freshness_counter: u32,
    lookup_name: LpWStr,
    data: LpByte,
    data_len: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(lookup_name);
    check_null!(data_len);

    let context = (context as *mut WinScardContextHandle).as_mut().unwrap();
    let lookup_name = c_w_str_to_string(lookup_name);

    if let Some(cached_value) = context.scard_context.read_cache(&lookup_name) {
        let cached_value = cached_value.to_vec();
        try_execute!(copy_buff(context, data, data_len, &cached_value));

        ErrorKind::Success.into()
    } else {
        warn!(cache = ?ErrorKind::CacheItemNotFound);
        ErrorKind::CacheItemNotFound.into()
    }
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardWriteCacheA"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardWriteCacheA(
    context: ScardContext,
    _card_identifier: LpUuid,
    _freshness_counter: u32,
    lookup_name: LpStr,
    data: LpByte,
    data_len: u32,
) -> ScardStatus {
    let context = try_execute!(scard_context_to_winscard_context(context));
    let lookup_name = try_execute!(
        CStr::from_ptr(lookup_name as *const i8).to_str(),
        ErrorKind::InvalidParameter
    );
    let data = from_raw_parts_mut(data, data_len.try_into().unwrap()).to_vec();
    info!(write_lookup_name = lookup_name, ?data);

    context.write_cache(lookup_name.to_owned(), data);

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardWriteCacheW"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardWriteCacheW(
    context: ScardContext,
    _card_identifier: LpUuid,
    _freshness_counter: u32,
    lookup_name: LpWStr,
    data: LpByte,
    data_len: u32,
) -> ScardStatus {
    let context = try_execute!(scard_context_to_winscard_context(context));
    let lookup_name = c_w_str_to_string(lookup_name);
    let data = from_raw_parts_mut(data, data_len.try_into().unwrap()).to_vec();
    info!(write_lookup_name = lookup_name, ?data);

    context.write_cache(lookup_name, data);

    ErrorKind::Success.into()
}

unsafe fn get_reader_icon(
    context: &mut WinScardContextHandle,
    reader_name: &str,
    pb_icon: LpByte,
    pcb_icon: LpDword,
) -> WinScardResult<()> {
    let icon = context.scard_context.reader_icon(reader_name)?.as_ref().to_vec();

    copy_buff(context, pb_icon, pcb_icon, icon.as_ref())
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetReaderIconA"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardGetReaderIconA(
    context: ScardContext,
    sz_reader_name: LpCStr,
    pb_icon: LpByte,
    pcb_icon: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(sz_reader_name);
    // `pb_icon` can be null.
    check_null!(pcb_icon);

    let context = (context as *mut WinScardContextHandle).as_mut().unwrap();
    let reader_name = try_execute!(
        CStr::from_ptr(sz_reader_name as *const i8).to_str(),
        ErrorKind::InvalidParameter
    );
    debug!(reader_name);

    try_execute!(get_reader_icon(context, &reader_name, pb_icon, pcb_icon));

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetReaderIconW"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardGetReaderIconW(
    context: ScardContext,
    sz_reader_name: LpCWStr,
    pb_icon: LpByte,
    pcb_icon: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(sz_reader_name);
    // `pb_icon` can be null.
    check_null!(pcb_icon);

    let context = (context as *mut WinScardContextHandle).as_mut().unwrap();
    let reader_name = c_w_str_to_string(sz_reader_name);
    debug!(reader_name);

    try_execute!(get_reader_icon(context, &reader_name, pb_icon, pcb_icon));

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetDeviceTypeIdA"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardGetDeviceTypeIdA(
    context: ScardContext,
    sz_reader_name: LpCStr,
    pdw_device_type_id: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(sz_reader_name);
    check_null!(pdw_device_type_id);

    let context = try_execute!(scard_context_to_winscard_context(context));
    let reader_name = try_execute!(
        CStr::from_ptr(sz_reader_name as *const i8).to_str(),
        ErrorKind::InvalidParameter
    );

    let type_id = try_execute!(context.device_type_id(&reader_name));
    *pdw_device_type_id = type_id.into();

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetDeviceTypeIdW"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardGetDeviceTypeIdW(
    context: ScardContext,
    sz_reader_name: LpCWStr,
    pdw_device_type_id: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(sz_reader_name);
    check_null!(pdw_device_type_id);

    let context = try_execute!(scard_context_to_winscard_context(context));
    let reader_name = c_w_str_to_string(sz_reader_name);

    let type_id = try_execute!(context.device_type_id(&reader_name));
    *pdw_device_type_id = type_id.into();

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetReaderDeviceInstanceIdA"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardGetReaderDeviceInstanceIdA(
    _context: ScardContext,
    _sz_reader_name: LpCStr,
    _sz_device_instance_id: LpStr,
    _pcch_device_instance_id: LpDword,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetReaderDeviceInstanceIdW"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardGetReaderDeviceInstanceIdW(
    _context: ScardContext,
    _sz_reader_name: LpCWStr,
    _sz_device_instance_id: LpWStr,
    _pcch_device_instance_id: LpDword,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListReadersWithDeviceInstanceIdA"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardListReadersWithDeviceInstanceIdA(
    _context: ScardContext,
    _sz_device_instance_id: LpCStr,
    _msz_readers: LpStr,
    _pcch_readers: LpDword,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListReadersWithDeviceInstanceIdW"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardListReadersWithDeviceInstanceIdW(
    _context: ScardContext,
    _sz_device_instance_id: LpCWStr,
    _msz_readers: LpWStr,
    _pcch_readers: LpDword,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardAudit"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardAudit(_context: ScardContext, _dw_event: u32) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}
