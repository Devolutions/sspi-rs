use std::ffi::CStr;
use std::slice::from_raw_parts_mut;
use std::sync::Mutex;

use ffi_types::winscard::{
    LpScardAtrMask, LpScardContext, LpScardReaderStateA, LpScardReaderStateW, ScardContext, ScardStatus,
};
use ffi_types::{Handle, LpByte, LpCByte, LpCGuid, LpCStr, LpCVoid, LpCWStr, LpDword, LpGuid, LpStr, LpUuid, LpWStr};
use libc::c_void;
use sspi::cert_utils::extract_certificate_and_pk_from_env;
use symbol_rename_macro::rename_symbol;
use winscard::winscard::WinScardContext;
use winscard::{Error, ErrorKind, ScardContext as PivCardContext, SmartCardInfo, WinScardResult};

use super::scard_handle::{AllocationType, ALLOCATIONS};
use crate::utils::{c_w_str_to_string, into_raw_ptr};
use crate::winscard::scard_handle::{
    null_terminated_lpwstr_to_string, scard_context_to_winscard_context, write_readers_a, write_readers_w,
};

const SCARD_STATE_CHANGED: u32 = 0x00000002;
const SCARD_STATE_INUSE: u32 = 0x00000100;
const SCARD_STATE_PRESENT: u32 = 0x00000020;
// Undocumented constant that appears in all API captures
const SCARD_STATE_UNNAMED_CONSTANT: u32 = 0x00010000;
const WINSCARD_PIN_ENV: &str = "WINSCARD_SCARD_PIN";

pub(crate) static CONTEXTS: Mutex<Vec<usize>> = Mutex::new(vec![]);

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

    let pin = try_execute!(std::env::var(WINSCARD_PIN_ENV).map_err(|e| {
        Error::new(
            ErrorKind::InvalidParameter,
            format!("Cannot extract PIN from the env variable: {}", e),
        )
    }));
    let (certificate, auth_pk) = try_execute!(extract_certificate_and_pk_from_env().map_err(|e| {
        Error::new(
            ErrorKind::InternalError,
            format!(
                "Error while extracting certificate and private key from env variables: {}",
                e
            ),
        )
    }));
    let certificate = try_execute!(picky_asn1_der::to_vec(&certificate).map_err(|e| {
        Error::new(
            ErrorKind::InternalError,
            format!("Error while trying to encode certificate using the der format: {}", e),
        )
    }));
    let scard_info = SmartCardInfo::new(pin.into_bytes(), certificate, auth_pk);
    // We have only one available reader
    let established_context: Box<dyn WinScardContext> = Box::new(PivCardContext::new(scard_info));

    let raw_ptr = into_raw_ptr(established_context) as ScardContext;
    let mut vec = CONTEXTS.lock().unwrap();
    vec.push(raw_ptr);
    info!(context = ?raw_ptr);
    *context = raw_ptr;

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardReleaseContext"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardReleaseContext(context: ScardContext) -> ScardStatus {
    let _ = Box::from_raw(try_execute!(scard_context_to_winscard_context(context)));
    let mut ctx = CONTEXTS.lock().unwrap();
    // we know that it is present because scard_context_to_winscard_context didn't fail
    let idx = ctx.iter().position(|&x| x == context).unwrap();
    ctx.remove(idx);
    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIsValidContext"))]
#[no_mangle]
pub unsafe extern "system" fn SCardIsValidContext(context: ScardContext) -> ScardStatus {
    let ctx = CONTEXTS.lock().unwrap();
    if ctx.contains(&context) {
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

    let context = &*try_execute!(scard_context_to_winscard_context(context));
    let readers = context.list_readers();
    let readers = readers.iter().map(|reader| reader.as_ref()).collect::<Vec<_>>();

    try_execute!(write_readers_a(&readers, msz_readers, pcch_readers));

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

    let context = &*try_execute!(scard_context_to_winscard_context(context));
    let readers = context.list_readers();
    let readers = readers.iter().map(|reader| reader.as_ref()).collect::<Vec<_>>();

    try_execute!(write_readers_w(&readers, msz_readers, pcch_readers));

    ErrorKind::Success.into()
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
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListCardsW"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardListCardsW(
    _context: ScardContext,
    _pb_atr: LpCByte,
    _rgquid_nterfaces: LpCGuid,
    _cguid_interface_count: u32,
    msz_cards: *mut u16,
    pcch_cards: LpDword,
) -> ScardStatus {
    check_null!(pcch_cards);
    let scard_name = "Cool card";
    let encoded: Vec<u16> = scard_name.encode_utf16().chain([0, 0]).collect();

    if msz_cards.is_null() {
        *pcch_cards = encoded.len().try_into().unwrap();
        return ErrorKind::Success.into();
    }

    let dest_str_len = (*pcch_cards).try_into().unwrap();
    if encoded.len() > dest_str_len {
        return ErrorKind::InsufficientBuffer.into();
    }

    let dest_buffer = from_raw_parts_mut(msz_cards, encoded.len());
    dest_buffer.copy_from_slice(&encoded);

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListInterfacesA"))]
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
#[no_mangle]
pub extern "system" fn SCardGetProviderIdA(
    _context: ScardContext,
    _sz_card: LpCStr,
    _pguid_provider_id: LpGuid,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetProviderIdW"))]
#[no_mangle]
pub extern "system" fn SCardGetProviderIdW(
    _context: ScardContext,
    _sz_card: LpCWStr,
    _pguid_provider_id: LpGuid,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
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
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetCardTypeProviderNameW"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardGetCardTypeProviderNameW(
    _context: ScardContext,
    _sz_card_name: LpCWStr,
    dw_provide_id: u32,
    szProvider: *mut u16,
    pcch_provider: LpDword,
) -> ScardStatus {
    check_null!(pcch_provider);

    if szProvider.is_null() {
        *pcch_provider = 0x2a;
    } else {
        let provider = match dw_provide_id {
            2 => "Microsoft Base Smart Card Crypto Provider",
            3 => "Microsoft Smart Card Key Storage Provider",
            _ => {
                error!("Unsupported dw_provide_id: {}", dw_provide_id);
                return ErrorKind::UnsupportedFeature.into();
            }
        };
        let encoded: Vec<u16> = provider.encode_utf16().chain([0, 0]).collect();

        let dest_str_len = (*pcch_provider).try_into().unwrap();
        if encoded.len() > dest_str_len {
            return ErrorKind::InsufficientBuffer.into();
        }

        let dest_buffer = from_raw_parts_mut(szProvider, encoded.len());
        dest_buffer.copy_from_slice(&encoded);
    }

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceReaderGroupA"))]
#[no_mangle]
pub extern "system" fn SCardIntroduceReaderGroupA(_context: ScardContext, _sz_group_name: LpCStr) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceReaderGroupW"))]
#[no_mangle]
pub extern "system" fn SCardIntroduceReaderGroupW(_context: ScardContext, _sz_group_name: LpCWStr) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetReaderGroupA"))]
#[no_mangle]
pub extern "system" fn SCardForgetReaderGroupA(_context: ScardContext, _sz_group_name: LpCStr) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetReaderGroupW"))]
#[no_mangle]
pub extern "system" fn SCardForgetReaderGroupW(_context: ScardContext, _sz_group_name: LpCWStr) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceReaderA"))]
#[no_mangle]
pub extern "system" fn SCardIntroduceReaderA(
    _context: ScardContext,
    _sz_reader_name: LpCStr,
    _sz_device_name: LpCStr,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceReaderW"))]
#[no_mangle]
pub extern "system" fn SCardIntroduceReaderW(
    _context: ScardContext,
    _sz_reader_name: LpCWStr,
    _sz_device_name: LpCWStr,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetReaderA"))]
#[no_mangle]
pub extern "system" fn SCardForgetReaderA(_context: ScardContext, _sz_reader_name: LpCStr) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetReaderW"))]
#[no_mangle]
pub extern "system" fn SCardForgetReaderW(_context: ScardContext, _sz_reader_name: LpCWStr) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardAddReaderToGroupA"))]
#[no_mangle]
pub extern "system" fn SCardAddReaderToGroupA(
    _context: ScardContext,
    _sz_reader_name: LpCStr,
    _sz_group_name: LpCStr,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardAddReaderToGroupW"))]
#[no_mangle]
pub extern "system" fn SCardAddReaderToGroupW(
    _context: ScardContext,
    _sz_reader_name: LpCWStr,
    _sz_group_name: LpCWStr,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardRemoveReaderFromGroupA"))]
#[no_mangle]
pub extern "system" fn SCardRemoveReaderFromGroupA(
    _context: ScardContext,
    _sz_reader_name: LpCStr,
    _sz_group_name: LpCStr,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardRemoveReaderFromGroupW"))]
#[no_mangle]
pub extern "system" fn SCardRemoveReaderFromGroupW(
    _context: ScardContext,
    _sz_reader_name: LpCWStr,
    _sz_group_name: LpCWStr,
) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
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
    ErrorKind::UnsupportedFeature.into()
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
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardSetCardTypeProviderNameA"))]
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
#[no_mangle]
pub extern "system" fn SCardForgetCardTypeA(_context: ScardContext, _sz_card_name: LpCStr) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetCardTypeW"))]
#[no_mangle]
pub extern "system" fn SCardForgetCardTypeW(_context: ScardContext, _sz_card_name: LpCWStr) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardFreeMemory"))]
#[no_mangle]
pub unsafe extern "system" fn SCardFreeMemory(_context: ScardContext, pv_mem: LpCVoid) -> ScardStatus {
    let removed_value = ALLOCATIONS.with(|map| map.borrow_mut().remove(&(pv_mem as usize)));
    if let Some((ptr, alloc_type)) = removed_value {
        match alloc_type {
            AllocationType::U16 => {
                let _ = Box::from_raw(ptr as *mut [u16]);
            }
            AllocationType::U8 => {
                let _ = Box::from_raw(ptr as *mut [u8]);
            }
        };
    } else {
        error!("Tried to free an invalid memory chunk: {:?}", pv_mem);
    }

    ErrorKind::Success.into()
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
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardLocateCardsW"))]
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
#[no_mangle]
pub unsafe extern "system" fn SCardGetStatusChangeA(
    _context: ScardContext,
    _dw_timeout: u32,
    rg_reader_states: LpScardReaderStateA,
    c_readers: u32,
) -> ScardStatus {
    check_null!(rg_reader_states);

    let reader_states = std::slice::from_raw_parts_mut(rg_reader_states, c_readers.try_into().unwrap());

    let reader_state = match reader_states.last_mut() {
        Some(state) => state,
        None => return ErrorKind::InvalidParameter.into(),
    };

    if reader_state.cb_atr == 0 {
        let mut rgb_atr = [0; 36];
        let captured_atr = &[
            0x3b, 0x8d, 0x01, 0x80, 0xfb, 0xa0, 0x00, 0x00, 0x03, 0x97, 0x42, 0x54, 0x46, 0x59, 0x04, 0x01, 0xcf,
        ];
        rgb_atr[0..captured_atr.len()].clone_from_slice(captured_atr);

        reader_state.cb_atr = captured_atr.len().try_into().unwrap();
        reader_state.rgb_atr = rgb_atr;
    }

    reader_state.dw_event_state =
        SCARD_STATE_CHANGED | SCARD_STATE_INUSE | SCARD_STATE_PRESENT | SCARD_STATE_UNNAMED_CONSTANT;

    if reader_states.len() > 1 {
        reader_states[0].dw_event_state = SCARD_STATE_UNNAMED_CONSTANT;
    }

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetStatusChangeW"))]
#[no_mangle]
pub unsafe extern "system" fn SCardGetStatusChangeW(
    _context: ScardContext,
    _dw_timeout: u32,
    rg_reader_states: LpScardReaderStateW,
    c_readers: u32,
) -> ScardStatus {
    check_null!(rg_reader_states);

    let reader_states = std::slice::from_raw_parts_mut(rg_reader_states, c_readers.try_into().unwrap());

    let reader_state = match reader_states.last_mut() {
        Some(state) => state,
        None => return ErrorKind::InvalidParameter.into(),
    };

    if reader_state.cb_atr == 0 {
        let mut rgb_atr = [0; 36];
        let captured_atr = &[
            0x3b, 0x8d, 0x01, 0x80, 0xfb, 0xa0, 0x00, 0x00, 0x03, 0x97, 0x42, 0x54, 0x46, 0x59, 0x04, 0x01, 0xcf,
        ];
        rgb_atr[0..captured_atr.len()].clone_from_slice(captured_atr);

        reader_state.cb_atr = captured_atr.len().try_into().unwrap();
        reader_state.rgb_atr = rgb_atr;
    }

    reader_state.dw_event_state =
        SCARD_STATE_CHANGED | SCARD_STATE_INUSE | SCARD_STATE_PRESENT | SCARD_STATE_UNNAMED_CONSTANT;

    if reader_states.len() > 1 {
        reader_states[0].dw_event_state = SCARD_STATE_UNNAMED_CONSTANT;
    }

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardCancel"))]
#[no_mangle]
pub extern "system" fn SCardCancel(_context: ScardContext) -> ScardStatus {
    // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardcancel
    // The SCardCancel function terminates all outstanding actions within a specific resource manager context.
    //
    // We do not have such actions in an emulated scard context
    ErrorKind::Success.into()
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
    ErrorKind::UnsupportedFeature.into()
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
    let context = &*try_execute!(scard_context_to_winscard_context(context));
    let lookup_name = null_terminated_lpwstr_to_string(lookup_name);
    info!(lookup_name = lookup_name);

    if let Some(cached_value) = context.read_cache(&lookup_name) {
        let dest_buffer_len = (*data_len).try_into().unwrap();
        if cached_value.len() > dest_buffer_len {
            return ErrorKind::InsufficientBuffer.into();
        }

        let dest_buffer = from_raw_parts_mut(data, cached_value.len());
        dest_buffer.copy_from_slice(cached_value);
        *data_len = cached_value.len().try_into().unwrap();

        ErrorKind::Success.into()
    } else {
        ErrorKind::CacheItemNotFound.into()
    }
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
    ErrorKind::UnsupportedFeature.into()
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
    let context = &mut *try_execute!(scard_context_to_winscard_context(context));
    let lookup_name = null_terminated_lpwstr_to_string(lookup_name);
    let data = from_raw_parts_mut(data, data_len.try_into().unwrap()).to_vec();
    info!(lookup_name, ?data);

    context.write_cache(lookup_name, data);

    ErrorKind::Success.into()
}

unsafe fn get_reader_icon(
    context: &dyn WinScardContext,
    reader_name: &str,
    pb_icon: LpByte,
    pcb_icon: LpDword,
) -> WinScardResult<()> {
    let icon = context.reader_icon(reader_name)?;
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

    let context = &mut *try_execute!(scard_context_to_winscard_context(context));
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

    let context = &mut *try_execute!(scard_context_to_winscard_context(context));
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

    let context = &mut *try_execute!(scard_context_to_winscard_context(context));
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

    let context = &mut *try_execute!(scard_context_to_winscard_context(context));
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
    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetReaderDeviceInstanceIdW"))]
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
#[no_mangle]
pub extern "system" fn SCardAudit(_context: ScardContext, _dw_event: u32) -> ScardStatus {
    ErrorKind::UnsupportedFeature.into()
}
