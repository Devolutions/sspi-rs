use std::borrow::Cow;
use std::ffi::CStr;
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::sync::{Mutex, OnceLock};

#[cfg(target_os = "windows")]
use ffi_types::winscard::functions::SCardApiFunctionTable;
use ffi_types::winscard::{
    LpScardAtrMask, LpScardContext, LpScardReaderStateA, LpScardReaderStateW, ScardContext, ScardStatus,
};
use ffi_types::{Handle, LpByte, LpCByte, LpCGuid, LpCStr, LpCVoid, LpCWStr, LpDword, LpGuid, LpStr, LpUuid, LpWStr};
use libc::c_void;
#[cfg(target_os = "windows")]
use symbol_rename_macro::rename_symbol;
use uuid::Uuid;
use winscard::winscard::{CurrentState, ReaderState, WinScardContext};
use winscard::{ErrorKind, ScardContext as PivCardContext, SmartCardInfo, WinScardResult};

use super::buf_alloc::{build_buf_request_type, build_buf_request_type_wide, save_out_buf, save_out_buf_wide};
use crate::utils::{c_w_str_to_string, into_raw_ptr, str_encode_utf16};
use crate::winscard::scard_handle::{
    raw_scard_context_handle_to_scard_context_handle, scard_context_to_winscard_context, WinScardContextHandle,
};
use crate::winscard::system_scard::SystemScardContext;

const ERROR_INVALID_HANDLE: u32 = 6;

// Environment variable that indicates what smart card type use. It can have the following values:
// `true` - use a system-provided smart card.
// `false` (or unset) - use an emulated smart card.
const SMART_CARD_TYPE: &str = "WINSCARD_USE_SYSTEM_SCARD";

// We need to store all active smart card contexts in one collection.
// The `SCardIsValidContext` function can be called with already released context. So, with the help
// of `SCARD_CONTEXTS` we can track all active contexts and correctly check is the passed context is valid.
// The same applies to the `SCardReleaseContext`. We need to ensure that the passed context handle was not
// released before.
static SCARD_CONTEXTS: OnceLock<Mutex<Vec<ScardContext>>> = OnceLock::new();
// This API table instance is only needed for the `SCardAccessStartedEvent` function. This function
// doesn't accept any parameters, so we need a separate initialized API table to call the system API.
#[cfg(target_os = "windows")]
static WINSCARD_API: OnceLock<SCardApiFunctionTable> = OnceLock::new();

fn save_context(context: ScardContext) {
    SCARD_CONTEXTS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .expect("SCARD_CONTEXTS mutex locking should not fail")
        .push(context)
}

fn is_present(context: ScardContext) -> bool {
    SCARD_CONTEXTS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .expect("SCARD_CONTEXTS mutex locking should not fail")
        .iter()
        .any(|ctx| *ctx == context)
}

fn release_context(context: ScardContext) {
    SCARD_CONTEXTS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .expect("SCARD_CONTEXTS mutex locking should not fail")
        .retain(|ctx| *ctx != context)
}

fn create_emulated_smart_card_context() -> WinScardResult<Box<dyn WinScardContext>> {
    Ok(Box::new(PivCardContext::new(SmartCardInfo::try_from_env()?)?))
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardEstablishContext"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardEstablishContext(
    dw_scope: u32,
    _r1: *const c_void,
    _r2: *const c_void,
    context: LpScardContext,
) -> ScardStatus {
    crate::logging::setup_logger();

    check_null!(context);

    let scard_context = if let Ok(use_system_card) = std::env::var(SMART_CARD_TYPE) {
        if use_system_card == "true" {
            info!("Creating system-provided smart card context");
            Box::new(try_execute!(SystemScardContext::establish(try_execute!(
                dw_scope.try_into()
            ))))
        } else {
            info!("Creating emulated smart card context");
            try_execute!(create_emulated_smart_card_context())
        }
    } else {
        info!("Creating emulated smart card context");
        try_execute!(create_emulated_smart_card_context())
    };

    let scard_context = WinScardContextHandle::with_scard_context(scard_context);

    let raw_ptr = into_raw_ptr(scard_context) as ScardContext;
    info!(new_established_context = ?raw_ptr);
    // SAFETY: The `context` is not null (checked above).
    unsafe {
        *context = raw_ptr;
    }
    save_context(raw_ptr);

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardReleaseContext"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardReleaseContext(context: ScardContext) -> ScardStatus {
    check_handle!(context);

    if is_present(context) {
        // SAFETY: The `context` is not zero (checked above). All other guarantees should be provided by the user.
        let _ = unsafe { Box::from_raw(context as *mut WinScardContextHandle) };
        release_context(context);

        info!("Scard context has been successfully released");

        ErrorKind::Success.into()
    } else {
        warn!(context, "Scard context is invalid or has been released");

        ERROR_INVALID_HANDLE
    }
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIsValidContext"))]
#[no_mangle]
pub unsafe extern "system" fn SCardIsValidContext(context: ScardContext) -> ScardStatus {
    if is_present(context) {
        check_handle!(context);

        let context = try_execute!(
            // SAFETY: The `context` is not zero (checked above). All other guarantees should be provided by the user.
            unsafe { scard_context_to_winscard_context(context) }
        );

        if context.is_valid() {
            ErrorKind::Success.into()
        } else {
            ERROR_INVALID_HANDLE
        }
    } else {
        debug!(context, "Provided context is not present in active contexts");

        ERROR_INVALID_HANDLE
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

    // SAFETY: The `context` value is not zero (checked above).
    let context = try_execute!(unsafe { raw_scard_context_handle_to_scard_context_handle(context) });
    // SAFETY: The `msz_readers` and `pcch_readers` parameters are not null (checked above).
    let buffer_type = try_execute!(unsafe { build_buf_request_type(msz_readers, pcch_readers) });

    let out_buf = try_execute!(context.list_readers(buffer_type));

    // SAFETY: The `msz_readers` and `pcch_readers` parameters are not null (checked above).
    try_execute!(unsafe { save_out_buf(out_buf, msz_readers, pcch_readers) });

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

    // SAFETY: The `context` value is not zero (checked above).
    let context = try_execute!(unsafe { raw_scard_context_handle_to_scard_context_handle(context) });
    // SAFETY: The `msz_readers` and `pcch_readers` parameters are not null (checked above).
    let buffer_type = try_execute!(unsafe { build_buf_request_type_wide(msz_readers, pcch_readers) });

    let out_buf = try_execute!(context.list_readers_wide(buffer_type));

    // SAFETY: The `msz_readers` and `pcch_readers` parameters are not null (checked above).
    try_execute!(unsafe { save_out_buf_wide(out_buf, msz_readers, pcch_readers) });

    ErrorKind::Success.into()
}

unsafe fn guids_to_uuids(guids: LpCGuid, len: u32) -> WinScardResult<Option<Vec<Uuid>>> {
    Ok(if guids.is_null() {
        None
    } else {
        Some(
            // SAFETY: The `guids` parameter is not null (checked above).
            unsafe { from_raw_parts(guids, len.try_into()?) }
                .iter()
                .map(|id| Uuid::from_fields(id.data1, id.data2, id.data3, &id.data4))
                .collect::<Vec<_>>(),
        )
    })
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListCardsA"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardListCardsA(
    context: ScardContext,
    pb_atr: LpCByte,
    rgquid_nterfaces: LpCGuid,
    cguid_interface_count: u32,
    msz_cards: *mut u8,
    pcch_cards: LpDword,
) -> ScardStatus {
    use std::slice::from_raw_parts;

    check_handle!(context);
    check_null!(msz_cards);
    check_null!(pcch_cards);

    // SAFETY: The `context` value is not zero (checked above).
    let context = try_execute!(unsafe { raw_scard_context_handle_to_scard_context_handle(context) });
    // SAFETY: The `msz_cards` and `pcch_cards` parameters are not null (checked above).
    let buffer_type = try_execute!(unsafe { build_buf_request_type(msz_cards, pcch_cards) });
    let atr = if pb_atr.is_null() {
        None
    } else {
        // SAFETY: The `pb_atr` parameter is not null (checked above).
        Some(unsafe { from_raw_parts(pb_atr, 32) })
    };
    let required_interfaces = try_execute!(
        // SAFETY: The `rgquid_nterfaces` parameter is checked inside the function.
        // All other guarantees should be provided by the user.
        unsafe { guids_to_uuids(rgquid_nterfaces, cguid_interface_count) }
    );

    let out_buf = try_execute!(context.list_cards(atr, required_interfaces.as_deref(), buffer_type));

    // SAFETY: The `msz_cards` and `pcch_cards` parameters are not null (checked above).
    try_execute!(unsafe { save_out_buf(out_buf, msz_cards, pcch_cards) });

    ErrorKind::UnsupportedFeature.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListCardsW"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardListCardsW(
    context: ScardContext,
    pb_atr: LpCByte,
    rgquid_nterfaces: LpCGuid,
    cguid_interface_count: u32,
    msz_cards: *mut u16,
    pcch_cards: LpDword,
) -> ScardStatus {
    use std::slice::from_raw_parts;

    check_handle!(context);
    check_null!(msz_cards);
    check_null!(pcch_cards);

    // SAFETY: The `context` value is not zero (checked above).
    let context = try_execute!(unsafe { raw_scard_context_handle_to_scard_context_handle(context) });
    // SAFETY: The `msz_cards` and `pcch_cards` parameters are not null (checked above).
    let buffer_type = try_execute!(unsafe { build_buf_request_type_wide(msz_cards, pcch_cards) });
    let atr = if pb_atr.is_null() {
        None
    } else {
        // SAFETY: The `pb_atr` parameter is not null (checked above).
        Some(unsafe { from_raw_parts(pb_atr, 32) })
    };
    let required_interfaces = try_execute!(
        // SAFETY: The `rgquid_nterfaces` parameter is checked inside the function.
        // All other guarantees should be provided by the user.
        unsafe { guids_to_uuids(rgquid_nterfaces, cguid_interface_count) }
    );

    let out_buf = try_execute!(context.list_cards_wide(atr, required_interfaces.as_deref(), buffer_type));

    // SAFETY: The `msz_cards` and `pcch_cards` parameters are not null (checked above).
    try_execute!(unsafe { save_out_buf_wide(out_buf, msz_cards, pcch_cards) });

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
    sz_card_name: LpCStr,
    dw_provide_id: u32,
    szProvider: *mut u8,
    pcch_provider: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(sz_card_name);
    check_null!(szProvider);
    check_null!(pcch_provider);

    let card_name = try_execute!(
        // SAFETY: It's safe to construct a slice because the `sz_card_name` is not null (checked above).
        // All other guarantees should be provided by the user.
        unsafe { CStr::from_ptr(sz_card_name as *const _) }.to_str(),
        ErrorKind::InvalidParameter
    );

    // SAFETY: The `context` value is not zero (checked above).
    let context_handle = try_execute!(unsafe { raw_scard_context_handle_to_scard_context_handle(context) });

    let context = context_handle.scard_context();
    let provider_name =
        try_execute!(context.get_card_type_provider_name(card_name, try_execute!(dw_provide_id.try_into())))
            .to_string();

    // SAFETY: The `szProvider` and `pcch_provider` parameters are not null (checked above).
    let buffer_type = try_execute!(unsafe { build_buf_request_type(szProvider, pcch_provider) });
    let out_buf = try_execute!(context_handle.write_to_out_buf(provider_name.as_bytes(), buffer_type));

    // SAFETY: The `szProvider` and `pcch_provider` parameters are not null (checked above).
    try_execute!(unsafe { save_out_buf(out_buf, szProvider, pcch_provider) });

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetCardTypeProviderNameW"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardGetCardTypeProviderNameW(
    context: ScardContext,
    sz_card_name: LpCWStr,
    dw_provide_id: u32,
    szProvider: *mut u16,
    pcch_provider: LpDword,
) -> ScardStatus {
    check_handle!(context);
    check_null!(sz_card_name);
    check_null!(szProvider);
    check_null!(pcch_provider);

    // SAFETY: The `sz_card_name` parameter is not null (checked above).
    let card_name = unsafe { c_w_str_to_string(sz_card_name) };

    // SAFETY: The `context` value is not zero (checked above).
    let context_handle = try_execute!(unsafe { raw_scard_context_handle_to_scard_context_handle(context) });

    let context = context_handle.scard_context();
    let provider_name =
        try_execute!(context.get_card_type_provider_name(&card_name, try_execute!(dw_provide_id.try_into())));
    let wide_provider_name = str_encode_utf16(provider_name.as_ref());

    // SAFETY: The `szProvider` and `pcch_provider` parameters are not null (checked above).
    let buffer_type = try_execute!(unsafe { build_buf_request_type_wide(szProvider, pcch_provider) });
    let out_buf = try_execute!(context_handle.write_to_out_buf(&wide_provider_name, buffer_type));

    // SAFETY: The `szProvider` and `pcch_provider` parameters are not null (checked above).
    try_execute!(unsafe { save_out_buf_wide(out_buf, szProvider, pcch_provider) });

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
    check_handle!(context);

    // SAFETY: The `context` value is not zero (checked above).
    if let Ok(context) = unsafe { raw_scard_context_handle_to_scard_context_handle(context) } {
        if context.free_buffer(pv_mem) {
            info!("Allocated buffer successfully freed");
        } else {
            warn!(?pv_mem, "Attempt to free unknown buffer");
        }

        ErrorKind::Success.into()
    } else {
        ErrorKind::InvalidHandle.into()
    }
}

// This handle exists up to the end of the program and never freed.
// We use created event to return its handle from the `SCardAccessStartedEvent` function.
// Note. If the `SCardAccessStartedEvent` frunction is not be called, the event will not be created.
#[cfg(target_os = "windows")]
static START_EVENT_HANDLE: OnceLock<windows_sys::Win32::Foundation::HANDLE> = OnceLock::new();

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardAccessStartedEvent"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardAccessStartedEvent() -> Handle {
    #[cfg(target_os = "windows")]
    {
        // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardaccessstartedevent
        // The `SCardAccessStartedEvent` function returns an event handle when an event signals that
        // the smart card resource manager is started. The event-object handle can be specified in a call
        // to one of the wait functions.

        use crate::winscard::system_scard::init_scard_api_table;

        if std::env::var(SMART_CARD_TYPE)
            .and_then(|use_system_card| Ok(use_system_card == "true"))
            .unwrap_or_default()
        {
            // Use system-provided smart card.
            let api =
                WINSCARD_API.get_or_init(|| init_scard_api_table().expect("winscard module loading should not fail"));

            // SAFETY: The `api` is initialized, so it's safe to call this function.
            unsafe { (api.SCardAccessStartedEvent)() }
        } else {
            // Use emulated smart card.
            //
            // We create the event once for the entire process and keep it like a singleton in the "signaled" state.
            // We assume we're always ready for our virtual smart cards. Moreover, we don't use reference counters
            // because we are always in a ready (signaled) state and have only one handle for the entire process.
            *START_EVENT_HANDLE.get_or_init(|| {
                use std::ptr::null;

                use windows_sys::Win32::Foundation::GetLastError;
                use windows_sys::Win32::System::Threading::CreateEventA;

                // SAFETY: All parameters are correct.
                let handle = unsafe { CreateEventA(null(), 1, 1, null()) };
                if handle == 0 {
                    error!(
                        "Unable to create event: returned event handle is null. Last error: {}",
                        // SAFETY: it's safe to call this function.
                        unsafe { GetLastError() }
                    );
                }
                handle
            })
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // We support the `SCardAccessStartedEvent` function only on Windows OS. Reason:
        // On non-Windows OS we use pcsc-lite API that doesn't have the `SCardAccessStartedEvent` function.
        // Thus, we don't need it there.
        //
        // The function returns an event HANDLE if it succeeds or NULL if it fails.
        0
    }
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardReleaseStartedEvent"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardReleaseStartedEvent() {
    #[cfg(target_os = "windows")]
    {
        use crate::winscard::system_scard::init_scard_api_table;

        if std::env::var(SMART_CARD_TYPE)
            .and_then(|use_system_card| Ok(use_system_card == "true"))
            .unwrap_or_default()
        {
            // Use system-provided smart card.
            let api =
                WINSCARD_API.get_or_init(|| init_scard_api_table().expect("winscard module loading should not fail"));

            // SAFETY: The `api` is initialized, so it's safe to call this function.
            unsafe { (api.SCardReleaseStartedEvent)() }
        } else {
            use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};

            // Use emulated smart card.
            //
            // We create the event once for the entire process and keep it like a singleton in the "signaled" state.
            // We assume we're always ready for our virtual smart cards. Moreover, we don't use reference counters
            // because we are always in a ready (signaled) state and have only one handle for the entire process.
            let event_handle = *START_EVENT_HANDLE.get_or_init(|| {
                use std::ptr::null;

                use windows_sys::Win32::System::Threading::CreateEventA;

                // SAFETY: All parameters are correct.
                let handle = unsafe { CreateEventA(null(), 1, 1, null()) };
                if handle == 0 {
                    error!(
                        "Unable to create event: returned event handle is null. Last error: {}",
                        // SAFETY: it's safe to call this function.
                        unsafe { GetLastError() }
                    );
                }
                handle
            });
            // SAFETY: It's safe to close the handle.
            if unsafe { CloseHandle(event_handle) } == 0 {
                error!(
                    "Cannot close the event handle. List error: {}",
                    // SAFETY: it's safe to call this function.
                    unsafe { GetLastError() }
                );
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // We support the `SCardReleaseStartedEvent` function only on Windows OS. Reason:
        // On non-Windows OS we use pcsc-lite API that doesn't have the `SCardReleaseStartedEvent` function.
        // Thus, we don't need it there.
    }
}

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
    dw_timeout: u32,
    rg_reader_states: LpScardReaderStateA,
    c_readers: u32,
) -> ScardStatus {
    check_handle!(context);
    check_null!(rg_reader_states);

    // SAFETY: The `context` value is not zero (checked above).
    let context = try_execute!(unsafe { scard_context_to_winscard_context(context) });

    // SAFETY: The `rg_reader_states` parameter is not null (checked above).
    let c_reader_states = unsafe {
        from_raw_parts_mut(
            rg_reader_states,
            try_execute!(c_readers.try_into(), ErrorKind::InsufficientBuffer),
        )
    };
    let mut reader_states = try_execute!(c_reader_states
        .iter()
        .map(|c_reader| {
            check_null!(c_reader.sz_reader, "reader name in reader state");

            Ok(ReaderState {
                // SAFETY: The reader name should not be null (checked above). All other guarantees
                // should be provided by the user.
                reader_name: unsafe { CStr::from_ptr(c_reader.sz_reader as *const _) }.to_string_lossy(),
                user_data: c_reader.pv_user_data as usize,
                current_state: CurrentState::from_bits(c_reader.dw_current_state).unwrap_or_default(),
                event_state: CurrentState::from_bits(c_reader.dw_event_state).unwrap_or_default(),
                atr_len: c_reader.cb_atr.try_into()?,
                atr: c_reader.rgb_atr,
            })
        })
        .collect::<Result<Vec<_>, winscard::Error>>());
    try_execute!(context.get_status_change(dw_timeout, &mut reader_states));

    for (reader_state, c_reader_state) in reader_states.iter().zip(c_reader_states.iter_mut()) {
        c_reader_state.dw_event_state = reader_state.event_state.bits();
        c_reader_state.cb_atr = try_execute!(reader_state.atr_len.try_into(), ErrorKind::InternalError);
        c_reader_state.rgb_atr.copy_from_slice(&reader_state.atr);
    }

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetStatusChangeW"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardGetStatusChangeW(
    context: ScardContext,
    dw_timeout: u32,
    rg_reader_states: LpScardReaderStateW,
    c_readers: u32,
) -> ScardStatus {
    check_handle!(context);
    check_null!(rg_reader_states);

    // SAFETY: The `context` value is not zero (checked above).
    let context = try_execute!(unsafe { scard_context_to_winscard_context(context) });

    // SAFETY: The `rg_reader_states` parameter is not null (checked above).
    let c_reader_states = unsafe {
        from_raw_parts_mut(
            rg_reader_states,
            try_execute!(c_readers.try_into(), ErrorKind::InsufficientBuffer),
        )
    };
    let mut reader_states = try_execute!(c_reader_states
        .iter()
        .map(|c_reader| {
            check_null!(c_reader.sz_reader, "reader name in reader state");

            Ok(ReaderState {
                // SAFETY: The reader name should not be null (checked above). All other guarantees
                // should be provided by the user.
                reader_name: Cow::Owned(unsafe { c_w_str_to_string(c_reader.sz_reader) }),
                user_data: c_reader.pv_user_data as usize,
                current_state: CurrentState::from_bits(c_reader.dw_current_state).unwrap_or_default(),
                event_state: CurrentState::from_bits(c_reader.dw_event_state).unwrap_or_default(),
                atr_len: c_reader.cb_atr.try_into()?,
                atr: c_reader.rgb_atr,
            })
        })
        .collect::<Result<Vec<_>, winscard::Error>>());
    try_execute!(context.get_status_change(dw_timeout, &mut reader_states));

    for (reader_state, c_reader_state) in reader_states.iter().zip(c_reader_states.iter_mut()) {
        c_reader_state.dw_event_state = reader_state.event_state.bits();
        c_reader_state.cb_atr = try_execute!(reader_state.atr_len.try_into(), ErrorKind::InternalError);
        c_reader_state.rgb_atr.copy_from_slice(&reader_state.atr);
    }

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardCancel"))]
#[instrument(ret)]
#[no_mangle]
pub extern "system" fn SCardCancel(context: ScardContext) -> ScardStatus {
    check_handle!(context);

    // SAFETY: The `context` value is not zero (checked above). All other guarantees should be provided by the user.
    let context = try_execute!(unsafe { scard_context_to_winscard_context(context) });
    try_execute!(context.cancel());

    ErrorKind::Success.into()
}

unsafe fn read_cache(
    context: ScardContext,
    card_identifier: LpUuid,
    freshness_counter: u32,
    lookup_name: &str,
    data: LpByte,
    data_len: LpDword,
) -> WinScardResult<()> {
    check_handle!(context, "scard context handle");
    check_null!(card_identifier, "scard card identifier");
    check_null!(data_len, "data buffer length");

    // SAFETY: The `context` value is not zero (checked above).
    let context = unsafe { raw_scard_context_handle_to_scard_context_handle(context) }?;

    // SAFETY: The `card_identifier` parameter is not null (checked above).
    let card_id = unsafe {
        Uuid::from_fields(
            (*card_identifier).data1,
            (*card_identifier).data2,
            (*card_identifier).data3,
            &(*card_identifier).data4,
        )
    };
    // SAFETY: It's safe to call this function because the `data` parameter is allowed to be null
    // and the `data_len` parameter cannot be null (checked above).
    let buffer_type = unsafe { build_buf_request_type(data, data_len) }?;

    let out_buf = context.read_cache(card_id, freshness_counter, lookup_name, buffer_type)?;

    // SAFETY: It's safe to call this function because all parameters are checked above.
    unsafe { save_out_buf(out_buf, data, data_len) }
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardReadCacheA"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardReadCacheA(
    context: ScardContext,
    card_identifier: LpUuid,
    freshness_counter: u32,
    lookup_name: LpStr,
    data: LpByte,
    data_len: LpDword,
) -> ScardStatus {
    check_null!(lookup_name);

    let lookup_name = try_execute!(
        // SAFETY: The `lookup_name` parameter is not null (checked above).
        unsafe { CStr::from_ptr(lookup_name as *const _) }.to_str(),
        ErrorKind::InvalidParameter
    );
    // SAFETY: The `lookup_name` parameter is type checked. All other parameters are checked inside the function.
    try_execute!(unsafe { read_cache(context, card_identifier, freshness_counter, lookup_name, data, data_len,) });

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardReadCacheW"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardReadCacheW(
    context: ScardContext,
    card_identifier: LpUuid,
    freshness_counter: u32,
    lookup_name: LpWStr,
    data: LpByte,
    data_len: LpDword,
) -> ScardStatus {
    check_null!(lookup_name);

    // SAFETY: The `lookup_name` parameter is not null (checked above).
    let lookup_name = unsafe { c_w_str_to_string(lookup_name) };
    try_execute!(
        // SAFETY: The `lookup_name` parameter is type checked. All other parameters are checked inside the function.
        unsafe {
            read_cache(
                context,
                card_identifier,
                freshness_counter,
                &lookup_name,
                data,
                data_len,
            )
        }
    );

    ErrorKind::Success.into()
}

unsafe fn write_cache(
    context: ScardContext,
    card_identifier: LpUuid,
    freshness_counter: u32,
    lookup_name: &str,
    data: LpCByte,
    data_len: u32,
) -> WinScardResult<()> {
    check_handle!(context, "scard context handle");
    check_null!(card_identifier, "card identified");
    check_null!(data, "cache data buffer");

    // SAFETY: The `card_identifier` parameter is not null (checked above).
    let card_id = unsafe {
        Uuid::from_fields(
            (*card_identifier).data1,
            (*card_identifier).data2,
            (*card_identifier).data3,
            &(*card_identifier).data4,
        )
    };

    // SAFETY: The `context` value is not zero (checked above).
    let context = unsafe { scard_context_to_winscard_context(context) }?;
    // SAFETY: The `data` parameter is not null (checked above).
    let data = unsafe { from_raw_parts(data, data_len.try_into()?) }.to_vec();

    context.write_cache(card_id, freshness_counter, lookup_name.to_owned(), data)
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardWriteCacheA"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardWriteCacheA(
    context: ScardContext,
    card_identifier: LpUuid,
    freshness_counter: u32,
    lookup_name: LpStr,
    data: LpCByte,
    data_len: u32,
) -> ScardStatus {
    check_null!(lookup_name);

    let lookup_name = try_execute!(
        // SAFETY: The `lookup_name` parameter is not null (checked above).
        unsafe { CStr::from_ptr(lookup_name as *const _) }.to_str(),
        ErrorKind::InvalidParameter
    );
    // SAFETY: The `lookup_name` parameter is type checked. All other parameters are checked inside the function
    try_execute!(unsafe { write_cache(context, card_identifier, freshness_counter, lookup_name, data, data_len,) });

    ErrorKind::Success.into()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardWriteCacheW"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardWriteCacheW(
    context: ScardContext,
    card_identifier: LpUuid,
    freshness_counter: u32,
    lookup_name: LpWStr,
    data: LpCByte,
    data_len: u32,
) -> ScardStatus {
    check_null!(lookup_name);

    // SAFETY: The `lookup_name` parameter is not null (checked above).
    let lookup_name = unsafe { c_w_str_to_string(lookup_name) };
    // SAFETY: The `lookup_name` parameter is type checked. All other parameters are checked inside the function
    try_execute!(unsafe {
        write_cache(
            context,
            card_identifier,
            freshness_counter,
            &lookup_name,
            data,
            data_len,
        )
    });

    ErrorKind::Success.into()
}

unsafe fn get_reader_icon(
    context: ScardContext,
    reader_name: &str,
    pb_icon: LpByte,
    pcb_icon: LpDword,
) -> WinScardResult<()> {
    check_handle!(context, "scard context handle");
    // `pb_icon` can be null.
    check_null!(pcb_icon, "pcb_icon");

    // SAFETY: The `context` value is not zero (checked above). All other guarantees should be provided by the user.
    let context = unsafe { raw_scard_context_handle_to_scard_context_handle(context) }?;

    // SAFETY: It's safe to call this function because the `pb_icon` parameter is allowed to be null
    // and the `pcb_icon` parameter cannot be null (checked above).
    let buffer_type = unsafe { build_buf_request_type(pb_icon, pcb_icon) }?;

    let out_buf = context.get_reader_icon(reader_name, buffer_type)?;

    // SAFETY: It's safe to call this function because all parameters are checked above.
    unsafe { save_out_buf(out_buf, pb_icon, pcb_icon) }?;

    Ok(())
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
    check_null!(sz_reader_name);

    let reader_name = try_execute!(
        // SAFETY: The `sz_reader_name` parameter is not null (checked above).
        unsafe { CStr::from_ptr(sz_reader_name as *const _) }.to_str(),
        ErrorKind::InvalidParameter
    );

    try_execute!(
        // SAFETY: The `reader_name` parameter is type checked. All other parameters are checked inside the function
        unsafe { get_reader_icon(context, reader_name, pb_icon, pcb_icon) }
    );

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
    check_null!(sz_reader_name);

    // SAFETY: The `sz_reader_name` parameter is not null (checked above).
    let reader_name = unsafe { c_w_str_to_string(sz_reader_name) };

    try_execute!(
        // SAFETY: The `reader_name` parameter is type checked. All other parameters are checked inside the function.
        unsafe { get_reader_icon(context, &reader_name, pb_icon, pcb_icon) }
    );

    ErrorKind::Success.into()
}

unsafe fn get_device_type_id(
    context: ScardContext,
    reader_name: &str,
    pdw_device_type_id: LpDword,
) -> WinScardResult<()> {
    check_handle!(context, "scard context handle");
    check_null!(pdw_device_type_id, "pdw_device_type_id");

    // SAFETY: The `context` value is not zero (checked above).
    let context = unsafe { scard_context_to_winscard_context(context) }?;

    // SAFETY: The `pdw_device_type_id` parameter is not null (checked above).
    unsafe {
        *pdw_device_type_id = context.device_type_id(reader_name)?.into();
    }

    Ok(())
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetDeviceTypeIdA"))]
#[instrument(ret)]
#[no_mangle]
pub unsafe extern "system" fn SCardGetDeviceTypeIdA(
    context: ScardContext,
    sz_reader_name: LpCStr,
    pdw_device_type_id: LpDword,
) -> ScardStatus {
    check_null!(sz_reader_name);

    let reader_name = try_execute!(
        // SAFETY: The `sz_reader_name` parameter is not null (checked above).
        unsafe { CStr::from_ptr(sz_reader_name as *const _) }.to_str(),
        ErrorKind::InvalidParameter
    );

    try_execute!(
        // SAFETY: `context` and `pdw_device_type_id` parameters are checked inside the function.
        // `reader_name` is type checked.
        unsafe { get_device_type_id(context, reader_name, pdw_device_type_id) }
    );

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
    check_null!(sz_reader_name);

    // SAFETY: The `sz_reader_name` parameter is not null (checked above).
    let reader_name = unsafe { c_w_str_to_string(sz_reader_name) };

    try_execute!(
        // SAFETY: `context` and `pdw_device_type_id` parameters are checked inside the function.
        // `reader_name` is type checked.
        unsafe { get_device_type_id(context, &reader_name, pdw_device_type_id) }
    );

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
