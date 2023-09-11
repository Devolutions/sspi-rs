use libc::c_void;
use symbol_rename_macro::rename_symbol;
use winscard_ffi_types::{
    Handle, LpCByte, LpCGuid, LpCStr, LpCVoid, LpCWStr, LpDword, LpGuid, LpScardAtrMask, LpScardContext,
    LpScardReaderStateA, LpScardReaderStateW, LpStr, LpWStr, ScardContext, ScardStatus,
};

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

pub type SCardEstablishContextFn = extern "system" fn(u32, *const c_void, *const c_void, LpScardContext) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardReleaseContext"))]
#[no_mangle]
pub extern "system" fn SCardReleaseContext(_context: ScardContext) -> ScardStatus {
    todo!()
}

pub type SCardReleaseContextFn = extern "system" fn(ScardContext) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIsValidContext"))]
#[no_mangle]
pub extern "system" fn SCardIsValidContext(_context: ScardContext) -> ScardStatus {
    todo!()
}

pub type SCardIsValidContextFn = extern "system" fn(ScardContext) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListReaderGroupsA"))]
#[no_mangle]
pub extern "system" fn SCardListReaderGroupsA(
    _context: ScardContext,
    _gmsz_groups: LpStr,
    _pcch_groups: LpDword,
) -> ScardStatus {
    todo!()
}

pub type SCardListReaderGroupsAFn = extern "system" fn(ScardContext, LpStr, LpDword) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardListReaderGroupsW"))]
#[no_mangle]
pub extern "system" fn SCardListReaderGroupsW(
    _context: ScardContext,
    _gmsz_groups: LpWStr,
    _pcch_groups: LpDword,
) -> ScardStatus {
    todo!()
}

pub type SCardListReaderGroupsWFn = extern "system" fn(ScardContext, LpWStr, LpDword) -> ScardStatus;

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

pub type SCardListReadersAFn = extern "system" fn(ScardContext, LpCStr, LpStr, LpDword) -> ScardStatus;

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

pub type SCardListReadersWFn = extern "system" fn(ScardContext, LpCWStr, LpStr, LpDword) -> ScardStatus;

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

pub type SCardListCardsAFn = extern "system" fn(ScardContext, LpCByte, LpCGuid, u32, *mut u8, LpDword) -> ScardStatus;

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

pub type SCardListCardsWFn = extern "system" fn(ScardContext, LpCByte, LpCGuid, u32, *mut u16, LpDword) -> ScardStatus;

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

pub type SCardListInterfacesAFn = extern "system" fn(ScardContext, LpCStr, LpGuid, LpDword) -> ScardStatus;

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

pub type SCardListInterfacesWFn = extern "system" fn(ScardContext, LpCWStr, LpGuid, LpDword) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetProviderIdA"))]
#[no_mangle]
pub extern "system" fn SCardGetProviderIdA(
    _context: ScardContext,
    _sz_card: LpCStr,
    _pguid_provider_id: LpGuid,
) -> ScardStatus {
    todo!()
}

pub type SCardGetProviderIdAFn = extern "system" fn(ScardContext, LpCStr, LpGuid) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardGetProviderIdW"))]
#[no_mangle]
pub extern "system" fn SCardGetProviderIdW(
    _context: ScardContext,
    _sz_card: LpCWStr,
    _pguid_provider_id: LpGuid,
) -> ScardStatus {
    todo!()
}

pub type SCardGetProviderIdWFn = extern "system" fn(ScardContext, LpCWStr, LpGuid) -> ScardStatus;

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

pub type SCardGetCardTypeProviderNameAFn =
    extern "system" fn(ScardContext, LpCStr, u32, *mut u8, LpDword) -> ScardStatus;

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

pub type SCardGetCardTypeProviderNameWFn =
    extern "system" fn(ScardContext, LpCWStr, u32, *mut u16, LpDword) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceReaderGroupA"))]
#[no_mangle]
pub extern "system" fn SCardIntroduceReaderGroupA(_context: ScardContext, _sz_group_name: LpCStr) -> ScardStatus {
    todo!()
}

pub type SCardIntroduceReaderGroupAFn = extern "system" fn(ScardContext, LpCStr) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceReaderGroupW"))]
#[no_mangle]
pub extern "system" fn SCardIntroduceReaderGroupW(_context: ScardContext, _sz_group_name: LpCWStr) -> ScardStatus {
    todo!()
}

pub type SCardIntroduceReaderGroupWFn = extern "system" fn(ScardContext, LpCWStr) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetReaderGroupA"))]
#[no_mangle]
pub extern "system" fn SCardForgetReaderGroupA(_context: ScardContext, _sz_group_name: LpCStr) -> ScardStatus {
    todo!()
}

pub type SCardForgetReaderGroupAFn = extern "system" fn(ScardContext, LpCStr) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetReaderGroupW"))]
#[no_mangle]
pub extern "system" fn SCardForgetReaderGroupW(_context: ScardContext, _sz_group_name: LpCWStr) -> ScardStatus {
    todo!()
}

pub type SCardForgetReaderGroupWFn = extern "system" fn(ScardContext, LpCWStr) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceReaderA"))]
#[no_mangle]
pub extern "system" fn SCardIntroduceReaderA(
    _context: ScardContext,
    _sz_reader_name: LpCStr,
    _sz_device_name: LpCStr,
) -> ScardStatus {
    todo!()
}

pub type SCardIntroduceReaderAFn = extern "system" fn(ScardContext, LpCStr, LpCStr) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardIntroduceReaderW"))]
#[no_mangle]
pub extern "system" fn SCardIntroduceReaderW(
    _context: ScardContext,
    _sz_reader_name: LpCWStr,
    _sz_device_name: LpCWStr,
) -> ScardStatus {
    todo!()
}

pub type SCardIntroduceReaderWFn = extern "system" fn(ScardContext, LpCWStr, LpCWStr) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetReaderA"))]
#[no_mangle]
pub extern "system" fn SCardForgetReaderA(_context: ScardContext, _sz_reader_name: LpCStr) -> ScardStatus {
    todo!()
}

pub type SCardForgetReaderAFn = extern "system" fn(ScardContext, LpCStr) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetReaderW"))]
#[no_mangle]
pub extern "system" fn SCardForgetReaderW(_context: ScardContext, _sz_reader_name: LpCWStr) -> ScardStatus {
    todo!()
}

pub type SCardForgetReaderWFn = extern "system" fn(ScardContext, LpCWStr) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardAddReaderToGroupA"))]
#[no_mangle]
pub extern "system" fn SCardAddReaderToGroupA(
    _context: ScardContext,
    _sz_reader_name: LpCStr,
    _sz_group_name: LpCStr,
) -> ScardStatus {
    todo!()
}

pub type SCardAddReaderToGroupAFn = extern "system" fn(ScardContext, LpCStr, LpCStr) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardAddReaderToGroupW"))]
#[no_mangle]
pub extern "system" fn SCardAddReaderToGroupW(
    _context: ScardContext,
    _sz_reader_name: LpCWStr,
    _sz_group_name: LpCWStr,
) -> ScardStatus {
    todo!()
}

pub type SCardAddReaderToGroupWFn = extern "system" fn(ScardContext, LpCWStr, LpCWStr) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardRemoveReaderFromGroupA"))]
#[no_mangle]
pub extern "system" fn SCardRemoveReaderFromGroupA(
    _context: ScardContext,
    _sz_reader_name: LpCStr,
    _sz_group_name: LpCStr,
) -> ScardStatus {
    todo!()
}

pub type SCardRemoveReaderFromGroupAFn = extern "system" fn(ScardContext, LpCStr, LpCStr) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardRemoveReaderFromGroupW"))]
#[no_mangle]
pub extern "system" fn SCardRemoveReaderFromGroupW(
    _context: ScardContext,
    _sz_reader_name: LpCWStr,
    _sz_group_name: LpCWStr,
) -> ScardStatus {
    todo!()
}

pub type SCardRemoveReaderFromGroupWFn = extern "system" fn(ScardContext, LpCWStr, LpCWStr) -> ScardStatus;

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

pub type SCardIntroduceCardTypeAFn =
    extern "system" fn(ScardContext, LpCStr, LpCGuid, u32, LpCByte, LpCByte, u32) -> ScardContext;

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

pub type SCardIntroduceCardTypeWFn =
    extern "system" fn(ScardContext, LpCWStr, LpCGuid, u32, LpCByte, LpCByte, u32) -> ScardContext;

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

pub type SCardSetCardTypeProviderNameAFn = extern "system" fn(ScardContext, LpCStr, u32, LpCStr) -> ScardContext;

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

pub type SCardSetCardTypeProviderNameWFn = extern "system" fn(ScardContext, LpCWStr, u32, LpCWStr) -> ScardContext;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetCardTypeA"))]
#[no_mangle]
pub extern "system" fn SCardForgetCardTypeA(_context: ScardContext, _sz_card_name: LpCStr) -> ScardStatus {
    todo!()
}

pub type SCardForgetCardTypeAFn = extern "system" fn(ScardContext, LpCStr) -> ScardContext;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardForgetCardTypeW"))]
#[no_mangle]
pub extern "system" fn SCardForgetCardTypeW(_context: ScardContext, _sz_card_name: LpCWStr) -> ScardStatus {
    todo!()
}

pub type SCardForgetCardTypeWFn = extern "system" fn(ScardContext, LpCWStr) -> ScardContext;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardFreeMemory"))]
#[no_mangle]
pub extern "system" fn SCardFreeMemory(_context: ScardContext, _pv_mem: LpCVoid) -> ScardStatus {
    todo!()
}

pub type SCardFreeMemoryFn = extern "system" fn(ScardContext, LpCVoid) -> ScardContext;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardAccessStartedEvent"))]
#[no_mangle]
pub extern "system" fn SCardAccessStartedEvent() -> Handle {
    todo!()
}

pub type SCardAccessStartedEventFn = extern "system" fn() -> Handle;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardReleaseStartedEvent"))]
#[no_mangle]
pub extern "system" fn SCardReleaseStartedEvent() -> c_void {
    todo!()
}

pub type SCardReleaseStartedEventFn = extern "system" fn() -> c_void;

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

pub type SCardLocateCardsAFn = extern "system" fn(ScardContext, LpCStr, LpScardReaderStateA, u32) -> ScardStatus;

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

pub type SCardLocateCardsWFn = extern "system" fn(ScardContext, LpCWStr, LpScardReaderStateW, u32) -> ScardStatus;

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

pub type SCardLocateCardsByATRAFn =
    extern "system" fn(ScardContext, LpScardAtrMask, u32, LpScardReaderStateA, u32) -> ScardStatus;

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

pub type SCardLocateCardsByATRWFn =
    extern "system" fn(ScardContext, LpScardAtrMask, u32, LpScardReaderStateW, u32) -> ScardStatus;

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

pub type SCardGetStatusChangeAFn = extern "system" fn(ScardContext, u32, LpScardReaderStateA, u32) -> ScardStatus;

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

pub type SCardGetStatusChangeWFn = extern "system" fn(ScardContext, u32, LpScardReaderStateW, u32) -> ScardStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SCardCancel"))]
#[no_mangle]
pub extern "system" fn SCardCancel(_context: ScardContext) -> ScardStatus {
    todo!()
}

pub type SCardCancelFn = extern "system" fn(ScardContext) -> ScardStatus;
