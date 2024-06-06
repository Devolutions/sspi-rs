use ffi_types::winscard::functions::{PSCardApiFunctionTable, SCardApiFunctionTable};
use ffi_types::winscard::ScardIoRequest;
use winscard::winscard::Protocol;

use self::scard::*;
use self::scard_context::*;
use crate::utils::into_raw_ptr;

#[macro_use]
mod macros;
mod buf_alloc;
pub mod pcsc_lite;
pub mod scard;
pub mod scard_context;
mod scard_handle;
mod system_scard;

// The constants below are not documented anywhere and were discovered during debugging.
// Related example: https://github.com/bluetech/pcsc-rust/blob/b397cc8e3834a1dc791631105f37f34d321c8696/pcsc/src/lib.rs#L605-L613
#[no_mangle]
pub static Rust_g_rgSCardT1Pci: ScardIoRequest = ScardIoRequest {
    dw_protocol: Protocol::T1.bits(),
    cb_pci_length: 8,
};

#[no_mangle]
pub static Rust_g_rgSCardT0Pci: ScardIoRequest = ScardIoRequest {
    dw_protocol: Protocol::T0.bits(),
    cb_pci_length: 8,
};

#[no_mangle]
pub static Rust_g_rgSCardRawPci: ScardIoRequest = ScardIoRequest {
    dw_protocol: Protocol::Raw.bits(),
    cb_pci_length: 8,
};

pub extern "system" fn GetSCardApiFunctionTable() -> PSCardApiFunctionTable {
    crate::logging::setup_logger();

    into_raw_ptr(SCardApiFunctionTable {
        dw_version: 0,
        dw_flags: 0,

        SCardEstablishContext,
        SCardReleaseContext,
        SCardIsValidContext,
        SCardListReaderGroupsA,
        SCardListReaderGroupsW,
        SCardListReadersA,
        SCardListReadersW,
        SCardListCardsA,
        SCardListCardsW,
        SCardListInterfacesA,
        SCardListInterfacesW,
        SCardGetProviderIdA,
        SCardGetProviderIdW,
        SCardGetCardTypeProviderNameA,
        SCardGetCardTypeProviderNameW,
        SCardIntroduceReaderGroupA,
        SCardIntroduceReaderGroupW,
        SCardForgetReaderGroupA,
        SCardForgetReaderGroupW,
        SCardIntroduceReaderA,
        SCardIntroduceReaderW,
        SCardForgetReaderA,
        SCardForgetReaderW,
        SCardAddReaderToGroupA,
        SCardAddReaderToGroupW,
        SCardRemoveReaderFromGroupA,
        SCardRemoveReaderFromGroupW,
        SCardIntroduceCardTypeA,
        SCardIntroduceCardTypeW,
        SCardSetCardTypeProviderNameA,
        SCardSetCardTypeProviderNameW,
        SCardFreeMemory,
        SCardAccessStartedEvent,
        SCardReleaseStartedEvent,
        SCardLocateCardsA,
        SCardLocateCardsW,
        SCardLocateCardsByATRA,
        SCardLocateCardsByATRW,
        SCardGetStatusChangeA,
        SCardGetStatusChangeW,
        SCardCancel,
        SCardConnectA,
        SCardConnectW,
        SCardReconnect,
        SCardDisconnect,
        SCardBeginTransaction,
        SCardEndTransaction,
        SCardCancelTransaction,
        SCardState,
        SCardStatusA,
        SCardStatusW,
        SCardTransmit,
        SCardGetTransmitCount,
        SCardControl,
        SCardGetAttrib,
        SCardSetAttrib,
        SCardUIDlgSelectCardA,
        SCardUIDlgSelectCardW,
        GetOpenCardNameA,
        GetOpenCardNameW,
        SCardReadCacheA,
        SCardReadCacheW,
        SCardWriteCacheA,
        SCardWriteCacheW,
        SCardGetReaderIconA,
        SCardGetReaderIconW,
        SCardGetDeviceTypeIdA,
        SCardGetDeviceTypeIdW,
        SCardGetReaderDeviceInstanceIdA,
        SCardGetReaderDeviceInstanceIdW,
        SCardListReadersWithDeviceInstanceIdA,
        SCardListReadersWithDeviceInstanceIdW,
        SCardAudit,
    })
}
