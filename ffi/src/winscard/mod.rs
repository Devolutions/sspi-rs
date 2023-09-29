use ffi_types::winscard::functions::{PSCardApiFunctionTable, SCardApiFunctionTable};

use self::scard::*;
use self::scard_context::*;
use crate::utils::into_raw_ptr;

#[macro_use]
mod macros;

pub mod scard;
pub mod scard_context;
mod scard_handle;

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
        SCardDlgExtendedError,
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
