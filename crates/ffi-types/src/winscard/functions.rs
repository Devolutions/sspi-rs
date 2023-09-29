use std::ffi::c_void;

use super::{
    LpOpenCardNameA, LpOpenCardNameExA, LpOpenCardNameExW, LpOpenCardNameW, LpScardAtrMask, LpScardContext,
    LpScardHandle, LpScardIoRequest, LpScardReaderStateA, LpScardReaderStateW, ScardContext, ScardHandle, ScardStatus,
};
use crate::{
    Handle, LpByte, LpCByte, LpCGuid, LpCStr, LpCVoid, LpCWStr, LpDword, LpGuid, LpStr, LpUuid, LpVoid, LpWStr,
};

pub type SCardEstablishContextFn = extern "system" fn(u32, *const c_void, *const c_void, LpScardContext) -> ScardStatus;
pub type SCardReleaseContextFn = extern "system" fn(ScardContext) -> ScardStatus;
pub type SCardIsValidContextFn = unsafe extern "system" fn(ScardContext) -> ScardStatus;
pub type SCardListReaderGroupsAFn = extern "system" fn(ScardContext, LpStr, LpDword) -> ScardStatus;
pub type SCardListReaderGroupsWFn = extern "system" fn(ScardContext, LpWStr, LpDword) -> ScardStatus;
pub type SCardListReadersAFn = extern "system" fn(ScardContext, LpCStr, LpStr, LpDword) -> ScardStatus;
pub type SCardListReadersWFn = extern "system" fn(ScardContext, LpCWStr, LpWStr, LpDword) -> ScardStatus;
pub type SCardListCardsAFn = extern "system" fn(ScardContext, LpCByte, LpCGuid, u32, *mut u8, LpDword) -> ScardStatus;
pub type SCardListCardsWFn = extern "system" fn(ScardContext, LpCByte, LpCGuid, u32, *mut u16, LpDword) -> ScardStatus;
pub type SCardListInterfacesAFn = extern "system" fn(ScardContext, LpCStr, LpGuid, LpDword) -> ScardStatus;
pub type SCardListInterfacesWFn = extern "system" fn(ScardContext, LpCWStr, LpGuid, LpDword) -> ScardStatus;
pub type SCardGetProviderIdAFn = extern "system" fn(ScardContext, LpCStr, LpGuid) -> ScardStatus;
pub type SCardGetProviderIdWFn = extern "system" fn(ScardContext, LpCWStr, LpGuid) -> ScardStatus;
pub type SCardGetCardTypeProviderNameAFn =
    extern "system" fn(ScardContext, LpCStr, u32, *mut u8, LpDword) -> ScardStatus;
pub type SCardGetCardTypeProviderNameWFn =
    extern "system" fn(ScardContext, LpCWStr, u32, *mut u16, LpDword) -> ScardStatus;
pub type SCardIntroduceReaderGroupAFn = extern "system" fn(ScardContext, LpCStr) -> ScardStatus;
pub type SCardIntroduceReaderGroupWFn = extern "system" fn(ScardContext, LpCWStr) -> ScardStatus;
pub type SCardForgetReaderGroupAFn = extern "system" fn(ScardContext, LpCStr) -> ScardStatus;
pub type SCardForgetReaderGroupWFn = extern "system" fn(ScardContext, LpCWStr) -> ScardStatus;
pub type SCardIntroduceReaderAFn = extern "system" fn(ScardContext, LpCStr, LpCStr) -> ScardStatus;
pub type SCardIntroduceReaderWFn = extern "system" fn(ScardContext, LpCWStr, LpCWStr) -> ScardStatus;
pub type SCardForgetReaderAFn = extern "system" fn(ScardContext, LpCStr) -> ScardStatus;
pub type SCardForgetReaderWFn = extern "system" fn(ScardContext, LpCWStr) -> ScardStatus;
pub type SCardAddReaderToGroupAFn = extern "system" fn(ScardContext, LpCStr, LpCStr) -> ScardStatus;
pub type SCardAddReaderToGroupWFn = extern "system" fn(ScardContext, LpCWStr, LpCWStr) -> ScardStatus;
pub type SCardRemoveReaderFromGroupAFn = extern "system" fn(ScardContext, LpCStr, LpCStr) -> ScardStatus;
pub type SCardRemoveReaderFromGroupWFn = extern "system" fn(ScardContext, LpCWStr, LpCWStr) -> ScardStatus;
pub type SCardIntroduceCardTypeAFn =
    extern "system" fn(ScardContext, LpCStr, LpCGuid, LpCGuid, u32, LpCByte, LpCByte, u32) -> ScardStatus;
pub type SCardIntroduceCardTypeWFn =
    extern "system" fn(ScardContext, LpCWStr, LpCGuid, LpCGuid, u32, LpCByte, LpCByte, u32) -> ScardStatus;
pub type SCardSetCardTypeProviderNameAFn = extern "system" fn(ScardContext, LpCStr, u32, LpCStr) -> ScardStatus;
pub type SCardSetCardTypeProviderNameWFn = extern "system" fn(ScardContext, LpCWStr, u32, LpCWStr) -> ScardStatus;
pub type SCardForgetCardTypeAFn = extern "system" fn(ScardContext, LpCStr) -> ScardStatus;
pub type SCardForgetCardTypeWFn = extern "system" fn(ScardContext, LpCWStr) -> ScardStatus;
pub type SCardFreeMemoryFn = extern "system" fn(ScardContext, LpCVoid) -> ScardStatus;
pub type SCardAccessStartedEventFn = extern "system" fn() -> Handle;
pub type SCardReleaseStartedEventFn = extern "system" fn();
pub type SCardLocateCardsAFn = extern "system" fn(ScardContext, LpCStr, LpScardReaderStateA, u32) -> ScardStatus;
pub type SCardLocateCardsWFn = extern "system" fn(ScardContext, LpCWStr, LpScardReaderStateW, u32) -> ScardStatus;
pub type SCardLocateCardsByATRAFn =
    extern "system" fn(ScardContext, LpScardAtrMask, u32, LpScardReaderStateA, u32) -> ScardStatus;
pub type SCardLocateCardsByATRWFn =
    extern "system" fn(ScardContext, LpScardAtrMask, u32, LpScardReaderStateW, u32) -> ScardStatus;
pub type SCardGetStatusChangeAFn = extern "system" fn(ScardContext, u32, LpScardReaderStateA, u32) -> ScardStatus;
pub type SCardGetStatusChangeWFn = extern "system" fn(ScardContext, u32, LpScardReaderStateW, u32) -> ScardStatus;
pub type SCardCancelFn = extern "system" fn(ScardContext) -> ScardStatus;
pub type SCardReadCacheAFn = extern "system" fn(ScardContext, LpUuid, u32, LpStr, LpByte, LpDword) -> ScardStatus;
pub type SCardReadCacheWFn = extern "system" fn(ScardContext, LpUuid, u32, LpWStr, LpByte, LpDword) -> ScardStatus;
pub type SCardWriteCacheAFn = extern "system" fn(ScardContext, LpUuid, u32, LpStr, LpByte, u32) -> ScardStatus;
pub type SCardWriteCacheWFn = extern "system" fn(ScardContext, LpUuid, u32, LpWStr, LpByte, u32) -> ScardStatus;
pub type SCardGetReaderIconAFn = extern "system" fn(ScardContext, LpCStr, LpByte, LpDword) -> ScardStatus;
pub type SCardGetReaderIconWFn = extern "system" fn(ScardContext, LpCWStr, LpByte, LpDword) -> ScardStatus;
pub type SCardGetReaderDeviceInstanceIdAFn = extern "system" fn(ScardContext, LpCStr, LpStr, LpDword) -> ScardStatus;
pub type SCardGetReaderDeviceInstanceIdWFn = extern "system" fn(ScardContext, LpCWStr, LpWStr, LpDword) -> ScardStatus;
pub type SCardListReadersWithDeviceInstanceIdAFn =
    extern "system" fn(ScardContext, LpCStr, LpStr, LpDword) -> ScardStatus;
pub type SCardListReadersWithDeviceInstanceIdWFn =
    extern "system" fn(ScardContext, LpCWStr, LpWStr, LpDword) -> ScardStatus;
pub type SCardAuditFn = extern "system" fn(ScardContext, u32) -> ScardStatus;
pub type SCardConnectAFn = extern "system" fn(ScardContext, LpCStr, u32, u32, LpScardHandle, LpDword) -> ScardStatus;
pub type SCardConnectWFn = extern "system" fn(ScardContext, LpCWStr, u32, u32, LpScardHandle, LpDword) -> ScardStatus;
pub type SCardReconnectFn = extern "system" fn(ScardHandle, u32, u32, u32, LpDword) -> ScardStatus;
pub type SCardDisconnectFn = extern "system" fn(ScardHandle, u32) -> ScardStatus;
pub type SCardBeginTransactionFn = unsafe extern "system" fn(ScardHandle) -> ScardStatus;
pub type SCardEndTransactionFn = unsafe extern "system" fn(ScardHandle, u32) -> ScardStatus;
pub type SCardCancelTransactionFn = extern "system" fn(ScardHandle) -> ScardStatus;
pub type SCardStateFn = extern "system" fn(ScardHandle, LpDword, LpDword, LpByte, LpDword) -> ScardStatus;
pub type SCardStatusAFn =
    extern "system" fn(ScardHandle, LpStr, LpDword, LpDword, LpDword, LpByte, LpDword) -> ScardStatus;
pub type SCardStatusWFn =
    extern "system" fn(ScardHandle, LpWStr, LpDword, LpDword, LpDword, LpByte, LpDword) -> ScardStatus;
pub type SCardTransmitFn =
    extern "system" fn(ScardHandle, LpScardIoRequest, LpCByte, u32, LpScardIoRequest, LpByte, LpDword) -> ScardStatus;
pub type SCardGetTransmitCountFn = extern "system" fn(ScardHandle, LpDword) -> ScardStatus;
pub type SCardControlFn =
    unsafe extern "system" fn(ScardHandle, u32, LpCVoid, u32, LpVoid, u32, LpDword) -> ScardStatus;
pub type SCardGetAttribFn = extern "system" fn(ScardHandle, u32, LpByte, LpDword) -> ScardStatus;
pub type SCardSetAttribFn = extern "system" fn(ScardHandle, u32, LpCByte, u32) -> ScardStatus;
pub type SCardUIDlgSelectCardAFn = extern "system" fn(LpOpenCardNameExA) -> ScardStatus;
pub type SCardUIDlgSelectCardWFn = extern "system" fn(LpOpenCardNameExW) -> ScardStatus;
pub type GetOpenCardNameAFn = extern "system" fn(LpOpenCardNameA) -> ScardStatus;
pub type GetOpenCardNameWFn = extern "system" fn(LpOpenCardNameW) -> ScardStatus;
pub type SCardDlgExtendedErrorFn = extern "system" fn() -> i32;

// https://github.com/FreeRDP/FreeRDP/blob/88f79c5748f4031cb50dfae3ebadcc6619b69f1c/winpr/include/winpr/smartcard.h#L1114
#[repr(C)]
#[allow(non_snake_case)]
pub struct SCardApiFunctionTable {
    pub dw_version: u32,
    pub dw_flags: u32,

    pub SCardEstablishContext: SCardEstablishContextFn,
    pub SCardReleaseContext: SCardReleaseContextFn,
    pub SCardIsValidContext: SCardIsValidContextFn,
    pub SCardListReaderGroupsA: SCardListReaderGroupsAFn,
    pub SCardListReaderGroupsW: SCardListReaderGroupsWFn,
    pub SCardListReadersA: SCardListReadersAFn,
    pub SCardListReadersW: SCardListReadersWFn,
    pub SCardListCardsA: SCardListCardsAFn,
    pub SCardListCardsW: SCardListCardsWFn,
    pub SCardListInterfacesA: SCardListInterfacesAFn,
    pub SCardListInterfacesW: SCardListInterfacesWFn,
    pub SCardGetProviderIdA: SCardGetProviderIdAFn,
    pub SCardGetProviderIdW: SCardGetProviderIdWFn,
    pub SCardGetCardTypeProviderNameA: SCardGetCardTypeProviderNameAFn,
    pub SCardGetCardTypeProviderNameW: SCardGetCardTypeProviderNameWFn,
    pub SCardIntroduceReaderGroupA: SCardIntroduceReaderGroupAFn,
    pub SCardIntroduceReaderGroupW: SCardIntroduceReaderGroupWFn,
    pub SCardForgetReaderGroupA: SCardForgetReaderGroupAFn,
    pub SCardForgetReaderGroupW: SCardForgetReaderGroupWFn,
    pub SCardIntroduceReaderA: SCardIntroduceReaderAFn,
    pub SCardIntroduceReaderW: SCardIntroduceReaderWFn,
    pub SCardForgetReaderA: SCardForgetReaderAFn,
    pub SCardForgetReaderW: SCardForgetReaderWFn,
    pub SCardAddReaderToGroupA: SCardAddReaderToGroupAFn,
    pub SCardAddReaderToGroupW: SCardAddReaderToGroupWFn,
    pub SCardRemoveReaderFromGroupA: SCardRemoveReaderFromGroupAFn,
    pub SCardRemoveReaderFromGroupW: SCardRemoveReaderFromGroupWFn,
    pub SCardIntroduceCardTypeA: SCardIntroduceCardTypeAFn,
    pub SCardIntroduceCardTypeW: SCardIntroduceCardTypeWFn,
    pub SCardSetCardTypeProviderNameA: SCardSetCardTypeProviderNameAFn,
    pub SCardSetCardTypeProviderNameW: SCardSetCardTypeProviderNameWFn,
    pub SCardFreeMemory: SCardFreeMemoryFn,
    pub SCardAccessStartedEvent: SCardAccessStartedEventFn,
    pub SCardReleaseStartedEvent: SCardReleaseStartedEventFn,
    pub SCardLocateCardsA: SCardLocateCardsAFn,
    pub SCardLocateCardsW: SCardLocateCardsWFn,
    pub SCardLocateCardsByATRA: SCardLocateCardsByATRAFn,
    pub SCardLocateCardsByATRW: SCardLocateCardsByATRWFn,
    pub SCardGetStatusChangeA: SCardGetStatusChangeAFn,
    pub SCardGetStatusChangeW: SCardGetStatusChangeWFn,
    pub SCardCancel: SCardCancelFn,
    pub SCardConnectA: SCardConnectAFn,
    pub SCardConnectW: SCardConnectWFn,
    pub SCardReconnect: SCardReconnectFn,
    pub SCardDisconnect: SCardDisconnectFn,
    pub SCardBeginTransaction: SCardBeginTransactionFn,
    pub SCardEndTransaction: SCardEndTransactionFn,
    pub SCardCancelTransaction: SCardCancelTransactionFn,
    pub SCardState: SCardStateFn,
    pub SCardStatusA: SCardStatusAFn,
    pub SCardStatusW: SCardStatusWFn,
    pub SCardTransmit: SCardTransmitFn,
    pub SCardGetTransmitCount: SCardGetTransmitCountFn,
    pub SCardControl: SCardControlFn,
    pub SCardGetAttrib: SCardGetAttribFn,
    pub SCardSetAttrib: SCardSetAttribFn,
    pub SCardUIDlgSelectCardA: SCardUIDlgSelectCardAFn,
    pub SCardUIDlgSelectCardW: SCardUIDlgSelectCardWFn,
    pub GetOpenCardNameA: GetOpenCardNameAFn,
    pub GetOpenCardNameW: GetOpenCardNameWFn,
    pub SCardDlgExtendedError: SCardDlgExtendedErrorFn,
    pub SCardReadCacheA: SCardReadCacheAFn,
    pub SCardReadCacheW: SCardReadCacheWFn,
    pub SCardWriteCacheA: SCardWriteCacheAFn,
    pub SCardWriteCacheW: SCardWriteCacheWFn,
    pub SCardGetReaderIconA: SCardGetReaderIconAFn,
    pub SCardGetReaderIconW: SCardGetReaderIconWFn,
    pub SCardGetReaderDeviceInstanceIdA: SCardGetReaderDeviceInstanceIdAFn,
    pub SCardGetReaderDeviceInstanceIdW: SCardGetReaderDeviceInstanceIdWFn,
    pub SCardListReadersWithDeviceInstanceIdA: SCardListReadersWithDeviceInstanceIdAFn,
    pub SCardListReadersWithDeviceInstanceIdW: SCardListReadersWithDeviceInstanceIdWFn,
    pub SCardAudit: SCardAuditFn,
}

pub type PSCardApiFunctionTable = *mut SCardApiFunctionTable;
