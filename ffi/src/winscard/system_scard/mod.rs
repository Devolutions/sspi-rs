#![cfg(feature = "scard")]

#[macro_use]
mod macros;

mod card;
mod context;

use std::borrow::Cow;

pub use card::SystemScard;
pub use context::SystemScardContext;
use num_traits::Zero;
use winscard::WinScardResult;

fn parse_multi_string(buf: &[u8]) -> WinScardResult<Vec<&str>> {
    let res: Result<Vec<&str>, _> = buf
        .split(|&c| c == 0)
        .filter(|v| !v.is_empty())
        .map(|v| std::str::from_utf8(v))
        .collect();

    Ok(res?)
}

fn parse_multi_string_owned(buf: &[u8]) -> WinScardResult<Vec<Cow<'static, str>>> {
    Ok(parse_multi_string(buf)?
        .into_iter()
        .map(|r| Cow::Owned(r.to_owned()))
        .collect())
}

#[cfg(target_os = "windows")]
fn uuid_to_c_guid(id: winscard::winscard::Uuid) -> ffi_types::Uuid {
    ffi_types::Uuid {
        data1: id.data1,
        data2: id.data2,
        data3: id.data3,
        data4: id.data4,
    }
}

#[cfg(target_os = "windows")]
pub fn init_scard_api_table() -> SCardApiFunctionTable {
    use std::mem::transmute;

    use ffi_types::winscard::functions::SCardApiFunctionTable;
    use windows_sys::s;
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

    let winscard_module = unsafe { LoadLibraryA(s!("C:\\Windows\\System32\\WinSCardOriginal.dll")) };

    if winscard_module.is_zero() {
        error!("Can not load the original winscard module.");
    } else {
        info!("Original winscard.dll has been loaded!");
    }

    // let f1: SCardEstablishContextFn = unsafe {
    //     transmute(GetProcAddress(winscard_module, s!("SCardEstablishContext")))
    // };

    macro_rules! load_fn {
        ($module:expr, $func_name:literal) => {{
            unsafe { transmute(GetProcAddress($module, s!($func_name))) }
        }};
    }

    let api_table = SCardApiFunctionTable {
        dw_version: 0,
        dw_flags: 0,
        SCardEstablishContext: load_fn!(winscard_module, "SCardEstablishContext"),
        SCardReleaseContext: load_fn!(winscard_module, "SCardReleaseContext"),
        SCardIsValidContext: load_fn!(winscard_module, "SCardIsValidContext"),
        SCardListReaderGroupsA: load_fn!(winscard_module, "SCardListReaderGroupsA"),
        SCardListReaderGroupsW: load_fn!(winscard_module, "SCardListReaderGroupsW"),
        SCardListReadersA: load_fn!(winscard_module, "SCardListReadersA"),
        SCardListReadersW: load_fn!(winscard_module, "SCardListReadersW"),
        SCardListCardsA: load_fn!(winscard_module, "SCardListCardsA"),
        SCardListCardsW: load_fn!(winscard_module, "SCardListCardsW"),
        SCardListInterfacesA: load_fn!(winscard_module, "SCardListInterfacesA"),
        SCardListInterfacesW: load_fn!(winscard_module, "SCardListInterfacesW"),
        SCardGetProviderIdA: load_fn!(winscard_module, "SCardGetProviderIdA"),
        SCardGetProviderIdW: load_fn!(winscard_module, "SCardGetProviderIdW"),
        SCardGetCardTypeProviderNameA: load_fn!(winscard_module, "SCardGetCardTypeProviderNameA"),
        SCardGetCardTypeProviderNameW: load_fn!(winscard_module, "SCardGetCardTypeProviderNameW"),
        SCardIntroduceReaderGroupA: load_fn!(winscard_module, "SCardIntroduceReaderGroupA"),
        SCardIntroduceReaderGroupW: load_fn!(winscard_module, "SCardIntroduceReaderGroupW"),
        SCardForgetReaderGroupA: load_fn!(winscard_module, "SCardForgetReaderGroupA"),
        SCardForgetReaderGroupW: load_fn!(winscard_module, "SCardForgetReaderGroupW"),
        SCardIntroduceReaderA: load_fn!(winscard_module, "SCardIntroduceReaderA"),
        SCardIntroduceReaderW: load_fn!(winscard_module, "SCardIntroduceReaderW"),
        SCardForgetReaderA: load_fn!(winscard_module, "SCardForgetReaderA"),
        SCardForgetReaderW: load_fn!(winscard_module, "SCardForgetReaderW"),
        SCardAddReaderToGroupA: load_fn!(winscard_module, "SCardAddReaderToGroupA"),
        SCardAddReaderToGroupW: load_fn!(winscard_module, "SCardAddReaderToGroupW"),
        SCardRemoveReaderFromGroupA: load_fn!(winscard_module, "SCardRemoveReaderFromGroupA"),
        SCardRemoveReaderFromGroupW: load_fn!(winscard_module, "SCardRemoveReaderFromGroupW"),
        SCardIntroduceCardTypeA: load_fn!(winscard_module, "SCardIntroduceCardTypeA"),
        SCardIntroduceCardTypeW: load_fn!(winscard_module, "SCardIntroduceCardTypeW"),
        SCardSetCardTypeProviderNameA: load_fn!(winscard_module, "SCardSetCardTypeProviderNameA"),
        SCardSetCardTypeProviderNameW: load_fn!(winscard_module, "SCardSetCardTypeProviderNameW"),
        SCardFreeMemory: load_fn!(winscard_module, "SCardFreeMemory"),
        SCardAccessStartedEvent: load_fn!(winscard_module, "SCardAccessStartedEvent"),
        SCardReleaseStartedEvent: load_fn!(winscard_module, "SCardReleaseStartedEvent"),
        SCardLocateCardsA: load_fn!(winscard_module, "SCardLocateCardsA"),
        SCardLocateCardsW: load_fn!(winscard_module, "SCardLocateCardsW"),
        SCardLocateCardsByATRA: load_fn!(winscard_module, "SCardLocateCardsByATRA"),
        SCardLocateCardsByATRW: load_fn!(winscard_module, "SCardLocateCardsByATRW"),
        SCardGetStatusChangeA: load_fn!(winscard_module, "SCardGetStatusChangeA"),
        SCardGetStatusChangeW: load_fn!(winscard_module, "SCardGetStatusChangeW"),
        SCardCancel: load_fn!(winscard_module, "SCardCancel"),
        SCardConnectA: load_fn!(winscard_module, "SCardConnectA"),
        SCardConnectW: load_fn!(winscard_module, "SCardConnectW"),
        SCardReconnect: load_fn!(winscard_module, "SCardReconnect"),
        SCardDisconnect: load_fn!(winscard_module, "SCardDisconnect"),
        SCardBeginTransaction: load_fn!(winscard_module, "SCardBeginTransaction"),
        SCardEndTransaction: load_fn!(winscard_module, "SCardEndTransaction"),
        SCardCancelTransaction: load_fn!(winscard_module, "SCardCancelTransaction"),
        SCardState: load_fn!(winscard_module, "SCardState"),
        SCardStatusA: load_fn!(winscard_module, "SCardStatusA"),
        SCardStatusW: load_fn!(winscard_module, "SCardStatusW"),
        SCardTransmit: load_fn!(winscard_module, "SCardTransmit"),
        SCardGetTransmitCount: load_fn!(winscard_module, "SCardGetTransmitCount"),
        SCardControl: load_fn!(winscard_module, "SCardControl"),
        SCardGetAttrib: load_fn!(winscard_module, "SCardGetAttrib"),
        SCardSetAttrib: load_fn!(winscard_module, "SCardSetAttrib"),
        SCardUIDlgSelectCardA: load_fn!(winscard_module, "SCardUIDlgSelectCardA"),
        SCardUIDlgSelectCardW: load_fn!(winscard_module, "SCardUIDlgSelectCardW"),
        GetOpenCardNameA: load_fn!(winscard_module, "GetOpenCardNameA"),
        GetOpenCardNameW: load_fn!(winscard_module, "GetOpenCardNameW"),
        SCardReadCacheA: load_fn!(winscard_module, "SCardReadCacheA"),
        SCardReadCacheW: load_fn!(winscard_module, "SCardReadCacheW"),
        SCardWriteCacheA: load_fn!(winscard_module, "SCardWriteCacheA"),
        SCardWriteCacheW: load_fn!(winscard_module, "SCardWriteCacheW"),
        SCardGetReaderIconA: load_fn!(winscard_module, "SCardGetReaderIconA"),
        SCardGetReaderIconW: load_fn!(winscard_module, "SCardGetReaderIconW"),
        SCardGetDeviceTypeIdA: load_fn!(winscard_module, "SCardGetDeviceTypeIdA"),
        SCardGetDeviceTypeIdW: load_fn!(winscard_module, "SCardGetDeviceTypeIdW"),
        SCardGetReaderDeviceInstanceIdA: load_fn!(winscard_module, "SCardGetReaderDeviceInstanceIdA"),
        SCardGetReaderDeviceInstanceIdW: load_fn!(winscard_module, "SCardGetReaderDeviceInstanceIdW"),
        SCardListReadersWithDeviceInstanceIdA: load_fn!(winscard_module, "SCardListReadersWithDeviceInstanceIdA"),
        SCardListReadersWithDeviceInstanceIdW: load_fn!(winscard_module, "SCardListReadersWithDeviceInstanceIdW"),
        SCardAudit: load_fn!(winscard_module, "SCardAudit"),
    };
    debug!(?api_table);
    api_table
}
