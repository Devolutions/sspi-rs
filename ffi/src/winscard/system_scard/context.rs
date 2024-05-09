use std::borrow::Cow;
use std::ffi::CString;
use std::ptr::{null, null_mut};
#[cfg(target_os = "windows")]
use std::slice::from_raw_parts;

#[cfg(target_os = "windows")]
use ffi_types::winscard::functions::SCardApiFunctionTable;
#[cfg(target_os = "windows")]
use ffi_types::winscard::{ScardContext, ScardHandle};
use uuid::Uuid;
use winscard::winscard::{
    DeviceTypeId, Icon, Protocol, ProviderId, ReaderState, ScardConnectData, ScardScope, ShareMode, WinScardContext,
};
use winscard::{Error, ErrorKind, WinScardResult};

use super::{parse_multi_string_owned, SystemScard};
#[cfg(not(target_os = "windows"))]
use crate::winscard::pcsc_lite::functions::PcscLiteApiFunctionTable;
#[cfg(not(target_os = "windows"))]
use crate::winscard::pcsc_lite::{initialize_pcsc_lite_api, ScardContext, ScardHandle};

pub struct SystemScardContext {
    h_context: ScardContext,
    #[cfg(target_os = "windows")]
    api: SCardApiFunctionTable,
    #[cfg(not(target_os = "windows"))]
    api: PcscLiteApiFunctionTable,
}

impl SystemScardContext {
    #[allow(dead_code)]
    pub fn establish(scope: ScardScope) -> WinScardResult<Self> {
        let mut h_context = 0;

        #[cfg(target_os = "windows")]
        let api = super::init_scard_api_table()?;
        #[cfg(not(target_os = "windows"))]
        let api = initialize_pcsc_lite_api()?;

        try_execute!(
            // SAFETY: This function is safe to call because the `scope` parameter value is type checked
            // and `*mut h_context` can't be `null`.
            unsafe { (api.SCardEstablishContext)(scope.into(), null_mut(), null_mut(), &mut h_context) },
            "SCardEstablishContext failed"
        )?;

        if h_context == 0 {
            return Err(Error::new(
                ErrorKind::InternalError,
                "can not establish context: SCardEstablishContext did not set the context handle",
            ));
        }

        Ok(Self { h_context, api })
    }
}

impl Drop for SystemScardContext {
    fn drop(&mut self) {
        if let Err(err) = try_execute!(
            // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle.
            unsafe { (self.api.SCardReleaseContext)(self.h_context) },
            "SCardReleaseContext failed"
        ) {
            error!(?err, "Can not release the scard context");
        }
    }
}

impl WinScardContext for SystemScardContext {
    fn connect(
        &self,
        reader_name: &str,
        share_mode: ShareMode,
        protocol: Option<Protocol>,
    ) -> WinScardResult<ScardConnectData> {
        let c_string = CString::new(reader_name)?;

        let mut scard: ScardHandle = 0;
        let mut active_protocol = 0;

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardConnect)(
                        self.h_context,
                        c_string.as_ptr() as *const _,
                        share_mode.into(),
                        protocol.unwrap_or_default().bits(),
                        &mut scard,
                        &mut active_protocol,
                    )
                },
                "SCardConnect failed"
            )?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardConnectA)(
                        self.h_context,
                        c_string.as_ptr() as *const _,
                        share_mode.into(),
                        protocol.unwrap_or_default().bits(),
                        &mut scard,
                        &mut active_protocol,
                    )
                },
                "SCardConnectA failed"
            )?;
        }

        let handle = Box::new(SystemScard::new(scard, self.h_context)?);

        Ok(ScardConnectData {
            handle,
            protocol: Protocol::from_bits(active_protocol).unwrap_or_default(),
        })
    }

    fn list_readers(&self) -> WinScardResult<Vec<Cow<str>>> {
        let mut readers_buf_len = 0;

        #[cfg(not(target_os = "windows"))]
        {
            // https://pcsclite.apdu.fr/api/group__API.html#ga93b07815789b3cf2629d439ecf20f0d9
            //
            // If the application sends mszGroups and mszReaders as NULL then this function will return the size of the buffer needed to allocate in pcchReaders.
            // `mszGroups`: List of groups to list readers (not used).
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe { (self.api.SCardListReaders)(self.h_context, null(), null_mut(), &mut readers_buf_len) },
                "SCardListReaders failed"
            )?;
        }
        #[cfg(target_os = "windows")]
        {
            // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardlistreadersa
            //
            //  If this value is NULL, SCardListReaders ignores the buffer length supplied in pcchReaders,
            //  writes the length of the buffer that would have been returned if this parameter
            //  had not been NULL to pcchReaders, and returns a success code.
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe { (self.api.SCardListReadersA)(self.h_context, null(), null_mut(), &mut readers_buf_len) },
                "SCardListReadersA failed"
            )?;
        }

        let mut readers = vec![0; readers_buf_len.try_into()?];

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardListReaders)(self.h_context, null(), readers.as_mut_ptr(), &mut readers_buf_len)
                },
                "SCardListReaders failed"
            )?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardListReadersA)(self.h_context, null(), readers.as_mut_ptr(), &mut readers_buf_len)
                },
                "SCardListReadersA failed"
            )?;
        }
        debug!(?readers, "Raw readers buffer");

        parse_multi_string_owned(&readers)
    }

    fn device_type_id(&self, _reader_name: &str) -> WinScardResult<DeviceTypeId> {
        #[cfg(not(target_os = "windows"))]
        {
            Err(Error::new(
                ErrorKind::UnsupportedFeature,
                "SCardGetDeviceTypeId function is not supported in PCSC-lite API",
            ))
        }
        #[cfg(target_os = "windows")]
        {
            use num_traits::FromPrimitive;

            let mut device_type_id = 0;

            let c_reader_name = CString::new(_reader_name)?;

            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardGetDeviceTypeIdA)(
                        self.h_context,
                        c_reader_name.as_ptr() as *const _,
                        &mut device_type_id,
                    )
                },
                "SCardGetDeviceTypeIdA failed"
            )?;

            DeviceTypeId::from_u32(device_type_id).ok_or_else(|| {
                Error::new(
                    ErrorKind::InternalError,
                    format!("WinSCard has returned invalid device type id: {}", device_type_id),
                )
            })
        }
    }

    fn reader_icon(&self, _reader_name: &str) -> WinScardResult<Icon> {
        #[cfg(not(target_os = "windows"))]
        {
            Err(Error::new(
                ErrorKind::UnsupportedFeature,
                "SCardGetReaderIcon function is not supported in PCSC-lite API",
            ))
        }
        #[cfg(target_os = "windows")]
        {
            let c_reader_name = CString::new(_reader_name)?;

            let mut icon_buf_len = 0;

            // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardgetreadericona
            //
            // If this value is NULL, the function ignores the buffer length supplied in the pcbIcon parameter,
            // writes the length of the buffer that would have been returned to pcbIcon if this parameter
            // had not been NULL, and returns a success code.
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardGetReaderIconA)(
                        self.h_context,
                        c_reader_name.as_ptr() as *const _,
                        null_mut(),
                        &mut icon_buf_len,
                    )
                },
                "SCardGetReaderIconA failed"
            )?;

            let mut icon_buf = vec![0; icon_buf_len.try_into()?];

            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardGetReaderIconA)(
                        self.h_context,
                        c_reader_name.as_ptr() as *const _,
                        icon_buf.as_mut_ptr(),
                        &mut icon_buf_len,
                    )
                },
                "SCardGetReaderIconA failed"
            )?;

            Ok(icon_buf.into())
        }
    }

    fn is_valid(&self) -> bool {
        try_execute!(
            // SAFETY: This function is safe to call because we are allowed to pass any value.
            unsafe { (self.api.SCardIsValidContext)(self.h_context) },
            "SCardIsValidContext failed"
        )
        .is_ok()
    }

    fn read_cache(&self, _card_id: Uuid, _freshness_counter: u32, _key: &str) -> WinScardResult<Cow<[u8]>> {
        #[cfg(not(target_os = "windows"))]
        {
            Err(Error::new(
                ErrorKind::UnsupportedFeature,
                "SCardReadCache function is not supported in PCSC-lite API",
            ))
        }
        #[cfg(target_os = "windows")]
        {
            use super::uuid_to_c_guid;
            use crate::winscard::buf_alloc::SCARD_AUTOALLOCATE;

            let mut data_len = SCARD_AUTOALLOCATE;

            let c_cache_key = CString::new(_key)?;
            let mut card_id = uuid_to_c_guid(_card_id);

            let mut data: *mut u8 = null_mut();

            // It's not specified in the `SCardReadCacheA` function documentation, but after some
            // `msclmd.dll` reversing, we found out that this function supports the `SCARD_AUTOALLOCATE`.
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardReadCacheA)(
                        self.h_context,
                        &mut card_id,
                        _freshness_counter,
                        c_cache_key.into_raw() as *mut _,
                        ((&mut data) as *mut *mut u8) as *mut _,
                        &mut data_len,
                    )
                },
                "SCardReadCacheA failed"
            )?;

            let data_len: usize = if let Ok(len) = data_len.try_into() {
                len
            } else {
                try_execute!(
                    // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle.
                    unsafe { (self.api.SCardFreeMemory)(self.h_context, data as *const _) },
                    "SCardFreeMemory failed"
                )?;

                return Err(Error::new(ErrorKind::InternalError, "u32 to usize conversion error"));
            };

            let mut cache_item = vec![0; data_len];
            cache_item.copy_from_slice(
                // SAFETY: A slice creation is safe here because the `data` pointer is a local pointer and
                // was initialized by `SCardReadCacheA` function.
                unsafe { from_raw_parts(data, data_len) },
            );

            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle.
                unsafe { (self.api.SCardFreeMemory)(self.h_context, data as *const _) },
                "SCardFreeMemory failed"
            )?;

            Ok(Cow::Owned(cache_item))
        }
    }

    fn write_cache(
        &mut self,
        _card_id: Uuid,
        _freshness_counter: u32,
        _key: String,
        mut _value: Vec<u8>,
    ) -> WinScardResult<()> {
        #[cfg(not(target_os = "windows"))]
        {
            Err(Error::new(
                ErrorKind::UnsupportedFeature,
                "SCardWriteCache function is not supported in PCSC-lite API",
            ))
        }
        #[cfg(target_os = "windows")]
        {
            use super::uuid_to_c_guid;

            let c_cache_key = CString::new(_key.as_str())?;
            let mut card_id = uuid_to_c_guid(_card_id);

            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardWriteCacheA)(
                        self.h_context,
                        &mut card_id,
                        _freshness_counter,
                        c_cache_key.into_raw() as *mut _,
                        _value.as_mut_ptr(),
                        _value.len().try_into()?,
                    )
                },
                "SCardWriteCacheA failed"
            )
        }
    }

    fn list_reader_groups(&self) -> WinScardResult<Vec<Cow<str>>> {
        let mut reader_groups_buf_len = 0;

        #[cfg(not(target_os = "windows"))]
        {
            // https://pcsclite.apdu.fr/api/group__API.html#ga9d970d086d5218e080d0079d63f9d496
            //
            // If the application sends mszGroups as NULL then this function will return the size of the buffer needed to allocate in pcchGroups.
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe { (self.api.SCardListReaderGroups)(self.h_context, null_mut(), &mut reader_groups_buf_len) },
                "SCardListReaderGroups failed"
            )?;
        }
        #[cfg(target_os = "windows")]
        {
            // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardlistreadergroupsw
            //
            // If this value is NULL, SCardListReaderGroups ignores the buffer length supplied in pcchGroups,
            // writes the length of the buffer that would have been returned if this parameter had not been
            // NULL to pcchGroups, and returns a success code.
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe { (self.api.SCardListReaderGroupsA)(self.h_context, null_mut(), &mut reader_groups_buf_len) },
                "SCardListReaderGroupsA failed"
            )?;
        }

        let mut reader_groups = vec![0; reader_groups_buf_len.try_into()?];

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardListReaderGroups)(
                        self.h_context,
                        reader_groups.as_mut_ptr(),
                        &mut reader_groups_buf_len,
                    )
                },
                "SCardListReaderGroups failed"
            )?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardListReaderGroupsA)(
                        self.h_context,
                        reader_groups.as_mut_ptr(),
                        &mut reader_groups_buf_len,
                    )
                },
                "SCardListReaderGroupsA failed"
            )?;
        }

        parse_multi_string_owned(&reader_groups)
    }

    fn cancel(&mut self) -> WinScardResult<()> {
        // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle.
        try_execute!(unsafe { (self.api.SCardCancel)(self.h_context) }, "SCardCancel failed")
    }

    fn get_status_change(&self, _timeout: u32, _reader_states: &mut [ReaderState]) -> WinScardResult<()> {
        #[cfg(not(target_os = "windows"))]
        {
            Err(Error::new(
                ErrorKind::UnsupportedFeature,
                "SCardGetStatusChangeW function is not supported in PCSC-lite API",
            ))
        }
        #[cfg(target_os = "windows")]
        {
            use std::ffi::NulError;

            use ffi_types::winscard::ScardReaderStateA;
            use winscard::winscard::CurrentState;

            let mut states = Vec::with_capacity(_reader_states.len());
            let c_readers = _reader_states
                .iter()
                .map(|reader_state| CString::new(reader_state.reader_name.as_ref()))
                .collect::<Result<Vec<CString>, NulError>>()?;

            for (reader_state, c_reader) in _reader_states.iter_mut().zip(c_readers.iter()) {
                states.push(ScardReaderStateA {
                    sz_reader: c_reader.as_ptr() as *const _,
                    pv_user_data: reader_state.user_data as _,
                    dw_current_state: reader_state.current_state.bits(),
                    dw_event_state: reader_state.event_state.bits(),
                    cb_atr: reader_state.atr_len.try_into()?,
                    rgb_atr: reader_state.atr,
                });
            }

            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardGetStatusChangeA)(
                        self.h_context,
                        _timeout,
                        states.as_mut_ptr(),
                        _reader_states.len().try_into()?,
                    )
                },
                "SCardGetStatusChangeA failed"
            )?;

            // We do not need to change all fields. Only event state and atr values can be changed.
            for (state, reader_state) in states.iter().zip(_reader_states.iter_mut()) {
                reader_state.event_state = CurrentState::from_bits(state.dw_event_state)
                    .ok_or_else(|| Error::new(ErrorKind::InternalError, "invalid dwEventState"))?;
                reader_state.atr_len = state.cb_atr.try_into()?;
                reader_state.atr = state.rgb_atr;
            }

            Ok(())
        }
    }

    fn list_cards(&self, _atr: Option<&[u8]>, _required_interfaces: Option<&[Uuid]>) -> WinScardResult<Vec<Cow<str>>> {
        #[cfg(not(target_os = "windows"))]
        {
            Err(Error::new(
                ErrorKind::UnsupportedFeature,
                "SCardGetStatusChangeW function is not supported in PCSC-lite API",
            ))
        }
        #[cfg(target_os = "windows")]
        {
            use crate::winscard::system_scard::uuid_to_c_guid;

            let mut cards_buf_len = 0;
            let atr = _atr.map(|a| a.as_ptr()).unwrap_or(null());
            let uuids = _required_interfaces
                .into_iter()
                .flatten()
                .cloned()
                .map(uuid_to_c_guid)
                .collect::<Vec<ffi_types::Uuid>>();
            let uuids_len = uuids.len().try_into()?;
            let c_uuids = if uuids.is_empty() { null() } else { uuids.as_ptr() };

            // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardlistcardsw
            //
            // mszCards: If this value is NULL, SCardListCards ignores the buffer length supplied in
            // pcchCards, returning the length of the buffer that would have been returned if this
            // parameter had not been NULL to pcchCards and a success code.
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardListCardsA)(self.h_context, atr, c_uuids, uuids_len, null_mut(), &mut cards_buf_len)
                },
                "SCardListCardsA failed"
            )?;

            let mut cards = vec![0; cards_buf_len.try_into()?];

            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardListCardsA)(
                        self.h_context,
                        atr,
                        c_uuids,
                        uuids_len,
                        cards.as_mut_ptr(),
                        &mut cards_buf_len,
                    )
                },
                "SCardListCardsA failed"
            )?;

            parse_multi_string_owned(&cards)
        }
    }

    fn get_card_type_provider_name(&self, _card_name: &str, _provider_id: ProviderId) -> WinScardResult<Cow<str>> {
        #[cfg(not(target_os = "windows"))]
        {
            Err(Error::new(
                ErrorKind::UnsupportedFeature,
                "SCardGetCardTypeProviderNameW function is not supported in PCSC-lite API",
            ))
        }
        #[cfg(target_os = "windows")]
        {
            use crate::winscard::buf_alloc::SCARD_AUTOALLOCATE;

            let mut data_len = SCARD_AUTOALLOCATE;
            let mut data: *mut u8 = null_mut();

            let c_card_name = CString::new(_card_name)?;

            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardGetCardTypeProviderNameA)(
                        self.h_context,
                        c_card_name.as_ptr() as *const _,
                        _provider_id.into(),
                        ((&mut data) as *mut *mut u8) as *mut _,
                        &mut data_len,
                    )
                },
                "SCardGetCardTypeProviderNameA failed"
            )?;

            let data_len: usize = if let Ok(len) = data_len.try_into() {
                len
            } else {
                try_execute!(
                    // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle.
                    unsafe { (self.api.SCardFreeMemory)(self.h_context, data as *const _) },
                    "SCardFreeMemory failed"
                )?;

                return Err(Error::new(ErrorKind::InternalError, "u32 to usize conversion error"));
            };

            let name = if let Ok(name) = String::from_utf8(
                // SAFETY: A slice create is safe because the `data` pointer is a local pointer and
                // was initialized by `SCardGetCardTypeProviderNameA` function.
                unsafe { from_raw_parts(data, data_len) }.to_vec(),
            ) {
                name
            } else {
                try_execute!(
                    // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle.
                    unsafe { (self.api.SCardFreeMemory)(self.h_context, data as *const _) },
                    "SCardFreeMemory failed"
                )?;

                return Err(Error::new(ErrorKind::InternalError, "u32 to usize conversion error"));
            };

            Ok(Cow::Owned(name))
        }
    }
}
