use std::borrow::Cow;
use std::ffi::CString;
use std::fmt;
use std::ptr::{self, null, null_mut};
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

use super::{SystemScard, parse_multi_string_owned};
#[cfg(not(target_os = "windows"))]
use crate::winscard::cache;
#[cfg(not(target_os = "windows"))]
use crate::winscard::pcsc_lite::functions::PcscLiteApiFunctionTable;
#[cfg(not(target_os = "windows"))]
use crate::winscard::pcsc_lite::{ScardContext, ScardHandle, initialize_pcsc_lite_api};

/// Default name of the system provided smart card.
///
/// pcsc-lite and PC/SC framework don't have method for querying scard name, so we use predefined value. It doesn't affect the auth process.
#[cfg(not(target_os = "windows"))]
const DEFAULT_CARD_NAME: &str = "Sspi-rs system provided scard";

pub struct SystemScardContext {
    h_context: ScardContext,

    #[cfg(target_os = "windows")]
    api: SCardApiFunctionTable,
    #[cfg(not(target_os = "windows"))]
    api: PcscLiteApiFunctionTable,
}

impl fmt::Debug for SystemScardContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemScardContext")
            .field("h_context", &self.h_context)
            .finish()
    }
}

impl SystemScardContext {
    #[instrument(ret)]
    pub fn establish(scope: ScardScope) -> WinScardResult<Self> {
        let mut h_context = 0;

        #[cfg(target_os = "windows")]
        let api = super::init_scard_api_table()?;
        #[cfg(not(target_os = "windows"))]
        let api = initialize_pcsc_lite_api()?;

        try_execute!(
            // SAFETY:
            // - `scope.into()` is a valid `u32` value corresponding to the scope of the resource manager context.
            // - `pvReserved1` is null.
            // - `pvReserved2` is null.
            // - `&mut h_context` is a properly-aligned, writable pointer to a local variable.
            unsafe { (api.SCardEstablishContext)(scope.into(), null_mut(), null_mut(), &mut h_context) },
            "SCardEstablishContext failed"
        )?;

        if h_context == 0 {
            return Err(Error::new(
                ErrorKind::InternalError,
                "can not establish context: SCardEstablishContext did not set the context handle",
            ));
        }

        let scard_context = Self { h_context, api };

        Ok(scard_context)
    }
}

impl Drop for SystemScardContext {
    fn drop(&mut self) {
        if let Err(err) = try_execute!(
            // SAFETY: `h_context` is set by a previous call to `SCardEstablishContext`.
            unsafe { (self.api.SCardReleaseContext)(self.h_context) },
            "SCardReleaseContext failed"
        ) {
            error!(?err, "Can not release the scard context");
        }
    }
}

impl WinScardContext for SystemScardContext {
    #[instrument]
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
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `c_string` is a valid, null-terminated C String due to the `CString` type.
                // - `share_mode.into()` is a valid `u32` value corresponding to a share mode flag.
                // - `protocol.unwrap_or_default.bits()` is a valid `u32` value corresponding to a
                //   bitmask of acceptable protocols.
                // - `&mut scard` is a properly-aligned, writable pointer to a local variable.
                // - `&mut active_protocol` is a properly-aligned, writable pointer to a local variable.
                unsafe {
                    (self.api.SCardConnect)(
                        self.h_context,
                        c_string.as_ptr().cast(),
                        share_mode.into(),
                        protocol.unwrap_or_default().bits().into(),
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
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `c_string` is a valid, null-terminated C String due to the `CString` type.
                // - `share_mode.into()` is a valid `u32` value corresponding to a share mode flag.
                // - `protocol.unwrap_or_default.bits()` is a valid `u32` value corresponding to a
                //   bitmask of acceptable protocols.
                // - `&mut scard` is a properly-aligned, writable pointer to a local variable.
                // - `&mut active_protocol` is a properly-aligned, writable pointer to a local variable.
                unsafe {
                    (self.api.SCardConnectA)(
                        self.h_context,
                        c_string.as_ptr().cast(),
                        share_mode.into(),
                        protocol.unwrap_or_default().bits(),
                        &mut scard,
                        &mut active_protocol,
                    )
                },
                "SCardConnectA failed"
            )?;
        }

        // `DWORD` is aliased to `c_ulong` for Linux targets. In turn, `c_ulong` is aliased to `u64` on some targets.
        // Thus, depending on the compilation target, *sometimes* we need to convert `u64` to `u32`.
        #[allow(clippy::useless_conversion)]
        let active_protocol = active_protocol.try_into()?;
        let protocol = Protocol::from_bits(active_protocol).unwrap_or_default();
        let handle = Box::new(SystemScard::new(scard, protocol, self.h_context)?);

        Ok(ScardConnectData { handle, protocol })
    }

    fn list_readers(&self) -> WinScardResult<Vec<Cow<'_, str>>> {
        let mut readers_buf_len = 0;

        #[cfg(not(target_os = "windows"))]
        {
            // https://pcsclite.apdu.fr/api/group__API.html#ga93b07815789b3cf2629d439ecf20f0d9
            //
            // If the application sends mszGroups and mszReaders as NULL then this function will return the size of the buffer needed to allocate in pcchReaders.
            // `mszGroups`: List of groups to list readers (not used).
            try_execute!(
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `mszGroups` can be null.
                // - `mszReaders` can be null.
                // - `&mut readers_buf_len` is a properly-aligned, writable pointer to a local variable.
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
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `mszGroups` can be null.
                // - `mszReaders` can be null.
                // - `&mut readers_buf_len` is a properly-aligned, writable pointer to a local variable.
                unsafe { (self.api.SCardListReadersA)(self.h_context, null(), null_mut(), &mut readers_buf_len) },
                "SCardListReadersA failed"
            )?;
        }

        let mut readers = vec![0; readers_buf_len.try_into()?];

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `mszGroups` can be null.
                // - `readers.as_mut_ptr()` is a valid pointer to a locally allocated `Vec` with size `readers_buf_len`.
                // - `&mut readers_buf_len` is a properly-aligned, writable pointer to a local variable.
                //   The length is correct because it was set by a previous call to `SCardListReadersA`.
                unsafe {
                    (self.api.SCardListReaders)(self.h_context, null(), readers.as_mut_ptr(), &mut readers_buf_len)
                },
                "SCardListReaders failed"
            )?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `mszGroups` can be null.
                // - `readers.as_mut_ptr()` is a valid pointer to a locally allocated `Vec` with size `readers_buf_len`.
                // - `&mut readers_buf_len` is a properly-aligned, writable pointer to a local variable.
                //   The length is correct because it was set by a previous call to `SCardListReadersA`.
                unsafe {
                    (self.api.SCardListReadersA)(self.h_context, null(), readers.as_mut_ptr(), &mut readers_buf_len)
                },
                "SCardListReadersA failed"
            )?;
        }

        parse_multi_string_owned(&readers)
    }

    fn device_type_id(&self, _reader_name: &str) -> WinScardResult<DeviceTypeId> {
        #[cfg(not(target_os = "windows"))]
        {
            Ok(DeviceTypeId::Usb)
        }
        #[cfg(target_os = "windows")]
        {
            use num_traits::FromPrimitive;

            let mut device_type_id = 0;

            let c_reader_name = CString::new(_reader_name)?;

            try_execute!(
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `c_reader_name` is a valid, null-terminated C String due to the `CString` type.
                // - `device_type_id` is a properly-aligned, writable pointer to a local variable.
                unsafe {
                    (self.api.SCardGetDeviceTypeIdA)(self.h_context, c_reader_name.as_ptr().cast(), &mut device_type_id)
                },
                "SCardGetDeviceTypeIdA failed"
            )?;

            DeviceTypeId::from_u32(device_type_id).ok_or_else(|| {
                Error::new(
                    ErrorKind::InternalError,
                    format!("WinSCard has returned invalid device type id: {device_type_id}"),
                )
            })
        }
    }

    fn reader_icon(&self, _reader_name: &str) -> WinScardResult<Icon<'_>> {
        #[cfg(not(target_os = "windows"))]
        {
            use winscard::SmartCardInfo;

            Ok(Icon::from(SmartCardInfo::reader_icon()))
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
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `c_reader_name` is a valid, null-terminated C String due to the `CString` type.
                // - `pvIcon` can be null.
                // - `&mut icon_buf_len` is a properly-aligned, writable pointer to a local variable.
                unsafe {
                    (self.api.SCardGetReaderIconA)(
                        self.h_context,
                        c_reader_name.as_ptr().cast(),
                        null_mut(),
                        &mut icon_buf_len,
                    )
                },
                "SCardGetReaderIconA failed"
            )?;

            let mut icon_buf = vec![0; icon_buf_len.try_into()?];

            try_execute!(
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `c_reader_name` is a valid, null-terminated C String due to the `CString` type.
                // - `icon_buf.as_mut_ptr()` is a valid pointer to a locally allocated `Vec` with size `icon_buf_len`.
                // - `&mut icon_buf_len` is a properly-aligned, writable pointer to a local variable.
                //   The length is correct because it was set by a previous call to `SCardGetReaderIconA`.
                unsafe {
                    (self.api.SCardGetReaderIconA)(
                        self.h_context,
                        c_reader_name.as_ptr().cast(),
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
            // SAFETY: `h_context` is set by a previous call to `SCardEstablishContext`.
            unsafe { (self.api.SCardIsValidContext)(self.h_context) },
            "SCardIsValidContext failed"
        )
        .is_ok()
    }

    #[instrument(ret)]
    fn read_cache(&self, _card_id: Uuid, freshness_counter: u32, key: &str) -> WinScardResult<Cow<'_, [u8]>> {
        #[cfg(not(target_os = "windows"))]
        {
            Ok(Cow::Owned(cache::read(key, freshness_counter)?))
        }
        #[cfg(target_os = "windows")]
        {
            use std::ptr;

            use super::uuid_to_c_guid;
            use crate::winscard::buf_alloc::SCARD_AUTOALLOCATE;

            let mut data_len = SCARD_AUTOALLOCATE;

            let c_cache_key = CString::new(key)?;
            let mut card_id = uuid_to_c_guid(_card_id);

            let mut data: *mut u8 = null_mut();

            // It's not specified in the `SCardReadCacheA` function documentation, but after some
            // `msclmd.dll` reversing, we found out that this function supports the `SCARD_AUTOALLOCATE`.
            try_execute!(
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `&mut card_id` is a properly-aligned, readable pointer to a local variable.
                // - `c_cache_key` is a valid, null-terminated C String due to the `CString` type.
                // - `&mut data` is a properly-aligned, writable pointer to a local pointer.
                // - `&mut data_len` is a properly-aligned, writable pointer to a local variable.
                unsafe {
                    (self.api.SCardReadCacheA)(
                        self.h_context,
                        &mut card_id,
                        freshness_counter,
                        c_cache_key.into_raw().cast(),
                        ptr::from_mut(&mut data).cast(),
                        &mut data_len,
                    )
                },
                "SCardReadCacheA failed"
            )?;

            let data_len: usize = if let Ok(len) = data_len.try_into() {
                len
            } else {
                try_execute!(
                    // SAFETY:
                    // - `h_context` is set by a previous call to `SCardEstablishContext`.
                    // - `data` is a valid pointer that was allocated by a previous call to `SCardReadCacheA`.
                    unsafe { (self.api.SCardFreeMemory)(self.h_context, data.cast()) },
                    "SCardFreeMemory failed"
                )?;

                return Err(Error::new(ErrorKind::InternalError, "u32 to usize conversion error"));
            };

            let mut cache_item = vec![0; data_len];
            cache_item.copy_from_slice(
                // SAFETY: `data` pointer is a local pointer that was initialized by `SCardReadCacheA` function.
                unsafe { from_raw_parts(data, data_len) },
            );

            try_execute!(
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `data` is a valid pointer that was allocated by a previous call to `SCardReadCacheA`.
                unsafe { (self.api.SCardFreeMemory)(self.h_context, data.cast()) },
                "SCardFreeMemory failed"
            )?;

            Ok(Cow::Owned(cache_item))
        }
    }

    fn write_cache(
        &mut self,
        _card_id: Uuid,
        freshness_counter: u32,
        key: String,
        value: Vec<u8>,
    ) -> WinScardResult<()> {
        #[cfg(not(target_os = "windows"))]
        {
            cache::write(key, freshness_counter, value);

            Ok(())
        }
        #[cfg(target_os = "windows")]
        {
            use super::uuid_to_c_guid;

            let c_cache_key = CString::new(key.as_str())?;
            let mut card_id = uuid_to_c_guid(_card_id);

            try_execute!(
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `&mut card_id` is a properly-aligned, readable pointer to a local variable.
                // - `c_cache_key` is a valid, null-terminated C String due to the `CString` type.
                // - `&mut value` is a properly-aligned, readable pointer to a local `Vec`.
                // - `value.len()` is a valid length of the `value` buffer.
                unsafe {
                    (self.api.SCardWriteCacheA)(
                        self.h_context,
                        &mut card_id,
                        freshness_counter,
                        c_cache_key.into_raw().cast(),
                        value.as_ptr(),
                        value.len().try_into()?,
                    )
                },
                "SCardWriteCacheA failed"
            )
        }
    }

    fn list_reader_groups(&self) -> WinScardResult<Vec<Cow<'_, str>>> {
        let mut reader_groups_buf_len = 0;

        #[cfg(not(target_os = "windows"))]
        {
            // https://pcsclite.apdu.fr/api/group__API.html#ga9d970d086d5218e080d0079d63f9d496
            //
            // If the application sends mszGroups as NULL then this function will return the size of the buffer needed to allocate in pcchGroups.
            try_execute!(
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `mszGroups` can be null.
                // - `&mut reader_groups_buf_len` is a properly-aligned, writable pointer to a local variable.
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
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `mszGroups` can be null.
                // - `&mut reader_groups_buf_len` is a properly-aligned, writable pointer to a local variable.
                unsafe { (self.api.SCardListReaderGroupsA)(self.h_context, null_mut(), &mut reader_groups_buf_len) },
                "SCardListReaderGroupsA failed"
            )?;
        }

        let mut reader_groups = vec![0; reader_groups_buf_len.try_into()?];

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `reader_groups.as_mut_ptr()` is a valid pointer to a locally allocated `Vec` with size `reader_groups_buf_len`.
                // - `&mut reader_groups_buf_len` is a properly-aligned, writable pointer to a local variable.
                //   The length is correct because it was set by a previous call to `SCardListReaderGroupsA`.
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
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `reader_groups.as_mut_ptr()` is a valid pointer to a locally allocated `Vec` with size `reader_groups_buf_len`.
                // - `&mut reader_groups_buf_len` is a properly-aligned, writable pointer to a local variable.
                //   The length is correct because it was set by a previous call to `SCardListReaderGroupsA`.
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
        // SAFETY: `h_context` is set by a previous call to `SCardEstablishContext`.
        try_execute!(unsafe { (self.api.SCardCancel)(self.h_context) }, "SCardCancel failed")
    }

    #[instrument(ret)]
    fn get_status_change(&mut self, timeout: u32, reader_states: &mut [ReaderState<'_>]) -> WinScardResult<()> {
        use std::ffi::NulError;

        #[cfg(target_os = "windows")]
        use ffi_types::winscard::ScardReaderStateA as ScardReaderState;
        use winscard::winscard::CurrentState;

        #[cfg(not(target_os = "windows"))]
        use crate::winscard::pcsc_lite::ScardReaderState;

        let mut states = Vec::with_capacity(reader_states.len());
        let c_readers = reader_states
            .iter()
            .map(|reader_state| CString::new(reader_state.reader_name.as_ref()))
            .collect::<Result<Vec<CString>, NulError>>()?;

        for (reader_state, c_reader) in reader_states.iter_mut().zip(c_readers.iter()) {
            states.push(ScardReaderState {
                sz_reader: c_reader.as_ptr().cast(),
                pv_user_data: ptr::with_exposed_provenance_mut(reader_state.user_data),
                dw_current_state: reader_state.current_state.bits(),
                dw_event_state: reader_state.event_state.bits(),
                cb_atr: reader_state.atr_len.try_into()?,
                rgb_atr: reader_state.atr,
            });
        }

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `states.as_mut_ptr()` is a properly-aligned, both readable and writable pointer
                //   to a locally allocated `Vec` that contains `ScardReaderStateA` structures.
                // - `states.len()` is a valid length of a `states` array.
                unsafe {
                    (self.api.SCardGetStatusChange)(
                        self.h_context,
                        #[allow(clippy::useless_conversion)]
                        timeout.into(),
                        states.as_mut_ptr(),
                        states.len().try_into()?,
                    )
                },
                "SCardGetStatusChange failed"
            )?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `states.as_mut_ptr()` is a properly-aligned, both readable and writable pointer
                //   to a locally allocated `Vec` that contains `ScardReaderStateA` structures.
                // - `states.len()` is a valid length of a `states` array.
                unsafe {
                    (self.api.SCardGetStatusChangeA)(
                        self.h_context,
                        timeout,
                        states.as_mut_ptr(),
                        states.len().try_into()?,
                    )
                },
                "SCardGetStatusChangeA failed"
            )?;
        }

        // We do not need to change all fields. Only event state and atr values can be changed.
        for (state, reader_state) in states.iter().zip(reader_states.iter_mut()) {
            reader_state.event_state = CurrentState::from_bits(state.dw_event_state)
                .ok_or_else(|| Error::new(ErrorKind::InternalError, "invalid dwEventState"))?;
            reader_state.atr_len = state.cb_atr.try_into()?;
            reader_state.atr = state.rgb_atr;
        }

        Ok(())
    }

    fn list_cards(
        &self,
        _atr: Option<&[u8]>,
        _required_interfaces: Option<&[Uuid]>,
    ) -> WinScardResult<Vec<Cow<'_, str>>> {
        #[cfg(not(target_os = "windows"))]
        {
            Ok(vec![Cow::Borrowed(DEFAULT_CARD_NAME)])
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
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `atr` TODO: Clarify the safety requirement.
                // - `c_uuids` can be null. If it's non-null, it's a properly-aligned, readable pointer to a locally allocated `Vec`.
                // - `uuids_len` is a valid length for `c_uuids` array.
                // - `mszCards` can be null.
                // - `&mut cards_buf_len` is a properly-aligned, both readable and writable pointer to a local variable.
                unsafe {
                    (self.api.SCardListCardsA)(self.h_context, atr, c_uuids, uuids_len, null_mut(), &mut cards_buf_len)
                },
                "SCardListCardsA failed"
            )?;

            let mut cards = vec![0; cards_buf_len.try_into()?];

            try_execute!(
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `atr` TODO: Clarify the safety requirement.
                // - `c_uuids` can be null. If it's non-null, it's a properly-aligned, readable pointer to a locally allocated `Vec`.
                // - `uuids_len` is a valid length for `c_uuids` array.
                // - `cards.as_mut_ptr()` is a valid pointer to a locally allocated `Vec` with size `cards_buf_len`.
                // - `&mut cards_buf_len` is a properly-aligned, both readable and writable pointer to a local variable.
                //   The length is correct because it was set by a previous call to `SCardListCardsA`.
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

    fn get_card_type_provider_name(&self, _card_name: &str, provider_id: ProviderId) -> WinScardResult<Cow<'_, str>> {
        #[cfg(not(target_os = "windows"))]
        {
            Ok(match provider_id {
                ProviderId::Primary => {
                    return Err(Error::new(
                        ErrorKind::UnsupportedFeature,
                        "ProviderId::Primary is not supported for emulated smart card",
                    ));
                }
                ProviderId::Csp => winscard::MICROSOFT_DEFAULT_CSP.into(),
                ProviderId::Ksp => winscard::MICROSOFT_DEFAULT_KSP.into(),
                ProviderId::CardModule => winscard::MICROSOFT_SCARD_DRIVER_LOCATION.into(),
            })
        }
        #[cfg(target_os = "windows")]
        {
            use crate::winscard::buf_alloc::SCARD_AUTOALLOCATE;

            let mut data_len = SCARD_AUTOALLOCATE;
            let mut data: *mut u8 = null_mut();

            let c_card_name = CString::new(_card_name)?;

            try_execute!(
                // SAFETY:
                // - `h_context` is set by a previous call to `SCardEstablishContext`.
                // - `c_card_name` is a valid, null-terminated C String due to the `CString` type.
                // - `&mut data` is a properly-aligned, writable pointer to a local pointer. It can
                //   be null because it receives the provider name upon successful completion of this function.
                unsafe {
                    (self.api.SCardGetCardTypeProviderNameA)(
                        self.h_context,
                        c_card_name.as_ptr().cast(),
                        provider_id.into(),
                        std::ptr::addr_of_mut!(data).cast(),
                        &mut data_len,
                    )
                },
                "SCardGetCardTypeProviderNameA failed"
            )?;

            let data_len: usize = if let Ok(len) = data_len.try_into() {
                len
            } else {
                try_execute!(
                    // SAFETY:
                    // - `h_context` is set by a previous call to `SCardEstablishContext`.
                    // - `data` is a valid pointer that was allocated by a previous call to `SCardGetCardTypeProviderNameA`.
                    unsafe { (self.api.SCardFreeMemory)(self.h_context, data.cast()) },
                    "SCardFreeMemory failed"
                )?;

                return Err(Error::new(ErrorKind::InternalError, "u32 to usize conversion error"));
            };

            let name = if let Ok(name) = String::from_utf8(
                // SAFETY: `data` pointer is a local pointer that was initialized by `SCardGetCardTypeProviderNameA` function.
                unsafe { from_raw_parts(data, data_len) }.to_vec(),
            ) {
                name
            } else {
                try_execute!(
                    // SAFETY:
                    // - `h_context` is set by a previous call to `SCardEstablishContext`.
                    // - `data` is a valid pointer that was allocated by a previous call to `SCardGetCardTypeProviderNameA`.
                    unsafe { (self.api.SCardFreeMemory)(self.h_context, data.cast()) },
                    "SCardFreeMemory failed"
                )?;

                return Err(Error::new(ErrorKind::InternalError, "u32 to usize conversion error"));
            };

            Ok(Cow::Owned(name))
        }
    }
}
