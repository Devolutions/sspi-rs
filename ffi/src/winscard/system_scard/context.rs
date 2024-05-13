use std::borrow::Cow;
use std::ffi::CString;
use std::ptr::{null, null_mut};
use std::slice::from_raw_parts;

use ffi_types::winscard::{ScardContext, ScardHandle};
use winscard::winscard::{
    CurrentState, DeviceTypeId, Icon, Protocol, ReaderState, ScardConnectData, ShareMode, Uuid, WinScardContext,
};
use winscard::{Error, ErrorKind, WinScardResult};

use super::{parse_multi_string_owned, SystemScard};

pub struct SystemScardContext {
    h_context: ScardContext,
}

impl SystemScardContext {
    pub fn establish(dw_scope: u32) -> WinScardResult<Self> {
        let mut h_context = 0;

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(unsafe { pcsc_lite_rs::SCardEstablishContext(dw_scope, null(), null(), &mut h_context,) })?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(unsafe {
                windows_sys::Win32::Security::Credentials::SCardEstablishContext(
                    dw_scope,
                    null(),
                    null(),
                    &mut h_context,
                )
            })?;
        }

        Ok(Self { h_context })
    }
}

impl WinScardContext for SystemScardContext {
    fn connect(
        &self,
        reader_name: &str,
        share_mode: ShareMode,
        protocol: Option<Protocol>,
    ) -> WinScardResult<ScardConnectData> {
        // SAFETY:
        // https://doc.rust-lang.org/std/ffi/struct.CString.html#method.new
        // > This function will return an error if the supplied bytes contain an internal 0 byte.
        //
        // The Rust string slice cannot contain 0 bytes. So, it's safe to unwrap it.
        let c_string = CString::new(reader_name).expect("Rust string slice should not contain 0 bytes");

        let mut scard: ScardHandle = 0;
        let mut active_protocol = 0;

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(unsafe {
                pcsc_lite_rs::SCardConnect(
                    self.h_context,
                    c_string.as_ptr() as *const _,
                    share_mode.into(),
                    protocol.unwrap_or_default().bits(),
                    &mut scard,
                    &mut active_protocol,
                )
            })?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(unsafe {
                windows_sys::Win32::Security::Credentials::SCardConnectA(
                    self.h_context,
                    c_string.as_ptr() as *const _,
                    share_mode.into(),
                    protocol.unwrap_or_default().bits(),
                    &mut scard,
                    &mut active_protocol,
                )
            })?;
        }

        let scard = Box::new(SystemScard::new(scard, self.h_context));

        Ok(ScardConnectData {
            scard,
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
            try_execute!(unsafe {
                pcsc_lite_rs::SCardListReaders(self.h_context, null(), null_mut(), &mut readers_buf_len)
            })?;
        }
        #[cfg(target_os = "windows")]
        {
            // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardlistreadersa
            //
            //  If this value is NULL, SCardListReaders ignores the buffer length supplied in pcchReaders,
            //  writes the length of the buffer that would have been returned if this parameter
            //  had not been NULL to pcchReaders, and returns a success code.
            try_execute!(unsafe {
                windows_sys::Win32::Security::Credentials::SCardListReadersA(
                    self.h_context,
                    null(),
                    null_mut(),
                    &mut readers_buf_len,
                )
            })?;
        }

        let mut readers = vec![0; readers_buf_len.try_into()?];

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(unsafe {
                pcsc_lite_rs::SCardListReaders(self.h_context, null(), readers.as_mut_ptr(), &mut readers_buf_len)
            })?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(unsafe {
                windows_sys::Win32::Security::Credentials::SCardListReadersA(
                    self.h_context,
                    null(),
                    readers.as_mut_ptr(),
                    &mut readers_buf_len,
                )
            })?;
        }

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

            // SAFETY:
            // https://doc.rust-lang.org/std/ffi/struct.CString.html#method.new
            // > This function will return an error if the supplied bytes contain an internal 0 byte.
            //
            // The Rust string slice cannot contain 0 bytes. So, it's safe to unwrap it.
            let c_reader_name = CString::new(_reader_name).expect("Rust string slice should not contain 0 bytes");

            try_execute!(unsafe {
                windows_sys::Win32::Security::Credentials::SCardGetDeviceTypeIdA(
                    self.h_context,
                    c_reader_name.as_ptr() as *const _,
                    &mut device_type_id,
                )
            })?;

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
            // SAFETY:
            // https://doc.rust-lang.org/std/ffi/struct.CString.html#method.new
            // > This function will return an error if the supplied bytes contain an internal 0 byte.
            //
            // The Rust string slice cannot contain 0 bytes. So, it's safe to unwrap it.
            let c_reader_name = CString::new(_reader_name).expect("Rust string slice should not contain 0 bytes");

            let mut icon_buf_len = 0;

            // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardgetreadericona
            //
            // If this value is NULL, the function ignores the buffer length supplied in the pcbIcon parameter,
            // writes the length of the buffer that would have been returned to pcbIcon if this parameter
            // had not been NULL, and returns a success code.
            try_execute!(unsafe {
                windows_sys::Win32::Security::Credentials::SCardGetReaderIconA(
                    self.h_context,
                    c_reader_name.as_ptr() as *const _,
                    null_mut(),
                    &mut icon_buf_len,
                )
            })?;

            let mut icon_buf = vec![0; icon_buf_len.try_into()?];

            try_execute!(unsafe {
                windows_sys::Win32::Security::Credentials::SCardGetReaderIconA(
                    self.h_context,
                    c_reader_name.as_ptr() as *const _,
                    icon_buf.as_mut_ptr(),
                    &mut icon_buf_len,
                )
            })?;

            Ok(icon_buf.into())
        }
    }

    fn is_valid(&self) -> bool {
        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(unsafe { pcsc_lite_rs::SCardIsValidContext(self.h_context) }).is_ok()
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(unsafe { windows_sys::Win32::Security::Credentials::SCardIsValidContext(self.h_context) })
                .is_ok()
        }
    }

    fn read_cache(&self, _card_id: Uuid, _freshness_counter: u32, _key: &str) -> WinScardResult<Cow<[u8]>> {
        #[cfg(not(target_os = "windows"))]
        {
            None
        }
        #[cfg(target_os = "windows")]
        {
            use super::uuid_to_c_guid;
            use crate::winscard::buf_alloc::SCARD_AUTOALLOCATE;

            let mut data_len = SCARD_AUTOALLOCATE;

            // SAFETY:
            // https://doc.rust-lang.org/std/ffi/struct.CString.html#method.new
            // > This function will return an error if the supplied bytes contain an internal 0 byte.
            //
            // The Rust string slice cannot contain 0 bytes. So, it's safe to unwrap it.
            let c_cache_key = CString::new(_key).expect("Rust string slice should not contain 0 bytes");
            let card_id = uuid_to_c_guid(_card_id);

            let mut data: *mut u8 = null_mut();

            // It's not specified in the `SCardReadCacheA` function documentation, but after some
            // `msclmd.dll` reversing, we found out that this function supports the `SCARD_AUTOALLOCATE`.
            try_execute!(unsafe {
                windows_sys::Win32::Security::Credentials::SCardReadCacheA(
                    self.h_context,
                    &card_id,
                    _freshness_counter,
                    c_cache_key.as_ptr() as *const _,
                    ((&mut data) as *mut *mut u8) as *mut _,
                    &mut data_len,
                )
            })?;

            let data_len: usize = if let Ok(len) = data_len.try_into() {
                len
            } else {
                try_execute!(unsafe {
                    windows_sys::Win32::Security::Credentials::SCardFreeMemory(self.h_context, *data as *const _)
                })?;

                return Err(Error::new(ErrorKind::InternalError, "u32 to usize conversion error"));
            };

            let mut cache_item = vec![0; data_len];
            cache_item.copy_from_slice(unsafe { from_raw_parts(data, data_len) });

            try_execute!(unsafe {
                windows_sys::Win32::Security::Credentials::SCardFreeMemory(self.h_context, *data as *const _)
            })?;

            Ok(Cow::Owned(cache_item))
        }
    }

    fn write_cache(
        &mut self,
        _card_id: Uuid,
        _freshness_counter: u32,
        _key: String,
        _value: Vec<u8>,
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

            // SAFETY:
            // https://doc.rust-lang.org/std/ffi/struct.CString.html#method.new
            // > This function will return an error if the supplied bytes contain an internal 0 byte.
            //
            // The Rust string slice cannot contain 0 bytes. So, it's safe to unwrap it.
            let c_cache_key = CString::new(_key.as_str()).expect("Rust string slice should not contain 0 bytes");
            let card_id = uuid_to_c_guid(_card_id);

            try_execute!(unsafe {
                windows_sys::Win32::Security::Credentials::SCardWriteCacheA(
                    self.h_context,
                    &card_id,
                    _freshness_counter,
                    c_cache_key.as_ptr() as *const _,
                    _value.as_ptr(),
                    _value.len().try_into()?,
                )
            })
        }
    }

    fn list_reader_groups(&self) -> WinScardResult<Vec<Cow<str>>> {
        let mut reader_groups_buf_len = 0;

        #[cfg(not(target_os = "windows"))]
        {
            // https://pcsclite.apdu.fr/api/group__API.html#ga9d970d086d5218e080d0079d63f9d496
            //
            // If the application sends mszGroups as NULL then this function will return the size of the buffer needed to allocate in pcchGroups.
            try_execute!(unsafe {
                pcsc_lite_rs::SCardListReaderGroups(self.h_context, null_mut(), &mut reader_groups_buf_len)
            })?;
        }
        #[cfg(target_os = "windows")]
        {
            // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardlistreadergroupsw
            //
            // If this value is NULL, SCardListReaderGroups ignores the buffer length supplied in pcchGroups,
            // writes the length of the buffer that would have been returned if this parameter had not been
            // NULL to pcchGroups, and returns a success code.
            try_execute!(unsafe {
                windows_sys::Win32::Security::Credentials::SCardListReaderGroupsA(
                    self.h_context,
                    null_mut(),
                    &mut reader_groups_buf_len,
                )
            })?;
        }

        let mut reader_groups = vec![0; reader_groups_buf_len.try_into()?];

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(unsafe {
                pcsc_lite_rs::SCardListReaderGroups(
                    self.h_context,
                    reader_groups.as_mut_ptr(),
                    &mut reader_groups_buf_len,
                )
            })?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(unsafe {
                windows_sys::Win32::Security::Credentials::SCardListReaderGroupsA(
                    self.h_context,
                    reader_groups.as_mut_ptr(),
                    &mut reader_groups_buf_len,
                )
            })?;
        }

        parse_multi_string_owned(&reader_groups)
    }

    fn cancel(&mut self) -> WinScardResult<()> {
        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(unsafe { pcsc_lite_rs::SCardCancel(self.h_context) })
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(unsafe { windows_sys::Win32::Security::Credentials::SCardCancel(self.h_context) })
        }
    }

    fn get_status_change(&self, timeout: u32, reader_states: &mut [ReaderState]) -> WinScardResult<()> {
        #[cfg(not(target_os = "windows"))]
        {
            Err(Error::new(
                ErrorKind::UnsupportedFeature,
                "SCardGetStatusChangeW function is not supported in PCSC-lite API",
            ))
        }
        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Security::Credentials::SCARD_READERSTATEA;

            let mut states = Vec::with_capacity(reader_states.len());
            let c_readers: Vec<_> = reader_states
                .iter()
                .map(|reader_state| {
                    // SAFETY:
                    // https://doc.rust-lang.org/std/ffi/struct.CString.html#method.new
                    // > This function will return an error if the supplied bytes contain an internal 0 byte.
                    //
                    // The Rust string slice cannot contain 0 bytes. So, it's safe to unwrap it.
                    CString::new(reader_state.reader_name.as_ref())
                        .expect("Rust string slice should not contain 0 bytes")
                })
                .collect();

            for (index, reader_state) in reader_states.iter_mut().enumerate() {
                states.push(SCARD_READERSTATEA {
                    szReader: c_readers.get(index).unwrap().as_ptr() as *const _,
                    pvUserData: reader_state.user_data as _,
                    dwCurrentState: reader_state.current_state.bits(),
                    dwEventState: reader_state.event_state.bits(),
                    cbAtr: reader_state.atr_len.try_into()?,
                    rgbAtr: reader_state.atr.clone(),
                });
            }

            try_execute!(unsafe {
                windows_sys::Win32::Security::Credentials::SCardGetStatusChangeA(
                    self.h_context,
                    timeout,
                    states.as_mut_ptr(),
                    reader_states.len().try_into()?,
                )
            })?;

            // We do not need to change all fields. Only event state and atr values can be changed.
            for (state, reader_state) in states.iter().zip(reader_states.iter_mut()) {
                reader_state.event_state = CurrentState::from_bits(state.dwEventState)
                    .ok_or_else(|| Error::new(ErrorKind::InternalError, "Invalid dwEventState"))?;
                reader_state.atr_len = state.cbAtr.try_into()?;
                reader_state.atr = state.rgbAtr.clone();
            }

            Ok(())
        }
    }
}
