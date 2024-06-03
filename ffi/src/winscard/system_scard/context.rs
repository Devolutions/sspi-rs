use std::borrow::Cow;
use std::ffi::CString;
use std::ptr::{null, null_mut};

use ffi_types::winscard::{ScardContext, ScardHandle};
use winscard::winscard::{DeviceTypeId, Icon, Protocol, ScardConnectData, ShareMode, Uuid, WinScardContext};
use winscard::{Error, ErrorKind, WinScardResult};

use super::{parse_multi_string_owned, SystemScard};

pub struct SystemScardContext {
    h_context: ScardContext,
}

impl SystemScardContext {
    pub fn new(h_context: ScardContext) -> Self {
        Self { h_context }
    }
}

impl WinScardContext for SystemScardContext {
    fn connect(
        &self,
        reader_name: &str,
        share_mode: ShareMode,
        protocol: Option<Protocol>,
    ) -> WinScardResult<ScardConnectData> {
        #[cfg(not(target_os = "windows"))]
        {
            // SAFETY:
            // https://doc.rust-lang.org/std/ffi/struct.CString.html#method.new
            // > This function will return an error if the supplied bytes contain an internal 0 byte.
            //
            // The Rust string slice cannot contain 0 bytes. So, it's safe to unwrap it.
            let c_string = CString::new(reader_name).expect("Rust string slice should not contain 0 bytes");

            let mut scard: ScardHandle = 0;
            let mut active_protocol = 0;

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

            let scard = Box::new(SystemScard::new(scard, self.h_context));

            Ok(ScardConnectData {
                scard,
                protocol: Protocol::from_bits(active_protocol).unwrap_or_default(),
            })
        }
        #[cfg(target_os = "windows")]
        {
            // TODO(@TheBestTvarynka): implement for Windows too.
            todo!()
        }
    }

    fn list_readers(&self) -> WinScardResult<Vec<Cow<str>>> {
        #[cfg(not(target_os = "windows"))]
        {
            let mut readers_buf_len = 0;

            // https://pcsclite.apdu.fr/api/group__API.html#ga93b07815789b3cf2629d439ecf20f0d9
            //
            // If the application sends mszGroups and mszReaders as NULL then this function will return the size of the buffer needed to allocate in pcchReaders.
            // `mszGroups`: List of groups to list readers (not used).
            try_execute!(unsafe {
                pcsc_lite_rs::SCardListReaders(self.h_context, null(), null_mut(), &mut readers_buf_len)
            })?;

            let mut readers = vec![0; readers_buf_len.try_into()?];

            try_execute!(unsafe {
                pcsc_lite_rs::SCardListReaders(self.h_context, null(), readers.as_mut_ptr(), &mut readers_buf_len)
            })?;

            parse_multi_string_owned(&readers)
        }
        #[cfg(target_os = "windows")]
        {
            // TODO(@TheBestTvarynka): implement for Windows too.
            todo!()
        }
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
            // TODO(@TheBestTvarynka): implement for Windows too.
            todo!()
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
            // TODO(@TheBestTvarynka): implement for Windows too.
            todo!()
        }
    }

    fn is_valid(&self) -> bool {
        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(unsafe { pcsc_lite_rs::SCardIsValidContext(self.h_context) }).is_ok()
        }
        #[cfg(target_os = "windows")]
        {
            // TODO(@TheBestTvarynka): implement for Windows too.
            todo!()
        }
    }

    fn read_cache(&self, _key: &str) -> Option<Cow<[u8]>> {
        #[cfg(not(target_os = "windows"))]
        {
            None
        }
        #[cfg(target_os = "windows")]
        {
            // TODO(@TheBestTvarynka): implement for Windows too.
            todo!()
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
}
