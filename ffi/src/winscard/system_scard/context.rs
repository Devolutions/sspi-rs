use std::borrow::Cow;

use ffi_types::winscard::ScardContext;
use winscard::winscard::{DeviceTypeId, Icon, MemoryPtr, Protocol, ShareMode, WinScard, WinScardContext};
use winscard::{Error, ErrorKind, WinScardResult};

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
    ) -> WinScardResult<Box<dyn WinScard>> {
        todo!()
    }

    fn list_readers(&self) -> Vec<Cow<str>> {
        todo!()
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

    fn read_cache(&self, key: &str) -> Option<&[u8]> {
        todo!()
    }

    fn write_cache(&mut self, key: String, value: Vec<u8>) {
        todo!()
    }

    fn list_reader_groups(&self) -> WinScardResult<Vec<Cow<str>>> {
        todo!()
    }

    fn cancel(&mut self) -> WinScardResult<()> {
        todo!()
    }
}
