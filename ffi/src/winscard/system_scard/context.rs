use std::borrow::Cow;

use winscard::winscard::{DeviceTypeId, Icon, MemoryPtr, Protocol, ShareMode, WinScard, WinScardContext};
use winscard::WinScardResult;

pub struct SystemScardContext {}

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

    fn device_type_id(&self, reader_name: &str) -> WinScardResult<DeviceTypeId> {
        todo!()
    }

    fn reader_icon(&self, reader_name: &str) -> WinScardResult<Icon> {
        todo!()
    }

    fn is_valid(&self) -> bool {
        todo!()
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

    fn free(&mut self, ptr: MemoryPtr) -> WinScardResult<()> {
        todo!()
    }
}
