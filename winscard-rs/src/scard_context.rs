use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::winscard::{Icon, Protocol, ShareMode, WinScard, WinScardContext};
use crate::Result;

pub struct ScardContext {}

impl WinScardContext for ScardContext {
    fn connect(
        &self,
        _reader_name: &str,
        _share_mode: ShareMode,
        _protocol: Option<Protocol>,
    ) -> Result<Box<dyn WinScard>> {
        todo!()
    }

    fn list_readers(&self) -> Vec<String> {
        todo!()
    }

    fn device_type_id(&self, _reader_name: &str) -> Result<u32> {
        todo!()
    }

    fn reader_icon(&self, _reader_name: &str) -> Result<Icon> {
        todo!()
    }

    fn is_valid(&self) -> bool {
        todo!()
    }
}
