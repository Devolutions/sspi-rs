use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::winscard::{DeviceTypeId, Icon, Protocol, ShareMode, WinScard, WinScardContext};
use crate::{Error, ErrorKind};
use crate::WinScardResult as Result;

/// Describes a smart card reader.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    pub name: String,
    pub icon: Icon<'a>,
    pub device_type_id: DeviceTypeId,
}

/// Represents the resource manager context (the scope).
pub struct ScardContext<'a> {
    readers: Vec<Reader<'a>>,
}

impl<'a> ScardContext<'a> {
    /// Creates a new smart card based on the list of smart card readers
    pub fn new(readers: Vec<Reader<'a>>) -> Self {
        Self { readers }
    }
}

impl<'a> WinScardContext for ScardContext<'a> {
    fn connect(
        &self,
        _reader_name: &str,
        _share_mode: ShareMode,
        _protocol: Option<Protocol>,
    ) -> Result<Box<dyn WinScard>> {
        todo!()
    }

    fn list_readers(&self) -> Vec<String> {
        self.readers.iter().map(|reader| reader.name.clone()).collect()
    }

    fn device_type_id(&self, reader_name: &str) -> Result<DeviceTypeId> {
        self.readers
            .iter()
            .find(|reader| reader.name == reader_name)
            .ok_or_else(|| Error::new(ErrorKind::UnknownReader, format!("reader {} not found", reader_name)))
            .map(|reader| reader.device_type_id)
    }

    fn reader_icon(&self, reader_name: &str) -> Result<Icon> {
        self.readers
            .iter()
            .find(|reader| reader.name == reader_name)
            .ok_or_else(|| Error::new(ErrorKind::UnknownReader, format!("reader {} not found", reader_name)))
            .map(|reader| reader.icon.clone())
    }

    fn is_valid(&self) -> bool {
        !self.readers.is_empty()
    }
}
