use alloc::borrow::{Cow, ToOwned};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec::Vec;

use picky::key::PrivateKey;

use crate::scard::SmartCard;
use crate::winscard::{DeviceTypeId, Icon, Protocol, ShareMode, WinScard, WinScardContext};
use crate::{Error, ErrorKind, WinScardResult};

/// Describes a smart card reader.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    pub name: Cow<'a, str>,
    pub icon: Icon<'a>,
    pub device_type_id: DeviceTypeId,
}

/// Describes smart card info used for the smart card creation
pub struct SmartCardInfo<'a> {
    pub pin: Vec<u8>,
    pub auth_cert_der: Vec<u8>,
    pub auth_pk: PrivateKey,
    pub reader: Reader<'a>,
}

impl<'a> SmartCardInfo<'a> {
    pub fn new(pin: Vec<u8>, auth_cert_der: Vec<u8>, auth_pk: PrivateKey) -> Self {
        // Value from captured API calls
        let icon = vec![0x50];
        let reader: Reader<'_> = Reader {
            name: Cow::Borrowed("Emulated Reader 0"),
            icon: Icon::from(icon),
            device_type_id: DeviceTypeId::Tpm,
        };
        SmartCardInfo {
            pin,
            auth_cert_der,
            auth_pk,
            reader,
        }
    }
}

/// Represents the resource manager context (the scope).
pub struct ScardContext<'a> {
    smart_cards_info: Vec<SmartCardInfo<'a>>,
    cache: BTreeMap<String, Vec<u8>>,
}

impl<'a> ScardContext<'a> {
    /// Creates a new smart card based on the list of smart card readers
    pub fn new(smart_cards_info: Vec<SmartCardInfo<'a>>) -> Self {
        Self {
            smart_cards_info,
            cache: BTreeMap::new(),
        }
    }
}

impl<'a> WinScardContext for ScardContext<'a> {
    fn connect(
        &self,
        reader_name: &str,
        _share_mode: ShareMode,
        _protocol: Option<Protocol>,
    ) -> WinScardResult<Box<dyn WinScard>> {
        let smart_card_info = self
            .smart_cards_info
            .iter()
            .find(|card_info| card_info.reader.name == reader_name)
            .ok_or_else(|| Error::new(ErrorKind::UnknownReader, format!("reader {} not found", reader_name)))?;

        Ok(Box::new(SmartCard::new(
            Cow::Owned(reader_name.to_owned()),
            smart_card_info.pin.clone(),
            smart_card_info.auth_cert_der.clone(),
            smart_card_info.auth_pk.clone(),
        )?))
    }

    fn list_readers(&self) -> Vec<Cow<str>> {
        self.smart_cards_info
            .iter()
            .map(|card_info| card_info.reader.name.clone())
            .collect()
    }

    fn device_type_id(&self, reader_name: &str) -> WinScardResult<DeviceTypeId> {
        self.smart_cards_info
            .iter()
            .find(|card_info| card_info.reader.name == reader_name)
            .ok_or_else(|| Error::new(ErrorKind::UnknownReader, format!("reader {} not found", reader_name)))
            .map(|card_info| card_info.reader.device_type_id)
    }

    fn reader_icon(&self, reader_name: &str) -> WinScardResult<Icon> {
        self.smart_cards_info
            .iter()
            .find(|card_info| card_info.reader.name == reader_name)
            .ok_or_else(|| Error::new(ErrorKind::UnknownReader, format!("reader {} not found", reader_name)))
            .map(|card_info| card_info.reader.icon.clone())
    }

    fn is_valid(&self) -> bool {
        !self.smart_cards_info.is_empty()
    }

    fn read_cache(&self, key: &str) -> Option<&[u8]> {
        self.cache.get(key).map(|item| item.as_slice())
    }

    fn write_cache(&mut self, key: String, value: Vec<u8>) {
        self.cache.insert(key, value);
    }
}
