#![cfg(feature = "scard")]

use std::borrow::Cow;
use std::fmt;

use picky::key::PrivateKey;
use winscard::SmartCard as PivSmartCard;

use crate::Result;

pub enum SmartCardApi {
    PivSmartCard(Box<PivSmartCard<'static>>),
}

impl fmt::Debug for SmartCardApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PivSmartCard { .. } => f.write_str("SmartCardApi::PivSmartCard"),
        }
    }
}

#[derive(Debug)]
pub struct SmartCard {
    smart_card_type: SmartCardApi,
    pin: Vec<u8>,
}

impl SmartCard {
    // FIXME: This code will be used when support for system-provided smart cards is added
    #[allow(dead_code)]
    pub fn new_emulated(
        reader_name: Cow<'_, str>,
        pin: Vec<u8>,
        private_key_pem: &str,
        auth_cert_der: Vec<u8>,
    ) -> Result<Self> {
        let owned_reader_name = match reader_name {
            Cow::Borrowed(name) => Cow::Owned(name.to_owned()),
            Cow::Owned(name) => Cow::Owned(name),
        };
        let private_key = PrivateKey::from_pem_str(private_key_pem)?;
        let scard = PivSmartCard::new(owned_reader_name, pin.clone(), auth_cert_der, private_key)?;
        Ok(Self {
            smart_card_type: SmartCardApi::PivSmartCard(Box::new(scard)),
            pin,
        })
    }

    // FIXME: This code will be used when support for system-provided smart cards is added
    #[allow(dead_code)]
    pub fn sign(&mut self, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        match self.smart_card_type {
            SmartCardApi::PivSmartCard(ref mut scard) => {
                scard.verify_pin(&self.pin)?;
                Ok(scard.sign_hashed(data)?)
            }
        }
    }
}
