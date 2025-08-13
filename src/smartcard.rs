#![cfg(feature = "scard")]

use std::borrow::Cow;
use std::fmt;
use std::path::Path;

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use picky::key::PrivateKey;
use winscard::SmartCard as PivSmartCard;

use crate::{Error, ErrorKind, Result, Secret, SmartCardIdentity};

/// Smart cad API to use.
pub enum SmartCardApi {
    /// Represents emulated smart cards API.
    ///
    /// No real device or driver is needed.
    Emulated(Box<PivSmartCard<'static>>),
    /// Represents system-provided smart card API.
    ///
    /// PKCS11 API will be used for data signing.
    SystemProvided {
        /// PKCS11 module.
        pkcs11_module: Pkcs11,
        /// Reader name.
        ///
        /// Reader name is needed to determine which PKCS11 slot to use.
        reader_name: String,
    },
}

impl fmt::Debug for SmartCardApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Emulated { .. } => f.write_str("SmartCardApi::Emulated"),
            Self::SystemProvided { .. } => f.write_str("SmartCardApi::SystemProvided"),
        }
    }
}

/// Generic interface for data signing using smart card.
///
/// This implementation can use any supported smart card type. It depends on the provided credentials set.
#[derive(Debug)]
pub struct SmartCard {
    smart_card_type: SmartCardApi,
    pin: Secret<Vec<u8>>,
}

impl SmartCard {
    /// Creates a new [SmartCard] instance from the provided credentials.
    pub fn from_credentials(credentials: &SmartCardIdentity) -> Result<Self> {
        let SmartCardIdentity {
            username: _,
            certificate,
            reader_name,
            card_name: _,
            container_name: _,
            csp_name: _,
            pin: user_pin,
            private_key,
            scard_type,
        } = credentials;

        match scard_type {
            crate::SmartCardType::Emulated { scard_pin } => {
                let Some(private_key) = private_key else {
                    return Err(Error::new(
                        ErrorKind::IncompleteCredentials,
                        "emulated smart card private key is missing",
                    ));
                };

                Self::new_emulated(
                    Cow::Borrowed(reader_name.as_str()),
                    scard_pin.as_ref(),
                    user_pin.as_ref(),
                    private_key.as_ref(),
                    picky_asn1_der::to_vec(certificate)?,
                )
            }
            crate::SmartCardType::SystemProvided { pkcs11_module_path } => {
                Self::new_system_provided(pkcs11_module_path, user_pin.as_ref(), reader_name)
            }
        }
    }

    /// Creates a new [SmartCard] instance with the emulated smart card inside.
    fn new_emulated(
        reader_name: Cow<'_, str>,
        scard_pin: &[u8],
        user_pin: &[u8],
        private_key: &PrivateKey,
        auth_cert_der: Vec<u8>,
    ) -> Result<Self> {
        let reader_name = match reader_name {
            Cow::Borrowed(name) => Cow::Owned(name.to_owned()),
            Cow::Owned(name) => Cow::Owned(name),
        };
        let scard = PivSmartCard::new(reader_name, scard_pin.to_vec(), auth_cert_der, private_key.clone())?;

        Ok(Self {
            smart_card_type: SmartCardApi::Emulated(Box::new(scard)),
            pin: user_pin.to_vec().into(),
        })
    }

    /// Creates a new [SmartCard] instance with the system provided smart card inside.
    fn new_system_provided(pkcs11_module_path: &Path, user_pin: &[u8], reader_name: &str) -> Result<Self> {
        let pkcs11 = Pkcs11::new(pkcs11_module_path)?;
        pkcs11.initialize(CInitializeArgs::OsThreads)?;

        Ok(Self {
            smart_card_type: SmartCardApi::SystemProvided {
                pkcs11_module: pkcs11,
                reader_name: reader_name.to_owned(),
            },
            pin: user_pin.to_vec().into(),
        })
    }

    /// Signs the provided byte slice using smart card.
    pub fn sign(&mut self, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        match &mut self.smart_card_type {
            SmartCardApi::Emulated(ref mut scard) => {
                scard.verify_pin(self.pin.as_ref())?;
                Ok(scard.sign_hashed(data)?)
            }
            SmartCardApi::SystemProvided {
                pkcs11_module,
                reader_name,
            } => {
                let slot = 's: {
                    for slot in pkcs11_module.get_slots_with_token()? {
                        let slot_info = pkcs11_module.get_slot_info(slot)?;

                        if slot_info.slot_description() == reader_name {
                            break 's slot;
                        }
                    }

                    return Err(Error::new(
                        ErrorKind::NoCredentials,
                        format!("provided reader name ({reader_name}) does not match any smart card slots"),
                    ));
                };

                let session = pkcs11_module.open_ro_session(slot)?;

                let pin = String::from_utf8(self.pin.as_ref().to_vec())?;
                let pin = AuthPin::new(pin);
                session.login(UserType::User, Some(&pin))?;

                let objects = session.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])?;
                if let Some(private_key) = objects.into_iter().next() {
                    let checksum = session.sign(&Mechanism::RsaPkcs, private_key, data.as_ref())?;
                    // let checksum = session.sign(&Mechanism::Sha1RsaPkcs, object, data.as_ref());

                    Ok(checksum)
                } else {
                    Err(Error::new(
                        ErrorKind::NoCredentials,
                        "the selected PKCS11 slot does not have private key",
                    ))
                }
            }
        }
    }
}
