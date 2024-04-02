#![cfg(feature = "scard")]

use std::borrow::Cow;
use std::fmt;

use pcsc::{Card, Context, Protocols, Scope, ShareMode};
use picky::key::PrivateKey;
use picky_asn1::wrapper::OctetStringAsn1;
use picky_asn1_x509::{AlgorithmIdentifier, DigestInfo};
use winscard::SmartCard as PivSmartCard;

use crate::{Error, ErrorKind, Result};

pub enum SmartCardApi {
    #[allow(dead_code)]
    WinSCard(Card),
    PivSmartCard(Box<PivSmartCard<'static>>),
}

impl fmt::Debug for SmartCardApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WinSCard { .. } => f.write_str("SmartCardApi::WinSCard"),
            Self::PivSmartCard { .. } => f.write_str("SmartCardApi::PivSmartCard"),
        }
    }
}

#[derive(Debug)]
pub struct SmartCard {
    smart_card_type: SmartCardApi,
    pin: Vec<u8>,
    private_key_file_index: u8,
}

impl SmartCard {
    #[allow(dead_code)]
    pub fn new(pin: Vec<u8>, scard_reader_name: &str, private_key_file_index: u8) -> Result<Self> {
        let context = Context::establish(Scope::User)?;
        let readers_len = context.list_readers_len()?;
        let mut buff = vec![0_u8; readers_len];
        let mut names = context.list_readers(&mut buff)?;

        let reader_name = names
            .find(|reader_name| reader_name.to_bytes() == scard_reader_name.as_bytes())
            .ok_or_else(|| Error::new(ErrorKind::InternalError, "Requested smart card reader does not exist."))?;

        let scard = context.connect(reader_name, ShareMode::Shared, Protocols::T1)?;

        Ok(Self {
            smart_card_type: SmartCardApi::WinSCard(scard),
            pin,
            private_key_file_index,
        })
    }

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
            // we don't need it when using the PIV card
            private_key_file_index: 0,
        })
    }

    pub fn sign(&mut self, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        match self.smart_card_type {
            SmartCardApi::WinSCard(ref scard) => {
                // https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses
                const APDU_RESPONSE_OK: [u8; 2] = [0x90, 0x00];

                // this control code is extracted from the API calls recording during the mstsc connection establishing
                scard.control(0x00313520, &[], &mut [])?;

                let mut result_buff = [0; 16];
                #[rustfmt::skip]
                let output = scard.transmit(
                    &[
                        // apdu header
                        0x00, 0xa4, 0x00, 0x0c,
                        // data len
                        0x02,
                        // data
                        0x3f, 0xff,
                    ],
                    &mut result_buff,
                )?;
                if output != APDU_RESPONSE_OK {
                    return Err(Error::new(
                        ErrorKind::InternalError,
                        format!("smart card error: {:?} != {:?}", output, APDU_RESPONSE_OK),
                    ));
                }

                let mut pin_apdu = vec![
                    // command header
                    0x00,
                    0x20,
                    0x00,
                    0x80,
                    // pin len
                    self.pin.len().try_into().unwrap(),
                ];
                pin_apdu.extend_from_slice(&self.pin);

                let output = scard.transmit(&pin_apdu, &mut result_buff)?;

                if output != APDU_RESPONSE_OK {
                    return Err(Error::new(
                        ErrorKind::InternalError,
                        format!("smart card error: {:?} != {:?}", output, APDU_RESPONSE_OK),
                    ));
                }

                #[rustfmt::skip]
                let output = scard.transmit(
                    &[
                        // apdu header
                        0x00, 0x22, 0x41, 0xb6,
                        // data len
                        0x06,
                        // data
                        0x80, 0x01, 0x57, 0x84, 0x01, 0x80 + self.private_key_file_index,
                    ],
                    &mut result_buff,
                )?;
                if output != APDU_RESPONSE_OK {
                    return Err(Error::new(
                        ErrorKind::InternalError,
                        format!("smart card error: {:?} != {:?}", output, APDU_RESPONSE_OK),
                    ));
                }

                let mut signature_buff = vec![0; 300];
                let output = scard.transmit(&build_data_sign_apdu(data)?, &mut signature_buff)?;
                // the last two bytes is status bytes
                let output_len = output.len();
                if output[output_len - 2..] != APDU_RESPONSE_OK {
                    return Err(Error::new(
                        ErrorKind::InternalError,
                        format!("Smart card error: {:?} != {:?}", output, APDU_RESPONSE_OK),
                    ));
                }

                // the last two bytes is status bytes
                let signature = output[..(output_len - 2)].to_vec();

                let _output = scard.transmit(
                    &[
                        // apdu header
                        0x00, 0x20, 0x00, 0x82,
                    ],
                    &mut result_buff,
                )?;

                Ok(signature)
            }
            SmartCardApi::PivSmartCard(ref mut scard) => {
                scard.verify_pin(&self.pin)?;
                Ok(scard.sign_hashed(data)?)
            }
        }
    }
}

fn build_data_sign_apdu(data_to_sign: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    #[rustfmt::skip]
    let mut sign_data_apdu = vec![
        // apdu header
        0x00, 0x2a, 0x9e, 0x9a, // data length
        0x00, 0x00,
    ];

    let data_to_sign = DigestInfo {
        oid: AlgorithmIdentifier::new_sha1(),
        digest: OctetStringAsn1::from(data_to_sign.as_ref().to_vec()),
    };
    let encoded_data = picky_asn1_der::to_vec(&data_to_sign)?;

    sign_data_apdu.push(encoded_data.len().try_into().unwrap());
    sign_data_apdu.extend_from_slice(&encoded_data);

    // expected output length
    // we don't know the resulting signature len so we set [0x00 0x00] here
    sign_data_apdu.extend_from_slice(&[0x00, 0x00]);

    Ok(sign_data_apdu)
}
