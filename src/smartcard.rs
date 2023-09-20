use std::fmt;

use iso7816_tlv::ber::{Tag, Tlv, Value};
use pcsc::{Card, Context, Protocols, Scope, ShareMode};
use picky_asn1::wrapper::OctetStringAsn1;
use picky_asn1_x509::{AlgorithmIdentifier, DigestInfo};
use winscard::{ber_tlv_length_encoding, tlv_tags, SmartCard as PivSmartCard, Status, PIV_AID};

use crate::{Error, ErrorKind, Result};

// ISO/IEC 7816-4
const CLA_BYTE_NO_CHAINING: u8 = 0x00;
const CLA_BYTE_CHAINING: u8 = 0x10;
// the max amount of data a one APDU command can contain
const APDU_COMMAND_DATA_SIZE: usize = 255;
// tag is always 1 byte in length
const TLV_TAG_LENGTH: usize = 1;

pub enum SmartCardApi {
    WinSCard(Card),
    PivSmartCard(Box<PivSmartCard>),
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

    pub fn new_emulated(mut pin: Vec<u8>, private_key_pem: &str, auth_cert_der: Vec<u8>) -> Result<Self> {
        let scard = PivSmartCard::new(pin.clone(), auth_cert_der, private_key_pem)?;
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
                // select the PIV app
                let select_apdu = build_select_apdu()?;
                let mut response = scard.handle_command(&select_apdu)?;
                if response.status != Status::OK {
                    return Err(Error::new(
                        ErrorKind::InternalError,
                        format!("Smart card error: {:?} != {:?}", response, Status::OK),
                    ));
                }

                // unlock the card using the PIN code
                let verify_apdu = build_verify_apdu(&self.pin)?;
                response = scard.handle_command(&verify_apdu)?;
                if response.status != Status::OK {
                    return Err(Error::new(
                        ErrorKind::InternalError,
                        format!("Smart card error: {:?} != {:?}", response, Status::OK),
                    ));
                }

                // sign the data
                let general_authenticate_apdus = build_general_authenticate_apdu(&data)?;
                let mut response_data = Vec::with_capacity(data.as_ref().len());

                for command in general_authenticate_apdus {
                    response = scard.handle_command(&command)?;
                    if response.data.is_none() && response.status != Status::OK {
                        return Err(Error::new(
                            ErrorKind::InternalError,
                            format!("Smart card error: {:?} != {:?}", response, Status::OK),
                        ));
                    } else if let Some(data) = response.data {
                        // last command in the chain triggers processing of the whole chain and has data in the Response structure
                        response_data.extend(data);
                    }
                }

                // use the GET RESPONSE command until there is no data left
                while let Status::MoreAvailable(bytes) = response.status {
                    let get_response_apdu = build_get_response_apdu(bytes)?;
                    response = scard.handle_command(&get_response_apdu)?;
                    match response.status {
                        Status::OK => (),
                        Status::MoreAvailable(_) => (),
                        _ => {
                            return Err(Error::new(
                                ErrorKind::InternalError,
                                format!("Smart card error: {:?} != {:?}", response, Status::OK),
                            ));
                        }
                    };
                    if let Some(data) = response.data {
                        response_data.extend_from_slice(&data);
                    } else {
                        return Err(Error::new(
                            ErrorKind::InternalError,
                            format!("Smart card error: {:?} != {:?}", response, Status::OK),
                        ));
                    }
                }

                // The smart card responds with a BER-TLV structure that we need to parse and extract the data from
                let parsed_response = Tlv::from_bytes(&response_data).map_err(|e| {
                    Error::new(
                        ErrorKind::InternalError,
                        format!("Error while parsing the smart card response: {}", e),
                    )
                })?;

                let signed_data = match parsed_response.value() {
                    Value::Constructed(nested_tlv) => {
                        let dat_response_tag = Tag::try_from(tlv_tags::DAT_RESPONSE).map_err(|_| {
                            Error::new(
                                ErrorKind::InternalError,
                                "Error while parsing the smart card response".to_string(),
                            )
                        })?;
                        let dat_response =
                            nested_tlv
                                .iter()
                                .find(|tlv| tlv.tag() == &dat_response_tag)
                                .ok_or(Error::new(
                                    ErrorKind::InternalError,
                                    "Bad TLV response received from the smart card".to_string(),
                                ))?;
                        match dat_response.value() {
                            Value::Primitive(signed_data) => signed_data,
                            Value::Constructed(_) => {
                                return Err(Error::new(
                                    ErrorKind::InternalError,
                                    "Bad TLV response received from the smart card".to_string(),
                                ));
                            }
                        }
                    }
                    Value::Primitive(_) => {
                        return Err(Error::new(
                            ErrorKind::InternalError,
                            "Bad TLV response received from the smart card".to_string(),
                        ))
                    }
                };
                Ok(signed_data.clone())
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

/// Creates a GET RESPONSE APDU command as described in ISO/IEC 7816-4, Section 7.6.1
fn build_get_response_apdu(bytes_to_read: u8) -> Result<Vec<u8>> {
    // ISO/IEC 7816-4
    const GET_RESPONSE_INS_BYTE: u8 = 0xC0;
    const GET_RESPONSE_P1_P2: u8 = 0x00;

    Ok(vec![
        CLA_BYTE_NO_CHAINING,
        GET_RESPONSE_INS_BYTE,
        GET_RESPONSE_P1_P2,
        GET_RESPONSE_P1_P2,
        bytes_to_read,
    ])
}

/// Creates a VERIFY APDU command as described in NIST.SP.800-73-4, Part 2, Section 3.2.1
/// PIN should already be padded with 0xFF bytes if it is shorter than 8 bytes
fn build_verify_apdu(pin: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    // ISO/IEC 7816-4
    const VERIFY_INS_BYTE: u8 = 0x20;
    // ISO/IEC 7816-4, Section 7.5.1
    const NO_IDENTIFIER: u8 = 0x00;
    // ISO/IEC 7816-4, Section 7.5.1, Table 65
    const SPECIFIC_REFERENCE_DATA: u8 = 0x80;
    const PIN_LENGTH: u8 = 0x08;

    let mut apdu_verify = vec![
        CLA_BYTE_NO_CHAINING,
        VERIFY_INS_BYTE,
        NO_IDENTIFIER,
        SPECIFIC_REFERENCE_DATA,
        PIN_LENGTH,
    ];
    apdu_verify.extend_from_slice(pin.as_ref());
    Ok(apdu_verify)
}

/// Creates a SELECT APDU command as described in NIST.SP.800-73-4, Part 2, Section 3.1.1
fn build_select_apdu() -> Result<Vec<u8>> {
    // ISO/IEC 7816-4
    const SELECT_INS_BYTE: u8 = 0xA4;
    // ISO/IEC 7816-4, Section 7.1.1, Table 39
    const APPLICATION_IDENTIFIER: u8 = 0x04;
    // ISO/IEC 7816-4, Section 7.1.1, Table 40
    const FIRST_OR_ONLY_OCCURRENCE: u8 = 0x00;
    // not truncated
    const AID_LENGTH: u8 = 0x0B;

    let mut apdu_select = vec![
        CLA_BYTE_NO_CHAINING,
        SELECT_INS_BYTE,
        APPLICATION_IDENTIFIER,
        FIRST_OR_ONLY_OCCURRENCE,
        AID_LENGTH,
    ];
    apdu_select.extend_from_slice(&PIV_AID);
    Ok(apdu_select)
}

/// Creates a GENERAL AUTHeNTICATE APDU commands as described in NIST.SP.800-73-4, Part 2, Section 3.2.4
/// Returns multiple commands if `data` is too big to fit into one command
fn build_general_authenticate_apdu(data: impl AsRef<[u8]>) -> Result<Vec<Vec<u8>>> {
    // ISO/IEC 7816-4
    const GENERAL_AUTHENTICATE_INS_BYTE: u8 = 0x87;
    // NIST.SP.800-73-4, Part 1, Table 5
    const RSA_ALGORITHM: u8 = 0x07;
    // NIST.SP.800-73-4, Part 1, Table 4b
    const PIV_AUTHENTICATION_KEY: u8 = 0x9A;

    let encoded_data_length = ber_tlv_length_encoding(data.as_ref().len());
    // encoded_data_length + challenge_tag + data
    let encoded_dat_tag_data_length =
        ber_tlv_length_encoding(TLV_TAG_LENGTH + encoded_data_length.len() + data.as_ref().len());
    // Actual size of our APDU command
    // dat_tag + encoded_dat_tag_data_length + challenge_tag + encoded_data_length + data
    let command_size = TLV_TAG_LENGTH
        + encoded_dat_tag_data_length.len()
        + TLV_TAG_LENGTH
        + encoded_data_length.len()
        + data.as_ref().len();

    // build the first APDU command
    let mut apdu_general_authenticate = vec![
        CLA_BYTE_NO_CHAINING,
        GENERAL_AUTHENTICATE_INS_BYTE,
        RSA_ALGORITHM,
        PIV_AUTHENTICATION_KEY,
    ];
    apdu_general_authenticate.extend_from_slice(&[APDU_COMMAND_DATA_SIZE.min(command_size).try_into().unwrap()]);
    apdu_general_authenticate.extend_from_slice(&[tlv_tags::DYNAMIC_AUTHENTICATION_TEMPLATE]);
    apdu_general_authenticate.extend_from_slice(&encoded_dat_tag_data_length);
    apdu_general_authenticate.extend_from_slice(&[tlv_tags::DAT_CHALLENGE]);
    apdu_general_authenticate.extend_from_slice(&encoded_data_length);

    // the data can be too long to be sent in a single APDU command, so we may have to split it into a few separate commands using the command chaining
    let commands = if command_size > APDU_COMMAND_DATA_SIZE {
        // enable command chaining
        apdu_general_authenticate[0] = CLA_BYTE_CHAINING;

        let commands_num = {
            let mut commands_num = command_size / APDU_COMMAND_DATA_SIZE;
            if command_size % APDU_COMMAND_DATA_SIZE != 0 {
                commands_num += 1;
            }
            commands_num
        };
        let mut commands = Vec::with_capacity(commands_num);

        // the first five bytes of an APDU command are not counted as data
        let remaining_data_size = APDU_COMMAND_DATA_SIZE - apdu_general_authenticate.len() + TLV_TAG_LENGTH * 5;

        // Build a vec from the byte slice so that we can drain it
        let mut data = {
            let mut vec_data = Vec::with_capacity(data.as_ref().len());
            vec_data.extend(data.as_ref());
            vec_data
        };

        // Add data to the first command and append it to the command vec
        apdu_general_authenticate.extend_from_slice(data.drain(0..remaining_data_size).as_slice());
        commands.extend_from_slice(&[apdu_general_authenticate]);

        while !data.is_empty() {
            let chunk_length = APDU_COMMAND_DATA_SIZE.min(data.len());
            // CLA + INS + P1 + P2 + DATA_LENGTH + DATA
            let mut chained_apdu_command = Vec::with_capacity(TLV_TAG_LENGTH * 5 + chunk_length);
            chained_apdu_command.extend_from_slice(&[
                CLA_BYTE_CHAINING,
                GENERAL_AUTHENTICATE_INS_BYTE,
                RSA_ALGORITHM,
                PIV_AUTHENTICATION_KEY,
            ]);
            chained_apdu_command.extend_from_slice(&[chunk_length.try_into().unwrap()]);
            chained_apdu_command.extend_from_slice(data.drain(0..chunk_length).as_slice());
            commands.extend_from_slice(&[chained_apdu_command]);
        }

        // disable command chaining for the last command in the chain
        let last_command = commands.len() - 1;
        commands[last_command][0] = CLA_BYTE_NO_CHAINING;

        commands
    } else {
        apdu_general_authenticate.extend_from_slice(data.as_ref());
        vec![apdu_general_authenticate]
    };
    Ok(commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn piv_smart_card() {
        let rsa_2048_private_key = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAiJ/d1/2d1CQYlJfZ02TOH7F/5U53a6IZc8QwTQEsBQbVGfQO
RN/+b09NzJJZmtyuLdBAXLzP8lEzKcfgn4JNl5G7DuKOxRreE5tq8uA+j2SQCw7m
Sm6todEOvkWG5Dov3Q9QnlPbvqp871pfbRsfKwOo2RxJIjbjpM5FQnlqOd+3gu2I
TF8dt+/PY+wl1w6kPTUZg/mzElY95WSnOE9bFlHcVL//Sl3caW85AB0lLUbd96b/
7PMO6IWJQyvS0ssG0emcyQYllvvSCFSpVWA/e1EGzKrwbtG1Xn9je5L4mIKiSw/p
gbjnYE9g+pibLJNobBBLkzGdo/KzyCQbMWirkQIDAQABAoIBAEbAm28mXNymkMAq
31g1BPWuwy/p8bggqxOjjuvh5nz369XT6KvMYAQeyohdZd/n1p/ND/e2o+22FUvW
wcF5Bluu0XNE6nCymD0JKFp8vIkfp+TCI4p6RJrfG8Z3VQLOC0lsi/BiNxNHUQnX
AEINYJey/nboygrY6AzJ8V4aaGNtbtnz7tfyALJHUK0qRa+AmyLCzaZR5RSbDgB5
srCX9J5OCxH2s5tVSfqg48Z0RIiBcDFPYbJDakZWLRNLD8ByW3e0jEFDA1vQPsaj
CsyY4E6UZwYNZemC60zW0e8BYJYnOAhcmwaYnaxvL5xy0aW5pUGr+FgnO4NrNr33
pKT2eFECgYEA2LJdjjFGdTsuW8esbTn+9hGyNnUR9gxYGdNhcINhPHMhoR8GkakC
5sLOlpgCDpdzHDduW2GjhIAUnXt50yZNpkXQuSWdjucbYGc2G5ySc8eHaP+5tHAr
svyZBchE+Kf4p2nNoXoQxsgxY2Qgz/ctUgCR7SnbgRW0cHDH7HIXlJ0CgYEAoWeY
rt2q8PFW3sEWy1RK0dxD+7UnuN76x5rd0IUxi2HS5F4tyfiDy3LgVs0XJqF9IN6K
IQ7pX/0C1g91NbUl8pAnu+k7R/CiynqGAmQumkMscIRO4VoR+v3+Hta9NV6sy/0U
fDfQSK9AnrFXGCpHPLC+YrmgbVnKqJ526vBxboUCgYEAvx4pJ0TMWI62p1nm+HrD
JLGc1SzRh4mBll15PeuRsef1DA66E3PVzEKaQ/WTMt1eN8+ntE7cEfuIsxB49MJ+
j5xZp0HGwYeQ/Khq71VbUWP0SKXqWnrn/7eLGq90LT6wLq9BHh7zdu6PqJJh4iml
vgIkseBN6X6EIvtFSIOjyn0CgYBRvEiRpSd/xHedbmLArPsGs2ip+t8Wu7R7iG1z
vz+Lugo2I4tEkFkNmisJSerDYVwgXRHOE+MS/OmGxWUxwX5qC55ThpTCpZWKu+lJ
JLqE3CeRAy9+50HbvOwHae9/K2aOFqddEFaluDodIulcD2zrywVesWoQdjwuj7Dg
4MpQkQKBgA4vlTf+n8kpOJWls2YMyZaauY48xcNzDdhpBGFCjVm+aiKX5dyIjAQK
9LX8/iVau8ZRM+qSLpuEP+o8qGR11TbGZrLH/wITc7r9cWnaGDsozmPAnxMcu1zz
9IRTY9zr9QWzxGiSqr834q5IZIQ/5uDBW/857MP0bpMl6cTdxzg0
-----END RSA PRIVATE KEY-----";
        // use a stub
        let auth_cert = vec![0xff; 2048];
        let pin = vec![0x34; 8];

        let mut scard = SmartCard::new_emulated(pin, rsa_2048_private_key, auth_cert)
            .expect("Failed to initialize a PIV smart card");
        let padded_hash = &[
            1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 0, 48, 81, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 10, 5, 0, 4, 64, 217, 251, 180, 124, 191,
            68, 76, 14, 222, 168, 240, 41, 42, 163, 77, 193, 145, 61, 94, 209, 90, 255, 216, 119, 129, 215, 128, 10,
            47, 115, 153, 79, 178, 139, 139, 113, 45, 118, 105, 206, 0, 250, 144, 138, 189, 191, 155, 243, 190, 174,
            179, 22, 214, 22, 183, 190, 12, 50, 16, 24, 207, 12, 36, 64,
        ];
        scard.sign(padded_hash).expect("Failed to sign the padded data");
    }
}
