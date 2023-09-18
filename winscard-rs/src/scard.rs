use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};

use iso7816::{Aid, Command, Instruction};
use iso7816_tlv::ber::{Tag, Tlv, Value};
use picky::key::{sign_hashed_rsa, PrivateKey};
use tracing::error;

use crate::chuid::{build_chuid, CHUID_LENGTH};
use crate::piv_cert::build_auth_cert;
use crate::{tlv_tags, Error, ErrorKind, Response, Result, Status};

const PIV_AID: Aid = Aid::new_truncatable(&[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00], 9);
// the max amount of data one APDU response can transmit
const CHUNK_SIZE: usize = 256;
const CHUID_TAG: &[u8] = &[0x5F, 0xC1, 0x02];
const PIV_CERT_TAG: &[u8] = &[0x5F, 0xC1, 0x05];

pub struct SmartCard {
    chuid: [u8; CHUID_LENGTH],
    pin: Vec<u8>,
    auth_cert: Vec<u8>,
    auth_pk: PrivateKey,
    state: SCardState,
    pending_command: Option<Command<1024>>,
    pending_response: Option<Vec<u8>>,
}

impl SmartCard {
    pub fn new(mut pin: Vec<u8>, auth_cert_der: Vec<u8>, auth_pk_pem: &str) -> Result<Self> {
        let chuid = build_chuid()?;
        let auth_cert = build_auth_cert(auth_cert_der)?;
        let auth_pk = PrivateKey::from_pem_str(auth_pk_pem)?;
        // All PIN requirements can be found here: NIST.SP.800-73-4 part 2, section 2.4.3
        if !(6..=8).contains(&pin.len()) {
            return Err(Error::new(
                ErrorKind::InvalidValue,
                "PIN should be no shorter than 6 bytes and no longer than 8",
            ));
        }
        if pin.iter().any(|byte| !(0x30..=0x39).contains(byte)) {
            return Err(Error::new(
                ErrorKind::InvalidValue,
                "PIN should consist only of ASCII values representing decimal digits (0x30-0x39)",
            ));
        };
        if pin.len() < 8 {
            pin.resize(8, 0xFF);
        }
        Ok(SmartCard {
            chuid,
            pin,
            auth_cert,
            auth_pk,
            state: SCardState::Ready,
            pending_command: None,
            pending_response: None,
        })
    }

    pub fn handle_command(&mut self, data: &[u8]) -> Result<Response> {
        let cmd = Command::<1024>::try_from(data).map_err(|e| {
            error!("APDU command parsing error: {:?}", e);
            Error::new(
                ErrorKind::InternalError,
                format!("Error: an error happened while parsing an APDU command: {:?}", e),
            )
        })?;
        let cmd = if let Some(mut chained) = self.pending_command.take() {
            chained.extend_from_command(&cmd).map_err(|_| {
                Error::new(
                    ErrorKind::InternalError,
                    "Error: an error happened while trying to build a chained APDU command",
                )
            })?;
            chained
        } else {
            cmd
        };
        if cmd.class().chain().not_the_last() {
            self.pending_command = Some(cmd);
            return Ok(Status::OK.into());
        }
        if self.state == SCardState::Ready && cmd.instruction() != Instruction::Select {
            // if the application wasn't selected, only the SELECT command can be used
            return Ok(Status::NotFound.into());
        } else if self.state == SCardState::PivAppSelected && cmd.instruction() == Instruction::GeneralAuthenticate {
            // GENERAL AUTHENTICATE can only be used if the smart card has already been unlocked using the PIN code
            return Ok(Status::SecurityStatusNotSatisfied.into());
        }
        match cmd.instruction() {
            Instruction::Select => self.select(cmd),
            Instruction::GetData => self.get_data(cmd),
            Instruction::Verify => self.verify(cmd),
            Instruction::GeneralAuthenticate => self.general_authenticate(cmd),
            Instruction::GetResponse => self.get_response(),
            _ => {
                error!("unimplemented instruction {:?}", cmd.instruction());
                Ok(Status::InstructionNotSupported.into())
            }
        }
    }

    fn select(&self, cmd: Command<1024>) -> Result<Response> {
        // PIV SELECT command
        //      CLA - 0x00
        //      INS - 0xA4
        //      P1  - 0x04
        //      P2  - 0x00
        if cmd.p1 != 0x04 || cmd.p2 != 0x00 || !PIV_AID.matches(cmd.data()) {
            return Ok(Status::NotFound.into());
        }
        let data = Tlv::new(
            Tag::try_from(tlv_tags::APPLICATION_PROPERTY_TEMPLATE)?,
            Value::Constructed(vec![
                Tlv::new(
                    Tag::try_from(tlv_tags::APPLICATION_IDENTIFIER)?,
                    // application portion + version portion of the PIV AID
                    // NIST.SP.800-73-4 Part 1, section 2.2
                    Value::Primitive(vec![0x00, 0x00, 0x10, 0x00, 0x01, 0x00]),
                )?,
                Tlv::new(
                    Tag::try_from(tlv_tags::COEXISTING_TAG_ALLOCATION_AUTHORITY)?,
                    Value::Constructed(vec![Tlv::new(
                        Tag::try_from(tlv_tags::APPLICATION_IDENTIFIER)?,
                        Value::Primitive(PIV_AID.to_vec()),
                    )?]),
                )?,
            ]),
        )?;
        Ok(Response::new(Status::OK, Some(data.to_vec())))
    }

    fn verify(&mut self, cmd: Command<1024>) -> Result<Response> {
        // PIV VERIFY command
        //      CLA  - 0x00
        //      INS  - 0x20
        //      P1   - 0x00 | 0xFF
        //      P2   - 0x80
        //      Data - PIN
        //
        // If P1 is 0xFF, the Data field should be empty
        if cmd.p1 == 0xFF && !cmd.data().is_empty() {
            return Ok(Status::IncorrectP1orP2.into());
        }
        if cmd.p2 != 0x80 {
            return Ok(Status::KeyReferenceNotFound.into());
        }
        match cmd.p1 {
            0x00 => {
                // PIN was already verified -> return OK
                if self.state != SCardState::PinVerified {
                    if !cmd.data().is_empty() && !(6..=8).contains(&cmd.data().len()) {
                        // Incorrect PIN length -> do not proceed and return an error
                        return Ok(Status::IncorrectDataField.into());
                    }
                    // Retrieve the number of further allowed retries if the data field is absent
                    // Otherwise just compare the provided PIN with the stored one
                    if cmd.data().is_empty() || cmd.data() != self.pin.as_slice() {
                        return Ok(Status::VerificationFailedWithRetries.into());
                    } else {
                        // data field is present and the provided PIN is correct -> change state and return OK
                        self.state = SCardState::PinVerified;
                    }
                }
            }
            0xFF => {
                // p1 is 0xFF and the data field is absent -> reset the security status and return OK
                self.state = SCardState::PivAppSelected;
            }
            _ => return Ok(Status::IncorrectP1orP2.into()),
        };
        Ok(Status::OK.into())
    }

    fn get_data(&mut self, cmd: Command<1024>) -> Result<Response> {
        // PIV GET DATA command
        //      CLA  - 0x00
        //      INS  - 0xCB
        //      P1   - 0x3F
        //      P2   - 0xFF
        //      Data - a single BER-TLV tag of the data object to be retrieved
        //
        // Our PIV smart card only supports:
        //      5FC102 - Card Holder Unique Identifier
        //      5FC105 - X.509 Certificate for PIV Authentication
        if cmd.p1 != 0x3F || cmd.p2 != 0xFF {
            return Ok(Status::IncorrectP1orP2.into());
        }
        let request = Tlv::from_bytes(cmd.data())?;
        if request.tag() != &Tag::try_from(tlv_tags::TAG_LIST)? {
            return Ok(Status::NotFound.into());
        }
        match request.value() {
            Value::Primitive(tag) => match tag.as_slice() {
                CHUID_TAG => Ok(Response::new(Status::OK, Some(self.chuid.to_vec()))),
                PIV_CERT_TAG => {
                    // certificate is almost certainly longer than 256 bytes, so we can just set a pending response and call the GET RESPONSE handler
                    self.pending_response = Some(self.auth_cert.clone());
                    self.get_response()
                }
                _ => Ok(Status::NotFound.into()),
            },
            Value::Constructed(_) => Ok(Status::NotFound.into()),
        }
    }

    fn get_response(&mut self) -> Result<Response> {
        match self.get_next_response_chunk() {
            Some((chunk, bytes_left)) => {
                let status = if bytes_left == 0 {
                    self.pending_response = None;
                    Status::OK
                } else if bytes_left < CHUNK_SIZE {
                    // conversion is safe as we know that bytes_left isn't bigger than 256
                    Status::MoreAvailable(bytes_left.try_into().unwrap())
                } else {
                    // 0 indicates that we have 256 or more bytes left to be read
                    Status::MoreAvailable(0)
                };
                Ok(Response::new(status, Some(chunk)))
            }
            None => Ok(Status::NotFound.into()),
        }
    }

    fn general_authenticate(&mut self, cmd: Command<1024>) -> Result<Response> {
        // PIV GENERAL AUTHENTICATE command
        //      CLA  - 0x00 | 0x10 (command chaining)
        //      INS  - 0x87
        //      P1   - 0x07 - RSA
        //      P2   - 0x9A - PIV Authentication Key
        //      Data - Dynamic Authentication Template with Challenge inside
        //
        // There are many possible P1 and P2 values in this command, but our smart card only supports the RSA algorithm and data signing using the PIV Authentication Key
        if cmd.p1 != 0x07 || cmd.p2 != 0x9A {
            return Err(Error::new(
                ErrorKind::UnsupportedFeature,
                format!("Provided algorithm or key reference isn't supported: got algorithm {}, expected 0x07; got key reference {}, expected 0x9A", cmd.p1, cmd.p2)
            ));
        }
        let request = Tlv::from_bytes(cmd.data())?;
        if request.tag() != &Tag::try_from(tlv_tags::DYNAMIC_AUTHENTICATION_TEMPLATE)?
            || !request.value().is_constructed()
        {
            // wrong TLV request structure
            return Err(Error::new(
                ErrorKind::InvalidValue,
                "TLV structure is invalid: wrong top-level tag structure".to_string(),
            ));
        }
        let inner_tlv = match request.value() {
            // we already know that the value is constructed at this point
            Value::Primitive(_) => unreachable!(),
            Value::Constructed(tlv_vec) => tlv_vec,
        };
        // to avoid constructing the tag on each iteration
        let challenge_tag = Tag::try_from(tlv_tags::DAT_CHALLENGE)?;
        let challenge = inner_tlv
            .iter()
            .find(|&tlv| tlv.tag() == &challenge_tag)
            .ok_or(Error::new(
                ErrorKind::InvalidValue,
                "TLV structure is invalid: no challenge field is present in the request".to_string(),
            ))?;
        let challenge = match challenge.value() {
            Value::Primitive(ref challenge) => challenge,
            Value::Constructed(_) => {
                // this tag must contain a primitive value
                return Err(Error::new(
                    ErrorKind::InvalidValue,
                    "TLV structure is invalid: challenge field contains constructed value".to_string(),
                ));
            }
        };
        let signed_challenge = sign_hashed_rsa(&self.auth_pk, challenge)?;
        let response = Tlv::new(
            Tag::try_from(tlv_tags::DYNAMIC_AUTHENTICATION_TEMPLATE)?,
            Value::Constructed(vec![Tlv::new(
                Tag::try_from(tlv_tags::DAT_RESPONSE)?,
                Value::Primitive(signed_challenge),
            )?]),
        )?
        .to_vec();
        self.pending_response = Some(response);
        self.get_response()
    }

    fn get_next_response_chunk(&mut self) -> Option<(Vec<u8>, usize)> {
        let vec = self.pending_response.as_mut()?;
        if vec.is_empty() {
            return None;
        }
        let next_chunk_length = CHUNK_SIZE.min(vec.len());
        let chunk = vec.drain(0..next_chunk_length).collect::<Vec<u8>>();
        Some((chunk, vec.len()))
    }
}

#[derive(Debug, PartialEq)]
enum SCardState {
    Ready,
    PivAppSelected,
    PinVerified,
}

#[cfg(test)]
mod tests {
    extern crate std;

    use picky::hash::HashAlgorithm;
    use picky::signature::SignatureAlgorithm;
    use rand::distributions::Uniform;
    use rand::Rng;
    use rsa::traits::PublicKeyParts;
    use rsa::BigUint;

    pub use super::*;
    use crate::ber_tlv::ber_tlv_length_encoding;

    #[cfg(feature = "proptest")]
    mod proptests {
        use proptest::prelude::*;
        use proptest::{collection, option, prop_compose};

        use super::*;

        fn arb_status() -> impl Strategy<Value = Status> {
            prop_oneof![
                Just(Status::NotFound),
                Just(Status::OK),
                Just(Status::VerificationFailedWithRetries),
                any::<u8>().prop_map(Status::MoreAvailable),
                Just(Status::KeyReferenceNotFound),
                Just(Status::SecurityStatusNotSatisfied),
                Just(Status::IncorrectP1orP2),
                Just(Status::IncorrectDataField),
                Just(Status::InstructionNotSupported)
            ]
        }

        prop_compose! {
            fn arb_response()(status in arb_status(), data in option::of(collection::vec(any::<u8>(), 0..256))) -> Response {
                Response::new(status, data)
            }
        }

        proptest! {
            #[test]
            fn response_is_encoded_correctly(arb_response in arb_response()) {
                let data = arb_response.data.clone();
                let status: [u8; 2] = arb_response.status.clone().into();
                let expected_result = if let Some(mut bytes) = data {
                    bytes.extend(status);
                    bytes
                } else {
                    Vec::from(status)
                };
                assert_eq!(expected_result, Vec::from(arb_response));
            }
        }
    }

    fn new_scard() -> SmartCard {
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
        let certificate_stub = vec![0xff; 1024];
        let pin = vec![0x39; 6];
        SmartCard::new(pin, certificate_stub, rsa_2048_private_key).unwrap()
    }

    // Helper function that calls the GET RESPONSE handler until there is no more data to read
    fn get_all_available_data(mut response: Response, scard: &mut SmartCard) -> Vec<u8> {
        let mut complete_response = vec![];
        while let Status::MoreAvailable(bytes_left) = response.status {
            complete_response.extend_from_slice(&response.data.expect("Data should be present"));
            let apdu_get_response = vec![0x00, 0xC0, 0x00, 0x00, bytes_left];
            response = scard
                .handle_command(&apdu_get_response)
                .expect("Can't retrieve all available data");
        }
        assert_eq!(response.status, Status::OK);
        complete_response.extend_from_slice(&response.data.expect("The last chunk of data isn't present"));
        complete_response
    }

    #[test]
    fn scard_invalid_apdu_command() {
        // Verify that smart card correctly handles invalid APDU commands
        let mut scard = new_scard();

        let bad_apdu_command = vec![0x00; 2048];
        let response = scard.handle_command(&bad_apdu_command);
        assert!(response.is_err_and(|err| err.error_kind == ErrorKind::InternalError
            && err
                .description
                .contains("Error: an error happened while parsing an APDU command")));
    }

    #[test]
    fn scard_wrong_command_order() {
        // Verify that the smart card prohibits using any commands besides SELECT when no app was selected
        let mut scard = new_scard();

        let mut apdu_verify_cmd = vec![0x00, 0x20, 0x00, 0x80, 0x08];
        // add pin
        apdu_verify_cmd.extend_from_slice(&[0xA9; 8]);
        let response = scard.handle_command(&apdu_verify_cmd);
        assert!(response.is_ok_and(|resp| resp.status == Status::NotFound));
    }

    #[test]
    fn scard_invalid_select_command() {
        // Verify that the SELECT handler correctly responds if called with an invalid AID
        let mut scard = new_scard();

        let bad_aid = vec![0xff; 11];

        let mut apdu_select_cmd = vec![0x00, 0xA4, 0x04, 0x00, 0x0B];
        apdu_select_cmd.extend_from_slice(&bad_aid);
        let response = scard.handle_command(&apdu_select_cmd);
        assert!(response.is_ok_and(|resp| resp.status == Status::NotFound));
    }

    #[test]
    fn scard_select_command() {
        // Verify that the SELECT command works as expected and returns expected output
        let mut scard = new_scard();

        let mut expected_response = vec![
            0x61, 0x17, 0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x0D, 0x4F, 0x0B,
        ];
        expected_response.extend_from_slice(&PIV_AID);

        let mut apdu_select_cmd = vec![0x00, 0xA4, 0x04, 0x00, 0x0B];
        apdu_select_cmd.extend_from_slice(&PIV_AID);
        let response = scard.handle_command(&apdu_select_cmd);
        assert!(response.is_ok_and(
            |resp| resp.status == Status::OK && resp.data.expect("Data should be present") == expected_response
        ));
    }

    #[test]
    fn scard_unsupported_command() {
        // Verify that smart card correctly handles unsupported commands
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // RESET RETRY COUNTER APDU command
        let apdu_reset_retry_cmd = vec![0x00, 0x2C, 0x00, 0x80, 0x00];
        let response = scard.handle_command(&apdu_reset_retry_cmd);
        assert!(response.is_ok_and(|resp| resp.status == Status::InstructionNotSupported));
    }

    #[test]
    fn scard_invalid_verify_commands() {
        // Verify that the VERIFY command handler correctly handles badly structured or malformed requests
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // p1 can only be 0x00 or 0xFF
        let apdu_verify_bad_p1 = vec![0x00, 0x20, 0xAA, 0x80, 0x00];
        let response = scard.handle_command(&apdu_verify_bad_p1);
        assert!(response.is_ok_and(|resp| resp.status == Status::IncorrectP1orP2));

        // if p1 is 0xFF, the data field should be empty
        let apdu_verify_bad_p1_data = vec![0x00, 0x20, 0xFF, 0x80, 0x02, 0xFF, 0xFF];
        let response = scard.handle_command(&apdu_verify_bad_p1_data);
        assert!(response.is_ok_and(|resp| resp.status == Status::IncorrectP1orP2));

        // p2 should always be 0x80
        let apdu_verify_bad_p2 = vec![0x00, 0x20, 0x00, 0x81, 0x02, 0xFF, 0xFF];
        let response = scard.handle_command(&apdu_verify_bad_p2);
        assert!(response.is_ok_and(|resp| resp.status == Status::KeyReferenceNotFound));

        // PIN should be no shorter than six bytes and no longer than 8
        let apdu_verify_bad_pin = vec![0x00, 0x20, 0x00, 0x80, 0x02, 0xAA, 0xAA];
        let response = scard.handle_command(&apdu_verify_bad_pin);
        assert!(response.is_ok_and(|resp| resp.status == Status::IncorrectDataField));
    }

    #[test]
    fn scard_verify_command() {
        // Verify that the VERIFY command handler correctly handles all supported types of requests
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // retrieve number of allowed retries by omitting the data field
        let apdu_verify_no_data = vec![0x00, 0x20, 0x00, 0x80, 0x00];
        let response = scard.handle_command(&apdu_verify_no_data);
        assert!(response.is_ok_and(|resp| resp.status == Status::VerificationFailedWithRetries));

        // VERIFY command with the wrong PIN code
        let mut apdu_verify_wrong_pin = vec![0x00, 0x20, 0x00, 0x80, 0x08];
        apdu_verify_wrong_pin.extend_from_slice(&[0xCC; 8]);
        let response = scard.handle_command(&apdu_verify_wrong_pin);
        assert!(response.is_ok_and(|resp| resp.status == Status::VerificationFailedWithRetries));

        // VERIFY command with the correct PIN code
        let mut apdu_verify_correct_pin = vec![0x00, 0x20, 0x00, 0x80, 0x08];
        apdu_verify_correct_pin.extend_from_slice(&[0x39; 6]);
        // 0xFF padding
        apdu_verify_correct_pin.extend_from_slice(&[0xFF; 2]);
        let response = scard.handle_command(&apdu_verify_correct_pin);
        assert!(response.is_ok_and(|resp| resp.status == Status::OK));
        assert_eq!(scard.state, SCardState::PinVerified);

        // Reset the security status
        let apdu_verify_reset = vec![0x00, 0x20, 0xFF, 0x80, 0x00];
        let response = scard.handle_command(&apdu_verify_reset);
        assert!(response.is_ok_and(|resp| resp.status == Status::OK));
        assert_eq!(scard.state, SCardState::PivAppSelected);
    }

    #[test]
    fn scard_get_response_command() {
        // Verify that the GET RESPONSE handler correctly sends the data
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;
        let mut rng = rand::thread_rng();

        // get a random Vec<u8> of length 513
        let data: Vec<u8> = (0..513).map(|_| rng.sample(Uniform::new(0, 255))).collect();
        // we will have to make 3 calls to get this data
        scard.pending_response = Some(data.clone());

        let mut received_result = vec![];
        // 0 means any valid number in range 0..=256
        // We set this to 0 on the first call so that the smart card returns whatever it got
        let bytes_left = 0;
        let mut apdu_get_response = vec![0x00, 0xC0, 0x00, 0x00, bytes_left];

        let response = scard.handle_command(&apdu_get_response);
        assert!(response
            .as_ref()
            .is_ok_and(|resp| resp.status == Status::MoreAvailable(0)
                && resp.data.is_some()
                && resp.data.as_ref().unwrap() == &data[0..256]));
        received_result.extend_from_slice(&response.unwrap().data.unwrap());

        let response = scard.handle_command(&apdu_get_response);
        assert!(response
            .as_ref()
            .is_ok_and(|resp| resp.status == Status::MoreAvailable(1)
                && resp.data.is_some()
                && resp.data.as_ref().unwrap() == &data[256..512]));
        received_result.extend_from_slice(&response.unwrap().data.unwrap());

        // set the Le field to 1 so that we get the last remaining byte
        apdu_get_response[4] = 1;
        let response = scard.handle_command(&apdu_get_response);
        assert!(response.as_ref().is_ok_and(|resp| resp.status == Status::OK
            && resp.data.is_some()
            && resp.data.as_ref().unwrap() == &data[512..]));
        received_result.extend_from_slice(&response.unwrap().data.unwrap());

        assert_eq!(received_result, data);
    }

    #[test]
    fn scard_invalid_get_data_command() {
        // Verify that the GET DATA handler correctly handles invalid requests
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // p1 should always be 0x3F; p2 should always be 0xFF
        let apdu_get_data_bad_p1_p2 = vec![0x00, 0xCB, 0x10, 0x21, 0x00];
        let response = scard.handle_command(&apdu_get_data_bad_p1_p2);
        assert!(response.is_ok_and(|resp| resp.status == Status::IncorrectP1orP2));

        // bad object tag in the data field
        let apdu_get_data_bad_tag = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x08];
        let response = scard.handle_command(&apdu_get_data_bad_tag);
        assert!(response.is_ok_and(|resp| resp.status == Status::NotFound));
    }

    #[test]
    fn scard_get_data_command() {
        // Verify that the GET DATA handler correctly handles all supported requests and returns correct data
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        // get CHUID
        let apdu_get_data_chuid = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x02];
        let response = scard.handle_command(&apdu_get_data_chuid);
        assert!(
            response.is_ok_and(|resp| resp.status == Status::OK && resp.data.expect("Expected CHUID") == scard.chuid)
        );

        // get PIV authentication certificate
        let apdu_get_data_chuid = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05];
        let response = scard.handle_command(&apdu_get_data_chuid);
        // verify the contents
        assert!(response.is_ok_and(|resp| {
            // as the certificate is larger than 256 bytes, we have to call the GET RESPONSE function a few times
            let complete_response = get_all_available_data(resp, &mut scard);
            complete_response == scard.auth_cert
        }));
    }

    #[test]
    fn scard_general_authenticate_no_pin() {
        // Verify that the GENERAL AUTHENTICATE handler can't be used without unlocking the smart card first
        let mut scard = new_scard();
        scard.state = SCardState::PivAppSelected;

        let apdu_general_authenticate = vec![0x00, 0x87, 0x07, 0x9A, 0x00];
        let response = scard.handle_command(&apdu_general_authenticate);
        assert!(response.is_ok_and(|resp| resp.status == Status::SecurityStatusNotSatisfied));
    }

    #[test]
    fn scard_invalid_general_authenticate_command() {
        // Verify that the GENERAL AUTHENTICATE handler correctly handles invalid requests
        let mut scard = new_scard();
        scard.state = SCardState::PinVerified;

        // p1 should always be 0x07; p2 should always be 0x9A
        let apdu_general_authenticate = vec![0x00, 0x87, 0xFF, 0xCC, 0x00];
        let response = scard.handle_command(&apdu_general_authenticate);
        assert!(response.is_err_and(|err| err.error_kind == ErrorKind::UnsupportedFeature));
    }

    #[test]
    fn scard_general_authenticate_command() {
        // Verify that the GENERAL AUTHENTICATE handler correctly encrypts the provided data
        let mut scard = new_scard();
        scard.state = SCardState::PinVerified;

        let data = "My message".as_bytes();

        let rsa_pk = rsa::RsaPrivateKey::try_from(&scard.auth_pk).expect("Can't convert the private key");
        // sign the data using the PKCS1-v1.5 padding scheme
        let signature_algorithm = SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA3_512);
        let signed_data = signature_algorithm
            .sign(data, &scard.auth_pk)
            .expect("Error while signing the data");
        // extract the padded hash by decrypting the signature using the public key
        // we need to extract the padded hash to calculate the signature ourselves
        let padded_hash = BigUint::from_bytes_be(&signed_data)
            .modpow(rsa_pk.e(), rsa_pk.n())
            .to_bytes_be();

        // the hash is bigger than 127, so we have to use BER-TLV encoding
        let encoded_hash_length = ber_tlv_length_encoding(padded_hash.len());
        // encoded_hash_length + tag + hash
        let dat_tag_data_length = ber_tlv_length_encoding(1 + encoded_hash_length.len() + padded_hash.len());

        // use command chaining to send the data that is bigger than 255 bytes
        let mut apdu_general_authenticate = vec![0x10, 0x87, 0x07, 0x9A, 0xFF, 0x7C];
        apdu_general_authenticate.extend_from_slice(&dat_tag_data_length);
        apdu_general_authenticate.extend_from_slice(&[0x81]);
        apdu_general_authenticate.extend_from_slice(&encoded_hash_length);
        apdu_general_authenticate.extend_from_slice(&padded_hash[..248]);

        let response = scard.handle_command(&apdu_general_authenticate);
        assert!(response.is_ok_and(|resp| resp.status == Status::OK));

        // send the remaining data and end command chaining by setting the CLA byte to 0x00
        let mut apdu_general_authenticate = vec![0x00, 0x87, 0x07, 0x9A, 0x07];
        apdu_general_authenticate.extend_from_slice(&padded_hash[248..]);
        // Le
        apdu_general_authenticate.extend_from_slice(&[0x00]);

        let response = scard
            .handle_command(&apdu_general_authenticate)
            .expect("Shouldn't have failed");

        let complete_response = get_all_available_data(response, &mut scard);
        let parsed_response =
            Tlv::from_bytes(&complete_response).expect("Couldn't parse a TLV object sent from the smart card");

        // verify the structure of the response and extract the signed hash
        assert_eq!(
            parsed_response.tag(),
            &Tag::try_from(tlv_tags::DYNAMIC_AUTHENTICATION_TEMPLATE).expect("Couldn't construct a TLV tag")
        );
        let response_tag = match parsed_response.value() {
            Value::Constructed(data) => data
                .iter()
                .find(|tlv_object| {
                    tlv_object.tag() == &Tag::try_from(tlv_tags::DAT_RESPONSE).expect("Couldn't construct a TLV tag")
                })
                .expect("The inner TLV object should contain a Response tag"),
            Value::Primitive(_) => panic!("Dynamic Authentication Template should contain constructed value"),
        };
        let signed_hash = match response_tag.value() {
            Value::Constructed(_) => panic!("Response tag should contain a primitive value"),
            Value::Primitive(signed_hash) => signed_hash,
        };
        // verify that the returned signature can be verified using the corresponding public key
        assert!(signature_algorithm
            .verify(
                &scard
                    .auth_pk
                    .to_public_key()
                    .expect("Error while creating public key from a private key"),
                data,
                signed_hash
            )
            .is_ok());
    }
}
