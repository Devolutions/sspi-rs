#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::{fmt, result};

use iso7816::Aid;

const PIV_AID: Aid = Aid::new_truncatable(&[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00], 9);

pub type ApduResult<T> = result::Result<T, Error>;

#[derive(Debug)]
pub struct Response {
    status: Status,
    data: Option<Vec<u8>>,
}

impl Response {
    pub fn new(status: Status, data: Option<Vec<u8>>) -> Self {
        Response { status, data }
    }
}

impl From<Response> for Vec<u8> {
    fn from(value: Response) -> Self {
        let status_as_bytes: [u8; 2] = value.status.into();
        let vec_capacity = status_as_bytes.len() + value.data.as_ref().map(|data| data.len()).unwrap_or(0);
        let mut encoded: Vec<u8> = Vec::with_capacity(vec_capacity);
        if let Some(bytes) = value.data {
            encoded.extend(bytes);
        }
        encoded.extend(status_as_bytes);
        encoded
    }
}

pub struct Error {
    pub error_kind: ErrorKind,
    pub description: String,
}

impl Error {
    fn new(error_kind: ErrorKind, description: impl Into<String>) -> Self {
        Error {
            error_kind,
            description: description.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.error_kind, self.description)?;
        Ok(())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[derive(Debug)]
pub enum ErrorKind {
    MalformedRequest,
}

pub enum SCardState {
    Ready,
    PivAppSelected,
    PinVerified,
    TransactionInProgress,
}

#[derive(Debug, Clone)]
pub enum Status {
    NotFound,
    OK,
    VerificationFailed,
    MoreAvailable(u8),
    KeyReferenceNotFound,
    SecurityStatusNotSatisfied,
    IncorrectP1orP2,
    IncorrectDataField,
}

impl From<Status> for [u8; 2] {
    fn from(value: Status) -> Self {
        match value {
            Status::NotFound => [0x6A, 0x82],
            Status::OK => [0x90, 0x00],
            Status::VerificationFailed => [0x63, 0x00],
            Status::MoreAvailable(bytes_left) => [0x61, bytes_left],
            Status::KeyReferenceNotFound => [0x6A, 0x88],
            Status::SecurityStatusNotSatisfied => [0x69, 0x82],
            Status::IncorrectP1orP2 => [0x6A, 0x86],
            Status::IncorrectDataField => [0x6A, 0x80],
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    pub use super::*;

    #[cfg(feature = "proptest")]
    mod proptests {
        use proptest::prelude::*;
        use proptest::{collection, option, prop_compose};

        use super::*;

        fn arb_status() -> impl Strategy<Value = Status> {
            prop_oneof![
                Just(Status::NotFound),
                Just(Status::OK),
                Just(Status::VerificationFailed),
                any::<u8>().prop_map(Status::MoreAvailable),
                Just(Status::KeyReferenceNotFound),
                Just(Status::SecurityStatusNotSatisfied),
                Just(Status::IncorrectP1orP2),
                Just(Status::IncorrectDataField)
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
}
