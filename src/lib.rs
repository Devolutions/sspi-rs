// FromPrimitive and ToPrimitive causes clippy error, so we disable it until
// https://github.com/rust-num/num-derive/issues/20 is fixed
#![cfg_attr(feature = "cargo-clippy", allow(clippy::useless_attribute))]

#[macro_use]
pub mod utils;
pub mod ber;
pub mod credssp;
pub mod ntlm;
pub mod sspi;

mod crypto;

pub use crate::{
    credssp::{
        ts_request::TsRequest, CredSsp, CredSspClient, CredSspResult, CredSspServer,
        CredentialsProxy, EarlyUserAuthResult, NegotiationRequestFlags,
        EARLY_USER_AUTH_RESULT_PDU_SIZE,
    },
    ntlm::NTLM_VERSION_SIZE,
    sspi::{Credentials, SspiError, SspiErrorType},
};
