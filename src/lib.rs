//! The Rust implementation of the Remote Desktop Protocol.

// FromPrimitive and ToPrimitive causes clippy error, so we disable it until
// https://github.com/rust-num/num-derive/issues/20 is fixed
#![cfg_attr(feature = "cargo-clippy", allow(clippy::useless_attribute))]

mod utils;
mod ber;
mod crypto;

pub mod credssp;
pub mod ntlm;
pub mod sspi;

pub use crate::credssp::{
    ts_request::TsRequest, CredSsp, CredSspClient, CredSspResult, CredSspServer, CredentialsProxy,
};
pub use crate::ntlm::NTLM_VERSION_SIZE;
pub use crate::sspi::{Credentials, Sspi, SspiResult, SspiError, SspiErrorType};

