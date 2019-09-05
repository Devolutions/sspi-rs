#[macro_use]
pub mod utils;
pub mod ber;
pub mod credssp;
pub mod ntlm;
pub mod sspi;

mod crypto;

pub use crate::{
    credssp::{
        ts_request::{TsRequest, MAX_TS_REQUEST_LENGTH_BUFFER_SIZE},
        CredSspClient, CredSspMode, CredSspResult, CredSspServer, CredentialsProxy,
        EarlyUserAuthResult, EARLY_USER_AUTH_RESULT_PDU_SIZE,
    },
    ntlm::NTLM_VERSION_SIZE,
    sspi::{Credentials, SspiError, SspiErrorType},
};
