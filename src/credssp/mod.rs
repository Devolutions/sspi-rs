mod ts_request;

pub use ts_request::{NStatusCode, TsRequest, read_ts_credentials, write_ts_credentials};

/// Controls whether delegated credentials are included in a CredSSP credentials message.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CredSspMode {
    WithCredentials,
    /// Requests credential-less logon, also known as restricted admin mode.
    CredentialLess,
}

#[cfg(feature = "credssp")]
mod protocol;
#[cfg(feature = "tsssp")]
pub use protocol::sspi_cred_ssp;
#[cfg(feature = "credssp")]
pub use protocol::*;
