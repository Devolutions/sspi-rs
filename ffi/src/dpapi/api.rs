#[cfg(not(any(test, miri)))]
mod inner {
    pub use dpapi::{n_crypt_protect_secret, n_crypt_unprotect_secret};
}

#[cfg(any(test, miri))]
mod inner {
    //! We have FFI wrappers for DPAPI functions from the [dpapi] crate and we want to test them.
    //! The DPAPI implementation is complex and makes calls to the RPC and KDC servers.
    //! Implementing a mock for KDF and RPC servers is too hard and unreasonable. So, we wrote a simple
    //! high-level mock of [n_crypt_protect_secret] and [n_crypt_unprotect_secret] functions.
    //!
    //! **Note**: The goal is to test FFI functions, not the DPAPI implementation correctness.
    //! The FFI tests should not care about returned data correctness but rather check
    //! for memory corruptions and memory leaks.

    use sspi::Secret;
    use uuid::Uuid;

    pub fn n_crypt_unprotect_secret(
        _blob: &[u8],
        _server: &str,
        _username: &str,
        _password: Secret<String>,
        _client_computer_name: Option<String>,
    ) -> dpapi::Result<Secret<Vec<u8>>> {
        Ok(b"secret-to-encrypt".to_vec().into())
    }

    pub fn n_crypt_protect_secret(
        _data: Secret<Vec<u8>>,
        _sid: String,
        _root_key_id: Option<Uuid>,
        _server: &str,
        _username: &str,
        _password: Secret<String>,
        _client_computer_name: Option<String>,
    ) -> dpapi::Result<Vec<u8>> {
        Ok(b"DPAPI_blob".to_vec())
    }
}

pub use inner::*;
