#![doc = include_str!("../README.md")]
#![allow(dead_code)]

#[macro_use]
extern crate tracing;

pub mod blob;
mod client;
pub mod crypto;
pub mod epm;
pub mod error;
pub mod gkdi;
pub mod rpc;
pub(crate) mod sid;
pub(crate) mod str;

pub use client::{n_crypt_protect_secret, n_crypt_unprotect_secret};
pub use error::{Error, Result};
pub use sspi::Secret;

#[cfg(test)]
mod tests {
    use super::*;

    pub fn init_tracing() {
        use std::io;

        use tracing_subscriber::prelude::*;
        use tracing_subscriber::EnvFilter;

        const DEFAULT_LOG_LEVEL: &str = "trace";

        let logging_filter: EnvFilter = EnvFilter::builder()
            .with_default_directive(DEFAULT_LOG_LEVEL.parse().expect("Default log level constant is bad."))
            .with_env_var("DPAPI_LOG_LEVEL")
            .from_env_lossy();

        let stdout_layer = tracing_subscriber::fmt::layer().pretty().with_writer(io::stdout);

        tracing_subscriber::registry()
            .with(stdout_layer)
            .with(logging_filter)
            .init();
    }

    #[test]
    fn run() {
        init_tracing();

        let username = "t2@tbt.com";
        let password = "qqqQQQ111!!!".to_owned();

        let secret = "TheBestTvarynka";
        println!("secret: {secret}");

        let blob = n_crypt_protect_secret(
            secret.as_bytes(),
            "S-1-5-21-1485435871-894665558-560847465-1104".into(),
            None,
            "192.168.1.104",
            username,
            password.clone().into(),
        )
        .unwrap();

        println!("ENCRYPTED!!!!");

        let plaintext = n_crypt_unprotect_secret(&blob, "192.168.1.104", username, password.into()).unwrap();

        println!("DECRYPTED!!!!");

        assert_eq!(secret.as_bytes(), plaintext.as_slice());
    }
}
