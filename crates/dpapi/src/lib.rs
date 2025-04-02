#![doc = include_str!("../README.md")]
#![allow(dead_code)]

#[macro_use]
extern crate tracing;

pub mod blob;
mod client;
mod connect_options;
pub mod crypto;
pub mod error;
pub mod gkdi;
pub mod rpc;
pub(crate) mod sid;
mod stream;

pub use client::{n_crypt_protect_secret, n_crypt_unprotect_secret, CryptProtectSecretArgs};
pub use connect_options::{ConnectionOptions, ConnectionUrlParseError, WebAppAuth};
pub use error::{Error, Result};
pub use sspi;
pub use stream::{LocalStream, Transport};
