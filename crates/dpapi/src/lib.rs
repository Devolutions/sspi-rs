#![doc = include_str!("../README.md")]
#![allow(dead_code)]

#[macro_use]
extern crate tracing;

pub mod blob;
pub mod client;
pub mod crypto;
pub mod error;
pub mod gkdi;
pub mod rpc;
pub(crate) mod sid;
mod stream;

pub use client::{n_crypt_protect_secret, n_crypt_unprotect_secret};
pub use error::{Error, Result};
pub use stream::{LocalStream, Transport};

// Re-export
pub use sspi;
