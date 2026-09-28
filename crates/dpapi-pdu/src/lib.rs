#![cfg_attr(not(feature = "std"), no_std)]
// This crate decodes untrusted network data, so out-of-bounds access must be handled explicitly.
#![deny(clippy::indexing_slicing)]

extern crate alloc;

mod error;
pub mod gkdi;
pub mod rpc;
pub use error::{Error, Result};
