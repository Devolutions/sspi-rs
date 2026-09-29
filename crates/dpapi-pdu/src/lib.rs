#![cfg_attr(not(feature = "std"), no_std)]
#![deny(
    clippy::indexing_slicing,
    reason = "crate decodes untrusted network data, we handle out-of-bounds access explicitly"
)]

extern crate alloc;

mod error;
pub mod gkdi;
pub mod rpc;
pub use error::{Error, Result};
