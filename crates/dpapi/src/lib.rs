// #![warn(missing_docs)]
#![doc = include_str!("../README.md")]
#![allow(dead_code)]

mod macros;

mod blob;
mod error;
pub mod rpc;

pub use error::*;
