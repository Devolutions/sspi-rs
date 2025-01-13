#![doc = include_str!("../README.md")]
#![allow(dead_code)]

#[macro_use]
extern crate tracing;

pub mod blob;
mod client;
pub mod crypto;
pub mod error;
pub mod epm;
pub mod gkdi;
pub mod rpc;
pub(crate) mod sid;
pub(crate) mod str;

pub use client::*;
pub use error::{Error, Result};
