#![doc = include_str!("../README.md")]
#![allow(dead_code)]

#[macro_use]
extern crate tracing;

pub mod blob;
pub mod crypto;
pub mod error;
pub mod gkdi;
pub mod rpc;
pub(crate) mod sid;
pub(crate) mod str;

pub use error::{DpapiResult, Error};
