#![allow(clippy::missing_safety_doc)]
#![allow(non_snake_case)]

#[macro_use]
extern crate tracing;

pub mod logging;
pub mod sspi;
mod utils;
#[cfg(feature = "scard")]
pub mod winscard;
