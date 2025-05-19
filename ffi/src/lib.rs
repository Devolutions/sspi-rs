#![allow(clippy::missing_safety_doc)]
#![allow(clippy::print_stdout)]
#![allow(non_snake_case)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]

#[macro_use]
extern crate tracing;

#[cfg(feature = "dpapi")]
#[deny(unsafe_op_in_unsafe_fn)]
#[warn(clippy::undocumented_unsafe_blocks)]
pub mod dpapi;
pub mod logging;
pub mod sspi;
mod utils;
#[cfg(feature = "scard")]
pub mod winscard;
