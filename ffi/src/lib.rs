#![allow(clippy::missing_safety_doc)]
#![allow(clippy::print_stdout)]
#![allow(non_snake_case)]

#[macro_use]
extern crate tracing;

#[cfg(feature = "dpapi")]
#[deny(unsafe_op_in_unsafe_fn)]
#[warn(clippy::undocumented_unsafe_blocks)]
pub mod dpapi;
pub mod logging;
#[deny(unsafe_op_in_unsafe_fn)]
#[warn(clippy::undocumented_unsafe_blocks)]
pub mod sspi;
mod utils;
#[cfg(feature = "scard")]
#[deny(unsafe_op_in_unsafe_fn)]
#[warn(clippy::undocumented_unsafe_blocks)]
pub mod winscard;
