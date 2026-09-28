#![allow(clippy::missing_safety_doc)]
#![allow(clippy::print_stdout)]
#![allow(non_snake_case)]
#![deny(unsafe_op_in_unsafe_fn)]
// The FFI layer works with caller-provided buffers and lengths, so out-of-bounds access must be handled explicitly.
#![deny(clippy::indexing_slicing)]

#[macro_use]
extern crate tracing;

#[cfg(feature = "dpapi")]
#[deny(unsafe_op_in_unsafe_fn)]
pub mod dpapi;
pub mod logging;
pub mod sspi;
mod utils;
#[cfg(feature = "scard")]
pub mod winscard;
