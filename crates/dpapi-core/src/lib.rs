#![cfg_attr(not(feature = "std"), no_std)]
#![warn(clippy::std_instead_of_alloc)]
#![warn(clippy::std_instead_of_core)]
// #![warn(missing_docs)]

extern crate alloc;

mod cursor;
mod decode;
mod encode;
mod error;
mod marker;
mod padding;
pub mod rpc;
mod write_buf;

pub use cursor::{ReadCursor, WriteCursor};
pub use decode::{Decode, DecodeWithContext, FindLength};
pub use encode::Encode;
pub use error::{Error, Result};
pub use marker::NeedsContext;
pub use padding::Padding;
pub use write_buf::WriteBuf;
