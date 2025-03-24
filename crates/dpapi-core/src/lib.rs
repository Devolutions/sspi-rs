#![cfg_attr(not(feature = "std"), no_std)]
#![warn(clippy::std_instead_of_alloc)]
#![warn(clippy::std_instead_of_core)]
// #![warn(missing_docs)]

extern crate alloc;

mod decode;
mod encode;
mod error;
pub mod gkdi;
mod marker;
mod padding;
pub mod rpc;
pub mod str;

pub use decode::{DecodeWithContextOwned, FindLength, FixedPartSize, decode_uuid, read_c_str_utf16_le};
pub use encode::{EncodeVec, encode_seq, encode_uuid, size_seq};
pub use error::{Error, Result};
pub use ironrdp_core::{DecodeError, DecodeOwned, Encode, EncodeError, ReadCursor, WriteCursor, decode_owned};
pub use marker::NeedsContext;
pub use padding::Padding;
