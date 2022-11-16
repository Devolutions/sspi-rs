#![allow(clippy::missing_safety_doc)]

#[cfg(feature = "debug_mode")]
#[macro_use]
extern crate tracing;

#[macro_use]
mod macros;

pub mod common;
pub mod credentials_attributes;
pub mod debug;
pub mod sec_buffer;
pub mod sec_handle;
pub mod sec_pkg_info;
pub mod sec_winnt_auth_identity;
pub mod security_tables;
pub mod sspi_data_types;
pub mod utils;
