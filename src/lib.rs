//! sspi-rs is a Rust implementation of [Security Support Provider Interface (SSPI)](https://docs.microsoft.com/en-us/windows/win32/rpc/security-support-provider-interface-sspi-).
//! It ships with platform-independent implementations of [Security Support Providers (SSP)](https://docs.microsoft.com/en-us/windows/win32/rpc/security-support-providers-ssps-),
//! and is able to utilize native Microsoft libraries when ran under Windows.
//!
//! The purpose of sspi-rs is to clean the original interface from cluttering and provide users with Rust-friendly SSPs for execution under Linux or any other platform that is
//! able to compile Rust.
//!
//! # Getting started
//!
//! Here is a quick example how to start working with the crate. This is the first stage of the client-server authentication performed on the client side.
//! It includes calling several SSPI functions and choosing between our own and WinAPI implementations of NTLM SSP depending on the system:
//! ```
//! use sspi::Sspi;
//!
//! #[cfg(windows)]
//! use sspi::winapi::Ntlm;
//! #[cfg(not(windows))]
//! use sspi::Ntlm;
//!
//! fn main() {
//!     let mut ntlm = Ntlm::new();
//!
//!     let identity = sspi::AuthIdentity {
//!         username: "user".to_string(),
//!         password: "password".to_string(),
//!         domain: None,
//!     };
//!
//!     let mut acq_creds_handle_result = ntlm
//!         .acquire_credentials_handle()
//!         .with_credential_use(sspi::CredentialUse::Outbound)
//!         .with_auth_data(&identity)
//!         .execute()
//!         .expect("AcquireCredentialsHandle resulted in error");
//!
//!     let mut output = vec![sspi::SecurityBuffer::new(
//!         Vec::new(),
//!         sspi::SecurityBufferType::Token,
//!     )];
//!
//!     let result = ntlm
//!         .initialize_security_context()
//!         .with_credentials_handle(&mut acq_creds_handle_result.credentials_handle)
//!         .with_context_requirements(
//!             sspi::ClientRequestFlags::CONFIDENTIALITY | sspi::ClientRequestFlags::ALLOCATE_MEMORY
//!         )
//!         .with_target_data_representation(sspi::DataRepresentation::Native)
//!         .with_output(&mut output)
//!         .execute()
//!         .expect("InitializeSecurityContext resulted in error");
//!
//!     println!("Initialized security context with result status: {:?}", result.status);
//! }
//!
//! ```
//! It is also possible to use any of the Windows SSPs that we do not implement. Here is an example of querying all
//! available SSPs and acquiring Negotiate SSP on Windows:
//! ```
//! # #[cfg(windows)]
//! # mod win {
//! # fn main() {
//! let package_name = "Negotiate";
//! // Get information about the specified security package
//! let package = sspi::winapi::query_security_package_info(sspi::SecurityPackageType::Other(package_name.to_string()))
//!     .expect("query_security_package_info resulted in error");
//!
//! // Acquire the SSP using its name
//! let pack = sspi::winapi::SecurityPackage::from_package_name(package_name.to_string());
//! # }
//! # }
//! ```

mod ber;
mod crypto;
mod sspi;
mod utils;

#[cfg(windows)]
pub use crate::sspi::winapi;
pub use crate::sspi::{
    builders, enumerate_security_packages, internal, query_security_package_info,
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity,
    CertTrustErrorStatus, CertTrustInfoStatus, CertTrustStatus, ClientRequestFlags,
    ClientResponseFlags, ContextNames, ContextSizes, CredentialUse, DataRepresentation,
    DecryptionFlags, EncryptionFlags, Error, ErrorKind, InitializeSecurityContextResult, Ntlm,
    PackageCapabilities, PackageInfo, Result, SecurityBuffer, SecurityBufferType,
    SecurityPackageType, SecurityStatus, ServerRequestFlags, ServerResponseFlags, Sspi, SspiEx,
};
