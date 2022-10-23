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
//!
//! ```rust
//! use sspi::Sspi;
//!
//! #[cfg(windows)]
//! use sspi::winapi::Ntlm;
//! #[cfg(not(windows))]
//! use sspi::Ntlm;
//! use sspi::builders::EmptyInitializeSecurityContext;
//! use crate::sspi::internal::SspiImpl;
//!
//! let mut ntlm = Ntlm::new();
//!
//! let identity = sspi::AuthIdentity {
//!     username: "user".to_string(),
//!     password: "password".to_string(),
//!     domain: None,
//! };
//!
//! let mut acq_creds_handle_result = ntlm
//!     .acquire_credentials_handle()
//!     .with_credential_use(sspi::CredentialUse::Outbound)
//!     .with_auth_data(&identity)
//!     .execute()
//!     .expect("AcquireCredentialsHandle resulted in error");
//!
//! let mut output = vec![sspi::SecurityBuffer::new(
//!     Vec::new(),
//!     sspi::SecurityBufferType::Token,
//! )];
//!
//! let mut builder = EmptyInitializeSecurityContext::<<Ntlm as SspiImpl>::CredentialsHandle>::new()
//!     .with_credentials_handle(&mut acq_creds_handle_result.credentials_handle)
//!     .with_context_requirements(
//!         sspi::ClientRequestFlags::CONFIDENTIALITY | sspi::ClientRequestFlags::ALLOCATE_MEMORY
//!     )
//!     .with_target_data_representation(sspi::DataRepresentation::Native)
//!     .with_output(&mut output);
//!
//! let result = ntlm.initialize_security_context_impl(&mut builder)
//!     .expect("InitializeSecurityContext resulted in error");
//!
//! println!("Initialized security context with result status: {:?}", result.status);
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
//! let pack = sspi::winapi::SecurityPackage::from_package_type(package.name);
//! # }
//! # }
//! ```

mod ber;
mod crypto;
mod utils;

cfg_if::cfg_if! {
    if #[cfg(fuzzing)] {
        pub mod sspi;
    } else {
        mod sspi;
    }
}

#[cfg(feature = "network_client")]
pub use utils::resolve_kdc_host;

pub use crate::sspi::kerberos::config::KerberosConfig;
pub use crate::sspi::kerberos::{Kerberos, KERBEROS_VERSION, PACKAGE_INFO as KERBEROS_PACKAGE_INFO};
pub use crate::sspi::negotiate::{Negotiate, NegotiateConfig};
pub use crate::sspi::pku2u::{Pku2u, PACKAGE_INFO as PKU2U_PACKAGE_INFO, Pku2uConfig};
#[cfg(windows)]
pub use crate::sspi::winapi;
pub use crate::sspi::{
    builders, enumerate_security_packages, internal, kerberos, negotiate, ntlm, query_security_package_info,
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers,
    CertTrustErrorStatus, CertTrustInfoStatus, CertTrustStatus, ClientRequestFlags, ClientResponseFlags, ContextNames,
    ContextSizes, CredentialUse, DataRepresentation, DecryptionFlags, EncryptionFlags, Error, ErrorKind,
    InitializeSecurityContextResult, Ntlm, PackageCapabilities, PackageInfo, Result, SecurityBuffer,
    SecurityBufferType, SecurityPackageType, SecurityStatus, ServerRequestFlags, ServerResponseFlags, Sspi, SspiEx,
};
