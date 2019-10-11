# sspi-rs
[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

**sspi-rs** is a Rust implementation of [Security Support Provider Interface (SSPI)](https://docs.microsoft.com/en-us/windows/win32/rpc/security-support-provider-interface-sspi-). It ships with platform-independent implementations of [Security Support Providers (SSP)](https://docs.microsoft.com/en-us/windows/win32/rpc/security-support-providers-ssps-), and is able to utilize native Microsoft libraries when ran under Windows.

The purpose of sspi-rs is to clean the original interface from cluttering and provide users with Rust-friendly SSPs for execution under *nix or any other platform that is able to compile Rust.

## Overview

The sspi-rs works in accordance with the MSDN documentation. At the moment, [NT LAN Manager (NTLM)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4) is implemented and available for platform independent execution. It is also possible to create your own SSPs by implementing the [`SspiImpl`]() trait. More on that in the [Documentation](target/doc/sspi/index.html).

###### WinAPI
You can switch between the [`sspi`]() module to use the platform independent implementations of the SSPs, and the [`sspi::winapi`]() module to use the native Windows libraries when running under Windows.

###### Ease of use
Some SSPI functions tend to be cumbersome, that's why sspi-rs allows to use SSPI in a convenient way by utilizing builders. Examples are available in the [examples](examples), [example section](#example), and [Documentation](target/doc/sspi/index.html).

## Usage
sspi-rs is included in the Cargo.toml like this:
```TOML
[dependencies]
sspi = "0.1.0"
```
After that you can `use` the types that you need.


## Documentation

Documentation will give you a comprehensive overlook of the crate. For the example of a simple use case, visit the [examples](examples) folder.

## Example

The usage of the SSPs is as simple as creating an instance of the security provider and calling its functions.

It is easy to switch between Windows and our SSP implementations. Here is an example of acquiring a credentials handle and a timestamp of their vaidity. The source of `Ntlm` is selected automatically depending on the platform:
```Rust
#[cfg(windows)]
use sspi::{winapi::Ntlm, Sspi, CredentialUse};
#[cfg(unix)]
use sspi::{Ntlm, Sspi, CredentialUse};

fn main() {
    let mut ntlm = Ntlm::new();
        
    let (cred_handle, timestamp) = ntlm
        .acquire_credentials_handle()
        .with_credential_use(CredentialUse::Inbound)
        .execute()
        .unwrap();
}
```

Example of acquiring an SSP provided by Windows:
```Rust
let mut negotiate = SecurityPackage::from_package_type(
    SecurityPackageType::Other(String::from("Negotiate"))
);
```

## Projects that use sspi-rs

* [Jet](https://github.com/Devolutions/devolutions-jet)
* [LDAP client library](https://github.com/Devolutions/ldap3/tree/spnego)

## License
sspi-rs is licensed under MIT license.
