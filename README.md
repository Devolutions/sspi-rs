# sspi-rs

[![](https://docs.rs/sspi/badge.svg)](https://docs.rs/sspi/) [![](https://img.shields.io/crates/v/sspi)](https://crates.io/crates/sspi)

**sspi-rs** is a Rust implementation of [Security Support Provider Interface (SSPI)](https://docs.microsoft.com/en-us/windows/win32/rpc/security-support-provider-interface-sspi-). It ships with platform-independent implementations of [Security Support Providers (SSP)](https://docs.microsoft.com/en-us/windows/win32/rpc/security-support-providers-ssps-), and is able to utilize native Microsoft libraries when ran under Windows.

The purpose of sspi-rs is to clean the original interface from cluttering and provide users with Rust-friendly SSPs for execution under *nix or any other platform that is able to compile Rust.

## Cargo features

The default feature set is `all-ssps` plus the normal rustls `aws-lc-rs` provider. `all-ssps`
preserves the existing protocol surface and enables these positive protocol features:

- `ntlm` enables NTLM.
- `kerberos` enables Kerberos.
- `pku2u` enables PKU2U and its shared Kerberos message/crypto support.
- `negotiate` enables SPNEGO over NTLM, Kerberos, and PKU2U.
- `credssp` enables CredSSP over Negotiate.

The optional component features retain their existing roles: `network_client` adds the built-in
network client, `dns_resolver` adds KDC DNS discovery, `scard` adds smart-card logon, and `tsssp`
adds the Windows native CredSSP replacement. They enable their required protocol features
automatically. For example, an NTLM-only build is:

```console
cargo build -p sspi --no-default-features --features ntlm
```

### Build-time FIPS profile

The `sspi` crate provides a deliberately narrow FIPS provider profile:

```console
cargo build -p sspi --no-default-features --features fips
```

This profile selects the rustls AWS-LC FIPS provider and Picky's `fips-aws-lc` backend. It does not
compile the in-crate NTLM, Kerberos, PKU2U, Negotiate, CredSSP, smartcard, TSSSP, or DPAPI surfaces.
Those protocols require cryptography outside the validated provider boundary and remain available
through the positive features above. `fips` is mutually exclusive with `all-ssps`, every individual
protocol feature, `network_client`, `dns_resolver`, `scard`, `tsssp`, `aws-lc-rs`, and `ring`.

Selecting this feature does not by itself establish deployment compliance. The exact AWS-LC module,
target platform, build procedure, operational environment, and applicable certificate coverage must
be validated for each deployment.

## Overview

The sspi-rs works in accordance with the MSDN documentation. At the moment, [NT LAN Manager (NTLM)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4) is implemented and available for platform independent execution. It is also possible to create your own SSPs by implementing the [`SspiImpl`]() trait.

###### Ease of use

Some SSPI functions tend to be cumbersome, that's why sspi-rs allows to use SSPI in a convenient way by utilizing builders.

## Example

The usage of the SSPs is as simple as creating an instance of the security provider and calling its functions.

Here is an example of acquiring a credentials handle and a timestamp of their validity:
```rust
use sspi::{CredentialUse, Ntlm, Sspi, Username, builders::EmptyInitializeSecurityContext, SecurityBuffer, ClientRequestFlags, DataRepresentation, BufferType, SspiImpl};

fn main() {
    let account_name = "example_user";
    let computer_name = "example_computer";
    let mut ntlm = Ntlm::new();
    let username = Username::new(&account_name, Some(&computer_name)).unwrap();
    let identity = sspi::AuthIdentity {
        username,
        password: String::from("example_password").into(),
    };

    let mut acq_cred_result = ntlm
        .acquire_credentials_handle()
        .with_credential_use(CredentialUse::Outbound)
        .with_auth_data(&identity)
        .execute()
        .unwrap();

    let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
    // first time calling initialize_security_context, the input buffer should be empty
    let mut input_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];

    // create a builder for the first call to initialize_security_context
    // the target should start with the protocol name, e.g. "HTTP/example.com" or "LDAP/example.com"
    let mut builder = EmptyInitializeSecurityContext::<<Ntlm as SspiImpl>::CredentialsHandle>::new()
        .with_credentials_handle(&mut acq_cred_result.credentials_handle)
        .with_context_requirements(ClientRequestFlags::CONFIDENTIALITY | ClientRequestFlags::ALLOCATE_MEMORY)
        .with_target_data_representation(DataRepresentation::Native)
        .with_target_name("LDAP/example.com")
        .with_input(&mut input_buffer)
        .with_output(&mut output_buffer);

    // call initialize_security_context
    // Note: the initialize_security_context_impl returns a generator, for NTLM, 
    // this generator will never yield as NTLM requires no network communication to a third party
    // but negotiate and kerberos do require network communication, so the generator is used to
    // allow the caller to provide the network information through the generator.resume() method
    // take a look at the examples/kerberos.rs for more information
    let _result = ntlm
        .initialize_security_context_impl(&mut builder)
        .resolve_to_result()
        .unwrap();
    // ... exchange your token in output buffer with the server and repeat the process until either server is satisfied or an error is thrown
}

```

Example of acquiring an SSP provided by Windows:
```Rust
let mut negotiate = SecurityPackage::from_package_type(
    SecurityPackageType::Other(String::from("Negotiate"))
);
```

## Projects using sspi-rs

* [Devolutions Gateway](https://github.com/Devolutions/devolutions-gateway)
* [IronRDP](https://github.com/Devolutions/IronRDP)
* [Python SSPI Library](https://github.com/jborean93/sspilib)
* [NetExec](https://github.com/Pennyw0rth/NetExec)
* [LDAP client library](https://github.com/kanidm/ldap3/blob/master/proto/examples/sasltest/main.rs)
* [Remote Desktop Manager](https://devolutions.net/remote-desktop-manager/)

(Feel free to open a PR if you know about other projects!)

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
