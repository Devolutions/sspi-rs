# sspi-rs

**sspi-rs** is a Rust implementation of [Security Support Provider Interface (SSPI)](https://docs.microsoft.com/en-us/windows/win32/rpc/security-support-provider-interface-sspi-). It ships with platform-independent implementations of [Security Support Providers (SSP)](https://docs.microsoft.com/en-us/windows/win32/rpc/security-support-providers-ssps-), and is able to utilize native Microsoft libraries when ran under Windows.

The purpose of sspi-rs is to clean the original interface from cluttering and provide users with Rust-friendly SSPs for execution under *nix or any other platform that is able to compile Rust.

## Overview

The sspi-rs works in accordance with the MSDN documentation. At the moment, [NT LAN Manager (NTLM)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4) is implemented and available for platform independent execution. It is also possible to create your own SSPs by implementing the [`SspiImpl`]() trait. More on that in the [Documentation](target/doc/sspi/index.html).

###### Ease of use
Some SSPI functions tend to be cumbersome, that's why sspi-rs allows to use SSPI in a convenient way by utilizing builders. Examples are available in the [examples](examples), [example section](#example), and [Documentation](target/doc/sspi/index.html).

## Usage
sspi-rs is included in the Cargo.toml like this:
```TOML
[dependencies]
sspi = "0.11.1"
```
After that you can `use` the types that you need.


## Documentation

Documentation will give you a comprehensive overlook of the crate. For the example of a simple use case, visit the [examples](examples) folder.

## Example

The usage of the SSPs is as simple as creating an instance of the security provider and calling its functions.

Here is an example of acquiring a credentials handle and a timestamp of their validity:
```rust
use sspi::{CredentialUse, Ntlm, Sspi, Username, builders::EmptyInitializeSecurityContext, SecurityBuffer, ClientRequestFlags, DataRepresentation, SecurityBufferType, SspiImpl};

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

    let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];
    // first time calling initialize_security_context, the input buffer should be empty
    let mut input_buffer = vec![SecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];

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

## Projects that use sspi-rs

* [Devolutions Gateway](https://github.com/Devolutions/devolutions-gateway)
* [LDAP client library](https://github.com/kanidm/ldap3/blob/master/proto/examples/sasltest/main.rs)

## License
sspi-rs is licensed under MIT license.
