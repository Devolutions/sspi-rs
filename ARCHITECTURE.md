# Architecture

## Code Map

This section talks briefly about various important directories and data structures.

### `sspi` crate

This crate implements the Microsoft auth protocols stack: NTLM, Kerberos, PKU2U, SPNEGO, CredSSP, and TSSSP.
All protocols are transport agnostic.
Protocols correctness is confirmed in module-local unit tests and integration tests in the repository root `tests/` directory.

### `ffi` crate

This crate contains FFI bindings for SSPI, TSSSP, WinSCard, and DPAPI (Microsoft Data Protection API) APIs.
All APIs are exported from the same dynamic library.
WinSCard, DPAPI, and TSSSP are feature-gated and the user is able to disable them when building the library.

We run FFI tests using Miri as much as we can.

### `crates/ffi-types`

This crate contains _only_ FFI-related types (C-definitions) for building FFI APIs.
Every extern C type must be documented. If the type has its own MSDN link, it must be specified.

### `crates/kdc`

This crate contains a minimal KDC implementation.
It is used in tests and fake KDC for issuing user and service tickets.

### `crates/winscard`

This crate contains an emulated PIV-compatible smart card implementation.
The user provides its own certificate and private key, and then are able to establish an RDP connection using the provided certificate and private key as a real one.

### `crates/dpapi-pdu`

DPAPI PDU encoding and decoding. This crate is `no_std` compatible.
PDUs are fuzzed using `crates/dpapi-fuzzing` crate.

### `crates/dpapi-fuzzing`

Implements fuzzing oracles for DPAPI PDUs.

### `crates/dpapi-core`

This crate contains DPAPI core traits and types.
PDUs from `crates/dpapi-pdu` implement these traits.

### `crates/dpapi-transport`

This crate contains common types and traits for implementing custom DPAPI RPC communication transport.

### `crates/dpapi-native-transport`

This crate implements DPAPI transport (traits from the `crates/dpapi-transport`) using native networking stack (TCP and WebSocket).

### `crates/dpapi-web`

This crate implements WebAssembly high-level bindings targeting web browsers of the DPAPI implementation.
It has its own WS-based transport implementation using browsers API.

## MSRV policy

`sspi-rs` follows a conservative MSRV (Minimum Supported Rust Version) policy.
MSRV is equal to the latest stable Rust version minus five.
MSRV is specified in the root `Cargo.toml`.
The active development Rust version is specified in `rust-toolchain.toml`.
