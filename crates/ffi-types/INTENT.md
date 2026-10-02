The `ffi-types` crate must contain _only_ FFI-related types definitions.
The main goal is to reuse types on multiple platforms without relying on external crates.
`windows` and `windows-sys` crates have exports only on Windows targets.
