The `dpapi` crate implements the Microsoft Data Protection API (DPAPI) using `dpapi-*` crates as building blocks.
The implementation is IO-agnostic and the user should provide their own transport implementation by implementing traits from the `dpapi-transport`.
