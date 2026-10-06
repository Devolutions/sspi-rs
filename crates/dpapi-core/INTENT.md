The `dpapi-core` crate implements a set of common traits and types for decoding and encoding DPAPI packets.

This crate is motivated by the fact that only a few items are required to build most of the other crates.
To move these crates up in the compilation tree, `dpapi-core` must remain small, with very few dependencies.
