
The `dpapi-core` crate is a core-tier for the DPAPI implementation.

## Implementation requirements

* The `dpapi-core` crate is `no_std` compatible.
  Do not break the `no_std` compatibility.
  Code that requires `std` must be feature-gated.
* Do not introduce any I/O in the core-tier crates.
* Keep PDUs implementation in the separate `dpapi-pdu` crate.
