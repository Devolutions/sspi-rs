
## Implementation requirements

* The `winscard` crate is `no_std` compatible.
  Do not break the `no_std` compatibility.
  Code that requires `std` must be feature-gated.
* Follow the [NIST.SP.800-73-4] specification as close as possible.

[NIST.SP.800-73-4]: https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-73-4.pdf
