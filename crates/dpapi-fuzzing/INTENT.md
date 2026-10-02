The `dpapi-fuzzing` crate implements oracles for fuzzing PDUs encoding and decoding.
The purpose of this crate is to catch encoding and decoding inconsistencies and bugs.

This crate is not intended to perform fuzzing by itself.
It only provides oracles for fuzzing.
The actual fuzzing is performed by the root `fuzz/` crate.
