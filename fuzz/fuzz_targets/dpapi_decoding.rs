#![no_main]

extern crate libfuzzer_sys;
extern crate dpapi_fuzzing;

use dpapi_fuzzing::structure_decoding;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    structure_decoding(data);
});