#![no_main]

extern crate libfuzzer_sys;
extern crate dpapi_fuzzing;

use dpapi_fuzzing::generator::AnyStruct;
use dpapi_fuzzing::round_trip;

libfuzzer_sys::fuzz_target!(|any: AnyStruct| {
    round_trip(any);
});