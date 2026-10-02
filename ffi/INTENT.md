The `ffi` crates exports SSPI, TSSSP, WinSCard, and DPAPI APIs in one dynamic library.
The TSSSP, WinSCard, and DPAPI APIs are feature-gated and can be disabled.

The exported APIs should act as close as possible to the original ones.
