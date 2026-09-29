The `ffi` crates exports SSPI, TSSSP, WinSCard, and DPAPI APIs in one dynamic library.
The TSSSP, WinSCard, and DPAPI APIs are feature-gates and can be disables.

The exported APIs should ask as close as possible to the original ones.
