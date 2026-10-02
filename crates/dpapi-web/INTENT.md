The `dpapi-web` crate implements WebAssembly bindings for the DPAPI.
This crate is intended to be used inside browsers.

This crate has its own transport implementation based on browser-based WebSockets since native OS APIs are not available.
