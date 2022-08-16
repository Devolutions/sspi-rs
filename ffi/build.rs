use std::env;
use std::path::PathBuf;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();

    if target_os == "windows" {
        // On Windows, we provide the linker with a .def file to rename exports.
        // This module definition file is used to rename some symbols
        // and avoid linkage conflicts with secur32.dll when building the library.
        // (secur32.dll is used by `rust-tls-native-roots` crate)

        // See:
        // https://docs.microsoft.com/en-us/cpp/build/reference/module-definition-dot-def-files
        // https://docs.microsoft.com/en-us/cpp/build/reference/exports

        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let sspi_def_file = manifest_dir.join("sspi.def");
        println!("cargo:rustc-link-arg=/DEF:{}", sspi_def_file.display());
    }
}
