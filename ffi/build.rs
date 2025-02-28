use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let is_running_tests = env::var("SSPI_RS_IS_RUNNING_TESTS").is_ok();

    if target_os == "windows" && !is_running_tests {
        // On Windows, we provide the linker with a .def file to rename exports.
        // This module definition file is used to rename some symbols
        // and avoid linkage conflicts with secur32.dll when building the library.
        // (secur32.dll is used by `rust-tls-native-roots` crate)

        // See:
        // https://docs.microsoft.com/en-us/cpp/build/reference/module-definition-dot-def-files
        // https://docs.microsoft.com/en-us/cpp/build/reference/exports

        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let base_def_file = manifest_dir.join("sspi_base.def");
        let merged_def_file = out_dir.join("sspi_merged.def");

        let mut merged_content = fs::read_to_string(&base_def_file).expect("Failed to read sspi_base.def");

        #[cfg(feature = "scard")]
        {
            let scard_def_file = manifest_dir.join("sspi_winscard.def");
            let scard_content = fs::read_to_string(&scard_def_file).expect("Failed to read sspi_winscard.def");
            let filtered_scard_content: String = scard_content
                .lines()
                .filter(|line| line.starts_with("    "))
                .collect::<Vec<_>>()
                .join("\n");
            merged_content.push('\n');
            merged_content.push_str(&filtered_scard_content);
        }

        #[cfg(feature = "dpapi")]
        {
            let dpapi_def_file = manifest_dir.join("sspi_dpapi.def");
            let dpapi_content = fs::read_to_string(&dpapi_def_file).expect("Failed to read sspi_dpapi.def");
            let filtered_dpapi_content: String = dpapi_content
                .lines()
                .filter(|line| line.starts_with("    "))
                .collect::<Vec<_>>()
                .join("\n");
            merged_content.push('\n');
            merged_content.push_str(&filtered_dpapi_content);
        }

        fs::write(&merged_def_file, merged_content).expect("Failed to write merged .def file");
        println!("cargo:rustc-link-arg=/DEF:{}", merged_def_file.display());
    }
}
