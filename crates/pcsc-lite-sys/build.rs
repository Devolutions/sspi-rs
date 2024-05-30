use std::env;

use pkg_config::Config;

fn main() {
    if let Ok(lib_dir) = env::var("PCSC_LIB_DIR") {
        println!("cargo:rustc-link-search=native={}", lib_dir);
        println!(
            "cargo:rustc-link-lib={}",
            env::var("PCSC_LIB_NAME").unwrap_or_else(|_| "pcsclite".to_string())
        );
    } else {
        Config::new()
            .atleast_version("1")
            .probe("libpcsclite")
            .expect("Could not find a PCSC library");
    }
}
