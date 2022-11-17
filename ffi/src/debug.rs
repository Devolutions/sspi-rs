pub use self::implementation::*;

#[cfg(feature = "debug_mode")]
mod implementation {
    use std::fs::OpenOptions;
    use std::path::PathBuf;
    use std::sync::Once;

    use tracing_subscriber::prelude::*;
    use tracing_subscriber::EnvFilter;

    static SETUP: Once = Once::new();

    const SSPI_DBG_LOG_PATH_ENV: &str = "SSPI_DBG_LOG_PATH";

    #[cfg(windows)]
    const HOME_PATH_ENV: &str = "USERPROFILE";

    #[cfg(not(windows))]
    const HOME_PATH_ENV: &str = "HOME";

    pub fn setup_logger() {
        SETUP.call_once(|| {
            let path = if let Ok(path) = std::env::var(SSPI_DBG_LOG_PATH_ENV) {
                PathBuf::from(path)
            } else if let Ok(path) = std::env::var(HOME_PATH_ENV) {
                let mut path = PathBuf::from(path);
                path.push("sspi-rs.log");
                path
            } else {
                println!("[SSPI-DEBUG] Couldn’t find path for log file");
                return;
            };

            let file = match OpenOptions::new().read(true).append(true).open(path) {
                Ok(f) => f,
                Err(e) => {
                    println!("[SSPI-DEBUG] Couldn’t open log file: {e}");
                    return;
                }
            };

            let fmt_layer = tracing_subscriber::fmt::layer()
                .pretty()
                .with_thread_names(true)
                .with_writer(file);

            tracing_subscriber::registry()
                .with(fmt_layer)
                .with(EnvFilter::from_default_env())
                .init();

            std::panic::set_hook(Box::new(move |panic| {
                if let Some(location) = panic.location() {
                    error!(
                        message = %panic,
                        panic.file = location.file(),
                        panic.line = location.line(),
                        panic.column = location.column(),
                    );
                } else {
                    error!(message = %panic);
                }
            }));
        })
    }

    /// FFI function to call in order to manually setup the debug logger.
    ///
    /// Under normal circumstances, it is not required to call this function.
    /// Indeed `InitSecurityInterface*` family functions will trigger the same
    /// behavior. However, you can call this directly if you need to manually set up the logger
    /// (maybe in order to debug `InitSecurityInterface*`).
    ///
    /// This function can be called multiple times safely.
    #[no_mangle]
    pub extern "system" fn RustSspiSetupLogger() {
        setup_logger();
    }
}

#[cfg(not(feature = "debug_mode"))]
mod implementation {
    pub fn setup_logger() {
        // -- no op -- //
    }
}
