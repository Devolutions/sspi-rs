pub use self::implementation::*;

#[cfg(feature = "debug_mode")]
mod implementation {
    use std::fs::OpenOptions;
    use std::sync::Once;

    use tracing_subscriber::prelude::*;
    use tracing_subscriber::EnvFilter;

    static SETUP: Once = Once::new();

    pub fn setup_logger() {
        SETUP.call_once(|| {
            let path = format!("{}/sspi-rs.log", std::env::var("HOMEPATH").unwrap());

            let file = OpenOptions::new().read(true).append(true).open(path).unwrap();
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
}

#[cfg(not(feature = "debug_mode"))]
mod implementation {
    pub fn setup_logger() {
        // -- no op -- //
    }
}
