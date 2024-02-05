macro_rules! env {
    ($name:expr) => {{
        std::env::var($name).map_err(|_| {
            crate::Error::new(
                crate::ErrorKind::InvalidParameter,
                format!("The {} env var is not present or invalid", $name),
            )
        })
    }};
}
