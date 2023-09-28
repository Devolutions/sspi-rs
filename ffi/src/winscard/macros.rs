macro_rules! check_handle {
    ($x:expr) => {{
        if $x == 0 {
            return u32::from(winscard::ErrorKind::InvalidParameter);
        }
    }};
}

macro_rules! try_execute {
    ($x:expr) => {{
        match $x {
            Ok(value) => value,
            Err(err) => {
                error!(%err, "an error occurred");
                return u32::from(err.error_kind);
            }
        }
    }};
}
