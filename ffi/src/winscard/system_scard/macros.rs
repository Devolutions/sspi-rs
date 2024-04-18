macro_rules! try_execute {
    ($x:expr) => {{
        use num_traits::FromPrimitive;
        use winscard::{Error, ErrorKind};

        // Note. WinSCard API functions from `windows-sys` crate return `i32` as status code.
        // So, we cast the `i32` status code into `u32`.
        let error_kind = ErrorKind::from_u32($x as u32).unwrap_or(ErrorKind::InternalError);
        if error_kind == ErrorKind::Success {
            Ok(())
        } else {
            Err(Error::new(error_kind, ""))
        }
    }};
}
