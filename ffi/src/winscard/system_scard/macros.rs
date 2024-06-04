macro_rules! try_execute {
    ($x:expr, $msg:expr) => {{
        use num_traits::FromPrimitive;
        use winscard::{Error, ErrorKind};

        let error_kind = ErrorKind::from_u32($x).unwrap_or(ErrorKind::InternalError);
        if error_kind == ErrorKind::Success {
            Ok(())
        } else {
            Err(Error::new(error_kind, $msg))
        }
    }};
    ($x:expr) => {
        try_execute!($x, "")
    };
}
