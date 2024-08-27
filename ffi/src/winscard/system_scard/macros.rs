macro_rules! try_execute {
    ($x:expr, $msg:expr) => {{
        use num_traits::FromPrimitive;
        use winscard::{Error, ErrorKind};

        let error_kind = ErrorKind::from_u32(
            // In pcsc-lite API, the status code has 8-byte width. But the Windows WinSCard uses 4-byte width status code.
            #[allow(clippy::useless_conversion)]
            $x.try_into().unwrap()
        ).unwrap_or(ErrorKind::InternalError);
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
