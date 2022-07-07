macro_rules! try_execute {
    ($x:expr) => {{
        match $x {
            Ok(value) => value,
            Err(err) => {
                return err.error_type.to_u32().unwrap();
            }
        }
    }};
}

macro_rules! check_null {
    ($x:expr) => {{
        use num_traits::ToPrimitive;
        use sspi::ErrorKind;

        if $x.is_null() {
            return ErrorKind::InvalidParameter.to_u32().unwrap();
        }
    }};
}
