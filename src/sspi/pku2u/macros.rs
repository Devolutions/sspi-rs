macro_rules! check_conversation_id {
    ($actual:expr, $expected:expr) => {
        if $actual != $expected {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                format!(
                    "Server sent invalid conversation id. Got {:?} but expected {:?}.",
                    $actual, $expected
                ),
            ));
        }
    };
}

macro_rules! check_auth_scheme {
    ($actual:expr, $expected:expr) => {
        if $expected.is_none() {
            return Err(Error::new(ErrorKind::InternalError, "auth scheme id is not set".into()));
        }

        if $actual != $expected.unwrap() {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                format!(
                    "Server sent invalid conversation id. Got {:?} but expected {:?}.",
                    $actual,
                    $expected.unwrap()
                ),
            ));
        }
    };
}
