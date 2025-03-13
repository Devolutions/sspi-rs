//! Helper macros for PDU encoding and decoding
//!
//! Some are exported and available to external crates

/// Ensures that a given buffer has the expected size.
#[macro_export]
macro_rules! ensure_size {
    (name: $name:expr, in: $buf:ident, size: $expected:expr) => {{
        let received = $buf.len();
        let expected = $expected;
        if !(received >= expected) {
            Err($crate::Error::NotEnoughBytes {
                name: $name,
                received,
                expected,
            })?;
        }
    }};
    (in: $buf:ident, size: $expected:expr) => {{
        $crate::ensure_size!(name: <Self as $crate::StaticName>::NAME, in: $buf, size: $expected)
    }};
}
