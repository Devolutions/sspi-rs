use std::ops::Not;

use widestring::Utf16Str;
pub use widestring::Utf16String;
pub use widestring::error::Utf16Error;
use zeroize::Zeroize;

use crate::{Error, ErrorKind};

pub trait Utf16StringExt: Sized {
    fn from_bytes_le(bytes: impl AsRef<[u8]>) -> Result<Self, Error>;

    /// Returns reference to internal buffer as &[u8], assuming the native endianness.
    fn as_bytes(&self) -> &[u8];

    /// Returns internal buffer as Vec<u8>, assuming the native endianness.
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl Utf16StringExt for Utf16String {
    fn from_bytes_le(bytes: impl AsRef<[u8]>) -> Result<Utf16String, Error> {
        let bytes = bytes.as_ref();

        if bytes.len() % 2 != 0 {
            return Err(Error::new(
                ErrorKind::InvalidParameter,
                "invalid UTF-16 string: lone byte",
            ));
        }

        let buffer: Vec<u16> = bytes
            .chunks(2)
            .map(|c| u16::from_le_bytes(c.try_into().expect("c is 2 bytes, checked earlier")))
            .collect();

        Utf16String::from_vec(buffer)
            .map_err(|error| Error::new(ErrorKind::InvalidParameter, format!("invalid UTF-16 string: {error}")))
    }

    fn as_bytes(&self) -> &[u8] {
        let slice: &[u16] = self.as_ref();
        bytemuck::cast_slice(slice)
    }
}

#[derive(Clone, Default, Eq, PartialEq)]
pub struct ZeroizedUtf16String(pub Utf16String);

impl ZeroizedUtf16String {
    pub fn from_bytes_le(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        Ok(Self(Utf16String::from_bytes_le(bytes)?))
    }
}

impl Zeroize for ZeroizedUtf16String {
    fn zeroize(&mut self) {
        // SAFETY: Borrow is safe as long as contens of the slice is valid UTF-16 after it ends.
        let buffer = unsafe { self.0.as_mut_slice() };
        buffer.zeroize();
    }
}

impl AsRef<Utf16Str> for ZeroizedUtf16String {
    fn as_ref(&self) -> &Utf16Str {
        self.0.as_ref()
    }
}

#[derive(Zeroize, Clone, Eq, PartialEq, Default, Debug)]
pub struct NonEmpty<T: AsRef<Utf16Str>>(T);

impl<T: AsRef<Utf16Str>> NonEmpty<T> {
    pub fn new(value: T) -> Option<NonEmpty<T>> {
        value.as_ref().is_empty().not().then(|| Self(value))
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: AsRef<Utf16Str>> AsRef<T> for NonEmpty<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{Utf16String, Utf16StringExt};
    use crate::{ErrorKind, NonEmpty};

    #[test]
    fn from_bytes_le_lone_byte() {
        let bytes = [
            0x45, 0x00, 0x6c, 0x00, 0x20, 0x00, 0x50, 0x00, 0x73, 0x00, 0x79, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6f, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x00,
        ];

        let result = Utf16String::from_bytes_le(bytes);

        assert!(result.is_err());
        assert_eq!(
            result.expect_err("result is err").error_type,
            ErrorKind::InvalidParameter
        );
    }

    #[test]
    fn from_bytes_le_lone_surrogate() {
        let bytes = [
            0x45, 0x00, 0x6c, 0x00, 0x20, 0x00, 0x50, 0x00, 0x73, 0x00, 0x79, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6f, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x00, 0xd8,
        ];

        let result = Utf16String::from_bytes_le(bytes);

        assert!(result.is_err());
        assert_eq!(
            result.expect_err("result is err").error_type,
            ErrorKind::InvalidParameter
        );
    }

    #[test]
    fn from_bytes_le_valid_bytes() {
        let bytes = [
            0x45, 0x00, 0x6c, 0x00, 0x20, 0x00, 0x50, 0x00, 0x73, 0x00, 0x79, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6f, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x6f, 0x00,
        ];

        let result = Utf16String::from_bytes_le(bytes);

        assert!(result.is_ok());
        assert_eq!(result.expect("result is ok"), "El Psy Congroo");
    }

    #[test]
    fn from_bytes_le_roundtrip() {
        let bytes = [
            0x45, 0x00, 0x6c, 0x00, 0x20, 0x00, 0x50, 0x00, 0x73, 0x00, 0x79, 0x00, 0x20, 0x00, 0x43, 0x00, 0x6f, 0x00,
            0x6e, 0x00, 0x67, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x6f, 0x00,
        ];

        let result = Utf16String::from_bytes_le(bytes);

        assert!(result.is_ok());
        assert_eq!(result.as_ref().expect("result is ok").as_bytes(), bytes);
        assert_eq!(result.as_ref().expect("result is ok").as_bytes(), Vec::from(bytes));
    }

    #[test]
    fn non_empty_empty() {
        let test_str = "";

        let string = NonEmpty::new(Utf16String::from_str(test_str));
        assert!(string.is_none());
    }

    #[test]
    fn non_empty_non_empty() {
        let test_string = Utf16String::from_str("non empty test string");

        let string = NonEmpty::new(test_string.clone());

        assert!(string.is_some());
        let string = string.expect("string is some");

        assert_eq!(string.0, test_string);
        assert_eq!(string.into_inner(), test_string);
    }
}
