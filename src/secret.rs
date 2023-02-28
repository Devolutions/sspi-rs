use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop, Eq, PartialEq, Default, Clone, Serialize, Deserialize)]
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "secret")?;

        Ok(())
    }
}

impl<T: Zeroize> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(secret)")?;

        Ok(())
    }
}

impl<T: Zeroize> AsRef<T> for Secret<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> From<T> for Secret<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}
