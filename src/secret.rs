use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "picky")]
use picky::key::PrivateKey;

#[derive(Zeroize, ZeroizeOnDrop, Eq, PartialEq, Default, Clone, Serialize, Deserialize)]
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret")?;

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

impl<T: Zeroize> AsMut<T> for Secret<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> From<T> for Secret<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

#[cfg(feature = "picky")]
#[derive(Clone, PartialEq)]
pub struct SecretPrivateKey(PrivateKey);

#[cfg(feature = "picky")]
impl SecretPrivateKey {
    pub fn new(inner: PrivateKey) -> Self {
        Self(inner)
    }
}

#[cfg(feature = "picky")]
impl fmt::Debug for SecretPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretPrivateKey")?;

        Ok(())
    }
}

#[cfg(feature = "picky")]
impl fmt::Display for SecretPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(secret private key)")?;

        Ok(())
    }
}

#[cfg(feature = "picky")]
impl AsRef<PrivateKey> for SecretPrivateKey {
    fn as_ref(&self) -> &PrivateKey {
        &self.0
    }
}

#[cfg(feature = "picky")]
impl From<PrivateKey> for SecretPrivateKey {
    fn from(inner: PrivateKey) -> Self {
        Self(inner)
    }
}
