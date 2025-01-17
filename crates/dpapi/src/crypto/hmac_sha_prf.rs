use hmac::{Hmac, Mac};
use rust_kbkdf::{PseudoRandomFunction, PseudoRandomFunctionKey};

use super::{CryptoError, CryptoResult};

pub struct HmacShaPrfKey<'key>(&'key [u8]);

impl<'key> HmacShaPrfKey<'key> {
    pub fn new(key: &'key [u8]) -> Self {
        Self(key)
    }

    pub fn key(&self) -> &[u8] {
        self.0
    }
}

impl<'key> PseudoRandomFunctionKey for HmacShaPrfKey<'key> {
    type KeyHandle = HmacShaPrfKey<'key>;

    fn key_handle(&self) -> &Self::KeyHandle {
        self
    }
}

macro_rules! define_hmac_sha_prf {
    ($name:ident, $sha:ty, $out_size:ty) => {
        pub struct $name {
            hmac: Option<Hmac<$sha>>,
        }

        impl $name {
            pub fn new() -> Self {
                Self { hmac: None }
            }
        }

        impl<'a> PseudoRandomFunction<'a> for $name {
            type KeyHandle = HmacShaPrfKey<'a>;
            type PrfOutputSize = $out_size;
            type Error = CryptoError;

            fn init(
                &mut self,
                key: &'a dyn PseudoRandomFunctionKey<KeyHandle = HmacShaPrfKey<'a>>,
            ) -> CryptoResult<()> {
                self.hmac = Some(Hmac::<$sha>::new_from_slice(key.key_handle().key()).map_err(|_| {
                    use hmac::digest::crypto_common::KeySizeUser;

                    CryptoError::InvalidKeyLength {
                        expected: Hmac::<$sha>::key_size(),
                        actual: key.key_handle().key().len(),
                    }
                })?);

                Ok(())
            }

            fn update(&mut self, msg: &[u8]) -> CryptoResult<()> {
                if let Some(hmac) = self.hmac.as_mut() {
                    hmac.update(msg);

                    Ok(())
                } else {
                    Err(CryptoError::Uninitialized("HMAC hasher"))
                }
            }

            fn finish(&mut self, out: &mut [u8]) -> CryptoResult<usize> {
                if let Some(hmac) = self.hmac.as_mut() {
                    let hmac = hmac.clone().finalize().into_bytes();

                    out.copy_from_slice(hmac.as_slice());

                    Ok(hmac.as_slice().len())
                } else {
                    Err(CryptoError::Uninitialized("HMAC hasher"))
                }
            }
        }
    };
}

define_hmac_sha_prf!(HmacSha1Prf, sha1::Sha1, typenum::U20);
define_hmac_sha_prf!(HmacSha256Prf, sha2::Sha256, typenum::U32);
define_hmac_sha_prf!(HmacSha384Prf, sha2::Sha384, typenum::U48);
define_hmac_sha_prf!(HmacSha512Prf, sha2::Sha512, typenum::U64);
