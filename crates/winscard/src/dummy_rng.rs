use rand_core::{CryptoRng, Error, RngCore};

// We use this generator only as a type parameter for the `rsa::hazmat::rsa_decrypt_and_check` function.
pub struct Dummy;

impl RngCore for Dummy {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, _: &mut [u8]) {}

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Error> {
        Ok(())
    }
}

impl CryptoRng for Dummy {}
