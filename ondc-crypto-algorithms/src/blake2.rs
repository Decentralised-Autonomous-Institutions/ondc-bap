//! BLAKE2 hashing implementation.

use ondc_crypto_traits::{Hasher, ONDCCryptoError};

/// BLAKE2 hasher implementation.
pub struct Blake2Hasher;

impl Blake2Hasher {
    /// Create a new BLAKE2 hasher.
    pub fn new() -> Self {
        Self
    }
}

impl Hasher for Blake2Hasher {
    type Error = ONDCCryptoError;
    type Output = Vec<u8>;

    fn hash(&self, _data: &[u8]) -> Result<Self::Output, Self::Error> {
        // TODO: Implement BLAKE2 hashing
        todo!("BLAKE2 hashing implementation")
    }

    fn hash_with_length(&self, _data: &[u8], _length: usize) -> Result<Self::Output, Self::Error> {
        // TODO: Implement BLAKE2 hashing with custom length
        todo!("BLAKE2 hashing with custom length implementation")
    }
}
