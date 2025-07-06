//! Core traits for ONDC cryptographic operations.

use crate::ONDCCryptoError;

/// Trait for signing operations.
pub trait Signer {
    /// The error type returned by signing operations.
    type Error: std::error::Error + Send + Sync + 'static;
    
    /// The signature type.
    type Signature: AsRef<[u8]>;
    
    /// Sign a message.
    fn sign(&self, message: &[u8]) -> Result<Self::Signature, Self::Error>;
}

/// Trait for verification operations.
pub trait Verifier {
    /// The error type returned by verification operations.
    type Error: std::error::Error + Send + Sync + 'static;
    
    /// The public key type.
    type PublicKey: AsRef<[u8]>;
    
    /// The signature type.
    type Signature: AsRef<[u8]>;
    
    /// Verify a signature.
    fn verify(
        &self,
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Self::Error>;
}

/// Trait for hashing operations.
pub trait Hasher {
    /// The error type returned by hashing operations.
    type Error: std::error::Error + Send + Sync + 'static;
    
    /// The hash output type.
    type Output: AsRef<[u8]>;
    
    /// Hash data with default output length.
    fn hash(&self, data: &[u8]) -> Result<Self::Output, Self::Error>;
    
    /// Hash data with specified output length.
    fn hash_with_length(&self, data: &[u8], length: usize) -> Result<Self::Output, Self::Error>;
}

// Implement traits for ONDCCryptoError
impl From<ONDCCryptoError> for Box<dyn std::error::Error + Send + Sync> {
    fn from(err: ONDCCryptoError) -> Self {
        Box::new(err)
    }
} 