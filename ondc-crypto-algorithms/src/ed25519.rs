//! Ed25519 signing and verification implementation.

use ondc_crypto_traits::{ONDCCryptoError, Signer, Verifier};

/// Ed25519 signer implementation.
pub struct Ed25519Signer {
    // TODO: Implement Ed25519 signer
}

impl Ed25519Signer {
    /// Create a new Ed25519 signer from a private key.
    pub fn new(_private_key: &[u8]) -> Result<Self, ONDCCryptoError> {
        // TODO: Implement Ed25519 signer creation
        todo!("Ed25519 signer implementation")
    }
}

impl Signer for Ed25519Signer {
    type Error = ONDCCryptoError;
    type Signature = [u8; 64];

    fn sign(&self, _message: &[u8]) -> Result<Self::Signature, Self::Error> {
        // TODO: Implement Ed25519 signing
        todo!("Ed25519 signing implementation")
    }
}

/// Ed25519 verifier implementation.
pub struct Ed25519Verifier;

impl Ed25519Verifier {
    /// Create a new Ed25519 verifier.
    pub fn new() -> Self {
        Self
    }
}

impl Verifier for Ed25519Verifier {
    type Error = ONDCCryptoError;
    type PublicKey = [u8; 32];
    type Signature = [u8; 64];

    fn verify(
        &self,
        _public_key: &Self::PublicKey,
        _message: &[u8],
        _signature: &Self::Signature,
    ) -> Result<(), Self::Error> {
        // TODO: Implement Ed25519 verification
        todo!("Ed25519 verification implementation")
    }
} 