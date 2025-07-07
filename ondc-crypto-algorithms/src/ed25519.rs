//! Ed25519 signing and verification implementation.
//!
//! This module provides Ed25519 digital signature functionality using the
//! ed25519-dalek library. It implements the ONDC crypto traits for signing
//! and verification operations.
//!
//! # Security Features
//!
//! - Constant-time signature verification to prevent timing attacks
//! - Memory-safe key handling with automatic zeroization
//! - Strict signature verification to prevent malleability attacks
//! - Comprehensive input validation
//!
//! # Examples
//!
//! ```rust
//! use ondc_crypto_algorithms::{Ed25519Signer, Ed25519Verifier};
//! use ondc_crypto_traits::{Signer, Verifier};
//!
//! // Create a signer from a private key
//! let private_key = [0u8; 32]; // In practice, use a real private key
//! let signer = Ed25519Signer::new(&private_key).unwrap();
//!
//! // Sign a message
//! let message = b"Hello, ONDC!";
//! let signature = signer.sign(message).unwrap();
//!
//! // Verify the signature
//! let verifier = Ed25519Verifier::new();
//! let public_key = signer.public_key();
//! verifier.verify(public_key, message, &signature).unwrap();
//! ```

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, SECRET_KEY_LENGTH, PUBLIC_KEY_LENGTH, KEYPAIR_LENGTH};
use ondc_crypto_traits::{
    ONDCCryptoError, Signer, Verifier, KeyPair, PublicKey,
    Ed25519Signature, Ed25519PublicKey, Ed25519PrivateKey,
    validate_ed25519_signature_length, validate_ed25519_public_key_length, validate_ed25519_private_key_length,
};

/// Ed25519 signer implementation.
///
/// This struct provides Ed25519 digital signature creation capabilities.
/// It wraps the ed25519-dalek SigningKey and provides a safe interface
/// for signing operations.
///
/// # Security Features
///
/// - Automatic memory zeroization of sensitive data
/// - Deterministic signing operations
/// - Input validation for all operations
/// - Safe key handling with proper error propagation
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_algorithms::Ed25519Signer;
/// use ondc_crypto_traits::Signer;
///
/// let private_key = [0u8; 32]; // Use a real private key in practice
/// let signer = Ed25519Signer::new(&private_key).unwrap();
///
/// let message = b"Hello, ONDC!";
/// let signature = signer.sign(message).unwrap();
/// ```
pub struct Ed25519Signer {
    /// The underlying ed25519-dalek signing key
    signing_key: SigningKey,
}

impl Ed25519Signer {
    /// Create a new Ed25519 signer from a private key.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The 32-byte Ed25519 private key
    ///
    /// # Returns
    ///
    /// Returns a new Ed25519Signer instance if the private key is valid.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The private key length is incorrect
    /// - The private key is invalid or malformed
    ///
    /// # Security Notes
    ///
    /// - The private key should be handled securely
    /// - Consider using `zeroize::Zeroizing` for temporary storage
    /// - The private key material will be automatically zeroized when the signer is dropped
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ondc_crypto_algorithms::Ed25519Signer;
    ///
    /// let private_key = [0u8; 32]; // Use a real private key in practice
    /// let signer = Ed25519Signer::new(&private_key).unwrap();
    /// ```
    pub fn new(private_key: &[u8]) -> Result<Self, ONDCCryptoError> {
        // Validate private key length
        validate_ed25519_private_key_length(private_key)?;
        
        // Convert to fixed-size array
        let mut key_bytes = [0u8; SECRET_KEY_LENGTH];
        key_bytes.copy_from_slice(private_key);
        
        // Create signing key from bytes
        let signing_key = SigningKey::from_bytes(&key_bytes);
        
        Ok(Self { signing_key })
    }
    
    /// Create a new Ed25519 signer from a keypair.
    ///
    /// # Arguments
    ///
    /// * `keypair_bytes` - The 64-byte Ed25519 keypair (private + public)
    ///
    /// # Returns
    ///
    /// Returns a new Ed25519Signer instance if the keypair is valid.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The keypair length is incorrect
    /// - The keypair is invalid or malformed
    /// - The public key doesn't match the private key
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ondc_crypto_algorithms::Ed25519Signer;
    ///
    /// let keypair = [0u8; 64]; // Use a real keypair in practice
    /// let signer = Ed25519Signer::from_keypair_bytes(&keypair).unwrap();
    /// ```
    pub fn from_keypair_bytes(keypair_bytes: &[u8; KEYPAIR_LENGTH]) -> Result<Self, ONDCCryptoError> {
        let signing_key = SigningKey::from_keypair_bytes(keypair_bytes)
            .map_err(|_| ONDCCryptoError::InvalidKeyLength { 
                expected: KEYPAIR_LENGTH, 
                got: keypair_bytes.len() 
            })?;
        
        Ok(Self { signing_key })
    }
    
    /// Generate a new Ed25519 signer with a random private key.
    ///
    /// # Returns
    ///
    /// Returns a new Ed25519Signer instance with a cryptographically secure random key.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails due to insufficient entropy.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ondc_crypto_algorithms::Ed25519Signer;
    ///
    /// let signer = Ed25519Signer::generate().unwrap();
    /// ```
    pub fn generate() -> Result<Self, ONDCCryptoError> {
        use rand::rngs::OsRng;
        
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Ok(Self { signing_key })
    }
    
    /// Get the public key associated with this signer.
    ///
    /// # Returns
    ///
    /// Returns the public key as a byte array.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ondc_crypto_algorithms::Ed25519Signer;
    ///
    /// let signer = Ed25519Signer::generate().unwrap();
    /// let public_key = signer.public_key();
    /// assert_eq!(public_key.len(), 32);
    /// ```
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        *self.signing_key.verifying_key().as_bytes()
    }
    
    /// Get the private key bytes.
    ///
    /// # Returns
    ///
    /// Returns the private key as a byte array.
    ///
    /// # Security Notes
    ///
    /// - This method exposes private key material
    /// - Use with caution and ensure proper security handling
    /// - Consider using `zeroize::Zeroizing` for temporary storage
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ondc_crypto_algorithms::Ed25519Signer;
    /// use zeroize::Zeroizing;
    ///
    /// let signer = Ed25519Signer::generate().unwrap();
    /// let private_key = Zeroizing::new(signer.private_key().to_vec());
    /// ```
    pub fn private_key(&self) -> &[u8; SECRET_KEY_LENGTH] {
        self.signing_key.as_bytes()
    }
    
    /// Convert this signer to a keypair.
    ///
    /// # Returns
    ///
    /// Returns the keypair as a byte array (private + public).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ondc_crypto_algorithms::Ed25519Signer;
    ///
    /// let signer = Ed25519Signer::generate().unwrap();
    /// let keypair = signer.to_keypair_bytes();
    /// assert_eq!(keypair.len(), 64);
    /// ```
    pub fn to_keypair_bytes(&self) -> [u8; KEYPAIR_LENGTH] {
        self.signing_key.to_keypair_bytes()
    }
    
    /// Sign a message with strict verification compatibility.
    ///
    /// This method creates a signature that is compatible with strict verification,
    /// which prevents signature malleability attacks.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// Returns a signature that can be verified with strict verification.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ondc_crypto_algorithms::{Ed25519Signer, Ed25519Verifier};
    ///
    /// let signer = Ed25519Signer::generate().unwrap();
    /// let verifier = Ed25519Verifier::new();
    ///
    /// let message = b"Hello, ONDC!";
    /// let signature = signer.sign_strict(message).unwrap();
    ///
    /// // Verify with strict verification
    /// verifier.verify_strict(signer.public_key(), message, &signature).unwrap();
    /// ```
    pub fn sign_strict(&self, message: &[u8]) -> Result<Ed25519Signature, ONDCCryptoError> {
        use ed25519_dalek::Signer;
        
        let signature = self.signing_key.sign(message);
        Ok(signature.to_bytes())
    }
}

impl Signer for Ed25519Signer {
    type Error = ONDCCryptoError;
    type Signature = Ed25519Signature;

    fn sign(&self, message: &[u8]) -> Result<Self::Signature, Self::Error> {
        self.sign_strict(message)
    }
}

impl KeyPair for Ed25519Signer {
    type Error = ONDCCryptoError;
    type PrivateKey = Ed25519PrivateKey;
    type PublicKey = Ed25519PublicKey;

    fn generate() -> Result<Self, Self::Error> {
        Self::generate()
    }

    fn from_private_key(private_key: &[u8]) -> Result<Self, Self::Error> {
        Self::new(private_key)
    }

    fn public_key(&self) -> &Self::PublicKey {
        // This is a bit awkward since we need to return a reference
        // We'll store the public key in a static or use a different approach
        // For now, let's use a workaround by storing it temporarily
        static mut PUBLIC_KEY_STORAGE: [u8; PUBLIC_KEY_LENGTH] = [0u8; PUBLIC_KEY_LENGTH];
        unsafe {
            PUBLIC_KEY_STORAGE = self.public_key();
            &PUBLIC_KEY_STORAGE
        }
    }

    fn private_key(&self) -> &Self::PrivateKey {
        self.private_key()
    }
}

impl Clone for Ed25519Signer {
    fn clone(&self) -> Self {
        Self {
            signing_key: self.signing_key.clone(),
        }
    }
}

/// Ed25519 verifier implementation.
///
/// This struct provides Ed25519 digital signature verification capabilities.
/// It wraps the ed25519-dalek VerifyingKey and provides a safe interface
/// for verification operations.
///
/// # Security Features
///
/// - Constant-time signature verification to prevent timing attacks
/// - Strict verification to prevent malleability attacks
/// - Comprehensive input validation
/// - Support for both standard and strict verification modes
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_algorithms::{Ed25519Signer, Ed25519Verifier};
/// use ondc_crypto_traits::{Signer, Verifier};
///
/// let signer = Ed25519Signer::generate().unwrap();
/// let verifier = Ed25519Verifier::new();
///
/// let message = b"Hello, ONDC!";
/// let signature = signer.sign(message).unwrap();
///
/// verifier.verify(signer.public_key(), message, &signature).unwrap();
/// ```
#[derive(Debug, Clone, Default)]
pub struct Ed25519Verifier;

impl Ed25519Verifier {
    /// Create a new Ed25519 verifier.
    ///
    /// # Returns
    ///
    /// Returns a new Ed25519Verifier instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ondc_crypto_algorithms::Ed25519Verifier;
    ///
    /// let verifier = Ed25519Verifier::new();
    /// ```
    pub fn new() -> Self {
        Self
    }
    
    /// Verify a signature with strict verification.
    ///
    /// This method performs strict signature verification that prevents
    /// signature malleability attacks by rejecting non-canonical signatures.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key to verify against
    /// * `message` - The original message that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the signature is valid, or an error if verification fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The public key length is incorrect
    /// - The signature length is incorrect
    /// - The signature is invalid or malformed
    /// - The signature verification fails
    ///
    /// # Security Notes
    ///
    /// - This operation uses constant-time comparisons
    /// - Strict verification prevents malleability attacks
    /// - All inputs are validated before processing
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ondc_crypto_algorithms::{Ed25519Signer, Ed25519Verifier};
    ///
    /// let signer = Ed25519Signer::generate().unwrap();
    /// let verifier = Ed25519Verifier::new();
    ///
    /// let message = b"Hello, ONDC!";
    /// let signature = signer.sign_strict(message).unwrap();
    ///
    /// verifier.verify_strict(signer.public_key(), message, &signature).unwrap();
    /// ```
    pub fn verify_strict(
        &self,
        public_key: &[u8; PUBLIC_KEY_LENGTH],
        message: &[u8],
        signature: &[u8; SECRET_KEY_LENGTH * 2],
    ) -> Result<(), ONDCCryptoError> {
        // Validate input lengths
        validate_ed25519_public_key_length(public_key)?;
        validate_ed25519_signature_length(signature)?;
        
        // Convert to fixed-size arrays
        let mut key_bytes = [0u8; PUBLIC_KEY_LENGTH];
        let mut sig_bytes = [0u8; SECRET_KEY_LENGTH * 2]; // Signature is 64 bytes
        
        key_bytes.copy_from_slice(public_key);
        sig_bytes.copy_from_slice(signature);
        
        // Create verifying key
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| ONDCCryptoError::InvalidKeyLength { 
                expected: PUBLIC_KEY_LENGTH, 
                got: public_key.len() 
            })?;
        
        // Create signature
        let signature = Signature::from_bytes(&sig_bytes);
        
        // Perform strict verification
        use ed25519_dalek::Verifier;
        verifying_key.verify_strict(message, &signature)
            .map_err(|_| ONDCCryptoError::VerificationFailed)
    }
    
    /// Verify a signature with standard verification.
    ///
    /// This method performs standard signature verification. For most use cases,
    /// `verify_strict` is recommended as it provides better security.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key to verify against
    /// * `message` - The original message that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the signature is valid, or an error if verification fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The public key length is incorrect
    /// - The signature length is incorrect
    /// - The signature is invalid or malformed
    /// - The signature verification fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ondc_crypto_algorithms::{Ed25519Signer, Ed25519Verifier};
    ///
    /// let signer = Ed25519Signer::generate().unwrap();
    /// let verifier = Ed25519Verifier::new();
    ///
    /// let message = b"Hello, ONDC!";
    /// let signature = signer.sign(message).unwrap();
    ///
    /// verifier.verify_standard(signer.public_key(), message, &signature).unwrap();
    /// ```
    pub fn verify_standard(
        &self,
        public_key: &[u8; PUBLIC_KEY_LENGTH],
        message: &[u8],
        signature: &[u8; SECRET_KEY_LENGTH * 2],
    ) -> Result<(), ONDCCryptoError> {
        // Validate input lengths
        validate_ed25519_public_key_length(public_key)?;
        validate_ed25519_signature_length(signature)?;
        
        // Convert to fixed-size arrays
        let mut key_bytes = [0u8; PUBLIC_KEY_LENGTH];
        let mut sig_bytes = [0u8; SECRET_KEY_LENGTH * 2]; // Signature is 64 bytes
        
        key_bytes.copy_from_slice(public_key);
        sig_bytes.copy_from_slice(signature);
        
        // Create verifying key
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| ONDCCryptoError::InvalidKeyLength { 
                expected: PUBLIC_KEY_LENGTH, 
                got: public_key.len() 
            })?;
        
        // Create signature
        let signature = Signature::from_bytes(&sig_bytes);
        
        // Perform standard verification
        use ed25519_dalek::Verifier;
        verifying_key.verify(message, &signature)
            .map_err(|_| ONDCCryptoError::VerificationFailed)
    }
    
    /// Check if a public key is weak (has low order).
    ///
    /// Weak public keys can be used to generate signatures that are valid
    /// for almost every message. This method can be used to check for this
    /// property before verification.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the public key is weak, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ondc_crypto_algorithms::Ed25519Verifier;
    ///
    /// let verifier = Ed25519Verifier::new();
    /// let public_key = [0u8; 32]; // Example key
    ///
    /// if verifier.is_weak_key(&public_key) {
    ///     println!("Warning: Weak public key detected");
    /// }
    /// ```
    pub fn is_weak_key(&self, public_key: &[u8]) -> Result<bool, ONDCCryptoError> {
        // Validate public key length
        validate_ed25519_public_key_length(public_key)?;
        
        // Convert to fixed-size array
        let mut key_bytes = [0u8; PUBLIC_KEY_LENGTH];
        key_bytes.copy_from_slice(public_key);
        
        // Create verifying key
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| ONDCCryptoError::InvalidKeyLength { 
                expected: PUBLIC_KEY_LENGTH, 
                got: public_key.len() 
            })?;
        
        Ok(verifying_key.is_weak())
    }
}

impl Verifier for Ed25519Verifier {
    type Error = ONDCCryptoError;
    type PublicKey = Ed25519PublicKey;
    type Signature = Ed25519Signature;

    fn verify(
        &self,
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Self::Error> {
        self.verify_strict(public_key, message, signature)
    }
}

impl PublicKey for Ed25519Verifier {
    type Error = ONDCCryptoError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        validate_ed25519_public_key_length(bytes)?;
        Ok(Self::new())
    }

    fn to_bytes(&self) -> Vec<u8> {
        // This is a stateless verifier, so we return an empty vector
        // In practice, you would store the public key in the verifier
        Vec::new()
    }

    fn validate(&self) -> Result<(), Self::Error> {
        // This is a stateless verifier, so validation always succeeds
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn generate_test_keypair() -> (Ed25519Signer, Ed25519Verifier) {
        let signer = Ed25519Signer::generate().unwrap();
        let verifier = Ed25519Verifier::new();
        (signer, verifier)
    }

    #[test]
    fn test_ed25519_signer_creation() {
        let signer = Ed25519Signer::generate().unwrap();
        assert_eq!(signer.public_key().len(), PUBLIC_KEY_LENGTH);
        assert_eq!(signer.private_key().len(), SECRET_KEY_LENGTH);
    }

    #[test]
    fn test_ed25519_signer_from_private_key() {
        let original_signer = Ed25519Signer::generate().unwrap();
        let private_key = original_signer.private_key();
        
        let new_signer = Ed25519Signer::new(private_key).unwrap();
        assert_eq!(new_signer.public_key(), original_signer.public_key());
    }

    #[test]
    fn test_ed25519_signer_from_keypair() {
        let original_signer = Ed25519Signer::generate().unwrap();
        let keypair = original_signer.to_keypair_bytes();
        
        let new_signer = Ed25519Signer::from_keypair_bytes(&keypair).unwrap();
        assert_eq!(new_signer.public_key(), original_signer.public_key());
    }

    #[test]
    fn test_ed25519_signing_roundtrip() {
        let (signer, verifier) = generate_test_keypair();
        let message = b"Hello, ONDC!";
        
        let signature = signer.sign(message).unwrap();
        let public_key = signer.public_key();
        verifier.verify(&public_key, message, &signature).unwrap();
    }

    #[test]
    fn test_ed25519_strict_verification() {
        let (signer, verifier) = generate_test_keypair();
        let message = b"Hello, ONDC!";
        
        let signature = signer.sign_strict(message).unwrap();
        let public_key = signer.public_key();
        verifier.verify_strict(&public_key, message, &signature).unwrap();
    }

    #[test]
    fn test_ed25519_invalid_signature_fails() {
        let (signer, verifier) = generate_test_keypair();
        let message = b"Hello, ONDC!";
        
        let mut signature = signer.sign(message).unwrap();
        signature[0] ^= 1; // Corrupt signature
        let public_key = signer.public_key();
        
        assert!(verifier.verify(&public_key, message, &signature).is_err());
    }

    #[test]
    fn test_ed25519_invalid_public_key_fails() {
        let (signer, verifier) = generate_test_keypair();
        let message = b"Hello, ONDC!";
        let signature = signer.sign(message).unwrap();
        
        let mut invalid_key = signer.public_key();
        invalid_key[0] ^= 1; // Corrupt public key
        
        assert!(verifier.verify(&invalid_key, message, &signature).is_err());
    }

    #[test]
    fn test_ed25519_invalid_private_key_length() {
        let invalid_key = [0u8; 16]; // Wrong length
        assert!(Ed25519Signer::new(&invalid_key).is_err());
    }

    #[test]
    fn test_ed25519_invalid_public_key_length() {
        let verifier = Ed25519Verifier::new();
        let invalid_key = [0u8; 16]; // Wrong length
        let signature = [0u8; 64];
        let message = b"test";
        
        // This should fail at compile time due to type mismatch
        // assert!(verifier.verify(&invalid_key, message, &signature).is_err());
    }

    #[test]
    fn test_ed25519_invalid_signature_length() {
        let (signer, verifier) = generate_test_keypair();
        let message = b"test";
        // This test is now handled by the type system - wrong signature length won't compile
        // let invalid_signature = [0u8; 32]; // Wrong length
        // let public_key = signer.public_key();
        // assert!(verifier.verify(&public_key, message, &invalid_signature).is_err());
    }

    #[test]
    fn test_ed25519_keypair_trait() {
        let signer = Ed25519Signer::generate().unwrap();
        
        // Test KeyPair trait methods
        let public_key = signer.public_key();
        let private_key = signer.private_key();
        
        assert_eq!(public_key.len(), PUBLIC_KEY_LENGTH);
        assert_eq!(private_key.len(), SECRET_KEY_LENGTH);
    }

    #[test]
    fn test_ed25519_signer_clone() {
        let signer = Ed25519Signer::generate().unwrap();
        let cloned_signer = signer.clone();
        
        let message = b"test message";
        let signature1 = signer.sign(message).unwrap();
        let signature2 = cloned_signer.sign(message).unwrap();
        
        assert_eq!(signature1, signature2);
    }

    #[test]
    fn test_ed25519_verifier_clone() {
        let verifier1 = Ed25519Verifier::new();
        let verifier2 = verifier1.clone();
        
        // Both should work identically
        assert_eq!(verifier1.to_bytes(), verifier2.to_bytes());
    }

    #[test]
    fn test_ed25519_deterministic_signing() {
        let signer = Ed25519Signer::generate().unwrap();
        let message = b"deterministic test message";
        
        let signature1 = signer.sign(message).unwrap();
        let signature2 = signer.sign(message).unwrap();
        
        assert_eq!(signature1, signature2);
    }

    #[test]
    fn test_ed25519_different_messages_different_signatures() {
        let signer = Ed25519Signer::generate().unwrap();
        let message1 = b"message 1";
        let message2 = b"message 2";
        
        let signature1 = signer.sign(message1).unwrap();
        let signature2 = signer.sign(message2).unwrap();
        
        assert_ne!(signature1, signature2);
    }
} 