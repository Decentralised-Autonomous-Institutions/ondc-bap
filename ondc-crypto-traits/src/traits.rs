//! Core traits for ONDC cryptographic operations.
//!
//! This module defines the foundational traits used throughout the ONDC crypto SDK.
//! All traits are designed with security, performance, and extensibility in mind.
//!
//! # Security Considerations
//!
//! - All traits that handle sensitive data should implement proper memory zeroization
//! - Signing operations must be deterministic and constant-time where possible
//! - Verification operations must use constant-time comparisons to prevent timing attacks
//! - Key material should be handled with appropriate security measures

// ONDCCryptoError is used in the documentation examples

/// Trait for signing operations.
///
/// This trait provides a generic interface for digital signature creation.
/// Implementations should ensure deterministic output and constant-time operations
/// where possible to prevent side-channel attacks.
///
/// # Safety Requirements
///
/// - Signing operations must be deterministic (same input produces same output)
/// - Implementations should use constant-time algorithms where possible
/// - Private key material must be handled securely and zeroized after use
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_traits::{Signer, ONDCCryptoError};
///
/// struct MySigner;
///
/// impl Signer for MySigner {
///     type Error = ONDCCryptoError;
///     type Signature = Vec<u8>;
///     
///     fn sign(&self, message: &[u8]) -> Result<Self::Signature, Self::Error> {
///         // Implementation here
///         todo!()
///     }
/// }
/// ```
pub trait Signer {
    /// The error type returned by signing operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// The signature type.
    type Signature: AsRef<[u8]>;

    /// Sign a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// Returns a signature that can be used to verify the message authenticity.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails due to invalid key material,
    /// unsupported message format, or cryptographic failures.
    ///
    /// # Security Notes
    ///
    /// - This operation must be deterministic
    /// - Implementations should use constant-time algorithms
    /// - Private key material should be handled securely
    fn sign(&self, message: &[u8]) -> Result<Self::Signature, Self::Error>;
}

/// Trait for verification operations.
///
/// This trait provides a generic interface for digital signature verification.
/// Implementations must use constant-time comparisons to prevent timing attacks.
///
/// # Safety Requirements
///
/// - Verification must use constant-time comparisons
/// - Implementations should validate all inputs before processing
/// - Public keys should be validated for correct format and length
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_traits::{Verifier, ONDCCryptoError};
///
/// struct MyVerifier;
///
/// impl Verifier for MyVerifier {
///     type Error = ONDCCryptoError;
///     type PublicKey = [u8; 32];
///     type Signature = [u8; 64];
///     
///     fn verify(
///         &self,
///         public_key: &Self::PublicKey,
///         message: &[u8],
///         signature: &Self::Signature,
///     ) -> Result<(), Self::Error> {
///         // Implementation here
///         todo!()
///     }
/// }
/// ```
pub trait Verifier {
    /// The error type returned by verification operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// The public key type.
    type PublicKey: AsRef<[u8]>;

    /// The signature type.
    type Signature: AsRef<[u8]>;

    /// Verify a signature.
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
    /// Returns an error if verification fails due to invalid signature,
    /// malformed public key, or cryptographic failures.
    ///
    /// # Security Notes
    ///
    /// - This operation must use constant-time comparisons
    /// - All inputs should be validated before processing
    /// - Implementations should be resistant to timing attacks
    fn verify(
        &self,
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Self::Error>;
}

/// Trait for hashing operations.
///
/// This trait provides a generic interface for cryptographic hashing.
/// Implementations should use secure hash functions suitable for the intended use case.
///
/// # Safety Requirements
///
/// - Hash functions should be cryptographically secure
/// - Output should be deterministic for the same input
/// - Variable-length output should be handled securely
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_traits::{Hasher, ONDCCryptoError};
///
/// struct MyHasher;
///
/// impl Hasher for MyHasher {
///     type Error = ONDCCryptoError;
///     type Output = Vec<u8>;
///     
///     fn hash(&self, data: &[u8]) -> Result<Self::Output, Self::Error> {
///         // Implementation here
///         todo!()
///     }
///     
///     fn hash_with_length(&self, data: &[u8], length: usize) -> Result<Self::Output, Self::Error> {
///         // Implementation here
///         todo!()
///     }
/// }
/// ```
pub trait Hasher {
    /// The error type returned by hashing operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// The hash output type.
    type Output: AsRef<[u8]>;

    /// Hash data with default output length.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to hash
    ///
    /// # Returns
    ///
    /// Returns the hash of the input data using the default output length.
    ///
    /// # Errors
    ///
    /// Returns an error if hashing fails due to unsupported input or
    /// cryptographic failures.
    fn hash(&self, data: &[u8]) -> Result<Self::Output, Self::Error>;

    /// Hash data with specified output length.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to hash
    /// * `length` - The desired output length in bytes
    ///
    /// # Returns
    ///
    /// Returns the hash of the input data with the specified output length.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested length is not supported or
    /// hashing fails for other reasons.
    ///
    /// # Security Notes
    ///
    /// - Output length should be validated against security requirements
    /// - Variable-length output should be handled carefully to prevent
    ///   length extension attacks where applicable
    fn hash_with_length(&self, data: &[u8], length: usize) -> Result<Self::Output, Self::Error>;
}

/// Trait for key pair operations.
///
/// This trait provides a generic interface for cryptographic key pairs.
/// Implementations should handle private key material securely.
///
/// # Safety Requirements
///
/// - Private key material must be zeroized when dropped
/// - Key generation should use cryptographically secure random number generators
/// - Key validation should be performed on creation
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_traits::{KeyPair, ONDCCryptoError};
///
/// struct MyKeyPair;
///
/// impl KeyPair for MyKeyPair {
///     type Error = ONDCCryptoError;
///     type PrivateKey = Vec<u8>;
///     type PublicKey = [u8; 32];
///     
///     fn generate() -> Result<Self, Self::Error> {
///         // Implementation here
///         todo!()
///     }
///     
///     fn from_private_key(private_key: &[u8]) -> Result<Self, Self::Error> {
///         // Implementation here
///         todo!()
///     }
///     
///     fn public_key(&self) -> &Self::PublicKey {
///         // Implementation here
///         todo!()
///     }
///     
///     fn private_key(&self) -> &Self::PrivateKey {
///         // Implementation here
///         todo!()
///     }
/// }
/// ```
pub trait KeyPair {
    /// The error type returned by key pair operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// The private key type.
    type PrivateKey: AsRef<[u8]> + zeroize::Zeroize;

    /// The public key type.
    type PublicKey: AsRef<[u8]>;

    /// Generate a new key pair.
    ///
    /// # Returns
    ///
    /// Returns a newly generated key pair using cryptographically secure
    /// random number generation.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails due to insufficient entropy
    /// or cryptographic failures.
    ///
    /// # Security Notes
    ///
    /// - Key generation must use cryptographically secure RNG
    /// - Generated keys should be validated for correctness
    fn generate() -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Create a key pair from an existing private key.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The private key bytes
    ///
    /// # Returns
    ///
    /// Returns a key pair derived from the provided private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid, malformed, or
    /// unsupported.
    ///
    /// # Security Notes
    ///
    /// - Private key should be validated for correct format and length
    /// - The private key material should be handled securely
    fn from_private_key(private_key: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Get the public key from this key pair.
    ///
    /// # Returns
    ///
    /// Returns a reference to the public key.
    fn public_key(&self) -> &Self::PublicKey;

    /// Get the private key from this key pair.
    ///
    /// # Returns
    ///
    /// Returns a reference to the private key.
    ///
    /// # Security Notes
    ///
    /// - This method should be used carefully as it exposes private key material
    /// - Callers should ensure the returned data is handled securely
    /// - Consider using `zeroize::Zeroizing` for temporary storage
    fn private_key(&self) -> &Self::PrivateKey;
}

/// Trait for public key operations.
///
/// This trait provides a generic interface for public key validation and
/// format conversion.
///
/// # Safety Requirements
///
/// - Public key validation should be thorough and secure
/// - Format conversions should preserve key integrity
/// - Implementations should be resistant to malformed input
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_traits::{PublicKey, ONDCCryptoError};
///
/// struct MyPublicKey([u8; 32]);
///
/// impl PublicKey for MyPublicKey {
///     type Error = ONDCCryptoError;
///     
///     fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
///         // Implementation here
///         todo!()
///     }
///     
///     fn to_bytes(&self) -> Vec<u8> {
///         // Implementation here
///         todo!()
///     }
///     
///     fn validate(&self) -> Result<(), Self::Error> {
///         // Implementation here
///         todo!()
///     }
/// }
/// ```
pub trait PublicKey {
    /// The error type returned by public key operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Create a public key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw public key bytes
    ///
    /// # Returns
    ///
    /// Returns a public key instance if the bytes are valid.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are invalid, malformed, or unsupported.
    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Convert the public key to raw bytes.
    ///
    /// # Returns
    ///
    /// Returns the public key as raw bytes.
    fn to_bytes(&self) -> Vec<u8>;

    /// Validate the public key.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the public key is valid, or an error if validation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the public key is invalid, malformed, or corrupted.
    fn validate(&self) -> Result<(), Self::Error>;
}

/// Trait for ONDC-specific signing string operations.
///
/// This trait provides functionality for creating and validating ONDC signing strings,
/// which are used in HTTP signature generation and verification.
///
/// # ONDC Signing String Format
///
/// ONDC signing strings follow this format:
/// ```text
/// (created): {timestamp}
/// (expires): {timestamp}
/// digest: BLAKE-512={base64_digest}
/// ```
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_traits::{SigningString, ONDCCryptoError};
///
/// struct MySigningString;
///
/// impl SigningString for MySigningString {
///     type Error = ONDCCryptoError;
///     
///     fn create(
///         body: &[u8],
///         created: Option<u64>,
///         expires: Option<u64>,
///     ) -> Result<Self, Self::Error> {
///         // Implementation here
///         todo!()
///     }
///     
///     fn to_string(&self) -> String {
///         // Implementation here
///         todo!()
///     }
///     
///     fn created(&self) -> u64 {
///         // Implementation here
///         todo!()
///     }
///     
///     fn expires(&self) -> u64 {
///         // Implementation here
///         todo!()
///     }
///     
///     fn digest(&self) -> &str {
///         // Implementation here
///         todo!()
///     }
/// }
/// ```
pub trait SigningString {
    /// The error type returned by signing string operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Create a signing string from a request body and optional timestamps.
    ///
    /// # Arguments
    ///
    /// * `body` - The request body to create a digest from
    /// * `created` - Optional creation timestamp (uses current time if None)
    /// * `expires` - Optional expiration timestamp (uses created + 1 hour if None)
    ///
    /// # Returns
    ///
    /// Returns a signing string instance ready for signing.
    ///
    /// # Errors
    ///
    /// Returns an error if timestamp validation fails or digest creation fails.
    fn create(body: &[u8], created: Option<u64>, expires: Option<u64>) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Convert the signing string to its string representation.
    ///
    /// # Returns
    ///
    /// Returns the signing string in the standard ONDC format.
    fn to_string(&self) -> String;

    /// Get the creation timestamp.
    fn created(&self) -> u64;

    /// Get the expiration timestamp.
    fn expires(&self) -> u64;

    /// Get the digest string.
    fn digest(&self) -> &str;
}

// Note: ONDCCryptoError already implements std::error::Error + Send + Sync
// via thiserror, so it can be automatically converted to Box<dyn std::error::Error + Send + Sync>
// using the standard library's blanket implementation.
