//! Core types and constants for ONDC cryptographic operations.
//!
//! This module defines the fundamental types, constants, and type aliases used
//! throughout the ONDC crypto SDK. These provide type safety and clarity for
//! cryptographic operations.

use std::marker::PhantomData;

// ============================================================================
// Cryptographic Constants
// ============================================================================

/// Ed25519 signature length in bytes
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

/// Ed25519 public key length in bytes
pub const ED25519_PUBLIC_KEY_LENGTH: usize = 32;

/// Ed25519 private key length in bytes
pub const ED25519_PRIVATE_KEY_LENGTH: usize = 32;

/// Ed25519 key pair length in bytes (private + public)
pub const ED25519_KEYPAIR_LENGTH: usize = 64;

/// X25519 public key length in bytes
pub const X25519_PUBLIC_KEY_LENGTH: usize = 32;

/// X25519 private key length in bytes
pub const X25519_PRIVATE_KEY_LENGTH: usize = 32;

/// BLAKE2b maximum output length in bytes
pub const BLAKE2B_MAX_OUTPUT_LENGTH: usize = 64;

/// BLAKE2b default output length for ONDC (512 bits = 64 bytes)
pub const BLAKE2B_DEFAULT_OUTPUT_LENGTH: usize = 64;

/// Default timestamp tolerance in seconds (5 minutes)
pub const DEFAULT_TIMESTAMP_TOLERANCE: u64 = 300;

/// Default signature expiry time in seconds (1 hour)
pub const DEFAULT_SIGNATURE_EXPIRY: u64 = 3600;

// ============================================================================
// Type Aliases
// ============================================================================

/// Ed25519 signature type
pub type Ed25519Signature = [u8; ED25519_SIGNATURE_LENGTH];

/// Ed25519 public key type
pub type Ed25519PublicKey = [u8; ED25519_PUBLIC_KEY_LENGTH];

/// Ed25519 private key type
pub type Ed25519PrivateKey = [u8; ED25519_PRIVATE_KEY_LENGTH];

/// Ed25519 key pair type
pub type Ed25519KeyPair = [u8; ED25519_KEYPAIR_LENGTH];

/// X25519 public key type
pub type X25519PublicKey = [u8; X25519_PUBLIC_KEY_LENGTH];

/// X25519 private key type
pub type X25519PrivateKey = [u8; X25519_PRIVATE_KEY_LENGTH];

/// BLAKE2b hash output type
pub type Blake2bHash = [u8; BLAKE2B_DEFAULT_OUTPUT_LENGTH];

// ============================================================================
// Newtype Wrappers for Type Safety
// ============================================================================

/// Newtype wrapper for Ed25519 signatures
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519SignatureBytes(pub Ed25519Signature);

impl AsRef<[u8]> for Ed25519SignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Ed25519Signature> for Ed25519SignatureBytes {
    fn from(signature: Ed25519Signature) -> Self {
        Self(signature)
    }
}

/// Newtype wrapper for Ed25519 public keys
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519PublicKeyBytes(pub Ed25519PublicKey);

impl AsRef<[u8]> for Ed25519PublicKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Ed25519PublicKey> for Ed25519PublicKeyBytes {
    fn from(key: Ed25519PublicKey) -> Self {
        Self(key)
    }
}

/// Newtype wrapper for Ed25519 private keys
#[derive(Debug, Clone)]
pub struct Ed25519PrivateKeyBytes(pub Ed25519PrivateKey);

impl AsRef<[u8]> for Ed25519PrivateKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Ed25519PrivateKey> for Ed25519PrivateKeyBytes {
    fn from(key: Ed25519PrivateKey) -> Self {
        Self(key)
    }
}

/// Newtype wrapper for BLAKE2b hashes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blake2bHashBytes(pub Blake2bHash);

impl AsRef<[u8]> for Blake2bHashBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Blake2bHash> for Blake2bHashBytes {
    fn from(hash: Blake2bHash) -> Self {
        Self(hash)
    }
}

// ============================================================================
// ONDC-Specific Types
// ============================================================================

/// ONDC subscriber ID type
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriberId(pub String);

impl SubscriberId {
    /// Create a new subscriber ID
    pub fn new(id: String) -> Result<Self, crate::ONDCCryptoError> {
        if id.is_empty() {
            return Err(crate::ONDCCryptoError::ConfigError(
                "subscriber_id cannot be empty".into(),
            ));
        }
        if id.len() > 255 {
            return Err(crate::ONDCCryptoError::ConfigError(
                "subscriber_id too long".into(),
            ));
        }
        Ok(Self(id))
    }
}

impl AsRef<str> for SubscriberId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for SubscriberId {
    fn from(id: String) -> Self {
        Self(id)
    }
}

/// ONDC unique key ID type
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniqueKeyId(pub String);

impl UniqueKeyId {
    /// Create a new unique key ID
    pub fn new(id: String) -> Result<Self, crate::ONDCCryptoError> {
        if id.is_empty() {
            return Err(crate::ONDCCryptoError::ConfigError(
                "unique_key_id cannot be empty".into(),
            ));
        }
        Ok(Self(id))
    }
}

impl AsRef<str> for UniqueKeyId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for UniqueKeyId {
    fn from(id: String) -> Self {
        Self(id)
    }
}

/// ONDC authorization header parameters
#[derive(Debug, Clone)]
pub struct AuthorizationHeaderParams {
    /// Request body
    pub body: Vec<u8>,
    /// Subscriber ID
    pub subscriber_id: SubscriberId,
    /// Unique key ID
    pub unique_key_id: UniqueKeyId,
    /// Optional creation timestamp
    pub created: Option<u64>,
    /// Optional expiration timestamp
    pub expires: Option<u64>,
}

impl AuthorizationHeaderParams {
    /// Create new authorization header parameters
    pub fn new(body: Vec<u8>, subscriber_id: SubscriberId, unique_key_id: UniqueKeyId) -> Self {
        Self {
            body,
            subscriber_id,
            unique_key_id,
            created: None,
            expires: None,
        }
    }

    /// Set creation timestamp
    pub fn with_created(mut self, created: u64) -> Self {
        self.created = Some(created);
        self
    }

    /// Set expiration timestamp
    pub fn with_expires(mut self, expires: u64) -> Self {
        self.expires = Some(expires);
        self
    }
}

/// ONDC vLookup signature parameters
#[derive(Debug, Clone)]
pub struct VLookupSignatureParams {
    /// Country code
    pub country: String,
    /// Domain
    pub domain: String,
    /// Type field
    pub type_field: String,
    /// City
    pub city: String,
    /// Subscriber ID
    pub subscriber_id: SubscriberId,
}

impl VLookupSignatureParams {
    /// Create new vLookup signature parameters
    pub fn new(
        country: String,
        domain: String,
        type_field: String,
        city: String,
        subscriber_id: SubscriberId,
    ) -> Self {
        Self {
            country,
            domain,
            type_field,
            city,
            subscriber_id,
        }
    }
}

// ============================================================================
// Validation Helpers
// ============================================================================

/// Validate Ed25519 signature length
pub fn validate_ed25519_signature_length(signature: &[u8]) -> Result<(), crate::ONDCCryptoError> {
    if signature.len() != ED25519_SIGNATURE_LENGTH {
        return Err(crate::ONDCCryptoError::InvalidKeyLength {
            expected: ED25519_SIGNATURE_LENGTH,
            got: signature.len(),
        });
    }
    Ok(())
}

/// Validate Ed25519 public key length
pub fn validate_ed25519_public_key_length(key: &[u8]) -> Result<(), crate::ONDCCryptoError> {
    if key.len() != ED25519_PUBLIC_KEY_LENGTH {
        return Err(crate::ONDCCryptoError::InvalidKeyLength {
            expected: ED25519_PUBLIC_KEY_LENGTH,
            got: key.len(),
        });
    }
    Ok(())
}

/// Validate Ed25519 private key length
pub fn validate_ed25519_private_key_length(key: &[u8]) -> Result<(), crate::ONDCCryptoError> {
    if key.len() != ED25519_PRIVATE_KEY_LENGTH {
        return Err(crate::ONDCCryptoError::InvalidKeyLength {
            expected: ED25519_PRIVATE_KEY_LENGTH,
            got: key.len(),
        });
    }
    Ok(())
}

/// Validate BLAKE2b output length
pub fn validate_blake2b_output_length(length: usize) -> Result<(), crate::ONDCCryptoError> {
    if length == 0 || length > BLAKE2B_MAX_OUTPUT_LENGTH {
        return Err(crate::ONDCCryptoError::ConfigError(format!(
            "BLAKE2b output length must be 1-{} bytes",
            BLAKE2B_MAX_OUTPUT_LENGTH
        )));
    }
    Ok(())
}

/// Validate timestamp tolerance
pub fn validate_timestamp_tolerance(tolerance: u64) -> Result<(), crate::ONDCCryptoError> {
    if tolerance == 0 {
        return Err(crate::ONDCCryptoError::ConfigError(
            "timestamp tolerance cannot be zero".into(),
        ));
    }
    if tolerance > 86400 {
        return Err(crate::ONDCCryptoError::ConfigError(
            "timestamp tolerance cannot exceed 24 hours".into(),
        ));
    }
    Ok(())
}

// ============================================================================
// Phantom Types for Type Safety
// ============================================================================

/// Phantom type marker for Ed25519 algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519;

/// Phantom type marker for X25519 algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X25519;

/// Phantom type marker for BLAKE2b algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blake2b;

/// Generic key type with algorithm marker
#[derive(Debug, Clone)]
pub struct Key<A, T> {
    data: T,
    _algorithm: PhantomData<A>,
}

impl<A, T> Key<A, T> {
    /// Create a new key with algorithm marker
    pub fn new(data: T) -> Self {
        Self {
            data,
            _algorithm: PhantomData,
        }
    }

    /// Get the key data
    pub fn data(&self) -> &T {
        &self.data
    }

    /// Consume the key and return the data
    pub fn into_data(self) -> T {
        self.data
    }
}

impl<A, T> AsRef<T> for Key<A, T> {
    fn as_ref(&self) -> &T {
        &self.data
    }
}

/// Type alias for Ed25519 public key with algorithm marker
pub type Ed25519Key = Key<Ed25519, Ed25519PublicKeyBytes>;

/// Type alias for X25519 public key with algorithm marker
pub type X25519Key = Key<X25519, X25519PublicKey>;
