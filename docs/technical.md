# ONDC Rust SDK Technical Guide

## Overview

This document provides comprehensive technical guidance for implementing the ONDC (Open Network for Digital Commerce) cryptographic SDK in Rust. The SDK is designed as a multi-crate workspace that prioritizes security, performance, and maintainability while providing idiomatic Rust APIs.

## Core Design Principles

### 1. Security First
- **Memory Safety**: Leverage Rust's ownership system and use `zeroize` for sensitive data
- **Constant-Time Operations**: Use `subtle` crate for timing-attack resistant comparisons
- **Type Safety**: Prevent misuse through strong typing and compile-time guarantees
- **Fail-Safe Defaults**: Secure configurations by default, explicit opt-in for less secure options

### 2. Performance Oriented
- **Zero-Cost Abstractions**: High-level APIs that compile to efficient machine code
- **SIMD Optimizations**: Leverage hardware acceleration where available
- **Minimal Allocations**: Prefer stack allocation and borrowing over heap allocation
- **Async-Ready**: Support both sync and async patterns without overhead

### 3. Idiomatic Rust
- **Trait-Based Design**: Extensible and testable through well-defined interfaces
- **Error Handling**: Comprehensive `Result<T, E>` usage with structured error types
- **Documentation**: Extensive rustdoc with examples and safety requirements
- **Testing**: Property-based testing, fuzzing, and comprehensive test coverage

## Crate Architecture

### Dependency Graph
```
ondc-crypto (main SDK)
├── ondc-crypto-traits (foundational traits)
├── ondc-crypto-algorithms (cryptographic implementations)
│   └── ondc-crypto-traits
├── ondc-crypto-formats (encoding/decoding utilities)
│   └── ondc-crypto-traits
├── ondc-crypto-http (HTTP signature handling)
│   ├── ondc-crypto-traits
│   ├── ondc-crypto-algorithms
│   └── ondc-crypto-formats
└── ondc-crypto-utils (utilities and helpers)
    └── ondc-crypto-traits
```

### Project Structure:
```
ondc-crypto/
├── Cargo.toml (workspace root)
├── ondc-crypto/ (main SDK)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs (main API)
│       ├── api.rs (ONDCCrypto struct)
│       ├── config.rs (ONDCConfig)
│       └── bin/
│           └── main.rs (CLI tool)
├── ondc-crypto-traits/ (foundational traits)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── error.rs (ONDCCryptoError)
│       └── traits.rs (Signer, Verifier, Hasher)
├── ondc-crypto-algorithms/ (crypto implementations)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── ed25519.rs (Ed25519Signer, Ed25519Verifier)
│       ├── blake2.rs (Blake2Hasher)
│       └── x25519.rs (X25519KeyExchange)
├── ondc-crypto-formats/ (encoding utilities)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── base64.rs (encoding/decoding)
│       └── key_formats.rs (key conversions)
├── ondc-crypto-http/ (HTTP signatures)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── signing_string.rs (ONDCSigningString)
│       ├── authorization_header.rs (header generation/parsing)
│       └── vlookup.rs (vLookup signatures)
└── ondc-crypto-utils/ (utilities)
    ├── Cargo.toml
    └── src/
        ├── lib.rs
        ├── time.rs (timestamp utilities)
        └── validation.rs (validation helpers)
```


### 1. ondc-crypto-traits

**Purpose**: Foundation crate defining core traits, error types, and interfaces.

**Key Components**:
```rust
// Core signing trait
pub trait Signer {
    type Error: std::error::Error + Send + Sync + 'static;
    type Signature: AsRef<[u8]>;
    
    fn sign(&self, message: &[u8]) -> Result<Self::Signature, Self::Error>;
}

// Verification trait
pub trait Verifier {
    type Error: std::error::Error + Send + Sync + 'static;
    type PublicKey: AsRef<[u8]>;
    type Signature: AsRef<[u8]>;
    
    fn verify(
        &self, 
        public_key: &Self::PublicKey,
        message: &[u8], 
        signature: &Self::Signature
    ) -> Result<(), Self::Error>;
}

// Hashing trait
pub trait Hasher {
    type Error: std::error::Error + Send + Sync + 'static;
    type Output: AsRef<[u8]>;
    
    fn hash(&self, data: &[u8]) -> Result<Self::Output, Self::Error>;
    fn hash_with_length(&self, data: &[u8], length: usize) -> Result<Self::Output, Self::Error>;
}
```

**Error Hierarchy**:
```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ONDCCryptoError {
    #[error("signature verification failed")]
    VerificationFailed,
    
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    
    #[error("encoding error: {0}")]
    EncodingError(String),
    
    #[error("invalid timestamp: {timestamp}")]
    InvalidTimestamp { timestamp: u64 },
    
    #[error("ONDC protocol error: {code} - {message}")]
    ProtocolError { code: u32, message: String },
    
    #[error("configuration error: {0}")]
    ConfigError(String),
}

// ONDC-specific error codes
impl ONDCCryptoError {
    pub fn policy_error(message: impl Into<String>) -> Self {
        Self::ProtocolError { code: 132, message: message.into() }
    }
    
    pub fn domain_error(message: impl Into<String>) -> Self {
        Self::ProtocolError { code: 129, message: message.into() }
    }
}
```

### 2. ondc-crypto-algorithms

**Purpose**: Cryptographic algorithm implementations using proven libraries.

**Key Components**:

**Ed25519 Signer Implementation**:
```rust
use ed25519_dalek::{Keypair, SecretKey, PublicKey};
use zeroize::{Zeroize, Zeroizing};

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Ed25519Signer {
    keypair: Keypair,
}

impl Ed25519Signer {
    pub fn new(private_key: &[u8]) -> Result<Self, ONDCCryptoError> {
        if private_key.len() != 32 {
            return Err(ONDCCryptoError::InvalidKeyLength { 
                expected: 32, 
                got: private_key.len() 
            });
        }
        
        let secret = SecretKey::from_bytes(private_key)
            .map_err(|_| ONDCCryptoError::InvalidKeyLength { expected: 32, got: private_key.len() })?;
        let public = PublicKey::from(&secret);
        let keypair = Keypair { secret, public };
        
        Ok(Self { keypair })
    }
    
    pub fn from_keypair_bytes(keypair_bytes: &[u8]) -> Result<Self, ONDCCryptoError> {
        if keypair_bytes.len() != 64 {
            return Err(ONDCCryptoError::InvalidKeyLength { 
                expected: 64, 
                got: keypair_bytes.len() 
            });
        }
        
        let keypair = Keypair::from_bytes(keypair_bytes)
            .map_err(|_| ONDCCryptoError::InvalidKeyLength { expected: 64, got: keypair_bytes.len() })?;
        
        Ok(Self { keypair })
    }
    
    pub fn public_key(&self) -> &[u8] {
        self.keypair.public.as_bytes()
    }
}

impl Signer for Ed25519Signer {
    type Error = ONDCCryptoError;
    type Signature = [u8; 64];
    
    fn sign(&self, message: &[u8]) -> Result<Self::Signature, Self::Error> {
        use ed25519_dalek::Signer;
        Ok(self.keypair.sign(message).to_bytes())
    }
}
```

**Ed25519 Verifier Implementation**:
```rust
use ed25519_dalek::{PublicKey, Signature};
use subtle::ConstantTimeEq;

pub struct Ed25519Verifier;

impl Ed25519Verifier {
    pub fn new() -> Self {
        Self
    }
    
    /// Verify signature with malleability protection
    pub fn verify_strict(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), ONDCCryptoError> {
        let public_key = PublicKey::from_bytes(public_key)
            .map_err(|_| ONDCCryptoError::InvalidKeyLength { expected: 32, got: public_key.len() })?;
        
        let signature = Signature::from_bytes(signature)
            .map_err(|_| ONDCCryptoError::InvalidKeyLength { expected: 64, got: signature.len() })?;
        
        use ed25519_dalek::Verifier;
        public_key.verify_strict(message, &signature)
            .map_err(|_| ONDCCryptoError::VerificationFailed)
    }
}

impl Verifier for Ed25519Verifier {
    type Error = ONDCCryptoError;
    type PublicKey = [u8; 32];
    type Signature = [u8; 64];
    
    fn verify(
        &self,
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Self::Error> {
        self.verify_strict(public_key, message, signature)
    }
}
```

**BLAKE2 Hasher Implementation**:
```rust
use blake2_simd::{blake2b, Params};

pub struct Blake2Hasher;

impl Blake2Hasher {
    pub fn new() -> Self {
        Self
    }
    
    /// Generate ONDC-compliant digest
    pub fn generate_ondc_digest(&self, payload: &[u8]) -> String {
        let hash = blake2b(payload);
        format!("BLAKE-512={}", base64::engine::general_purpose::STANDARD.encode(hash.as_bytes()))
    }
}

impl Hasher for Blake2Hasher {
    type Error = ONDCCryptoError;
    type Output = Vec<u8>;
    
    fn hash(&self, data: &[u8]) -> Result<Self::Output, Self::Error> {
        Ok(blake2b(data).as_bytes().to_vec())
    }
    
    fn hash_with_length(&self, data: &[u8], length: usize) -> Result<Self::Output, Self::Error> {
        if length == 0 || length > 64 {
            return Err(ONDCCryptoError::ConfigError("BLAKE2 output length must be 1-64 bytes".into()));
        }
        
        let hash = Params::new()
            .hash_length(length)
            .to_state()
            .update(data)
            .finalize();
        
        Ok(hash.as_bytes().to_vec())
    }
}
```

### 3. ondc-crypto-formats

**Purpose**: Encoding, decoding, and format conversion utilities.

**Key Components**:
```rust
use base64::Engine;
use zeroize::Zeroizing;

pub struct FormatConverter;

impl FormatConverter {
    /// Encode signature for ONDC headers
    pub fn encode_signature(signature: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(signature)
    }
    
    /// Decode signature with validation
    pub fn decode_signature(encoded: &str) -> Result<Vec<u8>, ONDCCryptoError> {
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| ONDCCryptoError::EncodingError(e.to_string()))
    }
    
    /// Convert Ed25519 private key from various formats
    pub fn ed25519_private_key_from_base64(encoded: &str) -> Result<Zeroizing<Vec<u8>>, ONDCCryptoError> {
        let decoded = Self::decode_signature(encoded)?;
        if decoded.len() != 32 {
            return Err(ONDCCryptoError::InvalidKeyLength { expected: 32, got: decoded.len() });
        }
        Ok(Zeroizing::new(decoded))
    }
    
    /// Convert Ed25519 public key with validation
    pub fn ed25519_public_key_from_base64(encoded: &str) -> Result<[u8; 32], ONDCCryptoError> {
        let decoded = Self::decode_signature(encoded)?;
        if decoded.len() != 32 {
            return Err(ONDCCryptoError::InvalidKeyLength { expected: 32, got: decoded.len() });
        }
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(key)
    }
}
```

### 4. ondc-crypto-http

**Purpose**: ONDC-specific HTTP signature generation and verification.

**Key Components**:

**Signing String Generation**:
```rust
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct ONDCSigningString {
    pub created: u64,
    pub expires: u64,
    pub digest: String,
}

impl ONDCSigningString {
    pub fn new(
        body: &[u8], 
        created: Option<DateTime<Utc>>, 
        expires: Option<DateTime<Utc>>
    ) -> Result<Self, ONDCCryptoError> {
        let created_timestamp = created
            .unwrap_or_else(Utc::now)
            .timestamp() as u64;
        
        let expires_timestamp = expires
            .unwrap_or_else(|| Utc::now() + chrono::Duration::hours(1))
            .timestamp() as u64;
        
        // Validate timestamps
        if expires_timestamp <= created_timestamp {
            return Err(ONDCCryptoError::InvalidTimestamp { timestamp: expires_timestamp });
        }
        
        let hasher = Blake2Hasher::new();
        let digest = hasher.generate_ondc_digest(body);
        
        Ok(Self {
            created: created_timestamp,
            expires: expires_timestamp,
            digest,
        })
    }
    
    pub fn to_string(&self) -> String {
        format!(
            "(created): {}\n(expires): {}\ndigest: {}",
            self.created, self.expires, self.digest
        )
    }
}
```

**Authorization Header Generation**:
```rust
pub struct AuthorizationHeaderBuilder {
    signer: Ed25519Signer,
    hasher: Blake2Hasher,
}

impl AuthorizationHeaderBuilder {
    pub fn new(private_key: &[u8]) -> Result<Self, ONDCCryptoError> {
        Ok(Self {
            signer: Ed25519Signer::new(private_key)?,
            hasher: Blake2Hasher::new(),
        })
    }
    
    pub fn create_authorization_header(
        &self,
        body: &[u8],
        subscriber_id: &str,
        unique_key_id: &str,
        created: Option<DateTime<Utc>>,
        expires: Option<DateTime<Utc>>,
    ) -> Result<String, ONDCCryptoError> {
        // Validate inputs
        if subscriber_id.is_empty() || unique_key_id.is_empty() {
            return Err(ONDCCryptoError::ConfigError("subscriber_id and unique_key_id cannot be empty".into()));
        }
        
        let signing_string = ONDCSigningString::new(body, created, expires)?;
        let signing_string_bytes = signing_string.to_string();
        
        let signature = self.signer.sign(signing_string_bytes.as_bytes())?;
        let signature_b64 = FormatConverter::encode_signature(&signature);
        
        let header = format!(
            r#"Signature keyId="{}|{}|ed25519",algorithm="ed25519",created="{}",expires="{}",headers="(created) (expires) digest",signature="{}""#,
            subscriber_id,
            unique_key_id,
            signing_string.created,
            signing_string.expires,
            signature_b64
        );
        
        Ok(header)
    }
}
```

**Header Parsing and Validation**:
```rust
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ParsedAuthorizationHeader {
    pub key_id: String,
    pub algorithm: String,
    pub created: u64,
    pub expires: u64,
    pub headers: Vec<String>,
    pub signature: Vec<u8>,
}

impl ParsedAuthorizationHeader {
    pub fn parse(header: &str) -> Result<Self, ONDCCryptoError> {
        // Remove "Signature " prefix
        let header = header.strip_prefix("Signature ")
            .ok_or_else(|| ONDCCryptoError::EncodingError("Invalid authorization header format".into()))?;
        
        // Parse key-value pairs
        let mut components = HashMap::new();
        let re = Regex::new(r#"([^=]+)="([^"]+)""#)
            .map_err(|e| ONDCCryptoError::EncodingError(e.to_string()))?;
        
        for captures in re.captures_iter(header) {
            let key = captures.get(1).unwrap().as_str().trim();
            let value = captures.get(2).unwrap().as_str();
            components.insert(key, value);
        }
        
        // Extract required components
        let key_id = components.get("keyId")
            .ok_or_else(|| ONDCCryptoError::EncodingError("Missing keyId".into()))?
            .to_string();
        
        let algorithm = components.get("algorithm")
            .ok_or_else(|| ONDCCryptoError::EncodingError("Missing algorithm".into()))?
            .to_string();
        
        let created = components.get("created")
            .ok_or_else(|| ONDCCryptoError::EncodingError("Missing created".into()))?
            .parse::<u64>()
            .map_err(|_| ONDCCryptoError::EncodingError("Invalid created timestamp".into()))?;
        
        let expires = components.get("expires")
            .ok_or_else(|| ONDCCryptoError::EncodingError("Missing expires".into()))?
            .parse::<u64>()
            .map_err(|_| ONDCCryptoError::EncodingError("Invalid expires timestamp".into()))?;
        
        let headers = components.get("headers")
            .ok_or_else(|| ONDCCryptoError::EncodingError("Missing headers".into()))?
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        
        let signature_b64 = components.get("signature")
            .ok_or_else(|| ONDCCryptoError::EncodingError("Missing signature".into()))?;
        
        let signature = FormatConverter::decode_signature(signature_b64)?;
        
        Ok(Self {
            key_id,
            algorithm,
            created,
            expires,
            headers,
            signature,
        })
    }
    
    pub fn validate_timestamp(&self, tolerance_seconds: u64) -> Result<(), ONDCCryptoError> {
        let now = Utc::now().timestamp() as u64;
        
        // Check if signature has expired
        if now > self.expires {
            return Err(ONDCCryptoError::InvalidTimestamp { timestamp: self.expires });
        }
        
        // Check if signature is not yet valid (with tolerance)
        if now + tolerance_seconds < self.created {
            return Err(ONDCCryptoError::InvalidTimestamp { timestamp: self.created });
        }
        
        Ok(())
    }
}
```

### 5. ondc-crypto-utils

**Purpose**: Utility functions and helper types.

**Key Components**:
```rust
use chrono::{DateTime, Utc};

pub struct TimestampUtils;

impl TimestampUtils {
    pub fn current_timestamp() -> u64 {
        Utc::now().timestamp() as u64
    }
    
    pub fn timestamp_after_duration(duration_seconds: u64) -> u64 {
        (Utc::now() + chrono::Duration::seconds(duration_seconds as i64)).timestamp() as u64
    }
    
    pub fn is_timestamp_valid(timestamp: u64, tolerance_seconds: u64) -> bool {
        let now = Self::current_timestamp();
        timestamp <= now + tolerance_seconds && timestamp + tolerance_seconds >= now
    }
}

pub struct ValidationUtils;

impl ValidationUtils {
    pub fn validate_subscriber_id(id: &str) -> Result<(), ONDCCryptoError> {
        if id.is_empty() {
            return Err(ONDCCryptoError::ConfigError("subscriber_id cannot be empty".into()));
        }
        
        if id.len() > 255 {
            return Err(ONDCCryptoError::ConfigError("subscriber_id too long".into()));
        }
        
        // Add more validation rules as needed
        Ok(())
    }
    
    pub fn validate_key_id(id: &str) -> Result<(), ONDCCryptoError> {
        if id.is_empty() {
            return Err(ONDCCryptoError::ConfigError("key_id cannot be empty".into()));
        }
        
        // Add validation for key ID format
        Ok(())
    }
}
```

### 6. ondc-crypto (Main SDK)

**Purpose**: High-level API that ties everything together.

**Key Components**:
```rust
#[derive(Debug, Clone)]
pub struct ONDCConfig {
    pub timestamp_tolerance_seconds: u64,
    pub default_expiry_hours: u64,
    pub strict_verification: bool,
}

impl Default for ONDCConfig {
    fn default() -> Self {
        Self {
            timestamp_tolerance_seconds: 300, // 5 minutes
            default_expiry_hours: 1,
            strict_verification: true,
        }
    }
}

pub struct ONDCCrypto {
    signer: Ed25519Signer,
    verifier: Ed25519Verifier,
    hasher: Blake2Hasher,
    config: ONDCConfig,
}

impl ONDCCrypto {
    pub fn new(private_key: &[u8]) -> Result<Self, ONDCCryptoError> {
        Self::with_config(private_key, ONDCConfig::default())
    }
    
    pub fn with_config(private_key: &[u8], config: ONDCConfig) -> Result<Self, ONDCCryptoError> {
        Ok(Self {
            signer: Ed25519Signer::new(private_key)?,
            verifier: Ed25519Verifier::new(),
            hasher: Blake2Hasher::new(),
            config,
        })
    }
    
    pub fn create_authorization_header(
        &self,
        body: &[u8],
        subscriber_id: &str,
        unique_key_id: &str,
    ) -> Result<String, ONDCCryptoError> {
        let builder = AuthorizationHeaderBuilder::new(&self.signer.keypair.to_bytes())?;
        builder.create_authorization_header(
            body,
            subscriber_id,
            unique_key_id,
            None,
            Some(Utc::now() + chrono::Duration::hours(self.config.default_expiry_hours as i64)),
        )
    }
    
    pub fn verify_authorization_header(
        &self,
        header: &str,
        body: &[u8],
        public_key: &[u8],
    ) -> Result<bool, ONDCCryptoError> {
        let parsed = ParsedAuthorizationHeader::parse(header)?;
        parsed.validate_timestamp(self.config.timestamp_tolerance_seconds)?;
        
        // Reconstruct signing string
        let signing_string = ONDCSigningString::new(
            body,
            Some(DateTime::from_timestamp(parsed.created as i64, 0).unwrap()),
            Some(DateTime::from_timestamp(parsed.expires as i64, 0).unwrap()),
        )?;
        
        let signing_string_bytes = signing_string.to_string();
        
        if self.config.strict_verification {
            self.verifier.verify_strict(public_key, signing_string_bytes.as_bytes(), &parsed.signature)
                .map(|_| true)
        } else {
            self.verifier.verify(
                &public_key.try_into().map_err(|_| ONDCCryptoError::InvalidKeyLength { expected: 32, got: public_key.len() })?,
                signing_string_bytes.as_bytes(),
                &parsed.signature.try_into().map_err(|_| ONDCCryptoError::InvalidKeyLength { expected: 64, got: parsed.signature.len() })?,
            ).map(|_| true)
        }
    }
    
    pub fn create_vlookup_signature(
        &self,
        country: &str,
        domain: &str,
        type_field: &str,
        city: &str,
        subscriber_id: &str,
    ) -> Result<String, ONDCCryptoError> {
        let signing_string = format!("{}|{}|{}|{}|{}", country, domain, type_field, city, subscriber_id);
        let signature = self.signer.sign(signing_string.as_bytes())?;
        Ok(FormatConverter::encode_signature(&signature))
    }
}

// Async API
#[cfg(feature = "async")]
impl ONDCCrypto {
    pub async fn create_authorization_header_async(
        &self,
        body: &[u8],
        subscriber_id: &str,
        unique_key_id: &str,
    ) -> Result<String, ONDCCryptoError> {
        let signer = self.signer.clone();
        let body = body.to_vec();
        let subscriber_id = subscriber_id.to_string();
        let unique_key_id = unique_key_id.to_string();
        let default_expiry_hours = self.config.default_expiry_hours;
        
        tokio::task::spawn_blocking(move || {
            let builder = AuthorizationHeaderBuilder::new(&signer.keypair.to_bytes())?;
            builder.create_authorization_header(
                &body,
                &subscriber_id,
                &unique_key_id,
                None,
                Some(Utc::now() + chrono::Duration::hours(default_expiry_hours as i64)),
            )
        }).await
        .map_err(|_| ONDCCryptoError::ConfigError("Async task failed".into()))?
    }
}
```

## Implementation Patterns

### 1. Error Handling Pattern
```rust
// Use Result<T, E> consistently
pub fn risky_operation() -> Result<SuccessType, ONDCCryptoError> {
    // ... implementation
}

// Chain operations with ?
pub fn complex_operation() -> Result<String, ONDCCryptoError> {
    let step1 = first_step()?;
    let step2 = second_step(step1)?;
    let result = final_step(step2)?;
    Ok(result)
}

// Convert errors with context
let parsed_value = input.parse::<u64>()
    .map_err(|_| ONDCCryptoError::EncodingError("Invalid timestamp format".into()))?;
```

### 2. Memory Safety Pattern
```rust
use zeroize::{Zeroize, Zeroizing};

// For sensitive data structures
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SensitiveData {
    secret: Vec<u8>,
}

// For temporary sensitive data
fn handle_secret(secret_input: &[u8]) -> Result<(), ONDCCryptoError> {
    let secret = Zeroizing::new(secret_input.to_vec());
    // Use secret...
    // Automatic zeroization on drop
    Ok(())
}
```

### 3. Type Safety Pattern
```rust
// Use newtypes for different contexts
#[derive(Debug, Clone)]
pub struct SubscriberId(String);

#[derive(Debug, Clone)]
pub struct UniqueKeyId(String);

impl SubscriberId {
    pub fn new(id: String) -> Result<Self, ONDCCryptoError> {
        ValidationUtils::validate_subscriber_id(&id)?;
        Ok(Self(id))
    }
}

// Prevent mixing up different string types
pub fn create_header(
    subscriber_id: SubscriberId,
    key_id: UniqueKeyId,
) -> Result<String, ONDCCryptoError> {
    // Implementation guaranteed to receive validated types
}
```

### 4. Builder Pattern
```rust
pub struct AuthorizationHeaderBuilder {
    // ... fields
}

impl AuthorizationHeaderBuilder {
    pub fn new(private_key: &[u8]) -> Result<Self, ONDCCryptoError> {
        // ... implementation
    }
    
    pub fn with_timestamp_tolerance(mut self, tolerance: u64) -> Self {
        // ... configuration
        self
    }
    
    pub fn with_custom_expiry(mut self, expiry: DateTime<Utc>) -> Self {
        // ... configuration
        self
    }
    
    pub fn build(self) -> Result<AuthorizationHeader, ONDCCryptoError> {
        // ... validation and construction
    }
}
```

## Testing Patterns

### 1. Unit Testing
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_signing_roundtrip() {
        let private_key = generate_test_private_key();
        let signer = Ed25519Signer::new(&private_key).unwrap();
        let verifier = Ed25519Verifier::new();
        
        let message = b"test message";
        let signature = signer.sign(message).unwrap();
        
        assert!(verifier.verify(&signer.public_key().try_into().unwrap(), message, &signature).is_ok());
    }
    
    #[test]
    fn test_invalid_signature_fails() {
        let signer = Ed25519Signer::new(&generate_test_private_key()).unwrap();
        let verifier = Ed25519Verifier::new();
        
        let message = b"test message";
        let mut signature = signer.sign(message).unwrap();
        signature[0] ^= 1; // Corrupt signature
        
        assert!(verifier.verify(&signer.public_key().try_into().unwrap(), message, &signature).is_err());
    }
}

fn generate_test_private_key() -> [u8; 32] {
    // Use deterministic key for tests
    [0u8; 32]
}
```

### 2. Property-Based Testing
```rust
#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    
    proptest! {
        #[test]
        fn signature_deterministic(message in ".*") {
            let signer = Ed25519Signer::new(&generate_test_private_key()).unwrap();
            let sig1 = signer.sign(message.as_bytes()).unwrap();
            let sig2 = signer.sign(message.as_bytes()).unwrap();
            prop_assert_eq!(sig1, sig2);
        }
        
        #[test]
        fn different_messages_different_signatures(
            msg1 in "[a-zA-Z0-9]+",
            msg2 in "[a-zA-Z0-9]+",
        ) {
            prop_assume!(msg1 != msg2);
            let signer = Ed25519Signer::new(&generate_test_private_key()).unwrap();
            let sig1 = signer.sign(msg1.as_bytes()).unwrap();
            let sig2 = signer.sign(msg2.as_bytes()).unwrap();
            prop_assert_ne!(sig1, sig2);
        }
    }
}
```

### 3. Integration Testing
```rust
// tests/integration_test.rs
use ondc_crypto::*;

#[test]
fn test_full_ondc_workflow() {
    let private_key = generate_test_private_key();
    let crypto = ONDCCrypto::new(&private_key).unwrap();
    
    let body = br#"{"context": {"action": "search"}}"#;
    let subscriber_id = "test.example.com";
    let unique_key_id = "test_key_1";
    
    // Create authorization header
    let auth_header = crypto.create_authorization_header(
        body,
        subscriber_id,
        unique_key_id,
    ).unwrap();
    
    // Verify the header
    let public_key = extract_public_key_from_private(&private_key);
    let is_valid = crypto.verify_authorization_header(
        &auth_header,
        body,
        &public_key,
    ).unwrap();
    
    assert!(is_valid);
}
```

## Performance Considerations

### 1. Memory Allocation
- Prefer stack allocation for small, fixed-size data
- Use `Vec::with_capacity()` when the size is known
- Minimize string allocations in hot paths
- Use `Cow<str>` for potentially borrowed strings

### 2. Cryptographic Operations
- Batch operations when possible
- Use SIMD-optimized implementations
- Avoid unnecessary key conversions
- Cache public keys when verifying multiple signatures

### 3. Async Patterns
```rust
// Use spawn_blocking for CPU-intensive crypto operations
pub async fn sign_async(&self, message: &[u8]) -> Result<Vec<u8>, ONDCCryptoError> {
    let signer = self.signer.clone();
    let message = message.to_vec();
    
    tokio::task::spawn_blocking(move || {
        signer.sign(&message).map(|sig| sig.to_vec())
    }).await
    .map_err(|_| ONDCCryptoError::ConfigError("Async task failed".into()))?
}
```

## Security Best Practices

### 1. Constant-Time Operations
```rust
use subtle::ConstantTimeEq;

// Compare signatures in constant time
pub fn verify_signature_constant_time(
    expected: &[u8],
    actual: &[u8],
) -> bool {
    expected.ct_eq(actual).into()
}
```

### 2. Memory Zeroization
```rust
// Always zeroize sensitive data
impl Drop for SensitiveStruct {
    fn drop(&mut self) {
        self.secret_data.zeroize();
    }
}
```

### 3. Input Validation
```rust
pub fn validate_input(input: &[u8]) -> Result<(), ONDCCryptoError> {
    if input.is_empty() {
        return Err(ONDCCryptoError::ConfigError("Input cannot be empty".into()));
    }
    
    if input.len() > MAX_INPUT_SIZE {
        return Err(ONDCCryptoError::ConfigError("Input too large".into()));
    }
    
    Ok(())
}
```

This technical guide provides the foundation for implementing a secure, performant, and maintainable ONDC crypto SDK in Rust. Follow these patterns and principles to ensure consistency across all crates and modules.