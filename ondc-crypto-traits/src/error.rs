//! Error types for ONDC cryptographic operations.

use thiserror::Error;

/// Main error type for ONDC cryptographic operations.
#[derive(Error, Debug)]
pub enum ONDCCryptoError {
    /// Signature verification failed
    #[error("signature verification failed")]
    VerificationFailed,
    
    /// Invalid key length
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    
    /// Encoding error
    #[error("encoding error: {0}")]
    EncodingError(String),
    
    /// Invalid timestamp
    #[error("invalid timestamp: {timestamp}")]
    InvalidTimestamp { timestamp: u64 },
    
    /// ONDC protocol error
    #[error("ONDC protocol error: {code} - {message}")]
    ProtocolError { code: u32, message: String },
    
    /// Configuration error
    #[error("configuration error: {0}")]
    ConfigError(String),
}

impl ONDCCryptoError {
    /// Create a policy error (ONDC error code 132)
    pub fn policy_error(message: impl Into<String>) -> Self {
        Self::ProtocolError { code: 132, message: message.into() }
    }
    
    /// Create a domain error (ONDC error code 129)
    pub fn domain_error(message: impl Into<String>) -> Self {
        Self::ProtocolError { code: 129, message: message.into() }
    }
} 