//! Core traits and error types for ONDC cryptographic operations.
//!
//! This crate provides the foundational traits and error types used throughout
//! the ONDC crypto SDK. It defines the interfaces for signing, verification,
//! and hashing operations.

pub mod error;
pub mod traits;

pub use error::ONDCCryptoError;
pub use traits::{Hasher, Signer, Verifier};

/// Re-export commonly used types
pub mod prelude {
    pub use super::error::ONDCCryptoError;
    pub use super::traits::{Hasher, Signer, Verifier};
} 