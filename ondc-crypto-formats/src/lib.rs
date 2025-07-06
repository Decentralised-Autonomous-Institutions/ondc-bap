//! Encoding and decoding utilities for ONDC cryptographic operations.
//!
//! This crate provides utilities for encoding and decoding cryptographic
//! data in various formats, including Base64, hex, and key format conversions.

pub mod base64;
pub mod key_formats;

pub use base64::{decode_signature, encode_signature};
pub use key_formats::{ed25519_from_raw, x25519_to_der};

/// Re-export commonly used types
pub mod prelude {
    pub use super::base64::{decode_signature, encode_signature};
    pub use super::key_formats::{ed25519_from_raw, x25519_to_der};
} 