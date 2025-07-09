//! Encoding and decoding utilities for ONDC cryptographic operations.
//!
//! This crate provides utilities for encoding and decoding cryptographic
//! data in various formats, including Base64, hex, and key format conversions.

pub mod base64;
pub mod key_formats;

pub use base64::{
    decode_signature, decode_signature_secure, decode_signature_variant, encode_signature,
    encode_signature_secure, encode_signature_variant, is_valid_base64, Base64Variant,
};
pub use key_formats::{
    ed25519_from_raw,
    ed25519_private_key_from_base64,
    ed25519_private_key_from_der,
    // Ed25519 conversions
    ed25519_private_key_to_base64,
    ed25519_private_key_to_der,
    ed25519_public_key_from_base64,
    ed25519_public_key_to_base64,
    x25519_private_key_from_base64,
    x25519_private_key_from_der,
    // X25519 conversions
    x25519_private_key_to_base64,
    x25519_private_key_to_der,
    x25519_public_key_from_base64,
    x25519_public_key_from_der,
    x25519_public_key_to_base64,
    x25519_public_key_to_der,
    x25519_to_der,
};

/// Re-export commonly used types
pub mod prelude {
    pub use super::base64::{
        decode_signature, decode_signature_secure, decode_signature_variant, encode_signature,
        encode_signature_secure, encode_signature_variant, is_valid_base64, Base64Variant,
    };
    pub use super::key_formats::{
        ed25519_from_raw,
        ed25519_private_key_from_base64,
        ed25519_private_key_from_der,
        // Ed25519 conversions
        ed25519_private_key_to_base64,
        ed25519_private_key_to_der,
        ed25519_public_key_from_base64,
        ed25519_public_key_to_base64,
        x25519_private_key_from_base64,
        x25519_private_key_from_der,
        // X25519 conversions
        x25519_private_key_to_base64,
        x25519_private_key_to_der,
        x25519_public_key_from_base64,
        x25519_public_key_from_der,
        x25519_public_key_to_base64,
        x25519_public_key_to_der,
        x25519_to_der,
    };
}
