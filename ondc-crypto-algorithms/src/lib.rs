//! Cryptographic algorithm implementations for ONDC.
//!
//! This crate provides implementations of cryptographic algorithms used in
//! ONDC operations, including Ed25519 signing, BLAKE2 hashing, and X25519
//! key exchange.

pub mod ed25519;
pub mod blake2;
pub mod x25519;

pub use ed25519::{Ed25519Signer, Ed25519Verifier};
pub use blake2::Blake2Hasher;
pub use x25519::X25519KeyExchange;

/// Re-export commonly used types
pub mod prelude {
    pub use super::ed25519::{Ed25519Signer, Ed25519Verifier};
    pub use super::blake2::Blake2Hasher;
    pub use super::x25519::X25519KeyExchange;
} 