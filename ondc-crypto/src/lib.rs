//! ONDC Cryptographic SDK for Rust
//!
//! This crate provides a comprehensive cryptographic toolkit for ONDC (Open Network for Digital Commerce)
//! operations, including HTTP signature generation, verification, and key management.
//!
//! # Features
//!
//! - **Ed25519 Signing**: Secure digital signatures using Ed25519
//! - **BLAKE2 Hashing**: Fast cryptographic hashing with BLAKE2
//! - **HTTP Signatures**: ONDC-compliant HTTP signature generation and verification
//! - **Key Management**: Secure key handling with automatic memory zeroization
//! - **Async Support**: Optional async/await support for high-performance applications
//!
//! # Quick Start
//!
//! ```rust
//! use ondc_crypto::ONDCCrypto;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let private_key = b"your_32_byte_private_key_here...";
//!     let crypto = ONDCCrypto::new(private_key)?;
//!     
//!     let body = br#"{"context": {"action": "search"}}"#;
//!     let header = crypto.create_authorization_header(
//!         body,
//!         "your.subscriber.id",
//!         "your_unique_key_id"
//!     )?;
//!     
//!     println!("Authorization: {}", header);
//!     Ok(())
//! }
//! ```

// Re-export internal crates
pub use ondc_crypto_traits;
pub use ondc_crypto_algorithms;
pub use ondc_crypto_formats;
pub use ondc_crypto_http;
pub use ondc_crypto_utils;

// Main API
pub mod api;
pub mod config;

pub use api::ONDCCrypto;
pub use config::ONDCConfig;

/// Re-export commonly used types
pub mod prelude {
    pub use super::api::ONDCCrypto;
    pub use super::config::ONDCConfig;
    pub use ondc_crypto_traits::prelude::*;
    pub use ondc_crypto_algorithms::prelude::*;
    pub use ondc_crypto_formats::prelude::*;
    pub use ondc_crypto_http::prelude::*;
    pub use ondc_crypto_utils::prelude::*;
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
