//! ONDC-specific HTTP signature generation and verification.
//!
//! This crate provides utilities for creating and verifying HTTP signatures
//! according to the ONDC protocol specifications.

pub mod signing_string;
pub mod authorization_header;
pub mod vlookup;

pub use signing_string::ONDCSigningString;
pub use authorization_header::{create_authorization_header, parse_authorization_header};
pub use vlookup::create_vlookup_signature;

/// Re-export commonly used types
pub mod prelude {
    pub use super::signing_string::ONDCSigningString;
    pub use super::authorization_header::{create_authorization_header, parse_authorization_header};
    pub use super::vlookup::create_vlookup_signature;
} 