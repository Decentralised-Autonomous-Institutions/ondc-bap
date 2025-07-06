//! Utility functions and helper types for ONDC cryptographic operations.
//!
//! This crate provides utility functions for timestamp handling, validation,
//! and other common operations used throughout the ONDC crypto SDK.

pub mod time;
pub mod validation;

pub use time::{current_timestamp, is_timestamp_valid};
pub use validation::{validate_subscriber_id, validate_key_id};

/// Re-export commonly used types
pub mod prelude {
    pub use super::time::{current_timestamp, is_timestamp_valid};
    pub use super::validation::{validate_subscriber_id, validate_key_id};
} 