//! Configuration types for ONDC cryptographic operations.

/// Configuration for ONDC cryptographic operations.
#[derive(Debug, Clone)]
pub struct ONDCConfig {
    /// Timestamp tolerance in seconds for signature validation
    pub timestamp_tolerance_seconds: u64,
    /// Default expiry time in hours for signatures
    pub default_expiry_hours: u64,
    /// Whether to use strict verification (prevents signature malleability)
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