//! Configuration management for ONDC BAP Server
//!
//! This module handles all configuration aspects including:
//! - Environment-specific configuration loading
//! - Key management configuration
//! - ONDC registry settings
//! - Server configuration

pub mod app_config;
pub mod environment;
pub mod ondc_config;

pub use app_config::BAPConfig;
pub use environment::load_config;
pub use ondc_config::{Environment, ONDCConfig};

/// Configuration error types
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to load configuration: {0}")]
    LoadError(String),

    #[error("Invalid subscriber ID: {0}")]
    InvalidSubscriberId(String),

    #[error("Invalid registry URL: {0}")]
    InvalidRegistryUrl(String),

    #[error("Invalid signing key: {0}")]
    InvalidSigningKey(String),

    #[error("Invalid encryption key: {0}")]
    InvalidEncryptionKey(String),

    #[error("Invalid signing key length: expected 32 bytes, got {0}")]
    InvalidSigningKeyLength(usize),

    #[error("Invalid encryption key length: expected 32 bytes, got {0}")]
    InvalidEncryptionKeyLength(usize),

    #[error("Missing required configuration: {0}")]
    MissingConfig(String),
}
