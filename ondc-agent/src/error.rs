//! Error types and handling for the ONDC Agent.
//!
//! This module provides comprehensive error handling for all agent operations,
//! including LLM interactions, intent processing, and Beckn generation.

use std::fmt;
use thiserror::Error;

/// Result type alias for agent operations
pub type AgentResult<T> = Result<T, AgentError>;

/// Comprehensive error type for ONDC Agent operations
#[derive(Error, Debug)]
pub enum AgentError {
    /// Configuration-related errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// LLM provider connection or communication errors
    #[error("LLM provider error: {0}")]
    Provider(String),

    /// Intent extraction or parsing errors
    #[error("Intent extraction error: {0}")]
    IntentExtraction(String),

    /// Beckn JSON generation errors
    #[error("Beckn generation error: {0}")]
    BecknGeneration(String),

    /// Validation errors for input or output
    #[error("Validation error: {0}")]
    Validation(String),

    /// JSON serialization/deserialization errors
    #[error("JSON processing error: {0}")]
    Json(#[from] serde_json::Error),

    /// HTTP request errors
    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    /// UUID parsing errors
    #[error("UUID error: {0}")]
    Uuid(#[from] uuid::Error),

    /// Time parsing errors
    #[error("Time parsing error: {0}")]
    Time(String),

    /// Timeout errors
    #[error("Operation timed out after {timeout_secs} seconds")]
    Timeout { 
        /// Timeout duration in seconds
        timeout_secs: u64 
    },

    /// Confidence threshold not met
    #[error("Confidence threshold not met: {actual} < {required}")]
    InsufficientConfidence { 
        /// Actual confidence score
        actual: f32, 
        /// Required confidence threshold
        required: f32 
    },

    /// Model not available or unsupported
    #[error("Model '{model}' not supported by provider '{provider}'")]
    UnsupportedModel { 
        /// Model name
        model: String, 
        /// Provider name
        provider: String 
    },

    /// Rate limiting errors
    #[error("Rate limit exceeded, retry after {retry_after_secs} seconds")]
    RateLimit { 
        /// Seconds to wait before retry
        retry_after_secs: u64 
    },

    /// Chain building or execution errors
    #[error("Chain error: {0}")]
    Chain(String),

    /// Generic internal errors
    #[error("Internal error: {0}")]
    Internal(String),

    /// Errors that occurred during async operations
    #[error("Async operation error: {0}")]
    Async(String),
}

impl AgentError {
    /// Create a new configuration error
    pub fn config<T: fmt::Display>(msg: T) -> Self {
        Self::Config(msg.to_string())
    }

    /// Create a new provider error
    pub fn provider<T: fmt::Display>(msg: T) -> Self {
        Self::Provider(msg.to_string())
    }

    /// Create a new intent extraction error
    pub fn intent_extraction<T: fmt::Display>(msg: T) -> Self {
        Self::IntentExtraction(msg.to_string())
    }

    /// Create a new Beckn generation error
    pub fn beckn_generation<T: fmt::Display>(msg: T) -> Self {
        Self::BecknGeneration(msg.to_string())
    }

    /// Create a new validation error
    pub fn validation<T: fmt::Display>(msg: T) -> Self {
        Self::Validation(msg.to_string())
    }

    /// Create a new chain error
    pub fn chain<T: fmt::Display>(msg: T) -> Self {
        Self::Chain(msg.to_string())
    }

    /// Create a new internal error
    pub fn internal<T: fmt::Display>(msg: T) -> Self {
        Self::Internal(msg.to_string())
    }

    /// Create a new timeout error
    pub fn timeout(timeout_secs: u64) -> Self {
        Self::Timeout { timeout_secs }
    }

    /// Create a new insufficient confidence error
    pub fn insufficient_confidence(actual: f32, required: f32) -> Self {
        Self::InsufficientConfidence { actual, required }
    }

    /// Create a new unsupported model error
    pub fn unsupported_model<T: fmt::Display, U: fmt::Display>(model: T, provider: U) -> Self {
        Self::UnsupportedModel {
            model: model.to_string(),
            provider: provider.to_string(),
        }
    }

    /// Create a new rate limit error
    pub fn rate_limit(retry_after_secs: u64) -> Self {
        Self::RateLimit { retry_after_secs }
    }

    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            AgentError::Http(_) | 
            AgentError::Timeout { .. } | 
            AgentError::RateLimit { .. } |
            AgentError::Provider(_)
        )
    }

    /// Get the error category for metrics and logging
    pub fn category(&self) -> &'static str {
        match self {
            AgentError::Config(_) => "config",
            AgentError::Provider(_) => "provider",
            AgentError::IntentExtraction(_) => "intent_extraction",
            AgentError::BecknGeneration(_) => "beckn_generation",
            AgentError::Validation(_) => "validation",
            AgentError::Json(_) => "json",
            AgentError::Http(_) => "http",
            AgentError::Uuid(_) => "uuid",
            AgentError::Time(_) => "time",
            AgentError::Timeout { .. } => "timeout",
            AgentError::InsufficientConfidence { .. } => "confidence",
            AgentError::UnsupportedModel { .. } => "unsupported_model",
            AgentError::RateLimit { .. } => "rate_limit",
            AgentError::Chain(_) => "chain",
            AgentError::Internal(_) => "internal",
            AgentError::Async(_) => "async",
        }
    }
}

// Convert from anyhow::Error
impl From<anyhow::Error> for AgentError {
    fn from(err: anyhow::Error) -> Self {
        AgentError::Internal(err.to_string())
    }
}

// Convert from chrono errors
impl From<chrono::ParseError> for AgentError {
    fn from(err: chrono::ParseError) -> Self {
        AgentError::Time(err.to_string())
    }
}

// Convert from Tokio join errors
impl From<tokio::task::JoinError> for AgentError {
    fn from(err: tokio::task::JoinError) -> Self {
        AgentError::Async(err.to_string())
    }
}