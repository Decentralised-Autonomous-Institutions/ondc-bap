//! Input validation and sanitization utilities.
//!
//! This module provides validation and sanitization for user inputs.

use crate::{error::{AgentError, AgentResult}, config::AgentConfig};

/// Validator for user inputs
pub struct InputValidator {
    config: AgentConfig,
}

impl InputValidator {
    /// Create a new input validator
    pub fn new(config: AgentConfig) -> AgentResult<Self> {
        Ok(Self { config })
    }

    /// Validate and sanitize a query string
    pub fn validate_query(&self, query: &str) -> AgentResult<String> {
        let max_length = 1000; // Default max length
        
        Self::validate_query_static(query, max_length)
    }

    /// Static method for validation (existing functionality)
    pub fn validate_query_static(query: &str, max_length: usize) -> AgentResult<String> {
        if query.trim().is_empty() {
            return Err(AgentError::validation("Query cannot be empty"));
        }
        
        if query.len() > max_length {
            return Err(AgentError::validation("Query exceeds maximum length"));
        }
        
        // Basic sanitization - remove control characters
        let sanitized = query
            .chars()
            .filter(|c| !c.is_control() || c.is_whitespace())
            .collect();
        
        Ok(sanitized)
    }
}