//! Input validation and sanitization utilities.
//!
//! This module provides validation and sanitization for user inputs.

use crate::error::{AgentError, AgentResult};

/// Validator for user inputs
pub struct InputValidator;

impl InputValidator {
    /// Validate and sanitize a query string
    pub fn validate_query(query: &str, max_length: usize) -> AgentResult<String> {
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