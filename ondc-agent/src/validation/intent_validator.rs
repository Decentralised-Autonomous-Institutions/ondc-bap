//! Intent validation utilities.
//!
//! This module provides validation for extracted intent data.

use crate::{
    models::intent::Intent,
    error::{AgentError, AgentResult},
};

/// Validator for intent data
pub struct IntentValidator;

impl IntentValidator {
    /// Validate an extracted intent
    pub fn validate(intent: &Intent) -> AgentResult<()> {
        // TODO: Implement intent validation logic
        if intent.confidence < 0.1 {
            return Err(AgentError::validation("Intent confidence too low"));
        }
        
        Ok(())
    }
}