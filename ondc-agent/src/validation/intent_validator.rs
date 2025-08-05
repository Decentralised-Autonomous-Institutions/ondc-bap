//! Intent validation utilities.
//!
//! This module provides validation for extracted intent data.

use crate::{
    models::intent::Intent,
    error::{AgentError, AgentResult},
    config::AgentConfig,
};

/// Validator for intent data
pub struct IntentValidator {
    config: AgentConfig,
}

impl IntentValidator {
    /// Create a new intent validator
    pub fn new(config: AgentConfig) -> AgentResult<Self> {
        Ok(Self { config })
    }

    /// Validate an extracted intent
    pub fn validate(&self, intent: &Intent) -> AgentResult<()> {
        Self::validate_static(intent)
    }

    /// Static method for validation (existing functionality)
    pub fn validate_static(intent: &Intent) -> AgentResult<()> {
        // TODO: Implement intent validation logic
        if intent.confidence < 0.1 {
            return Err(AgentError::validation("Intent confidence too low"));
        }
        
        Ok(())
    }
}