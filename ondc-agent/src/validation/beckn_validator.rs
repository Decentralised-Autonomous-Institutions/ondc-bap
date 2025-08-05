//! Beckn protocol validation utilities.
//!
//! This module provides validation for Beckn protocol compliance.

use crate::{
    models::beckn::BecknSearchRequest,
    error::{AgentError, AgentResult},
    config::AgentConfig,
};

/// Validator for Beckn protocol data
pub struct BecknValidator {
    config: AgentConfig,
}

impl BecknValidator {
    /// Create a new Beckn validator
    pub fn new(config: AgentConfig) -> AgentResult<Self> {
        Ok(Self { config })
    }

    /// Validate a Beckn search request
    pub fn validate(&self, request: &BecknSearchRequest) -> AgentResult<()> {
        Self::validate_static(request)
    }

    /// Static method for validation (existing functionality)
    pub fn validate_static(request: &BecknSearchRequest) -> AgentResult<()> {
        // TODO: Implement Beckn validation logic
        if !request.is_valid() {
            return Err(AgentError::validation("Invalid Beckn request structure"));
        }
        
        Ok(())
    }
}