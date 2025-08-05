//! Validation utilities for agent inputs and outputs.
//!
//! This module provides validation for:
//! - Intent extraction results
//! - Beckn protocol compliance
//! - Input sanitization and checks
//! - Confidence scoring

pub mod intent_validator;
pub mod beckn_validator;
pub mod input_validator;

pub use intent_validator::IntentValidator;
pub use beckn_validator::BecknValidator;
pub use input_validator::InputValidator;