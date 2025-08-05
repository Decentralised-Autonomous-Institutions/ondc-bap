//! Data models for the ONDC Agent.
//!
//! This module contains all the data structures used throughout the agent:
//! - Intent models for extracted user intent
//! - Beckn models for protocol-compliant requests
//! - Common utilities and types

pub mod intent;
pub mod beckn;

pub use intent::*;
pub use beckn::*;