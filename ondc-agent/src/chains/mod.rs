//! LangChain integration and chain definitions.
//!
//! This module contains the LangChain-Rust integrations for:
//! - Intent extraction chains
//! - Beckn JSON generation chains
//! - Chain composition and management

pub mod intent_chain;
pub mod beckn_chain;

pub use intent_chain::IntentChain;
pub use beckn_chain::BecknChain;