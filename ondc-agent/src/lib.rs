//! # ONDC Agent
//!
//! A Rust library for converting natural language queries into ONDC/Beckn protocol-compliant JSON requests
//! using Large Language Models (LLMs). This crate provides the core functionality for:
//!
//! - Intent extraction from natural language queries
//! - Generation of Beckn protocol search requests
//! - Integration with various LLM providers (Ollama, OpenAI, etc.)
//! - Validation and error handling for agent operations
//!
//! ## Features
//!
//! - **Intent Extraction**: Parse user queries to extract e-commerce intent
//! - **Beckn Generation**: Convert extracted intent to valid Beckn search requests  
//! - **Provider Agnostic**: Support for multiple LLM providers through traits
//! - **Validation**: Comprehensive validation for both intent and Beckn outputs
//! - **Error Handling**: Robust error handling with detailed error types
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use ondc_agent::{ONDCAgent, AgentConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = AgentConfig::default();
//!     let agent = ONDCAgent::new(config).await?;
//!     
//!     let query = "I need to buy fresh vegetables in Bangalore";
//!     let intent = agent.extract_intent(query).await?;
//!     let beckn_request = agent.generate_search_request(intent).await?;
//!     
//!     println!("Generated Beckn request: {}", serde_json::to_string_pretty(&beckn_request)?);
//!     Ok(())
//! }
//! ```

#![deny(missing_docs)]
#![warn(rust_2018_idioms)]

// Public exports
pub use agent::ONDCAgent;
pub use config::{AgentConfig, BapConfig};
pub use error::{AgentError, AgentResult};
pub use models::{
    intent::{Intent, PriceRange, FulfillmentType, Urgency, IntentSummary},
    beckn::{BecknSearchRequest, BecknContext, BecknMessage, BecknIntent},
};
pub use providers::{LLMProvider, ProviderConfig};

// Internal modules
pub mod agent;
pub mod chains;
pub mod config;
pub mod error;
pub mod models;
pub mod providers;
pub mod services;
pub mod validation;

// Re-export common types for convenience
pub use serde_json::Value as JsonValue;
pub use uuid::Uuid;
pub use chrono::{DateTime, Utc};

/// Current version of the ONDC Agent library
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default timeout for LLM requests in seconds
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Default confidence threshold for intent extraction
pub const DEFAULT_CONFIDENCE_THRESHOLD: f32 = 0.7;

/// Maximum retry attempts for LLM requests
pub const MAX_RETRY_ATTEMPTS: u32 = 3;