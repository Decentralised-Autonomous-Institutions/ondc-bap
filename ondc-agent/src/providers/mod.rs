//! LLM provider implementations and abstractions.
//!
//! This module provides:
//! - Provider trait definitions
//! - Concrete implementations for Ollama, OpenAI, etc.
//! - Provider configuration and management

pub mod traits;
pub mod ollama;

pub use traits::LLMProvider;
pub use crate::config::ProviderConfig;
pub use ollama::OllamaProvider;