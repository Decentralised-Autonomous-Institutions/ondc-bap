//! LLM provider trait definitions.
//!
//! This module defines the trait interface that all LLM providers
//! must implement for use with the ONDC Agent.

use async_trait::async_trait;
use crate::error::AgentResult;

/// Trait for LLM providers
#[async_trait]
pub trait LLMProvider: Send + Sync {
    /// Generate a response from the LLM
    async fn generate(&self, prompt: &str) -> AgentResult<String>;
    
    /// Generate a response with system message
    async fn generate_with_system(&self, system: &str, prompt: &str) -> AgentResult<String>;
    
    /// Check if the provider is available/healthy
    async fn health_check(&self) -> AgentResult<()>;
    
    /// Get the provider name
    fn provider_name(&self) -> &str;
}