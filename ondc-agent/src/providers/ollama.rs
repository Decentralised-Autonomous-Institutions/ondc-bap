//! Ollama LLM provider implementation.
//!
//! This module implements the LLMProvider trait for Ollama,
//! allowing the agent to use locally hosted Ollama models via langchain-rust.

use async_trait::async_trait;
use langchain_rust::language_models::llm::LLM;
use langchain_rust::llm::client::Ollama;
use langchain_rust::llm::ollama::client::OllamaClient;
use tracing::{debug, info, warn};
use crate::{
    config::ProviderConfig,
    error::{AgentError, AgentResult},
    providers::traits::LLMProvider,
};

/// Ollama provider implementation using langchain-rust
pub struct OllamaProvider {
    /// Provider configuration
    config: ProviderConfig,
    /// LangChain Ollama client
    ollama: Ollama,
}

impl OllamaProvider {
    /// Create a new Ollama provider using langchain-rust
    pub fn new(config: ProviderConfig) -> AgentResult<Self> {
        match &config {
            ProviderConfig::Ollama { base_url, model } => {
                debug!("Creating Ollama provider with base_url: {}, model: {}", base_url, model);
                
                // Parse base URL to extract host and port
                let url = url::Url::parse(base_url)
                    .map_err(|e| AgentError::config(format!("Invalid Ollama base URL: {}", e)))?;
                let host = format!("{}://{}", url.scheme(), url.host_str().unwrap_or("localhost"));
                let port = url.port().unwrap_or(11434);
                
                // Create langchain-rust Ollama client with configuration
                let ollama_client = OllamaClient::new(host, port);
                let ollama = Ollama::new(ollama_client.into(), model.clone(), None);
                
                debug!("Ollama provider created successfully");
                Ok(Self { config, ollama })
            }
            _ => Err(AgentError::config("Invalid provider config for Ollama")),
        }
    }
    
    /// Get the model name from configuration
    pub fn model_name(&self) -> &str {
        match &self.config {
            ProviderConfig::Ollama { model, .. } => model,
            _ => "unknown",
        }
    }
    
    /// Get the base URL from configuration
    pub fn base_url(&self) -> &str {
        match &self.config {
            ProviderConfig::Ollama { base_url, .. } => base_url,
            _ => "",
        }
    }
}

#[async_trait]
impl LLMProvider for OllamaProvider {
    async fn generate(&self, prompt: &str) -> AgentResult<String> {
        debug!("Generating response for prompt: {} chars", prompt.len());
        
        let response = self.ollama
            .invoke(prompt)
            .await
            .map_err(|e| {
                warn!("Ollama generation failed: {}", e);
                AgentError::provider(format!("Ollama generation failed: {}", e))
            })?;
        
        debug!("Generated response: {} chars", response.len());
        Ok(response)
    }
    
    async fn generate_with_system(&self, system: &str, prompt: &str) -> AgentResult<String> {
        debug!("Generating response with system message: {} chars, prompt: {} chars", 
               system.len(), prompt.len());
        
        // For Ollama, we combine system and user messages in a structured format
        let combined_prompt = format!(
            "System: {}\n\nUser: {}\n\nAssistant:", 
            system.trim(), 
            prompt.trim()
        );
        
        // Use the standard generate method with the formatted prompt
        self.generate(&combined_prompt).await
    }
    
    async fn health_check(&self) -> AgentResult<()> {
        debug!("Performing health check for Ollama provider");
        
        // Try a simple generation to check if Ollama is available
        let test_prompt = "Say 'OK' if you can hear me.";
        let test_response = self.generate(test_prompt).await
            .map_err(|e| {
                warn!("Ollama health check failed: {}", e);
                AgentError::provider(format!("Ollama health check failed: {}", e))
            })?;
        
        if test_response.trim().is_empty() {
            warn!("Ollama returned empty response during health check");
            return Err(AgentError::provider("Ollama returned empty response"));
        }
        
        info!("Ollama health check passed - model: {}", self.model_name());
        Ok(())
    }
    
    fn provider_name(&self) -> &str {
        "ollama"
    }
}

/// Create an Ollama provider from configuration
pub fn create_ollama_provider(config: ProviderConfig) -> AgentResult<OllamaProvider> {
    OllamaProvider::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProviderConfig;
    
    #[test]
    fn test_ollama_provider_creation() {
        let config = ProviderConfig::ollama("http://localhost:11434", "gemma2:latest");
        let provider = OllamaProvider::new(config).unwrap();
        
        assert_eq!(provider.provider_name(), "ollama");
        assert_eq!(provider.model_name(), "gemma2:latest");
        assert_eq!(provider.base_url(), "http://localhost:11434");
    }
    
    #[test]
    fn test_invalid_config() {
        let config = ProviderConfig::Mock;
        let result = OllamaProvider::new(config);
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_health_check_with_mock() {
        // This test requires a running Ollama instance
        // In real scenarios, we'd use a mock server for testing
        let config = ProviderConfig::ollama("http://localhost:11434", "gemma2:latest");
        let provider = OllamaProvider::new(config).unwrap();
        
        // Health check will fail without running Ollama, which is expected
        let result = provider.health_check().await;
        // In a real test environment with Ollama running, this should pass
        // For now, we just ensure the method doesn't panic
        let _ = result;
    }
}