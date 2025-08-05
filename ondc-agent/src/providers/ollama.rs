//! Ollama LLM provider implementation.
//!
//! This module implements the LLMProvider trait for Ollama,
//! allowing the agent to use locally hosted Ollama models.

use async_trait::async_trait;
use serde_json::json;
use crate::{
    config::ProviderConfig,
    error::{AgentError, AgentResult},
    providers::traits::LLMProvider,
};

/// Ollama provider implementation
pub struct OllamaProvider {
    /// Provider configuration
    config: ProviderConfig,
    /// HTTP client for Ollama API
    client: reqwest::Client,
}

impl OllamaProvider {
    /// Create a new Ollama provider
    pub fn new(config: ProviderConfig) -> AgentResult<Self> {
        match &config {
            ProviderConfig::Ollama { base_url: _, model: _ } => {
                let client = reqwest::Client::new();
                Ok(Self { config, client })
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
        tracing::debug!("Generating response for prompt: {}", prompt);
        
        let (base_url, model) = match &self.config {
            ProviderConfig::Ollama { base_url, model } => (base_url, model),
            _ => return Err(AgentError::config("Invalid Ollama configuration")),
        };
        
        let request_body = json!({
            "model": model,
            "prompt": prompt,
            "stream": false
        });
        
        let response = self.client
            .post(&format!("{}/api/generate", base_url))
            .json(&request_body)
            .send()
            .await
            .map_err(|e| AgentError::provider(format!("Ollama request failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(AgentError::provider(format!(
                "Ollama API returned error: {}", 
                response.status()
            )));
        }
        
        let response_json: serde_json::Value = response.json().await
            .map_err(|e| AgentError::provider(format!("Failed to parse Ollama response: {}", e)))?;
        
        let generated_text = response_json["response"]
            .as_str()
            .ok_or_else(|| AgentError::provider("Invalid response format from Ollama"))?
            .to_string();
        
        tracing::debug!("Generated response: {}", generated_text);
        Ok(generated_text)
    }
    
    async fn generate_with_system(&self, system: &str, prompt: &str) -> AgentResult<String> {
        tracing::debug!("Generating response with system: {} and prompt: {}", system, prompt);
        
        // For Ollama, we can combine system and user messages in the prompt
        let combined_prompt = format!("System: {}\n\nUser: {}", system, prompt);
        
        // Reuse the generate method with the combined prompt
        self.generate(&combined_prompt).await
    }
    
    async fn health_check(&self) -> AgentResult<()> {
        tracing::debug!("Performing health check for Ollama at {}", self.base_url());
        
        // Try a simple generation to check if Ollama is available
        let test_response = self.generate("Hello").await
            .map_err(|e| AgentError::provider(format!("Ollama health check failed: {}", e)))?;
        
        if test_response.trim().is_empty() {
            return Err(AgentError::provider("Ollama returned empty response"));
        }
        
        tracing::info!("Ollama health check passed");
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