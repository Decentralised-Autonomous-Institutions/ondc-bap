//! LLM provider configuration.
//!
//! This module defines configuration structures for different LLM providers
//! supported by the ONDC Agent.

use serde::{Deserialize, Serialize};
use crate::error::{AgentError, AgentResult};

/// Configuration for different LLM providers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ProviderConfig {
    /// Ollama local LLM provider
    Ollama {
        /// Base URL of the Ollama server
        base_url: String,
        /// Model name to use
        model: String,
    },
    
    /// OpenAI API provider
    OpenAI {
        /// API key for OpenAI
        api_key: String,
        /// Model name (e.g., "gpt-4", "gpt-3.5-turbo")
        model: String,
        /// Optional custom base URL
        base_url: Option<String>,
    },
    
    /// Anthropic Claude provider
    Anthropic {
        /// API key for Anthropic
        api_key: String,
        /// Model name (e.g., "claude-3-sonnet-20240229")
        model: String,
        /// Optional custom base URL
        base_url: Option<String>,
    },
    
    /// Mock provider for testing
    Mock,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self::Ollama {
            base_url: "http://localhost:11434".to_string(),
            model: "gemma2:latest".to_string(),
        }
    }
}

impl ProviderConfig {
    /// Validate the provider configuration
    pub fn validate(&self) -> AgentResult<()> {
        match self {
            ProviderConfig::Ollama { base_url, model } => {
                if base_url.is_empty() {
                    return Err(AgentError::config("Ollama base URL cannot be empty"));
                }
                if model.is_empty() {
                    return Err(AgentError::config("Ollama model name cannot be empty"));
                }
                
                // Validate URL format
                url::Url::parse(base_url)
                    .map_err(|_| AgentError::config("Invalid Ollama base URL format"))?;
            }
            
            ProviderConfig::OpenAI { api_key, model, base_url } => {
                if api_key.is_empty() {
                    return Err(AgentError::config("OpenAI API key cannot be empty"));
                }
                if model.is_empty() {
                    return Err(AgentError::config("OpenAI model name cannot be empty"));
                }
                
                // Validate API key format (should start with "sk-")
                if !api_key.starts_with("sk-") && !api_key.starts_with("sk_") {
                    return Err(AgentError::config("Invalid OpenAI API key format"));
                }
                
                // Validate custom base URL if provided
                if let Some(url) = base_url {
                    url::Url::parse(url)
                        .map_err(|_| AgentError::config("Invalid OpenAI base URL format"))?;
                }
            }
            
            ProviderConfig::Anthropic { api_key, model, base_url } => {
                if api_key.is_empty() {
                    return Err(AgentError::config("Anthropic API key cannot be empty"));
                }
                if model.is_empty() {
                    return Err(AgentError::config("Anthropic model name cannot be empty"));
                }
                
                // Validate custom base URL if provided
                if let Some(url) = base_url {
                    url::Url::parse(url)
                        .map_err(|_| AgentError::config("Invalid Anthropic base URL format"))?;
                }
            }
            
            ProviderConfig::Mock => {
                // Mock provider is always valid
            }
        }
        
        Ok(())
    }
    
    /// Get the provider type as a string
    pub fn provider_type(&self) -> &'static str {
        match self {
            ProviderConfig::Ollama { .. } => "ollama",
            ProviderConfig::OpenAI { .. } => "openai",
            ProviderConfig::Anthropic { .. } => "anthropic",
            ProviderConfig::Mock => "mock",
        }
    }
    
    /// Get the model name
    pub fn model_name(&self) -> &str {
        match self {
            ProviderConfig::Ollama { model, .. } => model,
            ProviderConfig::OpenAI { model, .. } => model,
            ProviderConfig::Anthropic { model, .. } => model,
            ProviderConfig::Mock => "mock-model",
        }
    }
    
    /// Check if this is a cloud-based provider
    pub fn is_cloud_provider(&self) -> bool {
        matches!(self, ProviderConfig::OpenAI { .. } | ProviderConfig::Anthropic { .. })
    }
    
    /// Check if this provider requires an API key
    pub fn requires_api_key(&self) -> bool {
        matches!(self, ProviderConfig::OpenAI { .. } | ProviderConfig::Anthropic { .. })
    }
    
    /// Get the base URL for the provider
    pub fn base_url(&self) -> Option<&str> {
        match self {
            ProviderConfig::Ollama { base_url, .. } => Some(base_url),
            ProviderConfig::OpenAI { base_url, .. } => base_url.as_deref(),
            ProviderConfig::Anthropic { base_url, .. } => base_url.as_deref(),
            ProviderConfig::Mock => None,
        }
    }
    
    /// Create Ollama configuration
    pub fn ollama(base_url: impl Into<String>, model: impl Into<String>) -> Self {
        Self::Ollama {
            base_url: base_url.into(),
            model: model.into(),
        }
    }
    
    /// Create OpenAI configuration
    pub fn openai(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        Self::OpenAI {
            api_key: api_key.into(),
            model: model.into(),
            base_url: None,
        }
    }
    
    /// Create OpenAI configuration with custom base URL
    pub fn openai_with_url(
        api_key: impl Into<String>, 
        model: impl Into<String>, 
        base_url: impl Into<String>
    ) -> Self {
        Self::OpenAI {
            api_key: api_key.into(),
            model: model.into(),
            base_url: Some(base_url.into()),
        }
    }
    
    /// Create Anthropic configuration
    pub fn anthropic(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        Self::Anthropic {
            api_key: api_key.into(),
            model: model.into(),
            base_url: None,
        }
    }
    
    /// Create Anthropic configuration with custom base URL
    pub fn anthropic_with_url(
        api_key: impl Into<String>, 
        model: impl Into<String>, 
        base_url: impl Into<String>
    ) -> Self {
        Self::Anthropic {
            api_key: api_key.into(),
            model: model.into(),
            base_url: Some(base_url.into()),
        }
    }
}

/// Supported LLM providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderType {
    /// Ollama
    Ollama,
    /// OpenAI
    OpenAI,
    /// Anthropic
    Anthropic,
    /// Mock (for testing)
    Mock,
}

impl ProviderType {
    /// Get all supported provider types
    pub fn all() -> Vec<Self> {
        vec![Self::Ollama, Self::OpenAI, Self::Anthropic, Self::Mock]
    }
    
    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ollama => "ollama",
            Self::OpenAI => "openai",
            Self::Anthropic => "anthropic",
            Self::Mock => "mock",
        }
    }
    
    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ollama" => Some(Self::Ollama),
            "openai" => Some(Self::OpenAI),
            "anthropic" => Some(Self::Anthropic),
            "mock" => Some(Self::Mock),
            _ => None,
        }
    }
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ProviderType {
    type Err = AgentError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str(s).ok_or_else(|| AgentError::config(format!("Unknown provider type: {}", s)))
    }
}

/// Model capabilities and constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCapabilities {
    /// Maximum context length (tokens)
    pub max_context_length: usize,
    
    /// Maximum output length (tokens)
    pub max_output_length: usize,
    
    /// Supports function calling
    pub supports_functions: bool,
    
    /// Supports JSON mode
    pub supports_json_mode: bool,
    
    /// Supports streaming
    pub supports_streaming: bool,
    
    /// Cost per input token (USD)
    pub cost_per_input_token: f64,
    
    /// Cost per output token (USD)
    pub cost_per_output_token: f64,
}

impl ModelCapabilities {
    /// Get default capabilities for a model
    pub fn for_model(provider: &ProviderConfig) -> Self {
        match provider {
            ProviderConfig::Ollama { model, .. } => {
                // Default capabilities for Ollama models
                // These can be overridden based on specific models
                Self {
                    max_context_length: if model.contains("gemma") { 8192 } else { 4096 },
                    max_output_length: 2048,
                    supports_functions: false,
                    supports_json_mode: true,
                    supports_streaming: true,
                    cost_per_input_token: 0.0, // Free for local models
                    cost_per_output_token: 0.0,
                }
            }
            
            ProviderConfig::OpenAI { model, .. } => {
                match model.as_str() {
                    "gpt-4o" | "gpt-4o-mini" => Self {
                        max_context_length: 128000,
                        max_output_length: 4096,
                        supports_functions: true,
                        supports_json_mode: true,
                        supports_streaming: true,
                        cost_per_input_token: if model == "gpt-4o-mini" { 0.00000015 } else { 0.000005 },
                        cost_per_output_token: if model == "gpt-4o-mini" { 0.0000006 } else { 0.000015 },
                    },
                    "gpt-4" => Self {
                        max_context_length: 8192,
                        max_output_length: 4096,
                        supports_functions: true,
                        supports_json_mode: true,
                        supports_streaming: true,
                        cost_per_input_token: 0.00003,
                        cost_per_output_token: 0.00006,
                    },
                    "gpt-3.5-turbo" => Self {
                        max_context_length: 16385,
                        max_output_length: 4096,
                        supports_functions: true,
                        supports_json_mode: true,
                        supports_streaming: true,
                        cost_per_input_token: 0.0000005,
                        cost_per_output_token: 0.0000015,
                    },
                    _ => Self::default_openai(),
                }
            }
            
            ProviderConfig::Anthropic { model, .. } => {
                match model.as_str() {
                    "claude-3-5-sonnet-20241022" => Self {
                        max_context_length: 200000,
                        max_output_length: 8192,
                        supports_functions: true,
                        supports_json_mode: true,
                        supports_streaming: true,
                        cost_per_input_token: 0.000003,
                        cost_per_output_token: 0.000015,
                    },
                    "claude-3-haiku-20240307" => Self {
                        max_context_length: 200000,
                        max_output_length: 4096,
                        supports_functions: false,
                        supports_json_mode: true,
                        supports_streaming: true,
                        cost_per_input_token: 0.00000025,
                        cost_per_output_token: 0.00000125,
                    },
                    _ => Self::default_anthropic(),
                }
            }
            
            ProviderConfig::Mock => Self {
                max_context_length: 4096,
                max_output_length: 1024,
                supports_functions: true,
                supports_json_mode: true,
                supports_streaming: false,
                cost_per_input_token: 0.0,
                cost_per_output_token: 0.0,
            },
        }
    }
    
    fn default_openai() -> Self {
        Self {
            max_context_length: 4096,
            max_output_length: 1024,
            supports_functions: true,
            supports_json_mode: true,
            supports_streaming: true,
            cost_per_input_token: 0.00001,
            cost_per_output_token: 0.00002,
        }
    }
    
    fn default_anthropic() -> Self {
        Self {
            max_context_length: 100000,
            max_output_length: 4096,
            supports_functions: false,
            supports_json_mode: true,
            supports_streaming: true,
            cost_per_input_token: 0.000008,
            cost_per_output_token: 0.000024,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_provider_config_validation() {
        // Valid Ollama config
        let ollama_config = ProviderConfig::ollama("http://localhost:11434", "gemma2:latest");
        assert!(ollama_config.validate().is_ok());
        
        // Invalid Ollama config (empty URL)
        let invalid_ollama = ProviderConfig::Ollama {
            base_url: "".to_string(),
            model: "test".to_string(),
        };
        assert!(invalid_ollama.validate().is_err());
        
        // Valid OpenAI config
        let openai_config = ProviderConfig::openai("sk-test123", "gpt-4");
        assert!(openai_config.validate().is_ok());
        
        // Invalid OpenAI config (bad API key format)
        let invalid_openai = ProviderConfig::OpenAI {
            api_key: "invalid_key".to_string(),
            model: "gpt-4".to_string(),
            base_url: None,
        };
        assert!(invalid_openai.validate().is_err());
    }
    
    #[test]
    fn test_provider_type_parsing() {
        assert_eq!(ProviderType::from_str("ollama"), Some(ProviderType::Ollama));
        assert_eq!(ProviderType::from_str("OPENAI"), Some(ProviderType::OpenAI));
        assert_eq!(ProviderType::from_str("unknown"), None);
    }
    
    #[test]
    fn test_model_capabilities() {
        let ollama_config = ProviderConfig::ollama("http://localhost:11434", "gemma2:latest");
        let capabilities = ModelCapabilities::for_model(&ollama_config);
        assert_eq!(capabilities.max_context_length, 8192);
        assert_eq!(capabilities.cost_per_input_token, 0.0);
        
        let openai_config = ProviderConfig::openai("sk-test", "gpt-4o-mini");
        let capabilities = ModelCapabilities::for_model(&openai_config);
        assert_eq!(capabilities.max_context_length, 128000);
        assert!(capabilities.supports_functions);
    }
    
    #[test]
    fn test_provider_properties() {
        let ollama_config = ProviderConfig::ollama("http://localhost:11434", "gemma2");
        assert_eq!(ollama_config.provider_type(), "ollama");
        assert_eq!(ollama_config.model_name(), "gemma2");
        assert!(!ollama_config.is_cloud_provider());
        assert!(!ollama_config.requires_api_key());
        
        let openai_config = ProviderConfig::openai("sk-test", "gpt-4");
        assert_eq!(openai_config.provider_type(), "openai");
        assert!(openai_config.is_cloud_provider());
        assert!(openai_config.requires_api_key());
    }
}