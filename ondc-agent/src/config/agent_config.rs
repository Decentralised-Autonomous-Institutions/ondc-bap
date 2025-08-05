//! Agent configuration management.
//!
//! This module defines the main configuration structure for the ONDC Agent,
//! including LLM provider settings, validation thresholds, and operational parameters.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use crate::config::ProviderConfig;
use crate::error::{AgentError, AgentResult};
use crate::{DEFAULT_TIMEOUT_SECS, DEFAULT_CONFIDENCE_THRESHOLD, MAX_RETRY_ATTEMPTS};

/// Main configuration for the ONDC Agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// LLM provider configuration
    pub provider: ProviderConfig,
    
    /// Confidence threshold for intent extraction (0.0 to 1.0)
    pub confidence_threshold: f32,
    
    /// Request timeout in seconds
    pub timeout_secs: u64,
    
    /// Maximum retry attempts for failed requests
    pub max_retries: u32,
    
    /// Default ONDC domain to use
    pub default_domain: String,
    
    /// Default country code
    pub default_country: String,
    
    /// Default city for searches
    pub default_city: String,
    
    /// BAP configuration
    pub bap: BapConfig,
    
    /// Validation settings
    pub validation: ValidationConfig,
    
    /// Cache settings
    pub cache: CacheConfig,
    
    /// Logging and observability settings
    pub observability: ObservabilityConfig,
}

/// BAP (Beckn Application Platform) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BapConfig {
    /// BAP ID (unique identifier)
    pub id: String,
    
    /// BAP URI (callback URL)
    pub uri: String,
    
    /// Core version to use
    pub core_version: String,
    
    /// Default TTL for messages
    pub default_ttl: String,
}

/// Validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    /// Enable strict validation of generated Beckn JSON
    pub strict_beckn_validation: bool,
    
    /// Enable input sanitization
    pub sanitize_inputs: bool,
    
    /// Maximum query length allowed
    pub max_query_length: usize,
    
    /// Minimum confidence for auto-acceptance
    pub auto_accept_threshold: f32,
    
    /// Enable intent validation
    pub validate_intent: bool,
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Enable response caching
    pub enabled: bool,
    
    /// Cache TTL in seconds
    pub ttl_secs: u64,
    
    /// Maximum cache size (number of entries)
    pub max_entries: usize,
    
    /// Cache similar queries (based on semantic similarity)
    pub semantic_caching: bool,
}

/// Observability and monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Enable metrics collection
    pub metrics_enabled: bool,
    
    /// Enable distributed tracing
    pub tracing_enabled: bool,
    
    /// Log level for agent operations
    pub log_level: String,
    
    /// Enable performance profiling
    pub profiling_enabled: bool,
    
    /// Sample rate for tracing (0.0 to 1.0)
    pub trace_sample_rate: f32,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            provider: ProviderConfig::default(),
            confidence_threshold: DEFAULT_CONFIDENCE_THRESHOLD,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            max_retries: MAX_RETRY_ATTEMPTS,
            default_domain: "nic2004:52110".to_string(), // Retail trade
            default_country: "IND".to_string(),
            default_city: "Bangalore".to_string(),
            bap: BapConfig::default(),
            validation: ValidationConfig::default(),
            cache: CacheConfig::default(),
            observability: ObservabilityConfig::default(),
        }
    }
}

impl Default for BapConfig {
    fn default() -> Self {
        Self {
            id: "".to_string(),
            uri: "".to_string(),
            core_version: "1.0.0".to_string(),
            default_ttl: "PT30S".to_string(),
        }
    }
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            strict_beckn_validation: true,
            sanitize_inputs: true,
            max_query_length: 1000,
            auto_accept_threshold: 0.8,
            validate_intent: true,
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl_secs: 300, // 5 minutes
            max_entries: 1000,
            semantic_caching: false, // Disabled by default due to complexity
        }
    }
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            metrics_enabled: true,
            tracing_enabled: true,
            log_level: "info".to_string(),
            profiling_enabled: false,
            trace_sample_rate: 1.0,
        }
    }
}

impl AgentConfig {
    /// Create a new configuration from environment variables
    pub fn from_env() -> AgentResult<Self> {
        let mut config = Self::default();
        
        // Provider configuration
        if let Ok(provider_type) = std::env::var("ONDC_AGENT_PROVIDER") {
            match provider_type.to_lowercase().as_str() {
                "ollama" => {
                    let base_url = std::env::var("ONDC_AGENT_OLLAMA_URL")
                        .unwrap_or_else(|_| "http://localhost:11434".to_string());
                    let model = std::env::var("ONDC_AGENT_OLLAMA_MODEL")
                        .unwrap_or_else(|_| "gemma2:latest".to_string());
                    config.provider = ProviderConfig::Ollama { base_url, model };
                }
                "openai" => {
                    let api_key = std::env::var("OPENAI_API_KEY")
                        .map_err(|_| AgentError::config("OPENAI_API_KEY environment variable not set"))?;
                    let model = std::env::var("ONDC_AGENT_OPENAI_MODEL")
                        .unwrap_or_else(|_| "gpt-4".to_string());
                    let base_url = std::env::var("ONDC_AGENT_OPENAI_URL").ok();
                    config.provider = ProviderConfig::OpenAI { api_key, model, base_url };
                }
                _ => return Err(AgentError::config(format!("Unsupported provider: {}", provider_type))),
            }
        }
        
        // BAP configuration
        if let Ok(bap_id) = std::env::var("ONDC_BAP_ID") {
            config.bap.id = bap_id;
        }
        if let Ok(bap_uri) = std::env::var("ONDC_BAP_URI") {
            config.bap.uri = bap_uri;
        }
        
        // Thresholds and limits
        if let Ok(threshold) = std::env::var("ONDC_AGENT_CONFIDENCE_THRESHOLD") {
            config.confidence_threshold = threshold.parse()
                .map_err(|_| AgentError::config("Invalid confidence threshold"))?;
        }
        
        if let Ok(timeout) = std::env::var("ONDC_AGENT_TIMEOUT_SECS") {
            config.timeout_secs = timeout.parse()
                .map_err(|_| AgentError::config("Invalid timeout value"))?;
        }
        
        if let Ok(retries) = std::env::var("ONDC_AGENT_MAX_RETRIES") {
            config.max_retries = retries.parse()
                .map_err(|_| AgentError::config("Invalid max retries value"))?;
        }
        
        // Default values
        if let Ok(domain) = std::env::var("ONDC_DEFAULT_DOMAIN") {
            config.default_domain = domain;
        }
        if let Ok(country) = std::env::var("ONDC_DEFAULT_COUNTRY") {
            config.default_country = country;
        }
        if let Ok(city) = std::env::var("ONDC_DEFAULT_CITY") {
            config.default_city = city;
        }
        
        Ok(config)
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> AgentResult<()> {
        // Validate confidence threshold
        if !(0.0..=1.0).contains(&self.confidence_threshold) {
            return Err(AgentError::config("Confidence threshold must be between 0.0 and 1.0"));
        }
        
        // Validate timeout
        if self.timeout_secs == 0 || self.timeout_secs > 300 {
            return Err(AgentError::config("Timeout must be between 1 and 300 seconds"));
        }
        
        // Validate max retries
        if self.max_retries > 10 {
            return Err(AgentError::config("Max retries cannot exceed 10"));
        }
        
        // Validate BAP configuration
        if self.bap.id.is_empty() {
            return Err(AgentError::config("BAP ID cannot be empty"));
        }
        if self.bap.uri.is_empty() {
            return Err(AgentError::config("BAP URI cannot be empty"));
        }
        
        // Validate URL format
        url::Url::parse(&self.bap.uri)
            .map_err(|_| AgentError::config("Invalid BAP URI format"))?;
        
        // Validate domain format (should be nic2004:XXXXX format)
        if !self.default_domain.starts_with("nic2004:") {
            return Err(AgentError::config("Domain should be in nic2004:XXXXX format"));
        }
        
        // Validate provider configuration
        self.provider.validate()?;
        
        // Validate validation config
        if !(0.0..=1.0).contains(&self.validation.auto_accept_threshold) {
            return Err(AgentError::config("Auto-accept threshold must be between 0.0 and 1.0"));
        }
        
        if self.validation.max_query_length == 0 || self.validation.max_query_length > 10000 {
            return Err(AgentError::config("Max query length must be between 1 and 10000"));
        }
        
        // Validate cache config
        if self.cache.ttl_secs == 0 {
            return Err(AgentError::config("Cache TTL must be greater than 0"));
        }
        
        if self.cache.max_entries == 0 {
            return Err(AgentError::config("Cache max entries must be greater than 0"));
        }
        
        // Validate observability config
        if !(0.0..=1.0).contains(&self.observability.trace_sample_rate) {
            return Err(AgentError::config("Trace sample rate must be between 0.0 and 1.0"));
        }
        
        Ok(())
    }
    
    /// Get the request timeout as a Duration
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
    
    /// Check if the configuration is for production use
    pub fn is_production(&self) -> bool {
        self.confidence_threshold >= 0.8 &&
        self.validation.strict_beckn_validation &&
        self.validation.sanitize_inputs &&
        !self.bap.id.contains("test") &&
        !self.bap.uri.contains("localhost")
    }
    
    /// Create a minimal configuration for testing
    pub fn for_testing() -> Self {
        Self {
            provider: ProviderConfig::Mock,
            bap: BapConfig {
                id: "test.bap.com".to_string(),
                uri: "https://test.bap.com".to_string(),
                ..Default::default()
            },
            validation: ValidationConfig {
                strict_beckn_validation: false,
                ..Default::default()
            },
            observability: ObservabilityConfig {
                metrics_enabled: false,
                tracing_enabled: false,
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = AgentConfig::default();
        assert_eq!(config.default_country, "IND");
        assert_eq!(config.confidence_threshold, DEFAULT_CONFIDENCE_THRESHOLD);
        assert!(config.validation.strict_beckn_validation);
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = AgentConfig::for_testing();
        assert!(config.validate().is_ok());
        
        // Test invalid confidence threshold
        config.confidence_threshold = 1.5;
        assert!(config.validate().is_err());
        
        // Reset and test invalid timeout
        config.confidence_threshold = 0.8;
        config.timeout_secs = 0;
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_production_detection() {
        let mut config = AgentConfig::default();
        config.bap.id = "prod.bap.com".to_string();
        config.bap.uri = "https://prod.bap.com".to_string();
        config.confidence_threshold = 0.9;
        assert!(config.is_production());
        
        config.bap.id = "test.bap.com".to_string();
        assert!(!config.is_production());
    }
    
    #[test]
    fn test_timeout_conversion() {
        let config = AgentConfig::default();
        let duration = config.timeout();
        assert_eq!(duration, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
    }
}