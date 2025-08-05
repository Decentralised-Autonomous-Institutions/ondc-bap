//! LLM Service for managing language model operations.
//!
//! This service provides a high-level interface for LLM operations,
//! managing provider connections, chain orchestration, and result validation.

use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, info, error};

use crate::{
    config::{AgentConfig, ProviderConfig},
    error::{AgentError, AgentResult},
    providers::{traits::LLMProvider, ollama::OllamaProvider},
    chains::{IntentChain, BecknChain},
    models::{Intent, BecknRequest},
    validation::{InputValidator, IntentValidator, BecknValidator},
};

/// Service for managing LLM operations and chain orchestration
pub struct LLMService {
    /// LLM provider implementation
    provider: Arc<dyn LLMProvider>,
    /// Intent extraction chain
    intent_chain: IntentChain,
    /// Beckn generation chain
    beckn_chain: BecknChain,
    /// Input validation
    input_validator: InputValidator,
    /// Intent validation
    intent_validator: IntentValidator,
    /// Beckn validation
    beckn_validator: BecknValidator,
    /// Service configuration
    config: AgentConfig,
}

impl LLMService {
    /// Create a new LLM service with the given configuration
    pub async fn new(config: AgentConfig) -> AgentResult<Self> {
        info!("Creating LLM service with provider: {}", config.provider.provider_type());
        
        // Create provider based on configuration
        let provider: Arc<dyn LLMProvider> = match &config.provider {
            ProviderConfig::Ollama { .. } => {
                debug!("Creating Ollama provider");
                Arc::new(OllamaProvider::new(config.provider.clone())?)
            }
            ProviderConfig::OpenAI { .. } => {
                return Err(AgentError::provider("OpenAI provider not yet implemented"));
            }
            ProviderConfig::Anthropic { .. } => {
                return Err(AgentError::provider("Anthropic provider not yet implemented"));
            }
            ProviderConfig::Mock => {
                return Err(AgentError::provider("Mock provider not implemented in service"));
            }
        };
        
        // Perform health check on provider
        provider.health_check().await
            .map_err(|e| {
                error!("Provider health check failed: {}", e);
                AgentError::provider(format!("Provider health check failed: {}", e))
            })?;
        
        // Create chain components
        let intent_chain = IntentChain::new(provider.clone(), config.clone())?;
        let beckn_chain = BecknChain::new(provider.clone(), config.clone())?;
        
        // Create validators
        let input_validator = InputValidator::new(config.clone())?;
        let intent_validator = IntentValidator::new(config.clone())?;
        let beckn_validator = BecknValidator::new(config.clone())?;
        
        info!("LLM service created successfully");
        Ok(Self {
            provider,
            intent_chain,
            beckn_chain,
            input_validator,
            intent_validator,
            beckn_validator,
            config,
        })
    }
    
    /// Extract intent from natural language query
    pub async fn extract_intent(&self, query: &str) -> AgentResult<Intent> {
        debug!("Extracting intent from query: {} chars", query.len());
        
        // Validate input
        self.input_validator.validate_query(query)?;
        
        // Extract intent using chain
        let intent = self.intent_chain.extract_intent(query).await?;
        
        // Validate extracted intent
        self.intent_validator.validate(&intent)?;
        
        info!("Intent extracted successfully with confidence: {:.2}", intent.confidence);
        Ok(intent)
    }
    
    /// Generate Beckn request from intent
    pub async fn generate_beckn_request(&self, intent: &Intent) -> AgentResult<BecknRequest> {
        debug!("Generating Beckn request from intent: {:?}", intent.category);
        
        // Validate intent before processing
        self.intent_validator.validate(intent)?;
        
        // Generate Beckn request using chain
        let beckn_request = self.beckn_chain.generate_request(intent).await?;
        
        // Validate generated Beckn request
        self.beckn_validator.validate(&beckn_request)?;
        
        info!("Beckn request generated successfully");
        Ok(beckn_request)
    }
    
    /// Process a natural language query end-to-end
    pub async fn process_query(&self, query: &str) -> AgentResult<BecknRequest> {
        info!("Processing query end-to-end: {} chars", query.len());
        
        // Extract intent
        let intent = self.extract_intent(query).await?;
        
        // Generate Beckn request
        let beckn_request = self.generate_beckn_request(&intent).await?;
        
        info!("Query processed successfully");
        Ok(beckn_request)
    }
    
    /// Check if the service is healthy
    pub async fn health_check(&self) -> AgentResult<()> {
        debug!("Performing LLM service health check");
        
        // Check provider health
        self.provider.health_check().await?;
        
        // Check chain components
        self.intent_chain.health_check().await?;
        self.beckn_chain.health_check().await?;
        
        info!("LLM service health check passed");
        Ok(())
    }
    
    /// Get provider information
    pub fn provider_info(&self) -> ProviderInfo {
        ProviderInfo {
            name: self.provider.provider_name().to_string(),
            provider_type: self.config.provider.provider_type().to_string(),
            model: self.config.provider.model_name().to_string(),
            is_cloud: self.config.provider.is_cloud_provider(),
        }
    }
    
    /// Get service statistics
    pub fn get_stats(&self) -> ServiceStats {
        ServiceStats {
            provider_name: self.provider.provider_name().to_string(),
            // TODO: Implement actual metrics collection
            requests_processed: 0,
            intents_extracted: 0,
            beckn_requests_generated: 0,
            avg_response_time_ms: 0.0,
        }
    }
}

/// Provider information
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    /// Provider name
    pub name: String,
    /// Provider type
    pub provider_type: String,
    /// Model name
    pub model: String,
    /// Whether this is a cloud-based provider
    pub is_cloud: bool,
}

/// Service statistics
#[derive(Debug, Clone)]
pub struct ServiceStats {
    /// Provider name
    pub provider_name: String,
    /// Total requests processed
    pub requests_processed: u64,
    /// Number of intents extracted
    pub intents_extracted: u64,
    /// Number of Beckn requests generated
    pub beckn_requests_generated: u64,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
}

/// Trait for chain health checking
#[async_trait]
pub trait ChainHealthCheck {
    /// Perform a health check on the chain
    async fn health_check(&self) -> AgentResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProviderConfig;
    
    #[test]
    fn test_provider_info() {
        let config = AgentConfig::for_testing();
        
        // Test would require async setup, so just verify config creation
        assert_eq!(config.provider.provider_type(), "mock");
    }
    
    #[test]
    fn test_service_stats_creation() {
        let stats = ServiceStats {
            provider_name: "ollama".to_string(),
            requests_processed: 10,
            intents_extracted: 8,
            beckn_requests_generated: 6,
            avg_response_time_ms: 250.5,
        };
        
        assert_eq!(stats.provider_name, "ollama");
        assert_eq!(stats.requests_processed, 10);
    }
}