//! Core ONDC Agent implementation.
//!
//! This module contains the main ONDCAgent struct that orchestrates
//! the process of converting natural language queries into ONDC/Beckn requests.

use crate::{
    config::AgentConfig,
    error::{AgentError, AgentResult},
    models::{intent::Intent, beckn::BecknSearchRequest},
};

/// Main ONDC Agent for natural language to Beckn protocol conversion
pub struct ONDCAgent {
    config: AgentConfig,
}

impl ONDCAgent {
    /// Create a new ONDC Agent with the given configuration
    pub async fn new(config: AgentConfig) -> AgentResult<Self> {
        config.validate()?;
        
        Ok(Self { config })
    }
    
    /// Extract intent from a natural language query
    pub async fn extract_intent(&self, query: &str) -> AgentResult<Intent> {
        // TODO: Implement intent extraction using LLM chains
        let mut intent = Intent::new(query);
        intent.confidence = 0.5; // Placeholder
        Ok(intent)
    }
    
    /// Generate a Beckn search request from extracted intent
    pub async fn generate_search_request(&self, intent: Intent) -> AgentResult<BecknSearchRequest> {
        // TODO: Implement Beckn JSON generation using LLM chains
        let summary = intent.summary();
        let mut request = BecknSearchRequest::new(summary, intent.confidence);
        
        // Apply BAP configuration
        request = request.with_bap_config(
            self.config.bap.id.clone(),
            self.config.bap.uri.clone(),
        );
        
        Ok(request)
    }
    
    /// Process a complete query: extract intent and generate Beckn request
    pub async fn process_query(&self, query: &str) -> AgentResult<BecknSearchRequest> {
        let intent = self.extract_intent(query).await?;
        
        if !intent.is_valid() {
            return Err(AgentError::insufficient_confidence(
                intent.confidence,
                self.config.confidence_threshold,
            ));
        }
        
        self.generate_search_request(intent).await
    }
}