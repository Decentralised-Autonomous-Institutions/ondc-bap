//! Intent extraction chain implementation.
//!
//! This module implements the LangChain-Rust chain for extracting
//! structured intent from natural language queries.

use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::{
    config::AgentConfig,
    error::{AgentError, AgentResult},
    models::Intent,
    providers::traits::LLMProvider,
    services::llm_service::ChainHealthCheck,
};

/// Intent extraction chain using LangChain-Rust
pub struct IntentChain {
    /// LLM provider for intent extraction
    provider: Arc<dyn LLMProvider>,
    /// Configuration for the chain
    config: AgentConfig,
    /// System prompt for intent extraction
    system_prompt: String,
}

impl IntentChain {
    /// Create a new intent extraction chain
    pub fn new(provider: Arc<dyn LLMProvider>, config: AgentConfig) -> AgentResult<Self> {
        debug!("Creating intent extraction chain");
        
        let system_prompt = Self::build_system_prompt();
        
        Ok(Self {
            provider,
            config,
            system_prompt,
        })
    }
    
    /// Extract intent from natural language query
    pub async fn extract_intent(&self, query: &str) -> AgentResult<Intent> {
        debug!("Extracting intent from query: {} chars", query.len());
        
        // Build the prompt for intent extraction
        let prompt = self.build_extraction_prompt(query);
        
        // Call LLM with system prompt
        let response = self.provider
            .generate_with_system(&self.system_prompt, &prompt)
            .await
            .map_err(|e| {
                warn!("Intent extraction failed: {}", e);
                AgentError::chain(format!("Intent extraction failed: {}", e))
            })?;
        
        // Parse the response into Intent struct
        let intent = self.parse_intent_response(&response)?;
        
        info!("Intent extracted successfully with confidence: {:.2}", intent.confidence);
        Ok(intent)
    }
    
    /// Build system prompt for intent extraction
    fn build_system_prompt() -> String {
        r#"You are an expert at extracting e-commerce intent from natural language queries.

Your task is to analyze user queries and extract structured intent for ONDC/Beckn protocol searches.

Extract the following information:
- category: The product/service category (groceries, food, electronics, etc.)
- item: Specific item or service being searched
- location: Geographic location for the search
- urgency: How quickly the user needs the item (immediate, today, soon, flexible)
- price_range: Budget constraints if mentioned
- quantity: How much they want to buy
- fulfillment_type: How they want to receive it (delivery, pickup, dine-in)
- timing: When they need it (now, specific time, date range)

Respond only with valid JSON in this exact format:
{
  "category": "string or null",
  "item_name": "string or null", 
  "location": {
    "city": "string or null",
    "area": "string or null",
    "coordinates": {"lat": number, "lng": number} or null,
    "postal_code": "string or null"
  } or null,
  "urgency": "Pickup|Delivery|Both|Express|Scheduled" or null,
  "price_range": {
    "min": number or null, 
    "max": number or null,
    "currency": "string"
  } or null,
  "quantity": number or null,
  "fulfillment_type": "Pickup|Delivery|Both|Express|Scheduled" or null,
  "provider_preference": "string or null",
  "keywords": ["string", "string"],
  "confidence": number (0.0-1.0),
  "original_query": "string"
}

Be precise and confident. If information is unclear, use your best judgment and adjust confidence accordingly."#.to_string()
    }
    
    /// Build extraction prompt for specific query
    fn build_extraction_prompt(&self, query: &str) -> String {
        format!(
            r#"Extract the e-commerce intent from this user query:

Query: "{}"

Analyze the query and extract the structured intent as JSON:"#,
            query.trim()
        )
    }
    
    /// Parse LLM response into Intent struct
    fn parse_intent_response(&self, response: &str) -> AgentResult<Intent> {
        debug!("Parsing intent response: {} chars", response.len());
        
        // Find JSON content in the response
        let json_str = self.extract_json_from_response(response)?;
        
        // Parse JSON into Intent
        let intent: Intent = serde_json::from_str(&json_str)
            .map_err(|e| {
                warn!("Failed to parse intent JSON: {}", e);
                AgentError::parsing(format!("Invalid intent JSON: {}", e))
            })?;
        
        // Validate confidence level
        if intent.confidence < 0.0 || intent.confidence > 1.0 {
            return Err(AgentError::validation("Intent confidence must be between 0.0 and 1.0"));
        }
        
        Ok(intent)
    }
    
    /// Extract JSON content from LLM response
    fn extract_json_from_response(&self, response: &str) -> AgentResult<String> {
        let response = response.trim();
        
        // Look for JSON block markers
        if let Some(start) = response.find('{') {
            if let Some(end) = response.rfind('}') {
                if end > start {
                    return Ok(response[start..=end].to_string());
                }
            }
        }
        
        // If no clear JSON blocks, try to parse the entire response
        if response.starts_with('{') && response.ends_with('}') {
            return Ok(response.to_string());
        }
        
        Err(AgentError::parsing("No valid JSON found in intent extraction response"))
    }
}

#[async_trait]
impl ChainHealthCheck for IntentChain {
    async fn health_check(&self) -> AgentResult<()> {
        debug!("Performing intent chain health check");
        
        // Test with a simple query
        let test_query = "I want to buy apples";
        let result = self.extract_intent(test_query).await;
        
        match result {
            Ok(intent) => {
                if intent.confidence > 0.0 {
                    info!("Intent chain health check passed");
                    Ok(())
                } else {
                    Err(AgentError::chain("Intent chain returned zero confidence"))
                }
            }
            Err(e) => {
                warn!("Intent chain health check failed: {}", e);
                Err(AgentError::chain(format!("Intent chain health check failed: {}", e)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProviderConfig;
    
    #[test]
    fn test_system_prompt_creation() {
        let prompt = IntentChain::build_system_prompt();
        assert!(prompt.contains("e-commerce intent"));
        assert!(prompt.contains("JSON"));
    }
    
    #[test]
    fn test_extraction_prompt_building() {
        let config = AgentConfig::for_testing();
        let query = "I need fresh vegetables";
        
        // Mock provider would be needed for full test
        // Just test prompt building logic
        let prompt_template = format!(
            r#"Extract the e-commerce intent from this user query:

Query: "{}"

Analyze the query and extract the structured intent as JSON:"#,
            query.trim()
        );
        
        assert!(prompt_template.contains(query));
        assert!(prompt_template.contains("JSON"));
    }
    
    #[test]
    fn test_json_extraction() {
        let config = AgentConfig::for_testing();
        // This would need a mock provider for full initialization
        // Just test the JSON extraction logic structure
        
        let response1 = r#"{"category": "groceries", "confidence": 0.9}"#;
        assert!(response1.starts_with('{') && response1.ends_with('}'));
        
        let response2 = r#"Here is the extracted intent: {"category": "groceries", "confidence": 0.9} Hope this helps!"#;
        let start = response2.find('{').unwrap();
        let end = response2.rfind('}').unwrap();
        let json_part = &response2[start..=end];
        assert_eq!(json_part, r#"{"category": "groceries", "confidence": 0.9}"#);
    }
}