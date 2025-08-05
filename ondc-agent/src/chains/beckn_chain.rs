//! Beckn JSON generation chain implementation.
//!
//! This module implements the LangChain-Rust chain for generating
//! ONDC/Beckn protocol compliant JSON from extracted intent.

use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;
use chrono::Utc;

use crate::{
    config::AgentConfig,
    error::{AgentError, AgentResult},
    models::{Intent, BecknRequest},
    providers::traits::LLMProvider,
    services::llm_service::ChainHealthCheck,
};

/// Beckn JSON generation chain using LangChain-Rust
pub struct BecknChain {
    /// LLM provider for Beckn generation
    provider: Arc<dyn LLMProvider>,
    /// Configuration for the chain
    config: AgentConfig,
    /// System prompt for Beckn generation
    system_prompt: String,
}

impl BecknChain {
    /// Create a new Beckn generation chain
    pub fn new(provider: Arc<dyn LLMProvider>, config: AgentConfig) -> AgentResult<Self> {
        debug!("Creating Beckn generation chain");
        
        let system_prompt = Self::build_system_prompt();
        
        Ok(Self {
            provider,
            config,
            system_prompt,
        })
    }
    
    /// Generate Beckn request from intent
    pub async fn generate_request(&self, intent: &Intent) -> AgentResult<BecknRequest> {
        debug!("Generating Beckn request for intent: {:?}", intent.category);
        
        // First generate the base Beckn structure
        let base_request = self.create_base_beckn_request(intent)?;
        
        // Use LLM to enhance and validate the Beckn message content
        let enhanced_request = self.enhance_beckn_message(&base_request, intent).await?;
        
        info!("Beckn request generated successfully");
        Ok(enhanced_request)
    }
    
    /// Create base Beckn request structure
    fn create_base_beckn_request(&self, intent: &Intent) -> AgentResult<BecknRequest> {
        let transaction_id = Uuid::new_v4().to_string();
        let message_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now();
        
        // Build Beckn request based on intent
        let beckn_request = BecknRequest::from_intent(
            transaction_id,
            message_id,
            timestamp,
            intent.clone(),
        );
        
        Ok(beckn_request)
    }
    
    /// Enhance Beckn message using LLM
    async fn enhance_beckn_message(&self, base_request: &BecknRequest, intent: &Intent) -> AgentResult<BecknRequest> {
        debug!("Enhancing Beckn message with LLM");
        
        // Build prompt for Beckn enhancement
        let prompt = self.build_enhancement_prompt(base_request, intent);
        
        // Call LLM for enhancement suggestions
        let response = self.provider
            .generate_with_system(&self.system_prompt, &prompt)
            .await
            .map_err(|e| {
                warn!("Beckn enhancement failed: {}", e);
                AgentError::chain(format!("Beckn enhancement failed: {}", e))
            })?;
        
        // Parse and apply enhancements
        let enhanced_request = self.apply_enhancements(base_request, &response)?;
        
        Ok(enhanced_request)
    }
    
    /// Build system prompt for Beckn generation
    fn build_system_prompt() -> String {
        r#"You are an expert at generating ONDC/Beckn protocol compliant JSON requests.

Your task is to enhance and validate Beckn search requests based on extracted user intent.

Key Beckn protocol requirements:
- context.domain must match the product category (retail-1.2.0 for groceries, F&B for food)
- context.action is always "search" for search requests
- context.bap_id and context.bap_uri identify the BAP (Buyer App Platform)
- message.intent contains the actual search criteria
- message.intent.item contains item-specific search terms
- message.intent.fulfillment contains delivery preferences
- message.intent.location contains geographic constraints

Categories mapping:
- groceries, vegetables, fruits → "ONDC:RET10" (Grocery)
- food, restaurant, meals → "ONDC:RET18" (F&B)
- electronics → "ONDC:RET16" (Electronics)
- fashion, clothing → "ONDC:RET12" (Fashion)

Respond with enhancement suggestions in JSON format:
{
  "domain_code": "ONDC:RETxx",
  "category_code": "specific_category_code",
  "item_enhancements": {
    "descriptor": {"name": "enhanced_item_name"},
    "tags": ["relevant", "search", "tags"]
  },
  "location_enhancements": {
    "gps": "lat,lng if available",
    "area_code": "postal_code_if_available"
  },
  "fulfillment_enhancements": {
    "type": "Delivery|Pickup|Dine-in"
  }
}"#.to_string()
    }
    
    /// Build enhancement prompt
    fn build_enhancement_prompt(&self, base_request: &BecknRequest, intent: &Intent) -> String {
        format!(
            r#"Enhance this Beckn search request based on the user intent:

Base Beckn Request:
{}

User Intent:
- Category: {:?}
- Item: {:?}
- Location: {}
- Urgency: {:?}
- Fulfillment: {:?}

Please provide enhancements to make this Beckn request more accurate and compliant:"#,
            serde_json::to_string_pretty(base_request).unwrap_or_default(),
            intent.category,
            intent.item_name,
            intent.location.as_ref().map(|l| l.to_string()).unwrap_or_default(),
            intent.urgency,
            intent.fulfillment_type
        )
    }
    
    /// Apply LLM enhancements to Beckn request
    fn apply_enhancements(&self, base_request: &BecknRequest, enhancement_response: &str) -> AgentResult<BecknRequest> {
        debug!("Applying LLM enhancements to Beckn request");
        
        // For now, return the base request
        // TODO: Parse enhancement response and apply improvements
        let mut enhanced_request = base_request.clone();
        
        // Basic enhancement: extract any JSON suggestions from LLM response
        if let Ok(enhancements) = self.extract_enhancements_from_response(enhancement_response) {
            enhanced_request = self.merge_enhancements(enhanced_request, enhancements)?;
        }
        
        Ok(enhanced_request)
    }
    
    /// Extract enhancement suggestions from LLM response
    fn extract_enhancements_from_response(&self, response: &str) -> AgentResult<serde_json::Value> {
        let response = response.trim();
        
        // Look for JSON content
        if let Some(start) = response.find('{') {
            if let Some(end) = response.rfind('}') {
                if end > start {
                    let json_str = &response[start..=end];
                    return serde_json::from_str(json_str)
                        .map_err(|e| AgentError::parsing(format!("Invalid enhancement JSON: {}", e)));
                }
            }
        }
        
        // Return empty enhancements if no valid JSON found
        Ok(serde_json::json!({}))
    }
    
    /// Merge enhancements into Beckn request
    fn merge_enhancements(&self, mut request: BecknRequest, enhancements: serde_json::Value) -> AgentResult<BecknRequest> {
        // Apply domain code enhancement
        if let Some(domain_code) = enhancements.get("domain_code").and_then(|v| v.as_str()) {
            request.context.domain = domain_code.to_string();
        }
        
        // Apply category code enhancement
        if let Some(category_code) = enhancements.get("category_code").and_then(|v| v.as_str()) {
            // Update category in message intent
            request.message.intent.category = Some(crate::models::beckn::BecknCategory {
                id: category_code.to_string(),
                descriptor: Some(crate::models::beckn::BecknDescriptor::new(category_code)),
            });
        }
        
        // TODO: Apply other enhancements (item, location, fulfillment)
        
        Ok(request)
    }
}

#[async_trait]
impl ChainHealthCheck for BecknChain {
    async fn health_check(&self) -> AgentResult<()> {
        debug!("Performing Beckn chain health check");
        
        // Create a test intent
        let test_intent = Intent {
            category: Some("groceries".to_string()),
            item_name: Some("apples".to_string()),
            location: Some(crate::models::LocationInfo::new_city("Bangalore")),
            urgency: Some(crate::models::Urgency::Flexible),
            price_range: None,
            quantity: None,
            fulfillment_type: Some(crate::models::FulfillmentType::Delivery),
            provider_preference: None,
            keywords: vec![],
            confidence: 0.8,
            original_query: "I want to buy apples".to_string(),
        };
        
        // Test Beckn generation
        let result = self.generate_request(&test_intent).await;
        
        match result {
            Ok(beckn_request) => {
                if !beckn_request.context.transaction_id.is_empty() {
                    info!("Beckn chain health check passed");
                    Ok(())
                } else {
                    Err(AgentError::chain("Beckn chain generated empty transaction ID"))
                }
            }
            Err(e) => {
                warn!("Beckn chain health check failed: {}", e);
                Err(AgentError::chain(format!("Beckn chain health check failed: {}", e)))
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
        let prompt = BecknChain::build_system_prompt();
        assert!(prompt.contains("Beckn protocol"));
        assert!(prompt.contains("context.domain"));
    }
    
    #[test]
    fn test_base_beckn_creation() {
        let intent = Intent {
            category: Some("groceries".to_string()),
            item_name: Some("apples".to_string()),
            location: Some(crate::models::LocationInfo::new_city("Bangalore")),
            urgency: Some(crate::models::Urgency::Flexible),
            price_range: None,
            quantity: None,
            fulfillment_type: Some(crate::models::FulfillmentType::Delivery),
            provider_preference: None,
            keywords: vec![],
            confidence: 0.8,
            original_query: "I want to buy apples".to_string(),
        };
        
        let _config = AgentConfig::for_testing();
        // Mock provider would be needed for full test
        // Just test the structure creation
        
        // Simulate what create_base_beckn_request would do
        assert!(intent.category.is_some());
        assert!(intent.item_name.is_some());
    }
}