//! Beckn protocol models for ONDC integration.
//!
//! This module defines the data structures that represent Beckn protocol
//! requests and responses, specifically for search operations.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::models::intent::IntentSummary;

/// Complete Beckn search request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknSearchRequest {
    /// Beckn protocol context
    pub context: BecknContext,
    
    /// Message containing the search intent
    pub message: BecknMessage,
    
    /// Summary of the original intent (for debugging/tracking)
    #[serde(skip_serializing)]
    pub intent_summary: IntentSummary,
    
    /// Confidence score of the generated request
    #[serde(skip_serializing)]
    pub confidence: f32,
}

/// Beckn protocol context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknContext {
    /// Domain of the transaction (e.g., "nic2004:52110" for retail)
    pub domain: String,
    
    /// Country code
    pub country: String,
    
    /// City name or code
    pub city: String,
    
    /// Action being performed
    pub action: String,
    
    /// Core version of the Beckn protocol
    pub core_version: String,
    
    /// BAP ID (Beckn Application Platform identifier)
    pub bap_id: String,
    
    /// BAP URI (callback URL)
    pub bap_uri: String,
    
    /// Unique transaction ID
    pub transaction_id: String,
    
    /// Unique message ID
    pub message_id: String,
    
    /// Timestamp in ISO 8601 format
    pub timestamp: DateTime<Utc>,
    
    /// Time-to-live for the message
    pub ttl: String,
}

/// Beckn message containing search intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknMessage {
    /// Search intent details
    pub intent: BecknIntent,
}

/// Beckn search intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknIntent {
    /// Item being searched for
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item: Option<BecknItem>,
    
    /// Category information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<BecknCategory>,
    
    /// Fulfillment requirements
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfillment: Option<BecknFulfillment>,
    
    /// Location constraints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<BecknLocation>,
    
    /// Provider constraints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<BecknProvider>,
    
    /// Payment preferences
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment: Option<BecknPayment>,
    
    /// Tags for additional metadata
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<BecknTag>,
}

/// Beckn item specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknItem {
    /// Item descriptor
    pub descriptor: BecknDescriptor,
    
    /// Price constraints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price: Option<BecknPrice>,
    
    /// Quantity requirements
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<BecknQuantity>,
}

/// Beckn category specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknCategory {
    /// Category ID (e.g., ONDC category code)
    pub id: String,
    
    /// Category descriptor
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<BecknDescriptor>,
}

/// Beckn fulfillment requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknFulfillment {
    /// Fulfillment type
    #[serde(rename = "type")]
    pub fulfillment_type: String,
    
    /// Start location (pickup point)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<BecknFulfillmentPoint>,
    
    /// End location (delivery point)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<BecknFulfillmentPoint>,
}

/// Beckn fulfillment point (pickup/delivery location)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknFulfillmentPoint {
    /// Location information
    pub location: BecknLocation,
    
    /// Time constraints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<BecknTime>,
}

/// Beckn location specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknLocation {
    /// GPS coordinates
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gps: Option<String>,
    
    /// Area code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub area_code: Option<String>,
    
    /// City information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<BecknCity>,
    
    /// Address details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<BecknAddress>,
}

/// Beckn city information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknCity {
    /// City name
    pub name: String,
    
    /// City code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// Beckn address information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknAddress {
    /// Full address string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full: Option<String>,
    
    /// Building/door number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub door: Option<String>,
    
    /// Street name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street: Option<String>,
    
    /// Locality/area
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    
    /// City
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    
    /// State
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    
    /// Country
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    
    /// Area/postal code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub area_code: Option<String>,
}

/// Beckn provider specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknProvider {
    /// Provider ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    
    /// Provider descriptor
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<BecknDescriptor>,
    
    /// Provider location
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<BecknLocation>,
}

/// Beckn payment preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknPayment {
    /// Payment type
    #[serde(rename = "type")]
    pub payment_type: String,
    
    /// Payment methods accepted
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
}

/// Beckn descriptor for items, categories, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknDescriptor {
    /// Name/title
    pub name: String,
    
    /// Short description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_desc: Option<String>,
    
    /// Long description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub long_desc: Option<String>,
    
    /// Images
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub images: Vec<BecknImage>,
}

/// Beckn image specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknImage {
    /// Image URL
    pub url: String,
    
    /// Image size category
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_type: Option<String>,
}

/// Beckn price specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknPrice {
    /// Currency code
    pub currency: String,
    
    /// Price value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    
    /// Minimum price
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_value: Option<String>,
    
    /// Maximum price
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_value: Option<String>,
}

/// Beckn quantity specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknQuantity {
    /// Quantity count
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    
    /// Measurement unit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measure: Option<BecknMeasure>,
}

/// Beckn measurement unit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknMeasure {
    /// Unit type (e.g., "kilogram", "litre")
    pub unit: String,
    
    /// Value
    pub value: f64,
}

/// Beckn time specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknTime {
    /// Time label
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    
    /// Timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,
    
    /// Duration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
    
    /// Time range
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<BecknTimeRange>,
}

/// Beckn time range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknTimeRange {
    /// Start time
    pub start: DateTime<Utc>,
    
    /// End time
    pub end: DateTime<Utc>,
}

/// Beckn tag for metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BecknTag {
    /// Tag key/code
    pub code: String,
    
    /// Tag name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    
    /// Tag value
    pub value: String,
}

impl Default for BecknContext {
    fn default() -> Self {
        Self {
            domain: "nic2004:52110".to_string(), // Default to retail
            country: "IND".to_string(),
            city: "Bangalore".to_string(),
            action: "search".to_string(),
            core_version: "1.0.0".to_string(),
            bap_id: "".to_string(),
            bap_uri: "".to_string(),
            transaction_id: Uuid::new_v4().to_string(),
            message_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            ttl: "PT30S".to_string(), // 30 seconds TTL
        }
    }
}

impl BecknSearchRequest {
    /// Create a new Beckn search request
    pub fn new(intent_summary: IntentSummary, confidence: f32) -> Self {
        Self {
            context: BecknContext::default(),
            message: BecknMessage {
                intent: BecknIntent::default(),
            },
            intent_summary,
            confidence,
        }
    }
    
    /// Set the BAP configuration
    pub fn with_bap_config(mut self, bap_id: String, bap_uri: String) -> Self {
        self.context.bap_id = bap_id;
        self.context.bap_uri = bap_uri;
        self
    }
    
    /// Set the city
    pub fn with_city(mut self, city: String) -> Self {
        self.context.city = city;
        self
    }
    
    /// Set the domain
    pub fn with_domain(mut self, domain: String) -> Self {
        self.context.domain = domain;
        self
    }
    
    /// Add a tag to the intent
    pub fn with_tag(mut self, code: String, value: String) -> Self {
        self.message.intent.tags.push(BecknTag {
            code,
            name: None,
            value,
        });
        self
    }
    
    /// Validate the Beckn request structure
    pub fn is_valid(&self) -> bool {
        !self.context.bap_id.is_empty() &&
        !self.context.bap_uri.is_empty() &&
        (self.message.intent.item.is_some() || 
         self.message.intent.category.is_some() ||
         !self.message.intent.tags.is_empty())
    }
}

impl Default for BecknIntent {
    fn default() -> Self {
        Self {
            item: None,
            category: None,
            fulfillment: None,
            location: None,
            provider: None,
            payment: None,
            tags: Vec::new(),
        }
    }
}

impl BecknDescriptor {
    /// Create a new descriptor with just a name
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            short_desc: None,
            long_desc: None,
            images: Vec::new(),
        }
    }
    
    /// Add a description
    pub fn with_description(mut self, desc: String) -> Self {
        self.short_desc = Some(desc);
        self
    }
}

impl BecknLocation {
    /// Create a location with GPS coordinates
    pub fn new_gps(lat: f64, lng: f64) -> Self {
        Self {
            gps: Some(format!("{}, {}", lat, lng)),
            area_code: None,
            city: None,
            address: None,
        }
    }
    
    /// Create a location with city name
    pub fn new_city(city_name: &str) -> Self {
        Self {
            gps: None,
            area_code: None,
            city: Some(BecknCity {
                name: city_name.to_string(),
                code: None,
            }),
            address: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::intent::IntentSummary;
    
    #[test]
    fn test_beckn_request_creation() {
        let intent_summary = IntentSummary {
            category: Some("Food".to_string()),
            items: vec!["vegetables".to_string()],
            location: Some("Bangalore".to_string()),
            price_summary: None,
            fulfillment_summary: None,
            confidence: 0.8,
            entity_count: 3,
        };
        
        let request = BecknSearchRequest::new(intent_summary, 0.8)
            .with_bap_config("test.bap.com".to_string(), "https://test.bap.com".to_string())
            .with_city("Bangalore".to_string());
        
        assert_eq!(request.context.bap_id, "test.bap.com");
        assert_eq!(request.context.city, "Bangalore");
        assert_eq!(request.confidence, 0.8);
    }
    
    #[test]
    fn test_beckn_request_validation() {
        let intent_summary = IntentSummary {
            category: Some("Food".to_string()),
            items: vec!["vegetables".to_string()],
            location: Some("Bangalore".to_string()),
            price_summary: None,
            fulfillment_summary: None,
            confidence: 0.8,
            entity_count: 3,
        };
        
        let mut request = BecknSearchRequest::new(intent_summary, 0.8);
        assert!(!request.is_valid()); // Missing BAP config
        
        request = request.with_bap_config("test.bap.com".to_string(), "https://test.bap.com".to_string());
        request.message.intent.category = Some(BecknCategory {
            id: "food".to_string(),
            descriptor: Some(BecknDescriptor::new("Food")),
        });
        assert!(request.is_valid());
    }
    
    #[test]
    fn test_location_creation() {
        let gps_location = BecknLocation::new_gps(12.9716, 77.5946);
        assert!(gps_location.gps.is_some());
        assert_eq!(gps_location.gps.unwrap(), "12.9716, 77.5946");
        
        let city_location = BecknLocation::new_city("Mumbai");
        assert!(city_location.city.is_some());
        assert_eq!(city_location.city.unwrap().name, "Mumbai");
    }
}