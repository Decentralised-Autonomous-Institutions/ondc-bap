//! Intent models for extracted user queries.
//!
//! This module defines the data structures that represent user intent
//! extracted from natural language queries.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Represents extracted intent from a natural language query
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Intent {
    /// Category of items the user is looking for
    pub category: Option<String>,
    
    /// Specific item name or description
    pub item_name: Option<String>,
    
    /// Location preference (city, area, coordinates)
    pub location: Option<LocationInfo>,
    
    /// Price range constraints
    pub price_range: Option<PriceRange>,
    
    /// Fulfillment type preference
    pub fulfillment_type: Option<FulfillmentType>,
    
    /// Preferred provider or brand
    pub provider_preference: Option<String>,
    
    /// Urgency of the request
    pub urgency: Option<Urgency>,
    
    /// Quantity needed
    pub quantity: Option<u32>,
    
    /// Additional search terms or keywords
    pub keywords: Vec<String>,
    
    /// Confidence score of the extraction (0.0 to 1.0)
    pub confidence: f32,
    
    /// Original query text
    pub original_query: String,
}

/// Location information extracted from the query
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocationInfo {
    /// City name
    pub city: Option<String>,
    
    /// Area or locality
    pub area: Option<String>,
    
    /// GPS coordinates if available
    pub coordinates: Option<Coordinates>,
    
    /// Postal code
    pub postal_code: Option<String>,
}

/// GPS coordinates
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Coordinates {
    /// Latitude
    pub lat: f64,
    
    /// Longitude
    pub lng: f64,
}

/// Price range constraints
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PriceRange {
    /// Minimum price
    pub min: Option<f64>,
    
    /// Maximum price
    pub max: Option<f64>,
    
    /// Currency code (e.g., "INR", "USD")
    pub currency: String,
}

/// Fulfillment type preferences
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FulfillmentType {
    /// Pickup from store/location
    Pickup,
    
    /// Home delivery
    Delivery,
    
    /// Either pickup or delivery is acceptable
    Both,
    
    /// Immediate/express delivery
    Express,
    
    /// Scheduled delivery
    Scheduled,
}

/// Urgency levels for requests
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Urgency {
    /// Immediate requirement
    Immediate,
    
    /// Within a few hours
    Soon,
    
    /// Scheduled for later
    Scheduled,
    
    /// No specific urgency
    Flexible,
}

/// Summary of extracted intent for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentSummary {
    /// Main category identified
    pub category: Option<String>,
    
    /// Key items identified
    pub items: Vec<String>,
    
    /// Location summary
    pub location: Option<String>,
    
    /// Price range summary
    pub price_summary: Option<String>,
    
    /// Fulfillment summary
    pub fulfillment_summary: Option<String>,
    
    /// Overall confidence
    pub confidence: f32,
    
    /// Number of extracted entities
    pub entity_count: u32,
}

impl Default for Intent {
    fn default() -> Self {
        Self {
            category: None,
            item_name: None,
            location: None,
            price_range: None,
            fulfillment_type: None,
            provider_preference: None,
            urgency: None,
            quantity: None,
            keywords: Vec::new(),
            confidence: 0.0,
            original_query: String::new(),
        }
    }
}

impl Default for PriceRange {
    fn default() -> Self {
        Self {
            min: None,
            max: None,
            currency: "INR".to_string(),
        }
    }
}

impl fmt::Display for FulfillmentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FulfillmentType::Pickup => write!(f, "Pickup"),
            FulfillmentType::Delivery => write!(f, "Delivery"),
            FulfillmentType::Both => write!(f, "Both"),
            FulfillmentType::Express => write!(f, "Express"),
            FulfillmentType::Scheduled => write!(f, "Scheduled"),
        }
    }
}

impl fmt::Display for Urgency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Urgency::Immediate => write!(f, "Immediate"),
            Urgency::Soon => write!(f, "Soon"),
            Urgency::Scheduled => write!(f, "Scheduled"),
            Urgency::Flexible => write!(f, "Flexible"),
        }
    }
}

impl Intent {
    /// Create a new Intent with the given query
    pub fn new(query: &str) -> Self {
        Self {
            original_query: query.to_string(),
            ..Default::default()
        }
    }
    
    /// Check if the intent has sufficient information for processing
    pub fn is_valid(&self) -> bool {
        self.confidence >= 0.5 && (
            self.category.is_some() || 
            self.item_name.is_some() || 
            !self.keywords.is_empty()
        )
    }
    
    /// Get a summary of the extracted intent
    pub fn summary(&self) -> IntentSummary {
        let mut items = Vec::new();
        if let Some(ref item) = self.item_name {
            items.push(item.clone());
        }
        items.extend(self.keywords.clone());
        
        let location = self.location.as_ref().and_then(|l| {
            l.city.as_ref().or(l.area.as_ref()).map(|s| s.clone())
        });
        
        let price_summary = self.price_range.as_ref().map(|pr| {
            match (&pr.min, &pr.max) {
                (Some(min), Some(max)) => format!("{} {} - {} {}", min, pr.currency, max, pr.currency),
                (Some(min), None) => format!("Above {} {}", min, pr.currency),
                (None, Some(max)) => format!("Below {} {}", max, pr.currency),
                (None, None) => "Price range specified".to_string(),
            }
        });
        
        let fulfillment_summary = self.fulfillment_type.as_ref().map(|f| f.to_string());
        
        let entity_count = [
            self.category.is_some() as u32,
            self.item_name.is_some() as u32,
            self.location.is_some() as u32,
            self.price_range.is_some() as u32,
            self.fulfillment_type.is_some() as u32,
            self.provider_preference.is_some() as u32,
            self.urgency.is_some() as u32,
            self.quantity.is_some() as u32,
        ].iter().sum::<u32>() + self.keywords.len() as u32;
        
        IntentSummary {
            category: self.category.clone(),
            items,
            location,
            price_summary,
            fulfillment_summary,
            confidence: self.confidence,
            entity_count,
        }
    }
    
    /// Update confidence score
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }
    
    /// Add a keyword to the intent
    pub fn with_keyword(mut self, keyword: String) -> Self {
        if !self.keywords.contains(&keyword) {
            self.keywords.push(keyword);
        }
        self
    }
}

impl IntentSummary {
    /// Create IntentSummary from Intent
    pub fn from_intent(intent: &Intent) -> Self {
        intent.summary()
    }
}

impl LocationInfo {
    /// Create a new LocationInfo with city
    pub fn new_city(city: &str) -> Self {
        Self {
            city: Some(city.to_string()),
            area: None,
            coordinates: None,
            postal_code: None,
        }
    }
    
    /// Create a new LocationInfo with coordinates
    pub fn new_coordinates(lat: f64, lng: f64) -> Self {
        Self {
            city: None,
            area: None,
            coordinates: Some(Coordinates { lat, lng }),
            postal_code: None,
        }
    }
    
    /// Get the best available location string
    pub fn to_string(&self) -> String {
        if let Some(ref city) = self.city {
            if let Some(ref area) = self.area {
                format!("{}, {}", area, city)
            } else {
                city.clone()
            }
        } else if let Some(ref area) = self.area {
            area.clone()
        } else if let Some(ref coords) = self.coordinates {
            format!("{}, {}", coords.lat, coords.lng)
        } else if let Some(ref postal) = self.postal_code {
            postal.clone()
        } else {
            "Unknown location".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_intent_creation() {
        let intent = Intent::new("Buy vegetables in Bangalore");
        assert_eq!(intent.original_query, "Buy vegetables in Bangalore");
        assert!(!intent.is_valid()); // Low confidence by default
    }
    
    #[test]
    fn test_intent_validity() {
        let mut intent = Intent::new("Buy vegetables");
        intent.confidence = 0.8;
        intent.category = Some("Food".to_string());
        assert!(intent.is_valid());
    }
    
    #[test]
    fn test_intent_summary() {
        let mut intent = Intent::new("Buy fresh vegetables in Bangalore under 500 INR");
        intent.confidence = 0.9;
        intent.category = Some("Food".to_string());
        intent.item_name = Some("fresh vegetables".to_string());
        intent.location = Some(LocationInfo::new_city("Bangalore"));
        intent.price_range = Some(PriceRange {
            min: None,
            max: Some(500.0),
            currency: "INR".to_string(),
        });
        
        let summary = intent.summary();
        assert_eq!(summary.category, Some("Food".to_string()));
        assert_eq!(summary.location, Some("Bangalore".to_string()));
        assert!(summary.price_summary.is_some());
        assert!(summary.confidence > 0.8);
    }
    
    #[test]
    fn test_location_info() {
        let location = LocationInfo::new_city("Mumbai");
        assert_eq!(location.to_string(), "Mumbai");
        
        let coords_location = LocationInfo::new_coordinates(19.0760, 72.8777);
        assert_eq!(coords_location.to_string(), "19.076, 72.8777");
    }
}