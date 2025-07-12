//! ONDC-specific configuration

use serde::{Deserialize, Serialize};
use ondc_crypto_formats::decode_signature;
use crate::config::ConfigError;

/// ONDC environment types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum Environment {
    #[serde(rename = "staging")]
    Staging,
    #[serde(rename = "preprod")]
    PreProd,
    #[serde(rename = "production")]
    Production,
}

impl Environment {
    /// Get the registry base URL for this environment
    pub fn registry_url(&self) -> &'static str {
        match self {
            Environment::Staging => "https://staging.registry.ondc.org",
            Environment::PreProd => "https://preprod.registry.ondc.org",
            Environment::Production => "https://prod.registry.ondc.org",
        }
    }

    /// Get the ONDC public key for this environment
    pub fn ondc_public_key(&self) -> &'static str {
        match self {
            Environment::Staging => "MCowBQYDK2VuAyEAduMuZgmtpjdCuxv+Nc49K0cB6tL/Dj3HZetvVN7ZekM=",
            Environment::PreProd => "MCowBQYDK2VuAyEAa9Wbpvd9SsrpOZFcynyt/TO3x0Yrqyys4NUGIvyxX2Q=",
            Environment::Production => {
                "MCowBQYDK2VuAyEAvVEyZY91O2yV8w8/CAwVDAnqIZDJJUPdLUUKwLo3K0M="
            }
        }
    }
}

impl Default for Environment {
    fn default() -> Self {
        Environment::Staging
    }
}

impl std::str::FromStr for Environment {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "staging" => Ok(Environment::Staging),
            "preprod" => Ok(Environment::PreProd),
            "production" => Ok(Environment::Production),
            _ => Err(format!("Unknown environment: {}", s)),
        }
    }
}

/// GST configuration for business entity
#[derive(Debug, Clone, Deserialize)]
pub struct GstConfig {
    pub legal_entity_name: String,
    pub business_address: String,
    pub city_code: Vec<String>,
    pub gst_no: Option<String>,
}

/// PAN configuration for business entity
#[derive(Debug, Clone, Deserialize)]
pub struct PanConfig {
    pub name_as_per_pan: String,
    pub pan_no: String,
    pub date_of_incorporation: String,
}

/// Business entity configuration
#[derive(Debug, Clone, Deserialize)]
pub struct BusinessEntityConfig {
    pub gst: GstConfig,
    pub pan: PanConfig,
    pub name_of_authorised_signatory: String,
    pub address_of_authorised_signatory: String,
    pub email_id: String,
    pub mobile_no: u64,
    pub country: String,
}

/// Network participant configuration
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkParticipantConfig {
    pub subscriber_url: String,
    pub domain: String,
    pub participant_type: ParticipantType,
    pub msn: bool,
    pub city_code: Vec<String>,
}

/// Participant type enumeration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum ParticipantType {
    #[serde(rename = "buyerApp")]
    BuyerApp,
    #[serde(rename = "sellerApp")]
    SellerApp,
    #[serde(rename = "gateway")]
    Gateway,
}

/// ONDC configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ONDCConfig {
    pub environment: Environment,
    pub registry_base_url: String,
    pub subscriber_id: String,
    pub callback_url: String,
    pub request_timeout_secs: u64,
    pub max_retries: usize,
    pub business_entity: BusinessEntityConfig,
    pub network_participants: Option<Vec<NetworkParticipantConfig>>,
}

impl ONDCConfig {
    /// Create ONDC config with default values for environment
    pub fn new(environment: Environment, subscriber_id: String) -> Self {
        Self {
            environment,
            registry_base_url: environment.registry_url().to_string(),
            subscriber_id,
            callback_url: "/".to_string(),
            request_timeout_secs: 30,
            max_retries: 3,
            business_entity: BusinessEntityConfig {
                gst: GstConfig {
                    legal_entity_name: "Default Entity".to_string(),
                    business_address: "Default Address".to_string(),
                    city_code: vec!["std:080".to_string()],
                    gst_no: None,
                },
                pan: PanConfig {
                    name_as_per_pan: "Default Entity".to_string(),
                    pan_no: "AAAAA0000A".to_string(),
                    date_of_incorporation: "01/01/2020".to_string(),
                },
                name_of_authorised_signatory: "Default Signatory".to_string(),
                address_of_authorised_signatory: "Default Address".to_string(),
                email_id: "default@example.com".to_string(),
                mobile_no: 9999999999,
                country: "IND".to_string(),
            },
            network_participants: None,
        }
    }

    /// Get the ONDC public key for this environment
    pub fn ondc_public_key(&self) -> &'static str {
        self.environment.ondc_public_key()
    }

    /// Get the decoded ONDC public key as raw bytes
    pub fn ondc_public_key_bytes(&self) -> Result<[u8; 32], ConfigError> {
        let public_key_b64 = self.ondc_public_key();
        let decoded = decode_signature(public_key_b64)
            .map_err(|e| ConfigError::InvalidONDCKey(format!("Failed to decode ONDC public key: {}", e)))?;
        
        // Extract raw key from DER format (last 32 bytes)
        if decoded.len() < 32 {
            return Err(ConfigError::InvalidONDCKey("ONDC public key too short".to_string()));
        }
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded[decoded.len() - 32..]);
        Ok(key)
    }
}

impl Default for ONDCConfig {
    fn default() -> Self {
        Self {
            environment: Environment::Staging,
            registry_base_url: Environment::Staging.registry_url().to_string(),
            subscriber_id: "example.com".to_string(),
            callback_url: "/".to_string(),
            request_timeout_secs: 30,
            max_retries: 3,
            business_entity: BusinessEntityConfig {
                gst: GstConfig {
                    legal_entity_name: "Example Entity".to_string(),
                    business_address: "Example Address".to_string(),
                    city_code: vec!["std:080".to_string()],
                    gst_no: None,
                },
                pan: PanConfig {
                    name_as_per_pan: "Example Entity".to_string(),
                    pan_no: "AAAAA0000A".to_string(),
                    date_of_incorporation: "01/01/2020".to_string(),
                },
                name_of_authorised_signatory: "Example Signatory".to_string(),
                address_of_authorised_signatory: "Example Address".to_string(),
                email_id: "example@example.com".to_string(),
                mobile_no: 9999999999,
                country: "IND".to_string(),
            },
            network_participants: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_parsing() {
        assert_eq!(
            "staging".parse::<Environment>().unwrap(),
            Environment::Staging
        );
        assert_eq!(
            "preprod".parse::<Environment>().unwrap(),
            Environment::PreProd
        );
        assert_eq!(
            "production".parse::<Environment>().unwrap(),
            Environment::Production
        );
        assert!("invalid".parse::<Environment>().is_err());
    }

    #[test]
    fn test_environment_urls() {
        assert_eq!(
            Environment::Staging.registry_url(),
            "https://staging.registry.ondc.org"
        );
        assert_eq!(
            Environment::PreProd.registry_url(),
            "https://preprod.registry.ondc.org"
        );
        assert_eq!(
            Environment::Production.registry_url(),
            "https://prod.registry.ondc.org"
        );
    }

    #[test]
    fn test_ondc_config_default() {
        let config = ONDCConfig::default();
        assert_eq!(config.environment, Environment::Staging);
        assert_eq!(config.subscriber_id, "example.com");
        assert_eq!(config.request_timeout_secs, 30);
        assert_eq!(config.business_entity.country, "IND");
        assert_eq!(config.network_participants.is_none(), true);
    }

    #[test]
    fn test_ondc_config_new() {
        let config = ONDCConfig::new(Environment::Production, "test.com".to_string());
        assert_eq!(config.environment, Environment::Production);
        assert_eq!(config.subscriber_id, "test.com");
        assert_eq!(
            config.registry_base_url,
            Environment::Production.registry_url()
        );
    }
}
