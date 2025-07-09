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

/// ONDC configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ONDCConfig {
    pub environment: Environment,
    pub registry_base_url: String,
    pub subscriber_id: String,
    pub callback_url: String,
    pub request_timeout_secs: u64,
    pub max_retries: usize,
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
