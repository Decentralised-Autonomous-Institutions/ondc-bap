//! Environment configuration loading utilities

use crate::config::{ondc_config::{BusinessEntityConfig, GstConfig, PanConfig}, BAPConfig, ConfigError};

/// Load configuration from environment
pub fn load_config() -> Result<BAPConfig, ConfigError> {
    BAPConfig::load()
}

/// Load configuration for specific environment
pub fn load_config_for_environment(env: &str) -> Result<BAPConfig, ConfigError> {
    std::env::set_var("ONDC_ENV", env);
    BAPConfig::load()
}

/// Create test configuration for development
pub fn create_test_config() -> BAPConfig {
    use crate::config::{
        app_config::KeyConfig, app_config::SecurityConfig, app_config::ServerConfig,
        ondc_config::Environment, ondc_config::ONDCConfig,
    };

    BAPConfig {
        server: ServerConfig {
            host: "0.0.0.0".to_string(),
            port: 8080,
            tls: None,
            request_timeout_secs: 30,
            max_connections: 1000,
        },
        ondc: ONDCConfig {
            environment: Environment::Staging,
            registry_base_url: "https://staging.registry.ondc.org".to_string(),
            subscriber_id: "test.example.com".to_string(),
            callback_url: "/".to_string(),
            request_timeout_secs: 30,
            max_retries: 3,
            network_participants: None,
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
        },
        keys: KeyConfig {
            signing_private_key: generate_test_signing_key(),
            encryption_private_key: generate_test_encryption_key(),
            unique_key_id: "test_key_1".to_string(),
        },
        security: SecurityConfig {
            enable_rate_limiting: true,
            max_requests_per_minute: 100,
            enable_cors: true,
            allowed_origins: vec!["*".to_string()],
        },
    }
}

/// Generate test signing key for development
fn generate_test_signing_key() -> String {
    // Generate a test Ed25519 key pair
    use ondc_crypto_algorithms::Ed25519Signer;
    use ondc_crypto_formats::encode_signature;

    let signer = Ed25519Signer::generate().expect("Failed to generate test signer");
    let private_key = signer.private_key();
    encode_signature(private_key)
}

/// Generate test encryption key for development
fn generate_test_encryption_key() -> String {
    // Generate a test X25519 key pair
    use ondc_crypto_algorithms::X25519KeyExchange;
    use ondc_crypto_formats::encode_signature;

    let key_exchange = X25519KeyExchange::generate().expect("Failed to generate test key exchange");
    let private_key = key_exchange.private_key();
    encode_signature(private_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_test_config() {
        let config = create_test_config();
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.ondc.subscriber_id, "test.example.com");
    }

    #[test]
    fn test_generate_test_keys() {
        let signing_key = generate_test_signing_key();
        let encryption_key = generate_test_encryption_key();

        assert!(!signing_key.is_empty());
        assert!(!encryption_key.is_empty());

        // Verify they can be decoded
        use ondc_crypto_formats::decode_signature;
        assert!(decode_signature(&signing_key).is_ok());
        assert!(decode_signature(&encryption_key).is_ok());
    }
}
