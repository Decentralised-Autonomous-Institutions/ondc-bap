//! Main application configuration for ONDC BAP Server

use crate::config::{ConfigError, ONDCConfig};
use figment::providers::Format;
use serde::Deserialize;

/// Main BAP server configuration
#[derive(Debug, Clone, Deserialize)]
pub struct BAPConfig {
    pub server: ServerConfig,
    pub ondc: ONDCConfig,
    pub keys: KeyConfig,
    pub security: SecurityConfig,
}

/// Server configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub tls: Option<TlsConfig>,
    pub request_timeout_secs: u64,
    pub max_connections: usize,
}

/// TLS configuration
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

/// Key configuration
#[derive(Debug, Clone, Deserialize)]
pub struct KeyConfig {
    pub signing_private_key: String,    // Base64 encoded
    pub encryption_private_key: String, // Base64 encoded
    pub unique_key_id: String,
}

/// Security configuration
#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    pub enable_rate_limiting: bool,
    pub max_requests_per_minute: usize,
    pub enable_cors: bool,
    pub allowed_origins: Vec<String>,
}

impl BAPConfig {
    /// Load configuration from environment and files
    pub fn load() -> Result<Self, ConfigError> {
        let environment = std::env::var("ONDC_ENV").unwrap_or_else(|_| "staging".to_string());

        let cwd = std::env::current_dir().unwrap();

        let config_path = format!("{}/ondc-bap/config/{}.toml", cwd.display(), environment);

        // Check if file exists
        if !std::path::Path::new(&config_path).exists() {
            return Err(ConfigError::LoadError(format!(
                "Config file not found: {}",
                config_path
            )));
        }

        let config: BAPConfig = figment::Figment::new()
            .merge(figment::providers::Toml::file(&config_path))
            .merge(figment::providers::Env::prefixed("ONDC_"))
            .extract()
            .map_err(|e| ConfigError::LoadError(e.to_string()))?;

        // Validate configuration
        config.validate()?;

        Ok(config)
    }

    /// Validate configuration consistency
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate subscriber ID
        if self.ondc.subscriber_id.is_empty() {
            return Err(ConfigError::InvalidSubscriberId(
                "Subscriber ID cannot be empty".to_string(),
            ));
        }

        // Validate key formats
        self.keys.validate()?;

        // Validate URLs
        url::Url::parse(&self.ondc.registry_base_url)
            .map_err(|_| ConfigError::InvalidRegistryUrl(self.ondc.registry_base_url.clone()))?;

        Ok(())
    }
}

impl KeyConfig {
    /// Validate key configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        use ondc_crypto_formats::decode_signature;

        // Validate signing key format and length
        let signing_key = decode_signature(&self.signing_private_key).map_err(|_| {
            ConfigError::InvalidSigningKey("Invalid signing key format".to_string())
        })?;
        if signing_key.len() != 32 {
            return Err(ConfigError::InvalidSigningKeyLength(signing_key.len()));
        }

        // Validate encryption key format and length
        let encryption_key = decode_signature(&self.encryption_private_key).map_err(|_| {
            ConfigError::InvalidEncryptionKey("Invalid encryption key format".to_string())
        })?;
        if encryption_key.len() != 32 {
            return Err(ConfigError::InvalidEncryptionKeyLength(
                encryption_key.len(),
            ));
        }

        Ok(())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            tls: None,
            request_timeout_secs: 30,
            max_connections: 1000,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_rate_limiting: true,
            max_requests_per_minute: 100,
            enable_cors: true,
            allowed_origins: vec!["*".to_string()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 8080);
        assert!(config.tls.is_none());
    }

    #[test]
    fn test_security_config_default() {
        let config = SecurityConfig::default();
        assert!(config.enable_rate_limiting);
        assert_eq!(config.max_requests_per_minute, 100);
        assert!(config.enable_cors);
    }
}
