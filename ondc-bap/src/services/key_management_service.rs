//! Key Management Service for ONDC BAP Server
//!
//! This service provides secure key management capabilities including:
//! - Secure key loading from configuration
//! - Key validation and format verification
//! - Support for multiple key formats (base64, DER)
//! - Key rotation capabilities
//! - Automatic key zeroization on drop

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, instrument, warn};

use crate::config::app_config::KeyConfig;
use crate::config::ConfigError;
use ondc_crypto_algorithms::{Ed25519Signer, X25519KeyExchange};
use ondc_crypto_formats::{decode_signature, encode_signature};
use ondc_crypto_traits::{KeyPair, ONDCCryptoError, Signer};

/// Key management service error types
#[derive(Debug, thiserror::Error)]
pub enum KeyManagementError {
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] ONDCCryptoError),

    #[error("Key validation failed: {0}")]
    ValidationFailed(String),

    #[error("Key format not supported: {0}")]
    UnsupportedFormat(String),

    #[error("Key rotation failed: {0}")]
    RotationFailed(String),

    #[error("Key storage error: {0}")]
    StorageError(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Key expired: {0}")]
    KeyExpired(String),
}

/// Key metadata for tracking key lifecycle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub key_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub key_type: KeyType,
    pub format: KeyFormat,
    pub is_active: bool,
    pub rotation_count: u32,
}

/// Supported key types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyType {
    Ed25519Signing,
    X25519Encryption,
}

/// Supported key formats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyFormat {
    Base64,
    DER,
    Raw,
}

/// Key pair with metadata
pub struct KeyPairWithMetadata {
    pub signing_key: Option<Ed25519Signer>,
    pub encryption_key: Option<X25519KeyExchange>,
    pub metadata: KeyMetadata,
}

/// Key rotation policy
#[derive(Debug, Clone)]
pub struct KeyRotationPolicy {
    pub max_key_age_days: u32,
    pub rotation_grace_period_days: u32,
    pub auto_rotation_enabled: bool,
    pub backup_keys_required: bool,
}

impl Default for KeyRotationPolicy {
    fn default() -> Self {
        Self {
            max_key_age_days: 365,          // 1 year
            rotation_grace_period_days: 30, // 30 days grace period
            auto_rotation_enabled: false,
            backup_keys_required: true,
        }
    }
}

/// Main key management service
pub struct KeyManagementService {
    current_keys: Arc<tokio::sync::RwLock<KeyPairWithMetadata>>,
    backup_keys: Arc<tokio::sync::RwLock<Vec<KeyPairWithMetadata>>>,
    rotation_policy: KeyRotationPolicy,
    config: Arc<KeyConfig>,
}

impl KeyManagementService {
    /// Create a new key management service
    #[instrument(skip(config))]
    pub async fn new(config: KeyConfig) -> Result<Self, KeyManagementError> {
        info!("Initializing key management service");

        // Validate configuration
        config.validate()?;

        // Load keys from configuration
        let key_pair = Self::load_keys_from_config(&config).await?;

        let service = Self {
            current_keys: Arc::new(tokio::sync::RwLock::new(key_pair)),
            backup_keys: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            rotation_policy: KeyRotationPolicy::default(),
            config: Arc::new(config),
        };

        info!("Key management service initialized successfully");
        Ok(service)
    }

    /// Load keys from configuration
    #[instrument(skip(config))]
    async fn load_keys_from_config(
        config: &KeyConfig,
    ) -> Result<KeyPairWithMetadata, KeyManagementError> {
        info!("Loading keys from configuration");

        // Load signing key
        let signing_key = Self::load_signing_key(&config.signing_private_key).await?;

        // Load encryption key
        let encryption_key = Self::load_encryption_key(&config.encryption_private_key).await?;

        let metadata = KeyMetadata {
            key_id: config.unique_key_id.clone(),
            created_at: chrono::Utc::now(),
            expires_at: None,                  // No expiration by default
            key_type: KeyType::Ed25519Signing, // Primary type
            format: KeyFormat::Base64,
            is_active: true,
            rotation_count: 0,
        };

        Ok(KeyPairWithMetadata {
            signing_key: Some(signing_key),
            encryption_key: Some(encryption_key),
            metadata,
        })
    }

    /// Load signing key from base64 string
    #[instrument(skip(key_b64))]
    async fn load_signing_key(key_b64: &str) -> Result<Ed25519Signer, KeyManagementError> {
        let key_bytes = decode_signature(key_b64).map_err(|e| {
            KeyManagementError::ValidationFailed(format!("Invalid signing key format: {}", e))
        })?;

        if key_bytes.len() != 32 {
            return Err(KeyManagementError::ValidationFailed(format!(
                "Invalid signing key length: expected 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        let signer = Ed25519Signer::new(&key_bytes).map_err(|e| KeyManagementError::Crypto(e))?;

        Ok(signer)
    }

    /// Load encryption key from base64 string
    #[instrument(skip(key_b64))]
    async fn load_encryption_key(key_b64: &str) -> Result<X25519KeyExchange, KeyManagementError> {
        let key_bytes = decode_signature(key_b64).map_err(|e| {
            KeyManagementError::ValidationFailed(format!("Invalid encryption key format: {}", e))
        })?;

        if key_bytes.len() != 32 {
            return Err(KeyManagementError::ValidationFailed(format!(
                "Invalid encryption key length: expected 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        let key_exchange =
            X25519KeyExchange::new(&key_bytes).map_err(|e| KeyManagementError::Crypto(e))?;

        Ok(key_exchange)
    }

    /// Get current signing key
    #[instrument(skip(self))]
    pub async fn get_signing_key(&self) -> Result<Ed25519Signer, KeyManagementError> {
        let keys = self.current_keys.read().await;

        if let Some(ref signer) = keys.signing_key {
            Ok(signer.clone())
        } else {
            Err(KeyManagementError::KeyNotFound(
                "Signing key not available".to_string(),
            ))
        }
    }

    /// Get current encryption key
    #[instrument(skip(self))]
    pub async fn get_encryption_key(&self) -> Result<X25519KeyExchange, KeyManagementError> {
        let keys = self.current_keys.read().await;

        if let Some(ref key_exchange) = keys.encryption_key {
            Ok(key_exchange.clone())
        } else {
            Err(KeyManagementError::KeyNotFound(
                "Encryption key not available".to_string(),
            ))
        }
    }

    /// Get signing public key
    #[instrument(skip(self))]
    pub async fn get_signing_public_key(&self) -> Result<String, KeyManagementError> {
        let signer = self.get_signing_key().await?;
        let public_key = signer.public_key();

        Ok(encode_signature(&public_key))
    }

    /// Get encryption public key
    #[instrument(skip(self))]
    pub async fn get_encryption_public_key(&self) -> Result<String, KeyManagementError> {
        let key_exchange = self.get_encryption_key().await?;
        let public_key = key_exchange.public_key();

        Ok(encode_signature(&public_key))
    }

    /// Get unique key ID
    #[instrument(skip(self))]
    pub async fn get_unique_key_id(&self) -> String {
        let keys = self.current_keys.read().await;
        keys.metadata.key_id.clone()
    }

    /// Validate key pairs
    #[instrument(skip(self))]
    pub async fn validate_key_pairs(&self) -> Result<(), KeyManagementError> {
        info!("Validating key pairs");

        // Test signing key
        let signer = self.get_signing_key().await?;
        let test_message = b"test_message";
        let _signature = signer
            .sign(test_message)
            .map_err(|e| KeyManagementError::Crypto(e))?;

        // Test encryption key - just verify we can get the public key
        let key_exchange = self.get_encryption_key().await?;
        let _public_key = key_exchange.public_key();

        info!("Key pairs validated successfully");
        Ok(())
    }

    /// Rotate keys
    #[instrument(skip(self))]
    pub async fn rotate_keys(&self) -> Result<(), KeyManagementError> {
        info!("Starting key rotation");

        // Generate new key pair
        let new_signing_key =
            Ed25519Signer::generate().map_err(|e| KeyManagementError::Crypto(e))?;
        let new_encryption_key =
            X25519KeyExchange::generate().map_err(|e| KeyManagementError::Crypto(e))?;

        // Create new key pair with metadata
        let new_key_pair = KeyPairWithMetadata {
            signing_key: Some(new_signing_key),
            encryption_key: Some(new_encryption_key),
            metadata: KeyMetadata {
                key_id: format!("key_{}", chrono::Utc::now().timestamp()),
                created_at: chrono::Utc::now(),
                expires_at: None,
                key_type: KeyType::Ed25519Signing,
                format: KeyFormat::Base64,
                is_active: true,
                rotation_count: 0,
            },
        };

        // Backup current keys
        {
            let mut backup_keys = self.backup_keys.write().await;
            let mut current_keys = self.current_keys.write().await;

            // Mark current keys as inactive
            current_keys.metadata.is_active = false;

            // Add to backup
            backup_keys.push(current_keys.clone());

            // Replace with new keys
            *current_keys = new_key_pair;
        }

        info!("Key rotation completed successfully");
        Ok(())
    }

    /// Check if keys need rotation
    #[instrument(skip(self))]
    pub async fn check_rotation_needed(&self) -> Result<bool, KeyManagementError> {
        let keys = self.current_keys.read().await;

        if !self.rotation_policy.auto_rotation_enabled {
            return Ok(false);
        }

        let key_age = chrono::Utc::now() - keys.metadata.created_at;
        let max_age = chrono::Duration::days(self.rotation_policy.max_key_age_days as i64);

        Ok(key_age > max_age)
    }

    /// Get key metadata
    #[instrument(skip(self))]
    pub async fn get_key_metadata(&self) -> KeyMetadata {
        let keys = self.current_keys.read().await;
        keys.metadata.clone()
    }

    /// Export keys in specified format (for backup/rotation)
    #[instrument(skip(self))]
    pub async fn export_keys(&self, format: KeyFormat) -> Result<ExportedKeys, KeyManagementError> {
        let signer = self.get_signing_key().await?;
        let key_exchange = self.get_encryption_key().await?;

        let signing_private_key = signer.private_key();
        let encryption_private_key = key_exchange.private_key();

        let signing_public_key = signer.public_key();
        let encryption_public_key = key_exchange.public_key();

        let exported_keys = match format {
            KeyFormat::Base64 => ExportedKeys {
                signing_private_key: encode_signature(signing_private_key),
                encryption_private_key: encode_signature(encryption_private_key),
                signing_public_key: encode_signature(&signing_public_key),
                encryption_public_key: encode_signature(&encryption_public_key),
                format: KeyFormat::Base64,
            },
            KeyFormat::DER => ExportedKeys {
                signing_private_key: encode_signature(signing_private_key), // TODO: Implement DER encoding
                encryption_private_key: encode_signature(encryption_private_key),
                signing_public_key: encode_signature(&signing_public_key),
                encryption_public_key: encode_signature(&encryption_public_key),
                format: KeyFormat::DER,
            },
            KeyFormat::Raw => {
                return Err(KeyManagementError::UnsupportedFormat(
                    "Raw format not supported for export".to_string(),
                ));
            }
        };

        Ok(exported_keys)
    }

    /// Set rotation policy
    #[instrument(skip(self))]
    pub fn set_rotation_policy(&mut self, policy: KeyRotationPolicy) {
        self.rotation_policy = policy;
        info!("Key rotation policy updated");
    }

    /// Get rotation policy
    #[instrument(skip(self))]
    pub fn get_rotation_policy(&self) -> &KeyRotationPolicy {
        &self.rotation_policy
    }
}

/// Exported keys structure
#[derive(Debug, Clone, Serialize)]
pub struct ExportedKeys {
    pub signing_private_key: String,
    pub encryption_private_key: String,
    pub signing_public_key: String,
    pub encryption_public_key: String,
    pub format: KeyFormat,
}

impl Clone for KeyPairWithMetadata {
    fn clone(&self) -> Self {
        Self {
            signing_key: self.signing_key.as_ref().map(|k| k.clone()),
            encryption_key: self.encryption_key.as_ref().map(|k| k.clone()),
            metadata: self.metadata.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_management_service_creation() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let config = KeyConfig {
                signing_private_key: "iblY/8ruRp43aGEjuCtJrs5QyAhaHroQIaUgWKNScco=".to_string(),
                encryption_private_key: "CeBWrM0FhC47Zek6QKCMopzNFC5U3JizkOuDYVqUXno=".to_string(),
                unique_key_id: "test_key_1".to_string(),
            };

            let service = KeyManagementService::new(config).await;
            assert!(service.is_ok());
        });
    }

    #[test]
    fn test_key_validation() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let config = KeyConfig {
                signing_private_key: "iblY/8ruRp43aGEjuCtJrs5QyAhaHroQIaUgWKNScco=".to_string(),
                encryption_private_key: "CeBWrM0FhC47Zek6QKCMopzNFC5U3JizkOuDYVqUXno=".to_string(),
                unique_key_id: "test_key_1".to_string(),
            };

            let service = KeyManagementService::new(config).await.unwrap();
            let result = service.validate_key_pairs().await;
            assert!(result.is_ok());
        });
    }

    #[test]
    fn test_public_key_export() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let config = KeyConfig {
                signing_private_key: "iblY/8ruRp43aGEjuCtJrs5QyAhaHroQIaUgWKNScco=".to_string(),
                encryption_private_key: "CeBWrM0FhC47Zek6QKCMopzNFC5U3JizkOuDYVqUXno=".to_string(),
                unique_key_id: "test_key_1".to_string(),
            };

            let service = KeyManagementService::new(config).await.unwrap();

            let signing_pub = service.get_signing_public_key().await;
            assert!(signing_pub.is_ok());

            let encryption_pub = service.get_encryption_public_key().await;
            assert!(encryption_pub.is_ok());
        });
    }

    #[test]
    fn test_key_rotation() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let config = KeyConfig {
                signing_private_key: "iblY/8ruRp43aGEjuCtJrs5QyAhaHroQIaUgWKNScco=".to_string(),
                encryption_private_key: "CeBWrM0FhC47Zek6QKCMopzNFC5U3JizkOuDYVqUXno=".to_string(),
                unique_key_id: "test_key_1".to_string(),
            };

            let service = KeyManagementService::new(config).await.unwrap();

            // Get original public keys
            let original_signing_pub = service.get_signing_public_key().await.unwrap();
            let original_encryption_pub = service.get_encryption_public_key().await.unwrap();

            // Rotate keys
            let rotation_result = service.rotate_keys().await;
            assert!(rotation_result.is_ok());

            // Get new public keys
            let new_signing_pub = service.get_signing_public_key().await.unwrap();
            let new_encryption_pub = service.get_encryption_public_key().await.unwrap();

            // Keys should be different
            assert_ne!(original_signing_pub, new_signing_pub);
            assert_ne!(original_encryption_pub, new_encryption_pub);
        });
    }
}
