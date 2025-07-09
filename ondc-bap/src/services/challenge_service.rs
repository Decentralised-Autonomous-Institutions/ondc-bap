//! Challenge processing service for ONDC BAP Server
//!
//! This service handles the processing of ONDC onboarding challenges
//! received in the on_subscribe endpoint. It performs X25519 key exchange
//! with ONDC public keys and AES-256-ECB decryption of challenges.

use std::sync::Arc;
use tracing::{info, error, instrument};
use serde::{Deserialize, Serialize};

use crate::config::BAPConfig;
use crate::services::KeyManagementService;
use ondc_crypto_algorithms::decrypt_aes256_ecb;
use ondc_crypto_formats::decode_signature;

/// Challenge processing error types
#[derive(Debug, thiserror::Error)]
pub enum ChallengeError {
    #[error("Invalid challenge format: {0}")]
    InvalidChallenge(String),

    #[error("Key exchange failed: {0}")]
    KeyExchangeError(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("ONDC public key error: {0}")]
    ONDCKeyError(String),

    #[error("Key manager error: {0}")]
    KeyManagerError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// On-subscribe request from ONDC registry
#[derive(Debug, Deserialize)]
pub struct OnSubscribeRequest {
    pub subscriber_id: String,
    pub challenge: String,
}

/// On-subscribe response to ONDC registry
#[derive(Debug, Serialize)]
pub struct OnSubscribeResponse {
    pub answer: String,
}

/// Challenge processing service
pub struct ChallengeService {
    key_manager: Arc<KeyManagementService>,
    config: Arc<BAPConfig>,
}

impl ChallengeService {
    /// Create a new challenge service
    pub fn new(key_manager: Arc<KeyManagementService>, config: Arc<BAPConfig>) -> Self {
        Self { key_manager, config }
    }

    /// Process an on_subscribe challenge
    ///
    /// This method:
    /// 1. Decodes the base64-encoded challenge
    /// 2. Generates a shared secret using X25519 key exchange
    /// 3. Decrypts the challenge using AES-256-ECB
    /// 4. Returns the decrypted answer
    #[instrument(skip(self, request), fields(subscriber_id = %request.subscriber_id))]
    pub async fn process_challenge(
        &self,
        request: OnSubscribeRequest,
    ) -> Result<OnSubscribeResponse, ChallengeError> {
        info!("Processing on_subscribe challenge");

        // Validate subscriber ID matches configuration
        if request.subscriber_id != self.config.ondc.subscriber_id {
            return Err(ChallengeError::ConfigError(format!(
                "Subscriber ID mismatch: expected {}, got {}",
                self.config.ondc.subscriber_id, request.subscriber_id
            )));
        }

        // Decode the base64-encoded challenge
        let encrypted_challenge = decode_signature(&request.challenge)
            .map_err(|e| ChallengeError::InvalidChallenge(format!("Failed to decode challenge: {}", e)))?;

        // Generate shared secret using X25519
        let shared_secret = self.generate_shared_secret().await?;

        // Decrypt challenge using AES-256-ECB
        let decrypted_bytes = decrypt_aes256_ecb(&encrypted_challenge, &shared_secret)
            .map_err(|e| ChallengeError::DecryptionError(format!("AES decryption failed: {}", e)))?;

        // Convert decrypted bytes to string
        let answer = String::from_utf8(decrypted_bytes)
            .map_err(|e| ChallengeError::DecryptionError(format!("Invalid UTF-8 in decrypted challenge: {}", e)))?;

        info!("Challenge processed successfully");
        Ok(OnSubscribeResponse { answer })
    }

    /// Generate shared secret using X25519 key exchange with ONDC public key
    async fn generate_shared_secret(&self) -> Result<Vec<u8>, ChallengeError> {
        // Get encryption key from key manager
        let encryption_key = self.key_manager.get_encryption_key().await
            .map_err(|e| ChallengeError::KeyManagerError(e.to_string()))?;

        // Get ONDC public key for current environment
        let ondc_public_key = self.config.ondc.ondc_public_key_bytes()
            .map_err(|e| ChallengeError::ONDCKeyError(e.to_string()))?;

        // Perform X25519 key exchange
        let shared_secret = encryption_key.diffie_hellman(&ondc_public_key)
            .map_err(|e| ChallengeError::KeyExchangeError(e.to_string()))?;

        Ok(shared_secret.to_vec())
    }
}
