//! Site Verification Service for ONDC BAP Server
//!
//! This service handles ONDC site verification requirements:
//! - Generate unique request IDs
//! - Sign request IDs using Ed25519 without hashing
//! - Generate HTML verification pages
//! - Store request IDs for later verification

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

use crate::config::BAPConfig;
use crate::services::key_management_service::KeyManagementError;
use crate::services::KeyManagementService;
use ondc_crypto_formats::encode_signature;
use ondc_crypto_traits::ONDCCryptoError;

/// Site verification service error types
#[derive(Debug, thiserror::Error)]
pub enum SiteVerificationError {
    #[error("Key management error: {0}")]
    KeyManagement(#[from] KeyManagementError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] ONDCCryptoError),

    #[error("Request ID generation failed: {0}")]
    RequestIdGeneration(String),

    #[error("HTML generation failed: {0}")]
    HtmlGeneration(String),

    #[error("Request ID not found: {0}")]
    RequestIdNotFound(String),

    #[error("Request ID expired: {0}")]
    RequestIdExpired(String),
}

/// Stored request ID with metadata
#[derive(Debug, Clone)]
struct StoredRequestId {
    request_id: String,
    signed_content: String,
    created_at: Instant,
    expires_at: Instant,
}

/// Site verification service
pub struct SiteVerificationService {
    key_manager: Arc<KeyManagementService>,
    config: Arc<BAPConfig>,
    request_ids: Arc<RwLock<HashMap<String, StoredRequestId>>>,
    ttl: Duration,
}

impl SiteVerificationService {
    /// Create a new site verification service
    pub fn new(key_manager: Arc<KeyManagementService>, config: Arc<BAPConfig>) -> Self {
        Self {
            key_manager,
            config,
            request_ids: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(3600), // 1 hour TTL
        }
    }

    /// Generate site verification HTML content
    #[instrument(skip(self))]
    pub async fn generate_site_verification(&self) -> Result<String, SiteVerificationError> {
        info!("Generating site verification content");

        // Generate unique request ID
        let request_id = self.generate_request_id()?;

        // Sign the request ID using Ed25519 without hashing
        let signed_content = self.sign_request_id(&request_id).await?;

        // Store the request ID for later verification
        self.store_request_id(&request_id, &signed_content).await;

        // Generate HTML content
        let html_content = self.generate_html_template(&signed_content)?;

        info!(
            "Site verification content generated successfully for request_id: {}",
            request_id
        );
        Ok(html_content)
    }

    /// Verify a request ID exists and is valid
    #[instrument(skip(self), fields(request_id = %request_id))]
    pub async fn verify_request_id(&self, request_id: &str) -> Result<bool, SiteVerificationError> {
        let request_ids = self.request_ids.read().await;

        if let Some(stored) = request_ids.get(request_id) {
            if Instant::now() < stored.expires_at {
                info!("Request ID verified successfully: {}", request_id);
                Ok(true)
            } else {
                warn!("Request ID expired: {}", request_id);
                Err(SiteVerificationError::RequestIdExpired(
                    request_id.to_string(),
                ))
            }
        } else {
            warn!("Request ID not found: {}", request_id);
            Err(SiteVerificationError::RequestIdNotFound(
                request_id.to_string(),
            ))
        }
    }

    /// Get stored request ID metadata
    #[instrument(skip(self), fields(request_id = %request_id))]
    pub async fn get_request_id_metadata(
        &self,
        request_id: &str,
    ) -> Result<StoredRequestId, SiteVerificationError> {
        let request_ids = self.request_ids.read().await;

        if let Some(stored) = request_ids.get(request_id) {
            if Instant::now() < stored.expires_at {
                Ok(stored.clone())
            } else {
                Err(SiteVerificationError::RequestIdExpired(
                    request_id.to_string(),
                ))
            }
        } else {
            Err(SiteVerificationError::RequestIdNotFound(
                request_id.to_string(),
            ))
        }
    }

    /// Clean up expired request IDs
    #[instrument(skip(self))]
    pub async fn cleanup_expired_request_ids(&self) -> Result<usize, SiteVerificationError> {
        let mut request_ids = self.request_ids.write().await;
        let now = Instant::now();
        let initial_count = request_ids.len();

        request_ids.retain(|_, stored| now < stored.expires_at);

        let removed_count = initial_count - request_ids.len();
        if removed_count > 0 {
            info!("Cleaned up {} expired request IDs", removed_count);
        }

        Ok(removed_count)
    }

    /// Generate a unique request ID
    fn generate_request_id(&self) -> Result<String, SiteVerificationError> {
        let request_id = Uuid::new_v4().to_string();
        info!("Generated request ID: {}", request_id);
        Ok(request_id)
    }

    /// Sign a request ID using Ed25519 without hashing
    #[instrument(skip(self, request_id))]
    async fn sign_request_id(&self, request_id: &str) -> Result<String, SiteVerificationError> {
        info!("Signing request ID with Ed25519");

        // Get the signing key
        let signer = self
            .key_manager
            .get_signing_key()
            .await
            .map_err(|e| SiteVerificationError::KeyManagement(e))?;

        // Sign the request ID without hashing (critical ONDC requirement)
        let signature = signer
            .sign_strict(request_id.as_bytes())
            .map_err(|e| SiteVerificationError::Crypto(e))?;

        // Encode the signature as base64
        let signed_content = encode_signature(&signature);

        info!("Request ID signed successfully");
        Ok(signed_content)
    }

    /// Store a request ID with metadata
    #[instrument(skip(self, request_id, signed_content))]
    async fn store_request_id(&self, request_id: &str, signed_content: &str) {
        let now = Instant::now();
        let expires_at = now + self.ttl;

        let stored = StoredRequestId {
            request_id: request_id.to_string(),
            signed_content: signed_content.to_string(),
            created_at: now,
            expires_at,
        };

        let mut request_ids = self.request_ids.write().await;
        request_ids.insert(request_id.to_string(), stored);

        info!(
            "Stored request ID: {} (expires at {:?})",
            request_id, expires_at
        );
    }

    /// Generate HTML template with signed content
    fn generate_html_template(
        &self,
        signed_content: &str,
    ) -> Result<String, SiteVerificationError> {
        // Escape the signed content for HTML
        let escaped_content: std::borrow::Cow<'_, str> = html_escape::encode_text(signed_content);

        let html_content = format!(
            r#"
<html>
  <head>
    <meta
      name="ondc-site-verification"
      content="{}"
    />
    <title>ONDC Site Verification</title>
  </head>
  <body>
    <h1>ONDC Site Verification Page</h1>
    <p>This page is used for ONDC network participant verification.</p>
    <p>Generated at: {}</p>
  </body>
</html>"#,
            escaped_content,
            chrono::Utc::now().to_rfc3339()
        );

        Ok(html_content)
    }

    /// Set custom TTL for request IDs
    pub fn set_ttl(&mut self, ttl: Duration) {
        self.ttl = ttl;
        info!("Updated request ID TTL to {:?}", ttl);
    }

    /// Get current TTL
    pub fn get_ttl(&self) -> Duration {
        self.ttl
    }

    /// Get statistics about stored request IDs
    pub async fn get_stats(&self) -> RequestIdStats {
        let request_ids = self.request_ids.read().await;
        let now = Instant::now();

        let total_count = request_ids.len();
        let expired_count = request_ids
            .values()
            .filter(|stored| now >= stored.expires_at)
            .count();
        let active_count = total_count - expired_count;

        RequestIdStats {
            total_count,
            active_count,
            expired_count,
            ttl_seconds: self.ttl.as_secs(),
        }
    }
}

/// Statistics about stored request IDs
#[derive(Debug, Clone)]
pub struct RequestIdStats {
    pub total_count: usize,
    pub active_count: usize,
    pub expired_count: usize,
    pub ttl_seconds: u64,
}

impl Clone for SiteVerificationService {
    fn clone(&self) -> Self {
        Self {
            key_manager: self.key_manager.clone(),
            config: self.config.clone(),
            request_ids: self.request_ids.clone(),
            ttl: self.ttl,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::app_config::{BAPConfig, KeyConfig, SecurityConfig, ServerConfig};
    use crate::config::ondc_config::{Environment, ONDCConfig};

    fn create_test_config() -> BAPConfig {
        BAPConfig {
            server: ServerConfig::default(),
            ondc: ONDCConfig::new(Environment::Staging, "test.example.com".to_string()),
            keys: KeyConfig {
                signing_private_key: "dGVzdF9zaWduaW5nX3ByaXZhdGVfa2V5XzMyX2J5dGVzX2xvbmc="
                    .to_string(), // 32 bytes base64
                encryption_private_key: "dGVzdF9lbmNyeXB0aW9uX3ByaXZhdGVfa2V5XzMyX2J5dGVz"
                    .to_string(), // 32 bytes base64
                unique_key_id: "test_key_1".to_string(),
            },
            security: SecurityConfig::default(),
        }
    }

    #[tokio::test]
    async fn test_site_verification_service_creation() {
        let config = create_test_config();
        let key_manager = Arc::new(
            KeyManagementService::new(config.keys.clone())
                .await
                .unwrap(),
        );
        let config = Arc::new(config);

        let service = SiteVerificationService::new(key_manager, config);
        assert_eq!(service.get_ttl(), Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn test_request_id_generation() {
        let config = create_test_config();
        let key_manager = Arc::new(
            KeyManagementService::new(config.keys.clone())
                .await
                .unwrap(),
        );
        let config = Arc::new(config);

        let service = SiteVerificationService::new(key_manager, config);

        let request_id = service.generate_request_id().unwrap();
        assert!(!request_id.is_empty());
        assert_eq!(request_id.len(), 36); // UUID v4 length
    }

    #[tokio::test]
    async fn test_html_template_generation() {
        let config = create_test_config();
        let key_manager = Arc::new(
            KeyManagementService::new(config.keys.clone())
                .await
                .unwrap(),
        );
        let config = Arc::new(config);

        let service = SiteVerificationService::new(key_manager, config);

        let test_signature = "dGVzdF9zaWduYXR1cmVfNjRfYnl0ZXNfbG9uZ19iYXNlNjRfZW5jb2RlZA==";
        let html = service.generate_html_template(test_signature).unwrap();

        assert!(html.contains("ondc-site-verification"));
        assert!(html.contains(test_signature));
        assert!(html.contains("<html>"));
        assert!(html.contains("</html>"));
    }

    #[tokio::test]
    async fn test_request_id_storage_and_verification() {
        let config = create_test_config();
        let key_manager = Arc::new(
            KeyManagementService::new(config.keys.clone())
                .await
                .unwrap(),
        );
        let config = Arc::new(config);

        let service = SiteVerificationService::new(key_manager, config);

        // Generate and store a request ID
        let request_id = service.generate_request_id().unwrap();
        let signed_content = "test_signature".to_string();

        // Store manually for testing
        {
            let mut request_ids = service.request_ids.write().await;
            let now = Instant::now();
            let stored = StoredRequestId {
                request_id: request_id.clone(),
                signed_content: signed_content.clone(),
                created_at: now,
                expires_at: now + Duration::from_secs(3600),
            };
            request_ids.insert(request_id.clone(), stored);
        }

        // Verify the request ID
        let is_valid = service.verify_request_id(&request_id).await.unwrap();
        assert!(is_valid);

        // Get metadata
        let metadata = service.get_request_id_metadata(&request_id).await.unwrap();
        assert_eq!(metadata.request_id, request_id);
        assert_eq!(metadata.signed_content, signed_content);
    }

    #[tokio::test]
    async fn test_stats_collection() {
        let config = create_test_config();
        let key_manager = Arc::new(
            KeyManagementService::new(config.keys.clone())
                .await
                .unwrap(),
        );
        let config = Arc::new(config);

        let service = SiteVerificationService::new(key_manager, config);

        let stats = service.get_stats().await;
        assert_eq!(stats.total_count, 0);
        assert_eq!(stats.active_count, 0);
        assert_eq!(stats.expired_count, 0);
        assert_eq!(stats.ttl_seconds, 3600);
    }
}
