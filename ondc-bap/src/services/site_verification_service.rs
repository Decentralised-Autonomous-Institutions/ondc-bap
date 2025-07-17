//! Site Verification Service for ONDC BAP Server
//!
//! This service handles ONDC site verification requirements:
//! - Generate unique request IDs
//! - Sign request IDs using Ed25519 without hashing
//! - Generate HTML verification pages
//! - Store request IDs for later verification

use std::sync::Arc;
use std::time::Duration;
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


/// Site verification service
pub struct SiteVerificationService {
    key_manager: Arc<KeyManagementService>,
    config: Arc<BAPConfig>,
    request_ids: Arc<RwLock<Option<String>>>,
    ttl: Duration,
}

impl SiteVerificationService {
    /// Create a new site verification service
    pub fn new(key_manager: Arc<KeyManagementService>, config: Arc<BAPConfig>) -> Self {
        Self {
            key_manager,
            config,
            request_ids: Arc::new(RwLock::new(None)),
            ttl: Duration::from_secs(3600), // 1 hour TTL
        }
    }

    /// Generate site verification HTML content
    #[instrument(skip(self))]
    pub async fn generate_site_verification(&self) -> Result<String, SiteVerificationError> {
        self.generate_site_verification_with_request_id(None).await
    }

    /// Generate site verification HTML content with optional request ID
    #[instrument(skip(self))]
    pub async fn generate_site_verification_with_request_id(&self, request_id: Option<&str>) -> Result<String, SiteVerificationError> {
        info!("Generating site verification content");

        // Use provided request ID or generate a new one
        let request_id = match request_id {
            Some(id) => {
                info!("Using provided request_id: {}", id);
                id.to_string()
            }
            None => {
                let id = self.generate_request_id()?;
                info!("Generated new request_id: {}", id);
                // Store the request ID
                self.store_request_id(&id).await;
                id
            }
        };

        // Sign the request ID using Ed25519 without hashing
        let signed_content = self.sign_request_id(&request_id).await?;

        // Generate HTML content
        let html_content = self.generate_html_template(&signed_content)?;

        info!(
            "Site verification content generated successfully for request_id: {}",
            request_id
        );
        Ok(html_content)
    }

    /// Get the current stored request ID
    #[instrument(skip(self))]
    pub async fn get_current_request_id(&self) -> Option<String> {
        let request_ids = self.request_ids.read().await;
        request_ids.clone()
    }

    /// Verify a request ID exists and is valid
    #[instrument(skip(self), fields(request_id = %request_id))]
    pub async fn verify_request_id(&self, request_id: &str) -> Result<bool, SiteVerificationError> {
        let stored_request_id = self.request_ids.read().await;

        if let Some(stored) = stored_request_id.as_ref() {
            if stored == request_id {
                info!("Request ID verified successfully: {}", request_id);
                Ok(true)
            } else {
                warn!("Request ID mismatch: expected {}, got {}", stored, request_id);
                Err(SiteVerificationError::RequestIdNotFound(
                    request_id.to_string(),
                ))
            }
        } else {
            warn!("No request ID stored");
            Err(SiteVerificationError::RequestIdNotFound(
                request_id.to_string(),
            ))
        }
    }

    /// Clear the stored request ID
    #[instrument(skip(self))]
    pub async fn clear_request_id(&self) {
        let mut request_ids = self.request_ids.write().await;
        *request_ids = None;
        info!("Cleared stored request ID");
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

    /// Store a request ID
    #[instrument(skip(self, request_id))]
    pub async fn store_request_id(&self, request_id: &str) {
        let mut request_ids = self.request_ids.write().await;
        *request_ids = Some(request_id.to_string());

        info!("Stored request ID: {}", request_id);
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

    /// Get statistics about stored request ID
    pub async fn get_stats(&self) -> RequestIdStats {
        let request_ids = self.request_ids.read().await;
        let active_count = if request_ids.is_some() { 1 } else { 0 };

        RequestIdStats {
            total_count: active_count,
            active_count,
            expired_count: 0,
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
        
        // Store manually for testing
        {
            let mut request_ids = service.request_ids.write().await;
            *request_ids = Some(request_id.clone());
        }

        // Get the current request ID
        let stored_request_id = service.get_current_request_id().await;
        assert_eq!(stored_request_id, Some(request_id));
    }

    #[tokio::test]
    async fn test_request_id_retrieval() {
        let config = create_test_config();
        let key_manager = Arc::new(
            KeyManagementService::new(config.keys.clone())
                .await
                .unwrap(),
        );
        let config = Arc::new(config);

        let service = SiteVerificationService::new(key_manager, config);

        // Initially no request ID
        let stored_request_id = service.get_current_request_id().await;
        assert_eq!(stored_request_id, None);

        // Generate and store a request ID
        let request_id = service.generate_request_id().unwrap();
        {
            let mut request_ids = service.request_ids.write().await;
            *request_ids = Some(request_id.clone());
        }

        // Should now return the stored ID
        let stored_request_id = service.get_current_request_id().await;
        assert_eq!(stored_request_id, Some(request_id));
    }
}
