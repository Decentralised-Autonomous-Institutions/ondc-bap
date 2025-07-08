# ONDC BAP Server Technical Guide

## Overview

This document provides comprehensive technical guidance for implementing the ONDC (Open Network for Digital Commerce) BAP (Beckn Application Platform) server in Rust. The server is designed as a layered web service that handles ONDC network participant onboarding and provides the required endpoints for registry integration, built on top of our established cryptographic foundation.

## Core Design Principles

### 1. Layered Architecture
- **Presentation Layer**: HTTP request handling with Axum framework
- **Services Layer**: Business logic and service orchestration
- **Domain Layer**: Core business entities and rules
- **Infrastructure Layer**: External integrations and data persistence

### 2. Security First
- **Zero-Trust Model**: Validate all inputs and authenticate all requests
- **Cryptographic Security**: Leverage existing crypto foundation for all operations
- **Network Security**: TLS/HTTPS for all communications
- **Key Security**: Secure key management with automatic zeroization

### 3. ONDC Protocol Compliance
- **Registry Integration**: Full compliance with ONDC registry APIs
- **Challenge-Response**: Proper implementation of onboarding flow
- **Digital Signatures**: Correct HTTP signature generation and verification
- **Error Handling**: ONDC-compliant error codes and responses

### 4. Production Ready
- **Observability**: Comprehensive logging, metrics, and tracing
- **Reliability**: Retry mechanisms, circuit breakers, and graceful degradation
- **Scalability**: Horizontal scaling support with stateless design
- **Maintainability**: Clean architecture with clear separation of concerns

## Updated Crate Architecture

### Updated Crate Architecture

The project now consists of four foundational crates plus the main BAP server:

#### Foundational Crates (Phase 2 - COMPLETED ✅)

1. **`ondc-crypto-traits`** - Core traits and types
   - Cryptographic trait definitions
   - Error handling system
   - Common types and constants

2. **`ondc-crypto-algorithms`** - Cryptographic implementations
   - Ed25519 signing and verification
   - X25519 key exchange
   - Blake2 hashing

3. **`ondc-crypto-formats`** - Encoding and formatting
   - Base64 encoding utilities
   - Key format conversions
   - DER format support

#### Main BAP Server Crate: `ondc-bap`

**Purpose**: Production-ready ONDC BAP server with web API and registry integration.

**New Structure**:
```
ondc-bap/
├── Cargo.toml
├── src/
│   ├── main.rs                    # Application entry point
│   ├── lib.rs                     # Library exports
│   ├── config/                    # Configuration management
│   │   ├── mod.rs
│   │   ├── app_config.rs          # Application configuration
│   │   ├── ondc_config.rs         # ONDC-specific settings
│   │   └── environment.rs         # Environment handling
│   ├── presentation/              # HTTP layer (Axum)
│   │   ├── mod.rs
│   │   ├── server.rs              # Axum server setup
│   │   ├── middleware/            # HTTP middleware
│   │   ├── handlers/              # Request handlers
│   │   └── routes.rs              # Route definitions
│   ├── services/                  # Application services
│   │   ├── mod.rs
│   │   ├── onboarding_service.rs  # Onboarding orchestration
│   │   ├── key_management_service.rs
│   │   ├── registry_client.rs     # Registry API client
│   │   └── challenge_service.rs   # Challenge handling
│   ├── infrastructure/            # Infrastructure layer
│   │   ├── mod.rs
│   │   ├── http_client.rs         # External HTTP client
│   │   ├── file_storage.rs        # File system operations
│   │   └── logging.rs             # Logging configuration
│   └── error/                     # Error handling
│       ├── mod.rs
│       ├── app_error.rs           # Application errors
│       └── registry_error.rs      # Registry-specific errors
├── config/                        # Configuration files
│   ├── staging.toml
│   ├── preprod.toml
│   └── production.toml
├── examples/                      # Usage examples
└── tests/                         # Integration tests
```

**Key Dependencies**:
```toml
[dependencies]
# Existing crypto crates
ondc-crypto-traits = { path = "../ondc-crypto-traits" }
ondc-crypto-algorithms = { path = "../ondc-crypto-algorithms" }
ondc-crypto-formats = { path = "../ondc-crypto-formats" }

# Web framework
axum = "0.7"
tower = "0.4"
tower-http = { version = "0.5", features = ["cors", "trace"] }
hyper = "1.0"

# Async runtime
tokio = { version = "1.0", features = ["full"] }

# HTTP client
reqwest = { version = "0.11", features = ["json", "native-tls"] }

# Configuration
config = "0.14"
figment = { version = "0.10", features = ["toml", "env"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Logging and tracing
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
tracing-opentelemetry = "0.21"

# Error handling
anyhow = "1.0"
thiserror = "1.0"

# Security
rustls = "0.22"
rustls-pemfile = "2.0"
```

## Implementation Patterns

### 1. Configuration Management Pattern

```rust
// config/app_config.rs
use figment::{Figment, providers::{Format, Toml, Env}};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BAPConfig {
    pub server: ServerConfig,
    pub ondc: ONDCConfig,
    pub keys: KeyConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub tls: Option<TlsConfig>,
    pub request_timeout_secs: u64,
    pub max_connections: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ONDCConfig {
    pub environment: Environment,
    pub registry_base_url: String,
    pub subscriber_id: String,
    pub callback_url: String,
    pub request_timeout_secs: u64,
    pub max_retries: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeyConfig {
    pub signing_private_key: String,      // Base64 encoded
    pub encryption_private_key: String,   // Base64 encoded
    pub unique_key_id: String,
}

impl BAPConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let environment = std::env::var("ONDC_ENV").unwrap_or_else(|_| "staging".to_string());
        
        Figment::new()
            .merge(Toml::file(format!("config/{}.toml", environment)))
            .merge(Env::prefixed("ONDC_"))
            .extract()
    }
    
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate configuration consistency
        if self.ondc.subscriber_id.is_empty() {
            return Err(ConfigError::InvalidSubscriberId);
        }
        
        // Validate key formats
        self.keys.validate()?;
        
        // Validate URLs
        url::Url::parse(&self.ondc.registry_base_url)
            .map_err(|_| ConfigError::InvalidRegistryUrl)?;
        
        Ok(())
    }
}

impl KeyConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        use ondc_crypto_formats::{decode_signature};
        
        // Validate signing key format and length
        let signing_key = decode_signature(&self.signing_private_key)
            .map_err(|_| ConfigError::InvalidSigningKey)?;
        if signing_key.len() != 32 {
            return Err(ConfigError::InvalidSigningKeyLength);
        }
        
        // Validate encryption key format and length
        let encryption_key = decode_signature(&self.encryption_private_key)
            .map_err(|_| ConfigError::InvalidEncryptionKey)?;
        if encryption_key.len() != 32 {
            return Err(ConfigError::InvalidEncryptionKeyLength);
        }
        
        Ok(())
    }
}
```

### 2. Layered Service Pattern

```rust
// application/onboarding_service.rs
use std::sync::Arc;
use anyhow::Result;
use tracing::{info, warn, error, instrument};

pub struct OnboardingService {
    registry_client: Arc<RegistryClient>,
    key_manager: Arc<KeyManager>,
    config: Arc<ONDCConfig>,
}

impl OnboardingService {
    pub fn new(
        registry_client: Arc<RegistryClient>,
        key_manager: Arc<KeyManager>,
        config: Arc<ONDCConfig>,
    ) -> Self {
        Self {
            registry_client,
            key_manager,
            config,
        }
    }
    
    #[instrument(skip(self), fields(subscriber_id = %self.config.subscriber_id))]
    pub async fn register_participant(
        &self,
        registration_request: RegistrationRequest,
    ) -> Result<RegistrationResponse, OnboardingError> {
        info!("Starting participant registration");
        
        // Validate prerequisites
        self.validate_prerequisites(&registration_request).await?;
        
        // Generate unique request ID
        let request_id = self.generate_request_id();
        
        // Prepare subscription payload
        let subscription_payload = self.prepare_subscription_payload(
            &registration_request,
            &request_id,
        ).await?;
        
        // Register with ONDC registry
        match self.registry_client.subscribe(subscription_payload).await {
            Ok(response) => {
                info!("Registration successful");
                Ok(RegistrationResponse {
                    status: RegistrationStatus::Success,
                    request_id,
                    message: "Successfully registered with ONDC registry".to_string(),
                })
            }
            Err(e) => {
                error!("Registration failed: {}", e);
                Err(OnboardingError::RegistrationFailed(e.to_string()))
            }
        }
    }
    
    #[instrument(skip(self))]
    pub async fn check_registration_status(&self) -> Result<RegistrationStatus, OnboardingError> {
        info!("Checking registration status");
        
        let lookup_criteria = LookupCriteria {
            country: "IND".to_string(),
            domain: self.determine_domain(),
            subscriber_id: Some(self.config.subscriber_id.clone()),
        };
        
        match self.registry_client.lookup(lookup_criteria).await {
            Ok(participants) => {
                if participants.iter().any(|p| p.subscriber_id == self.config.subscriber_id) {
                    info!("Registration confirmed in registry");
                    Ok(RegistrationStatus::Active)
                } else {
                    warn!("Participant not found in registry");
                    Ok(RegistrationStatus::NotFound)
                }
            }
            Err(e) => {
                error!("Failed to check registration status: {}", e);
                Err(OnboardingError::StatusCheckFailed(e.to_string()))
            }
        }
    }
    
    async fn validate_prerequisites(
        &self,
        request: &RegistrationRequest,
    ) -> Result<(), OnboardingError> {
        // Validate domain accessibility
        self.validate_domain_accessibility().await?;
        
        // Validate SSL certificate
        self.validate_ssl_certificate().await?;
        
        // Validate key pairs
        self.key_manager.validate_key_pairs()?;
        
        Ok(())
    }
    
    async fn prepare_subscription_payload(
        &self,
        request: &RegistrationRequest,
        request_id: &str,
    ) -> Result<SubscriptionPayload, OnboardingError> {
        let signing_public_key = self.key_manager.get_signing_public_key()?;
        let encryption_public_key = self.key_manager.get_encryption_public_key()?;
        
        Ok(SubscriptionPayload {
            subscriber_id: self.config.subscriber_id.clone(),
            callback_url: self.config.callback_url.clone(),
            subscriber_url: self.config.subscriber_id.clone(),
            signing_public_key: signing_public_key,
            encryption_public_key: encryption_public_key,
            unique_key_id: self.key_manager.get_unique_key_id(),
            request_id: request_id.to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            ops_no: request.ops_no,
            // Add other required fields based on ops_no
        })
    }
}
```

### 3. Axum Handler Pattern

```rust
// presentation/handlers/ondc_handlers.rs
use axum::{
    extract::{State, Json},
    response::{Html, Result as AxumResult},
    http::StatusCode,
};
use tracing::{info, error, instrument};

#[derive(Clone)]
pub struct AppState {
    pub onboarding_service: Arc<OnboardingService>,
    pub challenge_service: Arc<ChallengeService>,
    pub key_manager: Arc<KeyManager>,
    pub config: Arc<BAPConfig>,
}

#[instrument(skip(state))]
pub async fn serve_site_verification(
    State(state): State<AppState>,
) -> AxumResult<Html<String>> {
    info!("Serving site verification page");
    
    match state.challenge_service.generate_site_verification().await {
        Ok(html_content) => {
            info!("Site verification page generated successfully");
            Ok(Html(html_content))
        }
        Err(e) => {
            error!("Failed to generate site verification: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to generate verification page: {}", e),
            ).into())
        }
    }
}

#[instrument(skip(state, request), fields(subscriber_id = ?request.subscriber_id))]
pub async fn handle_on_subscribe(
    State(state): State<AppState>,
    Json(request): Json<OnSubscribeRequest>,
) -> AxumResult<Json<OnSubscribeResponse>> {
    info!("Processing on_subscribe challenge");
    
    // Validate request
    if let Err(e) = validate_on_subscribe_request(&request) {
        error!("Invalid on_subscribe request: {}", e);
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Invalid request: {}", e),
        ).into());
    }
    
    // Process challenge
    match state.challenge_service.process_challenge(request).await {
        Ok(response) => {
            info!("Challenge processed successfully");
            Ok(Json(response))
        }
        Err(e) => {
            error!("Failed to process challenge: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Challenge processing failed: {}", e),
            ).into())
        }
    }
}

#[instrument(skip(state, request))]
pub async fn admin_register(
    State(state): State<AppState>,
    Json(request): Json<AdminRegistrationRequest>,
) -> AxumResult<Json<AdminRegistrationResponse>> {
    info!("Processing admin registration request");
    
    // Validate admin request
    if let Err(e) = validate_admin_request(&request) {
        error!("Invalid admin request: {}", e);
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Invalid request: {}", e),
        ).into());
    }
    
    // Process registration
    match state.onboarding_service.register_participant(request.into()).await {
        Ok(response) => {
            info!("Registration initiated successfully");
            Ok(Json(AdminRegistrationResponse {
                status: "initiated".to_string(),
                message: response.message,
                request_id: response.request_id,
            }))
        }
        Err(e) => {
            error!("Registration failed: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Registration failed: {}", e),
            ).into())
        }
    }
}

pub async fn health_check() -> AxumResult<Json<HealthResponse>> {
    Ok(Json(HealthResponse {
        status: "healthy".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    }))
}

fn validate_on_subscribe_request(request: &OnSubscribeRequest) -> Result<(), ValidationError> {
    if request.subscriber_id.is_empty() {
        return Err(ValidationError::EmptySubscriberId);
    }
    
    if request.challenge.is_empty() {
        return Err(ValidationError::EmptyChallenge);
    }
    
    // Add more validation as needed
    Ok(())
}
```

### 4. Challenge Processing Pattern

```rust
// application/challenge_service.rs
use std::sync::Arc;
use ondc_crypto_algorithms::{X25519KeyExchange, Ed25519Signer};
use ondc_crypto_formats::{decode_signature, encode_signature};

pub struct ChallengeService {
    key_manager: Arc<KeyManager>,
    config: Arc<BAPConfig>,
}

impl ChallengeService {
    pub fn new(key_manager: Arc<KeyManager>, config: Arc<BAPConfig>) -> Self {
        Self { key_manager, config }
    }
    
    #[instrument(skip(self))]
    pub async fn generate_site_verification(&self) -> Result<String, ChallengeError> {
        info!("Generating site verification content");
        
        // Generate unique request ID
        let request_id = uuid::Uuid::new_v4().to_string();
        
        // Sign the request ID using Ed25519
        let signed_content = self.sign_request_id(&request_id).await?;
        
        // Generate HTML content
        let html_content = format!(
            r#"<!--Contents of ondc-site-verification.html. -->
<!--Please replace SIGNED_UNIQUE_REQ_ID with an actual value-->
<html>
  <head>
    <meta
      name="ondc-site-verification"
      content="{}"
    />
  </head>
  <body>
    ONDC Site Verification Page
  </body>
</html>"#,
            signed_content
        );
        
        info!("Site verification content generated");
        Ok(html_content)
    }
    
    #[instrument(skip(self, request), fields(challenge_length = request.challenge.len()))]
    pub async fn process_challenge(
        &self,
        request: OnSubscribeRequest,
    ) -> Result<OnSubscribeResponse, ChallengeError> {
        info!("Processing on_subscribe challenge");
        
        // Decode the encrypted challenge
        let encrypted_challenge = decode_signature(&request.challenge)
            .map_err(|e| ChallengeError::InvalidChallenge(e.to_string()))?;
        
        // Generate shared secret using X25519
        let shared_secret = self.generate_shared_secret().await?;
        
        // Decrypt challenge using AES-256-ECB
        let decrypted_answer = self.decrypt_challenge(&encrypted_challenge, &shared_secret)?;
        
        info!("Challenge decrypted successfully");
        
        Ok(OnSubscribeResponse {
            answer: decrypted_answer,
        })
    }
    
    async fn sign_request_id(&self, request_id: &str) -> Result<String, ChallengeError> {
        let signer = self.key_manager.get_ed25519_signer()
            .map_err(|e| ChallengeError::KeyManagerError(e.to_string()))?;
        
        let signature = signer.sign(request_id.as_bytes())
            .map_err(|e| ChallengeError::SigningError(e.to_string()))?;
        
        Ok(encode_signature(&signature))
    }
    
    async fn generate_shared_secret(&self) -> Result<Vec<u8>, ChallengeError> {
        let key_exchange = self.key_manager.get_x25519_key_exchange()
            .map_err(|e| ChallengeError::KeyManagerError(e.to_string()))?;
        
        // Get ONDC public key for the current environment
        let ondc_public_key = self.get_ondc_public_key()?;
        
        let shared_secret = key_exchange.diffie_hellman(&ondc_public_key)
            .map_err(|e| ChallengeError::KeyExchangeError(e.to_string()))?;
        
        Ok(shared_secret.to_vec())
    }
    
    fn decrypt_challenge(
        &self,
        encrypted_challenge: &[u8],
        shared_secret: &[u8],
    ) -> Result<String, ChallengeError> {
        use aes::Aes256;
        use block_modes::{BlockMode, Ecb};
        use block_modes::block_padding::NoPadding;
        
        type Aes256Ecb = Ecb<Aes256, NoPadding>;
        
        let cipher = Aes256Ecb::new_from_slices(shared_secret, &[])
            .map_err(|e| ChallengeError::DecryptionError(e.to_string()))?;
        
        let decrypted = cipher.decrypt_vec(encrypted_challenge)
            .map_err(|e| ChallengeError::DecryptionError(e.to_string()))?;
        
        String::from_utf8(decrypted)
            .map_err(|e| ChallengeError::DecryptionError(e.to_string()))
    }
    
    fn get_ondc_public_key(&self) -> Result<[u8; 32], ChallengeError> {
        let public_key_b64 = match self.config.ondc.environment {
            Environment::Staging => "MCowBQYDK2VuAyEAduMuZgmtpjdCuxv+Nc49K0cB6tL/Dj3HZetvVN7ZekM=",
            Environment::PreProd => "MCowBQYDK2VuAyEAa9Wbpvd9SsrpOZFcynyt/TO3x0Yrqyys4NUGIvyxX2Q=",
            Environment::Production => "MCowBQYDK2VuAyEAvVEyZY91O2yV8w8/CAwVDAnqIZDJJUPdLUUKwLo3K0M=",
        };
        
        let decoded = decode_signature(public_key_b64)
            .map_err(|e| ChallengeError::InvalidONDCKey(e.to_string()))?;
        
        // Extract raw key from DER format (last 32 bytes)
        if decoded.len() < 32 {
            return Err(ChallengeError::InvalidONDCKey("Key too short".to_string()));
        }
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded[decoded.len() - 32..]);
        Ok(key)
    }
}
```

### 5. Registry Client Pattern

```rust
// application/registry_client.rs
use std::time::Duration;
use reqwest::{Client, ClientBuilder};
use serde::{Serialize, Deserialize};
use tracing::{info, warn, error, instrument};

pub struct RegistryClient {
    client: Client,
    base_url: String,
    key_manager: Arc<KeyManager>,
    config: Arc<ONDCConfig>,
}

impl RegistryClient {
    pub fn new(
        key_manager: Arc<KeyManager>,
        config: Arc<ONDCConfig>,
    ) -> Result<Self, RegistryClientError> {
        let client = ClientBuilder::new()
            .timeout(Duration::from_secs(config.request_timeout_secs))
            .use_rustls_tls()
            .build()
            .map_err(|e| RegistryClientError::ClientCreationFailed(e.to_string()))?;
        
        Ok(Self {
            client,
            base_url: config.registry_base_url.clone(),
            key_manager,
            config: config.clone(),
        })
    }
    
    #[instrument(skip(self, payload), fields(subscriber_id = %payload.subscriber_id))]
    pub async fn subscribe(
        &self,
        payload: SubscriptionPayload,
    ) -> Result<SubscriptionResponse, RegistryClientError> {
        info!("Sending subscription request to registry");
        
        let url = format!("{}/subscribe", self.base_url);
        
        let response = self.client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| RegistryClientError::RequestFailed(e.to_string()))?;
        
        if response.status().is_success() {
            let subscription_response: SubscriptionResponse = response
                .json()
                .await
                .map_err(|e| RegistryClientError::DeserializationFailed(e.to_string()))?;
            
            info!("Subscription request successful");
            Ok(subscription_response)
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            
            error!("Subscription request failed: {}", error_text);
            Err(RegistryClientError::SubscriptionFailed(error_text))
        }
    }
    
    #[instrument(skip(self, criteria))]
    pub async fn lookup(
        &self,
        criteria: LookupCriteria,
    ) -> Result<Vec<Participant>, RegistryClientError> {
        info!("Performing registry lookup");
        
        let url = format!("{}/v2.0/lookup", self.base_url);
        
        // Create authorization header for v2.0 API
        let auth_header = self.create_authorization_header(&criteria).await?;
        
        let response = self.client
            .post(&url)
            .header("Authorization", auth_header)
            .header("Content-Type", "application/json")
            .json(&criteria)
            .send()
            .await
            .map_err(|e| RegistryClientError::RequestFailed(e.to_string()))?;
        
        if response.status().is_success() {
            let lookup_response: LookupResponse = response
                .json()
                .await
                .map_err(|e| RegistryClientError::DeserializationFailed(e.to_string()))?;
            
            info!("Lookup request successful, found {} participants", lookup_response.participants.len());
            Ok(lookup_response.participants)
        } else if response.status() == 429 {
            warn!("Rate limit exceeded, should retry with backoff");
            Err(RegistryClientError::RateLimitExceeded)
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            
            error!("Lookup request failed: {}", error_text);
            Err(RegistryClientError::LookupFailed(error_text))
        }
    }
    
    async fn create_authorization_header(
        &self,
        criteria: &LookupCriteria,
    ) -> Result<String, RegistryClientError> {
        let created = chrono::Utc::now().timestamp() as u64;
        let expires = created + 300; // 5 minutes from now
        
        // Create digest
        let body_json = serde_json::to_string(criteria)
            .map_err(|e| RegistryClientError::SerializationFailed(e.to_string()))?;
        
        let hasher = Blake2Hasher::new();
        let digest = hasher.generate_ondc_digest(body_json.as_bytes());
        
        // Create signing string
        let signing_string = format!(
            "(created): {}\n(expires): {}\ndigest: {}",
            created, expires, digest
        );
        
        // Sign the string
        let signer = self.key_manager.get_ed25519_signer()
            .map_err(|e| RegistryClientError::KeyManagerError(e.to_string()))?;
        
        let signature = signer.sign(signing_string.as_bytes())
            .map_err(|e| RegistryClientError::SigningError(e.to_string()))?;
        
        let signature_b64 = encode_signature(&signature);
        
        // Create authorization header
        let auth_header = format!(
            r#"Signature keyId="{}|{}|ed25519",algorithm="ed25519",created="{}",expires="{}",headers="(created) (expires) digest",signature="{}""#,
            self.config.subscriber_id,
            self.key_manager.get_unique_key_id(),
            created,
            expires,
            signature_b64
        );
        
        Ok(auth_header)
    }
}

// Retry implementation with exponential backoff
impl RegistryClient {
    pub async fn subscribe_with_retry(
        &self,
        payload: SubscriptionPayload,
    ) -> Result<SubscriptionResponse, RegistryClientError> {
        let mut attempts = 0;
        let max_attempts = self.config.max_retries;
        
        loop {
            match self.subscribe(payload.clone()).await {
                Ok(response) => return Ok(response),
                Err(RegistryClientError::RateLimitExceeded) if attempts < max_attempts => {
                    let delay = Duration::from_millis(1000 * 2_u64.pow(attempts));
                    warn!("Rate limited, retrying in {:?}", delay);
                    tokio::time::sleep(delay).await;
                    attempts += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }
}
```

## Security Implementation

### 1. TLS/HTTPS Configuration

```rust
// presentation/server.rs
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;

pub async fn create_server(config: &BAPConfig, app_state: AppState) -> Result<(), ServerError> {
    let app = create_router(app_state);
    
    let addr = SocketAddr::from(([0, 0, 0, 0], config.server.port));
    
    if let Some(tls_config) = &config.server.tls {
        info!("Starting HTTPS server on {}", addr);
        
        let rustls_config = RustlsConfig::from_pem_file(
            &tls_config.cert_path,
            &tls_config.key_path,
        ).await
        .map_err(|e| ServerError::TlsConfigurationFailed(e.to_string()))?;
        
        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service())
            .await
            .map_err(|e| ServerError::ServerStartFailed(e.to_string()))?;
    } else {
        warn!("Starting HTTP server (TLS disabled) on {}", addr);
        
        axum_server::bind(addr)
            .serve(app.into_make_service())
            .await
            .map_err(|e| ServerError::ServerStartFailed(e.to_string()))?;
    }
    
    Ok(())
}
```

### 2. Input Validation and Sanitization

```rust
// domain/validation.rs
use regex::Regex;

pub struct InputValidator;

impl InputValidator {
    pub fn validate_subscriber_id(subscriber_id: &str) -> Result<(), ValidationError> {
        if subscriber_id.is_empty() {
            return Err(ValidationError::EmptySubscriberId);
        }
        
        if subscriber_id.len() > 255 {
            return Err(ValidationError::SubscriberIdTooLong);
        }
        
        // Validate FQDN format
        let fqdn_regex = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
            .unwrap();
        
        if !fqdn_regex.is_match(subscriber_id) {
            return Err(ValidationError::InvalidSubscriberIdFormat);
        }
        
        Ok(())
    }
    
    pub fn validate_challenge(challenge: &str) -> Result<(), ValidationError> {
        if challenge.is_empty() {
            return Err(ValidationError::EmptyChallenge);
        }
        
        // Validate base64 format
        if let Err(_) = base64::decode(challenge) {
            return Err(ValidationError::InvalidChallengeFormat);
        }
        
        Ok(())
    }
    
    pub fn sanitize_callback_url(callback_url: &str) -> Result<String, ValidationError> {
        // Remove any potentially dangerous characters
        let sanitized = callback_url
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '/' || *c == '-' || *c == '_')
            .collect::<String>();
        
        if sanitized != callback_url {
            return Err(ValidationError::UnsafeCallbackUrl);
        }
        
        Ok(sanitized)
    }
}
```

### 3. Rate Limiting and Security Middleware

```rust
// presentation/middleware/security.rs
use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
    http::{HeaderMap, HeaderValue, StatusCode},
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct RateLimiter {
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window_duration: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_duration: Duration) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window_duration,
        }
    }
    
    pub fn check_rate_limit(&self, client_ip: &str) -> bool {
        let mut requests = self.requests.lock().unwrap();
        let now = Instant::now();
        
        let client_requests = requests.entry(client_ip.to_string()).or_insert_with(Vec::new);
        
        // Remove old requests outside the window
        client_requests.retain(|&request_time| {
            now.duration_since(request_time) < self.window_duration
        });
        
        if client_requests.len() >= self.max_requests {
            false
        } else {
            client_requests.push(now);
            true
        }
    }
}

pub async fn rate_limit_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let client_ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .or_else(|| {
            request
                .headers()
                .get("x-real-ip")
                .and_then(|h| h.to_str().ok())
        })
        .unwrap_or("unknown");
    
    // Get rate limiter from app state (this would be injected)
    // For demonstration purposes, create a default limiter
    let rate_limiter = RateLimiter::new(100, Duration::from_secs(60)); // 100 requests per minute
    
    if !rate_limiter.check_rate_limit(client_ip) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    
    Ok(next.run(request).await)
}

pub async fn security_headers_middleware(
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    
    let headers = response.headers_mut();
    
    // Add security headers
    headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert("X-XSS-Protection", HeaderValue::from_static("1; mode=block"));
    headers.insert("Referrer-Policy", HeaderValue::from_static("strict-origin-when-cross-origin"));
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
    );
    
    response
}
```

## Testing Patterns

### 1. Integration Testing with Test Containers

```rust
// tests/integration_tests.rs
use std::collections::HashMap;
use tokio::test;
use axum_test::TestServer;
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};

#[tokio::test]
async fn test_onboarding_flow() -> Result<(), Box<dyn std::error::Error>> {
    // Start mock ONDC registry
    let mock_server = MockServer::start().await;
    
    // Configure mock responses
    Mock::given(method("POST"))
        .and(path("/subscribe"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "message": {
                    "ack": {
                        "status": "ACK"
                    }
                },
                "error": {
                    "type": null,
                    "code": null,
                    "path": null,
                    "message": null
                }
            })))
        .mount(&mock_server)
        .await;
    
    Mock::given(method("POST"))
        .and(path("/on_subscribe"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "answer": "test_challenge_response"
            })))
        .mount(&mock_server)
        .await;
    
    // Create test configuration
    let mut test_config = create_test_config();
    test_config.ondc.registry_base_url = mock_server.uri();
    
    // Create test server
    let app_state = create_test_app_state(test_config).await?;
    let test_server = TestServer::new(create_router(app_state))?;
    
    // Test site verification endpoint
    let response = test_server
        .get("/ondc-site-verification.html")
        .await;
    
    assert_eq!(response.status_code(), 200);
    assert!(response.text().contains("ondc-site-verification"));
    
    // Test on_subscribe endpoint
    let on_subscribe_request = serde_json::json!({
        "subscriber_id": "test.example.com",
        "challenge": "dGVzdF9jaGFsbGVuZ2U=" // base64 encoded "test_challenge"
    });
    
    let response = test_server
        .post("/on_subscribe")
        .json(&on_subscribe_request)
        .await;
    
    assert_eq!(response.status_code(), 200);
    
    let response_body: serde_json::Value = response.json();
    assert!(response_body["answer"].is_string());
    
    // Test admin registration endpoint
    let registration_request = serde_json::json!({
        "ops_no": 1,
        "domain": "ONDC:RET10",
        "country": "IND"
    });
    
    let response = test_server
        .post("/admin/register")
        .json(&registration_request)
        .await;
    
    assert_eq!(response.status_code(), 200);
    
    Ok(())
}

#[tokio::test]
async fn test_challenge_decryption() -> Result<(), Box<dyn std::error::Error>> {
    let test_config = create_test_config();
    let key_manager = Arc::new(KeyManager::new(&test_config.keys).await?);
    let challenge_service = ChallengeService::new(key_manager, Arc::new(test_config));
    
    // Create test challenge (this would normally be encrypted by ONDC)
    let test_challenge = "test_challenge_string";
    let challenge_request = OnSubscribeRequest {
        subscriber_id: "test.example.com".to_string(),
        challenge: base64::encode(test_challenge.as_bytes()),
    };
    
    let response = challenge_service.process_challenge(challenge_request).await?;
    
    // Verify that the challenge was processed correctly
    assert!(!response.answer.is_empty());
    
    Ok(())
}

async fn create_test_app_state(config: BAPConfig) -> Result<AppState, Box<dyn std::error::Error>> {
    let key_manager = Arc::new(KeyManager::new(&config.keys).await?);
    let registry_client = Arc::new(RegistryClient::new(
        key_manager.clone(),
        Arc::new(config.ondc.clone()),
    )?);
    let onboarding_service = Arc::new(OnboardingService::new(
        registry_client.clone(),
        key_manager.clone(),
        Arc::new(config.ondc.clone()),
    ));
    let challenge_service = Arc::new(ChallengeService::new(
        key_manager.clone(),
        Arc::new(config.clone()),
    ));
    
    Ok(AppState {
        onboarding_service,
        challenge_service,
        key_manager,
        config: Arc::new(config),
    })
}

fn create_test_config() -> BAPConfig {
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
```

### 2. Property-Based Testing for Crypto Operations

```rust
// tests/property_tests.rs
use proptest::prelude::*;
use ondc_crypto_algorithms::{Ed25519Signer, Ed25519Verifier};
use ondc_crypto_formats::{encode_signature, decode_signature};

proptest! {
    #[test]
    fn test_signature_roundtrip(message in ".*") {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        
        runtime.block_on(async {
            let signer = Ed25519Signer::generate().unwrap();
            let verifier = Ed25519Verifier::new();
            
            let signature = signer.sign(message.as_bytes()).unwrap();
            let public_key = signer.public_key();
            
            // Signature should verify correctly
            verifier.verify(&public_key, message.as_bytes(), &signature).unwrap();
        });
    }
    
    #[test]
    fn test_base64_encoding_roundtrip(data in prop::collection::vec(any::<u8>(), 0..1000)) {
        let encoded = encode_signature(&data);
        let decoded = decode_signature(&encoded).unwrap();
        
        prop_assert_eq!(data, decoded);
    }
    
    #[test]
    fn test_challenge_processing(challenge_data in prop::collection::vec(any::<u8>(), 32..256)) {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        
        runtime.block_on(async {
            let test_config = create_test_config();
            let key_manager = Arc::new(KeyManager::new(&test_config.keys).await.unwrap());
            let challenge_service = ChallengeService::new(key_manager, Arc::new(test_config));
            
            let challenge_b64 = encode_signature(&challenge_data);
            let request = OnSubscribeRequest {
                subscriber_id: "test.example.com".to_string(),
                challenge: challenge_b64,
            };
            
            // Challenge processing should not panic
            let _result = challenge_service.process_challenge(request).await;
        });
    }
}
```

## Performance Considerations

### 1. Async/Await Performance Patterns

```rust
// application/performance_optimizations.rs
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use std::time::Duration;

pub struct PerformanceOptimizedService {
    // Use RwLock for read-heavy operations
    cache: Arc<RwLock<HashMap<String, CachedValue>>>,
    // Limit concurrent expensive operations
    semaphore: Arc<Semaphore>,
}

impl PerformanceOptimizedService {
    pub fn new(max_concurrent_operations: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            semaphore: Arc::new(Semaphore::new(max_concurrent_operations)),
        }
    }
    
    pub async fn expensive_operation(&self, key: &str) -> Result<String, ServiceError> {
        // Check cache first (read lock)
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(key) {
                if !cached.is_expired() {
                    return Ok(cached.value.clone());
                }
            }
        }
        
        // Acquire semaphore to limit concurrent operations
        let _permit = self.semaphore.acquire().await
            .map_err(|_| ServiceError::ResourceExhausted)?;
        
        // Double-check cache after acquiring semaphore
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(key) {
                if !cached.is_expired() {
                    return Ok(cached.value.clone());
                }
            }
        }
        
        // Perform expensive operation
        let result = self.perform_expensive_computation(key).await?;
        
        // Update cache (write lock)
        {
            let mut cache = self.cache.write().await;
            cache.insert(key.to_string(), CachedValue {
                value: result.clone(),
                expires_at: tokio::time::Instant::now() + Duration::from_secs(300),
            });
        }
        
        Ok(result)
    }
    
    async fn perform_expensive_computation(&self, _key: &str) -> Result<String, ServiceError> {
        // Simulate expensive operation
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok("computed_value".to_string())
    }
}

#[derive(Clone)]
struct CachedValue {
    value: String,
    expires_at: tokio::time::Instant,
}

impl CachedValue {
    fn is_expired(&self) -> bool {
        tokio::time::Instant::now() > self.expires_at
    }
}
```

### 2. Connection Pooling and Resource Management

```rust
// infrastructure/connection_pool.rs
use reqwest::{Client, ClientBuilder};
use std::sync::Arc;
use std::time::Duration;

pub struct ConnectionPoolManager {
    http_client: Client,
}

impl ConnectionPoolManager {
    pub fn new(config: &BAPConfig) -> Result<Self, ConnectionError> {
        let client = ClientBuilder::new()
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(config.server.request_timeout_secs))
            .tcp_keepalive(Duration::from_secs(60))
            .http2_keep_alive_interval(Duration::from_secs(30))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .use_rustls_tls()
            .build()
            .map_err(|e| ConnectionError::ClientCreationFailed(e.to_string()))?;
        
        Ok(Self {
            http_client: client,
        })
    }
    
    pub fn get_http_client(&self) -> &Client {
        &self.http_client
    }
}

// Use connection pool in registry client
impl RegistryClient {
    pub fn new_with_pool(
        pool_manager: Arc<ConnectionPoolManager>,
        key_manager: Arc<KeyManager>,
        config: Arc<ONDCConfig>,
    ) -> Self {
        Self {
            client: pool_manager.get_http_client().clone(),
            base_url: config.registry_base_url.clone(),
            key_manager,
            config,
        }
    }
}
```