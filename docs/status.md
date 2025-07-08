# ONDC BAP Server: Complete Project Breakdown

## Project Overview

Implement a production-ready ONDC BAP (Beckn Application Platform) server in Rust with crypto utilities, comprehensive testing, and professional documentation. The server must handle ONDC network participant onboarding and provide required endpoints for registry integration.

## Current Status

**Phase 2 - Crypto Foundation COMPLETED** ✅

All foundational cryptographic components have been successfully implemented:
- ✅ Ed25519 signing and verification with ONDC compliance
- ✅ X25519 key exchange with secure key handling
- ✅ Base64 encoding utilities with multiple variants support
- ✅ Key format conversions (Base64/DER) for Ed25519/X25519
- ✅ Comprehensive error handling and type safety
- ✅ Memory-safe operations with automatic zeroization

**Phase 3 - BAP Server Core Implementation IN PROGRESS** 🚧

**Task 3.3.1 COMPLETED** ✅ - Axum web server setup with production-ready middleware stack

**Key Accomplishments:**
- ✅ **Layered Router Architecture**: Complete Axum router with all required endpoints
- ✅ **Middleware Stack**: Logging, CORS, error handling, security headers, rate limiting
- ✅ **Per-IP Rate Limiting**: Adaptive rate limiting with comprehensive IP extraction
- ✅ **Graceful Shutdown**: Signal handling for clean server termination
- ✅ **Health & Metrics**: Prometheus-style metrics and health check endpoints
- ✅ **Service Integration**: KeyManager service integrated into application state
- ✅ **Production Ready**: Security headers, request validation, comprehensive error handling

**Next Phase**: Complete Domain Layer Implementation (Task 3.3.2)

## Phase 1: Project Foundation & Setup (Week 1) ✅

### 1.1 Workspace Setup ✅
- [x] **Task 1.1.1**: Initialize cargo workspace
- [x] **Task 1.1.2**: Configure development environment

### 1.2 Documentation Framework ✅
- [x] **Task 1.2.1**: Set up documentation structure

## Phase 2: Core Crypto Implementation (Weeks 2-4) ✅

### 2.1 ondc-crypto-traits Crate ✅
- [x] **Task 2.1.1**: Define core traits
- [x] **Task 2.1.2**: Error handling system  
- [x] **Task 2.1.3**: Core types and constants

### 2.2 ondc-crypto-algorithms Crate ✅
- [x] **Task 2.2.1**: Ed25519 implementation
- [x] **Task 2.2.2**: Ed25519 verification
- [x] **Task 2.2.3**: X25519 key exchange

### 2.3 ondc-crypto-formats Crate ✅
- [x] **Task 2.3.1**: Base64 encoding utilities
- [x] **Task 2.3.2**: Key format conversions

## Phase 3: BAP Server Core Implementation (Weeks 5-6)

### 3.1 Workspace Restructuring
- [x] **Task 3.1.1**: Rename and restructure main crate ✅
  ```toml
  # Priority: High | Estimated: 0.5 days
  [package]
  name = "ondc-bap"
  description = "ONDC BAP (Beckn Application Platform) server implementation"
  ```
  - [x] Rename `ondc-crypto` to `ondc-bap` ✅
  - [x] Update workspace dependencies and references ✅
  - [x] Restructure directory layout for web server architecture ✅
  - [x] Update documentation and README files ✅

- [x] **Task 3.1.2**: Add web server dependencies
  ```toml
  # Priority: High | Estimated: 0.5 days
  [dependencies]
  axum = "0.7"
  tokio = { version = "1.0", features = ["full"] }
  tower = "0.4"
  tower-http = { version = "0.5", features = ["cors", "trace"] }
  ```
  - [x] Add Axum web framework dependencies
  - [x] Add HTTP client dependencies (reqwest)
  - [x] Add configuration management (config, figment)
  - [x] Add logging and tracing dependencies
  - [x] Add serialization dependencies (serde_json, toml)

### 3.2 Configuration Management
- [x] **Task 3.2.1**: Environment configuration system
  ```rust
  // Priority: High | Estimated: 1 day
  #[derive(Debug, Clone, Deserialize)]
  pub struct BAPConfig {
      pub server: ServerConfig,
      pub ondc: ONDCConfig,
      pub keys: KeyConfig,
  }
  ```
  - [x] Create hierarchical configuration structure
  - [x] Support environment-specific configs (staging, pre-prod, prod)
  - [x] Add validation for required configuration fields
  - [x] Support environment variable overrides
  - [x] Add configuration documentation and examples

- [x] **Task 3.2.2**: Key management system
  ```rust
  // Priority: High | Estimated: 1 day
  pub struct KeyManager {
      signing_key: Ed25519Signer,
      encryption_key: X25519KeyExchange,
  }
  ```
  - [x] Secure key loading from configuration
  - [x] Key validation and format verification
  - [x] Support for multiple key formats (base64, DER)
  - [x] Key rotation capabilities

### 3.3 Core BAP Server Implementation
- [x] **Task 3.3.1**: Axum web server setup ✅
  ```rust
  // Priority: High | Estimated: 1.5 days
  pub struct BAPServer {
      config: BAPConfig,
      key_manager: KeyManager,
      registry_client: RegistryClient,
  }
  ```
  - [x] Basic `BAPServer` struct created
  - [x] Configuration loading implemented
  - [x] Create Axum router with layered architecture
  - [x] Implement middleware for logging, CORS, error handling
  - [x] Add graceful shutdown handling
  - [x] Configure SSL/TLS for HTTPS (optional for development)
  - [x] Add health check and metrics endpoints
  - [x] **Enhanced**: Per-IP rate limiting with adaptive limits
  - [x] **Enhanced**: Comprehensive IP extraction (X-Forwarded-For, X-Real-IP, CF-Connecting-IP)
  - [x] **Enhanced**: Production-ready middleware stack with security headers

- [ ] **Task 3.3.2**: Domain layer implementation
  ```rust
  // Priority: High | Estimated: 1 day
  pub struct SubscriberInfo {
      pub subscriber_id: String,
      pub signing_public_key: String,
      pub encryption_public_key: String,
      pub unique_key_id: String,
  }
  ```
  - [ ] Define core domain entities (Subscriber, Challenge, etc.)
  - [ ] Implement business rules validation
  - [ ] Add domain services for key operations
  - [ ] Create value objects with validation
  - [ ] Document domain boundaries and invariants

## Phase 4: ONDC Protocol Implementation (Week 7)

### 4.1 Site Verification Implementation
- [ ] **Task 4.1.1**: Site verification endpoint
  ```rust
  // Priority: High | Estimated: 1 day
  pub async fn serve_site_verification(
      State(app_state): State<AppState>,
  ) -> Result<Html<String>, AppError> {
      // Generate signed verification content
  }
  ```
  - [ ] Implement `/ondc-site-verification.html` endpoint
  - [ ] Generate signed request_id using Ed25519
  - [ ] Template HTML content generation
  - [ ] Add proper content-type headers
  - [ ] Validate signature generation process

- [ ] **Task 4.1.2**: On-subscribe endpoint implementation
  ```rust
  // Priority: High | Estimated: 1.5 days
  pub async fn on_subscribe(
      State(app_state): State<AppState>,
      Json(request): Json<OnSubscribeRequest>,
  ) -> Result<Json<OnSubscribeResponse>, AppError> {
      // Decrypt challenge and respond
  }
  ```
  - [ ] Implement `/on_subscribe` POST endpoint
  - [ ] X25519 shared secret generation
  - [ ] AES-256-ECB challenge decryption
  - [ ] Synchronous response handling
  - [ ] Comprehensive error handling and logging

### 4.2 Registry Client Implementation
- [ ] **Task 4.2.1**: Registry HTTP client
  ```rust
  // Priority: High | Estimated: 1.5 days
  pub struct RegistryClient {
      client: reqwest::Client,
      base_url: String,
      key_manager: Arc<KeyManager>,
  }
  ```
  - [ ] Implement HTTP client for registry APIs
  - [ ] Add request/response serialization
  - [ ] Implement retry logic with exponential backoff
  - [ ] Add request signing for authenticated endpoints
  - [ ] Handle rate limiting (429 responses)

- [ ] **Task 4.2.2**: Subscribe API implementation
  ```rust
  // Priority: High | Estimated: 1 day
  pub async fn subscribe_to_registry(
      &self,
      subscriber_info: SubscriberInfo,
  ) -> Result<SubscribeResponse, RegistryError> {
      // Implement /subscribe API call
  }
  ```
  - [ ] Implement `/subscribe` API call
  - [ ] Support different ops_no values (1, 2, 4)
  - [ ] Add payload validation and serialization
  - [ ] Handle various error responses
  - [ ] Add environment-specific URL handling

- [ ] **Task 4.2.3**: Lookup API implementation
  ```rust
  // Priority: Medium | Estimated: 1 day
  pub async fn lookup_participants(
      &self,
      criteria: LookupCriteria,
  ) -> Result<Vec<Participant>, RegistryError> {
      // Implement v2.0/lookup with auth
  }
  ```
  - [ ] Implement `/v2.0/lookup` with authorization
  - [ ] Support legacy `/lookup` endpoint
  - [ ] Add request signing with HTTP signatures
  - [ ] Handle paginated responses
  - [ ] Cache lookup results appropriately

## Phase 5: Application Services (Week 8)

### 5.1 Onboarding Service
- [ ] **Task 5.1.1**: Onboarding orchestration
  ```rust
  // Priority: High | Estimated: 2 days
  pub struct OnboardingService {
      registry_client: RegistryClient,
      key_manager: KeyManager,
      config: ONDCConfig,
  }
  ```
  - [ ] Orchestrate complete onboarding flow
  - [ ] Validate prerequisites (domain, SSL, whitelisting)
  - [ ] Handle onboarding state management
  - [ ] Add retry mechanisms for failed steps
  - [ ] Provide detailed progress reporting

- [ ] **Task 5.1.2**: Registration status tracking
  ```rust
  // Priority: Medium | Estimated: 1 day
  pub async fn check_registration_status(
      &self,
  ) -> Result<RegistrationStatus, ServiceError> {
      // Check current registration status
  }
  ```
  - [ ] Implement registration status checking
  - [ ] Add lookup verification
  - [ ] Track registration across environments
  - [ ] Provide registration health monitoring
  - [ ] Add alerts for registration issues

### 5.2 Key Management Service
- [ ] **Task 5.2.1**: Key lifecycle management
  ```rust
  // Priority: Medium | Estimated: 1 day
  pub struct KeyLifecycleService {
      key_manager: KeyManager,
      storage: KeyStorage,
  }
  ```
  - [ ] Implement key generation utilities
  - [ ] Add key validation and testing
  - [ ] Support key backup and recovery
  - [ ] Implement key rotation procedures
  - [ ] Add key expiration monitoring

## Phase 6: REST API Implementation (Week 9)

### 6.1 Administrative Endpoints
- [ ] **Task 6.1.1**: Admin API implementation
  ```rust
  // Priority: Medium | Estimated: 1.5 days
  pub async fn admin_register(
      State(app_state): State<AppState>,
      Json(request): Json<RegisterRequest>,
  ) -> Result<Json<RegisterResponse>, AppError> {
      // Administrative registration endpoint
  }
  ```
  - [ ] Implement administrative registration endpoint
  - [ ] Add configuration update endpoints
  - [ ] Implement key rotation endpoints
  - [ ] Add status and health monitoring APIs
  - [ ] Secure admin endpoints with authentication

- [ ] **Task 6.1.2**: Public API endpoints
  ```rust
  // Priority: Medium | Estimated: 1 day
  pub async fn get_participant_info(
      State(app_state): State<AppState>,
  ) -> Result<Json<ParticipantInfo>, AppError> {
      // Public participant information
  }
  ```
  - [ ] Implement public participant info endpoint
  - [ ] Add registry lookup proxy endpoints
  - [ ] Implement status check endpoints
  - [ ] Add CORS support for web clients
  - [ ] Document API specifications

### 6.2 Error Handling and Middleware
- [ ] **Task 6.2.1**: Error handling system
  ```rust
  // Priority: High | Estimated: 1 day
  #[derive(Error, Debug)]
  pub enum AppError {
      #[error("Registry error: {0}")]
      Registry(#[from] RegistryError),
      // ... other variants
  }
  ```
  - [ ] Implement comprehensive error handling
  - [ ] Add structured error responses
  - [ ] Implement error logging and monitoring
  - [ ] Add user-friendly error messages
  - [ ] Handle different error types appropriately

- [ ] **Task 6.2.2**: Middleware implementation
  ```rust
  // Priority: Medium | Estimated: 1 day
  pub fn create_middleware_stack() -> ServiceBuilder<Stack<...>> {
      // Build middleware stack
  }
  ```
  - [ ] Implement request/response logging
  - [ ] Add request tracing and correlation IDs
  - [ ] Implement rate limiting middleware
  - [ ] Add security headers middleware
  - [ ] Create performance monitoring middleware

## Phase 7: Testing and Quality (Week 10)

### 7.1 Integration Testing
- [ ] **Task 7.1.1**: Server integration tests
  ```rust
  // Priority: High | Estimated: 2 days
  #[tokio::test]
  async fn test_onboarding_flow() {
      // Test complete onboarding workflow
  }
  ```
  - [ ] Test complete onboarding workflow
  - [ ] Test registry API interactions
  - [ ] Test key management operations
  - [ ] Test error handling scenarios
  - [ ] Add performance and load testing

- [ ] **Task 7.1.2**: Mock registry testing
  ```rust
  // Priority: Medium | Estimated: 1 day
  pub struct MockRegistryServer {
      // Mock server for testing
  }
  ```
  - [ ] Implement mock registry server
  - [ ] Test against mock registry responses
  - [ ] Add chaos testing for resilience
  - [ ] Test network failure scenarios
  - [ ] Validate retry and recovery mechanisms

### 7.2 Security Testing
- [ ] **Task 7.2.1**: Security validation
  ```rust
  // Priority: High | Estimated: 1 day
  #[test]
  fn test_key_security() {
      // Validate key security measures
  }
  ```
  - [ ] Test key zeroization and memory safety
  - [ ] Validate crypto operations security
  - [ ] Test against timing attacks
  - [ ] Add TLS/SSL configuration testing
  - [ ] Perform security audit

## Phase 8: Documentation and Deployment (Week 11)

### 8.1 Documentation
- [ ] **Task 8.1.1**: API documentation
  - [ ] Generate OpenAPI/Swagger specifications
  - [ ] Add comprehensive endpoint documentation
  - [ ] Create deployment guides
  - [ ] Document configuration options
  - [ ] Add troubleshooting guides

- [ ] **Task 8.1.2**: Integration guides
  - [ ] Create ONDC integration tutorial
  - [ ] Add environment setup guides
  - [ ] Document onboarding procedures
  - [ ] Create migration guides
  - [ ] Add best practices documentation

### 8.2 Deployment and Operations
- [ ] **Task 8.2.1**: Deployment preparation
  ```dockerfile
  # Priority: Medium | Estimated: 1 day
  FROM rust:1.70 as builder
  WORKDIR /app
  COPY . .
  RUN cargo build --release
  ```
  - [ ] Create Docker containers
  - [ ] Add Kubernetes deployment manifests
  - [ ] Configure monitoring and alerting
  - [ ] Add log aggregation
  - [ ] Create operational runbooks

## Estimated Timeline

**Total Duration**: 11 weeks
**Effort Required**: ~300-350 person-hours
**Team Size**: 2-3 developers

### Critical Path Dependencies
1. Phase 1-2 → Phase 3 (Foundation before server implementation)
2. Phase 3.1-3.2 → Phase 3.3 (Config and keys before server)
3. Phase 3.3 → Phase 4 (Server before ONDC protocol)
4. Phase 4 → Phase 5 (Protocol before services)
5. Phase 5 → Phase 6 (Services before REST API)
6. Phase 6 → Phase 7 (Implementation before testing)
7. Phase 7 → Phase 8 (Testing before deployment)

### Risk Mitigation
- **ONDC Protocol Changes**: Regular validation against official specifications
- **Registry Integration Issues**: Comprehensive mock testing and error handling
- **Security Vulnerabilities**: Regular security audits and testing
- **Performance Issues**: Early load testing and monitoring
- **Deployment Complexity**: Containerization and automation

This comprehensive breakdown ensures a production-ready ONDC BAP server that meets all protocol requirements while maintaining high security, performance, and reliability standards.