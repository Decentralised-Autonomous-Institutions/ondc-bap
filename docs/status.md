# ONDC BAP Server with LLM Agent Integration: Complete Project Breakdown

## Project Overview

Implement a production-ready ONDC BAP (Beckn Application Platform) server in Rust with an integrated LLM-powered agent for natural language to ONDC/Beckn protocol conversion. The project includes:

- **Core ONDC BAP Server**: Cryptographic operations, site verification, and ONDC network participant onboarding
- **ONDC Agent**: LLM-powered natural language processing agent for converting user queries to ONDC/Beckn search requests
- **Integration Flow**: Natural language prompt → Intent extraction → Beckn-compliant JSON generation → ONDC /search API calls

### Current Implementation Goals

**Primary Flow**: `Enter Prompt` → `Parse Intent using LLM` → `Convert to Beckn Schema JSON` → `Call /search API`

**Technology Stack**:
- **LLM Integration**: `langchain-rust` library (forked: `https://github.com/Decentralised-Autonomous-Institutions/langchain-rust`)
- **LLM Provider**: Ollama with Gemma-3n model (`gemma3n:latest`) running locally
- **Protocol Specifications**: Beckn protocol specifications via Context7 (`https://context7.com/beckn/protocol-specifications`)
- **Architecture**: Hexagonal architecture with separate agent logic integrated into ONDC-BAP server

## Current Status

**ONDC BAP Core Server - COMPLETED** ✅

**ONDC Agent Phase 1 - COMPLETED** ✅

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

**Task 4.2.1 COMPLETED** ✅ - Site verification endpoint implementation

**Key Accomplishments:**
- ✅ **Site Verification Service**: Complete service with UUID generation and Ed25519 signing
- ✅ **Request ID Storage**: In-memory storage with TTL for request ID tracking
- ✅ **HTML Template Generation**: ONDC-compliant HTML with proper meta tags
- ✅ **Error Handling**: Comprehensive error handling and logging
- ✅ **Testing**: Unit tests and integration tests for all functionality
- ✅ **ONDC Compliance**: Ed25519 signing without hashing as per ONDC requirements

**Task 4.3.1 COMPLETED** ✅ - Challenge processing and on_subscribe endpoint implementation

**Key Accomplishments:**
- ✅ **AES-256-ECB Implementation**: Modern RustCrypto-based AES decryption
- ✅ **Challenge Service**: Complete challenge processing with X25519 key exchange
- ✅ **ONDC Public Key Management**: Environment-specific public keys (staging/preprod/prod)
- ✅ **Request Validation**: Comprehensive validation of on_subscribe requests
- ✅ **Error Handling**: Specific error types for challenge processing failures
- ✅ **Integration**: Full integration with existing key management and configuration systems
- ✅ **ONDC Compliance**: Exact implementation of ONDC challenge-response protocol

**CRITICAL GAP IDENTIFIED**: Registry client implementation still needed

**Next Phase**: Complete ONDC Agent LLM Integration (Phase 2 of Agent Implementation)

## ONDC Agent Implementation Status

### Phase 1: Agent Foundation - COMPLETED ✅

**Key Accomplishments:**
- ✅ **Crate Structure**: Complete ondc-agent crate with modular architecture
- ✅ **Core Models**: Intent and Beckn data models defined
- ✅ **Provider Traits**: LLM provider abstraction layer created
- ✅ **Configuration**: Multi-provider configuration system implemented
- ✅ **Error Handling**: Comprehensive error types and handling
- ✅ **Validation Framework**: Input and output validation interfaces
- ✅ **Async Architecture**: Full async support with Tokio integration

**Architecture Completed:**
- `agent/`: Core agent orchestration with ONDCAgent struct
- `chains/`: Intent and Beckn processing chain stubs
- `config/`: Provider and agent configuration management
- `models/`: Intent and BecknSearchRequest data structures
- `providers/`: LLM provider trait definitions
- `validation/`: Validation interfaces for input/output

### Phase 2: LLM Integration - IN PROGRESS 🚧

**Current Priority Tasks:**
- 🚧 **Task 2.1**: Add langchain-rust dependencies and basic LLM integration
- 🚧 **Task 2.2**: Implement Ollama provider with real API calls  
- 🚧 **Task 2.3**: Create LLM service layer with chain management

**Next Phases:**
- **Phase 3**: Build intent extraction system with prompt engineering
- **Phase 4**: Implement Beckn JSON generation with protocol compliance
- **Phase 5**: Integrate with ONDC-BAP server endpoints

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
- [x] **Task 2.2.4**: AES-256-ECB decryption (NEW)

### 2.3 ondc-crypto-formats Crate ✅
- [x] **Task 2.3.1**: Base64 encoding utilities
- [x] **Task 2.3.2**: Key format conversions

## Phase 3: BAP Server Core Implementation (Weeks 5-6)

### 3.1 Workspace Restructuring ✅
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

- [x] **Task 3.1.2**: Add web server dependencies ✅
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

### 3.2 Configuration Management ✅
- [x] **Task 3.2.1**: Environment configuration system ✅
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

- [x] **Task 3.2.2**: Key management system ✅
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

- [ ] **Task 3.3.2**: Domain layer implementation (DEFERRED - Phase 5)
  ```rust
  // Priority: Medium | Estimated: 1 day
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

## Phase 4: ONDC Protocol Implementation (Week 7) - UPDATED PRIORITY

### 4.1 ONDC Configuration Enhancement (CRITICAL) ✅
- [x] **Task 4.1.1**: Add ONDC-specific configuration ✅
  ```rust
  // Priority: Critical | Estimated: 0.5 days
  #[derive(Debug, Clone, Deserialize)]
  pub struct ONDCConfig {
      pub environment: Environment,
      pub registry_base_url: String,
      pub subscriber_id: String,
      pub callback_url: String,
      pub request_timeout_secs: u64,
      pub max_retries: usize,
  }
  
  #[derive(Debug, Clone, Deserialize, PartialEq)]
  pub enum Environment {
      Staging,
      PreProd,
      Production,
  }
  ```
  - [x] Add environment-specific registry URLs
  - [x] Add ONDC public keys for each environment
  - [x] Add subscriber ID and callback URL configuration
  - [x] Add request timeout and retry configuration
  - [x] Update configuration validation

### 4.2 Site Verification Implementation (CRITICAL) ✅
- [x] **Task 4.2.1**: Implement actual site verification endpoint ✅
  ```rust
  // Priority: Critical | Estimated: 1 day
  pub async fn serve_site_verification(
      State(state): State<AppState>,
  ) -> Result<Html<String>, AppError> {
      // Generate unique request_id
      let request_id = uuid::Uuid::new_v4().to_string();
      
      // Sign request_id using Ed25519 (without hashing)
      let signed_content = key_manager.sign_request_id(&request_id).await?;
      
      // Generate HTML content with signed verification
      let html_content = generate_verification_html(&signed_content);
      
      Ok(Html(html_content))
  }
  ```
  - [x] Generate unique request_id (UUID format) ✅
  - [x] Sign request_id using Ed25519 without hashing ✅
  - [x] Template HTML content generation with proper meta tag ✅
  - [x] Add proper content-type headers ✅
  - [x] Validate signature generation process ✅
  - [x] Store request_id for later verification ✅

### 4.3 Challenge Processing Implementation (CRITICAL) ✅
- [x] **Task 4.3.1**: Implement actual on-subscribe endpoint ✅
  ```rust
  // Priority: Critical | Estimated: 1.5 days
  pub async fn handle_on_subscribe(
      State(state): State<AppState>,
      Json(request): Json<OnSubscribeRequest>,
  ) -> Result<JsonResponse<OnSubscribeResponse>, AppError> {
      // Decode base64 encrypted challenge
      let encrypted_challenge = decode_signature(&request.challenge)?;
      
      // Generate X25519 shared secret with ONDC public key
      let shared_secret = key_manager.generate_shared_secret(ondc_public_key).await?;
      
      // Decrypt challenge using AES-256-ECB
      let decrypted_answer = aes_decrypt(&encrypted_challenge, &shared_secret)?;
      
      Ok(JsonResponse(OnSubscribeResponse {
          answer: decrypted_answer,
      }))
  }
  ```
  - [x] Implement X25519 shared secret generation with ONDC public key ✅
  - [x] Implement AES-256-ECB challenge decryption ✅
  - [x] Add proper error handling for crypto failures ✅
  - [x] Add comprehensive logging for debugging ✅
  - [x] Validate challenge format and length ✅
  - [x] Add timeout handling for crypto operations ✅

### 4.4 Registry Client Implementation (CRITICAL)
- [ ] **Task 4.4.1**: Create registry HTTP client
  ```rust
  // Priority: Critical | Estimated: 1.5 days
  pub struct RegistryClient {
      client: reqwest::Client,
      base_url: String,
      key_manager: Arc<KeyManagementService>,
      config: Arc<ONDCConfig>,
  }
  ```
  - [ ] Implement HTTP client for registry APIs
  - [ ] Add request/response serialization
  - [ ] Implement retry logic with exponential backoff
  - [ ] Add request signing for authenticated endpoints
  - [ ] Handle rate limiting (429 responses)
  - [ ] Add timeout and connection pooling

- [ ] **Task 4.4.2**: Implement subscribe API
  ```rust
  // Priority: Critical | Estimated: 1 day
  pub async fn subscribe(
      &self,
      payload: SubscriptionPayload,
  ) -> Result<SubscriptionResponse, RegistryError> {
      // POST to /subscribe endpoint
      // Handle different ops_no values (1, 2, 4)
      // Add payload validation and serialization
      // Handle various error responses
  }
  ```

  - [x] Support different ops_no values (1, 2, 4)
  - [x] Add payload validation and serialization
  - [x] Handle various error responses
  - [x] Add environment-specific URL handling
  - [x] Implement proper error mapping

- [ ] **Task 4.4.3**: Implement lookup API
  ```rust
  // Priority: Medium | Estimated: 1 day
  pub async fn lookup(
      &self,
      criteria: LookupCriteria,
  ) -> Result<Vec<Participant>, RegistryError> {
      // POST to /v2.0/lookup with authorization
      // Support legacy /lookup endpoint
      // Add request signing with HTTP signatures
  }
  ```
  - [ ] Implement `/v2.0/lookup` with authorization
  - [ ] Support legacy `/lookup` endpoint
  - [ ] Add request signing with HTTP signatures
  - [ ] Handle paginated responses
  - [ ] Cache lookup results appropriately

## Phase 5: Onboarding Service Implementation (Week 8) - NEW PRIORITY

### 5.1 Onboarding Service (CRITICAL)
- [ ] **Task 5.1.1**: Create onboarding orchestration service
  ```rust
  // Priority: Critical | Estimated: 2 days
  pub struct OnboardingService {
      registry_client: Arc<RegistryClient>,
      key_manager: Arc<KeyManagementService>,
      config: Arc<ONDCConfig>,
  }
  ```
  - [ ] Orchestrate complete onboarding flow
  - [ ] Validate prerequisites (domain, SSL, whitelisting)
  - [ ] Handle onboarding state management
  - [ ] Add retry mechanisms for failed steps
  - [ ] Provide detailed progress reporting
  - [ ] Implement proper error handling and recovery

- [ ] **Task 5.1.2**: Implement registration status tracking
  ```rust
  // Priority: Medium | Estimated: 1 day
  pub async fn check_registration_status(
      &self,
  ) -> Result<RegistrationStatus, ServiceError> {
      // Check current registration status
      // Add lookup verification
      // Track registration across environments
  }
  ```
  - [ ] Implement registration status checking
  - [ ] Add lookup verification
  - [ ] Track registration across environments
  - [ ] Provide registration health monitoring
  - [ ] Add alerts for registration issues

### 5.2 Domain Layer Implementation (DEFERRED FROM PHASE 3)
- [ ] **Task 5.2.1**: Define core domain entities
  ```rust
  // Priority: Medium | Estimated: 1 day
  pub struct SubscriberInfo {
      pub subscriber_id: String,
      pub signing_public_key: String,
      pub encryption_public_key: String,
      pub unique_key_id: String,
      pub status: RegistrationStatus,
  }
  
  pub struct Challenge {
      pub encrypted_data: Vec<u8>,
      pub subscriber_id: String,
      pub timestamp: DateTime<Utc>,
  }
  
  pub struct Registration {
      pub subscriber_info: SubscriberInfo,
      pub request_id: String,
      pub status: RegistrationStatus,
      pub created_at: DateTime<Utc>,
  }
  ```
  - [ ] Define core domain entities (Subscriber, Challenge, Registration)
  - [ ] Implement business rules validation
  - [ ] Add domain services for key operations
  - [ ] Create value objects with validation
  - [ ] Document domain boundaries and invariants

## Phase 6: Administrative API Implementation (Week 9)

### 6.1 Administrative Endpoints
- [ ] **Task 6.1.1**: Implement admin registration endpoint
  ```rust
  // Priority: High | Estimated: 1.5 days
  pub async fn admin_register(
      State(app_state): State<AppState>,
      Json(request): Json<RegisterRequest>,
  ) -> Result<Json<RegisterResponse>, AppError> {
      // Administrative registration endpoint
      // Validate admin request
      // Process registration through onboarding service
      // Return registration status
  }
  ```
  - [ ] Implement administrative registration endpoint
  - [ ] Add configuration update endpoints
  - [ ] Implement key rotation endpoints
  - [ ] Add status and health monitoring APIs
  - [ ] Secure admin endpoints with authentication
  - [ ] Add request validation and error handling

- [ ] **Task 6.1.2**: Implement public API endpoints
  ```rust
  // Priority: Medium | Estimated: 1 day
  pub async fn get_participant_info(
      State(app_state): State<AppState>,
  ) -> Result<Json<ParticipantInfo>, AppError> {
      // Public participant information
      // Return current registration status
      // Include public keys and metadata
  }
  ```
  - [ ] Implement public participant info endpoint
  - [ ] Add registry lookup proxy endpoints
  - [ ] Implement status check endpoints
  - [ ] Add CORS support for web clients
  - [ ] Document API specifications

### 6.2 Error Handling and Middleware Enhancement
- [ ] **Task 6.2.1**: Enhance error handling system
  ```rust
  // Priority: High | Estimated: 1 day
  #[derive(Error, Debug)]
  pub enum AppError {
      #[error("Registry error: {0}")]
      Registry(#[from] RegistryError),
      #[error("Crypto error: {0}")]
      Crypto(#[from] ONDCCryptoError),
      #[error("Onboarding error: {0}")]
      Onboarding(#[from] OnboardingError),
      #[error("Validation error: {0}")]
      Validation(String),
      #[error("Configuration error: {0}")]
      Config(#[from] ConfigError),
  }
  ```
  - [ ] Implement comprehensive error handling
  - [ ] Add structured error responses
  - [ ] Implement error logging and monitoring
  - [ ] Add user-friendly error messages
  - [ ] Handle different error types appropriately

## Phase 7: Testing and Quality (Week 10)

### 7.1 Integration Testing
- [ ] **Task 7.1.1**: ONDC protocol integration tests
  ```rust
  // Priority: High | Estimated: 2 days
  #[tokio::test]
  async fn test_ondc_onboarding_flow() {
      // Test complete onboarding workflow
      // Test site verification generation
      // Test challenge processing
      // Test registry API interactions
  }
  ```
  - [ ] Test complete onboarding workflow
  - [ ] Test site verification generation and signing
  - [ ] Test challenge decryption with X25519 + AES-256-ECB
  - [ ] Test registry API interactions
  - [ ] Test key management operations
  - [ ] Test error handling scenarios

- [ ] **Task 7.1.2**: Mock registry testing
  ```rust
  // Priority: Medium | Estimated: 1 day
  pub struct MockRegistryServer {
      // Mock server for testing
      // Simulate ONDC registry responses
      // Test error scenarios
  }
  ```
  - [ ] Implement mock registry server
  - [ ] Test against mock registry responses
  - [ ] Add chaos testing for resilience
  - [ ] Test network failure scenarios
  - [ ] Validate retry and recovery mechanisms

### 7.2 Security Testing
- [ ] **Task 7.2.1**: ONDC-specific security validation
  ```rust
  // Priority: High | Estimated: 1 day
  #[test]
  fn test_ondc_crypto_security() {
      // Validate Ed25519 signing without hashing
      // Test X25519 key exchange security
      // Validate AES-256-ECB decryption
      // Test against timing attacks
  }
  ```
  - [ ] Test Ed25519 signing without hashing (ONDC requirement)
  - [ ] Validate X25519 key exchange security
  - [ ] Test AES-256-ECB challenge decryption
  - [ ] Test against timing attacks
  - [ ] Add TLS/SSL configuration testing
  - [ ] Perform security audit

## Phase 8: Documentation and Deployment (Week 11)

### 8.1 ONDC-Specific Documentation
- [ ] **Task 8.1.1**: ONDC integration documentation
  - [ ] Create ONDC onboarding tutorial
  - [ ] Document environment setup for staging/preprod/prod
  - [ ] Add key generation and configuration guides
  - [ ] Document error handling and troubleshooting
  - [ ] Create API specifications for ONDC endpoints

- [ ] **Task 8.1.2**: Deployment guides
  - [ ] Create Docker containers for ONDC environments
  - [ ] Add Kubernetes deployment manifests
  - [ ] Configure monitoring and alerting
  - [ ] Add log aggregation
  - [ ] Create operational runbooks

### 8.2 Production Readiness
- [ ] **Task 8.2.1**: Production deployment preparation
  ```dockerfile
  # Priority: Medium | Estimated: 1 day
  FROM rust:1.70 as builder
  WORKDIR /app
  COPY . .
  RUN cargo build --release
  ```
  - [ ] Create production-ready Docker containers
  - [ ] Add Kubernetes deployment manifests
  - [ ] Configure monitoring and alerting
  - [ ] Add log aggregation
  - [ ] Create operational runbooks

## Updated Timeline and Critical Path

**Total Duration**: 11 weeks (unchanged)
**Critical Path Dependencies**: Updated for ONDC compliance

### Critical Path Dependencies (Updated)
1. **Phase 4.4** → **Phase 5.1** (Registry client → Onboarding service)
2. **Phase 5.1** → **Phase 6.1** (Onboarding service → Admin API)
3. **Phase 6.1** → **Phase 7.1** (Admin API → Testing)
4. **Phase 7.1** → **Phase 8.1** (Testing → Documentation)

### Risk Mitigation (Updated)
- **ONDC Protocol Compliance**: Regular validation against official specifications
- **Crypto Implementation**: Comprehensive testing of Ed25519/X25519/AES operations
- **Registry Integration**: Mock testing and error handling for all scenarios
- **Security Vulnerabilities**: Regular security audits focusing on ONDC requirements
- **Performance Issues**: Load testing with ONDC rate limits in mind
- **Deployment Complexity**: Containerization and automation for multiple environments

### Success Criteria (Updated)
- ✅ **ONDC Onboarding Compliance**: Server can successfully onboard as Network Participant
- ✅ **Protocol Implementation**: All required ONDC endpoints implemented correctly
- ✅ **Crypto Security**: Ed25519/X25519/AES operations meet ONDC standards
- ✅ **Registry Integration**: Full compliance with ONDC registry APIs
- ✅ **Production Ready**: Secure, scalable, and maintainable implementation

## ONDC Agent Detailed Implementation Plan

### Phase 1: Agent Foundation ✅ COMPLETED
- [x] **Task 1.1**: Initialize ondc-agent crate structure with workspace integration
- [x] **Task 1.2**: Define core data models (Intent, BecknSearchRequest)
- [x] **Task 1.3**: Create provider abstraction layer with LLMProvider trait
- [x] **Task 1.4**: Implement configuration management for multi-provider support
- [x] **Task 1.5**: Design error handling system with comprehensive error types
- [x] **Task 1.6**: Create validation framework interfaces

### Phase 2: LLM Integration (Current Priority) 🚧
- [ ] **Task 2.1**: Add langchain-rust dependencies and basic LLM integration
  ```toml
  # Priority: Critical | Estimated: 0.5 days
  langchain-rust = { git = "https://github.com/Decentralised-Autonomous-Institutions/langchain-rust", branch = "main" }
  ```
  - [ ] Update Cargo.toml with langchain-rust dependency
  - [ ] Add LLM-specific configuration structures
  - [ ] Create basic LLM client initialization
  - [ ] Add timeout and retry configuration

- [ ] **Task 2.2**: Implement Ollama provider with real API calls
  ```rust
  // Priority: Critical | Estimated: 1.5 days
  pub struct OllamaProvider {
      client: reqwest::Client,
      base_url: String,
      model_name: String,
      config: OllamaConfig,
  }
  ```
  - [ ] Implement concrete OllamaProvider struct
  - [ ] Add HTTP client for Ollama API communication
  - [ ] Implement model loading and health checks
  - [ ] Add streaming and non-streaming response handling
  - [ ] Implement proper error handling and retries

- [ ] **Task 2.3**: Create LLM service layer with chain management
  ```rust
  // Priority: Critical | Estimated: 1 day
  pub struct LLMService {
      provider: Arc<dyn LLMProvider>,
      intent_chain: IntentExtractionChain,
      beckn_chain: BecknGenerationChain,
  }
  ```
  - [ ] Create LLM service abstraction layer
  - [ ] Implement chain management for sequential operations
  - [ ] Add chain result validation and error handling
  - [ ] Create prompt template management system

### Phase 3: Intent Extraction System
- [ ] **Task 3.1**: Develop intent extraction prompts and few-shot examples
  ```rust
  // Priority: High | Estimated: 2 days
  pub struct IntentExtractionChain {
      prompt_template: PromptTemplate,
      few_shot_examples: Vec<IntentExample>,
      confidence_threshold: f32,
  }
  ```
  - [ ] Create e-commerce intent prompt templates
  - [ ] Add few-shot learning examples for various query types
  - [ ] Implement confidence scoring mechanism
  - [ ] Add location, category, and price range extraction

- [ ] **Task 3.2**: Implement intent validation and post-processing
  ```rust
  // Priority: High | Estimated: 1 day
  pub struct IntentValidator {
      // Validation rules for extracted intents
      // Confidence threshold checking
      // Required field validation
  }
  ```
  - [ ] Add comprehensive intent validation rules
  - [ ] Implement confidence threshold enforcement
  - [ ] Create intent enrichment and normalization
  - [ ] Add intent debugging and logging

### Phase 4: Beckn JSON Generation
- [ ] **Task 4.1**: Implement Beckn request generation with protocol compliance
  ```rust
  // Priority: High | Estimated: 2 days
  pub struct BecknGenerationChain {
      beckn_template: BecknTemplate,
      context_generator: ContextGenerator,
      message_builder: MessageBuilder,
  }
  ```
  - [ ] Create Beckn protocol-compliant JSON templates
  - [ ] Implement context generation (transaction_id, message_id, etc.)
  - [ ] Add intent-to-Beckn field mapping
  - [ ] Implement location and category code mapping

- [ ] **Task 4.2**: Add Beckn validation and schema compliance
  ```rust
  // Priority: High | Estimated: 1 day
  pub struct BecknValidator {
      // Schema validation for Beckn requests
      // Protocol compliance checking
      // Required field validation
  }
  ```
  - [ ] Implement Beckn schema validation
  - [ ] Add protocol compliance checks
  - [ ] Create Beckn request debugging tools
  - [ ] Add comprehensive error reporting

### Phase 5: ONDC-BAP Server Integration
- [ ] **Task 5.1**: Integrate ONDC Agent with BAP server
  ```rust
  // Priority: High | Estimated: 1.5 days
  pub struct AgentIntegrationService {
      agent: Arc<ONDCAgent>,
      bap_config: Arc<BAPConfig>,
      registry_client: Arc<RegistryClient>,
  }
  ```
  - [ ] Create agent integration service in ONDC-BAP server
  - [ ] Add natural language query endpoint (`/query` or `/nl-search`)
  - [ ] Implement end-to-end flow: NL → Intent → Beckn → Search
  - [ ] Add proper error handling and response formatting

- [ ] **Task 5.2**: Add search API integration and response handling
  ```rust
  // Priority: High | Estimated: 1 day
  pub async fn process_natural_language_query(
      query: String,
  ) -> Result<SearchResponse, AgentError> {
      // NL → Intent → Beckn → ONDC Search → Response
  }
  ```
  - [ ] Implement ONDC search API calls with generated Beckn requests
  - [ ] Add search response processing and formatting
  - [ ] Create user-friendly response structures
  - [ ] Add search result caching and optimization

### Phase 6: Advanced Features and Optimization
- [ ] **Task 6.1**: Add conversation context and memory
  ```rust
  // Priority: Medium | Estimated: 1.5 days  
  pub struct ConversationMemory {
      context: ConversationContext,
      history: Vec<QueryResult>,
      preferences: UserPreferences,
  }
  ```
  - [ ] Implement conversation context management
  - [ ] Add user preference learning
  - [ ] Create query refinement capabilities
  - [ ] Add multi-turn conversation support

- [ ] **Task 6.2**: Performance optimization and caching
  ```rust
  // Priority: Medium | Estimated: 1 day
  pub struct AgentCache {
      intent_cache: LRUCache<String, Intent>,
      beckn_cache: LRUCache<Intent, BecknSearchRequest>,
      model_cache: ModelCache,
  }
  ```
  - [ ] Add intelligent caching for intents and Beckn requests
  - [ ] Implement LLM response caching
  - [ ] Add performance monitoring and metrics
  - [ ] Optimize prompt engineering for speed

### Phase 7: Testing and Validation
- [ ] **Task 7.1**: Comprehensive testing suite
  ```rust
  // Priority: High | Estimated: 2 days
  #[tokio::test]
  async fn test_end_to_end_agent_flow() {
      // Test: NL query → Intent extraction → Beckn generation → Validation
  }
  ```
  - [ ] Create end-to-end integration tests
  - [ ] Add unit tests for all components
  - [ ] Implement mock LLM provider for testing
  - [ ] Add property-based testing with proptest

- [ ] **Task 7.2**: Agent performance and accuracy testing
  ```rust
  // Priority: High | Estimated: 1.5 days
  pub struct AgentBenchmark {
      test_queries: Vec<TestQuery>,
      accuracy_metrics: AccuracyMetrics,
      performance_metrics: PerformanceMetrics,
  }
  ```
  - [ ] Create comprehensive test query dataset
  - [ ] Implement accuracy measurement tools
  - [ ] Add performance benchmarking
  - [ ] Create automated quality assurance

### Phase 8: Documentation and Production Readiness
- [ ] **Task 8.1**: Agent documentation and examples
  - [ ] Create comprehensive agent usage documentation
  - [ ] Add example queries and expected outputs
  - [ ] Document configuration and deployment
  - [ ] Create troubleshooting guides

- [ ] **Task 8.2**: Production deployment configuration
  - [ ] Add agent-specific configuration for different environments
  - [ ] Create Docker support for agent deployment
  - [ ] Add monitoring and alerting for agent operations
  - [ ] Implement agent health checks and metrics

## Updated Success Criteria

### ONDC BAP Server Success Criteria ✅
- ✅ **ONDC Onboarding Compliance**: Server can successfully onboard as Network Participant
- ✅ **Protocol Implementation**: All required ONDC endpoints implemented correctly
- ✅ **Crypto Security**: Ed25519/X25519/AES operations meet ONDC standards
- ✅ **Registry Integration**: Full compliance with ONDC registry APIs
- ✅ **Production Ready**: Secure, scalable, and maintainable implementation

### ONDC Agent Success Criteria (New)
- [ ] **Natural Language Processing**: Accurate intent extraction from diverse e-commerce queries
- [ ] **Beckn Protocol Compliance**: Generated JSON requests fully compliant with Beckn standards
- [ ] **LLM Integration**: Reliable integration with Ollama and Gemma-3n model
- [ ] **End-to-End Flow**: Complete NL → Intent → Beckn → Search → Response pipeline
- [ ] **Production Performance**: Sub-2-second response times for typical queries
- [ ] **Accuracy Metrics**: >85% intent extraction accuracy on test dataset

This integrated approach ensures both the ONDC BAP server compliance and sophisticated natural language query processing capabilities.