# ONDC BAP Server - Network Participant Implementation

[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![ONDC](https://img.shields.io/badge/ONDC-Network%20Participant-orange.svg)](https://ondc.org/)

A production-ready ONDC BAP (Beckn Application Platform) server implementation in Rust, designed to onboard as a Network Participant in the ONDC (Open Network for Digital Commerce) ecosystem. This server provides all required endpoints for ONDC registry integration and participant onboarding.

## 🎯 Project Goal

**Primary Objective**: Successfully onboard as a Network Participant in the ONDC ecosystem by implementing a compliant BAP server that can:

- ✅ Generate and serve site verification pages with Ed25519 signatures
- ✅ Process ONDC challenge-response authentication via X25519 key exchange and AES-256-ECB decryption
- 🔄 Register with ONDC registry using `/subscribe` API
- 🔄 Support all participant types (Buyer App, Seller App, Buyer & Seller App)
- 🔄 Provide administrative endpoints for registration management

## 🚀 Current Status

**Phase 2 - Crypto Foundation**: ✅ **COMPLETED**
- Ed25519 signing and verification with ONDC compliance
- X25519 key exchange with secure key handling
- AES-256-ECB decryption for challenge processing
- Base64 encoding utilities and key format conversions

**Phase 3 - BAP Server Core**: ✅ **COMPLETED**
- Axum web server with production-ready middleware stack
- Site verification endpoint (`/ondc-site-verification.html`)
- Challenge processing endpoint (`/on_subscribe`)
- Comprehensive configuration management
- Security headers, rate limiting, and error handling

**Phase 4 - ONDC Protocol**: 🚧 **IN PROGRESS**
- ✅ Site verification implementation
- ✅ Challenge processing implementation
- 🔄 Registry client implementation (Next)
- 🔄 Onboarding service orchestration

## 📦 Installation

### Prerequisites

1. **Domain Name**: Valid FQDN for your Network Participant
2. **SSL Certificate**: Valid SSL certificate for your domain
3. **ONDC Whitelisting**: Approval from ONDC for your subscriber_id
4. **Rust Environment**: Rust 1.70+ with Cargo

### Quick Start

```bash
# Clone the repository
git clone https://github.com/your-username/ondc-bap-server.git
cd ondc-bap-server

# Build the project
cargo build --release

# Run with staging configuration
ONDC_ENV=staging cargo run --bin ondc-bap
```

### Configuration

Create environment-specific configuration files:

```toml
# config/staging.toml
[server]
host = "0.0.0.0"
port = 8080

[ondc]
environment = "staging"
subscriber_id = "your-domain.com"
callback_url = "/ondc"

[keys]
signing_private_key = "base64-encoded-ed25519-private-key"
encryption_private_key = "base64-encoded-x25519-private-key"
unique_key_id = "key-1"
```

## 🏗️ Architecture

The project follows a layered architecture with modular crates:

```
ondc-bap/                           # Main BAP server
├── ondc-crypto-traits/            # Core traits and error types
├── ondc-crypto-algorithms/        # Cryptographic implementations
├── ondc-crypto-formats/           # Encoding and format utilities
└── ondc-crypto-cli/               # Command-line utilities
```

### Key Components

- **Presentation Layer**: Axum HTTP server with middleware stack
- **Services Layer**: Business logic for onboarding and challenge processing
- **Infrastructure Layer**: Configuration, logging, and external integrations
- **Crypto Foundation**: Secure cryptographic operations for ONDC compliance

## 🔐 ONDC Compliance Features

### 1. Site Verification
```rust
// Generates ONDC-compliant site verification page
GET /ondc-site-verification.html
```

**Features**:
- ✅ Unique request ID generation (UUID format)
- ✅ Ed25519 signing without hashing (ONDC requirement)
- ✅ Proper HTML meta tag format
- ✅ Request ID storage with TTL

### 2. Challenge Processing
```rust
// Processes ONDC challenge-response authentication
POST /on_subscribe
{
  "subscriber_id": "your-domain.com",
  "challenge": "base64-encoded-encrypted-challenge"
}
```

**Features**:
- ✅ X25519 key exchange with ONDC public keys
- ✅ AES-256-ECB challenge decryption
- ✅ Environment-specific ONDC public keys
- ✅ Comprehensive error handling and validation

### 3. Registry Integration (In Progress)
```rust
// Registry client for ONDC API integration
POST /subscribe  // Participant registration
POST /v2.0/lookup  // Participant lookup
```

**Planned Features**:
- 🔄 HTTP signature generation for authenticated requests
- 🔄 Retry logic with exponential backoff
- 🔄 Rate limiting compliance
- 🔄 Environment-specific registry URLs

## 🛡️ Security Features

- **Memory Safety**: Automatic zeroization of sensitive data
- **Cryptographic Security**: Ed25519/X25519/AES-256-ECB operations
- **Input Validation**: Comprehensive request validation
- **Rate Limiting**: Per-IP adaptive rate limiting
- **Security Headers**: Production-ready security middleware
- **TLS Support**: HTTPS configuration for production

## 📚 Documentation

- **[Technical Guide](docs/technical.md)** - Implementation details and patterns
- **[Architecture](docs/architecture.mermaid)** - System design and data flows
- **[Project Status](docs/status.md)** - Implementation progress and roadmap
- **[ONDC Onboarding Guide](docs/Onboarding%20of%20Participants.md)** - ONDC-specific requirements

## 🔧 Development

### Building

```bash
# Build all crates
cargo build

# Build with optimizations
cargo build --release

# Run tests
cargo test

# Check code quality
cargo clippy
cargo fmt
```

### Configuration Management

```bash
# Development environment
ONDC_ENV=staging cargo run

# Production environment
ONDC_ENV=production cargo run --release

# Custom configuration
ONDC_SUBSCRIBER_ID=your-domain.com cargo run
```

### Key Generation

Use the provided CLI utilities for key generation:

```bash
# Generate Ed25519 signing key pair
cargo run --bin ondc-crypto-cli -- generate-signing-keys

# Generate X25519 encryption key pair
cargo run --bin ondc-crypto-cli -- generate-encryption-keys

# Convert key formats
cargo run --bin ondc-crypto-cli -- convert-key-format
```

## 🚀 Deployment

### Docker Deployment

```dockerfile
# Multi-stage build for production
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
COPY --from=builder /app/target/release/ondc-bap /usr/local/bin/
EXPOSE 8080
CMD ["ondc-bap"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ondc-bap-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ondc-bap-server
  template:
    metadata:
      labels:
        app: ondc-bap-server
    spec:
      containers:
      - name: ondc-bap
        image: ondc-bap-server:latest
        ports:
        - containerPort: 8080
        env:
        - name: ONDC_ENV
          value: "production"
```

## 🔍 Monitoring and Observability

- **Health Checks**: `/health` endpoint for system status
- **Metrics**: Prometheus-style metrics collection
- **Logging**: Structured logging with tracing
- **Error Tracking**: Comprehensive error handling and reporting

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and ensure they pass
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📄 License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

## 🙏 Acknowledgments

- [ONDC](https://ondc.org/) for the specification and protocol
- [Beckn Protocol](https://becknprotocol.io/) for the underlying protocol
- [Rust Crypto](https://github.com/RustCrypto) for cryptographic implementations
- [Axum](https://github.com/tokio-rs/axum) for the web framework

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-username/ondc-bap-server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-username/ondc-bap-server/discussions)
- **ONDC Support**: techsupport@ondc.org

## 🗺️ Roadmap

See our [Project Status](docs/status.md) for detailed implementation progress.

### Next Milestones

- [ ] Registry client implementation
- [ ] Onboarding service orchestration
- [ ] Administrative API endpoints
- [ ] Integration testing with ONDC environments
- [ ] Production deployment guides

---

**Note**: This project is designed to help organizations successfully onboard as Network Participants in the ONDC ecosystem. The implementation follows ONDC specifications and best practices for secure, scalable, and maintainable BAP server development. 