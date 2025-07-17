# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an ONDC (Open Network for Digital Commerce) BAP (Beckn Application Platform) server implementation in Rust. The project provides a production-ready server for onboarding as a Network Participant in the ONDC ecosystem, handling cryptographic operations, site verification, and challenge-response authentication.

## Build and Development Commands

### Primary Build Commands
```bash
# Build all crates in release mode
make build
# or
cargo build --release --all-targets --all-features

# Build in debug mode
make build-dev
# or
cargo build --all-targets --all-features

# Check compilation
make check
# or
cargo check --all-targets --all-features
```

### Testing Commands
```bash
# Run all tests
make test
# or
cargo test --all-targets --all-features

# Run tests in release mode
make test-release
# or
cargo test --release --all-targets --all-features

# Run tests with coverage
make test-coverage
```

### Code Quality Commands
```bash
# Format code
make fmt
# or
cargo fmt --all

# Check formatting
make fmt-check
# or
cargo fmt --all -- --check

# Run linter
make clippy
# or
cargo clippy --all-targets --all-features -- -D warnings

# Security audit
make audit
# or
cargo audit
```

### Development Workflow
```bash
# Quick development cycle
make dev  # runs fmt, clippy, test

# Pre-commit checks
make pre-commit  # runs fmt, clippy, test

# CI checks
make ci  # runs fmt-check, clippy, test, audit
```

### Running the Server
```bash
# Run with staging configuration
make run-staging
# or
cd ondc-bap && ONDC_ENV=staging cargo run

# Run with production configuration
make run-production
# or
cd ondc-bap && ONDC_ENV=production cargo run
```

## Architecture Overview

This is a Rust workspace with 5 crates following a layered architecture:

### Crate Structure
- **`ondc-bap/`**: Main BAP server application (Axum web server)
- **`ondc-crypto-traits/`**: Core traits and error types for cryptographic operations
- **`ondc-crypto-algorithms/`**: Cryptographic implementations (Ed25519, X25519, AES-256-ECB, Blake2)
- **`ondc-crypto-formats/`**: Encoding utilities (Base64, key format conversions)
- **`ondc-crypto-cli/`**: Command-line utilities for key generation and testing

### Main Application Architecture (ondc-bap)
- **Presentation Layer**: Axum HTTP server with comprehensive middleware stack
  - Routes: Health checks, ONDC protocol endpoints, administrative endpoints
  - Middleware: CORS, security headers, rate limiting, logging, error handling
- **Services Layer**: Business logic for ONDC operations
  - `ChallengeService`: Challenge-response authentication
  - `KeyManagementService`: Cryptographic key management
  - `RegistryClient`: ONDC registry API integration
  - `SiteVerificationService`: Site verification page generation
- **Infrastructure Layer**: Configuration, logging, external integrations
- **Config Layer**: Environment-specific configuration management

### Key Endpoints
- `/health`, `/ready`, `/live`: Health and readiness checks
- `/ondc-site-verification.html`: ONDC site verification with Ed25519 signatures
- `/on_subscribe`: Challenge-response authentication endpoint
- `/admin/register`: Administrative registration endpoint
- `/admin/subscribe`: Registry subscription endpoint

## Development Guidelines

### Mandatory File Reads Before Code Changes
Always read these files before making any changes:
1. `docs/architecture.mermaid`: System architecture and data flows
2. `docs/technical.md`: Technical specifications and security requirements
3. `docs/status.md`: Current implementation progress
4. `Cargo.toml`: Dependencies and workspace configuration

### Security-First Development
- Use `Result<T, E>` for all fallible operations
- Apply `#[derive(Zeroize)]` for sensitive data structures
- Use `subtle` crate for constant-time operations
- Implement comprehensive error handling with `thiserror`
- Use `zeroize::Zeroizing` for temporary sensitive data

### Code Quality Standards
- Follow trait-based design patterns
- Use type safety to prevent misuse (newtypes)
- Write comprehensive tests (unit, integration, property-based with `proptest`)
- Maintain rustdoc documentation with security warnings
- Zero compiler warnings and clippy issues

### Configuration Management
- Environment-specific configs in `ondc-bap/config/`
- Use `ONDC_ENV` environment variable for config selection
- Support for staging and production environments
- Figment-based configuration with TOML and environment variable support

### Task Management Workflow
1. Check `docs/status.md` for current progress and pending tasks
2. Verify architectural compliance with `docs/architecture.mermaid`
3. Follow security patterns from `docs/technical.md`
4. Update `docs/status.md` after completing tasks
5. Run full test suite before considering tasks complete

## Important Notes

- This is a cryptographic security project requiring careful attention to security best practices
- All cryptographic operations must be constant-time and resistant to timing attacks
- The project implements ONDC protocol compliance with specific requirements for Ed25519 signing and X25519 key exchange
- Configuration files contain sensitive cryptographic keys and should be handled securely
- The server supports TLS and includes comprehensive middleware for production deployment

## Key Dependencies

- **Web Framework**: Axum with Tower middleware
- **Cryptography**: ed25519-dalek, x25519-dalek, aes, blake2b_simd
- **Async Runtime**: Tokio
- **Configuration**: Figment with TOML support
- **Error Handling**: thiserror, anyhow
- **Security**: zeroize, subtle
- **Testing**: proptest for property-based testing

## Documentation

Comprehensive documentation is available in the `docs/` directory:
- Technical implementation details
- System architecture diagrams
- ONDC onboarding procedures
- Development environment setup