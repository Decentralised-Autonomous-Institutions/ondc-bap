# ONDC BAP Server

A production-ready ONDC BAP (Beckn Application Platform) server implementation in Rust that handles ONDC network participant onboarding and provides required endpoints for registry integration.

## Features

- **ONDC Protocol Compliance**: Full implementation of ONDC registry APIs
- **Cryptographic Security**: Built on secure crypto foundation using Ed25519 and X25519
- **Production Ready**: Comprehensive logging, monitoring, and error handling
- **Layered Architecture**: Clean separation of concerns with Axum web framework
- **Configuration Management**: Environment-specific configuration with validation
- **Security First**: TLS/HTTPS support, rate limiting, and input validation

## Quick Start

### Prerequisites

- Rust 1.70 or later
- Valid ONDC cryptographic keys (Ed25519 signing, X25519 encryption)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd ondc-crypto

# Build the BAP server
cargo build --package ondc-bap

# Run the server
cargo run --package ondc-bap
```

### Configuration

1. Copy the configuration template:
```bash
cp ondc-bap/config/staging.toml ondc-bap/config/your-env.toml
```

2. Update the configuration with your settings:
```toml
[ondc]
subscriber_id = "your-domain.com"

[keys]
signing_private_key = "your-base64-encoded-signing-key"
encryption_private_key = "your-base64-encoded-encryption-key"
unique_key_id = "your-key-id"
```

3. Set the environment:
```bash
export ONDC_ENV=your-env
```

### Usage

```rust
use ondc_bap::BAPServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = BAPServer::new().await?;
    server.run().await?;
    Ok(())
}
```

## Architecture

The BAP server follows a layered architecture:

```
┌─────────────────────────────────────┐
│           Presentation Layer        │
│         (Axum HTTP Server)          │
├─────────────────────────────────────┤
│           Services Layer            │
│    (Onboarding, Key Management)     │
├─────────────────────────────────────┤
│           Domain Layer              │
│      (Business Entities & Rules)    │
├─────────────────────────────────────┤
│        Infrastructure Layer         │
│     (HTTP Client, File Storage)     │
├─────────────────────────────────────┤
│         Crypto Foundation           │
│    (Ed25519, X25519, Base64)        │
└─────────────────────────────────────┘
```

## API Endpoints

### ONDC Protocol Endpoints

- `GET /ondc-site-verification.html` - Site verification page
- `POST /on_subscribe` - Challenge-response endpoint

### Administrative Endpoints

- `POST /admin/register` - Initiate registration
- `GET /admin/status` - Check registration status
- `GET /health` - Health check

## Development

### Building

```bash
# Build all crates
cargo build

# Build only BAP server
cargo build --package ondc-bap

# Build with optimizations
cargo build --release --package ondc-bap
```

### Testing

```bash
# Run all tests
cargo test

# Run BAP server tests
cargo test --package ondc-bap

# Run integration tests
cargo test --test integration_tests
```

### Documentation

```bash
# Generate documentation
cargo doc --package ondc-bap --open
```

## Configuration Reference

### Server Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | String | "0.0.0.0" | Server host address |
| `port` | u16 | 8080 | Server port |
| `tls` | Optional | None | TLS configuration |
| `request_timeout_secs` | u64 | 30 | Request timeout |
| `max_connections` | usize | 1000 | Max concurrent connections |

### ONDC Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `environment` | Environment | staging | ONDC environment |
| `registry_base_url` | String | - | Registry API URL |
| `subscriber_id` | String | - | Your domain/subscriber ID |
| `callback_url` | String | "/" | Callback URL path |
| `request_timeout_secs` | u64 | 30 | Registry request timeout |
| `max_retries` | usize | 3 | Max retry attempts |

### Key Configuration

| Field | Type | Description |
|-------|------|-------------|
| `signing_private_key` | String | Base64 encoded Ed25519 private key |
| `encryption_private_key` | String | Base64 encoded X25519 private key |
| `unique_key_id` | String | Unique identifier for the key pair |

## Security Considerations

- All private keys are automatically zeroized when dropped
- TLS/HTTPS is required for production deployments
- Rate limiting is enabled by default
- Input validation is performed on all endpoints
- Cryptographic operations use constant-time algorithms

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option. 