# ONDC Crypto SDK for Rust

[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/ondc-crypto)](https://crates.io/crates/ondc-crypto)
[![Documentation](https://img.shields.io/badge/docs-latest-blue.svg)](https://docs.rs/ondc-crypto)

A production-ready cryptographic SDK for the Open Network for Digital Commerce (ONDC) platform, implemented in Rust with a focus on security, performance, and developer experience.

## 🚀 Features

- **🔐 Ed25519 Digital Signatures**: Secure signing and verification using Ed25519
- **🏃 BLAKE2 Hashing**: Fast and secure hashing with BLAKE2b-512
- **🌐 HTTP Signature Support**: ONDC-compliant HTTP authorization headers
- **🔄 X25519 Key Exchange**: Elliptic curve Diffie-Hellman key exchange
- **🛡️ Memory Safety**: Automatic zeroization of sensitive data
- **⚡ High Performance**: Zero-cost abstractions and SIMD optimizations
- **🔧 Developer Friendly**: Comprehensive error handling and documentation

## 📦 Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
ondc-crypto = "0.1.0"
```

Or install specific crates for modular usage:

```toml
[dependencies]
ondc-crypto-traits = "0.1.0"      # Core traits and error types
ondc-crypto-algorithms = "0.1.0"  # Cryptographic implementations
ondc-crypto-http = "0.1.0"        # HTTP signature handling
ondc-crypto-formats = "0.1.0"     # Encoding and format utilities
ondc-crypto-utils = "0.1.0"       # Helper utilities
```

## 🎯 Quick Start

### Basic Usage

```rust
use ondc_crypto::ONDCCrypto;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize with your private key
    let private_key = b"your-32-byte-private-key-here...";
    let crypto = ONDCCrypto::new(private_key)?;
    
    // Create authorization header for ONDC request
    let request_body = br#"{"context": {"action": "search"}}"#;
    let subscriber_id = "your.subscriber.id";
    let unique_key_id = "your-unique-key-id";
    
    let auth_header = crypto.create_authorization_header(
        request_body,
        subscriber_id,
        unique_key_id,
    )?;
    
    println!("Authorization: {}", auth_header);
    Ok(())
}
```

### Verification

```rust
use ondc_crypto::ONDCCrypto;

fn verify_request() -> Result<(), Box<dyn std::error::Error>> {
    let crypto = ONDCCrypto::new(&[0u8; 32])?; // Dummy key for verification
    
    let auth_header = r#"Signature keyId="subscriber|key|ed25519",algorithm="ed25519",created="1234567890",expires="1234567890",headers="(created) (expires) digest",signature="base64-signature""#;
    let request_body = br#"{"context": {"action": "search"}}"#;
    let public_key = b"32-byte-public-key";
    
    let is_valid = crypto.verify_authorization_header(
        auth_header,
        request_body,
        public_key,
    )?;
    
    if is_valid {
        println!("✅ Request verified successfully!");
    } else {
        println!("❌ Request verification failed!");
    }
    
    Ok(())
}
```

### Advanced Configuration

```rust
use ondc_crypto::{ONDCCrypto, ONDCConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ONDCConfig {
        timestamp_tolerance_seconds: 300,  // 5 minutes
        default_expiry_hours: 2,
        strict_verification: true,
    };
    
    let private_key = b"your-32-byte-private-key-here...";
    let crypto = ONDCCrypto::with_config(private_key, config)?;
    
    // Use with custom configuration...
    Ok(())
}
```

## 🏗️ Architecture

The SDK is organized into focused crates for modular usage:

```
ondc-crypto/                    # Main SDK (high-level API)
├── ondc-crypto-traits/        # Core traits and error types
├── ondc-crypto-algorithms/    # Cryptographic implementations
├── ondc-crypto-http/          # HTTP signature handling
├── ondc-crypto-formats/       # Encoding and format utilities
└── ondc-crypto-utils/         # Helper utilities
```

### Crate Dependencies

- **ondc-crypto-traits**: Foundation traits (`Signer`, `Verifier`, `Hasher`) and error types
- **ondc-crypto-algorithms**: Ed25519, BLAKE2, and X25519 implementations
- **ondc-crypto-http**: ONDC HTTP signature generation and verification
- **ondc-crypto-formats**: Base64 encoding, key format conversions
- **ondc-crypto-utils**: Timestamp utilities, validation helpers

## 🔧 Development

### Prerequisites

- Rust 1.70+ (stable)
- Cargo

### Building

```bash
# Clone the repository
git clone https://github.com/your-username/ondc-crypto-rs.git
cd ondc-crypto-rs

# Build all crates
cargo build

# Run tests
cargo test

# Build documentation
cargo doc --open
```

### Development Commands

```bash
# Format code
make fmt

# Run linter
make clippy

# Run tests
make test

# Check security
make audit

# Build documentation
make doc
```

## 📚 Documentation

- **[API Documentation](https://docs.rs/ondc-crypto)** - Complete API reference
- **[Technical Guide](docs/technical.md)** - Implementation details and patterns
- **[Architecture](docs/architecture.mermaid)** - System design and data flows
- **[Development Setup](docs/dev-environment-setup.md)** - Environment configuration
- **[Project Status](docs/status.md)** - Implementation progress and roadmap

## 🔒 Security

This SDK implements several security best practices:

- **Memory Safety**: Automatic zeroization of sensitive data using `zeroize`
- **Constant-Time Operations**: Timing attack resistance with `subtle`
- **Input Validation**: Comprehensive validation of all inputs
- **Error Handling**: Secure error messages that don't leak sensitive information
- **Dependency Auditing**: Regular security audits of all dependencies

### Security Considerations

- Always use the latest version of the SDK
- Keep your private keys secure and never commit them to version control
- Use strong, randomly generated keys
- Validate all inputs before processing
- Handle errors appropriately in your application

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

### Code Style

- Follow Rust formatting guidelines (`cargo fmt`)
- Address all clippy warnings (`cargo clippy`)
- Write comprehensive tests
- Add documentation for all public APIs

## 📄 License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

## 🙏 Acknowledgments

- [ONDC](https://ondc.org/) for the specification and protocol
- [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek) for Ed25519 implementation
- [blake2b_simd](https://github.com/cesarb/blake2b_simd) for BLAKE2 implementation
- [zeroize](https://github.com/iqlusioninc/crates/tree/main/zeroize) for memory safety
- [subtle](https://github.com/dalek-cryptography/subtle) for constant-time operations

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-username/ondc-crypto-rs/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-username/ondc-crypto-rs/discussions)
- **Documentation**: [API Docs](https://docs.rs/ondc-crypto)

## 🗺️ Roadmap

See our [Project Status](docs/status.md) for detailed implementation progress and upcoming features.

### Upcoming Features

- [ ] Async/await support
- [ ] WebAssembly (WASM) support
- [ ] Additional cryptographic algorithms
- [ ] Performance optimizations
- [ ] Extended ONDC protocol support

---

**Note**: This SDK is currently in active development. The API may change between versions until we reach 1.0.0. Please check the [changelog](CHANGELOG.md) for breaking changes. 