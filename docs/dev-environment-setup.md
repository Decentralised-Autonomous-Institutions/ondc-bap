# ONDC Crypto SDK - Development Environment Setup

## Overview

This document describes the development environment configuration for the ONDC Crypto SDK project. Task 1.1.2 has been completed with the following components:

## Configuration Files Created

### 1. `rust-toolchain.toml`
**Purpose**: Ensures consistent Rust toolchain across all development environments and CI/CD systems.

**Configuration**:
- Uses stable Rust channel
- Includes essential components: `rustfmt`, `clippy`, `rust-docs`, `rust-analyzer`
- Targets multiple platforms: Linux, macOS, Windows

**Usage**:
```bash
# The toolchain will be automatically installed when you run any cargo command
cargo build
cargo test
```

### 2. `.cargo/config.toml`
**Purpose**: Configures Cargo build system with optimizations and linting rules.

**Key Features**:
- **Build Optimizations**: Incremental compilation, parallel jobs, link-time optimization
- **Platform-Specific Settings**: Optimized flags for Linux, macOS, and Windows
- **Linting Configuration**: Comprehensive Rust and Clippy lint rules
- **Security Focus**: Forbids unsafe code, warns about security issues

**Usage**:
```bash
# All cargo commands automatically use these settings
cargo build --release  # Uses LTO and optimizations
cargo clippy          # Uses configured lint rules
```

### 3. `.pre-commit-config.yaml`
**Purpose**: Automated code quality checks that run before each commit.

**Hooks Included**:
- **Rust Formatting**: `cargo fmt --all`
- **Rust Linting**: `cargo clippy --all-targets --all-features -- -D warnings`
- **Compilation Check**: `cargo check --all-targets --all-features`
- **General File Checks**: Trailing whitespace, file endings, YAML/TOML syntax
- **Security Checks**: Secret detection

**Setup and Usage**:
```bash
# Install pre-commit hooks
make install-hooks
# or manually:
pre-commit install
pre-commit install --hook-type commit-msg

# Run hooks manually
pre-commit run --all-files

# Run specific hook
pre-commit run rustfmt
```

### 4. `rustfmt.toml`
**Purpose**: Configures code formatting rules for consistent style across the project.

**Key Settings**:
- **Line Width**: 100 characters
- **Indentation**: 4 spaces
- **Edition**: 2021
- **Documentation**: Formats code in doc comments

**Usage**:
```bash
# Format all code
cargo fmt --all
# or
make fmt

# Check formatting without changing files
cargo fmt --all -- --check
# or
make fmt-check
```

### 5. `.clippy.toml`
**Purpose**: Customizes Clippy linting rules for cryptographic code.

**Configuration**:
- **Security Lints**: Enabled for unsafe code detection
- **Performance Lints**: Warns about inefficient patterns
- **Code Quality**: Enforces documentation and best practices
- **Crypto-Specific**: Allows necessary patterns for cryptographic operations

**Usage**:
```bash
# Run clippy with configured rules
cargo clippy --all-targets --all-features -- -D warnings
# or
make clippy
```

### 6. `Makefile`
**Purpose**: Provides convenient commands for common development tasks.

**Available Commands**:
```bash
# Show all available commands
make help

# Build commands
make build          # Release build
make build-dev      # Debug build
make check          # Compilation check

# Testing commands
make test           # Run all tests
make test-release   # Release mode tests
make test-coverage  # Coverage reporting

# Code quality commands
make fmt            # Format code
make fmt-check      # Check formatting
make clippy         # Run linter
make audit          # Security audit

# Documentation commands
make doc            # Generate docs
make doc-open       # Generate and open docs

# Setup commands
make install-hooks  # Install pre-commit hooks
make clean          # Clean build artifacts

# Workflow commands
make dev-setup      # Complete setup
make pre-commit     # Run pre-commit checks
make ci             # Run CI checks
make dev            # Quick development cycle
```

## Development Workflow

### Initial Setup
```bash
# 1. Clone the repository
git clone <repository-url>
cd ondc-crypto

# 2. Install pre-commit hooks
make install-hooks

# 3. Verify setup
make check
make test
```

### Daily Development Workflow
```bash
# 1. Start development session
make build-dev

# 2. Make code changes...

# 3. Run quality checks
make dev  # This runs: fmt, clippy, test

# 4. Commit changes (pre-commit hooks run automatically)
git add .
git commit -m "Your commit message"
```

### Pre-Release Checklist
```bash
# Run complete release preparation
make release-prep
# This runs: clean, build, test-release, doc, audit
```

## IDE Integration

### VS Code
Recommended extensions:
- `rust-analyzer` - Rust language support
- `crates` - Cargo.toml dependency management
- `even-better-toml` - TOML file support
- `markdown-all-in-one` - Markdown support

### IntelliJ IDEA / CLion
- Install Rust plugin
- Configure to use the project's `rust-toolchain.toml`

## Troubleshooting

### Common Issues

1. **Pre-commit hooks fail**:
   ```bash
   # Reinstall hooks
   make install-hooks
   
   # Run manually to see detailed errors
   pre-commit run --all-files
   ```

2. **Clippy warnings**:
   ```bash
   # See specific warnings
   cargo clippy --all-targets --all-features
   
   # Fix automatically where possible
   cargo clippy --fix --all-targets --all-features
   ```

3. **Formatting issues**:
   ```bash
   # Format all code
   make fmt
   
   # Check what would be formatted
   make fmt-check
   ```

4. **Toolchain issues**:
   ```bash
   # Update toolchain
   rustup update
   
   # Verify toolchain
   rustup show
   ```

### Performance Tips

1. **Faster builds**:
   ```bash
   # Use incremental compilation (already enabled)
   cargo build --release
   
   # Use parallel compilation (already enabled)
   cargo build -j $(nproc)
   ```

2. **Faster tests**:
   ```bash
   # Run tests in parallel
   cargo test --jobs $(nproc)
   
   # Run specific test
   cargo test test_name
   ```

## Security Considerations

The development environment is configured with security in mind:

1. **Unsafe Code**: Forbidden by default in `.cargo/config.toml`
2. **Secret Detection**: Pre-commit hooks scan for accidentally committed secrets
3. **Dependency Auditing**: `cargo audit` integrated into workflow
4. **Security Lints**: Clippy configured to warn about security issues

## Next Steps

With Task 1.1.2 completed, you can now proceed to:

1. **Task 1.1.3**: Set up CI/CD pipeline
2. **Phase 2**: Begin core crate development
3. **Start Implementation**: Begin working on the actual cryptographic functionality

## Verification

To verify that everything is working correctly:

```bash
# Run the complete verification suite
make ci

# This should run without errors and show:
# - Code formatting is correct
# - No clippy warnings
# - All tests pass
# - No security vulnerabilities
```

The development environment is now ready for productive work on the ONDC Crypto SDK! 