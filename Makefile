# ONDC Crypto SDK Development Makefile
# Provides convenient commands for development workflow

.PHONY: help build test check fmt clippy clean doc install-hooks

# Default target
help:
	@echo "ONDC Crypto SDK Development Commands:"
	@echo ""
	@echo "Build Commands:"
	@echo "  build          - Build all crates in release mode"
	@echo "  build-dev      - Build all crates in debug mode"
	@echo "  check          - Check that code compiles without warnings"
	@echo ""
	@echo "Testing Commands:"
	@echo "  test           - Run all tests"
	@echo "  test-release   - Run tests in release mode"
	@echo "  test-coverage  - Run tests with coverage reporting"
	@echo ""
	@echo "Code Quality Commands:"
	@echo "  fmt            - Format code with rustfmt"
	@echo "  fmt-check      - Check code formatting"
	@echo "  clippy         - Run clippy linter"
	@echo "  audit          - Run security audit"
	@echo ""
	@echo "Documentation Commands:"
	@echo "  doc            - Generate documentation"
	@echo "  doc-open       - Generate and open documentation"
	@echo ""
	@echo "Setup Commands:"
	@echo "  install-hooks  - Install pre-commit hooks"
	@echo "  clean          - Clean build artifacts"
	@echo ""

# Build commands
build:
	cargo build --release --all-targets --all-features

build-dev:
	cargo build --all-targets --all-features

check:
	cargo check --all-targets --all-features

# Testing commands
test:
	cargo test --all-targets --all-features

test-release:
	cargo test --release --all-targets --all-features

test-coverage:
	cargo install cargo-tarpaulin --no-default-features --features native-tls
	cargo tarpaulin --all-features --out Html --output-dir coverage

# Code quality commands
fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

audit:
	cargo audit

# Documentation commands
doc:
	cargo doc --all-features --no-deps

doc-open:
	cargo doc --all-features --no-deps --open

# Setup commands
install-hooks:
	pre-commit install
	pre-commit install --hook-type commit-msg

clean:
	cargo clean
	rm -rf coverage/
	rm -rf target/

# Development workflow commands
dev-setup: install-hooks
	@echo "Development environment setup complete!"
	@echo "Run 'make check' to verify everything is working."

pre-commit: fmt clippy test
	@echo "Pre-commit checks passed!"

ci: fmt-check clippy test audit
	@echo "CI checks passed!"

# Security and performance commands
bench:
	cargo bench --all-features

security-check: audit clippy
	@echo "Security checks completed!"

# Release preparation
release-prep: clean build test-release doc audit
	@echo "Release preparation completed!"

# Quick development cycle
dev: fmt clippy test
	@echo "Development cycle completed!" 