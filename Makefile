# Password Manager Makefile

.PHONY: help build test clean install release security format lint

# Default target
help:
	@echo "Available targets:"
	@echo "  build        - Build the application"
	@echo "  test         - Run tests"
	@echo "  clean        - Clean build artifacts"
	@echo "  install      - Install system-wide"
	@echo "  release      - Build release version"
	@echo "  security     - Run security audit"
	@echo "  format       - Format code"
	@echo "  lint         - Run clippy"
	@echo "  check-all    - Run format, lint, security, and tests"

# Build the application
build:
	cargo build

# Build release version
release:
	cargo build --release

# Run tests
test:
	cargo test --all-features

# Run tests with coverage
test-coverage:
	cargo install cargo-tarpaulin
	cargo tarpaulin --out Html

# Clean build artifacts
clean:
	cargo clean

# Install system-wide
install:
	cargo install --path .

# Format code
format:
	cargo fmt

# Run clippy
lint:
	cargo clippy --all-features -- -D warnings

# Run security audit
security:
	cargo audit

# Check for outdated dependencies
outdated:
	cargo install cargo-outdated
	cargo outdated

# Update dependencies
update:
	cargo update

# Create a new release
release-create:
	@read -p "Enter version (e.g., 1.0.0): " version; \
	./scripts/release.sh $$version

# Development environment setup
dev-setup:
	cargo install cargo-watch
	cargo install cargo-audit
	cargo install cargo-outdated
	cargo install cargo-tarpaulin

# Run with hot reload
dev-watch:
	cargo watch -x check -x test -x run

# Check everything
check-all: format lint security test

# Full build and test
all: clean build test release

# Production build
prod: clean release

# Help for release process
release-help:
	@echo "Release Process:"
	@echo "1. Update version in Cargo.toml"
	@echo "2. Run: make test"
	@echo "3. Run: make security"
	@echo "4. Run: make release"
	@echo "5. Create git tag: git tag v1.0.0"
	@echo "6. Push: git push origin main --tags"
	@echo "Or use: make release-create"

# Quick development cycle
dev: format lint test

# Install development dependencies
setup:
	cargo install cargo-watch
	cargo install cargo-audit
	cargo install cargo-outdated
	cargo install cargo-tarpaulin
	cargo install cargo-edit 