# CI/CD Pipeline Documentation

This repository includes a comprehensive CI/CD pipeline that automatically builds, tests, and releases the password manager across all major platforms.

## 🚀 Pipeline Overview

### Jobs

1. **Lint and Format** - Code quality checks
2. **Security Audit** - Security vulnerability scanning
3. **Test** - Cross-platform testing
4. **Build** - Multi-platform builds
5. **Release** - GitHub releases
6. **Publish** - Crates.io publishing

### Supported Platforms

- **Linux**: x86_64-unknown-linux-gnu
- **Windows**: x86_64-pc-windows-msvc
- **macOS**: x86_64-apple-darwin, aarch64-apple-darwin (Apple Silicon)

## 🔧 Configuration Files

### `.github/workflows/ci.yml`
Main CI/CD pipeline configuration with:
- Cross-platform testing
- Security audits
- Automated releases
- Crates.io publishing

### `rustfmt.toml`
Code formatting configuration for consistent style.

### `.clippy.toml`
Linting rules configuration for code quality.

## 📋 Pipeline Triggers

- **Push to main/master**: Runs tests and builds
- **Pull Requests**: Runs tests and quality checks
- **Release published**: Creates GitHub release and publishes to crates.io

## 🔐 Required Secrets

### GitHub Secrets
- `CARGO_REGISTRY_TOKEN`: Token for publishing to crates.io

### Setup Instructions
1. Go to GitHub repository settings
2. Navigate to Secrets and variables → Actions
3. Add the required secrets

## 📦 Release Artifacts

The pipeline creates the following artifacts:
- `password_manager-linux-x86_64.tar.gz`
- `password_manager-windows-x86_64.zip`
- `password_manager-macos-x86_64.tar.gz`
- `password_manager-macos-aarch64.tar.gz`

## 🧪 Testing

### Hardware Acceleration Tests
- macOS builds include hardware acceleration tests
- Tests Apple Silicon detection and optimization
- Validates progress indicators with hardware acceleration

### Security Tests
- Runs `cargo audit` for vulnerability scanning
- Checks for known security issues in dependencies

## 🚀 Deployment

### GitHub Releases
- Automatic release creation on tag push
- Includes all platform binaries
- Generates release notes automatically

### Crates.io Publishing
- Publishes to crates.io registry
- Requires `CARGO_REGISTRY_TOKEN` secret
- Only runs on release events

## 🔍 Monitoring

### Build Status
- All jobs must pass before release
- Parallel execution for faster feedback
- Cached dependencies for efficiency

### Quality Gates
- Code formatting check
- Clippy linting
- Security audit
- Cross-platform tests

## 🛠️ Local Development

### Running Tests Locally
```bash
# Format code
cargo fmt

# Run lints
cargo clippy

# Run tests
cargo test

# Security audit
cargo audit
```

### Building for Different Platforms
```bash
# Linux
cargo build --release --target x86_64-unknown-linux-gnu

# Windows
cargo build --release --target x86_64-pc-windows-msvc

# macOS Intel
cargo build --release --target x86_64-apple-darwin

# macOS Apple Silicon
cargo build --release --target aarch64-apple-darwin
```

## 📈 Performance

### Caching
- Cargo registry cache
- Git dependencies cache
- Build artifacts cache

### Parallelization
- Independent job execution
- Matrix builds for multiple platforms
- Optimized dependency installation

## 🔧 Troubleshooting

### Common Issues
1. **Build failures**: Check target installation
2. **Test timeouts**: Increase timeout limits
3. **Cache issues**: Clear GitHub Actions cache
4. **Secret errors**: Verify secret configuration

### Debugging
- Enable `RUST_BACKTRACE=1` for detailed errors
- Check job logs for specific failure points
- Verify platform-specific requirements

## 📚 Additional Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Rust CI/CD Best Practices](https://rust-lang.github.io/rustup/concepts/channels.html)
- [Cargo Publishing Guide](https://doc.rust-lang.org/cargo/reference/publishing.html) 