# Password Manager v{{ version }}

## 🚀 What's New

### ✨ Features
- Hardware acceleration for Apple Silicon
- Progress indicators for encryption operations
- Cross-platform support (Linux, Windows, macOS)
- Quantum-resistant encryption

### 🔧 Improvements
- Enhanced security with multi-layer encryption
- Better error handling and user feedback
- Optimized performance with hardware acceleration
- Improved CLI interface

### 🐛 Bug Fixes
- Fixed encryption/decryption issues
- Resolved progress indicator display problems
- Corrected hardware detection on Apple Silicon

## 📦 Downloads

### Linux
- **x86_64**: [password_manager-linux-x86_64.tar.gz]({{ linux_x86_64_url }})

### Windows
- **x86_64**: [password_manager-windows-x86_64.zip]({{ windows_x86_64_url }})

### macOS
- **Intel**: [password_manager-macos-x86_64.tar.gz]({{ macos_x86_64_url }})
- **Apple Silicon**: [password_manager-macos-aarch64.tar.gz]({{ macos_aarch64_url }})

## 🔧 Installation

### From Binary
1. Download the appropriate binary for your platform
2. Extract the archive
3. Make the binary executable (Linux/macOS): `chmod +x password_manager`
4. Run: `./password_manager --help`

### From Source
```bash
git clone https://github.com/your-repo/password_manager.git
cd password_manager
cargo build --release
./target/release/password_manager --help
```

## 🚀 Quick Start

```bash
# Create a new database
password_manager create my_passwords.db

# Add a credential
password_manager add credential

# List all items
password_manager list

# Search for items
password_manager search "gmail"

# Generate a password
password_manager generate --length 20 --uppercase --lowercase --numbers --symbols
```

## 🔐 Security Features

- **AES-256-GCM**: Standard encryption
- **ChaCha20-Poly1305**: High security encryption
- **Quantum-resistant**: Multi-layer encryption for future-proof security
- **Hardware acceleration**: Apple Silicon and Intel AES-NI support
- **Argon2id**: Secure key derivation
- **CRC32/SHA-256**: Data integrity verification

## 🧪 Hardware Acceleration

The password manager automatically detects and uses hardware acceleration:

- **Apple Silicon**: ARM AES acceleration
- **Intel**: AES-NI instructions
- **Cross-platform**: Fallback to software implementation

Check hardware support:
```bash
password_manager hardware
```

## 📊 Performance

- **Encryption**: Hardware-accelerated AES operations
- **Key derivation**: Optimized Argon2id parameters
- **Progress tracking**: Real-time operation feedback
- **Multi-threading**: Parallel processing for quantum encryption

## 🔧 Configuration

### Security Levels
- **Standard**: AES-256-GCM (fast, secure)
- **High**: AES + ChaCha20 (very secure)
- **Quantum**: Multi-layer with quantum rounds (maximum security)

### Testing Mode
For development and testing, use reduced security parameters:
```bash
# Demo with testing mode
password_manager demo
```

## 🐛 Known Issues

- Long-running quantum encryption on older hardware
- Progress indicators may not update smoothly on all terminals

## 🔄 Migration

### From Previous Versions
- Database format is backward compatible
- No migration required for existing databases
- New features are opt-in

## 📚 Documentation

- [User Guide](https://github.com/your-repo/password_manager/wiki)
- [API Documentation](https://docs.rs/password_manager)
- [Security Whitepaper](https://github.com/your-repo/password_manager/blob/main/SECURITY.md)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](https://github.com/your-repo/password_manager/blob/main/CONTRIBUTING.md).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/your-repo/password_manager/blob/main/LICENSE) file for details.

## 🙏 Acknowledgments

- Rust cryptography community
- Apple Silicon optimization contributors
- Security researchers and auditors

---

**Download**: [Latest Release]({{ release_url }})

**Source**: [GitHub Repository](https://github.com/your-repo/password_manager)

**Issues**: [Report a Bug](https://github.com/your-repo/password_manager/issues) 