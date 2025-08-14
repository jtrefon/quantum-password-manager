# Ultra-Secure Password Manager

A quantum-resistant password manager written in Rust with ultra-strong encryption and comprehensive data integrity checking.

## 🔐 Security Features

### Encryption Levels
- **Standard**: AES-256-GCM encryption
- **High**: AES-256-GCM with stronger KDF parameters
- **Quantum**: AES-256-GCM with quantum-safe profile (stronger KDF, SHA-3-based HMAC)

### Security Highlights
- **Argon2id** key derivation with configurable parameters
- **CRC32 + SHA256** integrity checking for individual items
- **Database-wide integrity verification** with salted hashing
- **Authenticated encryption** using AES-256-GCM
- **Memory-hard key derivation** to resist hardware attacks
- **Configurable security parameters** for different threat models

## 🚀 Features

### Data Types Supported
- **Credentials**: Usernames, passwords, URLs, TOTP secrets
- **Folders**: Organizational structure
- **Keys**: Cryptographic keys (symmetric, asymmetric, HMAC)
- **URLs**: Web addresses with metadata
- **Notes**: Plain text and formatted notes
- **Secure Notes**: Additional encryption layer for sensitive data

### Core Functionality
- **Password Generation**: Configurable random password generation
- **Search & Filter**: Find items by name, type, or content
- **Import/Export**: JSON backup and restore capabilities
- **Master Password Management**: Secure password changes
- **Database Locking**: Temporary and permanent locking
- **Integrity Verification**: Comprehensive data integrity checking

## 📦 Installation

### Prerequisites
- Rust 1.70+ and Cargo

### Build from Source
```bash
git clone <repository>
cd password_manager
cargo build --release
```

### Install System-Wide
```bash
cargo install --path .
```

## 🛠️ Usage

### Basic Commands

#### Create a New Database
```bash
password_manager create --file passwords.db --name "My Passwords" --security quantum
```

#### Add a Credential
```bash
password_manager add --file passwords.db --item-type credential --name "GitHub"
```

#### List All Items
```bash
password_manager list --file passwords.db
```

#### Search Items
```bash
password_manager search --file passwords.db --query "github"
```

#### Show Item Details
```bash
password_manager show --file passwords.db --id <item-uuid>
```

#### Generate Password
```bash
password_manager generate --length 32 --uppercase --lowercase --numbers --symbols
```

#### Verify Database Integrity
```bash
password_manager verify --file passwords.db
```

#### Export Database
```bash
password_manager export --file passwords.db --output backup.json
```

#### Change Master Password
```bash
password_manager change-password --file passwords.db
```

### Security Levels

#### Standard Security
- AES-256-GCM encryption
- 100,000 Argon2id iterations
- Suitable for most use cases

#### High Security
- Double encryption (AES-256-GCM + ChaCha20-Poly1305)
- 200,000 Argon2id iterations
- Recommended for sensitive data

#### Quantum Security
- Single AEAD (AES-256-GCM)
- Higher Argon2id parameters
- SHA-3-based HMAC for integrity

## 🔧 Configuration

### Security Settings
The password manager uses configurable security parameters:

```rust
SecuritySettings {
    key_derivation_iterations: 100_000,  // Argon2 iterations
    memory_cost: 65536,                   // Memory cost (64MB)
    parallelism: 4,                       // Parallel threads
    salt_length: 32,                      // Salt size
    iv_length: 12,                        // Initialization vector size
    tag_length: 16,                       // Authentication tag size
}
```

### Password Generator Settings
```rust
PasswordGeneratorSettings {
    length: 20,                           // Password length
    use_uppercase: true,                  // Include uppercase letters
    use_lowercase: true,                  // Include lowercase letters
    use_numbers: true,                    // Include numbers
    use_symbols: true,                    // Include symbols
    exclude_similar: true,                // Exclude similar characters
    exclude_ambiguous: false,             // Exclude ambiguous characters
}
```

## 🛡️ Security Architecture

### Encryption Flow
1. **Master Password** → Argon2id key derivation
2. **Derived Keys** → Multiple encryption layers
3. **Data Encryption** → AES-256-GCM + ChaCha20-Poly1305
4. **Integrity Checking** → CRC32 + SHA256 per item
5. **Database Integrity** → Salted SHA256 for entire dataset

### Security Notes
- **256-bit Keys**: Strong against brute force
- **Argon2id**: Memory-hard derivation
- **AEAD Tags**: Chosen-ciphertext protection
- **SHA-3-based HMAC (Quantum profile)**: Modern hash for integrity

### Integrity Verification
- **Per-Item Checksums**: CRC32 for fast integrity checking
- **Cryptographic Hashes**: SHA256 for tamper detection
- **Database-Wide Hash**: Salted SHA256 for overall integrity
- **Consistent Ordering**: Deterministic hashing for reliable verification

## 📊 Database Structure

### File Format
- **Header + Ciphertext**: `PMDB` magic + JSON header length + header + ciphertext
- **Header includes**: Argon2 settings, salt, security level, algorithm id, HMAC over plaintext
- **Versioned**: Header version for forward compatibility

### Data Organization
```
PasswordDatabase {
    version: String,
    created_at: DateTime,
    updated_at: DateTime,
    security_level: SecurityLevel,
    items: Vec<Item>,
    metadata: DatabaseMetadata,
    integrity_hash: String,
}
```

## 🔍 Integrity Checking

### Individual Item Integrity
- **CRC32 Checksum**: Fast integrity verification
- **SHA256 Hash**: Cryptographic integrity verification
- **Automatic Updates**: Checksums updated on every modification

### Database Integrity
- **HMAC-SHA256** over plaintext using a derived integrity key
- **Per-item CRC32/SHA256** retained for quick checks

## 🚨 Security Considerations

### Best Practices
1. **Strong Master Password**: Use a long, complex master password
2. **Regular Backups**: Export database regularly
3. **Secure Storage**: Store database file securely
4. **Lock When Away**: Lock database when not in use
5. **Verify Integrity**: Regularly verify database integrity

### Threat Model
- **Physical Access**: Encrypted database resists offline attacks
- **Memory Attacks**: Argon2id resists memory-based attacks
- **Quantum Attacks**: Multi-layer encryption provides quantum resistance
- **Tampering**: Integrity checks detect unauthorized modifications

## 🧪 Testing

### Run Tests
```bash
cargo test
```

### Security Tests
```bash
cargo test --features security-tests
```

### Performance Tests
```bash
cargo test --features performance-tests
```

## 📈 Performance

### Encryption Performance
- Dependent on hardware and KDF parameters

### Memory Usage
- **Small Database**: <10MB memory
- **Large Database**: <100MB memory
- **Scalable**: Linear memory growth

## 🔄 Migration

### From Other Password Managers
1. Export data from existing password manager
2. Convert to JSON format
3. Import using `password_manager import`
4. Verify all data imported correctly

### Version Upgrades
- Automatic migration between versions
- Backward compatibility maintained
- Integrity verification after migration

## 🤝 Contributing

### Development Setup
```bash
git clone <repository>
cd password_manager
cargo build
cargo test
```

### Code Style
- Follow Rust coding conventions
- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting

### Security Review
- All cryptographic code reviewed
- Security tests required
- Performance benchmarks included

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This password manager provides strong security features, but no software is completely secure. Use at your own risk and always maintain regular backups of your data.

## 🆘 Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Review the documentation
- Check the security considerations

---

**Built with ❤️ and Rust for maximum security and performance.** 