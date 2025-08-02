use crate::models::{SecurityLevel, SecuritySettings};
use aes_gcm::{Aes256Gcm, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce, KeyInit as ChaChaKeyInit};
use chacha20poly1305::aead::Aead as ChaChaAead;
use argon2::{Argon2, PasswordHasher};
use rand::{Rng, RngCore};
use sha2::{Sha256, Digest};
use crc::{Crc, CRC_32_ISO_HDLC};
use base64::{Engine as _, engine::general_purpose};
use anyhow::{Result, anyhow};
use std::collections::HashMap;

/// CRC-32 calculator for integrity checking
static CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

/// Encryption context with all necessary keys and parameters
#[derive(Clone)]
pub struct EncryptionContext {
    pub master_key: Vec<u8>,
    pub salt: Vec<u8>,
    pub iv: Vec<u8>,
    pub security_level: SecurityLevel,
    pub settings: SecuritySettings,
    pub derived_keys: HashMap<String, Vec<u8>>,
}

impl EncryptionContext {
    /// Create new encryption context with master password
    pub fn new(master_password: &str, security_level: SecurityLevel, settings: SecuritySettings) -> Result<Self> {
        let mut rng = rand::thread_rng();
        
        // Generate salt and IV
        let mut salt = vec![0u8; settings.salt_length];
        let mut iv = vec![0u8; settings.iv_length];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut iv);
        
        // Derive master key using Argon2
        let master_key = Self::derive_master_key(master_password, &salt, &settings)?;
        
        // Generate additional keys for different purposes
        let mut derived_keys = HashMap::new();
        
        // Key for AES encryption
        let aes_key = Self::derive_key(&master_key, b"aes_key", &settings)?;
        derived_keys.insert("aes".to_string(), aes_key);
        
        // Key for ChaCha20 encryption
        let chacha_key = Self::derive_key(&master_key, b"chacha_key", &settings)?;
        derived_keys.insert("chacha".to_string(), chacha_key);
        
        // Key for integrity checking
        let integrity_key = Self::derive_key(&master_key, b"integrity_key", &settings)?;
        derived_keys.insert("integrity".to_string(), integrity_key);
        
        // Key for additional quantum resistance layer
        let quantum_key = Self::derive_key(&master_key, b"quantum_key", &settings)?;
        derived_keys.insert("quantum".to_string(), quantum_key);
        
        Ok(Self {
            master_key,
            salt,
            iv,
            security_level,
            settings,
            derived_keys,
        })
    }
    
    /// Derive master key using Argon2
    fn derive_master_key(password: &str, salt: &[u8], settings: &SecuritySettings) -> Result<Vec<u8>> {
        let salt_string = argon2::password_hash::SaltString::encode_b64(salt)
            .map_err(|e| anyhow!("Failed to encode salt: {}", e))?;
        
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                settings.memory_cost,
                settings.key_derivation_iterations,
                settings.parallelism,
                Some(32), // 256-bit key
            ).map_err(|e| anyhow!("Failed to create Argon2 params: {}", e))?,
        );
        
        let hash = argon2.hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| anyhow!("Failed to hash password: {}", e))?;
        
        Ok(hash.hash.unwrap().as_bytes().to_vec())
    }
    
    /// Derive additional keys for different purposes
    fn derive_key(master_key: &[u8], purpose: &[u8], settings: &SecuritySettings) -> Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(master_key);
        hasher.update(purpose);
        hasher.update(&settings.key_derivation_iterations.to_le_bytes());
        
        let mut key = vec![0u8; 32];
        let hash = hasher.finalize();
        key.copy_from_slice(&hash);
        
        Ok(key)
    }
    
    /// Encrypt data with ultra-strong encryption
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.security_level {
            SecurityLevel::Standard => self.encrypt_standard(data),
            SecurityLevel::High => self.encrypt_high(data),
            SecurityLevel::Quantum => self.encrypt_quantum(data),
        }
    }
    
    /// Standard encryption: AES-256-GCM
    fn encrypt_standard(&self, data: &[u8]) -> Result<Vec<u8>> {
        let aes_key = self.derived_keys.get("aes")
            .ok_or_else(|| anyhow!("AES key not found"))?;
        
        let cipher = Aes256Gcm::new_from_slice(aes_key)
            .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;
        
        let nonce = Nonce::from_slice(&self.iv);
        
        let encrypted = cipher.encrypt(nonce, data)
            .map_err(|e| anyhow!("Failed to encrypt data: {}", e))?;
        
        // Combine IV + encrypted data
        let mut result = Vec::new();
        result.extend_from_slice(&self.iv);
        result.extend_from_slice(&encrypted);
        
        Ok(result)
    }
    
    /// High security: AES-256-GCM + ChaCha20-Poly1305
    fn encrypt_high(&self, data: &[u8]) -> Result<Vec<u8>> {
        // First layer: AES-256-GCM
        let aes_encrypted = self.encrypt_standard(data)?;
        
        // Second layer: ChaCha20-Poly1305
        let chacha_key = self.derived_keys.get("chacha")
            .ok_or_else(|| anyhow!("ChaCha key not found"))?;
        
        let cipher = ChaCha20Poly1305::new_from_slice(chacha_key)
            .map_err(|e| anyhow!("Failed to create ChaCha cipher: {}", e))?;
        
        let nonce = ChaChaNonce::try_from(&self.iv[..])
            .map_err(|e| anyhow!("Failed to create ChaCha nonce: {}", e))?;
        
        let double_encrypted = cipher.encrypt(&nonce, &*aes_encrypted)
            .map_err(|e| anyhow!("Failed to encrypt with ChaCha: {}", e))?;
        
        // Combine IV + double encrypted data
        let mut result = Vec::new();
        result.extend_from_slice(&self.iv);
        result.extend_from_slice(&double_encrypted);
        
        Ok(result)
    }
    
    /// Quantum-resistant encryption: Multiple layers with additional security
    fn encrypt_quantum(&self, data: &[u8]) -> Result<Vec<u8>> {
        // First layer: AES-256-GCM
        let aes_encrypted = self.encrypt_standard(data)?;
        
        // Second layer: ChaCha20-Poly1305
        let chacha_encrypted = self.encrypt_high(data)?;
        
        // Third layer: Additional quantum-resistant layer
        let quantum_key = self.derived_keys.get("quantum")
            .ok_or_else(|| anyhow!("Quantum key not found"))?;
        
        // Apply multiple rounds of encryption for quantum resistance
        let mut quantum_encrypted = aes_encrypted.clone();
        
        // Multiple rounds with different keys derived from quantum key
        for round in 0u32..3 {
            let round_key = Self::derive_key(quantum_key, &round.to_le_bytes(), &self.settings)?;
            let cipher = Aes256Gcm::new_from_slice(&round_key)
                .map_err(|e| anyhow!("Failed to create round cipher: {}", e))?;
            
            let nonce = Nonce::from_slice(&self.iv);
            quantum_encrypted = cipher.encrypt(nonce, &*quantum_encrypted)
                .map_err(|e| anyhow!("Failed to encrypt round {}: {}", round, e))?;
        }
        
        // Combine all layers
        let mut result = Vec::new();
        result.extend_from_slice(&self.iv);
        result.extend_from_slice(&quantum_encrypted);
        
        Ok(result)
    }
    
    /// Decrypt data
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        match self.security_level {
            SecurityLevel::Standard => self.decrypt_standard(encrypted_data),
            SecurityLevel::High => self.decrypt_high(encrypted_data),
            SecurityLevel::Quantum => self.decrypt_quantum(encrypted_data),
        }
    }
    
    /// Decrypt standard encryption
    fn decrypt_standard(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        if encrypted_data.len() < self.settings.iv_length {
            return Err(anyhow!("Encrypted data too short"));
        }
        
        let (iv_data, cipher_data) = encrypted_data.split_at(self.settings.iv_length);
        
        let aes_key = self.derived_keys.get("aes")
            .ok_or_else(|| anyhow!("AES key not found"))?;
        
        let cipher = Aes256Gcm::new_from_slice(aes_key)
            .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;
        
        let nonce = Nonce::from_slice(iv_data);
        
        let decrypted = cipher.decrypt(nonce, cipher_data)
            .map_err(|e| anyhow!("Failed to decrypt data: {}", e))?;
        
        Ok(decrypted)
    }
    
    /// Decrypt high security encryption
    fn decrypt_high(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        if encrypted_data.len() < self.settings.iv_length {
            return Err(anyhow!("Encrypted data too short"));
        }
        
        let (iv_data, cipher_data) = encrypted_data.split_at(self.settings.iv_length);
        
        // Decrypt ChaCha20 layer
        let chacha_key = self.derived_keys.get("chacha")
            .ok_or_else(|| anyhow!("ChaCha key not found"))?;
        
        let cipher = ChaCha20Poly1305::new_from_slice(chacha_key)
            .map_err(|e| anyhow!("Failed to create ChaCha cipher: {}", e))?;
        
        let nonce = ChaChaNonce::try_from(iv_data)
            .map_err(|e| anyhow!("Failed to create ChaCha nonce: {}", e))?;
        
        let chacha_decrypted = cipher.decrypt(&nonce, cipher_data)
            .map_err(|e| anyhow!("Failed to decrypt ChaCha layer: {}", e))?;
        
        // Decrypt AES layer
        self.decrypt_standard(&chacha_decrypted)
    }
    
    /// Decrypt quantum-resistant encryption
    fn decrypt_quantum(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        if encrypted_data.len() < self.settings.iv_length {
            return Err(anyhow!("Encrypted data too short"));
        }
        
        let (iv_data, cipher_data) = encrypted_data.split_at(self.settings.iv_length);
        
        // Decrypt quantum layer (reverse of encryption)
        let quantum_key = self.derived_keys.get("quantum")
            .ok_or_else(|| anyhow!("Quantum key not found"))?;
        
        let mut quantum_decrypted = cipher_data.to_vec();
        
        // Multiple rounds in reverse order
        for round in (0u32..3).rev() {
            let round_key = Self::derive_key(quantum_key, &round.to_le_bytes(), &self.settings)?;
            let cipher = Aes256Gcm::new_from_slice(&round_key)
                .map_err(|e| anyhow!("Failed to create round cipher: {}", e))?;
            
            let nonce = Nonce::from_slice(iv_data);
            quantum_decrypted = cipher.decrypt(nonce, &*quantum_decrypted)
                .map_err(|e| anyhow!("Failed to decrypt round {}: {}", round, e))?;
        }
        
        // Decrypt remaining layers
        let mut combined = Vec::new();
        combined.extend_from_slice(iv_data);
        combined.extend_from_slice(&quantum_decrypted);
        
        self.decrypt_high(&combined)
    }
    
    /// Calculate CRC32 checksum
    pub fn calculate_crc32(&self, data: &[u8]) -> u32 {
        CRC32.checksum(data)
    }
    
    /// Calculate SHA256 hash
    pub fn calculate_sha256(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        general_purpose::STANDARD.encode(hasher.finalize())
    }
    
    /// Calculate integrity hash for entire dataset
    pub fn calculate_integrity_hash(&self, items: &[crate::models::Item]) -> Result<String> {
        let mut hasher = Sha256::new();
        
        // Sort items by ID for consistent hashing
        let mut sorted_items = items.to_vec();
        sorted_items.sort_by(|a, b| a.get_id().cmp(&b.get_id()));
        
        for item in &sorted_items {
            // Hash item ID and type
            hasher.update(item.get_id().as_bytes());
            hasher.update(format!("{:?}", item.get_type()).as_bytes());
            
            // Hash item data
            let item_data = serde_json::to_vec(item)
                .map_err(|e| anyhow!("Failed to serialize item: {}", e))?;
            hasher.update(&item_data);
        }
        
        // Add salt for additional security
        hasher.update(&self.salt);
        
        Ok(general_purpose::STANDARD.encode(hasher.finalize()))
    }
    
    /// Verify integrity of an item
    pub fn verify_item_integrity(&self, item: &crate::models::Item) -> Result<bool> {
        let base = item.get_base();
        let item_data = serde_json::to_vec(item)
            .map_err(|e| anyhow!("Failed to serialize item: {}", e))?;
        
        let calculated_crc = self.calculate_crc32(&item_data);
        let calculated_sha = self.calculate_sha256(&item_data);
        
        Ok(calculated_crc == base.crc32 && calculated_sha == base.sha256)
    }
    
    /// Update integrity checksums for an item
    pub fn update_item_integrity(&self, item: &mut crate::models::Item) -> Result<()> {
        let item_data = serde_json::to_vec(item)
            .map_err(|e| anyhow!("Failed to serialize item: {}", e))?;
        
        let base = item.get_base_mut();
        base.crc32 = self.calculate_crc32(&item_data);
        base.sha256 = self.calculate_sha256(&item_data);
        
        Ok(())
    }
    
    /// Generate random password
    pub fn generate_password(&self, settings: &crate::models::PasswordGeneratorSettings) -> String {
        let mut rng = rand::thread_rng();
        let mut chars = Vec::new();
        
        if settings.use_lowercase {
            chars.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz");
        }
        if settings.use_uppercase {
            chars.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }
        if settings.use_numbers {
            chars.extend_from_slice(b"0123456789");
        }
        if settings.use_symbols {
            chars.extend_from_slice(b"!@#$%^&*()_+-=[]{}|;:,.<>?");
        }
        
        if chars.is_empty() {
            chars.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz");
        }
        
        let mut password = String::new();
        for _ in 0..settings.length {
            let idx = rng.gen_range(0..chars.len());
            password.push(chars[idx] as char);
        }
        
        password
    }
} 