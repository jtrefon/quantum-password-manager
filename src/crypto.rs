use crate::hardware::{HardwareAes, HardwareAccelerator};
use crate::models::{SecurityLevel, SecuritySettings};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, Result};
use argon2::Argon2;
use base64::{engine::general_purpose, Engine as _};
use crc::{Crc, CRC_32_ISO_HDLC};
use hmac::{Hmac, Mac};
use sha3::Sha3_256;
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Progress callback function type
pub type ProgressCallback = Arc<Mutex<dyn Fn(&str, f32) + Send + Sync>>;

/// Progress indicator for encryption operations
pub struct ProgressIndicator {
    callback: Option<ProgressCallback>,
    operation: String,
    total_steps: u32,
    current_step: u32,
}

impl ProgressIndicator {
    pub fn new(operation: &str, total_steps: u32) -> Self {
        Self {
            callback: None,
            operation: operation.to_string(),
            total_steps,
            current_step: 0,
        }
    }

    pub fn with_callback(mut self, callback: ProgressCallback) -> Self {
        self.callback = Some(callback);
        self
    }

    pub fn update(&mut self, step: u32, message: &str) {
        self.current_step = step;
        let progress = if self.total_steps > 0 {
            (step as f32) / (self.total_steps as f32)
        } else {
            0.0
        };

        if let Some(callback) = &self.callback {
            if let Ok(callback) = callback.lock() {
                callback(&format!("{}: {}", self.operation, message), progress);
            }
        }
    }

    #[allow(dead_code)]
    pub fn increment(&mut self, message: &str) {
        self.current_step += 1;
        self.update(self.current_step, message);
    }

    pub fn finish(&mut self, message: &str) {
        self.update(self.total_steps, message);
    }
}

/// CRC-32 calculator for integrity checking
static CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

/// Encryption context with all necessary keys and parameters
#[derive(Clone)]
pub struct EncryptionContext {
    #[allow(dead_code)]
    pub master_key: Vec<u8>,
    pub salt: Vec<u8>,
    #[allow(dead_code)]
    pub security_level: SecurityLevel,
    pub settings: SecuritySettings,
    pub derived_keys: HashMap<String, Vec<u8>>,
    pub progress_callback: Option<ProgressCallback>,
    #[allow(dead_code)]
    pub hardware_aes: HardwareAes,
}

impl EncryptionContext {
    /// Create new encryption context with master password
    pub fn new(
        master_password: &str,
        security_level: SecurityLevel,
        settings: SecuritySettings,
    ) -> Result<Self> {
        Self::new_with_progress(master_password, security_level, settings, None)
    }

    /// Create new encryption context with master password and progress callback
    pub fn new_with_progress(
        master_password: &str,
        security_level: SecurityLevel,
        settings: SecuritySettings,
        progress_callback: Option<ProgressCallback>,
    ) -> Result<Self> {
        let mut salt = vec![0u8; settings.salt_length];
        rand::thread_rng().fill_bytes(&mut salt);
        Self::from_params_with_progress(
            master_password,
            security_level,
            settings,
            salt,
            progress_callback,
        )
    }

    /// Create new encryption context with provided salt and progress callback (used during load)
    pub fn from_params_with_progress(
        master_password: &str,
        security_level: SecurityLevel,
        settings: SecuritySettings,
        salt: Vec<u8>,
        progress_callback: Option<ProgressCallback>,
    ) -> Result<Self> {
        // Derive master key using Argon2
        let master_key = Self::derive_master_key(
            master_password,
            &salt,
            &settings,
            progress_callback.as_ref(),
        )?;

        // Generate additional keys for different purposes
        let mut derived_keys = HashMap::new();

        // Key for AES encryption
        let aes_key = Self::derive_key(&master_key, b"aes_key", &settings)?;
        derived_keys.insert("aes".to_string(), aes_key);

        // Key for integrity checking (HMAC)
        let integrity_key = Self::derive_key(&master_key, b"integrity_key", &settings)?;
        derived_keys.insert("integrity".to_string(), integrity_key);

        Ok(Self {
            master_key,
            salt,
            security_level,
            settings,
            derived_keys,
            progress_callback,
            hardware_aes: HardwareAes::new(),
        })
    }

    /// Derive master key using Argon2
    fn derive_master_key(
        password: &str,
        salt: &[u8],
        settings: &SecuritySettings,
        progress_callback: Option<&ProgressCallback>,
    ) -> Result<Vec<u8>> {
        let params = argon2::Params::new(
            settings.memory_cost,
            settings.key_derivation_iterations,
            settings.parallelism,
            Some(32),
        )
        .map_err(|e| anyhow!("Failed to create Argon2 params: {}", e))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        // Report progress for key derivation
        if let Some(callback) = progress_callback {
            if let Ok(callback) = callback.lock() {
                callback("Deriving master key with Argon2", 0.0);
            }
        }

        let mut output = vec![0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut output)
            .map_err(|e| anyhow!("Failed to derive key: {}", e))?;

        // Report completion
        if let Some(callback) = progress_callback {
            if let Ok(callback) = callback.lock() {
                callback("Master key derivation complete", 1.0);
            }
        }

        Ok(output)
    }

    /// Derive additional keys for different purposes
    fn derive_key(
        master_key: &[u8],
        purpose: &[u8],
        settings: &SecuritySettings,
    ) -> Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(master_key);
        hasher.update(purpose);
        hasher.update(settings.key_derivation_iterations.to_le_bytes());

        let mut key = vec![0u8; 32];
        let hash = hasher.finalize();
        key.copy_from_slice(&hash);

        Ok(key)
    }

    /// Encrypt data (single AEAD under the hood)
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut progress = ProgressIndicator::new("Encryption", 2);
        if let Some(callback) = &self.progress_callback {
            progress = progress.with_callback(callback.clone());
        }
        // Announce hardware acceleration status via progress callback
        if let Some(callback) = &self.progress_callback {
            if let Ok(callback) = callback.lock() {
                let accel = if HardwareAccelerator::is_available() {
                    "available"
                } else {
                    "not available"
                };
                callback(&format!("Hardware acceleration is {accel}"), 0.0);
            }
        }
        progress.update(1, "Encrypting with AES-256-GCM");
        let result = self.encrypt_aes_gcm(data)?;
        progress.finish("Encryption complete");
        Ok(result)
    }

    /// AES-256-GCM with fresh nonce per encryption. Output: nonce || ciphertext
    fn encrypt_aes_gcm(&self, data: &[u8]) -> Result<Vec<u8>> {
        let aes_key = self
            .derived_keys
            .get("aes")
            .ok_or_else(|| anyhow!("AES key not found"))?;

        let cipher = Aes256Gcm::new_from_slice(aes_key)
            .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;

        // Generate fresh nonce per message
        let mut nonce_bytes = vec![0u8; self.settings.iv_length];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, data)
            .map_err(|e| anyhow!("Failed to encrypt data: {}", e))?;

        // Combine Nonce + encrypted data
        let mut result = Vec::new();
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&encrypted);

        Ok(result)
    }

    /// Decrypt data (single AEAD under the hood)
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        let mut progress = ProgressIndicator::new("Decryption", 2);
        if let Some(callback) = &self.progress_callback {
            progress = progress.with_callback(callback.clone());
        }
        // Announce hardware acceleration status via progress callback
        if let Some(callback) = &self.progress_callback {
            if let Ok(callback) = callback.lock() {
                let accel = if HardwareAccelerator::is_available() {
                    "available"
                } else {
                    "not available"
                };
                callback(&format!("Hardware acceleration is {accel}"), 0.0);
            }
        }
        progress.update(1, "Decrypting with AES-256-GCM");
        let result = self.decrypt_aes_gcm(encrypted_data)?;
        progress.finish("Decryption complete");
        Ok(result)
    }

    /// Decrypt Nonce || ciphertext
    fn decrypt_aes_gcm(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        if encrypted_data.len() < self.settings.iv_length {
            return Err(anyhow!("Encrypted data too short"));
        }

        let (iv_data, cipher_data) = encrypted_data.split_at(self.settings.iv_length);

        let aes_key = self
            .derived_keys
            .get("aes")
            .ok_or_else(|| anyhow!("AES key not found"))?;

        let cipher = Aes256Gcm::new_from_slice(aes_key)
            .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;

        let nonce = Nonce::from_slice(iv_data);

        let decrypted = cipher
            .decrypt(nonce, cipher_data)
            .map_err(|e| anyhow!("Failed to decrypt data: {}", e))?;

        Ok(decrypted)
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
    #[allow(dead_code)]
    pub fn calculate_integrity_hash(&self, items: &[crate::models::Item]) -> Result<String> {
        let mut hasher = Sha256::new();

        // Sort items by ID for consistent hashing
        let mut sorted_items = items.to_vec();
        sorted_items.sort_by_key(|a| a.get_id());

        for item in &sorted_items {
            // Hash item ID and type
            hasher.update(item.get_id().as_bytes());
            hasher.update(format!("{:?}", item.get_type()).as_bytes());

            // Hash item data
            let item_data =
                serde_json::to_vec(item).map_err(|e| anyhow!("Failed to serialize item: {}", e))?;
            hasher.update(&item_data);
        }

        // Add salt for additional security
        hasher.update(&self.salt);

        Ok(general_purpose::STANDARD.encode(hasher.finalize()))
    }

    /// Compute HMAC using the integrity key
    pub fn compute_hmac(&self, data: &[u8]) -> Result<Vec<u8>> {
        let key = self
            .derived_keys
            .get("integrity")
            .ok_or_else(|| anyhow!("Integrity key not found"))?;
        if matches!(self.security_level, SecurityLevel::Quantum) {
            let mut mac = <Hmac<Sha3_256> as hmac::Mac>::new_from_slice(key)
                .map_err(|e| anyhow!("Failed to create HMAC: {}", e))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        } else {
            let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(key)
                .map_err(|e| anyhow!("Failed to create HMAC: {}", e))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }

    /// Verify HMAC
    pub fn verify_hmac(&self, data: &[u8], expected: &[u8]) -> Result<bool> {
        let key = self
            .derived_keys
            .get("integrity")
            .ok_or_else(|| anyhow!("Integrity key not found"))?;
        if matches!(self.security_level, SecurityLevel::Quantum) {
            let mut mac = <Hmac<Sha3_256> as hmac::Mac>::new_from_slice(key)
                .map_err(|e| anyhow!("Failed to create HMAC: {}", e))?;
            mac.update(data);
            Ok(mac.verify_slice(expected).is_ok())
        } else {
            let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(key)
                .map_err(|e| anyhow!("Failed to create HMAC: {}", e))?;
            mac.update(data);
            Ok(mac.verify_slice(expected).is_ok())
        }
    }

    /// Verify integrity of an item
    pub fn verify_item_integrity(&self, item: &crate::models::Item) -> Result<bool> {
        let base = item.get_base();
        let item_data =
            serde_json::to_vec(item).map_err(|e| anyhow!("Failed to serialize item: {}", e))?;

        let calculated_crc = self.calculate_crc32(&item_data);
        let calculated_sha = self.calculate_sha256(&item_data);

        Ok(calculated_crc == base.crc32 && calculated_sha == base.sha256)
    }

    /// Update integrity checksums for an item
    pub fn update_item_integrity(&self, item: &mut crate::models::Item) -> Result<()> {
        let item_data =
            serde_json::to_vec(item).map_err(|e| anyhow!("Failed to serialize item: {}", e))?;

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
