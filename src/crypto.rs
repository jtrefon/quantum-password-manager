use crate::hardware::{HardwareAccelerator, HardwareAes};
use crate::models::{SecurityLevel, SecuritySettings};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, Result};
use argon2::{Argon2, PasswordHasher};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::aead::Aead as ChaChaAead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as ChaChaKeyInit, Nonce as ChaChaNonce};
use crc::{Crc, CRC_32_ISO_HDLC};
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

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

    pub fn increment(&mut self, message: &str) {
        self.current_step += 1;
        self.update(self.current_step, message);
    }
}

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
    pub progress_callback: Option<ProgressCallback>,
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
        let mut rng = rand::thread_rng();

        // Generate salt and IV
        let mut salt = vec![0u8; settings.salt_length];
        let mut iv = vec![0u8; settings.iv_length];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut iv);

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
            )
            .map_err(|e| anyhow!("Failed to create Argon2 params: {}", e))?,
        );

        // Report progress for key derivation
        if let Some(callback) = progress_callback {
            if let Ok(callback) = callback.lock() {
                callback("Deriving master key with Argon2", 0.0);
            }
        }

        let hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| anyhow!("Failed to hash password: {}", e))?;

        // Report completion
        if let Some(callback) = progress_callback {
            if let Ok(callback) = callback.lock() {
                callback("Master key derivation complete", 1.0);
            }
        }

        Ok(hash.hash.unwrap().as_bytes().to_vec())
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
        hasher.update(&settings.key_derivation_iterations.to_le_bytes());

        let mut key = vec![0u8; 32];
        let hash = hasher.finalize();
        key.copy_from_slice(&hash);

        Ok(key)
    }

    /// Encrypt data with ultra-strong encryption
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut progress = ProgressIndicator::new("Encryption", 3);
        if let Some(callback) = &self.progress_callback {
            progress = progress.with_callback(callback.clone());
        }

        progress.update(1, "Starting encryption");

        let result = match self.security_level {
            SecurityLevel::Standard => {
                progress.update(2, "Using standard AES-256-GCM encryption");
                self.encrypt_standard(data)
            }
            SecurityLevel::High => {
                progress.update(2, "Using high security (AES + ChaCha20) encryption");
                self.encrypt_high(data)
            }
            SecurityLevel::Quantum => {
                progress.update(2, "Using quantum-resistant encryption");
                self.encrypt_quantum(data)
            }
        };

        progress.update(3, "Encryption complete");
        result
    }

    /// Standard encryption: AES-256-GCM
    fn encrypt_standard(&self, data: &[u8]) -> Result<Vec<u8>> {
        let aes_key = self
            .derived_keys
            .get("aes")
            .ok_or_else(|| anyhow!("AES key not found"))?;

        let cipher = Aes256Gcm::new_from_slice(aes_key)
            .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;

        let nonce = Nonce::from_slice(&self.iv);

        let encrypted = cipher
            .encrypt(nonce, data)
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
        let chacha_key = self
            .derived_keys
            .get("chacha")
            .ok_or_else(|| anyhow!("ChaCha key not found"))?;

        let cipher = ChaCha20Poly1305::new_from_slice(chacha_key)
            .map_err(|e| anyhow!("Failed to create ChaCha cipher: {}", e))?;

        let nonce = ChaChaNonce::try_from(&self.iv[..])
            .map_err(|e| anyhow!("Failed to create ChaCha nonce: {}", e))?;

        let double_encrypted = cipher
            .encrypt(&nonce, &*aes_encrypted)
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

        // Second layer: ChaCha20-Poly1305 on top of AES
        let chacha_key = self
            .derived_keys
            .get("chacha")
            .ok_or_else(|| anyhow!("ChaCha key not found"))?;

        let cipher = ChaCha20Poly1305::new_from_slice(chacha_key)
            .map_err(|e| anyhow!("Failed to create ChaCha cipher: {}", e))?;

        let nonce = ChaChaNonce::try_from(&self.iv[..])
            .map_err(|e| anyhow!("Failed to create ChaCha nonce: {}", e))?;

        let chacha_encrypted = cipher
            .encrypt(&nonce, &*aes_encrypted)
            .map_err(|e| anyhow!("Failed to encrypt with ChaCha: {}", e))?;

        // Third layer: Additional quantum-resistant layer with parallel processing
        let quantum_key = self
            .derived_keys
            .get("quantum")
            .ok_or_else(|| anyhow!("Quantum key not found"))?;

        // Report progress for quantum rounds
        if let Some(callback) = &self.progress_callback {
            if let Ok(callback) = callback.lock() {
                callback("Applying quantum-resistant encryption rounds", 0.0);
            }
        }

        // Use parallel processing for quantum rounds with hardware acceleration
        let num_rounds = if self.settings.testing_mode { 1 } else { 3 };
        let num_threads = HardwareAccelerator::optimal_thread_count().min(num_rounds as usize);

        let rounds_per_thread = num_rounds / num_threads as u32;
        let remaining_rounds = num_rounds % num_threads as u32;

        let mut quantum_encrypted = chacha_encrypted;
        let progress_counter = Arc::new(AtomicU32::new(0));

        // Process rounds in parallel
        for thread_id in 0..num_threads {
            let start_round = thread_id as u32 * rounds_per_thread;
            let end_round = if thread_id == num_threads - 1 {
                start_round + rounds_per_thread + remaining_rounds
            } else {
                start_round + rounds_per_thread
            };

            let thread_quantum_key = quantum_key.clone();
            let thread_settings = self.settings.clone();
            let thread_iv = self.iv.clone();
            let thread_progress_callback = self.progress_callback.clone();
            let thread_progress_counter = progress_counter.clone();
            let thread_data = quantum_encrypted.clone();
            let thread_hardware_aes = HardwareAes::new();

            let handle = thread::spawn(move || {
                let mut thread_encrypted = thread_data;

                for round in start_round..end_round {
                    // Report progress
                    if let Some(callback) = &thread_progress_callback {
                        if let Ok(callback) = callback.lock() {
                            let current_progress = thread_progress_counter.load(Ordering::Relaxed);
                            callback(
                                &format!(
                                    "Quantum encryption round {}/{}",
                                    current_progress + 1,
                                    num_rounds
                                ),
                                (current_progress as f32) / (num_rounds as f32),
                            );
                        }
                    }

                    let round_key = Self::derive_key(
                        &thread_quantum_key,
                        &round.to_le_bytes(),
                        &thread_settings,
                    )
                    .map_err(|e| anyhow!("Failed to derive round key: {}", e))?;

                    // Use hardware-accelerated AES for quantum rounds
                    thread_encrypted = thread_hardware_aes
                        .encrypt(&round_key, &thread_iv, &thread_encrypted)
                        .map_err(|e| anyhow!("Failed to encrypt round {}: {}", round, e))?;

                    thread_progress_counter.fetch_add(1, Ordering::Relaxed);
                }

                Ok::<Vec<u8>, anyhow::Error>(thread_encrypted)
            });

            quantum_encrypted = handle
                .join()
                .map_err(|_| anyhow!("Thread execution failed"))??;
        }

        // Combine all layers
        let mut result = Vec::new();
        result.extend_from_slice(&self.iv);
        result.extend_from_slice(&quantum_encrypted);

        Ok(result)
    }

    /// Decrypt data
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        let mut progress = ProgressIndicator::new("Decryption", 3);
        if let Some(callback) = &self.progress_callback {
            progress = progress.with_callback(callback.clone());
        }

        progress.update(1, "Starting decryption");

        let result = match self.security_level {
            SecurityLevel::Standard => {
                progress.update(2, "Using standard AES-256-GCM decryption");
                self.decrypt_standard(encrypted_data)
            }
            SecurityLevel::High => {
                progress.update(2, "Using high security (AES + ChaCha20) decryption");
                self.decrypt_high(encrypted_data)
            }
            SecurityLevel::Quantum => {
                progress.update(2, "Using quantum-resistant decryption");
                self.decrypt_quantum(encrypted_data)
            }
        };

        progress.update(3, "Decryption complete");
        result
    }

    /// Decrypt standard encryption
    fn decrypt_standard(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
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

    /// Decrypt high security encryption
    fn decrypt_high(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        if encrypted_data.len() < self.settings.iv_length {
            return Err(anyhow!("Encrypted data too short"));
        }

        let (iv_data, cipher_data) = encrypted_data.split_at(self.settings.iv_length);

        // Decrypt ChaCha20 layer
        let chacha_key = self
            .derived_keys
            .get("chacha")
            .ok_or_else(|| anyhow!("ChaCha key not found"))?;

        let cipher = ChaCha20Poly1305::new_from_slice(chacha_key)
            .map_err(|e| anyhow!("Failed to create ChaCha cipher: {}", e))?;

        let nonce = ChaChaNonce::try_from(iv_data)
            .map_err(|e| anyhow!("Failed to create ChaCha nonce: {}", e))?;

        let chacha_decrypted = cipher
            .decrypt(&nonce, cipher_data)
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
        let quantum_key = self
            .derived_keys
            .get("quantum")
            .ok_or_else(|| anyhow!("Quantum key not found"))?;

        let mut quantum_decrypted = cipher_data.to_vec();

        // Report progress for quantum decryption rounds
        if let Some(callback) = &self.progress_callback {
            if let Ok(callback) = callback.lock() {
                callback("Applying quantum-resistant decryption rounds", 0.0);
            }
        }

        // Use sequential processing for quantum decryption (simpler and safer)
        let num_rounds = if self.settings.testing_mode { 1 } else { 3 };

        // Multiple rounds in reverse order
        for (i, round) in (0u32..num_rounds).rev().enumerate() {
            if let Some(callback) = &self.progress_callback {
                if let Ok(callback) = callback.lock() {
                    callback(
                        &format!("Quantum decryption round {}/{}", i + 1, num_rounds),
                        (i as f32) / (num_rounds as f32),
                    );
                }
            }

            let round_key = Self::derive_key(quantum_key, &round.to_le_bytes(), &self.settings)?;

            // Use hardware-accelerated AES for quantum decryption
            quantum_decrypted = self
                .hardware_aes
                .decrypt(&round_key, iv_data, &quantum_decrypted)
                .map_err(|e| anyhow!("Failed to decrypt round {}: {}", round, e))?;
        }

        // Decrypt ChaCha20 layer
        let chacha_key = self
            .derived_keys
            .get("chacha")
            .ok_or_else(|| anyhow!("ChaCha key not found"))?;

        let cipher = ChaCha20Poly1305::new_from_slice(chacha_key)
            .map_err(|e| anyhow!("Failed to create ChaCha cipher: {}", e))?;

        let nonce = ChaChaNonce::try_from(iv_data)
            .map_err(|e| anyhow!("Failed to create ChaCha nonce: {}", e))?;

        let chacha_decrypted = cipher
            .decrypt(&nonce, &*quantum_decrypted)
            .map_err(|e| anyhow!("Failed to decrypt ChaCha layer: {}", e))?;

        // Decrypt AES layer
        self.decrypt_standard(&chacha_decrypted)
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
            let item_data =
                serde_json::to_vec(item).map_err(|e| anyhow!("Failed to serialize item: {}", e))?;
            hasher.update(&item_data);
        }

        // Add salt for additional security
        hasher.update(&self.salt);

        Ok(general_purpose::STANDARD.encode(hasher.finalize()))
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
