use crate::hardware::{HardwareAccelerator, HardwareAes};
use crate::models::{SecurityLevel, SecuritySettings};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, Result};
use argon2::Argon2;
use base64::{engine::general_purpose, Engine as _};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::progress::{ProgressCallback, ProgressIndicator};

/// Encryption context with all necessary keys and parameters
#[derive(Clone)]
pub struct EncryptionContext {
    pub salt: Vec<u8>,
    #[allow(dead_code)]
    pub security_level: SecurityLevel,
    pub settings: SecuritySettings,
    pub aes_key: Vec<u8>,
    pub integrity_key: Vec<u8>,
    pub progress_callback: Option<ProgressCallback>,
    #[allow(dead_code)]
    pub hardware_aes: HardwareAes,
}

impl Drop for EncryptionContext {
    fn drop(&mut self) {
        self.salt.zeroize();
        self.aes_key.zeroize();
        self.integrity_key.zeroize();
    }
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
        let mut master_key = Self::derive_master_key(
            master_password,
            &salt,
            &settings,
            progress_callback.as_ref(),
        )?;

        // Generate additional keys for different purposes using HKDF
        let aes_key = Self::derive_key(&master_key, b"aes_key", &security_level)?;

        // Key for integrity checking (HMAC)
        let integrity_key = Self::derive_key(&master_key, b"integrity_key", &security_level)?;

        // Master key is no longer needed after deriving other keys
        master_key.zeroize();

        Ok(Self {
            salt,
            security_level,
            settings,
            aes_key,
            integrity_key,
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
            callback("Deriving master key with Argon2", 0.0);
        }

        let mut output = vec![0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut output)
            .map_err(|e| anyhow!("Failed to derive key: {}", e))?;

        // Report completion
        if let Some(callback) = progress_callback {
            callback("Master key derivation complete", 1.0);
        }

        Ok(output)
    }

    /// Derive additional keys for different purposes
    fn derive_key(
        master_key: &[u8],
        purpose: &[u8],
        security_level: &SecurityLevel,
    ) -> Result<Vec<u8>> {
        let mut okm = [0u8; 32];
        if *security_level == SecurityLevel::Quantum {
            let hk = Hkdf::<Sha3_256>::new(None, master_key);
            hk.expand(purpose, &mut okm)
                .map_err(|e| anyhow!("Failed to derive key: {:?}", e))?;
        } else {
            let hk = Hkdf::<Sha256>::new(None, master_key);
            hk.expand(purpose, &mut okm)
                .map_err(|e| anyhow!("Failed to derive key: {:?}", e))?;
        }
        Ok(okm.to_vec())
    }

    /// Encrypt data (single AEAD under the hood)
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut progress = ProgressIndicator::new("Encryption", 2);
        if let Some(callback) = &self.progress_callback {
            progress = progress.with_callback(callback.clone());
        }
        // Announce hardware acceleration status via progress callback
        if let Some(callback) = &self.progress_callback {
            let accel = if HardwareAccelerator::is_available() {
                "available"
            } else {
                "not available"
            };
            callback(&format!("Hardware acceleration is {accel}"), 0.0);
        }
        progress.update(1, "Encrypting with AES-256-GCM");
        let result = self.encrypt_aes_gcm(data)?;
        progress.finish("Encryption complete");
        Ok(result)
    }

    /// AES-256-GCM with fresh nonce per encryption. Output: nonce || ciphertext
    fn encrypt_aes_gcm(&self, data: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.aes_key)
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
            let accel = if HardwareAccelerator::is_available() {
                "available"
            } else {
                "not available"
            };
            callback(&format!("Hardware acceleration is {accel}"), 0.0);
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

        let cipher = Aes256Gcm::new_from_slice(&self.aes_key)
            .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;

        let nonce = Nonce::from_slice(iv_data);

        let decrypted = cipher
            .decrypt(nonce, cipher_data)
            .map_err(|e| anyhow!("Failed to decrypt data: {}", e))?;

        Ok(decrypted)
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
        let key = &self.integrity_key;
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
        let key = &self.integrity_key;
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
        let expected = match general_purpose::STANDARD.decode(&base.hmac) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let calculated = self.compute_hmac(&item_data)?;
        Ok(expected.as_slice().ct_eq(&calculated).into())
    }

    /// Update integrity checksums for an item
    pub fn update_item_integrity(&self, item: &mut crate::models::Item) -> Result<()> {
        let item_data =
            serde_json::to_vec(item).map_err(|e| anyhow!("Failed to serialize item: {}", e))?;
        let hmac = self.compute_hmac(&item_data)?;
        let base = item.get_base_mut();
        base.hmac = general_purpose::STANDARD.encode(hmac);
        Ok(())
    }
}
