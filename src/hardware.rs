use anyhow::{anyhow, Result};

/// Hardware acceleration capabilities
#[derive(Debug, Clone)]
pub struct HardwareCapabilities {
    pub aes_ni: bool,
    pub aes_arm: bool,
    pub sha_ni: bool,
    pub sha_arm: bool,
    pub apple_silicon: bool,
    pub available_cores: usize,
}

static HARDWARE_CAPABILITIES: std::sync::OnceLock<HardwareCapabilities> =
    std::sync::OnceLock::new();

impl HardwareCapabilities {
    /// Detect hardware capabilities
    pub fn detect() -> Self {
        let mut caps = Self {
            aes_ni: false,
            aes_arm: false,
            sha_ni: false,
            sha_arm: false,
            apple_silicon: false,
            available_cores: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
        };

        // Detect Apple Silicon
        #[cfg(target_arch = "aarch64")]
        {
            caps.apple_silicon = true;
            caps.aes_arm = true;
            caps.sha_arm = true;
        }

        // Detect Intel AES-NI
        #[cfg(target_arch = "x86_64")]
        {
            caps.aes_ni = is_x86_feature_detected!("aes");
            caps.sha_ni = is_x86_feature_detected!("sha");
        }

        caps
    }

    /// Get cached hardware capabilities
    pub fn get() -> &'static Self {
        HARDWARE_CAPABILITIES.get_or_init(Self::detect)
    }

    /// Check if hardware acceleration is available
    pub fn has_hardware_acceleration(&self) -> bool {
        self.aes_ni || self.aes_arm || self.sha_ni || self.sha_arm
    }

    /// Get optimal thread count for this hardware
    pub fn optimal_thread_count(&self) -> usize {
        if self.apple_silicon {
            // Apple Silicon has excellent performance cores, use more threads
            self.available_cores * 2
        } else {
            self.available_cores
        }
    }

    /// Get hardware acceleration info
    pub fn info(&self) -> String {
        let mut info = Vec::new();

        if self.apple_silicon {
            info.push("Apple Silicon detected".to_string());
        }
        if self.aes_ni {
            info.push("Intel AES-NI available".to_string());
        }
        if self.aes_arm {
            info.push("ARM AES acceleration available".to_string());
        }
        if self.sha_ni {
            info.push("Intel SHA-NI available".to_string());
        }
        if self.sha_arm {
            info.push("ARM SHA acceleration available".to_string());
        }

        if info.is_empty() {
            info.push("No hardware acceleration detected".to_string());
        }

        info.join(", ")
    }
}

/// Hardware-accelerated AES implementation
#[derive(Clone)]
pub struct HardwareAes;

impl HardwareAes {
    pub fn new() -> Self {
        Self
    }

    /// Encrypt data using hardware acceleration
    #[allow(dead_code)]
    pub fn encrypt(&self, key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        // The aes-gcm crate automatically uses hardware acceleration when available
        // on Apple Silicon and x86_64 with AES-NI.
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;

        let nonce = Nonce::from_slice(nonce);
        let encrypted = cipher
            .encrypt(nonce, data)
            .map_err(|e| anyhow!("Failed to encrypt data: {}", e))?;

        Ok(encrypted)
    }

    /// Decrypt data using hardware acceleration
    #[allow(dead_code)]
    pub fn decrypt(&self, key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        // The aes-gcm crate automatically uses hardware acceleration when available
        // on Apple Silicon and x86_64 with AES-NI.
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;

        let nonce = Nonce::from_slice(nonce);
        let decrypted = cipher
            .decrypt(nonce, data)
            .map_err(|e| anyhow!("Failed to decrypt data: {}", e))?;

        Ok(decrypted)
    }
}

/// Hardware acceleration utilities
pub struct HardwareAccelerator;

impl HardwareAccelerator {
    /// Get hardware capabilities info
    pub fn get_capabilities_info() -> String {
        HardwareCapabilities::get().info()
    }

    /// Check if hardware acceleration is available
    pub fn is_available() -> bool {
        HardwareCapabilities::get().has_hardware_acceleration()
    }

    /// Get optimal thread count for current hardware
    pub fn optimal_thread_count() -> usize {
        HardwareCapabilities::get().optimal_thread_count()
    }

    /// Create hardware-accelerated AES instance
    #[allow(dead_code)]
    pub fn create_aes() -> HardwareAes {
        HardwareAes::new()
    }
}
