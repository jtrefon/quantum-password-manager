use crate::crypto::{EncryptionContext, ProgressCallback};
use crate::models::{DatabaseSettings, Item, PasswordDatabase, SecurityLevel, SecuritySettings};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use uuid::Uuid;
use zeroize::Zeroize;

/// File header stored alongside ciphertext
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileHeader {
    magic: String,       // "PMDB"
    header_version: u32, // 1
    security_level: SecurityLevel,
    kdf_settings: SecuritySettings,
    salt_b64: String,
    hmac_b64: String,  // HMAC over plaintext JSON
    algorithm: String, // "AES-256-GCM"
}

/// Database manager for handling password database operations
pub struct DatabaseManager {
    pub database: PasswordDatabase,
    pub encryption_context: Option<EncryptionContext>,
    pub file_path: Option<String>,
    pub file_hmac: Option<Vec<u8>>, // HMAC of last saved/loaded plaintext
}

impl DatabaseManager {
    /// Create a new empty database
    pub fn new(name: String, security_level: SecurityLevel) -> Result<Self> {
        Self::new_with_progress(name, security_level, None)
    }

    /// Create a new empty database with progress callback
    pub fn new_with_progress(
        name: String,
        security_level: SecurityLevel,
        _progress_callback: Option<ProgressCallback>,
    ) -> Result<Self> {
        let _settings = SecuritySettings::default();
        let database = PasswordDatabase {
            version: "1.0.0".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            security_level,
            items: Vec::new(),
            metadata: crate::models::DatabaseMetadata {
                name,
                description: None,
                settings: DatabaseSettings::default(),
                custom_fields: std::collections::HashMap::new(),
            },
            integrity_hash: String::new(),
        };

        Ok(Self {
            database,
            encryption_context: None,
            file_path: None,
            file_hmac: None,
        })
    }

    /// Load database from file
    pub fn load_from_file(file_path: &str, master_password: &str) -> Result<Self> {
        Self::load_from_file_with_progress(file_path, master_password, None)
    }

    /// Load database from file with progress callback
    pub fn load_from_file_with_progress(
        file_path: &str,
        master_password: &str,
        progress_callback: Option<ProgressCallback>,
    ) -> Result<Self> {
        let file_bytes =
            fs::read(file_path).map_err(|e| anyhow!("Failed to read database file: {}", e))?;

        // Parse magic and header length
        if file_bytes.len() < 8 {
            return Err(anyhow!("Database file too short"));
        }
        if &file_bytes[0..4] != b"PMDB" {
            return Err(anyhow!("Invalid file magic"));
        }
        let header_len =
            u32::from_le_bytes([file_bytes[4], file_bytes[5], file_bytes[6], file_bytes[7]])
                as usize;
        if file_bytes.len() < 8 + header_len {
            return Err(anyhow!("Corrupted file header"));
        }

        let header_json = &file_bytes[8..8 + header_len];
        let header: FileHeader = serde_json::from_slice(header_json)
            .map_err(|e| anyhow!("Failed to parse header: {}", e))?;
        if header.magic != "PMDB" {
            return Err(anyhow!("Invalid header magic"));
        }
        if header.header_version != 1 {
            return Err(anyhow!("Unsupported header version"));
        }
        if header.algorithm != "AES-256-GCM" {
            return Err(anyhow!("Unsupported algorithm"));
        }

        let salt = general_purpose::STANDARD
            .decode(header.salt_b64.as_bytes())
            .map_err(|e| anyhow!("Failed to decode salt: {}", e))?;

        let ciphertext = &file_bytes[8 + header_len..];

        let encryption_context = EncryptionContext::from_params_with_progress(
            master_password,
            header.security_level.clone(),
            header.kdf_settings.clone(),
            salt,
            progress_callback.clone(),
        )?;

        let decrypted_data = encryption_context.decrypt(ciphertext)?;

        // Verify HMAC over plaintext
        let expected_hmac = general_purpose::STANDARD
            .decode(header.hmac_b64.as_bytes())
            .map_err(|e| anyhow!("Failed to decode HMAC: {}", e))?;
        let is_valid = encryption_context.verify_hmac(&decrypted_data, &expected_hmac)?;
        if !is_valid {
            return Err(anyhow!("Database integrity (HMAC) check failed"));
        }

        let database: PasswordDatabase = serde_json::from_slice(&decrypted_data)
            .map_err(|e| anyhow!("Failed to deserialize database: {}", e))?;

        if let Some(callback) = &progress_callback {
            callback("Database loaded successfully", 1.0);
        }

        Ok(Self {
            database,
            encryption_context: Some(encryption_context),
            file_path: Some(file_path.to_string()),
            file_hmac: Some(expected_hmac),
        })
    }

    /// Save database to file
    pub fn save_to_file(&mut self, file_path: &str, master_password: &str) -> Result<()> {
        self.save_to_file_with_progress(file_path, master_password, None)
    }

    /// Save database to file with progress callback
    pub fn save_to_file_with_progress(
        &mut self,
        file_path: &str,
        master_password: &str,
        progress_callback: Option<ProgressCallback>,
    ) -> Result<()> {
        let encryption_context = if let Some(ctx) = &self.encryption_context {
            ctx.clone()
        } else {
            EncryptionContext::new_with_progress(
                master_password,
                self.database.security_level.clone(),
                self.database.metadata.settings.security_settings.clone(),
                progress_callback.clone(),
            )?
        };

        self.database.updated_at = Utc::now();

        // Serialize database
        if let Some(callback) = &progress_callback {
            callback("Serializing database", 0.3);
        }
        let json_data = serde_json::to_vec(&self.database)
            .map_err(|e| anyhow!("Failed to serialize database: {}", e))?;

        // Compute HMAC over plaintext
        let hmac = encryption_context.compute_hmac(&json_data)?;

        // Encrypt data
        if let Some(callback) = &progress_callback {
            callback("Encrypting database", 0.6);
        }
        let encrypted_data = encryption_context.encrypt(&json_data)?;

        // Build header
        let header = FileHeader {
            magic: "PMDB".to_string(),
            header_version: 1,
            security_level: self.database.security_level.clone(),
            kdf_settings: encryption_context.settings.clone(),
            salt_b64: general_purpose::STANDARD.encode(&encryption_context.salt),
            hmac_b64: general_purpose::STANDARD.encode(&hmac),
            algorithm: "AES-256-GCM".to_string(),
        };
        let header_json = serde_json::to_vec(&header)
            .map_err(|e| anyhow!("Failed to serialize header: {}", e))?;

        // Compose file: magic + header_len + header_json + encrypted
        let mut file_bytes = Vec::with_capacity(8 + header_json.len() + encrypted_data.len());
        file_bytes.extend_from_slice(b"PMDB");
        file_bytes.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
        file_bytes.extend_from_slice(&header_json);
        file_bytes.extend_from_slice(&encrypted_data);

        // Write to file
        if let Some(callback) = &progress_callback {
            callback("Writing to file", 0.9);
        }
        fs::write(file_path, file_bytes)
            .map_err(|e| anyhow!("Failed to write database file: {}", e))?;

        if let Some(callback) = &progress_callback {
            callback("Database saved successfully", 1.0);
        }

        self.encryption_context = Some(encryption_context);
        self.file_path = Some(file_path.to_string());
        self.file_hmac = Some(hmac);

        Ok(())
    }

    /// Add item to database
    pub fn add_item(&mut self, item: Item) -> Result<()> {
        if let Some(ctx) = &self.encryption_context {
            let mut item = item;
            ctx.update_item_integrity(&mut item)?;
            self.database.items.push(item);
            self.database.updated_at = Utc::now();
            Ok(())
        } else {
            Err(anyhow!("Database not initialized with encryption context"))
        }
    }

    /// Remove item from database
    pub fn remove_item(&mut self, item_id: Uuid) -> Result<()> {
        self.database.items.retain(|item| item.get_id() != item_id);
        self.database.updated_at = Utc::now();
        Ok(())
    }

    /// Get item by ID
    pub fn get_item(&self, item_id: Uuid) -> Option<&Item> {
        self.database
            .items
            .iter()
            .find(|item| item.get_id() == item_id)
    }

    /// Get item by ID (mutable)
    #[allow(dead_code)]
    pub fn get_item_mut(&mut self, item_id: Uuid) -> Option<&mut Item> {
        self.database
            .items
            .iter_mut()
            .find(|item| item.get_id() == item_id)
    }

    /// Update item in database
    pub fn update_item(&mut self, item_id: Uuid, updated_item: Item) -> Result<()> {
        if let Some(ctx) = &self.encryption_context {
            let mut updated_item = updated_item;
            ctx.update_item_integrity(&mut updated_item)?;

            if let Some(index) = self
                .database
                .items
                .iter()
                .position(|item| item.get_id() == item_id)
            {
                self.database.items[index] = updated_item;
                self.database.updated_at = Utc::now();
                Ok(())
            } else {
                Err(anyhow!("Item not found"))
            }
        } else {
            Err(anyhow!("Database not initialized with encryption context"))
        }
    }

    /// Search items by name
    pub fn search_items(&self, query: &str) -> Vec<&Item> {
        let query_lower = query.to_lowercase();
        self.database
            .items
            .iter()
            .filter(|item| {
                let name = item.get_name().to_lowercase();
                name.contains(&query_lower)
            })
            .collect()
    }

    /// Get items by type
    pub fn get_items_by_type(&self, item_type: &crate::models::ItemType) -> Vec<&Item> {
        self.database
            .items
            .iter()
            .filter(|item| {
                std::mem::discriminant(item.get_type()) == std::mem::discriminant(item_type)
            })
            .collect()
    }

    /// Get items in folder
    #[allow(dead_code)]
    pub fn get_items_in_folder(&self, folder_id: Uuid) -> Vec<&Item> {
        self.database
            .items
            .iter()
            .filter(|item| {
                if let Some(id) = item.get_base().folder_id {
                    id == folder_id
                } else {
                    false
                }
            })
            .collect()
    }

    /// Verify integrity of all items
    pub fn verify_integrity(&self) -> Result<bool> {
        if let Some(ctx) = &self.encryption_context {
            // Optional: keep per-item integrity checks
            for item in &self.database.items {
                if !ctx.verify_item_integrity(item)? {
                    return Ok(false);
                }
            }
            // Verify HMAC against the last loaded/saved HMAC
            let json_data = serde_json::to_vec(&self.database)
                .map_err(|e| anyhow!("Failed to serialize database: {}", e))?;
            if let Some(file_hmac) = &self.file_hmac {
                // Use constant-time verification via HMAC API
                ctx.verify_hmac(&json_data, file_hmac)
            } else {
                Ok(true)
            }
        } else {
            Err(anyhow!("Database not initialized with encryption context"))
        }
    }

    /// Get database statistics
    pub fn get_statistics(&self) -> DatabaseStatistics {
        let mut stats = DatabaseStatistics {
            total_items: self.database.items.len(),
            credentials: 0,
            folders: 0,
            keys: 0,
            urls: 0,
            notes: 0,
            secure_notes: 0,
        };

        for item in &self.database.items {
            match item {
                Item::Credential(_) => stats.credentials += 1,
                Item::Folder(_) => stats.folders += 1,
                Item::Key(_) => stats.keys += 1,
                Item::Url(_) => stats.urls += 1,
                Item::Note(_) => stats.notes += 1,
                Item::SecureNote(_) => stats.secure_notes += 1,
            }
        }

        stats
    }

    /// Export database to JSON (unencrypted, for backup)
    pub fn export_to_json(&self, file_path: &str) -> Result<()> {
        let json_data = serde_json::to_string_pretty(&self.database)
            .map_err(|e| anyhow!("Failed to serialize database: {}", e))?;

        fs::write(file_path, json_data).map_err(|e| anyhow!("Failed to write JSON file: {}", e))?;

        Ok(())
    }

    /// Import database from JSON (unencrypted, for restore)
    pub fn import_from_json(&mut self, file_path: &str) -> Result<()> {
        let json_data = fs::read_to_string(file_path)
            .map_err(|e| anyhow!("Failed to read JSON file: {}", e))?;

        let database: PasswordDatabase = serde_json::from_str(&json_data)
            .map_err(|e| anyhow!("Failed to deserialize JSON: {}", e))?;

        self.database = database;
        Ok(())
    }

    /// Change master password
    pub fn change_master_password(&mut self, new_password: &str) -> Result<()> {
        let settings = self.database.metadata.settings.security_settings.clone();
        let new_encryption_context =
            EncryptionContext::new(new_password, self.database.security_level.clone(), settings)?;

        // Recompute per-item integrity using the new context
        for item in &mut self.database.items {
            new_encryption_context.update_item_integrity(item)?;
        }

        self.encryption_context = Some(new_encryption_context);
        // Clear stored HMAC until database is saved with the new master password
        self.file_hmac = None;
        self.database.updated_at = Utc::now();

        Ok(())
    }

    fn zeroize_items(items: &mut [Item]) {
        for item in items.iter_mut() {
            {
                let base = item.get_base_mut();
                base.name.zeroize();
                for tag in &mut base.tags {
                    tag.zeroize();
                }
            }
            match item {
                Item::Credential(c) => {
                    c.username.zeroize();
                    c.password.zeroize();
                    if let Some(url) = &mut c.url {
                        url.zeroize();
                    }
                    if let Some(notes) = &mut c.notes {
                        notes.zeroize();
                    }
                    if let Some(totp) = &mut c.totp_secret {
                        totp.zeroize();
                    }
                    for history in &mut c.password_history {
                        history.password.zeroize();
                    }
                }
                Item::SecureNote(s) => {
                    s.encrypted_content.zeroize();
                    for value in s.additional_metadata.values_mut() {
                        value.zeroize();
                    }
                }
                Item::Key(k) => {
                    k.key_data.zeroize();
                }
                Item::Note(n) => {
                    n.content.zeroize();
                }
                Item::Url(u) => {
                    u.url.zeroize();
                    if let Some(title) = &mut u.title {
                        title.zeroize();
                    }
                    if let Some(favicon) = &mut u.favicon {
                        favicon.zeroize();
                    }
                    if let Some(notes) = &mut u.notes {
                        notes.zeroize();
                    }
                }
                Item::Folder(f) => {
                    if let Some(desc) = &mut f.description {
                        desc.zeroize();
                    }
                    if let Some(color) = &mut f.color {
                        color.zeroize();
                    }
                }
            }
        }
    }

    /// Get database metadata
    pub fn get_metadata(&self) -> &crate::models::DatabaseMetadata {
        &self.database.metadata
    }

    /// Update database metadata
    #[allow(dead_code)]
    pub fn update_metadata(&mut self, metadata: crate::models::DatabaseMetadata) -> Result<()> {
        self.database.metadata = metadata;
        self.database.updated_at = Utc::now();
        Ok(())
    }

    /// Check if database is locked
    #[allow(dead_code)]
    pub fn is_locked(&self) -> bool {
        self.encryption_context.is_none()
    }

    /// Lock database (clear encryption context)
    pub fn lock(&mut self) {
        Self::zeroize_items(&mut self.database.items);
        self.database.items.clear();
        self.encryption_context = None;
        self.file_hmac = None;
    }

    /// Unlock database with master password
    pub fn unlock(&mut self, master_password: &str) -> Result<()> {
        if let Some(file_path) = self.file_path.clone() {
            let new_manager = Self::load_from_file(&file_path, master_password)?;
            self.database = new_manager.database;
            self.encryption_context = new_manager.encryption_context;
            self.file_hmac = new_manager.file_hmac;
            self.file_path = new_manager.file_path;
            Ok(())
        } else {
            Err(anyhow!("No file path set for database"))
        }
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStatistics {
    pub total_items: usize,
    pub credentials: usize,
    pub folders: usize,
    pub keys: usize,
    pub urls: usize,
    pub notes: usize,
    pub secure_notes: usize,
}

impl std::fmt::Display for DatabaseStatistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Database Statistics:")?;
        writeln!(f, "  Total Items: {}", self.total_items)?;
        writeln!(f, "  Credentials: {}", self.credentials)?;
        writeln!(f, "  Folders: {}", self.folders)?;
        writeln!(f, "  Keys: {}", self.keys)?;
        writeln!(f, "  URLs: {}", self.urls)?;
        writeln!(f, "  Notes: {}", self.notes)?;
        write!(f, "  Secure Notes: {}", self.secure_notes)
    }
}
