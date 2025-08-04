use crate::crypto::{EncryptionContext, ProgressCallback};
use crate::models::{DatabaseSettings, Item, PasswordDatabase, SecurityLevel, SecuritySettings};
use anyhow::{anyhow, Result};
use chrono::Utc;
use std::fs;
use uuid::Uuid;

/// Database manager for handling password database operations
pub struct DatabaseManager {
    pub database: PasswordDatabase,
    pub encryption_context: Option<EncryptionContext>,
    pub file_path: Option<String>,
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
        let encrypted_data =
            fs::read(file_path).map_err(|e| anyhow!("Failed to read database file: {}", e))?;

        // Try to decrypt with different security levels
        for (i, security_level) in [
            SecurityLevel::Standard,
            SecurityLevel::High,
            SecurityLevel::Quantum,
        ]
        .iter()
        .enumerate()
        {
            if let Some(callback) = &progress_callback {
                if let Ok(callback) = callback.lock() {
                    callback(
                        &format!("Trying security level {security_level:?}"),
                        (i as f32) / 3.0,
                    );
                }
            }

            let settings = SecuritySettings::default();
            let encryption_context = EncryptionContext::new_with_progress(
                master_password,
                security_level.clone(),
                settings,
                progress_callback.clone(),
            )?;

            match encryption_context.decrypt(&encrypted_data) {
                Ok(decrypted_data) => {
                    let database: PasswordDatabase = serde_json::from_slice(&decrypted_data)
                        .map_err(|e| anyhow!("Failed to deserialize database: {}", e))?;

                    // Verify integrity
                    let calculated_hash =
                        encryption_context.calculate_integrity_hash(&database.items)?;
                    if calculated_hash != database.integrity_hash {
                        return Err(anyhow!("Database integrity check failed"));
                    }

                    if let Some(callback) = &progress_callback {
                        if let Ok(callback) = callback.lock() {
                            callback("Database loaded successfully", 1.0);
                        }
                    }

                    return Ok(Self {
                        database,
                        encryption_context: Some(encryption_context),
                        file_path: Some(file_path.to_string()),
                    });
                }
                Err(_) => continue,
            }
        }

        Err(anyhow!(
            "Failed to decrypt database with any security level"
        ))
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
                SecuritySettings::default(),
                progress_callback.clone(),
            )?
        };

        // Update integrity hash
        if let Some(callback) = &progress_callback {
            if let Ok(callback) = callback.lock() {
                callback("Calculating integrity hash", 0.2);
            }
        }
        self.database.integrity_hash =
            encryption_context.calculate_integrity_hash(&self.database.items)?;
        self.database.updated_at = Utc::now();

        // Serialize database
        if let Some(callback) = &progress_callback {
            if let Ok(callback) = callback.lock() {
                callback("Serializing database", 0.4);
            }
        }
        let json_data = serde_json::to_vec(&self.database)
            .map_err(|e| anyhow!("Failed to serialize database: {}", e))?;

        // Encrypt data
        if let Some(callback) = &progress_callback {
            if let Ok(callback) = callback.lock() {
                callback("Encrypting database", 0.6);
            }
        }
        let encrypted_data = encryption_context.encrypt(&json_data)?;

        // Write to file
        if let Some(callback) = &progress_callback {
            if let Ok(callback) = callback.lock() {
                callback("Writing to file", 0.8);
            }
        }
        fs::write(file_path, encrypted_data)
            .map_err(|e| anyhow!("Failed to write database file: {}", e))?;

        if let Some(callback) = &progress_callback {
            if let Ok(callback) = callback.lock() {
                callback("Database saved successfully", 1.0);
            }
        }

        self.encryption_context = Some(encryption_context);
        self.file_path = Some(file_path.to_string());

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
            for item in &self.database.items {
                if !ctx.verify_item_integrity(item)? {
                    return Ok(false);
                }
            }

            // Verify overall integrity hash
            let calculated_hash = ctx.calculate_integrity_hash(&self.database.items)?;
            Ok(calculated_hash == self.database.integrity_hash)
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
        let new_encryption_context = EncryptionContext::new(
            new_password,
            self.database.security_level.clone(),
            SecuritySettings::default(),
        )?;

        // Re-encrypt all items with new context
        for item in &mut self.database.items {
            new_encryption_context.update_item_integrity(item)?;
        }

        self.encryption_context = Some(new_encryption_context);
        self.database.updated_at = Utc::now();

        Ok(())
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
        self.encryption_context = None;
    }

    /// Unlock database with master password
    pub fn unlock(&mut self, master_password: &str) -> Result<()> {
        if let Some(file_path) = &self.file_path {
            let new_manager = Self::load_from_file(file_path, master_password)?;
            self.encryption_context = new_manager.encryption_context;
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
