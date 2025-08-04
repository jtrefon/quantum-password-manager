use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Security level configuration for encryption
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum SecurityLevel {
    Standard, // AES-256-GCM
    #[default]
    High,     // AES-256-GCM + ChaCha20-Poly1305
    Quantum,  // AES-256-GCM + ChaCha20-Poly1305 + additional rounds
}

/// Types of items that can be stored
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ItemType {
    Credential,
    Folder,
    Key,
    Url,
    Note,
    SecureNote,
}

/// Base item structure with common fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseItem {
    pub id: Uuid,
    pub name: String,
    pub item_type: ItemType,
    pub folder_id: Option<Uuid>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub crc32: u32,
    pub sha256: String,
}

/// Credential item for storing login information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub base: BaseItem,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub totp_secret: Option<String>,
    pub last_used: Option<DateTime<Utc>>,
    pub password_history: Vec<PasswordHistory>,
}

/// Password history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordHistory {
    pub password: String,
    pub changed_at: DateTime<Utc>,
}

/// Folder for organizing items
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub base: BaseItem,
    pub description: Option<String>,
    pub color: Option<String>,
}

/// Cryptographic key storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key {
    pub base: BaseItem,
    pub key_type: KeyType,
    pub key_data: String, // Base64 encoded
    pub algorithm: String,
    pub key_size: u32,
    pub usage: Vec<KeyUsage>,
}

/// Types of cryptographic keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    Symmetric,
    Asymmetric,
    Hmac,
    Derivation,
}

/// Key usage purposes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyUsage {
    Encryption,
    Decryption,
    Signing,
    Verification,
    KeyExchange,
    KeyDerivation,
}

/// URL item for storing web addresses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Url {
    pub base: BaseItem,
    pub url: String,
    pub title: Option<String>,
    pub favicon: Option<String>,
    pub notes: Option<String>,
}

/// Note item for storing text information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    pub base: BaseItem,
    pub content: String,
    pub is_encrypted: bool,
    pub format: NoteFormat,
}

/// Note format types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NoteFormat {
    PlainText,
    Markdown,
    Json,
    Xml,
}

/// Secure note with additional encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureNote {
    pub base: BaseItem,
    pub encrypted_content: String,
    pub content_type: String,
    pub additional_metadata: HashMap<String, String>,
}

/// Union type for all items
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Item {
    Credential(Credential),
    Folder(Folder),
    Key(Key),
    Url(Url),
    Note(Note),
    SecureNote(SecureNote),
}

impl Item {
    pub fn get_base(&self) -> &BaseItem {
        match self {
            Item::Credential(c) => &c.base,
            Item::Folder(f) => &f.base,
            Item::Key(k) => &k.base,
            Item::Url(u) => &u.base,
            Item::Note(n) => &n.base,
            Item::SecureNote(s) => &s.base,
        }
    }

    pub fn get_base_mut(&mut self) -> &mut BaseItem {
        match self {
            Item::Credential(c) => &mut c.base,
            Item::Folder(f) => &mut f.base,
            Item::Key(k) => &mut k.base,
            Item::Url(u) => &mut u.base,
            Item::Note(n) => &mut n.base,
            Item::SecureNote(s) => &mut s.base,
        }
    }

    pub fn get_id(&self) -> Uuid {
        self.get_base().id
    }

    pub fn get_name(&self) -> &str {
        &self.get_base().name
    }

    pub fn get_type(&self) -> &ItemType {
        &self.get_base().item_type
    }
}

/// Main database structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordDatabase {
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub security_level: SecurityLevel,
    pub items: Vec<Item>,
    pub metadata: DatabaseMetadata,
    pub integrity_hash: String,
}

/// Database metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseMetadata {
    pub name: String,
    pub description: Option<String>,
    pub settings: DatabaseSettings,
    pub custom_fields: HashMap<String, String>,
}

/// Database settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseSettings {
    pub auto_lock_timeout: u64,
    pub password_generator_settings: PasswordGeneratorSettings,
    pub security_settings: SecuritySettings,
}

/// Password generator settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordGeneratorSettings {
    pub length: u32,
    pub use_uppercase: bool,
    pub use_lowercase: bool,
    pub use_numbers: bool,
    pub use_symbols: bool,
    pub exclude_similar: bool,
    pub exclude_ambiguous: bool,
}

/// Security settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    pub key_derivation_iterations: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
    pub salt_length: usize,
    pub iv_length: usize,
    pub tag_length: usize,
    pub testing_mode: bool,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            key_derivation_iterations: 100_000,
            memory_cost: 65536,
            parallelism: 4,
            salt_length: 32,
            iv_length: 12,
            tag_length: 16,
            testing_mode: false,
        }
    }
}

impl Default for PasswordGeneratorSettings {
    fn default() -> Self {
        Self {
            length: 20,
            use_uppercase: true,
            use_lowercase: true,
            use_numbers: true,
            use_symbols: true,
            exclude_similar: true,
            exclude_ambiguous: false,
        }
    }
}

impl Default for DatabaseSettings {
    fn default() -> Self {
        Self {
            auto_lock_timeout: 300, // 5 minutes
            password_generator_settings: PasswordGeneratorSettings::default(),
            security_settings: SecuritySettings::default(),
        }
    }
}
