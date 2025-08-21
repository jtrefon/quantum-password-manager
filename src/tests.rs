#[cfg(test)]
mod unit_tests {
    use crate::crypto::{generate_password, EncryptionContext};
    use crate::database::DatabaseManager;
    use crate::models::*;
    use chrono::Utc;
    use tempfile::NamedTempFile;
    use uuid::Uuid;

    fn test_security_settings() -> SecuritySettings {
        SecuritySettings {
            key_derivation_iterations: 10, // Very reduced for CI testing
            memory_cost: 64,               // Very reduced for CI testing
            testing_mode: true,            // Enable testing mode for faster execution
            ..SecuritySettings::default()
        }
    }

    #[test]
    fn test_encryption_context_creation() {
        let settings = test_security_settings();

        let context =
            EncryptionContext::new("test_password", SecurityLevel::High, settings).unwrap();

        assert_eq!(context.security_level, SecurityLevel::High);
        assert_eq!(context.salt.len(), 32);
        assert_eq!(context.aes_key.len(), 32);
        assert_eq!(context.integrity_key.len(), 32);
    }

    #[test]
    fn test_encryption_decryption() {
        let settings = test_security_settings();

        let context =
            EncryptionContext::new("test_password", SecurityLevel::Standard, settings).unwrap();

        let test_data = b"Hello, World!";
        let encrypted = context.encrypt(test_data).unwrap();
        let decrypted = context.decrypt(&encrypted).unwrap();

        assert_eq!(test_data, decrypted.as_slice());
    }

    #[test]
    fn test_high_security_encryption() {
        let mut settings = test_security_settings();
        settings.key_derivation_iterations = 10; // Very reduced for CI testing

        let context =
            EncryptionContext::new("test_password", SecurityLevel::High, settings).unwrap();

        let test_data = b"Secret data for high security test";
        let encrypted = context.encrypt(test_data).unwrap();
        let decrypted = context.decrypt(&encrypted).unwrap();

        assert_eq!(test_data, decrypted.as_slice());
    }

    #[test]
    fn test_integrity_calculation() {
        let settings = test_security_settings();

        let context =
            EncryptionContext::new("test_password", SecurityLevel::Standard, settings).unwrap();

        let test_data = b"Data for integrity test";
        let hmac = context.compute_hmac(test_data).unwrap();
        assert!(!hmac.is_empty());
        assert!(context.verify_hmac(test_data, &hmac).unwrap());
    }

    #[test]
    fn test_password_generation() {
        let settings = PasswordGeneratorSettings {
            length: 16,
            use_uppercase: true,
            use_lowercase: true,
            use_numbers: true,
            use_symbols: true,
            exclude_similar: true,
            exclude_ambiguous: false,
        };

        let password = generate_password(&settings);
        assert_eq!(password.len(), 16);
        assert!(password.chars().any(|c| c.is_uppercase()));
        assert!(password.chars().any(|c| c.is_lowercase()));
        assert!(password.chars().any(|c| c.is_numeric()));
        assert!(password.chars().any(|c| !c.is_alphanumeric()));
    }

    #[test]
    fn test_password_generation_excludes_sets() {
        let settings = PasswordGeneratorSettings {
            length: 32,
            use_uppercase: true,
            use_lowercase: true,
            use_numbers: true,
            use_symbols: true,
            exclude_similar: true,
            exclude_ambiguous: true,
        };

        let password = generate_password(&settings);
        let similar = "il1Lo0O";
        let ambiguous = "{}[]()/\\'\"`~,;:.<>";
        assert!(!password.chars().any(|c| similar.contains(c)));
        assert!(!password.chars().any(|c| ambiguous.contains(c)));
    }

    #[test]
    fn test_database_creation() {
        let manager =
            DatabaseManager::new("Test Database".to_string(), SecurityLevel::High).unwrap();

        assert_eq!(manager.database.metadata.name, "Test Database");
        assert_eq!(manager.database.security_level, SecurityLevel::High);
        assert!(manager.database.items.is_empty());
    }

    #[test]
    fn test_item_creation() {
        let base = BaseItem {
            id: Uuid::new_v4(),
            name: "Test Credential".to_string(),
            item_type: ItemType::Credential,
            folder_id: None,
            tags: vec!["test".to_string()],
            attachments: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            hmac: String::new(),
        };

        let credential = Credential {
            base,
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            url: Some("https://example.com".to_string()),
            notes: Some("Test note".to_string()),
            totp_secret: None,
            last_used: None,
            password_history: Vec::new(),
        };

        let item = Item::Credential(credential);

        assert_eq!(item.get_name(), "Test Credential");
        assert_eq!(item.get_type(), &ItemType::Credential);
    }

    #[test]
    fn test_basic_functionality() {
        // Test basic database creation without encryption
        let manager =
            DatabaseManager::new("Test Database".to_string(), SecurityLevel::Standard).unwrap();

        assert_eq!(manager.database.metadata.name, "Test Database");
        assert_eq!(manager.database.security_level, SecurityLevel::Standard);
        assert!(manager.database.items.is_empty());
        assert!(manager.is_locked());
    }

    #[test]
    fn test_lock_and_unlock_cycle() {
        let mut manager =
            DatabaseManager::new("LockTest".to_string(), SecurityLevel::Standard).unwrap();

        // Reduce security params for faster testing
        let settings = test_security_settings();
        manager.database.metadata.settings.security_settings = settings.clone();

        // Initialize encryption context and add a credential
        let ctx =
            EncryptionContext::new("master", SecurityLevel::Standard, settings.clone()).unwrap();
        manager.encryption_context = Some(ctx);

        let base = BaseItem {
            id: Uuid::new_v4(),
            name: "Entry".to_string(),
            item_type: ItemType::Credential,
            folder_id: None,
            tags: Vec::new(),
            attachments: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            hmac: String::new(),
        };

        let cred = Credential {
            base,
            username: "user".to_string(),
            password: "pass".to_string(),
            url: None,
            notes: None,
            totp_secret: None,
            last_used: None,
            password_history: Vec::new(),
        };

        manager.add_item(Item::Credential(cred)).unwrap();

        let temp_file = NamedTempFile::new().unwrap();
        let file_path = temp_file.path().to_str().unwrap();
        manager.save_to_file(file_path, "master").unwrap();

        assert!(!manager.database.items.is_empty());
        manager.lock();
        assert!(manager.database.items.is_empty());
        assert!(manager.encryption_context.is_none());

        manager.unlock("master").unwrap();
        assert!(!manager.database.items.is_empty());
        assert!(manager.encryption_context.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn test_secure_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let mut manager =
            DatabaseManager::new("PermTest".to_string(), SecurityLevel::Standard).unwrap();
        let settings = test_security_settings();
        manager.database.metadata.settings.security_settings = settings.clone();
        manager.encryption_context =
            Some(EncryptionContext::new("master", SecurityLevel::Standard, settings).unwrap());

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        manager
            .save_to_file(path.to_str().unwrap(), "master")
            .unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_item_integrity() {
        let context = EncryptionContext::new(
            "test_password",
            SecurityLevel::Standard,
            test_security_settings(),
        )
        .unwrap();

        let base = BaseItem {
            id: Uuid::new_v4(),
            name: "Test Item".to_string(),
            item_type: ItemType::Note,
            folder_id: None,
            tags: Vec::new(),
            attachments: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            hmac: String::new(),
        };

        let note = Note {
            base,
            content: "Test content".to_string(),
            is_encrypted: false,
            format: NoteFormat::PlainText,
        };

        let mut item = Item::Note(note);

        // Update integrity
        context.update_item_integrity(&mut item).unwrap();

        // Verify integrity
        let is_valid = context.verify_item_integrity(&item).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_database_integrity() {
        let temp_file = NamedTempFile::new().unwrap();
        let file_path = temp_file.path().to_str().unwrap();

        let mut manager =
            DatabaseManager::new("Test Database".to_string(), SecurityLevel::Standard).unwrap();

        // Override security settings for testing
        manager.database.metadata.settings.security_settings = test_security_settings();

        // Initialize encryption context
        manager.save_to_file(file_path, "test_password").unwrap();

        // Add some items
        let base = BaseItem {
            id: Uuid::new_v4(),
            name: "Test Item".to_string(),
            item_type: ItemType::Note,
            folder_id: None,
            tags: Vec::new(),
            attachments: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            hmac: String::new(),
        };

        let note = Note {
            base,
            content: "Test content".to_string(),
            is_encrypted: false,
            format: NoteFormat::PlainText,
        };

        let item = Item::Note(note);
        manager.add_item(item).unwrap();

        // Save and verify integrity
        manager.save_to_file(file_path, "test_password").unwrap();

        let loaded_manager = DatabaseManager::load_from_file(file_path, "test_password").unwrap();
        let is_valid = loaded_manager.verify_integrity().unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_item_attachments() {
        let temp_file = NamedTempFile::new().unwrap();
        let file_path = temp_file.path().to_str().unwrap();

        let mut manager =
            DatabaseManager::new("Test Attach".to_string(), SecurityLevel::Standard).unwrap();
        manager.database.metadata.settings.security_settings = test_security_settings();
        // Initialize encryption context and persist database so attachments have a base path
        manager.save_to_file(file_path, "master").unwrap();

        let base = BaseItem {
            id: Uuid::new_v4(),
            name: "Attachment Item".to_string(),
            item_type: ItemType::Note,
            folder_id: None,
            tags: Vec::new(),
            attachments: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            hmac: String::new(),
        };
        let note = Note {
            base,
            content: "Has attachment".to_string(),
            is_encrypted: false,
            format: NoteFormat::PlainText,
        };
        let item = Item::Note(note);
        let item_id = item.get_id();
        manager.add_item(item).unwrap();

        let data = b"certificate".to_vec();
        let att_id = manager.add_attachment(item_id, "cert.pem", &data).unwrap();
        assert_eq!(
            manager
                .get_item(item_id)
                .unwrap()
                .get_base()
                .attachments
                .len(),
            1
        );
        let retrieved = manager.get_attachment(item_id, att_id).unwrap();
        assert_eq!(retrieved, data);

        manager.remove_attachment(item_id, att_id).unwrap();
        assert!(manager
            .get_item(item_id)
            .unwrap()
            .get_base()
            .attachments
            .is_empty());
    }
}
