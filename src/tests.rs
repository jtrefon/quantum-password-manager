#[cfg(test)]
mod tests {
    use crate::crypto::EncryptionContext;
    use crate::database::DatabaseManager;
    use crate::models::*;
    use chrono::Utc;
    // use tempfile::NamedTempFile; // Commented out since file-based tests are disabled for CI
    use uuid::Uuid;

    fn test_security_settings() -> SecuritySettings {
        let mut settings = SecuritySettings::default();
        settings.key_derivation_iterations = 10; // Very reduced for CI testing
        settings.memory_cost = 64; // Very reduced for CI testing
        settings.testing_mode = true; // Enable testing mode for faster execution
        settings
    }

    #[test]
    fn test_encryption_context_creation() {
        let mut settings = SecuritySettings::default();
        settings.key_derivation_iterations = 10; // Very reduced for CI testing

        let context =
            EncryptionContext::new("test_password", SecurityLevel::High, settings).unwrap();

        assert_eq!(context.security_level, SecurityLevel::High);
        assert_eq!(context.salt.len(), 32);
        assert!(!context.derived_keys.is_empty());
    }

    #[test]
    fn test_encryption_decryption() {
        let mut settings = SecuritySettings::default();
        settings.key_derivation_iterations = 10; // Very reduced for CI testing

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

    // #[test]
    // fn test_quantum_security_encryption() {
    //     let mut settings = test_security_settings();
    //     settings.key_derivation_iterations = 100; // Reduced for testing

    //     let context =
    //         EncryptionContext::new("test_password", SecurityLevel::Quantum, settings).unwrap();

    //     let test_data = b"Ultra-secret quantum-resistant data";
    //     let encrypted = context.encrypt(test_data).unwrap();
    //     let decrypted = context.decrypt(&encrypted).unwrap();

    //     assert_eq!(test_data, decrypted.as_slice());
    // }

    #[test]
    fn test_integrity_calculation() {
        let settings = test_security_settings();

        let context =
            EncryptionContext::new("test_password", SecurityLevel::Standard, settings).unwrap();

        let test_data = b"Data for integrity test";
        let crc = context.calculate_crc32(test_data);
        let sha = context.calculate_sha256(test_data);

        assert_ne!(crc, 0);
        assert!(!sha.is_empty());
    }

    #[test]
    fn test_password_generation() {
        let settings = test_security_settings();

        let context =
            EncryptionContext::new("test_password", SecurityLevel::Standard, settings).unwrap();

        let settings = PasswordGeneratorSettings {
            length: 16,
            use_uppercase: true,
            use_lowercase: true,
            use_numbers: true,
            use_symbols: true,
            exclude_similar: true,
            exclude_ambiguous: false,
        };

        let password = context.generate_password(&settings);
        assert_eq!(password.len(), 16);
        assert!(password.chars().any(|c| c.is_uppercase()));
        assert!(password.chars().any(|c| c.is_lowercase()));
        assert!(password.chars().any(|c| c.is_numeric()));
        assert!(password.chars().any(|c| !c.is_alphanumeric()));
    }

    #[test]
    fn test_password_generation_excludes_sets() {
        let settings = test_security_settings();

        let context =
            EncryptionContext::new("test_password", SecurityLevel::Standard, settings).unwrap();

        let settings = PasswordGeneratorSettings {
            length: 32,
            use_uppercase: true,
            use_lowercase: true,
            use_numbers: true,
            use_symbols: true,
            exclude_similar: true,
            exclude_ambiguous: true,
        };

        let password = context.generate_password(&settings);
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

    // #[test]
    // fn test_database_save_and_load() {
    //     let temp_file = NamedTempFile::new().unwrap();
    //     let file_path = temp_file.path().to_str().unwrap();

    //     // Create and save database with test settings
    //     let mut manager =
    //         DatabaseManager::new("Test Database".to_string(), SecurityLevel::Standard).unwrap();

    //     // Override security settings for testing - use very low values
    //     let mut settings = test_security_settings();
    //     settings.key_derivation_iterations = 10; // Very low for testing
    //     settings.memory_cost = 64; // Very low for testing
    //     manager.database.metadata.settings.security_settings = settings;

    //     manager.save_to_file(file_path, "test_password").unwrap();

    //     // Load database
    //     let loaded_manager = DatabaseManager::load_from_file(file_path, "test_password").unwrap();

    //     assert_eq!(loaded_manager.database.metadata.name, "Test Database");
    //     assert_eq!(
    //         loaded_manager.database.security_level,
    //         SecurityLevel::Standard
    //     );
    // }

    #[test]
    fn test_item_creation() {
        let base = BaseItem {
            id: Uuid::new_v4(),
            name: "Test Credential".to_string(),
            item_type: ItemType::Credential,
            folder_id: None,
            tags: vec!["test".to_string()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            crc32: 0,
            sha256: String::new(),
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

    // #[test]
    // fn test_item_integrity() {
    //     let context = EncryptionContext::new(
    //         "test_password",
    //         SecurityLevel::Standard,
    //         SecuritySettings::default(),
    //     )
    //     .unwrap();

    //     let base = BaseItem {
    //         id: Uuid::new_v4(),
    //         name: "Test Item".to_string(),
    //         item_type: ItemType::Note,
    //         folder_id: None,
    //         tags: Vec::new(),
    //         created_at: Utc::now(),
    //         updated_at: Utc::now(),
    //         crc32: 0,
    //         sha256: String::new(),
    //     };

    //     let note = Note {
    //         base,
    //         content: "Test content".to_string(),
    //         is_encrypted: false,
    //         format: NoteFormat::PlainText,
    //     };

    //     let mut item = Item::Note(note);

    //     // Update integrity
    //     context.update_item_integrity(&mut item).unwrap();

    //     // Verify integrity
    //     let is_valid = context.verify_item_integrity(&item).unwrap();
    //     assert!(is_valid);
    // }

    // #[test]
    // fn test_database_integrity() {
    //     let temp_file = NamedTempFile::new().unwrap();
    //     let file_path = temp_file.path().to_str().unwrap();

    //     let mut manager =
    //         DatabaseManager::new("Test Database".to_string(), SecurityLevel::Standard).unwrap();

    //     // Override security settings for testing
    //     manager.database.metadata.settings.security_settings = test_security_settings();

    //     // Initialize encryption context
    //     manager.save_to_file(file_path, "test_password").unwrap();

    //     // Add some items
    //     let base = BaseItem {
    //         id: Uuid::new_v4(),
    //         name: "Test Item".to_string(),
    //         item_type: ItemType::Note,
    //         folder_id: None,
    //         tags: Vec::new(),
    //         created_at: Utc::now(),
    //         updated_at: Utc::now(),
    //         crc32: 0,
    //         sha256: String::new(),
    //     };

    //     let note = Note {
    //         base,
    //         content: "Test content".to_string(),
    //         is_encrypted: false,
    //         format: NoteFormat::PlainText,
    //     };

    //     let item = Item::Note(note);
    //     manager.add_item(item).unwrap();

    //     // Save and verify integrity
    //     manager.save_to_file(file_path, "test_password").unwrap();

    //     let loaded_manager = DatabaseManager::load_from_file(file_path, "test_password").unwrap();
    //     let is_valid = loaded_manager.verify_integrity().unwrap();
    //     assert!(is_valid);
    // }

    // #[test]
    // fn test_search_functionality() {
    //     let temp_file = NamedTempFile::new().unwrap();
    //     let file_path = temp_file.path().to_str().unwrap();

    //     let mut manager =
    //         DatabaseManager::new("Test Database".to_string(), SecurityLevel::Standard).unwrap();

    //     // Override security settings for testing
    //     manager.database.metadata.settings.security_settings = test_security_settings();

    //     // Initialize encryption context
    //     manager.save_to_file(file_path, "test_password").unwrap();

    //     // Add test items
    //     let base1 = BaseItem {
    //         id: Uuid::new_v4(),
    //         name: "GitHub Account".to_string(),
    //         item_type: ItemType::Credential,
    //         folder_id: None,
    //         tags: Vec::new(),
    //         created_at: Utc::now(),
    //         updated_at: Utc::now(),
    //         crc32: 0,
    //         sha256: String::new(),
    //     };

    //     let credential1 = Credential {
    //         base: base1,
    //         username: "user1".to_string(),
    //         password: "pass1".to_string(),
    //         url: None,
    //         notes: None,
    //         totp_secret: None,
    //         last_used: None,
    //         password_history: Vec::new(),
    //     };

    //     let base2 = BaseItem {
    //         id: Uuid::new_v4(),
    //         name: "Gmail Account".to_string(),
    //         item_type: ItemType::Credential,
    //         folder_id: None,
    //         tags: Vec::new(),
    //         created_at: Utc::now(),
    //         updated_at: Utc::now(),
    //         crc32: 0,
    //         sha256: String::new(),
    //     };

    //     let credential2 = Credential {
    //         base: base2,
    //         username: "user2".to_string(),
    //         password: "pass2".to_string(),
    //         url: None,
    //         notes: None,
    //         totp_secret: None,
    //         last_used: None,
    //         password_history: Vec::new(),
    //     };

    //     manager.add_item(Item::Credential(credential1)).unwrap();
    //     manager.add_item(Item::Credential(credential2)).unwrap();

    //     // Test search
    //     let results = manager.search_items("github");
    //     assert_eq!(results.len(), 1);
    //     assert_eq!(results[0].get_name(), "GitHub Account");

    //     let results = manager.search_items("account");
    //     assert_eq!(results.len(), 2);
    // }

    // #[test]
    // fn test_statistics() {
    //     let temp_file = NamedTempFile::new().unwrap();
    //     let file_path = temp_file.path().to_str().unwrap();

    //     let mut manager =
    //         DatabaseManager::new("Test Database".to_string(), SecurityLevel::Standard).unwrap();

    //     // Override security settings for testing
    //     manager.database.metadata.settings.security_settings = test_security_settings();

    //     // Initialize encryption context
    //     manager.save_to_file(file_path, "test_password").unwrap();

    //     // Add different types of items
    //     let base1 = BaseItem {
    //         id: Uuid::new_v4(),
    //         name: "Test Credential".to_string(),
    //         item_type: ItemType::Credential,
    //         folder_id: None,
    //         tags: Vec::new(),
    //         created_at: Utc::now(),
    //         updated_at: Utc::now(),
    //         crc32: 0,
    //         sha256: String::new(),
    //     };

    //     let credential = Credential {
    //         base: base1,
    //         username: "user".to_string(),
    //         password: "pass".to_string(),
    //         url: None,
    //         notes: None,
    //         totp_secret: None,
    //         last_used: None,
    //         password_history: Vec::new(),
    //     };

    //     let base2 = BaseItem {
    //         id: Uuid::new_v4(),
    //         name: "Test Folder".to_string(),
    //         item_type: ItemType::Folder,
    //         folder_id: None,
    //         tags: Vec::new(),
    //         created_at: Utc::now(),
    //         updated_at: Utc::now(),
    //         crc32: 0,
    //         sha256: String::new(),
    //     };

    //     let folder = Folder {
    //         base: base2,
    //         description: None,
    //         color: None,
    //     };

    //     manager.add_item(Item::Credential(credential)).unwrap();
    //     manager.add_item(Item::Folder(folder)).unwrap();

    //     let stats = manager.get_statistics();
    //     assert_eq!(stats.total_items, 2);
    //     assert_eq!(stats.credentials, 1);
    //     assert_eq!(stats.folders, 1);
    // }

    // #[test]
    // fn test_master_password_change() {
    //     let temp_file = NamedTempFile::new().unwrap();
    //     let file_path = temp_file.path().to_str().unwrap();

    //     let mut manager =
    //         DatabaseManager::new("Test Database".to_string(), SecurityLevel::Standard).unwrap();

    //     // Override security settings for testing
    //     manager.database.metadata.settings.security_settings = test_security_settings();

    //     // Initialize encryption context
    //     manager.save_to_file(file_path, "old_password").unwrap();

    //     // Add an item
    //     let base = BaseItem {
    //         id: Uuid::new_v4(),
    //         name: "Test Item".to_string(),
    //         item_type: ItemType::Note,
    //         folder_id: None,
    //         tags: Vec::new(),
    //         created_at: Utc::now(),
    //         updated_at: Utc::now(),
    //         crc32: 0,
    //         sha256: String::new(),
    //     };

    //     let note = Note {
    //         base,
    //         content: "Test content".to_string(),
    //         is_encrypted: false,
    //         format: NoteFormat::PlainText,
    //     };

    //     manager.add_item(Item::Note(note)).unwrap();
    //     manager.save_to_file(file_path, "old_password").unwrap();

    //     // Change password
    //     manager.change_master_password("new_password").unwrap();
    //     manager.save_to_file(file_path, "new_password").unwrap();

    //     // Verify we can load with new password
    //     let loaded_manager = DatabaseManager::load_from_file(file_path, "new_password").unwrap();
    //     assert_eq!(loaded_manager.database.items.len(), 1);
    // }

    // #[test]
    // fn test_progress_indicator() {
    //     use crate::crypto::ProgressCallback;
    //     use std::sync::{Arc, Mutex};

    //     let progress_log = Arc::new(Mutex::new(Vec::new()));
    //     let progress_log_clone = progress_log.clone();

    //     let callback: ProgressCallback =
    //         Arc::new(Mutex::new(move |message: &str, progress: f32| {
    //         progress_log_clone
    //             .lock()
    //             .unwrap()
    //             .push((message.to_string(), progress));
    //     }));

    //     let mut settings = test_security_settings();
    //     settings.key_derivation_iterations = 100; // Reduced for testing

    //     let context = EncryptionContext::new_with_progress(
    //         "test_password",
    //         SecurityLevel::Quantum,
    //         settings,
    //         Some(callback.clone()),
    //     )
    //     .unwrap();

    //     let test_data = b"Test data for progress indicator";
    //     let encrypted = context.encrypt(test_data).unwrap();
    //     let decrypted = context.decrypt(&encrypted).unwrap();

    //     assert_eq!(test_data, decrypted.as_slice());

    //     // Check that progress was reported
    //     let log = progress_log.lock().unwrap();
    //     assert!(!log.is_empty(), "Progress should have been reported");

    //     // Check that we have progress messages
    //     let messages: Vec<String> = log.iter().map(|(msg, _)| msg.clone()).collect();
    //     assert!(
    //         messages
    //             .iter()
    //             .any(|msg| msg.contains("Deriving master key")),
    //         "Should have key derivation progress"
    //     );
    //     assert!(
    //         messages
    //             .iter()
    //             .any(|msg| msg.contains("Quantum encryption round")),
    //         "Should have quantum encryption progress"
    //     );
    // }
}
