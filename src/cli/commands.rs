use super::progress::demo_progress_indicator;
use crate::database::DatabaseManager;
use crate::models::{
    BaseItem, Credential, Folder, Item, ItemType, Key, KeyType, KeyUsage, Note, NoteFormat,
    SecureNote, SecurityLevel, Url,
};
use anyhow::{anyhow, Result};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use console::{style, Term};
use dialoguer::{Confirm, Input, Password};
use std::path::Path;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "password_manager")]
#[command(about = "Ultra-secure password manager with quantum-resistant encryption")]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a new password database
    Create(CreateArgs),
    /// Open an existing password database
    Open(OpenArgs),
    /// List all items in the database
    List(ListArgs),
    /// Add a new item to the database
    Add(AddArgs),
    /// Show details of a specific item
    Show(ShowArgs),
    /// Edit an existing item
    Edit(EditArgs),
    /// Remove an item from the database
    Remove(RemoveArgs),
    /// Search for items
    Search(SearchArgs),
    /// Generate a random password
    Generate(GenerateArgs),
    /// Show database statistics
    Stats(StatsArgs),
    /// Verify database integrity
    Verify(VerifyArgs),
    /// Export database to JSON
    Export(ExportArgs),
    /// Import database from JSON
    Import(ImportArgs),
    /// Change master password
    ChangePassword(ChangePasswordArgs),
    /// Lock the database
    Lock(LockArgs),
    /// Unlock the database
    Unlock(UnlockArgs),
    /// Demo progress indicator
    Demo,
    /// Show hardware acceleration info
    Hardware,
}

#[derive(Args)]
pub struct CreateArgs {
    /// Database file path
    #[arg(short, long)]
    file: String,

    /// Database name
    #[arg(short, long)]
    name: Option<String>,

    /// Security level (standard, high, quantum)
    #[arg(short, long, default_value = "high")]
    security: Option<String>,
}

#[derive(Args)]
pub struct OpenArgs {
    /// Database file path
    #[arg(short, long)]
    file: String,
}

#[derive(Args)]
pub struct ListArgs {
    /// Database file path
    #[arg(short, long)]
    file: String,

    /// Filter by item type
    #[arg(short, long)]
    type_filter: Option<String>,
}

#[derive(Args)]
pub struct AddArgs {
    /// Database file path
    #[arg(short, long)]
    file: String,

    /// Item type (credential, folder, key, url, note, secure_note)
    #[arg(short, long)]
    item_type: String,

    /// Item name
    #[arg(short, long)]
    name: String,
}

#[derive(Args)]
pub struct ShowArgs {
    /// Database file path
    #[arg(short, long)]
    file: String,

    /// Item ID
    #[arg(short, long)]
    id: String,
}

#[derive(Args)]
pub struct EditArgs {
    /// Database file path
    #[arg(short, long)]
    file: String,

    /// Item ID
    #[arg(short, long)]
    id: String,
}

#[derive(Args)]
pub struct RemoveArgs {
    /// Database file path
    #[arg(short, long)]
    file: String,

    /// Item ID
    #[arg(short, long)]
    id: String,
}

#[derive(Args)]
pub struct SearchArgs {
    /// Database file path
    #[arg(short, long)]
    file: String,

    /// Search query
    #[arg(short, long)]
    query: String,
}

#[derive(Args)]
pub struct GenerateArgs {
    /// Password length
    #[arg(long, default_value = "20")]
    length: u32,

    /// Include uppercase letters
    #[arg(long, default_value = "true")]
    uppercase: bool,

    /// Include lowercase letters
    #[arg(long, default_value = "true")]
    lowercase: bool,

    /// Include numbers
    #[arg(long, default_value = "true")]
    numbers: bool,

    /// Include symbols
    #[arg(long, default_value = "true")]
    symbols: bool,
}

#[derive(Args)]
pub struct StatsArgs {
    /// Database file path
    #[arg(short, long)]
    file: String,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Database file path
    #[arg(short, long)]
    file: String,
}

#[derive(Args)]
pub struct ExportArgs {
    /// Database file path
    #[arg(short, long)]
    file: String,

    /// Output JSON file path
    #[arg(short, long)]
    output: String,
}

#[derive(Args)]
pub struct ImportArgs {
    /// Database file path
    #[arg(short, long)]
    file: String,

    /// Input JSON file path
    #[arg(short, long)]
    input: String,
}

#[derive(Args)]
pub struct ChangePasswordArgs {
    /// Database file path
    #[arg(short, long)]
    file: String,
}

#[derive(Args)]
pub struct LockArgs {
    /// Database file path
    #[arg(short, long)]
    file: String,
}

#[derive(Args)]
pub struct UnlockArgs {
    /// Database file path
    #[arg(short, long)]
    file: String,
}

pub struct CliHandler;

impl CliHandler {
    pub fn run() -> Result<()> {
        let cli = Cli::parse();

        match cli.command {
            Commands::Create(args) => Self::handle_create(args),
            Commands::Open(args) => Self::handle_open(args),
            Commands::List(args) => Self::handle_list(args),
            Commands::Add(args) => Self::handle_add(args),
            Commands::Show(args) => Self::handle_show(args),
            Commands::Edit(args) => Self::handle_edit(args),
            Commands::Remove(args) => Self::handle_remove(args),
            Commands::Search(args) => Self::handle_search(args),
            Commands::Generate(args) => Self::handle_generate(args),
            Commands::Stats(args) => Self::handle_stats(args),
            Commands::Verify(args) => Self::handle_verify(args),
            Commands::Export(args) => Self::handle_export(args),
            Commands::Import(args) => Self::handle_import(args),
            Commands::ChangePassword(args) => Self::handle_change_password(args),
            Commands::Lock(args) => Self::handle_lock(args),
            Commands::Unlock(args) => Self::handle_unlock(args),
            Commands::Demo => Self::handle_demo(),
            Commands::Hardware => Self::handle_hardware(),
        }
    }

    fn handle_create(args: CreateArgs) -> Result<()> {
        let term = Term::stdout();

        let name = args.name.unwrap_or_else(|| {
            Input::<String>::new()
                .with_prompt("Enter database name")
                .interact()
                .unwrap_or_else(|_| "My Passwords".to_string())
        });

        let security_level = match args.security.as_deref() {
            Some("standard") => SecurityLevel::Standard,
            Some("high") => SecurityLevel::High,
            Some("quantum") => SecurityLevel::Quantum,
            _ => SecurityLevel::High,
        };

        let master_password = Password::new()
            .with_prompt("Enter master password")
            .with_confirmation("Confirm master password", "Passwords don't match")
            .interact()?;

        let mut manager = DatabaseManager::new(name, security_level)?;
        manager.save_to_file(&args.file, &master_password)?;

        term.write_line(&style("Database created successfully!").green().to_string())?;
        Ok(())
    }

    fn handle_open(args: OpenArgs) -> Result<()> {
        let term = Term::stdout();

        if !Path::new(&args.file).exists() {
            return Err(anyhow!("Database file does not exist"));
        }

        let master_password = Password::new()
            .with_prompt("Enter master password")
            .interact()?;

        let manager = DatabaseManager::load_from_file(&args.file, &master_password)?;

        term.write_line(&style("Database opened successfully!").green().to_string())?;
        term.write_line(&format!("Database: {}", manager.get_metadata().name))?;
        term.write_line(&format!("Items: {}", manager.database.items.len()))?;

        Ok(())
    }

    fn handle_list(args: ListArgs) -> Result<()> {
        let term = Term::stdout();

        let master_password = Password::new()
            .with_prompt("Enter master password")
            .interact()?;

        let manager = DatabaseManager::load_from_file(&args.file, &master_password)?;

        let items = if let Some(type_filter) = args.type_filter {
            let item_type = match type_filter.as_str() {
                "credential" => ItemType::Credential,
                "folder" => ItemType::Folder,
                "key" => ItemType::Key,
                "url" => ItemType::Url,
                "note" => ItemType::Note,
                "secure_note" => ItemType::SecureNote,
                _ => return Err(anyhow!("Invalid item type")),
            };
            manager.get_items_by_type(&item_type)
        } else {
            manager.database.items.iter().collect()
        };

        if items.is_empty() {
            term.write_line("No items found.")?;
            return Ok(());
        }

        term.write_line(&style("Items:").bold().to_string())?;
        for item in items {
            let item_type = match item.get_type() {
                ItemType::Credential => "Credential",
                ItemType::Folder => "Folder",
                ItemType::Key => "Key",
                ItemType::Url => "URL",
                ItemType::Note => "Note",
                ItemType::SecureNote => "Secure Note",
            };

            term.write_line(&format!(
                "{} - {} ({})",
                item.get_id(),
                item.get_name(),
                item_type
            ))?;
        }

        Ok(())
    }

    fn handle_add(args: AddArgs) -> Result<()> {
        let term = Term::stdout();

        let master_password = Password::new()
            .with_prompt("Enter master password")
            .interact()?;

        let mut manager = DatabaseManager::load_from_file(&args.file, &master_password)?;

        let item_type = match args.item_type.as_str() {
            "credential" => ItemType::Credential,
            "folder" => ItemType::Folder,
            "key" => ItemType::Key,
            "url" => ItemType::Url,
            "note" => ItemType::Note,
            "secure_note" => ItemType::SecureNote,
            _ => return Err(anyhow!("Invalid item type")),
        };

        let item = Self::create_item_interactive(&args.name, item_type)?;
        manager.add_item(item)?;
        manager.save_to_file(&args.file, &master_password)?;

        term.write_line(&style("Item added successfully!").green().to_string())?;
        Ok(())
    }

    fn handle_show(args: ShowArgs) -> Result<()> {
        let _term = Term::stdout();

        let master_password = Password::new()
            .with_prompt("Enter master password")
            .interact()?;

        let manager = DatabaseManager::load_from_file(&args.file, &master_password)?;

        let item_id = Uuid::parse_str(&args.id)?;
        if let Some(item) = manager.get_item(item_id) {
            Self::display_item(item)?;
        } else {
            return Err(anyhow!("Item not found"));
        }

        Ok(())
    }

    fn handle_edit(args: EditArgs) -> Result<()> {
        let term = Term::stdout();

        let master_password = Password::new()
            .with_prompt("Enter master password")
            .interact()?;

        let mut manager = DatabaseManager::load_from_file(&args.file, &master_password)?;

        let item_id = Uuid::parse_str(&args.id)?;
        if let Some(item) = manager.get_item(item_id) {
            let updated_item = Self::edit_item_interactive(item)?;
            manager.update_item(item_id, updated_item)?;
            manager.save_to_file(&args.file, &master_password)?;

            term.write_line(&style("Item updated successfully!").green().to_string())?;
        } else {
            return Err(anyhow!("Item not found"));
        }

        Ok(())
    }

    fn handle_remove(args: RemoveArgs) -> Result<()> {
        let term = Term::stdout();

        let master_password = Password::new()
            .with_prompt("Enter master password")
            .interact()?;

        let mut manager = DatabaseManager::load_from_file(&args.file, &master_password)?;

        let item_id = Uuid::parse_str(&args.id)?;

        if Confirm::new()
            .with_prompt("Are you sure you want to remove this item?")
            .interact()?
        {
            manager.remove_item(item_id)?;
            manager.save_to_file(&args.file, &master_password)?;
            term.write_line(&style("Item removed successfully!").green().to_string())?;
        }

        Ok(())
    }

    fn handle_search(args: SearchArgs) -> Result<()> {
        let term = Term::stdout();

        let master_password = Password::new()
            .with_prompt("Enter master password")
            .interact()?;

        let manager = DatabaseManager::load_from_file(&args.file, &master_password)?;

        let results = manager.search_items(&args.query);

        if results.is_empty() {
            term.write_line("No items found.")?;
            return Ok(());
        }

        term.write_line(&style("Search Results:").bold().to_string())?;
        for item in results {
            let item_type = match item.get_type() {
                ItemType::Credential => "Credential",
                ItemType::Folder => "Folder",
                ItemType::Key => "Key",
                ItemType::Url => "URL",
                ItemType::Note => "Note",
                ItemType::SecureNote => "Secure Note",
            };

            term.write_line(&format!(
                "{} - {} ({})",
                item.get_id(),
                item.get_name(),
                item_type
            ))?;
        }

        Ok(())
    }

    fn handle_generate(args: GenerateArgs) -> Result<()> {
        let term = Term::stdout();

        let settings = crate::models::PasswordGeneratorSettings {
            length: args.length,
            use_uppercase: args.uppercase,
            use_lowercase: args.lowercase,
            use_numbers: args.numbers,
            use_symbols: args.symbols,
            exclude_similar: true,
            exclude_ambiguous: false,
        };

        let encryption_context = crate::crypto::EncryptionContext::new(
            "temp",
            SecurityLevel::Standard,
            crate::models::SecuritySettings::default(),
        )?;

        let password = encryption_context.generate_password(&settings);
        term.write_line(&format!("Generated password: {password}"))?;

        Ok(())
    }

    fn handle_stats(args: StatsArgs) -> Result<()> {
        let term = Term::stdout();

        let master_password = Password::new()
            .with_prompt("Enter master password")
            .interact()?;

        let manager = DatabaseManager::load_from_file(&args.file, &master_password)?;

        let stats = manager.get_statistics();
        term.write_line(&stats.to_string())?;

        Ok(())
    }

    fn handle_verify(args: VerifyArgs) -> Result<()> {
        let term = Term::stdout();

        let master_password = Password::new()
            .with_prompt("Enter master password")
            .interact()?;

        let manager = DatabaseManager::load_from_file(&args.file, &master_password)?;

        if manager.verify_integrity()? {
            term.write_line(
                &style("Database integrity verified successfully!")
                    .green()
                    .to_string(),
            )?;
        } else {
            term.write_line(&style("Database integrity check failed!").red().to_string())?;
        }

        Ok(())
    }

    fn handle_export(args: ExportArgs) -> Result<()> {
        let term = Term::stdout();

        let master_password = Password::new()
            .with_prompt("Enter master password")
            .interact()?;

        let manager = DatabaseManager::load_from_file(&args.file, &master_password)?;

        manager.export_to_json(&args.output)?;
        term.write_line(&style("Database exported successfully!").green().to_string())?;

        Ok(())
    }

    fn handle_import(args: ImportArgs) -> Result<()> {
        let term = Term::stdout();

        let master_password = Password::new()
            .with_prompt("Enter master password")
            .interact()?;

        let mut manager = DatabaseManager::load_from_file(&args.file, &master_password)?;

        manager.import_from_json(&args.input)?;
        manager.save_to_file(&args.file, &master_password)?;

        term.write_line(&style("Database imported successfully!").green().to_string())?;

        Ok(())
    }

    fn handle_change_password(args: ChangePasswordArgs) -> Result<()> {
        let term = Term::stdout();

        let old_password = Password::new()
            .with_prompt("Enter current master password")
            .interact()?;

        let new_password = Password::new()
            .with_prompt("Enter new master password")
            .with_confirmation("Confirm new master password", "Passwords don't match")
            .interact()?;

        let mut manager = DatabaseManager::load_from_file(&args.file, &old_password)?;
        manager.change_master_password(&new_password)?;
        manager.save_to_file(&args.file, &new_password)?;

        term.write_line(
            &style("Master password changed successfully!")
                .green()
                .to_string(),
        )?;

        Ok(())
    }

    fn handle_lock(args: LockArgs) -> Result<()> {
        let term = Term::stdout();

        let master_password = Password::new()
            .with_prompt("Enter master password")
            .interact()?;

        let mut manager = DatabaseManager::load_from_file(&args.file, &master_password)?;
        manager.lock();
        manager.save_to_file(&args.file, &master_password)?;

        term.write_line(&style("Database locked successfully!").green().to_string())?;

        Ok(())
    }

    fn handle_unlock(args: UnlockArgs) -> Result<()> {
        let term = Term::stdout();

        let master_password = Password::new()
            .with_prompt("Enter master password")
            .interact()?;

        let mut manager = DatabaseManager::load_from_file(&args.file, &master_password)?;
        manager.unlock(&master_password)?;

        term.write_line(&style("Database unlocked successfully!").green().to_string())?;

        Ok(())
    }

    fn handle_demo() -> Result<()> {
        if let Err(e) = demo_progress_indicator() {
            println!("Error: {e}");
        }
        Ok(())
    }

    fn handle_hardware() -> Result<()> {
        use crate::hardware::HardwareAccelerator;

        println!("🔧 Hardware Acceleration Information");
        println!("===================================");
        println!();

        let capabilities = HardwareAccelerator::get_capabilities_info();
        let is_available = HardwareAccelerator::is_available();
        let optimal_threads = HardwareAccelerator::optimal_thread_count();

        println!("📊 Capabilities: {capabilities}");
        println!(
            "⚡ Hardware Acceleration: {}",
            if is_available {
                "✅ Available"
            } else {
                "❌ Not Available"
            }
        );
        println!("🧵 Optimal Thread Count: {optimal_threads}");
        println!();

        if is_available {
            println!("🚀 Hardware acceleration is active in AES-GCM operations (via aes-gcm).");
            println!(
                "   Expect significant performance improvements on supported Apple Silicon and x86_64."
            );
        } else {
            println!("⚠️  No hardware acceleration detected. Using software implementations.");
            println!("   Performance may be slower on this system.");
        }

        Ok(())
    }

    fn create_item_interactive(name: &str, item_type: ItemType) -> Result<Item> {
        let base = BaseItem {
            id: Uuid::new_v4(),
            name: name.to_string(),
            item_type: item_type.clone(),
            folder_id: None,
            tags: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            crc32: 0,
            sha256: String::new(),
        };

        match item_type {
            ItemType::Credential => {
                let username = Input::<String>::new().with_prompt("Username").interact()?;

                let password = Password::new().with_prompt("Password").interact()?;

                let url = Input::<String>::new()
                    .with_prompt("URL (optional)")
                    .allow_empty(true)
                    .interact()?;

                let notes = Input::<String>::new()
                    .with_prompt("Notes (optional)")
                    .allow_empty(true)
                    .interact()?;

                let credential = Credential {
                    base,
                    username,
                    password,
                    url: if url.is_empty() { None } else { Some(url) },
                    notes: if notes.is_empty() { None } else { Some(notes) },
                    totp_secret: None,
                    last_used: None,
                    password_history: Vec::new(),
                };

                Ok(Item::Credential(credential))
            }
            ItemType::Folder => {
                let description = Input::<String>::new()
                    .with_prompt("Description (optional)")
                    .allow_empty(true)
                    .interact()?;

                let folder = Folder {
                    base,
                    description: if description.is_empty() {
                        None
                    } else {
                        Some(description)
                    },
                    color: None,
                };

                Ok(Item::Folder(folder))
            }
            ItemType::Key => {
                let key_data = Password::new()
                    .with_prompt("Key data (base64)")
                    .interact()?;

                let key = Key {
                    base,
                    key_type: KeyType::Symmetric,
                    key_data,
                    algorithm: "AES-256".to_string(),
                    key_size: 256,
                    usage: vec![KeyUsage::Encryption, KeyUsage::Decryption],
                };

                Ok(Item::Key(key))
            }
            ItemType::Url => {
                let url = Input::<String>::new().with_prompt("URL").interact()?;

                let title = Input::<String>::new()
                    .with_prompt("Title (optional)")
                    .allow_empty(true)
                    .interact()?;

                let url_item = Url {
                    base,
                    url,
                    title: if title.is_empty() { None } else { Some(title) },
                    favicon: None,
                    notes: None,
                };

                Ok(Item::Url(url_item))
            }
            ItemType::Note => {
                let content = Input::<String>::new()
                    .with_prompt("Note content")
                    .interact()?;

                let note = Note {
                    base,
                    content,
                    is_encrypted: false,
                    format: NoteFormat::PlainText,
                };

                Ok(Item::Note(note))
            }
            ItemType::SecureNote => {
                let content = Password::new()
                    .with_prompt("Secure note content")
                    .interact()?;

                let secure_note = SecureNote {
                    base,
                    encrypted_content: content,
                    content_type: "text/plain".to_string(),
                    additional_metadata: std::collections::HashMap::new(),
                };

                Ok(Item::SecureNote(secure_note))
            }
        }
    }

    fn edit_item_interactive(item: &Item) -> Result<Item> {
        // For simplicity, we'll just return the item as-is
        // In a real implementation, you'd want to provide an interactive editor
        Ok(item.clone())
    }

    fn display_item(item: &Item) -> Result<()> {
        let term = Term::stdout();

        term.write_line(&format!("ID: {}", item.get_id()))?;
        term.write_line(&format!("Name: {}", item.get_name()))?;
        term.write_line(&format!("Type: {:?}", item.get_type()))?;
        term.write_line(&format!("Created: {}", item.get_base().created_at))?;
        term.write_line(&format!("Updated: {}", item.get_base().updated_at))?;

        match item {
            Item::Credential(c) => {
                term.write_line(&format!("Username: {}", c.username))?;
                term.write_line(&format!("Password: {}", "*".repeat(c.password.len())))?;
                if let Some(url) = &c.url {
                    term.write_line(&format!("URL: {url}"))?;
                }
                if let Some(notes) = &c.notes {
                    term.write_line(&format!("Notes: {notes}"))?;
                }
            }
            Item::Folder(f) => {
                if let Some(desc) = &f.description {
                    term.write_line(&format!("Description: {desc}"))?;
                }
            }
            Item::Key(k) => {
                term.write_line(&format!("Algorithm: {}", k.algorithm))?;
                term.write_line(&format!("Key Size: {}", k.key_size))?;
                term.write_line(&format!("Key Type: {:?}", k.key_type))?;
            }
            Item::Url(u) => {
                term.write_line(&format!("URL: {}", u.url))?;
                if let Some(title) = &u.title {
                    term.write_line(&format!("Title: {title}"))?;
                }
            }
            Item::Note(n) => {
                term.write_line(&format!("Content: {}", n.content))?;
                term.write_line(&format!("Format: {:?}", n.format))?;
                term.write_line(&format!("Encrypted: {}", n.is_encrypted))?;
            }
            Item::SecureNote(s) => {
                term.write_line(&format!("Content Type: {}", s.content_type))?;
                term.write_line(&format!(
                    "Content: {}",
                    "*".repeat(s.encrypted_content.len())
                ))?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_create_command() {
        let cli = Cli::parse_from(["app", "create", "-f", "test.db"]);
        match cli.command {
            Commands::Create(args) => assert_eq!(args.file, "test.db"),
            _ => panic!("expected create command"),
        }
    }
}
