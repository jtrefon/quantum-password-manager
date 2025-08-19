use anyhow::{anyhow, Result};
use console::Term;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use crate::crypto::{EncryptionContext, ProgressCallback};
use crate::hardware::HardwareAccelerator;
use crate::models::{SecurityLevel, SecuritySettings};

pub struct CliProgressBar {
    term: Term,
    last_message: String,
}

impl CliProgressBar {
    pub fn new() -> Self {
        Self {
            term: Term::stdout(),
            last_message: String::new(),
        }
    }

    pub fn update(&mut self, message: &str, progress: f32) {
        self.term.clear_line().ok();

        let bar_width = 40;
        let filled = (progress * bar_width as f32) as usize;
        let bar = format!(
            "[{}{}] {:.1}% {}",
            "█".repeat(filled),
            "░".repeat(bar_width - filled),
            progress * 100.0,
            message
        );

        print!("{bar}");
        io::stdout().flush().ok();

        self.last_message = message.to_string();
    }

    pub fn finish(&mut self, message: &str) {
        self.term.clear_line().ok();
        println!("✅ {message}");
    }
}

pub fn demo_progress_indicator() -> Result<()> {
    println!("🔐 Password Manager Progress Indicator Demo");
    println!("===========================================");

    println!(
        "\n🔧 Hardware Acceleration: {}",
        if HardwareAccelerator::is_available() {
            "✅ Available"
        } else {
            "❌ Not Available"
        }
    );
    println!(
        "📊 Capabilities: {}",
        HardwareAccelerator::get_capabilities_info()
    );
    println!(
        "🧵 Optimal Threads: {}",
        HardwareAccelerator::optimal_thread_count()
    );

    let progress_bar = Arc::new(Mutex::new(CliProgressBar::new()));
    let progress_bar_clone = progress_bar.clone();

    let progress_callback: ProgressCallback =
        Arc::new(Mutex::new(move |message: &str, progress: f32| {
            if let Ok(mut bar) = progress_bar_clone.lock() {
                bar.update(message, progress);
            }
        }));

    println!("\n📊 Creating encryption context with high security...");
    let settings = SecuritySettings {
        testing_mode: true,
        key_derivation_iterations: 1000,
        memory_cost: 1024,
        ..Default::default()
    };

    let context = EncryptionContext::new_with_progress(
        "demo_password",
        SecurityLevel::Quantum,
        settings,
        Some(progress_callback.clone()),
    )?;

    if let Ok(mut bar) = progress_bar.lock() {
        bar.finish("Encryption context created successfully!");
    }

    println!("\n🔒 Encrypting test data with quantum security...");
    let test_data =
        b"This is a test message that will be encrypted with quantum-resistant encryption";
    let encrypted = context.encrypt(test_data)?;

    if let Ok(mut bar) = progress_bar.lock() {
        bar.finish("Encryption completed successfully!");
    }

    println!("\n🔓 Decrypting test data...");
    let decrypted = context.decrypt(&encrypted)?;

    if let Ok(mut bar) = progress_bar.lock() {
        bar.finish("Decryption completed successfully!");
    }

    if test_data != decrypted.as_slice() {
        return Err(anyhow!("Decrypted data does not match original message"));
    }
    println!("\n✅ Data integrity verified - encryption/decryption working correctly!");
    println!("\n🎉 Progress indicator demo completed successfully!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_bar_updates_message() {
        let mut bar = CliProgressBar::new();
        bar.update("test", 0.5);
        assert_eq!(bar.last_message, "test");
    }
}
