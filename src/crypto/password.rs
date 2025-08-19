use rand::seq::SliceRandom;

use crate::models::PasswordGeneratorSettings;

/// Generate a random password using the provided settings.
///
/// This standalone function avoids the heavy initialization cost of an
/// `EncryptionContext` while still providing secure password generation. It
/// uses a cryptographically secure random number generator from the `rand`
/// crate and supports character set filtering for improved usability.
pub fn generate_password(settings: &PasswordGeneratorSettings) -> String {
    let mut rng = rand::thread_rng();
    let mut groups: Vec<Vec<u8>> = Vec::new();

    if settings.use_lowercase {
        groups.push(b"abcdefghijklmnopqrstuvwxyz".to_vec());
    }
    if settings.use_uppercase {
        groups.push(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec());
    }
    if settings.use_numbers {
        groups.push(b"0123456789".to_vec());
    }
    if settings.use_symbols {
        groups.push(b"!@#$%^&*()_+-=[]{}|;:,.<>?".to_vec());
    }

    if groups.is_empty() {
        groups.push(b"abcdefghijklmnopqrstuvwxyz".to_vec());
    }

    // Remove similar or ambiguous characters if requested
    if settings.exclude_similar || settings.exclude_ambiguous {
        let similar = b"il1Lo0O";
        let ambiguous = b"{}[]()/\\'\"`~,;:.<>";
        for group in &mut groups {
            if settings.exclude_similar {
                group.retain(|c| !similar.contains(c));
            }
            if settings.exclude_ambiguous {
                group.retain(|c| !ambiguous.contains(c));
            }
        }
        // Remove any groups that became empty after filtering
        groups.retain(|g| !g.is_empty());
        if groups.is_empty() {
            groups.push(b"abcdefghijklmnopqrstuvwxyz".to_vec());
        }
    }

    let chars: Vec<u8> = groups.iter().flatten().cloned().collect();
    let mut password: Vec<char> = Vec::with_capacity(settings.length as usize);

    for group in &groups {
        if password.len() < settings.length as usize {
            if let Some(&ch) = group.choose(&mut rng) {
                password.push(ch as char);
            }
        }
    }

    while password.len() < settings.length as usize {
        if let Some(&ch) = chars.choose(&mut rng) {
            password.push(ch as char);
        }
    }

    password.shuffle(&mut rng);
    password.into_iter().collect()
}
