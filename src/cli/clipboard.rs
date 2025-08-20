use anyhow::{anyhow, Result};

/// Copy the provided text to the system clipboard.
pub fn copy_to_clipboard(text: &str) -> Result<()> {
    let mut clipboard =
        arboard::Clipboard::new().map_err(|e| anyhow!("Failed to access clipboard: {e}"))?;
    clipboard
        .set_text(text.to_owned())
        .map_err(|e| anyhow!("Failed to copy to clipboard: {e}"))?;
    Ok(())
}
