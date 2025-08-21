use anyhow::{anyhow, Result};
use std::{thread, time::Duration};
use zeroize::Zeroizing;

/// Copy the provided text to the system clipboard and optionally clear it
/// after the given timeout. The previous clipboard contents are restored when
/// possible. This function never prints the copied value.
pub fn copy_to_clipboard(text: &str, timeout: Option<Duration>) -> Result<()> {
    let mut clipboard =
        arboard::Clipboard::new().map_err(|e| anyhow!("Failed to access clipboard: {e}"))?;

    // Preserve current clipboard contents so we can restore them later. Failure
    // to read the clipboard is not considered fatal; we simply won't restore it
    // afterwards.
    let previous = clipboard.get_text().ok().map(Zeroizing::new);

    clipboard
        .set_text(text.to_owned())
        .map_err(|e| anyhow!("Failed to copy to clipboard: {e}"))?;

    if let Some(duration) = timeout {
        // Spawn a background thread that waits for the timeout and then clears
        // or restores the clipboard. Any errors during this best-effort cleanup
        // are intentionally ignored to avoid exposing secrets.
        thread::spawn(move || {
            thread::sleep(duration);
            if let Ok(mut cb) = arboard::Clipboard::new() {
                if let Some(prev) = previous {
                    let _ = cb.set_text(prev.to_string());
                } else {
                    let _ = cb.clear();
                }
            }
        });
    }

    Ok(())
}
