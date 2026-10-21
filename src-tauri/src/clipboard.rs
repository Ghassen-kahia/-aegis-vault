//! Clipboard handling (THREAT_MODEL threat 11, boundary B3).
//!
//! * Secrets are written by Rust, so "copy" never sends the value to JavaScript.
//! * On Windows the entry is excluded from clipboard history and cloud clipboard.
//! * Only a SHA-256 of what we copied is remembered; we clear the clipboard after the
//!   timeout (or on lock/exit) only if it still holds *our* value.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::commands::CmdError;

struct Entry {
    digest: [u8; 32],
    clear_at: Instant,
}

#[derive(Default)]
pub struct ClipboardGuard {
    entry: Mutex<Option<Entry>>,
}

fn digest(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

fn clip_err(_: arboard::Error) -> CmdError {
    CmdError::new("clipboard", "the clipboard is unavailable")
}

impl ClipboardGuard {
    fn entry(&self) -> std::sync::MutexGuard<'_, Option<Entry>> {
        self.entry.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn copy(&self, value: &str, ttl: Duration) -> Result<(), CmdError> {
        let mut cb = arboard::Clipboard::new().map_err(clip_err)?;
        #[cfg(windows)]
        {
            use arboard::SetExtWindows;
            cb.set().exclude_from_cloud().exclude_from_history().text(value).map_err(clip_err)?;
        }
        #[cfg(not(windows))]
        cb.set_text(value).map_err(clip_err)?;
        *self.entry() = Some(Entry {
            digest: digest(value),
            clear_at: Instant::now() + ttl,
        });
        Ok(())
    }

    /// Clears our entry once its timeout has passed. Called periodically.
    pub fn sweep(&self) {
        let due = self.entry().as_ref().is_some_and(|e| Instant::now() >= e.clear_at);
        if due {
            self.clear_now();
        }
    }

    /// Clears the clipboard if it still holds the value we put there (lock / exit).
    pub fn clear_now(&self) {
        let Some(entry) = self.entry().take() else { return };
        let Ok(mut cb) = arboard::Clipboard::new() else { return };
        let ours = match cb.get_text() {
            Ok(text) => {
                let text = Zeroizing::new(text);
                bool::from(digest(&text).ct_eq(&entry.digest))
            }
            Err(_) => false,
        };
        if ours {
            // Best effort: nothing useful can be done if the OS refuses.
            let _ = cb.clear();
        }
    }
}
