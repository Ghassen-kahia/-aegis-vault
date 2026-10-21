//! Application state held by the Rust core. The unlocked vault never leaves this process.

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use aegis_core::vault::UnlockedVault;

use crate::clipboard::ClipboardGuard;

/// Failed unlocks allowed before back-off starts.
const FREE_ATTEMPTS: u32 = 3;
const MAX_BACKOFF: Duration = Duration::from_secs(300);

pub struct AppState {
    pub vault_path: PathBuf,
    pub session: Mutex<Session>,
    pub clipboard: ClipboardGuard,
}

impl AppState {
    pub fn new(vault_path: PathBuf) -> Self {
        Self {
            vault_path,
            session: Mutex::new(Session::new()),
            clipboard: ClipboardGuard::default(),
        }
    }

    /// A poisoned lock still holds a consistent `Session` (all mutations are single
    /// assignments), so recover it rather than leaving the vault stuck.
    pub fn session(&self) -> MutexGuard<'_, Session> {
        self.session.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

pub struct Session {
    pub vault: Option<UnlockedVault>,
    last_activity: Instant,
    failures: u32,
    blocked_until: Option<Instant>,
}

impl Session {
    fn new() -> Self {
        Self {
            vault: None,
            last_activity: Instant::now(),
            failures: 0,
            blocked_until: None,
        }
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Dropping the vault zeroizes the Vault Key and every decrypted item.
    pub fn lock(&mut self) {
        self.vault = None;
    }

    /// True if the auto-lock timeout has elapsed. Enforced here, not in the UI (AC-L1).
    pub fn idle_expired(&self) -> bool {
        match &self.vault {
            Some(v) => {
                let limit = Duration::from_secs(u64::from(v.settings().auto_lock_minutes) * 60);
                self.last_activity.elapsed() >= limit
            }
            None => false,
        }
    }

    /// Seconds remaining before another unlock attempt is accepted.
    pub fn retry_after(&self) -> Option<u64> {
        let until = self.blocked_until?;
        let now = Instant::now();
        (now < until).then(|| {
            let left = until - now;
            left.as_secs() + u64::from(left.subsec_nanos() > 0)
        })
    }

    /// Exponential back-off after failed unlocks (AC-L4): 1 s, 2 s, 4 s … capped at 5 min.
    pub fn register_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= FREE_ATTEMPTS {
            let exp = (self.failures - FREE_ATTEMPTS).min(16);
            let delay = Duration::from_secs(1u64 << exp).min(MAX_BACKOFF);
            self.blocked_until = Some(Instant::now() + delay);
        }
    }

    pub fn register_success(&mut self) {
        self.failures = 0;
        self.blocked_until = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_starts_after_free_attempts_and_is_capped() {
        let mut s = Session::new();
        for _ in 0..FREE_ATTEMPTS - 1 {
            s.register_failure();
            assert_eq!(s.retry_after(), None);
        }
        s.register_failure();
        assert_eq!(s.retry_after(), Some(1));
        s.register_failure();
        assert_eq!(s.retry_after(), Some(2));
        for _ in 0..40 {
            s.register_failure();
        }
        let r = s.retry_after().unwrap();
        assert!(r <= MAX_BACKOFF.as_secs() && r > 250);
        s.register_success();
        assert_eq!(s.retry_after(), None);
    }

    #[test]
    fn locked_session_never_expires() {
        assert!(!Session::new().idle_expired());
    }
}
