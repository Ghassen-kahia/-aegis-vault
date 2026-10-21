//! Detects the two OS events that must lock the vault (L-9): the machine being suspended
//! and the user's session being locked. Both are polled from the sweeper thread.

use std::time::{Duration, Instant, SystemTime};

/// A gap between two sweeps longer than this means the process was frozen: suspend,
/// hibernate, or a forward wall-clock jump. Locking on a false positive is harmless.
const SUSPEND_GAP: Duration = Duration::from_secs(30);

/// Remembers when the sweeper last ran, on both the monotonic and the wall clock.
/// Some platforms stop the monotonic clock during sleep, others don't; checking both
/// catches the gap either way.
pub struct SuspendDetector {
    mono: Instant,
    wall: SystemTime,
}

impl SuspendDetector {
    pub fn new() -> Self {
        Self { mono: Instant::now(), wall: SystemTime::now() }
    }

    /// Call once per sweep. Returns true if the machine appears to have been suspended
    /// since the previous call.
    pub fn check(&mut self) -> bool {
        let (mono, wall) = (Instant::now(), SystemTime::now());
        let mono_gap = mono.duration_since(self.mono);
        // A backward clock change gives an error here; that is not a suspend.
        let wall_gap = wall.duration_since(self.wall).unwrap_or_default();
        self.mono = mono;
        self.wall = wall;
        mono_gap > SUSPEND_GAP || wall_gap > SUSPEND_GAP
    }
}

/// Reports a session lock once, on the transition from unlocked to locked. Edge-triggered so
/// that an environment where the check always reports "locked" cannot make the vault
/// re-lock every second.
pub struct SessionLockDetector {
    was_locked: bool,
}

impl SessionLockDetector {
    pub fn new() -> Self {
        Self { was_locked: session_locked() }
    }

    /// Call once per sweep. Returns true if the session became locked since the last call.
    pub fn check(&mut self) -> bool {
        self.observe(session_locked())
    }

    fn observe(&mut self, locked: bool) -> bool {
        let became_locked = locked && !self.was_locked;
        self.was_locked = locked;
        became_locked
    }
}

/// True if the interactive session is locked (Win+L, lid close with lock, RDP disconnect).
///
/// When the session is locked, or a secure desktop such as UAC is showing, the input
/// desktop is Winlogon's and a normal user process cannot open it. A UAC prompt therefore
/// also locks the vault, which errs on the safe side.
#[cfg(windows)]
#[allow(unsafe_code)]
fn session_locked() -> bool {
    use windows_sys::Win32::System::StationsAndDesktops::{CloseDesktop, OpenInputDesktop, DESKTOP_SWITCHDESKTOP};

    // SAFETY: plain Win32 calls with no pointers passed in. The returned handle is either
    // null or a desktop handle we own and close exactly once.
    unsafe {
        let desk = OpenInputDesktop(0, 0, DESKTOP_SWITCHDESKTOP);
        if desk.is_null() {
            return true;
        }
        CloseDesktop(desk);
        false
    }
}

/// Session-lock detection is not implemented on this platform yet; suspend detection
/// and the inactivity timeout still apply.
#[cfg(not(windows))]
fn session_locked() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consecutive_checks_are_not_a_suspend() {
        let mut d = SuspendDetector::new();
        assert!(!d.check());
        assert!(!d.check());
    }

    #[test]
    fn long_gap_is_a_suspend_and_resets() {
        let mut d = SuspendDetector::new();
        d.wall -= SUSPEND_GAP + Duration::from_secs(1);
        assert!(d.check());
        assert!(!d.check());
    }

    #[test]
    fn session_lock_fires_once_per_transition() {
        let mut d = SessionLockDetector { was_locked: false };
        assert!(!d.observe(false));
        assert!(d.observe(true));
        assert!(!d.observe(true), "staying locked must not fire again");
        assert!(!d.observe(false));
        assert!(d.observe(true));
    }

    #[test]
    fn always_locked_environment_never_fires() {
        let mut d = SessionLockDetector { was_locked: true };
        assert!(!d.observe(true));
        assert!(!d.observe(true));
    }

    /// Needs an interactive, unlocked desktop, so not run in CI: `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn interactive_desktop_is_not_locked() {
        assert!(!session_locked());
    }

    #[test]
    fn backward_clock_change_is_not_a_suspend() {
        let mut d = SuspendDetector::new();
        d.wall += Duration::from_secs(3600);
        assert!(!d.check());
    }
}
