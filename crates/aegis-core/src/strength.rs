//! Password strength estimation (zxcvbn) and master-password policy.

use serde::Serialize;

use crate::error::{Error, Result};

pub const MIN_MASTER_CHARS: usize = 12;
pub const MAX_MASTER_CHARS: usize = 1024;
pub const MIN_MASTER_SCORE: u8 = 3;
/// zxcvbn is super-linear in input length; longer inputs are estimated on a prefix.
const MAX_ESTIMATE_CHARS: usize = 256;

#[derive(Clone, Debug, Serialize)]
pub struct StrengthReport {
    /// 0 (very weak) … 4 (very strong)
    pub score: u8,
    pub guesses_log10: f64,
    pub warning: Option<String>,
    pub suggestions: Vec<String>,
}

pub fn estimate(password: &str) -> StrengthReport {
    let prefix: String = password.chars().take(MAX_ESTIMATE_CHARS).collect();
    let e = zxcvbn::zxcvbn(&prefix, &[]);
    let feedback = e.feedback();
    StrengthReport {
        score: e.score() as u8,
        guesses_log10: e.guesses_log10(),
        warning: feedback.and_then(|f| f.warning()).map(|w| w.to_string()),
        suggestions: feedback
            .map(|f| f.suggestions().iter().map(|s| s.to_string()).collect())
            .unwrap_or_default(),
    }
}

pub fn check_master_password_policy(password: &str) -> Result<()> {
    let n = password.chars().count();
    if n < MIN_MASTER_CHARS {
        return Err(Error::Policy(format!("master password must be at least {MIN_MASTER_CHARS} characters")));
    }
    if n > MAX_MASTER_CHARS {
        return Err(Error::Policy("master password is too long".into()));
    }
    if estimate(password).score < MIN_MASTER_SCORE {
        return Err(Error::Policy("master password is too easy to guess — use a longer passphrase".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy() {
        assert!(check_master_password_policy("short").is_err());
        assert!(check_master_password_policy("passwordpassword").is_err());
        assert!(check_master_password_policy("quarry-velvet-ozone-lantern-71").is_ok());
    }
}
