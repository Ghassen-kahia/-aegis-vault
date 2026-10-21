//! Recovery Key: a 256-bit random key, held by the user, that can unwrap the Vault Key.
//!
//! Encoding: `RK ‖ SHA-256("aegis-vault/v1/rk-check" ‖ RK)[..2]` → base32 (RFC 4648, no padding)
//! → 11 groups of 5 characters. The 2-byte check only detects typos.

use std::fmt;

use data_encoding::BASE32_NOPAD;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{hkdf_extract_expand, sha256, LABEL_KEK_RECOVERY};
use crate::error::{Error, Result};
use crate::secret::{SecretKey, SecretString, KEY_LEN};

const CHECK_LABEL: &[u8] = b"aegis-vault/v1/rk-check";
const CHECK_LEN: usize = 2;
const GROUP: usize = 5;

pub struct RecoveryKey(SecretKey);

impl RecoveryKey {
    pub fn generate() -> Self {
        Self(SecretKey::generate())
    }

    fn check(key: &[u8]) -> [u8; CHECK_LEN] {
        let h = sha256(&[CHECK_LABEL, key]);
        [h[0], h[1]]
    }

    /// Human-readable form, e.g. `ABCDE-FGHIJ-…` (65 characters).
    pub fn encode(&self) -> SecretString {
        let mut raw = Zeroizing::new(Vec::with_capacity(KEY_LEN + CHECK_LEN));
        raw.extend_from_slice(self.0.expose());
        raw.extend_from_slice(&Self::check(self.0.expose()));
        let b32 = Zeroizing::new(BASE32_NOPAD.encode(&raw));
        let mut out = String::with_capacity(b32.len() + b32.len() / GROUP);
        for (i, c) in b32.chars().enumerate() {
            if i > 0 && i % GROUP == 0 {
                out.push('-');
            }
            out.push(c);
        }
        SecretString::new(out)
    }

    /// Parses user input, ignoring case, spaces and dashes.
    pub fn parse(input: &str) -> Result<Self> {
        let invalid = || Error::Validation("recovery key is malformed — check for typos".into());
        let cleaned: Zeroizing<String> = Zeroizing::new(
            input
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        let raw = Zeroizing::new(BASE32_NOPAD.decode(cleaned.as_bytes()).map_err(|_| invalid())?);
        if raw.len() != KEY_LEN + CHECK_LEN {
            return Err(invalid());
        }
        let (key, check) = raw.split_at(KEY_LEN);
        if !bool::from(Self::check(key).ct_eq(check)) {
            return Err(invalid());
        }
        SecretKey::from_slice(key).map(Self).ok_or_else(invalid)
    }

    /// KEK_rk = HKDF-SHA256(salt = vault_id, IKM = RK, info = "aegis-vault/v1/kek/recovery").
    pub fn kek(&self, vault_id: &Uuid) -> Result<SecretKey> {
        hkdf_extract_expand(vault_id.as_bytes(), self.0.expose(), LABEL_KEK_RECOVERY)
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_parse_roundtrip() {
        let rk = RecoveryKey::generate();
        let text = rk.encode();
        assert_eq!(text.len(), 55 + 10);
        let parsed = RecoveryKey::parse(text.expose()).unwrap();
        assert!(parsed.0.ct_eq(&rk.0));
        // Lower-case, spaces instead of dashes.
        let sloppy = text.expose().to_lowercase().replace('-', " ");
        assert!(RecoveryKey::parse(&sloppy).unwrap().0.ct_eq(&rk.0));
    }

    #[test]
    fn typos_are_detected() {
        let rk = RecoveryKey::generate();
        let text = rk.encode().expose().to_owned();
        let mut chars: Vec<char> = text.chars().collect();
        chars[3] = if chars[3] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert!(RecoveryKey::parse(&typo).is_err());
        assert!(RecoveryKey::parse(&text[..text.len() - 1]).is_err());
        assert!(RecoveryKey::parse("").is_err());
        assert!(RecoveryKey::parse("not a key!").is_err());
    }

    #[test]
    fn kek_depends_on_vault_id() {
        let rk = RecoveryKey::generate();
        let a = rk.kek(&Uuid::new_v4()).unwrap();
        let b = rk.kek(&Uuid::new_v4()).unwrap();
        assert!(!a.ct_eq(&b));
    }
}
