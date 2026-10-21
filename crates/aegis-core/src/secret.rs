//! Zeroize-on-drop containers for key material and secret strings.

use std::fmt;

use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const KEY_LEN: usize = 32;

/// A 256-bit symmetric key. Heap-allocated so moves do not leave stack copies,
/// wiped on drop, and never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(Box<[u8; KEY_LEN]>);

impl SecretKey {
    /// A fresh key from the operating system CSPRNG.
    pub fn generate() -> Self {
        let mut key = Self::zeroed();
        crate::rng::os_rng().fill_bytes(key.0.as_mut());
        key
    }

    pub(crate) fn zeroed() -> Self {
        Self(Box::new([0u8; KEY_LEN]))
    }

    /// Builds a key from a slice, which must be exactly `KEY_LEN` bytes.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != KEY_LEN {
            return None;
        }
        let mut key = Self::zeroed();
        key.0.copy_from_slice(bytes);
        Some(key)
    }

    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub(crate) fn expose_mut(&mut self) -> &mut [u8; KEY_LEN] {
        &mut self.0
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &SecretKey) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

/// A UTF-8 secret (master password, item secret) wiped on drop.
#[derive(Clone, Default, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // The intermediate String is moved (not copied) into the wrapper.
        String::deserialize(d).map(SecretString)
    }
}

/// Plaintext byte buffer that is wiped on drop.
pub type SecretBytes = Zeroizing<Vec<u8>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let k = SecretKey::from_slice(&[0x41; 32]).unwrap();
        let s = SecretString::from("hunter2-super-secret");
        let out = format!("{k:?} {s:?}");
        assert!(!out.contains("hunter2"));
        assert!(!out.contains("41"));
        assert!(out.contains("redacted"));
    }

    #[test]
    fn generated_keys_differ_and_compare_in_constant_time() {
        let a = SecretKey::generate();
        let b = SecretKey::generate();
        assert!(!a.ct_eq(&b));
        assert!(a.ct_eq(&a.clone()));
        assert_ne!(a.expose(), &[0u8; 32]);
    }

    #[test]
    fn from_slice_rejects_wrong_length() {
        assert!(SecretKey::from_slice(&[0; 31]).is_none());
        assert!(SecretKey::from_slice(&[0; 33]).is_none());
    }
}
