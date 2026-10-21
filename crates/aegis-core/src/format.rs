//! On-disk vault file (format version 1). Everything here is either public header data
//! or AEAD ciphertext. See `docs/CRYPTOGRAPHY.md` §7.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{Sealed, NONCE_LEN, TAG_LEN};
use crate::encoding::b64;
use crate::error::{Error, Result};
use crate::kdf::KdfParams;

pub const FORMAT_NAME: &str = "aegis-vault";
pub const FORMAT_VERSION: u32 = 1;
/// Refuse to parse absurdly large files (DoS guard).
pub const MAX_FILE_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_ITEMS: usize = 100_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedBlob {
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

impl From<Sealed> for SealedBlob {
    fn from(s: Sealed) -> Self {
        Self {
            nonce: s.nonce.to_vec(),
            ciphertext: s.ciphertext,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySlots {
    pub password: SealedBlob,
    pub recovery: Option<SealedBlob>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemRecord {
    pub id: Uuid,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

impl ItemRecord {
    /// SHA-256(nonce ‖ ciphertext), committed to by the encrypted manifest.
    pub fn digest(&self) -> [u8; 32] {
        crate::crypto::sha256(&[&self.nonce, &self.ciphertext])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultFile {
    pub format: String,
    pub version: u32,
    pub vault_id: Uuid,
    pub kdf: KdfParams,
    pub slots: KeySlots,
    pub meta: SealedBlob,
    pub items: Vec<ItemRecord>,
}

impl VaultFile {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_FILE_BYTES {
            return Err(Error::Format("file too large".into()));
        }
        let f: VaultFile =
            serde_json::from_slice(bytes).map_err(|e| Error::Format(format!("parse error: {}", e.classify_name())))?;
        f.validate_structure()?;
        Ok(f)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|_| Error::Format("serialisation failed".into()))
    }

    /// Structural checks that need no key. Cryptographic checks happen at unlock.
    pub fn validate_structure(&self) -> Result<()> {
        if self.format != FORMAT_NAME {
            return Err(Error::Format("not an AEGIS VAULT file".into()));
        }
        if self.version != FORMAT_VERSION {
            return Err(Error::Format(format!("unsupported format version {}", self.version)));
        }
        self.kdf.validate()?;
        let blobs = std::iter::once(&self.slots.password)
            .chain(self.slots.recovery.iter())
            .chain(std::iter::once(&self.meta));
        for b in blobs {
            check_blob(&b.nonce, &b.ciphertext)?;
        }
        if self.items.len() > MAX_ITEMS {
            return Err(Error::Format("too many items".into()));
        }
        let mut seen = HashSet::with_capacity(self.items.len());
        for r in &self.items {
            check_blob(&r.nonce, &r.ciphertext)?;
            if !seen.insert(r.id) {
                return Err(Error::Format("duplicate item id".into()));
            }
        }
        Ok(())
    }
}

fn check_blob(nonce: &[u8], ct: &[u8]) -> Result<()> {
    if nonce.len() != NONCE_LEN {
        return Err(Error::Format("bad nonce length".into()));
    }
    if ct.len() < TAG_LEN {
        return Err(Error::Format("ciphertext too short".into()));
    }
    Ok(())
}

trait ClassifyName {
    fn classify_name(&self) -> &'static str;
}

impl ClassifyName for serde_json::Error {
    /// A category string only — never echoes file content back.
    fn classify_name(&self) -> &'static str {
        match self.classify() {
            serde_json::error::Category::Io => "io",
            serde_json::error::Category::Syntax => "syntax",
            serde_json::error::Category::Data => "unexpected structure",
            serde_json::error::Category::Eof => "truncated file",
        }
    }
}
