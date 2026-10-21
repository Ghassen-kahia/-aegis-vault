//! Encrypted backup export (format `aegis-backup` v1). See `docs/CRYPTOGRAPHY.md` §13.
//!
//! A backup is self-contained: it is protected by its own **backup passphrase**, not by the
//! vault's keys, so it can be restored after the vault file, master password and Recovery
//! Key are all lost.
//!
//! ```text
//! MK_b    = Argon2id(passphrase, salt_b)            fresh salt, vault's cost parameters
//! K_b     = HKDF-Expand(MK_b, "aegis-vault/v1/backup")
//! payload = AES-256-GCM(K_b, pad(json{folders, items}),
//!                       AAD = "aegis-vault/v1/backup/payload" ‖ backup_id ‖ i64_be(created_at) ‖ kdf_canonical)
//! ```

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{hkdf_expand, open, pad, seal, unpad, NONCE_LEN, TAG_LEN};
use crate::error::{Error, Result};
use crate::format::{SealedBlob, MAX_FILE_BYTES, MAX_ITEMS};
use crate::import::ImportEntry;
use crate::item::{FieldInput, Item, ItemInput};
use crate::kdf::KdfParams;
use crate::secret::{SecretKey, SecretString};
use crate::strength::check_master_password_policy;
use crate::vault::Folder;

pub const BACKUP_FORMAT_NAME: &str = "aegis-backup";
pub const BACKUP_FORMAT_VERSION: u32 = 1;
pub const BACKUP_EXTENSION: &str = "aegisbackup";

// Domain-separation labels. Changing either is a format break.
const LABEL_BACKUP_KEY: &[u8] = b"aegis-vault/v1/backup";
const AAD_BACKUP_PAYLOAD: &[u8] = b"aegis-vault/v1/backup/payload";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupFile {
    pub format: String,
    pub version: u32,
    pub backup_id: Uuid,
    /// Unix seconds. Bound into the payload AAD.
    pub created_at: i64,
    pub kdf: KdfParams,
    pub payload: SealedBlob,
}

/// Decrypted backup contents.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    folders: Vec<Folder>,
    items: Vec<Item>,
}

fn aad(backup_id: &Uuid, created_at: i64, kdf: &KdfParams) -> Vec<u8> {
    [AAD_BACKUP_PAYLOAD, backup_id.as_bytes(), &created_at.to_be_bytes(), &kdf.canonical_bytes()].concat()
}

fn backup_key(kdf: &KdfParams, passphrase: &SecretString) -> Result<SecretKey> {
    let mk = kdf.derive_master_key(passphrase.expose().as_bytes())?;
    hkdf_expand(&mk, LABEL_BACKUP_KEY)
}

impl BackupFile {
    /// Encrypts `items` and `folders` under `passphrase`. `kdf` must carry a fresh salt.
    pub(crate) fn create<'a>(
        folders: &[Folder],
        items: impl Iterator<Item = &'a Item>,
        passphrase: &SecretString,
        kdf: KdfParams,
        now: i64,
    ) -> Result<Self> {
        check_master_password_policy(passphrase.expose())
            .map_err(|e| Error::Policy(e.to_string().replace("master password", "backup passphrase")))?;
        let payload = Payload { folders: folders.to_vec(), items: items.cloned().collect() };
        let json = Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| Error::Crypto)?);
        drop(payload);
        let backup_id = Uuid::new_v4();
        let key = backup_key(&kdf, passphrase)?;
        let sealed = seal(&key, &aad(&backup_id, now, &kdf), &pad(&json)?)?;
        Ok(Self {
            format: BACKUP_FORMAT_NAME.to_owned(),
            version: BACKUP_FORMAT_VERSION,
            backup_id,
            created_at: now,
            kdf,
            payload: sealed.into(),
        })
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_FILE_BYTES {
            return Err(Error::Format("file too large".into()));
        }
        let f: BackupFile =
            serde_json::from_slice(bytes).map_err(|_| Error::Format("not an AEGIS VAULT backup".into()))?;
        if f.format != BACKUP_FORMAT_NAME {
            return Err(Error::Format("not an AEGIS VAULT backup".into()));
        }
        if f.version != BACKUP_FORMAT_VERSION {
            return Err(Error::Format(format!("unsupported backup version {}", f.version)));
        }
        f.kdf.validate()?;
        if f.payload.nonce.len() != NONCE_LEN || f.payload.ciphertext.len() < TAG_LEN {
            return Err(Error::Format("malformed backup payload".into()));
        }
        Ok(f)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|_| Error::Format("serialisation failed".into()))
    }

    /// Decrypts the backup into import entries. A wrong passphrase, or any modification of
    /// the header or payload, gives `InvalidCredentials` (indistinguishable by design).
    pub fn open(&self, passphrase: &SecretString) -> Result<Vec<ImportEntry>> {
        let key = backup_key(&self.kdf, passphrase)?;
        let pt = open(&key, &aad(&self.backup_id, self.created_at, &self.kdf), &self.payload.nonce, &self.payload.ciphertext)
            .map_err(|_| Error::InvalidCredentials)?;
        let payload: Payload =
            serde_json::from_slice(unpad(&pt)?).map_err(|_| Error::Integrity("backup contents are malformed"))?;
        if payload.items.len() > MAX_ITEMS {
            return Err(Error::Integrity("backup has too many items"));
        }
        let folder_name = |id: Option<Uuid>| {
            id.and_then(|id| payload.folders.iter().find(|f| f.id == id)).map(|f| f.name.clone())
        };
        Ok(payload
            .items
            .iter()
            .map(|item| ImportEntry {
                input: ItemInput {
                    kind: item.kind,
                    title: item.title.clone(),
                    folder_id: None,
                    tags: item.tags.clone(),
                    favorite: item.favorite,
                    fields: item
                        .fields
                        .iter()
                        .map(|f| FieldInput { id: None, label: f.label.clone(), kind: f.kind, value: f.value.clone() })
                        .collect(),
                    notes: item.notes.clone(),
                },
                folder: folder_name(item.folder_id),
                history: item.history.clone(),
                created_at: Some(item.created_at),
                updated_at: Some(item.updated_at),
            })
            .collect())
    }
}
