//! The unlocked vault: holds the Vault Key and decrypted items in zeroizing memory.
//! Dropping an `UnlockedVault` *is* locking it.

use std::collections::{BTreeMap, HashSet};

use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::backup::BackupFile;
use crate::crypto::{
    aad_item, aad_meta, aad_slot_password, aad_slot_recovery, hkdf_expand, open, pad, seal, sha256, unpad,
    LABEL_KEK_PASSWORD,
};
use crate::error::{Error, Result};
use crate::format::{ItemRecord, KeySlots, SealedBlob, VaultFile, FORMAT_NAME, FORMAT_VERSION, MAX_ITEMS};
use crate::import::ImportEntry;
use crate::item::{Item, ItemInput, ItemSummary, MAX_HISTORY};
use crate::kdf::KdfParams;
use crate::recovery::RecoveryKey;
use crate::secret::{SecretKey, SecretString};
use crate::strength::check_master_password_policy;

pub const MAX_FOLDER_NAME: usize = 64;
pub const MAX_FOLDERS: usize = 256;

/// User settings. Stored inside the encrypted manifest so a file attacker cannot weaken them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub auto_lock_minutes: u32,
    pub clipboard_clear_seconds: u32,
}

impl Settings {
    pub const AUTO_LOCK_RANGE: (u32, u32) = (1, 480);
    pub const CLIPBOARD_RANGE: (u32, u32) = (5, 600);

    pub fn validate(&self) -> Result<()> {
        let (a, b) = Self::AUTO_LOCK_RANGE;
        if !(a..=b).contains(&self.auto_lock_minutes) {
            return Err(Error::Validation(format!("auto-lock must be between {a} and {b} minutes")));
        }
        let (a, b) = Self::CLIPBOARD_RANGE;
        if !(a..=b).contains(&self.clipboard_clear_seconds) {
            return Err(Error::Validation(format!("clipboard clearing must be between {a} and {b} seconds")));
        }
        Ok(())
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 5,
            clipboard_clear_seconds: 30,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Folder {
    pub id: Uuid,
    pub name: String,
}

/// Outcome of [`UnlockedVault::import`]. Counts only; never item content.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ImportReport {
    pub imported: usize,
    /// Identical to an item already in the vault (or earlier in the same import).
    pub duplicates: usize,
    /// Failed item validation (e.g. a value over the size limit).
    pub invalid: usize,
    pub folders_created: usize,
}

/// Identity of an item's content for duplicate detection: kind, title, every field's kind and
/// value, and notes. Hashed so the comparison set holds no plaintext.
fn fingerprint(kind: crate::item::ItemKind, title: &str, fields: &[(crate::item::FieldKind, &str)], notes: &str) -> [u8; 32] {
    let mut fields: Vec<_> = fields.to_vec();
    fields.sort_by(|a, b| (a.0 as u8, a.1).cmp(&(b.0 as u8, b.1)));
    let mut buf = Zeroizing::new(Vec::new());
    let mut part = |bytes: &[u8]| {
        buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        buf.extend_from_slice(bytes);
    };
    part(&[kind as u8]);
    part(title.trim().to_lowercase().as_bytes());
    for (k, v) in &fields {
        part(&[*k as u8]);
        part(v.as_bytes());
    }
    part(notes.trim_end().as_bytes());
    sha256(&[&buf])
}

fn item_fingerprint(item: &Item) -> [u8; 32] {
    let fields: Vec<_> = item.fields.iter().map(|f| (f.kind, f.value.as_str())).collect();
    fingerprint(item.kind, &item.title, &fields, &item.notes)
}

/// Encrypted manifest: commits to the exact item set and protects settings.
#[derive(Serialize, Deserialize)]
struct VaultMeta {
    revision: u64,
    /// item id → hex SHA-256(nonce ‖ ciphertext)
    items: BTreeMap<Uuid, String>,
    settings: Settings,
    folders: Vec<Folder>,
}

pub struct UnlockedVault {
    vault_id: Uuid,
    kdf: KdfParams,
    vault_key: SecretKey,
    slots: KeySlots,
    revision: u64,
    settings: Settings,
    folders: Vec<Folder>,
    items: BTreeMap<Uuid, Item>,
    records: BTreeMap<Uuid, ItemRecord>,
    /// Unlocked with the Recovery Key: a new master password must be set.
    recovered: bool,
}

impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("vault_id", &self.vault_id)
            .field("items", &self.items.len())
            .finish_non_exhaustive()
    }
}

// ---- Key slots ------------------------------------------------------------------

fn wrap_password_slot(vault_id: &Uuid, kdf: &KdfParams, password: &SecretString, vk: &SecretKey) -> Result<SealedBlob> {
    let mk = kdf.derive_master_key(password.expose().as_bytes())?;
    let kek = hkdf_expand(&mk, LABEL_KEK_PASSWORD)?;
    drop(mk);
    Ok(seal(&kek, &aad_slot_password(vault_id, kdf), vk.expose())?.into())
}

fn unwrap_password_slot(vault_id: &Uuid, kdf: &KdfParams, slot: &SealedBlob, password: &SecretString) -> Result<SecretKey> {
    let mk = kdf.derive_master_key(password.expose().as_bytes())?;
    let kek = hkdf_expand(&mk, LABEL_KEK_PASSWORD)?;
    drop(mk);
    let raw = open(&kek, &aad_slot_password(vault_id, kdf), &slot.nonce, &slot.ciphertext)
        .map_err(|_| Error::InvalidCredentials)?;
    SecretKey::from_slice(&raw).ok_or(Error::Integrity("bad vault key length"))
}

fn wrap_recovery_slot(vault_id: &Uuid, rk: &RecoveryKey, vk: &SecretKey) -> Result<SealedBlob> {
    let kek = rk.kek(vault_id)?;
    Ok(seal(&kek, &aad_slot_recovery(vault_id), vk.expose())?.into())
}

impl UnlockedVault {
    // ---- Lifecycle ----------------------------------------------------------------

    /// Creates a new vault. Returns the Recovery Key, which must be shown to the user once.
    pub fn create(password: &SecretString, kdf: KdfParams) -> Result<(Self, RecoveryKey)> {
        check_master_password_policy(password.expose())?;
        kdf.validate()?;
        let vault_id = Uuid::new_v4();
        let vault_key = SecretKey::generate();
        let rk = RecoveryKey::generate();
        let slots = KeySlots {
            password: wrap_password_slot(&vault_id, &kdf, password, &vault_key)?,
            recovery: Some(wrap_recovery_slot(&vault_id, &rk, &vault_key)?),
        };
        let vault = Self {
            vault_id,
            kdf,
            vault_key,
            slots,
            revision: 0,
            settings: Settings::default(),
            folders: Vec::new(),
            items: BTreeMap::new(),
            records: BTreeMap::new(),
            recovered: false,
        };
        Ok((vault, rk))
    }

    pub fn unlock_with_password(file: &VaultFile, password: &SecretString) -> Result<Self> {
        file.validate_structure()?;
        let vk = unwrap_password_slot(&file.vault_id, &file.kdf, &file.slots.password, password)?;
        Self::open_with_key(file, vk, false)
    }

    pub fn unlock_with_recovery_key(file: &VaultFile, rk: &RecoveryKey) -> Result<Self> {
        file.validate_structure()?;
        let slot = file.slots.recovery.as_ref().ok_or(Error::InvalidCredentials)?;
        let kek = rk.kek(&file.vault_id)?;
        let raw = open(&kek, &aad_slot_recovery(&file.vault_id), &slot.nonce, &slot.ciphertext)
            .map_err(|_| Error::InvalidCredentials)?;
        let vk = SecretKey::from_slice(&raw).ok_or(Error::Integrity("bad vault key length"))?;
        Self::open_with_key(file, vk, true)
    }

    fn open_with_key(file: &VaultFile, vk: SecretKey, recovered: bool) -> Result<Self> {
        let id = file.vault_id;
        let meta_pt = open(&vk, &aad_meta(&id), &file.meta.nonce, &file.meta.ciphertext)
            .map_err(|_| Error::Integrity("manifest authentication failed"))?;
        let meta: VaultMeta =
            serde_json::from_slice(unpad(&meta_pt)?).map_err(|_| Error::Integrity("manifest is malformed"))?;
        meta.settings.validate().map_err(|_| Error::Integrity("manifest settings out of range"))?;

        // The file's item set must equal the manifest's exactly (ids are unique: validate_structure).
        if meta.items.len() != file.items.len() {
            return Err(Error::Integrity("item set does not match manifest"));
        }
        let mut items = BTreeMap::new();
        let mut records = BTreeMap::new();
        for rec in &file.items {
            let expected = meta.items.get(&rec.id).ok_or(Error::Integrity("item not in manifest"))?;
            if *expected != HEXLOWER.encode(&rec.digest()) {
                return Err(Error::Integrity("item does not match manifest"));
            }
            let pt = open(&vk, &aad_item(&id, &rec.id), &rec.nonce, &rec.ciphertext)
                .map_err(|_| Error::Integrity("item authentication failed"))?;
            let item: Item =
                serde_json::from_slice(unpad(&pt)?).map_err(|_| Error::Integrity("item is malformed"))?;
            if item.id != rec.id {
                return Err(Error::Integrity("item id mismatch"));
            }
            items.insert(rec.id, item);
            records.insert(rec.id, rec.clone());
        }
        Ok(Self {
            vault_id: id,
            kdf: file.kdf.clone(),
            vault_key: vk,
            slots: file.slots.clone(),
            revision: meta.revision,
            settings: meta.settings,
            folders: meta.folders,
            items,
            records,
            recovered,
        })
    }

    /// Seals the manifest (revision + 1) and produces the file to persist.
    pub fn seal_to_file(&mut self) -> Result<VaultFile> {
        self.revision += 1;
        let meta = VaultMeta {
            revision: self.revision,
            items: self.records.iter().map(|(id, r)| (*id, HEXLOWER.encode(&r.digest()))).collect(),
            settings: self.settings,
            folders: self.folders.clone(),
        };
        let json = Zeroizing::new(serde_json::to_vec(&meta).map_err(|_| Error::Crypto)?);
        let sealed = seal(&self.vault_key, &aad_meta(&self.vault_id), &pad(&json)?)?;
        Ok(VaultFile {
            format: FORMAT_NAME.to_owned(),
            version: FORMAT_VERSION,
            vault_id: self.vault_id,
            kdf: self.kdf.clone(),
            slots: self.slots.clone(),
            meta: sealed.into(),
            items: self.records.values().cloned().collect(),
        })
    }

    fn seal_item(&self, item: &Item) -> Result<ItemRecord> {
        let json = Zeroizing::new(serde_json::to_vec(item).map_err(|_| Error::Crypto)?);
        let sealed = seal(&self.vault_key, &aad_item(&self.vault_id, &item.id), &pad(&json)?)?;
        Ok(ItemRecord {
            id: item.id,
            nonce: sealed.nonce.to_vec(),
            ciphertext: sealed.ciphertext,
        })
    }

    fn store_item(&mut self, item: Item) -> Result<()> {
        let record = self.seal_item(&item)?;
        self.records.insert(item.id, record);
        self.items.insert(item.id, item);
        Ok(())
    }

    // ---- Accessors ----------------------------------------------------------------

    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn kdf_params(&self) -> &KdfParams {
        &self.kdf
    }

    pub fn settings(&self) -> Settings {
        self.settings
    }

    pub fn folders(&self) -> &[Folder] {
        &self.folders
    }

    pub fn must_change_password(&self) -> bool {
        self.recovered
    }

    pub fn has_recovery_key(&self) -> bool {
        self.slots.recovery.is_some()
    }

    pub fn item(&self, id: &Uuid) -> Result<&Item> {
        self.items.get(id).ok_or(Error::NotFound)
    }

    pub fn summaries(&self) -> Vec<ItemSummary> {
        let mut v: Vec<ItemSummary> = self.items.values().map(Item::summary).collect();
        v.sort_by_cached_key(|s| s.title.to_lowercase());
        v
    }

    // ---- Items ----------------------------------------------------------------------

    fn check_folder(&self, folder: Option<Uuid>) -> Result<()> {
        match folder {
            Some(f) if !self.folders.iter().any(|x| x.id == f) => Err(Error::Validation("unknown folder".into())),
            _ => Ok(()),
        }
    }

    pub fn create_item(&mut self, input: &ItemInput, now: i64) -> Result<Uuid> {
        self.check_folder(input.folder_id)?;
        let item = Item::from_input(input, now)?;
        let id = item.id;
        self.store_item(item)?;
        Ok(id)
    }

    pub fn update_item(&mut self, id: &Uuid, input: &ItemInput, now: i64) -> Result<()> {
        self.check_folder(input.folder_id)?;
        let mut item = self.item(id)?.clone();
        item.apply_update(input, now)?;
        self.store_item(item)
    }

    pub fn set_favorite(&mut self, id: &Uuid, favorite: bool) -> Result<()> {
        let mut item = self.item(id)?.clone();
        item.favorite = favorite;
        self.store_item(item)
    }

    pub fn delete_item(&mut self, id: &Uuid) -> Result<()> {
        self.items.remove(id).ok_or(Error::NotFound)?;
        self.records.remove(id);
        Ok(())
    }

    // ---- Import & export -------------------------------------------------------------------

    /// Adds `entries` to the vault. All or nothing: on error the vault is unchanged.
    /// Entries identical to an existing item are skipped, so importing the same file twice
    /// is harmless. Folders are matched by name (case-insensitive) or created.
    pub fn import(&mut self, entries: &[ImportEntry], now: i64) -> Result<ImportReport> {
        let mut report = ImportReport::default();
        let mut seen: HashSet<[u8; 32]> = self.items.values().map(item_fingerprint).collect();
        let mut folders = self.folders.clone();
        let mut staged = Vec::new();
        for e in entries {
            let mut item = match Item::from_input(&e.input, now) {
                Ok(item) => item,
                Err(_) => {
                    report.invalid += 1;
                    continue;
                }
            };
            if !seen.insert(item_fingerprint(&item)) {
                report.duplicates += 1;
                continue;
            }
            item.folder_id = e.folder.as_deref().and_then(|name| {
                let name: String = name.trim().chars().take(MAX_FOLDER_NAME).collect();
                if let Some(f) = folders.iter().find(|f| f.name.eq_ignore_ascii_case(&name)) {
                    return Some(f.id);
                }
                if name.is_empty() || folders.len() >= MAX_FOLDERS {
                    return None;
                }
                let f = Folder { id: Uuid::new_v4(), name };
                let id = f.id;
                folders.push(f);
                report.folders_created += 1;
                Some(id)
            });
            item.history = e.history.clone();
            if item.history.len() > MAX_HISTORY {
                item.history.drain(..item.history.len() - MAX_HISTORY);
            }
            item.created_at = e.created_at.unwrap_or(now);
            item.updated_at = e.updated_at.unwrap_or(item.created_at);
            staged.push(item);
        }
        if self.items.len() + staged.len() > MAX_ITEMS {
            return Err(Error::Validation(format!("the vault can hold at most {MAX_ITEMS} items")));
        }
        let mut sealed = Vec::with_capacity(staged.len());
        for item in staged {
            sealed.push((self.seal_item(&item)?, item));
        }
        report.imported = sealed.len();
        self.folders = folders;
        for (record, item) in sealed {
            self.records.insert(item.id, record);
            self.items.insert(item.id, item);
        }
        Ok(report)
    }

    /// Encrypted backup of every item and folder under a separate `passphrase` (AC-L3: requires
    /// the current master password). The passphrase must differ from the master password, so a
    /// leaked backup file cannot be used to brute-force the master password.
    pub fn export_backup(&self, current: &SecretString, passphrase: &SecretString, now: i64) -> Result<BackupFile> {
        self.verify_password(current)?;
        if passphrase.expose() == current.expose() {
            return Err(Error::Policy("use a backup passphrase that differs from your master password".into()));
        }
        BackupFile::create(&self.folders, self.items.values(), passphrase, self.kdf.with_fresh_salt()?, now)
    }

    // ---- Folders & settings -------------------------------------------------------------

    fn validate_folder_name(&self, name: &str, except: Option<Uuid>) -> Result<String> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_FOLDER_NAME {
            return Err(Error::Validation("folder name must be 1–64 characters".into()));
        }
        if self.folders.iter().any(|f| Some(f.id) != except && f.name.eq_ignore_ascii_case(name)) {
            return Err(Error::Validation("a folder with that name already exists".into()));
        }
        Ok(name.to_owned())
    }

    pub fn create_folder(&mut self, name: &str) -> Result<Folder> {
        if self.folders.len() >= MAX_FOLDERS {
            return Err(Error::Validation("too many folders".into()));
        }
        let folder = Folder {
            id: Uuid::new_v4(),
            name: self.validate_folder_name(name, None)?,
        };
        self.folders.push(folder.clone());
        Ok(folder)
    }

    pub fn rename_folder(&mut self, id: &Uuid, name: &str) -> Result<()> {
        let name = self.validate_folder_name(name, Some(*id))?;
        let f = self.folders.iter_mut().find(|f| f.id == *id).ok_or(Error::NotFound)?;
        f.name = name;
        Ok(())
    }

    /// Deletes a folder; its items are kept and moved to "no folder".
    pub fn delete_folder(&mut self, id: &Uuid) -> Result<()> {
        let pos = self.folders.iter().position(|f| f.id == *id).ok_or(Error::NotFound)?;
        let affected: Vec<Uuid> = self.items.values().filter(|i| i.folder_id == Some(*id)).map(|i| i.id).collect();
        for item_id in affected {
            let mut item = self.item(&item_id)?.clone();
            item.folder_id = None;
            self.store_item(item)?;
        }
        self.folders.remove(pos);
        Ok(())
    }

    pub fn set_settings(&mut self, settings: Settings) -> Result<()> {
        settings.validate()?;
        self.settings = settings;
        Ok(())
    }

    // ---- Credentials (all require re-authentication) --------------------------------------

    /// Re-authentication: the password must unwrap to *this* vault key (constant-time compare).
    pub fn verify_password(&self, password: &SecretString) -> Result<()> {
        let vk = unwrap_password_slot(&self.vault_id, &self.kdf, &self.slots.password, password)?;
        if vk.ct_eq(&self.vault_key) {
            Ok(())
        } else {
            Err(Error::InvalidCredentials)
        }
    }

    /// Changes the master password. Re-wraps the same Vault Key with a fresh salt and
    /// `new_kdf` parameters. The Recovery Key keeps working.
    pub fn change_password(&mut self, current: &SecretString, new: &SecretString, new_kdf: KdfParams) -> Result<()> {
        self.verify_password(current)?;
        self.set_password_unchecked(new, new_kdf)
    }

    /// After a Recovery-Key unlock, sets a new master password (the RK proved possession).
    pub fn set_password_after_recovery(&mut self, new: &SecretString, new_kdf: KdfParams) -> Result<()> {
        if !self.recovered {
            return Err(Error::Validation("current master password required".into()));
        }
        self.set_password_unchecked(new, new_kdf)
    }

    fn set_password_unchecked(&mut self, new: &SecretString, new_kdf: KdfParams) -> Result<()> {
        check_master_password_policy(new.expose())?;
        new_kdf.validate()?;
        self.slots.password = wrap_password_slot(&self.vault_id, &new_kdf, new, &self.vault_key)?;
        self.kdf = new_kdf;
        self.recovered = false;
        Ok(())
    }

    /// Issues a new Recovery Key; the previous one stops working.
    pub fn regenerate_recovery_key(&mut self, current: &SecretString) -> Result<RecoveryKey> {
        self.verify_password(current)?;
        let rk = RecoveryKey::generate();
        self.slots.recovery = Some(wrap_recovery_slot(&self.vault_id, &rk, &self.vault_key)?);
        Ok(rk)
    }

    /// Generates a brand-new Vault Key and re-encrypts everything under it.
    /// The old Recovery Key is invalidated and a new one returned.
    pub fn rotate_vault_key(&mut self, current: &SecretString) -> Result<RecoveryKey> {
        self.verify_password(current)?;
        let new_kdf = self.kdf.with_fresh_salt()?;
        let new_vk = SecretKey::generate();
        let rk = RecoveryKey::generate();
        let new_slots = KeySlots {
            password: wrap_password_slot(&self.vault_id, &new_kdf, current, &new_vk)?,
            recovery: Some(wrap_recovery_slot(&self.vault_id, &rk, &new_vk)?),
        };
        // Re-encrypt into a staging map so a failure leaves the vault unchanged.
        let old_vk = std::mem::replace(&mut self.vault_key, new_vk);
        let mut staged = BTreeMap::new();
        for item in self.items.values() {
            match self.seal_item(item) {
                Ok(r) => {
                    staged.insert(item.id, r);
                }
                Err(e) => {
                    self.vault_key = old_vk;
                    return Err(e);
                }
            }
        }
        drop(old_vk);
        self.records = staged;
        self.slots = new_slots;
        self.kdf = new_kdf;
        Ok(rk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::seal_with_nonce;

    /// Format regression: these bytes are produced by format v1 and must never change.
    #[test]
    fn format_v1_regression_vector() {
        let vault_id = Uuid::from_bytes([0x11; 16]);
        let item_id = Uuid::from_bytes([0x22; 16]);
        let aad = aad_item(&vault_id, &item_id);
        assert_eq!(
            HEXLOWER.encode(&aad),
            concat!(
                "61656769732d7661756c742f76312f6974656d", // "aegis-vault/v1/item"
                "11111111111111111111111111111111",
                "22222222222222222222222222222222"
            )
        );
        let key = SecretKey::from_slice(&[0x33; 32]).unwrap();
        let padded = pad(br#"{"t":"synthetic"}"#).unwrap();
        let s = seal_with_nonce(&key, &[0x44; 12], &aad, &padded).unwrap();
        assert_eq!(s.ciphertext.len(), 256 + 16);
        let digest = HEXLOWER.encode(&crate::crypto::sha256(&[&s.ciphertext]));
        assert_eq!(digest, GOLDEN_ITEM_CT_SHA256);
        let pt = open(&key, &aad, &s.nonce, &s.ciphertext).unwrap();
        assert_eq!(unpad(&pt).unwrap(), br#"{"t":"synthetic"}"#);
    }

    const GOLDEN_ITEM_CT_SHA256: &str = "0ee8e372cc6a4be0bd51128fae1fa4caaaec13b49eaf794c64b7d0b58e5d263e";
}
