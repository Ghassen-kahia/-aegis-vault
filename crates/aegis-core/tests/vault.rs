//! Vault-level acceptance tests (docs/SECURITY_REQUIREMENTS.md, AC-C3…C9, AC-L1, AC-L3, AC-F1, AC-F2).
//! Uses the fast test KDF via the `insecure-test-kdf` feature. Synthetic credentials only.

use aegis_core::format::VaultFile;
use aegis_core::item::{FieldInput, FieldKind, ItemInput, ItemKind};
use aegis_core::kdf::KdfParams;
use aegis_core::recovery::RecoveryKey;
use aegis_core::storage::{backup_path, read_vault, write_vault_atomic};
use aegis_core::vault::{Settings, UnlockedVault};
use aegis_core::{Error, SecretString};

const PW: &str = "quarry-velvet-ozone-lantern-71";
const PW2: &str = "harbor-thistle-quantum-meadow-58";

fn pw(s: &str) -> SecretString {
    SecretString::from(s)
}

fn login(title: &str, secret: &str) -> ItemInput {
    ItemInput {
        kind: ItemKind::Login,
        title: title.into(),
        folder_id: None,
        tags: vec![],
        favorite: false,
        fields: vec![
            FieldInput { id: None, label: "Username".into(), kind: FieldKind::Username, value: "synthetic@example.test".into() },
            FieldInput { id: None, label: "Password".into(), kind: FieldKind::Password, value: secret.into() },
        ],
        notes: String::new(),
    }
}

/// A sealed vault with three items, plus its Recovery Key.
fn sample() -> (VaultFile, RecoveryKey) {
    let (mut v, rk) = UnlockedVault::create(&pw(PW), KdfParams::insecure_for_tests()).unwrap();
    for i in 0..3 {
        v.create_item(&login(&format!("Item {i}"), &format!("synthetic-secret-{i}")), i).unwrap();
    }
    (v.seal_to_file().unwrap(), rk)
}

fn json(f: &VaultFile) -> serde_json::Value {
    serde_json::to_value(f).unwrap()
}

fn from_json(v: serde_json::Value) -> Result<VaultFile, Error> {
    VaultFile::from_json(&serde_json::to_vec(&v).unwrap())
}

#[test]
fn roundtrip_preserves_items_settings_and_revision() {
    let (mut v, _) = UnlockedVault::create(&pw(PW), KdfParams::insecure_for_tests()).unwrap();
    let folder = v.create_folder("Work").unwrap();
    let mut input = login("Example", "synthetic-secret");
    input.folder_id = Some(folder.id);
    let id = v.create_item(&input, 10).unwrap();
    v.set_settings(Settings { auto_lock_minutes: 15, clipboard_clear_seconds: 45 }).unwrap();
    let file = v.seal_to_file().unwrap();
    let file = VaultFile::from_json(&file.to_json().unwrap()).unwrap();

    let u = UnlockedVault::unlock_with_password(&file, &pw(PW)).unwrap();
    assert_eq!(u.revision(), 1);
    assert_eq!(u.settings().auto_lock_minutes, 15);
    assert_eq!(u.folders()[0].name, "Work");
    let item = u.item(&id).unwrap();
    assert_eq!(item.fields[1].value, "synthetic-secret");
    assert_eq!(item.folder_id, Some(folder.id));
    assert!(!u.must_change_password());
}

#[test]
fn file_contains_no_plaintext() {
    let (file, _) = sample();
    let text = String::from_utf8(file.to_json().unwrap()).unwrap();
    for needle in ["synthetic-secret", "synthetic@example.test", "Item 0", "Username"] {
        assert!(!text.contains(needle), "{needle} leaked into the file");
    }
}

// AC-C3
#[test]
fn wrong_credentials_fail_generically() {
    let (file, _) = sample();
    assert_eq!(
        UnlockedVault::unlock_with_password(&file, &pw("wrong-password-entirely")).unwrap_err(),
        Error::InvalidCredentials
    );
    assert_eq!(
        UnlockedVault::unlock_with_recovery_key(&file, &RecoveryKey::generate()).unwrap_err(),
        Error::InvalidCredentials
    );
}

// AC-C4: flipping any byte of any nonce/ciphertext, the salt, or a KDF parameter must fail.
#[test]
fn any_tampering_fails_unlock() {
    let (file, _) = sample();
    let mut targets: Vec<Box<dyn Fn(&mut VaultFile, usize) -> bool>> = Vec::new();
    fn flip(buf: &mut [u8], i: usize) -> bool {
        match buf.get_mut(i) {
            Some(b) => {
                *b ^= 0x01;
                true
            }
            None => false,
        }
    }
    targets.push(Box::new(|f, i| flip(&mut f.kdf.salt, i)));
    targets.push(Box::new(|f, i| flip(&mut f.slots.password.nonce, i)));
    targets.push(Box::new(|f, i| flip(&mut f.slots.password.ciphertext, i)));
    targets.push(Box::new(|f, i| flip(&mut f.meta.nonce, i)));
    targets.push(Box::new(|f, i| flip(&mut f.meta.ciphertext, i)));
    for n in 0..3 {
        targets.push(Box::new(move |f, i| flip(&mut f.items[n].nonce, i)));
        targets.push(Box::new(move |f, i| flip(&mut f.items[n].ciphertext, i)));
    }
    for mutate in &targets {
        // Every byte of short buffers; a spread of positions across long ciphertexts.
        let mut i = 0;
        loop {
            let mut f = file.clone();
            if !mutate(&mut f, i) {
                break;
            }
            assert!(UnlockedVault::unlock_with_password(&f, &pw(PW)).is_err(), "byte {i} not detected");
            i += if i < 48 { 1 } else { 37 };
        }
    }
    let params: [fn(&mut VaultFile); 3] = [|f| f.kdf.m_cost_kib += 1, |f| f.kdf.t_cost += 1, |f| f.kdf.p_cost += 1];
    for mutate in params {
        let mut f = file.clone();
        mutate(&mut f);
        assert!(UnlockedVault::unlock_with_password(&f, &pw(PW)).is_err());
    }
    // Sanity: the untouched file still opens.
    UnlockedVault::unlock_with_password(&file, &pw(PW)).unwrap();
}

// AC-C5
#[test]
fn swapping_deleting_injecting_or_duplicating_records_fails() {
    let (file, _) = sample();
    let integrity = |f: &VaultFile| {
        matches!(UnlockedVault::unlock_with_password(f, &pw(PW)), Err(Error::Integrity(_)))
    };

    let mut swapped = file.clone();
    let (a, b) = (swapped.items[0].clone(), swapped.items[1].clone());
    swapped.items[0].nonce = b.nonce;
    swapped.items[0].ciphertext = b.ciphertext;
    swapped.items[1].nonce = a.nonce;
    swapped.items[1].ciphertext = a.ciphertext;
    assert!(integrity(&swapped));

    let mut deleted = file.clone();
    deleted.items.pop();
    assert!(integrity(&deleted));

    let (other, _) = sample();
    let mut injected = file.clone();
    injected.items.push(other.items[0].clone());
    assert!(integrity(&injected));

    let mut replaced = file.clone();
    replaced.items[2] = other.items[0].clone();
    assert!(integrity(&replaced));

    let mut duplicated = json(&file);
    let first = duplicated["items"][0].clone();
    duplicated["items"].as_array_mut().unwrap().push(first);
    assert!(matches!(from_json(duplicated), Err(Error::Format(_))));
}

/// An older copy of a single record (same id, valid ciphertext) must be rejected.
#[test]
fn replaying_an_old_item_record_fails() {
    let (mut v, _) = UnlockedVault::create(&pw(PW), KdfParams::insecure_for_tests()).unwrap();
    let id = v.create_item(&login("Example", "synthetic-old"), 1).unwrap();
    let old = v.seal_to_file().unwrap();
    v.update_item(&id, &login("Example", "synthetic-new"), 2).unwrap();
    let mut new = v.seal_to_file().unwrap();
    new.items[0] = old.items[0].clone();
    assert!(matches!(UnlockedVault::unlock_with_password(&new, &pw(PW)), Err(Error::Integrity(_))));
}

// AC-C6 (file side): out-of-bounds parameters are refused at parse time, before any derivation.
#[test]
fn kdf_ceiling_refused_on_parse() {
    let (file, _) = sample();
    let mut v = json(&file);
    v["kdf"]["m_cost_kib"] = serde_json::json!(4u64 * 1024 * 1024 + 1);
    assert!(matches!(from_json(v), Err(Error::KdfParams(_))));
}

// AC-C7
#[test]
fn unknown_versions_and_fields_are_refused() {
    let (file, _) = sample();
    let mut v = json(&file);
    v["version"] = serde_json::json!(2);
    assert!(matches!(from_json(v), Err(Error::Format(_))));

    let mut v = json(&file);
    v["format"] = serde_json::json!("other");
    assert!(matches!(from_json(v), Err(Error::Format(_))));

    for path in [&[][..], &["slots"][..], &["meta"][..]] {
        let mut v = json(&file);
        let mut target = &mut v;
        for p in path {
            target = &mut target[*p];
        }
        target["smuggled"] = serde_json::json!("x");
        assert!(from_json(v).is_err(), "unknown field accepted at {path:?}");
    }
    let mut v = json(&file);
    v["items"][0]["smuggled"] = serde_json::json!("x");
    assert!(from_json(v).is_err());
}

// AC-C9
#[test]
fn password_change_keeps_recovery_key() {
    let (file, rk) = sample();
    let mut v = UnlockedVault::unlock_with_password(&file, &pw(PW)).unwrap();
    assert!(v.change_password(&pw("not-the-password"), &pw(PW2), KdfParams::insecure_for_tests()).is_err());
    v.change_password(&pw(PW), &pw(PW2), KdfParams::insecure_for_tests()).unwrap();
    let file = v.seal_to_file().unwrap();
    assert_eq!(UnlockedVault::unlock_with_password(&file, &pw(PW)).unwrap_err(), Error::InvalidCredentials);
    UnlockedVault::unlock_with_password(&file, &pw(PW2)).unwrap();
    UnlockedVault::unlock_with_recovery_key(&file, &rk).unwrap();
}

#[test]
fn weak_new_password_is_refused() {
    let (file, _) = sample();
    let mut v = UnlockedVault::unlock_with_password(&file, &pw(PW)).unwrap();
    let r = v.change_password(&pw(PW), &pw("passwordpassword"), KdfParams::insecure_for_tests());
    assert!(matches!(r, Err(Error::Policy(_))));
}

#[test]
fn rotation_invalidates_old_recovery_key_and_keeps_data() {
    let (file, old_rk) = sample();
    let mut v = UnlockedVault::unlock_with_password(&file, &pw(PW)).unwrap();
    let before: Vec<_> = v.summaries().into_iter().map(|s| s.id).collect();
    let new_rk = v.rotate_vault_key(&pw(PW)).unwrap();
    let rotated = v.seal_to_file().unwrap();

    assert_eq!(UnlockedVault::unlock_with_recovery_key(&rotated, &old_rk).unwrap_err(), Error::InvalidCredentials);
    UnlockedVault::unlock_with_recovery_key(&rotated, &new_rk).unwrap();
    let u = UnlockedVault::unlock_with_password(&rotated, &pw(PW)).unwrap();
    let after: Vec<_> = u.summaries().into_iter().map(|s| s.id).collect();
    assert_eq!(before, after);
    assert_eq!(u.item(&after[0]).unwrap().fields[1].value.starts_with("synthetic-secret-"), true);
    // Every ciphertext changed.
    for (a, b) in file.items.iter().zip(&rotated.items) {
        assert_ne!(a.ciphertext, b.ciphertext);
    }
    assert_ne!(file.kdf.salt, rotated.kdf.salt);
}

#[test]
fn regenerated_recovery_key_replaces_old_one() {
    let (file, old_rk) = sample();
    let mut v = UnlockedVault::unlock_with_password(&file, &pw(PW)).unwrap();
    assert!(v.regenerate_recovery_key(&pw("not-the-password")).is_err());
    let new_rk = v.regenerate_recovery_key(&pw(PW)).unwrap();
    let file = v.seal_to_file().unwrap();
    assert!(UnlockedVault::unlock_with_recovery_key(&file, &old_rk).is_err());
    UnlockedVault::unlock_with_recovery_key(&file, &new_rk).unwrap();
}

#[test]
fn recovery_unlock_requires_new_password() {
    let (file, rk) = sample();
    let mut v = UnlockedVault::unlock_with_recovery_key(&file, &rk).unwrap();
    assert!(v.must_change_password());
    v.set_password_after_recovery(&pw(PW2), KdfParams::insecure_for_tests()).unwrap();
    assert!(!v.must_change_password());
    let file = v.seal_to_file().unwrap();
    UnlockedVault::unlock_with_password(&file, &pw(PW2)).unwrap();
    assert!(UnlockedVault::unlock_with_password(&file, &pw(PW)).is_err());

    // Not allowed without a recovery unlock.
    let mut normal = UnlockedVault::unlock_with_password(&file, &pw(PW2)).unwrap();
    assert!(normal.set_password_after_recovery(&pw(PW), KdfParams::insecure_for_tests()).is_err());
}

// AC-L1
#[test]
fn settings_are_bounded() {
    let (mut v, _) = UnlockedVault::create(&pw(PW), KdfParams::insecure_for_tests()).unwrap();
    for (a, c) in [(0, 30), (481, 30), (5, 4), (5, 601)] {
        assert!(v.set_settings(Settings { auto_lock_minutes: a, clipboard_clear_seconds: c }).is_err());
    }
    v.set_settings(Settings { auto_lock_minutes: 480, clipboard_clear_seconds: 5 }).unwrap();
}

// AC-L3
#[test]
fn reauthentication_uses_constant_time_vault_key_check() {
    let (file, _) = sample();
    let v = UnlockedVault::unlock_with_password(&file, &pw(PW)).unwrap();
    v.verify_password(&pw(PW)).unwrap();
    assert_eq!(v.verify_password(&pw(PW2)).unwrap_err(), Error::InvalidCredentials);
}

#[test]
fn deleting_folder_keeps_items() {
    let (mut v, _) = UnlockedVault::create(&pw(PW), KdfParams::insecure_for_tests()).unwrap();
    let f = v.create_folder("Personal").unwrap();
    assert!(v.create_folder("personal").is_err());
    let mut input = login("Example", "synthetic");
    input.folder_id = Some(f.id);
    let id = v.create_item(&input, 0).unwrap();
    v.delete_folder(&f.id).unwrap();
    assert_eq!(v.item(&id).unwrap().folder_id, None);
    let file = v.seal_to_file().unwrap();
    UnlockedVault::unlock_with_password(&file, &pw(PW)).unwrap();
}

// AC-F1
#[test]
fn atomic_save_keeps_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.aegis");
    let (mut v, _) = UnlockedVault::create(&pw(PW), KdfParams::insecure_for_tests()).unwrap();
    write_vault_atomic(&path, &v.seal_to_file().unwrap()).unwrap();
    assert!(!backup_path(&path).exists());
    v.create_item(&login("Example", "synthetic"), 0).unwrap();
    write_vault_atomic(&path, &v.seal_to_file().unwrap()).unwrap();

    let current = UnlockedVault::unlock_with_password(&read_vault(&path).unwrap(), &pw(PW)).unwrap();
    assert_eq!((current.revision(), current.summaries().len()), (2, 1));
    let backup = UnlockedVault::unlock_with_password(&read_vault(&backup_path(&path)).unwrap(), &pw(PW)).unwrap();
    assert_eq!((backup.revision(), backup.summaries().len()), (1, 0));
    assert!(!path.with_extension("aegis.tmp").exists());
}

// AC-F2
#[test]
fn corrupted_file_is_detected_and_never_overwrites_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.aegis");
    let (mut v, _) = UnlockedVault::create(&pw(PW), KdfParams::insecure_for_tests()).unwrap();
    write_vault_atomic(&path, &v.seal_to_file().unwrap()).unwrap();
    write_vault_atomic(&path, &v.seal_to_file().unwrap()).unwrap();
    let good_backup = std::fs::read(backup_path(&path)).unwrap();

    // Truncate the live file.
    let bytes = std::fs::read(&path).unwrap();
    std::fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
    assert!(matches!(read_vault(&path), Err(Error::Format(_))));

    // Saving over a corrupted file must leave the good backup intact.
    write_vault_atomic(&path, &v.seal_to_file().unwrap()).unwrap();
    assert_eq!(std::fs::read(backup_path(&path)).unwrap(), good_backup);
    assert_eq!(UnlockedVault::unlock_with_password(&read_vault(&path).unwrap(), &pw(PW)).unwrap().revision(), 3);
}
