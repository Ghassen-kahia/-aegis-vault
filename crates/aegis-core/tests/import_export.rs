//! Encrypted backup and import acceptance tests (AC-X1…X6). Fast test KDF, synthetic data only.

use aegis_core::backup::BackupFile;
use aegis_core::import::{self, ImportSource};
use aegis_core::item::{FieldInput, FieldKind, ItemInput, ItemKind, MAX_VALUE};
use aegis_core::kdf::KdfParams;
use aegis_core::vault::UnlockedVault;
use aegis_core::{Error, SecretString};

const PW: &str = "quarry-velvet-ozone-lantern-71";
const PASSPHRASE: &str = "orchid-copper-glacier-sonnet-42";

fn pw(s: &str) -> SecretString {
    SecretString::from(s)
}

fn login(title: &str, secret: &str) -> ItemInput {
    ItemInput {
        kind: ItemKind::Login,
        title: title.into(),
        folder_id: None,
        tags: vec!["synthetic".into()],
        favorite: false,
        fields: vec![
            FieldInput { id: None, label: "Username".into(), kind: FieldKind::Username, value: "synthetic@example.test".into() },
            FieldInput { id: None, label: "Password".into(), kind: FieldKind::Password, value: secret.into() },
        ],
        notes: String::new(),
    }
}

fn empty_vault() -> UnlockedVault {
    UnlockedVault::create(&pw(PW), KdfParams::insecure_for_tests()).unwrap().0
}

/// A vault with a folder, a favorite, and an item with password history.
fn populated_vault() -> UnlockedVault {
    let mut v = empty_vault();
    let folder = v.create_folder("Work").unwrap();
    let mut a = login("Alpha", "synthetic-secret-a1");
    a.folder_id = Some(folder.id);
    a.favorite = true;
    let id = v.create_item(&a, 100).unwrap();
    a.fields[1].value = "synthetic-secret-a2".into();
    a.fields[1].id = Some(v.item(&id).unwrap().fields[1].id);
    a.fields[0].id = Some(v.item(&id).unwrap().fields[0].id);
    v.update_item(&id, &a, 200).unwrap();
    v.create_item(&login("Beta", "synthetic-secret-b"), 300).unwrap();
    v
}

fn backup_bytes(v: &UnlockedVault) -> Vec<u8> {
    v.export_backup(&pw(PW), &pw(PASSPHRASE), 1_700_000_000).unwrap().to_json().unwrap()
}

fn restore(bytes: &[u8], passphrase: &str) -> Result<import::Parsed, Error> {
    import::parse(ImportSource::AegisBackup, bytes, Some(&pw(passphrase)), 0)
}

/// AC-X1: a backup restores every item, field, folder, favorite and history entry.
#[test]
fn backup_roundtrip_into_a_fresh_vault() {
    let src = populated_vault();
    let bytes = backup_bytes(&src);

    let mut dst = empty_vault();
    let parsed = restore(&bytes, PASSPHRASE).unwrap();
    let report = dst.import(&parsed.entries, 999).unwrap();
    assert_eq!((report.imported, report.duplicates, report.invalid, report.folders_created), (2, 0, 0, 1));

    let alpha = dst.summaries().into_iter().find(|s| s.title == "Alpha").unwrap();
    let item = dst.item(&alpha.id).unwrap();
    assert!(item.favorite);
    assert_eq!(item.tags, ["synthetic"]);
    assert_eq!(item.fields[1].value, "synthetic-secret-a2");
    assert_eq!(item.history.len(), 1);
    assert_eq!(item.history[0].value, "synthetic-secret-a1");
    assert_eq!((item.created_at, item.updated_at), (100, 200));
    assert_eq!(dst.folders()[0].name, "Work");
    assert_eq!(item.folder_id, Some(dst.folders()[0].id));
}

/// AC-X2: restoring the same backup twice adds nothing the second time.
#[test]
fn reimport_is_deduplicated() {
    let mut v = populated_vault();
    let parsed = restore(&backup_bytes(&v), PASSPHRASE).unwrap();
    let report = v.import(&parsed.entries, 0).unwrap();
    assert_eq!((report.imported, report.duplicates, report.folders_created), (0, 2, 0));
    assert_eq!(v.summaries().len(), 2);
    assert_eq!(v.folders().len(), 1);
}

/// AC-X3: the backup contains no plaintext and is unreadable without the passphrase.
#[test]
fn backup_is_encrypted_and_passphrase_bound() {
    let bytes = backup_bytes(&populated_vault());
    let text = String::from_utf8_lossy(&bytes);
    for needle in ["synthetic-secret", "Alpha", "Work", "synthetic@example.test"] {
        assert!(!text.contains(needle), "backup leaks {needle}");
    }
    assert!(matches!(restore(&bytes, PW), Err(Error::InvalidCredentials)));
    assert!(matches!(restore(&bytes, "wrong-passphrase-entirely-1"), Err(Error::InvalidCredentials)));
}

/// AC-X4: any change to the header or payload is detected.
#[test]
fn backup_tampering_is_detected() {
    let bytes = backup_bytes(&populated_vault());
    let base: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mutations: [fn(&mut serde_json::Value); 5] = [
        |v| v["created_at"] = serde_json::json!(1),
        |v| v["backup_id"] = serde_json::json!("00000000-0000-4000-8000-000000000000"),
        |v| {
            let mut salt = v["kdf"]["salt"].as_str().unwrap().to_owned();
            salt.replace_range(0..1, if salt.starts_with('A') { "B" } else { "A" });
            v["kdf"]["salt"] = serde_json::json!(salt);
        },
        |v| v["kdf"]["t_cost"] = serde_json::json!(v["kdf"]["t_cost"].as_u64().unwrap() + 1),
        |v| {
            let mut ct = v["payload"]["ciphertext"].as_str().unwrap().to_owned();
            ct.replace_range(4..5, if &ct[4..5] == "A" { "B" } else { "A" });
            v["payload"]["ciphertext"] = serde_json::json!(ct);
        },
    ];
    for mutate in mutations {
        let mut v = base.clone();
        mutate(&mut v);
        let r = restore(&serde_json::to_vec(&v).unwrap(), PASSPHRASE);
        assert!(matches!(r, Err(Error::InvalidCredentials)), "tampering not detected");
    }
    let mut v = base.clone();
    v["format"] = serde_json::json!("aegis-vault");
    assert!(matches!(restore(&serde_json::to_vec(&v).unwrap(), PASSPHRASE), Err(Error::Format(_))));
    let mut v = base.clone();
    v["version"] = serde_json::json!(2);
    assert!(matches!(restore(&serde_json::to_vec(&v).unwrap(), PASSPHRASE), Err(Error::Format(_))));
    let mut v = base;
    v["extra"] = serde_json::json!(1);
    assert!(matches!(restore(&serde_json::to_vec(&v).unwrap(), PASSPHRASE), Err(Error::Format(_))));
}

/// AC-X5 (AC-L3): export needs the master password and a strong, different passphrase.
#[test]
fn export_requires_reauthentication_and_a_separate_strong_passphrase() {
    let v = populated_vault();
    assert!(matches!(v.export_backup(&pw("not-the-master-password-9"), &pw(PASSPHRASE), 0), Err(Error::InvalidCredentials)));
    assert!(matches!(v.export_backup(&pw(PW), &pw(PW), 0), Err(Error::Policy(_))));
    let weak = v.export_backup(&pw(PW), &pw("short"), 0);
    assert!(matches!(&weak, Err(Error::Policy(m)) if m.contains("backup passphrase")));
    // Fresh salt per backup.
    let a = v.export_backup(&pw(PW), &pw(PASSPHRASE), 0).unwrap();
    let b = v.export_backup(&pw(PW), &pw(PASSPHRASE), 0).unwrap();
    assert_ne!(a.kdf.salt, b.kdf.salt);
    assert_ne!(a.kdf.salt, v.kdf_params().salt);
    assert!(BackupFile::from_json(&a.to_json().unwrap()).is_ok());
}

/// AC-X6: invalid entries are counted, not fatal; folders are matched case-insensitively.
#[test]
fn csv_import_end_to_end() {
    let mut v = populated_vault();
    let too_long = "x".repeat(MAX_VALUE + 1);
    let csv = format!(
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
         work,,login,Gamma,,,0,https://gamma.example.test,u,synthetic-secret-g,\n\
         Personal,,login,Delta,,,0,,u,synthetic-secret-d,\n\
         ,,login,Huge,,,0,,u,{too_long},\n\
         ,,login,Gamma,,,0,https://gamma.example.test,u,synthetic-secret-g,\n"
    );
    let parsed = import::parse(ImportSource::BitwardenCsv, csv.as_bytes(), None, 500).unwrap();
    let before = v.summaries().len();
    let report = v.import(&parsed.entries, 500).unwrap();
    assert_eq!((report.imported, report.duplicates, report.invalid, report.folders_created), (2, 1, 1, 1));
    assert_eq!(v.summaries().len(), before + 2);
    let names: Vec<_> = v.folders().iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["Work", "Personal"]);

    // The imported items survive a seal / unlock cycle.
    let file = v.seal_to_file().unwrap();
    let reopened = UnlockedVault::unlock_with_password(&file, &pw(PW)).unwrap();
    assert_eq!(reopened.summaries().len(), before + 2);
}
