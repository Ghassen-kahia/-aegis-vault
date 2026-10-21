//! Files written by earlier builds must keep opening (AC-C8). The fixtures were produced by the
//! first release (aes-gcm 0.10 / argon2 0.5 / hkdf 0.12 / sha2 0.10 / rand 0.8) and must never be
//! regenerated: they exist to catch any change in how bytes are derived or decrypted.

use aegis_core::backup::BackupFile;
use aegis_core::format::VaultFile;
use aegis_core::vault::UnlockedVault;

const PW: &str = "quarry-velvet-ozone-lantern-71";
const PASSPHRASE: &str = "orchid-copper-glacier-sonnet-42";

#[test]
fn vault_written_by_v0_1_0_still_opens() {
    let file = VaultFile::from_json(include_bytes!("fixtures/vault-v1.json")).unwrap();
    let v = UnlockedVault::unlock_with_password(&file, &PW.into()).unwrap();
    let titles: Vec<_> = v.summaries().into_iter().map(|s| s.title).collect();
    assert_eq!(titles, ["Item 0", "Item 1", "Item 2"]);
    let item = v.item(&v.summaries()[1].id).unwrap();
    assert_eq!(item.fields[0].value, "synthetic-secret-1");
}

#[test]
fn backup_written_by_v0_1_0_still_opens() {
    let backup = BackupFile::from_json(include_bytes!("fixtures/backup-v1.json")).unwrap();
    let entries = backup.open(&PASSPHRASE.into()).unwrap();
    let mut secrets: Vec<_> = entries.iter().map(|e| e.input.fields[0].value.clone()).collect();
    secrets.sort();
    assert_eq!(secrets, ["synthetic-secret-0", "synthetic-secret-1", "synthetic-secret-2"]);
}
