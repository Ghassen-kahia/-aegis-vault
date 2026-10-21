//! Hostile-input property tests (AC-H1…H3). Every parser must reject garbage with an error,
//! never a panic, and no modification of sealed data may ever decrypt. Synthetic data only.

use aegis_core::backup::BackupFile;
use aegis_core::format::VaultFile;
use aegis_core::import::{self, csv, ImportSource};
use aegis_core::item::{FieldInput, FieldKind, ItemInput, ItemKind};
use aegis_core::kdf::KdfParams;
use aegis_core::recovery::RecoveryKey;
use aegis_core::vault::UnlockedVault;
use aegis_core::SecretString;
use proptest::prelude::*;
use std::sync::OnceLock;

const PW: &str = "quarry-velvet-ozone-lantern-71";
const PASSPHRASE: &str = "orchid-copper-glacier-sonnet-42";

const TEXT_SOURCES: [ImportSource; 4] = [
    ImportSource::BitwardenJson,
    ImportSource::BitwardenCsv,
    ImportSource::BrowserCsv,
    ImportSource::OnePasswordCsv,
];

fn sample_vault() -> UnlockedVault {
    let (mut v, _) = UnlockedVault::create(&PW.into(), KdfParams::insecure_for_tests()).unwrap();
    for i in 0..3 {
        v.create_item(
            &ItemInput {
                kind: ItemKind::Login,
                title: format!("Item {i}"),
                folder_id: None,
                tags: vec![],
                favorite: false,
                fields: vec![FieldInput {
                    id: None,
                    label: "Password".into(),
                    kind: FieldKind::Password,
                    value: format!("synthetic-secret-{i}"),
                }],
                notes: String::new(),
            },
            0,
        )
        .unwrap();
    }
    v
}

/// One sealed vault and one backup, built once and shared by every case.
fn fixtures() -> &'static (VaultFile, BackupFile) {
    static F: OnceLock<(VaultFile, BackupFile)> = OnceLock::new();
    F.get_or_init(|| {
        let mut v = sample_vault();
        let backup = v.export_backup(&PW.into(), &PASSPHRASE.into(), 0).unwrap();
        (v.seal_to_file().unwrap(), backup)
    })
}

/// Text that looks enough like CSV/JSON to get past the first checks.
fn structured_text() -> impl Strategy<Value = String> {
    let header = prop::sample::select(vec![
        "name,url,username,password,note\n",
        "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n",
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n",
        "{\"encrypted\":false,\"items\":[",
        "",
    ]);
    (header, "[a-z0-9,\"\n\r :{}\\[\\]é\u{feff}-]{0,300}").prop_map(|(h, body)| format!("{h}{body}"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// AC-H1: arbitrary bytes never panic any parser.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = VaultFile::from_json(&bytes);
        let _ = BackupFile::from_json(&bytes);
        let pass = SecretString::from(PASSPHRASE);
        let _ = import::parse(ImportSource::AegisBackup, &bytes, Some(&pass), 0);
        for source in TEXT_SOURCES {
            let _ = import::parse(source, &bytes, None, 0);
        }
        if let Ok(text) = std::str::from_utf8(&bytes) {
            let _ = RecoveryKey::parse(text);
            let _ = csv::parse(text);
        }
    }

    /// AC-H1: CSV/JSON-shaped text never panics an importer, and whatever it accepts
    /// can be imported into a vault without error.
    #[test]
    fn structured_text_never_panics(text in structured_text()) {
        for source in TEXT_SOURCES {
            if let Ok(parsed) = import::parse(source, text.as_bytes(), None, 0) {
                let mut v = UnlockedVault::create(&PW.into(), KdfParams::insecure_for_tests()).unwrap().0;
                prop_assert!(v.import(&parsed.entries, 0).is_ok());
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    /// AC-H2: flipping any bit of any sealed vault blob makes unlocking fail.
    #[test]
    fn vault_bit_flips_never_decrypt(target in 0usize..5, byte in any::<prop::sample::Index>(), bit in 0u8..8) {
        let mut file = fixtures().0.clone();
        let buf = match target {
            0 => &mut file.slots.password.ciphertext,
            1 => &mut file.meta.ciphertext,
            2 => &mut file.meta.nonce,
            3 => &mut file.items[0].ciphertext,
            _ => &mut file.items[2].nonce,
        };
        let i = byte.index(buf.len());
        buf[i] ^= 1 << bit;
        prop_assert!(UnlockedVault::unlock_with_password(&file, &PW.into()).is_err());
    }

    /// AC-H2: flipping any bit of a backup's payload or salt makes restoring fail.
    #[test]
    fn backup_bit_flips_never_decrypt(target in 0usize..3, byte in any::<prop::sample::Index>(), bit in 0u8..8) {
        let mut b = fixtures().1.clone();
        let buf = match target {
            0 => &mut b.payload.ciphertext,
            1 => &mut b.payload.nonce,
            _ => &mut b.kdf.salt,
        };
        let i = byte.index(buf.len());
        buf[i] ^= 1 << bit;
        prop_assert!(b.open(&PASSPHRASE.into()).is_err());
    }

    /// AC-H3: no wrong password unlocks the vault or opens the backup.
    #[test]
    fn wrong_secrets_never_unlock(guess in "[ -~]{0,40}") {
        prop_assume!(guess != PW && guess != PASSPHRASE);
        let (file, backup) = fixtures();
        prop_assert!(UnlockedVault::unlock_with_password(file, &guess.as_str().into()).is_err());
        prop_assert!(backup.open(&guess.as_str().into()).is_err());
    }
}
