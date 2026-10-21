//! Hostile import files. The first byte picks the importer; whatever parses is then
//! imported into a real vault, which must never fail on parser output.
#![no_main]

use std::sync::{Mutex, OnceLock};

use aegis_core::import::{self, ImportSource};
use aegis_core::kdf::KdfParams;
use aegis_core::vault::UnlockedVault;
use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

const SOURCES: [ImportSource; 4] = [
    ImportSource::BitwardenJson,
    ImportSource::BitwardenCsv,
    ImportSource::BrowserCsv,
    ImportSource::OnePasswordCsv,
];

fn vault() -> &'static Mutex<UnlockedVault> {
    static V: OnceLock<Mutex<UnlockedVault>> = OnceLock::new();
    V.get_or_init(|| {
        let (v, _) = UnlockedVault::create(&common::PASSWORD.into(), KdfParams::insecure_for_tests()).unwrap();
        Mutex::new(v)
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else { return };
    let source = SOURCES[usize::from(pick) % SOURCES.len()];
    if let Ok(parsed) = import::parse(source, rest, None, 0) {
        // Reuse one vault (creating one costs an Argon2 call) but keep it small: every import
        // fingerprints all existing items, which would otherwise dominate run time.
        let mut v = vault().lock().unwrap();
        if v.summaries().len() > 200 {
            *v = UnlockedVault::create(&common::PASSWORD.into(), KdfParams::insecure_for_tests()).unwrap().0;
        }
        v.import(&parsed.entries, 0).expect("importing parser output must not fail");
    }
});
