//! Hostile vault files: parse, and if the KDF is cheap, try to unlock.
#![no_main]

use aegis_core::format::VaultFile;
use aegis_core::vault::UnlockedVault;
use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    if let Ok(file) = VaultFile::from_json(data) {
        if common::cheap(&file.kdf) {
            let _ = UnlockedVault::unlock_with_password(&file, &common::PASSWORD.into());
        }
    }
});
