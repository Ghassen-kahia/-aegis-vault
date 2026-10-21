//! Hostile backup files: parse, and if the KDF is cheap, try to open.
#![no_main]

use aegis_core::backup::BackupFile;
use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    if let Ok(file) = BackupFile::from_json(data) {
        if common::cheap(&file.kdf) {
            let _ = file.open(&common::PASSWORD.into());
        }
    }
});
