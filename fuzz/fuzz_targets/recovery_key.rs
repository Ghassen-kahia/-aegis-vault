//! Hostile Recovery Key input: parsing must never panic, and a parsed key must round-trip.
#![no_main]

use aegis_core::recovery::RecoveryKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(rk) = RecoveryKey::parse(text) {
            let encoded = rk.encode();
            let again = RecoveryKey::parse(encoded.expose()).expect("encoded key must parse");
            assert_eq!(again.encode().expose(), encoded.expose());
        }
    }
});
