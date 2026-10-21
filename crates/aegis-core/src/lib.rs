//! AEGIS VAULT cryptographic core.
//!
//! Everything that touches keys or plaintext vault data lives in this crate.
//! See `docs/CRYPTOGRAPHY.md` for the key hierarchy and file format.
//!
//! Rules enforced here:
//! * only audited RustCrypto primitives are used — no custom cryptography;
//! * every key and decrypted buffer is held in a zeroize-on-drop type;
//! * secret-bearing types have redacted `Debug` implementations;
//! * error values never carry secret data.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod backup;
pub mod crypto;
pub mod encoding;
pub mod error;
pub mod format;
pub mod generator;
pub mod import;
pub mod item;
pub mod kdf;
pub mod recovery;
pub mod rng;
pub mod secret;
pub mod storage;
pub mod strength;
pub mod vault;

pub use error::{Error, Result};
pub use secret::{SecretKey, SecretString};
