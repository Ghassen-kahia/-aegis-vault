# AEGIS VAULT — Library Selection & Security Acceptance Criteria

## 1. Library selection

| Concern | Choice | Why |
|---------|--------|-----|
| AEAD | `aes-gcm` 0.10 (RustCrypto) | Pure Rust, constant-time with AES-NI/CLMUL, NCC Group audit (2020), very widely deployed |
| Password KDF | `argon2` 0.5 (RustCrypto) | RFC 9106 Argon2id, maintained by RustCrypto |
| KDF (key separation) | `hkdf` 0.12 + `sha2` 0.10 | RFC 5869 reference-quality implementation |
| Randomness | `rand_core::OsRng` → `getrandom` | Direct OS CSPRNG (`BCryptGenRandom` / `getrandom(2)` / `SecRandomCopyBytes`) |
| Memory hygiene | `zeroize`, `subtle` | Wipe secrets on drop; constant-time comparison |
| Encoding | `data-encoding` | Strict base64/base32, no custom codecs |
| Strength estimation | `zxcvbn` | Port of Dropbox's zxcvbn, pattern-aware |
| Clipboard | `arboard` | Supports Windows history/cloud exclusion |
| File dialogs | `tauri-plugin-dialog` (called from Rust only) | Native OS dialogs; the WebView is granted no dialog permission and never handles file paths or import contents |
| Desktop shell | Tauri 2 | Small attack surface, Rust core, capability-based IPC, CSP |
| UI | React + TypeScript (no UI component libraries, icons inlined) | Minimal npm dependency surface |
| Phase 2 (planned) | `webauthn-rs`, `totp-rs`, `axum`, `sqlx` + PostgreSQL, `tower-governor` | Established, maintained |

## 2. Acceptance criteria — Phase 1

Each criterion has an automated test (T) or a manual / documented check (M).

### Cryptography
- [x] **AC-C1 (T)** AES-256-GCM, HKDF-SHA-256 and Argon2id outputs match published test vectors.
- [x] **AC-C2 (T)** Every encryption uses a fresh random nonce; 10,000 encryptions of identical plaintext produce no repeated nonce or ciphertext.
- [x] **AC-C3 (T)** A wrong master password or Recovery Key fails with a generic error and yields no data.
- [x] **AC-C4 (T)** Flipping any byte of any nonce, ciphertext, salt or KDF parameter causes unlock to fail.
- [x] **AC-C5 (T)** Swapping item ciphertexts between IDs, deleting an item record, injecting a record from another vault, or duplicating a record causes unlock to fail.
- [x] **AC-C6 (T)** KDF parameters below the floor or above the ceiling are refused before derivation.
- [x] **AC-C7 (T)** Unknown format versions and unknown JSON fields are refused.
- [x] **AC-C8 (T)** Format regression vectors stay stable across builds.
- [x] **AC-C9 (T)** After a password change the old password no longer unlocks and the Recovery Key still does; after Vault Key rotation the old Recovery Key no longer unlocks.

### Secret handling
- [x] **AC-S1 (T)** `Debug` output of secret-bearing types never contains the secret.
- [x] **AC-S2 (M)** No `println!`/`log`/`console.log` of secret values (grep check in CI).
- [x] **AC-S3 (M)** VK, MK, KEKs and decrypted items are held in zeroize-on-drop types.
- [x] **AC-S4 (M)** The WebView never receives key material. Item lists contain no secret field values.
- [x] **AC-S5 (M)** The master password is never written to disk.

### Locking
- [x] **AC-L1 (T)** The auto-lock timeout is enforced in Rust and bounded to [1, 480] minutes.
- [x] **AC-L2 (M)** Manual lock, lock on window close, and lock on inactivity zeroize the vault and notify the UI.
- [x] **AC-L3 (T)** Sensitive operations (change password, rotate key, new Recovery Key, reveal-all export) require the current master password.
- [x] **AC-L4 (T)** Failed unlocks trigger exponential back-off enforced in Rust.

### Storage
- [x] **AC-F1 (T)** Saves are atomic (temp + fsync + rename) and the previous version is kept as `.bak`.
- [x] **AC-F2 (T)** A truncated or corrupted file is detected and never overwrites the `.bak`.

### Generator
- [x] **AC-G1 (T)** Output respects length, character classes and ambiguous-character exclusion.
- [x] **AC-G2 (T)** Character distribution passes a coarse chi-square uniformity check.
- [x] **AC-G3 (T)** The wordlist is the pinned EFF large list (SHA-256 checked, 7,776 unique words).

### Platform / UI
- [x] **AC-U1 (M)** CSP forbids remote scripts, `eval`, inline scripts and remote connections.
- [x] **AC-U2 (M)** Tauri capabilities grant only the app's own commands and core event and window handling.
- [x] **AC-U3 (M)** Phase 1 makes no network requests.
- [x] **AC-U4 (M)** The window is content-protected against screen capture where the OS supports it.
- [x] **AC-U5 (M)** WebView2 general autofill, password autosave and browser shortcuts are disabled; the app exits if they cannot be (L-11).
- [x] **AC-U6 (M)** Only one instance runs, so two windows can never overwrite each other's saves.

### Backup & import (Phase 3)
- [x] **AC-X1 (T)** An encrypted backup restores every item, field, folder, favorite, timestamp and history entry.
- [x] **AC-X2 (T)** Importing the same data twice adds nothing; duplicates are counted, not re-added.
- [x] **AC-X3 (T)** A backup contains no plaintext and opens only with its passphrase (not the master password).
- [x] **AC-X4 (T)** Modifying any backup header field or ciphertext byte is detected.
- [x] **AC-X5 (T)** Export requires the current master password and a policy-compliant passphrase that differs from it.
- [x] **AC-X6 (T)** Import is all-or-nothing on the vault; invalid rows are skipped and reported by row number, never by content.
- [x] **AC-X7 (M)** Files are chosen in native dialogs opened from Rust; import file contents never cross to the WebView.

### Hostile input
- [x] **AC-H1 (T)** Property tests feed thousands of random and CSV/JSON-shaped inputs to every parser (vault, backup, Recovery Key, all importers); none may panic.
- [x] **AC-H2 (T)** A bit flip anywhere in a sealed vault's key slot, manifest or items, or in a backup's payload, nonce or salt, never decrypts.
- [x] **AC-H3 (T)** Random wrong passwords never unlock a vault or open a backup.

## 3. Rules for contributors

1. Never add a cryptographic primitive implementation. Use the libraries above.
2. Never log, `Debug`-print or `format!` a secret. Secret types implement redacted `Debug`.
3. Never weaken a security control to make development easier. The fast test KDF parameters exist
   only behind the `insecure-test-kdf` feature, which the desktop app never enables.
4. Use synthetic credentials only. Don't put real passwords in a development vault.
