# AEGIS VAULT — Security Audit Scope

This document is for the people auditing AEGIS VAULT. It says what to review, what we most want to
know, and how to build and test the code. Pin the review to a tagged commit (see §7).

## 1. What the product is

A local-first desktop password manager (Windows first; macOS/Linux build but are less tested).
One encrypted vault file per device, no network access, no accounts. A Rust core does all
cryptography; a Tauri 2 shell exposes a narrow command set to a React UI running in the OS WebView
(WebView2 on Windows).

Background reading, in order (≈30 min):

1. [THREAT_MODEL.md](THREAT_MODEL.md): assets, attackers T1–T9, threats, and known limitations L-1…L-11
2. [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md): key hierarchy, AAD, file formats (§7 vault, §13 backup)
3. [SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md): acceptance criteria and how each is tested

## 2. In scope

Sizes are non-blank, non-comment lines.

| Priority | Component | Path | Size |
|----------|-----------|------|------|
| **1** | Cryptographic core: key derivation, key slots, AEAD wrappers, AAD, padding, manifest integrity, Recovery Key, backup format | `crates/aegis-core/src/{crypto,kdf,vault,format,recovery,backup,secret}.rs` | ≈1,500 |
| **1** | IPC boundary: every command the WebView can call, session state, auto-lock, back-off, re-authentication | `src-tauri/src/{commands,state,main}.rs`, `src-tauri/build.rs`, `src-tauri/capabilities/default.json` | ≈650 |
| **2** | Parsers of untrusted files: vault/backup JSON, CSV reader, Bitwarden/browser/1Password importers | `crates/aegis-core/src/{format,backup}.rs`, `crates/aegis-core/src/import/` | ≈700 |
| **2** | Platform hardening: lock on suspend/session lock, WebView2 settings, clipboard clearing, the two `unsafe` blocks | `src-tauri/src/{os_lock,webview,clipboard}.rs` | ≈150 |
| **2** | WebView configuration: CSP, content protection, capability set | `src-tauri/tauri.conf.json` | — |
| **3** | Password generator and strength policy | `crates/aegis-core/src/{generator/mod,strength}.rs` | ≈250 |
| **3** | UI: secret handling in React state, what it requests and when | `ui/src/` | ≈1,600 |

Core total ≈2,900 lines (≈700 of them unit tests), shell ≈800, UI ≈1,600, integration tests ≈600.

## 3. Out of scope

* Third-party code: Tauri, WebView2, RustCrypto crates, React (we rely on them; misuse by us is in scope).
* The planned sync server and 2FA (Phase 2), which don't exist yet.
* Attacks listed as non-goals in THREAT_MODEL §5 (malware or an administrator on the unlocked device).
* Known limitations L-1…L-11, unless they are worse than described.

## 4. Questions we most want answered

1. **Key hierarchy.** Is the derivation and wrapping of the Vault Key under the password KEK and the
   Recovery Key KEK sound? Is key separation (HKDF labels, AAD contexts) complete?
2. **Integrity.** Can an attacker who controls the vault file (T2) delete, reorder, replay, swap or
   inject items, downgrade KDF parameters, or alter settings, without detection (beyond the
   documented whole-file rollback, L-7)?
3. **Backup format.** Is `aegis-backup` v1 (CRYPTOGRAPHY §13) sound as a standalone format? Is
   every header field authenticated?
4. **IPC boundary.** Can the WebView, assuming fully compromised JavaScript, obtain key material,
   secret values it didn't explicitly ask for, or file contents; skip re-authentication; or defeat
   auto-lock or back-off? Are the capability and command allow-lists tight?
5. **Secret lifetime.** Where do secrets persist in memory, on disk or in the clipboard beyond what
   the threat model admits?
6. **Parsers.** Can a crafted vault, backup or import file cause a panic, excessive memory or CPU
   use, or a logic error that corrupts the vault?
7. **`unsafe` code.** Two small blocks: `os_lock::session_locked` and `webview::apply`.

## 5. Building and testing

Prerequisites: Rust ≥ 1.80 (stable), Node ≥ 20, WebView2 runtime (preinstalled on Windows 11).

```sh
npm ci
cargo test --workspace          # unit, integration and property tests (fast test KDF)
npm run typecheck
cargo deny check                # dependency policy, deny.toml
npm run tauri build             # release app and installers
```

Fuzzing (nightly): see [fuzz/README.md](../fuzz/README.md). Four targets cover the vault file,
backup file, importers and Recovery Key.

The test suite uses the `insecure-test-kdf` feature (Argon2 floor lowered to 8 KiB/1 pass) so it runs
quickly. Production builds can't enable it: it is a dev-dependency feature only, and the floor in
`kdf.rs` is selected with `cfg(not(any(test, feature = "insecure-test-kdf")))`. Please verify this.

## 6. Current verification

* Known-answer tests: AES-256-GCM (McGrew–Viega TC 13/14), HKDF-SHA-256 (RFC 5869), Argon2id
  (RFC 9106), plus fixed format regression vectors.
* Tamper tests: bit flips in every sealed vault and backup component; header-field tampering.
* Property tests: ≈5,000 hostile inputs per run across all parsers; random wrong passwords.
* CI: tests on Windows and Linux, `cargo deny`, `npm audit`, CodeQL (Rust, TypeScript), a
  secret-logging grep, and fuzzing on every push.
* Not yet done: any external review.

## 7. Engagement details

* **Commit under review:** to be set when the engagement is booked (tag `audit-YYYY-MM`).
* **Contact:** the maintainer, through the repository's private vulnerability reporting (SECURITY.md).
* **Report:** we intend to publish the final report and our fixes once findings are resolved.
