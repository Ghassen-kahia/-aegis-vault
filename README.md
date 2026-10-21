# AEGIS VAULT

A local-first password manager. Phase 1: a single encrypted vault file on this device, no network.

> **Not independently reviewed.** Do not store real credentials until it has been audited.
> See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what it does and does not protect against.

## Layout

| Path | What |
|------|------|
| `crates/aegis-core` | All cryptography, the vault format, generator, strength checks. No UI, no I/O beyond the vault file. |
| `src-tauri` | Desktop shell (Tauri 2). Holds the unlocked vault, enforces auto-lock, back-off and clipboard clearing, exposes a narrow command set to the UI. |
| `ui` | React + TypeScript UI. Never receives key material; secret values only on explicit reveal or edit. |
| `docs` | Cryptographic design, threat model, security requirements, audit scope. |
| `fuzz` | `cargo-fuzz` targets for every parser of untrusted input. |

## Develop

Prerequisites: Rust ≥ 1.80, Node ≥ 20, and on Windows the WebView2 runtime (preinstalled on Windows 11).

```sh
npm install
npm run tauri dev          # UI with hot reload + debug Rust build
cargo test --workspace     # core + shell tests (fast test KDF via the insecure-test-kdf feature)
npm run typecheck
```

Fuzzing (nightly toolchain) is described in [fuzz/README.md](fuzz/README.md). Auditors: start with
[docs/AUDIT_SCOPE.md](docs/AUDIT_SCOPE.md).

Build an installer:

```sh
npm run tauri build        # → target/release/bundle/{nsis,msi}
```

The vault is stored at `%APPDATA%\app.aegisvault.desktop\vault.aegis` (Windows),
`~/Library/Application Support/app.aegisvault.desktop/` (macOS) or
`~/.local/share/app.aegisvault.desktop/` (Linux), with the previous version kept as `vault.aegis.bak`.

## Security-relevant places to review

* `crates/aegis-core/src/crypto.rs`: AEAD, HKDF, AAD construction, padding
* `crates/aegis-core/src/vault.rs`: key slots, manifest integrity, credential operations
* `src-tauri/src/commands.rs`: everything the WebView can ask for
* `crates/aegis-core/src/backup.rs` + `import/`: encrypted backup format and the importers
* `src-tauri/build.rs` + `src-tauri/capabilities/default.json`: the IPC allow-list
* `src-tauri/tauri.conf.json`: CSP, content protection
* `src-tauri/src/os_lock.rs`: lock on suspend / session lock; the only `unsafe` code in the project
* `deny.toml`: dependency policy and accepted advisories

## Known gaps (tracked for later phases)

* Unlock back-off is in memory and resets when the app restarts. That is acceptable because an attacker with the file
  attacks it offline anyway (threat 13), but it is not a hard limit.
* Session-lock detection (L-9) is Windows-only; macOS/Linux lock on sleep and inactivity only.
* CI (`.github/workflows/ci.yml`: tests, `cargo deny`, `npm audit`, CodeQL, secret-logging check) only runs once the
  project is pushed to GitHub; the folder is not a git repository yet.
