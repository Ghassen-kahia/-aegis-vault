# AEGIS VAULT — Threat Model

Status: **Phase 1 (local vault).** This document is written *before* implementation and
updated as phases land. It has **not** been independently reviewed. AEGIS VAULT must not be
described as audited or production-secure until it has been.

## 1. Assets

| ID | Asset | Sensitivity |
|----|-------|-------------|
| A1 | Vault item contents (passwords, notes, recovery codes, API keys, custom fields) | Critical |
| A2 | Vault Key (VK) — symmetric key that encrypts A1 | Critical |
| A3 | Master password | Critical |
| A4 | Recovery Key (RK) — 256-bit user-held key that can unwrap VK | Critical |
| A5 | Item metadata (titles, usernames, URLs, tags, folders, item count, timestamps) | High (all encrypted at rest) |
| A6 | Vault integrity (no undetected modification, deletion, injection, or swapping of items) | High |
| A7 | Availability of the vault (the user can still decrypt their data) | High |

## 2. Actors and adversaries

| ID | Adversary | Capability | In scope? |
|----|-----------|-----------|-----------|
| T1 | **Offline attacker with a copy of the vault file** (stolen laptop backup, cloud-sync folder leak, malicious backup provider) | Read/modify file at rest, unlimited offline compute | **Yes, primary** |
| T2 | **Attacker who modifies the vault file on disk** (sync conflict, malware without code exec in our process, tampered backup) | Flip bits, delete/reorder/inject/swap records, downgrade KDF params | **Yes** |
| T3 | **Passer-by / shoulder surfer** with brief physical access to an unlocked or recently used machine | Look at the screen, use the open app, read the clipboard | **Yes (mitigated, not eliminated)** |
| T4 | **Other unprivileged local apps** | Read the clipboard, take screenshots, read clipboard history | **Partially** (best-effort mitigations) |
| T5 | **Malicious web content** | Phase 1 loads no remote content; strict CSP prevents loading any | **Yes** |
| T6 | **Compromised dependency / supply chain** | Malicious code in a crate or npm package | **Partially** (lockfiles, minimal deps, scanning) |
| T7 | **Malware running as the same user / admin / kernel** | Keylogging, memory reading, process injection | **No — out of scope.** No password manager can protect secrets on a compromised endpoint. |
| T8 | **Future sync server operator** (Phase 3) | Sees everything the server stores and every request | **Designed for now**, implemented in Phase 3: the server only ever receives ciphertext. |
| T9 | **Network attacker** (Phase 2+) | MITM, replay | Phase 2+: TLS everywhere, server-side 2FA enforcement |

## 3. Trust boundaries

```
 ┌──────────────────────── User's device (trusted while not compromised) ─────────────────────────┐
 │                                                                                                 │
 │  ┌──────────── WebView (React UI) ───────────┐   IPC (Tauri invoke)   ┌──── Rust core ───────┐  │
 │  │ Less trusted. Never holds VK/KEK/RK.      │ ─────── B1 ──────────▶ │ Holds VK in zeroizing │  │
 │  │ Receives item summaries; secrets only on  │ ◀────────────────────  │ memory. All crypto,   │  │
 │  │ explicit reveal/edit. Strict CSP, no       │                        │ KDF, file I/O,        │  │
 │  │ remote content.                            │                        │ clipboard, auto-lock. │  │
 │  └────────────────────────────────────────────┘                        └──────────┬───────────┘  │
 │                                                                                   │ B2           │
 │                                                                     ┌─────────────▼───────────┐  │
 │                                                                     │ Disk: vault.aegis       │  │
 │                                                                     │ (ciphertext only)       │  │
 │                                                                     └─────────────────────────┘  │
 │                  B3: OS clipboard (shared with other apps — untrusted)                          │
 └─────────────────────────────────────────────────────────────────────────────────────────────────┘
             B4 (Phase 3): network to optional sync server — ciphertext only, TLS
```

* **B1 — WebView ↔ Rust.** The UI is treated as less trusted than the core: keys never cross
  B1. Plaintext secrets cross B1 only when the user explicitly reveals or edits an item.
  "Copy" is performed by Rust directly into the clipboard so copying a secret does not
  require sending it to JavaScript.
* **B2 — Rust ↔ disk.** Everything that crosses B2 is authenticated ciphertext except the
  public header (format version, vault UUID, KDF parameters, salt). Data read back across B2
  is untrusted until AEAD verification succeeds.
* **B3 — Clipboard.** Anything placed on the clipboard is readable by every app the user
  runs. Mitigated by timed clearing and by excluding entries from Windows clipboard
  history / cloud clipboard.
* **B4 — Network (Phase 3).** Not present in Phase 1. Phase 1 makes **no network requests**.

## 4. Threats and mitigations (STRIDE-oriented)

| # | Threat | Mitigation | Residual risk |
|---|--------|-----------|---------------|
| 1 | T1 brute-forces the master password offline | Argon2id, memory-hard, calibrated (default 256 MiB, t ≥ 3, ≥ ~0.5–1 s); hard floor of 64 MiB / t=3 refused below; master-password policy (≥ 12 chars and zxcvbn score ≥ 3) | A weak-but-accepted password is still guessable with enough resources. |
| 2 | T1 reads item metadata | All metadata (titles, URLs, usernames, folders, tags, settings) is inside AEAD ciphertext; plaintext is padded to 256-byte buckets | File size and approximate item count/size remain visible. |
| 3 | T2 flips bits in ciphertext | AES-256-GCM authentication; any failure aborts unlock with an error and never yields partial plaintext | — |
| 4 | T2 swaps two items' ciphertexts, or moves an item from another vault | AAD binds every ciphertext to `vault_id` and `item_id` | — |
| 5 | T2 deletes, injects or replays an individual item record | Encrypted **manifest** holds the set of item IDs and SHA-256 of every item record; any mismatch aborts unlock | — |
| 6 | T2 rolls the **entire** file back to an older valid version | **Not prevented in Phase 1** (no trusted monotonic counter). Manifest carries a revision number to enable rollback detection once a trusted store (OS keychain / sync server) exists | Documented limitation (L-7). |
| 7 | T2 downgrades KDF parameters in the header | Parameters are bound into the password key-slot AAD (tamper ⇒ unwrap fails) and a floor is enforced before derivation; ceilings prevent a DoS file | — |
| 8 | T2 replaces the whole file with an attacker-created vault | The attacker can't learn the master password from this, but the user could store new secrets in a vault whose key the attacker knows. Unlock only succeeds if the attacker knows the user's password, so for this attack they already have it | Documented (L-8). |
| 9 | Nonce reuse under VK | 96-bit nonces from the OS CSPRNG, fresh for every encryption; only changed records are re-encrypted. Expected encryptions per key are many orders of magnitude below the 2^32 random-nonce bound | — |
| 10 | T3 uses an unlocked, unattended app | Inactivity auto-lock enforced **in Rust** (default 5 min, max 8 h, no "never"); manual lock (Ctrl+L); lock on window close; secrets masked by default; re-authentication for sensitive operations | Window between last activity and auto-lock. |
| 11 | T3/T4 reads copied secrets | Clipboard cleared after a timeout (default 30 s) only if it still holds our value; cleared on lock/exit; on Windows the entry is excluded from clipboard history and cloud sync | Another app may read the clipboard during the window. |
| 12 | T4 screenshots / screen recording | Window marked content-protected (Windows `WDA_EXCLUDEFROMCAPTURE`, macOS sharing type none) | OS dependent; not a guarantee. |
| 13 | Online guessing in the UI | Exponential back-off after failed unlocks, enforced in Rust | Irrelevant to T1 (who has the file). |
| 14 | Secrets in logs / crash dumps | No logging of secrets: secret types have redacted `Debug`; errors carry no secret data; no telemetry | Crash dumps of process memory may contain secrets (L-2). |
| 15 | Secrets lingering in memory after lock | Keys and decrypted items wrapped in `zeroize` types and wiped on drop/lock | Best effort only: see L-1, L-3. |
| 16 | Malicious script injection in the WebView | No remote content, strict CSP (`script-src 'self'`, no `unsafe-eval`, `object-src 'none'`), React escaping, no `dangerouslySetInnerHTML`, minimal Tauri capability set | A compromised dependency in the UI bundle could read secrets that are revealed. |
| 17 | Supply-chain compromise | Lockfiles committed, minimal dependency set, `cargo deny` (advisories, licenses, sources), `npm audit`, Dependabot, secret scanning, CodeQL in CI | Cannot be eliminated. |
| 18 | Weak randomness | All keys, salts, nonces and generated passwords come from the OS CSPRNG (`getrandom`), never from a seeded userspace PRNG | — |
| 19 | Data loss (forgotten password, corruption) | Recovery Key (second key slot); atomic writes (temp file + fsync + rename) and a `.bak` of the last good vault; encrypted backup export protected by its own passphrase (CRYPTOGRAPHY §13) | Forgetting **both** the master password and the Recovery Key makes the vault **unrecoverable, by design** (no back door). |

## 5. Explicit non-goals

* Protection against malware, a debugger, or an administrator on the unlocked device (T7).
* Protection against a user who chooses to disclose their master password.
* Hiding the existence of a vault, its approximate size, or when it was last modified.
* Master-password reset that bypasses encryption. **No such mechanism exists.**

## 6. Security assumptions

1. The OS CSPRNG is sound.
2. RustCrypto `aes-gcm`, `argon2`, `hkdf`, `sha2` are correct implementations (they are widely
   used, and `aes-gcm` was independently audited by NCC Group in 2020; known-answer tests in our suite
   check how we wire them up).
3. The device is not compromised while the vault is unlocked.
4. The application binary the user runs is the genuine one (code signing is a Phase 5 item).

## 7. Known limitations (Phase 1)

* **L-1 Memory.** Rust wipes keys and decrypted item buffers on drop, but cannot wipe copies the
  OS made (swap/pagefile, hibernation file) or copies inside the WebView's JavaScript heap
  (JS strings are immutable and garbage-collected). Secrets revealed in the UI may persist in
  WebView memory until GC.
* **L-2 Crash dumps.** Windows Error Reporting may capture process memory.
* **L-3 Allocator copies.** `Vec`/`String` reallocation during deserialization can leave
  un-zeroized fragments in freed heap memory.
* **L-4 Clipboard.** See threat 11. Clipboard managers that ignore the Windows exclusion
  formats will still capture secrets. Linux/Wayland clipboard behaviour varies.
* **L-5 Screen capture protection** is OS-dependent and not available on all Linux setups.
* **L-6 Secure deletion.** Deleted items are removed from the vault file and the file is
  rewritten, but SSD wear-levelling, file-system journaling, OneDrive/Dropbox version history and
  backups can keep old ciphertext. Old ciphertext is still protected by the master password/VK; rotate the
  Vault Key after a suspected compromise.
* **L-7 Whole-file rollback** is undetectable locally (threat 6).
* **L-8 Whole-file substitution** (threat 8).
* **L-9 Lock on OS sleep / session lock** — *resolved.* The vault locks when the machine resumes from
  suspend or hibernate (detected as a >30 s gap between 1 s sweeps, on both the monotonic and wall clock,
  so a forward clock jump also locks), and on Windows when the session is locked (input desktop becomes
  unavailable, polled every second; a UAC secure-desktop prompt also locks). Remaining gap: session-lock
  detection is Windows-only, so on macOS/Linux only the suspend and inactivity locks apply. Because the
  check is a 1 s poll, the vault can stay unlocked for up to ~1 s after resume.
* **L-10 Plaintext import files.** Exports from other password managers and browsers are plaintext
  files that the user creates before importing. AEGIS VAULT reads them without copying them anywhere
  and reminds the user to delete them, but cannot securely erase them (see L-6).
* **L-11 Browser-engine autofill** — *resolved.* WebView2 remembers text typed into form fields by
  default, in its profile folder outside the vault. The app turns off general autofill, password
  autosave and browser shortcuts (print, reload, find, developer tools) when the window is created,
  and exits if it cannot. Every input also sets `autocomplete="off"`.