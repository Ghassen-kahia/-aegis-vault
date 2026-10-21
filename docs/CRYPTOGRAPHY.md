# AEGIS VAULT — Cryptographic Design

Status: Phase 1. Format version **1**. Not independently reviewed.

## 1. Principles

* **No custom primitives.** Only RustCrypto implementations are used: `aes-gcm` (AES-256-GCM),
  `argon2` (Argon2id, RFC 9106), `hkdf` + `sha2` (HKDF-SHA-256, RFC 5869), and `getrandom` via
  `rand_core::OsRng` (OS CSPRNG). The only "design" here is how standard primitives are combined.
* **All cryptography runs in the Rust core** of the desktop app. The WebView never sees any key.
* **Key separation.** Each derived key has exactly one purpose and a distinct HKDF `info` label.
* **Domain separation.** Every AEAD call has a distinct, versioned AAD label plus identifiers that
  bind the ciphertext to where it belongs.
* **Key wrapping.** Data is encrypted with a random Vault Key; passwords only ever protect
  (wrap) that key. Changing the password never requires re-encrypting data, and Vault Key
  rotation is a separate, explicit operation.

## 2. Key hierarchy

```
 master password ──┐
 salt (16 B, CSPRNG)┼─► Argon2id(m, t, p, v=0x13) ─► MK  Master Key (32 B, never stored)
 KDF params ───────┘                                   │
                                                       │ HKDF-SHA256-Expand(PRK = MK, info = …)
                    ┌──────────────────────────────────┼─────────────────────────────────────┐
                    ▼                                  ▼                                     ▼
   KEK_pw  "aegis-vault/v1/kek/password"   AUTH  "aegis-vault/v1/auth" (Phase 2 only)   (reserved)
       │                                       sent (after another one-way step) to the
       │ AES-256-GCM wrap                      sync server for login; can't derive KEK_pw
       ▼
  ┌─────────────────────┐            ┌──────────────────────────────────────────────────────┐
  │ VK  Vault Key 32 B  │◄── wrap ───│ KEK_rk = HKDF-SHA256(salt = vault_id,                │
  │ (CSPRNG, random)    │            │   IKM = RK, info = "aegis-vault/v1/kek/recovery")    │
  └─────────┬───────────┘            │ RK = Recovery Key, 256-bit CSPRNG, shown once        │
            │                        └──────────────────────────────────────────────────────┘
            │ AES-256-GCM, fresh 96-bit random nonce per encryption
     ┌──────┴────────────────┐
     ▼                       ▼
  Manifest (meta)        Item records (one per item)
```

| Key | Size | Origin | Stored? | Lifetime |
|-----|------|--------|---------|----------|
| Master password | — | User memory | **Never** | Wiped right after the KDF runs |
| MK | 256 bit | Argon2id | Never | Only during unlock or password change |
| KEK_pw | 256 bit | HKDF(MK) | Never | Only during unlock or password change |
| AUTH | 256 bit | HKDF(MK) | Phase 2 | Not used in Phase 1 |
| RK | 256 bit | CSPRNG | Never by the app — the user writes it down | Shown once |
| KEK_rk | 256 bit | HKDF(RK) | Never | Only during recovery unlock |
| VK | 256 bit | CSPRNG | Only wrapped | Lives in memory (zeroizing) while unlocked |

**Separating authentication from encryption (Phase 2 design).** The server will authenticate
the user with a value derived from `AUTH`. Because `AUTH` and `KEK_pw` are independent HKDF outputs
of MK, holding `AUTH` (or anything derived from it) doesn't reveal `KEK_pw` or VK. The server
also never sees MK or the password. 2FA gates *access to the ciphertext*; it never replaces the
master password as the decryption secret.

## 3. Parameters

| Item | Value |
|------|-------|
| AEAD | AES-256-GCM, 96-bit nonce, 128-bit tag |
| Nonces | 12 bytes from OsRng, freshly generated for **every** encryption |
| KDF | Argon2id v0x13, output 32 B, salt 16 B |
| Default Argon2id | m = 256 MiB, p = 1, t calibrated on the device so one derivation takes ~0.75 s (t ∈ [3, 12]) |
| Floor (refused below) | m ≥ 64 MiB, t ≥ 3, p ≥ 1 (≥ RFC 9106 "second recommended" option) |
| Ceiling (DoS guard) | m ≤ 4 GiB, t ≤ 64, p ≤ 16 |
| HKDF | HKDF-SHA-256; MK is used directly as the PRK (it is already uniformly random) |
| Hash for manifest | SHA-256 |

## 4. Associated data (AAD)

All integers are big-endian. `‖` is concatenation. `vault_id` and `item_id` are 16-byte UUID
bytes. `kdf_bytes = "argon2id" ‖ u32 version ‖ u32 m_kib ‖ u32 t ‖ u32 p ‖ salt`.

| Ciphertext | AAD |
|------------|-----|
| Password key slot (VK wrapped by KEK_pw) | `"aegis-vault/v1/slot/password" ‖ vault_id ‖ kdf_bytes` |
| Recovery key slot (VK wrapped by KEK_rk) | `"aegis-vault/v1/slot/recovery" ‖ vault_id` |
| Manifest | `"aegis-vault/v1/meta" ‖ vault_id` |
| Item record | `"aegis-vault/v1/item" ‖ vault_id ‖ item_id` |

Binding the KDF parameters into the password slot means that if anyone tampers with the plaintext
header, unwrapping fails. The recovery slot deliberately does **not** bind KDF params, so that a
password change (new salt and parameters) doesn't invalidate the user's Recovery Key.

## 5. Plaintext encoding and padding

Item and manifest plaintext = `u32 length ‖ UTF-8 JSON ‖ zero padding` up to the next multiple of
256 bytes. This hides exact secret lengths (e.g. password length) within a bucket. On
decryption the length prefix is checked and the padding must be all zeros.

## 6. Integrity of the vault as a whole

Per-record AEAD alone can't detect that a record was **removed**, **re-added** from an older
copy, or **injected**. The encrypted manifest therefore contains:

* `revision` — incremented on every save,
* `items` — map `item_id → SHA-256(nonce ‖ ciphertext)` of every item record,
* settings (auto-lock, clipboard timeout) and folders, so a file attacker can't weaken
  settings either.

On unlock the set of item records in the file must equal the manifest's set exactly, and every
hash must match. Otherwise unlock fails with `IntegrityError`. Whole-file rollback stays
possible (see THREAT_MODEL L-7). `revision` is there so a trusted store can detect it later.

## 7. File format (`vault.aegis`, JSON)

```jsonc
{
  "format": "aegis-vault",
  "version": 1,
  "vault_id": "1b4e28ba-2fa1-11d2-883f-0016d3cca427",
  "kdf": { "alg": "argon2id", "version": 19, "m_cost_kib": 262144, "t_cost": 3, "p_cost": 1,
           "salt": "<base64>" },
  "slots": {
    "password": { "nonce": "<b64 12B>", "ciphertext": "<b64 32B + 16B tag>" },
    "recovery": { "nonce": "...", "ciphertext": "..." }        // may be null
  },
  "meta":  { "nonce": "...", "ciphertext": "..." },
  "items": [ { "id": "<uuid>", "nonce": "...", "ciphertext": "..." } ]
}
```

Unknown `format`/`version` is rejected. Unknown JSON fields are rejected
(`deny_unknown_fields`), so nothing unauthenticated can be smuggled into the file.

## 8. Operations

| Operation | Procedure | Re-auth required |
|-----------|-----------|------------------|
| Create | VK, RK, salt, vault_id ← CSPRNG; calibrate KDF; wrap VK twice; write manifest | — |
| Unlock (password) | Validate header and KDF bounds → Argon2id → HKDF → AEAD-unwrap VK → decrypt manifest → verify item set and hashes → decrypt items | — |
| Unlock (recovery) | HKDF(RK) → unwrap VK → same checks → **user must set a new master password** | — |
| Save | Re-encrypt only changed items (fresh nonce each), update manifest, `revision += 1`, write atomically | — |
| Change password | Verify current password → new salt and recalibrated params → re-wrap the *same* VK | Yes |
| Rotate Vault Key | Verify password → new VK → re-encrypt every item and the manifest → re-wrap the password slot → **new RK issued, old RK invalidated** | Yes |
| New Recovery Key | Verify password → new RK → re-wrap recovery slot | Yes |
| Lock | Drop the unlocked vault (all key and plaintext buffers zeroized), clear our clipboard entry | — |

Password verification for re-auth unwraps the password slot again and compares the result
with VK in constant time (`subtle`).

## 9. Recovery Key encoding

`RK (32 B) ‖ SHA-256("aegis-vault/v1/rk-check" ‖ RK)[0..2]` → RFC 4648 base32 (no padding),
grouped as `XXXX-XXXX-…`. The 2-byte check value only catches typos. It isn't a security
mechanism, and it reduces nothing, because RK alone has 256 bits of entropy.

## 10. Password generator

* Characters are drawn uniformly with `rand::Rng::gen_range` on `OsRng` (rejection sampling, no
  modulo bias).
* When character classes are required, one character from each class is placed first and then
  the whole password is shuffled (Fisher–Yates via `SliceRandom::shuffle` on `OsRng`).
* Passphrases are drawn uniformly from the EFF large wordlist (7,776 words, 12.925 bits/word).
  The list is embedded and its SHA-256 is pinned in a test.
* Reported entropy is `length × log2(alphabet)` for random passwords (an upper bound when class
  requirements apply) and `words × log2(7776)` for passphrases. zxcvbn gives a second,
  pattern-aware estimate.

## 11. Library versions

`aes-gcm 0.10`, `argon2 0.5`, `hkdf 0.12`, `sha2 0.10`, `rand 0.8`/`rand_core 0.6` (OsRng),
`zeroize 1`, `subtle 2`. These are mature, widely deployed releases that share one
`digest`/`crypto-common` generation. Upgrading to the next RustCrypto generation (`aes-gcm 0.11`,
`argon2 0.6`, `rand 0.10`) is tracked as a Phase 4 item. Known-answer tests (§12) must pass
unchanged after any upgrade.

## 12. Test vectors

* AES-256-GCM: McGrew–Viega GCM spec test cases 13 and 14.
* HKDF-SHA-256: RFC 5869 test case 1.
* Argon2id: RFC 9106 §5.3 test vector.
* Format regression vectors: fixed key/nonce encryption of a fixed item, so that the on-disk
  format can't change silently.
* Backup tamper tests: changing any header field (`backup_id`, `created_at`, any KDF parameter or
  salt) or any ciphertext byte makes the backup fail to open.

## 13. Encrypted backup (`*.aegisbackup`, format `aegis-backup` v1)

A backup is independent of the vault's keys: it is protected only by a **backup passphrase** chosen
at export time, so it can be restored after the vault file, master password and Recovery Key are
all lost. Code: `crates/aegis-core/src/backup.rs`.

```text
salt_b  = 16 random bytes (fresh for every backup)
MK_b    = Argon2id(passphrase, salt_b)        cost parameters copied from the vault
K_b     = HKDF-Expand(MK_b, "aegis-vault/v1/backup")
AAD     = "aegis-vault/v1/backup/payload" ‖ backup_id ‖ i64_be(created_at) ‖ kdf_canonical
payload = AES-256-GCM(K_b, pad(json{ folders, items }), AAD)     random 96-bit nonce
```

```json
{ "format": "aegis-backup", "version": 1, "backup_id": "<uuid v4>", "created_at": 1700000000,
  "kdf": { …same shape as the vault… }, "payload": { "nonce": "<b64>", "ciphertext": "<b64>" } }
```

* Every header field is authenticated: the KDF parameters and salt via `kdf_canonical`, the rest
  directly. A wrong passphrase and a modified file both give the same "invalid credentials" error.
* Items keep their fields, notes, tags, favorite flag, timestamps and password history. Folders are
  carried by name.
* Exporting requires the current master password (AC-L3). The passphrase must meet the master
  password policy and must differ from the master password, so a leaked backup can't be used to
  brute-force the master password.
* Restoring goes through the normal import path: items get new IDs and are re-encrypted under the
  destination vault's key. Items identical to an existing one (same kind, title, field kinds and
  values, and notes, compared by SHA-256 fingerprint) are skipped.

**Plaintext imports** (Bitwarden JSON/CSV, browser CSV, 1Password CSV) are parsed entirely in Rust.
The file is chosen in a native dialog opened by Rust and read into zeroize-on-drop buffers; its
contents never reach the WebView. CSV is parsed by a small in-crate RFC 4180 reader so every cell
can be wiped. The JSON parser (`serde_json`) does not zeroize its intermediate buffers.

