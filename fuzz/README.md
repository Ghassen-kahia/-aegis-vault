# Fuzzing

Coverage-guided fuzzing (libFuzzer via `cargo-fuzz`) of everything that reads untrusted bytes.
The property tests in `crates/aegis-core/tests/hostile_input.rs` run on every `cargo test`; these
targets go much deeper and are meant to run for minutes to hours.

| Target | Input | Checks |
|--------|-------|--------|
| `vault_file` | a vault file | parse never panics; cheap-KDF files also go through unlock |
| `backup_file` | an `.aegisbackup` file | parse never panics; cheap-KDF files also go through decryption |
| `importers` | first byte picks Bitwarden JSON/CSV, browser CSV or 1Password CSV | parse never panics; parser output always imports into a vault without error |
| `recovery_key` | Recovery Key text | parse never panics; any accepted key re-encodes and re-parses identically |

The fuzz crate enables `aegis-core`'s `insecure-test-kdf` feature so that inputs with tiny
Argon2 parameters reach decryption. The desktop app never enables it.

## Running

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

# from the repository root (libFuzzer needs the corpus directory to exist)
mkdir -p fuzz/corpus/importers
cargo +nightly fuzz run importers fuzz/corpus/importers fuzz/seeds/importers -- -max_total_time=600
```

The first directory collects the growing corpus (git-ignored); the second holds the committed seed
inputs. A crash is written to `fuzz/artifacts/<target>/`. To reproduce it, pass that file as the only
argument: `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-…`.

Regenerate the seeds after a file-format change:

```sh
cargo test -p aegis-core --test hostile_input -- --ignored write_fuzz_seeds
```

CI runs every target for a few minutes on each push (`.github/workflows/ci.yml`, job `fuzz`).
