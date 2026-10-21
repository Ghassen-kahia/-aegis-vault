//! The single source of randomness: the operating system CSPRNG (`getrandom`), never a seeded
//! userspace generator (threat 18).

use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::TryRng;

use crate::error::{Error, Result};

/// Fills `buf` from the OS CSPRNG. A failure of the OS generator is reported, not ignored.
pub fn fill(buf: &mut [u8]) -> Result<()> {
    SysRng.try_fill_bytes(buf).map_err(|_| Error::Crypto)
}

/// An infallible handle for APIs that need one (sampling, shuffling, key generation). If the OS
/// generator fails this panics: no secure operation can continue without randomness.
pub fn os_rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}
