// Shared by the fuzz targets (included with `#[path]`, not a module of its own crate).
// Not every target uses every item.
#![allow(dead_code)]
use aegis_core::kdf::KdfParams;

/// The fuzzer controls the KDF parameters in the files it builds. Skip derivation for
/// expensive ones so each run stays fast; cheap parameters still reach decryption.
pub fn cheap(kdf: &KdfParams) -> bool {
    kdf.m_cost_kib <= 64 && kdf.t_cost <= 2 && kdf.p_cost <= 2
}

pub const PASSWORD: &str = "quarry-velvet-ozone-lantern-71";
