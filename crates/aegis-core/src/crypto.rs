//! Thin, misuse-resistant wrappers around AES-256-GCM, HKDF-SHA-256 and SHA-256.
//!
//! * Nonces are always generated internally from the OS CSPRNG — callers cannot supply one.
//! * Every call requires associated data, built by the `aad_*` helpers for domain separation.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::kdf::KdfParams;
use crate::secret::{SecretBytes, SecretKey};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// Plaintexts are padded to a multiple of this to hide exact lengths.
pub const PAD_BLOCK: usize = 256;

// Domain-separation labels. Changing any of these is a format break.
pub const LABEL_KEK_PASSWORD: &[u8] = b"aegis-vault/v1/kek/password";
pub const LABEL_KEK_RECOVERY: &[u8] = b"aegis-vault/v1/kek/recovery";
pub const LABEL_AUTH: &[u8] = b"aegis-vault/v1/auth";
const AAD_SLOT_PASSWORD: &[u8] = b"aegis-vault/v1/slot/password";
const AAD_SLOT_RECOVERY: &[u8] = b"aegis-vault/v1/slot/recovery";
const AAD_META: &[u8] = b"aegis-vault/v1/meta";
const AAD_ITEM: &[u8] = b"aegis-vault/v1/item";

/// Output of an AEAD encryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Encrypts `plaintext` under `key` with a fresh random 96-bit nonce.
pub fn seal(key: &SecretKey, aad: &[u8], plaintext: &[u8]) -> Result<Sealed> {
    let mut nonce = [0u8; NONCE_LEN];
    crate::rng::fill(&mut nonce)?;
    seal_with_nonce(key, &nonce, aad, plaintext)
}

/// Deterministic variant. Only reachable from tests (known-answer vectors);
/// production code must use [`seal`].
pub(crate) fn seal_with_nonce(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Sealed> {
    let cipher = Aes256Gcm::new_from_slice(key.expose()).map_err(|_| Error::Crypto)?;
    let ciphertext = cipher
        .encrypt(&Nonce::from(*nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Crypto)?;
    Ok(Sealed {
        nonce: *nonce,
        ciphertext,
    })
}

/// Decrypts and authenticates. Any failure is reported as `Error::Crypto`;
/// callers map it to a context-appropriate error.
pub fn open(key: &SecretKey, aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<SecretBytes> {
    if nonce.len() != NONCE_LEN || ciphertext.len() < TAG_LEN {
        return Err(Error::Crypto);
    }
    let nonce = Nonce::try_from(nonce).map_err(|_| Error::Crypto)?;
    let cipher = Aes256Gcm::new_from_slice(key.expose()).map_err(|_| Error::Crypto)?;
    cipher
        .decrypt(&nonce, Payload { msg: ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Crypto)
}

/// HKDF-Expand with `prk` used directly as the pseudorandom key (it is already uniform).
pub fn hkdf_expand(prk: &SecretKey, info: &[u8]) -> Result<SecretKey> {
    let hk = Hkdf::<Sha256>::from_prk(prk.expose()).map_err(|_| Error::Crypto)?;
    let mut out = SecretKey::zeroed();
    hk.expand(info, out.expose_mut()).map_err(|_| Error::Crypto)?;
    Ok(out)
}

/// Full HKDF (extract + expand).
pub fn hkdf_extract_expand(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<SecretKey> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = SecretKey::zeroed();
    hk.expand(info, out.expose_mut()).map_err(|_| Error::Crypto)?;
    Ok(out)
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

// ---- Associated data builders ------------------------------------------------

pub fn aad_slot_password(vault_id: &Uuid, kdf: &KdfParams) -> Vec<u8> {
    let mut v = Vec::with_capacity(128);
    v.extend_from_slice(AAD_SLOT_PASSWORD);
    v.extend_from_slice(vault_id.as_bytes());
    v.extend_from_slice(&kdf.canonical_bytes());
    v
}

pub fn aad_slot_recovery(vault_id: &Uuid) -> Vec<u8> {
    [AAD_SLOT_RECOVERY, vault_id.as_bytes()].concat()
}

pub fn aad_meta(vault_id: &Uuid) -> Vec<u8> {
    [AAD_META, vault_id.as_bytes()].concat()
}

pub fn aad_item(vault_id: &Uuid, item_id: &Uuid) -> Vec<u8> {
    [AAD_ITEM, vault_id.as_bytes(), item_id.as_bytes()].concat()
}

// ---- Length-hiding padding ---------------------------------------------------

/// `u32_be(len) ‖ data ‖ 0x00…` up to a multiple of [`PAD_BLOCK`].
pub fn pad(data: &[u8]) -> Result<SecretBytes> {
    let len = u32::try_from(data.len()).map_err(|_| Error::Validation("payload too large".into()))?;
    let total = (4 + data.len()).div_ceil(PAD_BLOCK) * PAD_BLOCK;
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    out.resize(total, 0);
    Ok(out)
}

/// Inverse of [`pad`]; rejects malformed length prefixes and non-zero padding.
pub fn unpad(buf: &[u8]) -> Result<&[u8]> {
    if buf.len() < 4 || buf.len() % PAD_BLOCK != 0 {
        return Err(Error::Integrity("bad padding"));
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let end = 4usize.checked_add(len).ok_or(Error::Integrity("bad padding"))?;
    if end > buf.len() || buf[end..].iter().any(|&b| b != 0) {
        return Err(Error::Integrity("bad padding"));
    }
    Ok(&buf[4..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::HEXLOWER;

    fn hex(s: &str) -> Vec<u8> {
        HEXLOWER.decode(s.as_bytes()).unwrap()
    }

    // McGrew & Viega, "The Galois/Counter Mode of Operation", Test Case 13.
    #[test]
    fn aes256gcm_known_answer_tc13() {
        let key = SecretKey::from_slice(&[0u8; 32]).unwrap();
        let s = seal_with_nonce(&key, &[0u8; 12], b"", b"").unwrap();
        assert_eq!(s.ciphertext, hex("530f8afbc74536b9a963b4f1c4cb738b"));
    }

    // Test Case 14: one zero block.
    #[test]
    fn aes256gcm_known_answer_tc14() {
        let key = SecretKey::from_slice(&[0u8; 32]).unwrap();
        let s = seal_with_nonce(&key, &[0u8; 12], b"", &[0u8; 16]).unwrap();
        assert_eq!(
            s.ciphertext,
            hex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")
        );
        let pt = open(&key, b"", &[0u8; 12], &s.ciphertext).unwrap();
        assert_eq!(&pt[..], &[0u8; 16]);
    }

    // RFC 5869, Appendix A.1 (HKDF-SHA-256, test case 1) — first 32 bytes of OKM.
    #[test]
    fn hkdf_sha256_rfc5869_case1() {
        let ikm = [0x0bu8; 22];
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let okm = hkdf_extract_expand(&salt, &ikm, &info).unwrap();
        assert_eq!(
            okm.expose().to_vec(),
            hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
        );
    }

    #[test]
    fn roundtrip_and_aad_binding() {
        let key = SecretKey::generate();
        let s = seal(&key, b"aad-1", b"hello").unwrap();
        assert_eq!(&open(&key, b"aad-1", &s.nonce, &s.ciphertext).unwrap()[..], b"hello");
        assert_eq!(open(&key, b"aad-2", &s.nonce, &s.ciphertext), Err(Error::Crypto));
        let other = SecretKey::generate();
        assert_eq!(open(&other, b"aad-1", &s.nonce, &s.ciphertext), Err(Error::Crypto));
    }

    #[test]
    fn every_bit_flip_is_detected() {
        let key = SecretKey::generate();
        let s = seal(&key, b"aad", b"attack at dawn").unwrap();
        for i in 0..s.ciphertext.len() {
            for bit in 0..8 {
                let mut ct = s.ciphertext.clone();
                ct[i] ^= 1 << bit;
                assert!(open(&key, b"aad", &s.nonce, &ct).is_err());
            }
        }
        for i in 0..NONCE_LEN {
            let mut n = s.nonce;
            n[i] ^= 1;
            assert!(open(&key, b"aad", &n, &s.ciphertext).is_err());
        }
        assert!(open(&key, b"aad", &s.nonce, &s.ciphertext[..s.ciphertext.len() - 1]).is_err());
        assert!(open(&key, b"aad", &s.nonce[..11], &s.ciphertext).is_err());
    }

    #[test]
    fn nonces_never_repeat() {
        use std::collections::HashSet;
        let key = SecretKey::generate();
        let mut nonces = HashSet::new();
        let mut cts = HashSet::new();
        for _ in 0..10_000 {
            let s = seal(&key, b"", b"same plaintext").unwrap();
            assert!(nonces.insert(s.nonce));
            assert!(cts.insert(s.ciphertext));
        }
    }

    #[test]
    fn hkdf_labels_give_independent_keys() {
        let mk = SecretKey::generate();
        let a = hkdf_expand(&mk, LABEL_KEK_PASSWORD).unwrap();
        let b = hkdf_expand(&mk, LABEL_AUTH).unwrap();
        assert!(!a.ct_eq(&b));
        assert!(a.ct_eq(&hkdf_expand(&mk, LABEL_KEK_PASSWORD).unwrap()));
    }

    #[test]
    fn padding_roundtrip_and_hiding() {
        for n in [0usize, 1, 251, 252, 253, 1000] {
            let data = vec![7u8; n];
            let p = pad(&data).unwrap();
            assert_eq!(p.len() % PAD_BLOCK, 0);
            assert_eq!(unpad(&p).unwrap(), &data[..]);
        }
        assert_eq!(pad(b"a").unwrap().len(), pad(&[1u8; 200]).unwrap().len());
    }

    #[test]
    fn unpad_rejects_malformed() {
        let mut p = pad(b"abc").unwrap();
        p[100] = 1; // non-zero padding
        assert!(unpad(&p).is_err());
        let mut p = pad(b"abc").unwrap();
        p[0] = 0xff; // length beyond buffer
        assert!(unpad(&p).is_err());
        assert!(unpad(&[0u8; 255]).is_err());
        assert!(unpad(&[]).is_err());
    }

    #[test]
    fn aad_contexts_are_distinct() {
        let v = Uuid::new_v4();
        let i = Uuid::new_v4();
        let all = [aad_slot_recovery(&v), aad_meta(&v), aad_item(&v, &i)];
        for (a, x) in all.iter().enumerate() {
            for (b, y) in all.iter().enumerate() {
                if a != b {
                    assert_ne!(x, y);
                }
            }
        }
    }
}
