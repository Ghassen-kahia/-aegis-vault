//! Argon2id master-key derivation with enforced parameter bounds and device calibration.

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::encoding::b64;
use crate::error::{Error, Result};
use crate::secret::{SecretKey, KEY_LEN};

pub const SALT_LEN: usize = 16;
pub const ARGON2_VERSION: u32 = 0x13;

/// Production default memory: 256 MiB.
pub const DEFAULT_M_COST_KIB: u32 = 256 * 1024;
pub const DEFAULT_P_COST: u32 = 1;
pub const DEFAULT_TARGET: Duration = Duration::from_millis(750);

/// Floor (RFC 9106 §4 second recommended option is 64 MiB, t = 3).
#[cfg(not(any(test, feature = "insecure-test-kdf")))]
const FLOOR: Bounds = Bounds { m: 64 * 1024, t: 3, p: 1 };
#[cfg(any(test, feature = "insecure-test-kdf"))]
const FLOOR: Bounds = Bounds { m: 8, t: 1, p: 1 };

/// Ceiling, so a hostile vault file cannot exhaust memory/CPU.
const CEILING: Bounds = Bounds {
    m: 4 * 1024 * 1024,
    t: 64,
    p: 16,
};

const MIN_CALIBRATED_T: u32 = 3;
const MAX_CALIBRATED_T: u32 = 12;

struct Bounds {
    m: u32,
    t: u32,
    p: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KdfAlg {
    Argon2id,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfParams {
    pub alg: KdfAlg,
    pub version: u32,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
}

impl KdfParams {
    /// New parameters with a fresh random salt.
    pub fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Result<Self> {
        let mut salt = vec![0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let p = Self {
            alg: KdfAlg::Argon2id,
            version: ARGON2_VERSION,
            m_cost_kib,
            t_cost,
            p_cost,
            salt,
        };
        p.validate()?;
        Ok(p)
    }

    /// Same cost parameters, fresh salt (used on password change).
    pub fn with_fresh_salt(&self) -> Result<Self> {
        Self::new(self.m_cost_kib, self.t_cost, self.p_cost)
    }

    /// Calibrates `t_cost` at 256 MiB so that one derivation takes roughly `target`
    /// on this device, clamped to [3, 12].
    pub fn calibrate(target: Duration) -> Result<Self> {
        let probe = Self::new(DEFAULT_M_COST_KIB, MIN_CALIBRATED_T, DEFAULT_P_COST)?;
        let start = Instant::now();
        drop(probe.derive_master_key(b"aegis-calibration-probe")?);
        let elapsed = start.elapsed().as_secs_f64().max(1e-3);
        let t = (f64::from(MIN_CALIBRATED_T) * target.as_secs_f64() / elapsed).ceil();
        let t = (t as u32).clamp(MIN_CALIBRATED_T, MAX_CALIBRATED_T);
        Self::new(DEFAULT_M_COST_KIB, t, DEFAULT_P_COST)
    }

    /// Fast parameters for the test suite only.
    #[cfg(any(test, feature = "insecure-test-kdf"))]
    pub fn insecure_for_tests() -> Self {
        let mut salt = vec![0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Self {
            alg: KdfAlg::Argon2id,
            version: ARGON2_VERSION,
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
            salt,
        }
    }

    /// Rejects parameters below the security floor or above the DoS ceiling.
    /// Called before every derivation.
    pub fn validate(&self) -> Result<()> {
        validate_against(self, &FLOOR)
    }

    /// Stable byte encoding bound into the password key slot's AAD.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + 16 + self.salt.len());
        v.extend_from_slice(b"argon2id");
        v.extend_from_slice(&self.version.to_be_bytes());
        v.extend_from_slice(&self.m_cost_kib.to_be_bytes());
        v.extend_from_slice(&self.t_cost.to_be_bytes());
        v.extend_from_slice(&self.p_cost.to_be_bytes());
        v.extend_from_slice(&self.salt);
        v
    }

    /// Argon2id(password, salt) → 256-bit master key.
    pub fn derive_master_key(&self, password: &[u8]) -> Result<SecretKey> {
        self.validate()?;
        let params = Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|e| Error::KdfParams(e.to_string()))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut mk = SecretKey::zeroed();
        argon
            .hash_password_into(password, &self.salt, mk.expose_mut())
            .map_err(|_| Error::Crypto)?;
        Ok(mk)
    }
}

fn validate_against(p: &KdfParams, floor: &Bounds) -> Result<()> {
    let err = |m: &str| Err(Error::KdfParams(m.to_owned()));
    if p.version != ARGON2_VERSION {
        return err("unsupported Argon2 version");
    }
    if p.salt.len() != SALT_LEN {
        return err("salt must be 16 bytes");
    }
    if p.m_cost_kib < floor.m || p.t_cost < floor.t || p.p_cost < floor.p {
        return err("parameters below the minimum security floor");
    }
    if p.m_cost_kib > CEILING.m || p.t_cost > CEILING.t || p.p_cost > CEILING.p {
        return err("parameters above the permitted maximum");
    }
    if p.m_cost_kib < 8 * p.p_cost {
        return err("memory must be at least 8 KiB per lane");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::HEXLOWER;

    /// RFC 9106 §5.3 Argon2id test vector (exercises the library we depend on).
    #[test]
    fn argon2id_rfc9106_vector() {
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .output_len(32)
            .data(argon2::AssociatedData::new(&[4u8; 12]).unwrap())
            .build()
            .unwrap();
        let a = Argon2::new_with_secret(&[3u8; 8], Algorithm::Argon2id, Version::V0x13, params)
            .unwrap();
        let mut out = [0u8; 32];
        a.hash_password_into(&[1u8; 32], &[2u8; 16], &mut out).unwrap();
        assert_eq!(
            HEXLOWER.encode(&out),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    #[test]
    fn production_floor_is_enforced() {
        let prod_floor = Bounds { m: 64 * 1024, t: 3, p: 1 };
        let mut p = KdfParams::insecure_for_tests();
        assert!(validate_against(&p, &prod_floor).is_err());
        p.m_cost_kib = 64 * 1024;
        p.t_cost = 3;
        assert!(validate_against(&p, &prod_floor).is_ok());
        p.t_cost = 2;
        assert!(validate_against(&p, &prod_floor).is_err());
        p.t_cost = 3;
        p.m_cost_kib = 64 * 1024 - 1;
        assert!(validate_against(&p, &prod_floor).is_err());
    }

    #[test]
    fn ceiling_and_shape_are_enforced() {
        let base = KdfParams::insecure_for_tests();
        let cases: [fn(&mut KdfParams); 6] = [
            |p| p.m_cost_kib = 4 * 1024 * 1024 + 1,
            |p| p.t_cost = 65,
            |p| p.p_cost = 17,
            |p| p.salt = vec![0; 15],
            |p| p.version = 0x10,
            |p| p.p_cost = 0,
        ];
        for mutate in cases {
            let mut p = base.clone();
            mutate(&mut p);
            assert!(matches!(p.validate(), Err(Error::KdfParams(_))));
            assert!(p.derive_master_key(b"pw").is_err());
        }
    }

    #[test]
    fn derivation_is_deterministic_and_salted() {
        let p = KdfParams::insecure_for_tests();
        let a = p.derive_master_key(b"password").unwrap();
        let b = p.derive_master_key(b"password").unwrap();
        assert!(a.ct_eq(&b));
        let c = p.derive_master_key(b"Password").unwrap();
        assert!(!a.ct_eq(&c));
        let q = p.with_fresh_salt();
        // with_fresh_salt validates against the (test) floor and must change the salt.
        let q = q.unwrap();
        assert_ne!(p.salt, q.salt);
        assert!(!a.ct_eq(&q.derive_master_key(b"password").unwrap()));
    }

    #[test]
    fn canonical_bytes_cover_every_parameter() {
        let p = KdfParams::insecure_for_tests();
        let base = p.canonical_bytes();
        for mutate in [
            (|p: &mut KdfParams| p.m_cost_kib += 1) as fn(&mut KdfParams),
            |p| p.t_cost += 1,
            |p| p.p_cost += 1,
            |p| p.salt[0] ^= 1,
            |p| p.version += 1,
        ] {
            let mut q = p.clone();
            mutate(&mut q);
            assert_ne!(q.canonical_bytes(), base);
        }
    }

    #[test]
    fn serde_rejects_unknown_fields() {
        let p = KdfParams::insecure_for_tests();
        let mut v = serde_json::to_value(&p).unwrap();
        v["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<KdfParams>(v).is_err());
    }
}
