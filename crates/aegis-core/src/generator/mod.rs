//! Password and passphrase generator using only the OS CSPRNG.
//! Sampling uses `random_range` / `choose` (rejection sampling, no modulo bias).

use rand::seq::{IndexedRandom, SliceRandom};
use rand::RngExt;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::secret::SecretString;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?/~";
const AMBIGUOUS: &str = "0Oo1lI|`'\";:,.~{}[]()/<>";
const WORDLIST: &str = include_str!("eff_large_wordlist.txt");

#[derive(Clone, Debug, Deserialize)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

#[derive(Debug, Serialize)]
pub struct Generated {
    pub value: SecretString,
    pub entropy_bits: f64,
}

fn words() -> Vec<&'static str> {
    WORDLIST.lines().filter_map(|l| l.split('\t').nth(1)).map(str::trim).collect()
}

pub fn generate_password(o: &PasswordOptions) -> Result<Generated> {
    if !(8..=128).contains(&o.length) {
        return Err(Error::Validation("length must be between 8 and 128".into()));
    }
    let classes: Vec<Vec<char>> = [(o.lowercase, LOWER), (o.uppercase, UPPER), (o.digits, DIGITS), (o.symbols, SYMBOLS)]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, set)| set.chars().filter(|c| !o.exclude_ambiguous || !AMBIGUOUS.contains(*c)).collect())
        .collect();
    if classes.is_empty() {
        return Err(Error::Validation("select at least one character set".into()));
    }
    let alphabet: Vec<char> = classes.concat();
    let mut rng = crate::rng::os_rng();
    // One character from each selected class, the rest from the full alphabet, then shuffle.
    let mut chars: Vec<char> = classes.iter().filter_map(|c| c.choose(&mut rng).copied()).collect();
    while chars.len() < o.length {
        chars.push(alphabet[rng.random_range(0..alphabet.len())]);
    }
    chars.shuffle(&mut rng);
    let value = SecretString::new(chars.iter().collect());
    zeroize::Zeroize::zeroize(&mut chars);
    Ok(Generated { value, entropy_bits: o.length as f64 * (alphabet.len() as f64).log2() })
}

pub fn generate_passphrase(o: &PassphraseOptions) -> Result<Generated> {
    if !(3..=20).contains(&o.words) || o.separator.chars().count() > 3 {
        return Err(Error::Validation("use 3–20 words and a separator of at most 3 characters".into()));
    }
    let list = words();
    let mut rng = crate::rng::os_rng();
    let mut picked: Vec<String> = (0..o.words)
        .map(|_| {
            let w = list[rng.random_range(0..list.len())];
            if o.capitalize {
                let mut c = w.chars();
                c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or_default()
            } else {
                w.to_owned()
            }
        })
        .collect();
    let mut entropy = o.words as f64 * (list.len() as f64).log2();
    if o.include_number {
        let i = rng.random_range(0..picked.len());
        picked[i].push(char::from(b'0' + rng.random_range(0..10u8)));
        entropy += 10f64.log2() + (o.words as f64).log2();
    }
    let value = SecretString::new(picked.join(&o.separator));
    zeroize::Zeroize::zeroize(&mut picked);
    Ok(Generated { value, entropy_bits: entropy })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(len: usize) -> PasswordOptions {
        PasswordOptions { length: len, lowercase: true, uppercase: true, digits: true, symbols: true, exclude_ambiguous: false }
    }

    #[test]
    fn wordlist_is_pinned_eff_list() {
        let w = words();
        assert_eq!(w.len(), 7776);
        let mut u = w.clone();
        u.sort_unstable();
        u.dedup();
        assert_eq!(u.len(), 7776);
        let h = data_encoding::HEXLOWER.encode(&crate::crypto::sha256(&[WORDLIST.as_bytes()]));
        assert_eq!(h, "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e");
    }

    #[test]
    fn respects_length_classes_and_ambiguity() {
        for _ in 0..200 {
            let mut o = opts(16);
            o.exclude_ambiguous = true;
            let p = generate_password(&o).unwrap();
            let s = p.value.expose();
            assert_eq!(s.chars().count(), 16);
            assert!(s.chars().any(|c| c.is_ascii_lowercase()));
            assert!(s.chars().any(|c| c.is_ascii_uppercase()));
            assert!(s.chars().any(|c| c.is_ascii_digit()));
            assert!(!s.chars().any(|c| AMBIGUOUS.contains(c)));
        }
        assert!(generate_password(&opts(7)).is_err());
        let none = PasswordOptions { lowercase: false, uppercase: false, digits: false, symbols: false, ..opts(16) };
        assert!(generate_password(&none).is_err());
    }

    #[test]
    fn coarse_uniformity() {
        let o = PasswordOptions { lowercase: false, uppercase: false, symbols: false, ..opts(100) };
        let mut counts = [0f64; 10];
        for _ in 0..200 {
            for c in generate_password(&o).unwrap().value.expose().chars() {
                counts[(c as u8 - b'0') as usize] += 1.0;
            }
        }
        let expected = 2000.0;
        let chi2: f64 = counts.iter().map(|c| (c - expected).powi(2) / expected).sum();
        assert!(chi2 < 40.0, "chi2 = {chi2}"); // df = 9; p ≈ 5e-6
    }

    #[test]
    fn passphrase() {
        let o = PassphraseOptions { words: 6, separator: "-".into(), capitalize: false, include_number: false };
        let p = generate_passphrase(&o).unwrap();
        assert_eq!(p.value.expose().split('-').count(), 6);
        assert!((p.entropy_bits - 77.55).abs() < 0.1);
    }
}
