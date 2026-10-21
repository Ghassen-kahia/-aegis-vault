//! Error type. Variants intentionally carry no secret material.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// Wrong master password or Recovery Key (or a tampered key slot — indistinguishable by design).
    #[error("invalid master password or recovery key")]
    InvalidCredentials,

    /// The vault key unwrapped correctly but the vault contents failed authentication
    /// or consistency checks (tampering, corruption, or a mixed-up file).
    #[error("vault integrity check failed: {0}")]
    Integrity(&'static str),

    /// The file is not a well-formed vault of a supported version.
    #[error("invalid vault file: {0}")]
    Format(String),

    /// KDF parameters are outside the permitted bounds.
    #[error("unsafe or invalid key-derivation parameters: {0}")]
    KdfParams(String),

    /// A cryptographic library call failed unexpectedly.
    #[error("cryptographic operation failed")]
    Crypto,

    /// A user-supplied secret does not meet policy (e.g. weak master password).
    #[error("{0}")]
    Policy(String),

    /// Invalid input (bad item fields, out-of-range settings…).
    #[error("{0}")]
    Validation(String),

    #[error("item not found")]
    NotFound,

    #[error("storage error: {0}")]
    Io(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.kind().to_string())
    }
}
