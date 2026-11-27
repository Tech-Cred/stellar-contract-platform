//! Hashing helpers.
//!
//! Deterministic fingerprints use SHA-256 by default. This is an
//! artifact/interface identity primitive, not a signature scheme. SHA-512 is
//! available for consumers that need a wider digest; the algorithm is always
//! reported alongside the digest so a value is never ambiguous.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

/// Hash algorithm used for deterministic fingerprints.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    /// SHA-256, the backward-compatible default.
    #[default]
    Sha256,
    /// SHA-512, for consumers that need a wider digest.
    Sha512,
}

impl HashAlgorithm {
    /// Return the stable lowercase algorithm name used in reports and CLI input.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    /// Parse a report/CLI algorithm name.
    pub fn parse(raw: &str) -> Result<Self, crate::ObservatoryError> {
        match raw {
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            other => Err(crate::ObservatoryError::invalid(format!(
                "unsupported hash algorithm '{other}'; use sha256 or sha512"
            ))),
        }
    }
}

/// Return the lowercase hex digest of `bytes` using `algorithm`.
#[must_use]
pub fn hash_hex(algorithm: HashAlgorithm, bytes: &[u8]) -> String {
    match algorithm {
        HashAlgorithm::Sha256 => hex::encode(Sha256::digest(bytes)),
        HashAlgorithm::Sha512 => hex::encode(Sha512::digest(bytes)),
    }
}

/// Return the lowercase hex SHA-256 digest of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hash_hex(HashAlgorithm::Sha256, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector_empty() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hash_hex(HashAlgorithm::Sha512, b""),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn known_vector_abc() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hash_hex(HashAlgorithm::Sha512, b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn different_inputs_differ() {
        assert_ne!(sha256_hex(b"a"), sha256_hex(b"b"));
        assert_ne!(
            hash_hex(HashAlgorithm::Sha512, b"a"),
            hash_hex(HashAlgorithm::Sha512, b"b")
        );
    }

    #[test]
    fn algorithm_names_are_stable() {
        assert_eq!(HashAlgorithm::default().as_str(), "sha256");
        assert_eq!(
            HashAlgorithm::parse("sha512").unwrap(),
            HashAlgorithm::Sha512
        );
        assert!(HashAlgorithm::parse("md5").is_err());
        assert_eq!(
            serde_json::to_string(&HashAlgorithm::Sha512).unwrap(),
            "\"sha512\""
        );
    }
}
