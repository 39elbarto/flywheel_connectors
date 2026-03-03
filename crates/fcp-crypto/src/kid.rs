//! Key Identifier (KID) types for FCP2.
//!
//! KIDs are 8-byte identifiers used to route signature verification and
//! decryption to the correct key. They are derived from the public key
//! using BLAKE3 truncation.

use crate::error::{CryptoError, CryptoResult};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Key identifier size in bytes.
pub const KID_SIZE: usize = 8;

/// Key Identifier - 8-byte truncated BLAKE3 hash of the public key.
///
/// KIDs are used in COSE headers to identify which key should be used
/// for verification or decryption without exposing the full public key.
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct KeyId([u8; KID_SIZE]);

impl KeyId {
    /// Create a new KID from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Derive a KID from a public key using BLAKE3.
    ///
    /// The derivation uses a domain-separated BLAKE3 hash:
    /// `BLAKE3(b"fcp.kid.v2" || public_key_bytes)[0..8]`
    #[must_use]
    pub fn derive_from_public_key(public_key_bytes: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"fcp.kid.v2");
        hasher.update(public_key_bytes);
        let hash = hasher.finalize();
        let mut kid = [0u8; KID_SIZE];
        kid.copy_from_slice(&hash.as_bytes()[..KID_SIZE]);
        Self(kid)
    }

    /// Get the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KID_SIZE] {
        &self.0
    }

    /// Convert to a slice.
    #[must_use]
    pub const fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Try to create from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly `KID_SIZE` bytes.
    pub fn try_from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != KID_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: KID_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; KID_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Encode as lowercase hexadecimal string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hexadecimal string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not valid hex or wrong length.
    pub fn from_hex(s: &str) -> CryptoResult<Self> {
        let bytes = hex::decode(s).map_err(|e| CryptoError::InvalidKeyId(e.to_string()))?;
        Self::try_from_slice(&bytes)
    }
}

impl ConstantTimeEq for KeyId {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for KeyId {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for KeyId {}

impl std::fmt::Debug for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyId({})", self.to_hex())
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Zeroize for KeyId {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for KeyId {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kid_derive_deterministic() {
        let pubkey = b"test public key bytes";
        let kid1 = KeyId::derive_from_public_key(pubkey);
        let kid2 = KeyId::derive_from_public_key(pubkey);
        assert_eq!(kid1, kid2);
    }

    #[test]
    fn kid_derive_different_keys() {
        let kid1 = KeyId::derive_from_public_key(b"key1");
        let kid2 = KeyId::derive_from_public_key(b"key2");
        assert_ne!(kid1, kid2);
    }

    #[test]
    fn kid_hex_roundtrip() {
        let kid = KeyId::derive_from_public_key(b"test key");
        let hex = kid.to_hex();
        let parsed = KeyId::from_hex(&hex).unwrap();
        assert_eq!(kid, parsed);
    }

    #[test]
    fn kid_from_bytes() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        let kid = KeyId::from_bytes(bytes);
        assert_eq!(kid.as_bytes(), &bytes);
    }

    #[test]
    fn kid_try_from_slice_valid() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        let kid = KeyId::try_from_slice(&bytes).unwrap();
        assert_eq!(kid.as_bytes(), &bytes);
    }

    #[test]
    fn kid_try_from_slice_invalid_length() {
        let result = KeyId::try_from_slice(&[1, 2, 3]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 8,
                actual: 3
            })
        ));
    }

    #[test]
    fn kid_golden_vector() {
        // Golden vector: BLAKE3("fcp.kid.v2" || pubkey)
        let pubkey = b"FCP2 test public key";
        let kid = KeyId::derive_from_public_key(pubkey);

        // Manual verification of the spec logic
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"fcp.kid.v2");
        hasher.update(pubkey);
        let hash = hasher.finalize();
        let expected = &hash.as_bytes()[..8];

        assert_eq!(kid.as_bytes(), expected);
    }

    #[test]
    fn kid_display_is_hex() {
        let kid = KeyId::from_bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        assert_eq!(kid.to_string(), "0123456789abcdef");
    }

    #[test]
    fn kid_debug_format() {
        let kid = KeyId::from_bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        assert_eq!(format!("{kid:?}"), "KeyId(0123456789abcdef)");
    }

    #[test]
    fn kid_from_hex_invalid_hex() {
        let err = KeyId::from_hex("not-hex").unwrap_err();
        assert!(matches!(err, CryptoError::InvalidKeyId(_)));
    }

    #[test]
    fn kid_from_hex_wrong_length() {
        // Valid hex but wrong length (4 bytes instead of 8)
        let err = KeyId::from_hex("01234567").unwrap_err();
        assert!(matches!(
            err,
            CryptoError::InvalidKeyLength {
                expected: 8,
                actual: 4
            }
        ));
    }

    #[test]
    fn kid_as_slice() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        let kid = KeyId::from_bytes(bytes);
        assert_eq!(kid.as_slice(), &bytes);
    }

    #[test]
    fn kid_default_is_zeroed() {
        let kid = KeyId::default();
        assert_eq!(kid.as_bytes(), &[0u8; KID_SIZE]);
    }

    #[test]
    fn kid_serde_roundtrip() {
        let kid = KeyId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let json = serde_json::to_string(&kid).unwrap();
        let decoded: KeyId = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, kid);
    }

    #[test]
    fn kid_derive_empty_key() {
        let kid = KeyId::derive_from_public_key(b"");
        assert_eq!(kid.as_bytes().len(), KID_SIZE);
        // Should still be deterministic
        assert_eq!(kid, KeyId::derive_from_public_key(b""));
    }
}
