//! HKDF-SHA256 key derivation for FCP.
//!
//! Provides HMAC-based Key Derivation Function as specified in RFC 5869.

use crate::error::{CryptoError, CryptoResult};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

/// Maximum output key material length for HKDF-SHA256.
/// Per RFC 5869: L <= 255 * `HashLen` = 255 * 32 = 8160 bytes.
pub const HKDF_MAX_OUTPUT_LENGTH: usize = 255 * 32;

/// HKDF-SHA256 instance for key derivation.
///
/// This wraps the extract-expand pattern for deriving keys from
/// input keying material (IKM).
pub struct HkdfSha256 {
    prk: Hkdf<Sha256>,
}

impl HkdfSha256 {
    /// Create a new HKDF instance from input keying material.
    ///
    /// # Arguments
    ///
    /// * `salt` - Optional salt value (a non-secret random value). If `None`, a zero-filled
    ///   string of `HashLen` bytes is used.
    /// * `ikm` - Input keying material (the secret input).
    #[must_use]
    pub fn new(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        let prk = Hkdf::<Sha256>::new(salt, ikm);
        Self { prk }
    }

    /// Expand the PRK to derive output keying material.
    ///
    /// # Arguments
    ///
    /// * `info` - Application-specific context/label.
    /// * `output` - Buffer to fill with derived key material.
    ///
    /// # Errors
    ///
    /// Returns an error if the output length exceeds `HKDF_MAX_OUTPUT_LENGTH`.
    pub fn expand(&self, info: &[u8], output: &mut [u8]) -> CryptoResult<()> {
        self.prk
            .expand(info, output)
            .map_err(|_| CryptoError::KeyDerivationFailed("HKDF expand failed".into()))
    }

    /// Expand to a fixed-size array.
    ///
    /// # Errors
    ///
    /// Returns an error if N exceeds `HKDF_MAX_OUTPUT_LENGTH`.
    pub fn expand_to_array<const N: usize>(&self, info: &[u8]) -> CryptoResult<[u8; N]> {
        let mut output = [0u8; N];
        self.expand(info, &mut output)?;
        Ok(output)
    }
}

/// Derive a key using HKDF-SHA256 in one shot.
///
/// This is a convenience function that combines extract and expand.
///
/// # Arguments
///
/// * `salt` - Optional salt value.
/// * `ikm` - Input keying material.
/// * `info` - Application-specific context/label.
/// * `output` - Buffer to fill with derived key material.
///
/// # Errors
///
/// Returns an error if the output length exceeds `HKDF_MAX_OUTPUT_LENGTH`.
pub fn hkdf_sha256(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> CryptoResult<()> {
    let hkdf = HkdfSha256::new(salt, ikm);
    hkdf.expand(info, output)
}

/// Derive a fixed-size key using HKDF-SHA256.
///
/// # Errors
///
/// Returns an error if N exceeds `HKDF_MAX_OUTPUT_LENGTH`.
pub fn hkdf_sha256_array<const N: usize>(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
) -> CryptoResult<[u8; N]> {
    let hkdf = HkdfSha256::new(salt, ikm);
    hkdf.expand_to_array(info)
}

/// Derived key material with zeroize-on-drop semantics.
#[derive(ZeroizeOnDrop)]
pub struct DerivedKey<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> DerivedKey<N> {
    /// Derive a key using HKDF-SHA256.
    ///
    /// # Errors
    ///
    /// Returns an error if N exceeds `HKDF_MAX_OUTPUT_LENGTH`.
    pub fn derive(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> CryptoResult<Self> {
        let bytes = hkdf_sha256_array(salt, ikm, info)?;
        Ok(Self { bytes })
    }

    /// Get the derived key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }
}

impl<const N: usize> AsRef<[u8]> for DerivedKey<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<const N: usize> std::fmt::Debug for DerivedKey<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedKey")
            .field("len", &N)
            .finish_non_exhaustive()
    }
}

/// FCP2-specific key derivation with standard domain separation.
///
/// Uses explicit length-prefixed framing inside the HKDF `info` string so
/// variable-length components cannot collide through simple concatenation.
pub struct Fcp2KeyDerivation;

/// Direction label for session-key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDirection {
    /// Key material for frames sent to the peer.
    Send,
    /// Key material for frames received from the peer.
    Recv,
}

impl SessionDirection {
    #[must_use]
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Send => b"send",
            Self::Recv => b"recv",
        }
    }
}

/// Purpose label for per-session MAC-key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacKeyPurpose {
    /// Authenticate complete frames.
    Frame,
    /// Authenticate frame headers.
    Header,
    /// Authenticate generic session traffic.
    Auth,
}

impl MacKeyPurpose {
    #[must_use]
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Frame => b"frame",
            Self::Header => b"header",
            Self::Auth => b"auth",
        }
    }
}

impl Fcp2KeyDerivation {
    fn framed_info(label: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let mut info = Vec::with_capacity(
            label.len() + parts.iter().map(|part| 4 + part.len()).sum::<usize>(),
        );
        info.extend_from_slice(label);
        for part in parts {
            let part_len =
                u32::try_from(part.len()).expect("HKDF info part length exceeds u32::MAX");
            info.extend_from_slice(&part_len.to_be_bytes());
            info.extend_from_slice(part);
        }
        info
    }

    /// Derive a zone encryption key.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn derive_zone_key(
        zone_key_material: &[u8],
        zone_id: &[u8],
    ) -> CryptoResult<DerivedKey<32>> {
        let info = Self::framed_info(b"FCP2-ZONE-KEY", &[zone_id]);
        DerivedKey::derive(None, zone_key_material, &info)
    }

    /// Derive an `ObjectIdKey` for content-addressed storage.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn derive_objectid_key(
        zone_key_material: &[u8],
        zone_id: &[u8],
    ) -> CryptoResult<DerivedKey<32>> {
        let info = Self::framed_info(b"FCP2-OBJECTID-KEY", &[zone_id]);
        DerivedKey::derive(None, zone_key_material, &info)
    }

    /// Derive a session key from ECDH shared secret.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn derive_session_key(
        shared_secret: &[u8],
        session_id: &[u8],
        direction: SessionDirection,
    ) -> CryptoResult<DerivedKey<32>> {
        let info = Self::framed_info(b"FCP2-SESSION", &[direction.label(), session_id]);
        DerivedKey::derive(None, shared_secret, &info)
    }

    /// Derive a MAC key for session frame authentication.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn derive_mac_key(
        session_key: &[u8],
        purpose: MacKeyPurpose,
    ) -> CryptoResult<DerivedKey<32>> {
        let info = Self::framed_info(b"FCP2-MAC", &[purpose.label()]);
        DerivedKey::derive(None, session_key, &info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_basic() {
        let ikm = b"input keying material";
        let salt = b"salt";
        let info = b"info";

        let mut output = [0u8; 32];
        hkdf_sha256(Some(salt), ikm, info, &mut output).unwrap();

        // Output should be deterministic
        let mut output2 = [0u8; 32];
        hkdf_sha256(Some(salt), ikm, info, &mut output2).unwrap();
        assert_eq!(output, output2);
    }

    #[test]
    fn hkdf_different_inputs() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        hkdf_sha256(None, b"ikm1", b"info", &mut out1).unwrap();
        hkdf_sha256(None, b"ikm2", b"info", &mut out2).unwrap();

        assert_ne!(out1, out2);
    }

    #[test]
    fn hkdf_different_info() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        hkdf_sha256(None, b"ikm", b"info1", &mut out1).unwrap();
        hkdf_sha256(None, b"ikm", b"info2", &mut out2).unwrap();

        assert_ne!(out1, out2);
    }

    #[test]
    fn hkdf_different_salt() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];

        hkdf_sha256(Some(b"salt1"), b"ikm", b"info", &mut out1).unwrap();
        hkdf_sha256(Some(b"salt2"), b"ikm", b"info", &mut out2).unwrap();

        assert_ne!(out1, out2);
    }

    #[test]
    fn hkdf_array() {
        let key: [u8; 32] = hkdf_sha256_array(None, b"ikm", b"info").unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn derived_key() {
        let key = DerivedKey::<32>::derive(None, b"ikm", b"info").unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn fcp2_zone_key_derivation() {
        let zone_material = [0u8; 32];
        let zone_id = b"z:work";

        let key = Fcp2KeyDerivation::derive_zone_key(&zone_material, zone_id).unwrap();
        assert_eq!(key.as_bytes().len(), 32);

        // Should be deterministic
        let key2 = Fcp2KeyDerivation::derive_zone_key(&zone_material, zone_id).unwrap();
        assert_eq!(key.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn fcp2_different_zones() {
        let zone_material = [0u8; 32];

        let key1 = Fcp2KeyDerivation::derive_zone_key(&zone_material, b"z:work").unwrap();
        let key2 = Fcp2KeyDerivation::derive_zone_key(&zone_material, b"z:private").unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn golden_vector_hkdf_sha256() {
        // RFC 5869 Test Case 1
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let mut okm = [0u8; 42];
        hkdf_sha256(Some(&salt), &ikm, &info, &mut okm).unwrap();

        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn rfc5869_test_case_2() {
        // RFC 5869 Test Case 2 - Longer inputs/outputs
        let ikm = hex::decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
        )
        .unwrap();
        let salt = hex::decode(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        )
        .unwrap();
        let info = hex::decode(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        )
        .unwrap();

        let mut okm = [0u8; 82];
        hkdf_sha256(Some(&salt), &ikm, &info, &mut okm).unwrap();

        assert_eq!(
            hex::encode(okm),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87"
        );
    }

    #[test]
    fn rfc5869_test_case_3() {
        // RFC 5869 Test Case 3 - Zero-length salt and info
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();

        let mut okm = [0u8; 42];
        // Empty salt (None) and empty info
        hkdf_sha256(None, &ikm, &[], &mut okm).unwrap();

        assert_eq!(
            hex::encode(okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn fcp2_session_key_derivation() {
        let shared_secret = [42u8; 32];
        let session_id = b"session-12345";

        let send_key = Fcp2KeyDerivation::derive_session_key(
            &shared_secret,
            session_id,
            SessionDirection::Send,
        )
        .unwrap();
        let recv_key = Fcp2KeyDerivation::derive_session_key(
            &shared_secret,
            session_id,
            SessionDirection::Recv,
        )
        .unwrap();

        // Different directions should produce different keys
        assert_ne!(send_key.as_bytes(), recv_key.as_bytes());

        // Same direction should be deterministic
        let send_key2 = Fcp2KeyDerivation::derive_session_key(
            &shared_secret,
            session_id,
            SessionDirection::Send,
        )
        .unwrap();
        assert_eq!(send_key.as_bytes(), send_key2.as_bytes());
    }

    #[test]
    fn fcp2_mac_key_derivation() {
        let session_key = [42u8; 32];

        let mac_key1 =
            Fcp2KeyDerivation::derive_mac_key(&session_key, MacKeyPurpose::Frame).unwrap();
        let mac_key2 =
            Fcp2KeyDerivation::derive_mac_key(&session_key, MacKeyPurpose::Header).unwrap();

        // Different purposes should produce different keys
        assert_ne!(mac_key1.as_bytes(), mac_key2.as_bytes());
    }

    #[test]
    fn fcp2_objectid_key_derivation() {
        let zone_material = [0u8; 32];
        let zone_id = b"z:work";

        let key = Fcp2KeyDerivation::derive_objectid_key(&zone_material, zone_id).unwrap();
        assert_eq!(key.as_bytes().len(), 32);

        // Should differ from zone key derivation
        let zone_key = Fcp2KeyDerivation::derive_zone_key(&zone_material, zone_id).unwrap();
        assert_ne!(key.as_bytes(), zone_key.as_bytes());
    }

    #[test]
    fn derived_key_as_ref() {
        let key = DerivedKey::<32>::derive(None, b"ikm", b"info").unwrap();
        let bytes: &[u8] = key.as_ref();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn hkdf_instance_multiple_expansions() {
        let hkdf = HkdfSha256::new(Some(b"salt"), b"ikm");

        let key1: [u8; 32] = hkdf.expand_to_array(b"info1").unwrap();
        let key2: [u8; 32] = hkdf.expand_to_array(b"info2").unwrap();

        // Same HKDF instance, different info → different keys
        assert_ne!(key1, key2);
    }

    // ---- Expand to different sizes ----

    #[test]
    fn hkdf_expand_to_16_bytes() {
        let key: [u8; 16] = hkdf_sha256_array(None, b"ikm", b"info").unwrap();
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn hkdf_expand_to_64_bytes() {
        let key: [u8; 64] = hkdf_sha256_array(None, b"ikm", b"info").unwrap();
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn hkdf_expand_to_1_byte() {
        let key: [u8; 1] = hkdf_sha256_array(None, b"ikm", b"info").unwrap();
        assert_eq!(key.len(), 1);
    }

    // ---- DerivedKey debug redacts ----

    #[test]
    fn derived_key_debug_redacted() {
        let key = DerivedKey::<32>::derive(None, b"ikm", b"info").unwrap();
        let debug = format!("{key:?}");
        assert!(debug.contains("DerivedKey"));
        assert!(debug.contains("len"));
        assert!(debug.contains("32"));
        // Must not contain key material
        assert!(!debug.contains("0x"));
    }

    // ---- DerivedKey AsRef ----

    #[test]
    fn derived_key_as_ref_matches_as_bytes() {
        let key = DerivedKey::<32>::derive(None, b"ikm", b"info").unwrap();
        let from_ref: &[u8] = key.as_ref();
        assert_eq!(from_ref, key.as_bytes());
    }

    // ---- Empty inputs ----

    #[test]
    fn hkdf_empty_ikm() {
        let mut out = [0u8; 32];
        hkdf_sha256(None, b"", b"info", &mut out).unwrap();
        // Should produce deterministic output
        let mut out2 = [0u8; 32];
        hkdf_sha256(None, b"", b"info", &mut out2).unwrap();
        assert_eq!(out, out2);
    }

    #[test]
    fn hkdf_empty_info() {
        let mut out = [0u8; 32];
        hkdf_sha256(None, b"ikm", b"", &mut out).unwrap();
        // Non-empty IKM with empty info should produce output
        assert_ne!(out, [0u8; 32]);
    }

    #[test]
    fn hkdf_empty_salt_explicit_vs_none() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        // None salt should be equivalent to Some(&[0u8; 32]) per RFC
        hkdf_sha256(None, b"ikm", b"info", &mut out1).unwrap();
        hkdf_sha256(Some(&[0u8; 32]), b"ikm", b"info", &mut out2).unwrap();
        // Per RFC 5869: if salt is not provided, it defaults to HashLen zeros
        assert_eq!(out1, out2);
    }

    // ---- FCP2 derivation domain separation ----

    #[test]
    fn fcp2_zone_key_differs_from_objectid_key() {
        let material = [1u8; 32];
        let zone_id = b"z:test";
        let zk = Fcp2KeyDerivation::derive_zone_key(&material, zone_id).unwrap();
        let ok = Fcp2KeyDerivation::derive_objectid_key(&material, zone_id).unwrap();
        assert_ne!(zk.as_bytes(), ok.as_bytes());
    }

    #[test]
    fn fcp2_session_key_different_session_ids() {
        let shared = [42u8; 32];
        let k1 = Fcp2KeyDerivation::derive_session_key(&shared, b"sess-1", SessionDirection::Send)
            .unwrap();
        let k2 = Fcp2KeyDerivation::derive_session_key(&shared, b"sess-2", SessionDirection::Send)
            .unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn fcp2_mac_key_deterministic() {
        let session_key = [99u8; 32];
        let k1 = Fcp2KeyDerivation::derive_mac_key(&session_key, MacKeyPurpose::Auth).unwrap();
        let k2 = Fcp2KeyDerivation::derive_mac_key(&session_key, MacKeyPurpose::Auth).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn fcp2_session_key_framing_prevents_concat_collisions() {
        let info1 = Fcp2KeyDerivation::framed_info(b"FCP2-SESSION", &[b"a", b"bc"]);
        let info2 = Fcp2KeyDerivation::framed_info(b"FCP2-SESSION", &[b"ab", b"c"]);
        let shared = [7u8; 32];
        let k1 = DerivedKey::<32>::derive(None, &shared, &info1).unwrap();
        let k2 = DerivedKey::<32>::derive(None, &shared, &info2).unwrap();
        assert_ne!(info1, info2);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn fcp2_mac_key_framing_matches_explicit_helper() {
        let session_key = [11u8; 32];
        let direct = Fcp2KeyDerivation::derive_mac_key(&session_key, MacKeyPurpose::Frame).unwrap();
        let info = Fcp2KeyDerivation::framed_info(b"FCP2-MAC", &[MacKeyPurpose::Frame.label()]);
        let expected = DerivedKey::<32>::derive(None, &session_key, &info).unwrap();
        assert_eq!(direct.as_bytes(), expected.as_bytes());
    }

    // ---- HKDF_MAX_OUTPUT_LENGTH constant ----

    #[test]
    fn hkdf_max_output_length_constant() {
        assert_eq!(HKDF_MAX_OUTPUT_LENGTH, 255 * 32);
        assert_eq!(HKDF_MAX_OUTPUT_LENGTH, 8160);
    }

    // ---- DerivedKey various sizes ----

    #[test]
    fn derived_key_16_bytes() {
        let key = DerivedKey::<16>::derive(None, b"ikm", b"info").unwrap();
        assert_eq!(key.as_bytes().len(), 16);
    }

    #[test]
    fn derived_key_64_bytes() {
        let key = DerivedKey::<64>::derive(None, b"ikm", b"info").unwrap();
        assert_eq!(key.as_bytes().len(), 64);
    }

    #[test]
    fn derived_key_1_byte() {
        let key = DerivedKey::<1>::derive(None, b"ikm", b"info").unwrap();
        assert_eq!(key.as_bytes().len(), 1);
    }

    // ---- FCP2 derivation with empty inputs ----

    #[test]
    fn fcp2_zone_key_empty_material() {
        let key = Fcp2KeyDerivation::derive_zone_key(&[], b"z:test").unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn fcp2_zone_key_empty_zone_id() {
        let key = Fcp2KeyDerivation::derive_zone_key(&[42u8; 32], b"").unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn fcp2_direction_and_purpose_labels_are_domain_separated() {
        let shared = [1u8; 32];
        let session_id = b"sess";
        let send_key =
            Fcp2KeyDerivation::derive_session_key(&shared, session_id, SessionDirection::Send)
                .unwrap();
        let recv_key =
            Fcp2KeyDerivation::derive_session_key(&shared, session_id, SessionDirection::Recv)
                .unwrap();
        let frame_key =
            Fcp2KeyDerivation::derive_mac_key(send_key.as_bytes(), MacKeyPurpose::Frame).unwrap();
        let header_key =
            Fcp2KeyDerivation::derive_mac_key(send_key.as_bytes(), MacKeyPurpose::Header).unwrap();

        assert_ne!(send_key.as_bytes(), recv_key.as_bytes());
        assert_ne!(frame_key.as_bytes(), header_key.as_bytes());
    }

    // ---- HKDF expand to same size gives same result ----

    #[test]
    fn hkdf_expand_deterministic_same_instance() {
        let hkdf = HkdfSha256::new(Some(b"s"), b"ikm");
        let k1: [u8; 32] = hkdf.expand_to_array(b"info").unwrap();
        let k2: [u8; 32] = hkdf.expand_to_array(b"info").unwrap();
        assert_eq!(k1, k2);
    }

    // ---- DerivedKey debug shows len but not key ----

    #[test]
    fn derived_key_debug_16() {
        let key = DerivedKey::<16>::derive(None, b"ikm", b"info").unwrap();
        let debug = format!("{key:?}");
        assert!(debug.contains("16"));
        assert!(!debug.contains("0x"));
    }

    // ---- HKDF prefix property ----

    #[test]
    fn hkdf_shorter_output_is_prefix_of_longer() {
        let hkdf = HkdfSha256::new(None, b"ikm");
        let short: [u8; 16] = hkdf.expand_to_array(b"info").unwrap();
        let long: [u8; 32] = hkdf.expand_to_array(b"info").unwrap();
        assert_eq!(&long[..16], &short);
    }

    // Metamorphic: no collision across the full (direction × session_id) product
    // under a fixed shared secret. This is strictly stronger than pairwise
    // direction separation — it catches any regression that makes e.g. the
    // session_id length-prefix ineffective.
    #[test]
    fn fcp2_session_key_mutual_distinctness() {
        let shared = [7u8; 32];
        let directions = [SessionDirection::Send, SessionDirection::Recv];
        let session_ids: [&[u8]; 5] = [b"", b"a", b"bc", b"abc", b"\x00\x00\x00\x01"];

        let mut derived = Vec::new();
        for dir in directions {
            for sid in session_ids {
                let key = Fcp2KeyDerivation::derive_session_key(&shared, sid, dir).unwrap();
                derived.push(*key.as_bytes());
            }
        }

        for i in 0..derived.len() {
            for j in (i + 1)..derived.len() {
                assert_ne!(
                    derived[i], derived[j],
                    "session keys must be mutually distinct across (direction, session_id) pairs \
                     (index {i} vs {j})"
                );
            }
        }
    }

    // Metamorphic: no collision across all MacKeyPurpose variants under a fixed
    // session key. Guards against label-table drift that would silently merge
    // two MAC scopes.
    #[test]
    fn fcp2_mac_key_mutual_distinctness() {
        let session_key = [9u8; 32];
        let purposes = [
            MacKeyPurpose::Frame,
            MacKeyPurpose::Header,
            MacKeyPurpose::Auth,
        ];

        let keys: Vec<[u8; 32]> = purposes
            .iter()
            .map(|p| {
                *Fcp2KeyDerivation::derive_mac_key(&session_key, *p)
                    .unwrap()
                    .as_bytes()
            })
            .collect();

        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(
                    keys[i], keys[j],
                    "mac keys must be mutually distinct across MacKeyPurpose variants \
                     ({:?} vs {:?})",
                    purposes[i], purposes[j]
                );
            }
        }
    }

    // Metamorphic: swapping SessionDirection labels in the framed info must
    // yield a different key — confirms the direction component contributes
    // to the derivation and is not short-circuited by length-prefix framing.
    #[test]
    fn fcp2_session_direction_is_not_swap_symmetric() {
        let shared = [5u8; 32];
        let sid = b"sess-42";
        let send =
            Fcp2KeyDerivation::derive_session_key(&shared, sid, SessionDirection::Send).unwrap();
        let recv =
            Fcp2KeyDerivation::derive_session_key(&shared, sid, SessionDirection::Recv).unwrap();
        assert_ne!(send.as_bytes(), recv.as_bytes());

        // Direction label bytes must actually differ — a regression that stubbed
        // both arms to the same slice would silently break domain separation.
        assert_ne!(
            SessionDirection::Send.label(),
            SessionDirection::Recv.label()
        );
    }
}
