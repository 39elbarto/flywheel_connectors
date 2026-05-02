//! X-Wing hybrid KEM (X25519 + ML-KEM-768) — V4 zone-key sealing primitive.
//!
//! This module is a **wiring stub**. It defines the types and trait that the
//! V4 zone-key sealing path will use, so downstream code (`fcp-core`'s
//! `ZoneKeyManifest`, `fcp-mesh`'s rotation logic) can be written against a
//! stable surface while the actual ML-KEM-768 + X-Wing combiner implementation
//! is delivered under sub-beads `kyopb.1.2.1` through `kyopb.1.2.5`.
//!
//! The full design is documented in
//! `docs/post-quantum/x_wing_kem_design.md` (parent bead `kyopb.1.2`).
//!
//! # Why a stub now?
//!
//! - It pins the public API shape so the V4 schema migration
//!   (`ZoneKeyManifest::WrappedKey::XWing`) can be drafted in parallel.
//! - It gives `grep` and the type checker a single, named landing point for
//!   "where does the real X-Wing implementation plug in?".
//! - Until the impl lands, every operation returns
//!   [`CryptoError::HpkeFailed`] with a sentinel message naming the
//!   responsible sub-bead, so accidental production calls fail loudly
//!   rather than silently downgrading to a broken state.

use crate::error::{CryptoError, CryptoResult};

/// X-Wing public-key wire size: `pk_mlkem` (1184) + `pk_x25519` (32).
pub const XWING_PUBLIC_KEY_SIZE: usize = 1216;

/// X-Wing secret-key wire size: `sk_mlkem` (2400) + `sk_x25519` (32) + `pk_x25519` (32).
pub const XWING_SECRET_KEY_SIZE: usize = 2464;

/// X-Wing encapsulated-key wire size: `ct_mlkem` (1088) + `ct_x25519` (32).
pub const XWING_ENC_SIZE: usize = 1120;

/// Maximum accepted X-Wing sealed-box ciphertext length, mirrors
/// [`crate::hpke_seal::HPKE_MAX_CIPHERTEXT`] for consistency.
pub const XWING_MAX_CIPHERTEXT: usize = 64 * 1024;

/// X-Wing public key (opaque wire bytes).
///
/// Internal layout is `pk_mlkem || pk_x25519`; consumers MUST treat it as
/// opaque and round-trip through [`XWingPublicKey::from_bytes`] /
/// [`XWingPublicKey::to_bytes`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XWingPublicKey(Vec<u8>);

impl XWingPublicKey {
    /// Wrap raw public-key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HpkeFailed`] if the input is not exactly
    /// [`XWING_PUBLIC_KEY_SIZE`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != XWING_PUBLIC_KEY_SIZE {
            return Err(CryptoError::HpkeFailed(format!(
                "xwing public key must be {} bytes, got {}",
                XWING_PUBLIC_KEY_SIZE,
                bytes.len()
            )));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Copy out the raw bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// X-Wing secret key (opaque wire bytes).
///
/// Internal layout is `sk_mlkem || sk_x25519 || pk_x25519`. Wrapped in a
/// dedicated newtype so a redacting `Debug` impl can avoid leaking secret
/// material into logs.
#[derive(Clone, PartialEq, Eq)]
pub struct XWingSecretKey(Vec<u8>);

impl core::fmt::Debug for XWingSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("XWingSecretKey")
            .field(&"[redacted; xwing secret key bytes]")
            .finish()
    }
}

impl XWingSecretKey {
    /// Wrap raw secret-key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HpkeFailed`] if the input is not exactly
    /// [`XWING_SECRET_KEY_SIZE`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != XWING_SECRET_KEY_SIZE {
            return Err(CryptoError::HpkeFailed(format!(
                "xwing secret key must be {} bytes, got {}",
                XWING_SECRET_KEY_SIZE,
                bytes.len()
            )));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// X-Wing sealed box: a fixed-size encapsulated key plus the AEAD ciphertext
/// over the wrapped payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XWingSealedBox {
    /// V4 KEM ciphertext: `ct_mlkem || ct_x25519`, exactly
    /// [`XWING_ENC_SIZE`] bytes.
    pub enc: Vec<u8>,
    /// AEAD ciphertext (ChaCha20-Poly1305 today, possibly XChaCha20-Poly1305
    /// post-`kyopb.1.2.2`) including the 16-byte authentication tag.
    pub ciphertext: Vec<u8>,
}

impl XWingSealedBox {
    /// Encode to bytes: `enc || ciphertext`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.enc.len() + self.ciphertext.len());
        out.extend_from_slice(&self.enc);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Decode from bytes: the first [`XWING_ENC_SIZE`] are `enc`, the rest is
    /// the AEAD ciphertext.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HpkeFailed`] if the input is too short to
    /// contain `enc` plus a 16-byte AEAD tag, or larger than
    /// [`XWING_MAX_CIPHERTEXT`].
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        const AEAD_TAG: usize = 16;
        if bytes.len() < XWING_ENC_SIZE + AEAD_TAG {
            return Err(CryptoError::HpkeFailed(
                "xwing sealed box too short".into(),
            ));
        }
        if bytes.len() > XWING_MAX_CIPHERTEXT {
            return Err(CryptoError::HpkeFailed(format!(
                "xwing sealed box too large: {} bytes exceeds {} byte limit",
                bytes.len(),
                XWING_MAX_CIPHERTEXT
            )));
        }
        let (enc, ciphertext) = bytes.split_at(XWING_ENC_SIZE);
        Ok(Self {
            enc: enc.to_vec(),
            ciphertext: ciphertext.to_vec(),
        })
    }
}

/// X-Wing KEM operations contract.
///
/// Implementations live behind this trait so the V4 wiring code can be
/// written against [`XWingStub`] today and swapped for the real impl
/// (sub-bead `kyopb.1.2.1`) without further call-site changes.
///
/// Aside from `wire_size`, every method returns
/// [`CryptoError::HpkeFailed`] in the stub implementation; do not call them
/// from production paths until the real impl lands.
pub trait XWingKem {
    /// Generate a fresh X-Wing keypair.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HpkeFailed`] in the stub.
    fn generate(&self) -> CryptoResult<(XWingPublicKey, XWingSecretKey)>;

    /// Seal `plaintext` to `recipient`, binding `aad` into the AEAD.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HpkeFailed`] in the stub.
    fn seal(
        &self,
        recipient: &XWingPublicKey,
        plaintext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<XWingSealedBox>;

    /// Open a sealed box with `secret`, verifying `aad`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HpkeFailed`] in the stub, or on any
    /// authentication failure in the real implementation.
    fn open(
        &self,
        secret: &XWingSecretKey,
        sealed: &XWingSealedBox,
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>>;

    /// Report the constant wire sizes used by this KEM, so callers can
    /// pre-size buffers without crate-private constants.
    fn wire_size(&self) -> XWingWireSize {
        XWingWireSize {
            public_key: XWING_PUBLIC_KEY_SIZE,
            secret_key: XWING_SECRET_KEY_SIZE,
            enc: XWING_ENC_SIZE,
            max_ciphertext: XWING_MAX_CIPHERTEXT,
        }
    }
}

/// Wire-size descriptor returned by [`XWingKem::wire_size`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XWingWireSize {
    /// Bytes in a public key.
    pub public_key: usize,
    /// Bytes in a secret key.
    pub secret_key: usize,
    /// Bytes in an encapsulated-key wire blob.
    pub enc: usize,
    /// Hard cap on AEAD ciphertext length we will deserialise.
    pub max_ciphertext: usize,
}

/// Stub [`XWingKem`] implementation that fails loudly with a sentinel error
/// message naming the responsible sub-bead.
///
/// Exists so V4 wiring code can be drafted against a concrete trait object
/// while the real implementation is built out under `kyopb.1.2.{1..5}`.
#[derive(Clone, Copy, Debug, Default)]
pub struct XWingStub;

impl XWingStub {
    /// Construct a new stub. Provided for API symmetry with the future real
    /// impl, which will likely take a config struct.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

const STUB_MSG: &str = "xwing not yet implemented (br-kyopb.1.2.1 vendor selection pending)";

impl XWingKem for XWingStub {
    fn generate(&self) -> CryptoResult<(XWingPublicKey, XWingSecretKey)> {
        Err(CryptoError::HpkeFailed(STUB_MSG.to_owned()))
    }

    fn seal(
        &self,
        _recipient: &XWingPublicKey,
        _plaintext: &[u8],
        _aad: &[u8],
    ) -> CryptoResult<XWingSealedBox> {
        Err(CryptoError::HpkeFailed(STUB_MSG.to_owned()))
    }

    fn open(
        &self,
        _secret: &XWingSecretKey,
        _sealed: &XWingSealedBox,
        _aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        Err(CryptoError::HpkeFailed(STUB_MSG.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_wire_size_is_pinned_to_x_wing_draft() {
        // br-kyopb.1.2: pin the X-Wing draft sizes so a vendor swap that
        // changes the wire format trips this test loudly. See
        // docs/post-quantum/x_wing_kem_design.md §2.1 for the source.
        assert_eq!(XWING_PUBLIC_KEY_SIZE, 1216);
        assert_eq!(XWING_SECRET_KEY_SIZE, 2464);
        assert_eq!(XWING_ENC_SIZE, 1120);
    }

    #[test]
    fn public_key_rejects_wrong_length() {
        let too_short = vec![0u8; XWING_PUBLIC_KEY_SIZE - 1];
        let too_long = vec![0u8; XWING_PUBLIC_KEY_SIZE + 1];
        assert!(XWingPublicKey::from_bytes(&too_short).is_err());
        assert!(XWingPublicKey::from_bytes(&too_long).is_err());
        assert!(XWingPublicKey::from_bytes(&vec![0u8; XWING_PUBLIC_KEY_SIZE]).is_ok());
    }

    #[test]
    fn secret_key_rejects_wrong_length() {
        let too_short = vec![0u8; XWING_SECRET_KEY_SIZE - 1];
        assert!(XWingSecretKey::from_bytes(&too_short).is_err());
        assert!(XWingSecretKey::from_bytes(&vec![0u8; XWING_SECRET_KEY_SIZE]).is_ok());
    }

    #[test]
    fn secret_key_debug_redacts() {
        // br-kyopb.1.2: secret key bytes must NEVER appear in Debug output;
        // operator logs commonly include {:?} formatting.
        let sk = XWingSecretKey::from_bytes(&vec![0xABu8; XWING_SECRET_KEY_SIZE]).unwrap();
        let dbg = format!("{sk:?}");
        assert!(dbg.contains("redacted"), "Debug must redact: {dbg}");
        assert!(!dbg.contains("ab"), "Debug must not leak hex: {dbg}");
    }

    #[test]
    fn sealed_box_round_trip_through_wire_bytes() {
        let sealed = XWingSealedBox {
            enc: vec![0x42u8; XWING_ENC_SIZE],
            ciphertext: vec![0x01u8; 16 + 64], // tag + payload
        };
        let bytes = sealed.to_bytes();
        let decoded = XWingSealedBox::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, sealed);
    }

    #[test]
    fn sealed_box_rejects_too_short() {
        let bytes = vec![0u8; XWING_ENC_SIZE + 15]; // missing 1 tag byte
        assert!(XWingSealedBox::from_bytes(&bytes).is_err());
    }

    #[test]
    fn sealed_box_rejects_too_large() {
        let bytes = vec![0u8; XWING_MAX_CIPHERTEXT + 1];
        assert!(XWingSealedBox::from_bytes(&bytes).is_err());
    }

    #[test]
    fn stub_generate_returns_sentinel_error() {
        let stub = XWingStub::new();
        let err = stub.generate().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("xwing not yet implemented") && msg.contains("kyopb.1.2"),
            "stub error must name the responsible sub-bead: {msg}"
        );
    }

    #[test]
    fn stub_seal_returns_sentinel_error() {
        let stub = XWingStub::new();
        let pk = XWingPublicKey::from_bytes(&vec![0u8; XWING_PUBLIC_KEY_SIZE]).unwrap();
        let err = stub.seal(&pk, b"plaintext", b"aad").unwrap_err();
        assert!(format!("{err}").contains("xwing not yet implemented"));
    }

    #[test]
    fn stub_open_returns_sentinel_error() {
        let stub = XWingStub::new();
        let sk = XWingSecretKey::from_bytes(&vec![0u8; XWING_SECRET_KEY_SIZE]).unwrap();
        let sealed = XWingSealedBox {
            enc: vec![0u8; XWING_ENC_SIZE],
            ciphertext: vec![0u8; 32],
        };
        let err = stub.open(&sk, &sealed, b"aad").unwrap_err();
        assert!(format!("{err}").contains("xwing not yet implemented"));
    }

    #[test]
    fn stub_wire_size_reports_constants() {
        let stub = XWingStub::new();
        let sizes = stub.wire_size();
        assert_eq!(sizes.public_key, XWING_PUBLIC_KEY_SIZE);
        assert_eq!(sizes.secret_key, XWING_SECRET_KEY_SIZE);
        assert_eq!(sizes.enc, XWING_ENC_SIZE);
        assert_eq!(sizes.max_ciphertext, XWING_MAX_CIPHERTEXT);
    }
}
