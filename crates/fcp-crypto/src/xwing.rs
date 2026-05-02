//! X-Wing hybrid KEM (X25519 + ML-KEM-768) — V4 zone-key sealing primitive.
//!
//! Production implementation backed by the RustCrypto [`x-wing`] crate
//! (X-Wing draft-connolly-cfrg-xwing-kem **draft 06**, pure Rust, audited).
//!
//! The [`XWingKem`] trait surface remains the same shape that was designed
//! in `flywheel_connectors-kyopb.1.2`. The real [`XWingProvider`] now
//! satisfies it; the legacy [`XWingStub`] is preserved for callers that
//! want to fail loudly during the V4 cutover (sub-bead `kyopb.1.2.4`).
//!
//! # Vendor selection (br-kyopb.1.2.1)
//!
//! See `docs/architecture/ADR-0001_xwing_kem_vendor.md` for the full
//! decision record. Summary: we use `x-wing = 0.1.0-rc.0` from the
//! RustCrypto KEMs workspace because (a) it is a pure-Rust hybrid that
//! composes ML-KEM-768 (`ml-kem` crate, FIPS 203) with `x25519-dalek`
//! ECDH using the X-Wing draft-06 combiner verbatim, (b) it ships with
//! an opt-in `zeroize` feature on both halves, and (c) it passes the
//! upstream IETF draft test vectors (re-checked here in
//! `tests/xwing_vectors.rs`).
//!
//! # Wire shapes (X-Wing draft 06)
//!
//! | Field             | Bytes  |
//! | ----------------- | -----: |
//! | Public key        | 1216   |
//! | Secret key (seed) | 32     |
//! | Ciphertext        | 1120   |
//! | Encapsulation rnd | 64     |
//! | Shared secret     | 32     |
//!
//! Note: draft 06 stores the *secret key* as a 32-byte seed; the expanded
//! form (~2.4 KiB) is reconstructed on demand via SHAKE256. Earlier
//! design notes that quoted 2464 bytes for the secret key referred to the
//! pre-draft-06 expanded representation and are corrected to 32 here.
//!
//! # AEAD layering
//!
//! [`XWingProvider::seal`] and [`XWingProvider::open`] layer
//! ChaCha20-Poly1305 over the X-Wing shared secret per
//! `docs/post-quantum/x_wing_kem_design.md` §4.2:
//!
//! ```text
//! aead_key = HKDF-SHA256(IKM = ss, salt = aad, info = b"FCP4-XWING-AEAD")[0..32]
//! ciphertext = ChaCha20Poly1305(aead_key, nonce = 0, plaintext, aad = aad)
//! ```
//!
//! The all-zero nonce is sound here because the AEAD key is unique per
//! (KEM ciphertext, recipient-pk) pair — the X-Wing combiner mixes both
//! into the shared secret, so the AEAD key is never reused under a fresh
//! encapsulation. Same trick HPKE single-shot uses (RFC 9180).
//!
//! [`x-wing`]: https://docs.rs/x-wing

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use rand_core_pq::{TryCryptoRng, TryRng};
use x_wing::{
    Decapsulate, Decapsulator, DecapsulationKey as RealDecapKey, Encapsulate,
    EncapsulationKey as RealEncapKey, KeyExport,
};

use crate::error::{CryptoError, CryptoResult};
use crate::hkdf::hkdf_sha256_array;

/// X-Wing public-key wire size: `pk_mlkem` (1184) + `pk_x25519` (32).
pub const XWING_PUBLIC_KEY_SIZE: usize = 1216;

/// X-Wing secret-key wire size — 32-byte compressed seed (draft 06).
///
/// Earlier design notes that quoted 2464 bytes referred to the pre-draft-06
/// expanded representation; draft 06 stores only the 32-byte seed and
/// re-expands via SHAKE256 on each decapsulation.
pub const XWING_SECRET_KEY_SIZE: usize = 32;

/// X-Wing encapsulated-key wire size: `ct_mlkem` (1088) + `ct_x25519` (32).
pub const XWING_ENC_SIZE: usize = 1120;

/// X-Wing shared-secret size.
pub const XWING_SHARED_SECRET_SIZE: usize = 32;

/// Length of the ephemeral randomness fed into a single encapsulation
/// (`ENCAPSULATION_RANDOMNESS_SIZE` in the X-Wing draft: 32 B for ML-KEM
/// + 32 B for X25519).
pub const XWING_ENCAPSULATION_RANDOMNESS_SIZE: usize = 64;

/// Maximum accepted X-Wing sealed-box ciphertext length, mirrors
/// [`crate::hpke_seal::HPKE_MAX_CIPHERTEXT`] for consistency.
pub const XWING_MAX_CIPHERTEXT: usize = 64 * 1024;

/// HKDF info string used by the FCP V4 X-Wing AEAD layer.
pub const XWING_AEAD_INFO: &[u8] = b"FCP4-XWING-AEAD";

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

/// X-Wing secret key (32-byte compressed seed per draft 06).
///
/// Wrapped in a dedicated newtype so a redacting `Debug` impl can avoid
/// leaking secret material into logs.
#[derive(Clone, PartialEq, Eq)]
pub struct XWingSecretKey([u8; XWING_SECRET_KEY_SIZE]);

impl core::fmt::Debug for XWingSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("XWingSecretKey")
            .field(&"[redacted; 32-byte xwing seed]")
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
        let mut arr = [0u8; XWING_SECRET_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
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
    /// AEAD ciphertext (ChaCha20-Poly1305) including the 16-byte
    /// authentication tag. AEAD key is derived from the X-Wing shared
    /// secret via HKDF-SHA256(IKM=ss, salt=aad, info=`FCP4-XWING-AEAD`).
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
            return Err(CryptoError::HpkeFailed("xwing sealed box too short".into()));
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
/// written against [`XWingProvider`] today and swapped for a different
/// vendor (e.g. PQClean bindings via FFI) without further call-site
/// changes.
pub trait XWingKem {
    /// Generate a fresh X-Wing keypair.
    ///
    /// # Errors
    ///
    /// Provider-defined; the production [`XWingProvider`] returns
    /// [`CryptoError::KeyDerivationFailed`] only if the OS RNG is
    /// unavailable.
    fn generate(&self) -> CryptoResult<(XWingPublicKey, XWingSecretKey)>;

    /// Seal `plaintext` to `recipient`, binding `aad` into the AEAD.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::AeadEncryptFailed`] if the AEAD layer
    /// fails (cannot happen with valid inputs in the current impl).
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
    /// - [`CryptoError::HpkeFailed`] if the encapsulated-key portion is
    ///   structurally invalid.
    /// - [`CryptoError::AeadDecryptFailed`] on any cryptographic failure
    ///   (wrong key, tampered ciphertext, wrong AAD).
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

/// Production [`XWingKem`] implementation backed by the RustCrypto
/// [`x-wing`] crate (draft 06).
#[derive(Clone, Copy, Debug, Default)]
pub struct XWingProvider;

impl XWingProvider {
    /// Construct a new provider. Stateless; no allocation.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl XWingKem for XWingProvider {
    fn generate(&self) -> CryptoResult<(XWingPublicKey, XWingSecretKey)> {
        // X-Wing draft 06 stores secret keys as 32-byte seeds; we generate
        // those with `getrandom` and let the upstream expand them via
        // SHAKE256 on first decap. This keeps the API symmetrical with
        // every other FCP key type and avoids pulling rand 0.9.
        let mut seed = [0u8; XWING_SECRET_KEY_SIZE];
        getrandom::fill(&mut seed).map_err(|e| {
            CryptoError::KeyDerivationFailed(format!("OS RNG unavailable: {e}"))
        })?;
        let real_sk: RealDecapKey = seed.into();
        let pk_bytes = real_sk
            .encapsulation_key()
            .to_bytes()
            .as_slice()
            .to_vec();
        let pk = XWingPublicKey(pk_bytes);
        let sk = XWingSecretKey(seed);
        Ok((pk, sk))
    }

    fn seal(
        &self,
        recipient: &XWingPublicKey,
        plaintext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<XWingSealedBox> {
        let pk = RealEncapKey::try_from(recipient.0.as_slice()).map_err(|_| {
            CryptoError::HpkeFailed("xwing public key failed structural validation".into())
        })?;
        let mut rng = OsRngV10;
        let (ct, ss) = pk.encapsulate_with_rng(&mut rng);
        let ss_bytes: [u8; 32] = ss.into();
        let aead = build_aead(&ss_bytes, aad)?;
        let nonce = Nonce::from([0u8; 12]);
        let ciphertext = aead
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::AeadEncryptFailed)?;
        Ok(XWingSealedBox {
            enc: ct.as_slice().to_vec(),
            ciphertext,
        })
    }

    fn open(
        &self,
        secret: &XWingSecretKey,
        sealed: &XWingSealedBox,
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if sealed.enc.len() != XWING_ENC_SIZE {
            return Err(CryptoError::HpkeFailed(format!(
                "xwing sealed box `enc` field must be {} bytes, got {}",
                XWING_ENC_SIZE,
                sealed.enc.len()
            )));
        }
        let real_sk: RealDecapKey = secret.0.into();
        let ct_arr =
            <[u8; XWING_ENC_SIZE]>::try_from(sealed.enc.as_slice()).expect("length checked above");
        let ct = x_wing::Ciphertext::from(ct_arr);
        let ss = real_sk.decapsulate(&ct);
        let ss_bytes: [u8; 32] = ss.into();
        let aead = build_aead(&ss_bytes, aad)?;
        let nonce = Nonce::from([0u8; 12]);
        aead.decrypt(
            &nonce,
            Payload {
                msg: &sealed.ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadDecryptFailed)
    }
}

/// Stub [`XWingKem`] implementation that fails loudly with a sentinel error.
///
/// Retained from the design-doc commit so callers that have not yet finished
/// the V4 cutover (`kyopb.1.2.4`) can keep their type-bounds against
/// `dyn XWingKem` while explicitly opting out of attempting any KEM
/// operation. New code should use [`XWingProvider`].
#[derive(Clone, Copy, Debug, Default)]
pub struct XWingStub;

impl XWingStub {
    /// Construct a new stub.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

const STUB_MSG: &str = "xwing not yet wired in this caller (see br-kyopb.1.2.4); switch to XWingProvider";

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

fn build_aead(shared_secret: &[u8; 32], aad: &[u8]) -> CryptoResult<ChaCha20Poly1305> {
    // HKDF-SHA256(IKM = ss, salt = aad, info = "FCP4-XWING-AEAD") → 32 B.
    // Binding `aad` into the salt makes the derived AEAD key context-
    // dependent on top of the AAD that the AEAD itself authenticates.
    let key_arr: [u8; 32] = hkdf_sha256_array(Some(aad), shared_secret, XWING_AEAD_INFO)
        .map_err(|e| CryptoError::KeyDerivationFailed(format!("xwing AEAD HKDF: {e}")))?;
    Ok(ChaCha20Poly1305::new((&key_arr).into()))
}

/// `getrandom`-backed adapter implementing `rand_core` v0.10's
/// [`TryCryptoRng`].
///
/// Same shim used in [`crate::ml_dsa`]; duplicated here so x-wing can pick
/// it up without depending on the ml-dsa module surface.
struct OsRngV10;

impl TryRng for OsRngV10 {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf).expect("OS RNG must be available for X-Wing encap");
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf).expect("OS RNG must be available for X-Wing encap");
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst).expect("OS RNG must be available for X-Wing encap");
        Ok(())
    }
}

impl TryCryptoRng for OsRngV10 {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_wire_size_is_pinned_to_x_wing_draft_06() {
        // br-kyopb.1.2.1: pin the X-Wing draft-06 sizes so a vendor swap
        // that changes the wire format trips this test loudly.
        assert_eq!(XWING_PUBLIC_KEY_SIZE, 1216);
        assert_eq!(XWING_SECRET_KEY_SIZE, 32);
        assert_eq!(XWING_ENC_SIZE, 1120);
        assert_eq!(XWING_SHARED_SECRET_SIZE, 32);
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
        let sk = XWingSecretKey::from_bytes(&[0xABu8; XWING_SECRET_KEY_SIZE]).unwrap();
        let dbg = format!("{sk:?}");
        assert!(dbg.contains("redacted"), "Debug must redact: {dbg}");
        assert!(!dbg.contains("ab"), "Debug must not leak hex: {dbg}");
    }

    #[test]
    fn sealed_box_round_trip_through_wire_bytes() {
        let sealed = XWingSealedBox {
            enc: vec![0x42u8; XWING_ENC_SIZE],
            ciphertext: vec![0x01u8; 16 + 64],
        };
        let bytes = sealed.to_bytes();
        let decoded = XWingSealedBox::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, sealed);
    }

    #[test]
    fn sealed_box_rejects_too_short() {
        let bytes = vec![0u8; XWING_ENC_SIZE + 15];
        assert!(XWingSealedBox::from_bytes(&bytes).is_err());
    }

    #[test]
    fn sealed_box_rejects_too_large() {
        let bytes = vec![0u8; XWING_MAX_CIPHERTEXT + 1];
        assert!(XWingSealedBox::from_bytes(&bytes).is_err());
    }

    #[test]
    fn provider_generate_produces_correctly_sized_keys() {
        let provider = XWingProvider::new();
        let (pk, sk) = provider.generate().unwrap();
        assert_eq!(pk.as_bytes().len(), XWING_PUBLIC_KEY_SIZE);
        assert_eq!(sk.as_bytes().len(), XWING_SECRET_KEY_SIZE);
    }

    #[test]
    fn provider_seal_then_open_round_trips() {
        let provider = XWingProvider::new();
        let (pk, sk) = provider.generate().unwrap();
        let plaintext = b"FCP V4 zone-key payload (br-kyopb.1.2.1)";
        let aad = b"zone:work|recipient:node-7|purpose:FCP4-ZONE-KEY";
        let sealed = provider.seal(&pk, plaintext, aad).unwrap();
        assert_eq!(sealed.enc.len(), XWING_ENC_SIZE);
        let opened = provider.open(&sk, &sealed, aad).unwrap();
        assert_eq!(opened.as_slice(), plaintext);
    }

    #[test]
    fn provider_open_rejects_wrong_aad() {
        let provider = XWingProvider::new();
        let (pk, sk) = provider.generate().unwrap();
        let sealed = provider
            .seal(&pk, b"payload", b"zone:work|node:7")
            .unwrap();
        let err = provider
            .open(&sk, &sealed, b"zone:home|node:7")
            .unwrap_err();
        assert!(matches!(err, CryptoError::AeadDecryptFailed));
    }

    #[test]
    fn provider_open_rejects_wrong_secret() {
        let provider = XWingProvider::new();
        let (pk_a, _sk_a) = provider.generate().unwrap();
        let (_pk_b, sk_b) = provider.generate().unwrap();
        let sealed = provider.seal(&pk_a, b"payload", b"aad").unwrap();
        // Decapsulating with the wrong sk yields an unrelated shared
        // secret per ML-KEM's implicit-rejection rule, so HKDF derives
        // an unrelated AEAD key and the AEAD tag fails.
        let err = provider.open(&sk_b, &sealed, b"aad").unwrap_err();
        assert!(matches!(err, CryptoError::AeadDecryptFailed));
    }

    #[test]
    fn provider_open_rejects_tampered_ciphertext() {
        let provider = XWingProvider::new();
        let (pk, sk) = provider.generate().unwrap();
        let mut sealed = provider.seal(&pk, b"payload", b"aad").unwrap();
        // Flip a bit in the ML-KEM ciphertext half; ML-KEM implicit
        // rejection produces a junk shared secret, AEAD then fails.
        sealed.enc[42] ^= 0x01;
        let err = provider.open(&sk, &sealed, b"aad").unwrap_err();
        assert!(matches!(err, CryptoError::AeadDecryptFailed));
    }

    #[test]
    fn provider_open_rejects_malformed_enc_length() {
        let provider = XWingProvider::new();
        let (_pk, sk) = provider.generate().unwrap();
        let bad = XWingSealedBox {
            enc: vec![0u8; XWING_ENC_SIZE - 1],
            ciphertext: vec![0u8; 32],
        };
        let err = provider.open(&sk, &bad, b"aad").unwrap_err();
        assert!(matches!(err, CryptoError::HpkeFailed(_)));
    }

    #[test]
    fn provider_seal_produces_unique_ciphertext_each_time() {
        let provider = XWingProvider::new();
        let (pk, _sk) = provider.generate().unwrap();
        let a = provider.seal(&pk, b"payload", b"aad").unwrap();
        let b = provider.seal(&pk, b"payload", b"aad").unwrap();
        // Encapsulation randomness is fresh per call → ct_x and ct_m
        // both diverge → distinct shared secret → distinct AEAD output.
        assert_ne!(a.enc, b.enc, "fresh encap randomness must yield fresh enc");
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn stub_generate_returns_sentinel_error() {
        let stub = XWingStub::new();
        let err = stub.generate().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("xwing not yet wired") && msg.contains("kyopb.1.2.4"),
            "stub error must name the cutover bead: {msg}"
        );
    }

    #[test]
    fn stub_seal_returns_sentinel_error() {
        let stub = XWingStub::new();
        let pk = XWingPublicKey::from_bytes(&vec![0u8; XWING_PUBLIC_KEY_SIZE]).unwrap();
        let err = stub.seal(&pk, b"plaintext", b"aad").unwrap_err();
        assert!(format!("{err}").contains("xwing not yet wired"));
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
        assert!(format!("{err}").contains("xwing not yet wired"));
    }

    #[test]
    fn wire_size_reports_constants() {
        let p = XWingProvider::new();
        let s = p.wire_size();
        assert_eq!(s.public_key, XWING_PUBLIC_KEY_SIZE);
        assert_eq!(s.secret_key, XWING_SECRET_KEY_SIZE);
        assert_eq!(s.enc, XWING_ENC_SIZE);
        assert_eq!(s.max_ciphertext, XWING_MAX_CIPHERTEXT);
    }
}
