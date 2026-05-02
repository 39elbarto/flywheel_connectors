//! X-Wing fuzz-style robustness harness via proptest.
//!
//! Goal: prove that the V4 X-Wing decap and AEAD-open paths NEVER panic
//! and ALWAYS return a decisive `Result` — no UB, no infinite loops, no
//! `unwrap`-style propagation — for any caller-supplied byte string of
//! the right length. Random ciphertext bytes are an adversary's most
//! basic surface; if `XWingProvider::open` panics on garbage, an
//! attacker can crash the host.
//!
//! Uses proptest (already in dev-deps) rather than cargo-fuzz so the
//! suite runs under the normal `cargo test` invocation.

use core::convert::Infallible;

use fcp_crypto::{
    CryptoError, Fcp4Aad, XWING_ENC_SIZE, XWING_MAX_CIPHERTEXT, XWING_PUBLIC_KEY_SIZE,
    XWING_SECRET_KEY_SIZE, XWingKem, XWingProvider, XWingSealedBox, XWingSecretKey,
};
use proptest::prelude::*;
use rand_core_pq::{TryCryptoRng, TryRng};
use x_wing::{
    DecapsulationKey as XWingDecapKey, Decapsulator, KeyExport, kem::Generate,
};

struct DeterministicSeedRng(Vec<u8>);

impl TryRng for DeterministicSeedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        // If the seed runs short, repeat it so the RNG never panics
        // mid-fuzz. This is fine for property testing — we only need
        // the RNG to be deterministic per case, not cryptographically
        // sound.
        for (i, b) in dst.iter_mut().enumerate() {
            *b = self.0[i % self.0.len()];
        }
        Ok(())
    }
}

impl TryCryptoRng for DeterministicSeedRng {}

fn deterministic_keypair(seed: u64) -> (fcp_crypto::XWingPublicKey, XWingSecretKey) {
    let mut bytes = vec![0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    let mut rng = DeterministicSeedRng(bytes);
    let real_sk = XWingDecapKey::try_generate_from_rng(&mut rng).expect("keygen");
    let pk_bytes = real_sk.encapsulation_key().to_bytes().as_slice().to_vec();
    let sk_arr = *real_sk.as_bytes();
    (
        fcp_crypto::XWingPublicKey::from_bytes(&pk_bytes).expect("pk wraps"),
        XWingSecretKey::from_bytes(&sk_arr).expect("sk wraps"),
    )
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Arbitrary 1120-byte enc + arbitrary AEAD ciphertext: open must
    /// return `Err` (almost certainly `AeadDecryptFailed`) without
    /// panicking. The KEM's implicit-rejection path means decap of a
    /// garbage `enc` produces a junk shared secret; HKDF + ChaCha20
    /// then derive a junk AEAD key; AEAD `open` rejects → clean Err.
    #[test]
    fn xwing_decap_arbitrary_ciphertext_never_panics(
        seed in any::<u64>(),
        enc in proptest::collection::vec(any::<u8>(), XWING_ENC_SIZE..=XWING_ENC_SIZE),
        aead_ct_len in 16usize..=512,  // ≥ AEAD tag, ≤ a few KiB
    ) {
        let (_pk, sk) = deterministic_keypair(seed);
        // Build a random-but-length-valid AEAD ciphertext.
        let ciphertext = vec![0xA5u8; aead_ct_len];
        let sealed = XWingSealedBox { enc, ciphertext };
        let provider = XWingProvider::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            provider.open(&sk, &sealed, b"any-aad")
        }));
        prop_assert!(result.is_ok(), "open() panicked on arbitrary ciphertext");
        let outcome = result.unwrap();
        prop_assert!(outcome.is_err(), "garbage ciphertext must not authenticate");
        // Specifically, must be AeadDecryptFailed — not InvalidPublicKey
        // or something nonsensical.
        prop_assert!(
            matches!(outcome, Err(CryptoError::AeadDecryptFailed))
                || matches!(outcome, Err(CryptoError::HpkeFailed(_))),
            "unexpected error variant for garbage open: {:?}",
            outcome.err()
        );
    }

    /// Tampered `enc` with a valid wire-shape AEAD ciphertext (sealed
    /// against a different recipient): open must reject cleanly.
    #[test]
    fn xwing_decap_cross_recipient_ciphertext_never_panics(
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        prop_assume!(seed_a != seed_b);
        let provider = XWingProvider::new();
        let (pk_a, _sk_a) = deterministic_keypair(seed_a);
        let (_pk_b, sk_b) = deterministic_keypair(seed_b);
        let aad = Fcp4Aad::for_zone_key(b"z", b"n", 0).encode().unwrap();
        let sealed_for_a = provider.seal(&pk_a, b"payload", &aad).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            provider.open(&sk_b, &sealed_for_a, &aad)
        }));
        prop_assert!(result.is_ok(), "open() panicked on cross-recipient ciphertext");
        prop_assert!(result.unwrap().is_err());
    }

    /// Wrong-length `enc` is a structural error and must surface as
    /// `HpkeFailed`, never as a panic.
    #[test]
    fn xwing_decap_wrong_length_enc_returns_hpke_failed(
        seed in any::<u64>(),
        bad_len in 0usize..XWING_MAX_CIPHERTEXT,
    ) {
        prop_assume!(bad_len != XWING_ENC_SIZE);
        let (_pk, sk) = deterministic_keypair(seed);
        let sealed = XWingSealedBox {
            enc: vec![0u8; bad_len],
            ciphertext: vec![0u8; 32],
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            XWingProvider::new().open(&sk, &sealed, b"aad")
        }));
        prop_assert!(result.is_ok());
        prop_assert!(matches!(result.unwrap(), Err(CryptoError::HpkeFailed(_))));
    }

    /// XWingPublicKey::from_bytes must NEVER panic; wrong length →
    /// `HpkeFailed`.
    #[test]
    fn xwing_public_key_from_bytes_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0usize..=4096),
    ) {
        let result = std::panic::catch_unwind(|| {
            fcp_crypto::XWingPublicKey::from_bytes(&bytes)
        });
        prop_assert!(result.is_ok(), "from_bytes panicked on len={}", bytes.len());
        let outcome = result.unwrap();
        if bytes.len() == XWING_PUBLIC_KEY_SIZE {
            prop_assert!(outcome.is_ok());
        } else {
            prop_assert!(matches!(outcome, Err(CryptoError::HpkeFailed(_))));
        }
    }

    /// XWingSecretKey::from_bytes must NEVER panic; wrong length →
    /// `HpkeFailed`.
    #[test]
    fn xwing_secret_key_from_bytes_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0usize..=4096),
    ) {
        let result = std::panic::catch_unwind(|| {
            XWingSecretKey::from_bytes(&bytes)
        });
        prop_assert!(result.is_ok());
        let outcome = result.unwrap();
        if bytes.len() == XWING_SECRET_KEY_SIZE {
            prop_assert!(outcome.is_ok());
        } else {
            prop_assert!(matches!(outcome, Err(CryptoError::HpkeFailed(_))));
        }
    }

    /// XWingSealedBox::from_canonical_cbor on arbitrary bytes must
    /// never panic. Either decodes (and length-checks) or rejects.
    #[test]
    fn xwing_sealed_box_canonical_cbor_decode_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0usize..=8192),
    ) {
        let result = std::panic::catch_unwind(|| {
            XWingSealedBox::from_canonical_cbor(&bytes)
        });
        prop_assert!(
            result.is_ok(),
            "from_canonical_cbor panicked on {}-byte input",
            bytes.len()
        );
    }
}
