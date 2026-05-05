//! IETF X-Wing draft test-vector harness (br-kyopb.1.2.1).
//!
//! Replays the normative test vectors from
//! `draft-connolly-cfrg-xwing-kem` against our [`XWingProvider`] and the
//! upstream `x-wing` crate's lower-level seed-driven API. The vectors are
//! vendored under `tests/data/xwing_test_vectors.json` and were fetched
//! from the official spec repository on 2026-05-02.
//!
//! What we check
//! -------------
//!
//! 1. **Vendor-impl conformance** (`x_wing_kat_upstream_seed_driven`):
//!    Drives the `x-wing` crate's `generate_keypair_from_rng` with each
//!    vector's `seed`, then `encapsulate_with_rng` with each vector's
//!    `eseed`, and confirms the resulting `sk` / `pk` / `ct` / `ss` bytes
//!    match the published draft expectations bit-for-bit. This is the
//!    "KAT" pin against the IETF spec.
//!
//! 2. **FCP-provider round-trip** (`x_wing_kat_fcp_provider_round_trips`):
//!    Reconstructs the keypair from each vector's `sk` seed, seals a
//!    payload with the FCP-shaped [`XWingProvider`] API, and confirms it
//!    opens with the matching secret. Proves the FCP wrapper does not
//!    drift from the upstream wire format.
//!
//! Both tests live in the same file so a single
//! `cargo test -p fcp-crypto x_wing_kat` invocation runs the full
//! conformance set, matching the user-facing acceptance command for this
//! sub-bead.

use core::convert::Infallible;

use fcp_crypto::{XWING_ENC_SIZE, XWING_SECRET_KEY_SIZE, XWingKem, XWingProvider, XWingPublicKey};
use serde::Deserialize;
use x_wing::{Decapsulate, DecapsulationKey, Decapsulator, Encapsulate, KeyExport, kem::Generate};

#[derive(Debug, Deserialize)]
struct TestVector {
    /// 32-byte hex seed for keygen (`generate_keypair_from_rng` input).
    #[serde(with = "hex::serde")]
    seed: Vec<u8>,
    /// 64-byte hex seed for encap randomness (`encapsulate_with_rng` input).
    #[serde(with = "hex::serde")]
    eseed: Vec<u8>,
    /// 32-byte expected shared secret.
    #[serde(with = "hex::serde")]
    ss: Vec<u8>,
    /// 32-byte expected secret key (compressed seed form, draft 06).
    #[serde(with = "hex::serde")]
    sk: Vec<u8>,
    /// 1216-byte expected encapsulation key.
    #[serde(with = "hex::serde")]
    pk: Vec<u8>,
    /// 1120-byte expected ciphertext.
    #[serde(with = "hex::serde")]
    ct: Vec<u8>,
}

/// `getrandom`-free RNG that simply emits a pre-baked seed buffer.
///
/// The X-Wing crate consumes randomness incrementally; this RNG hands out
/// successive bytes from `seed` until it runs out (after which the test
/// fails loudly via `expect`). Matches the pattern the upstream `x-wing`
/// crate uses in its own KAT harness.
struct SeedRng {
    seed: Vec<u8>,
}

impl SeedRng {
    fn new(seed: &[u8]) -> Self {
        Self {
            seed: seed.to_vec(),
        }
    }
}

impl rand_core_pq::TryRng for SeedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.try_fill_bytes(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.try_fill_bytes(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        assert!(
            dst.len() <= self.seed.len(),
            "X-Wing KAT SeedRng exhausted: needed {} bytes, had {}",
            dst.len(),
            self.seed.len()
        );
        let drained: Vec<u8> = self.seed.drain(..dst.len()).collect();
        dst.copy_from_slice(&drained);
        Ok(())
    }
}

impl rand_core_pq::TryCryptoRng for SeedRng {}

fn vectors() -> Vec<TestVector> {
    let raw = include_str!("data/xwing_test_vectors.json");
    serde_json::from_str(raw).expect("xwing_test_vectors.json must parse as Vec<TestVector>")
}

#[test]
fn x_wing_kat_upstream_seed_driven() {
    let vectors = vectors();
    assert!(
        !vectors.is_empty(),
        "vendored test vectors file must contain at least one entry"
    );

    for (i, v) in vectors.iter().enumerate() {
        // 1. Re-derive the keypair from the published seed.
        let mut keygen_rng = SeedRng::new(&v.seed);
        let real_sk = DecapsulationKey::try_generate_from_rng(&mut keygen_rng)
            .expect("upstream keygen with SeedRng must succeed");

        assert_eq!(
            real_sk.as_bytes().as_slice(),
            v.sk.as_slice(),
            "vector #{i}: derived sk diverges from spec expectation"
        );
        let pk_bytes = real_sk.encapsulation_key().to_bytes();
        assert_eq!(
            pk_bytes.as_slice(),
            v.pk.as_slice(),
            "vector #{i}: derived pk diverges from spec expectation"
        );

        // 2. Re-derive the encapsulation from the published encap seed.
        let mut encap_rng = SeedRng::new(&v.eseed);
        let (ct, ss) = real_sk
            .encapsulation_key()
            .encapsulate_with_rng(&mut encap_rng);
        let ss_bytes: [u8; 32] = ss.into();
        assert_eq!(
            ct.as_slice(),
            v.ct.as_slice(),
            "vector #{i}: encap ciphertext diverges from spec expectation"
        );
        assert_eq!(
            ss_bytes.as_slice(),
            v.ss.as_slice(),
            "vector #{i}: encap shared secret diverges from spec expectation"
        );

        // 3. Decapsulate and confirm the same shared secret falls out.
        let ss_dec = real_sk.decapsulate(&ct);
        let ss_dec_bytes: [u8; 32] = ss_dec.into();
        assert_eq!(
            ss_dec_bytes.as_slice(),
            v.ss.as_slice(),
            "vector #{i}: decap shared secret diverges from spec expectation"
        );
    }
}

#[test]
fn x_wing_kat_fcp_provider_round_trips() {
    // For each spec vector: rebuild the keypair from the spec sk (32 B
    // seed), then exercise the FCP-shaped seal/open round trip on top of
    // it. This proves XWingProvider's wire form aligns with the upstream
    // (and therefore with the IETF draft) without a separate sealed-box
    // KAT.
    let vectors = vectors();
    let provider = XWingProvider::new();

    for (i, v) in vectors.iter().enumerate() {
        assert_eq!(
            v.sk.len(),
            XWING_SECRET_KEY_SIZE,
            "vector #{i} sk wrong size"
        );
        assert_eq!(v.ct.len(), XWING_ENC_SIZE, "vector #{i} ct wrong size");

        // Reconstruct the upstream sk from the spec-published seed and
        // pull its encapsulation key out for the FCP provider to seal to.
        let sk_arr = <[u8; XWING_SECRET_KEY_SIZE]>::try_from(v.sk.as_slice())
            .expect("vector sk is exactly XWING_SECRET_KEY_SIZE");
        let real_sk: DecapsulationKey = sk_arr.into();
        let pk_bytes = real_sk.encapsulation_key().to_bytes();
        let wrapped_public_key =
            XWingPublicKey::from_bytes(&pk_bytes).expect("upstream pk has correct size");
        assert_eq!(
            wrapped_public_key.as_bytes(),
            v.pk.as_slice(),
            "vector #{i}: FCP-wrapped pk diverges from spec"
        );

        let plaintext = b"FCP V4 KAT round-trip payload";
        let aad = format!("xwing-kat-vector-{i}");
        let sealed = provider
            .seal(&wrapped_public_key, plaintext, aad.as_bytes())
            .expect("seal must succeed against spec-derived pk");
        assert_eq!(
            sealed.enc.len(),
            XWING_ENC_SIZE,
            "vector #{i}: sealed.enc has wrong size"
        );

        let wrapped_secret_key = fcp_crypto::XWingSecretKey::from_bytes(&v.sk)
            .expect("vector sk wraps into XWingSecretKey");
        let opened = provider
            .open(&wrapped_secret_key, &sealed, aad.as_bytes())
            .expect("open must succeed with matching sk + aad");
        assert_eq!(opened.as_slice(), plaintext);
    }
}

/// Sanity check on _the harness itself_: the bundled file must contain
/// the canonical 3-vector draft set and parse with the sizes the spec
/// declares. If this test fails, someone replaced the JSON with the wrong
/// corpus and the conformance tests above would silently pass against
/// nothing.
#[test]
fn x_wing_kat_harness_loads_three_canonical_vectors() {
    let vs = vectors();
    assert_eq!(
        vs.len(),
        3,
        "draft-connolly-cfrg-xwing-kem ships 3 normative vectors"
    );
    for v in &vs {
        assert_eq!(v.seed.len(), 32);
        assert_eq!(v.eseed.len(), 64);
        assert_eq!(v.ss.len(), 32);
        assert_eq!(v.sk.len(), 32);
        assert_eq!(v.pk.len(), 1216);
        assert_eq!(v.ct.len(), 1120);
    }
}
