#![no_main]

//! Fuzz target for `fcp_crypto::KeyId::derive_from_public_key` and
//! `try_from_slice` (kid.rs:35-72).
//!
//! `KeyId::derive_from_public_key` computes `BLAKE3(b"fcp.kid.v2" ||
//! pubkey)[..8]` — the 8-byte KID used in COSE headers for routing
//! verification + decryption. A regression that dropped the domain tag
//! `b"fcp.kid.v2"` would let `derive(p)` collide with raw
//! `BLAKE3(p)[..8]` (or any other unkeyed-BLAKE3 of the same input),
//! enabling cross-context KID collisions across primitives.
//!
//! Existing fcp-crypto fuzz coverage (crypto_hpke_open, x25519_dh,
//! ed25519_verify, crypto_shamir_reconstruct) does NOT touch the KID
//! derivation surface.
//!
//! Properties asserted:
//!
//!   1. **Determinism**: same pubkey ⇒ same KID.
//!   2. **Bit-level injectivity**: distinct pubkey bytes MUST produce
//!      distinct KIDs (modulo the 1-in-2^64 truncation collision space,
//!      which is statistically inaccessible to fuzzer-generated inputs).
//!   3. **try_from_slice length gate**: any non-8-byte slice MUST yield
//!      InvalidKeyLength.
//!   4. **try_from_slice + as_bytes identity**: an 8-byte slice
//!      reconstitutes to a KID with those bytes.
//!   5. **from_hex/to_hex round-trip**: identity for any constructed KID.
//!   6. **Hex case insensitivity**: from_hex(lowercase) == from_hex(uppercase).
//!   7. **Stable length**: KID is always 8 bytes.
//!
//!   Once-gated regression anchors:
//!     (a) Domain-tag binding: derive(b"") MUST NOT equal the well-
//!         known BLAKE3(b"")[..8] = af 13 49 b9 f5 f9 a1 a6 (which is
//!         what the regression that drops the b"fcp.kid.v2" prefix
//!         would produce).
//!     (b) try_from_slice on length 0, 7, 9 MUST trip InvalidKeyLength.

use arbitrary::{Arbitrary, Unstructured};
use fcp_crypto::{CryptoError, KeyId};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const KID_SIZE: usize = 8;

static KID_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    pubkey_a: Vec<u8>,
    pubkey_b: Vec<u8>,
    /// Slice we feed to try_from_slice — may have any length.
    arbitrary_slice: Vec<u8>,
}

const MAX_PUBKEY_LEN: usize = 4 * 1024;

fuzz_target!(|data: &[u8]| {
    KID_ANCHOR.call_once(assert_kid_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    if input.pubkey_a.len() > MAX_PUBKEY_LEN || input.pubkey_b.len() > MAX_PUBKEY_LEN {
        return;
    }

    // ── PROPERTY 1: determinism ──────────────────────────────────────
    let kid_a1 = KeyId::derive_from_public_key(&input.pubkey_a);
    let kid_a2 = KeyId::derive_from_public_key(&input.pubkey_a);
    assert_eq!(
        kid_a1, kid_a2,
        "KeyId::derive_from_public_key not deterministic"
    );

    // ── PROPERTY 7: stable length ────────────────────────────────────
    assert_eq!(
        kid_a1.as_bytes().len(),
        KID_SIZE,
        "KID byte length not equal to KID_SIZE={KID_SIZE}"
    );

    // ── PROPERTY 2: bit-level injectivity ────────────────────────────
    if input.pubkey_a != input.pubkey_b {
        let kid_b = KeyId::derive_from_public_key(&input.pubkey_b);
        assert_ne!(
            kid_a1, kid_b,
            "distinct pubkeys produced identical KIDs — derivation collision; \
             cross-key routing would attribute a verify failure to the wrong key"
        );
    }

    // ── PROPERTY 3+4: try_from_slice length gate ─────────────────────
    let result = KeyId::try_from_slice(&input.arbitrary_slice);
    if input.arbitrary_slice.len() == KID_SIZE {
        let kid = result.expect("8-byte slice MUST be accepted");
        assert_eq!(
            kid.as_bytes().as_slice(),
            input.arbitrary_slice.as_slice(),
            "try_from_slice + as_bytes did not round-trip"
        );
    } else {
        match result {
            Err(CryptoError::InvalidKeyLength { expected, actual }) => {
                assert_eq!(expected, KID_SIZE);
                assert_eq!(actual, input.arbitrary_slice.len());
            }
            Err(other) => panic!(
                "wrong-length slice ({}) returned {other:?}; expected InvalidKeyLength",
                input.arbitrary_slice.len()
            ),
            Ok(_) => panic!(
                "non-8-byte slice (len={}) was accepted by try_from_slice",
                input.arbitrary_slice.len()
            ),
        }
    }

    // ── PROPERTY 5: from_hex/to_hex round-trip ───────────────────────
    let hex = kid_a1.to_hex();
    let parsed = KeyId::from_hex(&hex).expect("from_hex(to_hex(kid)) MUST succeed");
    assert_eq!(parsed, kid_a1, "from_hex(to_hex) round-trip lost bytes");

    // ── PROPERTY 6: hex case insensitivity ───────────────────────────
    let upper = hex.to_uppercase();
    let parsed_upper = KeyId::from_hex(&upper).expect("uppercase hex MUST parse");
    assert_eq!(parsed_upper, kid_a1, "from_hex case-insensitivity broken");
});

/// Once-gated regression anchors for the most load-bearing KID
/// invariants.
fn assert_kid_anchored() {
    // (a) Domain-tag binding: a regression that drops the b"fcp.kid.v2"
    // prefix from BLAKE3 would let derive(b"") collide with the
    // well-known BLAKE3(b"") = af1349b9 f5f9a1a6 ... [..8].
    //
    // We hardcode the unprefixed-BLAKE3-of-empty first 8 bytes and assert
    // derive(b"") MUST NOT equal them. If a regression drops the domain
    // tag, this anchor trips on every fuzz invocation.
    const BLAKE3_EMPTY_PREFIX_8: [u8; 8] = [0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6];

    let kid_empty = KeyId::derive_from_public_key(b"");
    assert_ne!(
        kid_empty.as_bytes(),
        &BLAKE3_EMPTY_PREFIX_8,
        "ANCHOR REGRESSION: KeyId::derive_from_public_key(b\"\") == BLAKE3(b\"\")[..8] \
         — the b\"fcp.kid.v2\" domain tag has been dropped from kid.rs:35-43; \
         KIDs would now collide with raw BLAKE3 hashes from any other unkeyed \
         use, enabling cross-context routing collisions."
    );

    // The KID for empty input must still be deterministic and 8 bytes.
    let kid_empty2 = KeyId::derive_from_public_key(b"");
    assert_eq!(
        kid_empty, kid_empty2,
        "ANCHOR: derive(b\"\") not deterministic"
    );
    assert_eq!(kid_empty.as_bytes().len(), KID_SIZE);

    // (b) try_from_slice length gate edges.
    for bad_len in [0usize, 1, 7, 9, 16, 32] {
        let bad = vec![0x42u8; bad_len];
        match KeyId::try_from_slice(&bad) {
            Err(CryptoError::InvalidKeyLength { expected, actual }) => {
                assert_eq!(
                    expected, KID_SIZE,
                    "ANCHOR: try_from_slice expected field wrong"
                );
                assert_eq!(
                    actual, bad_len,
                    "ANCHOR: try_from_slice actual field wrong for len={bad_len}"
                );
            }
            Err(other) => panic!("ANCHOR: try_from_slice(len={bad_len}) returned {other:?}"),
            Ok(_) => panic!(
                "ANCHOR REGRESSION: try_from_slice accepted non-8-byte slice \
                 (len={bad_len}) — KID length gate broken; routing layer could \
                 dispatch on a malformed KID"
            ),
        }
    }

    // 8-byte slice MUST round-trip cleanly.
    let exact = [0xCDu8; KID_SIZE];
    let kid = KeyId::try_from_slice(&exact).expect("ANCHOR: 8-byte slice MUST be accepted");
    assert_eq!(
        kid.as_bytes(),
        &exact,
        "ANCHOR: try_from_slice + as_bytes round-trip broken"
    );
}
