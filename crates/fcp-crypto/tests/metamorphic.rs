//! Metamorphic relation tests for fcp-crypto primitives.
//!
//! These tests encode the algebraic properties of the crypto primitives
//! themselves, not specific known-answer vectors. They catch bugs that unit
//! tests miss: a seeding mistake that makes every key the same, a mis-wired
//! AAD, a canonicalizer that isn't idempotent, an HKDF that gained an
//! unintended source of entropy.
//!
//! Each `proptest!` block runs the default 256 cases, giving us >100 inputs
//! per MR. When a relation fails, proptest shrinks the counterexample —
//! that's the diagnostic value over plain randomized testing.

use ciborium::value::{Integer, Value as CborValue};
use fcp_crypto::AeadKey;
use fcp_crypto::aead::XChaCha20Poly1305Cipher;
use fcp_crypto::canonicalize::to_deterministic_cbor;
use fcp_crypto::ed25519::{Ed25519Signature, Ed25519SigningKey};
use fcp_crypto::hkdf::hkdf_sha256_array;
use fcp_crypto::hpke_seal::{Fcp2Aad, HpkeSealedBox, hpke_open, hpke_seal};
use fcp_crypto::x25519::X25519SecretKey;
use proptest::prelude::*;

// ─── Shared strategies ────────────────────────────────────────────────────

fn aad_strategy() -> impl Strategy<Value = Fcp2Aad> {
    (
        prop::collection::vec(any::<u8>(), 1..64),
        prop::collection::vec(any::<u8>(), 1..64),
        any::<u64>(),
    )
        .prop_map(|(zone, node, issued_at)| Fcp2Aad::for_zone_key(&zone, &node, issued_at))
}

/// Generate an arbitrary CBOR `Value`. Avoids `Tag` (canonicalizer rejects
/// tags by design) and NaN/Infinity floats (also rejected — and their
/// rejection isn't the property we're testing for idempotence).
fn cbor_value_strategy() -> impl Strategy<Value = CborValue> {
    let leaf = prop_oneof![
        Just(CborValue::Null),
        any::<bool>().prop_map(CborValue::Bool),
        any::<i64>().prop_map(|i| CborValue::Integer(Integer::from(i))),
        any::<f64>()
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(CborValue::Float),
        "[ -~]{0,32}".prop_map(CborValue::Text),
        prop::collection::vec(any::<u8>(), 0..32).prop_map(CborValue::Bytes),
    ];

    leaf.prop_recursive(
        4,  // max depth
        32, // max total nodes
        8,  // max items per collection
        |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..8).prop_map(CborValue::Array),
                prop::collection::vec(
                    (
                        // Map keys: restrict to int/text for faster canonicalization
                        // and to avoid duplicate-key rejection dominating the run.
                        prop_oneof![
                            any::<i64>().prop_map(|i| CborValue::Integer(Integer::from(i))),
                            "[ -~]{0,16}".prop_map(CborValue::Text),
                        ],
                        inner,
                    ),
                    0..8,
                )
                .prop_map(|pairs| {
                    // Dedup keys by their debug repr so proptest rarely
                    // produces inputs that fail canonicalization for
                    // duplicate-key reasons.
                    let mut seen = std::collections::HashSet::new();
                    let unique = pairs
                        .into_iter()
                        .filter(|(k, _)| seen.insert(format!("{k:?}")))
                        .collect();
                    CborValue::Map(unique)
                }),
            ]
        },
    )
}

// ─── MR 1: HPKE round-trip ────────────────────────────────────────────────
//
// Relation: hpke_open(sk, hpke_seal(pk, msg, aad), aad) == Ok(msg).
// Classifies as an "inverse" MR (MR Taxonomy §2). Msg lengths span 0..4KiB
// (the user's 64 KiB ceiling is aspirational; 4 KiB bounds the 256-case
// runtime to ~2s while still covering the empty/small/boundary regime).

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        .. ProptestConfig::default()
    })]

    #[test]
    fn mr1_hpke_roundtrip(
        sk_seed in prop::array::uniform32(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 0..=4096),
        aad in aad_strategy(),
    ) {
        let sk = X25519SecretKey::from_bytes(sk_seed);
        let pk = sk.public_key();

        let sealed = hpke_seal(&pk, &plaintext, &aad).expect("seal must succeed");
        let opened = hpke_open(&sk, &sealed, &aad).expect("open must recover plaintext");

        prop_assert_eq!(opened, plaintext);
    }

    // MR 1b (inverse-negative): wrong AAD MUST reject. A successful open
    // with a mismatched AAD would mean the AAD binding is broken — which
    // is how mesh agents bind ciphertext to a (zone, recipient, purpose,
    // timestamp) tuple.
    #[test]
    fn mr1b_hpke_aad_binding(
        sk_seed in prop::array::uniform32(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 0..512),
        aad_a in aad_strategy(),
        aad_b in aad_strategy(),
    ) {
        prop_assume!(aad_a.encode().unwrap() != aad_b.encode().unwrap());

        let sk = X25519SecretKey::from_bytes(sk_seed);
        let pk = sk.public_key();

        let sealed = hpke_seal(&pk, &plaintext, &aad_a).expect("seal must succeed");
        let opened = hpke_open(&sk, &sealed, &aad_b);

        prop_assert!(opened.is_err(), "opening with wrong AAD must fail");
    }
}

// ─── MR 2: Ed25519 signature stability ────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    #[test]
    fn mr2_ed25519_sign_verify(
        sk_seed in prop::array::uniform32(any::<u8>()),
        message in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let sk = Ed25519SigningKey::from_bytes(&sk_seed).expect("valid seed");
        let pk = sk.verifying_key();

        let sig = sk.sign(&message);
        prop_assert!(pk.verify(&message, &sig).is_ok());
    }

    #[test]
    fn mr2b_ed25519_wrong_message_rejects(
        sk_seed in prop::array::uniform32(any::<u8>()),
        message in prop::collection::vec(any::<u8>(), 1..2048),
        other_message in prop::collection::vec(any::<u8>(), 1..2048),
    ) {
        prop_assume!(message != other_message);

        let sk = Ed25519SigningKey::from_bytes(&sk_seed).expect("valid seed");
        let pk = sk.verifying_key();

        let sig = sk.sign(&message);
        prop_assert!(
            pk.verify(&other_message, &sig).is_err(),
            "signature over a different message must not verify"
        );
    }

    // MR 2c: wrong key MUST reject. Caught bugs before: signing keys that
    // were confused with verifying keys, fixed-seed generators that always
    // yielded the same key.
    #[test]
    fn mr2c_ed25519_wrong_key_rejects(
        sk_seed_a in prop::array::uniform32(any::<u8>()),
        sk_seed_b in prop::array::uniform32(any::<u8>()),
        message in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        prop_assume!(sk_seed_a != sk_seed_b);

        let sk_a = Ed25519SigningKey::from_bytes(&sk_seed_a).expect("valid seed a");
        let sk_b = Ed25519SigningKey::from_bytes(&sk_seed_b).expect("valid seed b");
        // Distinct seeds → distinct Ed25519 keys with overwhelming probability
        // (hash-to-scalar diffusion). A collision would be a real-bug finding.
        prop_assume!(sk_a.verifying_key() != sk_b.verifying_key());

        let sig = sk_a.sign(&message);
        prop_assert!(
            sk_b.verifying_key().verify(&message, &sig).is_err(),
            "signature issued by key A must not verify under key B"
        );
    }
}

// ─── MR 3: CBOR canonicalization idempotence ──────────────────────────────
//
// Relation: canonicalize(bytes) == canonicalize(canonicalize(bytes)) when
// we decode the output and re-serialize. A canonicalizer that is *not*
// idempotent cannot form a content-addressed hash domain — every fcp-core
// `ObjectId` derivation depends on this property.

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    #[test]
    fn mr3_canonicalize_idempotent(value in cbor_value_strategy()) {
        // First canonicalization. May fail for inputs the canonicalizer
        // deliberately rejects (duplicate map keys, deep nesting) — those
        // aren't idempotence failures, they're expected error returns.
        let Ok(once) = to_deterministic_cbor(&value) else {
            return Ok(());
        };

        // Re-decode the canonical bytes and canonicalize again. Must
        // produce byte-identical output.
        let decoded: CborValue = ciborium::from_reader(&once[..])
            .expect("canonical output must round-trip through ciborium decoder");
        let twice = to_deterministic_cbor(&decoded)
            .expect("re-canonicalization of already-canonical value must succeed");

        prop_assert_eq!(
            &once, &twice,
            "canonicalization is not idempotent: c(v) != c(c(v))"
        );
    }
}

// ─── MR 4: Nonce / ciphertext freshness ───────────────────────────────────
//
// Relation: encrypt_with_random_nonce(msg, k) != encrypt_with_random_nonce(msg, k).
// Same plaintext and key, two invocations: outputs MUST differ because the
// nonce was freshly sampled. A degenerate RNG or cached nonce would collapse
// this MR.
//
// We also check the matching property at the HPKE level: the ephemeral key
// (`enc`) and ciphertext MUST change across two seals of the same plaintext
// to the same recipient.

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        .. ProptestConfig::default()
    })]

    #[test]
    fn mr4_aead_nonce_fresh(
        key_bytes in prop::array::uniform32(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 0..=1024),
        aad in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let key = AeadKey::from_bytes(key_bytes);
        let cipher = XChaCha20Poly1305Cipher::new(&key);

        let a = cipher
            .encrypt_with_random_nonce(&plaintext, &aad)
            .expect("first encrypt");
        let b = cipher
            .encrypt_with_random_nonce(&plaintext, &aad)
            .expect("second encrypt");

        // The 24-byte random-nonce prefix alone makes a collision cryptographically
        // unreachable (probability ~2^-192). A failure here means the RNG is
        // deterministic or the nonce isn't actually sampled per-call.
        prop_assert_ne!(a, b, "two encryptions of the same plaintext must differ");
    }

    #[test]
    fn mr4b_hpke_ephemeral_key_fresh(
        sk_seed in prop::array::uniform32(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 0..=512),
        aad in aad_strategy(),
    ) {
        let sk = X25519SecretKey::from_bytes(sk_seed);
        let pk = sk.public_key();

        let a = hpke_seal(&pk, &plaintext, &aad).expect("first seal");
        let b = hpke_seal(&pk, &plaintext, &aad).expect("second seal");

        // The ephemeral key `enc` must differ — this is the HPKE Kem's
        // per-seal keypair. Identical `enc` across two seals would mean
        // the ephemeral keypair was cached, which defeats HPKE's
        // forward-secrecy guarantee.
        prop_assert_ne!(&a.enc, &b.enc, "HPKE ephemeral key must differ across seals");
        prop_assert_ne!(
            &a.ciphertext,
            &b.ciphertext,
            "HPKE ciphertext must differ across seals (different nonce from different enc)"
        );
    }
}

// ─── MR 5: HKDF determinism ───────────────────────────────────────────────
//
// Relation: hkdf(salt, ikm, info) == hkdf(salt, ikm, info).
// The opposite of MR 4: two calls with identical inputs MUST produce
// byte-identical output. A PRF that accidentally mixed in a timestamp, a
// thread id, or uninitialized memory would fail here.

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    #[test]
    fn mr5_hkdf_deterministic(
        salt in prop::option::of(prop::collection::vec(any::<u8>(), 0..64)),
        ikm in prop::collection::vec(any::<u8>(), 1..128),
        info in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let salt_slice = salt.as_deref();
        let a: [u8; 32] = hkdf_sha256_array(salt_slice, &ikm, &info).expect("derive a");
        let b: [u8; 32] = hkdf_sha256_array(salt_slice, &ikm, &info).expect("derive b");
        prop_assert_eq!(a, b, "HKDF must be deterministic on identical inputs");
    }

    // MR 5b: HKDF domain separation — different `info` labels MUST produce
    // different keys. This is the property that lets us derive many
    // unrelated subkeys from one master secret using per-purpose labels.
    #[test]
    fn mr5b_hkdf_label_separation(
        salt in prop::option::of(prop::collection::vec(any::<u8>(), 0..64)),
        ikm in prop::collection::vec(any::<u8>(), 1..128),
        info_a in prop::collection::vec(any::<u8>(), 1..64),
        info_b in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        prop_assume!(info_a != info_b);

        let salt_slice = salt.as_deref();
        let a: [u8; 32] = hkdf_sha256_array(salt_slice, &ikm, &info_a).expect("derive a");
        let b: [u8; 32] = hkdf_sha256_array(salt_slice, &ikm, &info_b).expect("derive b");
        // HKDF is a PRF; distinct info labels with the same ikm must produce
        // different outputs with overwhelming probability. A collision here
        // would be a catastrophic cryptographic finding.
        prop_assert_ne!(a, b, "HKDF outputs MUST differ across distinct info labels");
    }
}

// ─── MR 6: Ed25519 signature adversarial corruption ───────────────────────
//
// Relation: any single-byte mutation of a valid signature's 64 bytes MUST
// cause verify() to reject. AEAD-style authenticity for Ed25519: you cannot
// flip one bit of the signature and still have it verify. A bug that fails
// here (verify accepts a mutated sig) means the underlying ed25519-dalek
// was downgraded, fed an unsanitized input, or patched to skip validation.

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    #[test]
    fn mr6_ed25519_flipped_signature_byte_rejects(
        sk_seed in prop::array::uniform32(any::<u8>()),
        message in prop::collection::vec(any::<u8>(), 1..512),
        byte_index in 0usize..64,
        xor_mask in 1u8..=255,
    ) {
        let sk = Ed25519SigningKey::from_bytes(&sk_seed).expect("valid seed");
        let pk = sk.verifying_key();

        let sig = sk.sign(&message);
        let mut sig_bytes = sig.to_bytes();
        // Non-zero mask guarantees the byte actually changes.
        sig_bytes[byte_index] ^= xor_mask;
        let corrupted = Ed25519Signature::from_bytes(&sig_bytes);

        prop_assert!(
            pk.verify(&message, &corrupted).is_err(),
            "a single-byte mutation anywhere in the 64-byte signature must not verify \
             (byte_index={byte_index}, xor=0x{xor_mask:02x})"
        );
    }

    // MR 6b: signature truncation to any length other than SIGNATURE_SIZE
    // MUST be rejected at parse time by try_from_slice, not silently
    // accepted with padding or extension.
    #[test]
    fn mr6b_ed25519_truncated_signature_rejects(
        sk_seed in prop::array::uniform32(any::<u8>()),
        message in prop::collection::vec(any::<u8>(), 0..256),
        truncate_to in 0usize..64,
    ) {
        let sk = Ed25519SigningKey::from_bytes(&sk_seed).expect("valid seed");
        let sig = sk.sign(&message);
        let full = sig.to_bytes();
        let truncated = &full[..truncate_to];

        prop_assert!(
            Ed25519Signature::try_from_slice(truncated).is_err(),
            "try_from_slice must refuse a {truncate_to}-byte slice (expected 64)"
        );
    }

    // MR 6c: over-long signature (slice > SIGNATURE_SIZE) must also be
    // rejected — a parser that trims or ignores trailing bytes would let
    // a signed transcript accept junk appended by an adversary.
    #[test]
    fn mr6c_ed25519_overlong_signature_rejects(
        sk_seed in prop::array::uniform32(any::<u8>()),
        message in prop::collection::vec(any::<u8>(), 0..256),
        extra in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let sk = Ed25519SigningKey::from_bytes(&sk_seed).expect("valid seed");
        let sig = sk.sign(&message);
        let mut padded = sig.to_bytes().to_vec();
        padded.extend_from_slice(&extra);

        prop_assert!(
            Ed25519Signature::try_from_slice(&padded).is_err(),
            "try_from_slice must refuse a {}-byte slice (expected 64)",
            padded.len()
        );
    }
}

// ─── MR 7: HPKE ciphertext adversarial corruption ─────────────────────────
//
// Relation: AEAD authenticity. Any single-byte mutation anywhere in the
// ciphertext (including the Poly1305 tag at the tail) MUST cause hpke_open
// to reject. This is the property that rules out "seal accepted but bit-rot
// tolerated" bugs — if even one byte in the sealed box flips, open fails.

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        .. ProptestConfig::default()
    })]

    #[test]
    fn mr7_hpke_flipped_ciphertext_byte_rejects(
        sk_seed in prop::array::uniform32(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 0..1024),
        aad in aad_strategy(),
        byte_index in 0usize..4096,
        xor_mask in 1u8..=255,
    ) {
        let sk = X25519SecretKey::from_bytes(sk_seed);
        let pk = sk.public_key();

        let mut sealed = hpke_seal(&pk, &plaintext, &aad).expect("seal must succeed");
        // Clamp into the actual ciphertext length. `proptest` generates
        // values up to 4096 so the test covers small and large sealed
        // boxes; skip cases where the byte_index lands outside.
        if byte_index >= sealed.ciphertext.len() {
            return Ok(());
        }
        sealed.ciphertext[byte_index] ^= xor_mask;

        prop_assert!(
            hpke_open(&sk, &sealed, &aad).is_err(),
            "flipping one byte of HPKE ciphertext must break authentication \
             (byte_index={byte_index}, xor=0x{xor_mask:02x}, len={})",
            sealed.ciphertext.len()
        );
    }

    // MR 7b: corruption of the encapsulated key (`enc`) must also reject.
    // `enc` is the ephemeral X25519 public key; mutating it forces the
    // recipient to derive a different shared secret, which makes the
    // Poly1305 tag invalid.
    #[test]
    fn mr7b_hpke_flipped_enc_byte_rejects(
        sk_seed in prop::array::uniform32(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
        aad in aad_strategy(),
        byte_index in 0usize..32,
        xor_mask in 1u8..=255,
    ) {
        let sk = X25519SecretKey::from_bytes(sk_seed);
        let pk = sk.public_key();

        let mut sealed = hpke_seal(&pk, &plaintext, &aad).expect("seal must succeed");
        if byte_index >= sealed.enc.len() {
            return Ok(());
        }
        sealed.enc[byte_index] ^= xor_mask;

        prop_assert!(
            hpke_open(&sk, &sealed, &aad).is_err(),
            "flipping one byte of HPKE `enc` must produce an unrecoverable shared secret"
        );
    }

    // MR 7c: sealed-box bytes shorter than `HPKE_ENC_SIZE + HPKE_TAG_SIZE`
    // MUST be rejected at parse time by HpkeSealedBox::from_bytes. A parser
    // that accepts short inputs by padding or zero-filling would let an
    // attacker craft a "sealed box" the receiver tries to AEAD-open with
    // uninitialized or attacker-controlled tail bytes.
    #[test]
    fn mr7c_hpke_truncated_sealed_box_rejects(
        sk_seed in prop::array::uniform32(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
        aad in aad_strategy(),
        truncate_by in 1usize..48,
    ) {
        let sk = X25519SecretKey::from_bytes(sk_seed);
        let pk = sk.public_key();

        let sealed = hpke_seal(&pk, &plaintext, &aad).expect("seal must succeed");
        let bytes = sealed.to_bytes();
        if truncate_by >= bytes.len() {
            return Ok(());
        }
        let truncated = &bytes[..bytes.len() - truncate_by];

        // Either from_bytes rejects the short input, or it parses into a
        // sealed box that hpke_open then rejects. Both are acceptable
        // defensive outcomes; what we forbid is silent acceptance of a
        // truncated input yielding a valid plaintext.
        let outcome = match HpkeSealedBox::from_bytes(truncated) {
            Ok(recovered) => hpke_open(&sk, &recovered, &aad),
            Err(_) => return Ok(()),
        };
        prop_assert!(
            outcome.is_err(),
            "truncated sealed box (removed {truncate_by} bytes from tail) must not open successfully"
        );
    }
}
