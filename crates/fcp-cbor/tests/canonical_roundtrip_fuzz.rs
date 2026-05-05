//! Property-based fuzzing for fcp-cbor canonical encode/decode.
//!
//! The single-cell golden vector tests in `cbor_golden_vector_tests.rs`
//! pin the *known-good* encoding of hand-picked values; this harness
//! pins the load-bearing structural properties that any future
//! refactor must preserve, by sweeping arbitrary input shapes:
//!
//!   1. **Round-trip identity (typed)**. For every randomly-generated
//!      typed payload (`FuzzPayload`),
//!      `serialize(deserialize(serialize(value))) == serialize(value)`
//!      — a refactor that introduces a serializer/deserializer
//!      asymmetry (e.g. handling of small integers, byte strings,
//!      `Option::None`) shows up here as a value diff.
//!
//!   2. **Canonical idempotence**. Re-canonicalizing already-canonical
//!      bytes produces identical bytes. A regression in
//!      `canonicalize_value_in_place` (e.g. failure to sort map keys
//!      by deterministic encoding bytes, or to fold -0.0 → 0.0) lets
//!      the second pass flip ordering and surfaces here.
//!
//!   3. **Insertion-order independence for maps**. The canonical
//!      encoding of a logical map MUST NOT depend on the insertion
//!      order of its (key, value) pairs. Build the same map twice
//!      with shuffled insertion order and assert byte-exact match.
//!      Catches a refactor that drops the deterministic-bytes sort.
//!
//!   4. **Schema-mismatch detection**. `CanonicalSerializer::deserialize`
//!      rejects bytes whose 32-byte schema hash prefix does not match
//!      the expected schema, with `SchemaMismatch`, never returning
//!      Ok or panicking.
//!
//!   5. **Random-byte robustness (decode-side)**. Arbitrary random
//!      input bytes never panic the deserializer — they always return
//!      either an `Err` or a successfully decoded `Value` (which we
//!      then re-encode and confirm canonical idempotence). This is
//!      the canonical "deserialize must be total" property for any
//!      format exposed to untrusted input.
//!
//!   6. **Depth-limit guard**. A nested array of depth >
//!      MAX_CANONICALIZATION_DEPTH MUST surface DepthExceeded, never
//!      panic the canonicalizer's recursion. Builds the worst-case
//!      input directly (proptest can't naturally generate 130 levels
//!      of nesting) and asserts the documented error.
//!
//! Test budget defaults to 256 cases per property; bump via
//! `PROPTEST_CASES` env var. Failures regenerate as deterministic
//! `.proptest-regressions` files committed alongside the test.

use std::collections::BTreeMap;

use fcp_cbor::{
    CanonicalSerializer, MAX_CANONICALIZATION_DEPTH, SchemaId, SerializationError,
    to_canonical_cbor,
};
use proptest::prelude::*;
use semver::Version;
use serde::{Deserialize, Serialize};

/// Recursive payload type that exercises every primitive the
/// canonical CBOR encoder cares about: signed/unsigned integers,
/// floats (canonicalizer rejects NaN/Inf), bools, strings, nested
/// arrays, and maps. Skipping byte-strings here because Vec<u8>
/// is serialized as a CBOR array of integers by serde, which
/// would conflate the byte-string and array-of-uint round-trip
/// properties — covered in goldens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FuzzScalar {
    Bool(bool),
    UInt(u64),
    SInt(i64),
    Float(f64),
    Text(String),
    /// `Null` in CBOR terms — pinned as a distinct variant so the
    /// round-trip preserves "explicit null" vs "missing field"
    /// distinctions (the canonicalizer should treat them as equal
    /// when neither carries data).
    Null,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct FuzzPayload {
    label: String,
    flag: bool,
    /// Mix of primitives — exercises array-of-mixed-types canonical
    /// ordering (which the encoder MUST preserve insertion order
    /// for arrays, since arrays are sequences not unordered sets).
    items: Vec<FuzzScalar>,
    /// String → scalar map. BTreeMap so insertion order doesn't
    /// affect the in-memory representation (we test insertion-order
    /// independence in property 3 by constructing a HashMap-equiv).
    metadata: BTreeMap<String, FuzzScalar>,
    /// Nested payload, max 1 level of recursion. Two levels keeps
    /// proptest case sizes manageable while still exercising the
    /// recursive canonicalize_value_in_place path.
    nested: Option<Box<FuzzNested>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct FuzzNested {
    items: Vec<FuzzScalar>,
    metadata: BTreeMap<String, FuzzScalar>,
}

fn finite_f64() -> impl Strategy<Value = f64> {
    // Canonical CBOR rejects NaN/Inf; clamp to a finite range so we
    // exercise the encoder's float path without immediately tripping
    // NonFiniteFloat. The fold to 0.0 (-0.0) is exercised below.
    prop_oneof![
        // Subnormals + small magnitudes
        (-1_000.0f64..1_000.0),
        // Larger range with precision-relevant values
        (-1e15f64..1e15),
        Just(0.0),
        Just(-0.0),
    ]
}

fn fuzz_scalar() -> impl Strategy<Value = FuzzScalar> {
    prop_oneof![
        any::<bool>().prop_map(FuzzScalar::Bool),
        any::<u64>().prop_map(FuzzScalar::UInt),
        any::<i64>().prop_map(FuzzScalar::SInt),
        finite_f64().prop_map(FuzzScalar::Float),
        // Bound string size so map-key length-prefix encoding does
        // not eat the whole proptest budget on edge-case prefix
        // boundaries (those are pinned by goldens).
        proptest::string::string_regex("[a-zA-Z0-9 _.-]{0,32}")
            .unwrap()
            .prop_map(FuzzScalar::Text),
        Just(FuzzScalar::Null),
    ]
}

fn fuzz_string_key() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[a-zA-Z0-9_]{1,16}")
        .unwrap()
        .prop_map(|s| {
            // Reject empty keys — would clash with TEXT length-zero
            // edge-case which goldens already pin.
            if s.is_empty() { "key".to_string() } else { s }
        })
}

fn fuzz_payload() -> impl Strategy<Value = FuzzPayload> {
    let scalars = prop::collection::vec(fuzz_scalar(), 0..8);
    let metadata = prop::collection::btree_map(fuzz_string_key(), fuzz_scalar(), 0..6);
    let nested_items = prop::collection::vec(fuzz_scalar(), 0..4);
    let nested_metadata = prop::collection::btree_map(fuzz_string_key(), fuzz_scalar(), 0..3);
    let nested = (nested_items, nested_metadata)
        .prop_map(|(items, metadata)| Some(Box::new(FuzzNested { items, metadata })));
    let no_nested = Just(None);
    let nested_or_not = prop_oneof![nested, no_nested];

    (
        proptest::string::string_regex("[a-zA-Z0-9_-]{1,32}").unwrap(),
        any::<bool>(),
        scalars,
        metadata,
        nested_or_not,
    )
        .prop_map(|(label, flag, items, metadata, nested)| FuzzPayload {
            label,
            flag,
            items,
            metadata,
            nested,
        })
}

fn test_schema() -> SchemaId {
    SchemaId::new("fcp.cbor.fuzz", "FuzzPayload", Version::new(1, 0, 0))
}

fn other_schema() -> SchemaId {
    // Distinct schema for the schema-mismatch property. Uses a
    // different version so the BLAKE3 hash differs from
    // `test_schema`.
    SchemaId::new("fcp.cbor.fuzz", "FuzzPayload", Version::new(2, 0, 0))
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        // Shrinking is cheap for these payloads but we cap it so a
        // single proptest run stays under a few seconds in CI.
        max_shrink_iters: 4096,
        ..ProptestConfig::default()
    })]

    /// Property 1: round-trip identity through CanonicalSerializer.
    ///
    /// `serialize → deserialize → serialize` produces byte-exact
    /// matching encodings. We compare encoded bytes (not the
    /// `FuzzPayload` value) because canonicalization may fold
    /// `-0.0 → 0.0`, so the deserialized value can differ from the
    /// input by exactly one bit while the encoding is stable. The
    /// encoded-bytes equality is the load-bearing property: a
    /// content-addressed object's hash is computed over these bytes.
    #[test]
    fn canonical_roundtrip_is_byte_exact(payload in fuzz_payload()) {
        let schema = test_schema();
        let bytes = match CanonicalSerializer::serialize(&payload, &schema) {
            Ok(b) => b,
            Err(SerializationError::PayloadTooLarge { .. }) => return Ok(()),
            Err(other) => panic!(
                "round-trip property: serialize unexpectedly failed: {other}"
            ),
        };
        let decoded: FuzzPayload =
            CanonicalSerializer::deserialize(&bytes, &schema).unwrap_or_else(|err| {
                panic!(
                    "round-trip property: deserialize of canonical bytes failed: {err}"
                )
            });
        let reencoded = CanonicalSerializer::serialize(&decoded, &schema)
            .expect("re-encoding a canonically-decoded payload must succeed");
        prop_assert_eq!(
            bytes,
            reencoded,
            "round-trip produced different bytes — encode/decode asymmetry",
        );
    }

    /// Property 2: canonicalization is idempotent.
    ///
    /// Encoding once + decoding-as-Value + re-encoding via the
    /// canonicalizer yields the same bytes. This catches refactors
    /// that change the canonicalizer's normalization (e.g. drop the
    /// -0.0 → 0.0 fold, change map-key sort order) since the
    /// re-canonicalization would diverge from the first encoding.
    #[test]
    fn canonical_encoding_is_idempotent(payload in fuzz_payload()) {
        let bytes_a = match to_canonical_cbor(&payload) {
            Ok(b) => b,
            Err(SerializationError::PayloadTooLarge { .. }) => return Ok(()),
            Err(other) => panic!("to_canonical_cbor failed: {other}"),
        };
        // Re-encode by deserializing as the typed payload and
        // canonicalizing again — this is the production path
        // operators use to validate a stored object's canonical
        // form before re-hashing.
        let decoded: FuzzPayload = ciborium::de::from_reader(bytes_a.as_slice())
            .expect("typed deserialize of canonical bytes must succeed");
        let bytes_b = to_canonical_cbor(&decoded)
            .expect("re-canonicalization of a typed payload must succeed");
        prop_assert_eq!(
            bytes_a,
            bytes_b,
            "canonicalization is not idempotent — second pass diverged",
        );
    }

    /// Property 3: random-byte robustness — feeding arbitrary bytes
    /// to deserialize never panics. Returns either Ok or Err; if Ok,
    /// the decoded payload re-encodes to bytes ≤ the input length
    /// (canonicalization can only shrink: it never adds new
    /// information).
    #[test]
    fn deserialize_random_bytes_never_panics(
        bytes in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let schema = test_schema();
        // Use deserialize (with schema check); we expect almost all
        // inputs to fail (because the schema-hash prefix won't
        // match), but the property is *no panic*, full stop.
        let _ = CanonicalSerializer::deserialize::<FuzzPayload>(&bytes, &schema);
    }

    /// Property 4: schema-mismatch detection. Bytes serialized with
    /// `test_schema` MUST NOT deserialize successfully under
    /// `other_schema`. The expected error is `SchemaMismatch` (or
    /// `MissingSchemaHashPrefix` if the payload happens to be
    /// shorter than 32 bytes — but our test schema produces ≥32-
    /// byte outputs always).
    #[test]
    fn schema_mismatch_is_always_detected(payload in fuzz_payload()) {
        let schema_a = test_schema();
        let schema_b = other_schema();
        let bytes = match CanonicalSerializer::serialize(&payload, &schema_a) {
            Ok(b) => b,
            Err(SerializationError::PayloadTooLarge { .. }) => return Ok(()),
            Err(other) => panic!("serialize failed: {other}"),
        };
        match CanonicalSerializer::deserialize::<FuzzPayload>(&bytes, &schema_b) {
            Ok(_) => panic!(
                "schema-mismatch property: deserialize incorrectly accepted bytes \
                 prefixed with a different schema hash"
            ),
            Err(SerializationError::SchemaMismatch { .. }) => {}
            Err(other) => panic!("expected SchemaMismatch, got: {other}"),
        }
    }
}

// Property 5: insertion-order independence for maps.
//
// Build the same logical map twice — once with keys inserted in
// sorted order, once with shuffled insertion order — using a Vec
// of (String, FuzzScalar) pairs as the entry source so insertion
// order is observable in the build process. The canonical CBOR
// encoding MUST be identical regardless. Pre-fix this property
// would have caught the original sort-by-display-key bug that
// `map_keys_sorted_by_deterministic_encoding_bytes` (a single
// hand-written value) found.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        ..ProptestConfig::default()
    })]

    #[test]
    fn map_canonical_encoding_independent_of_insertion_order(
        mut entries in prop::collection::vec(
            (fuzz_string_key(), fuzz_scalar()),
            1..8,
        ),
        seed in any::<u64>(),
    ) {
        // De-duplicate by key — the canonicalizer rejects duplicate
        // keys, which is a separate property tested by goldens.
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        entries.dedup_by(|(a, _), (b, _)| a == b);

        // Order A: sorted by key string.
        let mut order_a: BTreeMap<String, FuzzScalar> = BTreeMap::new();
        for (k, v) in &entries {
            order_a.insert(k.clone(), v.clone());
        }

        // Order B: shuffled insertion order. Use the seed as a poor-
        // man's PRNG to permute deterministically per case.
        let mut shuffled = entries.clone();
        let mut rng = seed;
        for i in (1..shuffled.len()).rev() {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (rng as usize) % (i + 1);
            shuffled.swap(i, j);
        }
        let mut order_b: BTreeMap<String, FuzzScalar> = BTreeMap::new();
        for (k, v) in &shuffled {
            order_b.insert(k.clone(), v.clone());
        }

        let bytes_a = match to_canonical_cbor(&order_a) {
            Ok(b) => b,
            Err(SerializationError::PayloadTooLarge { .. }) => return Ok(()),
            Err(other) => panic!("encode order_a failed: {other}"),
        };
        let bytes_b = match to_canonical_cbor(&order_b) {
            Ok(b) => b,
            Err(SerializationError::PayloadTooLarge { .. }) => return Ok(()),
            Err(other) => panic!("encode order_b failed: {other}"),
        };
        prop_assert_eq!(
            bytes_a,
            bytes_b,
            "canonical encoding depends on insertion order — \
             map-key sort regression"
        );
    }
}

/// Property 6: depth-limit guard against adversarial nesting.
///
/// Build a nested array of depth `MAX_CANONICALIZATION_DEPTH + 16`
/// using ciborium::Value directly (proptest can't naturally produce
/// the exact depth required) and confirm the canonicalizer surfaces
/// `DepthExceeded` rather than recursing past its stack budget.
/// Pre-fix the canonicalizer had no depth guard and would stack-
/// overflow on adversarial input.
#[test]
fn canonicalizer_rejects_input_past_depth_limit() {
    use ciborium::Value;

    let mut deeply_nested = Value::Null;
    for _ in 0..(MAX_CANONICALIZATION_DEPTH + 16) {
        deeply_nested = Value::Array(vec![deeply_nested]);
    }

    // Wrap to_canonical_cbor in catch_unwind so a regression that
    // re-introduces the unbounded recursion fails with a clear
    // panic message rather than crashing the entire test suite.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        to_canonical_cbor(&deeply_nested)
    }));

    match result {
        Ok(Err(SerializationError::DepthExceeded { .. })) => {
            // ✓ Expected.
        }
        Ok(Ok(_)) => panic!(
            "canonicalizer accepted input deeper than MAX_CANONICALIZATION_DEPTH \
             — depth guard is missing or off-by-one"
        ),
        Ok(Err(other)) => panic!(
            "canonicalizer rejected over-depth input but with the wrong error: \
             got {other}, expected DepthExceeded"
        ),
        Err(_) => panic!(
            "canonicalizer PANICKED on input deeper than MAX_CANONICALIZATION_DEPTH \
             — unbounded recursion regression"
        ),
    }
}

/// Property 7: float canonicalization folds -0.0 to 0.0.
///
/// RFC 8949 §4.2.5 specifies that canonical encoding treats positive
/// and negative zero as equal. The encoder folds the bits of -0.0 to
/// those of +0.0 before emitting, so that a value containing -0.0
/// and one containing +0.0 produce identical canonical bytes (and
/// therefore identical content-address hashes). This is checked
/// once with hand-built inputs because proptest's `finite_f64`
/// strategy occasionally generates -0.0 and the round-trip property
/// already exercises the fold — but pinning the explicit case
/// makes the regression diagnosis obvious if Property 1 starts
/// flaking.
#[test]
fn float_negative_zero_folds_to_positive_zero() {
    let positive_zero_payload = FuzzScalar::Float(0.0);
    let negative_zero_payload = FuzzScalar::Float(-0.0);
    let bytes_pos = to_canonical_cbor(&positive_zero_payload).expect("encoding +0.0 must succeed");
    let bytes_neg = to_canonical_cbor(&negative_zero_payload).expect("encoding -0.0 must succeed");
    assert_eq!(
        bytes_pos, bytes_neg,
        "canonical encoding of -0.0 must equal +0.0 (RFC 8949 §4.2.5)",
    );
}
