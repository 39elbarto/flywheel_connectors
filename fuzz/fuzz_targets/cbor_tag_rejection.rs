#![no_main]

//! Fuzz target for `canonicalize_value_in_place` Tag rejection across
//! every Value position (lib.rs:484-513).
//!
//! Tags are NOT part of canonical CBOR per RFC 8949 §4.2 — the
//! canonicalizer MUST reject every `Value::Tag` with `UnsupportedTag`,
//! including tags nested inside Array elements, Map values, Map keys,
//! and other Tags. A regression that allowed tags through anywhere
//! would let an attacker smuggle non-canonical wire forms past the
//! canonical-encoding gate (defeating SchemaCanonicalization for any
//! object containing tagged data).
//!
//! Existing `canonicalize_map_deterministic` explicitly skips tags
//! (per its docstring), and `canonical_cbor` only fuzzes panic-freedom.
//! No existing fuzz target probes Tag rejection across all positions.
//!
//! Properties asserted:
//!
//!   1. **Tag at root**: `Value::Tag(_, _)` MUST yield UnsupportedTag.
//!   2. **Tag inside Array**: an array containing a Tag MUST yield
//!      UnsupportedTag (recursion catches it).
//!   3. **Tag as Map value**: a map with a tagged value MUST yield
//!      UnsupportedTag.
//!   4. **Tag as Map key**: a map with a tagged key MUST yield
//!      UnsupportedTag.
//!   5. **Tag inside Tag**: a double-nested tag yields UnsupportedTag
//!      (outer rejected first per documented behavior).
//!   6. **Tag-free input round-trips**: a tag-free Value with the same
//!      structure (Tag replaced by Null) MUST canonicalize successfully
//!      — keeps the rejection-anchor non-vacuous.
//!
//!   Once-gated regression anchors:
//!     (a) Tag at root with tag values {0, 1, 12345, u64::MAX} → all
//!         must trip UnsupportedTag.
//!     (b) Tag inside [array], [array of array], map-value, map-key —
//!         each must trip UnsupportedTag.
//!     (c) Replacing the Tag with Null at the same position MUST
//!         canonicalize successfully (acceptance anchor).

use arbitrary::{Arbitrary, Unstructured};
use ciborium::value::{Integer, Value};
use fcp_cbor::{SerializationError, to_canonical_cbor};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static TAG_REJECTION_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    tag_value: u64,
    /// Position to inject the tag.
    position_disc: u8,
    /// Inner-payload bytes for the tagged Value (we wrap an Integer or
    /// Bytes; either way the tag rejection is what we probe).
    inner_int: i64,
}

fn make_tag(tag: u64, inner: Value) -> Value {
    Value::Tag(tag, Box::new(inner))
}

fn assert_tag_rejected(v: Value, ctx: &str) {
    match to_canonical_cbor(&v) {
        Err(SerializationError::UnsupportedTag { .. }) => {}
        Err(other) => panic!("tag at {ctx}: expected UnsupportedTag, got {other:?}"),
        Ok(_) => panic!(
            "tag at {ctx} was accepted by canonicalize — Tag rejection at \
             lib.rs:508 broken; non-canonical CBOR can pass the canonical \
             encoding gate"
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    TAG_REJECTION_ANCHOR.call_once(assert_tag_rejection_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let inner = Value::Integer(Integer::from(input.inner_int));
    let tagged = make_tag(input.tag_value, inner.clone());

    match input.position_disc % 5 {
        // Root.
        0 => assert_tag_rejected(tagged, "root"),
        // Array element.
        1 => {
            let arr = Value::Array(vec![tagged]);
            assert_tag_rejected(arr, "Array element");
        }
        // Map value.
        2 => {
            let map = Value::Map(vec![(Value::Integer(Integer::from(0)), tagged)]);
            assert_tag_rejected(map, "Map value");
        }
        // Map key.
        3 => {
            let map = Value::Map(vec![(tagged, Value::Bool(true))]);
            assert_tag_rejected(map, "Map key");
        }
        // Tag-in-tag.
        _ => {
            let outer = make_tag(input.tag_value.wrapping_add(1), tagged);
            assert_tag_rejected(outer, "Tag-in-Tag");
        }
    }

    // ── PROPERTY 6: tag-free input at the same structural position
    // canonicalizes ────────────────────────────────────────────────────
    let null_inner = Value::Null;
    let acceptance = match input.position_disc % 5 {
        0 => null_inner,
        1 => Value::Array(vec![null_inner]),
        2 => Value::Map(vec![(Value::Integer(Integer::from(0)), null_inner)]),
        3 => Value::Map(vec![(null_inner, Value::Bool(true))]),
        _ => Value::Array(vec![Value::Array(vec![null_inner])]),
    };
    to_canonical_cbor(&acceptance).expect(
        "tag-free Value at the same structural position MUST canonicalize \
         (acceptance branch keeps the rejection assertion non-vacuous)",
    );
});

/// Once-gated regression anchors: every documented Tag position MUST
/// trip UnsupportedTag, with tag values spanning the u64 range.
fn assert_tag_rejection_anchored() {
    let inner = Value::Integer(Integer::from(42));
    for &tag in &[0u64, 1, 12_345, u64::MAX] {
        // Tag at root.
        assert_tag_rejected(make_tag(tag, inner.clone()), "ANCHOR root");

        // Tag inside Array.
        let arr = Value::Array(vec![make_tag(tag, inner.clone())]);
        assert_tag_rejected(arr, "ANCHOR Array element");

        // Tag as Map value.
        let map_v = Value::Map(vec![(
            Value::Integer(Integer::from(0)),
            make_tag(tag, inner.clone()),
        )]);
        assert_tag_rejected(map_v, "ANCHOR Map value");

        // Tag as Map key.
        let map_k = Value::Map(vec![(make_tag(tag, inner.clone()), Value::Null)]);
        assert_tag_rejected(map_k, "ANCHOR Map key");

        // Tag inside nested Array.
        let nested = Value::Array(vec![Value::Array(vec![make_tag(tag, inner.clone())])]);
        assert_tag_rejected(nested, "ANCHOR Array of Array");

        // Tag inside Tag.
        let nested_tag = make_tag(tag, make_tag(tag.wrapping_add(1), inner.clone()));
        assert_tag_rejected(nested_tag, "ANCHOR Tag-in-Tag");
    }

    // Acceptance anchor: structurally-equivalent tag-free input
    // canonicalizes successfully.
    let tag_free_root = Value::Null;
    to_canonical_cbor(&tag_free_root).expect("ANCHOR: Null at root must canonicalize");

    let tag_free_array = Value::Array(vec![Value::Null, Value::Bool(true)]);
    to_canonical_cbor(&tag_free_array).expect("ANCHOR: tag-free Array must canonicalize");

    let tag_free_map = Value::Map(vec![(Value::Integer(Integer::from(0)), Value::Null)]);
    to_canonical_cbor(&tag_free_map).expect("ANCHOR: tag-free Map must canonicalize");
}
