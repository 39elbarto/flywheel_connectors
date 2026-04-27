#![no_main]

//! Fuzz target for `CanonicalSerializer` decoder-side recursion-limit
//! boundary (lib.rs:433-466).
//!
//! `CanonicalSerializer::{deserialize, deserialize_unchecked}` runs
//! CBOR bytes through ciborium's `from_reader_with_recursion_limit`,
//! bounded by `MAX_DESERIALIZATION_RECURSION_LIMIT = 128`. This is the
//! **decoder-side stack-overflow DoS guard**. An attacker sending
//! CBOR bytes encoding 10K-deep nested arrays/maps would, without it,
//! drive ciborium's recursive descent into stack exhaustion. A
//! regression that dropped the explicit limit or fell back to
//! ciborium's default would silently re-open this surface.
//!
//! Existing fuzz coverage:
//!   - `cbor_array_canonical` (y98gt) — ENCODE-side depth: a Value
//!     tree built MAX+10 deep MUST trip DepthExceeded inside
//!     canonicalize_value_in_place.
//!   - `canonical_cbor`               — panic-free deserialize on
//!     arbitrary bytes, NOT the depth boundary.
//!   - `canonical_serializer_schema_binding` (cchj5) — schema gates.
//!
//! NOT covered: the **decoder-side** boundary at the CBOR-bytes level.
//! Bytes encoding depth >> MAX must be rejected before the
//! canonicalizer runs (ciborium recursion-limit hits first).
//!
//! Properties asserted:
//!
//!   1. **Bytes-encoded depth N+1 rejected**: hand-constructed CBOR
//!      bytes encoding nested arrays/maps to depth >
//!      `MAX_DESERIALIZATION_RECURSION_LIMIT` MUST return a typed
//!      bounded-resource error (DepthExceeded, CborDeserialize, or
//!      PayloadTooLarge), never panic, never silently decode.
//!   2. **Bytes-encoded depth ≤ N accepted via deserialize_unchecked**:
//!      depth = MAX MUST decode successfully (acceptance counterpart
//!      keeping the rejection check non-vacuous).
//!   3. **Mixed array+map nesting parity**: alternating array/map at
//!      depth N+1 MUST be rejected — guards a regression where one
//!      branch forgets to count toward the limit.
//!
//!   Once-gated regression anchors:
//!     (a) Depth 129 nested arrays MUST trip a depth-class error.
//!     (b) Depth 128 nested arrays MUST decode (acceptance).
//!     (c) Depth 129 nested maps MUST trip a depth-class error.

use arbitrary::{Arbitrary, Unstructured};
use fcp_cbor::{
    CanonicalSerializer, MAX_CANONICAL_OBJECT_BYTES, MAX_DESERIALIZATION_RECURSION_LIMIT, SchemaId,
    SerializationError,
};
use libfuzzer_sys::fuzz_target;
use semver::Version;
use std::sync::Once;

static RECURSION_LIMIT_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    /// Depth offset added to MAX_DESERIALIZATION_RECURSION_LIMIT to
    /// generate test bytes near the boundary. Folded modulo a small
    /// window so iterations stay fast.
    depth_offset: u8,
    /// Discriminator: 0 = array, 1 = map, 2 = alternating.
    nesting_kind: u8,
}

fn schema() -> SchemaId {
    SchemaId::new("fcp.fuzz", "DecodeRecursion", Version::new(1, 0, 0))
}

/// Build CBOR bytes for `depth` nested 1-element arrays containing the
/// integer 0 at the leaf: 0x81 × depth || 0x00.
fn nested_arrays(depth: usize) -> Vec<u8> {
    let mut out = vec![0x81u8; depth];
    out.push(0x00); // unsigned integer 0 leaf
    out
}

/// Build CBOR bytes for `depth` nested 1-entry maps with key=0 at every
/// level and integer 0 at the leaf: (0xa1 0x00) × depth || 0x00.
fn nested_maps(depth: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(depth * 2 + 1);
    for _ in 0..depth {
        out.push(0xa1); // map of 1
        out.push(0x00); // key = unsigned integer 0
    }
    out.push(0x00); // leaf value = unsigned integer 0
    out
}

/// Build CBOR bytes alternating array/map nesting to `depth` levels.
fn nested_alternating(depth: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(depth * 2 + 1);
    for i in 0..depth {
        if i.is_multiple_of(2) {
            out.push(0x81);
        } else {
            out.push(0xa1);
            out.push(0x00);
        }
    }
    out.push(0x00);
    out
}

/// Wrap raw CBOR bytes in CanonicalSerializer's schema-prefixed envelope.
fn wrap(cbor_bytes: &[u8]) -> Vec<u8> {
    let s = schema();
    let prefix_bytes = s.hash();
    let mut out = Vec::with_capacity(prefix_bytes.as_bytes().len() + cbor_bytes.len());
    out.extend_from_slice(prefix_bytes.as_bytes());
    out.extend_from_slice(cbor_bytes);
    out
}

/// Did the deserialize result fall in the bounded-resource error
/// family? Any of these is acceptable for "rejected the over-limit
/// input" — the exact variant depends on which gate fires first
/// (ciborium recursion vs canonicalize depth vs size cap).
fn is_bounded_resource_err<T>(r: &Result<T, SerializationError>) -> bool {
    matches!(
        r,
        Err(SerializationError::DepthExceeded { .. })
            | Err(SerializationError::PayloadTooLarge { .. })
            | Err(SerializationError::CborDeserialize(_))
            | Err(SerializationError::NonCanonicalEncoding)
    )
}

fuzz_target!(|data: &[u8]| {
    RECURSION_LIMIT_ANCHOR.call_once(assert_recursion_limit_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    // Map depth_offset ∈ [0, 16] onto a window straddling the boundary.
    // Below MAX → expected accept (with deserialize_unchecked).
    // Above MAX → expected reject.
    let window = (input.depth_offset as i32) - 8; // ∈ [-8, 247]
    let raw_depth: i32 = (MAX_DESERIALIZATION_RECURSION_LIMIT as i32) + window;
    if raw_depth < 0 {
        return;
    }
    let depth = raw_depth as usize;

    // Cap depth so the bytes never exceed MAX_CANONICAL_OBJECT_BYTES.
    if depth.saturating_mul(2) + 32 > MAX_CANONICAL_OBJECT_BYTES.min(8 * 1024) {
        return;
    }

    let cbor_bytes = match input.nesting_kind % 3 {
        0 => nested_arrays(depth),
        1 => nested_maps(depth),
        _ => nested_alternating(depth),
    };
    let envelope = wrap(&cbor_bytes);
    let s = schema();

    let result =
        CanonicalSerializer::deserialize_unchecked::<ciborium::value::Value>(&envelope, &s);

    // ── PROPERTY 1+3: depth > MAX MUST be rejected ─────────────────────
    if depth > MAX_DESERIALIZATION_RECURSION_LIMIT {
        match &result {
            Ok(_) => panic!(
                "deserialize_unchecked accepted CBOR bytes of depth {depth} > MAX={} \
                 (kind={}) — recursion-limit gate broken; stack-overflow DoS \
                 surface re-opened",
                MAX_DESERIALIZATION_RECURSION_LIMIT,
                input.nesting_kind % 3
            ),
            Err(_) if is_bounded_resource_err(&result) => {}
            Err(other) => panic!(
                "deserialize_unchecked rejected with unexpected error variant for \
                 over-limit depth {depth}: {other:?}; expected DepthExceeded / \
                 PayloadTooLarge / CborDeserialize / NonCanonicalEncoding"
            ),
        }
    }
    // ── PROPERTY 2: depth ≤ MAX should accept ──────────────────────────
    // Acceptance is asserted in once-gated anchors; here we only check
    // panic-freedom for the in-range case (deserialize_unchecked may
    // still fail for other reasons on adversarial input via the schema
    // prefix or canonicalization side, which we don't constrain).
});

/// Once-gated regression anchors: depth = 128 (accept) + 129 (reject)
/// for both arrays and maps. Run once per process so a regression in
/// the recursion-limit gate trips on every fuzz invocation.
fn assert_recursion_limit_anchored() {
    let s = schema();

    // (b) Acceptance anchor: depth 128 nested arrays MUST decode.
    let accept_arrays = nested_arrays(MAX_DESERIALIZATION_RECURSION_LIMIT);
    let envelope = wrap(&accept_arrays);
    CanonicalSerializer::deserialize_unchecked::<ciborium::value::Value>(&envelope, &s).expect(
        "ANCHOR: depth=MAX nested arrays MUST decode (acceptance anchor; \
         otherwise the rejection anchor below is uninformative)",
    );

    // (a) Rejection anchor: depth 129 nested arrays MUST trip a
    // depth-class error.
    let reject_arrays = nested_arrays(MAX_DESERIALIZATION_RECURSION_LIMIT + 1);
    let envelope = wrap(&reject_arrays);
    let result =
        CanonicalSerializer::deserialize_unchecked::<ciborium::value::Value>(&envelope, &s);
    match &result {
        Ok(_) => panic!(
            "ANCHOR REGRESSION: depth=MAX+1 ({}) nested arrays were accepted — \
             ciborium recursion limit at lib.rs:447-449 dropped or fell back to \
             default; stack-overflow DoS surface re-opened",
            MAX_DESERIALIZATION_RECURSION_LIMIT + 1
        ),
        Err(_) if is_bounded_resource_err(&result) => {}
        Err(other) => panic!(
            "ANCHOR: depth=MAX+1 nested arrays produced unexpected error: \
             {other:?}; expected a bounded-resource error variant"
        ),
    }

    // (c) Rejection anchor: depth 129 nested maps MUST trip a
    // depth-class error (parity with the array branch — guards
    // a regression that increments depth on Array but not Map).
    let reject_maps = nested_maps(MAX_DESERIALIZATION_RECURSION_LIMIT + 1);
    let envelope = wrap(&reject_maps);
    let result =
        CanonicalSerializer::deserialize_unchecked::<ciborium::value::Value>(&envelope, &s);
    match &result {
        Ok(_) => panic!(
            "ANCHOR REGRESSION: depth=MAX+1 nested maps were accepted while the \
             array branch correctly rejected — depth-counting parity broken \
             (canonicalize_value_in_place at lib.rs:507 vs Array branch lib.rs:502)"
        ),
        Err(_) if is_bounded_resource_err(&result) => {}
        Err(other) => panic!(
            "ANCHOR: depth=MAX+1 nested maps produced unexpected error: \
             {other:?}; expected a bounded-resource error variant"
        ),
    }
}
