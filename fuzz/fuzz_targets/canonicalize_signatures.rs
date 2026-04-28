#![no_main]

//! Fuzz target for `fcp_crypto::canonicalize` multi-signature ordering
//! helpers + signing-context primitives (canonicalize.rs:20-248).
//!
//! Covers:
//! - `schema_hash`            (canonicalize.rs:20)
//! - `canonical_signing_bytes`(canonicalize.rs:36)
//! - `sort_signatures_by_node_id` (canonicalize.rs:49)
//! - `verify_signature_order`     (canonicalize.rs:60)
//! - `sort_node_signatures`       (canonicalize.rs:230)
//! - `verify_node_signature_order`(canonicalize.rs:239)
//!
//! These are the deterministic multi-sig sort + signing-bytes
//! primitives that protect quorum-signed objects (zone-key manifests,
//! capability tokens). Currently only `cargo test` smoke coverage.
//!
//! A regression that:
//!   - flipped sort to descending order would silently disagree with
//!     other implementations during multi-sig verification.
//!   - dropped the duplicate detection in `verify_*_order` would let
//!     a peer count one signature twice toward the quorum.
//!   - changed `SIGNING_DOMAIN` or shrunk `SCHEMA_HASH_SIZE` would
//!     defeat domain separation against cross-protocol replay.
//!
//! Properties asserted:
//!
//!   1. **Permutation invariant**: `sort_signatures_by_node_id`
//!      returns a vector of indices that is a permutation of `0..n`.
//!   2. **Sort correctness**: the indices, when applied, produce a
//!      non-decreasing sequence of `node_id` slices.
//!   3. **`verify_signature_order` matches strict increase**: returns
//!      `Ok` iff every adjacent pair satisfies `a < b`.
//!   4. **Duplicate / out-of-order rejection**: any input with a pair
//!      `a >= b` is rejected.
//!   5. **`sort_node_signatures` non-decreasing output**: the `node_id`
//!      vector after sort is non-decreasing.
//!   6. **`verify_node_signature_order` matches strict increase** on
//!      the `NodeSignature` slice.
//!   7. **`schema_hash` determinism**: same input → same 8-byte hash.
//!   8. **`canonical_signing_bytes` layout**: result starts with
//!      `SIGNING_DOMAIN`, then exactly `SCHEMA_HASH_SIZE` bytes of
//!      `schema_hash(schema_id)`, then the input `cbor_bytes`
//!      verbatim.
//!   9. **`canonical_signing_bytes` length**: `SIGNING_DOMAIN.len() +
//!      SCHEMA_HASH_SIZE + cbor_bytes.len()`.
//!
//!   Once-gated anchors verify hand-picked sorts, the layout, and
//!   `schema_hash` distinctness on two known-different inputs.

use arbitrary::{Arbitrary, Unstructured};
use fcp_crypto::canonicalize::{
    NodeSignature, SCHEMA_HASH_SIZE, SIGNING_DOMAIN, canonical_signing_bytes, schema_hash,
    sort_node_signatures, sort_signatures_by_node_id, verify_node_signature_order,
    verify_signature_order,
};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static CANON_SIG_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    node_ids: Vec<Vec<u8>>,
    schema_id: String,
    cbor_bytes: Vec<u8>,
}

const MAX_NODES: usize = 32;
const MAX_NODE_LEN: usize = 64;
const MAX_CBOR_LEN: usize = 4096;

fuzz_target!(|data: &[u8]| {
    CANON_SIG_ANCHOR.call_once(assert_canon_sig_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    if input.node_ids.len() > MAX_NODES
        || input.node_ids.iter().any(|n| n.len() > MAX_NODE_LEN)
        || input.cbor_bytes.len() > MAX_CBOR_LEN
    {
        return;
    }

    let id_refs: Vec<&[u8]> = input.node_ids.iter().map(Vec::as_slice).collect();

    // ── PROPERTY 1: permutation invariant ───────────────────────────────
    let indices = sort_signatures_by_node_id(&id_refs);
    assert_eq!(
        indices.len(),
        id_refs.len(),
        "sort_signatures_by_node_id length differs from input"
    );
    let mut seen = vec![false; id_refs.len()];
    for &i in &indices {
        assert!(
            i < id_refs.len(),
            "sort_signatures_by_node_id returned out-of-range index {i}"
        );
        assert!(
            !seen[i],
            "sort_signatures_by_node_id repeated index {i} — not a permutation"
        );
        seen[i] = true;
    }

    // ── PROPERTY 2: sort correctness (non-decreasing) ───────────────────
    for window in indices.windows(2) {
        assert!(
            id_refs[window[0]] <= id_refs[window[1]],
            "sort_signatures_by_node_id produced descending pair"
        );
    }

    // ── PROPERTY 3 + 4: verify_signature_order matches strict increase ──
    let strictly_sorted = id_refs.windows(2).all(|w| w[0] < w[1]);
    let result = verify_signature_order(&id_refs);
    if strictly_sorted {
        assert!(
            result.is_ok(),
            "verify_signature_order rejected a strictly increasing list"
        );
    } else {
        assert!(
            result.is_err(),
            "verify_signature_order accepted a non-strictly-increasing list"
        );
    }

    // ── PROPERTY 5 + 6: NodeSignature variant ───────────────────────────
    let mut sigs: Vec<NodeSignature> = input
        .node_ids
        .iter()
        .map(|nid| NodeSignature::new(nid.clone(), vec![]))
        .collect();
    sort_node_signatures(&mut sigs);
    for window in sigs.windows(2) {
        assert!(
            window[0].node_id <= window[1].node_id,
            "sort_node_signatures produced descending pair"
        );
    }

    let strictly_sorted_sigs = sigs.windows(2).all(|w| w[0].node_id < w[1].node_id);
    let r = verify_node_signature_order(&sigs);
    if strictly_sorted_sigs {
        assert!(
            r.is_ok(),
            "verify_node_signature_order rejected a strictly increasing slice"
        );
    } else {
        assert!(
            r.is_err(),
            "verify_node_signature_order accepted a non-strictly-increasing slice"
        );
    }

    // ── PROPERTY 7: schema_hash determinism ─────────────────────────────
    let h_a = schema_hash(&input.schema_id);
    let h_b = schema_hash(&input.schema_id);
    assert_eq!(h_a, h_b, "schema_hash non-deterministic");
    assert_eq!(h_a.len(), SCHEMA_HASH_SIZE, "schema_hash length != 8");

    // ── PROPERTY 8 + 9: canonical_signing_bytes layout + length ─────────
    let signing = canonical_signing_bytes(&input.schema_id, &input.cbor_bytes);
    assert_eq!(
        signing.len(),
        SIGNING_DOMAIN.len() + SCHEMA_HASH_SIZE + input.cbor_bytes.len(),
        "canonical_signing_bytes length unexpected"
    );
    assert!(
        signing.starts_with(SIGNING_DOMAIN),
        "canonical_signing_bytes does not start with SIGNING_DOMAIN"
    );
    let schema_off = SIGNING_DOMAIN.len();
    let body_off = schema_off + SCHEMA_HASH_SIZE;
    assert_eq!(
        &signing[schema_off..body_off],
        &h_a,
        "canonical_signing_bytes schema-hash slice != schema_hash(schema_id)"
    );
    assert_eq!(
        &signing[body_off..],
        input.cbor_bytes.as_slice(),
        "canonical_signing_bytes did not preserve cbor_bytes verbatim at the suffix"
    );
});

/// Once-gated anchors: hand-picked sorts, layout, and schema-hash
/// distinctness on two known-different inputs.
fn assert_canon_sig_anchored() {
    // (a) Permutation + non-decreasing on a hand-picked input.
    let ids: Vec<&[u8]> = vec![b"charlie", b"alice", b"bob", b"alice"];
    let order = sort_signatures_by_node_id(&ids);
    assert_eq!(order.len(), ids.len(), "ANCHOR: sorted length");
    // Indices must produce non-decreasing slice.
    for w in order.windows(2) {
        assert!(
            ids[w[0]] <= ids[w[1]],
            "ANCHOR REGRESSION: sort_signatures_by_node_id descending"
        );
    }

    // (b) verify_signature_order rejects duplicate.
    let dup: Vec<&[u8]> = vec![b"alice", b"alice"];
    assert!(
        verify_signature_order(&dup).is_err(),
        "ANCHOR REGRESSION: verify_signature_order accepted duplicate"
    );

    // (c) verify_signature_order accepts strict increase.
    let inc: Vec<&[u8]> = vec![b"alice", b"bob", b"charlie"];
    verify_signature_order(&inc).expect("ANCHOR: strictly increasing must pass");

    // (d) NodeSignature variant on hand-picked.
    let mut sigs = vec![
        NodeSignature::new(b"charlie".to_vec(), vec![1]),
        NodeSignature::new(b"alice".to_vec(), vec![2]),
        NodeSignature::new(b"bob".to_vec(), vec![3]),
    ];
    sort_node_signatures(&mut sigs);
    assert_eq!(
        sigs[0].node_id, b"alice",
        "ANCHOR: sort_node_signatures order"
    );
    assert_eq!(sigs[1].node_id, b"bob");
    assert_eq!(sigs[2].node_id, b"charlie");
    verify_node_signature_order(&sigs).expect("ANCHOR: sorted NodeSignatures must verify");

    // (e) schema_hash distinctness on two known-different inputs.
    let h1 = schema_hash("fcp.zone.ZoneKeyManifest/1.0.0");
    let h2 = schema_hash("fcp.zone.ZoneDefinition/1.0.0");
    assert_ne!(
        h1, h2,
        "ANCHOR REGRESSION: schema_hash collides on two known-different schemas"
    );
    assert_eq!(h1.len(), 8, "ANCHOR: schema_hash size != 8");

    // (f) canonical_signing_bytes layout.
    let body = b"anchor-cbor";
    let sb = canonical_signing_bytes("anchor.schema/1.0.0", body);
    assert!(
        sb.starts_with(SIGNING_DOMAIN),
        "ANCHOR REGRESSION: signing bytes prefix is not SIGNING_DOMAIN"
    );
    let suffix_off = SIGNING_DOMAIN.len() + SCHEMA_HASH_SIZE;
    assert_eq!(
        &sb[suffix_off..],
        body,
        "ANCHOR: canonical_signing_bytes did not preserve cbor body"
    );

    // (g) Empty list — verify_signature_order on empty MUST pass.
    let empty: Vec<&[u8]> = vec![];
    verify_signature_order(&empty).expect("ANCHOR: empty list must verify");
    let empty_sigs: [NodeSignature; 0] = [];
    verify_node_signature_order(&empty_sigs).expect("ANCHOR: empty NodeSignatures must verify");

    // (h) Single-element list — verify_signature_order MUST pass.
    let single: Vec<&[u8]> = vec![b"only"];
    verify_signature_order(&single).expect("ANCHOR: single-element list must verify");
}
