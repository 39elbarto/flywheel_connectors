#![no_main]

//! Fuzz target for `fcp_core::AuditEvent::follows` and
//! `is_genesis` (audit.rs:92, 108).
//!
//! These predicates wire `AuditEvent` instances into the tamper-
//! evident audit chain. NOT covered as a discrete unit by any
//! existing fuzz target — `fcp_audit::verify_chain` operates on a
//! different (cross-crate) `AuditEntry` type.
//!
//! A regression that:
//!   - silently accepted `self.seq == prev.seq` would break the
//!     monotonic sequence guarantee and let an attacker insert a
//!     duplicate event.
//!   - dropped the `prev` pointer check would let an attacker reuse
//!     a known seq number while pointing at a forged predecessor.
//!   - mishandled `prev.seq == u64::MAX` would either panic on
//!     overflow or silently wrap to 0 and let a sentinel event
//!     attach to the genesis link.
//!
//! Properties asserted:
//!
//!   1. **`is_genesis` definition**: true iff `seq == 0 &&
//!      prev.is_none()`.
//!   2. **`follows` happy path**: `(prev_event.seq + 1, Some(prev_id))`
//!      → `true`.
//!   3. **Wrong predecessor id rejection**: same seq layout but a
//!      different `prev_id` → `false`.
//!   4. **Wrong seq rejection**: `seq != prev.seq + 1` →
//!      `false` (any other delta, including `+2`, `0`, `-1`).
//!   5. **Genesis cannot follow anything**: a `seq=0, prev=None`
//!      event MUST return `false` from `follows`.
//!   6. **u64::MAX overflow rejection**: `prev.seq == u64::MAX` →
//!      `follows` always `false` (no event can be the legitimate
//!      successor since `prev.seq + 1` overflows).
//!   7. **Self-link rejection**: an event MUST NOT follow itself
//!      (its own seq is never seq+1).
//!
//!   Once-gated anchors verify each branch on hand-picked events.

use arbitrary::{Arbitrary, Unstructured};
use fcp_cbor::SchemaId;
use fcp_core::{
    AuditEvent, CorrelationId, NodeId, NodeSignature, ObjectHeader, ObjectId, PrincipalId,
    Provenance, ZoneId,
};
use libfuzzer_sys::fuzz_target;
use semver::Version;
use std::sync::Once;

static AUDIT_FOLLOWS_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    prev_seq: u64,
    self_seq: u64,
    prev_id_bytes: [u8; 32],
    other_id_bytes: [u8; 32],
    self_prev_is_none: bool,
}

fn make_event(seq: u64, prev: Option<ObjectId>) -> AuditEvent {
    AuditEvent {
        header: ObjectHeader {
            schema: SchemaId::new("fcp.core", "AuditEvent", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        },
        correlation_id: CorrelationId::new(),
        trace_context: None,
        event_type: "fuzz".into(),
        actor: PrincipalId::new("p:fuzz").expect("canonical principal id"),
        zone_id: ZoneId::work(),
        connector_id: None,
        operation: None,
        capability_token_jti: None,
        request_object_id: None,
        result_object_id: None,
        prev,
        seq,
        occurred_at: 0,
        signature: NodeSignature::new(NodeId::new("n:fuzz"), [0u8; 64], 0),
    }
}

fuzz_target!(|data: &[u8]| {
    AUDIT_FOLLOWS_ANCHOR.call_once(assert_audit_follows_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let prev_id = ObjectId::from_bytes(input.prev_id_bytes);
    let other_id = ObjectId::from_bytes(input.other_id_bytes);

    let prev_event = make_event(input.prev_seq, None);
    let self_prev = if input.self_prev_is_none {
        None
    } else {
        Some(prev_id)
    };
    let self_event = make_event(input.self_seq, self_prev);

    // ── PROPERTY 1: is_genesis definition ───────────────────────────────
    let is_g = self_event.is_genesis();
    let expected_is_g = self_event.seq == 0 && self_event.prev.is_none();
    assert_eq!(
        is_g,
        expected_is_g,
        "is_genesis disagrees with definition: seq={}, prev_is_none={}",
        self_event.seq,
        self_event.prev.is_none()
    );

    // ── PROPERTY 2 + 3 + 4 + 7: follows expected outcome ────────────────
    let result = self_event.follows(&prev_event, &prev_id);
    let expected_seq_match = input
        .prev_seq
        .checked_add(1)
        .is_some_and(|next| next == input.self_seq);
    let expected_prev_match = self_prev.as_ref() == Some(&prev_id);
    let expected = expected_seq_match && expected_prev_match;
    assert_eq!(
        result, expected,
        "follows({{seq: {}}}, prev_id) on (self.seq={}, self.prev={:?}) returned {result}; expected {expected}",
        input.prev_seq, input.self_seq, self_prev
    );

    // ── PROPERTY 3 (variant): wrong predecessor id ─────────────────────
    if input.prev_id_bytes != input.other_id_bytes {
        let with_other = self_event.follows(&prev_event, &other_id);
        // Either the seq math fails or the prev pointer fails — both
        // make follows() return false unless self.prev happens to equal
        // other_id.
        let other_prev_match = self_prev.as_ref() == Some(&other_id);
        let other_expected = expected_seq_match && other_prev_match;
        assert_eq!(
            with_other, other_expected,
            "follows with wrong prev_id returned {with_other}; expected {other_expected}"
        );
    }

    // ── PROPERTY 6: u64::MAX overflow ──────────────────────────────────
    let max_prev = make_event(u64::MAX, None);
    let succ_of_max = make_event(0, Some(prev_id));
    assert!(
        !succ_of_max.follows(&max_prev, &prev_id),
        "follows on prev.seq=u64::MAX accepted an apparent successor"
    );
});

/// Once-gated anchors: hand-picked branch coverage.
fn assert_audit_follows_anchored() {
    let prev_id = ObjectId::from_bytes([0xAAu8; 32]);
    let other_id = ObjectId::from_bytes([0xBBu8; 32]);

    // (a) is_genesis truth table.
    let g = make_event(0, None);
    assert!(g.is_genesis(), "ANCHOR: seq=0+prev=None must be genesis");
    let g_with_prev = make_event(0, Some(prev_id));
    assert!(
        !g_with_prev.is_genesis(),
        "ANCHOR REGRESSION: seq=0 with prev=Some classified as genesis"
    );
    let nonzero_seq = make_event(1, None);
    assert!(
        !nonzero_seq.is_genesis(),
        "ANCHOR REGRESSION: seq>0 classified as genesis"
    );

    // (b) follows happy path.
    let prev = make_event(5, None);
    let succ = make_event(6, Some(prev_id));
    assert!(
        succ.follows(&prev, &prev_id),
        "ANCHOR: legitimate successor must follow"
    );

    // (c) Wrong predecessor id.
    assert!(
        !succ.follows(&prev, &other_id),
        "ANCHOR REGRESSION: follows accepted wrong prev_id"
    );

    // (d) Wrong seq (delta=2).
    let succ_skip = make_event(7, Some(prev_id));
    assert!(
        !succ_skip.follows(&prev, &prev_id),
        "ANCHOR REGRESSION: follows accepted seq=7 after seq=5"
    );

    // (e) Wrong seq (delta=0).
    let succ_dup = make_event(5, Some(prev_id));
    assert!(
        !succ_dup.follows(&prev, &prev_id),
        "ANCHOR REGRESSION: follows accepted seq=5 after seq=5 (duplicate)"
    );

    // (f) Genesis cannot follow.
    let genesis = make_event(0, None);
    assert!(
        !genesis.follows(&prev, &prev_id),
        "ANCHOR REGRESSION: genesis classified as following another event"
    );

    // (g) u64::MAX overflow.
    let max_prev = make_event(u64::MAX, None);
    let succ_of_max = make_event(0, Some(prev_id));
    assert!(
        !succ_of_max.follows(&max_prev, &prev_id),
        "ANCHOR REGRESSION: follows on prev.seq=u64::MAX accepted (overflow)"
    );

    // (h) Self-link rejection.
    let alone = make_event(5, Some(prev_id));
    assert!(
        !alone.follows(&alone, &prev_id),
        "ANCHOR REGRESSION: event followed itself"
    );

    // (i) prev=None on self → cannot follow anything.
    let succ_no_prev = make_event(6, None);
    assert!(
        !succ_no_prev.follows(&prev, &prev_id),
        "ANCHOR REGRESSION: event with prev=None classified as following"
    );
}
