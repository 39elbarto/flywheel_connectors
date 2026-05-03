//! br-zhmuc — Conformance mirror for `MeshGossip::create_summary` and
//! `GossipSummary::signing_bytes`. Covers the anti-entropy summary
//! invariants from Van Renesse et al. "Efficient Reconciliation and
//! Flow Control for Anti-Entropy Protocols" (2008) as adapted by FCP:
//!
//!   MSH-GS-1 — summary is deterministic for a fixed zone state
//!   MSH-GS-2 — signing_bytes detects any single-byte tamper
//!   MSH-GS-4 — two peers with identical state produce byte-identical
//!              *payload* summaries (timestamp + from excluded)
//!   MSH-GS-5 — differs_from only flags digest deltas, not metadata
//!
//! Cross-reference: 2ot4f audit (signature verification) closed MSH-GS-3
//! via MeshNode::verify_summary_signature; forged-signature regression
//! tests already land in crates/fcp-mesh/src/node.rs.

use fcp_mesh::admission::ObjectAdmissionClass;
use fcp_mesh::gossip::{GossipSummary, MeshGossip};
use fcp_prelude::{EpochId, ObjectId, TailscaleNodeId, ZoneId};

fn obj(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn build_gossip_with_objects(node: &str, zone: &ZoneId, items: &[&str]) -> MeshGossip {
    let mut gossip = MeshGossip::with_defaults(TailscaleNodeId::new(node));
    for (idx, name) in items.iter().enumerate() {
        gossip.announce_object(
            zone,
            &obj(name),
            ObjectAdmissionClass::Admitted,
            1_000 + idx as u64,
        );
    }
    gossip
}

fn fresh_summary(gossip: &MeshGossip, zone: &ZoneId, epoch: &str) -> GossipSummary {
    gossip
        .create_summary(zone, EpochId::new(epoch))
        .expect("zone has at least one announced object")
}

// ── MSH-GS-1: determinism of per-peer summary for a fixed state ──────

#[test]
fn msh_gs_1_summary_for_fixed_state_is_deterministic() {
    let zone = ZoneId::work();
    let gossip = build_gossip_with_objects("node-det", &zone, &["alpha", "beta", "gamma"]);

    let s1 = fresh_summary(&gossip, &zone, "epoch-1");
    let s2 = fresh_summary(&gossip, &zone, "epoch-1");
    assert_eq!(s1.object_filter_digest, s2.object_filter_digest);
    assert_eq!(s1.symbol_filter_digest, s2.symbol_filter_digest);
    assert_eq!(s1.object_count, s2.object_count);
    assert_eq!(s1.symbol_count, s2.symbol_count);
    assert_eq!(s1.iblt, s2.iblt);
}

// ── MSH-GS-2: signing_bytes detects single-byte tamper on every field ─

#[test]
fn msh_gs_2_signing_bytes_flips_when_any_payload_byte_changes() {
    // Generate a reference summary, then mutate each payload field
    // exactly once and assert the signing-transcript bytes differ.
    let zone = ZoneId::work();
    let gossip = build_gossip_with_objects("node-tamper", &zone, &["alpha", "beta"]);
    let reference = fresh_summary(&gossip, &zone, "epoch-A");
    let reference_bytes = reference.signing_bytes();

    let mutate_object_digest = {
        let mut summary = reference.clone();
        summary.object_filter_digest[0] ^= 0x01;
        summary
    };
    let mutate_symbol_digest = {
        let mut summary = reference.clone();
        summary.symbol_filter_digest[0] ^= 0x01;
        summary
    };
    let mutate_object_count = {
        let mut summary = reference.clone();
        summary.object_count = summary.object_count.wrapping_add(1);
        summary
    };
    let mutate_symbol_count = {
        let mut summary = reference.clone();
        summary.symbol_count = summary.symbol_count.wrapping_add(1);
        summary
    };
    let mutate_timestamp = {
        let mut summary = reference.clone();
        summary.timestamp = summary.timestamp.wrapping_add(1);
        summary
    };
    let mutate_iblt = {
        let mut summary = reference.clone();
        if summary.iblt.is_empty() {
            summary.iblt.push(0xFF);
        } else {
            summary.iblt[0] ^= 0x01;
        }
        summary
    };
    let mutate_epoch = {
        let mut summary = reference.clone();
        summary.epoch_id = EpochId::new("epoch-A-bis");
        summary
    };
    let mutate_zone = {
        let mut summary = reference.clone();
        summary.zone_id = ZoneId::private();
        summary
    };
    let mutate_from = {
        let mut summary = reference.clone();
        summary.from = TailscaleNodeId::new("someone-else");
        summary
    };

    for (name, mutated) in [
        ("object_digest", mutate_object_digest),
        ("symbol_digest", mutate_symbol_digest),
        ("object_count", mutate_object_count),
        ("symbol_count", mutate_symbol_count),
        ("timestamp", mutate_timestamp),
        ("iblt", mutate_iblt),
        ("epoch_id", mutate_epoch),
        ("zone_id", mutate_zone),
        ("from", mutate_from),
    ] {
        assert_ne!(
            mutated.signing_bytes(),
            reference_bytes,
            "MSH-GS-2: single-byte tamper of {name} must change signing bytes"
        );
    }
}

// ── MSH-GS-4: identical zone state → byte-identical summary payload ──

#[test]
fn msh_gs_4_same_zone_state_same_payload_across_peers() {
    let zone = ZoneId::work();
    let items = &["apple", "banana", "cherry", "date"];
    let peer_a = build_gossip_with_objects("peer-a", &zone, items);
    let peer_b = build_gossip_with_objects("peer-b", &zone, items);

    let sa = fresh_summary(&peer_a, &zone, "epoch-42");
    let sb = fresh_summary(&peer_b, &zone, "epoch-42");

    // Payload-level equality — `from` and `timestamp` are metadata,
    // the anti-entropy payload (digests, counts, IBLT) MUST agree.
    assert_eq!(sa.object_filter_digest, sb.object_filter_digest, "MSH-GS-4");
    assert_eq!(sa.symbol_filter_digest, sb.symbol_filter_digest, "MSH-GS-4");
    assert_eq!(sa.object_count, sb.object_count, "MSH-GS-4");
    assert_eq!(sa.symbol_count, sb.symbol_count, "MSH-GS-4");
    assert_eq!(sa.iblt, sb.iblt, "MSH-GS-4");
    assert!(
        !sa.differs_from(&sb),
        "MSH-GS-4: equal-state peers must not differ"
    );
}

// ── MSH-GS-5: differs_from reflects only digest deltas ───────────────

#[test]
fn msh_gs_5_differs_from_flags_new_object_addition() {
    let zone = ZoneId::work();
    let base = build_gossip_with_objects("peer-base", &zone, &["x", "y"]);
    let ahead = build_gossip_with_objects("peer-ahead", &zone, &["x", "y", "z"]);

    let s_base = fresh_summary(&base, &zone, "epoch-d");
    let s_ahead = fresh_summary(&ahead, &zone, "epoch-d");
    assert!(
        s_base.differs_from(&s_ahead),
        "MSH-GS-5: peers with a different object set MUST differ"
    );
}

#[test]
fn msh_gs_5_differs_from_ignores_timestamp_drift() {
    // Two summaries from the same zone state but stamped at different
    // wall-clock times MUST NOT trigger reconciliation — the digests
    // are unchanged, so differs_from returns false.
    let zone = ZoneId::work();
    let gossip = build_gossip_with_objects("peer-time", &zone, &["only"]);
    let early = fresh_summary(&gossip, &zone, "epoch-t");
    let mut late = early.clone();
    late.timestamp = late.timestamp.saturating_add(60);
    assert!(
        !early.differs_from(&late),
        "MSH-GS-5: timestamp drift alone must not flag a difference"
    );
}

#[test]
fn msh_gs_5_differs_from_flags_object_removal() {
    // The existing MSH-GS-5 test only exercises addition. A malformed
    // digest implementation that handled added objects but ignored
    // removed ones would silently fail to reconcile shrinking zones —
    // peers that dropped an object would never resync the residue. Pin
    // both directions of the asymmetric difference here.
    let zone = ZoneId::work();
    let larger = build_gossip_with_objects("peer-large", &zone, &["x", "y", "z"]);
    let smaller = build_gossip_with_objects("peer-small", &zone, &["x", "y"]);

    let s_large = fresh_summary(&larger, &zone, "epoch-rm");
    let s_small = fresh_summary(&smaller, &zone, "epoch-rm");
    assert!(
        s_large.differs_from(&s_small),
        "MSH-GS-5: removal of an object MUST flip the digest (large vs small)"
    );
    assert!(
        s_small.differs_from(&s_large),
        "MSH-GS-5: removal must be symmetric — small vs large MUST also differ"
    );
}

// ── MSH-GS-6: is_stale freshness window (past-TTL + future-skew) ──────

#[test]
fn msh_gs_6_is_stale_false_for_summary_within_ttl() {
    // A summary stamped one second in the past with a 60-second TTL
    // MUST be considered fresh.
    let zone = ZoneId::work();
    let gossip = build_gossip_with_objects("peer-fresh", &zone, &["a"]);
    let mut summary = fresh_summary(&gossip, &zone, "epoch-fresh");
    let now = 1_000_000_u64;
    summary.timestamp = now - 1;
    assert!(
        !summary.is_stale(now, 60, 60),
        "MSH-GS-6: summary 1s old with 60s TTL must NOT be stale"
    );
}

#[test]
fn msh_gs_6_is_stale_true_for_summary_past_ttl() {
    let zone = ZoneId::work();
    let gossip = build_gossip_with_objects("peer-old", &zone, &["a"]);
    let mut summary = fresh_summary(&gossip, &zone, "epoch-old");
    let now = 1_000_000_u64;
    summary.timestamp = now - 61;
    assert!(
        summary.is_stale(now, 60, 60),
        "MSH-GS-6: summary 61s old with 60s TTL MUST be stale"
    );
}

#[test]
fn msh_gs_6_is_stale_false_for_summary_within_future_skew() {
    // Slightly future timestamps inside `max_future_skew_secs` are
    // legitimate clock drift and MUST NOT be flagged as stale.
    let zone = ZoneId::work();
    let gossip = build_gossip_with_objects("peer-skew", &zone, &["a"]);
    let mut summary = fresh_summary(&gossip, &zone, "epoch-skew");
    let now = 1_000_000_u64;
    summary.timestamp = now + 30;
    assert!(
        !summary.is_stale(now, 60, 60),
        "MSH-GS-6: summary 30s in the future with 60s skew window MUST NOT be stale"
    );
}

#[test]
fn msh_gs_6_is_stale_true_for_summary_beyond_future_skew() {
    // The regression this guards against is documented on
    // `GossipSummary::is_stale`: future-dated summaries used to slip
    // past the `age > ttl_secs` check because `saturating_sub` on a
    // future timestamp returns `0`. The future-skew bound MUST reject
    // arbitrarily future-dated summaries.
    let zone = ZoneId::work();
    let gossip = build_gossip_with_objects("peer-far-future", &zone, &["a"]);
    let mut summary = fresh_summary(&gossip, &zone, "epoch-far-future");
    let now = 1_000_000_u64;
    summary.timestamp = now + 61;
    assert!(
        summary.is_stale(now, 60, 60),
        "MSH-GS-6: summary 61s in the future with 60s skew window MUST be stale \
         (regression guard: saturating_sub-zero on future timestamps used to bypass TTL)"
    );
}

#[test]
fn msh_gs_6_is_stale_true_for_summary_far_in_past_zero_skew() {
    // Zero-skew configuration must still reject very-old summaries.
    let zone = ZoneId::work();
    let gossip = build_gossip_with_objects("peer-zero-skew", &zone, &["a"]);
    let mut summary = fresh_summary(&gossip, &zone, "epoch-zero-skew");
    let now = 1_000_000_u64;
    summary.timestamp = now.saturating_sub(3_600);
    assert!(
        summary.is_stale(now, 60, 0),
        "MSH-GS-6: summary 1h old with 60s TTL MUST be stale even with zero future-skew"
    );
}
