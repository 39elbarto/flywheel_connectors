//! Conformance coverage for masked mesh IBLT reconciliation and the layered
//! Bloom+XOR route hint budget.
//!
//! These tests pin the Phase A.bis.2 anti-entropy contract from
//! `flywheel_connectors-angoc.17.2`: IBLT wire sketches are zone-masked,
//! small multi-peer divergences converge through bounded reconciliation, and
//! corrupted sketches are rejected without mutating peer state.

use std::collections::{BTreeSet, HashSet};

use fcp_audit::{AuditEntryBuilder, Severity, verify_chain};
use fcp_mesh::admission::ObjectAdmissionClass;
use fcp_mesh::gossip::{GossipConfig, GossipSummary, MAX_OBJECT_IDS_PER_REQUEST, MeshGossip};
use fcp_mesh::iblt::{
    Iblt, IbltMask, LayeredFilterConfig, LayeredReconciliationFilter, MaskedIblt,
};
use fcp_prelude::{EpochId, ObjectId, TailscaleNodeId, ZoneId};
use serde_json::json;

fn obj(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn node(label: &str) -> TailscaleNodeId {
    TailscaleNodeId::new(label)
}

fn announce_all(gossip: &mut MeshGossip, zone: &ZoneId, labels: &[&str], timestamp: u64) {
    for label in labels {
        gossip.announce_object(zone, &obj(label), ObjectAdmissionClass::Admitted, timestamp);
    }
}

fn reconcile_pair(
    left: &mut MeshGossip,
    left_id: &TailscaleNodeId,
    right: &mut MeshGossip,
    right_id: &TailscaleNodeId,
    zone: &ZoneId,
    now: u64,
) {
    let right_iblt = right
        .build_zone_iblt(zone, 64)
        .expect("right zone should exist");
    let response = left
        .reconcile_zone_iblt(zone, right_id, &right_iblt, 64, now)
        .expect("same-zone masked IBLT reconciliation should decode");

    for object_id in response.we_missing_objects {
        left.announce_object(zone, &object_id, ObjectAdmissionClass::Admitted, now);
    }
    for object_id in response.peer_missing_objects {
        right.announce_object(zone, &object_id, ObjectAdmissionClass::Admitted, now);
    }

    let left_iblt = left
        .build_zone_iblt(zone, 64)
        .expect("left zone should exist after reconcile");
    let response = right
        .reconcile_zone_iblt(zone, left_id, &left_iblt, 64, now + 1)
        .expect("reverse same-zone masked IBLT reconciliation should decode");
    for object_id in response.we_missing_objects {
        right.announce_object(zone, &object_id, ObjectAdmissionClass::Admitted, now + 1);
    }
    for object_id in response.peer_missing_objects {
        left.announce_object(zone, &object_id, ObjectAdmissionClass::Admitted, now + 1);
    }
}

fn object_set(gossip: &MeshGossip, zone: &ZoneId) -> BTreeSet<ObjectId> {
    gossip
        .list_objects_in_zone(zone, 10_000)
        .into_iter()
        .collect()
}

#[test]
fn cross_peer_reconciliation_3way_converges_to_identical_payloads() {
    let zone = ZoneId::work();
    let epoch = EpochId::new("masked-iblt-conformance");
    let alpha_id = node("node-a");
    let beta_peer = node("node-b");
    let gamma_peer = node("node-c");
    let mut node_a = MeshGossip::with_defaults(alpha_id.clone());
    let mut node_b = MeshGossip::with_defaults(beta_peer.clone());
    let mut node_c = MeshGossip::with_defaults(gamma_peer.clone());

    announce_all(&mut node_a, &zone, &["shared-0", "shared-1", "a-only"], 1);
    announce_all(&mut node_b, &zone, &["shared-0", "shared-1", "b-only"], 1);
    announce_all(&mut node_c, &zone, &["shared-0", "shared-1", "c-only"], 1);

    for round in 0..2 {
        let now = 10 + round * 10;
        reconcile_pair(&mut node_a, &alpha_id, &mut node_b, &beta_peer, &zone, now);
        reconcile_pair(
            &mut node_b,
            &beta_peer,
            &mut node_c,
            &gamma_peer,
            &zone,
            now + 2,
        );
        reconcile_pair(
            &mut node_a,
            &alpha_id,
            &mut node_c,
            &gamma_peer,
            &zone,
            now + 4,
        );
    }

    let a_objects = object_set(&node_a, &zone);
    let b_objects = object_set(&node_b, &zone);
    let c_objects = object_set(&node_c, &zone);
    assert_eq!(a_objects, b_objects);
    assert_eq!(b_objects, c_objects);
    assert_eq!(a_objects.len(), 5);

    let summary_a = node_a
        .create_summary(&zone, epoch.clone())
        .expect("node A summary");
    let summary_b = node_b
        .create_summary(&zone, epoch.clone())
        .expect("node B summary");
    let summary_c = node_c.create_summary(&zone, epoch).expect("node C summary");

    assert_eq!(
        summary_a.object_filter_digest,
        summary_b.object_filter_digest
    );
    assert_eq!(
        summary_b.object_filter_digest,
        summary_c.object_filter_digest
    );
    assert_eq!(summary_a.object_count, summary_b.object_count);
    assert_eq!(summary_b.object_count, summary_c.object_count);
    assert_eq!(summary_a.iblt, summary_b.iblt);
    assert_eq!(summary_b.iblt, summary_c.iblt);
}

#[test]
fn summary_iblt_wire_contains_masked_keys_not_raw_object_ids() {
    let zone = ZoneId::work();
    let object_id = obj("wire-mask-singleton");
    let mut gossip = MeshGossip::with_defaults(node("masked-wire"));
    gossip.announce_object(&zone, &object_id, ObjectAdmissionClass::Admitted, 1);

    let summary = gossip
        .create_summary(&zone, EpochId::new("wire-mask"))
        .expect("summary should exist");
    let wire_iblt: Iblt = ciborium::from_reader(summary.iblt.as_slice()).expect("CBOR IBLT");
    let empty = Iblt::with_cell_count(wire_iblt.cell_count()).expect("matching empty sketch");
    let decoded_wire = wire_iblt
        .subtract(&empty)
        .expect("matching cell count")
        .decode();

    assert!(decoded_wire.is_complete());
    assert!(!decoded_wire.only_left.contains(&object_id));
    assert!(
        decoded_wire
            .only_left
            .contains(&IbltMask::for_zone(&zone).apply(object_id))
    );
}

#[test]
fn layered_filter_fpr_budget_conformance() {
    let config = LayeredFilterConfig::default();
    let members = (0..1_000)
        .map(|index| format!("member-{index:04}"))
        .collect::<Vec<_>>();
    let filter =
        LayeredReconciliationFilter::from_items(99, config, members.iter().map(String::as_bytes));

    for member in &members {
        assert!(filter.may_contain(member.as_bytes()));
    }

    let member_set = members.iter().cloned().collect::<HashSet<_>>();
    let false_positives = (0..10_000)
        .filter(|index| {
            let candidate = format!("non-member-{index:04}");
            !member_set.contains(&candidate) && filter.may_contain(candidate.as_bytes())
        })
        .count();
    let observed =
        f64::from(u32::try_from(false_positives).expect("query count fits u32")) / 10_000.0;

    assert!(
        observed < config.target_fpr,
        "observed false-positive rate {observed} exceeded {}",
        config.target_fpr
    );
}

#[test]
fn corrupted_summary_iblt_is_structured_rejection_without_peer_mutation() {
    let zone = ZoneId::work();
    let mut gossip = MeshGossip::new(node("receiver"), GossipConfig::default());
    let summary = GossipSummary {
        from: node("peer-corrupt"),
        zone_id: zone,
        epoch_id: EpochId::new("corrupt"),
        object_filter_digest: [0; 32],
        symbol_filter_digest: [0; 32],
        object_count: 1,
        symbol_count: 0,
        iblt: vec![0xDE, 0xAD, 0xBE, 0xEF],
        timestamp: 1,
        signature: None,
    };

    assert!(!gossip.handle_summary(summary, 1));
    assert_eq!(gossip.peer_count(), 0);
}

#[test]
fn overflow_fallback_is_audit_chain_verifiable() {
    let zone = ZoneId::work();
    let local_peer = node("local-overflow");
    let remote_peer = node("remote-overflow");
    let mut gossip = MeshGossip::with_defaults(local_peer.clone());
    gossip.announce_object(
        &zone,
        &obj("local-anchor"),
        ObjectAdmissionClass::Admitted,
        1,
    );

    let expected_difference = 1;
    let mask = IbltMask::for_zone(&zone);
    let mut overloaded_peer = MaskedIblt::with_expected_difference(mask, expected_difference);
    for index in 0..(MAX_OBJECT_IDS_PER_REQUEST * 3) {
        overloaded_peer.insert(obj(&format!("remote-overflow-{index:04}")));
    }

    let local_iblt = gossip
        .build_zone_iblt(&zone, expected_difference)
        .expect("local zone IBLT");
    let raw_diff = local_iblt
        .subtract(overloaded_peer.as_iblt())
        .expect("matching cell count")
        .decode();
    assert!(
        !raw_diff.is_complete(),
        "overloaded peer sketch should require fallback"
    );

    let response = gossip
        .reconcile_zone_iblt(
            &zone,
            &remote_peer,
            overloaded_peer.as_iblt(),
            expected_difference,
            2,
        )
        .expect("overflow still returns bounded fallback response");
    assert!(response.we_missing_objects.len() <= MAX_OBJECT_IDS_PER_REQUEST);

    let audit_entry = AuditEntryBuilder::new()
        .event_type("mesh.iblt.overflow_fallback")
        .severity(Severity::Warning)
        .actor(local_peer.as_str())
        .zone_id(zone.as_str())
        .seq(0)
        .occurred_at(2)
        .meta("scheme", json!("masked"))
        .meta("peer_id", json!(remote_peer.as_str()))
        .meta("overflow", json!(true))
        .meta("fallback", json!("paginated_list_exchange"))
        .meta(
            "remaining_nonzero_cells",
            json!(raw_diff.remaining_nonzero_cells),
        )
        .build_with_computed_id()
        .expect("overflow fallback audit entry should build");
    let report = verify_chain(&[audit_entry], None, Some(zone.as_str()));

    assert!(
        report.is_clean(),
        "overflow fallback audit chain should verify cleanly: {:?}",
        report.issues
    );
}
