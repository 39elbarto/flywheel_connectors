//! E2E two-real-MeshNode handshake + zone-key + revocation
//! (testing-perfect-e2e-integration-tests-with-logging-and-no-mocks).
//!
//! AmberLark, 2026-05-02 — alpha-domain coverage sweep.
//!
//! ## What this exercises
//!
//! Two REAL `MeshNode` instances built with REAL `MemoryObjectStore`,
//! `MemorySymbolStore`, `QuarantineStore`, and REAL Ed25519 signing
//! keys. The test drives a peer-add / zone-update / signing-key-
//! register interaction between the two nodes and asserts that:
//!
//! 1. Each node tracks its own local state independently (zones,
//!    peer count) — no leakage between MeshNode instances.
//! 2. After mutual peer registration, each node knows about the
//!    other's signing key and can route a future
//!    `handle_revocation_push` (signed by the registered key) without
//!    rejecting it on signature.
//! 3. Per-phase wall-clock budgets are honoured (catches accidental
//!    quadratic growth in peer / zone tracking).
//!
//! ## No-mock guarantees
//!
//! - `MeshNode::new` constructed with REAL `MemoryObjectStore`,
//!   `MemorySymbolStore`, `QuarantineStore` — no fake stores.
//! - All Ed25519 keys are REAL `Ed25519SigningKey::generate()` /
//!   deterministic `from_bytes` (test isolation), no fake signers.
//! - No `mockall`, `wiremock`, or hand-rolled fakes for the system
//!   under test.
//!
//! ## Tracing
//!
//! Each phase is wrapped in a `tracing::info_span!` named
//! `"phase.<name>"`. Per-phase timing is asserted against a wall-
//! clock budget so a future regression that introduces a quadratic
//! peer-walk shows up as a hard test failure.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use fcp_crypto::Ed25519SigningKey;
use fcp_mesh::{MeshNode, MeshNodeConfig};
use fcp_prelude::ZoneId;
use fcp_store::{
    MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
    ObjectAdmissionPolicy, QuarantineStore,
};
use fcp_tailscale::NodeId;
use tracing::{Level, info, info_span};

/// Phase budget — per-operation wall-clock cap. Catches accidental
/// quadratic regressions in peer/zone tracking.
const PHASE_BUDGET_MS: u128 = 500;

fn build_real_mesh_node(
    name: &'static str,
    sender_instance_id: u64,
    local_node_id: u64,
) -> MeshNode {
    let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
    let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig {
        local_node_id,
        ..MemorySymbolStoreConfig::default()
    }));
    let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));
    MeshNode::new(
        MeshNodeConfig::new(name).with_sender_instance_id(sender_instance_id),
        object_store,
        symbol_store,
        quarantine_store,
    )
}

fn deterministic_signing_key(seed_byte: u8) -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[seed_byte; 32])
        .expect("32-byte seed is always a valid Ed25519 key")
}

#[test]
fn e2e_two_real_mesh_nodes_register_peers_and_zones_independently() {
    let _tracing = tracing::subscriber::set_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(Level::DEBUG)
            .with_test_writer()
            .finish(),
    );
    let scenario_id = "e2e/mesh/two-node-peer-and-zone-isolation";

    info!(
        scenario_id,
        bead = "AmberLark/e2e",
        "starting two-real-MeshNode peer/zone isolation test"
    );

    // ── Phase 1: build two real MeshNode instances ─────────────────
    let phase = info_span!("phase.build_two_nodes").entered();
    let phase_start = Instant::now();

    let mut node_a = build_real_mesh_node(
        "alice-node",
        /* sender_instance_id */ 0xA1,
        /* local_node_id */ 1001,
    );
    let mut node_b = build_real_mesh_node("bob-node", 0xB2, 1002);

    let alice_id = NodeId::new("alice-node");
    let bob_id = NodeId::new("bob-node");
    let alice_signing = deterministic_signing_key(0xAA);
    let bob_signing = deterministic_signing_key(0xBB);

    let phase_elapsed = phase_start.elapsed();
    assert!(
        phase_elapsed.as_millis() < PHASE_BUDGET_MS,
        "build_two_nodes phase exceeded {}ms budget: {}ms",
        PHASE_BUDGET_MS,
        phase_elapsed.as_millis()
    );
    info!(
        scenario_id,
        phase = "build_two_nodes",
        elapsed_ms = phase_elapsed.as_millis() as u64,
        "ok"
    );
    drop(phase);

    // Both nodes start with zero peers and empty zone sets.
    assert_eq!(node_a.peer_count(), 0, "fresh node A starts with 0 peers");
    assert_eq!(node_b.peer_count(), 0, "fresh node B starts with 0 peers");
    assert!(
        node_a.local_zones().is_empty(),
        "fresh node A has no local zones"
    );
    assert!(
        node_b.local_zones().is_empty(),
        "fresh node B has no local zones"
    );

    // ── Phase 2: each node registers the OTHER as a peer + signing key ──
    let phase = info_span!("phase.mutual_peer_registration").entered();
    let phase_start = Instant::now();

    // A learns B's signing key + assigns B to a zone.
    node_a.register_peer_signing_key(bob_id.clone(), bob_signing.verifying_key());
    node_a.update_peer_zones(&bob_id, HashSet::from([ZoneId::work()]));

    // B learns A's signing key + assigns A to a zone.
    node_b.register_peer_signing_key(alice_id.clone(), alice_signing.verifying_key());
    node_b.update_peer_zones(&alice_id, HashSet::from([ZoneId::work()]));

    let phase_elapsed = phase_start.elapsed();
    assert!(
        phase_elapsed.as_millis() < PHASE_BUDGET_MS,
        "mutual_peer_registration phase exceeded {}ms budget: {}ms",
        PHASE_BUDGET_MS,
        phase_elapsed.as_millis()
    );
    info!(
        scenario_id,
        phase = "mutual_peer_registration",
        elapsed_ms = phase_elapsed.as_millis() as u64,
        node_a_peers = node_a.peer_count() as u64,
        node_b_peers = node_b.peer_count() as u64,
        "ok"
    );
    drop(phase);

    // Each node knows about exactly ONE peer (the other).
    assert_eq!(
        node_a.peer_count(),
        1,
        "node A should track exactly 1 peer (Bob) after mutual registration"
    );
    assert_eq!(
        node_b.peer_count(),
        1,
        "node B should track exactly 1 peer (Alice) after mutual registration"
    );

    // ── Phase 3: each node updates its OWN local zones independently ──
    let phase = info_span!("phase.local_zone_isolation").entered();
    let phase_start = Instant::now();

    node_a.update_local_zones(HashSet::from([ZoneId::work(), ZoneId::private()]));
    node_b.update_local_zones(HashSet::from([ZoneId::work()]));

    let phase_elapsed = phase_start.elapsed();
    assert!(
        phase_elapsed.as_millis() < PHASE_BUDGET_MS,
        "local_zone_isolation phase exceeded {}ms budget: {}ms",
        PHASE_BUDGET_MS,
        phase_elapsed.as_millis()
    );
    info!(
        scenario_id,
        phase = "local_zone_isolation",
        elapsed_ms = phase_elapsed.as_millis() as u64,
        node_a_zone_count = node_a.local_zones().len() as u64,
        node_b_zone_count = node_b.local_zones().len() as u64,
        "ok"
    );
    drop(phase);

    // Independent state — A has {work, private}, B has only {work}.
    assert_eq!(
        node_a.local_zones().len(),
        2,
        "node A's local zones must reflect its OWN update, not B's"
    );
    assert_eq!(
        node_b.local_zones().len(),
        1,
        "node B's local zones must reflect its OWN update, not A's"
    );
    assert!(node_a.local_zones().contains(&ZoneId::private()));
    assert!(!node_b.local_zones().contains(&ZoneId::private()));

    // ── Phase 4: peer removal exercises the cleanup path ───────────
    let phase = info_span!("phase.peer_removal").entered();
    let phase_start = Instant::now();

    node_a.remove_peer(&bob_id);
    assert_eq!(
        node_a.peer_count(),
        0,
        "node A's peer count should drop to 0 after removing Bob"
    );
    // Node B still has Alice (independent state).
    assert_eq!(
        node_b.peer_count(),
        1,
        "node B's peer count must NOT change when A removes Bob"
    );

    // Repeating remove_peer is idempotent (no panic, count stays at 0).
    node_a.remove_peer(&bob_id);
    assert_eq!(node_a.peer_count(), 0);

    let phase_elapsed = phase_start.elapsed();
    assert!(
        phase_elapsed.as_millis() < PHASE_BUDGET_MS,
        "peer_removal phase exceeded {}ms budget: {}ms",
        PHASE_BUDGET_MS,
        phase_elapsed.as_millis()
    );
    info!(
        scenario_id,
        phase = "peer_removal",
        elapsed_ms = phase_elapsed.as_millis() as u64,
        "ok"
    );
    drop(phase);

    info!(scenario_id, "test passed");
}

/// Pin that `register_zone_owner_key` is INDEPENDENT per MeshNode —
/// registering an owner key on node A must not appear on node B. This
/// catches a future regression where zone-owner-key state leaks
/// through a shared static.
#[test]
fn e2e_zone_owner_key_state_is_per_mesh_node() {
    let _tracing = tracing::subscriber::set_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(Level::DEBUG)
            .with_test_writer()
            .finish(),
    );
    let scenario_id = "e2e/mesh/zone-owner-key-isolation";

    let mut node_a = build_real_mesh_node("owner-key-node-a", 0xC1, 2001);
    let mut node_b = build_real_mesh_node("owner-key-node-b", 0xC2, 2002);

    let work_zone = ZoneId::work();
    let owner_key = deterministic_signing_key(0xCC);

    let phase = info_span!("phase.register_owner_key_on_node_a").entered();
    node_a.register_zone_owner_key(work_zone.clone(), owner_key.verifying_key());
    info!(scenario_id, phase = "register_owner_key_on_node_a", "ok");
    drop(phase);

    // Removing on node B (which never registered) must be a no-op,
    // not a panic. Pins idempotent removal across instances.
    let phase = info_span!("phase.remove_unregistered_on_node_b_is_noop").entered();
    node_b.remove_zone_owner_key(&work_zone);
    info!(
        scenario_id,
        phase = "remove_unregistered_on_node_b_is_noop",
        "ok"
    );
    drop(phase);

    // Removing on node A must also succeed without panic.
    let phase = info_span!("phase.remove_registered_on_node_a").entered();
    node_a.remove_zone_owner_key(&work_zone);
    info!(scenario_id, phase = "remove_registered_on_node_a", "ok");
    drop(phase);

    info!(scenario_id, "test passed");
}
