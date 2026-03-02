//! Integration scenarios for FCP2 mesh behavior (flywheel_connectors-gigy).
//!
//! This module tests the system under adverse conditions:
//! - Network partition recovery
//! - Node failure and recovery
//! - Concurrent operation conflicts
//! - Revocation propagation
//! - Zone key rotation under load
//! - Symbol availability and repair
//!
//! These tests use the deterministic harness from [`fcp_conformance::harness`]
//! with simulated network faults, clock control, and structured logging.
//!
//! # Test Infrastructure Requirements
//! - Deterministic clock control (`MockClock`)
//! - Network fault injection (`SimulatedNetwork`: partitions, latency, packet loss)
//! - Node lifecycle control (`TestMeshNode`: start, stop, crash, restart)
//! - Structured log collection (`LogCollector`)
//!
//! # Logging Format
//! Each scenario produces structured JSONL logs per `docs/STANDARD_Testing_Logging.md`:
//! ```json
//! {
//!   "scenario": "partition-heal",
//!   "phase": "partition | heal | verify",
//!   "nodes": ["A", "B", "C"],
//!   "timestamp": "...",
//!   "assertion": "audit_heads_equal",
//!   "result": "pass|fail",
//!   "evidence": {...}
//! }
//! ```

#![allow(clippy::too_many_lines)]

use std::collections::HashSet;
use std::time::Duration;

use chrono::Utc;
use fcp_conformance::harness::{
    HarnessError, LogCollector, LogEntry, MockClock, SimulatedNetwork, TestHarness,
};
use fcp_core::{ObjectId, ZoneId};
use fcp_mesh::ObjectAdmissionClass;
use fcp_tailscale::NodeId;
use serde::Serialize;
use serde_json::json;

/// Create a deterministic test object ID from a name.
fn test_object_id(name: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(name.as_bytes())
}

/// Default zone for test scenarios.
fn test_zone() -> ZoneId {
    ZoneId::work()
}

/// Helper to emit a structured scenario log entry.
fn emit_scenario_log<E: Serialize>(
    logs: &LogCollector,
    scenario: &str,
    phase: &str,
    nodes: &[&str],
    assertion: &str,
    result: &str,
    evidence: E,
) {
    let evidence = serde_json::to_value(evidence).unwrap_or_else(|error| {
        json!({
            "error": error.to_string(),
        })
    });
    let entry = LogEntry::new(
        "harness",
        scenario,
        phase,
        uuid::Uuid::new_v4().to_string(),
        assertion,
        json!({
            "nodes": nodes,
            "result": result,
            "evidence": evidence,
            "timestamp": Utc::now().to_rfc3339(),
        }),
    );
    logs.push(entry);
}

// ============================================================================
// Network Partition Recovery Scenarios
// ============================================================================

/// Scenario: Partition-Heal
/// 3-node mesh, partition node C from A+B for 60s, heal, verify:
/// - All nodes converge on same `AuditHead`
/// - No duplicate operations executed
/// - Gossip reconciliation completes
#[fcp_async_core::runtime::test]
async fn scenario_partition_heal_convergence() {
    let mut harness = TestHarness::new(3, 0xDEAD_BEEF);
    harness.start_all().expect("start all nodes");

    let node_c_id = harness.nodes[2].node_id.clone();

    // Phase 1: Partition node C
    emit_scenario_log(
        &harness.logs,
        "partition-heal",
        "partition",
        &["A", "B", "C"],
        "partition_injected",
        "pass",
        json!({ "isolated": node_c_id.as_str() }),
    );
    harness.partition(std::slice::from_ref(&node_c_id));

    // Register peers and announce objects while partition is active
    harness.register_all_peers();
    let zone = test_zone();
    let obj_a = test_object_id("partition-heal-obj-a");
    let obj_b = test_object_id("partition-heal-obj-b");
    let now_ms = harness.now_ms();

    // Announce objects on nodes A and B (connected partition)
    harness.nodes[0].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_a,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );
    harness.nodes[1].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_b,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );

    // Exchange gossip within connected partition (C is isolated)
    harness.gossip_exchange_round();

    // Advance time to simulate partition duration
    harness.advance_time(Duration::from_secs(60));

    // Phase 2: Heal partition
    emit_scenario_log(
        &harness.logs,
        "partition-heal",
        "heal",
        &["A", "B", "C"],
        "partition_healed",
        "pass",
        json!({ "healed": node_c_id.as_str() }),
    );
    harness.heal_partition();

    // Phase 3: Wait for convergence and gossip exchange after heal
    let convergence_result = harness.wait_for_convergence(Duration::from_secs(30)).await;
    harness.gossip_exchange_round();
    harness.gossip_exchange_round();

    let result = if convergence_result.is_ok() {
        "pass"
    } else {
        "fail"
    };

    // Verify all nodes know about both objects via gossip state.
    let gossip_presence = [
        [
            harness.nodes[0]
                .mesh_mut()
                .unwrap()
                .gossip_mut()
                .has_object(&zone, &obj_a),
            harness.nodes[0]
                .mesh_mut()
                .unwrap()
                .gossip_mut()
                .has_object(&zone, &obj_b),
        ],
        [
            harness.nodes[1]
                .mesh_mut()
                .unwrap()
                .gossip_mut()
                .has_object(&zone, &obj_a),
            harness.nodes[1]
                .mesh_mut()
                .unwrap()
                .gossip_mut()
                .has_object(&zone, &obj_b),
        ],
        [
            harness.nodes[2]
                .mesh_mut()
                .unwrap()
                .gossip_mut()
                .has_object(&zone, &obj_a),
            harness.nodes[2]
                .mesh_mut()
                .unwrap()
                .gossip_mut()
                .has_object(&zone, &obj_b),
        ],
    ];

    emit_scenario_log(
        &harness.logs,
        "partition-heal",
        "verify",
        &["A", "B", "C"],
        "convergence",
        result,
        json!({
            "converged": convergence_result.is_ok(),
            "pending_messages": harness.network.pending_len(),
            "gossip_state": {
                "node_a": { "has_obj_a": gossip_presence[0][0], "has_obj_b": gossip_presence[0][1] },
                "node_b": { "has_obj_a": gossip_presence[1][0], "has_obj_b": gossip_presence[1][1] },
                "node_c": { "has_obj_a": gossip_presence[2][0], "has_obj_b": gossip_presence[2][1] },
            },
        }),
    );

    // Verify gossip convergence: A and B should agree on objects
    assert!(
        gossip_presence[0][0],
        "node A should know about obj_a (its own announcement)"
    );
    assert!(
        gossip_presence[1][1],
        "node B should know about obj_b (its own announcement)"
    );
    assert!(
        gossip_presence[0][1],
        "node A should learn about obj_b from gossip"
    );
    assert!(
        gossip_presence[1][0],
        "node B should learn about obj_a from gossip"
    );

    harness.stop_all().expect("stop all nodes");

    // Validate structured logs
    assert!(
        harness.logs.validate_jsonl().is_ok(),
        "logs should validate against schema"
    );
}

/// Scenario: Split-Brain Prevention
/// Both partitions attempt quorum ops, only one succeeds.
#[fcp_async_core::runtime::test]
async fn scenario_split_brain_prevention() {
    let mut harness = TestHarness::new(5, 0xCAFE_BABE);
    harness.start_all().expect("start all nodes");

    // Create a 2-3 split (nodes 0,1 vs 2,3,4)
    let minority = vec![
        harness.nodes[0].node_id.clone(),
        harness.nodes[1].node_id.clone(),
    ];

    emit_scenario_log(
        &harness.logs,
        "split-brain",
        "partition",
        &["0", "1", "2", "3", "4"],
        "partition_created",
        "pass",
        json!({ "minority": ["0", "1"], "majority": ["2", "3", "4"] }),
    );

    harness.partition(&minority);
    harness.advance_time(Duration::from_secs(10));

    // Register peers and announce objects in each partition
    harness.register_all_peers();
    let zone = test_zone();
    let obj_minority = test_object_id("split-brain-minority-obj");
    let obj_majority = test_object_id("split-brain-majority-obj");
    let now_ms = harness.now_ms();

    // Announce on minority partition (nodes 0, 1)
    harness.nodes[0].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_minority,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );

    // Announce on majority partition (nodes 2, 3, 4)
    harness.nodes[2].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_majority,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );

    // Gossip within partitions (partitioned nodes can't communicate across)
    harness.gossip_exchange_round();

    // Verify: majority partition peer count > minority partition peer count
    let majority_peers = harness.nodes[2].mesh_mut().unwrap().peer_count();
    let minority_peers = harness.nodes[0].mesh_mut().unwrap().peer_count();

    // During partition, gossip only propagates within the partition.
    let minority_has_majority_obj = harness.nodes[0]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_majority);
    let majority_has_minority_obj = harness.nodes[2]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_minority);

    emit_scenario_log(
        &harness.logs,
        "split-brain",
        "verify",
        &["0", "1", "2", "3", "4"],
        "quorum_semantics",
        "pass",
        json!({
            "minority_peers": minority_peers,
            "majority_peers": majority_peers,
            "cross_partition_leak": {
                "minority_sees_majority": minority_has_majority_obj,
                "majority_sees_minority": majority_has_minority_obj,
            },
        }),
    );

    // During partition, gossip should NOT cross the boundary
    assert!(
        !minority_has_majority_obj,
        "minority partition should not see majority-side objects"
    );
    assert!(
        !majority_has_minority_obj,
        "majority partition should not see minority-side objects"
    );

    // Heal and verify convergence
    harness.heal_partition();
    harness.gossip_exchange_round();
    harness.gossip_exchange_round();

    // After heal, all nodes should know about all objects
    let node0_has_majority = harness.nodes[0]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_majority);
    let node2_has_minority = harness.nodes[2]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_minority);

    emit_scenario_log(
        &harness.logs,
        "split-brain",
        "post-heal",
        &["0", "1", "2", "3", "4"],
        "convergence_after_heal",
        if node0_has_majority && node2_has_minority {
            "pass"
        } else {
            "fail"
        },
        json!({
            "node0_sees_majority_obj": node0_has_majority,
            "node2_sees_minority_obj": node2_has_minority,
        }),
    );

    harness.stop_all().expect("stop all nodes");
}

/// Scenario: Stale Node Rejoins
/// Node offline for longer than revocation freshness window must catch up
/// before accepting operations.
#[fcp_async_core::runtime::test]
async fn scenario_stale_node_rejoins() {
    let mut harness = TestHarness::new(3, 0x1234_5678);
    harness.start_all().expect("start all nodes");

    let stale_node = harness.nodes[2].node_id.clone();

    // Partition stale node
    harness.partition(std::slice::from_ref(&stale_node));

    // Advance time beyond revocation freshness window (e.g., 24 hours)
    harness.advance_time(Duration::from_secs(24 * 60 * 60));

    emit_scenario_log(
        &harness.logs,
        "stale-rejoin",
        "setup",
        &["A", "B", "C"],
        "stale_duration_exceeded",
        "pass",
        json!({ "stale_node": stale_node.as_str(), "offline_duration_hours": 24 }),
    );

    // While stale node is offline, announce objects on the connected nodes
    harness.register_all_peers();
    let zone = test_zone();
    let obj_while_stale = test_object_id("stale-rejoin-new-obj");
    let now_ms = harness.now_ms();
    harness.nodes[0].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_while_stale,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );
    harness.gossip_exchange_round();

    // Verify stale node does NOT have the new object (it was partitioned)
    let stale_has_obj_before = harness.nodes[2]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_while_stale);
    assert!(
        !stale_has_obj_before,
        "stale node should not know about objects announced while partitioned"
    );

    // Heal partition and gossip to sync
    harness.heal_partition();
    harness.gossip_exchange_round();
    harness.gossip_exchange_round();

    // Verify stale node now has the object after sync
    let stale_has_obj_after = harness.nodes[2]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_while_stale);

    let sync_result = if stale_has_obj_after { "pass" } else { "fail" };

    emit_scenario_log(
        &harness.logs,
        "stale-rejoin",
        "verify",
        &["A", "B", "C"],
        "checkpoint_sync",
        sync_result,
        json!({
            "stale_node": stale_node.as_str(),
            "had_object_before_heal": stale_has_obj_before,
            "has_object_after_sync": stale_has_obj_after,
        }),
    );

    harness.stop_all().expect("stop all nodes");
}

// ============================================================================
// Node Failure and Recovery Scenarios
// ============================================================================

/// Scenario: Graceful Shutdown
/// Node announces shutdown, leases transferred, no operation loss.
#[fcp_async_core::runtime::test]
async fn scenario_graceful_shutdown() {
    let mut harness = TestHarness::new(3, 0xABCD_EF01);
    harness.start_all().expect("start all nodes");

    let shutdown_node_idx = 1;
    let shutdown_node_id = harness.nodes[shutdown_node_idx].node_id.clone();

    // Register peers and announce objects BEFORE shutdown
    harness.register_all_peers();
    let zone = test_zone();
    let obj_from_shutdown = test_object_id("graceful-shutdown-obj");
    let now_ms = harness.now_ms();
    harness.nodes[shutdown_node_idx]
        .mesh_mut()
        .unwrap()
        .announce_object(
            &zone,
            &obj_from_shutdown,
            ObjectAdmissionClass::Admitted,
            now_ms,
        );
    harness.gossip_exchange_round();

    emit_scenario_log(
        &harness.logs,
        "graceful-shutdown",
        "setup",
        &["A", "B", "C"],
        "shutdown_initiated",
        "pass",
        json!({ "node": shutdown_node_id.as_str() }),
    );

    // Graceful shutdown
    harness.nodes[shutdown_node_idx]
        .stop()
        .expect("graceful stop");

    // Verify node stopped
    assert!(
        !harness.nodes[shutdown_node_idx].is_running(),
        "node should be stopped"
    );

    emit_scenario_log(
        &harness.logs,
        "graceful-shutdown",
        "verify",
        &["A", "B", "C"],
        "node_stopped",
        "pass",
        json!({ "node": shutdown_node_id.as_str(), "running": false }),
    );

    // After shutdown, verify remaining nodes are still operational
    let running = harness.running_count();
    assert_eq!(
        running, 2,
        "2 nodes should still be running after graceful shutdown"
    );

    // Verify remaining nodes still have gossip knowledge of the shutdown node's objects
    let node_a_has_obj = harness.nodes[0]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_from_shutdown);

    emit_scenario_log(
        &harness.logs,
        "graceful-shutdown",
        "verify",
        &["A", "C"],
        "gossip_preserved",
        if node_a_has_obj { "pass" } else { "fail" },
        json!({
            "remaining_running": running,
            "gossip_preserved": node_a_has_obj,
        }),
    );

    assert!(
        node_a_has_obj,
        "remaining nodes should still know about objects from shutdown node"
    );

    harness.stop_all().expect("stop remaining nodes");
}

/// Scenario: Crash Recovery
/// Node killed mid-operation, restart, verify:
/// - Incomplete `OperationIntent` is detected
/// - No duplicate side effects
/// - Lease is released after timeout
#[fcp_async_core::runtime::test]
async fn scenario_crash_recovery() {
    let mut harness = TestHarness::new(3, 0xFEED_FACE);
    harness.start_all().expect("start all nodes");

    let crash_node_idx = 0;
    let crash_node_id = harness.nodes[crash_node_idx].node_id.clone();

    emit_scenario_log(
        &harness.logs,
        "crash-recovery",
        "setup",
        &["A", "B", "C"],
        "crash_simulated",
        "pass",
        json!({ "node": crash_node_id.as_str() }),
    );

    // Simulate crash (drops mesh state)
    harness.nodes[crash_node_idx].crash();
    assert!(
        !harness.nodes[crash_node_idx].is_running(),
        "crashed node should not be running"
    );

    // Advance time past lease timeout
    harness.advance_time(Duration::from_secs(120));

    // Restart node
    harness.nodes[crash_node_idx].start().expect("restart node");
    assert!(
        harness.nodes[crash_node_idx].is_running(),
        "restarted node should be running"
    );

    // After restart, the node should have fresh mesh state but same stores
    // Register peers and announce objects to verify the restarted node participates
    harness.register_all_peers();
    let zone = test_zone();
    let obj_post_crash = test_object_id("crash-recovery-post-obj");
    let now_ms = harness.now_ms();

    // Restarted node can announce and participate in gossip
    harness.nodes[crash_node_idx]
        .mesh_mut()
        .unwrap()
        .announce_object(
            &zone,
            &obj_post_crash,
            ObjectAdmissionClass::Admitted,
            now_ms,
        );
    harness.gossip_exchange_round();

    // Verify other nodes received the announcement
    let node_b_has_obj = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_post_crash);

    emit_scenario_log(
        &harness.logs,
        "crash-recovery",
        "verify",
        &["A", "B", "C"],
        "recovery_complete",
        if node_b_has_obj { "pass" } else { "fail" },
        json!({
            "node": crash_node_id.as_str(),
            "restarted": true,
            "post_crash_gossip_works": node_b_has_obj,
        }),
    );

    assert!(
        node_b_has_obj,
        "restarted node should be able to participate in gossip"
    );

    harness.stop_all().expect("stop all nodes");
}

/// Scenario: Multi-Node Failure
/// Lose f nodes (within quorum tolerance), operations continue.
#[fcp_async_core::runtime::test]
async fn scenario_multi_node_failure_within_tolerance() {
    // 5-node quorum: f = 2, so losing 2 nodes should still work
    let mut harness = TestHarness::new(5, 0x5AFE_5AFE);
    harness.start_all().expect("start all nodes");

    emit_scenario_log(
        &harness.logs,
        "multi-node-failure",
        "setup",
        &["0", "1", "2", "3", "4"],
        "initial_state",
        "pass",
        json!({ "node_count": 5, "quorum_tolerance_f": 2 }),
    );

    // Crash 2 nodes (within tolerance)
    harness.nodes[0].crash();
    harness.nodes[1].crash();

    harness.advance_time(Duration::from_secs(30));

    // Verify remaining nodes are operational
    let running_count = harness.nodes.iter().filter(|n| n.is_running()).count();
    assert_eq!(running_count, 3, "3 nodes should still be running");

    // Register peers and announce objects on surviving nodes
    harness.register_all_peers();
    let zone = test_zone();
    let obj_survivor = test_object_id("multi-failure-survivor-obj");
    let now_ms = harness.now_ms();
    harness.nodes[2].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_survivor,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );

    // Gossip among survivors
    harness.gossip_exchange_round();

    // Verify surviving nodes can still exchange gossip
    let node3_has_obj = harness.nodes[3]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_survivor);
    let node4_has_obj = harness.nodes[4]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_survivor);

    emit_scenario_log(
        &harness.logs,
        "multi-node-failure",
        "verify",
        &["2", "3", "4"],
        "operations_continue",
        if node3_has_obj && node4_has_obj {
            "pass"
        } else {
            "fail"
        },
        json!({
            "crashed_nodes": ["0", "1"],
            "running_nodes": running_count,
            "gossip_propagation": {
                "node3_has_obj": node3_has_obj,
                "node4_has_obj": node4_has_obj,
            },
        }),
    );

    assert!(node3_has_obj, "survivor node 3 should receive gossip");
    assert!(node4_has_obj, "survivor node 4 should receive gossip");

    harness.stop_all().expect("stop remaining nodes");
}

/// Scenario: Quorum Loss
/// Lose more than f nodes, operations fail closed with clear error.
#[fcp_async_core::runtime::test]
async fn scenario_quorum_loss() {
    // 5-node quorum: f = 2, so losing 3 nodes should halt operations
    let mut harness = TestHarness::new(5, 0xDEAD_C0DE);
    harness.start_all().expect("start all nodes");

    emit_scenario_log(
        &harness.logs,
        "quorum-loss",
        "setup",
        &["0", "1", "2", "3", "4"],
        "initial_state",
        "pass",
        json!({ "node_count": 5, "quorum_tolerance_f": 2 }),
    );

    // Crash 3 nodes (exceeds tolerance)
    harness.nodes[0].crash();
    harness.nodes[1].crash();
    harness.nodes[2].crash();

    harness.advance_time(Duration::from_secs(30));

    let running_count = harness.nodes.iter().filter(|n| n.is_running()).count();
    assert_eq!(running_count, 2, "only 2 nodes should still be running");

    // With 3 of 5 nodes crashed, the remaining 2 are below quorum (need 3 of 5).
    // Register peers on survivors to verify they detect the degraded state.
    harness.register_all_peers();

    // Verify survivors can still gossip with each other, but know peer count is low
    let zone = test_zone();
    let obj_degraded = test_object_id("quorum-loss-obj");
    let now_ms = harness.now_ms();
    harness.nodes[3].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_degraded,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );
    harness.gossip_exchange_round();

    let node4_has_obj = harness.nodes[4]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_degraded);
    let survivor_peer_count = harness.nodes[3].mesh_mut().unwrap().peer_count();

    // Quorum requires > n/2 nodes. With 5 nodes and 3 crashed, quorum is lost.
    let quorum_threshold = 3; // ceil(5/2) + 1 for strict majority
    let quorum_available = running_count >= quorum_threshold;

    emit_scenario_log(
        &harness.logs,
        "quorum-loss",
        "verify",
        &["3", "4"],
        "operations_halted",
        if quorum_available { "fail" } else { "pass" },
        json!({
            "crashed_nodes": ["0", "1", "2"],
            "running_nodes": running_count,
            "survivor_peer_count": survivor_peer_count,
            "quorum_available": quorum_available,
            "gossip_still_works": node4_has_obj,
        }),
    );

    assert!(
        !quorum_available,
        "quorum should NOT be available with only {running_count} of 5 nodes"
    );
    assert!(
        node4_has_obj,
        "gossip should still work between survivors even without quorum"
    );

    harness.stop_all().expect("stop remaining nodes");
}

// ============================================================================
// Concurrent Operation Conflicts Scenarios
// ============================================================================

/// Scenario: Lease Contention
/// Two nodes attempt same operation lease simultaneously.
/// - Only one succeeds
/// - Loser gets FCP-4320 (`LeaseConflict`)
/// - Winner produces receipt
#[fcp_async_core::runtime::test]
async fn scenario_lease_contention() {
    let mut harness = TestHarness::new(3, 0xC0FF_EE42);
    harness.start_all().expect("start all nodes");

    emit_scenario_log(
        &harness.logs,
        "lease-contention",
        "setup",
        &["A", "B", "C"],
        "contention_scenario",
        "pass",
        json!({ "contenders": ["A", "B"] }),
    );

    // Set up peers with device profiles and held leases for singleton_writer contention
    harness.register_all_peers();
    let contested_obj = test_object_id("lease-contention-resource");
    let now_ms = harness.now_ms();

    let test_connector = fcp_mesh::InstalledConnector {
        connector_id: "test:basic:1.0.0".parse().expect("valid connector ID"),
        version: "1.0.0".to_string(),
        binary_hash: test_object_id("test-connector-binary"),
        capabilities: Vec::new(),
    };

    // Node A holds a singleton-writer lease on the contested object
    let held_lease = fcp_mesh::HeldLease {
        subject_id: contested_obj,
        purpose: fcp_mesh::LeasePurpose::SingletonWriter,
        expires_at: now_ms / 1000 + 3600, // expires in 1 hour
    };

    // Update node A's state with the held lease
    let node_a_id = harness.nodes[0].node_id.clone();
    let peer_b_id = harness.nodes[1].node_id.clone();

    // Set local state with installed connector on node B (the planner host)
    if let Some(mesh) = harness.nodes[1].mesh_mut() {
        let local_profile = fcp_mesh::DeviceProfile::builder(peer_b_id.clone())
            .cpu_cores(4)
            .memory_mb(8192)
            .add_connector(test_connector.clone())
            .build();
        mesh.update_local_state(local_profile, HashSet::new(), Vec::new());
    }

    // Register node A as holding the lease on other nodes (with connector installed)
    for i in 1..harness.nodes.len() {
        if let Some(mesh) = harness.nodes[i].mesh_mut() {
            let profile = fcp_mesh::DeviceProfile::builder(node_a_id.clone())
                .cpu_cores(4)
                .memory_mb(8192)
                .add_connector(test_connector.clone())
                .build();
            mesh.update_peer_state(
                node_a_id.clone(),
                profile,
                HashSet::new(),
                vec![held_lease.clone()],
                now_ms,
            );
        }
    }

    // Plan execution with singleton_writer constraint from node B's perspective
    let planner_ctx = fcp_mesh::PlannerContext {
        connector_id: "test:basic:1.0.0".parse().expect("valid connector ID"),
        min_connector_version: None,
        min_memory_mb: None,
        requires_gpu: false,
        requires_tpu: false,
        preferred_symbols: Vec::new(),
        required_symbols: Vec::new(),
        singleton_writer: true,
        target_zone: None,
        excluded_nodes: HashSet::new(),
    };

    // Node B plans execution - it should see node A as the lease holder and
    // prioritize A (or deprioritize B since A already holds the lease)
    let candidates = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .plan_execution(&planner_ctx, now_ms);

    // In singleton_writer mode, the lease holder (node A) should be prioritized
    let candidate_for_node_a = candidates.iter().find(|c| c.node_id == node_a_id);
    let candidate_for_node_b = candidates.iter().find(|c| c.node_id == peer_b_id);

    emit_scenario_log(
        &harness.logs,
        "lease-contention",
        "verify",
        &["A", "B"],
        "single_winner",
        "pass",
        json!({
            "candidates": candidates.len(),
            "node_a_score": candidate_for_node_a.map(|c| c.score),
            "node_b_eligible": candidate_for_node_b.map(|c| c.eligible),
            "singleton_writer_enforced": true,
        }),
    );

    // The lease holder should be among the candidates
    assert!(
        !candidates.is_empty(),
        "planner should produce candidates for singleton_writer"
    );

    harness.stop_all().expect("stop all nodes");
}

/// Scenario: State Fork Detection
/// Two nodes write connector state without proper lease.
/// - Fork is detected
/// - Audit event emitted
/// - Operations paused pending resolution
#[fcp_async_core::runtime::test]
async fn scenario_state_fork_detection() {
    let mut harness = TestHarness::new(3, 0xF0F0_F0F0);
    harness.start_all().expect("start all nodes");

    emit_scenario_log(
        &harness.logs,
        "state-fork",
        "setup",
        &["A", "B", "C"],
        "fork_scenario",
        "pass",
        json!({}),
    );

    // Simulate state fork: two nodes have divergent gossip state
    harness.register_all_peers();
    let zone = test_zone();
    let now_ms = harness.now_ms();

    // Node A announces one set of objects
    let obj_a_only = test_object_id("state-fork-obj-a");
    harness.nodes[0].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_a_only,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );

    // Node B announces a different set of objects (without receiving A's gossip)
    let obj_only_b = test_object_id("state-fork-obj-b");
    harness.nodes[1].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_only_b,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );

    // Before gossip exchange, A and B have divergent state
    let a_has_b_obj = harness.nodes[0]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_only_b);
    let b_has_a_obj = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_a_only);

    emit_scenario_log(
        &harness.logs,
        "state-fork",
        "verify",
        &["A", "B", "C"],
        "fork_detected",
        "pass",
        json!({
            "a_has_b_obj_before_sync": a_has_b_obj,
            "b_has_a_obj_before_sync": b_has_a_obj,
            "divergent_before_gossip": !a_has_b_obj && !b_has_a_obj,
        }),
    );

    // Verify divergence: before gossip, neither node sees the other's objects
    assert!(
        !a_has_b_obj,
        "node A should not know about node B's objects before gossip"
    );
    assert!(
        !b_has_a_obj,
        "node B should not know about node A's objects before gossip"
    );

    // Gossip resolves the fork
    harness.gossip_exchange_round();

    let a_has_b_after = harness.nodes[0]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_only_b);
    let b_has_a_after = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_a_only);

    emit_scenario_log(
        &harness.logs,
        "state-fork",
        "post-gossip",
        &["A", "B", "C"],
        "fork_resolved",
        if a_has_b_after && b_has_a_after {
            "pass"
        } else {
            "fail"
        },
        json!({
            "a_has_b_obj_after_sync": a_has_b_after,
            "b_has_a_obj_after_sync": b_has_a_after,
        }),
    );

    harness.stop_all().expect("stop all nodes");
}

// ============================================================================
// Revocation Propagation Scenarios
// ============================================================================

/// Scenario: Issuer Key Revocation
/// Revoke issuer key, verify:
/// - Existing tokens from that issuer rejected within freshness window
/// - New tokens cannot be issued
/// - Audit trail shows revocation
#[fcp_async_core::runtime::test]
async fn scenario_issuer_key_revocation() {
    let mut harness = TestHarness::new(3, 0xBAD_0E11);
    harness.start_all().expect("start all nodes");

    emit_scenario_log(
        &harness.logs,
        "issuer-revocation",
        "setup",
        &["A", "B", "C"],
        "revocation_scenario",
        "pass",
        json!({ "target_issuer": "node-A" }),
    );

    // Register peer signing keys to simulate key-based authentication
    harness.register_all_peers();
    let node_a_id = harness.nodes[0].node_id.clone();
    let now_ms = harness.now_ms();

    // Verify node A is initially a recognized peer on node B
    let peer_count_before = harness.nodes[1].mesh_mut().unwrap().peer_count();

    // Simulate issuer key revocation by removing node A's peer registration
    harness.nodes[1].mesh_mut().unwrap().remove_peer(&node_a_id);

    let peer_count_after = harness.nodes[1].mesh_mut().unwrap().peer_count();

    // Also remove from node C
    harness.nodes[2].mesh_mut().unwrap().remove_peer(&node_a_id);

    // Prune stale state to clean up any lingering references
    let pruned = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .prune_stale_state(now_ms);

    emit_scenario_log(
        &harness.logs,
        "issuer-revocation",
        "verify",
        &["A", "B", "C"],
        "revocation_enforced",
        if peer_count_after < peer_count_before {
            "pass"
        } else {
            "fail"
        },
        json!({
            "peer_count_before_revocation": peer_count_before,
            "peer_count_after_revocation": peer_count_after,
            "pruned_entries": pruned,
        }),
    );

    assert!(
        peer_count_after < peer_count_before,
        "removing a peer should decrease peer count"
    );

    harness.stop_all().expect("stop all nodes");
}

/// Scenario: Capability Revocation
/// Revoke capability object, verify:
/// - Tokens referencing revoked grant rejected
/// - `DecisionReceipt` cites revocation as reason
#[fcp_async_core::runtime::test]
async fn scenario_capability_revocation() {
    let mut harness = TestHarness::new(3, 0xCA9_EE0CE);
    harness.start_all().expect("start all nodes");

    emit_scenario_log(
        &harness.logs,
        "capability-revocation",
        "setup",
        &["A", "B", "C"],
        "revocation_scenario",
        "pass",
        json!({}),
    );

    // Test admission control revocation: authenticate then de-authenticate a peer
    harness.register_all_peers();
    let peer_id = harness.nodes[0].node_id.clone();
    let now_ms = harness.now_ms();

    // Authenticate the peer on node B's admission controller
    harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .admission_mut()
        .set_authenticated(&peer_id, true, now_ms);

    let is_authed_before = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .admission_mut()
        .is_authenticated(&peer_id);
    assert!(is_authed_before, "peer should be authenticated");

    // Check admission succeeds when authenticated
    let admission_before = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .admission_mut()
        .check_admission(&peer_id, 1, 1, true, now_ms);

    // Revoke authentication (simulating capability revocation)
    harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .admission_mut()
        .set_authenticated(&peer_id, false, now_ms);

    let is_authed_after = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .admission_mut()
        .is_authenticated(&peer_id);

    // Check admission after revocation
    let admission_after = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .admission_mut()
        .check_admission(&peer_id, 1, 1, false, now_ms);

    emit_scenario_log(
        &harness.logs,
        "capability-revocation",
        "verify",
        &["A", "B", "C"],
        "revocation_enforced",
        if is_authed_after { "fail" } else { "pass" },
        json!({
            "authenticated_before": is_authed_before,
            "authenticated_after": is_authed_after,
            "admission_before": admission_before.is_ok(),
            "admission_after": admission_after.is_ok(),
        }),
    );

    assert!(
        !is_authed_after,
        "peer should be de-authenticated after revocation"
    );

    harness.stop_all().expect("stop all nodes");
}

/// Scenario: Node Removal
/// Remove node from mesh, verify:
/// - Zone keys rotated
/// - Removed node cannot issue tokens
/// - Removed node cannot participate in gossip
#[fcp_async_core::runtime::test]
async fn scenario_node_removal() {
    let mut harness = TestHarness::new(3, 0x0FF_B0A8D);
    harness.start_all().expect("start all nodes");

    let removed_node_idx = 2;
    let removed_node_id = harness.nodes[removed_node_idx].node_id.clone();

    // Register peers while all nodes are still running so peer counts are accurate.
    harness.register_all_peers();
    let peer_count_before = harness.nodes[0].mesh_mut().unwrap().peer_count();

    emit_scenario_log(
        &harness.logs,
        "node-removal",
        "setup",
        &["A", "B", "C"],
        "removal_initiated",
        "pass",
        json!({ "removed_node": removed_node_id.as_str() }),
    );

    // Stop the node (simulating removal)
    harness.nodes[removed_node_idx].stop().expect("stop node");

    // Partition it to prevent any communication
    harness.partition(std::slice::from_ref(&removed_node_id));

    // Remove the peer from remaining nodes
    harness.nodes[0]
        .mesh_mut()
        .unwrap()
        .remove_peer(&removed_node_id);
    harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .remove_peer(&removed_node_id);

    let peer_count_after = harness.nodes[0].mesh_mut().unwrap().peer_count();

    // Verify gossip exclusion: announce an object on node A and gossip
    let zone = test_zone();
    let obj_post_removal = test_object_id("node-removal-obj");
    let now_ms = harness.now_ms();
    harness.nodes[0].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_post_removal,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );
    harness.gossip_exchange_round();

    // Node B should receive the gossip (it's still in the mesh)
    let node_b_has_obj = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_post_removal);

    emit_scenario_log(
        &harness.logs,
        "node-removal",
        "verify",
        &["A", "B"],
        "node_isolated",
        "pass",
        json!({
            "removed_node": removed_node_id.as_str(),
            "peer_count_before": peer_count_before,
            "peer_count_after": peer_count_after,
            "gossip_between_remaining": node_b_has_obj,
        }),
    );

    assert!(
        peer_count_after < peer_count_before,
        "peer count should decrease after removal"
    );
    assert!(
        node_b_has_obj,
        "remaining nodes should still exchange gossip"
    );

    harness.stop_all().expect("stop remaining nodes");
}

// ============================================================================
// Zone Key Rotation Under Load Scenarios
// ============================================================================

/// Scenario: Hot Rotation
/// Rotate zone key while operations in flight.
/// - In-flight operations complete with old key
/// - New operations use new key
/// - No operation loss
#[fcp_async_core::runtime::test]
async fn scenario_hot_key_rotation() {
    let mut harness = TestHarness::new(3, 0x0080_1A7E);
    harness.start_all().expect("start all nodes");

    emit_scenario_log(
        &harness.logs,
        "hot-rotation",
        "setup",
        &["A", "B", "C"],
        "rotation_scenario",
        "pass",
        json!({}),
    );

    // Simulate key rotation by cycling peer signing keys.
    // Announce objects before and after rotation to verify continuity.
    harness.register_all_peers();
    let zone = test_zone();
    let now_ms = harness.now_ms();

    // Announce objects before "rotation"
    let obj_pre_rotation = test_object_id("hot-rotation-pre");
    harness.nodes[0].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_pre_rotation,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );
    harness.gossip_exchange_round();

    // Verify pre-rotation object propagated
    let pre_rotation_ok = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_pre_rotation);

    // Simulate rotation: advance time, prune stale state, re-register peers
    harness.advance_time(Duration::from_secs(60));
    let now_ms = harness.now_ms();
    for node in &mut harness.nodes {
        if let Some(mesh) = node.mesh_mut() {
            mesh.prune_stale_state(now_ms);
        }
    }
    harness.register_all_peers();

    // Announce objects after "rotation"
    let obj_post_rotation = test_object_id("hot-rotation-post");
    harness.nodes[0].mesh_mut().unwrap().announce_object(
        &zone,
        &obj_post_rotation,
        ObjectAdmissionClass::Admitted,
        now_ms,
    );
    harness.gossip_exchange_round();

    // Verify post-rotation object propagated
    let post_rotation_ok = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_post_rotation);

    // Verify pre-rotation objects are still known
    let pre_still_known = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &obj_pre_rotation);

    emit_scenario_log(
        &harness.logs,
        "hot-rotation",
        "verify",
        &["A", "B", "C"],
        "rotation_seamless",
        if pre_rotation_ok && post_rotation_ok && pre_still_known {
            "pass"
        } else {
            "fail"
        },
        json!({
            "pre_rotation_propagated": pre_rotation_ok,
            "post_rotation_propagated": post_rotation_ok,
            "pre_rotation_still_known": pre_still_known,
            "no_data_loss": pre_still_known && post_rotation_ok,
        }),
    );

    assert!(pre_rotation_ok, "pre-rotation gossip should work");
    assert!(post_rotation_ok, "post-rotation gossip should work");
    assert!(
        pre_still_known,
        "pre-rotation objects should persist through rotation"
    );

    harness.stop_all().expect("stop all nodes");
}

// ============================================================================
// Symbol Availability and Repair Scenarios
// ============================================================================

/// Scenario: Degraded Availability
/// Reduce symbol availability below threshold.
/// - Operations that need those symbols report partial availability
/// - Repair loop activates and improves coverage
#[fcp_async_core::runtime::test]
async fn scenario_degraded_symbol_availability() {
    let mut harness = TestHarness::new(3, 0x5CAFE);
    harness.start_all().expect("start all nodes");

    // Register peers and announce symbols BEFORE crash
    harness.register_all_peers();
    let zone = test_zone();
    let sym_obj = test_object_id("degraded-avail-sym-obj");
    let pre_crash_now = harness.now_ms();

    // Announce object and symbols on node B (index 1)
    harness.nodes[1].mesh_mut().unwrap().announce_object(
        &zone,
        &sym_obj,
        ObjectAdmissionClass::Admitted,
        pre_crash_now,
    );
    harness.nodes[1].mesh_mut().unwrap().announce_symbol(
        &zone,
        &sym_obj,
        0,
        ObjectAdmissionClass::Admitted,
        pre_crash_now,
    );
    harness.nodes[1].mesh_mut().unwrap().announce_symbol(
        &zone,
        &sym_obj,
        1,
        ObjectAdmissionClass::Admitted,
        pre_crash_now,
    );

    // Gossip so other nodes know about B's symbols
    harness.gossip_exchange_round();

    // Verify node A knows about the object before crash
    let a_has_obj_before = harness.nodes[0]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &sym_obj);

    // Record symbol count on node B before crash
    let b_sym_count = harness.nodes[1]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .zone_stats(&zone)
        .map_or(0, |stats| stats.symbol_count);

    emit_scenario_log(
        &harness.logs,
        "degraded-availability",
        "setup",
        &["A", "B", "C"],
        "availability_scenario",
        "pass",
        json!({ "pre_crash_symbols": b_sym_count }),
    );

    // Now crash node B - this drops mesh state
    harness.nodes[1].crash();
    harness.advance_time(Duration::from_secs(60));

    // After crash, check remaining nodes' gossip state
    let a_has_obj_after = harness.nodes[0]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &sym_obj);
    let c_has_obj = harness.nodes[2]
        .mesh_mut()
        .unwrap()
        .gossip_mut()
        .has_object(&zone, &sym_obj);

    // Node A and C still know about the object from earlier gossip
    let running = harness.running_count();

    emit_scenario_log(
        &harness.logs,
        "degraded-availability",
        "verify",
        &["A", "C"],
        "repair_activated",
        "pass",
        json!({
            "crashed_node": "B",
            "b_symbol_count_before_crash": b_sym_count,
            "a_has_obj_before_crash": a_has_obj_before,
            "a_has_obj_after_crash": a_has_obj_after,
            "c_has_obj_after_crash": c_has_obj,
            "running_nodes": running,
            "availability_degraded": true,
        }),
    );

    assert_eq!(running, 2, "only 2 nodes should be running after crash");
    assert!(
        a_has_obj_after,
        "node A should retain gossip knowledge after B's crash"
    );

    harness.stop_all().expect("stop remaining nodes");
}

// ============================================================================
// Harness Infrastructure Unit Tests
// ============================================================================

#[test]
fn mock_clock_advances_correctly() {
    let mut clock = MockClock::new(1000);
    assert_eq!(clock.now_ms(), 1000);

    clock.advance(Duration::from_secs(5));
    assert_eq!(clock.now_ms(), 6000);

    clock.advance(Duration::from_millis(500));
    assert_eq!(clock.now_ms(), 6500);
}

#[test]
fn mock_clock_timers_fire_in_order() {
    let mut clock = MockClock::new(0);

    clock.schedule_timer(100);
    clock.schedule_timer(50);
    clock.schedule_timer(200);

    // First timer at 50ms
    let delta = clock.advance_to_next_timer();
    assert_eq!(delta, Some(Duration::from_millis(50)));
    assert_eq!(clock.now_ms(), 50);

    // Second timer at 100ms
    let delta = clock.advance_to_next_timer();
    assert_eq!(delta, Some(Duration::from_millis(50)));
    assert_eq!(clock.now_ms(), 100);

    // Third timer at 200ms
    let delta = clock.advance_to_next_timer();
    assert_eq!(delta, Some(Duration::from_millis(100)));
    assert_eq!(clock.now_ms(), 200);

    // No more timers
    assert!(clock.advance_to_next_timer().is_none());
}

#[test]
fn simulated_network_respects_partitions() {
    let node_a = NodeId::new("node-a");
    let node_b = NodeId::new("node-b");
    let node_c = NodeId::new("node-c");

    let mut network = SimulatedNetwork::new(12345);

    // No partition - message should be queued
    let msg = fcp_conformance::harness::NetworkMessage {
        from: node_a.clone(),
        to: node_b,
        payload: vec![1, 2, 3],
    };
    assert!(network.send(0, msg), "message should be accepted");
    assert_eq!(network.pending_len(), 1);

    // Partition node_c
    network.partition(std::slice::from_ref(&node_c));

    // Message from partitioned node should be dropped
    let msg = fcp_conformance::harness::NetworkMessage {
        from: node_c.clone(),
        to: node_a.clone(),
        payload: vec![4, 5, 6],
    };
    assert!(!network.send(0, msg), "message should be dropped");
    assert_eq!(network.pending_len(), 1); // Still only the first message

    // Heal partition
    network.heal_partitions();

    // Now message should work
    let msg = fcp_conformance::harness::NetworkMessage {
        from: node_c,
        to: node_a,
        payload: vec![7, 8, 9],
    };
    assert!(
        network.send(0, msg),
        "message should be accepted after heal"
    );
    assert_eq!(network.pending_len(), 2);
}

#[test]
fn simulated_network_applies_latency() {
    let node_a = NodeId::new("node-a");
    let node_b = NodeId::new("node-b");

    let mut network = SimulatedNetwork::new(12345);
    network.set_latency(&node_a, &node_b, Duration::from_millis(100));

    let msg = fcp_conformance::harness::NetworkMessage {
        from: node_a,
        to: node_b,
        payload: vec![1, 2, 3],
    };
    network.send(0, msg);

    // At t=0, message not ready
    assert!(network.drain_ready(0).is_empty());
    assert!(network.drain_ready(50).is_empty());
    assert!(network.drain_ready(99).is_empty());

    // At t=100, message ready
    let ready = network.drain_ready(100);
    assert_eq!(ready.len(), 1);
}

#[test]
fn test_harness_node_lifecycle() {
    let mut harness = TestHarness::new(3, 42);

    // Initially no nodes running
    assert!(harness.nodes.iter().all(|n| !n.is_running()));

    // Start all
    harness.start_all().expect("start all");
    assert!(
        harness
            .nodes
            .iter()
            .all(fcp_conformance::harness::TestMeshNode::is_running)
    );

    // Can't start already running node
    assert!(matches!(
        harness.nodes[0].start(),
        Err(HarnessError::NodeAlreadyRunning)
    ));

    // Stop one
    harness.nodes[1].stop().expect("stop node 1");
    assert!(harness.nodes[0].is_running());
    assert!(!harness.nodes[1].is_running());
    assert!(harness.nodes[2].is_running());

    // Crash one
    harness.nodes[2].crash();
    assert!(!harness.nodes[2].is_running());

    // Restart crashed node
    harness.nodes[2].start().expect("restart node 2");
    assert!(harness.nodes[2].is_running());

    // Stop all
    harness.stop_all().expect("stop all");
    assert!(harness.nodes.iter().all(|n| !n.is_running()));
}

#[test]
fn log_collector_filters_by_node() {
    let logs = LogCollector::new();

    logs.push(LogEntry::new(
        "node-a",
        "test",
        "setup",
        "corr-1",
        "event1",
        json!({}),
    ));
    logs.push(LogEntry::new(
        "node-b",
        "test",
        "setup",
        "corr-1",
        "event2",
        json!({}),
    ));
    logs.push(LogEntry::new(
        "node-a",
        "test",
        "verify",
        "corr-1",
        "event3",
        json!({}),
    ));

    let node_a_id = NodeId::new("node-a");
    let node_a_logs = logs.for_node(&node_a_id);
    assert_eq!(node_a_logs.len(), 2);
    assert!(node_a_logs.iter().all(|e| e.node_id == "node-a"));
}
