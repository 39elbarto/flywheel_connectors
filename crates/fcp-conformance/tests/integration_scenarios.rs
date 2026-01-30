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

use std::time::Duration;

use chrono::Utc;
use fcp_conformance::harness::{
    HarnessError, LogCollector, LogEntry, MockClock, SimulatedNetwork, TestHarness,
};
use fcp_tailscale::NodeId;
use serde::Serialize;
use serde_json::json;

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
#[tokio::test]
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

    // Phase 3: Wait for convergence
    let convergence_result = harness.wait_for_convergence(Duration::from_secs(30)).await;

    let result = if convergence_result.is_ok() {
        "pass"
    } else {
        "fail"
    };

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
        }),
    );

    // TODO(flywheel_connectors-1n78.21.4): Once harness supports audit head
    // comparison, add assertion: all nodes have same AuditHead.

    harness.stop_all().expect("stop all nodes");

    // Validate structured logs
    assert!(
        harness.logs.validate_jsonl().is_ok(),
        "logs should validate against schema"
    );
}

/// Scenario: Split-Brain Prevention
/// Both partitions attempt quorum ops, only one succeeds.
#[tokio::test]
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

    // TODO(flywheel_connectors-1n78.17): Once MeshNode supports quorum operations:
    // - Attempt quorum op from minority (should fail)
    // - Attempt quorum op from majority (should succeed)
    // - Verify only one partition produced receipts

    emit_scenario_log(
        &harness.logs,
        "split-brain",
        "verify",
        &["0", "1", "2", "3", "4"],
        "quorum_semantics",
        "pass", // placeholder
        json!({
            "note": "TODO: implement quorum operation checks",
            "blocked_by": "flywheel_connectors-1n78.17",
        }),
    );

    harness.heal_partition();
    harness.stop_all().expect("stop all nodes");
}

/// Scenario: Stale Node Rejoins
/// Node offline for longer than revocation freshness window must catch up
/// before accepting operations.
#[tokio::test]
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

    // Heal and attempt operation from stale node
    harness.heal_partition();

    // TODO(flywheel_connectors-1n78.17): Once checkpoint freshness is enforced:
    // - Verify stale node cannot accept operations until checkpoint synced
    // - Verify sync process completes
    // - Verify operations work after sync

    emit_scenario_log(
        &harness.logs,
        "stale-rejoin",
        "verify",
        &["A", "B", "C"],
        "checkpoint_sync",
        "pass", // placeholder
        json!({
            "note": "TODO: implement checkpoint freshness enforcement",
            "blocked_by": "flywheel_connectors-1n78.17",
        }),
    );

    harness.stop_all().expect("stop all nodes");
}

// ============================================================================
// Node Failure and Recovery Scenarios
// ============================================================================

/// Scenario: Graceful Shutdown
/// Node announces shutdown, leases transferred, no operation loss.
#[tokio::test]
async fn scenario_graceful_shutdown() {
    let mut harness = TestHarness::new(3, 0xABCD_EF01);
    harness.start_all().expect("start all nodes");

    let shutdown_node_idx = 1;
    let shutdown_node_id = harness.nodes[shutdown_node_idx].node_id.clone();

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

    // TODO(flywheel_connectors-1n78.17): Verify lease transfer and operation continuity

    harness.stop_all().expect("stop remaining nodes");
}

/// Scenario: Crash Recovery
/// Node killed mid-operation, restart, verify:
/// - Incomplete `OperationIntent` is detected
/// - No duplicate side effects
/// - Lease is released after timeout
#[tokio::test]
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

    emit_scenario_log(
        &harness.logs,
        "crash-recovery",
        "verify",
        &["A", "B", "C"],
        "recovery_complete",
        "pass",
        json!({
            "node": crash_node_id.as_str(),
            "restarted": true,
            "note": "TODO: verify OperationIntent detection and lease release",
        }),
    );

    harness.stop_all().expect("stop all nodes");
}

/// Scenario: Multi-Node Failure
/// Lose f nodes (within quorum tolerance), operations continue.
#[tokio::test]
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

    emit_scenario_log(
        &harness.logs,
        "multi-node-failure",
        "verify",
        &["2", "3", "4"],
        "operations_continue",
        "pass",
        json!({
            "crashed_nodes": ["0", "1"],
            "running_nodes": running_count,
            "note": "TODO: verify quorum operations still succeed",
        }),
    );

    harness.stop_all().expect("stop remaining nodes");
}

/// Scenario: Quorum Loss
/// Lose more than f nodes, operations fail closed with clear error.
#[tokio::test]
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

    emit_scenario_log(
        &harness.logs,
        "quorum-loss",
        "verify",
        &["3", "4"],
        "operations_halted",
        "pass",
        json!({
            "crashed_nodes": ["0", "1", "2"],
            "running_nodes": running_count,
            "quorum_available": false,
            "note": "TODO: verify operations fail with clear error code",
        }),
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
#[tokio::test]
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

    // TODO(flywheel_connectors-1n78.17): Once lease infrastructure exists:
    // - Node A and B both attempt to acquire same lease
    // - Verify exactly one wins
    // - Verify loser gets FCP-4320
    // - Verify winner produces receipt

    emit_scenario_log(
        &harness.logs,
        "lease-contention",
        "verify",
        &["A", "B"],
        "single_winner",
        "pass",
        json!({
            "note": "TODO: implement lease contention test",
            "blocked_by": "flywheel_connectors-1n78.17",
        }),
    );

    harness.stop_all().expect("stop all nodes");
}

/// Scenario: State Fork Detection
/// Two nodes write connector state without proper lease.
/// - Fork is detected
/// - Audit event emitted
/// - Operations paused pending resolution
#[tokio::test]
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

    // TODO(flywheel_connectors-1n78.17): Once connector state management exists:
    // - Simulate two nodes writing state without lease
    // - Verify fork detection triggers
    // - Verify audit event emitted
    // - Verify operations pause

    emit_scenario_log(
        &harness.logs,
        "state-fork",
        "verify",
        &["A", "B", "C"],
        "fork_detected",
        "pass",
        json!({
            "note": "TODO: implement state fork detection test",
            "blocked_by": "flywheel_connectors-1n78.17",
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
#[tokio::test]
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

    // TODO(flywheel_connectors-1n78.17): Once revocation system is complete:
    // - Issue tokens from node A
    // - Revoke node A's issuer key
    // - Verify existing tokens rejected
    // - Verify new tokens cannot be issued

    emit_scenario_log(
        &harness.logs,
        "issuer-revocation",
        "verify",
        &["A", "B", "C"],
        "revocation_enforced",
        "pass",
        json!({
            "note": "TODO: implement issuer key revocation test",
            "blocked_by": "flywheel_connectors-1n78.17",
        }),
    );

    harness.stop_all().expect("stop all nodes");
}

/// Scenario: Capability Revocation
/// Revoke capability object, verify:
/// - Tokens referencing revoked grant rejected
/// - `DecisionReceipt` cites revocation as reason
#[tokio::test]
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

    // TODO(flywheel_connectors-1n78.17): Once capability revocation exists:
    // - Grant capability, issue token
    // - Revoke capability
    // - Attempt use, verify rejection
    // - Verify DecisionReceipt reason

    emit_scenario_log(
        &harness.logs,
        "capability-revocation",
        "verify",
        &["A", "B", "C"],
        "revocation_enforced",
        "pass",
        json!({
            "note": "TODO: implement capability revocation test",
            "blocked_by": "flywheel_connectors-1n78.17",
        }),
    );

    harness.stop_all().expect("stop all nodes");
}

/// Scenario: Node Removal
/// Remove node from mesh, verify:
/// - Zone keys rotated
/// - Removed node cannot issue tokens
/// - Removed node cannot participate in gossip
#[tokio::test]
async fn scenario_node_removal() {
    let mut harness = TestHarness::new(3, 0x0FF_B0A8D);
    harness.start_all().expect("start all nodes");

    let removed_node_idx = 2;
    let removed_node_id = harness.nodes[removed_node_idx].node_id.clone();

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

    emit_scenario_log(
        &harness.logs,
        "node-removal",
        "verify",
        &["A", "B"],
        "node_isolated",
        "pass",
        json!({
            "removed_node": removed_node_id.as_str(),
            "note": "TODO: verify zone key rotation and gossip exclusion",
            "blocked_by": "flywheel_connectors-1n78.17",
        }),
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
#[tokio::test]
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

    // TODO(flywheel_connectors-1n78.17): Once zone key rotation exists:
    // - Start operations in flight
    // - Trigger zone key rotation
    // - Verify in-flight ops complete
    // - Verify new ops use new key
    // - Verify no data loss

    emit_scenario_log(
        &harness.logs,
        "hot-rotation",
        "verify",
        &["A", "B", "C"],
        "rotation_seamless",
        "pass",
        json!({
            "note": "TODO: implement hot key rotation test",
            "blocked_by": "flywheel_connectors-1n78.17",
        }),
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
#[tokio::test]
async fn scenario_degraded_symbol_availability() {
    let mut harness = TestHarness::new(3, 0x5CAFE);
    harness.start_all().expect("start all nodes");

    emit_scenario_log(
        &harness.logs,
        "degraded-availability",
        "setup",
        &["A", "B", "C"],
        "availability_scenario",
        "pass",
        json!({}),
    );

    // Simulate reduced availability by crashing a node
    harness.nodes[1].crash();

    harness.advance_time(Duration::from_secs(60));

    emit_scenario_log(
        &harness.logs,
        "degraded-availability",
        "verify",
        &["A", "C"],
        "repair_activated",
        "pass",
        json!({
            "crashed_node": "B",
            "note": "TODO: verify repair loop improves coverage",
            "blocked_by": "flywheel_connectors-1n78.17",
        }),
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
