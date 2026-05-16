#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fcp_cbor::{CanonicalSerializer, SchemaId};
use fcp_testkit::local_mesh::{
    LocalChaosMode, LocalMeshHarness, LocalMeshHarnessError, LocalNodeSnapshot,
};
use semver::Version;
use serde_json::Value;

#[test]
fn deterministic_local_mesh_failover_smoke_covers_all_a4_chaos_modes()
-> Result<(), Box<dyn std::error::Error>> {
    let scenarios = seed_mode_scenarios();
    let artifact_root = replay_artifact_root("matrix_forward");
    let forward_matrix = failover_hash_matrix(scenarios.iter().copied(), Some(&artifact_root))?;
    let reverse_matrix = failover_hash_matrix(scenarios.iter().rev().copied(), None)?;

    assert_eq!(
        forward_matrix.len(),
        300,
        "A.4 smoke must cover 100 seeds x 3 chaos modes"
    );
    assert_eq!(
        replay_artifact_dir_count(&artifact_root)?,
        300,
        "forward seed/mode matrix should write one replay bundle per scenario"
    );
    assert_eq!(
        forward_matrix, reverse_matrix,
        "seed/mode final-state hashes must be independent of traversal order"
    );
    Ok(())
}

#[test]
fn local_mesh_replay_events_are_jsonl_serializable_and_redacted()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = LocalMeshHarness::new_three_node(42)?;
    let outcome = harness.run_failover_scenario(LocalChaosMode::KillLeaderMidWrite)?;
    let jsonl = outcome.replay_bundle.events_jsonl()?;

    assert!(!jsonl.trim().is_empty());
    let mut previous_logical_time_ms = 0;
    let mut observed_handoff_target = false;
    for line in jsonl.lines() {
        let value: Value = serde_json::from_str(line)?;
        assert_transition_event_contract(
            &value,
            &outcome.scenario_id,
            42,
            "kill_leader_mid_write",
            &mut previous_logical_time_ms,
            &mut observed_handoff_target,
        )?;
        assert!(
            !line.contains("mesh-harness-node-"),
            "JSONL events must be redacted: {line}"
        );
    }
    assert!(
        observed_handoff_target,
        "kill-leader replay should include at least one redacted handoff target"
    );
    Ok(())
}

#[test]
fn local_mesh_replay_bundle_writes_documented_artifacts() -> Result<(), Box<dyn std::error::Error>>
{
    let mut harness = LocalMeshHarness::new_three_node(7)?;
    let outcome = harness.run_failover_scenario(LocalChaosMode::NetworkPartitionThenHeal)?;
    let paths = outcome
        .replay_bundle
        .write_to_dir(replay_artifact_root(&outcome.scenario_id))?;

    assert!(paths.manifest.exists());
    assert!(paths.events.exists());
    assert!(paths.hashes.exists());
    assert!(paths.invariants.exists());
    assert!(paths.snapshot_root.is_dir());

    let manifest = fs::read_to_string(&paths.manifest)?;
    assert!(manifest.contains("\"schema_version\""));
    assert!(!manifest.contains("mesh-harness-node-"));

    let events = fs::read_to_string(&paths.events)?;
    assert!(events.contains("\"node_id_hash\""));
    assert!(!events.contains("mesh-harness-node-"));

    let hashes: Value = serde_json::from_str(&fs::read_to_string(&paths.hashes)?)?;
    let final_hash = required_string_field(&hashes, "final_state_hash")?;
    let expected_hash = required_string_field(&hashes, "expected_hash_for_seed")?;
    assert_eq!(
        final_hash, expected_hash,
        "artifact should record the expected hash for deterministic seed reruns"
    );
    let per_node_state_hashes = hashes
        .get("per_node_state_hashes")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_replay_artifact("hashes.json missing per_node_state_hashes"))?;
    assert_eq!(
        per_node_state_hashes.len(),
        3,
        "hashes.json should include one final state hash per node"
    );
    for entry in per_node_state_hashes {
        let node_id_hash = required_string_field(entry, "node_id_hash")?;
        let state_hash = required_string_field(entry, "state_hash")?;
        assert!(!node_id_hash.is_empty());
        assert_eq!(state_hash.len(), 64);
    }

    let invariants: Value = serde_json::from_str(&fs::read_to_string(&paths.invariants)?)?;
    assert_eq!(
        required_string_field(&invariants, "active_holder_hash")?,
        outcome.active_holder_hash
    );
    assert_eq!(
        required_u64_field(&invariants, "online_node_count")?,
        3,
        "invariants.json should record all nodes online after recovery"
    );
    assert!(
        required_bool_field(&invariants, "all_nodes_online_at_end")?,
        "invariants.json should record final all-online recovery"
    );
    assert_eq!(
        required_u64_field(&invariants, "orphaned_active_lease_count")?,
        0,
        "invariants.json should record no orphaned active leases"
    );
    assert_eq!(
        required_u64_field(&invariants, "orphaned_connector_state_count")?,
        0,
        "invariants.json should record no orphaned connector state"
    );
    assert_eq!(
        required_u64_field(&invariants, "invalid_receipt_signature_count")?,
        0,
        "invariants.json should record no invalid receipt signatures"
    );

    let node_dirs = fs::read_dir(&paths.snapshot_root)?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(node_dirs.len(), 3);
    for entry in node_dirs {
        let node_dir = entry.path();
        for stage in [
            "state_at_t0.cbor",
            "state_at_chaos.cbor",
            "state_at_heal.cbor",
            "state_at_end.cbor",
        ] {
            let bytes = fs::read(node_dir.join(stage))?;
            let schema = SchemaId::new("fcp.testkit", "LocalNodeSnapshot", Version::new(1, 0, 0));
            let snapshot: LocalNodeSnapshot = CanonicalSerializer::deserialize(&bytes, &schema)?;
            assert!(!snapshot.node_id_hash.is_empty());
        }
    }

    Ok(())
}

#[test]
fn local_mesh_replay_bundle_refuses_unredacted_artifact_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = LocalMeshHarness::new_three_node(7)?;
    let outcome = harness.run_failover_scenario(LocalChaosMode::KillLeaderMidWrite)?;
    let mut bundle = outcome.replay_bundle.clone();
    bundle.manifest.scenario_id = "mesh-harness-node-raw".to_owned();
    let unsafe_dir = replay_artifact_root("unsafe");

    assert!(matches!(
        bundle.write_to_dir(&unsafe_dir),
        Err(LocalMeshHarnessError::ReplayArtifactRedaction)
    ));
    assert!(
        !unsafe_dir.exists(),
        "redaction failure must happen before artifact directories are created"
    );
    Ok(())
}

fn seed_mode_scenarios() -> Vec<(u64, LocalChaosMode)> {
    (0..100)
        .flat_map(|seed_index| {
            LocalChaosMode::all().map(move |chaos_mode| (seed_index, chaos_mode))
        })
        .collect()
}

fn failover_hash_matrix(
    scenarios: impl IntoIterator<Item = (u64, LocalChaosMode)>,
    artifact_root: Option<&Path>,
) -> Result<BTreeMap<(u64, LocalChaosMode), String>, Box<dyn std::error::Error>> {
    let mut matrix = BTreeMap::new();
    for (seed_index, chaos_mode) in scenarios {
        let mut harness = LocalMeshHarness::new_three_node(seed_index)?;
        let outcome = harness.run_failover_scenario(chaos_mode)?;
        if let Some(root) = artifact_root {
            outcome
                .replay_bundle
                .write_to_dir(root.join(&outcome.scenario_id))?;
        }

        assert_eq!(
            harness.mesh_node_count(),
            3,
            "A.4 local harness must instantiate three real MeshNode values"
        );
        assert_eq!(
            outcome.receipt_count, 1,
            "idempotency retry should produce exactly one receipt"
        );
        assert_eq!(
            outcome.duplicate_receipt_count, 0,
            "duplicate receipt count must stay zero under chaos"
        );
        assert_eq!(
            outcome.invariants.active_holder_hash, outcome.active_holder_hash,
            "active holder invariant should identify the selected holder"
        );
        assert_eq!(
            outcome.invariants.online_node_count, 3,
            "all local mesh nodes should be online after recovery"
        );
        assert!(
            outcome.invariants.all_nodes_online_at_end,
            "failover recovery should leave every local node online"
        );
        assert_eq!(
            outcome.invariants.orphaned_active_lease_count, 0,
            "active singleton holder must be online and in holder role"
        );
        assert_eq!(
            outcome.invariants.orphaned_connector_state_count, 0,
            "operation receipts must stay connected to request refs, outcomes, and known nodes"
        );
        assert_eq!(
            outcome.invariants.invalid_receipt_signature_count, 0,
            "operation receipts must verify against the executing node key"
        );
        assert_eq!(
            outcome.replay_bundle.invariants.orphaned_active_lease_count, 0,
            "replay bundle should carry the same lease invariant evidence"
        );
        assert!(
            outcome.replay_bundle.is_redaction_safe()?,
            "replay bundle must not expose raw node ids or secret-bearing labels"
        );
        assert_eq!(outcome.replay_bundle.manifest.result, "pass");
        assert!(
            !outcome.replay_bundle.events.is_empty(),
            "replay bundle should include node transition events"
        );
        assert_eq!(
            outcome.replay_bundle.node_snapshots.len(),
            3,
            "replay bundle should include one redacted snapshot per node"
        );
        assert_eq!(
            outcome.replay_bundle.node_timelines.len(),
            3,
            "replay bundle should include one per-node timeline per node"
        );

        let previous = matrix.insert((seed_index, chaos_mode), outcome.final_state_hash);
        assert!(
            previous.is_none(),
            "seed/mode matrix should contain each scenario exactly once"
        );
    }
    Ok(matrix)
}

fn required_string_field<'a>(
    value: &'a Value,
    field: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_replay_artifact(format!("missing string field {field}")))
}

fn required_u64_field(value: &Value, field: &str) -> Result<u64, Box<dyn std::error::Error>> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_replay_artifact(format!("missing u64 field {field}")))
}

fn required_bool_field(value: &Value, field: &str) -> Result<bool, Box<dyn std::error::Error>> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid_replay_artifact(format!("missing bool field {field}")))
}

fn assert_transition_event_contract(
    value: &Value,
    scenario_id: &str,
    seed_index: u64,
    chaos_mode: &str,
    previous_logical_time_ms: &mut u64,
    observed_handoff_target: &mut bool,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(required_string_field(value, "scenario_id")?, scenario_id);
    assert_eq!(required_u64_field(value, "seed_index")?, seed_index);
    assert_eq!(required_string_field(value, "chaos_mode")?, chaos_mode);

    let node_id_hash = required_string_field(value, "node_id_hash")?;
    assert_hash_value("node_id_hash", node_id_hash);

    let prior_role = required_string_field(value, "prior_role")?;
    let new_role = required_string_field(value, "new_role")?;
    assert_known_local_role("prior_role", prior_role);
    assert_known_local_role("new_role", new_role);
    assert_ne!(
        prior_role, new_role,
        "transition event should only be emitted when the role changes"
    );

    let transition_duration_ms = required_u64_field(value, "transition_duration_ms")?;
    assert!(
        transition_duration_ms > 0,
        "transition duration should be positive"
    );
    let logical_time_ms = required_u64_field(value, "logical_time_ms")?;
    assert!(
        logical_time_ms > *previous_logical_time_ms,
        "logical transition time should increase monotonically"
    );
    *previous_logical_time_ms = logical_time_ms;

    match value.get("lease_handoff_target_hash") {
        Some(Value::Null) => {}
        Some(Value::String(target_hash)) => {
            *observed_handoff_target = true;
            assert_hash_value("lease_handoff_target_hash", target_hash);
        }
        Some(_) => {
            return Err(invalid_replay_artifact(
                "lease_handoff_target_hash must be a hash string or null",
            ));
        }
        None => {
            return Err(invalid_replay_artifact(
                "transition event missing lease_handoff_target_hash",
            ));
        }
    }

    Ok(())
}

fn assert_known_local_role(field: &str, role: &str) {
    assert!(
        matches!(
            role,
            "candidate" | "holder" | "follower" | "partitioned" | "offline" | "recovered"
        ),
        "{field} should use the LocalNodeRole snake_case contract: {role}"
    );
}

fn assert_hash_value(field: &str, value: &str) {
    assert_eq!(value.len(), 64, "{field} should be a 64-character hash");
    assert!(
        value.chars().all(|character| character.is_ascii_hexdigit()),
        "{field} should be hex-encoded"
    );
}

fn invalid_replay_artifact(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.into(),
    ))
}

fn replay_artifact_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!(
        "fcp-multi-node-failover-replay-{}-{nanos}-{label}",
        std::process::id()
    ))
}

fn replay_artifact_dir_count(root: &Path) -> Result<usize, Box<dyn std::error::Error>> {
    let mut count = 0;
    for entry in fs::read_dir(root)? {
        if entry?.file_type()?.is_dir() {
            count += 1;
        }
    }
    Ok(count)
}
