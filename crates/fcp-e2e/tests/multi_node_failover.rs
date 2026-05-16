#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;

use fcp_cbor::{CanonicalSerializer, SchemaId};
use fcp_testkit::local_mesh::{
    LocalChaosMode, LocalMeshHarness, LocalMeshHarnessError, LocalNodeSnapshot,
};
use semver::Version;

#[test]
fn deterministic_local_mesh_failover_smoke_covers_all_a4_chaos_modes()
-> Result<(), Box<dyn std::error::Error>> {
    let scenarios = seed_mode_scenarios();
    let forward_matrix = failover_hash_matrix(scenarios.iter().copied())?;
    let reverse_matrix = failover_hash_matrix(scenarios.iter().rev().copied())?;

    assert_eq!(
        forward_matrix.len(),
        300,
        "A.4 smoke must cover 100 seeds x 3 chaos modes"
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
    for line in jsonl.lines() {
        let value: serde_json::Value = serde_json::from_str(line)?;
        assert!(value.get("scenario_id").is_some());
        assert!(value.get("node_id_hash").is_some());
        assert!(
            !line.contains("mesh-harness-node-"),
            "JSONL events must be redacted: {line}"
        );
    }
    Ok(())
}

#[test]
fn local_mesh_replay_bundle_writes_documented_artifacts() -> Result<(), Box<dyn std::error::Error>>
{
    let mut harness = LocalMeshHarness::new_three_node(7)?;
    let outcome = harness.run_failover_scenario(LocalChaosMode::NetworkPartitionThenHeal)?;
    let tempdir = tempfile::tempdir()?;
    let paths = outcome
        .replay_bundle
        .write_to_dir(tempdir.path().join(&outcome.scenario_id))?;

    assert!(paths.manifest.exists());
    assert!(paths.events.exists());
    assert!(paths.hashes.exists());
    assert!(paths.snapshot_root.is_dir());

    let manifest = fs::read_to_string(&paths.manifest)?;
    assert!(manifest.contains("\"schema_version\""));
    assert!(!manifest.contains("mesh-harness-node-"));

    let events = fs::read_to_string(&paths.events)?;
    assert!(events.contains("\"node_id_hash\""));
    assert!(!events.contains("mesh-harness-node-"));

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
    let tempdir = tempfile::tempdir()?;
    let unsafe_dir = tempdir.path().join("unsafe");

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
) -> Result<BTreeMap<(u64, LocalChaosMode), String>, Box<dyn std::error::Error>> {
    let mut matrix = BTreeMap::new();
    for (seed_index, chaos_mode) in scenarios {
        let mut harness = LocalMeshHarness::new_three_node(seed_index)?;
        let outcome = harness.run_failover_scenario(chaos_mode)?;

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
