#![forbid(unsafe_code)]

use fcp_testkit::local_mesh::{LocalChaosMode, LocalMeshHarness};

#[test]
fn deterministic_local_mesh_failover_smoke_covers_all_a4_chaos_modes()
-> Result<(), Box<dyn std::error::Error>> {
    for chaos_mode in LocalChaosMode::all() {
        for seed_index in 0..100 {
            let mut first = LocalMeshHarness::new_three_node(seed_index)?;
            let first_outcome = first.run_failover_scenario(chaos_mode)?;

            let mut second = LocalMeshHarness::new_three_node(seed_index)?;
            let second_outcome = second.run_failover_scenario(chaos_mode)?;

            assert_eq!(
                first.mesh_node_count(),
                3,
                "A.4 local harness must instantiate three real MeshNode values"
            );
            assert_eq!(
                first_outcome.final_state_hash, second_outcome.final_state_hash,
                "same seed and chaos mode must produce deterministic final state"
            );
            assert_eq!(
                first_outcome.receipt_count, 1,
                "idempotency retry should produce exactly one receipt"
            );
            assert_eq!(
                first_outcome.duplicate_receipt_count, 0,
                "duplicate receipt count must stay zero under chaos"
            );
            assert!(
                first_outcome.replay_bundle.is_redaction_safe()?,
                "replay bundle must not expose raw node ids or secret-bearing labels"
            );
            assert_eq!(first_outcome.replay_bundle.manifest.result, "pass");
            assert!(
                !first_outcome.replay_bundle.events.is_empty(),
                "replay bundle should include node transition events"
            );
            assert_eq!(
                first_outcome.replay_bundle.node_snapshots.len(),
                3,
                "replay bundle should include one redacted snapshot per node"
            );
        }
    }
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
