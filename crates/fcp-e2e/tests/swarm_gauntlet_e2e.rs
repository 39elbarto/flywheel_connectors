//! Integrated massive-swarm gauntlet smoke lane.
//!
//! This is intentionally offline and deterministic: it exercises the same
//! replay/evidence contracts that a host-backed 10k soak must emit, without
//! depending on live connector services.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use chrono::Utc;
use fcp_testkit::evidence_helpers::{
    LatencyBreakdown, SwarmDecisionAction, SwarmDecisionCard, SwarmDecisionCounterfactual,
    SwarmDecisionDomain, SwarmDecisionEvidencePointer, SwarmDecisionFallback,
    SwarmDecisionLossTerm, SwarmEvidenceArtifact, SwarmEvidenceArtifactKind,
    SwarmEvidenceArtifactManifest, SwarmEvidenceExecutionMode, SwarmEvidenceRedactionPolicy,
    SwarmEvidenceSourceKind, SwarmGauntletCounters, SwarmGauntletEvidenceBundle,
    SwarmGauntletManifest, SwarmGauntletPhase, SwarmGauntletPhaseEvidence,
    SwarmLatencyEvidenceBundle, SwarmLatencySample, SwarmLatencyScenario, SwarmPromotionEnvelope,
    SwarmPromotionQualification, SwarmPromotionSkipArtifact, SwarmPromotionTopology,
    SwarmRegressionMetricSnapshot, SwarmRegressionResourceMetrics, SwarmRunEnvironment,
    SwarmWorkloadKind,
};
use serde_json::{Value, json};

fn smoke_environment() -> SwarmRunEnvironment {
    SwarmRunEnvironment {
        worker_id: "offline-e2e-runner".to_string(),
        cpu_count: 64,
        physical_cpu_count: Some(32),
        numa_node_count: Some(2),
        memory_bytes: Some(256 * 1024 * 1024 * 1024),
        cargo_target_dir: Some("/tmp/fcp-swarm-gauntlet-e2e".to_string()),
        command_line: vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "fcp-e2e".to_string(),
            "--test".to_string(),
            "swarm_gauntlet_e2e".to_string(),
        ],
        source_revision: Some("e2e-smoke-revision".to_string()),
        captured_at: Utc::now(),
    }
}

fn promotion_skip_environment() -> SwarmRunEnvironment {
    SwarmRunEnvironment {
        worker_id: "offline-e2e-small-worker".to_string(),
        cpu_count: 12,
        physical_cpu_count: None,
        numa_node_count: None,
        memory_bytes: None,
        cargo_target_dir: Some("/tmp/fcp-swarm-promotion-skip".to_string()),
        command_line: vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "fcp-e2e".to_string(),
            "--test".to_string(),
            "swarm_gauntlet_e2e".to_string(),
        ],
        source_revision: Some("e2e-promotion-skip-revision".to_string()),
        captured_at: Utc::now(),
    }
}

fn required_artifacts() -> Vec<SwarmEvidenceArtifact> {
    SwarmEvidenceArtifactKind::REQUIRED
        .into_iter()
        .map(|kind| SwarmEvidenceArtifact::new(kind, format!("blake3:{}", kind.as_str()), true))
        .collect()
}

fn phase_evidence() -> Vec<SwarmGauntletPhaseEvidence> {
    vec![
        SwarmGauntletPhaseEvidence::new(
            SwarmGauntletPhase::Fwc,
            "fwc",
            "command_log.txt#fwc-bench",
        ),
        SwarmGauntletPhaseEvidence::new(SwarmGauntletPhase::Host, "fcp-host", "summary.json#host"),
        SwarmGauntletPhaseEvidence::new(SwarmGauntletPhase::Mesh, "fcp-mesh", "summary.json#mesh"),
        SwarmGauntletPhaseEvidence::new(
            SwarmGauntletPhase::ConnectorTestkit,
            "fcp-testkit",
            "raw_samples.jsonl#connector",
        ),
        SwarmGauntletPhaseEvidence::new(
            SwarmGauntletPhase::Scheduler,
            "fcp-host",
            "decision-card:scheduler",
        ),
        SwarmGauntletPhaseEvidence::new(
            SwarmGauntletPhase::Placement,
            "fcp-mesh",
            "decision-card:placement",
        ),
        SwarmGauntletPhaseEvidence::new(
            SwarmGauntletPhase::Backpressure,
            "fcp-host",
            "decision-card:backpressure",
        ),
        SwarmGauntletPhaseEvidence::new(
            SwarmGauntletPhase::Audit,
            "fcp-host",
            "raw_samples.jsonl#audit",
        ),
        SwarmGauntletPhaseEvidence::new(
            SwarmGauntletPhase::Store,
            "fcp-store",
            "raw_samples.jsonl#sparse-high-k",
        ),
        SwarmGauntletPhaseEvidence::new(
            SwarmGauntletPhase::EvidenceBundle,
            "fcp-testkit",
            "manifest.json",
        ),
    ]
}

fn decision_cards(scenario_id: &str) -> Vec<SwarmDecisionCard> {
    [
        (
            "e2e-card:scheduler",
            SwarmDecisionDomain::Scheduler,
            SwarmDecisionAction::Dispatch,
            "queue_congested",
            "p99_queueing",
        ),
        (
            "e2e-card:placement",
            SwarmDecisionDomain::Placement,
            SwarmDecisionAction::Place,
            "numa_pressure",
            "rss_headroom",
        ),
        (
            "e2e-card:backpressure",
            SwarmDecisionDomain::Backpressure,
            SwarmDecisionAction::Delay,
            "downstream_throttled",
            "retry_amplification",
        ),
    ]
    .into_iter()
    .map(|(card_id, domain, action, state, loss_term)| {
        SwarmDecisionCard::new(
            card_id,
            domain,
            "connector:offline-gauntlet",
            state,
            action,
            100,
            SwarmDecisionFallback::available(SwarmDecisionAction::Fallback),
        )
        .with_scenario(scenario_id)
        .with_loss_terms(vec![SwarmDecisionLossTerm::new(
            loss_term, 10, 1_000_000, "score",
        )])
        .with_counterfactual(SwarmDecisionCounterfactual::new(
            SwarmDecisionAction::Fallback,
            120,
            "fallback remains replayable",
        ))
        .with_evidence_pointers(vec![SwarmDecisionEvidencePointer::bundle_artifact(
            format!("raw_samples.jsonl#{scenario_id}"),
            "blake3:raw",
            true,
        )])
        .with_replay_inputs(BTreeMap::from([
            ("scenario_id".to_string(), json!(scenario_id)),
            ("queue_depth".to_string(), json!(64)),
        ]))
    })
    .collect()
}

fn latency_bundle() -> Result<SwarmLatencyEvidenceBundle, Box<dyn Error>> {
    let scenarios = vec![
        SwarmLatencyScenario::new(SwarmWorkloadKind::FwcHostConnector, 1_000),
        SwarmLatencyScenario::new(SwarmWorkloadKind::HostBatchInvoke, 1_000),
        SwarmLatencyScenario::new(SwarmWorkloadKind::MeshGossipUpdate, 1_000),
        SwarmLatencyScenario::new(SwarmWorkloadKind::AuditEvidenceRecording, 1_000),
    ];
    let samples: Vec<_> = scenarios
        .iter()
        .enumerate()
        .flat_map(|(scenario_index, scenario)| {
            (0_u64..4).map(move |sample_index| {
                let offset = u64::try_from(scenario_index).unwrap_or(u64::MAX) * 10;
                SwarmLatencySample::new(
                    scenario.id.clone(),
                    format!("agent-{sample_index}"),
                    format!("op-{scenario_index}-{sample_index}"),
                    sample_index,
                    LatencyBreakdown::new(
                        100 + offset + sample_index,
                        200 + offset,
                        30,
                        sample_index,
                        40,
                        10,
                    ),
                )
            })
        })
        .collect();
    let environment = smoke_environment();
    let artifact_manifest = SwarmEvidenceArtifactManifest::from_environment(
        "gauntlet-e2e-smoke",
        SwarmEvidenceSourceKind::HostBacked,
        SwarmEvidenceExecutionMode::Smoke,
        &environment,
        required_artifacts(),
        SwarmEvidenceRedactionPolicy::conservative(),
    )?;

    Ok(
        SwarmLatencyEvidenceBundle::from_samples(environment, scenarios, samples)?
            .with_artifact_manifest(artifact_manifest)?,
    )
}

fn resource_snapshots(bundle: &SwarmLatencyEvidenceBundle) -> Vec<SwarmRegressionMetricSnapshot> {
    bundle
        .summaries
        .iter()
        .map(|summary| {
            SwarmRegressionMetricSnapshot::from_summary(
                summary,
                SwarmRegressionResourceMetrics {
                    throughput_ops_per_second: 10_000,
                    cpu_microunits: 4_000_000,
                    rss_bytes: 128 * 1024 * 1024,
                    max_queue_depth: 64,
                    retry_amplification_microunits: 100_000,
                },
            )
        })
        .collect()
}

fn record_types(records: &[Value]) -> BTreeSet<&str> {
    records
        .iter()
        .filter_map(|record| record["record_type"].as_str())
        .collect()
}

#[test]
fn integrated_swarm_gauntlet_smoke_emits_replayable_jsonl() -> Result<(), Box<dyn Error>> {
    let manifest = SwarmGauntletManifest::smoke(vec![
        "cargo".to_string(),
        "test".to_string(),
        "-p".to_string(),
        "fcp-e2e".to_string(),
        "--test".to_string(),
        "swarm_gauntlet_e2e".to_string(),
    ]);
    let latency_bundle = latency_bundle()?;
    let resources = resource_snapshots(&latency_bundle);
    let first_scenario = latency_bundle.summaries[0].scenario_id.clone();
    let gauntlet = SwarmGauntletEvidenceBundle::new(
        manifest,
        latency_bundle,
        resources,
        decision_cards(&first_scenario),
        phase_evidence(),
        SwarmGauntletCounters {
            audit_event_count: 4,
            same_zone_audit_appends: 512,
            sparse_high_k_metadata_events: 3,
        },
        None,
    )?;

    let records = gauntlet.to_jsonl_values()?;
    let types = record_types(&records);
    let log_record = records
        .iter()
        .find(|record| record["record_type"] == "swarm_gauntlet_log")
        .ok_or("gauntlet log record should be present")?;
    let jsonl = records
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");

    assert!(types.contains("swarm_gauntlet_manifest"));
    assert!(types.contains("swarm_latency_bundle"));
    assert!(types.contains("swarm_latency_sample"));
    assert!(types.contains("swarm_decision_card"));
    assert!(types.contains("swarm_gauntlet_phase_evidence"));
    assert!(types.contains("swarm_gauntlet_summary"));
    assert!(types.contains("swarm_gauntlet_log"));
    assert_eq!(log_record["git_revision"], "e2e-smoke-revision");
    assert_eq!(log_record["worker_id"], "offline-e2e-runner");
    assert_eq!(log_record["evidence_bundle_id"], "gauntlet-e2e-smoke");
    assert!(log_record["decision_card_ids"].is_array());
    assert!(log_record["p99_ns"].is_u64());
    assert!(log_record["throughput_ops_per_second"].is_u64());
    for line in jsonl.lines() {
        serde_json::from_str::<Value>(line)?;
    }
    assert!(!jsonl.contains("sk-live-"));
    assert!(!jsonl.contains("Bearer test-token"));
    assert!(!jsonl.contains("super-secret-value"));
    Ok(())
}

#[test]
fn swarm_promotion_skip_emits_exact_rerun_artifact() -> Result<(), Box<dyn Error>> {
    let envelope = SwarmPromotionEnvelope::high_core_256gib(vec![
        "rch".to_string(),
        "exec".to_string(),
        "--".to_string(),
        "cargo".to_string(),
        "test".to_string(),
        "-p".to_string(),
        "fcp-e2e".to_string(),
        "--test".to_string(),
        "swarm_gauntlet_e2e".to_string(),
        "--".to_string(),
        "--nocapture".to_string(),
    ]);
    let topology = SwarmPromotionTopology::from_environment(
        &promotion_skip_environment(),
        "macos 15.4",
        "24.4.0",
        Some("automatic".to_string()),
        Some("local-ssd".to_string()),
    );
    let qualification = SwarmPromotionQualification::evaluate(envelope, topology)?;
    let skip_artifact = SwarmPromotionSkipArtifact::from_qualification(qualification)
        .ok_or("small offline worker should emit a hardware promotion skip")?;

    let records = skip_artifact.to_jsonl_values()?;
    let types = record_types(&records);
    let skip_record = records
        .iter()
        .find(|record| record["record_type"] == "swarm_promotion_skip")
        .ok_or("promotion skip record should be present")?;
    let jsonl = records
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");

    assert!(types.contains("swarm_promotion_envelope"));
    assert!(types.contains("swarm_promotion_topology"));
    assert!(types.contains("swarm_promotion_skip"));
    assert_eq!(
        skip_record["artifact"]["qualification"]["topology"]["worker_id"],
        "offline-e2e-small-worker"
    );
    assert!(
        skip_record["skip_reason_codes"]
            .as_array()
            .ok_or("skip reason codes should be an array")?
            .iter()
            .any(|code| code == "insufficient_logical_cpus")
    );
    assert!(
        skip_record["skip_reason_codes"]
            .as_array()
            .ok_or("skip reason codes should be an array")?
            .iter()
            .any(|code| code == "missing_memory_measurement")
    );
    assert!(jsonl.contains("\"rerun_command\""));
    assert!(jsonl.contains("swarm_gauntlet_e2e"));
    for line in jsonl.lines() {
        serde_json::from_str::<Value>(line)?;
    }
    assert!(!jsonl.contains("sk-live-"));
    assert!(!jsonl.contains("Bearer test-token"));
    assert!(!jsonl.contains("super-secret-value"));
    Ok(())
}
