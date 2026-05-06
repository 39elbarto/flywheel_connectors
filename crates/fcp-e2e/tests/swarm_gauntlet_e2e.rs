//! Integrated massive-swarm gauntlet smoke lane.
//!
//! This is intentionally offline and deterministic: it exercises the same
//! replay/evidence contracts that a host-backed 10k soak must emit, without
//! depending on live connector services.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io::Write;

use chrono::Utc;
use fcp_host::{
    BatchExecutor, BatchInvokeRequest, BatchOperation, BatchOperationError, BatchOperationPriority,
    BatchOptions, BatchScheduleHint, BatchScheduleReport, BatchScheduleWaitPercentiles,
    BatchSchedulerMode, BatchSchedulerOptions, OperationResultStatus, ResourceLedgerInput,
    ResourceLedgerOutcome, ResourceLedgerRecord, ResourceLedgerRecordKind, ResourceLedgerSamples,
    ResourceTelemetryState,
};
use fcp_testkit::evidence_helpers::{
    LatencyBreakdown, SWARM_BASELINE_PROMOTION_SCHEMA_VERSION,
    SWARM_BATCH_MORSELIZATION_SCHEMA_VERSION, SWARM_CONTROLLER_SAFETY_SCHEMA_VERSION,
    SwarmBaselineArtifactDigests, SwarmBaselinePathKind, SwarmBaselinePromotionManifest,
    SwarmBatchFairnessBucket, SwarmBatchMorselizationEvidence, SwarmBatchResourceSample,
    SwarmBatchWaitPercentiles, SwarmCalibrationStatus, SwarmControllerInteractionScenario,
    SwarmControllerMode, SwarmControllerModeEvidence, SwarmControllerModeMetrics,
    SwarmControllerSafetyOutcome, SwarmControllerSafetyReport, SwarmControllerSafetyThresholds,
    SwarmDecisionAction, SwarmDecisionCard, SwarmDecisionCounterfactual, SwarmDecisionDomain,
    SwarmDecisionEvidencePointer, SwarmDecisionFallback, SwarmDecisionLossTerm,
    SwarmEvidenceArtifact, SwarmEvidenceArtifactKind, SwarmEvidenceArtifactManifest,
    SwarmEvidenceExecutionMode, SwarmEvidenceRedactionPolicy, SwarmEvidenceSourceKind,
    SwarmGauntletCounters, SwarmGauntletEvidenceBundle, SwarmGauntletManifest, SwarmGauntletPhase,
    SwarmGauntletPhaseEvidence, SwarmLatencyEvidenceBundle, SwarmLatencySample,
    SwarmLatencyScenario, SwarmPromotionEnvelope, SwarmPromotionQualification,
    SwarmPromotionSkipArtifact, SwarmPromotionTopology, SwarmRegressionGateThresholds,
    SwarmRegressionMetricSnapshot, SwarmRegressionResourceMetrics, SwarmRunEnvironment,
    SwarmStatisticalGateInput, SwarmStatisticalGateOutcome, SwarmStatisticalGateReasonKind,
    SwarmStatisticalGateReport, SwarmStatisticalGateTuning, SwarmStatisticalTraceQuality,
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

fn controller_safety_card(
    card_id: &str,
    domain: SwarmDecisionDomain,
    action: SwarmDecisionAction,
    scenario: SwarmControllerInteractionScenario,
) -> SwarmDecisionCard {
    SwarmDecisionCard::new(
        card_id,
        domain,
        "connector:offline-controller-safety",
        scenario.as_str(),
        action,
        100,
        SwarmDecisionFallback::available(SwarmDecisionAction::Fallback),
    )
    .with_scenario(scenario.as_str())
    .with_loss_terms(vec![
        SwarmDecisionLossTerm::new("p99_queueing", 100, 1_000_000, "ns"),
        SwarmDecisionLossTerm::new("audit_visibility", 1, 2_000_000, "events"),
    ])
    .with_counterfactual(SwarmDecisionCounterfactual::new(
        SwarmDecisionAction::Fallback,
        140,
        "fallback is safe but lower-throughput",
    ))
    .with_evidence_pointers(vec![SwarmDecisionEvidencePointer::bundle_artifact(
        format!("controller_safety.jsonl#{}", scenario.as_str()),
        "blake3:controller-safety",
        true,
    )])
    .with_replay_inputs(BTreeMap::from([
        ("scenario".to_string(), json!(scenario.as_str())),
        ("queue_depth".to_string(), json!(128)),
        (
            "zone".to_string(),
            json!("z:project:offline-controller-safety"),
        ),
    ]))
}

fn controller_safety_cards(scenario: SwarmControllerInteractionScenario) -> Vec<SwarmDecisionCard> {
    vec![
        controller_safety_card(
            "e2e-card:scheduler-safety",
            SwarmDecisionDomain::Scheduler,
            SwarmDecisionAction::Dispatch,
            scenario,
        ),
        controller_safety_card(
            "e2e-card:placement-safety",
            SwarmDecisionDomain::Placement,
            SwarmDecisionAction::Place,
            scenario,
        ),
        controller_safety_card(
            "e2e-card:backpressure-safety",
            SwarmDecisionDomain::Backpressure,
            SwarmDecisionAction::Delay,
            scenario,
        ),
        controller_safety_card(
            "e2e-card:fallback-safety",
            SwarmDecisionDomain::Backpressure,
            SwarmDecisionAction::Fallback,
            scenario,
        ),
    ]
}

fn controller_safety_metrics(
    submitted_ops: u64,
    decision_card_count: u64,
) -> SwarmControllerModeMetrics {
    SwarmControllerModeMetrics {
        submitted_ops,
        accounted_ops: submitted_ops,
        audit_event_count: submitted_ops,
        max_starvation_ms: 300,
        zone_fairness_skew_microunits: 10_000,
        principal_fairness_skew_microunits: 10_000,
        counterfactual_count: decision_card_count,
        decision_card_count,
        ..SwarmControllerModeMetrics::default()
    }
}

fn controller_safety_modes(
    scenario: SwarmControllerInteractionScenario,
) -> Vec<SwarmControllerModeEvidence> {
    let scheduler = controller_safety_metrics(256, 1);
    let placement = controller_safety_metrics(256, 1);
    let mut backpressure = controller_safety_metrics(256, 1);
    backpressure.delayed_ops = 16;
    let mut audit = controller_safety_metrics(256, 0);
    audit.counterfactual_count = 0;
    let mut combined = controller_safety_metrics(256, 3);
    combined.delayed_ops = 16;
    combined.shed_ops = 2;
    let mut fallback = controller_safety_metrics(256, 1);
    fallback.fallback_invocations = 1;

    vec![
        SwarmControllerModeEvidence::new(
            scenario,
            SwarmControllerMode::SchedulerOnly,
            scheduler,
            vec!["e2e-card:scheduler-safety".to_string()],
        ),
        SwarmControllerModeEvidence::new(
            scenario,
            SwarmControllerMode::PlacementOnly,
            placement,
            vec!["e2e-card:placement-safety".to_string()],
        ),
        SwarmControllerModeEvidence::new(
            scenario,
            SwarmControllerMode::BackpressureOnly,
            backpressure,
            vec!["e2e-card:backpressure-safety".to_string()],
        ),
        SwarmControllerModeEvidence::new(
            scenario,
            SwarmControllerMode::AuditOnly,
            audit,
            Vec::new(),
        ),
        SwarmControllerModeEvidence::new(
            scenario,
            SwarmControllerMode::CombinedController,
            combined,
            vec![
                "e2e-card:scheduler-safety".to_string(),
                "e2e-card:placement-safety".to_string(),
                "e2e-card:backpressure-safety".to_string(),
            ],
        ),
        SwarmControllerModeEvidence::new(
            scenario,
            SwarmControllerMode::ConservativeFallback,
            fallback,
            vec!["e2e-card:fallback-safety".to_string()],
        ),
    ]
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

fn resource_ledger_records(
    command_line: &[String],
    git_revision: &str,
    worker_identity: &str,
) -> Result<Vec<Value>, serde_json::Error> {
    [
        (
            "invoke",
            ResourceLedgerRecordKind::Invoke,
            ResourceLedgerOutcome::Admitted,
            ResourceLedgerSamples {
                state: ResourceTelemetryState::Observed,
                queue_pressure_per_mille: Some(120),
                cpu_pressure_per_mille: Some(180),
                memory_pressure_per_mille: Some(210),
                in_flight: Some(8),
                queue_depth: Some(2),
                retry_after_ms: None,
            },
            vec![10_000, 12_000, 15_000, 20_000],
        ),
        (
            "batch",
            ResourceLedgerRecordKind::Batch,
            ResourceLedgerOutcome::Admitted,
            ResourceLedgerSamples {
                state: ResourceTelemetryState::Observed,
                queue_pressure_per_mille: Some(240),
                cpu_pressure_per_mille: Some(360),
                memory_pressure_per_mille: Some(300),
                in_flight: Some(64),
                queue_depth: Some(8),
                retry_after_ms: None,
            },
            vec![30_000, 32_000, 40_000],
        ),
        (
            "backpressure",
            ResourceLedgerRecordKind::Backpressure,
            ResourceLedgerOutcome::Delayed,
            ResourceLedgerSamples {
                state: ResourceTelemetryState::Observed,
                queue_pressure_per_mille: Some(820),
                cpu_pressure_per_mille: Some(760),
                memory_pressure_per_mille: Some(650),
                in_flight: Some(64),
                queue_depth: Some(31),
                retry_after_ms: Some(25),
            },
            vec![20_000, 22_000, 30_000],
        ),
        (
            "placement",
            ResourceLedgerRecordKind::Placement,
            ResourceLedgerOutcome::Admitted,
            ResourceLedgerSamples {
                state: ResourceTelemetryState::Observed,
                queue_pressure_per_mille: Some(100),
                cpu_pressure_per_mille: Some(440),
                memory_pressure_per_mille: Some(390),
                in_flight: Some(16),
                queue_depth: Some(4),
                retry_after_ms: None,
            },
            vec![8_000, 9_000, 11_000],
        ),
        (
            "retry",
            ResourceLedgerRecordKind::Retry,
            ResourceLedgerOutcome::Retried,
            ResourceLedgerSamples {
                state: ResourceTelemetryState::Observed,
                queue_pressure_per_mille: Some(400),
                cpu_pressure_per_mille: Some(500),
                memory_pressure_per_mille: None,
                in_flight: Some(14),
                queue_depth: Some(7),
                retry_after_ms: Some(100),
            },
            vec![30_000, 50_000, 80_000],
        ),
        (
            "audit",
            ResourceLedgerRecordKind::Audit,
            ResourceLedgerOutcome::Admitted,
            ResourceLedgerSamples {
                state: ResourceTelemetryState::NotApplicable,
                ..ResourceLedgerSamples::default()
            },
            Vec::new(),
        ),
    ]
    .into_iter()
    .map(|(suffix, kind, outcome, samples, latency_samples_ns)| {
        let audit_receipt_id = if kind == ResourceLedgerRecordKind::Audit {
            Some("audit-receipt-resource-ledger-e2e".to_string())
        } else {
            None
        };
        ResourceLedgerRecord::new(ResourceLedgerInput {
            scenario_id: "swarm.resource-ledger.e2e-gauntlet".to_string(),
            operation_id: format!("op-proof-{suffix}"),
            kind,
            outcome,
            command_line: command_line.to_vec(),
            git_revision: git_revision.to_string(),
            worker_identity: worker_identity.to_string(),
            zone_id: Some("z:work".to_string()),
            principal_id: Some("principal:resource-ledger-e2e".to_string()),
            connector_id: Some("fcp.synthetic-gauntlet".to_string()),
            controller_decision: Some(suffix.to_string()),
            samples,
            latency_samples_ns,
            audit_receipt_id,
            fallback_reason: None,
            skip_reason: None,
        })
        .to_jsonl_value()
    })
    .collect()
}

fn batch_morselization_command_line() -> Vec<String> {
    vec![
        "rch".to_string(),
        "exec".to_string(),
        "--".to_string(),
        "cargo".to_string(),
        "test".to_string(),
        "-p".to_string(),
        "fcp-e2e".to_string(),
        "--no-default-features".to_string(),
        "--test".to_string(),
        "swarm_gauntlet_e2e".to_string(),
        "batch_morselization".to_string(),
        "--".to_string(),
        "--nocapture".to_string(),
    ]
}

fn batch_operation(index: usize, root_dependency: Option<&str>) -> BatchOperation {
    let is_long = index % 25 == 0;
    let fairness_key = if index % 3 == 0 {
        "zone:hot".to_string()
    } else {
        format!("zone:tenant:{}", index % 127)
    };
    BatchOperation {
        id: format!("op_{index:05}"),
        tool: "fcp.host.synthetic_batch".to_string(),
        input: json!({"shape": "redacted-fixture"}),
        depends_on: root_dependency.into_iter().map(str::to_string).collect(),
        zone: None,
        scheduler: BatchScheduleHint {
            priority: if index % 257 == 0 {
                BatchOperationPriority::Critical
            } else {
                BatchOperationPriority::Normal
            },
            estimated_duration_ms: Some(if is_long {
                20_000
            } else {
                2 + u64::try_from(index % 13).unwrap_or(u64::MAX)
            }),
            fairness_key: Some(fairness_key),
        },
    }
}

fn batch_morselization_request(operation_count: usize) -> BatchInvokeRequest {
    let mut operations = Vec::with_capacity(operation_count);
    for index in 0..operation_count {
        let root_dependency = (index >= operation_count / 2).then_some("op_00000");
        operations.push(batch_operation(index, root_dependency));
    }
    BatchInvokeRequest {
        operations,
        options: BatchOptions {
            max_parallelism: 256,
            timeout_ms: 30_000,
            scheduler: BatchSchedulerOptions {
                mode: BatchSchedulerMode::Adaptive,
                max_consecutive_per_fairness_key: 2,
            },
            ..Default::default()
        },
    }
}

fn batch_failure_request(timeout_ms: u64) -> BatchInvokeRequest {
    BatchInvokeRequest {
        operations: vec![
            batch_operation(0, None),
            batch_operation(1, Some("op_00000")),
        ],
        options: BatchOptions {
            max_parallelism: 2,
            timeout_ms,
            scheduler: BatchSchedulerOptions {
                mode: BatchSchedulerMode::Adaptive,
                max_consecutive_per_fairness_key: 2,
            },
            ..Default::default()
        },
    }
}

fn injected_batch_error() -> BatchOperationError {
    BatchOperationError {
        code: "INJECTED_FAILURE".to_string(),
        message: "redacted downstream failure".to_string(),
        retry_after_ms: Some(250),
    }
}

fn batch_failure_modes(
    executor: &BatchExecutor,
) -> Result<(String, String, String), Box<dyn Error>> {
    let failure = executor.execute_sync(&batch_failure_request(30_000), |operation| {
        if operation.id == "op_00000" {
            Err(injected_batch_error())
        } else {
            Ok(json!({"ok": true}))
        }
    })?;
    let error_kind = failure
        .results
        .iter()
        .find(|result| result.status == OperationResultStatus::Error)
        .and_then(|result| result.error.as_ref())
        .map(|error| format!("downstream_error:{}", error.code))
        .ok_or("failure scenario should include an error result")?;
    let skip_reason = failure
        .results
        .iter()
        .find(|result| result.status == OperationResultStatus::Skipped)
        .and_then(|result| result.error.as_ref())
        .map(|error| format!("dependency_failed:{}", error.code))
        .ok_or("failure scenario should include dependency skip")?;

    let timeout = executor.execute_sync(&batch_failure_request(0), |_| Ok(json!({"ok": true})))?;
    let cancellation_reason = timeout
        .results
        .iter()
        .find(|result| result.status == OperationResultStatus::Skipped)
        .and_then(|result| result.error.as_ref())
        .map(|error| format!("timeout:{}", error.code))
        .ok_or("timeout scenario should include a skipped operation")?;

    Ok((error_kind, cancellation_reason, skip_reason))
}

fn batch_wait_percentiles(wait: BatchScheduleWaitPercentiles) -> SwarmBatchWaitPercentiles {
    SwarmBatchWaitPercentiles {
        p50_ms: wait.p50_ms,
        p95_ms: wait.p95_ms,
        p99_ms: wait.p99_ms,
        p999_ms: wait.p999_ms,
        max_ms: wait.max_ms,
        mean_ms: wait.mean_ms,
    }
}

fn redacted_fairness_key(key: &str) -> String {
    format!("blake3:{}", blake3::hash(key.as_bytes()))
}

fn fairness_distribution(report: &BatchScheduleReport) -> Vec<SwarmBatchFairnessBucket> {
    let mut operation_counts = BTreeMap::<String, usize>::new();
    for decision in &report.decisions {
        let key = decision.fairness_key.as_deref().unwrap_or("unclassified");
        *operation_counts
            .entry(redacted_fairness_key(key))
            .or_default() += 1;
    }

    let mut morsel_counts = BTreeMap::<String, usize>::new();
    if let Some(morselization) = &report.morselization {
        for morsel in &morselization.morsels {
            for key in &morsel.fairness_keys {
                *morsel_counts.entry(redacted_fairness_key(key)).or_default() += 1;
            }
        }
    }

    operation_counts
        .into_iter()
        .map(
            |(fairness_key_hash, operation_count)| SwarmBatchFairnessBucket {
                morsel_count: morsel_counts.get(&fairness_key_hash).copied().unwrap_or(1),
                fairness_key_hash,
                operation_count,
            },
        )
        .collect()
}

fn batch_morselization_evidence(
    operation_count: usize,
    dependency_depth: usize,
    report: &BatchScheduleReport,
    error_kind: String,
    cancellation_reason: String,
    skip_reason: String,
) -> Result<SwarmBatchMorselizationEvidence, Box<dyn Error>> {
    let queueing = report
        .queueing_summary
        .as_ref()
        .ok_or("batch report should include queueing summary")?;
    let fifo_wait = queueing.fifo_wait;
    let scheduled_wait = queueing.scheduled_wait;
    let morselization = report
        .morselization
        .as_ref()
        .ok_or("batch report should include morselization")?;
    let operation_count_u64 = u64::try_from(operation_count).unwrap_or(u64::MAX);

    Ok(SwarmBatchMorselizationEvidence {
        schema_version: SWARM_BATCH_MORSELIZATION_SCHEMA_VERSION.to_string(),
        scenario_id: format!("host_batch_morselization_{operation_count}"),
        batch_id: format!("batch:offline:{operation_count}"),
        command_line: batch_morselization_command_line(),
        git_revision: "e2e-smoke-revision".to_string(),
        worker_id: "offline-e2e-runner".to_string(),
        scheduler_mode: format!("{:?}", report.mode).to_ascii_lowercase(),
        operation_count,
        dependency_depth,
        morsel_size: morselization.max_operations_per_morsel,
        total_morsels: morselization.total_morsels,
        split_tiers: morselization.split_tiers,
        largest_morsel_operations: morselization.largest_morsel_operations,
        fairness_distribution: fairness_distribution(report),
        fifo_wait: batch_wait_percentiles(fifo_wait),
        scheduled_wait: batch_wait_percentiles(scheduled_wait),
        resources: SwarmBatchResourceSample {
            rss_bytes: 128 * 1024 * 1024 + operation_count_u64.saturating_mul(512),
            cpu_microunits: 64_000_000,
            max_queue_depth: u64::try_from(morselization.max_operations_per_morsel)
                .unwrap_or(u64::MAX),
            retry_amplification_microunits: 0,
        },
        fallback_reason: morselization.fallback_reason.clone(),
        error_kind: Some(error_kind),
        cancellation_reason: Some(cancellation_reason),
        skip_reason: Some(skip_reason),
    })
}

fn maybe_write_batch_morselization_jsonl_artifact(jsonl: &str) -> std::io::Result<()> {
    let Some(path) = std::env::var_os("FCP_BATCH_MORSELIZATION_JSONL_OUT") else {
        return Ok(());
    };

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(jsonl.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

fn statistical_baseline_snapshot() -> SwarmRegressionMetricSnapshot {
    SwarmRegressionMetricSnapshot {
        scenario_id: "host_batch_invoke_10000".to_string(),
        sample_count: 120,
        p99_ns: 100_000,
        p999_ns: 125_000,
        throughput_ops_per_second: 1_000_000,
        cpu_microunits: 64_000_000,
        rss_bytes: 8 * 1024 * 1024 * 1024,
        max_queue_depth: 1_000,
        retry_amplification_microunits: 100_000,
    }
}

fn statistical_baseline_manifest(
    scenario_id: &str,
    expires_at: chrono::DateTime<Utc>,
) -> SwarmBaselinePromotionManifest {
    SwarmBaselinePromotionManifest {
        schema_version: SWARM_BASELINE_PROMOTION_SCHEMA_VERSION.to_string(),
        baseline_id: format!("baseline:{scenario_id}:e2e"),
        scenario_id: scenario_id.to_string(),
        execution_mode: SwarmEvidenceExecutionMode::Smoke,
        source_revision: "e2e-baseline-revision".to_string(),
        rch_worker_id: "offline-e2e-runner".to_string(),
        required_paths: SwarmBaselinePathKind::REQUIRED.to_vec(),
        artifact_digests: SwarmBaselineArtifactDigests::new(
            "blake3:e2e-raw-samples",
            "blake3:e2e-summary",
            "blake3:e2e-gate-report",
            "blake3:e2e-proof-notes",
            "blake3:e2e-manifest",
        ),
        redaction_policy: SwarmEvidenceRedactionPolicy::conservative(),
        operator_notes: "offline e2e baseline promoted from controlled traces".to_string(),
        promoted_at: Utc::now(),
        expires_at,
    }
}

fn statistical_report(
    candidate: SwarmRegressionMetricSnapshot,
    candidate_quality: SwarmStatisticalTraceQuality,
    audit_event_count: u64,
    decision_card_replay_matches: bool,
    expires_at: chrono::DateTime<Utc>,
) -> SwarmStatisticalGateReport {
    let baseline = statistical_baseline_snapshot();
    SwarmStatisticalGateReport::evaluate(SwarmStatisticalGateInput {
        baseline_manifest: statistical_baseline_manifest(&baseline.scenario_id, expires_at),
        baseline: baseline.clone(),
        candidate,
        thresholds: SwarmRegressionGateThresholds::smoke(),
        execution_mode: SwarmEvidenceExecutionMode::Smoke,
        tuning: SwarmStatisticalGateTuning::smoke(),
        baseline_quality: SwarmStatisticalTraceQuality::controlled(baseline.sample_count),
        candidate_quality,
        audit_event_count,
        decision_card_replay_matches,
        operator_notes: "offline e2e statistical gate proof".to_string(),
        generated_at: Utc::now(),
    })
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
    let resource_ledger_records = resource_ledger_records(
        &latency_bundle.environment.command_line,
        latency_bundle
            .environment
            .source_revision
            .as_deref()
            .unwrap_or("unknown"),
        &latency_bundle.environment.worker_id,
    )?;
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
    )?
    .with_resource_ledger_records(resource_ledger_records)?;

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
    assert!(types.contains("resource_ledger"));
    assert!(types.contains("swarm_gauntlet_phase_evidence"));
    assert!(types.contains("swarm_gauntlet_summary"));
    assert!(types.contains("swarm_gauntlet_log"));
    assert_eq!(log_record["git_revision"], "e2e-smoke-revision");
    assert_eq!(log_record["worker_id"], "offline-e2e-runner");
    assert_eq!(log_record["evidence_bundle_id"], "gauntlet-e2e-smoke");
    assert!(log_record["decision_card_ids"].is_array());
    assert_eq!(log_record["resource_ledger_record_count"], 6);
    assert_eq!(log_record["resource_ledger_record_type"], "resource_ledger");
    assert!(log_record["resource_ledger_operation_ids"].is_array());
    assert!(log_record["p99_ns"].is_u64());
    assert!(log_record["throughput_ops_per_second"].is_u64());
    let ledger_record = records
        .iter()
        .find(|record| record["record_type"] == "resource_ledger")
        .ok_or("resource ledger record should be present")?;
    assert_eq!(ledger_record["schema_version"], "resource-ledger/v1");
    assert!(
        ledger_record["ledger"]["worker_ref"]
            .as_str()
            .is_some_and(|worker| worker.starts_with("worker:blake3:"))
    );
    assert!(
        ledger_record["ledger"]["principal_ref"]
            .as_str()
            .is_some_and(|principal| principal.starts_with("principal:blake3:"))
    );
    for line in jsonl.lines() {
        serde_json::from_str::<Value>(line)?;
    }
    assert!(!jsonl.contains("sk-live-"));
    assert!(!jsonl.contains("Bearer test-token"));
    assert!(!jsonl.contains("super-secret-value"));
    assert!(!jsonl.contains("principal:resource-ledger-e2e"));
    Ok(())
}

#[test]
fn batch_morselization_e2e_emits_replayable_jsonl() -> Result<(), Box<dyn Error>> {
    let executor = BatchExecutor::new();
    let (error_kind, cancellation_reason, skip_reason) = batch_failure_modes(&executor)?;
    let mut records = Vec::new();

    for operation_count in [1_000_usize, 10_000] {
        let request = batch_morselization_request(operation_count);
        let (plan, report) = executor.plan_with_schedule_report(&request)?;
        let evidence = batch_morselization_evidence(
            operation_count,
            plan.tiers.len(),
            &report,
            error_kind.clone(),
            cancellation_reason.clone(),
            skip_reason.clone(),
        )?;

        evidence.validate()?;
        records.push(evidence.to_jsonl_value()?);
    }

    let jsonl = records
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    maybe_write_batch_morselization_jsonl_artifact(&jsonl)?;
    let types = record_types(&records);
    let tenk_record = records
        .iter()
        .find(|record| record["scenario_id"] == "host_batch_morselization_10000")
        .ok_or("10k batch morselization record should be present")?;

    assert!(types.contains("swarm_batch_morselization_evidence"));
    assert_eq!(
        tenk_record["schema_version"],
        SWARM_BATCH_MORSELIZATION_SCHEMA_VERSION
    );
    assert_eq!(tenk_record["operation_count"], 10_000);
    assert_eq!(tenk_record["dependency_depth"], 2);
    assert_eq!(tenk_record["morsel_size"], 256);
    assert!(
        tenk_record["evidence"]["total_morsels"]
            .as_u64()
            .is_some_and(|total| total > 1)
    );
    assert!(
        tenk_record["evidence"]["split_tiers"]
            .as_u64()
            .is_some_and(|tiers| tiers > 0)
    );
    assert_eq!(
        tenk_record["evidence"]["largest_morsel_operations"],
        tenk_record["morsel_size"]
    );
    assert!(
        tenk_record["evidence"]["fairness_distribution"]
            .as_array()
            .is_some_and(|distribution| distribution.len() > 8)
    );
    assert!(tenk_record["p50_wait_ms"].is_u64());
    assert!(tenk_record["p95_wait_ms"].is_u64());
    assert!(tenk_record["p99_wait_ms"].is_u64());
    assert!(tenk_record["p999_wait_ms"].is_u64());
    assert!(tenk_record["rss_bytes"].is_u64());
    assert!(tenk_record["max_queue_depth"].is_u64());
    assert_eq!(
        tenk_record["error_kind"],
        "downstream_error:INJECTED_FAILURE"
    );
    assert_eq!(tenk_record["cancellation_reason"], "timeout:BATCH_TIMEOUT");
    assert_eq!(tenk_record["skip_reason"], "dependency_failed:DEP_FAILED");
    for line in jsonl.lines() {
        serde_json::from_str::<Value>(line)?;
    }
    assert!(!jsonl.contains("sk-live-"));
    assert!(!jsonl.contains("Bearer test-token"));
    assert!(!jsonl.contains("super-secret-value"));
    Ok(())
}

#[test]
fn swarm_statistical_gate_e2e_emits_pass_fail_and_indeterminate_logs() -> Result<(), Box<dyn Error>>
{
    let baseline = statistical_baseline_snapshot();
    let future_expiry = Utc::now() + chrono::Duration::days(30);
    let pass_report = statistical_report(
        SwarmRegressionMetricSnapshot {
            p99_ns: 104_000,
            p999_ns: 131_000,
            throughput_ops_per_second: 970_000,
            cpu_microunits: 66_000_000,
            max_queue_depth: 1_050,
            retry_amplification_microunits: 105_000,
            ..baseline.clone()
        },
        SwarmStatisticalTraceQuality::controlled(120),
        4,
        true,
        future_expiry,
    );
    let fail_report = statistical_report(
        SwarmRegressionMetricSnapshot {
            p99_ns: 115_000,
            p999_ns: 145_000,
            throughput_ops_per_second: 900_000,
            cpu_microunits: 72_000_000,
            max_queue_depth: 1_250,
            retry_amplification_microunits: 125_000,
            ..baseline.clone()
        },
        SwarmStatisticalTraceQuality::controlled(120),
        0,
        false,
        future_expiry,
    );
    let mut noisy_quality = SwarmStatisticalTraceQuality::controlled(120);
    noisy_quality.worker_drift_percent = 25;
    let indeterminate_report = statistical_report(
        baseline,
        noisy_quality,
        4,
        true,
        Utc::now() + chrono::Duration::days(30),
    );
    let reports = [
        ("pass", pass_report),
        ("fail", fail_report),
        ("indeterminate", indeterminate_report),
    ];
    let outcomes: BTreeMap<_, _> = reports
        .iter()
        .map(|(name, report)| (*name, report.outcome))
        .collect();
    let mut records = Vec::new();
    for (_, report) in &reports {
        records.extend(report.to_jsonl_values()?);
    }
    let jsonl = records
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    let gate_records = records
        .iter()
        .filter(|record| record["record_type"] == "swarm_statistical_gate_report")
        .collect::<Vec<_>>();
    let fail_record = gate_records
        .iter()
        .find(|record| record["outcome"] == "fail")
        .ok_or("fail record should be present")?;
    let indeterminate_record = gate_records
        .iter()
        .find(|record| record["outcome"] == "indeterminate")
        .ok_or("indeterminate record should be present")?;

    assert_eq!(
        outcomes.get("pass"),
        Some(&SwarmStatisticalGateOutcome::Pass)
    );
    assert_eq!(
        outcomes.get("fail"),
        Some(&SwarmStatisticalGateOutcome::Fail)
    );
    assert_eq!(
        outcomes.get("indeterminate"),
        Some(&SwarmStatisticalGateOutcome::Indeterminate)
    );
    assert_eq!(gate_records.len(), 3);
    assert!(
        fail_record["reason_codes"]
            .as_array()
            .ok_or("fail reason codes should be an array")?
            .iter()
            .any(|code| code == SwarmStatisticalGateReasonKind::P99Regression.code())
    );
    assert!(
        fail_record["reason_codes"]
            .as_array()
            .ok_or("fail reason codes should be an array")?
            .iter()
            .any(|code| code == SwarmStatisticalGateReasonKind::AuditLoss.code())
    );
    assert!(
        indeterminate_record["reason_codes"]
            .as_array()
            .ok_or("indeterminate reason codes should be an array")?
            .iter()
            .any(|code| code == SwarmStatisticalGateReasonKind::NoisyWorker.code())
    );
    assert!(jsonl.contains("swarm_baseline_promotion_manifest"));
    assert!(jsonl.contains("blake3:e2e-raw-samples"));
    for line in jsonl.lines() {
        serde_json::from_str::<Value>(line)?;
    }
    assert!(!jsonl.contains("sk-live-"));
    assert!(!jsonl.contains("Bearer test-token"));
    assert!(!jsonl.contains("super-secret-value"));
    Ok(())
}

#[test]
fn swarm_controller_safety_e2e_emits_pass_fail_and_fallback_logs() -> Result<(), Box<dyn Error>> {
    let pass_scenario = SwarmControllerInteractionScenario::MixedPriority;
    let pass_report = SwarmControllerSafetyReport::evaluate(
        pass_scenario,
        SwarmControllerSafetyThresholds::smoke(),
        controller_safety_modes(pass_scenario),
        controller_safety_cards(pass_scenario),
    );

    let fail_scenario = SwarmControllerInteractionScenario::SameZoneAuditStorm;
    let mut fail_modes = controller_safety_modes(fail_scenario);
    let combined = fail_modes
        .iter_mut()
        .find(|mode| mode.mode == SwarmControllerMode::CombinedController)
        .ok_or("combined controller mode should be present")?;
    combined.metrics.accounted_ops = 252;
    combined.metrics.hidden_drop_count = 4;
    combined.metrics.audit_event_count = 240;
    combined.metrics.max_starvation_ms = 10_000;
    combined.metrics.zone_fairness_skew_microunits = 300_000;
    combined.metrics.replay_mismatch_count = 1;
    let fail_report = SwarmControllerSafetyReport::evaluate(
        fail_scenario,
        SwarmControllerSafetyThresholds::smoke(),
        fail_modes,
        controller_safety_cards(fail_scenario),
    );

    let fallback_scenario = SwarmControllerInteractionScenario::DownstreamThrottled;
    let mut fallback_cards = controller_safety_cards(fallback_scenario);
    fallback_cards[2] = fallback_cards[2]
        .clone()
        .with_calibration(SwarmCalibrationStatus::ReplayMismatch);
    let mut fallback_modes = controller_safety_modes(fallback_scenario);
    let backpressure = fallback_modes
        .iter_mut()
        .find(|mode| mode.mode == SwarmControllerMode::BackpressureOnly)
        .ok_or("backpressure mode should be present")?;
    backpressure.metrics.fallback_invocations = 1;
    backpressure.fallback_reason = Some("replay_mismatch".to_string());
    let fallback_report = SwarmControllerSafetyReport::evaluate(
        fallback_scenario,
        SwarmControllerSafetyThresholds::smoke(),
        fallback_modes,
        fallback_cards,
    );

    let reports = [
        ("pass", pass_report),
        ("fail", fail_report),
        ("fallback_required", fallback_report),
    ];
    let outcomes: BTreeMap<_, _> = reports
        .iter()
        .map(|(name, report)| (*name, report.outcome))
        .collect();
    let mut records = Vec::new();
    for (_, report) in &reports {
        records.extend(report.to_jsonl_values()?);
    }
    let jsonl = records
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    let report_records = records
        .iter()
        .filter(|record| record["record_type"] == "swarm_controller_safety_report")
        .collect::<Vec<_>>();
    let failure_records = records
        .iter()
        .filter(|record| record["record_type"] == "swarm_controller_safety_failure")
        .collect::<Vec<_>>();
    let fallback_record = report_records
        .iter()
        .find(|record| record["outcome"] == "fallback_required")
        .ok_or("fallback-required report should be present")?;
    let pass_record = report_records
        .iter()
        .find(|record| record["outcome"] == "pass")
        .ok_or("pass report should be present")?;

    assert_eq!(
        outcomes.get("pass"),
        Some(&SwarmControllerSafetyOutcome::Pass)
    );
    assert_eq!(
        outcomes.get("fail"),
        Some(&SwarmControllerSafetyOutcome::Fail)
    );
    assert_eq!(
        outcomes.get("fallback_required"),
        Some(&SwarmControllerSafetyOutcome::FallbackRequired)
    );
    assert_eq!(report_records.len(), 3);
    assert_eq!(
        pass_record["schema_version"],
        SWARM_CONTROLLER_SAFETY_SCHEMA_VERSION
    );
    assert!(
        pass_record["decision_card_ids"]
            .as_array()
            .ok_or("decision card ids should be an array")?
            .iter()
            .any(|id| id == "e2e-card:backpressure-safety")
    );
    assert!(failure_records.iter().any(|record| {
        record["invariant"] == "work_conservation" && record["reason"] == "hidden_drop"
    }));
    assert!(failure_records.iter().any(|record| {
        record["invariant"] == "no_audit_loss" && record["reason"] == "audit_event_shortfall"
    }));
    assert!(
        fallback_record["fallback_reasons"]
            .as_array()
            .ok_or("fallback reasons should be an array")?
            .iter()
            .any(|reason| reason
                .as_str()
                .is_some_and(|value| value.contains("replay_mismatch")))
    );
    assert!(jsonl.contains("swarm_controller_safety_mode_evidence"));
    assert!(jsonl.contains("swarm_decision_card"));
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
