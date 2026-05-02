//! Evidence and artifact assertion helpers.
//!
//! Provides utilities for testing that connectors produce the expected
//! evidence artifacts: audit events, operation receipts, decision records,
//! and structured log traces.
//!
//! # Example
//!
//! ```rust,ignore
//! use fcp_testkit::evidence_helpers::*;
//!
//! let mut collector = EvidenceCollector::new();
//! collector.record_audit_event("invoke", "gmail.search", json!({"zone": "z:private"}));
//! collector.record_receipt("req_1", "op_1", true);
//!
//! assert_evidence_has_audit_event(&collector, "invoke");
//! assert_evidence_has_receipt(&collector, "req_1");
//! assert_evidence_no_secrets(&collector, &["sk-test-", "Bearer "]);
//! ```

use crate::database_helpers::{
    CleanupVerificationResult, FixtureMutationRecord, FixtureSeedRecord,
};
use crate::live_suite::LiveEnvironment;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Evidence Collector
// ─────────────────────────────────────────────────────────────────────────────

/// Collects evidence artifacts during connector test execution.
#[derive(Debug, Default)]
pub struct EvidenceCollector {
    /// Recorded audit events.
    pub audit_events: Vec<AuditEvidence>,
    /// Recorded operation receipts.
    pub receipts: Vec<ReceiptEvidence>,
    /// Recorded decision records (approval/denial).
    pub decisions: Vec<DecisionEvidence>,
    /// Recorded structured log lines.
    pub log_lines: Vec<Value>,
    /// Recorded seeded state for truthful local fixture runs.
    pub seeded_state: Vec<FixtureSeedRecord>,
    /// Recorded state mutations exercised during the run.
    pub mutations: Vec<FixtureMutationRecord>,
    /// Recorded cleanup verification results from teardown.
    pub cleanup_verifications: Vec<CleanupVerificationResult>,
}

/// A recorded audit event.
#[derive(Debug, Clone)]
pub struct AuditEvidence {
    /// Event type (e.g., "invoke", "configure", "health").
    pub event_type: String,
    /// Operation that produced this event.
    pub operation: String,
    /// Additional context.
    pub context: Value,
    /// Whether this event was zone-scoped.
    pub zone_scoped: bool,
}

/// A recorded operation receipt.
#[derive(Debug, Clone)]
pub struct ReceiptEvidence {
    /// Request ID that produced this receipt.
    pub request_id: String,
    /// Operation ID.
    pub operation_id: String,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Idempotency key if present.
    pub idempotency_key: Option<String>,
}

/// A recorded decision (approval or denial).
#[derive(Debug, Clone)]
pub struct DecisionEvidence {
    /// What was decided on.
    pub subject: String,
    /// Whether it was approved.
    pub approved: bool,
    /// Reason for the decision.
    pub reason: String,
}

impl EvidenceCollector {
    /// Create a new empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an audit event.
    pub fn record_audit_event(&mut self, event_type: &str, operation: &str, context: Value) {
        self.audit_events.push(AuditEvidence {
            event_type: event_type.to_string(),
            operation: operation.to_string(),
            context,
            zone_scoped: true,
        });
    }

    /// Record an audit event without zone scoping.
    pub fn record_unscoped_audit_event(
        &mut self,
        event_type: &str,
        operation: &str,
        context: Value,
    ) {
        self.audit_events.push(AuditEvidence {
            event_type: event_type.to_string(),
            operation: operation.to_string(),
            context,
            zone_scoped: false,
        });
    }

    /// Record an operation receipt.
    pub fn record_receipt(&mut self, request_id: &str, operation_id: &str, success: bool) {
        self.receipts.push(ReceiptEvidence {
            request_id: request_id.to_string(),
            operation_id: operation_id.to_string(),
            success,
            idempotency_key: None,
        });
    }

    /// Record a receipt with idempotency key.
    pub fn record_receipt_with_key(
        &mut self,
        request_id: &str,
        operation_id: &str,
        success: bool,
        key: &str,
    ) {
        self.receipts.push(ReceiptEvidence {
            request_id: request_id.to_string(),
            operation_id: operation_id.to_string(),
            success,
            idempotency_key: Some(key.to_string()),
        });
    }

    /// Record an approval or denial decision.
    pub fn record_decision(&mut self, subject: &str, approved: bool, reason: &str) {
        self.decisions.push(DecisionEvidence {
            subject: subject.to_string(),
            approved,
            reason: reason.to_string(),
        });
    }

    /// Record a structured log line.
    pub fn record_log_line(&mut self, line: Value) {
        self.log_lines.push(line);
    }

    /// Record seeded state for a truthful local fixture.
    pub fn record_seeded_state(&mut self, resource: &str, identifier: &str, payload: Value) {
        self.seeded_state
            .push(FixtureSeedRecord::new(resource, identifier, payload));
    }

    /// Record a state mutation exercised during the run.
    pub fn record_mutation(&mut self, mutation: FixtureMutationRecord) {
        self.mutations.push(mutation);
    }

    /// Record a cleanup verification result from teardown.
    pub fn record_cleanup_verification(
        &mut self,
        check_id: &str,
        resource: &str,
        method: &str,
        expected_state: &str,
        observed: Value,
        passed: bool,
    ) {
        self.cleanup_verifications
            .push(CleanupVerificationResult::new(
                check_id,
                resource,
                method,
                expected_state,
                observed,
                passed,
            ));
    }

    /// Total evidence artifacts collected.
    #[must_use]
    pub fn total_artifacts(&self) -> usize {
        self.audit_events.len()
            + self.receipts.len()
            + self.decisions.len()
            + self.seeded_state.len()
            + self.mutations.len()
            + self.cleanup_verifications.len()
    }

    /// Check if any evidence was collected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_artifacts() == 0 && self.log_lines.is_empty()
    }

    /// Serialize all evidence to JSON for reporting.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "audit_events": self.audit_events.len(),
            "receipts": self.receipts.len(),
            "decisions": self.decisions.len(),
            "log_lines": self.log_lines.len(),
            "seeded_state": self.seeded_state.len(),
            "mutations": self.mutations.len(),
            "cleanup_verifications": self.cleanup_verifications.len(),
            "total_artifacts": self.total_artifacts(),
        })
    }
}

/// Render a redaction-safe live-suite environment snapshot suitable for
/// `environment.json` bundles.
///
/// This helper adds the V3 acceptance-contract routing fields on top of the
/// structured live-suite evidence summary so nightly/live orchestration can
/// reason about tier, gate, and mutation mode without exposing raw secrets.
#[must_use]
pub fn render_live_environment_json(
    environment: &LiveEnvironment,
    suite_class: &str,
    mutation_mode: &str,
) -> Value {
    json!({
        "suite_class": suite_class,
        "connector": environment.manifest.connector,
        "provider": environment.manifest.provider,
        "live_tier": environment.manifest.tier.to_string(),
        "gate_env_var": environment.manifest.tier.gate_env_var(),
        "mutation_mode": mutation_mode,
        "live_environment": environment.evidence_summary(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Swarm latency evidence
// ─────────────────────────────────────────────────────────────────────────────

/// Schema tag for replayable swarm-latency evidence bundles.
pub const SWARM_LATENCY_BUNDLE_SCHEMA_VERSION: &str = "swarm-latency-bundle/v1";

/// Synthetic-but-realistic workload families used for swarm latency baselines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmWorkloadKind {
    /// CLI/operator path through fwc, host, and connector dispatch.
    FwcHostConnector,
    /// Host-side batch invoke scheduling and dispatch.
    HostBatchInvoke,
    /// Mesh gossip, update, or control-plane propagation work.
    MeshGossipUpdate,
    /// Audit/evidence recording on the invoke path.
    AuditEvidenceRecording,
}

impl SwarmWorkloadKind {
    /// All canonical swarm workload families.
    pub const ALL: [Self; 4] = [
        Self::FwcHostConnector,
        Self::HostBatchInvoke,
        Self::MeshGossipUpdate,
        Self::AuditEvidenceRecording,
    ];

    /// Stable machine label for this workload family.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FwcHostConnector => "fwc_host_connector",
            Self::HostBatchInvoke => "host_batch_invoke",
            Self::MeshGossipUpdate => "mesh_gossip_update",
            Self::AuditEvidenceRecording => "audit_evidence_recording",
        }
    }
}

/// A canonical workload scenario for 1k/10k-agent swarm runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmLatencyScenario {
    /// Stable scenario identifier.
    pub id: String,
    /// Workload family measured by this scenario.
    pub workload: SwarmWorkloadKind,
    /// Number of simulated or real agents represented by the run.
    pub agent_count: u32,
    /// Human-readable measurement scope.
    pub description: String,
}

impl SwarmLatencyScenario {
    /// Build a canonical scenario descriptor.
    #[must_use]
    pub fn new(workload: SwarmWorkloadKind, agent_count: u32) -> Self {
        let id = format!("{}_{agent_count}", workload.as_str());
        let description = format!(
            "{} swarm scenario with {agent_count} agents",
            workload.as_str()
        );
        Self {
            id,
            workload,
            agent_count,
            description,
        }
    }
}

/// Standard 1k and 10k scenarios for the first swarm-performance harness.
#[must_use]
pub fn standard_swarm_latency_scenarios() -> Vec<SwarmLatencyScenario> {
    let mut scenarios = Vec::with_capacity(SwarmWorkloadKind::ALL.len() * 2);
    for agent_count in [1_000_u32, 10_000] {
        for workload in SwarmWorkloadKind::ALL {
            scenarios.push(SwarmLatencyScenario::new(workload, agent_count));
        }
    }
    scenarios
}

/// Runtime and source fingerprint attached to swarm benchmark artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmRunEnvironment {
    /// Worker identity, typically RCH worker, CI runner, or host name.
    pub worker_id: String,
    /// Logical CPU count visible to the run.
    pub cpu_count: usize,
    /// Total memory in bytes when supplied by the runner.
    pub memory_bytes: Option<u64>,
    /// Cargo target directory used for the run.
    pub cargo_target_dir: Option<String>,
    /// Exact command line that produced the artifact.
    pub command_line: Vec<String>,
    /// Source revision or commit hash when available.
    pub source_revision: Option<String>,
    /// Wall-clock capture time for the environment record.
    pub captured_at: DateTime<Utc>,
}

impl SwarmRunEnvironment {
    /// Capture a redaction-safe environment fingerprint for a swarm run.
    #[must_use]
    pub fn capture(command_line: Vec<String>, source_revision: Option<String>) -> Self {
        let worker_id = std::env::var("RCH_WORKER_ID")
            .or_else(|_| std::env::var("CI_RUNNER_ID"))
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "local".to_string());
        let cpu_count = std::thread::available_parallelism().map_or(1, usize::from);
        let memory_bytes = std::env::var("FCP_SWARM_MEMORY_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok());
        let cargo_target_dir = std::env::var("CARGO_TARGET_DIR").ok();

        Self {
            worker_id,
            cpu_count,
            memory_bytes,
            cargo_target_dir,
            command_line,
            source_revision,
            captured_at: Utc::now(),
        }
    }
}

/// Latency component used to explain tail behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyComponent {
    /// Time spent waiting before service starts.
    Queueing,
    /// Time spent doing the primary operation.
    Service,
    /// Network, mesh, or transport time.
    Network,
    /// Retry and backoff overhead.
    Retry,
    /// Locking, synchronization, or contention overhead.
    Synchronization,
    /// Allocation, allocator, or GC-like transient object overhead.
    Allocation,
}

impl LatencyComponent {
    /// All decomposition components in stable report order.
    pub const ALL: [Self; 6] = [
        Self::Queueing,
        Self::Service,
        Self::Network,
        Self::Retry,
        Self::Synchronization,
        Self::Allocation,
    ];
}

/// Nanosecond latency decomposition for one operation sample.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct LatencyBreakdown {
    /// Queue wait time in nanoseconds.
    pub queueing_ns: u64,
    /// Primary service time in nanoseconds.
    pub service_ns: u64,
    /// Network or mesh time in nanoseconds.
    pub network_ns: u64,
    /// Retry overhead in nanoseconds.
    pub retry_ns: u64,
    /// Synchronization overhead in nanoseconds.
    pub synchronization_ns: u64,
    /// Allocation overhead in nanoseconds.
    pub allocation_ns: u64,
}

impl LatencyBreakdown {
    /// Construct a decomposition with explicit nanosecond components.
    #[must_use]
    pub const fn new(
        queueing_ns: u64,
        service_ns: u64,
        network_ns: u64,
        retry_ns: u64,
        synchronization_ns: u64,
        allocation_ns: u64,
    ) -> Self {
        Self {
            queueing_ns,
            service_ns,
            network_ns,
            retry_ns,
            synchronization_ns,
            allocation_ns,
        }
    }

    /// Total latency represented by the component sum.
    #[must_use]
    pub fn total_ns(self) -> u64 {
        [
            self.queueing_ns,
            self.service_ns,
            self.network_ns,
            self.retry_ns,
            self.synchronization_ns,
            self.allocation_ns,
        ]
        .into_iter()
        .fold(0_u64, u64::saturating_add)
    }

    /// Return one component's nanosecond value.
    #[must_use]
    pub const fn component_ns(self, component: LatencyComponent) -> u64 {
        match component {
            LatencyComponent::Queueing => self.queueing_ns,
            LatencyComponent::Service => self.service_ns,
            LatencyComponent::Network => self.network_ns,
            LatencyComponent::Retry => self.retry_ns,
            LatencyComponent::Synchronization => self.synchronization_ns,
            LatencyComponent::Allocation => self.allocation_ns,
        }
    }
}

/// One raw latency sample from a swarm run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmLatencySample {
    /// Scenario identifier matching [`SwarmLatencyScenario::id`].
    pub scenario_id: String,
    /// Agent or worker identity that produced the operation.
    pub agent_id: String,
    /// Operation identifier inside the run.
    pub operation_id: String,
    /// Monotonic sample index within the scenario.
    pub sample_index: u64,
    /// Decomposed latency components.
    pub breakdown: LatencyBreakdown,
}

impl SwarmLatencySample {
    /// Build one raw sample from an explicit component breakdown.
    #[must_use]
    pub fn new(
        scenario_id: impl Into<String>,
        agent_id: impl Into<String>,
        operation_id: impl Into<String>,
        sample_index: u64,
        breakdown: LatencyBreakdown,
    ) -> Self {
        Self {
            scenario_id: scenario_id.into(),
            agent_id: agent_id.into(),
            operation_id: operation_id.into(),
            sample_index,
            breakdown,
        }
    }

    /// Total sample latency in nanoseconds.
    #[must_use]
    pub fn total_ns(&self) -> u64 {
        self.breakdown.total_ns()
    }
}

/// Nearest-rank latency percentiles in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct LatencyPercentiles {
    /// 50th percentile.
    pub p50_ns: u64,
    /// 95th percentile.
    pub p95_ns: u64,
    /// 99th percentile.
    pub p99_ns: u64,
    /// 99.9th percentile.
    pub p999_ns: u64,
    /// Minimum sample.
    pub min_ns: u64,
    /// Maximum sample.
    pub max_ns: u64,
    /// Integer mean.
    pub mean_ns: u64,
}

impl LatencyPercentiles {
    /// Compute nearest-rank percentiles from nanosecond samples.
    #[must_use]
    pub fn from_nanos<I>(samples: I) -> Option<Self>
    where
        I: IntoIterator<Item = u64>,
    {
        let mut sorted: Vec<u64> = samples.into_iter().collect();
        if sorted.is_empty() {
            return None;
        }
        sorted.sort_unstable();
        let sum = sorted
            .iter()
            .fold(0_u128, |acc, value| acc.saturating_add(u128::from(*value)));
        let mean = sum / sorted.len() as u128;
        let mean_ns = u64::try_from(mean).unwrap_or(u64::MAX);

        Some(Self {
            p50_ns: nearest_rank(&sorted, 500),
            p95_ns: nearest_rank(&sorted, 950),
            p99_ns: nearest_rank(&sorted, 990),
            p999_ns: nearest_rank(&sorted, 999),
            min_ns: sorted[0],
            max_ns: sorted[sorted.len() - 1],
            mean_ns,
        })
    }
}

fn nearest_rank(sorted: &[u64], per_mille: usize) -> u64 {
    let len = sorted.len();
    let rank = len.saturating_mul(per_mille).saturating_add(999) / 1_000;
    let index = rank.saturating_sub(1).min(len - 1);
    sorted[index]
}

/// Per-component percentile decomposition for a scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyDecompositionPercentiles {
    /// Queue wait percentiles.
    pub queueing: LatencyPercentiles,
    /// Service-time percentiles.
    pub service: LatencyPercentiles,
    /// Network or mesh percentiles.
    pub network: LatencyPercentiles,
    /// Retry-overhead percentiles.
    pub retry: LatencyPercentiles,
    /// Synchronization-overhead percentiles.
    pub synchronization: LatencyPercentiles,
    /// Allocation-overhead percentiles.
    pub allocation: LatencyPercentiles,
}

impl LatencyDecompositionPercentiles {
    /// Return the percentile summary for a single component.
    #[must_use]
    pub const fn component(&self, component: LatencyComponent) -> LatencyPercentiles {
        match component {
            LatencyComponent::Queueing => self.queueing,
            LatencyComponent::Service => self.service,
            LatencyComponent::Network => self.network,
            LatencyComponent::Retry => self.retry,
            LatencyComponent::Synchronization => self.synchronization,
            LatencyComponent::Allocation => self.allocation,
        }
    }

    /// Component with the largest p99 contribution.
    #[must_use]
    pub fn dominant_p99_component(&self) -> LatencyComponent {
        LatencyComponent::ALL
            .into_iter()
            .max_by_key(|component| self.component(*component).p99_ns)
            .unwrap_or(LatencyComponent::Queueing)
    }
}

/// Scenario-level swarm latency summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmLatencySummary {
    /// Scenario identifier.
    pub scenario_id: String,
    /// Number of raw samples included.
    pub sample_count: usize,
    /// Total latency percentiles.
    pub total: LatencyPercentiles,
    /// Per-component latency percentiles.
    pub components: LatencyDecompositionPercentiles,
    /// Component with the largest p99 contribution.
    pub dominant_p99_component: LatencyComponent,
}

/// Error raised when building swarm latency evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwarmLatencyError {
    /// A raw sample references a scenario that is not present in the bundle.
    UnknownScenario {
        /// Missing scenario identifier.
        scenario_id: String,
    },
}

impl fmt::Display for SwarmLatencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownScenario { scenario_id } => {
                write!(f, "unknown swarm latency scenario '{scenario_id}'")
            }
        }
    }
}

impl Error for SwarmLatencyError {}

/// Replayable evidence bundle for a swarm latency run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmLatencyEvidenceBundle {
    /// Bundle schema version.
    pub schema_version: String,
    /// Environment fingerprint.
    pub environment: SwarmRunEnvironment,
    /// Scenario descriptors known to this run.
    pub scenarios: Vec<SwarmLatencyScenario>,
    /// Raw operation samples.
    pub samples: Vec<SwarmLatencySample>,
    /// Scenario summaries computed from raw samples.
    pub summaries: Vec<SwarmLatencySummary>,
}

impl SwarmLatencyEvidenceBundle {
    /// Build a replayable bundle from scenarios and raw samples.
    ///
    /// # Errors
    ///
    /// Returns [`SwarmLatencyError::UnknownScenario`] when any sample references
    /// a scenario not declared by the bundle.
    pub fn from_samples(
        environment: SwarmRunEnvironment,
        scenarios: Vec<SwarmLatencyScenario>,
        samples: Vec<SwarmLatencySample>,
    ) -> Result<Self, SwarmLatencyError> {
        let known_scenarios: BTreeSet<&str> = scenarios
            .iter()
            .map(|scenario| scenario.id.as_str())
            .collect();
        for sample in &samples {
            if !known_scenarios.contains(sample.scenario_id.as_str()) {
                return Err(SwarmLatencyError::UnknownScenario {
                    scenario_id: sample.scenario_id.clone(),
                });
            }
        }

        let summaries = summarize_swarm_latency(&scenarios, &samples);
        Ok(Self {
            schema_version: SWARM_LATENCY_BUNDLE_SCHEMA_VERSION.to_string(),
            environment,
            scenarios,
            samples,
            summaries,
        })
    }

    /// Render the bundle as typed JSONL records.
    ///
    /// # Errors
    ///
    /// Returns a serde error if any bundle section cannot be converted to JSON.
    pub fn to_jsonl_values(&self) -> Result<Vec<Value>, serde_json::Error> {
        let mut records = Vec::with_capacity(2 + self.scenarios.len() + self.samples.len());
        records.push(json!({
            "record_type": "swarm_latency_bundle",
            "schema_version": self.schema_version,
            "environment": serde_json::to_value(&self.environment)?,
        }));
        for scenario in &self.scenarios {
            records.push(json!({
                "record_type": "swarm_latency_scenario",
                "scenario": serde_json::to_value(scenario)?,
            }));
        }
        for summary in &self.summaries {
            records.push(json!({
                "record_type": "swarm_latency_summary",
                "summary": serde_json::to_value(summary)?,
            }));
        }
        for sample in &self.samples {
            records.push(json!({
                "record_type": "swarm_latency_sample",
                "sample": serde_json::to_value(sample)?,
            }));
        }
        Ok(records)
    }
}

/// Compute scenario summaries from raw swarm latency samples.
#[must_use]
pub fn summarize_swarm_latency(
    scenarios: &[SwarmLatencyScenario],
    samples: &[SwarmLatencySample],
) -> Vec<SwarmLatencySummary> {
    let mut samples_by_scenario: BTreeMap<&str, Vec<&SwarmLatencySample>> = BTreeMap::new();
    for sample in samples {
        samples_by_scenario
            .entry(sample.scenario_id.as_str())
            .or_default()
            .push(sample);
    }

    scenarios
        .iter()
        .filter_map(|scenario| {
            samples_by_scenario
                .get(scenario.id.as_str())
                .and_then(|scenario_samples| summarize_one_scenario(&scenario.id, scenario_samples))
        })
        .collect()
}

fn summarize_one_scenario(
    scenario_id: &str,
    samples: &[&SwarmLatencySample],
) -> Option<SwarmLatencySummary> {
    let total = LatencyPercentiles::from_nanos(samples.iter().map(|sample| sample.total_ns()))?;
    let components = LatencyDecompositionPercentiles {
        queueing: component_percentiles(samples, LatencyComponent::Queueing)?,
        service: component_percentiles(samples, LatencyComponent::Service)?,
        network: component_percentiles(samples, LatencyComponent::Network)?,
        retry: component_percentiles(samples, LatencyComponent::Retry)?,
        synchronization: component_percentiles(samples, LatencyComponent::Synchronization)?,
        allocation: component_percentiles(samples, LatencyComponent::Allocation)?,
    };
    let dominant_p99_component = components.dominant_p99_component();

    Some(SwarmLatencySummary {
        scenario_id: scenario_id.to_string(),
        sample_count: samples.len(),
        total,
        components,
        dominant_p99_component,
    })
}

fn component_percentiles(
    samples: &[&SwarmLatencySample],
    component: LatencyComponent,
) -> Option<LatencyPercentiles> {
    LatencyPercentiles::from_nanos(
        samples
            .iter()
            .map(|sample| sample.breakdown.component_ns(component)),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Assertions
// ─────────────────────────────────────────────────────────────────────────────

/// Assert that the collector has at least one audit event of the given type.
///
/// # Panics
///
/// Panics if no audit event with the given type is found.
pub fn assert_evidence_has_audit_event(collector: &EvidenceCollector, event_type: &str) {
    assert!(
        collector
            .audit_events
            .iter()
            .any(|e| e.event_type == event_type),
        "expected audit event of type '{event_type}', found types: {:?}",
        collector
            .audit_events
            .iter()
            .map(|e| &e.event_type)
            .collect::<Vec<_>>()
    );
}

/// Assert that the collector has a receipt for the given request ID.
///
/// # Panics
///
/// Panics if no receipt with the given request ID is found.
pub fn assert_evidence_has_receipt(collector: &EvidenceCollector, request_id: &str) {
    assert!(
        collector
            .receipts
            .iter()
            .any(|r| r.request_id == request_id),
        "expected receipt for request '{request_id}', found: {:?}",
        collector
            .receipts
            .iter()
            .map(|r| &r.request_id)
            .collect::<Vec<_>>()
    );
}

/// Assert that all audit events are zone-scoped.
///
/// # Panics
///
/// Panics if any audit event is not zone-scoped.
pub fn assert_evidence_all_zone_scoped(collector: &EvidenceCollector) {
    let unscoped: Vec<&str> = collector
        .audit_events
        .iter()
        .filter(|e| !e.zone_scoped)
        .map(|e| e.event_type.as_str())
        .collect();
    assert!(
        unscoped.is_empty(),
        "expected all audit events to be zone-scoped, but these are not: {unscoped:?}"
    );
}

/// Assert that no evidence artifacts contain secret-like patterns.
///
/// # Panics
///
/// Panics if any secret pattern is found in the serialized evidence.
pub fn assert_evidence_no_secrets(collector: &EvidenceCollector, patterns: &[&str]) {
    let serialized = format!("{collector:?}");
    for pattern in patterns {
        assert!(
            !serialized.contains(pattern),
            "found secret pattern '{pattern}' in evidence artifacts"
        );
    }
}

/// Assert that the collector has at least N total artifacts.
///
/// # Panics
///
/// Panics if the total artifact count is less than expected.
pub fn assert_evidence_minimum_artifacts(collector: &EvidenceCollector, minimum: usize) {
    assert!(
        collector.total_artifacts() >= minimum,
        "expected at least {minimum} artifacts, got {}",
        collector.total_artifacts()
    );
}

/// Assert that all receipts for a given operation succeeded.
///
/// # Panics
///
/// Panics if any receipt for the operation failed.
pub fn assert_all_receipts_succeeded(collector: &EvidenceCollector, operation_id: &str) {
    let failed: Vec<&str> = collector
        .receipts
        .iter()
        .filter(|r| r.operation_id == operation_id && !r.success)
        .map(|r| r.request_id.as_str())
        .collect();
    assert!(
        failed.is_empty(),
        "expected all receipts for '{operation_id}' to succeed, but these failed: {failed:?}"
    );
}

/// Assert idempotency: duplicate receipts with the same key should exist.
///
/// # Panics
///
/// Panics if fewer than `expected_count` receipts share the given idempotency key.
pub fn assert_idempotent_receipts(
    collector: &EvidenceCollector,
    idempotency_key: &str,
    expected_count: usize,
) {
    let matching: Vec<_> = collector
        .receipts
        .iter()
        .filter(|r| r.idempotency_key.as_deref() == Some(idempotency_key))
        .collect();
    assert!(
        matching.len() >= expected_count,
        "expected at least {expected_count} receipts with idempotency key '{idempotency_key}', found {}",
        matching.len()
    );
}

/// Assert that a decision was recorded with the expected outcome.
///
/// # Panics
///
/// Panics if no matching decision is found.
pub fn assert_decision_recorded(
    collector: &EvidenceCollector,
    subject: &str,
    expected_approved: bool,
) {
    let found = collector.decisions.iter().find(|d| d.subject == subject);
    assert!(found.is_some(), "no decision found for subject '{subject}'");
    let decision = found.expect("checked above");
    assert_eq!(
        decision.approved,
        expected_approved,
        "decision for '{subject}' was {}, expected {}",
        if decision.approved {
            "approved"
        } else {
            "denied"
        },
        if expected_approved {
            "approved"
        } else {
            "denied"
        }
    );
}

/// Assert that a seeded resource was recorded.
///
/// # Panics
///
/// Panics if the seeded resource is missing.
pub fn assert_seeded_state_recorded(
    collector: &EvidenceCollector,
    resource: &str,
    identifier: &str,
) {
    assert!(
        collector
            .seeded_state
            .iter()
            .any(|seed| seed.resource == resource && seed.identifier == identifier),
        "expected seeded state for '{resource}/{identifier}', found: {:?}",
        collector
            .seeded_state
            .iter()
            .map(|seed| format!("{}/{}", seed.resource, seed.identifier))
            .collect::<Vec<_>>()
    );
}

/// Assert that a mutation was recorded.
///
/// # Panics
///
/// Panics if the mutation is missing.
pub fn assert_mutation_recorded(
    collector: &EvidenceCollector,
    operation: &str,
    resource: &str,
    identifier: &str,
) {
    assert!(
        collector.mutations.iter().any(|mutation| {
            mutation.operation == operation
                && mutation.resource == resource
                && mutation.identifier == identifier
        }),
        "expected mutation '{operation}' for '{resource}/{identifier}', found: {:?}",
        collector
            .mutations
            .iter()
            .map(|mutation| format!(
                "{}:{}/{}",
                mutation.operation, mutation.resource, mutation.identifier
            ))
            .collect::<Vec<_>>()
    );
}

/// Assert that all cleanup verifications passed.
///
/// # Panics
///
/// Panics if any cleanup verification failed.
pub fn assert_cleanup_verifications_passed(collector: &EvidenceCollector) {
    let failed: Vec<&str> = collector
        .cleanup_verifications
        .iter()
        .filter(|verification| !verification.passed)
        .map(|verification| verification.check_id.as_str())
        .collect();
    assert!(
        failed.is_empty(),
        "expected cleanup verification to pass, but these checks failed: {failed:?}"
    );
}

/// Assert that every mutation has at least one cleanup verification for the same resource.
///
/// # Panics
///
/// Panics if any mutation lacks teardown verification.
pub fn assert_mutations_have_cleanup_verifications(collector: &EvidenceCollector) {
    let missing: Vec<String> = collector
        .mutations
        .iter()
        .filter(|mutation| {
            !collector
                .cleanup_verifications
                .iter()
                .any(|verification| verification.resource == mutation.resource)
        })
        .map(|mutation| format!("{}/{}", mutation.resource, mutation.identifier))
        .collect();
    assert!(
        missing.is_empty(),
        "expected cleanup verification for every mutation, missing: {missing:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live_suite::{EnvironmentManifest, LiveEnvironment};

    #[test]
    fn collector_empty_by_default() {
        let collector = EvidenceCollector::new();
        assert!(collector.is_empty());
        assert_eq!(collector.total_artifacts(), 0);
    }

    #[test]
    fn collector_records_audit_events() {
        let mut collector = EvidenceCollector::new();
        collector.record_audit_event("invoke", "gmail.search", json!({"zone": "z:private"}));
        assert_eq!(collector.audit_events.len(), 1);
        assert_eq!(collector.total_artifacts(), 1);
        assert!(!collector.is_empty());
    }

    #[test]
    fn collector_records_receipts() {
        let mut collector = EvidenceCollector::new();
        collector.record_receipt("req_1", "op_1", true);
        collector.record_receipt("req_2", "op_1", false);
        assert_eq!(collector.receipts.len(), 2);
    }

    #[test]
    fn collector_records_receipts_with_key() {
        let mut collector = EvidenceCollector::new();
        collector.record_receipt_with_key("req_1", "op_1", true, "idem_123");
        assert_eq!(
            collector.receipts[0].idempotency_key.as_deref(),
            Some("idem_123")
        );
    }

    #[test]
    fn collector_records_decisions() {
        let mut collector = EvidenceCollector::new();
        collector.record_decision("risky_op", true, "approved by user");
        assert_eq!(collector.decisions.len(), 1);
        assert!(collector.decisions[0].approved);
    }

    #[test]
    fn collector_to_json() {
        let mut collector = EvidenceCollector::new();
        collector.record_audit_event("invoke", "op_1", json!({}));
        collector.record_receipt("r1", "op_1", true);
        let j = collector.to_json();
        assert_eq!(j["audit_events"], 1);
        assert_eq!(j["receipts"], 1);
        assert_eq!(j["total_artifacts"], 2);
    }

    #[test]
    fn render_live_environment_json_includes_contract_fields() {
        let manifest = EnvironmentManifest::sandbox("stripe", "Stripe")
            .with_account_setup("Use a dedicated Stripe test-mode account")
            .with_budget(1.0)
            .with_env_var_default("FCP_TESTKIT_REGION", "us-east-1", "Default region");
        let environment = LiveEnvironment::from_manifest(manifest);

        let snapshot = render_live_environment_json(&environment, "live", "dry_run_only");

        assert_eq!(snapshot["suite_class"], "live");
        assert_eq!(snapshot["connector"], "stripe");
        assert_eq!(snapshot["provider"], "Stripe");
        assert_eq!(snapshot["live_tier"], "sandbox_required");
        assert_eq!(snapshot["gate_env_var"], "FCP_LIVE_SANDBOX");
        assert_eq!(snapshot["mutation_mode"], "dry_run_only");
        assert!(snapshot["live_environment"].is_object());
    }

    #[test]
    fn render_live_environment_json_does_not_leak_default_values() {
        let manifest = EnvironmentManifest::sandbox("stripe", "Stripe")
            .with_test_default_secret(
                "mode",
                "FCP_TESTKIT_UNUSED_LIVE_SECRET",
                "danger-secret",
                "Test mode secret",
            )
            .with_env_var_default("FCP_TESTKIT_REGION", "eu-west-1", "Default region")
            .with_account_setup("Use a dedicated Stripe test-mode account")
            .with_budget(1.0);
        let environment = LiveEnvironment::from_manifest(manifest);

        let snapshot = render_live_environment_json(&environment, "live", "denial");
        let serialized = serde_json::to_string(&snapshot).expect("snapshot should serialize");

        assert!(!serialized.contains("danger-secret"));
        assert!(!serialized.contains("eu-west-1"));
        assert_eq!(snapshot["mutation_mode"], "denial");
    }

    #[test]
    fn standard_swarm_latency_scenarios_cover_required_workloads() {
        let scenarios = standard_swarm_latency_scenarios();

        assert_eq!(scenarios.len(), 8);
        for agent_count in [1_000_u32, 10_000] {
            for workload in SwarmWorkloadKind::ALL {
                let expected_id = format!("{}_{agent_count}", workload.as_str());
                assert!(
                    scenarios.iter().any(|scenario| scenario.id == expected_id
                        && scenario.workload == workload
                        && scenario.agent_count == agent_count),
                    "missing scenario {expected_id}"
                );
            }
        }
    }

    #[test]
    fn latency_percentiles_use_nearest_rank_tail_math() -> Result<(), &'static str> {
        let stats = LatencyPercentiles::from_nanos(1_u64..=1_000)
            .ok_or("non-empty sample set must have percentiles")?;

        assert_eq!(stats.p50_ns, 500);
        assert_eq!(stats.p95_ns, 950);
        assert_eq!(stats.p99_ns, 990);
        assert_eq!(stats.p999_ns, 999);
        assert_eq!(stats.min_ns, 1);
        assert_eq!(stats.max_ns, 1_000);
        assert_eq!(stats.mean_ns, 500);
        Ok(())
    }

    #[test]
    fn swarm_latency_summary_identifies_dominant_tail_component() {
        let scenario = SwarmLatencyScenario::new(SwarmWorkloadKind::HostBatchInvoke, 1_000);
        let samples: Vec<_> = (0_u64..100)
            .map(|sample_index| {
                let queueing_ns = if sample_index >= 95 { 10_000 } else { 100 };
                SwarmLatencySample::new(
                    scenario.id.clone(),
                    format!("agent-{sample_index}"),
                    format!("op-{sample_index}"),
                    sample_index,
                    LatencyBreakdown::new(queueing_ns, 200, 10, 0, 50, 25),
                )
            })
            .collect();

        let summaries = summarize_swarm_latency(std::slice::from_ref(&scenario), &samples);

        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].sample_count, 100);
        assert_eq!(
            summaries[0].dominant_p99_component,
            LatencyComponent::Queueing
        );
        assert_eq!(summaries[0].components.queueing.p99_ns, 10_000);
    }

    #[test]
    fn swarm_latency_bundle_rejects_unknown_sample_scenario() -> Result<(), &'static str> {
        let environment = SwarmRunEnvironment {
            worker_id: "worker-1".to_string(),
            cpu_count: 64,
            memory_bytes: Some(256 * 1024 * 1024 * 1024),
            cargo_target_dir: Some("/tmp/fcp-swarm-target".to_string()),
            command_line: vec!["cargo".to_string(), "test".to_string()],
            source_revision: Some("abc123".to_string()),
            captured_at: Utc::now(),
        };
        let sample = SwarmLatencySample::new(
            "missing-scenario",
            "agent-1",
            "op-1",
            0,
            LatencyBreakdown::new(1, 2, 3, 4, 5, 6),
        );

        let err = match SwarmLatencyEvidenceBundle::from_samples(
            environment,
            standard_swarm_latency_scenarios(),
            vec![sample],
        ) {
            Ok(_) => return Err("unknown sample scenario must fail closed"),
            Err(err) => err,
        };

        assert_eq!(
            err,
            SwarmLatencyError::UnknownScenario {
                scenario_id: "missing-scenario".to_string()
            }
        );
        Ok(())
    }

    #[test]
    fn swarm_latency_bundle_emits_replayable_jsonl_records() -> Result<(), Box<dyn Error>> {
        let scenario = SwarmLatencyScenario::new(SwarmWorkloadKind::AuditEvidenceRecording, 10_000);
        let environment = SwarmRunEnvironment {
            worker_id: "worker-64c".to_string(),
            cpu_count: 64,
            memory_bytes: Some(256 * 1024 * 1024 * 1024),
            cargo_target_dir: Some("/tmp/fcp-swarm-target".to_string()),
            command_line: vec![
                "rch".to_string(),
                "exec".to_string(),
                "--".to_string(),
                "cargo".to_string(),
                "test".to_string(),
            ],
            source_revision: Some("abc123".to_string()),
            captured_at: Utc::now(),
        };
        let samples = vec![
            SwarmLatencySample::new(
                scenario.id.clone(),
                "agent-1",
                "op-1",
                0,
                LatencyBreakdown::new(100, 200, 50, 0, 75, 25),
            ),
            SwarmLatencySample::new(
                scenario.id.clone(),
                "agent-2",
                "op-2",
                1,
                LatencyBreakdown::new(300, 250, 50, 10, 100, 40),
            ),
        ];
        let bundle =
            SwarmLatencyEvidenceBundle::from_samples(environment, vec![scenario], samples)?;

        let records = bundle.to_jsonl_values()?;
        let record_types: Vec<_> = records
            .iter()
            .filter_map(|record| record["record_type"].as_str())
            .collect();
        let bundle_json = serde_json::to_value(&bundle)?;
        let roundtrip: SwarmLatencyEvidenceBundle = serde_json::from_value(bundle_json)?;

        assert_eq!(roundtrip, bundle);
        assert!(record_types.contains(&"swarm_latency_bundle"));
        assert!(record_types.contains(&"swarm_latency_scenario"));
        assert!(record_types.contains(&"swarm_latency_summary"));
        assert_eq!(
            record_types
                .iter()
                .filter(|record_type| **record_type == "swarm_latency_sample")
                .count(),
            2
        );
        assert_eq!(bundle.summaries[0].total.p99_ns, 750);
        Ok(())
    }

    #[test]
    fn assert_audit_event_found() {
        let mut collector = EvidenceCollector::new();
        collector.record_audit_event("invoke", "gmail.search", json!({}));
        assert_evidence_has_audit_event(&collector, "invoke");
    }

    #[test]
    #[should_panic(expected = "expected audit event of type")]
    fn assert_audit_event_missing() {
        let collector = EvidenceCollector::new();
        assert_evidence_has_audit_event(&collector, "invoke");
    }

    #[test]
    fn assert_receipt_found() {
        let mut collector = EvidenceCollector::new();
        collector.record_receipt("req_42", "op_1", true);
        assert_evidence_has_receipt(&collector, "req_42");
    }

    #[test]
    fn assert_zone_scoped_passes() {
        let mut collector = EvidenceCollector::new();
        collector.record_audit_event("invoke", "op_1", json!({}));
        assert_evidence_all_zone_scoped(&collector);
    }

    #[test]
    #[should_panic(expected = "zone-scoped")]
    fn assert_zone_scoped_fails() {
        let mut collector = EvidenceCollector::new();
        collector.record_unscoped_audit_event("invoke", "op_1", json!({}));
        assert_evidence_all_zone_scoped(&collector);
    }

    #[test]
    fn assert_no_secrets_passes() {
        let mut collector = EvidenceCollector::new();
        collector.record_audit_event("invoke", "op_1", json!({"zone": "z:work"}));
        assert_evidence_no_secrets(&collector, &["sk-test-", "Bearer "]);
    }

    #[test]
    fn assert_minimum_artifacts() {
        let mut collector = EvidenceCollector::new();
        collector.record_audit_event("invoke", "op_1", json!({}));
        collector.record_receipt("r1", "op_1", true);
        assert_evidence_minimum_artifacts(&collector, 2);
    }

    #[test]
    fn assert_all_receipts_succeeded_passes() {
        let mut collector = EvidenceCollector::new();
        collector.record_receipt("r1", "op_1", true);
        collector.record_receipt("r2", "op_1", true);
        assert_all_receipts_succeeded(&collector, "op_1");
    }

    #[test]
    #[should_panic(expected = "these failed")]
    fn assert_all_receipts_succeeded_fails() {
        let mut collector = EvidenceCollector::new();
        collector.record_receipt("r1", "op_1", true);
        collector.record_receipt("r2", "op_1", false);
        assert_all_receipts_succeeded(&collector, "op_1");
    }

    #[test]
    fn assert_idempotent_receipts_passes() {
        let mut collector = EvidenceCollector::new();
        collector.record_receipt_with_key("r1", "op_1", true, "key_a");
        collector.record_receipt_with_key("r2", "op_1", true, "key_a");
        assert_idempotent_receipts(&collector, "key_a", 2);
    }

    #[test]
    fn assert_decision_recorded_passes() {
        let mut collector = EvidenceCollector::new();
        collector.record_decision("delete_account", false, "too dangerous");
        assert_decision_recorded(&collector, "delete_account", false);
    }

    #[test]
    #[should_panic(expected = "no decision found")]
    fn assert_decision_recorded_missing() {
        let collector = EvidenceCollector::new();
        assert_decision_recorded(&collector, "nonexistent", true);
    }

    #[test]
    fn unscoped_audit_event() {
        let mut collector = EvidenceCollector::new();
        collector.record_unscoped_audit_event("health", "system", json!({}));
        assert!(!collector.audit_events[0].zone_scoped);
    }

    #[test]
    fn log_lines_recorded() {
        let mut collector = EvidenceCollector::new();
        collector.record_log_line(json!({"level": "info", "msg": "test"}));
        assert_eq!(collector.log_lines.len(), 1);
    }

    #[test]
    fn collector_records_seeded_state_and_mutations() {
        let mut collector = EvidenceCollector::new();
        collector.record_seeded_state("users", "user-1", json!({"id": 1}));
        collector.record_mutation(
            FixtureMutationRecord::new(
                "update",
                "users",
                "user-1",
                "connector updates the seeded user row",
            )
            .with_after(json!({"id": 1, "name": "Alice Updated"})),
        );
        collector.record_cleanup_verification(
            "cleanup-users",
            "users",
            "query_row_digest",
            "seed digest matches the original payload",
            json!({"digest_match": true}),
            true,
        );

        assert_eq!(collector.seeded_state.len(), 1);
        assert_eq!(collector.mutations.len(), 1);
        assert_eq!(collector.cleanup_verifications.len(), 1);
        assert_seeded_state_recorded(&collector, "users", "user-1");
        assert_mutation_recorded(&collector, "update", "users", "user-1");
        assert_cleanup_verifications_passed(&collector);
        assert_mutations_have_cleanup_verifications(&collector);
    }

    #[test]
    #[should_panic(expected = "cleanup verification to pass")]
    fn cleanup_verifications_fail_when_any_check_fails() {
        let mut collector = EvidenceCollector::new();
        collector.record_cleanup_verification(
            "cleanup-temp-objects",
            "objects",
            "prefix_empty",
            "temporary objects are removed",
            json!({"remaining_keys": ["tmp/run-1.json"]}),
            false,
        );

        assert_cleanup_verifications_passed(&collector);
    }

    #[test]
    #[should_panic(expected = "missing")]
    fn mutations_require_cleanup_verification() {
        let mut collector = EvidenceCollector::new();
        collector.record_mutation(FixtureMutationRecord::new(
            "put",
            "objects",
            "tmp/run-1.json",
            "connector uploads a temporary object",
        ));

        assert_mutations_have_cleanup_verifications(&collector);
    }
}
