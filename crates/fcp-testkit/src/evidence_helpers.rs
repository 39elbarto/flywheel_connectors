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

/// Schema tag for replayable swarm performance artifact manifests.
pub const SWARM_EVIDENCE_BUNDLE_SCHEMA_VERSION: &str = "swarm-evidence-bundle/v1";

/// Schema tag for CI/nightly swarm performance regression gates.
pub const SWARM_REGRESSION_GATE_SCHEMA_VERSION: &str = "swarm-regression-gate/v1";

/// Schema tag for statistically-qualified swarm performance gate reports.
pub const SWARM_STATISTICAL_GATE_SCHEMA_VERSION: &str = "swarm-statistical-gate/v1";

/// Schema tag for retained swarm baseline promotion manifests.
pub const SWARM_BASELINE_PROMOTION_SCHEMA_VERSION: &str = "swarm-baseline-promotion/v1";

/// Schema tag for the integrated massive-swarm proof gauntlet.
pub const SWARM_GAUNTLET_SCHEMA_VERSION: &str = "swarm-gauntlet/v1";

/// Schema tag for one structured gauntlet log record.
pub const SWARM_GAUNTLET_LOG_SCHEMA_VERSION: &str = "swarm-gauntlet-log/v1";

/// Schema tag expected for per-operation resource ledger records.
pub const SWARM_RESOURCE_LEDGER_SCHEMA_VERSION: &str = "resource-ledger/v1";

/// Schema tag for 64-core/256GiB promotion qualification records.
pub const SWARM_PROMOTION_SCHEMA_VERSION: &str = "swarm-promotion/v1";

/// Schema tag for batch-invoke morselization evidence records.
pub const SWARM_BATCH_MORSELIZATION_SCHEMA_VERSION: &str = "swarm-batch-morselization/v1";

/// Schema tag for connector prewarm cold-start evidence records.
pub const SWARM_PREWARM_COLD_START_SCHEMA_VERSION: &str = "swarm-prewarm-cold-start/v2";

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
    /// Physical CPU core count when supplied by the runner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_cpu_count: Option<usize>,
    /// NUMA node count when supplied by the runner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub numa_node_count: Option<usize>,
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
        let physical_cpu_count = parse_env_usize("FCP_SWARM_PHYSICAL_CPU_COUNT");
        let numa_node_count = parse_env_usize("FCP_SWARM_NUMA_NODE_COUNT");
        let memory_bytes = parse_env_u64("FCP_SWARM_MEMORY_BYTES");
        let cargo_target_dir = std::env::var("CARGO_TARGET_DIR").ok();

        Self {
            worker_id,
            cpu_count,
            physical_cpu_count,
            numa_node_count,
            memory_bytes,
            cargo_target_dir,
            command_line,
            source_revision,
            captured_at: Utc::now(),
        }
    }
}

fn parse_env_usize(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
}

fn parse_env_u64(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
}

/// Source class for a replayable swarm evidence bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmEvidenceSourceKind {
    /// Fully synthetic or fixture-backed run; no live service dependency.
    Offline,
    /// Run executed against an RCH worker, CI host, or controlled benchmark host.
    HostBacked,
    /// Run depended on live services or production-like endpoints.
    Live,
}

impl SwarmEvidenceSourceKind {
    /// Stable machine label for this source class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::HostBacked => "host_backed",
            Self::Live => "live",
        }
    }

    /// Whether the source class can be replayed without live services.
    #[must_use]
    pub const fn replayable_offline(self) -> bool {
        matches!(self, Self::Offline | Self::HostBacked)
    }
}

/// Evidence mode used by CI and nightly swarm runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmEvidenceExecutionMode {
    /// Bounded, PR-friendly smoke run.
    Smoke,
    /// Longer soak or promotion run for retained baselines.
    Soak,
}

impl SwarmEvidenceExecutionMode {
    /// Stable machine label for this execution mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Soak => "soak",
        }
    }
}

/// Required artifact files for replayable swarm performance claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmEvidenceArtifactKind {
    /// Environment fingerprint.
    EnvJson,
    /// Artifact manifest with content hashes.
    ManifestJson,
    /// Raw per-operation samples.
    RawSamplesJsonl,
    /// Scenario summaries.
    SummaryJson,
    /// Command log with redacted invocations.
    CommandLogTxt,
    /// Git/source revision record.
    GitRevision,
    /// RCH worker or controlled-runner identity.
    RchWorkerInfo,
    /// Proof and isomorphism notes.
    ProofNotes,
}

impl SwarmEvidenceArtifactKind {
    /// Required artifact kinds in stable manifest order.
    pub const REQUIRED: [Self; 8] = [
        Self::EnvJson,
        Self::ManifestJson,
        Self::RawSamplesJsonl,
        Self::SummaryJson,
        Self::CommandLogTxt,
        Self::GitRevision,
        Self::RchWorkerInfo,
        Self::ProofNotes,
    ];

    /// Stable machine label for this artifact kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EnvJson => "env_json",
            Self::ManifestJson => "manifest_json",
            Self::RawSamplesJsonl => "raw_samples_jsonl",
            Self::SummaryJson => "summary_json",
            Self::CommandLogTxt => "command_log_txt",
            Self::GitRevision => "git_revision",
            Self::RchWorkerInfo => "rch_worker_info",
            Self::ProofNotes => "proof_notes",
        }
    }

    /// Canonical artifact path inside a bundle directory.
    #[must_use]
    pub const fn default_path(self) -> &'static str {
        match self {
            Self::EnvJson => "env.json",
            Self::ManifestJson => "manifest.json",
            Self::RawSamplesJsonl => "raw_samples.jsonl",
            Self::SummaryJson => "summary.json",
            Self::CommandLogTxt => "command_log.txt",
            Self::GitRevision => "git_revision.txt",
            Self::RchWorkerInfo => "rch_worker_info.json",
            Self::ProofNotes => "proof_notes.md",
        }
    }
}

/// One content-addressed artifact entry in a swarm evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmEvidenceArtifact {
    /// Artifact role.
    pub kind: SwarmEvidenceArtifactKind,
    /// Path relative to the bundle root.
    pub path: String,
    /// Content digest, typically `blake3:<hex>` or `sha256:<hex>`.
    pub digest: String,
    /// Whether artifact content was redacted before export.
    pub redacted: bool,
}

impl SwarmEvidenceArtifact {
    /// Build an artifact entry at the canonical path for its kind.
    #[must_use]
    pub fn new(kind: SwarmEvidenceArtifactKind, digest: impl Into<String>, redacted: bool) -> Self {
        Self {
            kind,
            path: kind.default_path().to_string(),
            digest: digest.into(),
            redacted,
        }
    }

    /// Build an artifact entry with an explicit relative path.
    #[must_use]
    pub fn with_path(
        kind: SwarmEvidenceArtifactKind,
        path: impl Into<String>,
        digest: impl Into<String>,
        redacted: bool,
    ) -> Self {
        Self {
            kind,
            path: path.into(),
            digest: digest.into(),
            redacted,
        }
    }
}

/// Redaction policy recorded with swarm performance artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmEvidenceRedactionPolicy {
    /// Environment variables and host details were redacted as needed.
    pub environment_redacted: bool,
    /// Command logs were redacted as needed.
    pub command_log_redacted: bool,
    /// Proof notes were checked for secrets/PII.
    pub proof_notes_checked: bool,
    /// Case-insensitive substrings treated as sensitive.
    pub sensitive_patterns: Vec<String>,
}

impl SwarmEvidenceRedactionPolicy {
    /// Conservative default for artifacts that may leave the local host.
    #[must_use]
    pub fn conservative() -> Self {
        Self {
            environment_redacted: true,
            command_log_redacted: true,
            proof_notes_checked: true,
            sensitive_patterns: [
                "authorization",
                "bearer ",
                "password",
                "secret",
                "token",
                "api_key",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
        }
    }

    /// Whether the policy is sufficient for host-backed or live evidence.
    #[must_use]
    pub fn protects_exported_artifacts(&self) -> bool {
        self.environment_redacted
            && self.command_log_redacted
            && self.proof_notes_checked
            && !self.sensitive_patterns.is_empty()
    }
}

/// Replayable artifact manifest for a swarm performance evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmEvidenceArtifactManifest {
    /// Manifest schema version.
    pub schema_version: String,
    /// Stable bundle identifier.
    pub bundle_id: String,
    /// Source class for the run.
    pub source_kind: SwarmEvidenceSourceKind,
    /// Smoke vs soak evidence mode.
    pub execution_mode: SwarmEvidenceExecutionMode,
    /// Source revision that produced the artifacts.
    pub source_revision: String,
    /// Worker identity that produced the artifacts.
    pub rch_worker_id: String,
    /// Content-addressed artifacts.
    pub artifacts: Vec<SwarmEvidenceArtifact>,
    /// Redaction policy applied before export.
    pub redaction_policy: SwarmEvidenceRedactionPolicy,
    /// Manifest creation time.
    pub generated_at: DateTime<Utc>,
}

impl SwarmEvidenceArtifactManifest {
    /// Build and validate a manifest from a captured run environment.
    ///
    /// # Errors
    ///
    /// Returns an error when required environment fields or artifacts are missing.
    pub fn from_environment(
        bundle_id: impl Into<String>,
        source_kind: SwarmEvidenceSourceKind,
        execution_mode: SwarmEvidenceExecutionMode,
        environment: &SwarmRunEnvironment,
        artifacts: Vec<SwarmEvidenceArtifact>,
        redaction_policy: SwarmEvidenceRedactionPolicy,
    ) -> Result<Self, SwarmEvidenceBundleError> {
        let source_revision = environment
            .source_revision
            .clone()
            .filter(|revision| !revision.trim().is_empty())
            .ok_or(SwarmEvidenceBundleError::MissingSourceRevision)?;

        let manifest = Self {
            schema_version: SWARM_EVIDENCE_BUNDLE_SCHEMA_VERSION.to_string(),
            bundle_id: bundle_id.into(),
            source_kind,
            execution_mode,
            source_revision,
            rch_worker_id: environment.worker_id.clone(),
            artifacts,
            redaction_policy,
            generated_at: Utc::now(),
        };
        manifest.validate_against_environment(environment)?;
        Ok(manifest)
    }

    /// Validate manifest completeness and freshness against the run environment.
    ///
    /// # Errors
    ///
    /// Returns a machine-readable error for missing, duplicate, stale, or unsafe fields.
    pub fn validate_against_environment(
        &self,
        environment: &SwarmRunEnvironment,
    ) -> Result<(), SwarmEvidenceBundleError> {
        if self.schema_version != SWARM_EVIDENCE_BUNDLE_SCHEMA_VERSION {
            return Err(SwarmEvidenceBundleError::SchemaMismatch {
                expected: SWARM_EVIDENCE_BUNDLE_SCHEMA_VERSION.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        if self.rch_worker_id.trim().is_empty() {
            return Err(SwarmEvidenceBundleError::MissingRchWorkerInfo);
        }
        if self.source_revision.trim().is_empty() {
            return Err(SwarmEvidenceBundleError::MissingSourceRevision);
        }
        let environment_revision = environment
            .source_revision
            .as_deref()
            .filter(|revision| !revision.trim().is_empty())
            .ok_or(SwarmEvidenceBundleError::MissingSourceRevision)?;
        if environment_revision != self.source_revision {
            return Err(SwarmEvidenceBundleError::StaleSourceRevision {
                expected: environment_revision.to_string(),
                actual: self.source_revision.clone(),
            });
        }
        if environment.worker_id != self.rch_worker_id {
            return Err(SwarmEvidenceBundleError::StaleWorkerInfo {
                expected: environment.worker_id.clone(),
                actual: self.rch_worker_id.clone(),
            });
        }
        if self.source_kind != SwarmEvidenceSourceKind::Offline
            && !self.redaction_policy.protects_exported_artifacts()
        {
            return Err(SwarmEvidenceBundleError::RedactionPolicyIncomplete);
        }
        validate_swarm_artifacts(&self.artifacts)
    }

    /// Whether this manifest can support offline replay.
    #[must_use]
    pub const fn replayable_offline(&self) -> bool {
        self.source_kind.replayable_offline()
    }

    /// Render the manifest as a typed JSONL record.
    ///
    /// # Errors
    ///
    /// Returns a serde error if the manifest cannot be converted to JSON.
    pub fn to_jsonl_value(&self) -> Result<Value, serde_json::Error> {
        Ok(json!({
            "record_type": "swarm_evidence_artifact_manifest",
            "schema_version": self.schema_version,
            "manifest": serde_json::to_value(self)?,
        }))
    }
}

fn validate_swarm_artifacts(
    artifacts: &[SwarmEvidenceArtifact],
) -> Result<(), SwarmEvidenceBundleError> {
    let mut seen = BTreeSet::new();
    for artifact in artifacts {
        if !seen.insert(artifact.kind) {
            return Err(SwarmEvidenceBundleError::DuplicateArtifact {
                kind: artifact.kind,
            });
        }
        if artifact.path.trim().is_empty() {
            return Err(SwarmEvidenceBundleError::EmptyArtifactPath {
                kind: artifact.kind,
            });
        }
        if artifact.digest.trim().is_empty() {
            return Err(SwarmEvidenceBundleError::EmptyArtifactDigest {
                kind: artifact.kind,
            });
        }
    }
    for kind in SwarmEvidenceArtifactKind::REQUIRED {
        if !seen.contains(&kind) {
            return Err(SwarmEvidenceBundleError::MissingArtifact { kind });
        }
    }
    Ok(())
}

/// Error raised when validating replayable swarm evidence artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwarmEvidenceBundleError {
    /// A required artifact entry was absent.
    MissingArtifact {
        /// Missing artifact kind.
        kind: SwarmEvidenceArtifactKind,
    },
    /// An artifact kind appeared more than once.
    DuplicateArtifact {
        /// Duplicate artifact kind.
        kind: SwarmEvidenceArtifactKind,
    },
    /// An artifact path was empty.
    EmptyArtifactPath {
        /// Artifact kind with the empty path.
        kind: SwarmEvidenceArtifactKind,
    },
    /// An artifact digest was empty.
    EmptyArtifactDigest {
        /// Artifact kind with the empty digest.
        kind: SwarmEvidenceArtifactKind,
    },
    /// Source revision was required but absent from the environment.
    MissingSourceRevision,
    /// Worker information was required but absent.
    MissingRchWorkerInfo,
    /// Manifest schema did not match the supported version.
    SchemaMismatch {
        /// Supported schema.
        expected: String,
        /// Observed schema.
        actual: String,
    },
    /// Manifest source revision disagreed with the environment.
    StaleSourceRevision {
        /// Environment source revision.
        expected: String,
        /// Manifest source revision.
        actual: String,
    },
    /// Manifest worker disagreed with the environment.
    StaleWorkerInfo {
        /// Environment worker identity.
        expected: String,
        /// Manifest worker identity.
        actual: String,
    },
    /// Host-backed or live artifacts lacked an export-safe redaction policy.
    RedactionPolicyIncomplete,
}

impl fmt::Display for SwarmEvidenceBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingArtifact { kind } => {
                write!(f, "missing swarm evidence artifact '{}'", kind.as_str())
            }
            Self::DuplicateArtifact { kind } => {
                write!(f, "duplicate swarm evidence artifact '{}'", kind.as_str())
            }
            Self::EmptyArtifactPath { kind } => {
                write!(
                    f,
                    "empty path for swarm evidence artifact '{}'",
                    kind.as_str()
                )
            }
            Self::EmptyArtifactDigest { kind } => {
                write!(
                    f,
                    "empty digest for swarm evidence artifact '{}'",
                    kind.as_str()
                )
            }
            Self::MissingSourceRevision => write!(f, "missing swarm evidence source revision"),
            Self::MissingRchWorkerInfo => write!(f, "missing swarm evidence worker identity"),
            Self::SchemaMismatch { expected, actual } => {
                write!(
                    f,
                    "swarm evidence schema mismatch: expected '{expected}', got '{actual}'"
                )
            }
            Self::StaleSourceRevision { expected, actual } => {
                write!(
                    f,
                    "stale swarm evidence source revision: expected '{expected}', got '{actual}'"
                )
            }
            Self::StaleWorkerInfo { expected, actual } => {
                write!(
                    f,
                    "stale swarm evidence worker identity: expected '{expected}', got '{actual}'"
                )
            }
            Self::RedactionPolicyIncomplete => {
                write!(f, "swarm evidence redaction policy is incomplete")
            }
        }
    }
}

impl Error for SwarmEvidenceBundleError {}

// ─────────────────────────────────────────────────────────────────────────────
// Integrated swarm gauntlet
// ─────────────────────────────────────────────────────────────────────────────

/// Surface that must be exercised by an integrated swarm gauntlet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmGauntletPhase {
    /// Operator path through the canonical CLI.
    Fwc,
    /// Host orchestration and invoke path.
    Host,
    /// Mesh control plane, placement, or routing surface.
    Mesh,
    /// Connector or testkit fixture surface.
    ConnectorTestkit,
    /// Host scheduler decision records.
    Scheduler,
    /// Resource-pool or topology placement decisions.
    Placement,
    /// Admission, delay, shed, or fallback backpressure decisions.
    Backpressure,
    /// Audit append or event combiner behavior.
    Audit,
    /// Store/cache/allocation behavior under high-K metadata pressure.
    Store,
    /// Replayable evidence bundle emission.
    EvidenceBundle,
}

impl SwarmGauntletPhase {
    /// Every phase required by the second-generation proof gauntlet.
    pub const REQUIRED: [Self; 10] = [
        Self::Fwc,
        Self::Host,
        Self::Mesh,
        Self::ConnectorTestkit,
        Self::Scheduler,
        Self::Placement,
        Self::Backpressure,
        Self::Audit,
        Self::Store,
        Self::EvidenceBundle,
    ];

    /// Stable machine label for the phase.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fwc => "fwc",
            Self::Host => "host",
            Self::Mesh => "mesh",
            Self::ConnectorTestkit => "connector_testkit",
            Self::Scheduler => "scheduler",
            Self::Placement => "placement",
            Self::Backpressure => "backpressure",
            Self::Audit => "audit",
            Self::Store => "store",
            Self::EvidenceBundle => "evidence_bundle",
        }
    }
}

/// One prerequisite for a smoke, soak, or promotion gauntlet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmGauntletPrerequisite {
    /// Stable prerequisite name.
    pub name: String,
    /// Whether this prerequisite was satisfied for the current run.
    pub satisfied: bool,
    /// Operator-readable detail or remediation.
    pub detail: String,
}

impl SwarmGauntletPrerequisite {
    /// Build a prerequisite record.
    #[must_use]
    pub fn new(name: impl Into<String>, satisfied: bool, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            satisfied,
            detail: detail.into(),
        }
    }
}

/// Controller mode that must be compared during hardware promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmPromotionControllerMode {
    /// Baseline placement and invoke behavior.
    DefaultPlacement,
    /// Resource-pool and NUMA-aware placement only.
    PoolAwarePlacement,
    /// Adaptive scheduler only.
    SchedulerOnly,
    /// Backpressure controller only.
    BackpressureOnly,
    /// Scheduler, placement, and backpressure enabled together.
    CombinedController,
}

impl SwarmPromotionControllerMode {
    /// Every controller mode needed before promotion.
    pub const REQUIRED: [Self; 5] = [
        Self::DefaultPlacement,
        Self::PoolAwarePlacement,
        Self::SchedulerOnly,
        Self::BackpressureOnly,
        Self::CombinedController,
    ];

    /// Stable machine label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DefaultPlacement => "default_placement",
            Self::PoolAwarePlacement => "pool_aware_placement",
            Self::SchedulerOnly => "scheduler_only",
            Self::BackpressureOnly => "backpressure_only",
            Self::CombinedController => "combined_controller",
        }
    }
}

/// Minimum hardware envelope for promoting massive-swarm defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPromotionEnvelope {
    /// Envelope schema version.
    pub schema_version: String,
    /// Scenario being promoted.
    pub scenario_id: String,
    /// Minimum logical CPU count.
    pub min_logical_cpus: u32,
    /// Minimum memory in bytes.
    pub min_memory_bytes: u64,
    /// Required controller comparisons.
    pub required_controller_modes: Vec<SwarmPromotionControllerMode>,
    /// Exact command to rerun on qualifying hardware.
    pub rerun_command: Vec<String>,
}

impl SwarmPromotionEnvelope {
    /// Build the canonical 64-core/256GiB promotion envelope.
    #[must_use]
    pub fn high_core_256gib(rerun_command: Vec<String>) -> Self {
        Self {
            schema_version: SWARM_PROMOTION_SCHEMA_VERSION.to_string(),
            scenario_id: "integrated_swarm_gauntlet_10000_promotion".to_string(),
            min_logical_cpus: 64,
            min_memory_bytes: 256 * 1024 * 1024 * 1024,
            required_controller_modes: SwarmPromotionControllerMode::REQUIRED.to_vec(),
            rerun_command,
        }
    }

    /// Validate the promotion envelope.
    ///
    /// # Errors
    ///
    /// Returns a machine-readable error when the envelope is incomplete or
    /// omits a required controller comparison.
    pub fn validate(&self) -> Result<(), SwarmPromotionEnvelopeError> {
        if self.schema_version != SWARM_PROMOTION_SCHEMA_VERSION {
            return Err(SwarmPromotionEnvelopeError::SchemaMismatch {
                expected: SWARM_PROMOTION_SCHEMA_VERSION.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        if self.scenario_id.trim().is_empty() {
            return Err(SwarmPromotionEnvelopeError::EmptyScenarioId);
        }
        if self.min_logical_cpus == 0 {
            return Err(SwarmPromotionEnvelopeError::EmptyLogicalCpuRequirement);
        }
        if self.min_memory_bytes == 0 {
            return Err(SwarmPromotionEnvelopeError::EmptyMemoryRequirement);
        }
        if self.rerun_command.is_empty()
            || self.rerun_command.iter().any(|part| part.trim().is_empty())
        {
            return Err(SwarmPromotionEnvelopeError::EmptyRerunCommand);
        }
        let observed: BTreeSet<_> = self.required_controller_modes.iter().copied().collect();
        for mode in SwarmPromotionControllerMode::REQUIRED {
            if !observed.contains(&mode) {
                return Err(SwarmPromotionEnvelopeError::MissingControllerMode { mode });
            }
        }
        Ok(())
    }
}

/// Error raised when validating hardware promotion envelopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwarmPromotionEnvelopeError {
    /// Schema tag was unsupported.
    SchemaMismatch {
        /// Supported schema.
        expected: String,
        /// Observed schema.
        actual: String,
    },
    /// Scenario id was empty.
    EmptyScenarioId,
    /// Logical CPU requirement was zero.
    EmptyLogicalCpuRequirement,
    /// Memory requirement was zero.
    EmptyMemoryRequirement,
    /// Rerun command was absent or contained empty parts.
    EmptyRerunCommand,
    /// A required controller comparison was absent.
    MissingControllerMode {
        /// Missing controller mode.
        mode: SwarmPromotionControllerMode,
    },
}

impl fmt::Display for SwarmPromotionEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaMismatch { expected, actual } => write!(
                f,
                "swarm promotion schema mismatch: expected '{expected}', got '{actual}'"
            ),
            Self::EmptyScenarioId => write!(f, "swarm promotion scenario id is empty"),
            Self::EmptyLogicalCpuRequirement => {
                write!(f, "swarm promotion logical CPU requirement is empty")
            }
            Self::EmptyMemoryRequirement => {
                write!(f, "swarm promotion memory requirement is empty")
            }
            Self::EmptyRerunCommand => write!(f, "swarm promotion rerun command is empty"),
            Self::MissingControllerMode { mode } => write!(
                f,
                "swarm promotion is missing controller mode '{}'",
                mode.as_str()
            ),
        }
    }
}

impl Error for SwarmPromotionEnvelopeError {}

/// Hardware and operating-system topology captured for promotion evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPromotionTopology {
    /// Worker or host identity.
    pub worker_id: String,
    /// Logical CPUs visible to the process.
    pub logical_cpus: u32,
    /// Physical CPU/core count, when available.
    pub physical_cpus: Option<u32>,
    /// NUMA node count, when available.
    pub numa_nodes: Option<u32>,
    /// Total host memory in bytes, when available.
    pub memory_bytes: Option<u64>,
    /// Operating system name/version.
    pub os: String,
    /// Kernel release/version.
    pub kernel: String,
    /// CPU governor or power policy.
    pub cpu_governor: Option<String>,
    /// Storage class used for target/artifact paths.
    pub storage_class: Option<String>,
}

impl SwarmPromotionTopology {
    /// Capture topology around an existing run environment.
    ///
    /// `SwarmRunEnvironment` stores CPU and NUMA counts as `usize` (the
    /// shape returned by `std::thread::available_parallelism` and the env
    /// parser); the topology record exposes them as `u32` so the JSON
    /// schema is portable across 32/64-bit hosts. Counts that exceed
    /// `u32::MAX` (~4 billion) cannot occur on real hardware, so the
    /// saturating conversion is a no-op on every realistic input but
    /// keeps the cast lossless and panic-free.
    #[must_use]
    pub fn from_environment(
        environment: &SwarmRunEnvironment,
        os: impl Into<String>,
        kernel: impl Into<String>,
        cpu_governor: Option<String>,
        storage_class: Option<String>,
    ) -> Self {
        Self {
            worker_id: environment.worker_id.clone(),
            logical_cpus: usize_to_u32_saturating(environment.cpu_count),
            physical_cpus: environment.physical_cpu_count.map(usize_to_u32_saturating),
            numa_nodes: environment.numa_node_count.map(usize_to_u32_saturating),
            memory_bytes: environment.memory_bytes,
            os: os.into(),
            kernel: kernel.into(),
            cpu_governor,
            storage_class,
        }
    }
}

/// Saturating `usize → u32` conversion used by topology capture.
///
/// CPU and NUMA-node counts cannot realistically exceed `u32::MAX`; this
/// helper is the explicit bridge between the 64-bit-native env parser and
/// the 32-bit-portable JSON schema. Pulled out as a free function so a
/// regression test can pin the saturation behavior directly.
fn usize_to_u32_saturating(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Machine-readable reason a worker cannot produce promotion evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmPromotionSkipReason {
    /// Worker identity was not captured.
    MissingWorkerIdentity,
    /// Logical CPU capacity is below the promotion envelope.
    InsufficientLogicalCpus {
        /// Required CPU count.
        required: u32,
        /// Observed CPU count.
        actual: u32,
    },
    /// Physical core topology was not captured.
    MissingPhysicalCpuTopology,
    /// NUMA topology was not captured.
    MissingNumaTopology,
    /// Total memory was not captured.
    MissingMemoryMeasurement {
        /// Required memory bytes.
        required_bytes: u64,
    },
    /// Total memory is below the promotion envelope.
    InsufficientMemory {
        /// Required memory bytes.
        required_bytes: u64,
        /// Observed memory bytes.
        actual_bytes: u64,
    },
    /// OS name/version was not captured.
    MissingOs,
    /// Kernel release/version was not captured.
    MissingKernel,
    /// CPU governor or power policy was not captured.
    MissingCpuGovernor,
    /// Storage class was not captured.
    MissingStorageClass,
}

impl SwarmPromotionSkipReason {
    /// Stable code for logs and dashboards.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MissingWorkerIdentity => "missing_worker_identity",
            Self::InsufficientLogicalCpus { .. } => "insufficient_logical_cpus",
            Self::MissingPhysicalCpuTopology => "missing_physical_cpu_topology",
            Self::MissingNumaTopology => "missing_numa_topology",
            Self::MissingMemoryMeasurement { .. } => "missing_memory_measurement",
            Self::InsufficientMemory { .. } => "insufficient_memory",
            Self::MissingOs => "missing_os",
            Self::MissingKernel => "missing_kernel",
            Self::MissingCpuGovernor => "missing_cpu_governor",
            Self::MissingStorageClass => "missing_storage_class",
        }
    }
}

/// Result of checking a worker against a promotion envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPromotionQualification {
    /// Envelope that was evaluated.
    pub envelope: SwarmPromotionEnvelope,
    /// Captured hardware and OS topology.
    pub topology: SwarmPromotionTopology,
    /// Machine-readable skip reasons. Empty means qualified.
    pub skip_reasons: Vec<SwarmPromotionSkipReason>,
}

impl SwarmPromotionQualification {
    /// Evaluate topology against a promotion envelope.
    ///
    /// # Errors
    ///
    /// Returns a validation error when the envelope is malformed.
    pub fn evaluate(
        envelope: SwarmPromotionEnvelope,
        topology: SwarmPromotionTopology,
    ) -> Result<Self, SwarmPromotionEnvelopeError> {
        envelope.validate()?;
        let mut skip_reasons = Vec::new();
        if topology.worker_id.trim().is_empty() {
            skip_reasons.push(SwarmPromotionSkipReason::MissingWorkerIdentity);
        }
        if topology.logical_cpus < envelope.min_logical_cpus {
            skip_reasons.push(SwarmPromotionSkipReason::InsufficientLogicalCpus {
                required: envelope.min_logical_cpus,
                actual: topology.logical_cpus,
            });
        }
        if topology.physical_cpus.unwrap_or_default() == 0 {
            skip_reasons.push(SwarmPromotionSkipReason::MissingPhysicalCpuTopology);
        }
        if topology.numa_nodes.unwrap_or_default() == 0 {
            skip_reasons.push(SwarmPromotionSkipReason::MissingNumaTopology);
        }
        match topology.memory_bytes {
            Some(actual_bytes) if actual_bytes < envelope.min_memory_bytes => {
                skip_reasons.push(SwarmPromotionSkipReason::InsufficientMemory {
                    required_bytes: envelope.min_memory_bytes,
                    actual_bytes,
                });
            }
            Some(_) => {}
            None => {
                skip_reasons.push(SwarmPromotionSkipReason::MissingMemoryMeasurement {
                    required_bytes: envelope.min_memory_bytes,
                });
            }
        }
        if topology.os.trim().is_empty() {
            skip_reasons.push(SwarmPromotionSkipReason::MissingOs);
        }
        if topology.kernel.trim().is_empty() {
            skip_reasons.push(SwarmPromotionSkipReason::MissingKernel);
        }
        if topology
            .cpu_governor
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            skip_reasons.push(SwarmPromotionSkipReason::MissingCpuGovernor);
        }
        if topology
            .storage_class
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            skip_reasons.push(SwarmPromotionSkipReason::MissingStorageClass);
        }
        Ok(Self {
            envelope,
            topology,
            skip_reasons,
        })
    }

    /// Whether this worker qualifies for hardware promotion.
    #[must_use]
    pub fn is_qualified(&self) -> bool {
        self.skip_reasons.is_empty()
    }
}

/// Structured artifact emitted when hardware promotion cannot run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPromotionSkipArtifact {
    /// Skip artifact schema version.
    pub schema_version: String,
    /// Qualification result that explains the skip.
    pub qualification: SwarmPromotionQualification,
    /// Exact command to rerun on qualifying hardware.
    pub rerun_command: Vec<String>,
    /// Creation time.
    pub generated_at: DateTime<Utc>,
}

impl SwarmPromotionSkipArtifact {
    /// Build a skip artifact only when promotion prerequisites are missing.
    #[must_use]
    pub fn from_qualification(qualification: SwarmPromotionQualification) -> Option<Self> {
        if qualification.is_qualified() {
            return None;
        }
        Some(Self {
            schema_version: SWARM_PROMOTION_SCHEMA_VERSION.to_string(),
            rerun_command: qualification.envelope.rerun_command.clone(),
            qualification,
            generated_at: Utc::now(),
        })
    }

    /// Render the skip as replayable JSONL records.
    ///
    /// # Errors
    ///
    /// Returns a serde error if the artifact cannot be converted to JSON.
    pub fn to_jsonl_values(&self) -> Result<Vec<Value>, serde_json::Error> {
        Ok(vec![
            json!({
                "record_type": "swarm_promotion_envelope",
                "schema_version": SWARM_PROMOTION_SCHEMA_VERSION,
                "envelope": serde_json::to_value(&self.qualification.envelope)?,
            }),
            json!({
                "record_type": "swarm_promotion_topology",
                "schema_version": SWARM_PROMOTION_SCHEMA_VERSION,
                "topology": serde_json::to_value(&self.qualification.topology)?,
            }),
            json!({
                "record_type": "swarm_promotion_skip",
                "schema_version": SWARM_PROMOTION_SCHEMA_VERSION,
                "skip_reason_codes": self.qualification.skip_reasons.iter().map(SwarmPromotionSkipReason::code).collect::<Vec<_>>(),
                "rerun_command": self.rerun_command,
                "artifact": serde_json::to_value(self)?,
            }),
        ])
    }
}

/// Declarative manifest for the integrated swarm gauntlet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmGauntletManifest {
    /// Manifest schema version.
    pub schema_version: String,
    /// Stable gauntlet scenario identifier.
    pub scenario_id: String,
    /// Smoke or soak execution mode.
    pub execution_mode: SwarmEvidenceExecutionMode,
    /// Whether the run is offline, host-backed, or live.
    pub source_kind: SwarmEvidenceSourceKind,
    /// Agent count represented by the scenario.
    pub agent_count: u32,
    /// Minimum raw samples expected for the scenario.
    pub sample_budget: usize,
    /// Phases that must have evidence in the run.
    pub required_phases: Vec<SwarmGauntletPhase>,
    /// Rerunnable command line for the smoke or soak lane.
    pub command_line: Vec<String>,
    /// Prerequisites that decide whether the run executes or emits a skip.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prerequisites: Vec<SwarmGauntletPrerequisite>,
}

impl SwarmGauntletManifest {
    /// Build a bounded, no-live-service smoke manifest.
    #[must_use]
    pub fn smoke(command_line: Vec<String>) -> Self {
        Self {
            schema_version: SWARM_GAUNTLET_SCHEMA_VERSION.to_string(),
            scenario_id: "integrated_swarm_gauntlet_1000".to_string(),
            execution_mode: SwarmEvidenceExecutionMode::Smoke,
            source_kind: SwarmEvidenceSourceKind::Offline,
            agent_count: 1_000,
            sample_budget: 1,
            required_phases: SwarmGauntletPhase::REQUIRED.to_vec(),
            command_line,
            prerequisites: Vec::new(),
        }
    }

    /// Build a long-soak manifest with explicit hardware/network prerequisites.
    #[must_use]
    pub fn soak(command_line: Vec<String>, prerequisites: Vec<SwarmGauntletPrerequisite>) -> Self {
        Self {
            schema_version: SWARM_GAUNTLET_SCHEMA_VERSION.to_string(),
            scenario_id: "integrated_swarm_gauntlet_10000".to_string(),
            execution_mode: SwarmEvidenceExecutionMode::Soak,
            source_kind: SwarmEvidenceSourceKind::HostBacked,
            agent_count: 10_000,
            sample_budget: 30,
            required_phases: SwarmGauntletPhase::REQUIRED.to_vec(),
            command_line,
            prerequisites,
        }
    }

    /// Parse and validate a manifest from JSON.
    ///
    /// # Errors
    ///
    /// Returns a machine-readable error when JSON parsing or validation fails.
    pub fn from_json_value(value: Value) -> Result<Self, SwarmGauntletManifestError> {
        let manifest: Self = serde_json::from_value(value)
            .map_err(|err| SwarmGauntletManifestError::InvalidJson(err.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validate the manifest contract.
    ///
    /// # Errors
    ///
    /// Returns a machine-readable error for unsupported schema, missing fields,
    /// unsupported agent counts, or incomplete phase coverage.
    pub fn validate(&self) -> Result<(), SwarmGauntletManifestError> {
        if self.schema_version != SWARM_GAUNTLET_SCHEMA_VERSION {
            return Err(SwarmGauntletManifestError::SchemaMismatch {
                expected: SWARM_GAUNTLET_SCHEMA_VERSION.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        if self.scenario_id.trim().is_empty() {
            return Err(SwarmGauntletManifestError::EmptyScenarioId);
        }
        if !matches!(self.agent_count, 1_000 | 10_000) {
            return Err(SwarmGauntletManifestError::UnsupportedAgentCount {
                actual: self.agent_count,
            });
        }
        if self.sample_budget == 0 {
            return Err(SwarmGauntletManifestError::EmptySampleBudget);
        }
        if self.command_line.is_empty()
            || self.command_line.iter().any(|part| part.trim().is_empty())
        {
            return Err(SwarmGauntletManifestError::EmptyCommandLine);
        }
        if self.required_phases.is_empty() {
            return Err(SwarmGauntletManifestError::EmptyRequiredPhases);
        }
        for prerequisite in &self.prerequisites {
            if prerequisite.name.trim().is_empty() {
                return Err(SwarmGauntletManifestError::EmptyPrerequisiteName);
            }
        }
        let phases: BTreeSet<_> = self.required_phases.iter().copied().collect();
        for phase in SwarmGauntletPhase::REQUIRED {
            if !phases.contains(&phase) {
                return Err(SwarmGauntletManifestError::MissingRequiredPhase { phase });
            }
        }
        Ok(())
    }

    /// Unsatisfied prerequisites for the current run.
    #[must_use]
    pub fn missing_prerequisites(&self) -> Vec<&SwarmGauntletPrerequisite> {
        self.prerequisites
            .iter()
            .filter(|prerequisite| !prerequisite.satisfied)
            .collect()
    }
}

/// Error raised when parsing or validating a gauntlet manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwarmGauntletManifestError {
    /// JSON could not be deserialized into the manifest type.
    InvalidJson(String),
    /// Schema tag was unsupported.
    SchemaMismatch {
        /// Supported schema.
        expected: String,
        /// Observed schema.
        actual: String,
    },
    /// Scenario id was empty.
    EmptyScenarioId,
    /// Only the canonical 1k smoke and 10k soak scenarios are accepted.
    UnsupportedAgentCount {
        /// Observed agent count.
        actual: u32,
    },
    /// The run would emit no raw samples.
    EmptySampleBudget,
    /// Command line was absent or contained an empty part.
    EmptyCommandLine,
    /// No required phases were listed.
    EmptyRequiredPhases,
    /// One of the required gauntlet phases was absent.
    MissingRequiredPhase {
        /// Missing phase.
        phase: SwarmGauntletPhase,
    },
    /// A prerequisite name was empty.
    EmptyPrerequisiteName,
}

impl fmt::Display for SwarmGauntletManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson(err) => write!(f, "invalid swarm gauntlet manifest JSON: {err}"),
            Self::SchemaMismatch { expected, actual } => write!(
                f,
                "swarm gauntlet schema mismatch: expected '{expected}', got '{actual}'"
            ),
            Self::EmptyScenarioId => write!(f, "swarm gauntlet scenario id is empty"),
            Self::UnsupportedAgentCount { actual } => {
                write!(f, "unsupported swarm gauntlet agent count {actual}")
            }
            Self::EmptySampleBudget => write!(f, "swarm gauntlet sample budget is empty"),
            Self::EmptyCommandLine => write!(f, "swarm gauntlet command line is empty"),
            Self::EmptyRequiredPhases => write!(f, "swarm gauntlet phases are empty"),
            Self::MissingRequiredPhase { phase } => {
                write!(f, "swarm gauntlet is missing phase '{}'", phase.as_str())
            }
            Self::EmptyPrerequisiteName => write!(f, "swarm gauntlet prerequisite name is empty"),
        }
    }
}

impl Error for SwarmGauntletManifestError {}

/// Machine-readable skip artifact for soak or promotion prerequisites.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmGauntletSkipArtifact {
    /// Skip artifact schema version.
    pub schema_version: String,
    /// Scenario that could not run.
    pub scenario_id: String,
    /// Smoke or soak lane.
    pub execution_mode: SwarmEvidenceExecutionMode,
    /// Source class that was requested.
    pub source_kind: SwarmEvidenceSourceKind,
    /// Unsatisfied prerequisite names.
    pub missing_prerequisites: Vec<String>,
    /// Exact command to rerun after prerequisites are satisfied.
    pub rerun_command: Vec<String>,
    /// Worker that produced the skip artifact.
    pub worker_id: String,
    /// Creation time.
    pub generated_at: DateTime<Utc>,
}

impl SwarmGauntletSkipArtifact {
    /// Build a skip artifact when prerequisites are missing.
    #[must_use]
    pub fn from_manifest(
        manifest: &SwarmGauntletManifest,
        environment: &SwarmRunEnvironment,
    ) -> Option<Self> {
        let missing_prerequisites: Vec<String> = manifest
            .missing_prerequisites()
            .into_iter()
            .map(|prerequisite| prerequisite.name.clone())
            .collect();
        if missing_prerequisites.is_empty() {
            return None;
        }
        Some(Self {
            schema_version: SWARM_GAUNTLET_SCHEMA_VERSION.to_string(),
            scenario_id: manifest.scenario_id.clone(),
            execution_mode: manifest.execution_mode,
            source_kind: manifest.source_kind,
            missing_prerequisites,
            rerun_command: manifest.command_line.clone(),
            worker_id: environment.worker_id.clone(),
            generated_at: Utc::now(),
        })
    }

    /// Render the skip as a JSONL record.
    ///
    /// # Errors
    ///
    /// Returns a serde error if the artifact cannot be converted to JSON.
    pub fn to_jsonl_value(&self) -> Result<Value, serde_json::Error> {
        Ok(json!({
            "record_type": "swarm_gauntlet_skip",
            "schema_version": self.schema_version,
            "skip": serde_json::to_value(self)?,
        }))
    }
}

/// Evidence pointer proving that one gauntlet phase was exercised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmGauntletPhaseEvidence {
    /// Phase being proven.
    pub phase: SwarmGauntletPhase,
    /// Component or crate that produced the evidence.
    pub component: String,
    /// Stable handle inside logs, summaries, or bundle artifacts.
    pub evidence_handle: String,
}

impl SwarmGauntletPhaseEvidence {
    /// Build a phase evidence record.
    #[must_use]
    pub fn new(
        phase: SwarmGauntletPhase,
        component: impl Into<String>,
        evidence_handle: impl Into<String>,
    ) -> Self {
        Self {
            phase,
            component: component.into(),
            evidence_handle: evidence_handle.into(),
        }
    }
}

/// Counters that prove audit and store surfaces participated in the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmGauntletCounters {
    /// Audit or event records emitted by the integrated path.
    pub audit_event_count: u64,
    /// Same-zone audit append operations represented by the run.
    pub same_zone_audit_appends: u64,
    /// Sparse or high-K store metadata events represented by the run.
    pub sparse_high_k_metadata_events: u64,
}

/// Integrated gauntlet evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmGauntletEvidenceBundle {
    /// Declarative manifest for the run.
    pub manifest: SwarmGauntletManifest,
    /// Existing swarm latency and raw-sample bundle.
    pub latency_bundle: SwarmLatencyEvidenceBundle,
    /// Resource snapshots corresponding to each summarized scenario.
    pub resource_snapshots: Vec<SwarmRegressionMetricSnapshot>,
    /// Scheduler, placement, and backpressure decision cards.
    pub decision_cards: Vec<SwarmDecisionCard>,
    /// Phase evidence proving the integrated surface was exercised.
    pub phase_evidence: Vec<SwarmGauntletPhaseEvidence>,
    /// Redaction-safe per-operation resource ledger records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_ledger_records: Vec<Value>,
    /// Audit/store counters.
    pub counters: SwarmGauntletCounters,
    /// Optional skip artifact for a soak/promotion lane.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_artifact: Option<SwarmGauntletSkipArtifact>,
}

impl SwarmGauntletEvidenceBundle {
    /// Build and validate an integrated gauntlet evidence bundle.
    ///
    /// # Errors
    ///
    /// Returns a machine-readable error when the manifest is invalid or when
    /// required phase, decision, resource, audit, or store evidence is missing.
    pub fn new(
        manifest: SwarmGauntletManifest,
        latency_bundle: SwarmLatencyEvidenceBundle,
        resource_snapshots: Vec<SwarmRegressionMetricSnapshot>,
        decision_cards: Vec<SwarmDecisionCard>,
        phase_evidence: Vec<SwarmGauntletPhaseEvidence>,
        counters: SwarmGauntletCounters,
        skip_artifact: Option<SwarmGauntletSkipArtifact>,
    ) -> Result<Self, SwarmGauntletError> {
        manifest.validate()?;
        validate_gauntlet_phase_evidence(&manifest, &phase_evidence)?;
        validate_gauntlet_decisions(&manifest, &decision_cards)?;
        validate_gauntlet_resources(&latency_bundle, &resource_snapshots)?;
        validate_gauntlet_counters(&manifest, counters)?;
        Ok(Self {
            manifest,
            latency_bundle,
            resource_snapshots,
            decision_cards,
            phase_evidence,
            resource_ledger_records: Vec::new(),
            counters,
            skip_artifact,
        })
    }

    /// Attach validated resource ledger JSONL records to the gauntlet bundle.
    ///
    /// # Errors
    ///
    /// Returns a machine-readable error if any record is not a
    /// `resource-ledger/v1` JSONL value with the fields operators need for
    /// correlation.
    pub fn with_resource_ledger_records(
        mut self,
        records: Vec<Value>,
    ) -> Result<Self, SwarmGauntletError> {
        validate_resource_ledger_records(&records)?;
        self.resource_ledger_records = records;
        Ok(self)
    }

    /// Render an operator and agent friendly summary.
    #[must_use]
    pub fn summary(&self) -> SwarmGauntletSummary {
        SwarmGauntletSummary {
            schema_version: SWARM_GAUNTLET_SCHEMA_VERSION.to_string(),
            scenario_id: self.manifest.scenario_id.clone(),
            execution_mode: self.manifest.execution_mode,
            source_kind: self.manifest.source_kind,
            agent_count: self.manifest.agent_count,
            sample_count: self.latency_bundle.samples.len(),
            summary_count: self.latency_bundle.summaries.len(),
            decision_card_ids: self
                .decision_cards
                .iter()
                .map(|card| card.card_id.clone())
                .collect(),
            resource_ledger_record_count: self.resource_ledger_records.len(),
            phase_count: self.phase_evidence.len(),
            counters: self.counters,
            skipped: self.skip_artifact.is_some(),
            generated_at: Utc::now(),
        }
    }

    /// Render the integrated gauntlet as typed JSONL records.
    ///
    /// # Errors
    ///
    /// Returns a serde error if any record cannot be converted to JSON.
    pub fn to_jsonl_values(&self) -> Result<Vec<Value>, serde_json::Error> {
        let mut records = Vec::new();
        records.push(json!({
            "record_type": "swarm_gauntlet_manifest",
            "schema_version": SWARM_GAUNTLET_SCHEMA_VERSION,
            "manifest": serde_json::to_value(&self.manifest)?,
        }));
        records.extend(self.latency_bundle.to_jsonl_values()?);
        for card in &self.decision_cards {
            records.push(card.to_jsonl_value()?);
        }
        for phase in &self.phase_evidence {
            records.push(json!({
                "record_type": "swarm_gauntlet_phase_evidence",
                "schema_version": SWARM_GAUNTLET_SCHEMA_VERSION,
                "phase_evidence": serde_json::to_value(phase)?,
            }));
        }
        records.extend(self.resource_ledger_records.iter().cloned());
        if let Some(skip_artifact) = &self.skip_artifact {
            records.push(skip_artifact.to_jsonl_value()?);
        }
        records.push(json!({
            "record_type": "swarm_gauntlet_summary",
            "schema_version": SWARM_GAUNTLET_SCHEMA_VERSION,
            "summary": serde_json::to_value(self.summary())?,
        }));
        for summary in &self.latency_bundle.summaries {
            records.push(self.log_record(summary));
        }
        Ok(records)
    }

    fn log_record(&self, summary: &SwarmLatencySummary) -> Value {
        let resource = self
            .resource_snapshots
            .iter()
            .find(|snapshot| snapshot.scenario_id == summary.scenario_id);
        json!({
            "record_type": "swarm_gauntlet_log",
            "schema_version": SWARM_GAUNTLET_LOG_SCHEMA_VERSION,
            "scenario_id": self.manifest.scenario_id,
            "latency_scenario_id": summary.scenario_id,
            "execution_mode": self.manifest.execution_mode,
            "source_kind": self.manifest.source_kind,
            "command_line": self.latency_bundle.environment.command_line,
            "git_revision": self.latency_bundle.environment.source_revision,
            "worker_id": self.latency_bundle.environment.worker_id,
            "cargo_target_dir": self.latency_bundle.environment.cargo_target_dir,
            "topology": {
                "logical_cpus": self.latency_bundle.environment.cpu_count,
                "physical_cpus": self.latency_bundle.environment.physical_cpu_count,
                "numa_nodes": self.latency_bundle.environment.numa_node_count,
                "memory_bytes": self.latency_bundle.environment.memory_bytes,
            },
            "sample_count": summary.sample_count,
            "raw_samples_record_type": "swarm_latency_sample",
            "p50_ns": summary.total.p50_ns,
            "p95_ns": summary.total.p95_ns,
            "p99_ns": summary.total.p99_ns,
            "p999_ns": summary.total.p999_ns,
            "throughput_ops_per_second": resource.map(|snapshot| snapshot.throughput_ops_per_second),
            "queue_depth": resource.map(|snapshot| snapshot.max_queue_depth),
            "retry_amplification_microunits": resource.map(|snapshot| snapshot.retry_amplification_microunits),
            "rss_bytes": resource.map(|snapshot| snapshot.rss_bytes),
            "cpu_microunits": resource.map(|snapshot| snapshot.cpu_microunits),
            "decision_card_ids": self.decision_cards.iter().map(|card| card.card_id.as_str()).collect::<Vec<_>>(),
            "resource_ledger_record_count": self.resource_ledger_records.len(),
            "resource_ledger_record_type": "resource_ledger",
            "resource_ledger_operation_ids": resource_ledger_operation_ids(&self.resource_ledger_records),
            "evidence_bundle_id": self.latency_bundle.artifact_manifest.as_ref().map(|manifest| manifest.bundle_id.as_str()),
            "skip_reason": self.skip_artifact.as_ref().map(|skip| skip.missing_prerequisites.join(",")),
            "audit_event_count": self.counters.audit_event_count,
            "same_zone_audit_appends": self.counters.same_zone_audit_appends,
            "sparse_high_k_metadata_events": self.counters.sparse_high_k_metadata_events,
        })
    }
}

/// Compact gauntlet summary carried as its own JSONL record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmGauntletSummary {
    /// Summary schema version.
    pub schema_version: String,
    /// Gauntlet scenario identifier.
    pub scenario_id: String,
    /// Smoke or soak lane.
    pub execution_mode: SwarmEvidenceExecutionMode,
    /// Source class.
    pub source_kind: SwarmEvidenceSourceKind,
    /// Agent count represented by the run.
    pub agent_count: u32,
    /// Raw latency sample count.
    pub sample_count: usize,
    /// Number of latency summaries emitted.
    pub summary_count: usize,
    /// Decision cards included in the run.
    pub decision_card_ids: Vec<String>,
    /// Per-operation resource ledger records included in the run.
    pub resource_ledger_record_count: usize,
    /// Number of phase evidence records.
    pub phase_count: usize,
    /// Audit/store counters.
    pub counters: SwarmGauntletCounters,
    /// Whether this record represents a structured skip.
    pub skipped: bool,
    /// Creation time.
    pub generated_at: DateTime<Utc>,
}

/// Error raised when assembling integrated gauntlet evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwarmGauntletError {
    /// Manifest validation failed.
    Manifest(SwarmGauntletManifestError),
    /// A required phase had no evidence handle.
    MissingPhaseEvidence {
        /// Missing phase.
        phase: SwarmGauntletPhase,
    },
    /// A required decision-card domain was absent.
    MissingDecisionDomain {
        /// Missing decision domain.
        domain: SwarmDecisionDomain,
    },
    /// A summarized latency scenario lacked resource metrics.
    MissingResourceSnapshot {
        /// Missing latency scenario id.
        scenario_id: String,
    },
    /// A resource ledger JSONL record was malformed.
    InvalidResourceLedgerRecord {
        /// Human-readable validation reason.
        reason: String,
    },
    /// Audit phase was requested but no audit events were recorded.
    MissingAuditEvidence,
    /// Store phase was requested but no high-K/sparse store events were recorded.
    MissingStoreEvidence,
}

impl From<SwarmGauntletManifestError> for SwarmGauntletError {
    fn from(value: SwarmGauntletManifestError) -> Self {
        Self::Manifest(value)
    }
}

impl fmt::Display for SwarmGauntletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(err) => write!(f, "{err}"),
            Self::MissingPhaseEvidence { phase } => {
                write!(f, "missing swarm gauntlet phase '{}'", phase.as_str())
            }
            Self::MissingDecisionDomain { domain } => {
                write!(
                    f,
                    "missing swarm gauntlet decision domain '{}'",
                    domain.as_str()
                )
            }
            Self::MissingResourceSnapshot { scenario_id } => {
                write!(
                    f,
                    "missing swarm gauntlet resource snapshot '{scenario_id}'"
                )
            }
            Self::InvalidResourceLedgerRecord { reason } => {
                write!(f, "invalid swarm gauntlet resource ledger record: {reason}")
            }
            Self::MissingAuditEvidence => write!(f, "missing swarm gauntlet audit evidence"),
            Self::MissingStoreEvidence => write!(f, "missing swarm gauntlet store evidence"),
        }
    }
}

impl Error for SwarmGauntletError {}

fn validate_resource_ledger_records(records: &[Value]) -> Result<(), SwarmGauntletError> {
    for (index, record) in records.iter().enumerate() {
        let reason = |message: &str| SwarmGauntletError::InvalidResourceLedgerRecord {
            reason: format!("record {index}: {message}"),
        };

        if record["record_type"] != "resource_ledger" {
            return Err(reason("record_type must be resource_ledger"));
        }
        if record["schema_version"] != SWARM_RESOURCE_LEDGER_SCHEMA_VERSION {
            return Err(reason(
                "top-level schema_version must be resource-ledger/v1",
            ));
        }
        let ledger = record
            .get("ledger")
            .and_then(Value::as_object)
            .ok_or_else(|| reason("ledger object is required"))?;
        for field in [
            "scenario_id",
            "operation_id",
            "kind",
            "outcome",
            "git_revision",
            "worker_ref",
        ] {
            if ledger
                .get(field)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(reason(&format!(
                    "ledger.{field} must be a non-empty string"
                )));
            }
        }
        if ledger
            .get("command_line")
            .and_then(Value::as_array)
            .is_none()
        {
            return Err(reason("ledger.command_line must be an array"));
        }
        if ledger.get("samples").and_then(Value::as_object).is_none() {
            return Err(reason("ledger.samples must be an object"));
        }
        if ledger
            .get("samples")
            .and_then(|samples| samples.get("state"))
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(reason("ledger.samples.state must be a non-empty string"));
        }
        if ledger
            .get("worker_ref")
            .and_then(Value::as_str)
            .is_some_and(|worker| !worker.starts_with("worker:blake3:"))
        {
            return Err(reason("ledger.worker_ref must be a hashed worker ref"));
        }
        for (field, prefix) in [
            ("zone_ref", "zone:blake3:"),
            ("principal_ref", "principal:blake3:"),
        ] {
            if ledger
                .get(field)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.starts_with(prefix))
            {
                return Err(reason(&format!("ledger.{field} must be hashed")));
            }
        }
    }
    Ok(())
}

fn resource_ledger_operation_ids(records: &[Value]) -> Vec<&str> {
    records
        .iter()
        .filter_map(|record| record["ledger"]["operation_id"].as_str())
        .collect()
}

fn validate_gauntlet_phase_evidence(
    manifest: &SwarmGauntletManifest,
    phase_evidence: &[SwarmGauntletPhaseEvidence],
) -> Result<(), SwarmGauntletError> {
    let observed: BTreeSet<_> = phase_evidence
        .iter()
        .map(|evidence| evidence.phase)
        .collect();
    for phase in &manifest.required_phases {
        if !observed.contains(phase) {
            return Err(SwarmGauntletError::MissingPhaseEvidence { phase: *phase });
        }
    }
    Ok(())
}

fn validate_gauntlet_decisions(
    manifest: &SwarmGauntletManifest,
    decision_cards: &[SwarmDecisionCard],
) -> Result<(), SwarmGauntletError> {
    let observed: BTreeSet<_> = decision_cards.iter().map(|card| card.domain).collect();
    for (phase, domain) in [
        (
            SwarmGauntletPhase::Scheduler,
            SwarmDecisionDomain::Scheduler,
        ),
        (
            SwarmGauntletPhase::Placement,
            SwarmDecisionDomain::Placement,
        ),
        (
            SwarmGauntletPhase::Backpressure,
            SwarmDecisionDomain::Backpressure,
        ),
    ] {
        if manifest.required_phases.contains(&phase) && !observed.contains(&domain) {
            return Err(SwarmGauntletError::MissingDecisionDomain { domain });
        }
    }
    Ok(())
}

fn validate_gauntlet_resources(
    latency_bundle: &SwarmLatencyEvidenceBundle,
    resource_snapshots: &[SwarmRegressionMetricSnapshot],
) -> Result<(), SwarmGauntletError> {
    let observed: BTreeSet<&str> = resource_snapshots
        .iter()
        .map(|snapshot| snapshot.scenario_id.as_str())
        .collect();
    for summary in &latency_bundle.summaries {
        if !observed.contains(summary.scenario_id.as_str()) {
            return Err(SwarmGauntletError::MissingResourceSnapshot {
                scenario_id: summary.scenario_id.clone(),
            });
        }
    }
    Ok(())
}

fn validate_gauntlet_counters(
    manifest: &SwarmGauntletManifest,
    counters: SwarmGauntletCounters,
) -> Result<(), SwarmGauntletError> {
    if manifest
        .required_phases
        .contains(&SwarmGauntletPhase::Audit)
        && counters.audit_event_count == 0
    {
        return Err(SwarmGauntletError::MissingAuditEvidence);
    }
    if manifest
        .required_phases
        .contains(&SwarmGauntletPhase::Store)
        && counters.sparse_high_k_metadata_events == 0
    {
        return Err(SwarmGauntletError::MissingStoreEvidence);
    }
    Ok(())
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

/// Queue-wait percentiles for batch scheduling evidence in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct SwarmBatchWaitPercentiles {
    /// 50th percentile queue wait.
    pub p50_ms: u64,
    /// 95th percentile queue wait.
    pub p95_ms: u64,
    /// 99th percentile queue wait.
    pub p99_ms: u64,
    /// 99.9th percentile queue wait.
    pub p999_ms: u64,
    /// Maximum queue wait.
    pub max_ms: u64,
    /// Integer mean queue wait.
    pub mean_ms: u64,
}

/// Redaction-safe count for one fairness bucket in a batch evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmBatchFairnessBucket {
    /// Stable redacted or hashed fairness key.
    pub fairness_key_hash: String,
    /// Operations assigned to this bucket.
    pub operation_count: usize,
    /// Morsels that included this bucket.
    pub morsel_count: usize,
}

/// Resource sample attached to one batch morselization evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmBatchResourceSample {
    /// Resident set size observed or bounded for the run.
    pub rss_bytes: u64,
    /// CPU usage in microunits, where `1_000_000` is one full core.
    pub cpu_microunits: u64,
    /// Maximum queue depth observed during the run.
    pub max_queue_depth: u64,
    /// Retry amplification in microunits, where `1_000_000` means one retry per op.
    pub retry_amplification_microunits: u64,
}

/// Replayable JSONL evidence for host batch-invoke morselization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmBatchMorselizationEvidence {
    /// Evidence schema version.
    pub schema_version: String,
    /// Swarm scenario identifier.
    pub scenario_id: String,
    /// Batch identifier inside the scenario.
    pub batch_id: String,
    /// Command line that produced or can reproduce this evidence.
    pub command_line: Vec<String>,
    /// Source revision associated with the run.
    pub git_revision: String,
    /// Worker that produced the evidence.
    pub worker_id: String,
    /// Scheduler mode used by the host batch planner.
    pub scheduler_mode: String,
    /// Number of operations submitted.
    pub operation_count: usize,
    /// Maximum dependency tier depth.
    pub dependency_depth: usize,
    /// Maximum operations per morsel.
    pub morsel_size: usize,
    /// Total morsels produced by the planner.
    pub total_morsels: usize,
    /// Number of dependency tiers split into multiple morsels.
    pub split_tiers: usize,
    /// Largest operation count in one morsel.
    pub largest_morsel_operations: usize,
    /// Redaction-safe fairness-key distribution.
    pub fairness_distribution: Vec<SwarmBatchFairnessBucket>,
    /// Queue wait percentiles under deterministic FIFO ordering.
    pub fifo_wait: SwarmBatchWaitPercentiles,
    /// Queue wait percentiles under the selected scheduler.
    pub scheduled_wait: SwarmBatchWaitPercentiles,
    /// Resource sample attached to this batch scenario.
    pub resources: SwarmBatchResourceSample,
    /// Explicit fallback reason when morselization did not split a tier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
    /// Error mode observed by the companion failure scenario.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    /// Cancellation or timeout mode observed by the companion scenario.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancellation_reason: Option<String>,
    /// Skip reason observed by the companion dependency scenario.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

impl SwarmBatchMorselizationEvidence {
    /// Validate the evidence record before serializing it to JSONL.
    ///
    /// # Errors
    ///
    /// Returns [`SwarmBatchMorselizationEvidenceError`] when required fields
    /// are missing, internally inconsistent, or would weaken the redaction
    /// and bounded-morsel evidence contract.
    pub fn validate(&self) -> Result<(), SwarmBatchMorselizationEvidenceError> {
        if self.schema_version != SWARM_BATCH_MORSELIZATION_SCHEMA_VERSION {
            return Err(SwarmBatchMorselizationEvidenceError::SchemaMismatch {
                expected: SWARM_BATCH_MORSELIZATION_SCHEMA_VERSION.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        for (field, value) in [
            ("scenario_id", self.scenario_id.as_str()),
            ("batch_id", self.batch_id.as_str()),
            ("git_revision", self.git_revision.as_str()),
            ("worker_id", self.worker_id.as_str()),
            ("scheduler_mode", self.scheduler_mode.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(SwarmBatchMorselizationEvidenceError::EmptyField { field });
            }
        }
        if self.command_line.is_empty()
            || self.command_line.iter().any(|part| part.trim().is_empty())
        {
            return Err(SwarmBatchMorselizationEvidenceError::EmptyCommandLine);
        }
        if self.operation_count == 0 {
            return Err(SwarmBatchMorselizationEvidenceError::EmptyOperationCount);
        }
        if self.dependency_depth == 0 {
            return Err(SwarmBatchMorselizationEvidenceError::EmptyDependencyDepth);
        }
        if self.morsel_size == 0 {
            return Err(SwarmBatchMorselizationEvidenceError::EmptyMorselSize);
        }
        if self.total_morsels == 0 {
            return Err(SwarmBatchMorselizationEvidenceError::MissingMorselReport);
        }
        if self.largest_morsel_operations > self.morsel_size {
            return Err(SwarmBatchMorselizationEvidenceError::OversizedMorsel {
                largest: self.largest_morsel_operations,
                limit: self.morsel_size,
            });
        }
        if self.fairness_distribution.is_empty() {
            return Err(SwarmBatchMorselizationEvidenceError::EmptyFairnessDistribution);
        }
        if self.fairness_distribution.iter().any(|bucket| {
            bucket.fairness_key_hash.trim().is_empty()
                || bucket.operation_count == 0
                || bucket.morsel_count == 0
        }) {
            return Err(SwarmBatchMorselizationEvidenceError::InvalidFairnessBucket);
        }
        let fairness_operations = self
            .fairness_distribution
            .iter()
            .fold(0_usize, |total, bucket| {
                total.saturating_add(bucket.operation_count)
            });
        if fairness_operations != self.operation_count {
            return Err(
                SwarmBatchMorselizationEvidenceError::FairnessOperationCountMismatch {
                    expected: self.operation_count,
                    actual: fairness_operations,
                },
            );
        }
        if self.resources.rss_bytes == 0 {
            return Err(
                SwarmBatchMorselizationEvidenceError::MissingResourceMeasurement {
                    field: "rss_bytes",
                },
            );
        }
        Ok(())
    }

    /// Render this evidence as one structured JSONL value.
    ///
    /// # Errors
    ///
    /// Returns a validation error when the evidence record is incomplete, or a
    /// serde error when the typed evidence cannot be converted into JSON.
    pub fn to_jsonl_value(&self) -> Result<Value, SwarmBatchMorselizationEvidenceJsonError> {
        self.validate()?;
        Ok(json!({
            "record_type": "swarm_batch_morselization_evidence",
            "schema_version": self.schema_version,
            "scenario_id": self.scenario_id,
            "batch_id": self.batch_id,
            "operation_count": self.operation_count,
            "dependency_depth": self.dependency_depth,
            "morsel_size": self.morsel_size,
            "scheduler_mode": self.scheduler_mode,
            "p50_wait_ms": self.scheduled_wait.p50_ms,
            "p95_wait_ms": self.scheduled_wait.p95_ms,
            "p99_wait_ms": self.scheduled_wait.p99_ms,
            "p999_wait_ms": self.scheduled_wait.p999_ms,
            "rss_bytes": self.resources.rss_bytes,
            "max_queue_depth": self.resources.max_queue_depth,
            "fallback_reason": self.fallback_reason,
            "error_kind": self.error_kind,
            "cancellation_reason": self.cancellation_reason,
            "skip_reason": self.skip_reason,
            "evidence": serde_json::to_value(self)?,
        }))
    }
}

/// Validation error for batch morselization evidence records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwarmBatchMorselizationEvidenceError {
    /// Schema tag was unsupported.
    SchemaMismatch {
        /// Supported schema.
        expected: String,
        /// Observed schema.
        actual: String,
    },
    /// A required string field was empty.
    EmptyField {
        /// Field name.
        field: &'static str,
    },
    /// Reproduction command line was empty or contained an empty part.
    EmptyCommandLine,
    /// Operation count was zero.
    EmptyOperationCount,
    /// Dependency depth was zero.
    EmptyDependencyDepth,
    /// Morsel size was zero.
    EmptyMorselSize,
    /// Planner produced no morsel report.
    MissingMorselReport,
    /// Planner reported a morsel larger than the requested limit.
    OversizedMorsel {
        /// Largest observed morsel.
        largest: usize,
        /// Configured morsel size.
        limit: usize,
    },
    /// Fairness distribution was empty.
    EmptyFairnessDistribution,
    /// A fairness bucket had an empty hash or zero counts.
    InvalidFairnessBucket,
    /// Fairness counts did not cover every operation.
    FairnessOperationCountMismatch {
        /// Expected operation count.
        expected: usize,
        /// Sum of fairness-bucket operation counts.
        actual: usize,
    },
    /// A required resource field was absent or zero.
    MissingResourceMeasurement {
        /// Field name.
        field: &'static str,
    },
}

impl fmt::Display for SwarmBatchMorselizationEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaMismatch { expected, actual } => write!(
                f,
                "swarm batch morselization schema mismatch: expected '{expected}', got '{actual}'"
            ),
            Self::EmptyField { field } => {
                write!(f, "swarm batch morselization field '{field}' is empty")
            }
            Self::EmptyCommandLine => {
                write!(f, "swarm batch morselization command line is empty")
            }
            Self::EmptyOperationCount => {
                write!(f, "swarm batch morselization operation count is zero")
            }
            Self::EmptyDependencyDepth => {
                write!(f, "swarm batch morselization dependency depth is zero")
            }
            Self::EmptyMorselSize => {
                write!(f, "swarm batch morselization morsel size is zero")
            }
            Self::MissingMorselReport => {
                write!(f, "swarm batch morselization report has no morsels")
            }
            Self::OversizedMorsel { largest, limit } => write!(
                f,
                "swarm batch morselization largest morsel {largest} exceeds limit {limit}"
            ),
            Self::EmptyFairnessDistribution => {
                write!(
                    f,
                    "swarm batch morselization fairness distribution is empty"
                )
            }
            Self::InvalidFairnessBucket => write!(
                f,
                "swarm batch morselization fairness bucket has empty hash or zero counts"
            ),
            Self::FairnessOperationCountMismatch { expected, actual } => write!(
                f,
                "swarm batch morselization fairness count mismatch: expected {expected}, got {actual}"
            ),
            Self::MissingResourceMeasurement { field } => write!(
                f,
                "swarm batch morselization resource field '{field}' is missing"
            ),
        }
    }
}

impl Error for SwarmBatchMorselizationEvidenceError {}

/// Error raised while rendering batch morselization evidence JSONL.
#[derive(Debug)]
pub enum SwarmBatchMorselizationEvidenceJsonError {
    /// Validation failed.
    Validation(SwarmBatchMorselizationEvidenceError),
    /// JSON serialization failed.
    Serde(serde_json::Error),
}

impl fmt::Display for SwarmBatchMorselizationEvidenceJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(err) => write!(f, "{err}"),
            Self::Serde(err) => write!(f, "{err}"),
        }
    }
}

impl Error for SwarmBatchMorselizationEvidenceJsonError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Validation(err) => Some(err),
            Self::Serde(err) => Some(err),
        }
    }
}

impl From<SwarmBatchMorselizationEvidenceError> for SwarmBatchMorselizationEvidenceJsonError {
    fn from(value: SwarmBatchMorselizationEvidenceError) -> Self {
        Self::Validation(value)
    }
}

impl From<serde_json::Error> for SwarmBatchMorselizationEvidenceJsonError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serde(value)
    }
}

/// Activation latency percentiles for one prewarm evidence scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct SwarmPrewarmLatencyPercentiles {
    /// 50th percentile activation latency.
    pub p50_ms: u64,
    /// 95th percentile activation latency.
    pub p95_ms: u64,
    /// 99th percentile activation latency.
    pub p99_ms: u64,
    /// 99.9th percentile activation latency.
    pub p999_ms: u64,
    /// Maximum activation latency.
    pub max_ms: u64,
    /// Integer mean activation latency.
    pub mean_ms: u64,
}

/// Replayable JSONL evidence for connector prewarm cold-start behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPrewarmColdStartEvidence {
    /// Evidence schema version.
    pub schema_version: String,
    /// Stable scenario identifier.
    pub scenario_id: String,
    /// Connector identifier.
    pub connector_id: String,
    /// Command line that produced or can reproduce this evidence.
    pub command_line: Vec<String>,
    /// Source revision associated with the run.
    pub git_revision: String,
    /// Worker that produced the evidence.
    pub worker_id: String,
    /// Cargo target directory used by the proof run.
    pub cargo_target_dir: String,
    /// Connector fixture activated by the host-backed proof.
    pub connector_fixture_id: String,
    /// Host boundary that made the checkout decision.
    pub host_boundary: String,
    /// Manifest hash used by the candidate warm entry.
    pub manifest_hash: String,
    /// Zone requested by checkout.
    pub zone: String,
    /// Startup strategy under evaluation.
    pub strategy: String,
    /// Pool state observed for checkout.
    pub pool_state: String,
    /// Configured prewarm pool capacity for the connector fixture.
    pub pool_size: u32,
    /// Coarse checkout decision label.
    pub admission_decision: String,
    /// Whether the run checked out a warm entry.
    pub warm_checkout: bool,
    /// Measured or modeled activation latency for this scenario.
    pub activation_latency_ms: u64,
    /// Conservative on-demand baseline used for comparison.
    pub baseline_on_demand_latency_ms: u64,
    /// Activation latency percentile summary.
    pub latency: SwarmPrewarmLatencyPercentiles,
    /// Conservative on-demand percentile baseline used for before/after comparison.
    pub baseline_latency: SwarmPrewarmLatencyPercentiles,
    /// Sandbox layer active for the connector.
    pub sandbox_layer: String,
    /// Sandbox profile requested for the connector fixture.
    pub sandbox_profile: String,
    /// Sandbox enforcement boundary represented by this record.
    pub sandbox_boundary: String,
    /// Redacted credential handling mode.
    pub credential_mode: String,
    /// Resident set size observed or bounded for the scenario.
    pub rss_bytes: u64,
    /// Connector process count observed for the scenario.
    pub process_count: u32,
    /// Number of simultaneous startup requests represented by the scenario.
    pub concurrent_startups: u32,
    /// Operator-facing error mapping class for fallback or rejection paths.
    pub error_mapping: String,
    /// Cleanup result recorded for the warm entry or fallback path.
    pub cleanup_result: String,
    /// Restart reason when a prior warm entry crashed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_reason: Option<String>,
    /// Conservative fallback reason, when on-demand startup was selected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
    /// Unsafe rejection reason, when checkout was denied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsafe_rejection_reason: Option<String>,
    /// Skip reason when a scenario cannot run on the current host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    /// Whether the scenario verified shutdown cleanup.
    pub shutdown_cleanup_verified: bool,
}

const fn validate_prewarm_latency_percentiles(latency: &SwarmPrewarmLatencyPercentiles) -> bool {
    latency.p50_ms != 0
        && latency.p50_ms <= latency.p95_ms
        && latency.p95_ms <= latency.p99_ms
        && latency.p99_ms <= latency.p999_ms
        && latency.p999_ms <= latency.max_ms
        && latency.mean_ms != 0
}

impl SwarmPrewarmColdStartEvidence {
    /// Validate the evidence record before serializing it to JSONL.
    ///
    /// # Errors
    ///
    /// Returns [`SwarmPrewarmColdStartEvidenceError`] when required fields are
    /// missing, resource measurements are absent, or latency evidence is
    /// internally inconsistent.
    pub fn validate(&self) -> Result<(), SwarmPrewarmColdStartEvidenceError> {
        if self.schema_version != SWARM_PREWARM_COLD_START_SCHEMA_VERSION {
            return Err(SwarmPrewarmColdStartEvidenceError::SchemaMismatch {
                expected: SWARM_PREWARM_COLD_START_SCHEMA_VERSION.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        for (field, value) in [
            ("scenario_id", self.scenario_id.as_str()),
            ("connector_id", self.connector_id.as_str()),
            ("git_revision", self.git_revision.as_str()),
            ("worker_id", self.worker_id.as_str()),
            ("cargo_target_dir", self.cargo_target_dir.as_str()),
            ("connector_fixture_id", self.connector_fixture_id.as_str()),
            ("host_boundary", self.host_boundary.as_str()),
            ("manifest_hash", self.manifest_hash.as_str()),
            ("zone", self.zone.as_str()),
            ("strategy", self.strategy.as_str()),
            ("pool_state", self.pool_state.as_str()),
            ("admission_decision", self.admission_decision.as_str()),
            ("sandbox_layer", self.sandbox_layer.as_str()),
            ("sandbox_profile", self.sandbox_profile.as_str()),
            ("sandbox_boundary", self.sandbox_boundary.as_str()),
            ("credential_mode", self.credential_mode.as_str()),
            ("error_mapping", self.error_mapping.as_str()),
            ("cleanup_result", self.cleanup_result.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(SwarmPrewarmColdStartEvidenceError::EmptyField { field });
            }
        }
        if self.command_line.is_empty()
            || self.command_line.iter().any(|part| part.trim().is_empty())
        {
            return Err(SwarmPrewarmColdStartEvidenceError::EmptyCommandLine);
        }
        if self.activation_latency_ms == 0 || self.baseline_on_demand_latency_ms == 0 {
            return Err(SwarmPrewarmColdStartEvidenceError::MissingLatencyMeasurement);
        }
        if self.activation_latency_ms > self.baseline_on_demand_latency_ms {
            return Err(SwarmPrewarmColdStartEvidenceError::LatencyRegression {
                activation_ms: self.activation_latency_ms,
                baseline_ms: self.baseline_on_demand_latency_ms,
            });
        }
        if !validate_prewarm_latency_percentiles(&self.latency)
            || !validate_prewarm_latency_percentiles(&self.baseline_latency)
        {
            return Err(SwarmPrewarmColdStartEvidenceError::InvalidLatencyPercentiles);
        }
        if self.latency.p50_ms > self.baseline_latency.p50_ms {
            return Err(SwarmPrewarmColdStartEvidenceError::LatencyRegression {
                activation_ms: self.latency.p50_ms,
                baseline_ms: self.baseline_latency.p50_ms,
            });
        }
        if self.latency.p95_ms > self.baseline_latency.p95_ms {
            return Err(SwarmPrewarmColdStartEvidenceError::LatencyRegression {
                activation_ms: self.latency.p95_ms,
                baseline_ms: self.baseline_latency.p95_ms,
            });
        }
        if self.latency.p99_ms > self.baseline_latency.p99_ms {
            return Err(SwarmPrewarmColdStartEvidenceError::LatencyRegression {
                activation_ms: self.latency.p99_ms,
                baseline_ms: self.baseline_latency.p99_ms,
            });
        }
        if self.rss_bytes == 0 {
            return Err(
                SwarmPrewarmColdStartEvidenceError::MissingResourceMeasurement {
                    field: "rss_bytes",
                },
            );
        }
        if self.pool_size == 0 {
            return Err(
                SwarmPrewarmColdStartEvidenceError::MissingResourceMeasurement {
                    field: "pool_size",
                },
            );
        }
        if self.process_count == 0 {
            return Err(
                SwarmPrewarmColdStartEvidenceError::MissingResourceMeasurement {
                    field: "process_count",
                },
            );
        }
        if self.concurrent_startups == 0 {
            return Err(SwarmPrewarmColdStartEvidenceError::EmptyConcurrentStartupCount);
        }
        Ok(())
    }

    /// Render this evidence as one structured JSONL value.
    ///
    /// # Errors
    ///
    /// Returns a validation error when the evidence record is incomplete, or a
    /// serde error when the typed evidence cannot be converted into JSON.
    pub fn to_jsonl_value(&self) -> Result<Value, SwarmPrewarmColdStartEvidenceJsonError> {
        self.validate()?;
        Ok(json!({
            "record_type": "swarm_prewarm_cold_start_evidence",
            "schema_version": self.schema_version,
            "scenario_id": self.scenario_id,
            "connector_id": self.connector_id,
            "command_line": self.command_line,
            "cargo_target_dir": self.cargo_target_dir,
            "connector_fixture_id": self.connector_fixture_id,
            "host_boundary": self.host_boundary,
            "manifest_hash": self.manifest_hash,
            "zone": self.zone,
            "strategy": self.strategy,
            "pool_state": self.pool_state,
            "pool_size": self.pool_size,
            "admission_decision": self.admission_decision,
            "warm_checkout": self.warm_checkout,
            "activation_latency_ms": self.activation_latency_ms,
            "baseline_on_demand_latency_ms": self.baseline_on_demand_latency_ms,
            "p50_activation_latency_ms": self.latency.p50_ms,
            "p95_activation_latency_ms": self.latency.p95_ms,
            "p99_activation_latency_ms": self.latency.p99_ms,
            "baseline_p50_activation_latency_ms": self.baseline_latency.p50_ms,
            "baseline_p95_activation_latency_ms": self.baseline_latency.p95_ms,
            "baseline_p99_activation_latency_ms": self.baseline_latency.p99_ms,
            "p50_activation_latency_improvement_ms": self
                .baseline_latency
                .p50_ms
                .saturating_sub(self.latency.p50_ms),
            "p95_activation_latency_improvement_ms": self
                .baseline_latency
                .p95_ms
                .saturating_sub(self.latency.p95_ms),
            "p99_activation_latency_improvement_ms": self
                .baseline_latency
                .p99_ms
                .saturating_sub(self.latency.p99_ms),
            "sandbox_layer": self.sandbox_layer,
            "sandbox_profile": self.sandbox_profile,
            "sandbox_boundary": self.sandbox_boundary,
            "credential_mode": self.credential_mode,
            "rss_bytes": self.rss_bytes,
            "process_count": self.process_count,
            "concurrent_startups": self.concurrent_startups,
            "error_mapping": self.error_mapping,
            "cleanup_result": self.cleanup_result,
            "restart_reason": self.restart_reason,
            "fallback_reason": self.fallback_reason,
            "unsafe_rejection_reason": self.unsafe_rejection_reason,
            "skip_reason": self.skip_reason,
            "shutdown_cleanup_verified": self.shutdown_cleanup_verified,
            "evidence": serde_json::to_value(self)?,
        }))
    }
}

/// Validation error for prewarm cold-start evidence records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwarmPrewarmColdStartEvidenceError {
    /// Schema tag was unsupported.
    SchemaMismatch {
        /// Supported schema.
        expected: String,
        /// Observed schema.
        actual: String,
    },
    /// A required string field was empty.
    EmptyField {
        /// Field name.
        field: &'static str,
    },
    /// Reproduction command line was empty or contained an empty part.
    EmptyCommandLine,
    /// A latency measurement was absent or zero.
    MissingLatencyMeasurement,
    /// Percentiles were absent or out of order.
    InvalidLatencyPercentiles,
    /// Warm path was slower than the on-demand baseline.
    LatencyRegression {
        /// Observed activation latency.
        activation_ms: u64,
        /// Conservative baseline latency.
        baseline_ms: u64,
    },
    /// A required resource field was absent or zero.
    MissingResourceMeasurement {
        /// Field name.
        field: &'static str,
    },
    /// Concurrent startup count was zero.
    EmptyConcurrentStartupCount,
}

impl fmt::Display for SwarmPrewarmColdStartEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaMismatch { expected, actual } => write!(
                f,
                "swarm prewarm schema mismatch: expected '{expected}', got '{actual}'"
            ),
            Self::EmptyField { field } => {
                write!(f, "swarm prewarm field '{field}' is empty")
            }
            Self::EmptyCommandLine => write!(f, "swarm prewarm command line is empty"),
            Self::MissingLatencyMeasurement => {
                write!(f, "swarm prewarm latency measurement is missing")
            }
            Self::InvalidLatencyPercentiles => {
                write!(f, "swarm prewarm latency percentiles are invalid")
            }
            Self::LatencyRegression {
                activation_ms,
                baseline_ms,
            } => write!(
                f,
                "swarm prewarm activation latency {activation_ms} exceeds baseline {baseline_ms}"
            ),
            Self::MissingResourceMeasurement { field } => {
                write!(f, "swarm prewarm resource field '{field}' is missing")
            }
            Self::EmptyConcurrentStartupCount => {
                write!(f, "swarm prewarm concurrent startup count is zero")
            }
        }
    }
}

impl Error for SwarmPrewarmColdStartEvidenceError {}

/// Error raised while rendering prewarm evidence JSONL.
#[derive(Debug)]
pub enum SwarmPrewarmColdStartEvidenceJsonError {
    /// Validation failed.
    Validation(SwarmPrewarmColdStartEvidenceError),
    /// JSON serialization failed.
    Serde(serde_json::Error),
}

impl fmt::Display for SwarmPrewarmColdStartEvidenceJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(err) => write!(f, "{err}"),
            Self::Serde(err) => write!(f, "{err}"),
        }
    }
}

impl Error for SwarmPrewarmColdStartEvidenceJsonError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Validation(err) => Some(err),
            Self::Serde(err) => Some(err),
        }
    }
}

impl From<SwarmPrewarmColdStartEvidenceError> for SwarmPrewarmColdStartEvidenceJsonError {
    fn from(value: SwarmPrewarmColdStartEvidenceError) -> Self {
        Self::Validation(value)
    }
}

impl From<serde_json::Error> for SwarmPrewarmColdStartEvidenceJsonError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serde(value)
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
    /// Optional replay artifact manifest for promoted smoke/soak evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_manifest: Option<SwarmEvidenceArtifactManifest>,
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
            artifact_manifest: None,
            scenarios,
            samples,
            summaries,
        })
    }

    /// Attach and validate a replay artifact manifest.
    ///
    /// # Errors
    ///
    /// Returns a manifest validation error when required fields are missing or stale.
    pub fn with_artifact_manifest(
        mut self,
        artifact_manifest: SwarmEvidenceArtifactManifest,
    ) -> Result<Self, SwarmEvidenceBundleError> {
        artifact_manifest.validate_against_environment(&self.environment)?;
        self.artifact_manifest = Some(artifact_manifest);
        Ok(self)
    }

    /// Render the bundle as typed JSONL records.
    ///
    /// # Errors
    ///
    /// Returns a serde error if any bundle section cannot be converted to JSON.
    pub fn to_jsonl_values(&self) -> Result<Vec<Value>, serde_json::Error> {
        let mut records = Vec::with_capacity(3 + self.scenarios.len() + self.samples.len());
        records.push(json!({
            "record_type": "swarm_latency_bundle",
            "schema_version": self.schema_version,
            "environment": serde_json::to_value(&self.environment)?,
        }));
        if let Some(artifact_manifest) = &self.artifact_manifest {
            records.push(artifact_manifest.to_jsonl_value()?);
        }
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

/// Scenario-level metric snapshot used by swarm regression gates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmRegressionMetricSnapshot {
    /// Scenario identifier.
    pub scenario_id: String,
    /// Raw sample count.
    pub sample_count: usize,
    /// Observed p99 latency in nanoseconds.
    pub p99_ns: u64,
    /// Observed p99.9 latency in nanoseconds.
    pub p999_ns: u64,
    /// Throughput in operations per second.
    pub throughput_ops_per_second: u64,
    /// CPU utilization in microunits, where `1_000_000` is one full core.
    pub cpu_microunits: u64,
    /// Resident set size in bytes.
    pub rss_bytes: u64,
    /// Maximum queue depth observed during the run.
    pub max_queue_depth: u64,
    /// Retry amplification in microunits, where `1_000_000` means one retry per op.
    pub retry_amplification_microunits: u64,
}

impl SwarmRegressionMetricSnapshot {
    /// Build a regression snapshot from a latency summary and side-channel resource metrics.
    #[must_use]
    pub fn from_summary(
        summary: &SwarmLatencySummary,
        resources: SwarmRegressionResourceMetrics,
    ) -> Self {
        Self {
            scenario_id: summary.scenario_id.clone(),
            sample_count: summary.sample_count,
            p99_ns: summary.total.p99_ns,
            p999_ns: summary.total.p999_ns,
            throughput_ops_per_second: resources.throughput_ops_per_second,
            cpu_microunits: resources.cpu_microunits,
            rss_bytes: resources.rss_bytes,
            max_queue_depth: resources.max_queue_depth,
            retry_amplification_microunits: resources.retry_amplification_microunits,
        }
    }

    /// Return a copy with the scenario identifier populated.
    #[must_use]
    pub fn with_scenario_id(mut self, scenario_id: impl Into<String>) -> Self {
        self.scenario_id = scenario_id.into();
        self
    }
}

/// Side-channel resource metrics that complement latency summaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmRegressionResourceMetrics {
    /// Throughput in operations per second.
    pub throughput_ops_per_second: u64,
    /// CPU utilization in microunits, where `1_000_000` is one full core.
    pub cpu_microunits: u64,
    /// Resident set size in bytes.
    pub rss_bytes: u64,
    /// Maximum queue depth observed during the run.
    pub max_queue_depth: u64,
    /// Retry amplification in microunits, where `1_000_000` means one retry per op.
    pub retry_amplification_microunits: u64,
}

/// Thresholds for CI/nightly swarm regression gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmRegressionGateThresholds {
    /// Maximum permitted p99 latency increase.
    pub max_p99_regression_percent: u32,
    /// Maximum permitted p99.9 latency increase.
    pub max_p999_regression_percent: u32,
    /// Minimum retained throughput relative to baseline.
    pub min_throughput_retention_percent: u32,
    /// Maximum permitted CPU utilization increase.
    pub max_cpu_increase_percent: u32,
    /// Maximum permitted RSS increase.
    pub max_rss_increase_percent: u32,
    /// Maximum permitted queue-depth increase.
    pub max_queue_depth_increase_percent: u32,
    /// Maximum permitted retry-amplification increase.
    pub max_retry_amplification_increase_percent: u32,
    /// Minimum candidate sample count.
    pub min_sample_count: usize,
}

impl SwarmRegressionGateThresholds {
    /// PR-friendly smoke thresholds.
    #[must_use]
    pub const fn smoke() -> Self {
        Self {
            max_p99_regression_percent: 5,
            max_p999_regression_percent: 5,
            min_throughput_retention_percent: 95,
            max_cpu_increase_percent: 10,
            max_rss_increase_percent: 10,
            max_queue_depth_increase_percent: 10,
            max_retry_amplification_increase_percent: 10,
            min_sample_count: 1,
        }
    }

    /// Promotion thresholds for retained soak baselines.
    #[must_use]
    pub const fn soak() -> Self {
        Self {
            max_p99_regression_percent: 3,
            max_p999_regression_percent: 3,
            min_throughput_retention_percent: 98,
            max_cpu_increase_percent: 5,
            max_rss_increase_percent: 5,
            max_queue_depth_increase_percent: 5,
            max_retry_amplification_increase_percent: 5,
            min_sample_count: 30,
        }
    }
}

/// Metric class evaluated by a swarm regression gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmRegressionMetricKind {
    /// Scenario identifiers must match.
    ScenarioId,
    /// Candidate sample count must be sufficient.
    SampleCount,
    /// p99 latency must not regress materially.
    P99Latency,
    /// p99.9 latency must not regress materially.
    P999Latency,
    /// Throughput must retain enough of baseline.
    Throughput,
    /// CPU use must not increase materially.
    Cpu,
    /// Resident set size must not increase materially.
    Rss,
    /// Queue depth must not increase materially.
    QueueDepth,
    /// Retry amplification must not increase materially.
    RetryAmplification,
}

/// One failed metric in a swarm regression gate report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmRegressionGateFailure {
    /// Failed metric.
    pub metric: SwarmRegressionMetricKind,
    /// Baseline value.
    pub baseline_value: u64,
    /// Candidate value.
    pub candidate_value: u64,
    /// Threshold-derived allowed value.
    pub allowed_value: u64,
    /// Human-readable reason for operators.
    pub reason: String,
}

/// CI/nightly regression report for one swarm scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmRegressionGateReport {
    /// Report schema version.
    pub schema_version: String,
    /// Scenario under evaluation.
    pub scenario_id: String,
    /// Smoke or soak gate.
    pub execution_mode: SwarmEvidenceExecutionMode,
    /// Baseline metrics.
    pub baseline: SwarmRegressionMetricSnapshot,
    /// Candidate metrics.
    pub candidate: SwarmRegressionMetricSnapshot,
    /// Gate thresholds.
    pub thresholds: SwarmRegressionGateThresholds,
    /// Whether all metrics passed.
    pub passed: bool,
    /// Failed metric details.
    pub failures: Vec<SwarmRegressionGateFailure>,
}

impl SwarmRegressionGateReport {
    /// Evaluate a deterministic swarm regression gate.
    #[must_use]
    pub fn evaluate(
        baseline: SwarmRegressionMetricSnapshot,
        candidate: SwarmRegressionMetricSnapshot,
        thresholds: SwarmRegressionGateThresholds,
        execution_mode: SwarmEvidenceExecutionMode,
    ) -> Self {
        let mut failures = Vec::new();
        if baseline.scenario_id != candidate.scenario_id {
            failures.push(SwarmRegressionGateFailure {
                metric: SwarmRegressionMetricKind::ScenarioId,
                baseline_value: 0,
                candidate_value: 0,
                allowed_value: 0,
                reason: format!(
                    "candidate scenario '{}' does not match baseline '{}'",
                    candidate.scenario_id, baseline.scenario_id
                ),
            });
        }
        let min_sample_count = u64::try_from(thresholds.min_sample_count).unwrap_or(u64::MAX);
        if u64::try_from(candidate.sample_count).unwrap_or(u64::MAX) < min_sample_count {
            failures.push(SwarmRegressionGateFailure {
                metric: SwarmRegressionMetricKind::SampleCount,
                baseline_value: u64::try_from(baseline.sample_count).unwrap_or(u64::MAX),
                candidate_value: u64::try_from(candidate.sample_count).unwrap_or(u64::MAX),
                allowed_value: min_sample_count,
                reason: "candidate sample count is below gate minimum".to_string(),
            });
        }
        push_upper_bound_failure(
            &mut failures,
            SwarmRegressionMetricKind::P99Latency,
            baseline.p99_ns,
            candidate.p99_ns,
            thresholds.max_p99_regression_percent,
            "candidate p99 latency exceeded regression budget",
        );
        push_upper_bound_failure(
            &mut failures,
            SwarmRegressionMetricKind::P999Latency,
            baseline.p999_ns,
            candidate.p999_ns,
            thresholds.max_p999_regression_percent,
            "candidate p999 latency exceeded regression budget",
        );
        push_throughput_failure(
            &mut failures,
            baseline.throughput_ops_per_second,
            candidate.throughput_ops_per_second,
            thresholds.min_throughput_retention_percent,
        );
        push_upper_bound_failure(
            &mut failures,
            SwarmRegressionMetricKind::Cpu,
            baseline.cpu_microunits,
            candidate.cpu_microunits,
            thresholds.max_cpu_increase_percent,
            "candidate CPU utilization exceeded regression budget",
        );
        push_upper_bound_failure(
            &mut failures,
            SwarmRegressionMetricKind::Rss,
            baseline.rss_bytes,
            candidate.rss_bytes,
            thresholds.max_rss_increase_percent,
            "candidate RSS exceeded regression budget",
        );
        push_upper_bound_failure(
            &mut failures,
            SwarmRegressionMetricKind::QueueDepth,
            baseline.max_queue_depth,
            candidate.max_queue_depth,
            thresholds.max_queue_depth_increase_percent,
            "candidate queue depth exceeded regression budget",
        );
        push_upper_bound_failure(
            &mut failures,
            SwarmRegressionMetricKind::RetryAmplification,
            baseline.retry_amplification_microunits,
            candidate.retry_amplification_microunits,
            thresholds.max_retry_amplification_increase_percent,
            "candidate retry amplification exceeded regression budget",
        );

        Self {
            schema_version: SWARM_REGRESSION_GATE_SCHEMA_VERSION.to_string(),
            scenario_id: candidate.scenario_id.clone(),
            execution_mode,
            baseline,
            candidate,
            thresholds,
            passed: failures.is_empty(),
            failures,
        }
    }

    /// Render as a typed JSONL record.
    ///
    /// # Errors
    ///
    /// Returns a serde error if the report cannot be converted to JSON.
    pub fn to_jsonl_value(&self) -> Result<Value, serde_json::Error> {
        Ok(json!({
            "record_type": "swarm_regression_gate_report",
            "schema_version": self.schema_version,
            "report": serde_json::to_value(self)?,
        }))
    }
}

fn push_upper_bound_failure(
    failures: &mut Vec<SwarmRegressionGateFailure>,
    metric: SwarmRegressionMetricKind,
    baseline_value: u64,
    candidate_value: u64,
    max_increase_percent: u32,
    reason: &str,
) {
    let allowed_value = increase_limit(baseline_value, max_increase_percent);
    if candidate_value > allowed_value {
        failures.push(SwarmRegressionGateFailure {
            metric,
            baseline_value,
            candidate_value,
            allowed_value,
            reason: reason.to_string(),
        });
    }
}

fn push_throughput_failure(
    failures: &mut Vec<SwarmRegressionGateFailure>,
    baseline_value: u64,
    candidate_value: u64,
    min_retention_percent: u32,
) {
    let allowed_value = retention_floor(baseline_value, min_retention_percent);
    if candidate_value < allowed_value {
        failures.push(SwarmRegressionGateFailure {
            metric: SwarmRegressionMetricKind::Throughput,
            baseline_value,
            candidate_value,
            allowed_value,
            reason: "candidate throughput fell below retention budget".to_string(),
        });
    }
}

fn increase_limit(baseline_value: u64, max_increase_percent: u32) -> u64 {
    let scaled = u128::from(baseline_value)
        .saturating_mul(u128::from(100_u32.saturating_add(max_increase_percent)));
    u64::try_from(scaled.saturating_add(99) / 100).unwrap_or(u64::MAX)
}

fn retention_floor(baseline_value: u64, min_retention_percent: u32) -> u64 {
    let scaled = u128::from(baseline_value).saturating_mul(u128::from(min_retention_percent));
    u64::try_from(scaled.saturating_add(99) / 100).unwrap_or(u64::MAX)
}

/// Retained baseline path that must be represented before promoting a swarm baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmBaselinePathKind {
    /// PR-friendly offline or host-backed smoke path.
    Smoke,
    /// Long-running soak path.
    Soak,
    /// Direct LAN mesh invocation path.
    DirectLan,
    /// DERP or fallback mesh invocation path.
    DerpFallback,
    /// Scheduler decision-card replay path.
    Scheduler,
    /// Placement decision-card replay path.
    Placement,
    /// Backpressure and retry-amplification path.
    Backpressure,
    /// Audit append and loss-detection path.
    Audit,
    /// Sparse/high-K store allocation path.
    StoreAllocation,
}

impl SwarmBaselinePathKind {
    /// Required retained baseline coverage in stable manifest order.
    pub const REQUIRED: [Self; 9] = [
        Self::Smoke,
        Self::Soak,
        Self::DirectLan,
        Self::DerpFallback,
        Self::Scheduler,
        Self::Placement,
        Self::Backpressure,
        Self::Audit,
        Self::StoreAllocation,
    ];

    /// Stable machine label for this baseline path.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Soak => "soak",
            Self::DirectLan => "direct_lan",
            Self::DerpFallback => "derp_fallback",
            Self::Scheduler => "scheduler",
            Self::Placement => "placement",
            Self::Backpressure => "backpressure",
            Self::Audit => "audit",
            Self::StoreAllocation => "store_allocation",
        }
    }
}

/// Content digests required to promote and later replay a swarm baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmBaselineArtifactDigests {
    /// Digest of retained raw per-operation samples.
    pub raw_sample_digest: String,
    /// Digest of scenario summary JSON.
    pub summary_digest: String,
    /// Digest of the gate report that promoted this baseline.
    pub gate_report_digest: String,
    /// Digest of operator proof notes.
    pub proof_notes_digest: String,
    /// Digest of the artifact manifest.
    pub artifact_manifest_digest: String,
}

impl SwarmBaselineArtifactDigests {
    /// Construct baseline artifact digests.
    #[must_use]
    pub fn new(
        raw_sample_digest: impl Into<String>,
        summary_digest: impl Into<String>,
        gate_report_digest: impl Into<String>,
        proof_notes_digest: impl Into<String>,
        artifact_manifest_digest: impl Into<String>,
    ) -> Self {
        Self {
            raw_sample_digest: raw_sample_digest.into(),
            summary_digest: summary_digest.into(),
            gate_report_digest: gate_report_digest.into(),
            proof_notes_digest: proof_notes_digest.into(),
            artifact_manifest_digest: artifact_manifest_digest.into(),
        }
    }

    fn validate(&self) -> Result<(), SwarmBaselinePromotionError> {
        for (field, value) in [
            ("raw_sample_digest", self.raw_sample_digest.as_str()),
            ("summary_digest", self.summary_digest.as_str()),
            ("gate_report_digest", self.gate_report_digest.as_str()),
            ("proof_notes_digest", self.proof_notes_digest.as_str()),
            (
                "artifact_manifest_digest",
                self.artifact_manifest_digest.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(SwarmBaselinePromotionError::EmptyField { field });
            }
        }
        Ok(())
    }
}

/// Manifest for a retained swarm baseline that is safe to compare against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmBaselinePromotionManifest {
    /// Manifest schema version.
    pub schema_version: String,
    /// Stable baseline identifier.
    pub baseline_id: String,
    /// Scenario this baseline represents.
    pub scenario_id: String,
    /// Smoke or soak baseline class.
    pub execution_mode: SwarmEvidenceExecutionMode,
    /// Source revision that produced the promoted baseline.
    pub source_revision: String,
    /// Worker that produced the promoted baseline.
    pub rch_worker_id: String,
    /// Required retained baseline paths covered by the promotion bundle.
    pub required_paths: Vec<SwarmBaselinePathKind>,
    /// Content digests required for replay and audit.
    pub artifact_digests: SwarmBaselineArtifactDigests,
    /// Redaction policy applied to retained artifacts.
    pub redaction_policy: SwarmEvidenceRedactionPolicy,
    /// Operator-readable proof notes summary.
    pub operator_notes: String,
    /// Promotion timestamp.
    pub promoted_at: DateTime<Utc>,
    /// Expiration timestamp after which the baseline must be regenerated.
    pub expires_at: DateTime<Utc>,
}

impl SwarmBaselinePromotionManifest {
    /// Validate the baseline promotion manifest in isolation.
    ///
    /// # Errors
    ///
    /// Returns a structured error when the manifest is incomplete, stale, or
    /// missing mandatory replay artifacts.
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), SwarmBaselinePromotionError> {
        if self.schema_version != SWARM_BASELINE_PROMOTION_SCHEMA_VERSION {
            return Err(SwarmBaselinePromotionError::SchemaMismatch {
                expected: SWARM_BASELINE_PROMOTION_SCHEMA_VERSION.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        for (field, value) in [
            ("baseline_id", self.baseline_id.as_str()),
            ("scenario_id", self.scenario_id.as_str()),
            ("source_revision", self.source_revision.as_str()),
            ("rch_worker_id", self.rch_worker_id.as_str()),
            ("operator_notes", self.operator_notes.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(SwarmBaselinePromotionError::EmptyField { field });
            }
        }
        self.artifact_digests.validate()?;
        let observed_paths: BTreeSet<_> = self.required_paths.iter().copied().collect();
        for path in SwarmBaselinePathKind::REQUIRED {
            if !observed_paths.contains(&path) {
                return Err(SwarmBaselinePromotionError::MissingRequiredPath { path });
            }
        }
        if !self.redaction_policy.protects_exported_artifacts() {
            return Err(SwarmBaselinePromotionError::RedactionPolicyIncomplete);
        }
        if now >= self.expires_at {
            return Err(SwarmBaselinePromotionError::StaleBaseline {
                expires_at: self.expires_at,
                now,
            });
        }
        Ok(())
    }

    /// Validate compatibility with the candidate scenario and execution mode.
    ///
    /// # Errors
    ///
    /// Returns a structured error when the candidate cannot be compared against
    /// this baseline.
    pub fn validate_compatibility(
        &self,
        scenario_id: &str,
        execution_mode: SwarmEvidenceExecutionMode,
    ) -> Result<(), SwarmBaselinePromotionError> {
        if self.scenario_id != scenario_id {
            return Err(SwarmBaselinePromotionError::ScenarioMismatch {
                expected: self.scenario_id.clone(),
                actual: scenario_id.to_string(),
            });
        }
        if self.execution_mode != execution_mode {
            return Err(SwarmBaselinePromotionError::ExecutionModeMismatch {
                expected: self.execution_mode,
                actual: execution_mode,
            });
        }
        Ok(())
    }

    /// Render the baseline manifest as a typed JSONL record.
    ///
    /// # Errors
    ///
    /// Returns a serde error if the manifest cannot be converted to JSON.
    pub fn to_jsonl_value(&self) -> Result<Value, serde_json::Error> {
        Ok(json!({
            "record_type": "swarm_baseline_promotion_manifest",
            "schema_version": self.schema_version,
            "baseline_id": self.baseline_id,
            "scenario_id": self.scenario_id,
            "raw_sample_digest": self.artifact_digests.raw_sample_digest,
            "summary_digest": self.artifact_digests.summary_digest,
            "gate_report_digest": self.artifact_digests.gate_report_digest,
            "proof_notes_digest": self.artifact_digests.proof_notes_digest,
            "artifact_manifest_digest": self.artifact_digests.artifact_manifest_digest,
            "redaction_policy": serde_json::to_value(&self.redaction_policy)?,
            "manifest": serde_json::to_value(self)?,
        }))
    }
}

/// Validation error for retained swarm baseline promotion manifests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwarmBaselinePromotionError {
    /// Schema tag was unsupported.
    SchemaMismatch {
        /// Expected schema.
        expected: String,
        /// Observed schema.
        actual: String,
    },
    /// Required text field was empty.
    EmptyField {
        /// Field name.
        field: &'static str,
    },
    /// Required retained path was absent.
    MissingRequiredPath {
        /// Missing path kind.
        path: SwarmBaselinePathKind,
    },
    /// Redaction policy is not sufficient for retained artifacts.
    RedactionPolicyIncomplete,
    /// Baseline has expired and must be regenerated.
    StaleBaseline {
        /// Expiration timestamp.
        expires_at: DateTime<Utc>,
        /// Evaluation timestamp.
        now: DateTime<Utc>,
    },
    /// Candidate scenario does not match the baseline.
    ScenarioMismatch {
        /// Baseline scenario.
        expected: String,
        /// Candidate scenario.
        actual: String,
    },
    /// Candidate execution mode does not match the baseline.
    ExecutionModeMismatch {
        /// Baseline mode.
        expected: SwarmEvidenceExecutionMode,
        /// Candidate mode.
        actual: SwarmEvidenceExecutionMode,
    },
}

impl fmt::Display for SwarmBaselinePromotionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaMismatch { expected, actual } => write!(
                f,
                "swarm baseline schema mismatch: expected '{expected}', got '{actual}'"
            ),
            Self::EmptyField { field } => write!(f, "swarm baseline field '{field}' is empty"),
            Self::MissingRequiredPath { path } => {
                write!(
                    f,
                    "swarm baseline missing required path '{}'",
                    path.as_str()
                )
            }
            Self::RedactionPolicyIncomplete => {
                write!(f, "swarm baseline redaction policy is incomplete")
            }
            Self::StaleBaseline { expires_at, now } => {
                write!(
                    f,
                    "swarm baseline expired at {expires_at}, evaluated at {now}"
                )
            }
            Self::ScenarioMismatch { expected, actual } => write!(
                f,
                "swarm baseline scenario mismatch: expected '{expected}', got '{actual}'"
            ),
            Self::ExecutionModeMismatch { expected, actual } => write!(
                f,
                "swarm baseline execution mode mismatch: expected '{}', got '{}'",
                expected.as_str(),
                actual.as_str()
            ),
        }
    }
}

impl Error for SwarmBaselinePromotionError {}

/// Trace-quality limits for statistical swarm gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmStatisticalGateTuning {
    /// Minimum samples required in both baseline and candidate traces.
    pub min_sample_count: usize,
    /// Minimum percent effect required before a deterministic breach becomes a regression.
    pub min_effect_percent: u32,
    /// Maximum tolerated worker drift before quarantining the run.
    pub max_worker_drift_percent: u32,
    /// Maximum tolerated bootstrap confidence band width.
    pub max_bootstrap_band_percent: u32,
    /// Maximum tolerated warmup sample share.
    pub max_warmup_sample_percent: u32,
    /// Maximum tolerated outlier sample share.
    pub max_outlier_sample_percent: u32,
}

impl SwarmStatisticalGateTuning {
    /// PR-friendly statistical gate tuning.
    #[must_use]
    pub const fn smoke() -> Self {
        Self {
            min_sample_count: 30,
            min_effect_percent: 2,
            max_worker_drift_percent: 10,
            max_bootstrap_band_percent: 8,
            max_warmup_sample_percent: 10,
            max_outlier_sample_percent: 5,
        }
    }

    /// Promotion tuning for retained soak baselines.
    #[must_use]
    pub const fn soak() -> Self {
        Self {
            min_sample_count: 100,
            min_effect_percent: 1,
            max_worker_drift_percent: 5,
            max_bootstrap_band_percent: 4,
            max_warmup_sample_percent: 5,
            max_outlier_sample_percent: 2,
        }
    }
}

/// Quality summary for one baseline or candidate trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmStatisticalTraceQuality {
    /// Total retained samples.
    pub sample_count: usize,
    /// Samples discarded as warmup.
    pub warmup_sample_count: usize,
    /// Samples classified as outliers.
    pub outlier_sample_count: usize,
    /// Bootstrap confidence band width around p99, as percent of p99.
    pub bootstrap_p99_band_percent: u32,
    /// Bootstrap confidence band width around p999, as percent of p999.
    pub bootstrap_p999_band_percent: u32,
    /// Worker/topology drift against the promoted baseline.
    pub worker_drift_percent: u32,
}

impl SwarmStatisticalTraceQuality {
    /// Controlled deterministic trace with narrow confidence bands and no discarded samples.
    #[must_use]
    pub const fn controlled(sample_count: usize) -> Self {
        Self {
            sample_count,
            warmup_sample_count: 0,
            outlier_sample_count: 0,
            bootstrap_p99_band_percent: 1,
            bootstrap_p999_band_percent: 1,
            worker_drift_percent: 0,
        }
    }
}

/// Statistical gate outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmStatisticalGateOutcome {
    /// Evidence is compatible and no meaningful regression was detected.
    Pass,
    /// Evidence is compatible and a meaningful regression was detected.
    Fail,
    /// Evidence is insufficient or noisy, so the run must not promote or fail code.
    Indeterminate,
}

impl SwarmStatisticalGateOutcome {
    /// Stable machine label for this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// Machine-readable reason attached to a statistical gate outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmStatisticalGateReasonKind {
    /// Baseline cannot be compared with this candidate.
    BaselineIncompatible,
    /// Baseline has expired.
    StaleBaseline,
    /// Baseline or candidate has too few samples.
    LowSampleCount,
    /// Worker drift is high enough to quarantine the run.
    NoisyWorker,
    /// Bootstrap confidence band is too wide.
    WideBootstrapBand,
    /// Warmup discard share is too high.
    WarmupBudgetExceeded,
    /// Outlier share is too high.
    OutlierBudgetExceeded,
    /// A deterministic breach was below the configured minimum effect size.
    BelowMinimumEffectSize,
    /// p99 latency regressed materially.
    P99Regression,
    /// p99.9 latency regressed materially.
    P999Regression,
    /// Throughput regressed materially.
    ThroughputRegression,
    /// CPU use regressed materially.
    CpuRegression,
    /// RSS regressed materially.
    RssRegression,
    /// Queue depth regressed materially.
    QueueDepthRegression,
    /// Retry amplification regressed materially.
    RetryAmplificationRegression,
    /// Audit evidence was absent or lost.
    AuditLoss,
    /// Decision-card replay disagreed with the candidate run.
    DecisionCardReplayMismatch,
}

impl SwarmStatisticalGateReasonKind {
    /// Stable machine reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BaselineIncompatible => "baseline_incompatible",
            Self::StaleBaseline => "stale_baseline",
            Self::LowSampleCount => "low_sample_count",
            Self::NoisyWorker => "noisy_worker",
            Self::WideBootstrapBand => "wide_bootstrap_band",
            Self::WarmupBudgetExceeded => "warmup_budget_exceeded",
            Self::OutlierBudgetExceeded => "outlier_budget_exceeded",
            Self::BelowMinimumEffectSize => "below_minimum_effect_size",
            Self::P99Regression => "p99_regression",
            Self::P999Regression => "p999_regression",
            Self::ThroughputRegression => "throughput_regression",
            Self::CpuRegression => "cpu_regression",
            Self::RssRegression => "rss_regression",
            Self::QueueDepthRegression => "queue_depth_regression",
            Self::RetryAmplificationRegression => "retry_amplification_regression",
            Self::AuditLoss => "audit_loss",
            Self::DecisionCardReplayMismatch => "decision_card_replay_mismatch",
        }
    }

    const fn is_indeterminate(self) -> bool {
        matches!(
            self,
            Self::BaselineIncompatible
                | Self::StaleBaseline
                | Self::LowSampleCount
                | Self::NoisyWorker
                | Self::WideBootstrapBand
                | Self::WarmupBudgetExceeded
                | Self::OutlierBudgetExceeded
                | Self::BelowMinimumEffectSize
        )
    }
}

/// One reason emitted by a statistical swarm gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmStatisticalGateReason {
    /// Machine-readable reason kind.
    pub kind: SwarmStatisticalGateReasonKind,
    /// Metric involved, when applicable.
    pub metric: Option<SwarmRegressionMetricKind>,
    /// Human-readable operator note.
    pub message: String,
    /// Baseline value for metric reasons.
    pub baseline_value: Option<u64>,
    /// Candidate value for metric reasons.
    pub candidate_value: Option<u64>,
    /// Allowed value for metric reasons.
    pub allowed_value: Option<u64>,
    /// Observed effect size as an integer percent.
    pub effect_percent: Option<u32>,
}

impl SwarmStatisticalGateReason {
    fn indeterminate(kind: SwarmStatisticalGateReasonKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            metric: None,
            message: message.into(),
            baseline_value: None,
            candidate_value: None,
            allowed_value: None,
            effect_percent: None,
        }
    }

    fn metric_reason(
        kind: SwarmStatisticalGateReasonKind,
        metric: SwarmRegressionMetricKind,
        failure: &SwarmRegressionGateFailure,
        effect_percent: Option<u32>,
    ) -> Self {
        Self {
            kind,
            metric: Some(metric),
            message: failure.reason.clone(),
            baseline_value: Some(failure.baseline_value),
            candidate_value: Some(failure.candidate_value),
            allowed_value: Some(failure.allowed_value),
            effect_percent,
        }
    }
}

/// Input bundle for evaluating a statistical swarm gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmStatisticalGateInput {
    /// Promoted baseline manifest.
    pub baseline_manifest: SwarmBaselinePromotionManifest,
    /// Baseline metric snapshot.
    pub baseline: SwarmRegressionMetricSnapshot,
    /// Candidate metric snapshot.
    pub candidate: SwarmRegressionMetricSnapshot,
    /// Deterministic metric thresholds.
    pub thresholds: SwarmRegressionGateThresholds,
    /// Smoke or soak gate mode.
    pub execution_mode: SwarmEvidenceExecutionMode,
    /// Statistical and noise limits.
    pub tuning: SwarmStatisticalGateTuning,
    /// Baseline trace quality summary.
    pub baseline_quality: SwarmStatisticalTraceQuality,
    /// Candidate trace quality summary.
    pub candidate_quality: SwarmStatisticalTraceQuality,
    /// Candidate audit events retained in the evidence log.
    pub audit_event_count: u64,
    /// Whether decision-card replay matched the candidate run.
    pub decision_card_replay_matches: bool,
    /// Operator-readable proof summary.
    pub operator_notes: String,
    /// Evaluation timestamp.
    pub generated_at: DateTime<Utc>,
}

/// Statistical wrapper around deterministic swarm regression gates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmStatisticalGateReport {
    /// Report schema version.
    pub schema_version: String,
    /// Scenario under evaluation.
    pub scenario_id: String,
    /// Smoke or soak gate.
    pub execution_mode: SwarmEvidenceExecutionMode,
    /// Promoted baseline manifest.
    pub baseline_manifest: SwarmBaselinePromotionManifest,
    /// Baseline metrics.
    pub baseline: SwarmRegressionMetricSnapshot,
    /// Candidate metrics.
    pub candidate: SwarmRegressionMetricSnapshot,
    /// Deterministic thresholds.
    pub thresholds: SwarmRegressionGateThresholds,
    /// Statistical tuning.
    pub tuning: SwarmStatisticalGateTuning,
    /// Baseline trace quality.
    pub baseline_quality: SwarmStatisticalTraceQuality,
    /// Candidate trace quality.
    pub candidate_quality: SwarmStatisticalTraceQuality,
    /// Underlying deterministic regression report.
    pub deterministic_report: SwarmRegressionGateReport,
    /// Final statistical outcome.
    pub outcome: SwarmStatisticalGateOutcome,
    /// Machine-readable reasons for fail or indeterminate outcomes.
    pub reasons: Vec<SwarmStatisticalGateReason>,
    /// Candidate audit events retained in the evidence log.
    pub audit_event_count: u64,
    /// Whether decision-card replay matched the candidate run.
    pub decision_card_replay_matches: bool,
    /// Operator-readable proof summary.
    pub operator_notes: String,
    /// Evaluation timestamp.
    pub generated_at: DateTime<Utc>,
}

impl SwarmStatisticalGateReport {
    /// Evaluate a statistical swarm gate from a promoted baseline and candidate trace.
    #[must_use]
    pub fn evaluate(input: SwarmStatisticalGateInput) -> Self {
        let deterministic_report = SwarmRegressionGateReport::evaluate(
            input.baseline.clone(),
            input.candidate.clone(),
            input.thresholds,
            input.execution_mode,
        );
        let mut reasons = Vec::new();
        if let Err(err) = input.baseline_manifest.validate(input.generated_at) {
            reasons.push(baseline_error_reason(&err));
        }
        if let Err(err) = input
            .baseline_manifest
            .validate_compatibility(&input.candidate.scenario_id, input.execution_mode)
        {
            reasons.push(baseline_error_reason(&err));
        }
        push_quality_reasons(
            &mut reasons,
            "baseline",
            input.baseline_quality,
            input.tuning,
        );
        push_quality_reasons(
            &mut reasons,
            "candidate",
            input.candidate_quality,
            input.tuning,
        );
        if input.audit_event_count == 0 {
            reasons.push(SwarmStatisticalGateReason::indeterminate(
                SwarmStatisticalGateReasonKind::AuditLoss,
                "candidate evidence did not retain audit events",
            ));
        }
        if !input.decision_card_replay_matches {
            reasons.push(SwarmStatisticalGateReason::indeterminate(
                SwarmStatisticalGateReasonKind::DecisionCardReplayMismatch,
                "candidate decision-card replay did not match retained decisions",
            ));
        }
        for failure in &deterministic_report.failures {
            reasons.push(statistical_reason_for_failure(
                failure,
                input.tuning.min_effect_percent,
            ));
        }
        let outcome = statistical_outcome(&reasons);

        Self {
            schema_version: SWARM_STATISTICAL_GATE_SCHEMA_VERSION.to_string(),
            scenario_id: input.candidate.scenario_id.clone(),
            execution_mode: input.execution_mode,
            baseline_manifest: input.baseline_manifest,
            baseline: input.baseline,
            candidate: input.candidate,
            thresholds: input.thresholds,
            tuning: input.tuning,
            baseline_quality: input.baseline_quality,
            candidate_quality: input.candidate_quality,
            deterministic_report,
            outcome,
            reasons,
            audit_event_count: input.audit_event_count,
            decision_card_replay_matches: input.decision_card_replay_matches,
            operator_notes: input.operator_notes,
            generated_at: input.generated_at,
        }
    }

    /// Render the baseline manifest and gate report as typed JSONL records.
    ///
    /// # Errors
    ///
    /// Returns a serde error if the records cannot be converted to JSON.
    pub fn to_jsonl_values(&self) -> Result<Vec<Value>, serde_json::Error> {
        Ok(vec![
            self.baseline_manifest.to_jsonl_value()?,
            json!({
                "record_type": "swarm_statistical_gate_report",
                "schema_version": self.schema_version,
                "scenario_id": self.scenario_id,
                "outcome": self.outcome.as_str(),
                "reason_codes": self.reasons.iter().map(|reason| reason.kind.code()).collect::<Vec<_>>(),
                "baseline_id": self.baseline_manifest.baseline_id,
                "raw_sample_digest": self.baseline_manifest.artifact_digests.raw_sample_digest,
                "summary_digest": self.baseline_manifest.artifact_digests.summary_digest,
                "gate_report_digest": self.baseline_manifest.artifact_digests.gate_report_digest,
                "proof_notes_digest": self.baseline_manifest.artifact_digests.proof_notes_digest,
                "redaction_policy": serde_json::to_value(&self.baseline_manifest.redaction_policy)?,
                "report": serde_json::to_value(self)?,
            }),
        ])
    }
}

fn baseline_error_reason(err: &SwarmBaselinePromotionError) -> SwarmStatisticalGateReason {
    let kind = match err {
        SwarmBaselinePromotionError::StaleBaseline { .. } => {
            SwarmStatisticalGateReasonKind::StaleBaseline
        }
        SwarmBaselinePromotionError::SchemaMismatch { .. }
        | SwarmBaselinePromotionError::EmptyField { .. }
        | SwarmBaselinePromotionError::MissingRequiredPath { .. }
        | SwarmBaselinePromotionError::RedactionPolicyIncomplete
        | SwarmBaselinePromotionError::ScenarioMismatch { .. }
        | SwarmBaselinePromotionError::ExecutionModeMismatch { .. } => {
            SwarmStatisticalGateReasonKind::BaselineIncompatible
        }
    };
    SwarmStatisticalGateReason::indeterminate(kind, err.to_string())
}

fn push_quality_reasons(
    reasons: &mut Vec<SwarmStatisticalGateReason>,
    scope: &str,
    quality: SwarmStatisticalTraceQuality,
    tuning: SwarmStatisticalGateTuning,
) {
    let min_sample_count = u64::try_from(tuning.min_sample_count).unwrap_or(u64::MAX);
    if quality.sample_count < tuning.min_sample_count {
        reasons.push(SwarmStatisticalGateReason {
            kind: SwarmStatisticalGateReasonKind::LowSampleCount,
            metric: Some(SwarmRegressionMetricKind::SampleCount),
            message: format!("{scope} trace sample count is below statistical minimum"),
            baseline_value: None,
            candidate_value: Some(u64::try_from(quality.sample_count).unwrap_or(u64::MAX)),
            allowed_value: Some(min_sample_count),
            effect_percent: None,
        });
    }
    if quality.worker_drift_percent > tuning.max_worker_drift_percent {
        reasons.push(SwarmStatisticalGateReason {
            kind: SwarmStatisticalGateReasonKind::NoisyWorker,
            metric: None,
            message: format!("{scope} worker drift exceeds quarantine budget"),
            baseline_value: None,
            candidate_value: Some(u64::from(quality.worker_drift_percent)),
            allowed_value: Some(u64::from(tuning.max_worker_drift_percent)),
            effect_percent: Some(quality.worker_drift_percent),
        });
    }
    push_bootstrap_band_reason(
        reasons,
        scope,
        SwarmRegressionMetricKind::P99Latency,
        quality.bootstrap_p99_band_percent,
        tuning.max_bootstrap_band_percent,
    );
    push_bootstrap_band_reason(
        reasons,
        scope,
        SwarmRegressionMetricKind::P999Latency,
        quality.bootstrap_p999_band_percent,
        tuning.max_bootstrap_band_percent,
    );
    let warmup_percent = percentage_ceil(quality.warmup_sample_count, quality.sample_count);
    if warmup_percent > tuning.max_warmup_sample_percent {
        reasons.push(SwarmStatisticalGateReason {
            kind: SwarmStatisticalGateReasonKind::WarmupBudgetExceeded,
            metric: None,
            message: format!("{scope} warmup discard share exceeds budget"),
            baseline_value: None,
            candidate_value: Some(u64::from(warmup_percent)),
            allowed_value: Some(u64::from(tuning.max_warmup_sample_percent)),
            effect_percent: Some(warmup_percent),
        });
    }
    let outlier_percent = percentage_ceil(quality.outlier_sample_count, quality.sample_count);
    if outlier_percent > tuning.max_outlier_sample_percent {
        reasons.push(SwarmStatisticalGateReason {
            kind: SwarmStatisticalGateReasonKind::OutlierBudgetExceeded,
            metric: None,
            message: format!("{scope} outlier share exceeds budget"),
            baseline_value: None,
            candidate_value: Some(u64::from(outlier_percent)),
            allowed_value: Some(u64::from(tuning.max_outlier_sample_percent)),
            effect_percent: Some(outlier_percent),
        });
    }
}

fn push_bootstrap_band_reason(
    reasons: &mut Vec<SwarmStatisticalGateReason>,
    scope: &str,
    metric: SwarmRegressionMetricKind,
    band_percent: u32,
    max_band_percent: u32,
) {
    if band_percent > max_band_percent {
        reasons.push(SwarmStatisticalGateReason {
            kind: SwarmStatisticalGateReasonKind::WideBootstrapBand,
            metric: Some(metric),
            message: format!("{scope} bootstrap confidence band is too wide"),
            baseline_value: None,
            candidate_value: Some(u64::from(band_percent)),
            allowed_value: Some(u64::from(max_band_percent)),
            effect_percent: Some(band_percent),
        });
    }
}

fn statistical_reason_for_failure(
    failure: &SwarmRegressionGateFailure,
    min_effect_percent: u32,
) -> SwarmStatisticalGateReason {
    let effect_percent = regression_effect_percent(failure);
    let fail_kind = match failure.metric {
        SwarmRegressionMetricKind::ScenarioId => {
            return SwarmStatisticalGateReason::metric_reason(
                SwarmStatisticalGateReasonKind::BaselineIncompatible,
                failure.metric,
                failure,
                None,
            );
        }
        SwarmRegressionMetricKind::SampleCount => {
            return SwarmStatisticalGateReason::metric_reason(
                SwarmStatisticalGateReasonKind::LowSampleCount,
                failure.metric,
                failure,
                None,
            );
        }
        SwarmRegressionMetricKind::P99Latency => SwarmStatisticalGateReasonKind::P99Regression,
        SwarmRegressionMetricKind::P999Latency => SwarmStatisticalGateReasonKind::P999Regression,
        SwarmRegressionMetricKind::Throughput => {
            SwarmStatisticalGateReasonKind::ThroughputRegression
        }
        SwarmRegressionMetricKind::Cpu => SwarmStatisticalGateReasonKind::CpuRegression,
        SwarmRegressionMetricKind::Rss => SwarmStatisticalGateReasonKind::RssRegression,
        SwarmRegressionMetricKind::QueueDepth => {
            SwarmStatisticalGateReasonKind::QueueDepthRegression
        }
        SwarmRegressionMetricKind::RetryAmplification => {
            SwarmStatisticalGateReasonKind::RetryAmplificationRegression
        }
    };
    let kind = if effect_percent.unwrap_or_default() < min_effect_percent {
        SwarmStatisticalGateReasonKind::BelowMinimumEffectSize
    } else {
        fail_kind
    };
    SwarmStatisticalGateReason::metric_reason(kind, failure.metric, failure, effect_percent)
}

fn regression_effect_percent(failure: &SwarmRegressionGateFailure) -> Option<u32> {
    match failure.metric {
        SwarmRegressionMetricKind::Throughput => {
            if failure.baseline_value == 0 || failure.candidate_value >= failure.baseline_value {
                Some(0)
            } else {
                Some(percent_delta(
                    failure.baseline_value - failure.candidate_value,
                    failure.baseline_value,
                ))
            }
        }
        SwarmRegressionMetricKind::ScenarioId | SwarmRegressionMetricKind::SampleCount => None,
        SwarmRegressionMetricKind::P99Latency
        | SwarmRegressionMetricKind::P999Latency
        | SwarmRegressionMetricKind::Cpu
        | SwarmRegressionMetricKind::Rss
        | SwarmRegressionMetricKind::QueueDepth
        | SwarmRegressionMetricKind::RetryAmplification => {
            if failure.baseline_value == 0 || failure.candidate_value <= failure.baseline_value {
                Some(0)
            } else {
                Some(percent_delta(
                    failure.candidate_value - failure.baseline_value,
                    failure.baseline_value,
                ))
            }
        }
    }
}

fn statistical_outcome(reasons: &[SwarmStatisticalGateReason]) -> SwarmStatisticalGateOutcome {
    if reasons.iter().any(|reason| reason.kind.is_indeterminate()) {
        SwarmStatisticalGateOutcome::Indeterminate
    } else if reasons.is_empty() {
        SwarmStatisticalGateOutcome::Pass
    } else {
        SwarmStatisticalGateOutcome::Fail
    }
}

fn percentage_ceil(part: usize, total: usize) -> u32 {
    if total == 0 {
        return 0;
    }
    let scaled = (part as u128).saturating_mul(100);
    u32::try_from(scaled.saturating_add(total as u128 - 1) / total as u128).unwrap_or(u32::MAX)
}

fn percent_delta(delta: u64, baseline: u64) -> u32 {
    if baseline == 0 {
        return u32::MAX;
    }
    let scaled = u128::from(delta).saturating_mul(100);
    u32::try_from(scaled / u128::from(baseline)).unwrap_or(u32::MAX)
}

// ─────────────────────────────────────────────────────────────────────────────
// Swarm decision cards
// ─────────────────────────────────────────────────────────────────────────────

/// Schema tag for operator-facing adaptive decision cards.
pub const SWARM_DECISION_CARD_SCHEMA_VERSION: &str = "swarm-decision-card/v1";

/// Adaptive subsystem that produced a decision card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmDecisionDomain {
    /// Host invoke scheduling or dispatch policy.
    Scheduler,
    /// Connector, task, or resource-pool placement policy.
    Placement,
    /// Admission, throttling, shedding, or retry backpressure policy.
    Backpressure,
}

impl SwarmDecisionDomain {
    /// Stable machine label for this decision domain.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scheduler => "scheduler",
            Self::Placement => "placement",
            Self::Backpressure => "backpressure",
        }
    }
}

/// Action selected by an adaptive swarm component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmDecisionAction {
    /// Admit work immediately.
    Admit,
    /// Dispatch work to an executor or connector.
    Dispatch,
    /// Delay work without rejecting it.
    Delay,
    /// Place work in a specific pool, node, or topology slot.
    Place,
    /// Throttle caller or downstream rate.
    Throttle,
    /// Shed work intentionally.
    Shed,
    /// Reject work without retry.
    Reject,
    /// Use deterministic conservative behavior instead of adaptive behavior.
    Fallback,
}

impl SwarmDecisionAction {
    /// Stable machine label for this action.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Dispatch => "dispatch",
            Self::Delay => "delay",
            Self::Place => "place",
            Self::Throttle => "throttle",
            Self::Shed => "shed",
            Self::Reject => "reject",
            Self::Fallback => "fallback",
        }
    }
}

/// Calibration state recorded beside an adaptive decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmCalibrationStatus {
    /// No adaptive calibration was needed for this decision.
    NotRequired,
    /// Calibration was present and within its accepted envelope.
    Valid,
    /// Calibration detected drift and adaptive behavior should fall back.
    DriftDetected,
    /// Required telemetry was absent.
    MissingTelemetry,
    /// Replay could not reproduce the selected action.
    ReplayMismatch,
}

impl SwarmCalibrationStatus {
    /// Stable machine label for this calibration state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::Valid => "valid",
            Self::DriftDetected => "drift_detected",
            Self::MissingTelemetry => "missing_telemetry",
            Self::ReplayMismatch => "replay_mismatch",
        }
    }

    /// Whether this calibration state requires conservative fallback.
    #[must_use]
    pub const fn requires_fallback(self) -> bool {
        matches!(
            self,
            Self::DriftDetected | Self::MissingTelemetry | Self::ReplayMismatch
        )
    }
}

/// One expected-loss term that contributed to an adaptive choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmDecisionLossTerm {
    /// Stable loss term name, such as `p99_queueing` or `zone_fairness`.
    pub name: String,
    /// Measured or modeled value for this term.
    pub value: i64,
    /// Weight in millionths, avoiding floating-point drift in evidence records.
    pub weight_microunits: i64,
    /// Unit label for the value.
    pub unit: String,
}

impl SwarmDecisionLossTerm {
    /// Build one deterministic expected-loss term.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        value: i64,
        weight_microunits: i64,
        unit: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value,
            weight_microunits,
            unit: unit.into(),
        }
    }

    /// Weighted score for comparing terms and actions.
    #[must_use]
    pub fn weighted_score(&self) -> i128 {
        i128::from(self.value).saturating_mul(i128::from(self.weight_microunits))
    }
}

/// Next-best action retained so operators can inspect the counterfactual.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmDecisionCounterfactual {
    /// Action that was not selected.
    pub action: SwarmDecisionAction,
    /// Deterministic expected-loss score for the counterfactual.
    pub expected_loss_score: i64,
    /// Short explanation for why the counterfactual lost.
    pub reason: String,
}

impl SwarmDecisionCounterfactual {
    /// Build a counterfactual action record.
    #[must_use]
    pub fn new(
        action: SwarmDecisionAction,
        expected_loss_score: i64,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            action,
            expected_loss_score,
            reason: reason.into(),
        }
    }
}

/// Source class for a replay or evidence pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmDecisionEvidenceKind {
    /// Inline data in the card is sufficient for replay.
    InlineSummary,
    /// Durable artifact expected inside a replayable bundle.
    BundleArtifact,
    /// Live-only source. Cards with this pointer are not offline replayable.
    LiveService,
}

/// Redaction-safe pointer to evidence that explains a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmDecisionEvidencePointer {
    /// Evidence source class.
    pub kind: SwarmDecisionEvidenceKind,
    /// Stable artifact or evidence handle.
    pub handle: String,
    /// Optional digest for bundle artifact integrity checks.
    pub digest: Option<String>,
    /// Whether the pointed artifact was redacted.
    pub redacted: bool,
}

impl SwarmDecisionEvidencePointer {
    /// Build a pointer to a bundle artifact.
    #[must_use]
    pub fn bundle_artifact(
        handle: impl Into<String>,
        digest: impl Into<String>,
        redacted: bool,
    ) -> Self {
        Self {
            kind: SwarmDecisionEvidenceKind::BundleArtifact,
            handle: handle.into(),
            digest: Some(digest.into()),
            redacted,
        }
    }

    /// Build an inline evidence pointer.
    #[must_use]
    pub fn inline_summary(handle: impl Into<String>) -> Self {
        Self {
            kind: SwarmDecisionEvidenceKind::InlineSummary,
            handle: handle.into(),
            digest: None,
            redacted: false,
        }
    }

    /// Build a live-service pointer for diagnostics that cannot be replayed offline.
    #[must_use]
    pub fn live_service(handle: impl Into<String>) -> Self {
        Self {
            kind: SwarmDecisionEvidenceKind::LiveService,
            handle: handle.into(),
            digest: None,
            redacted: false,
        }
    }

    /// Whether replay needs a live service for this pointer.
    #[must_use]
    pub const fn requires_live_service(&self) -> bool {
        matches!(self.kind, SwarmDecisionEvidenceKind::LiveService)
    }
}

/// Conservative fallback metadata for adaptive components.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmDecisionFallback {
    /// Whether the selected action is already using fallback behavior.
    pub active: bool,
    /// Deterministic fallback action.
    pub action: SwarmDecisionAction,
    /// Reason fallback was or would be selected.
    pub reason: Option<String>,
}

impl SwarmDecisionFallback {
    /// Build inactive fallback metadata with the fallback action that remains available.
    #[must_use]
    pub const fn available(action: SwarmDecisionAction) -> Self {
        Self {
            active: false,
            action,
            reason: None,
        }
    }

    /// Build active fallback metadata.
    #[must_use]
    pub fn active(action: SwarmDecisionAction, reason: impl Into<String>) -> Self {
        Self {
            active: true,
            action,
            reason: Some(reason.into()),
        }
    }
}

/// Operator-facing card explaining one adaptive swarm decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmDecisionCard {
    /// Card schema version.
    pub schema_version: String,
    /// Stable card identifier.
    pub card_id: String,
    /// Optional swarm scenario identifier.
    pub scenario_id: Option<String>,
    /// Adaptive subsystem that produced the decision.
    pub domain: SwarmDecisionDomain,
    /// Subject being scheduled, placed, admitted, throttled, or shed.
    pub subject: String,
    /// State label that the policy evaluated.
    pub state: String,
    /// Selected action.
    pub action: SwarmDecisionAction,
    /// Deterministic score for the selected action.
    pub selected_loss_score: i64,
    /// Expected-loss terms used to compute the selected action.
    pub loss_terms: Vec<SwarmDecisionLossTerm>,
    /// Calibration state for the adaptive policy.
    pub calibration: SwarmCalibrationStatus,
    /// Fallback metadata.
    pub fallback: SwarmDecisionFallback,
    /// Next-best action, when available.
    pub counterfactual: Option<SwarmDecisionCounterfactual>,
    /// Redaction-safe pointers to evidence used by the decision.
    pub evidence_pointers: Vec<SwarmDecisionEvidencePointer>,
    /// Offline replay inputs captured as stable JSON values.
    pub replay_inputs: BTreeMap<String, Value>,
    /// Creation time for the card.
    pub created_at: DateTime<Utc>,
}

impl SwarmDecisionCard {
    /// Build a decision card with the stable schema version.
    #[must_use]
    pub fn new(
        card_id: impl Into<String>,
        domain: SwarmDecisionDomain,
        subject: impl Into<String>,
        state: impl Into<String>,
        action: SwarmDecisionAction,
        selected_loss_score: i64,
        fallback: SwarmDecisionFallback,
    ) -> Self {
        Self {
            schema_version: SWARM_DECISION_CARD_SCHEMA_VERSION.to_string(),
            card_id: card_id.into(),
            scenario_id: None,
            domain,
            subject: subject.into(),
            state: state.into(),
            action,
            selected_loss_score,
            loss_terms: Vec::new(),
            calibration: SwarmCalibrationStatus::NotRequired,
            fallback,
            counterfactual: None,
            evidence_pointers: Vec::new(),
            replay_inputs: BTreeMap::new(),
            created_at: Utc::now(),
        }
    }

    /// Attach a swarm latency scenario identifier.
    #[must_use]
    pub fn with_scenario(mut self, scenario_id: impl Into<String>) -> Self {
        self.scenario_id = Some(scenario_id.into());
        self
    }

    /// Attach deterministic loss terms.
    #[must_use]
    pub fn with_loss_terms(mut self, loss_terms: Vec<SwarmDecisionLossTerm>) -> Self {
        self.loss_terms = loss_terms;
        self
    }

    /// Attach calibration state.
    #[must_use]
    pub const fn with_calibration(mut self, calibration: SwarmCalibrationStatus) -> Self {
        self.calibration = calibration;
        self
    }

    /// Attach the next-best action.
    #[must_use]
    pub fn with_counterfactual(mut self, counterfactual: SwarmDecisionCounterfactual) -> Self {
        self.counterfactual = Some(counterfactual);
        self
    }

    /// Attach redaction-safe evidence pointers.
    #[must_use]
    pub fn with_evidence_pointers(
        mut self,
        evidence_pointers: Vec<SwarmDecisionEvidencePointer>,
    ) -> Self {
        self.evidence_pointers = evidence_pointers;
        self
    }

    /// Attach offline replay inputs.
    #[must_use]
    pub fn with_replay_inputs(mut self, replay_inputs: BTreeMap<String, Value>) -> Self {
        self.replay_inputs = replay_inputs;
        self
    }

    /// Loss term with the largest weighted score.
    #[must_use]
    pub fn dominant_loss_term(&self) -> Option<&SwarmDecisionLossTerm> {
        self.loss_terms
            .iter()
            .max_by_key(|term| term.weighted_score())
    }

    /// Whether this card can be replayed from bundle artifacts without live services.
    #[must_use]
    pub fn is_replayable_offline(&self) -> bool {
        !self.replay_inputs.is_empty()
            && !self
                .evidence_pointers
                .iter()
                .any(SwarmDecisionEvidencePointer::requires_live_service)
    }

    /// Whether the adaptive feature can be disabled while retaining auditability.
    #[must_use]
    pub fn safe_to_disable(&self) -> bool {
        self.is_replayable_offline()
            && (self.fallback.action == SwarmDecisionAction::Fallback
                || self.fallback.active
                || self.calibration.requires_fallback())
    }

    /// Render as a typed JSONL record.
    ///
    /// # Errors
    ///
    /// Returns a serde error if the card cannot be converted to JSON.
    pub fn to_jsonl_value(&self) -> Result<Value, serde_json::Error> {
        Ok(json!({
            "record_type": "swarm_decision_card",
            "schema_version": self.schema_version,
            "card": serde_json::to_value(self)?,
        }))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-controller swarm safety reports
// ─────────────────────────────────────────────────────────────────────────────

/// Schema tag for cross-controller swarm safety reports.
pub const SWARM_CONTROLLER_SAFETY_SCHEMA_VERSION: &str = "swarm-controller-safety/v1";

/// Adaptive controller mode compared by the cross-controller safety report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmControllerMode {
    /// Scheduler policy enabled by itself.
    SchedulerOnly,
    /// Placement/resource-pool policy enabled by itself.
    PlacementOnly,
    /// Backpressure controller enabled by itself.
    BackpressureOnly,
    /// Audit/event combiner enabled by itself.
    AuditOnly,
    /// Scheduler, placement, backpressure, and audit behavior enabled together.
    CombinedController,
    /// Deterministic conservative behavior used for disable or rollback.
    ConservativeFallback,
}

impl SwarmControllerMode {
    /// Every controller mode needed by the cross-controller safety contract.
    pub const REQUIRED: [Self; 6] = [
        Self::SchedulerOnly,
        Self::PlacementOnly,
        Self::BackpressureOnly,
        Self::AuditOnly,
        Self::CombinedController,
        Self::ConservativeFallback,
    ];

    /// Stable machine label for this controller mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SchedulerOnly => "scheduler_only",
            Self::PlacementOnly => "placement_only",
            Self::BackpressureOnly => "backpressure_only",
            Self::AuditOnly => "audit_only",
            Self::CombinedController => "combined_controller",
            Self::ConservativeFallback => "conservative_fallback",
        }
    }
}

/// Scripted scenario class for proving controller interactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmControllerInteractionScenario {
    /// Nominal load below all controller thresholds.
    Healthy,
    /// Queue depth is the dominant pressure source.
    QueueCongested,
    /// CPU saturation is the dominant pressure source.
    CpuSaturated,
    /// RSS or allocation pressure is the dominant pressure source.
    MemoryPressure,
    /// Downstream service throttling is causing retry pressure.
    DownstreamThrottled,
    /// Retries are amplifying load across controllers.
    RetryStorm,
    /// Audit/event contention is concentrated in one zone.
    SameZoneAuditStorm,
    /// Mixed priorities, zones, and principals compete for capacity.
    MixedPriority,
}

impl SwarmControllerInteractionScenario {
    /// Every scripted scenario required by the safety contract.
    pub const REQUIRED: [Self; 8] = [
        Self::Healthy,
        Self::QueueCongested,
        Self::CpuSaturated,
        Self::MemoryPressure,
        Self::DownstreamThrottled,
        Self::RetryStorm,
        Self::SameZoneAuditStorm,
        Self::MixedPriority,
    ];

    /// Stable machine label for this scenario.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::QueueCongested => "queue_congested",
            Self::CpuSaturated => "cpu_saturated",
            Self::MemoryPressure => "memory_pressure",
            Self::DownstreamThrottled => "downstream_throttled",
            Self::RetryStorm => "retry_storm",
            Self::SameZoneAuditStorm => "same_zone_audit_storm",
            Self::MixedPriority => "mixed_priority",
        }
    }
}

/// Invariant checked by the cross-controller safety report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmControllerSafetyInvariant {
    /// Every submitted operation is accounted for by an outcome.
    WorkConservation,
    /// No zone, principal, or priority class waits beyond the configured bound.
    BoundedStarvation,
    /// Zone-level and principal-level fairness remain within skew budgets.
    ZonePrincipalFairness,
    /// Delay, shed, throttle, and fallback actions are visible in evidence.
    BackpressureActionVisible,
    /// Every accounted operation has audit evidence.
    NoAuditLoss,
    /// Replaying the decision record reproduces the same selected action.
    DeterministicReplay,
    /// Adaptive behavior can be disabled or rolled back to safe fallback.
    SafeDisableRollback,
    /// Combined mode retained next-best safe-action records.
    CounterfactualRetained,
    /// All required controller modes were compared for the scenario.
    ModeComparisonComplete,
}

impl SwarmControllerSafetyInvariant {
    /// Stable machine label for this invariant.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkConservation => "work_conservation",
            Self::BoundedStarvation => "bounded_starvation",
            Self::ZonePrincipalFairness => "zone_principal_fairness",
            Self::BackpressureActionVisible => "backpressure_action_visible",
            Self::NoAuditLoss => "no_audit_loss",
            Self::DeterministicReplay => "deterministic_replay",
            Self::SafeDisableRollback => "safe_disable_rollback",
            Self::CounterfactualRetained => "counterfactual_retained",
            Self::ModeComparisonComplete => "mode_comparison_complete",
        }
    }
}

/// Machine-readable cross-controller safety outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmControllerSafetyOutcome {
    /// All invariants passed and no fallback-only condition was detected.
    Pass,
    /// At least one hard safety invariant failed.
    Fail,
    /// Safety invariants held because adaptive behavior entered fallback.
    FallbackRequired,
}

impl SwarmControllerSafetyOutcome {
    /// Stable machine label for this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::FallbackRequired => "fallback_required",
        }
    }
}

/// Thresholds used by cross-controller safety checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmControllerSafetyThresholds {
    /// Maximum allowed starvation wait for any zone/principal/priority class.
    pub max_starvation_ms: u64,
    /// Maximum zone fairness skew in millionths.
    pub max_zone_fairness_skew_microunits: u64,
    /// Maximum principal fairness skew in millionths.
    pub max_principal_fairness_skew_microunits: u64,
}

impl SwarmControllerSafetyThresholds {
    /// Conservative offline smoke thresholds for replayable controller tests.
    #[must_use]
    pub const fn smoke() -> Self {
        Self {
            max_starvation_ms: 5_000,
            max_zone_fairness_skew_microunits: 100_000,
            max_principal_fairness_skew_microunits: 100_000,
        }
    }
}

/// Aggregated metrics for one controller mode under one scenario.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmControllerModeMetrics {
    /// Operations submitted to the controller set.
    pub submitted_ops: u64,
    /// Operations with a terminal or intentionally delayed outcome.
    pub accounted_ops: u64,
    /// Operations that disappeared without a visible outcome.
    pub hidden_drop_count: u64,
    /// Operations delayed by an explicit controller action.
    pub delayed_ops: u64,
    /// Operations shed by an explicit controller action.
    pub shed_ops: u64,
    /// Delay actions that did not actually delay or change admission state.
    pub no_op_delay_count: u64,
    /// Warning admissions that bypassed visible warning evidence.
    pub silent_warning_admission_count: u64,
    /// Audit events retained for accounted operations.
    pub audit_event_count: u64,
    /// Decision-card replays that did not reproduce the selected action.
    pub replay_mismatch_count: u64,
    /// Maximum observed starvation wait.
    pub max_starvation_ms: u64,
    /// Maximum zone fairness skew in millionths.
    pub zone_fairness_skew_microunits: u64,
    /// Maximum principal fairness skew in millionths.
    pub principal_fairness_skew_microunits: u64,
    /// Conservative fallback invocations.
    pub fallback_invocations: u64,
    /// Retained next-best safe-action records.
    pub counterfactual_count: u64,
    /// Decision cards expected for this mode evidence.
    pub decision_card_count: u64,
}

/// Evidence for one controller mode under one interaction scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmControllerModeEvidence {
    /// Scenario exercised by this evidence row.
    pub scenario: SwarmControllerInteractionScenario,
    /// Controller mode being evaluated.
    pub mode: SwarmControllerMode,
    /// Aggregated safety metrics.
    pub metrics: SwarmControllerModeMetrics,
    /// Decision cards that explain visible actions for this mode.
    pub decision_card_ids: Vec<String>,
    /// Machine-readable fallback reason, when this mode intentionally fell back.
    pub fallback_reason: Option<String>,
}

impl SwarmControllerModeEvidence {
    /// Build one mode evidence row.
    #[must_use]
    pub const fn new(
        scenario: SwarmControllerInteractionScenario,
        mode: SwarmControllerMode,
        metrics: SwarmControllerModeMetrics,
        decision_card_ids: Vec<String>,
    ) -> Self {
        Self {
            scenario,
            mode,
            metrics,
            decision_card_ids,
            fallback_reason: None,
        }
    }

    /// Attach a fallback reason to this row.
    #[must_use]
    pub fn with_fallback_reason(mut self, reason: impl Into<String>) -> Self {
        self.fallback_reason = Some(reason.into());
        self
    }
}

/// One invariant failure emitted by a cross-controller safety report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmControllerSafetyFailure {
    /// Failed invariant.
    pub invariant: SwarmControllerSafetyInvariant,
    /// Controller mode where the failure was observed.
    pub mode: SwarmControllerMode,
    /// Scenario where the failure was observed.
    pub scenario: SwarmControllerInteractionScenario,
    /// Machine-readable reason.
    pub reason: String,
    /// Observed value.
    pub observed_value: String,
    /// Allowed value.
    pub allowed_value: String,
    /// Decision card ids correlated with the failure.
    pub decision_card_ids: Vec<String>,
}

impl SwarmControllerSafetyFailure {
    fn new(
        invariant: SwarmControllerSafetyInvariant,
        mode: SwarmControllerMode,
        scenario: SwarmControllerInteractionScenario,
        reason: impl Into<String>,
        observed_value: impl Into<String>,
        allowed_value: impl Into<String>,
        decision_card_ids: Vec<String>,
    ) -> Self {
        Self {
            invariant,
            mode,
            scenario,
            reason: reason.into(),
            observed_value: observed_value.into(),
            allowed_value: allowed_value.into(),
            decision_card_ids,
        }
    }
}

/// Replayable report proving scheduler, placement, backpressure, and audit
/// controllers remain safe when enabled separately and together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmControllerSafetyReport {
    /// Report schema version.
    pub schema_version: String,
    /// Scenario evaluated by this report.
    pub scenario: SwarmControllerInteractionScenario,
    /// Safety thresholds applied to all mode evidence rows.
    pub thresholds: SwarmControllerSafetyThresholds,
    /// Mode evidence rows compared by the report.
    pub modes: Vec<SwarmControllerModeEvidence>,
    /// Final machine-readable outcome.
    pub outcome: SwarmControllerSafetyOutcome,
    /// Hard safety invariant failures.
    pub failures: Vec<SwarmControllerSafetyFailure>,
    /// Fallback reasons that made adaptive behavior intentionally conservative.
    pub fallback_reasons: Vec<String>,
    /// Decision cards correlated with mode evidence and failures.
    pub decision_cards: Vec<SwarmDecisionCard>,
    /// Report creation time.
    pub generated_at: DateTime<Utc>,
}

impl SwarmControllerSafetyReport {
    /// Evaluate cross-controller invariants for one scenario.
    #[must_use]
    pub fn evaluate(
        scenario: SwarmControllerInteractionScenario,
        thresholds: SwarmControllerSafetyThresholds,
        modes: Vec<SwarmControllerModeEvidence>,
        decision_cards: Vec<SwarmDecisionCard>,
    ) -> Self {
        let card_by_id: BTreeMap<_, _> = decision_cards
            .iter()
            .map(|card| (card.card_id.as_str(), card))
            .collect();
        let mut failures = Self::mode_comparison_failures(scenario, &modes);
        let mut fallback_reasons = Vec::new();
        for mode in &modes {
            failures.extend(Self::mode_shape_failures(scenario, mode, &card_by_id));
            failures.extend(Self::mode_accounting_failures(scenario, mode));
            failures.extend(Self::mode_fairness_failures(scenario, &thresholds, mode));
            failures.extend(Self::mode_visibility_failures(scenario, mode));
            failures.extend(Self::mode_counterfactual_failures(
                scenario,
                mode,
                &card_by_id,
            ));
            fallback_reasons.extend(Self::mode_fallback_reasons(mode));
        }
        for card in &decision_cards {
            failures.extend(Self::card_disable_failures(scenario, card));
            fallback_reasons.extend(Self::card_fallback_reasons(card));
        }
        fallback_reasons.sort();
        fallback_reasons.dedup();
        let outcome = if failures.is_empty() {
            if fallback_reasons.is_empty() {
                SwarmControllerSafetyOutcome::Pass
            } else {
                SwarmControllerSafetyOutcome::FallbackRequired
            }
        } else {
            SwarmControllerSafetyOutcome::Fail
        };

        Self {
            schema_version: SWARM_CONTROLLER_SAFETY_SCHEMA_VERSION.to_string(),
            scenario,
            thresholds,
            modes,
            outcome,
            failures,
            fallback_reasons,
            decision_cards,
            generated_at: Utc::now(),
        }
    }

    fn mode_comparison_failures(
        scenario: SwarmControllerInteractionScenario,
        modes: &[SwarmControllerModeEvidence],
    ) -> Vec<SwarmControllerSafetyFailure> {
        let mut failures = Vec::new();
        let observed_modes: BTreeSet<_> = modes.iter().map(|mode| mode.mode).collect();
        for required_mode in SwarmControllerMode::REQUIRED {
            if !observed_modes.contains(&required_mode) {
                failures.push(SwarmControllerSafetyFailure::new(
                    SwarmControllerSafetyInvariant::ModeComparisonComplete,
                    required_mode,
                    scenario,
                    "required_mode_missing",
                    "missing",
                    "present",
                    Vec::new(),
                ));
            }
        }

        let fallback_mode = modes
            .iter()
            .find(|mode| mode.mode == SwarmControllerMode::ConservativeFallback);
        if fallback_mode.is_none_or(|mode| mode.metrics.fallback_invocations == 0) {
            failures.push(SwarmControllerSafetyFailure::new(
                SwarmControllerSafetyInvariant::SafeDisableRollback,
                SwarmControllerMode::ConservativeFallback,
                scenario,
                "fallback_mode_not_exercised",
                fallback_mode.map_or_else(|| "missing".to_string(), |_| "0".to_string()),
                ">=1",
                Vec::new(),
            ));
        }
        failures
    }

    fn mode_shape_failures(
        scenario: SwarmControllerInteractionScenario,
        mode: &SwarmControllerModeEvidence,
        card_by_id: &BTreeMap<&str, &SwarmDecisionCard>,
    ) -> Vec<SwarmControllerSafetyFailure> {
        let mut failures = Vec::new();
        if mode.scenario != scenario {
            failures.push(SwarmControllerSafetyFailure::new(
                SwarmControllerSafetyInvariant::DeterministicReplay,
                mode.mode,
                scenario,
                "scenario_mismatch",
                mode.scenario.as_str(),
                scenario.as_str(),
                mode.decision_card_ids.clone(),
            ));
        }

        let expected_card_count = u64::try_from(mode.decision_card_ids.len()).unwrap_or(u64::MAX);
        if mode.metrics.decision_card_count != expected_card_count {
            failures.push(SwarmControllerSafetyFailure::new(
                SwarmControllerSafetyInvariant::DeterministicReplay,
                mode.mode,
                scenario,
                "decision_card_count_mismatch",
                mode.metrics.decision_card_count.to_string(),
                expected_card_count.to_string(),
                mode.decision_card_ids.clone(),
            ));
        }

        let missing_card_ids = mode
            .decision_card_ids
            .iter()
            .filter(|card_id| !card_by_id.contains_key(card_id.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if !missing_card_ids.is_empty() {
            failures.push(SwarmControllerSafetyFailure::new(
                SwarmControllerSafetyInvariant::DeterministicReplay,
                mode.mode,
                scenario,
                "decision_card_missing",
                missing_card_ids.join(","),
                "all referenced cards present",
                missing_card_ids,
            ));
        }
        failures
    }

    fn mode_accounting_failures(
        scenario: SwarmControllerInteractionScenario,
        mode: &SwarmControllerModeEvidence,
    ) -> Vec<SwarmControllerSafetyFailure> {
        let mut failures = Vec::new();
        if mode.metrics.submitted_ops != mode.metrics.accounted_ops {
            failures.push(SwarmControllerSafetyFailure::new(
                SwarmControllerSafetyInvariant::WorkConservation,
                mode.mode,
                scenario,
                "submitted_accounted_mismatch",
                mode.metrics.accounted_ops.to_string(),
                mode.metrics.submitted_ops.to_string(),
                mode.decision_card_ids.clone(),
            ));
        }
        if mode.metrics.hidden_drop_count > 0 {
            failures.push(SwarmControllerSafetyFailure::new(
                SwarmControllerSafetyInvariant::WorkConservation,
                mode.mode,
                scenario,
                "hidden_drop",
                mode.metrics.hidden_drop_count.to_string(),
                "0",
                mode.decision_card_ids.clone(),
            ));
        }
        if mode.metrics.audit_event_count < mode.metrics.accounted_ops {
            failures.push(SwarmControllerSafetyFailure::new(
                SwarmControllerSafetyInvariant::NoAuditLoss,
                mode.mode,
                scenario,
                "audit_event_shortfall",
                mode.metrics.audit_event_count.to_string(),
                mode.metrics.accounted_ops.to_string(),
                mode.decision_card_ids.clone(),
            ));
        }
        failures
    }

    fn mode_fairness_failures(
        scenario: SwarmControllerInteractionScenario,
        thresholds: &SwarmControllerSafetyThresholds,
        mode: &SwarmControllerModeEvidence,
    ) -> Vec<SwarmControllerSafetyFailure> {
        let mut failures = Vec::new();
        if mode.metrics.max_starvation_ms > thresholds.max_starvation_ms {
            failures.push(SwarmControllerSafetyFailure::new(
                SwarmControllerSafetyInvariant::BoundedStarvation,
                mode.mode,
                scenario,
                "starvation_bound_exceeded",
                mode.metrics.max_starvation_ms.to_string(),
                thresholds.max_starvation_ms.to_string(),
                mode.decision_card_ids.clone(),
            ));
        }
        if mode.metrics.zone_fairness_skew_microunits > thresholds.max_zone_fairness_skew_microunits
        {
            failures.push(SwarmControllerSafetyFailure::new(
                SwarmControllerSafetyInvariant::ZonePrincipalFairness,
                mode.mode,
                scenario,
                "zone_fairness_skew_exceeded",
                mode.metrics.zone_fairness_skew_microunits.to_string(),
                thresholds.max_zone_fairness_skew_microunits.to_string(),
                mode.decision_card_ids.clone(),
            ));
        }
        if mode.metrics.principal_fairness_skew_microunits
            > thresholds.max_principal_fairness_skew_microunits
        {
            failures.push(SwarmControllerSafetyFailure::new(
                SwarmControllerSafetyInvariant::ZonePrincipalFairness,
                mode.mode,
                scenario,
                "principal_fairness_skew_exceeded",
                mode.metrics.principal_fairness_skew_microunits.to_string(),
                thresholds
                    .max_principal_fairness_skew_microunits
                    .to_string(),
                mode.decision_card_ids.clone(),
            ));
        }
        failures
    }

    fn mode_visibility_failures(
        scenario: SwarmControllerInteractionScenario,
        mode: &SwarmControllerModeEvidence,
    ) -> Vec<SwarmControllerSafetyFailure> {
        let mut failures = Vec::new();
        if (mode.metrics.delayed_ops > 0
            || mode.metrics.shed_ops > 0
            || mode.metrics.fallback_invocations > 0)
            && mode.decision_card_ids.is_empty()
        {
            failures.push(SwarmControllerSafetyFailure::new(
                SwarmControllerSafetyInvariant::BackpressureActionVisible,
                mode.mode,
                scenario,
                "controller_action_without_decision_card",
                "0",
                ">=1",
                Vec::new(),
            ));
        }
        if mode.metrics.no_op_delay_count > 0 {
            failures.push(SwarmControllerSafetyFailure::new(
                SwarmControllerSafetyInvariant::BackpressureActionVisible,
                mode.mode,
                scenario,
                "no_op_delay",
                mode.metrics.no_op_delay_count.to_string(),
                "0",
                mode.decision_card_ids.clone(),
            ));
        }
        if mode.metrics.silent_warning_admission_count > 0 {
            failures.push(SwarmControllerSafetyFailure::new(
                SwarmControllerSafetyInvariant::BackpressureActionVisible,
                mode.mode,
                scenario,
                "silent_warning_admission",
                mode.metrics.silent_warning_admission_count.to_string(),
                "0",
                mode.decision_card_ids.clone(),
            ));
        }
        if mode.metrics.replay_mismatch_count > 0 {
            failures.push(SwarmControllerSafetyFailure::new(
                SwarmControllerSafetyInvariant::DeterministicReplay,
                mode.mode,
                scenario,
                "replay_mismatch",
                mode.metrics.replay_mismatch_count.to_string(),
                "0",
                mode.decision_card_ids.clone(),
            ));
        }
        failures
    }

    fn mode_counterfactual_failures(
        scenario: SwarmControllerInteractionScenario,
        mode: &SwarmControllerModeEvidence,
        card_by_id: &BTreeMap<&str, &SwarmDecisionCard>,
    ) -> Vec<SwarmControllerSafetyFailure> {
        if mode.mode != SwarmControllerMode::CombinedController {
            return Vec::new();
        }

        let mut failures = Vec::new();
        let missing_counterfactual_ids = mode
            .decision_card_ids
            .iter()
            .filter_map(|card_id| {
                card_by_id
                    .get(card_id.as_str())
                    .and_then(|card| card.counterfactual.is_none().then(|| card_id.clone()))
            })
            .collect::<Vec<_>>();
        if mode.metrics.counterfactual_count < mode.metrics.decision_card_count {
            failures.push(SwarmControllerSafetyFailure::new(
                SwarmControllerSafetyInvariant::CounterfactualRetained,
                mode.mode,
                scenario,
                "counterfactual_count_shortfall",
                mode.metrics.counterfactual_count.to_string(),
                mode.metrics.decision_card_count.to_string(),
                mode.decision_card_ids.clone(),
            ));
        }
        if !missing_counterfactual_ids.is_empty() {
            failures.push(SwarmControllerSafetyFailure::new(
                SwarmControllerSafetyInvariant::CounterfactualRetained,
                mode.mode,
                scenario,
                "decision_card_counterfactual_missing",
                missing_counterfactual_ids.join(","),
                "all combined decision cards include counterfactual",
                missing_counterfactual_ids,
            ));
        }
        failures
    }

    fn mode_fallback_reasons(mode: &SwarmControllerModeEvidence) -> Vec<String> {
        if mode.mode == SwarmControllerMode::ConservativeFallback {
            return Vec::new();
        }

        let mut reasons = Vec::new();
        if mode.metrics.fallback_invocations > 0 {
            reasons.push(format!(
                "{}:fallback_invocations={}",
                mode.mode.as_str(),
                mode.metrics.fallback_invocations
            ));
        }
        if let Some(reason) = &mode.fallback_reason {
            reasons.push(format!("{}:{reason}", mode.mode.as_str()));
        }
        reasons
    }

    fn card_disable_failures(
        scenario: SwarmControllerInteractionScenario,
        card: &SwarmDecisionCard,
    ) -> Vec<SwarmControllerSafetyFailure> {
        if card.safe_to_disable() {
            return Vec::new();
        }

        vec![SwarmControllerSafetyFailure::new(
            SwarmControllerSafetyInvariant::SafeDisableRollback,
            SwarmControllerMode::CombinedController,
            scenario,
            "decision_card_not_safe_to_disable",
            card.card_id.clone(),
            "offline replay inputs plus fallback action",
            vec![card.card_id.clone()],
        )]
    }

    fn card_fallback_reasons(card: &SwarmDecisionCard) -> Vec<String> {
        let mut reasons = Vec::new();
        if card.calibration.requires_fallback() {
            reasons.push(format!(
                "{}:calibration={}",
                card.card_id,
                card.calibration.as_str()
            ));
        }
        if card.fallback.active {
            let reason = card.fallback.reason.as_deref().unwrap_or("fallback_active");
            reasons.push(format!("{}:{reason}", card.card_id));
        }
        reasons
    }

    /// Render the report as detailed JSONL-ready records.
    ///
    /// # Errors
    ///
    /// Returns a serde error if any record cannot be converted to JSON.
    pub fn to_jsonl_values(&self) -> Result<Vec<Value>, serde_json::Error> {
        let mut records = Vec::new();
        for card in &self.decision_cards {
            records.push(card.to_jsonl_value()?);
        }
        for mode in &self.modes {
            records.push(json!({
                "record_type": "swarm_controller_safety_mode_evidence",
                "schema_version": self.schema_version,
                "scenario": self.scenario.as_str(),
                "mode": mode.mode.as_str(),
                "metrics": serde_json::to_value(&mode.metrics)?,
                "decision_card_ids": &mode.decision_card_ids,
                "fallback_reason": &mode.fallback_reason,
            }));
        }
        for failure in &self.failures {
            records.push(json!({
                "record_type": "swarm_controller_safety_failure",
                "schema_version": self.schema_version,
                "scenario": self.scenario.as_str(),
                "mode": failure.mode.as_str(),
                "invariant": failure.invariant.as_str(),
                "reason": &failure.reason,
                "observed_value": &failure.observed_value,
                "allowed_value": &failure.allowed_value,
                "decision_card_ids": &failure.decision_card_ids,
            }));
        }
        records.push(json!({
            "record_type": "swarm_controller_safety_report",
            "schema_version": self.schema_version,
            "scenario": self.scenario.as_str(),
            "outcome": self.outcome.as_str(),
            "thresholds": serde_json::to_value(&self.thresholds)?,
            "mode_count": self.modes.len(),
            "failure_codes": self
                .failures
                .iter()
                .map(|failure| failure.invariant.as_str())
                .collect::<Vec<_>>(),
            "fallback_reasons": &self.fallback_reasons,
            "decision_card_ids": self
                .decision_cards
                .iter()
                .map(|card| card.card_id.as_str())
                .collect::<Vec<_>>(),
            "generated_at": self.generated_at,
        }));
        Ok(records)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial revocation swarm reports
// ─────────────────────────────────────────────────────────────────────────────

/// Schema tag for adversarial admission and emergency revocation swarm reports.
pub const SWARM_ADVERSARIAL_REVOCATION_SCHEMA_VERSION: &str = "swarm-adversarial-revocation/v1";

/// Admission outcome observed for one adversarial swarm operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmAdversarialAdmissionOutcome {
    /// Work was admitted for execution.
    Admitted,
    /// Work was intentionally delayed by backpressure.
    Delayed,
    /// Work was denied before connector dispatch.
    Denied,
    /// Work was skipped because the scenario prerequisites were unavailable.
    Skipped,
}

impl SwarmAdversarialAdmissionOutcome {
    /// Stable machine label for this admission outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Delayed => "delayed",
            Self::Denied => "denied",
            Self::Skipped => "skipped",
        }
    }
}

/// Backpressure or emergency action observed for one adversarial operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmAdversarialBackpressureAction {
    /// No pressure response was required.
    Admit,
    /// Work was delayed with an operator-visible backpressure decision.
    Delay,
    /// Work was shed before connector dispatch.
    Shed,
    /// Conservative fallback path handled the operation.
    Fallback,
    /// Emergency revocation propagation was prioritized.
    EmergencyPropagate,
}

impl SwarmAdversarialBackpressureAction {
    /// Stable machine label for this action.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Delay => "delay",
            Self::Shed => "shed",
            Self::Fallback => "fallback",
            Self::EmergencyPropagate => "emergency_propagate",
        }
    }
}

/// Teardown result for one adversarial scenario row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmAdversarialCleanupOutcome {
    /// All scenario state was torn down.
    Completed,
    /// Teardown was not needed because the scenario was skipped.
    Skipped,
    /// Teardown failed and requires operator attention.
    Failed,
}

impl SwarmAdversarialCleanupOutcome {
    /// Stable machine label for this cleanup outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
        }
    }
}

/// Machine-readable adversarial revocation report outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmAdversarialRevocationOutcome {
    /// The deterministic fail-closed contract held.
    Pass,
    /// At least one adversarial invariant failed.
    Fail,
    /// The run emitted a structured skip artifact instead of executing.
    Skipped,
}

impl SwarmAdversarialRevocationOutcome {
    /// Stable machine label for this report outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Skipped => "skipped",
        }
    }
}

/// Invariant checked by the adversarial revocation report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmAdversarialRevocationInvariant {
    /// The run emitted concrete scenario rows or an explicit skip artifact.
    ScenarioEvidencePresent,
    /// Revoked principals or tokens never reached connector dispatch.
    RevokedWorkDenied,
    /// Emergency revocation propagation was not starved by overload.
    EmergencyRevocationNotStarved,
    /// Stale and malformed revocation messages were rejected.
    StaleMalformedRevocationRejected,
    /// Backpressure decisions carried visible state, action, and audit linkage.
    BackpressureActionVisible,
    /// Every non-skip row retained an audit receipt id.
    AuditReceiptContinuity,
    /// Retry and fallback counters were represented in the overload run.
    RetryFallbackCountersVisible,
    /// Scenario cleanup completed or the row was explicitly skipped.
    CleanupCompleted,
    /// Principal and token identifiers were redacted or hashed.
    RedactionSafe,
}

impl SwarmAdversarialRevocationInvariant {
    /// Stable machine label for this invariant.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ScenarioEvidencePresent => "scenario_evidence_present",
            Self::RevokedWorkDenied => "revoked_work_denied",
            Self::EmergencyRevocationNotStarved => "emergency_revocation_not_starved",
            Self::StaleMalformedRevocationRejected => "stale_malformed_revocation_rejected",
            Self::BackpressureActionVisible => "backpressure_action_visible",
            Self::AuditReceiptContinuity => "audit_receipt_continuity",
            Self::RetryFallbackCountersVisible => "retry_fallback_counters_visible",
            Self::CleanupCompleted => "cleanup_completed",
            Self::RedactionSafe => "redaction_safe",
        }
    }
}

/// Latency percentiles captured for one adversarial scenario row.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmAdversarialLatencyPercentiles {
    /// Median latency in milliseconds.
    pub p50_ms: u64,
    /// p95 latency in milliseconds.
    pub p95_ms: u64,
    /// p99 latency in milliseconds.
    pub p99_ms: u64,
}

impl SwarmAdversarialLatencyPercentiles {
    /// Build a latency percentile summary.
    #[must_use]
    pub const fn new(p50_ms: u64, p95_ms: u64, p99_ms: u64) -> Self {
        Self {
            p50_ms,
            p95_ms,
            p99_ms,
        }
    }
}

/// Thresholds used by adversarial revocation checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmAdversarialRevocationThresholds {
    /// Minimum emergency-revocation witness rows required for a pass.
    pub min_emergency_revocation_witnesses: u64,
    /// Maximum p99 propagation latency allowed for deterministic smoke proof.
    pub max_emergency_propagation_p99_ms: u64,
}

impl SwarmAdversarialRevocationThresholds {
    /// Conservative offline smoke thresholds for deterministic proof runs.
    #[must_use]
    pub const fn smoke() -> Self {
        Self {
            min_emergency_revocation_witnesses: 2,
            max_emergency_propagation_p99_ms: 250,
        }
    }
}

/// Input used to build one adversarial revocation event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct SwarmAdversarialRevocationEventInput {
    /// Scenario id shared by the run and JSONL records.
    pub scenario_id: String,
    /// Operation id for this row.
    pub operation_id: String,
    /// Number of nodes represented by the scenario.
    pub node_count: u64,
    /// Number of requests represented by the scenario.
    pub request_count: u64,
    /// Zone exercised by this row.
    pub zone: String,
    /// Redacted principal reference.
    pub principal_ref: String,
    /// Redacted token reference.
    pub token_ref: String,
    /// Admission outcome observed for the operation.
    pub admission_outcome: SwarmAdversarialAdmissionOutcome,
    /// Monotonic revocation sequence observed by the operation.
    pub revocation_seq: u64,
    /// Redacted revocation-head digest.
    pub revocation_head: String,
    /// Backpressure state label.
    pub backpressure_state: String,
    /// Backpressure or emergency action label.
    pub backpressure_action: SwarmAdversarialBackpressureAction,
    /// Audit receipt id retained for correlation.
    pub audit_receipt_id: String,
    /// Latency percentiles captured for this row.
    pub latency_percentiles: SwarmAdversarialLatencyPercentiles,
    /// Machine-readable denial reason, when denied.
    pub denial_reason: Option<String>,
    /// Scenario cleanup result.
    pub cleanup_outcome: SwarmAdversarialCleanupOutcome,
    /// Structured skip reason, when prerequisites were unavailable.
    pub skip_reason: Option<String>,
    /// Whether this row proves emergency revocation propagation.
    pub emergency_revocation_witness: bool,
    /// Whether this row attempted work with a revoked principal or token.
    pub revoked_work: bool,
    /// Whether this row carried a stale revocation message.
    pub stale_revocation: bool,
    /// Whether this row carried a malformed revocation message.
    pub malformed_revocation: bool,
    /// Retry counter represented by this row.
    pub retry_count: u64,
    /// Fallback counter represented by this row.
    pub fallback_count: u64,
}

/// One replayable adversarial admission/revocation evidence row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct SwarmAdversarialRevocationEvent {
    /// Event schema version.
    pub schema_version: String,
    /// Scenario id shared by the run and JSONL records.
    pub scenario_id: String,
    /// Operation id for this row.
    pub operation_id: String,
    /// Number of nodes represented by the scenario.
    pub node_count: u64,
    /// Number of requests represented by the scenario.
    pub request_count: u64,
    /// Zone exercised by this row.
    pub zone: String,
    /// Redacted principal reference.
    pub principal_ref: String,
    /// Redacted token reference.
    pub token_ref: String,
    /// Admission outcome observed for the operation.
    pub admission_outcome: SwarmAdversarialAdmissionOutcome,
    /// Monotonic revocation sequence observed by the operation.
    pub revocation_seq: u64,
    /// Redacted revocation-head digest.
    pub revocation_head: String,
    /// Backpressure state label.
    pub backpressure_state: String,
    /// Backpressure or emergency action label.
    pub backpressure_action: SwarmAdversarialBackpressureAction,
    /// Audit receipt id retained for correlation.
    pub audit_receipt_id: String,
    /// Latency percentiles captured for this row.
    pub latency_percentiles: SwarmAdversarialLatencyPercentiles,
    /// Machine-readable denial reason, when denied.
    pub denial_reason: Option<String>,
    /// Scenario cleanup result.
    pub cleanup_outcome: SwarmAdversarialCleanupOutcome,
    /// Structured skip reason, when prerequisites were unavailable.
    pub skip_reason: Option<String>,
    /// Whether this row proves emergency revocation propagation.
    pub emergency_revocation_witness: bool,
    /// Whether this row attempted work with a revoked principal or token.
    pub revoked_work: bool,
    /// Whether this row carried a stale revocation message.
    pub stale_revocation: bool,
    /// Whether this row carried a malformed revocation message.
    pub malformed_revocation: bool,
    /// Retry counter represented by this row.
    pub retry_count: u64,
    /// Fallback counter represented by this row.
    pub fallback_count: u64,
    /// Event creation time.
    pub generated_at: DateTime<Utc>,
}

impl SwarmAdversarialRevocationEvent {
    /// Build one adversarial event from structured input.
    #[must_use]
    pub fn new(input: SwarmAdversarialRevocationEventInput) -> Self {
        Self {
            schema_version: SWARM_ADVERSARIAL_REVOCATION_SCHEMA_VERSION.to_string(),
            scenario_id: input.scenario_id,
            operation_id: input.operation_id,
            node_count: input.node_count,
            request_count: input.request_count,
            zone: input.zone,
            principal_ref: input.principal_ref,
            token_ref: input.token_ref,
            admission_outcome: input.admission_outcome,
            revocation_seq: input.revocation_seq,
            revocation_head: input.revocation_head,
            backpressure_state: input.backpressure_state,
            backpressure_action: input.backpressure_action,
            audit_receipt_id: input.audit_receipt_id,
            latency_percentiles: input.latency_percentiles,
            denial_reason: input.denial_reason,
            cleanup_outcome: input.cleanup_outcome,
            skip_reason: input.skip_reason,
            emergency_revocation_witness: input.emergency_revocation_witness,
            revoked_work: input.revoked_work,
            stale_revocation: input.stale_revocation,
            malformed_revocation: input.malformed_revocation,
            retry_count: input.retry_count,
            fallback_count: input.fallback_count,
            generated_at: Utc::now(),
        }
    }

    fn is_skip(&self) -> bool {
        self.skip_reason.is_some()
            || self.admission_outcome == SwarmAdversarialAdmissionOutcome::Skipped
    }
}

/// One invariant failure emitted by an adversarial revocation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmAdversarialRevocationFailure {
    /// Failed invariant.
    pub invariant: SwarmAdversarialRevocationInvariant,
    /// Operation id associated with the failure, when row-specific.
    pub operation_id: Option<String>,
    /// Machine-readable reason.
    pub reason: String,
    /// Observed value.
    pub observed_value: String,
    /// Allowed value.
    pub allowed_value: String,
}

impl SwarmAdversarialRevocationFailure {
    fn new(
        invariant: SwarmAdversarialRevocationInvariant,
        operation_id: Option<String>,
        reason: impl Into<String>,
        observed_value: impl Into<String>,
        allowed_value: impl Into<String>,
    ) -> Self {
        Self {
            invariant,
            operation_id,
            reason: reason.into(),
            observed_value: observed_value.into(),
            allowed_value: allowed_value.into(),
        }
    }
}

/// Replayable report proving adversarial admission overload and revocation behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmAdversarialRevocationReport {
    /// Report schema version.
    pub schema_version: String,
    /// Scenario id shared by the run and JSONL records.
    pub scenario_id: String,
    /// Thresholds used to evaluate the report.
    pub thresholds: SwarmAdversarialRevocationThresholds,
    /// Event rows represented by the report.
    pub events: Vec<SwarmAdversarialRevocationEvent>,
    /// Final machine-readable outcome.
    pub outcome: SwarmAdversarialRevocationOutcome,
    /// Hard invariant failures.
    pub failures: Vec<SwarmAdversarialRevocationFailure>,
    /// Structured skip reasons emitted by the run.
    pub skip_reasons: Vec<String>,
    /// Report creation time.
    pub generated_at: DateTime<Utc>,
}

impl SwarmAdversarialRevocationReport {
    /// Evaluate adversarial revocation invariants for one scenario.
    #[must_use]
    pub fn evaluate(
        scenario_id: impl Into<String>,
        thresholds: SwarmAdversarialRevocationThresholds,
        events: Vec<SwarmAdversarialRevocationEvent>,
    ) -> Self {
        let scenario_id = scenario_id.into();
        let mut failures = Vec::new();
        let mut skip_reasons = events
            .iter()
            .filter_map(|event| event.skip_reason.clone())
            .collect::<Vec<_>>();
        skip_reasons.sort();
        skip_reasons.dedup();

        if events.is_empty() {
            failures.push(SwarmAdversarialRevocationFailure::new(
                SwarmAdversarialRevocationInvariant::ScenarioEvidencePresent,
                None,
                "no_adversarial_events",
                "0",
                ">=1 event or structured skip",
            ));
        }

        let run_events = events
            .iter()
            .filter(|event| !event.is_skip())
            .collect::<Vec<_>>();
        if run_events.is_empty() && !skip_reasons.is_empty() {
            return Self {
                schema_version: SWARM_ADVERSARIAL_REVOCATION_SCHEMA_VERSION.to_string(),
                scenario_id,
                thresholds,
                events,
                outcome: SwarmAdversarialRevocationOutcome::Skipped,
                failures,
                skip_reasons,
                generated_at: Utc::now(),
            };
        }

        failures.extend(Self::scenario_shape_failures(&scenario_id, &run_events));
        failures.extend(Self::revoked_work_failures(&run_events));
        failures.extend(Self::stale_malformed_failures(&run_events));
        failures.extend(Self::emergency_propagation_failures(
            &thresholds,
            &run_events,
        ));
        failures.extend(Self::audit_and_backpressure_failures(&run_events));
        failures.extend(Self::cleanup_failures(&run_events));
        failures.extend(Self::redaction_failures(&run_events));
        failures.extend(Self::retry_fallback_failures(&run_events));

        let outcome = if failures.is_empty() {
            SwarmAdversarialRevocationOutcome::Pass
        } else {
            SwarmAdversarialRevocationOutcome::Fail
        };

        Self {
            schema_version: SWARM_ADVERSARIAL_REVOCATION_SCHEMA_VERSION.to_string(),
            scenario_id,
            thresholds,
            events,
            outcome,
            failures,
            skip_reasons,
            generated_at: Utc::now(),
        }
    }

    fn scenario_shape_failures(
        scenario_id: &str,
        events: &[&SwarmAdversarialRevocationEvent],
    ) -> Vec<SwarmAdversarialRevocationFailure> {
        let mut failures = Vec::new();
        if events.is_empty() {
            failures.push(SwarmAdversarialRevocationFailure::new(
                SwarmAdversarialRevocationInvariant::ScenarioEvidencePresent,
                None,
                "no_executed_adversarial_events",
                "0",
                ">=1 non-skip event",
            ));
        }
        for event in events {
            if event.scenario_id != scenario_id {
                failures.push(SwarmAdversarialRevocationFailure::new(
                    SwarmAdversarialRevocationInvariant::ScenarioEvidencePresent,
                    Some(event.operation_id.clone()),
                    "scenario_mismatch",
                    event.scenario_id.clone(),
                    scenario_id.to_string(),
                ));
            }
            if event.node_count == 0 || event.request_count == 0 {
                failures.push(SwarmAdversarialRevocationFailure::new(
                    SwarmAdversarialRevocationInvariant::ScenarioEvidencePresent,
                    Some(event.operation_id.clone()),
                    "empty_scenario_dimensions",
                    format!(
                        "nodes={},requests={}",
                        event.node_count, event.request_count
                    ),
                    "node_count>0 and request_count>0",
                ));
            }
        }
        failures
    }

    fn revoked_work_failures(
        events: &[&SwarmAdversarialRevocationEvent],
    ) -> Vec<SwarmAdversarialRevocationFailure> {
        let mut failures = Vec::new();
        let revoked_events = events
            .iter()
            .copied()
            .filter(|event| event.revoked_work)
            .collect::<Vec<_>>();
        if revoked_events.is_empty() {
            failures.push(SwarmAdversarialRevocationFailure::new(
                SwarmAdversarialRevocationInvariant::RevokedWorkDenied,
                None,
                "no_revoked_work_probe",
                "0",
                ">=1 revoked operation",
            ));
        }
        for event in revoked_events {
            if event.admission_outcome != SwarmAdversarialAdmissionOutcome::Denied {
                failures.push(SwarmAdversarialRevocationFailure::new(
                    SwarmAdversarialRevocationInvariant::RevokedWorkDenied,
                    Some(event.operation_id.clone()),
                    "revoked_work_not_denied",
                    event.admission_outcome.as_str(),
                    SwarmAdversarialAdmissionOutcome::Denied.as_str(),
                ));
            }
            if event.denial_reason.as_deref().is_none_or(str::is_empty) {
                failures.push(SwarmAdversarialRevocationFailure::new(
                    SwarmAdversarialRevocationInvariant::RevokedWorkDenied,
                    Some(event.operation_id.clone()),
                    "missing_denial_reason",
                    "missing",
                    "revoked_token or revoked_principal",
                ));
            }
        }
        failures
    }

    fn stale_malformed_failures(
        events: &[&SwarmAdversarialRevocationEvent],
    ) -> Vec<SwarmAdversarialRevocationFailure> {
        let mut failures = Vec::new();
        if !events.iter().any(|event| event.stale_revocation) {
            failures.push(SwarmAdversarialRevocationFailure::new(
                SwarmAdversarialRevocationInvariant::StaleMalformedRevocationRejected,
                None,
                "missing_stale_revocation_probe",
                "0",
                ">=1 stale revocation row",
            ));
        }
        if !events.iter().any(|event| event.malformed_revocation) {
            failures.push(SwarmAdversarialRevocationFailure::new(
                SwarmAdversarialRevocationInvariant::StaleMalformedRevocationRejected,
                None,
                "missing_malformed_revocation_probe",
                "0",
                ">=1 malformed revocation row",
            ));
        }
        for event in events
            .iter()
            .copied()
            .filter(|event| event.stale_revocation || event.malformed_revocation)
        {
            if event.admission_outcome != SwarmAdversarialAdmissionOutcome::Denied {
                failures.push(SwarmAdversarialRevocationFailure::new(
                    SwarmAdversarialRevocationInvariant::StaleMalformedRevocationRejected,
                    Some(event.operation_id.clone()),
                    "revocation_probe_not_rejected",
                    event.admission_outcome.as_str(),
                    SwarmAdversarialAdmissionOutcome::Denied.as_str(),
                ));
            }
        }
        failures
    }

    fn emergency_propagation_failures(
        thresholds: &SwarmAdversarialRevocationThresholds,
        events: &[&SwarmAdversarialRevocationEvent],
    ) -> Vec<SwarmAdversarialRevocationFailure> {
        let mut failures = Vec::new();
        let witness_count = u64::try_from(
            events
                .iter()
                .filter(|event| event.emergency_revocation_witness)
                .count(),
        )
        .unwrap_or(u64::MAX);
        if witness_count < thresholds.min_emergency_revocation_witnesses {
            failures.push(SwarmAdversarialRevocationFailure::new(
                SwarmAdversarialRevocationInvariant::EmergencyRevocationNotStarved,
                None,
                "insufficient_emergency_revocation_witnesses",
                witness_count.to_string(),
                thresholds.min_emergency_revocation_witnesses.to_string(),
            ));
        }
        let max_p99 = events
            .iter()
            .filter(|event| event.emergency_revocation_witness)
            .map(|event| event.latency_percentiles.p99_ms)
            .max()
            .unwrap_or(0);
        if max_p99 > thresholds.max_emergency_propagation_p99_ms {
            failures.push(SwarmAdversarialRevocationFailure::new(
                SwarmAdversarialRevocationInvariant::EmergencyRevocationNotStarved,
                None,
                "emergency_revocation_p99_exceeded",
                max_p99.to_string(),
                thresholds.max_emergency_propagation_p99_ms.to_string(),
            ));
        }
        failures
    }

    fn audit_and_backpressure_failures(
        events: &[&SwarmAdversarialRevocationEvent],
    ) -> Vec<SwarmAdversarialRevocationFailure> {
        let mut failures = Vec::new();
        for event in events {
            if !event.audit_receipt_id.starts_with("audit-receipt-") {
                failures.push(SwarmAdversarialRevocationFailure::new(
                    SwarmAdversarialRevocationInvariant::AuditReceiptContinuity,
                    Some(event.operation_id.clone()),
                    "missing_audit_receipt",
                    event.audit_receipt_id.clone(),
                    "audit-receipt-*",
                ));
            }
            if event.backpressure_state.trim().is_empty() {
                failures.push(SwarmAdversarialRevocationFailure::new(
                    SwarmAdversarialRevocationInvariant::BackpressureActionVisible,
                    Some(event.operation_id.clone()),
                    "missing_backpressure_state",
                    "empty",
                    "non-empty state label",
                ));
            }
            if event.backpressure_action != SwarmAdversarialBackpressureAction::Admit
                && event.audit_receipt_id.is_empty()
            {
                failures.push(SwarmAdversarialRevocationFailure::new(
                    SwarmAdversarialRevocationInvariant::BackpressureActionVisible,
                    Some(event.operation_id.clone()),
                    "action_without_audit_link",
                    event.backpressure_action.as_str(),
                    "action with audit receipt id",
                ));
            }
        }
        failures
    }

    fn cleanup_failures(
        events: &[&SwarmAdversarialRevocationEvent],
    ) -> Vec<SwarmAdversarialRevocationFailure> {
        events
            .iter()
            .copied()
            .filter(|event| event.cleanup_outcome != SwarmAdversarialCleanupOutcome::Completed)
            .map(|event| {
                SwarmAdversarialRevocationFailure::new(
                    SwarmAdversarialRevocationInvariant::CleanupCompleted,
                    Some(event.operation_id.clone()),
                    "cleanup_not_completed",
                    event.cleanup_outcome.as_str(),
                    SwarmAdversarialCleanupOutcome::Completed.as_str(),
                )
            })
            .collect()
    }

    fn redaction_failures(
        events: &[&SwarmAdversarialRevocationEvent],
    ) -> Vec<SwarmAdversarialRevocationFailure> {
        let mut failures = Vec::new();
        for event in events {
            if !event.principal_ref.starts_with("principal:blake3:") {
                failures.push(SwarmAdversarialRevocationFailure::new(
                    SwarmAdversarialRevocationInvariant::RedactionSafe,
                    Some(event.operation_id.clone()),
                    "principal_ref_not_hashed",
                    event.principal_ref.clone(),
                    "principal:blake3:*",
                ));
            }
            if !event.token_ref.starts_with("token:blake3:") {
                failures.push(SwarmAdversarialRevocationFailure::new(
                    SwarmAdversarialRevocationInvariant::RedactionSafe,
                    Some(event.operation_id.clone()),
                    "token_ref_not_hashed",
                    event.token_ref.clone(),
                    "token:blake3:*",
                ));
            }
            let serialized = serde_json::to_string(event).unwrap_or_default();
            for marker in [
                "Bearer ",
                "sk-live-",
                "super-secret-value",
                "principal:raw:",
                "token:raw:",
            ] {
                if serialized.contains(marker) {
                    failures.push(SwarmAdversarialRevocationFailure::new(
                        SwarmAdversarialRevocationInvariant::RedactionSafe,
                        Some(event.operation_id.clone()),
                        "sensitive_marker_present",
                        marker,
                        "redacted evidence",
                    ));
                }
            }
        }
        failures
    }

    fn retry_fallback_failures(
        events: &[&SwarmAdversarialRevocationEvent],
    ) -> Vec<SwarmAdversarialRevocationFailure> {
        if events
            .iter()
            .any(|event| event.retry_count > 0 || event.fallback_count > 0)
        {
            return Vec::new();
        }

        vec![SwarmAdversarialRevocationFailure::new(
            SwarmAdversarialRevocationInvariant::RetryFallbackCountersVisible,
            None,
            "missing_retry_or_fallback_counters",
            "0",
            "retry_count>0 or fallback_count>0",
        )]
    }

    /// Render the report as detailed JSONL-ready records.
    ///
    /// # Errors
    ///
    /// Returns a serde error if any record cannot be converted to JSON.
    pub fn to_jsonl_values(&self) -> Result<Vec<Value>, serde_json::Error> {
        let mut records = Vec::new();
        for event in &self.events {
            records.push(json!({
                "record_type": "swarm_adversarial_revocation_event",
                "schema_version": event.schema_version,
                "scenario_id": event.scenario_id,
                "operation_id": event.operation_id,
                "node_count": event.node_count,
                "request_count": event.request_count,
                "zone": event.zone,
                "principal_ref": event.principal_ref,
                "token_ref": event.token_ref,
                "admission_outcome": event.admission_outcome.as_str(),
                "revocation_seq": event.revocation_seq,
                "revocation_head": event.revocation_head,
                "backpressure_state": event.backpressure_state,
                "backpressure_action": event.backpressure_action.as_str(),
                "audit_receipt_id": event.audit_receipt_id,
                "latency_percentiles": serde_json::to_value(event.latency_percentiles)?,
                "denial_reason": event.denial_reason,
                "cleanup_outcome": event.cleanup_outcome.as_str(),
                "skip_reason": event.skip_reason,
                "emergency_revocation_witness": event.emergency_revocation_witness,
                "revoked_work": event.revoked_work,
                "stale_revocation": event.stale_revocation,
                "malformed_revocation": event.malformed_revocation,
                "retry_count": event.retry_count,
                "fallback_count": event.fallback_count,
                "generated_at": event.generated_at,
            }));
        }
        for failure in &self.failures {
            records.push(json!({
                "record_type": "swarm_adversarial_revocation_failure",
                "schema_version": self.schema_version,
                "scenario_id": self.scenario_id,
                "operation_id": failure.operation_id,
                "invariant": failure.invariant.as_str(),
                "reason": failure.reason,
                "observed_value": failure.observed_value,
                "allowed_value": failure.allowed_value,
            }));
        }
        records.push(json!({
            "record_type": "swarm_adversarial_revocation_report",
            "schema_version": self.schema_version,
            "scenario_id": self.scenario_id,
            "outcome": self.outcome.as_str(),
            "thresholds": serde_json::to_value(self.thresholds)?,
            "node_count": self.events.iter().map(|event| event.node_count).max().unwrap_or(0),
            "request_count": self.events.iter().map(|event| event.request_count).max().unwrap_or(0),
            "event_count": self.events.len(),
            "revoked_denial_count": self.events.iter().filter(|event| {
                event.revoked_work
                    && event.admission_outcome == SwarmAdversarialAdmissionOutcome::Denied
            }).count(),
            "emergency_revocation_witness_count": self.events
                .iter()
                .filter(|event| event.emergency_revocation_witness)
                .count(),
            "stale_rejection_count": self.events.iter().filter(|event| {
                event.stale_revocation
                    && event.admission_outcome == SwarmAdversarialAdmissionOutcome::Denied
            }).count(),
            "malformed_rejection_count": self.events.iter().filter(|event| {
                event.malformed_revocation
                    && event.admission_outcome == SwarmAdversarialAdmissionOutcome::Denied
            }).count(),
            "retry_count": self.events.iter().map(|event| event.retry_count).sum::<u64>(),
            "fallback_count": self.events.iter().map(|event| event.fallback_count).sum::<u64>(),
            "failure_codes": self.failures
                .iter()
                .map(|failure| failure.invariant.as_str())
                .collect::<Vec<_>>(),
            "skip_reasons": self.skip_reasons,
            "generated_at": self.generated_at,
        }));
        Ok(records)
    }
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

    /// Pin the `usize → u32` bridge `from_environment` uses for CPU/NUMA
    /// counts. Realistic values must round-trip identically; the
    /// `u32::MAX + 1` boundary must saturate (panic-free) so the topology
    /// schema stays portable across 32/64-bit hosts.
    #[test]
    fn usize_to_u32_saturating_round_trips_realistic_counts_and_saturates_overflow() {
        // Real hardware sweep: 1, 64, 1024 cores, 4 GiB-equivalent count.
        for value in [0_usize, 1, 64, 1_024, 65_535, u32::MAX as usize] {
            assert_eq!(
                u64::from(usize_to_u32_saturating(value)),
                u64::try_from(value).expect("test inputs fit u64"),
                "realistic count {value} must round-trip identically"
            );
        }

        // Boundary: u32::MAX + 1 saturates to u32::MAX rather than wrapping
        // to 0. (On 32-bit hosts `usize::MAX == u32::MAX` so this branch
        // is no-op; this test only exercises the saturating arm on 64-bit.)
        if usize::BITS > u32::BITS {
            let oversize = (u32::MAX as usize) + 1;
            assert_eq!(usize_to_u32_saturating(oversize), u32::MAX);
            assert_eq!(usize_to_u32_saturating(usize::MAX), u32::MAX);
        }
    }

    fn swarm_test_environment() -> SwarmRunEnvironment {
        SwarmRunEnvironment {
            worker_id: "rch-worker-64c".to_string(),
            cpu_count: 64,
            physical_cpu_count: Some(32),
            numa_node_count: Some(2),
            memory_bytes: Some(256 * 1024 * 1024 * 1024),
            cargo_target_dir: Some("/tmp/fcp-swarm-target".to_string()),
            command_line: vec![
                "rch".to_string(),
                "exec".to_string(),
                "--".to_string(),
                "cargo".to_string(),
                "bench".to_string(),
            ],
            source_revision: Some("abc123".to_string()),
            captured_at: Utc::now(),
        }
    }

    fn required_swarm_artifacts() -> Vec<SwarmEvidenceArtifact> {
        SwarmEvidenceArtifactKind::REQUIRED
            .into_iter()
            .map(|kind| SwarmEvidenceArtifact::new(kind, format!("blake3:{}", kind.as_str()), true))
            .collect()
    }

    fn baseline_regression_snapshot() -> SwarmRegressionMetricSnapshot {
        SwarmRegressionMetricSnapshot {
            scenario_id: "host_batch_invoke_10000".to_string(),
            sample_count: 100,
            p99_ns: 100_000,
            p999_ns: 125_000,
            throughput_ops_per_second: 1_000_000,
            cpu_microunits: 64_000_000,
            rss_bytes: 8 * 1024 * 1024 * 1024,
            max_queue_depth: 1_000,
            retry_amplification_microunits: 100_000,
        }
    }

    fn baseline_promotion_manifest(
        scenario_id: &str,
        execution_mode: SwarmEvidenceExecutionMode,
    ) -> SwarmBaselinePromotionManifest {
        let now = Utc::now();
        SwarmBaselinePromotionManifest {
            schema_version: SWARM_BASELINE_PROMOTION_SCHEMA_VERSION.to_string(),
            baseline_id: format!("baseline:{scenario_id}:soak"),
            scenario_id: scenario_id.to_string(),
            execution_mode,
            source_revision: "baseline-revision".to_string(),
            rch_worker_id: "rch-worker-64c".to_string(),
            required_paths: SwarmBaselinePathKind::REQUIRED.to_vec(),
            artifact_digests: SwarmBaselineArtifactDigests::new(
                "blake3:raw-samples",
                "blake3:summary",
                "blake3:gate-report",
                "blake3:proof-notes",
                "blake3:manifest",
            ),
            redaction_policy: SwarmEvidenceRedactionPolicy::conservative(),
            operator_notes: "baseline promoted from retained raw samples and proof notes"
                .to_string(),
            promoted_at: now,
            expires_at: now + chrono::Duration::days(30),
        }
    }

    fn statistical_gate_input(
        candidate: SwarmRegressionMetricSnapshot,
    ) -> SwarmStatisticalGateInput {
        let baseline = baseline_regression_snapshot();
        SwarmStatisticalGateInput {
            baseline_manifest: baseline_promotion_manifest(
                &baseline.scenario_id,
                SwarmEvidenceExecutionMode::Smoke,
            ),
            baseline: baseline.clone(),
            candidate,
            thresholds: SwarmRegressionGateThresholds::smoke(),
            execution_mode: SwarmEvidenceExecutionMode::Smoke,
            tuning: SwarmStatisticalGateTuning::smoke(),
            baseline_quality: SwarmStatisticalTraceQuality::controlled(baseline.sample_count),
            candidate_quality: SwarmStatisticalTraceQuality::controlled(100),
            audit_event_count: 4,
            decision_card_replay_matches: true,
            operator_notes: "controlled statistical gate fixture".to_string(),
            generated_at: Utc::now(),
        }
    }

    fn gauntlet_phase_evidence() -> Vec<SwarmGauntletPhaseEvidence> {
        vec![
            SwarmGauntletPhaseEvidence::new(
                SwarmGauntletPhase::Fwc,
                "fwc",
                "command_log.txt#fwc-bench",
            ),
            SwarmGauntletPhaseEvidence::new(
                SwarmGauntletPhase::Host,
                "fcp-host",
                "summary.json#host",
            ),
            SwarmGauntletPhaseEvidence::new(
                SwarmGauntletPhase::Mesh,
                "fcp-mesh",
                "summary.json#mesh",
            ),
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

    fn gauntlet_decision_cards(scenario_id: &str) -> Vec<SwarmDecisionCard> {
        [
            (
                "card:scheduler",
                SwarmDecisionDomain::Scheduler,
                SwarmDecisionAction::Dispatch,
                "queue_congested",
                "p99_queueing",
            ),
            (
                "card:placement",
                SwarmDecisionDomain::Placement,
                SwarmDecisionAction::Place,
                "numa_pressure",
                "cross_numa_hops",
            ),
            (
                "card:backpressure",
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
                "connector:gauntlet-fixture",
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
                "counterfactual retained for replay",
            ))
            .with_evidence_pointers(vec![SwarmDecisionEvidencePointer::bundle_artifact(
                format!("raw_samples.jsonl#{scenario_id}"),
                "blake3:raw",
                true,
            )])
            .with_replay_inputs(BTreeMap::from([
                ("scenario_id".to_string(), json!(scenario_id)),
                ("queue_depth".to_string(), json!(512)),
            ]))
        })
        .collect()
    }

    fn gauntlet_latency_bundle() -> Result<SwarmLatencyEvidenceBundle, Box<dyn Error>> {
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
                (0_u64..3).map(move |sample_index| {
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
        let environment = swarm_test_environment();
        let manifest = SwarmEvidenceArtifactManifest::from_environment(
            "gauntlet-smoke",
            SwarmEvidenceSourceKind::HostBacked,
            SwarmEvidenceExecutionMode::Smoke,
            &environment,
            required_swarm_artifacts(),
            SwarmEvidenceRedactionPolicy::conservative(),
        )?;
        Ok(
            SwarmLatencyEvidenceBundle::from_samples(environment, scenarios, samples)?
                .with_artifact_manifest(manifest)?,
        )
    }

    fn gauntlet_resource_snapshots(
        bundle: &SwarmLatencyEvidenceBundle,
    ) -> Vec<SwarmRegressionMetricSnapshot> {
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

    fn gauntlet_resource_ledger_record(operation_id: &str, kind: &str) -> Value {
        json!({
            "record_type": "resource_ledger",
            "schema_version": SWARM_RESOURCE_LEDGER_SCHEMA_VERSION,
            "bead_id": "flywheel_connectors-k3zfl.10",
            "ledger": {
                "schema_version": SWARM_RESOURCE_LEDGER_SCHEMA_VERSION,
                "bead_id": "flywheel_connectors-k3zfl.10",
                "generated_at": Utc::now(),
                "scenario_id": "integrated_swarm_gauntlet_1000",
                "operation_id": operation_id,
                "kind": kind,
                "outcome": "admitted",
                "command_line": ["rch", "exec", "--", "cargo", "test"],
                "git_revision": "abc123",
                "worker_ref": "worker:blake3:0123456789abcdef",
                "zone_ref": "zone:blake3:0123456789abcdef",
                "principal_ref": "principal:blake3:0123456789abcdef",
                "connector_id": "connector:gauntlet-fixture",
                "controller_decision": "admitted",
                "samples": {
                    "state": "observed",
                    "queue_pressure_per_mille": 100,
                    "cpu_pressure_per_mille": 250,
                    "memory_pressure_per_mille": 300,
                    "in_flight": 32,
                    "queue_depth": 4,
                    "retry_after_ms": 0
                },
                "latency": {
                    "sample_count": 3,
                    "min_ns": 100,
                    "max_ns": 300,
                    "mean_ns": 200,
                    "p50_ns": 200,
                    "p95_ns": 300,
                    "p99_ns": 300
                }
            }
        })
    }

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
            physical_cpu_count: Some(32),
            numa_node_count: Some(2),
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

        let Err(err) = SwarmLatencyEvidenceBundle::from_samples(
            environment,
            standard_swarm_latency_scenarios(),
            vec![sample],
        ) else {
            return Err("unknown sample scenario must fail closed");
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
            physical_cpu_count: Some(32),
            numa_node_count: Some(2),
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
        assert_eq!(bundle.environment.physical_cpu_count, Some(32));
        assert_eq!(bundle.environment.numa_node_count, Some(2));
        assert_eq!(bundle.summaries[0].total.p99_ns, 750);
        Ok(())
    }

    #[test]
    fn swarm_evidence_manifest_validates_required_artifact_contract() -> Result<(), Box<dyn Error>>
    {
        let scenario = SwarmLatencyScenario::new(SwarmWorkloadKind::HostBatchInvoke, 1_000);
        let samples = vec![SwarmLatencySample::new(
            scenario.id.clone(),
            "agent-1",
            "op-1",
            0,
            LatencyBreakdown::new(100, 200, 0, 0, 0, 0),
        )];
        let environment = swarm_test_environment();
        let manifest = SwarmEvidenceArtifactManifest::from_environment(
            "bundle-smoke",
            SwarmEvidenceSourceKind::HostBacked,
            SwarmEvidenceExecutionMode::Smoke,
            &environment,
            required_swarm_artifacts(),
            SwarmEvidenceRedactionPolicy::conservative(),
        )?;
        let bundle =
            SwarmLatencyEvidenceBundle::from_samples(environment, vec![scenario], samples)?
                .with_artifact_manifest(manifest)?;

        let records = bundle.to_jsonl_values()?;
        let manifest_record = records
            .iter()
            .find(|record| record["record_type"] == "swarm_evidence_artifact_manifest")
            .ok_or("manifest record must be emitted")?;
        let roundtrip: SwarmEvidenceArtifactManifest =
            serde_json::from_value(manifest_record["manifest"].clone())?;

        assert_eq!(roundtrip.bundle_id, "bundle-smoke");
        assert_eq!(roundtrip.source_kind.as_str(), "host_backed");
        assert_eq!(roundtrip.execution_mode.as_str(), "smoke");
        assert!(roundtrip.replayable_offline());
        assert_eq!(
            roundtrip.artifacts.len(),
            SwarmEvidenceArtifactKind::REQUIRED.len()
        );
        Ok(())
    }

    #[test]
    fn swarm_evidence_manifest_rejects_missing_and_stale_fields() -> Result<(), &'static str> {
        let environment = swarm_test_environment();
        let mut missing_artifacts = required_swarm_artifacts();
        missing_artifacts.retain(|artifact| artifact.kind != SwarmEvidenceArtifactKind::ProofNotes);
        let Err(missing_err) = SwarmEvidenceArtifactManifest::from_environment(
            "bundle-missing",
            SwarmEvidenceSourceKind::HostBacked,
            SwarmEvidenceExecutionMode::Smoke,
            &environment,
            missing_artifacts,
            SwarmEvidenceRedactionPolicy::conservative(),
        ) else {
            return Err("missing proof notes artifact must fail");
        };

        assert_eq!(
            missing_err,
            SwarmEvidenceBundleError::MissingArtifact {
                kind: SwarmEvidenceArtifactKind::ProofNotes
            }
        );

        let stale_manifest = SwarmEvidenceArtifactManifest {
            schema_version: SWARM_EVIDENCE_BUNDLE_SCHEMA_VERSION.to_string(),
            bundle_id: "bundle-stale".to_string(),
            source_kind: SwarmEvidenceSourceKind::HostBacked,
            execution_mode: SwarmEvidenceExecutionMode::Smoke,
            source_revision: "def456".to_string(),
            rch_worker_id: environment.worker_id.clone(),
            artifacts: required_swarm_artifacts(),
            redaction_policy: SwarmEvidenceRedactionPolicy::conservative(),
            generated_at: Utc::now(),
        };
        let stale_err = match stale_manifest.validate_against_environment(&environment) {
            Ok(()) => return Err("stale source revision must fail"),
            Err(err) => err,
        };

        assert_eq!(
            stale_err,
            SwarmEvidenceBundleError::StaleSourceRevision {
                expected: "abc123".to_string(),
                actual: "def456".to_string()
            }
        );

        let mut missing_environment_revision = environment.clone();
        missing_environment_revision.source_revision = None;
        let missing_environment_err =
            match stale_manifest.validate_against_environment(&missing_environment_revision) {
                Ok(()) => return Err("missing environment source revision must fail"),
                Err(err) => err,
            };
        assert_eq!(
            missing_environment_err,
            SwarmEvidenceBundleError::MissingSourceRevision
        );

        let mut missing_manifest_revision = stale_manifest;
        missing_manifest_revision.source_revision = " ".to_string();
        let missing_manifest_err =
            match missing_manifest_revision.validate_against_environment(&environment) {
                Ok(()) => return Err("missing manifest source revision must fail"),
                Err(err) => err,
            };
        assert_eq!(
            missing_manifest_err,
            SwarmEvidenceBundleError::MissingSourceRevision
        );
        Ok(())
    }

    #[test]
    fn swarm_regression_gate_passes_bounded_smoke_budget() -> Result<(), Box<dyn Error>> {
        let baseline = baseline_regression_snapshot();
        let candidate = SwarmRegressionMetricSnapshot {
            p99_ns: 104_000,
            p999_ns: 131_000,
            throughput_ops_per_second: 970_000,
            cpu_microunits: 66_000_000,
            max_queue_depth: 1_050,
            retry_amplification_microunits: 105_000,
            ..baseline.clone()
        };
        let report = SwarmRegressionGateReport::evaluate(
            baseline,
            candidate,
            SwarmRegressionGateThresholds::smoke(),
            SwarmEvidenceExecutionMode::Smoke,
        );
        let record = report.to_jsonl_value()?;

        assert!(report.passed);
        assert!(report.failures.is_empty());
        assert_eq!(record["record_type"], "swarm_regression_gate_report");
        assert_eq!(
            record["schema_version"],
            SWARM_REGRESSION_GATE_SCHEMA_VERSION
        );
        Ok(())
    }

    #[test]
    fn swarm_regression_gate_reports_tail_and_resource_failures() {
        let baseline = baseline_regression_snapshot();
        let candidate = SwarmRegressionMetricSnapshot {
            sample_count: 5,
            p99_ns: 112_000,
            p999_ns: 140_000,
            throughput_ops_per_second: 900_000,
            cpu_microunits: 72_000_000,
            rss_bytes: 10 * 1024 * 1024 * 1024,
            max_queue_depth: 1_250,
            retry_amplification_microunits: 125_000,
            ..baseline.clone()
        };
        let report = SwarmRegressionGateReport::evaluate(
            baseline,
            candidate,
            SwarmRegressionGateThresholds::soak(),
            SwarmEvidenceExecutionMode::Soak,
        );
        let failed_metrics: BTreeSet<_> = report
            .failures
            .iter()
            .map(|failure| failure.metric)
            .collect();

        assert!(!report.passed);
        assert!(failed_metrics.contains(&SwarmRegressionMetricKind::SampleCount));
        assert!(failed_metrics.contains(&SwarmRegressionMetricKind::P99Latency));
        assert!(failed_metrics.contains(&SwarmRegressionMetricKind::P999Latency));
        assert!(failed_metrics.contains(&SwarmRegressionMetricKind::Throughput));
        assert!(failed_metrics.contains(&SwarmRegressionMetricKind::Cpu));
        assert!(failed_metrics.contains(&SwarmRegressionMetricKind::Rss));
        assert!(failed_metrics.contains(&SwarmRegressionMetricKind::QueueDepth));
        assert!(failed_metrics.contains(&SwarmRegressionMetricKind::RetryAmplification));
    }

    #[test]
    fn swarm_statistical_gate_passes_controlled_trace_with_retained_baseline()
    -> Result<(), Box<dyn Error>> {
        let baseline = baseline_regression_snapshot();
        let candidate = SwarmRegressionMetricSnapshot {
            p99_ns: 104_000,
            p999_ns: 131_000,
            throughput_ops_per_second: 970_000,
            cpu_microunits: 66_000_000,
            max_queue_depth: 1_050,
            retry_amplification_microunits: 105_000,
            ..baseline
        };
        let report = SwarmStatisticalGateReport::evaluate(statistical_gate_input(candidate));
        let records = report.to_jsonl_values()?;

        assert_eq!(report.outcome, SwarmStatisticalGateOutcome::Pass);
        assert!(report.reasons.is_empty());
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0]["record_type"],
            "swarm_baseline_promotion_manifest"
        );
        assert_eq!(records[1]["record_type"], "swarm_statistical_gate_report");
        assert_eq!(
            records[1]["schema_version"],
            SWARM_STATISTICAL_GATE_SCHEMA_VERSION
        );
        Ok(())
    }

    #[test]
    fn swarm_statistical_gate_fails_meaningful_tail_resource_audit_and_replay_regressions() {
        let baseline = baseline_regression_snapshot();
        let candidate = SwarmRegressionMetricSnapshot {
            p99_ns: 112_000,
            p999_ns: 141_000,
            throughput_ops_per_second: 900_000,
            cpu_microunits: 72_000_000,
            max_queue_depth: 1_250,
            retry_amplification_microunits: 125_000,
            ..baseline
        };
        let mut input = statistical_gate_input(candidate);
        input.audit_event_count = 0;
        input.decision_card_replay_matches = false;
        let report = SwarmStatisticalGateReport::evaluate(input);
        let reason_kinds: BTreeSet<_> = report.reasons.iter().map(|reason| reason.kind).collect();

        assert_eq!(report.outcome, SwarmStatisticalGateOutcome::Fail);
        assert!(reason_kinds.contains(&SwarmStatisticalGateReasonKind::P99Regression));
        assert!(reason_kinds.contains(&SwarmStatisticalGateReasonKind::P999Regression));
        assert!(reason_kinds.contains(&SwarmStatisticalGateReasonKind::ThroughputRegression));
        assert!(reason_kinds.contains(&SwarmStatisticalGateReasonKind::AuditLoss));
        assert!(reason_kinds.contains(&SwarmStatisticalGateReasonKind::DecisionCardReplayMismatch));
    }

    #[test]
    fn swarm_statistical_gate_rejects_stale_baseline_as_indeterminate() {
        let candidate = baseline_regression_snapshot();
        let mut input = statistical_gate_input(candidate);
        input.baseline_manifest.expires_at = input.generated_at - chrono::Duration::seconds(1);
        let report = SwarmStatisticalGateReport::evaluate(input);

        assert_eq!(report.outcome, SwarmStatisticalGateOutcome::Indeterminate);
        assert!(
            report
                .reasons
                .iter()
                .any(|reason| reason.kind == SwarmStatisticalGateReasonKind::StaleBaseline)
        );
    }

    #[test]
    fn swarm_statistical_gate_rejects_incompatible_baseline_as_indeterminate() {
        let candidate = baseline_regression_snapshot();
        let mut input = statistical_gate_input(candidate);
        input.baseline_manifest.scenario_id = "mesh_gossip_update_10000".to_string();
        let report = SwarmStatisticalGateReport::evaluate(input);

        assert_eq!(report.outcome, SwarmStatisticalGateOutcome::Indeterminate);
        assert!(report.reasons.iter().any(|reason| {
            reason.kind == SwarmStatisticalGateReasonKind::BaselineIncompatible
                && reason.message.contains("scenario mismatch")
        }));
    }

    #[test]
    fn swarm_statistical_gate_quarantines_noisy_worker_before_failing_candidate() {
        let baseline = baseline_regression_snapshot();
        let candidate = SwarmRegressionMetricSnapshot {
            p99_ns: 125_000,
            p999_ns: 160_000,
            ..baseline
        };
        let mut input = statistical_gate_input(candidate);
        input.candidate_quality.worker_drift_percent = 25;
        let report = SwarmStatisticalGateReport::evaluate(input);
        let reason_kinds: BTreeSet<_> = report.reasons.iter().map(|reason| reason.kind).collect();

        assert_eq!(report.outcome, SwarmStatisticalGateOutcome::Indeterminate);
        assert!(reason_kinds.contains(&SwarmStatisticalGateReasonKind::NoisyWorker));
        assert!(reason_kinds.contains(&SwarmStatisticalGateReasonKind::P99Regression));
    }

    #[test]
    fn swarm_statistical_gate_emits_golden_baseline_and_report_artifacts()
    -> Result<(), Box<dyn Error>> {
        let baseline = baseline_regression_snapshot();
        let report = SwarmStatisticalGateReport::evaluate(statistical_gate_input(baseline));
        let records = report.to_jsonl_values()?;
        let manifest_record = records
            .iter()
            .find(|record| record["record_type"] == "swarm_baseline_promotion_manifest")
            .ok_or("baseline manifest record should be present")?;
        let gate_record = records
            .iter()
            .find(|record| record["record_type"] == "swarm_statistical_gate_report")
            .ok_or("statistical gate report should be present")?;
        let jsonl = records
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()?
            .join("\n");

        assert_eq!(manifest_record["raw_sample_digest"], "blake3:raw-samples");
        assert_eq!(manifest_record["summary_digest"], "blake3:summary");
        assert_eq!(manifest_record["gate_report_digest"], "blake3:gate-report");
        assert_eq!(manifest_record["proof_notes_digest"], "blake3:proof-notes");
        assert_eq!(gate_record["redaction_policy"]["proof_notes_checked"], true);
        assert_eq!(gate_record["outcome"], "pass");
        assert_eq!(
            gate_record["reason_codes"].as_array().map(Vec::len),
            Some(0)
        );
        assert!(!jsonl.contains("Bearer test-token"));
        assert!(!jsonl.contains("super-secret-value"));
        Ok(())
    }

    #[test]
    fn swarm_decision_card_serializes_operator_contract() -> Result<(), Box<dyn Error>> {
        let card = SwarmDecisionCard::new(
            "card-1",
            SwarmDecisionDomain::Scheduler,
            "invoke:gmail.search",
            "queue_congested",
            SwarmDecisionAction::Delay,
            120,
            SwarmDecisionFallback::available(SwarmDecisionAction::Fallback),
        )
        .with_scenario("host_batch_invoke_10000")
        .with_loss_terms(vec![
            SwarmDecisionLossTerm::new("p99_queueing", 3_000, 1_000_000, "ns"),
            SwarmDecisionLossTerm::new("zone_fairness", 2, 2_000_000, "violations"),
        ])
        .with_calibration(SwarmCalibrationStatus::Valid)
        .with_counterfactual(SwarmDecisionCounterfactual::new(
            SwarmDecisionAction::Dispatch,
            900,
            "would amplify p99 queueing",
        ))
        .with_evidence_pointers(vec![
            SwarmDecisionEvidencePointer::bundle_artifact(
                "raw_samples.jsonl#host_batch_invoke_10000",
                "blake3:abc123",
                true,
            ),
            SwarmDecisionEvidencePointer::inline_summary("summary.p99_queueing"),
        ])
        .with_replay_inputs(BTreeMap::from([
            ("queue_depth".to_string(), json!(512)),
            ("zone".to_string(), json!("z:project:mail")),
        ]));

        let record = card.to_jsonl_value()?;
        let roundtrip: SwarmDecisionCard = serde_json::from_value(record["card"].clone())?;

        assert_eq!(roundtrip, card);
        assert_eq!(record["record_type"], "swarm_decision_card");
        assert_eq!(record["schema_version"], SWARM_DECISION_CARD_SCHEMA_VERSION);
        assert_eq!(card.domain.as_str(), "scheduler");
        assert_eq!(card.action.as_str(), "delay");
        assert!(card.is_replayable_offline());
        assert!(card.safe_to_disable());
        Ok(())
    }

    #[test]
    fn swarm_decision_card_marks_live_only_evidence_non_replayable() {
        let card = SwarmDecisionCard::new(
            "card-live",
            SwarmDecisionDomain::Backpressure,
            "connector:stripe",
            "downstream_throttled",
            SwarmDecisionAction::Throttle,
            25,
            SwarmDecisionFallback::available(SwarmDecisionAction::Fallback),
        )
        .with_evidence_pointers(vec![SwarmDecisionEvidencePointer::live_service(
            "https://live-host.example/status",
        )])
        .with_replay_inputs(BTreeMap::from([("retry_after_ms".to_string(), json!(250))]));

        assert!(!card.is_replayable_offline());
        assert!(!card.safe_to_disable());
    }

    #[test]
    fn swarm_decision_card_identifies_dominant_loss_term() -> Result<(), &'static str> {
        let card = SwarmDecisionCard::new(
            "card-loss",
            SwarmDecisionDomain::Placement,
            "connector:github",
            "numa_pressure",
            SwarmDecisionAction::Place,
            80,
            SwarmDecisionFallback::available(SwarmDecisionAction::Fallback),
        )
        .with_loss_terms(vec![
            SwarmDecisionLossTerm::new("rss_bytes", 512, 100, "bytes"),
            SwarmDecisionLossTerm::new("cross_numa_hops", 7, 10_000, "count"),
            SwarmDecisionLossTerm::new("cpu_headroom", 3, 1_000, "cores"),
        ]);

        let dominant = card
            .dominant_loss_term()
            .ok_or("decision card should have loss terms")?;

        assert_eq!(dominant.name, "cross_numa_hops");
        assert_eq!(dominant.weighted_score(), 70_000);
        Ok(())
    }

    #[test]
    fn swarm_decision_card_calibration_statuses_pin_fallback_triggers() {
        assert!(!SwarmCalibrationStatus::NotRequired.requires_fallback());
        assert!(!SwarmCalibrationStatus::Valid.requires_fallback());
        assert!(SwarmCalibrationStatus::DriftDetected.requires_fallback());
        assert!(SwarmCalibrationStatus::MissingTelemetry.requires_fallback());
        assert!(SwarmCalibrationStatus::ReplayMismatch.requires_fallback());
        assert_eq!(
            SwarmCalibrationStatus::ReplayMismatch.as_str(),
            "replay_mismatch"
        );
    }

    fn controller_decision_card(
        card_id: &str,
        domain: SwarmDecisionDomain,
        action: SwarmDecisionAction,
        scenario: SwarmControllerInteractionScenario,
    ) -> SwarmDecisionCard {
        SwarmDecisionCard::new(
            card_id,
            domain,
            "connector:swarm-safety",
            scenario.as_str(),
            action,
            100,
            SwarmDecisionFallback::available(SwarmDecisionAction::Fallback),
        )
        .with_scenario(scenario.as_str())
        .with_loss_terms(vec![
            SwarmDecisionLossTerm::new("p99_queueing", 100, 1_000_000, "ns"),
            SwarmDecisionLossTerm::new("zone_fairness", 2, 2_000_000, "skew"),
        ])
        .with_counterfactual(SwarmDecisionCounterfactual::new(
            SwarmDecisionAction::Fallback,
            120,
            "fallback is safe but lower-throughput",
        ))
        .with_evidence_pointers(vec![SwarmDecisionEvidencePointer::bundle_artifact(
            format!("raw_samples.jsonl#{}", scenario.as_str()),
            "blake3:controller-safety",
            true,
        )])
        .with_replay_inputs(BTreeMap::from([
            ("scenario".to_string(), json!(scenario.as_str())),
            ("queue_depth".to_string(), json!(64)),
            ("zone".to_string(), json!("z:project:swarm")),
        ]))
    }

    fn controller_decision_cards(
        scenario: SwarmControllerInteractionScenario,
    ) -> Vec<SwarmDecisionCard> {
        vec![
            controller_decision_card(
                "card:scheduler",
                SwarmDecisionDomain::Scheduler,
                SwarmDecisionAction::Dispatch,
                scenario,
            ),
            controller_decision_card(
                "card:placement",
                SwarmDecisionDomain::Placement,
                SwarmDecisionAction::Place,
                scenario,
            ),
            controller_decision_card(
                "card:backpressure",
                SwarmDecisionDomain::Backpressure,
                SwarmDecisionAction::Delay,
                scenario,
            ),
            controller_decision_card(
                "card:fallback",
                SwarmDecisionDomain::Backpressure,
                SwarmDecisionAction::Fallback,
                scenario,
            ),
        ]
    }

    fn controller_metrics(
        submitted_ops: u64,
        decision_card_count: u64,
    ) -> SwarmControllerModeMetrics {
        SwarmControllerModeMetrics {
            submitted_ops,
            accounted_ops: submitted_ops,
            audit_event_count: submitted_ops,
            max_starvation_ms: 250,
            zone_fairness_skew_microunits: 10_000,
            principal_fairness_skew_microunits: 10_000,
            counterfactual_count: decision_card_count,
            decision_card_count,
            ..SwarmControllerModeMetrics::default()
        }
    }

    fn passing_controller_modes(
        scenario: SwarmControllerInteractionScenario,
    ) -> Vec<SwarmControllerModeEvidence> {
        let scheduler = controller_metrics(128, 1);
        let placement = controller_metrics(128, 1);
        let mut backpressure = controller_metrics(128, 1);
        backpressure.delayed_ops = 8;
        let mut audit = controller_metrics(128, 0);
        audit.counterfactual_count = 0;
        let mut combined = controller_metrics(128, 3);
        combined.delayed_ops = 8;
        combined.shed_ops = 1;
        let mut fallback = controller_metrics(128, 1);
        fallback.fallback_invocations = 1;

        vec![
            SwarmControllerModeEvidence::new(
                scenario,
                SwarmControllerMode::SchedulerOnly,
                scheduler,
                vec!["card:scheduler".to_string()],
            ),
            SwarmControllerModeEvidence::new(
                scenario,
                SwarmControllerMode::PlacementOnly,
                placement,
                vec!["card:placement".to_string()],
            ),
            SwarmControllerModeEvidence::new(
                scenario,
                SwarmControllerMode::BackpressureOnly,
                backpressure,
                vec!["card:backpressure".to_string()],
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
                    "card:scheduler".to_string(),
                    "card:placement".to_string(),
                    "card:backpressure".to_string(),
                ],
            ),
            SwarmControllerModeEvidence::new(
                scenario,
                SwarmControllerMode::ConservativeFallback,
                fallback,
                vec!["card:fallback".to_string()],
            ),
        ]
    }

    fn adversarial_event(
        operation_id: &str,
        admission_outcome: SwarmAdversarialAdmissionOutcome,
        denial_reason: Option<&str>,
    ) -> SwarmAdversarialRevocationEvent {
        SwarmAdversarialRevocationEvent::new(SwarmAdversarialRevocationEventInput {
            scenario_id: "adversarial_revocation_overload_smoke".to_string(),
            operation_id: operation_id.to_string(),
            node_count: 8,
            request_count: 2_048,
            zone: "z:project:adversarial-swarm".to_string(),
            principal_ref: "principal:blake3:0123456789abcdef".to_string(),
            token_ref: "token:blake3:0123456789abcdef".to_string(),
            admission_outcome,
            revocation_seq: 42,
            revocation_head: "revocation-head:blake3:0123456789abcdef".to_string(),
            backpressure_state: "overloaded_zone".to_string(),
            backpressure_action: SwarmAdversarialBackpressureAction::Delay,
            audit_receipt_id: format!("audit-receipt-{operation_id}"),
            latency_percentiles: SwarmAdversarialLatencyPercentiles::new(12, 45, 120),
            denial_reason: denial_reason.map(str::to_string),
            cleanup_outcome: SwarmAdversarialCleanupOutcome::Completed,
            skip_reason: None,
            emergency_revocation_witness: false,
            revoked_work: false,
            stale_revocation: false,
            malformed_revocation: false,
            retry_count: 0,
            fallback_count: 0,
        })
    }

    fn passing_adversarial_events() -> Vec<SwarmAdversarialRevocationEvent> {
        let mut revoked = adversarial_event(
            "op-revoked-token",
            SwarmAdversarialAdmissionOutcome::Denied,
            Some("revoked_token"),
        );
        revoked.revoked_work = true;
        revoked.retry_count = 3;

        let mut emergency = adversarial_event(
            "op-emergency-propagation-a",
            SwarmAdversarialAdmissionOutcome::Delayed,
            None,
        );
        emergency.emergency_revocation_witness = true;
        emergency.backpressure_action = SwarmAdversarialBackpressureAction::EmergencyPropagate;
        emergency.latency_percentiles = SwarmAdversarialLatencyPercentiles::new(10, 30, 90);

        let mut emergency_fallback = adversarial_event(
            "op-emergency-propagation-b",
            SwarmAdversarialAdmissionOutcome::Delayed,
            None,
        );
        emergency_fallback.emergency_revocation_witness = true;
        emergency_fallback.backpressure_action = SwarmAdversarialBackpressureAction::Fallback;
        emergency_fallback.fallback_count = 1;
        emergency_fallback.latency_percentiles =
            SwarmAdversarialLatencyPercentiles::new(15, 50, 140);

        let mut stale = adversarial_event(
            "op-stale-revocation",
            SwarmAdversarialAdmissionOutcome::Denied,
            Some("stale_revocation"),
        );
        stale.stale_revocation = true;

        let mut malformed = adversarial_event(
            "op-malformed-revocation",
            SwarmAdversarialAdmissionOutcome::Denied,
            Some("malformed_revocation"),
        );
        malformed.malformed_revocation = true;

        vec![revoked, emergency, emergency_fallback, stale, malformed]
    }

    #[test]
    fn swarm_controller_safety_report_passes_every_scripted_scenario() {
        for scenario in SwarmControllerInteractionScenario::REQUIRED {
            let report = SwarmControllerSafetyReport::evaluate(
                scenario,
                SwarmControllerSafetyThresholds::smoke(),
                passing_controller_modes(scenario),
                controller_decision_cards(scenario),
            );

            assert_eq!(report.outcome, SwarmControllerSafetyOutcome::Pass);
            assert!(
                report.failures.is_empty(),
                "{scenario:?}: {:?}",
                report.failures
            );
            assert_eq!(report.modes.len(), SwarmControllerMode::REQUIRED.len());
            assert_eq!(scenario.as_str(), report.scenario.as_str());
        }
    }

    #[test]
    fn swarm_controller_safety_report_fails_hidden_drop_fairness_audit_and_replay_regressions()
    -> Result<(), &'static str> {
        let scenario = SwarmControllerInteractionScenario::SameZoneAuditStorm;
        let mut modes = passing_controller_modes(scenario);
        let combined = modes
            .iter_mut()
            .find(|mode| mode.mode == SwarmControllerMode::CombinedController)
            .ok_or("combined mode should be present")?;
        combined.metrics.accounted_ops = 126;
        combined.metrics.hidden_drop_count = 2;
        combined.metrics.no_op_delay_count = 1;
        combined.metrics.silent_warning_admission_count = 1;
        combined.metrics.audit_event_count = 120;
        combined.metrics.replay_mismatch_count = 1;
        combined.metrics.max_starvation_ms = 10_000;
        combined.metrics.zone_fairness_skew_microunits = 250_000;
        combined.metrics.principal_fairness_skew_microunits = 200_000;

        let report = SwarmControllerSafetyReport::evaluate(
            scenario,
            SwarmControllerSafetyThresholds::smoke(),
            modes,
            controller_decision_cards(scenario),
        );
        let invariants: BTreeSet<_> = report
            .failures
            .iter()
            .map(|failure| failure.invariant)
            .collect();

        assert_eq!(report.outcome, SwarmControllerSafetyOutcome::Fail);
        assert!(invariants.contains(&SwarmControllerSafetyInvariant::WorkConservation));
        assert!(invariants.contains(&SwarmControllerSafetyInvariant::BoundedStarvation));
        assert!(invariants.contains(&SwarmControllerSafetyInvariant::ZonePrincipalFairness));
        assert!(invariants.contains(&SwarmControllerSafetyInvariant::BackpressureActionVisible));
        assert!(invariants.contains(&SwarmControllerSafetyInvariant::NoAuditLoss));
        assert!(invariants.contains(&SwarmControllerSafetyInvariant::DeterministicReplay));
        Ok(())
    }

    #[test]
    fn swarm_controller_safety_report_requires_fallback_for_missing_telemetry_and_drift()
    -> Result<(), &'static str> {
        let scenario = SwarmControllerInteractionScenario::DownstreamThrottled;
        let mut cards = controller_decision_cards(scenario);
        cards[2] = cards[2]
            .clone()
            .with_calibration(SwarmCalibrationStatus::MissingTelemetry);
        let mut modes = passing_controller_modes(scenario);
        let backpressure = modes
            .iter_mut()
            .find(|mode| mode.mode == SwarmControllerMode::BackpressureOnly)
            .ok_or("backpressure mode should be present")?;
        backpressure.metrics.fallback_invocations = 1;
        backpressure.fallback_reason = Some("missing_telemetry".to_string());

        let missing_telemetry_report = SwarmControllerSafetyReport::evaluate(
            scenario,
            SwarmControllerSafetyThresholds::smoke(),
            modes,
            cards,
        );

        assert_eq!(
            missing_telemetry_report.outcome,
            SwarmControllerSafetyOutcome::FallbackRequired
        );
        assert!(missing_telemetry_report.failures.is_empty());
        assert!(
            missing_telemetry_report
                .fallback_reasons
                .iter()
                .any(|reason| reason.contains("missing_telemetry"))
        );

        let scenario = SwarmControllerInteractionScenario::CpuSaturated;
        let mut cards = controller_decision_cards(scenario);
        cards[0] = cards[0]
            .clone()
            .with_calibration(SwarmCalibrationStatus::DriftDetected);
        let mut modes = passing_controller_modes(scenario);
        let scheduler = modes
            .iter_mut()
            .find(|mode| mode.mode == SwarmControllerMode::SchedulerOnly)
            .ok_or("scheduler mode should be present")?;
        scheduler.metrics.fallback_invocations = 1;
        scheduler.fallback_reason = Some("calibration_drift".to_string());

        let drift_report = SwarmControllerSafetyReport::evaluate(
            scenario,
            SwarmControllerSafetyThresholds::smoke(),
            modes,
            cards,
        );

        assert_eq!(
            drift_report.outcome,
            SwarmControllerSafetyOutcome::FallbackRequired
        );
        assert!(drift_report.failures.is_empty());
        assert!(
            drift_report
                .fallback_reasons
                .iter()
                .any(|reason| reason.contains("drift_detected"))
        );
        Ok(())
    }

    #[test]
    fn swarm_controller_safety_report_requires_combined_counterfactuals() -> Result<(), &'static str>
    {
        let scenario = SwarmControllerInteractionScenario::MixedPriority;
        let mut cards = controller_decision_cards(scenario);
        cards[0].counterfactual = None;
        let mut modes = passing_controller_modes(scenario);
        let combined = modes
            .iter_mut()
            .find(|mode| mode.mode == SwarmControllerMode::CombinedController)
            .ok_or("combined mode should be present")?;
        combined.metrics.counterfactual_count = 2;

        let report = SwarmControllerSafetyReport::evaluate(
            scenario,
            SwarmControllerSafetyThresholds::smoke(),
            modes,
            cards,
        );

        assert_eq!(report.outcome, SwarmControllerSafetyOutcome::Fail);
        assert!(report.failures.iter().any(|failure| {
            failure.invariant == SwarmControllerSafetyInvariant::CounterfactualRetained
                && failure
                    .decision_card_ids
                    .iter()
                    .any(|id| id == "card:scheduler")
        }));
        Ok(())
    }

    #[test]
    fn swarm_controller_safety_report_emits_replayable_jsonl_with_decision_card_ids()
    -> Result<(), Box<dyn Error>> {
        let scenario = SwarmControllerInteractionScenario::RetryStorm;
        let report = SwarmControllerSafetyReport::evaluate(
            scenario,
            SwarmControllerSafetyThresholds::smoke(),
            passing_controller_modes(scenario),
            controller_decision_cards(scenario),
        );
        let records = report.to_jsonl_values()?;
        let record_types: BTreeSet<_> = records
            .iter()
            .filter_map(|record| record["record_type"].as_str())
            .collect();
        let summary = records
            .iter()
            .find(|record| record["record_type"] == "swarm_controller_safety_report")
            .ok_or("controller safety report should be present")?;
        let jsonl = records
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()?
            .join("\n");

        assert!(record_types.contains("swarm_decision_card"));
        assert!(record_types.contains("swarm_controller_safety_mode_evidence"));
        assert!(record_types.contains("swarm_controller_safety_report"));
        assert_eq!(
            summary["schema_version"],
            SWARM_CONTROLLER_SAFETY_SCHEMA_VERSION
        );
        assert_eq!(summary["scenario"], "retry_storm");
        assert_eq!(summary["outcome"], "pass");
        assert!(
            summary["decision_card_ids"]
                .as_array()
                .ok_or("decision card ids should be an array")?
                .iter()
                .any(|id| id == "card:backpressure")
        );
        for line in jsonl.lines() {
            serde_json::from_str::<Value>(line)?;
        }
        assert!(!jsonl.contains("Bearer test-token"));
        assert!(!jsonl.contains("super-secret-value"));
        Ok(())
    }

    #[test]
    fn swarm_adversarial_revocation_report_passes_fail_closed_overload_fixture()
    -> Result<(), Box<dyn Error>> {
        let report = SwarmAdversarialRevocationReport::evaluate(
            "adversarial_revocation_overload_smoke",
            SwarmAdversarialRevocationThresholds::smoke(),
            passing_adversarial_events(),
        );
        let records = report.to_jsonl_values()?;
        let summary = records
            .iter()
            .find(|record| record["record_type"] == "swarm_adversarial_revocation_report")
            .ok_or("adversarial revocation report should be present")?;
        let event_types: BTreeSet<_> = records
            .iter()
            .filter_map(|record| record["record_type"].as_str())
            .collect();
        let jsonl = records
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()?
            .join("\n");

        assert_eq!(report.outcome, SwarmAdversarialRevocationOutcome::Pass);
        assert!(report.failures.is_empty());
        assert!(event_types.contains("swarm_adversarial_revocation_event"));
        assert!(event_types.contains("swarm_adversarial_revocation_report"));
        assert_eq!(
            summary["schema_version"],
            SWARM_ADVERSARIAL_REVOCATION_SCHEMA_VERSION
        );
        assert_eq!(summary["node_count"], 8);
        assert_eq!(summary["request_count"], 2_048);
        assert_eq!(summary["revoked_denial_count"], 1);
        assert_eq!(summary["stale_rejection_count"], 1);
        assert_eq!(summary["malformed_rejection_count"], 1);
        assert_eq!(summary["emergency_revocation_witness_count"], 2);
        assert_eq!(summary["retry_count"], 3);
        assert_eq!(summary["fallback_count"], 1);
        for line in jsonl.lines() {
            serde_json::from_str::<Value>(line)?;
        }
        assert!(!jsonl.contains("Bearer test-token"));
        assert!(!jsonl.contains("super-secret-value"));
        assert!(!jsonl.contains("principal:raw:"));
        assert!(!jsonl.contains("token:raw:"));
        Ok(())
    }

    #[test]
    fn swarm_adversarial_revocation_report_fails_open_admission_stale_and_redaction_regressions() {
        let mut events = passing_adversarial_events();
        events[0].admission_outcome = SwarmAdversarialAdmissionOutcome::Admitted;
        events[0].principal_ref = "principal:raw:owner@example.com".to_string();
        events[3].admission_outcome = SwarmAdversarialAdmissionOutcome::Admitted;
        events[4].token_ref = "token:raw:Bearer sk-live-example".to_string();

        let report = SwarmAdversarialRevocationReport::evaluate(
            "adversarial_revocation_overload_smoke",
            SwarmAdversarialRevocationThresholds::smoke(),
            events,
        );
        let invariants = report
            .failures
            .iter()
            .map(|failure| failure.invariant)
            .collect::<BTreeSet<_>>();

        assert_eq!(report.outcome, SwarmAdversarialRevocationOutcome::Fail);
        assert!(invariants.contains(&SwarmAdversarialRevocationInvariant::RevokedWorkDenied));
        assert!(
            invariants
                .contains(&SwarmAdversarialRevocationInvariant::StaleMalformedRevocationRejected)
        );
        assert!(invariants.contains(&SwarmAdversarialRevocationInvariant::RedactionSafe));
    }

    #[test]
    fn swarm_adversarial_revocation_report_emits_structured_skip_artifact()
    -> Result<(), Box<dyn Error>> {
        let skip_event =
            SwarmAdversarialRevocationEvent::new(SwarmAdversarialRevocationEventInput {
                scenario_id: "adversarial_revocation_tailnet_10000".to_string(),
                operation_id: "op-skip-tailnet-prereq".to_string(),
                node_count: 0,
                request_count: 0,
                zone: "z:project:adversarial-swarm".to_string(),
                principal_ref: "principal:blake3:0123456789abcdef".to_string(),
                token_ref: "token:blake3:0123456789abcdef".to_string(),
                admission_outcome: SwarmAdversarialAdmissionOutcome::Skipped,
                revocation_seq: 0,
                revocation_head: "revocation-head:blake3:skip".to_string(),
                backpressure_state: "not_executed".to_string(),
                backpressure_action: SwarmAdversarialBackpressureAction::Admit,
                audit_receipt_id: "audit-receipt-skip-tailnet-prereq".to_string(),
                latency_percentiles: SwarmAdversarialLatencyPercentiles::default(),
                denial_reason: None,
                cleanup_outcome: SwarmAdversarialCleanupOutcome::Skipped,
                skip_reason: Some("requires_64_nodes_256gib_tailnet".to_string()),
                emergency_revocation_witness: false,
                revoked_work: false,
                stale_revocation: false,
                malformed_revocation: false,
                retry_count: 0,
                fallback_count: 0,
            });
        let report = SwarmAdversarialRevocationReport::evaluate(
            "adversarial_revocation_tailnet_10000",
            SwarmAdversarialRevocationThresholds::smoke(),
            vec![skip_event],
        );
        let records = report.to_jsonl_values()?;
        let jsonl = records
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()?
            .join("\n");

        assert_eq!(report.outcome, SwarmAdversarialRevocationOutcome::Skipped);
        assert!(report.failures.is_empty());
        assert!(jsonl.contains("requires_64_nodes_256gib_tailnet"));
        assert!(jsonl.contains("swarm_adversarial_revocation_event"));
        assert!(jsonl.contains("swarm_adversarial_revocation_report"));
        Ok(())
    }

    #[test]
    fn swarm_promotion_envelope_requires_all_controller_modes() {
        let mut envelope = SwarmPromotionEnvelope::high_core_256gib(vec![
            "rch".to_string(),
            "exec".to_string(),
            "--".to_string(),
            "cargo".to_string(),
            "bench".to_string(),
        ]);
        envelope
            .required_controller_modes
            .retain(|mode| *mode != SwarmPromotionControllerMode::CombinedController);

        assert_eq!(
            envelope.validate(),
            Err(SwarmPromotionEnvelopeError::MissingControllerMode {
                mode: SwarmPromotionControllerMode::CombinedController
            })
        );
    }

    #[test]
    fn swarm_promotion_qualification_accepts_complete_64c_256gib_topology()
    -> Result<(), Box<dyn Error>> {
        let envelope =
            SwarmPromotionEnvelope::high_core_256gib(vec!["rch".to_string(), "exec".to_string()]);
        let topology = SwarmPromotionTopology::from_environment(
            &swarm_test_environment(),
            "linux 6.8",
            "6.8.0-fcp",
            Some("performance".to_string()),
            Some("local-nvme".to_string()),
        );

        let qualification = SwarmPromotionQualification::evaluate(envelope, topology)?;

        assert!(qualification.is_qualified());
        assert!(qualification.skip_reasons.is_empty());
        assert_eq!(qualification.topology.logical_cpus, 64);
        assert_eq!(qualification.topology.numa_nodes, Some(2));
        Ok(())
    }

    #[test]
    fn swarm_promotion_qualification_classifies_missing_hardware_prerequisites()
    -> Result<(), Box<dyn Error>> {
        let mut environment = swarm_test_environment();
        environment.worker_id.clear();
        environment.cpu_count = 16;
        environment.physical_cpu_count = None;
        environment.numa_node_count = None;
        environment.memory_bytes = Some(32 * 1024 * 1024 * 1024);
        let envelope =
            SwarmPromotionEnvelope::high_core_256gib(vec!["rch".to_string(), "exec".to_string()]);
        let topology = SwarmPromotionTopology::from_environment(
            &environment,
            "",
            "",
            Some(String::new()),
            None,
        );

        let qualification = SwarmPromotionQualification::evaluate(envelope, topology)?;
        let codes: BTreeSet<_> = qualification
            .skip_reasons
            .iter()
            .map(SwarmPromotionSkipReason::code)
            .collect();

        assert!(!qualification.is_qualified());
        assert!(codes.contains("missing_worker_identity"));
        assert!(codes.contains("insufficient_logical_cpus"));
        assert!(codes.contains("missing_physical_cpu_topology"));
        assert!(codes.contains("missing_numa_topology"));
        assert!(codes.contains("insufficient_memory"));
        assert!(codes.contains("missing_os"));
        assert!(codes.contains("missing_kernel"));
        assert!(codes.contains("missing_cpu_governor"));
        assert!(codes.contains("missing_storage_class"));
        Ok(())
    }

    #[test]
    fn swarm_promotion_skip_artifact_emits_rerunnable_jsonl() -> Result<(), Box<dyn Error>> {
        let mut environment = swarm_test_environment();
        environment.cpu_count = 8;
        environment.memory_bytes = None;
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
        ]);
        let topology = SwarmPromotionTopology::from_environment(
            &environment,
            "macos 15",
            "24.4.0",
            Some("automatic".to_string()),
            Some("local-ssd".to_string()),
        );
        let qualification = SwarmPromotionQualification::evaluate(envelope, topology)?;
        let artifact = SwarmPromotionSkipArtifact::from_qualification(qualification)
            .ok_or("non-qualifying topology should emit promotion skip artifact")?;

        let records = artifact.to_jsonl_values()?;
        let record_types: BTreeSet<_> = records
            .iter()
            .filter_map(|record| record["record_type"].as_str())
            .collect();
        let skip_record = records
            .iter()
            .find(|record| record["record_type"] == "swarm_promotion_skip")
            .ok_or("promotion skip record should be emitted")?;
        let jsonl = records
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()?
            .join("\n");

        assert!(record_types.contains("swarm_promotion_envelope"));
        assert!(record_types.contains("swarm_promotion_topology"));
        assert!(record_types.contains("swarm_promotion_skip"));
        assert_eq!(
            skip_record["schema_version"],
            SWARM_PROMOTION_SCHEMA_VERSION
        );
        assert!(
            skip_record["skip_reason_codes"]
                .as_array()
                .ok_or("skip reason codes should be an array")?
                .iter()
                .any(|code| code == "missing_memory_measurement")
        );
        assert!(jsonl.contains("swarm_gauntlet_e2e"));
        for line in jsonl.lines() {
            serde_json::from_str::<Value>(line)?;
        }
        Ok(())
    }

    #[test]
    fn swarm_gauntlet_manifest_parser_validates_required_contract() -> Result<(), Box<dyn Error>> {
        let manifest_json = json!({
            "schema_version": SWARM_GAUNTLET_SCHEMA_VERSION,
            "scenario_id": "integrated_swarm_gauntlet_1000",
            "execution_mode": "smoke",
            "source_kind": "offline",
            "agent_count": 1000,
            "sample_budget": 1,
            "required_phases": SwarmGauntletPhase::REQUIRED,
            "command_line": ["cargo", "test", "-p", "fcp-e2e", "--test", "swarm_gauntlet_e2e"],
        });

        let manifest = SwarmGauntletManifest::from_json_value(manifest_json)?;

        assert_eq!(manifest.schema_version, SWARM_GAUNTLET_SCHEMA_VERSION);
        assert_eq!(manifest.agent_count, 1_000);
        assert_eq!(manifest.execution_mode, SwarmEvidenceExecutionMode::Smoke);
        assert_eq!(manifest.required_phases, SwarmGauntletPhase::REQUIRED);
        Ok(())
    }

    #[test]
    fn swarm_gauntlet_manifest_rejects_missing_phase() {
        let mut manifest = SwarmGauntletManifest::smoke(vec!["cargo".to_string()]);
        manifest
            .required_phases
            .retain(|phase| *phase != SwarmGauntletPhase::Backpressure);

        let err = manifest.validate().expect_err("missing phase must fail");

        assert_eq!(
            err,
            SwarmGauntletManifestError::MissingRequiredPhase {
                phase: SwarmGauntletPhase::Backpressure
            }
        );
    }

    #[test]
    fn swarm_gauntlet_soak_manifest_emits_structured_skip_artifact() -> Result<(), Box<dyn Error>> {
        let manifest = SwarmGauntletManifest::soak(
            vec![
                "rch".to_string(),
                "exec".to_string(),
                "--".to_string(),
                "cargo".to_string(),
                "test".to_string(),
                "-p".to_string(),
                "fcp-e2e".to_string(),
                "--test".to_string(),
                "swarm_gauntlet_e2e".to_string(),
            ],
            vec![
                SwarmGauntletPrerequisite::new("64-logical-cpus", false, "need promotion host"),
                SwarmGauntletPrerequisite::new("256gib-memory", false, "need promotion host"),
            ],
        );
        let skip = SwarmGauntletSkipArtifact::from_manifest(&manifest, &swarm_test_environment())
            .ok_or("missing prerequisites should create skip artifact")?;

        assert_eq!(skip.scenario_id, "integrated_swarm_gauntlet_10000");
        assert_eq!(skip.execution_mode, SwarmEvidenceExecutionMode::Soak);
        assert_eq!(
            skip.missing_prerequisites,
            vec!["64-logical-cpus".to_string(), "256gib-memory".to_string()]
        );
        assert!(skip.rerun_command.contains(&"rch".to_string()));
        Ok(())
    }

    #[test]
    fn swarm_gauntlet_summary_aggregates_existing_evidence_surfaces() -> Result<(), Box<dyn Error>>
    {
        let manifest = SwarmGauntletManifest::smoke(vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "fcp-e2e".to_string(),
            "--test".to_string(),
            "swarm_gauntlet_e2e".to_string(),
        ]);
        let latency_bundle = gauntlet_latency_bundle()?;
        let resources = gauntlet_resource_snapshots(&latency_bundle);
        let first_scenario = latency_bundle.summaries[0].scenario_id.clone();
        let gauntlet = SwarmGauntletEvidenceBundle::new(
            manifest,
            latency_bundle,
            resources,
            gauntlet_decision_cards(&first_scenario),
            gauntlet_phase_evidence(),
            SwarmGauntletCounters {
                audit_event_count: 4,
                same_zone_audit_appends: 512,
                sparse_high_k_metadata_events: 3,
            },
            None,
        )?;
        let summary = gauntlet.summary();

        assert_eq!(summary.agent_count, 1_000);
        assert_eq!(summary.sample_count, 12);
        assert_eq!(summary.summary_count, 4);
        assert_eq!(summary.decision_card_ids.len(), 3);
        assert_eq!(summary.resource_ledger_record_count, 0);
        assert_eq!(summary.phase_count, SwarmGauntletPhase::REQUIRED.len());
        assert_eq!(summary.counters.same_zone_audit_appends, 512);
        Ok(())
    }

    #[test]
    fn swarm_gauntlet_carries_resource_ledger_records_for_operator_correlation()
    -> Result<(), Box<dyn Error>> {
        let manifest = SwarmGauntletManifest::smoke(vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "fcp-e2e".to_string(),
            "--test".to_string(),
            "swarm_gauntlet_e2e".to_string(),
        ]);
        let latency_bundle = gauntlet_latency_bundle()?;
        let resources = gauntlet_resource_snapshots(&latency_bundle);
        let first_scenario = latency_bundle.summaries[0].scenario_id.clone();
        let gauntlet = SwarmGauntletEvidenceBundle::new(
            manifest,
            latency_bundle,
            resources,
            gauntlet_decision_cards(&first_scenario),
            gauntlet_phase_evidence(),
            SwarmGauntletCounters {
                audit_event_count: 4,
                same_zone_audit_appends: 512,
                sparse_high_k_metadata_events: 3,
            },
            None,
        )?
        .with_resource_ledger_records(vec![
            gauntlet_resource_ledger_record("op-host-invoke", "invoke"),
            gauntlet_resource_ledger_record("op-host-backpressure", "backpressure"),
        ])?;

        let records = gauntlet.to_jsonl_values()?;
        let summary = gauntlet.summary();
        let log_record = records
            .iter()
            .find(|record| record["record_type"] == "swarm_gauntlet_log")
            .ok_or("gauntlet log record must be emitted")?;

        assert_eq!(summary.resource_ledger_record_count, 2);
        assert_eq!(log_record["resource_ledger_record_count"], 2);
        assert_eq!(log_record["resource_ledger_record_type"], "resource_ledger");
        assert_eq!(
            log_record["resource_ledger_operation_ids"],
            json!(["op-host-invoke", "op-host-backpressure"])
        );
        assert!(
            records
                .iter()
                .any(|record| record["record_type"] == "resource_ledger")
        );
        Ok(())
    }

    #[test]
    fn swarm_gauntlet_rejects_malformed_resource_ledger_records() -> Result<(), Box<dyn Error>> {
        let manifest = SwarmGauntletManifest::smoke(vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "fcp-e2e".to_string(),
            "--test".to_string(),
            "swarm_gauntlet_e2e".to_string(),
        ]);
        let latency_bundle = gauntlet_latency_bundle()?;
        let resources = gauntlet_resource_snapshots(&latency_bundle);
        let first_scenario = latency_bundle.summaries[0].scenario_id.clone();
        let err = SwarmGauntletEvidenceBundle::new(
            manifest,
            latency_bundle,
            resources,
            gauntlet_decision_cards(&first_scenario),
            gauntlet_phase_evidence(),
            SwarmGauntletCounters {
                audit_event_count: 4,
                same_zone_audit_appends: 512,
                sparse_high_k_metadata_events: 3,
            },
            None,
        )?
        .with_resource_ledger_records(vec![json!({
            "record_type": "resource_ledger",
            "schema_version": SWARM_RESOURCE_LEDGER_SCHEMA_VERSION,
            "ledger": {
                "operation_id": "op-missing-worker-ref"
            }
        })])
        .expect_err("malformed ledger record must be rejected");

        assert!(matches!(
            err,
            SwarmGauntletError::InvalidResourceLedgerRecord { .. }
        ));
        Ok(())
    }

    #[test]
    fn swarm_gauntlet_jsonl_logs_include_required_debug_fields() -> Result<(), Box<dyn Error>> {
        let manifest = SwarmGauntletManifest::smoke(vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "fcp-e2e".to_string(),
            "--test".to_string(),
            "swarm_gauntlet_e2e".to_string(),
        ]);
        let latency_bundle = gauntlet_latency_bundle()?;
        let resources = gauntlet_resource_snapshots(&latency_bundle);
        let first_scenario = latency_bundle.summaries[0].scenario_id.clone();
        let gauntlet = SwarmGauntletEvidenceBundle::new(
            manifest,
            latency_bundle,
            resources,
            gauntlet_decision_cards(&first_scenario),
            gauntlet_phase_evidence(),
            SwarmGauntletCounters {
                audit_event_count: 4,
                same_zone_audit_appends: 512,
                sparse_high_k_metadata_events: 3,
            },
            None,
        )?;

        let records = gauntlet.to_jsonl_values()?;
        let log_record = records
            .iter()
            .find(|record| record["record_type"] == "swarm_gauntlet_log")
            .ok_or("gauntlet log record must be emitted")?;
        let serialized = serde_json::to_string(&records)?;

        assert_eq!(
            log_record["schema_version"],
            SWARM_GAUNTLET_LOG_SCHEMA_VERSION
        );
        assert!(log_record["command_line"].is_array());
        assert_eq!(log_record["git_revision"], "abc123");
        assert_eq!(log_record["worker_id"], "rch-worker-64c");
        assert_eq!(log_record["cargo_target_dir"], "/tmp/fcp-swarm-target");
        assert_eq!(log_record["topology"]["logical_cpus"], 64);
        assert!(log_record["p50_ns"].is_u64());
        assert!(log_record["p95_ns"].is_u64());
        assert!(log_record["p99_ns"].is_u64());
        assert!(log_record["p999_ns"].is_u64());
        assert!(log_record["throughput_ops_per_second"].is_u64());
        assert!(log_record["queue_depth"].is_u64());
        assert!(log_record["retry_amplification_microunits"].is_u64());
        assert!(log_record["rss_bytes"].is_u64());
        assert!(log_record["cpu_microunits"].is_u64());
        assert!(log_record["decision_card_ids"].is_array());
        assert_eq!(log_record["evidence_bundle_id"], "gauntlet-smoke");
        assert!(serialized.contains("\"record_type\":\"swarm_latency_sample\""));
        assert!(serialized.contains("\"record_type\":\"swarm_decision_card\""));
        assert!(!serialized.contains("sk-live-"));
        assert!(!serialized.contains("Bearer test-token"));
        assert!(!serialized.contains("super-secret-value"));
        Ok(())
    }

    fn batch_morselization_evidence_fixture() -> SwarmBatchMorselizationEvidence {
        SwarmBatchMorselizationEvidence {
            schema_version: SWARM_BATCH_MORSELIZATION_SCHEMA_VERSION.to_string(),
            scenario_id: "host_batch_morselization_10000".to_string(),
            batch_id: "batch:offline:10k".to_string(),
            command_line: vec![
                "rch".to_string(),
                "exec".to_string(),
                "--".to_string(),
                "cargo".to_string(),
                "test".to_string(),
                "-p".to_string(),
                "fcp-e2e".to_string(),
                "--test".to_string(),
                "swarm_gauntlet_e2e".to_string(),
            ],
            git_revision: "abc123".to_string(),
            worker_id: "rch-worker-64c".to_string(),
            scheduler_mode: "adaptive".to_string(),
            operation_count: 10_000,
            dependency_depth: 2,
            morsel_size: 256,
            total_morsels: 40,
            split_tiers: 2,
            largest_morsel_operations: 256,
            fairness_distribution: vec![
                SwarmBatchFairnessBucket {
                    fairness_key_hash: "blake3:hot-zone".to_string(),
                    operation_count: 5_000,
                    morsel_count: 20,
                },
                SwarmBatchFairnessBucket {
                    fairness_key_hash: "blake3:cold-zone".to_string(),
                    operation_count: 5_000,
                    morsel_count: 20,
                },
            ],
            fifo_wait: SwarmBatchWaitPercentiles {
                p50_ms: 10_000,
                p95_ms: 20_000,
                p99_ms: 24_000,
                p999_ms: 25_000,
                max_ms: 25_000,
                mean_ms: 12_000,
            },
            scheduled_wait: SwarmBatchWaitPercentiles {
                p50_ms: 500,
                p95_ms: 900,
                p99_ms: 1_100,
                p999_ms: 1_200,
                max_ms: 1_250,
                mean_ms: 700,
            },
            resources: SwarmBatchResourceSample {
                rss_bytes: 512 * 1024 * 1024,
                cpu_microunits: 64_000_000,
                max_queue_depth: 256,
                retry_amplification_microunits: 0,
            },
            fallback_reason: None,
            error_kind: Some("downstream_error:INJECTED_FAILURE".to_string()),
            cancellation_reason: Some("timeout:BATCH_TIMEOUT".to_string()),
            skip_reason: Some("dependency_failed:DEP_FAILED".to_string()),
        }
    }

    #[test]
    fn swarm_batch_morselization_evidence_serializes_required_jsonl_fields()
    -> Result<(), Box<dyn Error>> {
        let evidence = batch_morselization_evidence_fixture();

        evidence.validate()?;
        let record = evidence.to_jsonl_value()?;
        let serialized = serde_json::to_string(&record)?;

        assert_eq!(record["record_type"], "swarm_batch_morselization_evidence");
        assert_eq!(
            record["schema_version"],
            SWARM_BATCH_MORSELIZATION_SCHEMA_VERSION
        );
        assert_eq!(record["operation_count"], 10_000);
        assert_eq!(record["dependency_depth"], 2);
        assert_eq!(record["morsel_size"], 256);
        assert_eq!(record["p99_wait_ms"], 1_100);
        assert_eq!(record["rss_bytes"], 512 * 1024 * 1024);
        assert_eq!(record["max_queue_depth"], 256);
        assert_eq!(record["error_kind"], "downstream_error:INJECTED_FAILURE");
        assert_eq!(record["cancellation_reason"], "timeout:BATCH_TIMEOUT");
        assert_eq!(record["skip_reason"], "dependency_failed:DEP_FAILED");
        assert!(record["evidence"]["fairness_distribution"].is_array());
        assert!(!serialized.contains("sk-live-"));
        assert!(!serialized.contains("Bearer test-token"));
        assert!(!serialized.contains("super-secret-value"));
        Ok(())
    }

    #[test]
    fn swarm_batch_morselization_evidence_rejects_unbounded_or_incomplete_records() {
        let mut oversized = batch_morselization_evidence_fixture();
        oversized.largest_morsel_operations = 257;
        assert_eq!(
            oversized.validate(),
            Err(SwarmBatchMorselizationEvidenceError::OversizedMorsel {
                largest: 257,
                limit: 256
            })
        );

        let mut count_mismatch = batch_morselization_evidence_fixture();
        count_mismatch.fairness_distribution[0].operation_count = 4_999;
        assert_eq!(
            count_mismatch.validate(),
            Err(
                SwarmBatchMorselizationEvidenceError::FairnessOperationCountMismatch {
                    expected: 10_000,
                    actual: 9_999
                }
            )
        );

        let mut missing_rss = batch_morselization_evidence_fixture();
        missing_rss.resources.rss_bytes = 0;
        assert_eq!(
            missing_rss.validate(),
            Err(
                SwarmBatchMorselizationEvidenceError::MissingResourceMeasurement {
                    field: "rss_bytes"
                }
            )
        );
    }

    fn prewarm_cold_start_evidence_fixture() -> SwarmPrewarmColdStartEvidence {
        SwarmPrewarmColdStartEvidence {
            schema_version: SWARM_PREWARM_COLD_START_SCHEMA_VERSION.to_string(),
            scenario_id: "prewarm_warm_hit".to_string(),
            connector_id: "fcp.github:utility:1.0.0".to_string(),
            command_line: vec![
                "rch".to_string(),
                "exec".to_string(),
                "--".to_string(),
                "cargo".to_string(),
                "test".to_string(),
                "-p".to_string(),
                "fcp-e2e".to_string(),
                "--test".to_string(),
                "swarm_gauntlet_e2e".to_string(),
                "prewarm".to_string(),
            ],
            git_revision: "abc123".to_string(),
            worker_id: "rch-worker-64c".to_string(),
            cargo_target_dir: "/tmp/fcp-prewarm-e2e".to_string(),
            connector_fixture_id: "fcp-test-connector:request-response".to_string(),
            host_boundary: "fcp-host::supervisor::ConnectorPrewarmConfig::decide_checkout"
                .to_string(),
            manifest_hash: "blake3:manifest".to_string(),
            zone: "z:project:swarm".to_string(),
            strategy: "warm_pool".to_string(),
            pool_state: "warm_hit".to_string(),
            pool_size: 256,
            admission_decision: "admit_warm".to_string(),
            warm_checkout: true,
            activation_latency_ms: 18,
            baseline_on_demand_latency_ms: 96,
            latency: SwarmPrewarmLatencyPercentiles {
                p50_ms: 18,
                p95_ms: 22,
                p99_ms: 26,
                p999_ms: 29,
                max_ms: 30,
                mean_ms: 20,
            },
            baseline_latency: SwarmPrewarmLatencyPercentiles {
                p50_ms: 90,
                p95_ms: 96,
                p99_ms: 112,
                p999_ms: 125,
                max_ms: 130,
                mean_ms: 95,
            },
            sandbox_layer: "wasi".to_string(),
            sandbox_profile: "strict".to_string(),
            sandbox_boundary: "fcp-sandbox::strict-profile-limits".to_string(),
            credential_mode: "deferred".to_string(),
            rss_bytes: 96 * 1024 * 1024,
            process_count: 1,
            concurrent_startups: 1,
            error_mapping: "ok".to_string(),
            cleanup_result: "verified".to_string(),
            restart_reason: None,
            fallback_reason: None,
            unsafe_rejection_reason: None,
            skip_reason: None,
            shutdown_cleanup_verified: true,
        }
    }

    #[test]
    fn swarm_prewarm_cold_start_evidence_serializes_required_jsonl_fields()
    -> Result<(), Box<dyn Error>> {
        let evidence = prewarm_cold_start_evidence_fixture();

        evidence.validate()?;
        let record = evidence.to_jsonl_value()?;
        let serialized = serde_json::to_string(&record)?;

        assert_eq!(record["record_type"], "swarm_prewarm_cold_start_evidence");
        assert_eq!(
            record["schema_version"],
            SWARM_PREWARM_COLD_START_SCHEMA_VERSION
        );
        assert_eq!(record["connector_id"], "fcp.github:utility:1.0.0");
        assert_eq!(
            record["command_line"],
            serde_json::json!([
                "rch",
                "exec",
                "--",
                "cargo",
                "test",
                "-p",
                "fcp-e2e",
                "--test",
                "swarm_gauntlet_e2e",
                "prewarm"
            ])
        );
        assert_eq!(record["cargo_target_dir"], "/tmp/fcp-prewarm-e2e");
        assert_eq!(
            record["connector_fixture_id"],
            "fcp-test-connector:request-response"
        );
        assert_eq!(
            record["host_boundary"],
            "fcp-host::supervisor::ConnectorPrewarmConfig::decide_checkout"
        );
        assert_eq!(record["manifest_hash"], "blake3:manifest");
        assert_eq!(record["zone"], "z:project:swarm");
        assert_eq!(record["pool_state"], "warm_hit");
        assert_eq!(record["pool_size"], 256);
        assert_eq!(record["admission_decision"], "admit_warm");
        assert_eq!(record["warm_checkout"], true);
        assert_eq!(record["activation_latency_ms"], 18);
        assert_eq!(record["baseline_on_demand_latency_ms"], 96);
        assert_eq!(record["p50_activation_latency_ms"], 18);
        assert_eq!(record["p95_activation_latency_ms"], 22);
        assert_eq!(record["p99_activation_latency_ms"], 26);
        assert_eq!(record["baseline_p50_activation_latency_ms"], 90);
        assert_eq!(record["baseline_p95_activation_latency_ms"], 96);
        assert_eq!(record["baseline_p99_activation_latency_ms"], 112);
        assert_eq!(record["p50_activation_latency_improvement_ms"], 72);
        assert_eq!(record["p95_activation_latency_improvement_ms"], 74);
        assert_eq!(record["p99_activation_latency_improvement_ms"], 86);
        assert_eq!(record["sandbox_layer"], "wasi");
        assert_eq!(record["sandbox_profile"], "strict");
        assert_eq!(
            record["sandbox_boundary"],
            "fcp-sandbox::strict-profile-limits"
        );
        assert_eq!(record["credential_mode"], "deferred");
        assert_eq!(record["rss_bytes"], 96 * 1024 * 1024);
        assert_eq!(record["process_count"], 1);
        assert_eq!(record["concurrent_startups"], 1);
        assert_eq!(record["error_mapping"], "ok");
        assert_eq!(record["cleanup_result"], "verified");
        assert!(
            record["shutdown_cleanup_verified"]
                .as_bool()
                .unwrap_or(false)
        );
        assert!(!serialized.contains("sk-live-"));
        assert!(!serialized.contains("Bearer test-token"));
        assert!(!serialized.contains("super-secret-value"));
        Ok(())
    }

    #[test]
    fn swarm_prewarm_cold_start_evidence_rejects_incomplete_or_regressed_records() {
        let mut regressed = prewarm_cold_start_evidence_fixture();
        regressed.activation_latency_ms = 120;
        assert_eq!(
            regressed.validate(),
            Err(SwarmPrewarmColdStartEvidenceError::LatencyRegression {
                activation_ms: 120,
                baseline_ms: 96
            })
        );

        let mut missing_rss = prewarm_cold_start_evidence_fixture();
        missing_rss.rss_bytes = 0;
        assert_eq!(
            missing_rss.validate(),
            Err(
                SwarmPrewarmColdStartEvidenceError::MissingResourceMeasurement {
                    field: "rss_bytes"
                }
            )
        );

        let mut missing_pool_size = prewarm_cold_start_evidence_fixture();
        missing_pool_size.pool_size = 0;
        assert_eq!(
            missing_pool_size.validate(),
            Err(
                SwarmPrewarmColdStartEvidenceError::MissingResourceMeasurement {
                    field: "pool_size"
                }
            )
        );

        let mut bad_percentiles = prewarm_cold_start_evidence_fixture();
        bad_percentiles.latency.p99_ms = 10;
        assert_eq!(
            bad_percentiles.validate(),
            Err(SwarmPrewarmColdStartEvidenceError::InvalidLatencyPercentiles)
        );

        let mut bad_baseline_percentiles = prewarm_cold_start_evidence_fixture();
        bad_baseline_percentiles.baseline_latency.p95_ms = 80;
        bad_baseline_percentiles.baseline_latency.p99_ms = 70;
        assert_eq!(
            bad_baseline_percentiles.validate(),
            Err(SwarmPrewarmColdStartEvidenceError::InvalidLatencyPercentiles)
        );

        let mut regressed_percentile = prewarm_cold_start_evidence_fixture();
        regressed_percentile.baseline_latency.p50_ms = 18;
        regressed_percentile.baseline_latency.p95_ms = 22;
        regressed_percentile.baseline_latency.p99_ms = 24;
        assert_eq!(
            regressed_percentile.validate(),
            Err(SwarmPrewarmColdStartEvidenceError::LatencyRegression {
                activation_ms: 26,
                baseline_ms: 24
            })
        );
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
