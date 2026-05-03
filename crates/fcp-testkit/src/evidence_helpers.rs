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

/// Schema tag for 64-core/256GiB promotion qualification records.
pub const SWARM_PROMOTION_SCHEMA_VERSION: &str = "swarm-promotion/v1";

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
            counters,
            skip_artifact,
        })
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
            Self::MissingAuditEvidence => write!(f, "missing swarm gauntlet audit evidence"),
            Self::MissingStoreEvidence => write!(f, "missing swarm gauntlet store evidence"),
        }
    }
}

impl Error for SwarmGauntletError {}

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
        let missing_err = match SwarmEvidenceArtifactManifest::from_environment(
            "bundle-missing",
            SwarmEvidenceSourceKind::HostBacked,
            SwarmEvidenceExecutionMode::Smoke,
            &environment,
            missing_artifacts,
            SwarmEvidenceRedactionPolicy::conservative(),
        ) {
            Ok(_) => return Err("missing proof notes artifact must fail"),
            Err(err) => err,
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

        let mut missing_manifest_revision = stale_manifest.clone();
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
        let baseline = baseline_regression_snapshot();
        let candidate = baseline.clone();
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
        let baseline = baseline_regression_snapshot();
        let candidate = baseline.clone();
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
        assert_eq!(summary.phase_count, SwarmGauntletPhase::REQUIRED.len());
        assert_eq!(summary.counters.same_zone_audit_appends, 512);
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
