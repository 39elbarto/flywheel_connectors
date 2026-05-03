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
