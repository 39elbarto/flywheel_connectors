//! Redaction-safe proof-runner contract for `rch` and other proof executors.
//!
//! This module records the difference between command execution, local
//! fail-open behavior, artifact retrieval, and proof-quality classification.
//! Sync chatter and local fallback are intentionally representable, but neither
//! is accepted as remote proof.

#![allow(clippy::module_name_repetitions)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::proof_graph::{
    EvidenceId, EvidenceKind, EvidenceNode, FreshnessWindow, ProofGraphError, RedactionClass,
    RerunCommand, RerunCommandId, TruthSource,
};

/// Stable schema for proof-runner JSONL event records.
pub const PROOF_RUNNER_EVENT_SCHEMA: &str = "fcp.proof-runner-event.v1";

/// Stable schema for proof-runner summaries.
pub const PROOF_RUNNER_SUMMARY_SCHEMA: &str = "fcp.proof-runner-summary.v1";

/// Stable schema for fail-closed RCH remote-proof evidence rows.
pub const RCH_REMOTE_PROOF_EVIDENCE_SCHEMA: &str = "fcp.rch-remote-proof-evidence.v1";

/// Redaction-safe command and policy for a proof run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCommandSpec {
    /// Runner used to execute the command.
    pub runner: ProofRunnerKind,
    /// Argument vector, excluding raw secret values.
    pub argv: Vec<String>,
    /// Repository-relative or absolute working-directory hint.
    pub working_directory: String,
    /// Git revision or tree identifier available at planning time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_revision: Option<String>,
    /// Target directory isolation policy for Cargo proof lanes.
    pub target_dir_policy: TargetDirPolicy,
    /// Cargo-specific command metadata when the proof lane is Cargo-backed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cargo: Option<CargoProofInvocation>,
    /// Environment values represented without raw secret material.
    #[serde(default)]
    pub env: BTreeMap<String, RedactedEnvValue>,
    /// Environment variable names required by the command.
    #[serde(default)]
    pub required_env_keys: BTreeSet<String>,
    /// Optional worker/cache preference recorded as a hint, not a proof claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_affinity: Option<WorkerAffinityHint>,
    /// Execution policy for this proof run.
    pub policy: ProofRunPolicy,
}

impl ProofCommandSpec {
    /// Build a fingerprint over all command fields that affect proof reuse.
    ///
    /// # Errors
    ///
    /// Returns [`ProofRunError`] when command metadata is unsafe or cannot be
    /// serialized.
    pub fn fingerprint(&self) -> Result<ProofCommandFingerprint, ProofRunError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        Ok(ProofCommandFingerprint {
            algorithm: "blake3-256".to_owned(),
            digest: hex::encode(blake3::hash(&bytes).as_bytes()),
        })
    }

    /// Convert this command into the existing `ProofGraph` rerun-command shape.
    ///
    /// # Errors
    ///
    /// Returns [`ProofRunError`] if the command id or argv is not graph-safe.
    pub fn to_rerun_command(
        &self,
        command_id: impl Into<String>,
    ) -> Result<RerunCommand, ProofRunError> {
        self.validate()?;
        let command = RerunCommand {
            id: RerunCommandId::new(command_id)?,
            argv: self.argv.clone(),
            required_env_keys: self.required_env_keys.clone(),
            working_directory: Some(self.working_directory.clone()),
            requires_rch: matches!(self.runner, ProofRunnerKind::Rch)
                || self.policy.remote_required,
        };
        command.validate()?;
        Ok(command)
    }

    /// Validate command metadata against the redaction contract.
    ///
    /// # Errors
    ///
    /// Returns [`ProofRunError`] if fields contain raw endpoints, raw secrets,
    /// invalid environment keys, or an empty command vector.
    pub fn validate(&self) -> Result<(), ProofRunError> {
        if self.argv.is_empty() {
            return Err(ProofRunError::EmptyArgv);
        }
        self.runner.validate()?;
        validate_safe_text("command.working_directory", &self.working_directory)?;
        if let Some(git_revision) = &self.git_revision {
            validate_graphish_text("command.git_revision", git_revision)?;
        }
        self.target_dir_policy.validate()?;
        if let Some(cargo) = &self.cargo {
            cargo.validate()?;
        }
        for arg in &self.argv {
            validate_safe_text("command.argv", arg)?;
        }
        for (key, value) in &self.env {
            validate_env_key(key)?;
            value.validate()?;
        }
        for key in &self.required_env_keys {
            validate_env_key(key)?;
        }
        if let Some(worker_affinity) = &self.worker_affinity {
            worker_affinity.validate()?;
        }
        self.policy.validate()
    }
}

/// Proof runner implementation family.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofRunnerKind {
    /// `rch exec` remote Cargo host orchestration.
    Rch,
    /// Explicit local shell execution.
    LocalShell,
    /// Forward-compatible runner family.
    Unknown(String),
}

impl ProofRunnerKind {
    fn validate(&self) -> Result<(), ProofRunError> {
        if let Self::Unknown(value) = self {
            validate_graphish_text("runner.unknown", value)?;
        }
        Ok(())
    }
}

/// Target-dir policy included in command fingerprints.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TargetDirPolicy {
    /// Caller provided an isolated target directory.
    Explicit {
        /// Redaction-safe target directory path.
        path: String,
    },
    /// Runner should allocate an isolated temporary target directory.
    IsolatedTemp,
    /// Runner may use a shared target directory.
    Shared,
    /// No target directory policy was provided.
    Unset,
    /// Forward-compatible target directory policy.
    Unknown {
        /// Redaction-safe policy label.
        label: String,
    },
}

impl TargetDirPolicy {
    fn validate(&self) -> Result<(), ProofRunError> {
        match self {
            Self::Explicit { path } => validate_safe_text("target_dir.path", path),
            Self::Unknown { label } => validate_graphish_text("target_dir.label", label),
            Self::IsolatedTemp | Self::Shared | Self::Unset => Ok(()),
        }
    }
}

/// Cargo command metadata included in proof fingerprints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CargoProofInvocation {
    /// Cargo subcommand, for example `test`, `clippy`, or `check`.
    pub subcommand: String,
    /// Optional package selected by `-p` or `--package`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    /// Optional test, bin, lib, or target filters.
    #[serde(default)]
    pub target_filters: BTreeSet<String>,
    /// Feature flags explicitly selected for the run.
    #[serde(default)]
    pub features: BTreeSet<String>,
    /// Whether `--all-targets` was selected.
    pub all_targets: bool,
    /// Whether `--all-features` was selected.
    pub all_features: bool,
    /// Trailing arguments after `--`, if any.
    #[serde(default)]
    pub trailing_args: Vec<String>,
}

impl CargoProofInvocation {
    fn validate(&self) -> Result<(), ProofRunError> {
        validate_graphish_text("cargo.subcommand", &self.subcommand)?;
        if let Some(package) = &self.package {
            validate_graphish_text("cargo.package", package)?;
        }
        for target_filter in &self.target_filters {
            validate_graphish_text("cargo.target_filter", target_filter)?;
        }
        for feature in &self.features {
            validate_graphish_text("cargo.feature", feature)?;
        }
        for arg in &self.trailing_args {
            validate_safe_text("cargo.trailing_arg", arg)?;
        }
        Ok(())
    }
}

/// Redaction-safe environment value representation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RedactedEnvValue {
    /// Environment variable is required or present, but the value is omitted.
    Present,
    /// Environment variable value was removed.
    Redacted,
    /// Environment variable value is represented only by a digest.
    Digest {
        /// Digest string such as `blake3-256:<hex>`.
        digest: String,
    },
    /// Environment variable is set to a known non-secret literal.
    PublicLiteral {
        /// Redaction-safe literal value.
        value: String,
    },
}

impl RedactedEnvValue {
    fn validate(&self) -> Result<(), ProofRunError> {
        match self {
            Self::Present | Self::Redacted => Ok(()),
            Self::Digest { digest } => validate_digest(digest),
            Self::PublicLiteral { value } => validate_safe_text("env.public_literal", value),
        }
    }
}

/// Optional worker/cache affinity hints for proof reuse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerAffinityHint {
    /// Redaction-safe worker id or pool label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    /// Cache namespace that may carry warm dependencies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_namespace: Option<String>,
    /// Target directory policy expected to be warm on that worker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warm_target_dir: Option<String>,
}

impl WorkerAffinityHint {
    fn validate(&self) -> Result<(), ProofRunError> {
        if let Some(worker_id) = &self.worker_id {
            validate_graphish_text("worker.worker_id", worker_id)?;
        }
        if let Some(cache_namespace) = &self.cache_namespace {
            validate_graphish_text("worker.cache_namespace", cache_namespace)?;
        }
        if let Some(warm_target_dir) = &self.warm_target_dir {
            validate_safe_text("worker.warm_target_dir", warm_target_dir)?;
        }
        Ok(())
    }
}

/// Proof execution policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRunPolicy {
    /// Whether local fallback must be refused.
    pub remote_required: bool,
    /// Whether the runner may continue locally after remote selection fails.
    pub allow_local_fallback: bool,
    /// Timeout for queueing before classifying the run as a queue timeout.
    pub queue_timeout_ms: u64,
    /// Timeout for command execution after the command starts.
    pub command_timeout_ms: u64,
    /// Whether retrieved artifacts are required for the run to count as proof.
    pub artifact_retrieval_required: bool,
}

impl ProofRunPolicy {
    /// Construct the default remote-only policy for heavy Cargo proof lanes.
    #[must_use]
    pub const fn remote_only(command_timeout_ms: u64) -> Self {
        Self {
            remote_required: true,
            allow_local_fallback: false,
            queue_timeout_ms: 10 * 60 * 1_000,
            command_timeout_ms,
            artifact_retrieval_required: true,
        }
    }

    const fn validate(&self) -> Result<(), ProofRunError> {
        if self.remote_required && self.allow_local_fallback {
            return Err(ProofRunError::InvalidPolicy {
                reason: "remote-required proof cannot allow local fallback",
            });
        }
        if self.queue_timeout_ms == 0 || self.command_timeout_ms == 0 {
            return Err(ProofRunError::InvalidPolicy {
                reason: "timeouts must be non-zero",
            });
        }
        Ok(())
    }
}

/// Stable command fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProofCommandFingerprint {
    /// Digest algorithm.
    pub algorithm: String,
    /// Hex digest over the normalized command spec.
    pub digest: String,
}

impl ProofCommandFingerprint {
    /// Return a compact `algorithm:digest` string.
    #[must_use]
    pub fn as_ref_string(&self) -> String {
        format!("{}:{}", self.algorithm, self.digest)
    }
}

/// Full proof run summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRun {
    /// Schema identifier; must be [`PROOF_RUNNER_SUMMARY_SCHEMA`].
    #[serde(default = "default_summary_schema")]
    pub schema: String,
    /// Stable redaction-safe run id.
    pub run_id: String,
    /// Command and policy that produced this run.
    pub command: ProofCommandSpec,
    /// Redaction-safe log or artifact reference for the run.
    pub log_ref: String,
    /// Ordered event stream observed for the run.
    pub events: Vec<ProofRunEvent>,
}

impl ProofRun {
    /// Validate and classify the proof run.
    ///
    /// # Errors
    ///
    /// Returns [`ProofRunError`] when metadata is unsafe or the schema is
    /// unsupported.
    pub fn classify(&self) -> Result<ProofRunClassification, ProofRunError> {
        self.validate()?;

        let mut saw_remote = false;
        let mut saw_command_started = false;
        let mut exit_code = None;
        let mut retrieval_failed = false;
        let mut retrieval_finished = false;
        let mut saw_local_fallback = false;
        let mut queued = false;

        for event in &self.events {
            match &event.kind {
                ProofRunEventKind::Queued => queued = true,
                ProofRunEventKind::RemoteSelected { .. } => saw_remote = true,
                ProofRunEventKind::CommandStarted => saw_command_started = true,
                ProofRunEventKind::CommandExited { exit_code: code } => exit_code = Some(*code),
                ProofRunEventKind::ArtifactRetrievalFailed { .. } => retrieval_failed = true,
                ProofRunEventKind::ArtifactRetrievalFinished { .. } => retrieval_finished = true,
                ProofRunEventKind::LocalFallbackStarted { .. } => saw_local_fallback = true,
                ProofRunEventKind::LocalFallbackRefused { .. } => {
                    return Ok(ProofRunClassification::LocalFallbackRefused);
                }
                ProofRunEventKind::TimedOut { stage } => {
                    return Ok(if matches!(stage, ProofRunStage::Queue) && !saw_remote {
                        ProofRunClassification::QueueTimeout
                    } else {
                        ProofRunClassification::TimedOut { stage: *stage }
                    });
                }
                ProofRunEventKind::Cancelled { .. } => {
                    return Ok(ProofRunClassification::Cancelled);
                }
                ProofRunEventKind::Synced { .. } | ProofRunEventKind::ArtifactRetrievalStarted => {}
            }
        }

        match exit_code {
            Some(0) if saw_remote && retrieval_failed => {
                Ok(ProofRunClassification::RetrievalFailedAfterSuccess)
            }
            Some(0)
                if saw_remote
                    && (!self.command.policy.artifact_retrieval_required || retrieval_finished) =>
            {
                Ok(ProofRunClassification::RemoteSuccess)
            }
            Some(0) if saw_remote => Ok(ProofRunClassification::RetrievalMissingAfterSuccess),
            Some(0) if saw_local_fallback => Ok(ProofRunClassification::LocalFallback),
            Some(code) if saw_remote => {
                Ok(ProofRunClassification::RemoteFailure { exit_code: code })
            }
            Some(code) => Ok(ProofRunClassification::LocalFailure { exit_code: code }),
            None if queued && !saw_remote && !saw_command_started => {
                Ok(ProofRunClassification::Queued)
            }
            None => Ok(ProofRunClassification::Incomplete),
        }
    }

    /// Return whether this run can mark a remote-required proof as complete.
    ///
    /// # Errors
    ///
    /// Returns [`ProofRunError`] when classification cannot be computed.
    pub fn counts_as_remote_proof(&self) -> Result<bool, ProofRunError> {
        Ok(self.classify()? == ProofRunClassification::RemoteSuccess)
    }

    /// Require remote proof success.
    ///
    /// # Errors
    ///
    /// Returns [`ProofRunError::NotRemoteProof`] for local fallback, sync-only
    /// events, retrieval failures, timeouts, or failed commands.
    pub fn require_remote_success(&self) -> Result<(), ProofRunError> {
        let classification = self.classify()?;
        if classification == ProofRunClassification::RemoteSuccess {
            Ok(())
        } else {
            Err(ProofRunError::NotRemoteProof { classification })
        }
    }

    /// Serialize the event stream as deterministic JSONL records.
    ///
    /// # Errors
    ///
    /// Returns [`ProofRunError`] when metadata is unsafe or serialization fails.
    pub fn to_jsonl_events(&self) -> Result<Vec<String>, ProofRunError> {
        self.validate()?;
        let fingerprint = self.command.fingerprint()?;
        self.events
            .iter()
            .map(|event| {
                serde_json::to_string(&ProofRunJsonlEvent {
                    schema: PROOF_RUNNER_EVENT_SCHEMA.to_owned(),
                    run_id: self.run_id.clone(),
                    command_fingerprint: fingerprint.clone(),
                    event: event.clone(),
                })
                .map_err(ProofRunError::from)
            })
            .collect()
    }

    /// Convert a classified run into a `ProofGraph` evidence node.
    ///
    /// # Errors
    ///
    /// Returns [`ProofRunError`] when the run is unsafe or graph node
    /// validation rejects the resulting evidence metadata.
    pub fn to_evidence_node(
        &self,
        observed_at_unix_ms: u64,
        valid_for_ms: u64,
    ) -> Result<EvidenceNode, ProofRunError> {
        let classification = self.classify()?;
        let fingerprint = self.command.fingerprint()?;
        let event_digest = self.event_digest()?;
        let evidence = EvidenceNode {
            id: EvidenceId::new(format!("evidence:proof-run:{}", self.run_id))?,
            kind: classification.evidence_kind(),
            summary: format!(
                "Proof run {} classified as {}",
                fingerprint.as_ref_string(),
                classification.as_str()
            ),
            truth_source: classification.truth_source(),
            freshness: FreshnessWindow::new(observed_at_unix_ms, valid_for_ms),
            redaction_class: RedactionClass::Internal,
            source_ref: self.log_ref.clone(),
            content_digest: Some(event_digest),
            rerun_command: Some(
                self.command
                    .to_rerun_command(format!("rerun:proof-run:{}", self.run_id))?,
            ),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Validate run metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ProofRunError`] when the schema, ids, command, log reference,
    /// or event stream is unsafe.
    pub fn validate(&self) -> Result<(), ProofRunError> {
        if self.schema != PROOF_RUNNER_SUMMARY_SCHEMA {
            return Err(ProofRunError::InvalidSchema {
                expected: PROOF_RUNNER_SUMMARY_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        validate_graphish_text("run.run_id", &self.run_id)?;
        self.command.validate()?;
        validate_safe_text("run.log_ref", &self.log_ref)?;
        for event in &self.events {
            event.validate()?;
        }
        Ok(())
    }

    fn event_digest(&self) -> Result<String, ProofRunError> {
        let jsonl = self.to_jsonl_events()?.join("\n");
        Ok(format!(
            "blake3-256:{}",
            hex::encode(blake3::hash(jsonl.as_bytes()).as_bytes())
        ))
    }
}

fn default_summary_schema() -> String {
    PROOF_RUNNER_SUMMARY_SCHEMA.to_owned()
}

/// Redaction-safe proof-run event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRunEvent {
    /// Event timestamp in Unix milliseconds.
    pub at_unix_ms: u64,
    /// Event kind and stage-specific metadata.
    pub kind: ProofRunEventKind,
    /// Redaction-safe operator summary.
    pub summary: String,
}

impl ProofRunEvent {
    /// Construct an event.
    #[must_use]
    pub fn new(at_unix_ms: u64, kind: ProofRunEventKind, summary: impl Into<String>) -> Self {
        Self {
            at_unix_ms,
            kind,
            summary: summary.into(),
        }
    }

    fn validate(&self) -> Result<(), ProofRunError> {
        self.kind.validate()?;
        validate_safe_text("event.summary", &self.summary)
    }
}

/// Proof-run event kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProofRunEventKind {
    /// Proof request entered the runner queue.
    Queued,
    /// Remote worker was selected.
    RemoteSelected {
        /// Redaction-safe worker label if available.
        worker_id: Option<String>,
    },
    /// Source and dependency payloads were synced.
    Synced {
        /// Number of changed files or transfer records, if known.
        changed_files: Option<u64>,
    },
    /// Proof command started.
    CommandStarted,
    /// Proof command exited.
    CommandExited {
        /// Process exit code.
        exit_code: i32,
    },
    /// Artifact retrieval began after command exit.
    ArtifactRetrievalStarted,
    /// Artifact retrieval completed.
    ArtifactRetrievalFinished {
        /// Count of redaction-safe artifacts retrieved.
        artifact_count: u64,
    },
    /// Artifact retrieval failed after command execution.
    ArtifactRetrievalFailed {
        /// Redaction-safe failure reason.
        reason: String,
    },
    /// Local fallback was refused by policy.
    LocalFallbackRefused {
        /// Redaction-safe refusal reason.
        reason: String,
    },
    /// Local fallback started.
    LocalFallbackStarted {
        /// Redaction-safe explanation for the fail-open.
        reason: String,
    },
    /// Queue, sync, command, or retrieval timed out.
    TimedOut {
        /// Stage that timed out.
        stage: ProofRunStage,
    },
    /// Run was cancelled.
    Cancelled {
        /// Redaction-safe cancellation reason.
        reason: String,
    },
}

impl ProofRunEventKind {
    fn validate(&self) -> Result<(), ProofRunError> {
        match self {
            Self::RemoteSelected {
                worker_id: Some(worker_id),
            } => validate_graphish_text("event.worker_id", worker_id),
            Self::ArtifactRetrievalFailed { reason }
            | Self::LocalFallbackRefused { reason }
            | Self::LocalFallbackStarted { reason }
            | Self::Cancelled { reason } => validate_safe_text("event.reason", reason),
            Self::Queued
            | Self::RemoteSelected { worker_id: None }
            | Self::Synced { .. }
            | Self::CommandStarted
            | Self::CommandExited { .. }
            | Self::ArtifactRetrievalStarted
            | Self::ArtifactRetrievalFinished { .. }
            | Self::TimedOut { .. } => Ok(()),
        }
    }
}

/// Proof-run stage used for timeout classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofRunStage {
    /// Waiting for a worker.
    Queue,
    /// Syncing source, dependencies, or artifacts to the worker.
    Sync,
    /// Running the command.
    Command,
    /// Retrieving generated artifacts after command exit.
    ArtifactRetrieval,
}

/// Terminal proof-run classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProofRunClassification {
    /// Remote command exited zero and required artifacts were retrieved.
    RemoteSuccess,
    /// Remote command exited non-zero.
    RemoteFailure {
        /// Process exit code.
        exit_code: i32,
    },
    /// Remote command exited zero but required artifact retrieval failed.
    RetrievalFailedAfterSuccess,
    /// Remote command exited zero but no retrieval completion was observed.
    RetrievalMissingAfterSuccess,
    /// Remote queue timed out before a worker was selected.
    QueueTimeout,
    /// Local fallback was refused by remote-only policy.
    LocalFallbackRefused,
    /// Local fallback started; this is never remote proof.
    LocalFallback,
    /// Local command exited non-zero.
    LocalFailure {
        /// Process exit code.
        exit_code: i32,
    },
    /// Run timed out at a specific stage.
    TimedOut {
        /// Stage that timed out.
        stage: ProofRunStage,
    },
    /// Run was cancelled.
    Cancelled,
    /// Run is queued but no command has started.
    Queued,
    /// Event stream is not terminal.
    Incomplete,
}

impl ProofRunClassification {
    /// Stable string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RemoteSuccess => "remote_success",
            Self::RemoteFailure { .. } => "remote_failure",
            Self::RetrievalFailedAfterSuccess => "retrieval_failed_after_success",
            Self::RetrievalMissingAfterSuccess => "retrieval_missing_after_success",
            Self::QueueTimeout => "queue_timeout",
            Self::LocalFallbackRefused => "local_fallback_refused",
            Self::LocalFallback => "local_fallback",
            Self::LocalFailure { .. } => "local_failure",
            Self::TimedOut { .. } => "timed_out",
            Self::Cancelled => "cancelled",
            Self::Queued => "queued",
            Self::Incomplete => "incomplete",
        }
    }

    /// Whether the remote command itself exited successfully.
    #[must_use]
    pub const fn remote_command_succeeded(self) -> bool {
        matches!(
            self,
            Self::RemoteSuccess
                | Self::RetrievalFailedAfterSuccess
                | Self::RetrievalMissingAfterSuccess
        )
    }

    /// Truth source represented by this classification.
    #[must_use]
    pub const fn truth_source(self) -> TruthSource {
        match self {
            Self::RemoteSuccess
            | Self::RemoteFailure { .. }
            | Self::RetrievalFailedAfterSuccess
            | Self::RetrievalMissingAfterSuccess => TruthSource::HostBacked,
            Self::LocalFallback | Self::LocalFailure { .. } => TruthSource::NodeLocal,
            Self::QueueTimeout
            | Self::LocalFallbackRefused
            | Self::TimedOut { .. }
            | Self::Cancelled
            | Self::Queued
            | Self::Incomplete => TruthSource::Offline,
        }
    }

    /// Evidence category represented by this classification.
    #[must_use]
    pub const fn evidence_kind(self) -> EvidenceKind {
        match self {
            Self::RemoteSuccess
            | Self::RemoteFailure { .. }
            | Self::RetrievalFailedAfterSuccess
            | Self::RetrievalMissingAfterSuccess => EvidenceKind::HostIntegration,
            Self::LocalFallback | Self::LocalFailure { .. } => EvidenceKind::NodeLocalRun,
            Self::QueueTimeout
            | Self::LocalFallbackRefused
            | Self::TimedOut { .. }
            | Self::Cancelled
            | Self::Queued
            | Self::Incomplete => EvidenceKind::OperatorRecord,
        }
    }
}

/// Redaction-safe RCH remote-proof evidence row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchRemoteProofEvidence {
    /// Schema identifier; must be [`RCH_REMOTE_PROOF_EVIDENCE_SCHEMA`].
    #[serde(default = "default_rch_remote_proof_schema")]
    pub schema: String,
    /// Command vector that was planned or observed.
    pub command: Vec<String>,
    /// Working directory used for the command.
    pub cwd: String,
    /// Git revision under test.
    pub git_revision: String,
    /// Worker id reported by RCH, when a remote worker was actually selected.
    #[serde(default)]
    pub worker_id: Option<String>,
    /// Final `[RCH] remote|local` summary line, with secret-bearing details removed.
    #[serde(default)]
    pub rch_summary_line: Option<String>,
    /// Selector/admission reason when RCH did not produce a remote result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector_reason: Option<String>,
    /// Remote topology/preflight reason when setup failed before Cargo ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preflight_reason: Option<String>,
    /// Cargo target directory used for the run.
    #[serde(default)]
    pub target_dir: Option<String>,
    /// Run start timestamp in Unix milliseconds.
    pub started_at_unix_ms: u64,
    /// Run finish timestamp in Unix milliseconds, if terminal.
    #[serde(default)]
    pub finished_at_unix_ms: Option<u64>,
    /// Terminal exit kind observed by the governor.
    pub exit_kind: RchRemoteProofExitKind,
    /// Stable blocker reason when the row cannot be accepted as remote proof.
    #[serde(default)]
    pub blocker_reason: Option<RchRemoteProofBlockerReason>,
    /// Redaction flags for row consumers.
    pub redaction: RchRemoteProofRedaction,
}

impl RchRemoteProofEvidence {
    /// Validate and classify this evidence row.
    ///
    /// Unknown or ambiguous evidence deliberately returns a fail-closed
    /// classification rather than green proof.
    ///
    /// # Errors
    ///
    /// Returns [`ProofRunError`] when the row violates schema or redaction
    /// rules.
    pub fn classify(&self) -> Result<RchRemoteProofClassification, ProofRunError> {
        self.validate()?;

        if !command_contains_cargo(&self.command)
            || self.exit_kind == RchRemoteProofExitKind::NonProof
        {
            return Ok(RchRemoteProofClassification::NotProof {
                blocker: RchRemoteProofBlockerReason::NonCargoNonProof,
            });
        }

        match self.exit_kind {
            RchRemoteProofExitKind::RemotePassed => Ok(self.classify_remote_passed()),
            RchRemoteProofExitKind::RemoteFailed { exit_code } => {
                Ok(self.classify_remote_failed(exit_code))
            }
            RchRemoteProofExitKind::Blocked => Ok(classify_blocker(self.inferred_blocker_reason())),
            RchRemoteProofExitKind::NonProof => Ok(RchRemoteProofClassification::NotProof {
                blocker: RchRemoteProofBlockerReason::NonCargoNonProof,
            }),
            RchRemoteProofExitKind::Unknown => Ok(RchRemoteProofClassification::FailedClosed {
                blocker: RchRemoteProofBlockerReason::Unknown,
            }),
        }
    }

    /// Whether this row is accepted as remote proof.
    ///
    /// # Errors
    ///
    /// Returns [`ProofRunError`] when row validation fails.
    pub fn counts_as_remote_proof(&self) -> Result<bool, ProofRunError> {
        Ok(self.classify()? == RchRemoteProofClassification::AcceptedRemoteProof)
    }

    /// Require an accepted remote proof classification.
    ///
    /// # Errors
    ///
    /// Returns [`ProofRunError::NotRchRemoteProof`] for every non-green
    /// classification, including local fallback, infra blockers, missing
    /// summaries, and non-Cargo commands.
    pub fn require_remote_success(&self) -> Result<(), ProofRunError> {
        let classification = self.classify()?;
        if classification == RchRemoteProofClassification::AcceptedRemoteProof {
            Ok(())
        } else {
            Err(ProofRunError::NotRchRemoteProof { classification })
        }
    }

    /// Serialize this row as one deterministic JSONL record.
    ///
    /// # Errors
    ///
    /// Returns [`ProofRunError`] when the row is invalid or cannot serialize.
    pub fn to_jsonl_record(&self) -> Result<String, ProofRunError> {
        self.validate()?;
        serde_json::to_string(self).map_err(ProofRunError::from)
    }

    /// Parse the final RCH summary line if one is present.
    #[must_use]
    pub fn parsed_summary(&self) -> Option<RchRemoteProofSummary> {
        self.rch_summary_line
            .as_deref()
            .and_then(RchRemoteProofSummary::parse_final_summary_line)
    }

    /// Validate schema, required fields, redaction flags, and timestamp order.
    ///
    /// # Errors
    ///
    /// Returns [`ProofRunError`] when fields are unsafe or internally
    /// contradictory.
    pub fn validate(&self) -> Result<(), ProofRunError> {
        if self.schema != RCH_REMOTE_PROOF_EVIDENCE_SCHEMA {
            return Err(ProofRunError::InvalidSchema {
                expected: RCH_REMOTE_PROOF_EVIDENCE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        if self.command.is_empty() {
            return Err(ProofRunError::EmptyArgv);
        }
        for arg in &self.command {
            validate_safe_text("rch_remote_proof.command", arg)?;
        }
        validate_safe_text("rch_remote_proof.cwd", &self.cwd)?;
        validate_graphish_text("rch_remote_proof.git_revision", &self.git_revision)?;
        if let Some(worker_id) = &self.worker_id {
            validate_graphish_text("rch_remote_proof.worker_id", worker_id)?;
        }
        if let Some(summary) = &self.rch_summary_line {
            validate_safe_text(
                "rch_remote_proof.rch_summary_line",
                &strip_ansi_csi(summary),
            )?;
        }
        if let Some(selector_reason) = &self.selector_reason {
            validate_safe_text("rch_remote_proof.selector_reason", selector_reason)?;
        }
        if let Some(preflight_reason) = &self.preflight_reason {
            validate_safe_text("rch_remote_proof.preflight_reason", preflight_reason)?;
        }
        if let Some(target_dir) = &self.target_dir {
            validate_safe_text("rch_remote_proof.target_dir", target_dir)?;
        }
        if self
            .finished_at_unix_ms
            .is_some_and(|finished_at| finished_at < self.started_at_unix_ms)
        {
            return Err(ProofRunError::InvalidPolicy {
                reason: "finished_at_unix_ms cannot precede started_at_unix_ms",
            });
        }
        self.redaction.validate()
    }

    fn classify_remote_passed(&self) -> RchRemoteProofClassification {
        let Some(summary) = self.parsed_summary() else {
            return RchRemoteProofClassification::FailedClosed {
                blocker: self.summary_failure_reason(),
            };
        };
        if summary.location != RchRemoteProofSummaryLocation::Remote {
            return classify_blocker(self.inferred_blocker_reason());
        }
        if self.blocker_reason.is_some() {
            return RchRemoteProofClassification::FailedClosed {
                blocker: RchRemoteProofBlockerReason::AmbiguousRchSummary,
            };
        }
        if self.worker_id.is_none() && summary.worker_id.is_none() {
            return RchRemoteProofClassification::FailedClosed {
                blocker: RchRemoteProofBlockerReason::AmbiguousRchSummary,
            };
        }
        RchRemoteProofClassification::AcceptedRemoteProof
    }

    fn classify_remote_failed(&self, exit_code: i32) -> RchRemoteProofClassification {
        let Some(summary) = self.parsed_summary() else {
            return RchRemoteProofClassification::FailedClosed {
                blocker: self.summary_failure_reason(),
            };
        };
        if summary.location == RchRemoteProofSummaryLocation::Remote {
            RchRemoteProofClassification::RemoteCommandFailed { exit_code }
        } else {
            classify_blocker(self.inferred_blocker_reason())
        }
    }

    fn inferred_blocker_reason(&self) -> RchRemoteProofBlockerReason {
        if let Some(reason) = self.blocker_reason {
            return reason;
        }
        let Some(summary) = &self.rch_summary_line else {
            return RchRemoteProofBlockerReason::MissingRchSummary;
        };
        let cleaned = strip_ansi_csi(summary);
        let lower = cleaned.to_ascii_lowercase();
        if lower.contains("active_project_exclusion") {
            RchRemoteProofBlockerReason::ActiveProjectExclusion
        } else if lower.contains("no admissible workers") || lower.contains("no_admissible_workers")
        {
            RchRemoteProofBlockerReason::NoAdmissibleWorkers
        } else if lower.contains("topology")
            || lower.contains("preflight")
            || lower.contains("ln: already exists")
        {
            RchRemoteProofBlockerReason::TopologyPreflightFailure
        } else if lower.contains("pressure") || lower.contains("all_workers_busy") {
            RchRemoteProofBlockerReason::WorkerPressure
        } else if RchRemoteProofSummary::parse_final_summary_line(&cleaned)
            .is_some_and(|summary| summary.location == RchRemoteProofSummaryLocation::Local)
        {
            RchRemoteProofBlockerReason::LocalFallbackRefused
        } else if RchRemoteProofSummary::parse_final_summary_line(&cleaned).is_none() {
            RchRemoteProofBlockerReason::MalformedRchSummary
        } else {
            RchRemoteProofBlockerReason::AmbiguousRchSummary
        }
    }

    fn summary_failure_reason(&self) -> RchRemoteProofBlockerReason {
        match &self.rch_summary_line {
            Some(line) if RchRemoteProofSummary::parse_final_summary_line(line).is_none() => {
                RchRemoteProofBlockerReason::MalformedRchSummary
            }
            Some(_) => RchRemoteProofBlockerReason::AmbiguousRchSummary,
            None => RchRemoteProofBlockerReason::MissingRchSummary,
        }
    }
}

fn default_rch_remote_proof_schema() -> String {
    RCH_REMOTE_PROOF_EVIDENCE_SCHEMA.to_owned()
}

/// Terminal exit kind recorded by the RCH remote-proof schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RchRemoteProofExitKind {
    /// Remote command exited zero.
    RemotePassed,
    /// Remote command ran and exited non-zero.
    RemoteFailed {
        /// Process exit code.
        exit_code: i32,
    },
    /// The proof did not reach a trustworthy remote command result.
    Blocked,
    /// The command is not eligible to be claimed as RCH Cargo proof.
    NonProof,
    /// Exit state is unavailable or ambiguous.
    Unknown,
}

/// Stable blocker reason for non-green RCH remote-proof rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RchRemoteProofBlockerReason {
    /// Local fallback was attempted or would be attempted and must be refused.
    LocalFallbackRefused,
    /// Another active same-project RCH command blocked admission.
    ActiveProjectExclusion,
    /// RCH reported no admissible worker.
    NoAdmissibleWorkers,
    /// Remote path topology or preflight setup failed before a real build result.
    TopologyPreflightFailure,
    /// Worker pressure or slot pressure blocked a trustworthy remote proof.
    WorkerPressure,
    /// Command is not a Cargo proof command.
    NonCargoNonProof,
    /// The RCH summary line was present but malformed.
    MalformedRchSummary,
    /// The RCH summary line was missing.
    MissingRchSummary,
    /// The summary conflicted with row metadata.
    AmbiguousRchSummary,
    /// The reason is not classified.
    Unknown,
}

/// Fail-closed classification for one RCH remote-proof evidence row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RchRemoteProofClassification {
    /// Accepted as remote proof.
    AcceptedRemoteProof,
    /// Remote command executed and failed for real code/test reasons.
    RemoteCommandFailed {
        /// Process exit code.
        exit_code: i32,
    },
    /// RCH infrastructure blocked the run before a real command result.
    InfraBlocked {
        /// Stable blocker reason.
        blocker: RchRemoteProofBlockerReason,
    },
    /// Local fallback was refused by proof policy.
    RefusedLocalFallback,
    /// This row is explicitly not a remote Cargo proof.
    NotProof {
        /// Stable non-proof reason.
        blocker: RchRemoteProofBlockerReason,
    },
    /// The row is unknown or ambiguous and must not be green.
    FailedClosed {
        /// Stable fail-closed reason.
        blocker: RchRemoteProofBlockerReason,
    },
}

impl RchRemoteProofClassification {
    /// Stable string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AcceptedRemoteProof => "accepted_remote_proof",
            Self::RemoteCommandFailed { .. } => "remote_command_failed",
            Self::InfraBlocked { .. } => "infra_blocked",
            Self::RefusedLocalFallback => "refused_local_fallback",
            Self::NotProof { .. } => "not_proof",
            Self::FailedClosed { .. } => "failed_closed",
        }
    }
}

impl RchRemoteProofBlockerReason {
    /// Stable string label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalFallbackRefused => "local_fallback_refused",
            Self::ActiveProjectExclusion => "active_project_exclusion",
            Self::NoAdmissibleWorkers => "no_admissible_workers",
            Self::TopologyPreflightFailure => "topology_preflight_failure",
            Self::WorkerPressure => "worker_pressure",
            Self::NonCargoNonProof => "non_cargo_non_proof",
            Self::MalformedRchSummary => "malformed_rch_summary",
            Self::MissingRchSummary => "missing_rch_summary",
            Self::AmbiguousRchSummary => "ambiguous_rch_summary",
            Self::Unknown => "unknown",
        }
    }
}

/// Parsed leading tokens from the final RCH summary line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchRemoteProofSummary {
    /// Remote or local execution location.
    pub location: RchRemoteProofSummaryLocation,
    /// Worker id for remote summaries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
}

impl RchRemoteProofSummary {
    /// Parse the stable leading tokens from RCH's final summary line.
    #[must_use]
    pub fn parse_final_summary_line(line: &str) -> Option<Self> {
        let cleaned = strip_ansi_csi(line);
        let mut parts = cleaned.trim().strip_prefix("[RCH] ")?.split_whitespace();
        match parts.next()? {
            "remote" => {
                let worker_id = parts
                    .next()
                    .filter(|part| !part.starts_with('('))
                    .map(str::to_owned);
                Some(Self {
                    location: RchRemoteProofSummaryLocation::Remote,
                    worker_id,
                })
            }
            "local" => Some(Self {
                location: RchRemoteProofSummaryLocation::Local,
                worker_id: None,
            }),
            _ => None,
        }
    }
}

/// Location reported by a final RCH summary line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RchRemoteProofSummaryLocation {
    /// The command ran remotely.
    Remote,
    /// The command ran locally or fell back locally.
    Local,
}

/// Redaction flags for RCH remote-proof evidence rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchRemoteProofRedaction {
    /// Redaction flags asserted by the producer.
    pub flags: BTreeSet<RchRemoteProofRedactionFlag>,
}

/// Individual redaction guarantees for RCH remote-proof evidence rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RchRemoteProofRedactionFlag {
    /// Command was checked for raw secret-bearing arguments.
    CommandChecked,
    /// Working directory was normalized or otherwise made redaction-safe.
    CwdRedacted,
    /// Target directory was normalized or otherwise made redaction-safe.
    TargetDirRedacted,
    /// RCH summary line was stripped of secret-bearing details.
    SummaryRedacted,
    /// Raw secret values were removed from all row fields.
    SecretValuesRemoved,
}

impl RchRemoteProofRedaction {
    fn validate(&self) -> Result<(), ProofRunError> {
        if !self
            .flags
            .contains(&RchRemoteProofRedactionFlag::SecretValuesRemoved)
        {
            return Err(ProofRunError::InvalidPolicy {
                reason: "redaction must remove raw secret values",
            });
        }
        Ok(())
    }
}

const fn classify_blocker(blocker: RchRemoteProofBlockerReason) -> RchRemoteProofClassification {
    match blocker {
        RchRemoteProofBlockerReason::LocalFallbackRefused => {
            RchRemoteProofClassification::RefusedLocalFallback
        }
        RchRemoteProofBlockerReason::ActiveProjectExclusion
        | RchRemoteProofBlockerReason::NoAdmissibleWorkers
        | RchRemoteProofBlockerReason::TopologyPreflightFailure
        | RchRemoteProofBlockerReason::WorkerPressure => {
            RchRemoteProofClassification::InfraBlocked { blocker }
        }
        RchRemoteProofBlockerReason::NonCargoNonProof => {
            RchRemoteProofClassification::NotProof { blocker }
        }
        RchRemoteProofBlockerReason::MalformedRchSummary
        | RchRemoteProofBlockerReason::MissingRchSummary
        | RchRemoteProofBlockerReason::AmbiguousRchSummary
        | RchRemoteProofBlockerReason::Unknown => {
            RchRemoteProofClassification::FailedClosed { blocker }
        }
    }
}

fn command_contains_cargo(argv: &[String]) -> bool {
    argv.iter()
        .any(|arg| arg == "cargo" || arg.ends_with("/cargo"))
}

fn strip_ansi_csi(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            let _ = chars.next();
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// JSONL event record emitted by the proof-runner contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRunJsonlEvent {
    /// Schema identifier; must be [`PROOF_RUNNER_EVENT_SCHEMA`].
    pub schema: String,
    /// Stable run id.
    pub run_id: String,
    /// Fingerprint of the command spec this event belongs to.
    pub command_fingerprint: ProofCommandFingerprint,
    /// Event payload.
    pub event: ProofRunEvent,
}

/// Errors returned by proof-runner contract validation and classification.
#[derive(Debug, Error)]
pub enum ProofRunError {
    /// Summary schema was not recognized.
    #[error("invalid proof-runner schema: expected {expected}, got {actual}")]
    InvalidSchema {
        /// Expected schema identifier.
        expected: &'static str,
        /// Actual schema identifier.
        actual: String,
    },
    /// Command argv is empty.
    #[error("proof command argv must not be empty")]
    EmptyArgv,
    /// Policy is internally inconsistent.
    #[error("invalid proof-runner policy: {reason}")]
    InvalidPolicy {
        /// Redaction-safe reason.
        reason: &'static str,
    },
    /// Text field contains unsafe raw material.
    #[error("{field} is not redaction-safe: {reason}")]
    UnsafeText {
        /// Field name.
        field: &'static str,
        /// Rejection reason.
        reason: &'static str,
    },
    /// Proof run did not satisfy remote-proof requirements.
    #[error("proof run is not remote proof: {classification:?}")]
    NotRemoteProof {
        /// Terminal classification.
        classification: ProofRunClassification,
    },
    /// RCH evidence row did not satisfy remote-proof requirements.
    #[error("rch proof evidence is not accepted remote proof: {classification:?}")]
    NotRchRemoteProof {
        /// Terminal classification.
        classification: RchRemoteProofClassification,
    },
    /// Serialization failed.
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    /// `ProofGraph` conversion failed.
    #[error(transparent)]
    Graph(#[from] ProofGraphError),
}

fn validate_env_key(value: &str) -> Result<(), ProofRunError> {
    if value.is_empty() {
        return Err(ProofRunError::UnsafeText {
            field: "env.key",
            reason: "empty environment key",
        });
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
    {
        return Err(ProofRunError::UnsafeText {
            field: "env.key",
            reason: "environment keys must be uppercase ASCII, digits, or underscore",
        });
    }
    Ok(())
}

fn validate_graphish_text(field: &'static str, value: &str) -> Result<(), ProofRunError> {
    if value.is_empty() {
        return Err(ProofRunError::UnsafeText {
            field,
            reason: "empty value",
        });
    }
    if value.len() > 160 {
        return Err(ProofRunError::UnsafeText {
            field,
            reason: "value is too long for a stable key",
        });
    }
    if value.trim() != value || value.chars().any(char::is_whitespace) {
        return Err(ProofRunError::UnsafeText {
            field,
            reason: "whitespace is not allowed in stable identifiers",
        });
    }
    validate_safe_text(field, value)
}

fn validate_safe_text(field: &'static str, value: &str) -> Result<(), ProofRunError> {
    if value.is_empty() {
        return Err(ProofRunError::UnsafeText {
            field,
            reason: "empty value",
        });
    }
    if value.contains("://") {
        return Err(ProofRunError::UnsafeText {
            field,
            reason: "raw endpoints must be replaced with artifact ids",
        });
    }
    let lower = value.to_ascii_lowercase();
    if lower.contains("bearer ")
        || lower.contains("token=")
        || lower.contains("api_key=")
        || lower.contains("apikey=")
        || lower.contains("password=")
        || lower.contains("secret=")
    {
        return Err(ProofRunError::UnsafeText {
            field,
            reason: "raw secret-bearing text is not allowed",
        });
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), ProofRunError> {
    let Some((algorithm, digest)) = value.split_once(':') else {
        return Err(ProofRunError::UnsafeText {
            field: "digest",
            reason: "digest must include an algorithm prefix",
        });
    };
    validate_graphish_text("digest.algorithm", algorithm)?;
    if digest.len() < 16 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ProofRunError::UnsafeText {
            field: "digest",
            reason: "digest body must be hex and at least 16 characters",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000_000;

    fn command() -> ProofCommandSpec {
        ProofCommandSpec {
            runner: ProofRunnerKind::Rch,
            argv: vec![
                "rch".to_owned(),
                "exec".to_owned(),
                "--".to_owned(),
                "cargo".to_owned(),
                "test".to_owned(),
                "-p".to_owned(),
                "fcp-evidence".to_owned(),
                "proof_runner".to_owned(),
            ],
            working_directory: ".".to_owned(),
            git_revision: Some("abc1234".to_owned()),
            target_dir_policy: TargetDirPolicy::Explicit {
                path: "/tmp/fcp-evidence-proof-runner".to_owned(),
            },
            cargo: Some(CargoProofInvocation {
                subcommand: "test".to_owned(),
                package: Some("fcp-evidence".to_owned()),
                target_filters: BTreeSet::from(["proof_runner".to_owned()]),
                features: BTreeSet::new(),
                all_targets: false,
                all_features: false,
                trailing_args: vec!["--nocapture".to_owned()],
            }),
            env: BTreeMap::from([
                (
                    "CARGO_BUILD_JOBS".to_owned(),
                    RedactedEnvValue::PublicLiteral {
                        value: "1".to_owned(),
                    },
                ),
                (
                    "RCH_REQUIRE_REMOTE".to_owned(),
                    RedactedEnvValue::PublicLiteral {
                        value: "1".to_owned(),
                    },
                ),
            ]),
            required_env_keys: BTreeSet::from(["RCH_REQUIRE_REMOTE".to_owned()]),
            worker_affinity: Some(WorkerAffinityHint {
                worker_id: Some("worker-7".to_owned()),
                cache_namespace: Some("fcp-evidence".to_owned()),
                warm_target_dir: Some("/tmp/fcp-evidence-proof-runner".to_owned()),
            }),
            policy: ProofRunPolicy::remote_only(20 * 60 * 1_000),
        }
    }

    fn event(kind: ProofRunEventKind) -> ProofRunEvent {
        ProofRunEvent::new(NOW, kind, "redaction-safe event")
    }

    fn run(events: Vec<ProofRunEvent>) -> ProofRun {
        ProofRun {
            schema: PROOF_RUNNER_SUMMARY_SCHEMA.to_owned(),
            run_id: "proof-run-1".to_owned(),
            command: command(),
            log_ref: "artifacts/proof-runs/proof-run-1.jsonl".to_owned(),
            events,
        }
    }

    fn remote_success_events() -> Vec<ProofRunEvent> {
        vec![
            event(ProofRunEventKind::Queued),
            event(ProofRunEventKind::RemoteSelected {
                worker_id: Some("worker-7".to_owned()),
            }),
            event(ProofRunEventKind::Synced {
                changed_files: Some(3),
            }),
            event(ProofRunEventKind::CommandStarted),
            event(ProofRunEventKind::CommandExited { exit_code: 0 }),
            event(ProofRunEventKind::ArtifactRetrievalStarted),
            event(ProofRunEventKind::ArtifactRetrievalFinished { artifact_count: 2 }),
        ]
    }

    #[test]
    fn remote_success_classifies_as_remote_proof() {
        let run = run(remote_success_events());

        assert_eq!(
            run.classify().expect("classify"),
            ProofRunClassification::RemoteSuccess
        );
        assert!(run.counts_as_remote_proof().expect("remote proof"));
        run.require_remote_success().expect("remote success");
    }

    #[test]
    fn queue_timeout_is_not_remote_proof() {
        let run = run(vec![
            event(ProofRunEventKind::Queued),
            event(ProofRunEventKind::TimedOut {
                stage: ProofRunStage::Queue,
            }),
        ]);

        assert_eq!(
            run.classify().expect("classify"),
            ProofRunClassification::QueueTimeout
        );
        assert!(!run.counts_as_remote_proof().expect("remote proof"));
    }

    #[test]
    fn local_fallback_refusal_is_not_counted_as_remote_proof() {
        let run = run(vec![
            event(ProofRunEventKind::Queued),
            event(ProofRunEventKind::LocalFallbackRefused {
                reason: "remote required; refusing local fallback".to_owned(),
            }),
        ]);

        assert_eq!(
            run.classify().expect("classify"),
            ProofRunClassification::LocalFallbackRefused
        );
        assert!(matches!(
            run.require_remote_success(),
            Err(ProofRunError::NotRemoteProof {
                classification: ProofRunClassification::LocalFallbackRefused
            })
        ));
    }

    #[test]
    fn retrieval_failure_after_success_preserves_command_success_without_green_proof() {
        let run = run(vec![
            event(ProofRunEventKind::Queued),
            event(ProofRunEventKind::RemoteSelected {
                worker_id: Some("worker-7".to_owned()),
            }),
            event(ProofRunEventKind::CommandStarted),
            event(ProofRunEventKind::CommandExited { exit_code: 0 }),
            event(ProofRunEventKind::ArtifactRetrievalStarted),
            event(ProofRunEventKind::ArtifactRetrievalFailed {
                reason: "artifact retrieval failed after exit zero".to_owned(),
            }),
        ]);

        let classification = run.classify().expect("classify");
        assert_eq!(
            classification,
            ProofRunClassification::RetrievalFailedAfterSuccess
        );
        assert!(classification.remote_command_succeeded());
        assert!(!run.counts_as_remote_proof().expect("remote proof"));
    }

    #[test]
    fn remote_failure_reports_exit_code() {
        let run = run(vec![
            event(ProofRunEventKind::Queued),
            event(ProofRunEventKind::RemoteSelected {
                worker_id: Some("worker-7".to_owned()),
            }),
            event(ProofRunEventKind::CommandStarted),
            event(ProofRunEventKind::CommandExited { exit_code: 101 }),
        ]);

        assert_eq!(
            run.classify().expect("classify"),
            ProofRunClassification::RemoteFailure { exit_code: 101 }
        );
    }

    #[test]
    fn timeout_and_cancellation_are_terminal() {
        let timed_out = run(vec![
            event(ProofRunEventKind::RemoteSelected {
                worker_id: Some("worker-7".to_owned()),
            }),
            event(ProofRunEventKind::TimedOut {
                stage: ProofRunStage::Command,
            }),
            event(ProofRunEventKind::CommandExited { exit_code: 0 }),
        ]);
        let cancelled = run(vec![
            event(ProofRunEventKind::Queued),
            event(ProofRunEventKind::Cancelled {
                reason: "operator cancelled stale lane".to_owned(),
            }),
        ]);

        assert_eq!(
            timed_out.classify().expect("classify"),
            ProofRunClassification::TimedOut {
                stage: ProofRunStage::Command
            }
        );
        assert_eq!(
            cancelled.classify().expect("classify"),
            ProofRunClassification::Cancelled
        );
    }

    #[test]
    fn sync_chatter_alone_is_not_proof() {
        let run = run(vec![
            event(ProofRunEventKind::Queued),
            event(ProofRunEventKind::RemoteSelected {
                worker_id: Some("worker-7".to_owned()),
            }),
            event(ProofRunEventKind::Synced {
                changed_files: Some(20),
            }),
        ]);

        assert_eq!(
            run.classify().expect("classify"),
            ProofRunClassification::Incomplete
        );
        assert!(!run.counts_as_remote_proof().expect("remote proof"));
    }

    #[test]
    fn local_fallback_run_is_not_remote_proof() {
        let mut run = run(vec![
            event(ProofRunEventKind::Queued),
            event(ProofRunEventKind::LocalFallbackStarted {
                reason: "remote unavailable; fail-open enabled".to_owned(),
            }),
            event(ProofRunEventKind::CommandStarted),
            event(ProofRunEventKind::CommandExited { exit_code: 0 }),
        ]);
        run.command.policy = ProofRunPolicy {
            remote_required: false,
            allow_local_fallback: true,
            queue_timeout_ms: 1_000,
            command_timeout_ms: 1_000,
            artifact_retrieval_required: false,
        };

        assert_eq!(
            run.classify().expect("classify"),
            ProofRunClassification::LocalFallback
        );
        assert!(!run.counts_as_remote_proof().expect("remote proof"));
    }

    #[test]
    fn jsonl_sample_events_are_redaction_safe_and_deterministic() {
        let run = run(remote_success_events());

        let left = run.to_jsonl_events().expect("jsonl");
        let right = run.to_jsonl_events().expect("jsonl");

        assert_eq!(left, right);
        assert_eq!(left.len(), 7);
        assert!(left[1].contains(PROOF_RUNNER_EVENT_SCHEMA));
        assert!(left[1].contains("remote_selected"));
        assert!(!left.join("\n").contains("token="));
    }

    #[test]
    fn fingerprint_includes_cwd_git_target_features_and_redacted_env() {
        let base = command().fingerprint().expect("fingerprint");

        let mut changed_cwd = command();
        changed_cwd.working_directory = ".rch/probes/fcp-evidence".to_owned();
        let mut changed_git = command();
        changed_git.git_revision = Some("def5678".to_owned());
        let mut changed_target = command();
        changed_target.target_dir_policy = TargetDirPolicy::Explicit {
            path: "/tmp/other-target".to_owned(),
        };
        let mut changed_features = command();
        changed_features
            .cargo
            .as_mut()
            .expect("cargo")
            .features
            .insert("expensive-proof".to_owned());
        let mut changed_env = command();
        changed_env.env.insert(
            "RCH_PRIORITY".to_owned(),
            RedactedEnvValue::PublicLiteral {
                value: "high".to_owned(),
            },
        );

        assert_ne!(base, changed_cwd.fingerprint().expect("fingerprint"));
        assert_ne!(base, changed_git.fingerprint().expect("fingerprint"));
        assert_ne!(base, changed_target.fingerprint().expect("fingerprint"));
        assert_ne!(base, changed_features.fingerprint().expect("fingerprint"));
        assert_ne!(base, changed_env.fingerprint().expect("fingerprint"));
    }

    #[test]
    fn remote_success_can_emit_proof_graph_evidence_node() {
        let run = run(remote_success_events());

        let evidence = run.to_evidence_node(NOW, 60_000).expect("evidence node");

        assert_eq!(evidence.kind, EvidenceKind::HostIntegration);
        assert_eq!(evidence.truth_source, TruthSource::HostBacked);
        assert!(evidence.summary.contains("remote_success"));
        assert!(
            evidence
                .content_digest
                .expect("digest")
                .starts_with("blake3-256:")
        );
        assert!(evidence.rerun_command.expect("rerun").requires_rch);
    }

    fn rch_evidence(
        exit_kind: RchRemoteProofExitKind,
        blocker_reason: Option<RchRemoteProofBlockerReason>,
        rch_summary_line: Option<&str>,
    ) -> RchRemoteProofEvidence {
        RchRemoteProofEvidence {
            schema: RCH_REMOTE_PROOF_EVIDENCE_SCHEMA.to_owned(),
            command: vec![
                "rch".to_owned(),
                "exec".to_owned(),
                "--".to_owned(),
                "cargo".to_owned(),
                "test".to_owned(),
                "-p".to_owned(),
                "fcp-evidence".to_owned(),
            ],
            cwd: ".".to_owned(),
            git_revision: "abc1234".to_owned(),
            worker_id: Some("worker-7".to_owned()),
            rch_summary_line: rch_summary_line.map(str::to_owned),
            selector_reason: None,
            preflight_reason: None,
            target_dir: Some("/tmp/fcp-proof-governor".to_owned()),
            started_at_unix_ms: NOW,
            finished_at_unix_ms: Some(NOW + 1_000),
            exit_kind,
            blocker_reason,
            redaction: RchRemoteProofRedaction {
                flags: BTreeSet::from([
                    RchRemoteProofRedactionFlag::CommandChecked,
                    RchRemoteProofRedactionFlag::CwdRedacted,
                    RchRemoteProofRedactionFlag::TargetDirRedacted,
                    RchRemoteProofRedactionFlag::SummaryRedacted,
                    RchRemoteProofRedactionFlag::SecretValuesRemoved,
                ]),
            },
        }
    }

    fn assert_rch_fixture(
        label: &str,
        evidence: &RchRemoteProofEvidence,
        expected: RchRemoteProofClassification,
    ) {
        let actual = evidence.classify().expect(label);
        assert_eq!(
            actual, expected,
            "fixture {label}: expected {expected:?}, actual {actual:?}, summary={:?}, selector_reason={:?}, preflight_reason={:?}",
            evidence.rch_summary_line, evidence.selector_reason, evidence.preflight_reason
        );
        assert_eq!(
            evidence.counts_as_remote_proof().expect(label),
            expected == RchRemoteProofClassification::AcceptedRemoteProof,
            "fixture {label}: remote-proof boolean disagreed with classification {actual:?}"
        );
    }

    type RchFixture = (
        &'static str,
        RchRemoteProofEvidence,
        RchRemoteProofClassification,
    );

    fn remote_command_fixtures() -> [RchFixture; 5] {
        [
            (
                "remote pass",
                rch_evidence(
                    RchRemoteProofExitKind::RemotePassed,
                    None,
                    Some("[RCH] remote worker-7 (cargo test passed)"),
                ),
                RchRemoteProofClassification::AcceptedRemoteProof,
            ),
            (
                "remote build failure",
                rch_evidence(
                    RchRemoteProofExitKind::RemoteFailed { exit_code: 101 },
                    None,
                    Some("[RCH] remote worker-7 failed [RCH-E101]"),
                ),
                RchRemoteProofClassification::RemoteCommandFailed { exit_code: 101 },
            ),
            (
                "local fallback refused after daemon unavailable",
                rch_evidence(
                    RchRemoteProofExitKind::Blocked,
                    Some(RchRemoteProofBlockerReason::LocalFallbackRefused),
                    Some("[RCH] local (daemon unavailable; refusing local fallback)"),
                ),
                RchRemoteProofClassification::RefusedLocalFallback,
            ),
            (
                "local fallback refused after remote execution failed",
                rch_evidence(
                    RchRemoteProofExitKind::Blocked,
                    None,
                    Some("[RCH] local (remote execution failed)"),
                ),
                RchRemoteProofClassification::RefusedLocalFallback,
            ),
            (
                "ansi colored remote pass",
                rch_evidence(
                    RchRemoteProofExitKind::RemotePassed,
                    None,
                    Some("\u{1b}[32m[RCH] remote worker-7 (cargo test passed)\u{1b}[0m"),
                ),
                RchRemoteProofClassification::AcceptedRemoteProof,
            ),
        ]
    }

    fn infra_blocked_fixtures() -> [RchFixture; 4] {
        [
            (
                "active project exclusion",
                rch_evidence(
                    RchRemoteProofExitKind::Blocked,
                    None,
                    Some("[RCH] local (no admissible workers: active_project_exclusion=1)"),
                ),
                RchRemoteProofClassification::InfraBlocked {
                    blocker: RchRemoteProofBlockerReason::ActiveProjectExclusion,
                },
            ),
            (
                "no admissible workers",
                rch_evidence(
                    RchRemoteProofExitKind::Blocked,
                    None,
                    Some("[RCH] local (no admissible workers: healthy=0)"),
                ),
                RchRemoteProofClassification::InfraBlocked {
                    blocker: RchRemoteProofBlockerReason::NoAdmissibleWorkers,
                },
            ),
            (
                "topology preflight failure",
                rch_evidence(
                    RchRemoteProofExitKind::Blocked,
                    Some(RchRemoteProofBlockerReason::TopologyPreflightFailure),
                    Some("[RCH] local (remote topology preflight failed: ln: Already exists)"),
                ),
                RchRemoteProofClassification::InfraBlocked {
                    blocker: RchRemoteProofBlockerReason::TopologyPreflightFailure,
                },
            ),
            (
                "worker pressure",
                rch_evidence(
                    RchRemoteProofExitKind::Blocked,
                    None,
                    Some("[RCH] local (all_workers_busy under pressure)"),
                ),
                RchRemoteProofClassification::InfraBlocked {
                    blocker: RchRemoteProofBlockerReason::WorkerPressure,
                },
            ),
        ]
    }

    fn non_compilation_fixture() -> RchFixture {
        let mut non_cargo = rch_evidence(
            RchRemoteProofExitKind::NonProof,
            Some(RchRemoteProofBlockerReason::NonCargoNonProof),
            Some("[RCH] remote worker-7 (git status passed)"),
        );
        non_cargo.command = vec!["git".to_owned(), "status".to_owned()];

        (
            "non compilation command",
            non_cargo,
            RchRemoteProofClassification::NotProof {
                blocker: RchRemoteProofBlockerReason::NonCargoNonProof,
            },
        )
    }

    fn failed_closed_fixtures() -> [RchFixture; 4] {
        [
            (
                "missing rch summary",
                rch_evidence(RchRemoteProofExitKind::RemotePassed, None, None),
                RchRemoteProofClassification::FailedClosed {
                    blocker: RchRemoteProofBlockerReason::MissingRchSummary,
                },
            ),
            (
                "malformed rch summary",
                rch_evidence(
                    RchRemoteProofExitKind::RemotePassed,
                    None,
                    Some("RCH remote worker-7 without bracket prefix"),
                ),
                RchRemoteProofClassification::FailedClosed {
                    blocker: RchRemoteProofBlockerReason::MalformedRchSummary,
                },
            ),
            (
                "ambiguous summary metadata",
                rch_evidence(
                    RchRemoteProofExitKind::RemotePassed,
                    Some(RchRemoteProofBlockerReason::WorkerPressure),
                    Some("[RCH] remote worker-7 (cargo test passed)"),
                ),
                RchRemoteProofClassification::FailedClosed {
                    blocker: RchRemoteProofBlockerReason::AmbiguousRchSummary,
                },
            ),
            (
                "unknown exit state",
                rch_evidence(
                    RchRemoteProofExitKind::Unknown,
                    None,
                    Some("[RCH] remote worker-7 (unknown state)"),
                ),
                RchRemoteProofClassification::FailedClosed {
                    blocker: RchRemoteProofBlockerReason::Unknown,
                },
            ),
        ]
    }

    #[test]
    fn rch_remote_proof_fixture_corpus_covers_required_states() {
        for (label, evidence, expected) in remote_command_fixtures()
            .into_iter()
            .chain(infra_blocked_fixtures())
            .chain(std::iter::once(non_compilation_fixture()))
            .chain(failed_closed_fixtures())
        {
            assert_rch_fixture(label, &evidence, expected);
        }
    }

    #[test]
    fn rch_unknown_states_fail_closed() {
        let missing_summary = rch_evidence(RchRemoteProofExitKind::RemotePassed, None, None);
        let malformed_summary = rch_evidence(
            RchRemoteProofExitKind::RemotePassed,
            None,
            Some("RCH remote worker-7 without bracket prefix"),
        );
        let unknown = rch_evidence(
            RchRemoteProofExitKind::Unknown,
            None,
            Some("[RCH] remote worker-7 (unknown state)"),
        );

        for (label, evidence, expected) in [
            (
                "missing summary",
                missing_summary,
                RchRemoteProofClassification::FailedClosed {
                    blocker: RchRemoteProofBlockerReason::MissingRchSummary,
                },
            ),
            (
                "malformed summary",
                malformed_summary,
                RchRemoteProofClassification::FailedClosed {
                    blocker: RchRemoteProofBlockerReason::MalformedRchSummary,
                },
            ),
            (
                "unknown state",
                unknown,
                RchRemoteProofClassification::FailedClosed {
                    blocker: RchRemoteProofBlockerReason::Unknown,
                },
            ),
        ] {
            assert_rch_fixture(label, &evidence, expected);
        }

        let missing_summary = rch_evidence(RchRemoteProofExitKind::RemotePassed, None, None);
        assert!(matches!(
            missing_summary.require_remote_success(),
            Err(ProofRunError::NotRchRemoteProof {
                classification: RchRemoteProofClassification::FailedClosed {
                    blocker: RchRemoteProofBlockerReason::MissingRchSummary
                }
            })
        ));
    }

    #[test]
    fn rch_jsonl_golden_records_cover_accepted_and_blocked_proofs() {
        let accepted = rch_evidence(
            RchRemoteProofExitKind::RemotePassed,
            None,
            Some("[RCH] remote worker-7 (cargo test passed)"),
        );
        let mut blocked = rch_evidence(
            RchRemoteProofExitKind::Blocked,
            Some(RchRemoteProofBlockerReason::LocalFallbackRefused),
            Some("[RCH] local (remote execution failed)"),
        );
        blocked.worker_id = None;
        blocked.selector_reason = Some(
            RchRemoteProofBlockerReason::LocalFallbackRefused
                .as_str()
                .to_owned(),
        );

        let accepted_json: serde_json::Value =
            serde_json::from_str(&accepted.to_jsonl_record().expect("accepted jsonl"))
                .expect("accepted json");
        let blocked_json: serde_json::Value =
            serde_json::from_str(&blocked.to_jsonl_record().expect("blocked jsonl"))
                .expect("blocked json");

        assert_eq!(
            accepted_json,
            serde_json::json!({
                "schema": RCH_REMOTE_PROOF_EVIDENCE_SCHEMA,
                "command": ["rch", "exec", "--", "cargo", "test", "-p", "fcp-evidence"],
                "cwd": ".",
                "git_revision": "abc1234",
                "worker_id": "worker-7",
                "rch_summary_line": "[RCH] remote worker-7 (cargo test passed)",
                "target_dir": "/tmp/fcp-proof-governor",
                "started_at_unix_ms": NOW,
                "finished_at_unix_ms": NOW + 1_000,
                "exit_kind": {"state": "remote_passed"},
                "blocker_reason": null,
                "redaction": {
                    "flags": [
                        "command_checked",
                        "cwd_redacted",
                        "target_dir_redacted",
                        "summary_redacted",
                        "secret_values_removed"
                    ]
                }
            })
        );
        assert_eq!(
            blocked_json,
            serde_json::json!({
                "schema": RCH_REMOTE_PROOF_EVIDENCE_SCHEMA,
                "command": ["rch", "exec", "--", "cargo", "test", "-p", "fcp-evidence"],
                "cwd": ".",
                "git_revision": "abc1234",
                "worker_id": null,
                "rch_summary_line": "[RCH] local (remote execution failed)",
                "selector_reason": "local_fallback_refused",
                "target_dir": "/tmp/fcp-proof-governor",
                "started_at_unix_ms": NOW,
                "finished_at_unix_ms": NOW + 1_000,
                "exit_kind": {"state": "blocked"},
                "blocker_reason": "local_fallback_refused",
                "redaction": {
                    "flags": [
                        "command_checked",
                        "cwd_redacted",
                        "target_dir_redacted",
                        "summary_redacted",
                        "secret_values_removed"
                    ]
                }
            })
        );
        assert_rch_fixture(
            "accepted golden",
            &accepted,
            RchRemoteProofClassification::AcceptedRemoteProof,
        );
        assert_rch_fixture(
            "blocked golden",
            &blocked,
            RchRemoteProofClassification::RefusedLocalFallback,
        );
    }

    #[test]
    fn rch_missing_summary_requires_remote_success_error_remains_fail_closed() {
        let missing_summary = rch_evidence(RchRemoteProofExitKind::RemotePassed, None, None);

        assert_eq!(
            missing_summary.classify().expect("missing summary"),
            RchRemoteProofClassification::FailedClosed {
                blocker: RchRemoteProofBlockerReason::MissingRchSummary,
            }
        );
        assert!(matches!(
            missing_summary.require_remote_success(),
            Err(ProofRunError::NotRchRemoteProof {
                classification: RchRemoteProofClassification::FailedClosed {
                    blocker: RchRemoteProofBlockerReason::MissingRchSummary
                }
            })
        ));
    }

    #[test]
    fn rch_summary_parser_accepts_ansi_colored_stderr_lines() {
        let evidence = rch_evidence(
            RchRemoteProofExitKind::RemotePassed,
            None,
            Some("\u{1b}[32m[RCH] remote worker-7 (cargo test passed)\u{1b}[0m"),
        );

        assert_eq!(
            evidence.parsed_summary().expect("summary").worker_id,
            Some("worker-7".to_owned())
        );
        assert_eq!(
            evidence.classify().expect("ansi summary"),
            RchRemoteProofClassification::AcceptedRemoteProof
        );
    }

    #[test]
    fn rch_remote_proof_schema_serializes_required_contract_fields() {
        let evidence = rch_evidence(
            RchRemoteProofExitKind::RemotePassed,
            None,
            Some("[RCH] remote worker-7 (cargo test passed)"),
        );
        let value = serde_json::to_value(&evidence).expect("serialize evidence");

        for field in [
            "command",
            "cwd",
            "git_revision",
            "worker_id",
            "rch_summary_line",
            "target_dir",
            "started_at_unix_ms",
            "finished_at_unix_ms",
            "exit_kind",
            "blocker_reason",
            "redaction",
        ] {
            assert!(value.get(field).is_some(), "missing field {field}");
        }
        assert_eq!(value["schema"], RCH_REMOTE_PROOF_EVIDENCE_SCHEMA);
    }

    #[test]
    fn rch_jsonl_record_carries_selector_preflight_worker_and_redaction_metadata() {
        let mut evidence = rch_evidence(
            RchRemoteProofExitKind::Blocked,
            Some(RchRemoteProofBlockerReason::TopologyPreflightFailure),
            Some("[RCH] local (remote topology preflight failed: ln: Already exists)"),
        );
        evidence.selector_reason = Some(
            RchRemoteProofBlockerReason::NoAdmissibleWorkers
                .as_str()
                .to_owned(),
        );
        evidence.preflight_reason = Some(
            RchRemoteProofBlockerReason::TopologyPreflightFailure
                .as_str()
                .to_owned(),
        );

        let record = evidence.to_jsonl_record().expect("jsonl record");
        let value: serde_json::Value = serde_json::from_str(&record).expect("parse jsonl");

        assert_eq!(value["schema"], RCH_REMOTE_PROOF_EVIDENCE_SCHEMA);
        assert_eq!(value["worker_id"], "worker-7");
        assert_eq!(value["command"][0], "rch");
        assert_eq!(value["git_revision"], "abc1234");
        assert_eq!(value["target_dir"], "/tmp/fcp-proof-governor");
        assert_eq!(value["selector_reason"], "no_admissible_workers");
        assert_eq!(value["preflight_reason"], "topology_preflight_failure");
        assert!(
            value["redaction"]["flags"]
                .as_array()
                .expect("redaction flags")
                .iter()
                .any(|flag| flag == "secret_values_removed")
        );
    }

    #[test]
    fn raw_secret_text_is_rejected() {
        let mut run = run(remote_success_events());
        run.events[0].summary = "token=raw".to_owned();

        assert!(matches!(
            run.classify(),
            Err(ProofRunError::UnsafeText {
                field: "event.summary",
                ..
            })
        ));
    }
}
