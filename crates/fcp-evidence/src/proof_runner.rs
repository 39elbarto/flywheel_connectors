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
