//! Agent-session readiness evidence schema.
//!
//! This module records the state an agent observed before it claims work,
//! edits files, runs proof lanes, or pushes changes. It is intentionally
//! evidence-only: probe execution and operator command wiring live outside this
//! crate, while this crate owns the redaction-safe schema and validation rules.

#![allow(clippy::module_name_repetitions, clippy::struct_excessive_bools)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable schema for an agent readiness report.
pub const AGENT_READINESS_REPORT_SCHEMA: &str = "fcp.agent-readiness-report.v1";

/// Stable schema for JSONL events derived from a readiness report.
pub const AGENT_READINESS_EVENT_SCHEMA: &str = "fcp.agent-readiness-event.v1";

const MAX_KEY_FRAGMENT_LEN: usize = 160;

/// Complete redaction-safe report for a single agent startup or handoff check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentReadinessReport {
    /// Schema identifier; must be [`AGENT_READINESS_REPORT_SCHEMA`].
    pub schema: String,
    /// Stable run id for joining JSONL lines, Beads comments, and artifacts.
    pub run_id: String,
    /// Repository path after applying the selected path-redaction policy.
    pub repo_path: RedactedPath,
    /// Agent identity or fallback display name.
    pub agent_name: String,
    /// Start time as Unix milliseconds.
    pub started_at_unix_ms: u64,
    /// Finish time as Unix milliseconds.
    pub finished_at_unix_ms: u64,
    /// Policy source, for example `AGENTS.md`.
    pub policy_source: String,
    /// Redaction-safe argv that produced the report.
    pub command_line: Vec<String>,
    /// Git revision or tree observed at startup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_revision_observed: Option<String>,
    /// Remote `main` revision from `git ls-remote`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_main_sha: Option<String>,
    /// Remote `master` mirror revision from `git ls-remote`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_master_sha: Option<String>,
    /// Per-subsystem probe evidence.
    pub probes: AgentReadinessProbes,
    /// Final action decision derived from the probes.
    pub decision: ReadinessDecision,
    /// Redaction contract applied by the producer.
    pub redaction: ReadinessRedactionContract,
    /// Explicit mapping from repo policy to refused actions.
    pub policy: AgentReadinessPolicyMapping,
}

impl AgentReadinessReport {
    /// Validate the report schema, redaction contract, and safety decisions.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReadinessError`] when a field is unsafe, a required
    /// AGENTS.md guardrail is missing, or a decision contradicts probe state.
    pub fn validate(&self) -> Result<(), AgentReadinessError> {
        if self.schema != AGENT_READINESS_REPORT_SCHEMA {
            return Err(AgentReadinessError::InvalidSchema {
                expected: AGENT_READINESS_REPORT_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        validate_key_fragment("run_id", &self.run_id)?;
        validate_key_fragment("agent_name", &self.agent_name)?;
        self.repo_path.validate()?;
        validate_safe_text("policy_source", &self.policy_source)?;
        if self.command_line.is_empty() {
            return Err(AgentReadinessError::EmptyCommandLine);
        }
        for arg in &self.command_line {
            validate_safe_text("command_line", arg)?;
        }
        if let Some(revision) = &self.git_revision_observed {
            validate_revision("git_revision_observed", revision)?;
        }
        if let Some(revision) = &self.remote_main_sha {
            validate_revision("remote_main_sha", revision)?;
        }
        if let Some(revision) = &self.remote_master_sha {
            validate_revision("remote_master_sha", revision)?;
        }
        if self.finished_at_unix_ms < self.started_at_unix_ms {
            return Err(AgentReadinessError::InvalidTimeRange);
        }
        self.probes.validate()?;
        self.redaction.validate()?;
        self.policy.validate()?;
        self.decision.validate()?;
        self.validate_policy_decisions()
    }

    /// Return the decision that the built-in degraded-mode policy derives from
    /// this report's probes.
    #[must_use]
    pub fn derived_decision(&self) -> ReadinessDecision {
        ReadinessDecision::from_probes(&self.probes)
    }

    /// Build deterministic JSONL-ready events from the report.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReadinessError`] when the report is invalid.
    pub fn to_jsonl_events(&self) -> Result<Vec<AgentReadinessJsonlEvent>, AgentReadinessError> {
        self.validate()?;
        let mut events = Vec::new();
        events.push(AgentReadinessJsonlEvent {
            schema: AGENT_READINESS_EVENT_SCHEMA.to_owned(),
            run_id: self.run_id.clone(),
            event_sequence: 1,
            event_kind: ReadinessEventKind::ReportSummary,
            subsystem: ReadinessSubsystem::Decision,
            status: self.decision.status,
            reason_code: self.decision.primary_reason_code.clone(),
            remediation: self.decision.primary_remediation.clone(),
            evidence_digest: Some(self.record_digest()?),
            decision_status: self.decision.status,
        });

        for (subsystem, probe) in self.probes.iter_probe_results() {
            events.push(AgentReadinessJsonlEvent {
                schema: AGENT_READINESS_EVENT_SCHEMA.to_owned(),
                run_id: self.run_id.clone(),
                event_sequence: u32::try_from(events.len() + 1)
                    .map_err(|_| AgentReadinessError::TooManyEvents)?,
                event_kind: ReadinessEventKind::ProbeResult,
                subsystem,
                status: probe.status,
                reason_code: probe.reason_code.clone(),
                remediation: probe.remediation.clone(),
                evidence_digest: probe.evidence_digest.clone(),
                decision_status: self.decision.status,
            });
        }

        Ok(events)
    }

    /// Build deterministic JSONL lines from the report events.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReadinessError`] when the report is invalid or an event
    /// cannot be serialized.
    pub fn to_jsonl_lines(&self) -> Result<Vec<String>, AgentReadinessError> {
        self.to_jsonl_events()?
            .into_iter()
            .map(|event| serde_json::to_string(&event).map_err(AgentReadinessError::from))
            .collect()
    }

    /// Deterministic digest over the validated report.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReadinessError`] when validation or serialization fails.
    pub fn record_digest(&self) -> Result<String, AgentReadinessError> {
        self.validate_without_digest()?;
        let bytes = serde_json::to_vec(self)?;
        Ok(format!(
            "blake3:{}",
            hex::encode(blake3::hash(&bytes).as_bytes())
        ))
    }

    fn validate_without_digest(&self) -> Result<(), AgentReadinessError> {
        if self.schema != AGENT_READINESS_REPORT_SCHEMA {
            return Err(AgentReadinessError::InvalidSchema {
                expected: AGENT_READINESS_REPORT_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        validate_key_fragment("run_id", &self.run_id)?;
        self.repo_path.validate()?;
        self.probes.validate()?;
        self.redaction.validate()?;
        self.policy.validate()?;
        self.decision.validate()
    }

    fn validate_policy_decisions(&self) -> Result<(), AgentReadinessError> {
        if self.probes.agent_mail.repair_actions_attempted {
            return Err(AgentReadinessError::ForbiddenActionAttempted {
                action: ForbiddenAgentAction::AgentMailRepairOrRestart,
            });
        }

        if agent_mail_unavailable(&self.probes.agent_mail) {
            self.decision.requires_refusal(
                ReadinessAction::Coordinate,
                "Agent Mail unavailable or locked",
            )?;
        }
        if beads_unavailable(&self.probes.beads) {
            self.decision
                .requires_refusal(ReadinessAction::ClaimBead, "Beads write path unavailable")?;
            self.decision
                .requires_refusal(ReadinessAction::EditFiles, "Beads write path unavailable")?;
        }
        if rch_unavailable(&self.probes.rch) || disk_blocks_proof(&self.probes.disk) {
            self.decision
                .requires_refusal(ReadinessAction::CargoProof, "rch unavailable")?;
            self.decision
                .requires_refusal(ReadinessAction::Push, "proof is blocked")?;
        }
        if self.probes.rch.local_cargo_allowed {
            return Err(AgentReadinessError::PolicyContradiction {
                field: "rch.local_cargo_allowed",
                reason: "AGENTS.md requires Cargo proof through rch",
            });
        }
        if remote_ref_untrusted(&self.probes.git)
            || local_ref_stale(&self.probes.git, &self.probes.worktree)
        {
            self.decision.requires_refusal(
                ReadinessAction::ClaimBead,
                "remote ref truth is unavailable",
            )?;
            self.decision.requires_refusal(
                ReadinessAction::EditFiles,
                "remote ref truth is unavailable",
            )?;
            self.decision.requires_refusal(
                ReadinessAction::CargoProof,
                "remote ref truth is unavailable",
            )?;
            self.decision
                .requires_refusal(ReadinessAction::Push, "remote ref truth is unavailable")?;
        }
        if self.probes.git.branch_mirror_match == Some(false) {
            self.decision
                .requires_refusal(ReadinessAction::Push, "remote branch mirror mismatch")?;
        }
        if self.probes.worktree.unrelated_dirty_present {
            self.decision
                .requires_refusal(ReadinessAction::EditFiles, "unrelated dirty tree present")?;
            self.decision
                .requires_refusal(ReadinessAction::Push, "unrelated dirty tree present")?;
        }
        Ok(())
    }
}

impl Default for AgentReadinessReport {
    fn default() -> Self {
        Self {
            schema: AGENT_READINESS_REPORT_SCHEMA.to_owned(),
            run_id: String::new(),
            repo_path: RedactedPath::default(),
            agent_name: String::new(),
            started_at_unix_ms: 0,
            finished_at_unix_ms: 0,
            policy_source: String::new(),
            command_line: Vec::new(),
            git_revision_observed: None,
            remote_main_sha: None,
            remote_master_sha: None,
            probes: AgentReadinessProbes::default(),
            decision: ReadinessDecision::default(),
            redaction: ReadinessRedactionContract::default(),
            policy: AgentReadinessPolicyMapping::default(),
        }
    }
}

/// A path value annotated with whether it is safe to export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedPath {
    /// Path value or stable artifact id.
    pub value: String,
    /// Export scope for the value.
    pub scope: PathRedactionScope,
}

impl RedactedPath {
    fn validate(&self) -> Result<(), AgentReadinessError> {
        validate_safe_text("redacted_path.value", &self.value)?;
        if self.scope == PathRedactionScope::ExportSafe && looks_like_local_user_path(&self.value) {
            return Err(AgentReadinessError::UnsafeText {
                field: "redacted_path.value",
                reason: "export-safe paths must not include local user directories",
            });
        }
        Ok(())
    }
}

impl Default for RedactedPath {
    fn default() -> Self {
        Self {
            value: "repo:fcp".to_owned(),
            scope: PathRedactionScope::ExportSafe,
        }
    }
}

/// Export policy for a path-like value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathRedactionScope {
    /// Safe for persisted/shared evidence.
    ExportSafe,
    /// May contain machine-local detail and must remain local.
    LocalOnly,
}

/// Subsystem probe evidence grouped by integration boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AgentReadinessProbes {
    /// Agent Mail coordination state.
    pub agent_mail: AgentMailReadiness,
    /// Beads database and JSONL state.
    pub beads: BeadsReadiness,
    /// Git local/remote state.
    pub git: GitReadiness,
    /// Remote proof runner state.
    pub rch: RchReadiness,
    /// Filesystem pressure state.
    pub disk: DiskReadiness,
    /// Dirty-tree ownership risk.
    pub worktree: WorktreeReadiness,
}

impl AgentReadinessProbes {
    fn validate(&self) -> Result<(), AgentReadinessError> {
        self.agent_mail.validate()?;
        self.beads.validate()?;
        self.git.validate()?;
        self.rch.validate()?;
        self.disk.validate()?;
        self.worktree.validate()
    }

    fn iter_probe_results(&self) -> Vec<(ReadinessSubsystem, &ProbeResult)> {
        let mut probes = Vec::new();
        self.agent_mail.collect_probe_results(&mut probes);
        self.beads.collect_probe_results(&mut probes);
        self.git.collect_probe_results(&mut probes);
        self.rch.collect_probe_results(&mut probes);
        self.disk.collect_probe_results(&mut probes);
        self.worktree.collect_probe_results(&mut probes);
        probes
    }
}

/// Common shape for each command or API probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Subsystem that produced this result.
    pub subsystem: ReadinessSubsystem,
    /// Probe status.
    pub status: ReadinessStatus,
    /// Redaction-safe argv or API label.
    pub command_redacted: Vec<String>,
    /// Process exit code, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Observation time as Unix milliseconds.
    pub observed_at_unix_ms: u64,
    /// Stable reason code for warn/blocked/skipped/error states.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    /// Redaction-safe remediation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// Optional digest over the underlying local artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_digest: Option<String>,
    /// Whether redaction was applied before persistence.
    pub redaction_applied: bool,
}

impl ProbeResult {
    fn validate(&self) -> Result<(), AgentReadinessError> {
        if self.command_redacted.is_empty() {
            return Err(AgentReadinessError::EmptyProbeCommand {
                subsystem: self.subsystem,
            });
        }
        for arg in &self.command_redacted {
            validate_safe_text("probe.command_redacted", arg)?;
        }
        if let Some(reason_code) = &self.reason_code {
            validate_key_fragment("probe.reason_code", reason_code)?;
        }
        if let Some(remediation) = &self.remediation {
            validate_safe_text("probe.remediation", remediation)?;
        }
        if let Some(digest) = &self.evidence_digest {
            validate_digest(digest)?;
        }
        if !self.redaction_applied {
            return Err(AgentReadinessError::MissingRedaction {
                field: "probe.redaction_applied",
            });
        }
        Ok(())
    }
}

/// Status labels used by readiness probes and final decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatus {
    /// Probe or decision is healthy.
    Ok,
    /// Probe or decision is usable with caveats.
    Warn,
    /// Probe or decision blocks an action.
    Blocked,
    /// Probe was intentionally skipped.
    Skipped,
    /// Probe failed unexpectedly.
    Error,
}

/// Readiness subsystem labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessSubsystem {
    /// Agent Mail coordination.
    AgentMail,
    /// Beads task tracker.
    Beads,
    /// Git local/remote state.
    Git,
    /// Remote command runner.
    Rch,
    /// Filesystem capacity.
    Disk,
    /// Worktree ownership.
    Worktree,
    /// Final action decision.
    Decision,
}

/// Agent Mail readiness fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMailReadiness {
    /// MCP health check result.
    pub mcp_health: ProbeResult,
    /// Registration result.
    pub register_result: ProbeResult,
    /// Agent listing result.
    pub list_agents_result: ProbeResult,
    /// Inbox fetch result.
    pub inbox_result: ProbeResult,
    /// Optional direct CLI status fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_cli_status_result: Option<ProbeResult>,
    /// Optional direct CLI agent-list fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_cli_list_result: Option<ProbeResult>,
    /// Redaction-safe mailbox lock state.
    pub mailbox_lock_state: LockState,
    /// Database open error class, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_open_error_kind: Option<String>,
    /// Must remain false; agents may not repair or restart Agent Mail.
    pub repair_actions_attempted: bool,
}

impl AgentMailReadiness {
    fn validate(&self) -> Result<(), AgentReadinessError> {
        for probe in [
            &self.mcp_health,
            &self.register_result,
            &self.list_agents_result,
            &self.inbox_result,
        ] {
            probe.validate()?;
        }
        if let Some(probe) = &self.direct_cli_status_result {
            probe.validate()?;
        }
        if let Some(probe) = &self.direct_cli_list_result {
            probe.validate()?;
        }
        if let Some(kind) = &self.db_open_error_kind {
            validate_key_fragment("agent_mail.db_open_error_kind", kind)?;
        }
        Ok(())
    }

    fn collect_probe_results<'a>(
        &'a self,
        probes: &mut Vec<(ReadinessSubsystem, &'a ProbeResult)>,
    ) {
        probes.extend([
            (ReadinessSubsystem::AgentMail, &self.mcp_health),
            (ReadinessSubsystem::AgentMail, &self.register_result),
            (ReadinessSubsystem::AgentMail, &self.list_agents_result),
            (ReadinessSubsystem::AgentMail, &self.inbox_result),
        ]);
        if let Some(probe) = &self.direct_cli_status_result {
            probes.push((ReadinessSubsystem::AgentMail, probe));
        }
        if let Some(probe) = &self.direct_cli_list_result {
            probes.push((ReadinessSubsystem::AgentMail, probe));
        }
    }
}

impl Default for AgentMailReadiness {
    fn default() -> Self {
        Self {
            mcp_health: default_probe(ReadinessSubsystem::AgentMail, "agent-mail.mcp-health"),
            register_result: default_probe(ReadinessSubsystem::AgentMail, "agent-mail.register"),
            list_agents_result: default_probe(ReadinessSubsystem::AgentMail, "agent-mail.list"),
            inbox_result: default_probe(ReadinessSubsystem::AgentMail, "agent-mail.inbox"),
            direct_cli_status_result: None,
            direct_cli_list_result: None,
            mailbox_lock_state: LockState::Unknown,
            db_open_error_kind: None,
            repair_actions_attempted: false,
        }
    }
}

/// Beads readiness fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeadsReadiness {
    /// Beads DB path class.
    pub db_path_kind: PathKind,
    /// Beads JSONL path class.
    pub jsonl_path_kind: PathKind,
    /// Import probe result.
    pub import_status: ProbeResult,
    /// Write-smoke probe result.
    pub write_smoke_status: ProbeResult,
    /// Flush probe result.
    pub flush_status: ProbeResult,
    /// SQLite/write lock timeout.
    pub lock_timeout_ms: u64,
    /// Current issue count at observation time.
    pub current_issue_count: usize,
    /// Infrastructure blocker beads active at observation time.
    #[serde(default)]
    pub blocked_infra_bead_ids: BTreeSet<String>,
}

impl BeadsReadiness {
    fn validate(&self) -> Result<(), AgentReadinessError> {
        self.import_status.validate()?;
        self.write_smoke_status.validate()?;
        self.flush_status.validate()?;
        for bead_id in &self.blocked_infra_bead_ids {
            validate_key_fragment("beads.blocked_infra_bead_ids", bead_id)?;
        }
        Ok(())
    }

    fn collect_probe_results<'a>(
        &'a self,
        probes: &mut Vec<(ReadinessSubsystem, &'a ProbeResult)>,
    ) {
        probes.extend([
            (ReadinessSubsystem::Beads, &self.import_status),
            (ReadinessSubsystem::Beads, &self.write_smoke_status),
            (ReadinessSubsystem::Beads, &self.flush_status),
        ]);
    }
}

impl Default for BeadsReadiness {
    fn default() -> Self {
        Self {
            db_path_kind: PathKind::RepoLocal,
            jsonl_path_kind: PathKind::RepoLocal,
            import_status: default_probe(ReadinessSubsystem::Beads, "br.import"),
            write_smoke_status: default_probe(ReadinessSubsystem::Beads, "br.write-smoke"),
            flush_status: default_probe(ReadinessSubsystem::Beads, "br.sync-flush-only"),
            lock_timeout_ms: 0,
            current_issue_count: 0,
            blocked_infra_bead_ids: BTreeSet::new(),
        }
    }
}

/// Path class for local state stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    /// Path lives under the repository.
    RepoLocal,
    /// Path lives in external scratch storage.
    ExternalScratch,
    /// Path is unknown or unavailable.
    Unknown,
}

/// Git readiness fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitReadiness {
    /// `git ls-remote origin refs/heads/main` result.
    pub ls_remote_main: ProbeResult,
    /// `git ls-remote origin refs/heads/master` result.
    pub ls_remote_master: ProbeResult,
    /// Whether remote `main` and mirror `master` match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch_mirror_match: Option<bool>,
    /// Local ref write status.
    pub local_ref_write_status: ProbeResult,
    /// Object directory class used for writes.
    pub object_directory_kind: PathKind,
    /// Optional alternate object directory path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alternate_object_directory: Option<RedactedPath>,
    /// Push probe result.
    pub push_status: ProbeResult,
    /// Local tracking-ref error class, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_tracking_ref_error_kind: Option<String>,
}

impl GitReadiness {
    fn validate(&self) -> Result<(), AgentReadinessError> {
        self.ls_remote_main.validate()?;
        self.ls_remote_master.validate()?;
        self.local_ref_write_status.validate()?;
        self.push_status.validate()?;
        if let Some(path) = &self.alternate_object_directory {
            path.validate()?;
        }
        if let Some(kind) = &self.local_tracking_ref_error_kind {
            validate_key_fragment("git.local_tracking_ref_error_kind", kind)?;
        }
        Ok(())
    }

    fn collect_probe_results<'a>(
        &'a self,
        probes: &mut Vec<(ReadinessSubsystem, &'a ProbeResult)>,
    ) {
        probes.extend([
            (ReadinessSubsystem::Git, &self.ls_remote_main),
            (ReadinessSubsystem::Git, &self.ls_remote_master),
            (ReadinessSubsystem::Git, &self.local_ref_write_status),
            (ReadinessSubsystem::Git, &self.push_status),
        ]);
    }
}

impl Default for GitReadiness {
    fn default() -> Self {
        Self {
            ls_remote_main: default_probe(ReadinessSubsystem::Git, "git.ls-remote-main"),
            ls_remote_master: default_probe(ReadinessSubsystem::Git, "git.ls-remote-master"),
            branch_mirror_match: None,
            local_ref_write_status: default_probe(ReadinessSubsystem::Git, "git.local-ref-write"),
            object_directory_kind: PathKind::RepoLocal,
            alternate_object_directory: None,
            push_status: default_probe(ReadinessSubsystem::Git, "git.push"),
            local_tracking_ref_error_kind: None,
        }
    }
}

/// Remote command runner readiness fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchReadiness {
    /// `rch check --json` result.
    pub check_result: ProbeResult,
    /// Optional `rch diagnose --dry-run ...` admission result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnose_result: Option<ProbeResult>,
    /// Optional `rch queue` result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_result: Option<ProbeResult>,
    /// Optional final proof summary result parsed from an actual `rch exec`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_summary_result: Option<ProbeResult>,
    /// Whether the daemon was observed running.
    pub daemon_running: bool,
    /// Whether the repository hook was installed.
    pub hook_installed: bool,
    /// Total configured workers.
    pub workers_total: usize,
    /// Healthy workers.
    pub workers_healthy: usize,
    /// Unreachable worker names or hashes.
    #[serde(default)]
    pub unreachable_workers: BTreeSet<String>,
    /// Worker pressure telemetry status.
    pub pressure_telemetry_state: TelemetryState,
    /// Admission decision derived from `rch diagnose`, queue state, and proof summary.
    #[serde(default)]
    pub admission_decision: RchAdmissionDecision,
    /// Stable reason code explaining [`Self::admission_decision`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_reason_code: Option<RchAdmissionReasonCode>,
    /// Whether Cargo proof may be offloaded now.
    pub cargo_offload_allowed: bool,
    /// Whether local Cargo is allowed by repo policy.
    pub local_cargo_allowed: bool,
}

impl RchReadiness {
    fn validate(&self) -> Result<(), AgentReadinessError> {
        self.check_result.validate()?;
        if let Some(probe) = &self.diagnose_result {
            probe.validate()?;
        }
        if let Some(probe) = &self.queue_result {
            probe.validate()?;
        }
        if let Some(probe) = &self.proof_summary_result {
            probe.validate()?;
        }
        if self.workers_healthy > self.workers_total {
            return Err(AgentReadinessError::PolicyContradiction {
                field: "rch.workers_healthy",
                reason: "healthy workers cannot exceed total workers",
            });
        }
        for worker in &self.unreachable_workers {
            validate_key_fragment("rch.unreachable_workers", worker)?;
        }
        if self.admission_decision == RchAdmissionDecision::RunRemoteNow
            && (!self.cargo_offload_allowed || self.workers_healthy == 0)
        {
            return Err(AgentReadinessError::PolicyContradiction {
                field: "rch.admission_decision",
                reason: "run_remote_now requires available remote Cargo offload",
            });
        }
        if self.admission_decision == RchAdmissionDecision::RefuseLocalFallback
            && self.local_cargo_allowed
        {
            return Err(AgentReadinessError::PolicyContradiction {
                field: "rch.local_cargo_allowed",
                reason: "local fallback must be refused in this repository",
            });
        }
        Ok(())
    }

    fn collect_probe_results<'a>(
        &'a self,
        probes: &mut Vec<(ReadinessSubsystem, &'a ProbeResult)>,
    ) {
        probes.push((ReadinessSubsystem::Rch, &self.check_result));
        if let Some(probe) = &self.diagnose_result {
            probes.push((ReadinessSubsystem::Rch, probe));
        }
        if let Some(probe) = &self.queue_result {
            probes.push((ReadinessSubsystem::Rch, probe));
        }
        if let Some(probe) = &self.proof_summary_result {
            probes.push((ReadinessSubsystem::Rch, probe));
        }
    }
}

impl Default for RchReadiness {
    fn default() -> Self {
        Self {
            check_result: default_probe(ReadinessSubsystem::Rch, "rch.check"),
            diagnose_result: None,
            queue_result: None,
            proof_summary_result: None,
            daemon_running: false,
            hook_installed: false,
            workers_total: 0,
            workers_healthy: 0,
            unreachable_workers: BTreeSet::new(),
            pressure_telemetry_state: TelemetryState::Unknown,
            admission_decision: RchAdmissionDecision::Unknown,
            admission_reason_code: None,
            cargo_offload_allowed: false,
            local_cargo_allowed: false,
        }
    }
}

/// RCH admission decision for proof commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RchAdmissionDecision {
    /// Remote offload can run now.
    RunRemoteNow,
    /// Same-project active build or slot pressure requires waiting.
    WaitForProjectSlot,
    /// Source inspection/planning is useful, but proof should not run yet.
    SourceOnlyWork,
    /// `rch` attempted or advertised local fallback, which must be refused.
    RefuseLocalFallback,
    /// RCH infrastructure failed before a build/test result existed.
    RchInfraFailure,
    /// Remote Cargo/Lean execution ran and failed for real code or tests.
    RealBuildFailure,
    /// Admission state was not observed.
    #[default]
    Unknown,
}

/// Stable RCH admission reason code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RchAdmissionReasonCode {
    /// No blocking admission condition was observed.
    Healthy,
    /// Another active command for this project prevented admission.
    ActiveProjectExclusion,
    /// Worker or project slot pressure prevented immediate offload.
    SlotPressure,
    /// No reachable or healthy worker was available.
    WorkersUnavailable,
    /// Stale cancellation or cleanup residue prevented admission.
    StaleCancellationResidue,
    /// The command fell back or would fall back to local execution.
    LocalFallbackDetected,
    /// Remote execution completed and failed as a real build/test failure.
    RemoteBuildFailed,
    /// Pressure telemetry was stale or unavailable.
    PressureTelemetryStale,
    /// A GitHub/CI proof artifact is queued, missing, or stale.
    CiArtifactUnavailable,
    /// The reason is not classified yet.
    Unknown,
}

/// Worker telemetry state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryState {
    /// Pressure telemetry is current.
    Current,
    /// Telemetry is stale.
    Stale,
    /// Telemetry was unavailable.
    Unavailable,
    /// State is unknown.
    Unknown,
}

/// Filesystem readiness fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskReadiness {
    /// Disk check probe.
    pub check_result: ProbeResult,
    /// Mount summaries.
    #[serde(default)]
    pub checked_mounts: Vec<DiskMountState>,
    /// Whether external scratch storage was available.
    pub external_scratch_available: bool,
}

impl DiskReadiness {
    fn validate(&self) -> Result<(), AgentReadinessError> {
        self.check_result.validate()?;
        for mount in &self.checked_mounts {
            mount.validate()?;
        }
        Ok(())
    }

    fn collect_probe_results<'a>(
        &'a self,
        probes: &mut Vec<(ReadinessSubsystem, &'a ProbeResult)>,
    ) {
        probes.push((ReadinessSubsystem::Disk, &self.check_result));
    }
}

impl Default for DiskReadiness {
    fn default() -> Self {
        Self {
            check_result: default_probe(ReadinessSubsystem::Disk, "df"),
            checked_mounts: Vec::new(),
            external_scratch_available: false,
        }
    }
}

/// Capacity state for one filesystem mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskMountState {
    /// Redaction-safe mount label.
    pub mount_label: String,
    /// Free bytes.
    pub free_bytes: u64,
    /// Capacity percent from the probe.
    pub capacity_percent: u8,
    /// Optional inode pressure status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inode_state: Option<String>,
    /// Threshold state.
    pub threshold_status: ReadinessStatus,
}

impl DiskMountState {
    fn validate(&self) -> Result<(), AgentReadinessError> {
        validate_key_fragment("disk.mount_label", &self.mount_label)?;
        if self.capacity_percent > 100 {
            return Err(AgentReadinessError::PolicyContradiction {
                field: "disk.capacity_percent",
                reason: "capacity percent cannot exceed 100",
            });
        }
        if let Some(inode_state) = &self.inode_state {
            validate_key_fragment("disk.inode_state", inode_state)?;
        }
        Ok(())
    }
}

/// Worktree readiness fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorktreeReadiness {
    /// Dirty-tree probe.
    pub status_result: ProbeResult,
    /// Dirty path count.
    pub dirty_count: usize,
    /// Hashes or redaction-safe ids for dirty paths.
    #[serde(default)]
    pub dirty_paths_hashed: BTreeSet<String>,
    /// Owned path globs for this agent.
    #[serde(default)]
    pub owned_path_globs: BTreeSet<String>,
    /// Whether unrelated dirty changes were present.
    pub unrelated_dirty_present: bool,
    /// Whether local refs may be stale relative to remote truth.
    pub local_ref_staleness_risk: bool,
}

impl WorktreeReadiness {
    fn validate(&self) -> Result<(), AgentReadinessError> {
        self.status_result.validate()?;
        for path_hash in &self.dirty_paths_hashed {
            validate_digest(path_hash)?;
        }
        for glob in &self.owned_path_globs {
            validate_relative_glob(glob)?;
        }
        Ok(())
    }

    fn collect_probe_results<'a>(
        &'a self,
        probes: &mut Vec<(ReadinessSubsystem, &'a ProbeResult)>,
    ) {
        probes.push((ReadinessSubsystem::Worktree, &self.status_result));
    }
}

impl Default for WorktreeReadiness {
    fn default() -> Self {
        Self {
            status_result: default_probe(ReadinessSubsystem::Worktree, "git.status"),
            dirty_count: 0,
            dirty_paths_hashed: BTreeSet::new(),
            owned_path_globs: BTreeSet::new(),
            unrelated_dirty_present: false,
            local_ref_staleness_risk: false,
        }
    }
}

/// Advisory lock state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockState {
    /// No lock conflict observed.
    Clear,
    /// Lock was busy.
    Busy,
    /// Lock state was unknown.
    Unknown,
}

/// Final readiness decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessDecision {
    /// Operational mode selected by the degraded-mode policy.
    pub mode: ReadinessOperatingMode,
    /// Overall decision status.
    pub status: ReadinessStatus,
    /// Stable primary reason code.
    pub primary_reason_code: Option<String>,
    /// Primary remediation.
    pub primary_remediation: Option<String>,
    /// Whether this agent can coordinate via Agent Mail.
    pub can_coordinate: bool,
    /// Whether this agent can claim Beads.
    pub can_claim: bool,
    /// Whether this agent can edit owned files.
    pub can_edit: bool,
    /// Whether this agent can run Cargo proof.
    pub can_run_cargo_proof: bool,
    /// Whether this agent can push to remote.
    pub can_push: bool,
    /// Explicitly allowed actions.
    #[serde(default)]
    pub allowed_actions: BTreeSet<ReadinessAction>,
    /// Explicitly refused actions.
    #[serde(default)]
    pub refused_actions: BTreeSet<ReadinessAction>,
    /// Bead ids for blockers behind the decision.
    #[serde(default)]
    pub blocker_bead_ids: BTreeSet<String>,
}

impl ReadinessDecision {
    /// Classify an observed probe set into the safest allowed operating mode.
    #[must_use]
    pub fn from_probes(probes: &AgentReadinessProbes) -> Self {
        DecisionBuilder::from_probes(probes).finish()
    }

    fn validate(&self) -> Result<(), AgentReadinessError> {
        if let Some(reason_code) = &self.primary_reason_code {
            validate_key_fragment("decision.primary_reason_code", reason_code)?;
        }
        if let Some(remediation) = &self.primary_remediation {
            validate_safe_text("decision.primary_remediation", remediation)?;
        }
        for bead_id in &self.blocker_bead_ids {
            validate_key_fragment("decision.blocker_bead_ids", bead_id)?;
        }
        self.validate_action_state(ReadinessAction::Coordinate, self.can_coordinate)?;
        self.validate_action_state(ReadinessAction::ClaimBead, self.can_claim)?;
        self.validate_action_state(ReadinessAction::EditFiles, self.can_edit)?;
        self.validate_action_state(ReadinessAction::CargoProof, self.can_run_cargo_proof)?;
        self.validate_action_state(ReadinessAction::Push, self.can_push)?;
        Ok(())
    }

    fn validate_action_state(
        &self,
        action: ReadinessAction,
        allowed: bool,
    ) -> Result<(), AgentReadinessError> {
        if allowed && self.refused_actions.contains(&action) {
            return Err(AgentReadinessError::PolicyContradiction {
                field: action.field_name(),
                reason: "action cannot be both allowed and refused",
            });
        }
        if allowed && !self.allowed_actions.contains(&action) {
            return Err(AgentReadinessError::PolicyContradiction {
                field: action.field_name(),
                reason: "action flag must agree with allowed actions",
            });
        }
        if !allowed && self.allowed_actions.contains(&action) {
            return Err(AgentReadinessError::PolicyContradiction {
                field: action.field_name(),
                reason: "action flag must agree with allowed actions",
            });
        }
        if !allowed && !self.refused_actions.contains(&action) {
            return Err(AgentReadinessError::PolicyContradiction {
                field: action.field_name(),
                reason: "refused actions must explain every disabled action",
            });
        }
        Ok(())
    }

    fn requires_refusal(
        &self,
        action: ReadinessAction,
        reason: &'static str,
    ) -> Result<(), AgentReadinessError> {
        if self.refused_actions.contains(&action) {
            Ok(())
        } else {
            Err(AgentReadinessError::PolicyContradiction {
                field: action.field_name(),
                reason,
            })
        }
    }
}

impl Default for ReadinessDecision {
    fn default() -> Self {
        Self {
            mode: ReadinessOperatingMode::ReadOnlyPlanning,
            status: ReadinessStatus::Skipped,
            primary_reason_code: None,
            primary_remediation: None,
            can_coordinate: false,
            can_claim: false,
            can_edit: false,
            can_run_cargo_proof: false,
            can_push: false,
            allowed_actions: BTreeSet::new(),
            refused_actions: BTreeSet::new(),
            blocker_bead_ids: BTreeSet::new(),
        }
    }
}

/// Operating modes selected from startup readiness probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessOperatingMode {
    /// Agent Mail, Beads, rch proof, Git, disk, and worktree checks all allow
    /// normal work.
    FullMailBeadsRch,
    /// Agent Mail is unavailable, but Beads and proof/push lanes are usable.
    BeadsOnly,
    /// The agent may inspect and plan but must not claim, edit, prove, or push.
    ReadOnlyPlanning,
    /// The agent may coordinate, claim, and edit owned files, but proof/push are
    /// blocked until rch or disk pressure recovers.
    ProofBlocked,
    /// A human/operator action is required before productive work can proceed.
    OperatorActionRequired,
}

/// Actions governed by readiness decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessAction {
    /// Use Agent Mail for coordination.
    Coordinate,
    /// Claim or update Beads.
    ClaimBead,
    /// Edit owned files.
    EditFiles,
    /// Run Cargo proof.
    CargoProof,
    /// Push commits to remote.
    Push,
}

impl ReadinessAction {
    const fn field_name(self) -> &'static str {
        match self {
            Self::Coordinate => "decision.can_coordinate",
            Self::ClaimBead => "decision.can_claim",
            Self::EditFiles => "decision.can_edit",
            Self::CargoProof => "decision.can_run_cargo_proof",
            Self::Push => "decision.can_push",
        }
    }
}

#[derive(Debug, Clone)]
struct DecisionBuilder {
    mode: ReadinessOperatingMode,
    status: ReadinessStatus,
    reason_code: Option<&'static str>,
    remediation: Option<&'static str>,
    allowed_actions: BTreeSet<ReadinessAction>,
    refused_actions: BTreeSet<ReadinessAction>,
    blocker_bead_ids: BTreeSet<String>,
}

impl DecisionBuilder {
    fn from_probes(probes: &AgentReadinessProbes) -> Self {
        let mut builder = Self::full();
        let mail_unavailable = agent_mail_unavailable(&probes.agent_mail);
        let beads_unavailable = beads_unavailable(&probes.beads);
        let rch_unavailable = rch_unavailable(&probes.rch);
        let disk_blocked = disk_blocks_proof(&probes.disk);
        let remote_ref_untrusted = remote_ref_untrusted(&probes.git);
        let local_ref_stale = local_ref_stale(&probes.git, &probes.worktree);
        let dirty_shared_tree = probes.worktree.unrelated_dirty_present;

        if probes.agent_mail.repair_actions_attempted {
            builder.operator_required(
                "agent-mail-repair-attempted",
                "stop and remove repair/restart actions before continuing",
            );
            builder
                .blocker_bead_ids
                .insert("flywheel_connectors-d5yeb".to_owned());
        } else if remote_ref_untrusted {
            builder.operator_required(
                "remote-ref-truth-unavailable",
                "refresh with git ls-remote before trusting local refs or pushing",
            );
        } else if probes.git.branch_mirror_match == Some(false) {
            builder.operator_required(
                "branch-mirror-mismatch",
                "refuse push until remote main and mirror branch match",
            );
        } else if probes.rch.local_cargo_allowed {
            builder.operator_required(
                "local-cargo-policy-contradiction",
                "disable local Cargo fallback; repo proof must use rch",
            );
            builder
                .blocker_bead_ids
                .insert("flywheel_connectors-rfbrc".to_owned());
        } else if beads_unavailable {
            builder.read_only(
                "beads-write-unavailable",
                "use read-only planning until Beads import/write/flush probes recover",
            );
        } else if local_ref_stale {
            builder.read_only(
                "local-ref-staleness-risk",
                "use read-only planning until remote ref truth and local tracking state agree",
            );
        } else if dirty_shared_tree {
            builder.read_only(
                "unrelated-dirty-tree",
                "use read-only planning until owned and unrelated dirty paths are separated",
            );
        } else if rch_unavailable || disk_blocked {
            let (reason, remediation) = if rch_unavailable {
                rch_blocked_reason(&probes.rch)
            } else {
                (
                    "proof-blocked-disk-pressure",
                    "defer Cargo proof and push until disk pressure or scratch storage recovers",
                )
            };
            builder.proof_blocked(reason, remediation);
            builder
                .blocker_bead_ids
                .insert("flywheel_connectors-rfbrc".to_owned());
        } else if mail_unavailable {
            builder.beads_only(
                "agent-mail-db-error",
                "use Beads-only fallback; do not repair or restart Agent Mail",
            );
            builder
                .blocker_bead_ids
                .insert("flywheel_connectors-d5yeb".to_owned());
        }

        if mail_unavailable {
            builder.refuse(ReadinessAction::Coordinate);
        }
        builder
    }

    fn full() -> Self {
        Self {
            mode: ReadinessOperatingMode::FullMailBeadsRch,
            status: ReadinessStatus::Ok,
            reason_code: None,
            remediation: None,
            allowed_actions: all_readiness_actions(),
            refused_actions: BTreeSet::new(),
            blocker_bead_ids: BTreeSet::new(),
        }
    }

    fn beads_only(&mut self, reason_code: &'static str, remediation: &'static str) {
        self.mode = ReadinessOperatingMode::BeadsOnly;
        self.status = ReadinessStatus::Warn;
        self.reason_code = Some(reason_code);
        self.remediation = Some(remediation);
        self.refuse(ReadinessAction::Coordinate);
    }

    fn read_only(&mut self, reason_code: &'static str, remediation: &'static str) {
        self.mode = ReadinessOperatingMode::ReadOnlyPlanning;
        self.status = ReadinessStatus::Warn;
        self.reason_code = Some(reason_code);
        self.remediation = Some(remediation);
        for action in [
            ReadinessAction::ClaimBead,
            ReadinessAction::EditFiles,
            ReadinessAction::CargoProof,
            ReadinessAction::Push,
        ] {
            self.refuse(action);
        }
    }

    fn proof_blocked(&mut self, reason_code: &'static str, remediation: &'static str) {
        self.mode = ReadinessOperatingMode::ProofBlocked;
        self.status = ReadinessStatus::Blocked;
        self.reason_code = Some(reason_code);
        self.remediation = Some(remediation);
        self.refuse(ReadinessAction::CargoProof);
        self.refuse(ReadinessAction::Push);
    }

    fn operator_required(&mut self, reason_code: &'static str, remediation: &'static str) {
        self.mode = ReadinessOperatingMode::OperatorActionRequired;
        self.status = ReadinessStatus::Blocked;
        self.reason_code = Some(reason_code);
        self.remediation = Some(remediation);
        for action in [
            ReadinessAction::ClaimBead,
            ReadinessAction::EditFiles,
            ReadinessAction::CargoProof,
            ReadinessAction::Push,
        ] {
            self.refuse(action);
        }
    }

    fn refuse(&mut self, action: ReadinessAction) {
        self.allowed_actions.remove(&action);
        self.refused_actions.insert(action);
    }

    fn finish(self) -> ReadinessDecision {
        ReadinessDecision {
            mode: self.mode,
            status: self.status,
            primary_reason_code: self.reason_code.map(str::to_owned),
            primary_remediation: self.remediation.map(str::to_owned),
            can_coordinate: self.allowed_actions.contains(&ReadinessAction::Coordinate),
            can_claim: self.allowed_actions.contains(&ReadinessAction::ClaimBead),
            can_edit: self.allowed_actions.contains(&ReadinessAction::EditFiles),
            can_run_cargo_proof: self.allowed_actions.contains(&ReadinessAction::CargoProof),
            can_push: self.allowed_actions.contains(&ReadinessAction::Push),
            allowed_actions: self.allowed_actions,
            refused_actions: self.refused_actions,
            blocker_bead_ids: self.blocker_bead_ids,
        }
    }
}

fn all_readiness_actions() -> BTreeSet<ReadinessAction> {
    BTreeSet::from([
        ReadinessAction::Coordinate,
        ReadinessAction::ClaimBead,
        ReadinessAction::EditFiles,
        ReadinessAction::CargoProof,
        ReadinessAction::Push,
    ])
}

const fn probe_blocks(probe: &ProbeResult) -> bool {
    matches!(
        probe.status,
        ReadinessStatus::Blocked | ReadinessStatus::Error
    )
}

fn agent_mail_unavailable(agent_mail: &AgentMailReadiness) -> bool {
    agent_mail.repair_actions_attempted
        || probe_blocks(&agent_mail.register_result)
        || probe_blocks(&agent_mail.list_agents_result)
        || probe_blocks(&agent_mail.inbox_result)
        || agent_mail.db_open_error_kind.is_some()
        || agent_mail.mailbox_lock_state == LockState::Busy
}

const fn beads_unavailable(beads: &BeadsReadiness) -> bool {
    probe_blocks(&beads.import_status)
        || probe_blocks(&beads.write_smoke_status)
        || probe_blocks(&beads.flush_status)
}

const fn rch_unavailable(rch: &RchReadiness) -> bool {
    probe_blocks(&rch.check_result)
        || !rch.cargo_offload_allowed
        || rch.workers_healthy == 0
        || !matches!(
            rch.admission_decision,
            RchAdmissionDecision::RunRemoteNow | RchAdmissionDecision::Unknown
        )
}

const fn rch_blocked_reason(rch: &RchReadiness) -> (&'static str, &'static str) {
    match (rch.admission_decision, rch.admission_reason_code) {
        (
            RchAdmissionDecision::WaitForProjectSlot,
            Some(RchAdmissionReasonCode::ActiveProjectExclusion),
        ) => (
            "proof-blocked-rch-active-project-exclusion",
            "wait for the active same-project rch command to finish; do not run local Cargo fallback",
        ),
        (RchAdmissionDecision::WaitForProjectSlot, Some(RchAdmissionReasonCode::SlotPressure)) => (
            "proof-blocked-rch-slot-pressure",
            "wait for a remote rch slot; do not run local Cargo fallback",
        ),
        (
            RchAdmissionDecision::RefuseLocalFallback,
            Some(RchAdmissionReasonCode::LocalFallbackDetected),
        ) => (
            "proof-blocked-rch-local-fallback-refused",
            "treat rch local fallback as refusal, not proof",
        ),
        (
            RchAdmissionDecision::RchInfraFailure,
            Some(RchAdmissionReasonCode::StaleCancellationResidue),
        ) => (
            "proof-blocked-rch-stale-cancellation",
            "wait for rch cleanup or operator action; do not repair workers from readiness handling",
        ),
        (
            RchAdmissionDecision::RchInfraFailure,
            Some(RchAdmissionReasonCode::PressureTelemetryStale),
        ) => (
            "proof-blocked-rch-pressure-telemetry-stale",
            "refresh rch telemetry through read-only status before admitting proof",
        ),
        (
            RchAdmissionDecision::RchInfraFailure,
            Some(RchAdmissionReasonCode::WorkersUnavailable),
        ) => (
            "proof-blocked-rch-workers-unavailable",
            "defer Cargo proof and push until rch has healthy workers",
        ),
        (
            RchAdmissionDecision::RealBuildFailure,
            Some(RchAdmissionReasonCode::RemoteBuildFailed),
        ) => (
            "proof-failed-remote-build",
            "fix the reported remote build or test failure before pushing",
        ),
        (RchAdmissionDecision::SourceOnlyWork, _) => (
            "proof-blocked-rch-source-only",
            "continue source inspection only until rch proof admission recovers",
        ),
        _ => (
            "proof-blocked-rch-unavailable",
            "defer Cargo proof and push until rch has healthy workers",
        ),
    }
}

fn disk_blocks_proof(disk: &DiskReadiness) -> bool {
    probe_blocks(&disk.check_result)
        || !disk.external_scratch_available
        || disk
            .checked_mounts
            .iter()
            .any(|mount| probe_status_blocks(mount.threshold_status))
}

const fn remote_ref_untrusted(git: &GitReadiness) -> bool {
    probe_blocks(&git.ls_remote_main) || probe_blocks(&git.ls_remote_master)
}

const fn local_ref_stale(git: &GitReadiness, worktree: &WorktreeReadiness) -> bool {
    git.local_tracking_ref_error_kind.is_some() || worktree.local_ref_staleness_risk
}

const fn probe_status_blocks(status: ReadinessStatus) -> bool {
    matches!(status, ReadinessStatus::Blocked | ReadinessStatus::Error)
}

/// Redaction contract applied by the readiness producer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessRedactionContract {
    /// Contract schema label.
    pub schema: String,
    /// Fields that must never be persisted raw.
    #[serde(default)]
    pub redacted_classes: BTreeSet<RedactionTarget>,
    /// Whether bounded redacted stderr/stdout excerpts are allowed.
    pub bounded_stderr_excerpt_allowed: bool,
    /// Maximum retained excerpt bytes.
    pub max_excerpt_bytes: usize,
    /// Whether local user paths are redacted for export-safe reports.
    pub local_user_paths_redacted: bool,
}

impl ReadinessRedactionContract {
    pub(crate) fn validate(&self) -> Result<(), AgentReadinessError> {
        validate_key_fragment("redaction.schema", &self.schema)?;
        for required in REQUIRED_REDACTION_TARGETS {
            if !self.redacted_classes.contains(&required) {
                return Err(AgentReadinessError::MissingRedactionTarget { target: required });
            }
        }
        if !self.local_user_paths_redacted {
            return Err(AgentReadinessError::MissingRedaction {
                field: "redaction.local_user_paths_redacted",
            });
        }
        Ok(())
    }
}

impl Default for ReadinessRedactionContract {
    fn default() -> Self {
        Self {
            schema: "fcp.agent-readiness-redaction.v1".to_owned(),
            redacted_classes: REQUIRED_REDACTION_TARGETS.into_iter().collect(),
            bounded_stderr_excerpt_allowed: true,
            max_excerpt_bytes: 4096,
            local_user_paths_redacted: true,
        }
    }
}

const REQUIRED_REDACTION_TARGETS: [RedactionTarget; 9] = [
    RedactionTarget::Token,
    RedactionTarget::Cookie,
    RedactionTarget::Authorization,
    RedactionTarget::ProxyCredential,
    RedactionTarget::RawEndpoint,
    RedactionTarget::TargetUrl,
    RedactionTarget::LocalUserPath,
    RedactionTarget::MailboxDatabasePath,
    RedactionTarget::DirtyFilePath,
];

/// Data classes covered by the readiness redaction policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionTarget {
    /// Tokens and OAuth secrets.
    Token,
    /// Cookie values.
    Cookie,
    /// Authorization headers.
    Authorization,
    /// Proxy credentials.
    ProxyCredential,
    /// Raw endpoints.
    RawEndpoint,
    /// Target URLs.
    TargetUrl,
    /// Local user paths.
    LocalUserPath,
    /// Agent Mail mailbox database paths.
    MailboxDatabasePath,
    /// Dirty file paths.
    DirtyFilePath,
}

/// Explicit repo-policy mapping for forbidden actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentReadinessPolicyMapping {
    /// Policy source path or id.
    pub source: String,
    /// Forbidden actions from the policy.
    #[serde(default)]
    pub forbidden_actions: BTreeSet<ForbiddenAgentAction>,
    /// Stable refusal rules keyed by rule id.
    #[serde(default)]
    pub refusal_rules: BTreeMap<String, String>,
}

impl AgentReadinessPolicyMapping {
    fn validate(&self) -> Result<(), AgentReadinessError> {
        validate_safe_text("policy.source", &self.source)?;
        for required in REQUIRED_FORBIDDEN_ACTIONS {
            if !self.forbidden_actions.contains(&required) {
                return Err(AgentReadinessError::MissingForbiddenAction { action: required });
            }
        }
        for (rule_id, rule) in &self.refusal_rules {
            validate_key_fragment("policy.refusal_rules.key", rule_id)?;
            validate_safe_text("policy.refusal_rules.value", rule)?;
        }
        Ok(())
    }
}

impl Default for AgentReadinessPolicyMapping {
    fn default() -> Self {
        let refusal_rules = BTreeMap::from([
            (
                "agent-mail-no-repair".to_owned(),
                "Do not restart, repair, reconstruct, or kill Agent Mail.".to_owned(),
            ),
            (
                "no-file-deletion".to_owned(),
                "Do not delete files or folders without explicit written approval.".to_owned(),
            ),
            (
                "disk-cleanup-needs-approval".to_owned(),
                "Do not clean disk pressure by deleting files or artifacts without explicit written approval.".to_owned(),
            ),
            (
                "worker-fleet-repair-needs-approval".to_owned(),
                "Do not repair, restart, or reconfigure rch workers from readiness handling.".to_owned(),
            ),
            (
                "cargo-through-rch".to_owned(),
                "Run Cargo build, test, check, and clippy proof through rch.".to_owned(),
            ),
            (
                "remote-ref-truth".to_owned(),
                "Use git ls-remote for remote branch truth when local refs may be stale."
                    .to_owned(),
            ),
        ]);
        Self {
            source: "AGENTS.md".to_owned(),
            forbidden_actions: REQUIRED_FORBIDDEN_ACTIONS.into_iter().collect(),
            refusal_rules,
        }
    }
}

const REQUIRED_FORBIDDEN_ACTIONS: [ForbiddenAgentAction; 8] = [
    ForbiddenAgentAction::AgentMailRepairOrRestart,
    ForbiddenAgentAction::FileDeletion,
    ForbiddenAgentAction::DiskCleanup,
    ForbiddenAgentAction::WorkerFleetRepair,
    ForbiddenAgentAction::DestructiveGitCleanup,
    ForbiddenAgentAction::LocalCargoWhenRchRequired,
    ForbiddenAgentAction::TrustStaleLocalRef,
    ForbiddenAgentAction::FakeLiveProof,
];

/// Actions the readiness policy must refuse unless explicit operator approval exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForbiddenAgentAction {
    /// Restart, repair, reconstruct, or kill Agent Mail.
    AgentMailRepairOrRestart,
    /// Delete files or directories without explicit approval.
    FileDeletion,
    /// Clean disk pressure by deleting files or pruning artifacts.
    DiskCleanup,
    /// Repair, restart, or reconfigure rch worker fleets.
    WorkerFleetRepair,
    /// Run destructive Git cleanup or reset.
    DestructiveGitCleanup,
    /// Run Cargo locally when repo policy requires rch.
    LocalCargoWhenRchRequired,
    /// Treat stale local refs as remote truth.
    TrustStaleLocalRef,
    /// Treat sync chatter or skipped proof as live proof.
    FakeLiveProof,
}

/// JSONL-ready event derived from a readiness report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentReadinessJsonlEvent {
    /// Schema identifier; must be [`AGENT_READINESS_EVENT_SCHEMA`].
    pub schema: String,
    /// Readiness run id.
    pub run_id: String,
    /// Stable event sequence.
    pub event_sequence: u32,
    /// Event kind.
    pub event_kind: ReadinessEventKind,
    /// Subsystem summarized by this event.
    pub subsystem: ReadinessSubsystem,
    /// Event status.
    pub status: ReadinessStatus,
    /// Stable reason code, if any.
    pub reason_code: Option<String>,
    /// Redaction-safe remediation, if any.
    pub remediation: Option<String>,
    /// Optional evidence digest.
    pub evidence_digest: Option<String>,
    /// Final decision status for easy JSONL filtering.
    pub decision_status: ReadinessStatus,
}

/// JSONL event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessEventKind {
    /// Summary event for the full report.
    ReportSummary,
    /// Event for one probe result.
    ProbeResult,
}

/// Error type for readiness schema validation.
#[derive(Debug, Error)]
pub enum AgentReadinessError {
    /// Report schema was not the current schema.
    #[error("invalid agent readiness schema: expected {expected}, got {actual}")]
    InvalidSchema {
        /// Expected schema id.
        expected: &'static str,
        /// Actual schema id.
        actual: String,
    },
    /// Finished time preceded started time.
    #[error("invalid readiness time range")]
    InvalidTimeRange,
    /// Top-level command line was empty.
    #[error("readiness command line must not be empty")]
    EmptyCommandLine,
    /// Probe command label was empty.
    #[error("probe command for {subsystem:?} must not be empty")]
    EmptyProbeCommand {
        /// Probe subsystem.
        subsystem: ReadinessSubsystem,
    },
    /// Unsafe text was detected.
    #[error("unsafe {field}: {reason}")]
    UnsafeText {
        /// Field name.
        field: &'static str,
        /// Reason text.
        reason: &'static str,
    },
    /// Required redaction target was missing.
    #[error("readiness redaction contract is missing {target:?}")]
    MissingRedactionTarget {
        /// Missing target.
        target: RedactionTarget,
    },
    /// Required redaction state was missing.
    #[error("missing readiness redaction marker for {field}")]
    MissingRedaction {
        /// Field name.
        field: &'static str,
    },
    /// Required forbidden action mapping was missing.
    #[error("readiness policy mapping is missing forbidden action {action:?}")]
    MissingForbiddenAction {
        /// Missing action.
        action: ForbiddenAgentAction,
    },
    /// A forbidden action was attempted.
    #[error("forbidden readiness action was attempted: {action:?}")]
    ForbiddenActionAttempted {
        /// Attempted forbidden action.
        action: ForbiddenAgentAction,
    },
    /// Probe state and decision state were contradictory.
    #[error("policy contradiction in {field}: {reason}")]
    PolicyContradiction {
        /// Contradictory field.
        field: &'static str,
        /// Reason text.
        reason: &'static str,
    },
    /// Event count overflowed `u32`.
    #[error("too many readiness events")]
    TooManyEvents,
    /// JSON serialization failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

fn default_probe(subsystem: ReadinessSubsystem, command: &str) -> ProbeResult {
    ProbeResult {
        subsystem,
        status: ReadinessStatus::Skipped,
        command_redacted: vec![command.to_owned()],
        exit_code: None,
        duration_ms: 0,
        observed_at_unix_ms: 0,
        reason_code: Some("not-run".to_owned()),
        remediation: Some("probe was not run".to_owned()),
        evidence_digest: None,
        redaction_applied: true,
    }
}

pub(crate) fn validate_key_fragment(
    field: &'static str,
    value: &str,
) -> Result<(), AgentReadinessError> {
    validate_safe_text(field, value)?;
    if value.len() > MAX_KEY_FRAGMENT_LEN {
        return Err(AgentReadinessError::UnsafeText {
            field,
            reason: "identifier is too long",
        });
    }
    if value.trim() != value || value.chars().any(char::is_whitespace) {
        return Err(AgentReadinessError::UnsafeText {
            field,
            reason: "identifier must not contain whitespace",
        });
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '/'))
    {
        return Err(AgentReadinessError::UnsafeText {
            field,
            reason: "identifier contains unsupported characters",
        });
    }
    Ok(())
}

fn validate_revision(field: &'static str, value: &str) -> Result<(), AgentReadinessError> {
    validate_safe_text(field, value)?;
    if value.len() < 7 || value.len() > 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(AgentReadinessError::UnsafeText {
            field,
            reason: "revision must be 7 to 64 hex characters",
        });
    }
    Ok(())
}

fn validate_relative_glob(value: &str) -> Result<(), AgentReadinessError> {
    validate_safe_text("worktree.owned_path_globs", value)?;
    if value.starts_with('/') || value.contains("..") || looks_like_local_user_path(value) {
        return Err(AgentReadinessError::UnsafeText {
            field: "worktree.owned_path_globs",
            reason: "owned path globs must be repository-relative",
        });
    }
    Ok(())
}

pub(crate) fn validate_safe_text(
    field: &'static str,
    value: &str,
) -> Result<(), AgentReadinessError> {
    if value.trim().is_empty() {
        return Err(AgentReadinessError::UnsafeText {
            field,
            reason: "empty text",
        });
    }
    if value.contains("://") {
        return Err(AgentReadinessError::UnsafeText {
            field,
            reason: "raw endpoints must be replaced with artifact ids",
        });
    }
    if looks_like_secret(value) {
        return Err(AgentReadinessError::UnsafeText {
            field,
            reason: "raw secret-like text is not allowed",
        });
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), AgentReadinessError> {
    let Some((algorithm, digest)) = value.split_once(':') else {
        return Err(AgentReadinessError::UnsafeText {
            field: "digest",
            reason: "digest must include an algorithm prefix",
        });
    };
    validate_key_fragment("digest.algorithm", algorithm)?;
    if digest.len() < 16 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(AgentReadinessError::UnsafeText {
            field: "digest",
            reason: "digest body must be hex and at least 16 characters",
        });
    }
    Ok(())
}

fn looks_like_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("authorization:")
        || lower.contains("bearer ")
        || lower.contains("token=")
        || lower.contains("password=")
        || lower.contains("secret=")
        || lower.contains("api_key=")
        || lower.contains("apikey=")
        || lower.contains("ghp_")
        || lower.contains("oauth_")
}

fn looks_like_local_user_path(value: &str) -> bool {
    value.contains("/Users/") || value.contains("/home/")
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000_000;
    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn ok_probe(subsystem: ReadinessSubsystem, command: &str) -> ProbeResult {
        ProbeResult {
            subsystem,
            status: ReadinessStatus::Ok,
            command_redacted: command.split_whitespace().map(ToOwned::to_owned).collect(),
            exit_code: Some(0),
            duration_ms: 12,
            observed_at_unix_ms: NOW,
            reason_code: None,
            remediation: None,
            evidence_digest: Some(
                "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            ),
            redaction_applied: true,
        }
    }

    fn blocked_probe(
        subsystem: ReadinessSubsystem,
        command: &str,
        reason_code: &str,
    ) -> ProbeResult {
        ProbeResult {
            status: ReadinessStatus::Blocked,
            reason_code: Some(reason_code.to_owned()),
            remediation: Some("use degraded mode without unsafe repair".to_owned()),
            ..ok_probe(subsystem, command)
        }
    }

    fn healthy_report() -> AgentReadinessReport {
        let allowed_actions = [
            ReadinessAction::Coordinate,
            ReadinessAction::ClaimBead,
            ReadinessAction::EditFiles,
            ReadinessAction::CargoProof,
            ReadinessAction::Push,
        ]
        .into_iter()
        .collect();

        AgentReadinessReport {
            schema: AGENT_READINESS_REPORT_SCHEMA.to_owned(),
            run_id: "readiness-run-1".to_owned(),
            repo_path: RedactedPath {
                value: "repo:flywheel-connectors".to_owned(),
                scope: PathRedactionScope::ExportSafe,
            },
            agent_name: "GreenLake".to_owned(),
            started_at_unix_ms: NOW,
            finished_at_unix_ms: NOW + 100,
            policy_source: "AGENTS.md".to_owned(),
            command_line: vec![
                "fwc".to_owned(),
                "agent-readiness".to_owned(),
                "--jsonl".to_owned(),
            ],
            git_revision_observed: Some(SHA.to_owned()),
            remote_main_sha: Some(SHA.to_owned()),
            remote_master_sha: Some(SHA.to_owned()),
            probes: AgentReadinessProbes {
                agent_mail: AgentMailReadiness {
                    mcp_health: ok_probe(ReadinessSubsystem::AgentMail, "agent-mail mcp-health"),
                    register_result: ok_probe(ReadinessSubsystem::AgentMail, "agent-mail register"),
                    list_agents_result: ok_probe(ReadinessSubsystem::AgentMail, "agent-mail list"),
                    inbox_result: ok_probe(ReadinessSubsystem::AgentMail, "agent-mail inbox"),
                    direct_cli_status_result: None,
                    direct_cli_list_result: None,
                    mailbox_lock_state: LockState::Clear,
                    db_open_error_kind: None,
                    repair_actions_attempted: false,
                },
                beads: BeadsReadiness {
                    import_status: ok_probe(ReadinessSubsystem::Beads, "br import"),
                    write_smoke_status: ok_probe(ReadinessSubsystem::Beads, "br write-smoke"),
                    flush_status: ok_probe(ReadinessSubsystem::Beads, "br sync-flush-only"),
                    lock_timeout_ms: 60_000,
                    current_issue_count: 3545,
                    ..BeadsReadiness::default()
                },
                git: GitReadiness {
                    ls_remote_main: ok_probe(ReadinessSubsystem::Git, "git ls-remote main"),
                    ls_remote_master: ok_probe(ReadinessSubsystem::Git, "git ls-remote master"),
                    branch_mirror_match: Some(true),
                    local_ref_write_status: ok_probe(ReadinessSubsystem::Git, "git ref-write"),
                    push_status: ok_probe(ReadinessSubsystem::Git, "git push"),
                    ..GitReadiness::default()
                },
                rch: RchReadiness {
                    check_result: ok_probe(ReadinessSubsystem::Rch, "rch check --json"),
                    diagnose_result: Some(ok_probe(
                        ReadinessSubsystem::Rch,
                        "rch diagnose --dry-run",
                    )),
                    queue_result: Some(ok_probe(ReadinessSubsystem::Rch, "rch queue")),
                    proof_summary_result: Some(ok_probe(
                        ReadinessSubsystem::Rch,
                        "rch proof-summary",
                    )),
                    daemon_running: true,
                    hook_installed: true,
                    workers_total: 8,
                    workers_healthy: 8,
                    unreachable_workers: BTreeSet::new(),
                    pressure_telemetry_state: TelemetryState::Current,
                    admission_decision: RchAdmissionDecision::RunRemoteNow,
                    admission_reason_code: Some(RchAdmissionReasonCode::Healthy),
                    cargo_offload_allowed: true,
                    local_cargo_allowed: false,
                },
                disk: DiskReadiness {
                    check_result: ok_probe(ReadinessSubsystem::Disk, "df -h"),
                    checked_mounts: vec![DiskMountState {
                        mount_label: "system-data".to_owned(),
                        free_bytes: 170_000_000_000,
                        capacity_percent: 92,
                        inode_state: Some("ok".to_owned()),
                        threshold_status: ReadinessStatus::Ok,
                    }],
                    external_scratch_available: true,
                },
                worktree: WorktreeReadiness {
                    status_result: ok_probe(ReadinessSubsystem::Worktree, "git status --short"),
                    dirty_count: 0,
                    dirty_paths_hashed: BTreeSet::new(),
                    owned_path_globs: BTreeSet::from(["crates/fcp-evidence/src/*".to_owned()]),
                    unrelated_dirty_present: false,
                    local_ref_staleness_risk: false,
                },
            },
            decision: ReadinessDecision {
                mode: ReadinessOperatingMode::FullMailBeadsRch,
                status: ReadinessStatus::Ok,
                primary_reason_code: None,
                primary_remediation: None,
                can_coordinate: true,
                can_claim: true,
                can_edit: true,
                can_run_cargo_proof: true,
                can_push: true,
                allowed_actions,
                refused_actions: BTreeSet::new(),
                blocker_bead_ids: BTreeSet::new(),
            },
            redaction: ReadinessRedactionContract::default(),
            policy: AgentReadinessPolicyMapping::default(),
        }
    }

    #[test]
    fn healthy_fixture_validates_and_emits_deterministic_jsonl() {
        let report = healthy_report();
        report.validate().expect("healthy report validates");

        let events = report.to_jsonl_events().expect("jsonl events");
        assert_eq!(events[0].schema, AGENT_READINESS_EVENT_SCHEMA);
        assert_eq!(events[0].event_sequence, 1);
        assert_eq!(events[0].event_kind, ReadinessEventKind::ReportSummary);
        assert_eq!(events[0].status, ReadinessStatus::Ok);
        assert_eq!(events.len(), 18);

        let line = serde_json::to_string(&events[0]).expect("event serializes");
        assert!(line.contains("\"schema\":\"fcp.agent-readiness-event.v1\""));
        assert!(line.contains("\"run_id\":\"readiness-run-1\""));
    }

    #[test]
    fn degraded_agent_mail_fixture_refuses_coordination_without_repair() {
        let mut report = healthy_report();
        report.probes.agent_mail.register_result = blocked_probe(
            ReadinessSubsystem::AgentMail,
            "agent-mail register",
            "agent-mail-db-error",
        );
        report.probes.agent_mail.mailbox_lock_state = LockState::Busy;
        report.probes.agent_mail.db_open_error_kind = Some("io-error".to_owned());
        report.probes.agent_mail.repair_actions_attempted = false;
        report.decision.mode = ReadinessOperatingMode::BeadsOnly;
        report.decision.status = ReadinessStatus::Warn;
        report.decision.can_coordinate = false;
        report
            .decision
            .allowed_actions
            .remove(&ReadinessAction::Coordinate);
        report
            .decision
            .refused_actions
            .insert(ReadinessAction::Coordinate);
        report.decision.primary_reason_code = Some("agent-mail-db-error".to_owned());
        report.decision.primary_remediation =
            Some("proceed with Beads-only fallback; do not repair Agent Mail".to_owned());

        report.validate().expect("degraded report validates");
    }

    #[test]
    fn blocked_rch_fixture_requires_cargo_refusal() {
        let mut report = healthy_report();
        report.probes.rch.check_result = blocked_probe(
            ReadinessSubsystem::Rch,
            "rch check --json",
            "rch-workers-unreachable",
        );
        report.probes.rch.workers_healthy = 0;
        report.probes.rch.unreachable_workers = BTreeSet::from(["vmi1149989".to_owned()]);
        report.probes.rch.pressure_telemetry_state = TelemetryState::Unavailable;
        report.probes.rch.admission_decision = RchAdmissionDecision::RchInfraFailure;
        report.probes.rch.admission_reason_code = Some(RchAdmissionReasonCode::WorkersUnavailable);
        report.probes.rch.cargo_offload_allowed = false;
        report.decision.mode = ReadinessOperatingMode::ProofBlocked;
        report.decision.status = ReadinessStatus::Blocked;
        report.decision.can_run_cargo_proof = false;
        report.decision.can_push = false;
        report
            .decision
            .allowed_actions
            .remove(&ReadinessAction::CargoProof);
        report
            .decision
            .refused_actions
            .insert(ReadinessAction::CargoProof);
        report
            .decision
            .allowed_actions
            .remove(&ReadinessAction::Push);
        report
            .decision
            .refused_actions
            .insert(ReadinessAction::Push);
        report
            .decision
            .blocker_bead_ids
            .insert("flywheel_connectors-rfbrc".to_owned());

        report.validate().expect("blocked rch report validates");
    }

    #[test]
    fn blocked_rch_fixture_rejects_fake_cargo_permission() {
        let mut report = healthy_report();
        report.probes.rch.workers_healthy = 0;
        report.probes.rch.cargo_offload_allowed = false;
        report.probes.rch.admission_decision = RchAdmissionDecision::RchInfraFailure;
        report.probes.rch.admission_reason_code = Some(RchAdmissionReasonCode::WorkersUnavailable);

        let err = report.validate().expect_err("cargo proof must be refused");
        assert!(matches!(
            err,
            AgentReadinessError::PolicyContradiction {
                field: "decision.can_run_cargo_proof",
                reason: "rch unavailable",
            }
        ));
    }

    #[derive(Debug, Clone, Copy)]
    enum DegradedDecisionCase {
        Healthy,
        AgentMailUnavailable,
        BeadsUnavailable,
        LocalRefStale,
        DirtySharedTree,
        RchUnavailable,
        DiskPressure,
        BranchMirrorMismatch,
        RemoteRefUnavailable,
        LocalCargoAllowed,
        AgentMailRepairAttempted,
    }

    struct ExpectedDecisionCase {
        name: &'static str,
        scenario: DegradedDecisionCase,
        mode: ReadinessOperatingMode,
        status: ReadinessStatus,
        reason_code: Option<&'static str>,
        refused_actions: &'static [ReadinessAction],
        blocker_bead_ids: &'static [&'static str],
    }

    const WORK_REFUSALS: &[ReadinessAction] = &[
        ReadinessAction::ClaimBead,
        ReadinessAction::EditFiles,
        ReadinessAction::CargoProof,
        ReadinessAction::Push,
    ];
    const PROOF_REFUSALS: &[ReadinessAction] =
        &[ReadinessAction::CargoProof, ReadinessAction::Push];
    const ALL_REFUSALS: &[ReadinessAction] = &[
        ReadinessAction::Coordinate,
        ReadinessAction::ClaimBead,
        ReadinessAction::EditFiles,
        ReadinessAction::CargoProof,
        ReadinessAction::Push,
    ];

    #[test]
    fn derived_decision_classifies_degraded_modes_and_refusals() {
        let cases = normal_degraded_decision_cases()
            .into_iter()
            .chain(blocked_degraded_decision_cases());

        for case in cases {
            let mut report = healthy_report();
            apply_degraded_decision_case(case.scenario, &mut report);
            report.decision = report.derived_decision();

            assert_eq!(report.decision.mode, case.mode, "{}", case.name);
            assert_eq!(report.decision.status, case.status, "{}", case.name);
            assert_eq!(
                report.decision.primary_reason_code.as_deref(),
                case.reason_code,
                "{}",
                case.name
            );
            assert_refused_actions(&report.decision, case.refused_actions, case.name);
            assert_blocker_beads(&report.decision, case.blocker_bead_ids, case.name);

            match case.scenario {
                DegradedDecisionCase::AgentMailRepairAttempted => {
                    let err = report.validate().expect_err("repair attempt is forbidden");
                    assert!(matches!(
                        err,
                        AgentReadinessError::ForbiddenActionAttempted {
                            action: ForbiddenAgentAction::AgentMailRepairOrRestart,
                        }
                    ));
                }
                DegradedDecisionCase::LocalCargoAllowed => {
                    let err = report
                        .validate()
                        .expect_err("local cargo permission is forbidden");
                    assert!(matches!(
                        err,
                        AgentReadinessError::PolicyContradiction {
                            field: "rch.local_cargo_allowed",
                            reason: "AGENTS.md requires Cargo proof through rch",
                        }
                    ));
                }
                _ => report.validate().expect(case.name),
            }
        }
    }

    fn normal_degraded_decision_cases() -> [ExpectedDecisionCase; 5] {
        use DegradedDecisionCase::{
            AgentMailUnavailable, BeadsUnavailable, DirtySharedTree, Healthy, LocalRefStale,
        };
        use ReadinessOperatingMode::{BeadsOnly, FullMailBeadsRch, ReadOnlyPlanning};

        [
            expected_case(
                "healthy",
                Healthy,
                FullMailBeadsRch,
                ReadinessStatus::Ok,
                None,
                &[],
                &[],
            ),
            expected_case(
                "agent mail unavailable",
                AgentMailUnavailable,
                BeadsOnly,
                ReadinessStatus::Warn,
                Some("agent-mail-db-error"),
                &[ReadinessAction::Coordinate],
                &["flywheel_connectors-d5yeb"],
            ),
            expected_case(
                "beads unavailable",
                BeadsUnavailable,
                ReadOnlyPlanning,
                ReadinessStatus::Warn,
                Some("beads-write-unavailable"),
                WORK_REFUSALS,
                &[],
            ),
            expected_case(
                "local ref stale",
                LocalRefStale,
                ReadOnlyPlanning,
                ReadinessStatus::Warn,
                Some("local-ref-staleness-risk"),
                WORK_REFUSALS,
                &[],
            ),
            expected_case(
                "dirty shared tree",
                DirtySharedTree,
                ReadOnlyPlanning,
                ReadinessStatus::Warn,
                Some("unrelated-dirty-tree"),
                WORK_REFUSALS,
                &[],
            ),
        ]
    }

    fn blocked_degraded_decision_cases() -> [ExpectedDecisionCase; 6] {
        use DegradedDecisionCase::{
            AgentMailRepairAttempted, BranchMirrorMismatch, DiskPressure, LocalCargoAllowed,
            RchUnavailable, RemoteRefUnavailable,
        };
        use ReadinessOperatingMode::{OperatorActionRequired, ProofBlocked};

        [
            expected_case(
                "rch unavailable",
                RchUnavailable,
                ProofBlocked,
                ReadinessStatus::Blocked,
                Some("proof-blocked-rch-workers-unavailable"),
                PROOF_REFUSALS,
                &["flywheel_connectors-rfbrc"],
            ),
            expected_case(
                "disk pressure",
                DiskPressure,
                ProofBlocked,
                ReadinessStatus::Blocked,
                Some("proof-blocked-disk-pressure"),
                PROOF_REFUSALS,
                &["flywheel_connectors-rfbrc"],
            ),
            expected_case(
                "branch mirror mismatch",
                BranchMirrorMismatch,
                OperatorActionRequired,
                ReadinessStatus::Blocked,
                Some("branch-mirror-mismatch"),
                WORK_REFUSALS,
                &[],
            ),
            expected_case(
                "remote ref unavailable",
                RemoteRefUnavailable,
                OperatorActionRequired,
                ReadinessStatus::Blocked,
                Some("remote-ref-truth-unavailable"),
                WORK_REFUSALS,
                &[],
            ),
            expected_case(
                "local cargo allowed",
                LocalCargoAllowed,
                OperatorActionRequired,
                ReadinessStatus::Blocked,
                Some("local-cargo-policy-contradiction"),
                WORK_REFUSALS,
                &["flywheel_connectors-rfbrc"],
            ),
            expected_case(
                "agent mail repair attempted",
                AgentMailRepairAttempted,
                OperatorActionRequired,
                ReadinessStatus::Blocked,
                Some("agent-mail-repair-attempted"),
                ALL_REFUSALS,
                &["flywheel_connectors-d5yeb"],
            ),
        ]
    }

    const fn expected_case(
        name: &'static str,
        scenario: DegradedDecisionCase,
        mode: ReadinessOperatingMode,
        status: ReadinessStatus,
        reason_code: Option<&'static str>,
        refused_actions: &'static [ReadinessAction],
        blocker_bead_ids: &'static [&'static str],
    ) -> ExpectedDecisionCase {
        ExpectedDecisionCase {
            name,
            scenario,
            mode,
            status,
            reason_code,
            refused_actions,
            blocker_bead_ids,
        }
    }

    fn apply_degraded_decision_case(
        scenario: DegradedDecisionCase,
        report: &mut AgentReadinessReport,
    ) {
        match scenario {
            DegradedDecisionCase::Healthy => {}
            DegradedDecisionCase::AgentMailUnavailable => {
                report.probes.agent_mail.register_result = blocked_probe(
                    ReadinessSubsystem::AgentMail,
                    "agent-mail register",
                    "agent-mail-db-error",
                );
                report.probes.agent_mail.mailbox_lock_state = LockState::Busy;
                report.probes.agent_mail.db_open_error_kind = Some("database-error".to_owned());
            }
            DegradedDecisionCase::BeadsUnavailable => {
                report.probes.beads.write_smoke_status = blocked_probe(
                    ReadinessSubsystem::Beads,
                    "br write-smoke",
                    "beads-write-unavailable",
                );
            }
            DegradedDecisionCase::LocalRefStale => {
                report.probes.git.local_tracking_ref_error_kind =
                    Some("tracking-ref-stale".to_owned());
                report.probes.worktree.local_ref_staleness_risk = true;
            }
            DegradedDecisionCase::DirtySharedTree => {
                report.probes.worktree.status_result = ProbeResult {
                    status: ReadinessStatus::Warn,
                    reason_code: Some("unrelated-dirty-tree".to_owned()),
                    remediation: Some("restrict edits and commits to owned paths".to_owned()),
                    ..ok_probe(ReadinessSubsystem::Worktree, "git status --short")
                };
                report.probes.worktree.dirty_count = 2;
                report.probes.worktree.unrelated_dirty_present = true;
            }
            DegradedDecisionCase::RchUnavailable => {
                report.probes.rch.check_result = blocked_probe(
                    ReadinessSubsystem::Rch,
                    "rch status --json",
                    "rch-workers-unavailable",
                );
                report.probes.rch.workers_healthy = 0;
                report.probes.rch.cargo_offload_allowed = false;
                report.probes.rch.admission_decision = RchAdmissionDecision::RchInfraFailure;
                report.probes.rch.admission_reason_code =
                    Some(RchAdmissionReasonCode::WorkersUnavailable);
            }
            DegradedDecisionCase::DiskPressure => {
                report.probes.disk.check_result =
                    blocked_probe(ReadinessSubsystem::Disk, "df -h", "disk-pressure");
                report.probes.disk.external_scratch_available = false;
                report.probes.disk.checked_mounts[0].threshold_status = ReadinessStatus::Blocked;
            }
            DegradedDecisionCase::BranchMirrorMismatch => {
                report.probes.git.branch_mirror_match = Some(false);
                report.probes.git.push_status = blocked_probe(
                    ReadinessSubsystem::Git,
                    "git push --dry-run",
                    "branch-mirror-mismatch",
                );
            }
            DegradedDecisionCase::RemoteRefUnavailable => {
                report.probes.git.ls_remote_main = blocked_probe(
                    ReadinessSubsystem::Git,
                    "git ls-remote main",
                    "remote-ref-truth-unavailable",
                );
            }
            DegradedDecisionCase::LocalCargoAllowed => {
                report.probes.rch.local_cargo_allowed = true;
            }
            DegradedDecisionCase::AgentMailRepairAttempted => {
                report.probes.agent_mail.repair_actions_attempted = true;
            }
        }
    }

    fn assert_refused_actions(
        decision: &ReadinessDecision,
        expected: &[ReadinessAction],
        name: &str,
    ) {
        let expected = expected.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(decision.refused_actions, expected, "{name}");
        for action in all_readiness_actions() {
            assert_eq!(
                decision.allowed_actions.contains(&action),
                !expected.contains(&action),
                "{name}: {action:?}"
            );
        }
    }

    fn assert_blocker_beads(decision: &ReadinessDecision, expected: &[&str], name: &str) {
        let expected = expected
            .iter()
            .map(|bead_id| (*bead_id).to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(decision.blocker_bead_ids, expected, "{name}");
    }

    #[test]
    fn agent_mail_repair_attempt_is_rejected() {
        let mut report = healthy_report();
        report.probes.agent_mail.repair_actions_attempted = true;

        let err = report
            .validate()
            .expect_err("repair attempts are forbidden");
        assert!(matches!(
            err,
            AgentReadinessError::ForbiddenActionAttempted {
                action: ForbiddenAgentAction::AgentMailRepairOrRestart,
            }
        ));
    }

    #[test]
    fn default_policy_lists_explicit_operator_approval_gates() {
        let policy = AgentReadinessPolicyMapping::default();

        for action in [
            ForbiddenAgentAction::AgentMailRepairOrRestart,
            ForbiddenAgentAction::FileDeletion,
            ForbiddenAgentAction::DiskCleanup,
            ForbiddenAgentAction::WorkerFleetRepair,
            ForbiddenAgentAction::DestructiveGitCleanup,
        ] {
            assert!(policy.forbidden_actions.contains(&action), "{action:?}");
        }
        assert!(
            policy
                .refusal_rules
                .contains_key("disk-cleanup-needs-approval")
        );
        assert!(
            policy
                .refusal_rules
                .contains_key("worker-fleet-repair-needs-approval")
        );
        policy.validate().expect("default policy validates");
    }

    #[test]
    fn redaction_contract_rejects_raw_secrets_and_exported_user_paths() {
        let mut report = healthy_report();
        report.command_line.push("token=super-secret".to_owned());
        let err = report.validate().expect_err("raw token is rejected");
        assert!(matches!(err, AgentReadinessError::UnsafeText { .. }));

        let mut report = healthy_report();
        report.repo_path = RedactedPath {
            value: "/Users/jemanuel/projects/flywheel_connectors".to_owned(),
            scope: PathRedactionScope::ExportSafe,
        };
        let err = report
            .validate()
            .expect_err("exported user path is rejected");
        assert!(matches!(
            err,
            AgentReadinessError::UnsafeText {
                field: "redacted_path.value",
                reason: "export-safe paths must not include local user directories",
            }
        ));
    }
}
