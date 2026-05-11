//! Non-destructive startup probe plans for agent readiness evidence.
//!
//! This module does not execute shell commands or call shared services. It
//! defines the redaction-safe probe plan and deterministic no-network fixtures
//! that production command wiring can satisfy before constructing an
//! [`AgentReadinessReport`](crate::AgentReadinessReport).

#![allow(clippy::module_name_repetitions, clippy::struct_excessive_bools)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::agent_readiness::{
    AGENT_READINESS_REPORT_SCHEMA, AgentMailReadiness, AgentReadinessError,
    AgentReadinessPolicyMapping, AgentReadinessProbes, AgentReadinessReport, BeadsReadiness,
    DiskMountState, DiskReadiness, GitReadiness, LockState, PathKind, PathRedactionScope,
    ProbeResult, RchReadiness, ReadinessAction, ReadinessDecision, ReadinessRedactionContract,
    ReadinessStatus, ReadinessSubsystem, RedactedPath, TelemetryState, WorktreeReadiness,
    validate_key_fragment, validate_safe_text,
};

/// Stable schema for the startup probe plan.
pub const AGENT_READINESS_PROBE_PLAN_SCHEMA: &str = "fcp.agent-readiness-probe-plan.v1";

const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const AGENT_MAIL_MAX_ATTEMPTS: u8 = 2;
const FAKE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

const REQUIRED_PROBE_LABELS: [&str; 15] = [
    "agent-mail.health",
    "agent-mail.register",
    "agent-mail.list-agents",
    "agent-mail.inbox",
    "beads.import",
    "beads.write-smoke",
    "beads.flush",
    "git.ls-remote-main",
    "git.ls-remote-master",
    "git.index-write-smoke",
    "git.push-readiness",
    "rch.status",
    "disk.capacity",
    "worktree.status",
    "decision.summary",
];

const FORBIDDEN_COMMAND_FRAGMENTS: [&str; 11] = [
    "am service restart",
    "am service stop",
    "am doctor fix",
    "am doctor repair",
    "am doctor reconstruct",
    "mcp-agent-mail kill",
    "git reset --hard",
    "git clean -fd",
    "rm -rf",
    "cargo check",
    "cargo test",
];

/// Execution mode for a readiness probe plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeExecutionMode {
    /// Fixture mode: all observations are injected; no network or local command
    /// execution is allowed.
    NoNetworkFixture,
    /// Production mode for redacted observations gathered elsewhere.
    InjectedObservations,
    /// Live read-only mode. Commands may read remote/shared state but must not
    /// mutate it.
    LiveReadOnly,
}

/// Where a command is allowed to read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeNetworkPolicy {
    /// No network or service access.
    None,
    /// Observation must be injected by the caller.
    InjectedOnly,
    /// Local loopback or MCP API read access only.
    LoopbackReadOnly,
    /// Remote read-only access, such as `git ls-remote`.
    RemoteReadOnly,
}

/// Mutation scope for a probe command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeMutationScope {
    /// Command is read-only.
    None,
    /// Command may write only to disposable scratch state.
    DisposableScratch,
    /// Command may inspect shared state but must not mutate it.
    SharedReadOnly,
    /// Command may inspect remote state but must not mutate it.
    RemoteReadOnly,
}

impl ProbeMutationScope {
    /// Returns whether this command is permitted to mutate shared state.
    #[must_use]
    pub const fn allows_shared_service_mutation(self) -> bool {
        false
    }
}

/// Retry policy for one probe command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRetryPolicy {
    /// Total attempts including the first attempt.
    pub max_attempts: u8,
    /// Delay between attempts.
    pub delay_ms: u64,
}

impl ProbeRetryPolicy {
    const fn once() -> Self {
        Self {
            max_attempts: 1,
            delay_ms: 0,
        }
    }

    const fn retry_once(delay_ms: u64) -> Self {
        Self {
            max_attempts: 2,
            delay_ms,
        }
    }
}

/// One planned readiness probe command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeCommandPlan {
    /// Stable label used to join command observations to schema fields.
    pub label: String,
    /// Subsystem that consumes the result.
    pub subsystem: ReadinessSubsystem,
    /// Redaction-safe argv or API label.
    pub command_redacted: Vec<String>,
    /// Network/service access policy.
    pub network_policy: ProbeNetworkPolicy,
    /// Mutation boundary.
    pub mutation_scope: ProbeMutationScope,
    /// Retry policy.
    pub retry_policy: ProbeRetryPolicy,
    /// Per-attempt timeout.
    pub timeout_ms: u64,
}

impl ProbeCommandPlan {
    fn new(
        label: &str,
        subsystem: ReadinessSubsystem,
        command_redacted: &[&str],
        network_policy: ProbeNetworkPolicy,
        mutation_scope: ProbeMutationScope,
        retry_policy: ProbeRetryPolicy,
    ) -> Self {
        Self {
            label: label.to_owned(),
            subsystem,
            command_redacted: command_redacted
                .iter()
                .map(|part| (*part).to_owned())
                .collect(),
            network_policy,
            mutation_scope,
            retry_policy,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }

    fn validate(&self, mode: ProbeExecutionMode) -> Result<(), AgentReadinessError> {
        validate_key_fragment("probe_plan.label", &self.label)?;
        if self.command_redacted.is_empty() {
            return Err(AgentReadinessError::EmptyProbeCommand {
                subsystem: self.subsystem,
            });
        }
        for part in &self.command_redacted {
            validate_safe_text("probe_plan.command_redacted", part)?;
        }
        let joined = self.command_redacted.join(" ").to_ascii_lowercase();
        for forbidden in FORBIDDEN_COMMAND_FRAGMENTS {
            if joined.contains(forbidden) {
                return Err(AgentReadinessError::ForbiddenActionAttempted {
                    action: forbidden_action_for_fragment(forbidden),
                });
            }
        }
        if self.label.starts_with("agent-mail.")
            && self.retry_policy.max_attempts > AGENT_MAIL_MAX_ATTEMPTS
        {
            return Err(AgentReadinessError::PolicyContradiction {
                field: "probe_plan.agent_mail.retry_policy",
                reason: "Agent Mail probes may retry once and must not enter repair loops",
            });
        }
        if self.retry_policy.max_attempts == 0 {
            return Err(AgentReadinessError::PolicyContradiction {
                field: "probe_plan.retry_policy.max_attempts",
                reason: "probe commands must have at least one attempt",
            });
        }
        if mode == ProbeExecutionMode::NoNetworkFixture
            && !matches!(
                self.network_policy,
                ProbeNetworkPolicy::None | ProbeNetworkPolicy::InjectedOnly
            )
        {
            return Err(AgentReadinessError::PolicyContradiction {
                field: "probe_plan.network_policy",
                reason: "no-network fixture plans must use injected or no-network probes",
            });
        }
        Ok(())
    }
}

/// Non-destructive startup probe plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStartupProbePlan {
    /// Plan schema.
    pub schema: String,
    /// Execution mode.
    pub execution_mode: ProbeExecutionMode,
    /// Planned commands.
    pub commands: Vec<ProbeCommandPlan>,
    /// Whether Beads writes are limited to disposable state.
    pub beads_disposable_write_only: bool,
    /// Whether Git writes are limited to a disposable index/object area.
    pub git_disposable_write_only: bool,
    /// Redaction contract expected for produced reports.
    pub redaction: ReadinessRedactionContract,
}

impl AgentStartupProbePlan {
    /// Build the deterministic no-network fixture plan.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReadinessError`] if the built-in plan violates the
    /// non-destructive contract.
    pub fn no_network_fixture() -> Result<Self, AgentReadinessError> {
        let plan = Self::with_mode(ProbeExecutionMode::NoNetworkFixture);
        plan.validate()?;
        Ok(plan)
    }

    /// Build a live read-only plan for callers that execute probes elsewhere.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReadinessError`] if the built-in plan violates the
    /// non-destructive contract.
    pub fn live_read_only() -> Result<Self, AgentReadinessError> {
        let plan = Self::with_mode(ProbeExecutionMode::LiveReadOnly);
        plan.validate()?;
        Ok(plan)
    }

    /// Validate the plan's safety and coverage.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReadinessError`] when required probes are missing or a
    /// command would violate the no-repair/no-cleanup contract.
    pub fn validate(&self) -> Result<(), AgentReadinessError> {
        if self.schema != AGENT_READINESS_PROBE_PLAN_SCHEMA {
            return Err(AgentReadinessError::InvalidSchema {
                expected: AGENT_READINESS_PROBE_PLAN_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        let mut labels = BTreeSet::new();
        for command in &self.commands {
            command.validate(self.execution_mode)?;
            if !labels.insert(command.label.clone()) {
                return Err(AgentReadinessError::PolicyContradiction {
                    field: "probe_plan.commands",
                    reason: "duplicate probe labels are not allowed",
                });
            }
            if command.mutation_scope.allows_shared_service_mutation() {
                return Err(AgentReadinessError::PolicyContradiction {
                    field: "probe_plan.mutation_scope",
                    reason: "readiness probes must not mutate shared services",
                });
            }
        }
        for required in REQUIRED_PROBE_LABELS {
            if !labels.contains(required) {
                return Err(AgentReadinessError::PolicyContradiction {
                    field: "probe_plan.required_labels",
                    reason: "required readiness probe is missing",
                });
            }
        }
        if !self.beads_disposable_write_only || !self.git_disposable_write_only {
            return Err(AgentReadinessError::PolicyContradiction {
                field: "probe_plan.disposable_writes",
                reason: "write probes must be limited to disposable scratch state",
            });
        }
        self.redaction.validate()
    }

    /// Return a command by stable label.
    #[must_use]
    pub fn command(&self, label: &str) -> Option<&ProbeCommandPlan> {
        self.commands.iter().find(|command| command.label == label)
    }

    fn with_mode(execution_mode: ProbeExecutionMode) -> Self {
        let mut commands = Vec::with_capacity(REQUIRED_PROBE_LABELS.len());
        commands.extend(agent_mail_probe_commands(execution_mode));
        commands.extend(beads_probe_commands());
        commands.extend(git_probe_commands(execution_mode));
        commands.extend(local_probe_commands());
        Self {
            schema: AGENT_READINESS_PROBE_PLAN_SCHEMA.to_owned(),
            execution_mode,
            commands,
            beads_disposable_write_only: true,
            git_disposable_write_only: true,
            redaction: ReadinessRedactionContract::default(),
        }
    }
}

const fn network_policy(
    execution_mode: ProbeExecutionMode,
    live_policy: ProbeNetworkPolicy,
) -> ProbeNetworkPolicy {
    match execution_mode {
        ProbeExecutionMode::NoNetworkFixture | ProbeExecutionMode::InjectedObservations => {
            ProbeNetworkPolicy::InjectedOnly
        }
        ProbeExecutionMode::LiveReadOnly => live_policy,
    }
}

fn agent_mail_probe_commands(execution_mode: ProbeExecutionMode) -> Vec<ProbeCommandPlan> {
    let policy = network_policy(execution_mode, ProbeNetworkPolicy::LoopbackReadOnly);
    vec![
        ProbeCommandPlan::new(
            "agent-mail.health",
            ReadinessSubsystem::AgentMail,
            &["agent-mail", "health-check"],
            policy,
            ProbeMutationScope::SharedReadOnly,
            ProbeRetryPolicy::retry_once(2_000),
        ),
        ProbeCommandPlan::new(
            "agent-mail.register",
            ReadinessSubsystem::AgentMail,
            &["agent-mail", "register"],
            policy,
            ProbeMutationScope::SharedReadOnly,
            ProbeRetryPolicy::retry_once(2_000),
        ),
        ProbeCommandPlan::new(
            "agent-mail.list-agents",
            ReadinessSubsystem::AgentMail,
            &["agent-mail", "list-agents"],
            policy,
            ProbeMutationScope::SharedReadOnly,
            ProbeRetryPolicy::retry_once(2_000),
        ),
        ProbeCommandPlan::new(
            "agent-mail.inbox",
            ReadinessSubsystem::AgentMail,
            &["agent-mail", "fetch-inbox"],
            policy,
            ProbeMutationScope::SharedReadOnly,
            ProbeRetryPolicy::retry_once(2_000),
        ),
    ]
}

fn beads_probe_commands() -> Vec<ProbeCommandPlan> {
    vec![
        ProbeCommandPlan::new(
            "beads.import",
            ReadinessSubsystem::Beads,
            &["br", "sync", "--import-only", "--scratch"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::DisposableScratch,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "beads.write-smoke",
            ReadinessSubsystem::Beads,
            &["br", "write-smoke", "--scratch"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::DisposableScratch,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "beads.flush",
            ReadinessSubsystem::Beads,
            &["br", "sync", "--flush-only", "--scratch"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::DisposableScratch,
            ProbeRetryPolicy::once(),
        ),
    ]
}

fn git_probe_commands(execution_mode: ProbeExecutionMode) -> Vec<ProbeCommandPlan> {
    let remote_policy = network_policy(execution_mode, ProbeNetworkPolicy::RemoteReadOnly);
    vec![
        ProbeCommandPlan::new(
            "git.ls-remote-main",
            ReadinessSubsystem::Git,
            &["git", "ls-remote", "origin", "refs/heads/main"],
            remote_policy,
            ProbeMutationScope::RemoteReadOnly,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "git.ls-remote-master",
            ReadinessSubsystem::Git,
            &["git", "ls-remote", "origin", "refs/heads/master"],
            remote_policy,
            ProbeMutationScope::RemoteReadOnly,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "git.index-write-smoke",
            ReadinessSubsystem::Git,
            &["git", "read-tree", "--index-output", "scratch-index"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::DisposableScratch,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "git.push-readiness",
            ReadinessSubsystem::Git,
            &["git", "push", "--dry-run", "origin", "HEAD:refs/heads/main"],
            remote_policy,
            ProbeMutationScope::RemoteReadOnly,
            ProbeRetryPolicy::once(),
        ),
    ]
}

fn local_probe_commands() -> Vec<ProbeCommandPlan> {
    vec![
        ProbeCommandPlan::new(
            "rch.status",
            ReadinessSubsystem::Rch,
            &["rch", "status", "--json"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::None,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "disk.capacity",
            ReadinessSubsystem::Disk,
            &["df", "capacity", "redacted-mount"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::None,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "worktree.status",
            ReadinessSubsystem::Worktree,
            &["git", "status", "--short", "--branch"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::None,
            ProbeRetryPolicy::once(),
        ),
        ProbeCommandPlan::new(
            "decision.summary",
            ReadinessSubsystem::Decision,
            &["agent-readiness", "decision"],
            ProbeNetworkPolicy::None,
            ProbeMutationScope::None,
            ProbeRetryPolicy::once(),
        ),
    ]
}

/// Deterministic fake-readiness scenarios for no-network tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoNetworkProbeScenario {
    /// Every probe is healthy.
    Healthy,
    /// Agent Mail health may answer, but registration/list/inbox are blocked.
    AgentMailUnavailable,
    /// rch has no healthy workers, so Cargo proof must be refused.
    RchUnavailable,
    /// Remote `main` and `master` do not match, so push must be refused.
    BranchMirrorMismatch,
    /// Worktree contains unrelated dirty files.
    DirtySharedTree,
}

/// Inputs for deterministic no-network readiness fixture reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoNetworkProbeFixture {
    /// Readiness run id.
    pub run_id: String,
    /// Agent identity.
    pub agent_name: String,
    /// Fixture observation timestamp.
    pub observed_at_unix_ms: u64,
    /// Scenario to synthesize.
    pub scenario: NoNetworkProbeScenario,
    /// Owned globs used by the worktree summary.
    pub owned_path_globs: BTreeSet<String>,
}

impl NoNetworkProbeFixture {
    /// Build a redaction-safe report from injected fixture observations.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReadinessError`] if the fixture or generated report
    /// violates the readiness schema contract.
    pub fn build_report(&self) -> Result<AgentReadinessReport, AgentReadinessError> {
        let plan = AgentStartupProbePlan::no_network_fixture()?;
        let scenario = FixtureScenarioState::from(self.scenario);
        let decision = fixture_decision(scenario);

        let report = AgentReadinessReport {
            schema: AGENT_READINESS_REPORT_SCHEMA.to_owned(),
            run_id: self.run_id.clone(),
            repo_path: RedactedPath {
                value: "repo:flywheel-connectors".to_owned(),
                scope: PathRedactionScope::ExportSafe,
            },
            agent_name: self.agent_name.clone(),
            started_at_unix_ms: self.observed_at_unix_ms,
            finished_at_unix_ms: self.observed_at_unix_ms + 100,
            policy_source: "AGENTS.md".to_owned(),
            command_line: vec![
                "agent-readiness-probe".to_owned(),
                "no-network-fixture".to_owned(),
            ],
            git_revision_observed: Some(FAKE_SHA.to_owned()),
            remote_main_sha: Some(FAKE_SHA.to_owned()),
            remote_master_sha: Some(remote_master_sha(scenario).to_owned()),
            probes: AgentReadinessProbes {
                agent_mail: fixture_agent_mail(&plan, scenario, self.observed_at_unix_ms)?,
                beads: fixture_beads(&plan, &decision.blocker_bead_ids, self.observed_at_unix_ms)?,
                git: fixture_git(&plan, scenario, self.observed_at_unix_ms)?,
                rch: fixture_rch(&plan, scenario, self.observed_at_unix_ms)?,
                disk: fixture_disk(&plan, self.observed_at_unix_ms)?,
                worktree: fixture_worktree(
                    &plan,
                    scenario,
                    &self.owned_path_globs,
                    self.observed_at_unix_ms,
                )?,
            },
            decision: decision.into_readiness_decision(scenario),
            redaction: plan.redaction,
            policy: AgentReadinessPolicyMapping::default(),
        };
        report.validate()?;
        Ok(report)
    }
}

#[derive(Debug, Clone, Copy)]
struct FixtureScenarioState {
    agent_mail_blocked: bool,
    rch_blocked: bool,
    mirror_blocked: bool,
    dirty_tree: bool,
}

impl From<NoNetworkProbeScenario> for FixtureScenarioState {
    fn from(scenario: NoNetworkProbeScenario) -> Self {
        Self {
            agent_mail_blocked: scenario == NoNetworkProbeScenario::AgentMailUnavailable,
            rch_blocked: scenario == NoNetworkProbeScenario::RchUnavailable,
            mirror_blocked: scenario == NoNetworkProbeScenario::BranchMirrorMismatch,
            dirty_tree: scenario == NoNetworkProbeScenario::DirtySharedTree,
        }
    }
}

#[derive(Debug, Clone)]
struct FixtureDecisionParts {
    status: ReadinessStatus,
    reason_code: Option<&'static str>,
    remediation: Option<&'static str>,
    allowed_actions: BTreeSet<ReadinessAction>,
    refused_actions: BTreeSet<ReadinessAction>,
    blocker_bead_ids: BTreeSet<String>,
}

impl FixtureDecisionParts {
    fn into_readiness_decision(self, scenario: FixtureScenarioState) -> ReadinessDecision {
        ReadinessDecision {
            status: self.status,
            primary_reason_code: self.reason_code.map(str::to_owned),
            primary_remediation: self.remediation.map(str::to_owned),
            can_coordinate: !scenario.agent_mail_blocked,
            can_claim: true,
            can_edit: true,
            can_run_cargo_proof: !scenario.rch_blocked,
            can_push: !scenario.mirror_blocked,
            allowed_actions: self.allowed_actions,
            refused_actions: self.refused_actions,
            blocker_bead_ids: self.blocker_bead_ids,
        }
    }
}

fn fixture_decision(scenario: FixtureScenarioState) -> FixtureDecisionParts {
    let mut decision = FixtureDecisionParts {
        status: ReadinessStatus::Ok,
        reason_code: None,
        remediation: None,
        allowed_actions: BTreeSet::from([
            ReadinessAction::Coordinate,
            ReadinessAction::ClaimBead,
            ReadinessAction::EditFiles,
            ReadinessAction::CargoProof,
            ReadinessAction::Push,
        ]),
        refused_actions: BTreeSet::new(),
        blocker_bead_ids: BTreeSet::new(),
    };
    apply_scenario_decision(scenario, &mut decision);
    decision
}

fn apply_scenario_decision(scenario: FixtureScenarioState, decision: &mut FixtureDecisionParts) {
    if scenario.rch_blocked {
        decision
            .allowed_actions
            .remove(&ReadinessAction::CargoProof);
        decision.refused_actions.insert(ReadinessAction::CargoProof);
        decision
            .blocker_bead_ids
            .insert("flywheel_connectors-rfbrc".to_owned());
        decision.status = ReadinessStatus::Blocked;
        decision.reason_code = Some("rch-workers-unavailable");
        decision.remediation = Some("defer Cargo proof until rch has healthy workers");
    } else if scenario.mirror_blocked {
        decision.allowed_actions.remove(&ReadinessAction::Push);
        decision.refused_actions.insert(ReadinessAction::Push);
        decision.status = ReadinessStatus::Blocked;
        decision.reason_code = Some("branch-mirror-mismatch");
        decision.remediation = Some("refuse push until remote branch mirror is restored");
    } else if scenario.agent_mail_blocked {
        decision
            .allowed_actions
            .remove(&ReadinessAction::Coordinate);
        decision.refused_actions.insert(ReadinessAction::Coordinate);
        decision
            .blocker_bead_ids
            .insert("flywheel_connectors-d5yeb".to_owned());
        decision.status = ReadinessStatus::Warn;
        decision.reason_code = Some("agent-mail-db-error");
        decision.remediation = Some("use Beads fallback; do not repair Agent Mail");
    } else if scenario.dirty_tree {
        decision.status = ReadinessStatus::Warn;
        decision.reason_code = Some("unrelated-dirty-tree");
        decision.remediation = Some("restrict edits and commits to owned paths");
    }
}

const fn remote_master_sha(scenario: FixtureScenarioState) -> &'static str {
    if scenario.mirror_blocked {
        "fedcba9876543210fedcba9876543210fedcba98"
    } else {
        FAKE_SHA
    }
}

const fn fixture_status(blocked: bool, blocked_status: ReadinessStatus) -> ReadinessStatus {
    if blocked {
        blocked_status
    } else {
        ReadinessStatus::Ok
    }
}

fn fixture_agent_mail(
    plan: &AgentStartupProbePlan,
    scenario: FixtureScenarioState,
    observed_at_unix_ms: u64,
) -> Result<AgentMailReadiness, AgentReadinessError> {
    let blocked = scenario.agent_mail_blocked;
    Ok(AgentMailReadiness {
        mcp_health: fixture_probe_by_label(
            plan,
            "agent-mail.health",
            ReadinessStatus::Ok,
            None,
            None,
            observed_at_unix_ms,
        )?,
        register_result: fixture_probe_by_label(
            plan,
            "agent-mail.register",
            fixture_status(blocked, ReadinessStatus::Blocked),
            blocked.then_some("agent-mail-db-error"),
            blocked.then_some("proceed without Agent Mail repair"),
            observed_at_unix_ms,
        )?,
        list_agents_result: fixture_probe_by_label(
            plan,
            "agent-mail.list-agents",
            fixture_status(blocked, ReadinessStatus::Blocked),
            blocked.then_some("agent-mail-db-error"),
            blocked.then_some("skip Agent Mail coordination"),
            observed_at_unix_ms,
        )?,
        inbox_result: fixture_probe_by_label(
            plan,
            "agent-mail.inbox",
            fixture_status(blocked, ReadinessStatus::Blocked),
            blocked.then_some("agent-mail-db-error"),
            blocked.then_some("use Beads comments for audit trail"),
            observed_at_unix_ms,
        )?,
        direct_cli_status_result: None,
        direct_cli_list_result: None,
        mailbox_lock_state: if blocked {
            LockState::Busy
        } else {
            LockState::Clear
        },
        db_open_error_kind: blocked.then_some("database-error".to_owned()),
        repair_actions_attempted: false,
    })
}

fn fixture_beads(
    plan: &AgentStartupProbePlan,
    blocked_infra_bead_ids: &BTreeSet<String>,
    observed_at_unix_ms: u64,
) -> Result<BeadsReadiness, AgentReadinessError> {
    Ok(BeadsReadiness {
        db_path_kind: PathKind::ExternalScratch,
        jsonl_path_kind: PathKind::ExternalScratch,
        import_status: fixture_probe_by_label(
            plan,
            "beads.import",
            ReadinessStatus::Ok,
            None,
            None,
            observed_at_unix_ms,
        )?,
        write_smoke_status: fixture_probe_by_label(
            plan,
            "beads.write-smoke",
            ReadinessStatus::Ok,
            None,
            None,
            observed_at_unix_ms,
        )?,
        flush_status: fixture_probe_by_label(
            plan,
            "beads.flush",
            ReadinessStatus::Ok,
            None,
            None,
            observed_at_unix_ms,
        )?,
        lock_timeout_ms: 60_000,
        current_issue_count: 3_545,
        blocked_infra_bead_ids: blocked_infra_bead_ids.clone(),
    })
}

fn fixture_git(
    plan: &AgentStartupProbePlan,
    scenario: FixtureScenarioState,
    observed_at_unix_ms: u64,
) -> Result<GitReadiness, AgentReadinessError> {
    let blocked = scenario.mirror_blocked;
    Ok(GitReadiness {
        ls_remote_main: fixture_probe_by_label(
            plan,
            "git.ls-remote-main",
            ReadinessStatus::Ok,
            None,
            None,
            observed_at_unix_ms,
        )?,
        ls_remote_master: fixture_probe_by_label(
            plan,
            "git.ls-remote-master",
            ReadinessStatus::Ok,
            None,
            None,
            observed_at_unix_ms,
        )?,
        branch_mirror_match: Some(!blocked),
        local_ref_write_status: fixture_probe_by_label(
            plan,
            "git.index-write-smoke",
            ReadinessStatus::Ok,
            None,
            None,
            observed_at_unix_ms,
        )?,
        object_directory_kind: PathKind::ExternalScratch,
        alternate_object_directory: None,
        push_status: fixture_probe_by_label(
            plan,
            "git.push-readiness",
            fixture_status(blocked, ReadinessStatus::Blocked),
            blocked.then_some("branch-mirror-mismatch"),
            blocked.then_some("push only after main and mirror match"),
            observed_at_unix_ms,
        )?,
        local_tracking_ref_error_kind: None,
    })
}

fn fixture_rch(
    plan: &AgentStartupProbePlan,
    scenario: FixtureScenarioState,
    observed_at_unix_ms: u64,
) -> Result<RchReadiness, AgentReadinessError> {
    let blocked = scenario.rch_blocked;
    Ok(RchReadiness {
        check_result: fixture_probe_by_label(
            plan,
            "rch.status",
            fixture_status(blocked, ReadinessStatus::Blocked),
            blocked.then_some("rch-workers-unavailable"),
            blocked.then_some("do not run local Cargo fallback"),
            observed_at_unix_ms,
        )?,
        daemon_running: !blocked,
        hook_installed: true,
        workers_total: 8,
        workers_healthy: if blocked { 0 } else { 8 },
        unreachable_workers: if blocked {
            BTreeSet::from(["worker-unavailable".to_owned()])
        } else {
            BTreeSet::new()
        },
        pressure_telemetry_state: if blocked {
            TelemetryState::Unavailable
        } else {
            TelemetryState::Current
        },
        cargo_offload_allowed: !blocked,
        local_cargo_allowed: false,
    })
}

fn fixture_disk(
    plan: &AgentStartupProbePlan,
    observed_at_unix_ms: u64,
) -> Result<DiskReadiness, AgentReadinessError> {
    Ok(DiskReadiness {
        check_result: fixture_probe_by_label(
            plan,
            "disk.capacity",
            ReadinessStatus::Ok,
            None,
            None,
            observed_at_unix_ms,
        )?,
        checked_mounts: vec![DiskMountState {
            mount_label: "system-data".to_owned(),
            free_bytes: 170_000_000_000,
            capacity_percent: 88,
            inode_state: Some("ok".to_owned()),
            threshold_status: ReadinessStatus::Ok,
        }],
        external_scratch_available: true,
    })
}

fn fixture_worktree(
    plan: &AgentStartupProbePlan,
    scenario: FixtureScenarioState,
    owned_path_globs: &BTreeSet<String>,
    observed_at_unix_ms: u64,
) -> Result<WorktreeReadiness, AgentReadinessError> {
    let dirty = scenario.dirty_tree;
    Ok(WorktreeReadiness {
        status_result: fixture_probe_by_label(
            plan,
            "worktree.status",
            fixture_status(dirty, ReadinessStatus::Warn),
            dirty.then_some("unrelated-dirty-tree"),
            dirty.then_some("commit only owned paths"),
            observed_at_unix_ms,
        )?,
        dirty_count: if dirty { 3 } else { 0 },
        dirty_paths_hashed: dirty_paths_hashed(dirty),
        owned_path_globs: owned_path_globs.clone(),
        unrelated_dirty_present: dirty,
        local_ref_staleness_risk: dirty,
    })
}

fn dirty_paths_hashed(dirty: bool) -> BTreeSet<String> {
    if dirty {
        BTreeSet::from([
            digest_for("dirty:path:one"),
            digest_for("dirty:path:two"),
            digest_for("dirty:path:three"),
        ])
    } else {
        BTreeSet::new()
    }
}

impl Default for NoNetworkProbeFixture {
    fn default() -> Self {
        Self {
            run_id: "probe-fixture-1".to_owned(),
            agent_name: "GreenLake".to_owned(),
            observed_at_unix_ms: 1_800_000_000_000,
            scenario: NoNetworkProbeScenario::Healthy,
            owned_path_globs: BTreeSet::from(["crates/fcp-evidence/src/*".to_owned()]),
        }
    }
}

fn fixture_probe(
    command: &ProbeCommandPlan,
    status: ReadinessStatus,
    reason_code: Option<&str>,
    remediation: Option<&str>,
    observed_at_unix_ms: u64,
) -> ProbeResult {
    ProbeResult {
        subsystem: command.subsystem,
        status,
        command_redacted: command.command_redacted.clone(),
        exit_code: Some(i32::from(matches!(
            status,
            ReadinessStatus::Blocked | ReadinessStatus::Error
        ))),
        duration_ms: 0,
        observed_at_unix_ms,
        reason_code: reason_code.map(str::to_owned),
        remediation: remediation.map(str::to_owned),
        evidence_digest: Some(digest_for(&format!("{}:{status:?}", command.label))),
        redaction_applied: true,
    }
}

fn fixture_probe_by_label(
    plan: &AgentStartupProbePlan,
    label: &'static str,
    status: ReadinessStatus,
    reason_code: Option<&str>,
    remediation: Option<&str>,
    observed_at_unix_ms: u64,
) -> Result<ProbeResult, AgentReadinessError> {
    let command = plan
        .command(label)
        .ok_or(AgentReadinessError::PolicyContradiction {
            field: "probe_plan.fixture_label",
            reason: "fixture label is missing from built-in probe plan",
        })?;
    Ok(fixture_probe(
        command,
        status,
        reason_code,
        remediation,
        observed_at_unix_ms,
    ))
}

fn digest_for(input: &str) -> String {
    format!(
        "blake3:{}",
        hex::encode(blake3::hash(input.as_bytes()).as_bytes())
    )
}

fn forbidden_action_for_fragment(fragment: &str) -> crate::ForbiddenAgentAction {
    if fragment.starts_with("am ") || fragment.contains("mcp-agent-mail") {
        crate::ForbiddenAgentAction::AgentMailRepairOrRestart
    } else if fragment.starts_with("git ") {
        crate::ForbiddenAgentAction::DestructiveGitCleanup
    } else if fragment.starts_with("cargo ") {
        crate::ForbiddenAgentAction::LocalCargoWhenRchRequired
    } else {
        crate::ForbiddenAgentAction::FileDeletion
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_network_plan_contains_only_injected_or_local_probes() {
        let plan = AgentStartupProbePlan::no_network_fixture().expect("fixture plan validates");

        assert_eq!(plan.execution_mode, ProbeExecutionMode::NoNetworkFixture);
        for command in &plan.commands {
            assert!(!command.mutation_scope.allows_shared_service_mutation());
            assert!(matches!(
                command.network_policy,
                ProbeNetworkPolicy::None | ProbeNetworkPolicy::InjectedOnly
            ));
        }
        for required in REQUIRED_PROBE_LABELS {
            assert!(plan.command(required).is_some(), "missing {required}");
        }
    }

    #[test]
    fn plan_rejects_agent_mail_repair_commands() {
        let mut plan = AgentStartupProbePlan::no_network_fixture().expect("fixture plan validates");
        let command = plan
            .commands
            .iter_mut()
            .find(|command| command.label == "agent-mail.health")
            .expect("agent-mail command exists");
        command.command_redacted = vec!["am".to_owned(), "doctor".to_owned(), "repair".to_owned()];

        let err = plan.validate().expect_err("repair command is rejected");
        assert!(matches!(
            err,
            AgentReadinessError::ForbiddenActionAttempted {
                action: crate::ForbiddenAgentAction::AgentMailRepairOrRestart,
            }
        ));
    }

    #[test]
    fn healthy_fixture_emits_deterministic_redaction_safe_jsonl() {
        let fixture = NoNetworkProbeFixture::default();
        let first = fixture
            .build_report()
            .expect("healthy fixture report")
            .to_jsonl_lines()
            .expect("jsonl lines");
        let second = fixture
            .build_report()
            .expect("healthy fixture report")
            .to_jsonl_lines()
            .expect("jsonl lines");

        assert_eq!(first, second);
        assert_eq!(first.len(), 15);
        let joined = first.join("\n");
        assert!(!joined.contains("://"));
        assert!(!joined.contains("/Users/"));
        assert!(!joined.contains("token="));
        assert!(joined.contains("fcp.agent-readiness-event.v1"));
    }

    #[test]
    fn agent_mail_unavailable_fixture_refuses_coordination_without_repair() {
        let fixture = NoNetworkProbeFixture {
            scenario: NoNetworkProbeScenario::AgentMailUnavailable,
            ..NoNetworkProbeFixture::default()
        };
        let report = fixture.build_report().expect("fixture report validates");

        assert_eq!(report.decision.status, ReadinessStatus::Warn);
        assert!(!report.decision.can_coordinate);
        assert!(
            report
                .decision
                .refused_actions
                .contains(&ReadinessAction::Coordinate)
        );
        assert!(!report.probes.agent_mail.repair_actions_attempted);
    }

    #[test]
    fn rch_unavailable_fixture_refuses_cargo_proof() {
        let fixture = NoNetworkProbeFixture {
            scenario: NoNetworkProbeScenario::RchUnavailable,
            ..NoNetworkProbeFixture::default()
        };
        let report = fixture.build_report().expect("fixture report validates");

        assert_eq!(report.decision.status, ReadinessStatus::Blocked);
        assert!(!report.decision.can_run_cargo_proof);
        assert!(
            report
                .decision
                .refused_actions
                .contains(&ReadinessAction::CargoProof)
        );
    }

    #[test]
    fn branch_mismatch_fixture_refuses_push() {
        let fixture = NoNetworkProbeFixture {
            scenario: NoNetworkProbeScenario::BranchMirrorMismatch,
            ..NoNetworkProbeFixture::default()
        };
        let report = fixture.build_report().expect("fixture report validates");

        assert_eq!(report.probes.git.branch_mirror_match, Some(false));
        assert!(!report.decision.can_push);
        assert!(
            report
                .decision
                .refused_actions
                .contains(&ReadinessAction::Push)
        );
    }
}
