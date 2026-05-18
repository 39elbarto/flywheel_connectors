//! Operator command surface for agent-session readiness handoff bundles.
//!
//! The command family stays offline by default: fixture mode synthesizes the
//! redaction-safe evidence schema from `fcp-evidence`, replay mode validates
//! stored report/JSONL artifacts, and plan mode renders the non-destructive
//! probe plan an operator can audit before wiring live collection.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use clap::{Args, Subcommand, ValueEnum};
use fcp_evidence::{
    AgentReadinessJsonlEvent, AgentReadinessReport, AgentStartupProbePlan, NoNetworkProbeFixture,
    NoNetworkProbeScenario, ReadinessAction,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const AGENT_READINESS_HANDOFF_SCHEMA: &str = "fcp.agent-readiness-handoff.v1";
const STALLED_BEADS_REPORT_SCHEMA: &str = "fcp.stalled-bead-recovery-report.v1";
const REPORT_FILENAME: &str = "report.json";
const EVENTS_FILENAME: &str = "events.jsonl";
const HANDOFF_FILENAME: &str = "handoff.json";
const HANDOFF_MARKDOWN_FILENAME: &str = "handoff.md";
const DEFAULT_STALE_AFTER_DAYS: u64 = 3;
const DAY_MS: u64 = 86_400_000;
const OPERATOR_APPROVAL_GATES: [&str; 6] = [
    "agent_mail_repair: do not repair, reconstruct, restart, or kill Agent Mail without explicit user approval",
    "disk_cleanup: do not delete files or prune artifacts to relieve disk pressure without explicit user approval",
    "file_deletion: do not delete any file or folder without explicit user approval",
    "worker_fleet_repair: do not repair, restart, or reconfigure rch workers without explicit user approval",
    "destructive_git: do not run destructive Git cleanup, reset, or overwrite commands without explicit user approval",
    "local_cargo_proof: do not treat local Cargo or transfer logs as proof when rch proof is required",
];

/// Arguments for `fwc agent-readiness`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct AgentReadinessArgs {
    #[command(subcommand)]
    pub command: AgentReadinessCommand,
}

/// Agent-readiness subcommands.
#[derive(Subcommand, Debug, Clone, Serialize)]
pub enum AgentReadinessCommand {
    /// Emit the safe startup probe plan without executing probes.
    Plan(AgentReadinessPlanArgs),
    /// Build a deterministic no-network fixture and store a handoff bundle.
    Fixture(AgentReadinessFixtureArgs),
    /// Replay and validate a stored readiness report plus optional JSONL events.
    Replay(AgentReadinessReplayArgs),
    /// Report stale in-progress Beads plus safe non-mutating recovery commands.
    #[command(name = "stalled-beads")]
    StalledBeads(AgentReadinessStalledBeadsArgs),
}

/// Probe plan flavor to render.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[clap(rename_all = "kebab-case")]
#[serde(rename_all = "kebab-case")]
pub enum ProbePlanModeArg {
    /// Deterministic fixture commands with no network access.
    NoNetworkFixture,
    /// Read-only live probes that do not mutate shared services.
    LiveReadOnly,
}

/// Arguments for `fwc agent-readiness plan`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct AgentReadinessPlanArgs {
    /// Plan mode to render.
    #[arg(long, value_enum, default_value_t = ProbePlanModeArg::NoNetworkFixture)]
    pub mode: ProbePlanModeArg,
}

/// No-network fixture scenarios.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[clap(rename_all = "kebab-case")]
#[serde(rename_all = "kebab-case")]
pub enum FixtureScenarioArg {
    /// Every probe is healthy.
    Healthy,
    /// Agent Mail is unavailable, but Beads/rch/Git are usable.
    AgentMailUnavailable,
    /// rch has no healthy workers, blocking proof and push.
    RchUnavailable,
    /// rch admission is refused by active same-project work.
    RchActiveProjectExclusion,
    /// rch fell back or would fall back to local execution.
    RchLocalFallbackDetected,
    /// rch selected a worker but failed project-root topology preflight before Cargo.
    RchTopologyPreflightFailure,
    /// The remote branch mirror does not match the primary branch.
    BranchMirrorMismatch,
    /// Disk pressure blocks proof and push until scratch storage recovers.
    DiskPressure,
    /// The shared checkout has unrelated dirty files.
    DirtySharedTree,
}

impl From<FixtureScenarioArg> for NoNetworkProbeScenario {
    fn from(value: FixtureScenarioArg) -> Self {
        match value {
            FixtureScenarioArg::Healthy => Self::Healthy,
            FixtureScenarioArg::AgentMailUnavailable => Self::AgentMailUnavailable,
            FixtureScenarioArg::RchUnavailable => Self::RchUnavailable,
            FixtureScenarioArg::RchActiveProjectExclusion => Self::RchActiveProjectExclusion,
            FixtureScenarioArg::RchLocalFallbackDetected => Self::RchLocalFallbackDetected,
            FixtureScenarioArg::RchTopologyPreflightFailure => Self::RchTopologyPreflightFailure,
            FixtureScenarioArg::BranchMirrorMismatch => Self::BranchMirrorMismatch,
            FixtureScenarioArg::DiskPressure => Self::DiskPressure,
            FixtureScenarioArg::DirtySharedTree => Self::DirtySharedTree,
        }
    }
}

/// Arguments for `fwc agent-readiness fixture`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct AgentReadinessFixtureArgs {
    /// Fixture scenario to synthesize.
    #[arg(long, value_enum, default_value_t = FixtureScenarioArg::AgentMailUnavailable)]
    pub scenario: FixtureScenarioArg,

    /// Stable readiness run id. Defaults to a timestamped id.
    #[arg(long = "run-id")]
    pub run_id: Option<String>,

    /// Agent identity for the report. Defaults to AGENT_NAME or USER.
    #[arg(long)]
    pub agent: Option<String>,

    /// Observation time in Unix milliseconds. Defaults to the current clock.
    #[arg(long = "observed-at-unix-ms")]
    pub observed_at_unix_ms: Option<u64>,

    /// Owned path glob recorded in the worktree summary.
    #[arg(long = "owned-path-glob")]
    pub owned_path_globs: Vec<String>,

    /// Output directory for report.json, events.jsonl, handoff.json, and handoff.md.
    #[arg(long = "out-dir", value_name = "PATH")]
    pub out_dir: PathBuf,
}

/// Arguments for `fwc agent-readiness replay`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct AgentReadinessReplayArgs {
    /// Readiness report JSON to validate.
    #[arg(long, value_name = "PATH")]
    pub report: PathBuf,

    /// Optional JSONL events generated from the report.
    #[arg(long, value_name = "PATH")]
    pub jsonl: Option<PathBuf>,

    /// Optional output directory for a normalized handoff bundle.
    #[arg(long = "out-dir", value_name = "PATH")]
    pub out_dir: Option<PathBuf>,
}

/// Arguments for `fwc agent-readiness stalled-beads`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct AgentReadinessStalledBeadsArgs {
    /// Beads JSONL export to inspect.
    #[arg(
        long = "issues-jsonl",
        value_name = "PATH",
        default_value = ".beads/issues.jsonl"
    )]
    pub issues_jsonl: PathBuf,

    /// Age threshold for stale in-progress beads.
    #[arg(long = "stale-after-days", default_value_t = DEFAULT_STALE_AFTER_DAYS)]
    pub stale_after_days: u64,

    /// Stable observation time for tests, in Unix milliseconds.
    #[arg(long = "observed-at-unix-ms")]
    pub observed_at_unix_ms: Option<u64>,

    /// Process snapshot text to use instead of live `ps` output.
    #[arg(long = "process-snapshot", value_name = "PATH")]
    pub process_snapshot: Option<PathBuf>,

    /// Disable the read-only live process scan when no snapshot is supplied.
    #[arg(long = "no-process-scan", default_value_t = false)]
    pub no_process_scan: bool,

    /// Beads lock paths to inspect. Defaults to .write.lock and .sync.lock next to issues-jsonl.
    #[arg(long = "lock-path", value_name = "PATH")]
    pub lock_paths: Vec<PathBuf>,
}

/// Structured result returned to the main dispatcher.
#[derive(Debug)]
pub(crate) struct AgentReadinessCommandResult {
    pub payload: Value,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize)]
struct HandoffBundle {
    schema: &'static str,
    run_id: String,
    agent_name: String,
    source: &'static str,
    report_digest: String,
    decision: HandoffDecisionSummary,
    git_truth: HandoffGitTruth,
    active_blocker_beads: Vec<String>,
    owned_path_globs: Vec<String>,
    exact_allowed_next_actions: Vec<String>,
    refused_next_actions: Vec<String>,
    operator_approval_gates: Vec<&'static str>,
    artifact_files: HandoffArtifactFiles,
    redaction: Value,
    human_summary: String,
}

#[derive(Debug, Clone, Serialize)]
struct HandoffDecisionSummary {
    mode: String,
    status: String,
    primary_reason_code: Option<String>,
    primary_remediation: Option<String>,
    allowed_actions: Vec<String>,
    refused_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct HandoffGitTruth {
    observed_revision: Option<String>,
    remote_main_sha: Option<String>,
    remote_mirror_sha: Option<String>,
    branch_mirror_match: Option<bool>,
    ls_remote_main_status: String,
    ls_remote_mirror_status: String,
}

#[derive(Debug, Clone, Serialize)]
struct HandoffArtifactFiles {
    report_json: &'static str,
    events_jsonl: &'static str,
    handoff_json: &'static str,
    handoff_markdown: &'static str,
}

/// Run a `fwc agent-readiness` command and return a structured payload.
pub fn run(args: &AgentReadinessArgs) -> Result<AgentReadinessCommandResult> {
    match &args.command {
        AgentReadinessCommand::Plan(args) => plan(args),
        AgentReadinessCommand::Fixture(args) => fixture(args),
        AgentReadinessCommand::Replay(args) => replay(args),
        AgentReadinessCommand::StalledBeads(args) => stalled_beads(args),
    }
}

fn plan(args: &AgentReadinessPlanArgs) -> Result<AgentReadinessCommandResult> {
    let plan = match args.mode {
        ProbePlanModeArg::NoNetworkFixture => AgentStartupProbePlan::no_network_fixture()?,
        ProbePlanModeArg::LiveReadOnly => AgentStartupProbePlan::live_read_only()?,
    };
    let mut payload = json!({
        "status": "ok",
        "command": "agent-readiness",
        "subcommand": "plan",
        "mode": args.mode,
        "plan": plan,
        "message": "Rendered the non-destructive agent readiness probe plan.",
        "next_actions": [
            "Review the mutation_scope fields before wiring live probe execution.",
            "Use `fwc agent-readiness fixture --out-dir <dir>` for an offline handoff bundle.",
        ],
    });
    let toon = format_plan_toon(&payload);
    insert_toon(&mut payload, toon);
    Ok(AgentReadinessCommandResult {
        payload,
        success: true,
    })
}

fn fixture(args: &AgentReadinessFixtureArgs) -> Result<AgentReadinessCommandResult> {
    let owned_path_globs = owned_path_globs(args);
    let report = NoNetworkProbeFixture {
        run_id: args.run_id.clone().unwrap_or_else(default_run_id),
        agent_name: args.agent.clone().unwrap_or_else(default_agent_name),
        observed_at_unix_ms: args.observed_at_unix_ms.unwrap_or_else(now_unix_ms),
        scenario: args.scenario.into(),
        owned_path_globs,
    }
    .build_report()?;

    let materialized = materialize_handoff_bundle(&report, &args.out_dir, "fixture")?;
    let mut payload = payload_for_report(
        &report,
        &materialized,
        Some(&args.out_dir),
        "fixture",
        Some(args.scenario),
    )?;
    insert_toon(&mut payload, materialized.human_summary.clone());
    Ok(AgentReadinessCommandResult {
        payload,
        success: true,
    })
}

fn replay(args: &AgentReadinessReplayArgs) -> Result<AgentReadinessCommandResult> {
    let report = load_report(&args.report)?;
    let expected_events = report.to_jsonl_events()?;
    let replayed_events = match &args.jsonl {
        Some(path) => {
            let events = load_jsonl_events(path)?;
            if events != expected_events {
                let payload =
                    replay_mismatch_payload(&report, path, events.len(), expected_events.len());
                return Ok(AgentReadinessCommandResult {
                    payload,
                    success: false,
                });
            }
            events
        }
        None => expected_events,
    };

    let materialized = if let Some(out_dir) = &args.out_dir {
        materialize_handoff_bundle(&report, out_dir, "replay")?
    } else {
        build_handoff_bundle(&report, "replay")?
    };
    let mut payload = payload_for_report(
        &report,
        &materialized,
        args.out_dir.as_ref(),
        "replay",
        None,
    )?;
    payload["jsonl_replay"] = json!({
        "status": "ok",
        "event_count": replayed_events.len(),
        "source": args.jsonl.as_ref().map(|path| path.display().to_string()),
    });
    insert_toon(&mut payload, materialized.human_summary.clone());
    Ok(AgentReadinessCommandResult {
        payload,
        success: true,
    })
}

fn owned_path_globs(args: &AgentReadinessFixtureArgs) -> BTreeSet<String> {
    if args.owned_path_globs.is_empty() {
        return std::iter::once("crates/fcp-evidence/**".to_owned()).collect();
    }
    args.owned_path_globs.iter().cloned().collect()
}

fn materialize_handoff_bundle(
    report: &AgentReadinessReport,
    out_dir: &Path,
    source: &'static str,
) -> Result<HandoffBundle> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("create handoff output directory {}", out_dir.display()))?;

    let bundle = build_handoff_bundle(report, source)?;
    let report_path = out_dir.join(REPORT_FILENAME);
    let events_path = out_dir.join(EVENTS_FILENAME);
    let handoff_path = out_dir.join(HANDOFF_FILENAME);
    let markdown_path = out_dir.join(HANDOFF_MARKDOWN_FILENAME);

    write_new_file(&report_path, &serde_json::to_string_pretty(report)?)?;
    let event_lines = report.to_jsonl_lines()?.join("\n");
    write_new_file(&events_path, &format!("{event_lines}\n"))?;
    write_new_file(&handoff_path, &serde_json::to_string_pretty(&bundle)?)?;
    write_new_file(&markdown_path, &format!("{}\n", bundle.human_summary))?;

    Ok(bundle)
}

fn build_handoff_bundle(
    report: &AgentReadinessReport,
    source: &'static str,
) -> Result<HandoffBundle> {
    report.validate()?;
    let active_blocker_beads = active_blocker_beads(report);
    let decision = HandoffDecisionSummary {
        mode: serde_tag(&report.decision.mode)?,
        status: serde_tag(&report.decision.status)?,
        primary_reason_code: report.decision.primary_reason_code.clone(),
        primary_remediation: report.decision.primary_remediation.clone(),
        allowed_actions: action_labels(&report.decision.allowed_actions)?,
        refused_actions: action_labels(&report.decision.refused_actions)?,
    };
    let git_truth = HandoffGitTruth {
        observed_revision: report.git_revision_observed.clone(),
        remote_main_sha: report.remote_main_sha.clone(),
        remote_mirror_sha: report.remote_master_sha.clone(),
        branch_mirror_match: report.probes.git.branch_mirror_match,
        ls_remote_main_status: serde_tag(&report.probes.git.ls_remote_main.status)?,
        ls_remote_mirror_status: serde_tag(&report.probes.git.ls_remote_master.status)?,
    };
    let exact_allowed_next_actions = report
        .decision
        .allowed_actions
        .iter()
        .copied()
        .map(allowed_next_action)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let refused_next_actions = report
        .decision
        .refused_actions
        .iter()
        .copied()
        .map(refused_next_action)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let operator_approval_gates = OPERATOR_APPROVAL_GATES.to_vec();
    let owned_path_globs = report
        .probes
        .worktree
        .owned_path_globs
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let report_digest = report.record_digest()?;
    let artifact_files = HandoffArtifactFiles {
        report_json: REPORT_FILENAME,
        events_jsonl: EVENTS_FILENAME,
        handoff_json: HANDOFF_FILENAME,
        handoff_markdown: HANDOFF_MARKDOWN_FILENAME,
    };
    let redaction = serde_json::to_value(&report.redaction)?;
    let human_summary = format_handoff_summary(
        report,
        &decision,
        &git_truth,
        &active_blocker_beads,
        &exact_allowed_next_actions,
        &refused_next_actions,
        &operator_approval_gates,
        &report_digest,
    );

    Ok(HandoffBundle {
        schema: AGENT_READINESS_HANDOFF_SCHEMA,
        run_id: report.run_id.clone(),
        agent_name: report.agent_name.clone(),
        source,
        report_digest,
        decision,
        git_truth,
        active_blocker_beads,
        owned_path_globs,
        exact_allowed_next_actions,
        refused_next_actions,
        operator_approval_gates,
        artifact_files,
        redaction,
        human_summary,
    })
}

fn payload_for_report(
    report: &AgentReadinessReport,
    bundle: &HandoffBundle,
    out_dir: Option<&PathBuf>,
    subcommand: &'static str,
    scenario: Option<FixtureScenarioArg>,
) -> Result<Value> {
    Ok(json!({
        "status": "ok",
        "command": "agent-readiness",
        "subcommand": subcommand,
        "schema": AGENT_READINESS_HANDOFF_SCHEMA,
        "scenario": scenario,
        "run_id": &report.run_id,
        "agent_name": &report.agent_name,
        "output_dir": out_dir.map(|path| path.display().to_string()),
        "handoff": bundle,
        "report": {
            "schema": &report.schema,
            "digest": &bundle.report_digest,
            "jsonl_event_count": report.to_jsonl_events()?.len(),
        },
        "message": "Built a redaction-safe agent readiness handoff bundle.",
        "next_actions": &bundle.exact_allowed_next_actions,
    }))
}

fn replay_mismatch_payload(
    report: &AgentReadinessReport,
    path: &Path,
    actual_count: usize,
    expected_count: usize,
) -> Value {
    json!({
        "status": "error",
        "command": "agent-readiness",
        "subcommand": "replay",
        "run_id": &report.run_id,
        "error": {
            "type": "jsonl-replay-mismatch",
            "message": "The JSONL event file does not match the events derived from the readiness report.",
            "recoverable": true,
            "source": path.display().to_string(),
            "actual_event_count": actual_count,
            "expected_event_count": expected_count,
        },
        "next_actions": [
            "Regenerate events.jsonl from the matching report.json.",
            "Use the report digest in handoff.json to verify artifact provenance.",
        ],
    })
}

fn load_report(path: &Path) -> Result<AgentReadinessReport> {
    let file =
        File::open(path).with_context(|| format!("open readiness report {}", path.display()))?;
    let report: AgentReadinessReport = serde_json::from_reader(file)
        .with_context(|| format!("parse readiness report {}", path.display()))?;
    report.validate()?;
    Ok(report)
}

fn load_jsonl_events(path: &Path) -> Result<Vec<AgentReadinessJsonlEvent>> {
    let file =
        File::open(path).with_context(|| format!("open readiness JSONL {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        let line =
            line.with_context(|| format!("read JSONL line {} from {}", idx + 1, path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let event = serde_json::from_str::<AgentReadinessJsonlEvent>(&line)
            .with_context(|| format!("parse JSONL line {} from {}", idx + 1, path.display()))?;
        events.push(event);
    }
    if events.is_empty() {
        bail!("readiness JSONL file has no events: {}", path.display());
    }
    Ok(events)
}

fn write_new_file(path: &Path, contents: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create handoff artifact {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("write handoff artifact {}", path.display()))
}

fn active_blocker_beads(report: &AgentReadinessReport) -> Vec<String> {
    let mut blockers = report.decision.blocker_bead_ids.clone();
    blockers.extend(report.probes.beads.blocked_infra_bead_ids.iter().cloned());
    blockers.into_iter().collect()
}

fn action_labels(actions: &BTreeSet<ReadinessAction>) -> Result<Vec<String>> {
    actions.iter().map(serde_tag).collect()
}

fn serde_tag<T>(value: &T) -> Result<String>
where
    T: Serialize,
{
    match serde_json::to_value(value)? {
        Value::String(tag) => Ok(tag),
        other => bail!("expected enum to serialize as string, got {other}"),
    }
}

fn allowed_next_action(action: ReadinessAction) -> &'static str {
    match action {
        ReadinessAction::Coordinate => {
            "coordinate: use Agent Mail registration, file reservations, and inbox checks before editing"
        }
        ReadinessAction::ClaimBead => "claim_bead: update the selected Beads issue before editing",
        ReadinessAction::EditFiles => {
            "edit_files: edit only the owned path globs recorded in the report"
        }
        ReadinessAction::CargoProof => {
            "cargo_proof: run Cargo verification through rch with an isolated CARGO_TARGET_DIR"
        }
        ReadinessAction::Push => {
            "push: push proven commits to main and then mirror the legacy branch"
        }
    }
}

fn refused_next_action(action: ReadinessAction) -> &'static str {
    match action {
        ReadinessAction::Coordinate => {
            "coordinate: skip Agent Mail coordination and use Beads comments until the blocker clears"
        }
        ReadinessAction::ClaimBead => "claim_bead: do not claim or update Beads from this session",
        ReadinessAction::EditFiles => "edit_files: keep the session read-only",
        ReadinessAction::CargoProof => {
            "cargo_proof: do not treat local Cargo or sync chatter as proof"
        }
        ReadinessAction::Push => "push: do not push until proof and remote-ref checks pass",
    }
}

fn format_handoff_summary(
    report: &AgentReadinessReport,
    decision: &HandoffDecisionSummary,
    git_truth: &HandoffGitTruth,
    blockers: &[String],
    allowed: &[String],
    refused: &[String],
    approval_gates: &[&str],
    digest: &str,
) -> String {
    let blocker_text = if blockers.is_empty() {
        "none".to_owned()
    } else {
        blockers.join(", ")
    };
    let allowed_text = if allowed.is_empty() {
        "none".to_owned()
    } else {
        allowed.join("\n- ")
    };
    let refused_text = if refused.is_empty() {
        "none".to_owned()
    } else {
        refused.join("\n- ")
    };
    let approval_gate_text = approval_gates.join("\n- ");
    format!(
        "\
agent readiness handoff: {run_id}
agent: {agent}
mode: {mode}
status: {status}
reason: {reason}
remediation: {remediation}
report_digest: {digest}
remote_main_sha: {main_sha}
remote_mirror_sha: {mirror_sha}
branch_mirror_match: {mirror_match}
ls_remote_status: main={main_status}; mirror={mirror_status}
active_blocker_beads: {blockers}
allowed_next_actions:
- {allowed}
refused_next_actions:
- {refused}
operator_approval_gates:
- {approval_gates}
",
        run_id = report.run_id.as_str(),
        agent = report.agent_name.as_str(),
        mode = decision.mode.as_str(),
        status = decision.status.as_str(),
        reason = decision.primary_reason_code.as_deref().unwrap_or("none"),
        remediation = decision.primary_remediation.as_deref().unwrap_or("none"),
        main_sha = git_truth.remote_main_sha.as_deref().unwrap_or("unknown"),
        mirror_sha = git_truth.remote_mirror_sha.as_deref().unwrap_or("unknown"),
        mirror_match = git_truth
            .branch_mirror_match
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_owned()),
        main_status = git_truth.ls_remote_main_status.as_str(),
        mirror_status = git_truth.ls_remote_mirror_status.as_str(),
        blockers = blocker_text,
        allowed = allowed_text,
        refused = refused_text,
        approval_gates = approval_gate_text,
    )
}

fn format_plan_toon(payload: &Value) -> String {
    let mode = payload
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let command_count = payload
        .get("plan")
        .and_then(|plan| plan.get("commands"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    format!(
        "agent readiness plan: {mode}\ncommands: {command_count}\nmutation: disposable Beads/Git writes only"
    )
}

fn insert_toon(payload: &mut Value, toon: String) {
    if let Some(object) = payload.as_object_mut() {
        object.insert("toon".to_owned(), Value::String(toon));
    }
}

fn stalled_beads(args: &AgentReadinessStalledBeadsArgs) -> Result<AgentReadinessCommandResult> {
    if args.stale_after_days == 0 {
        bail!("--stale-after-days must be greater than zero");
    }

    let observed_at_unix_ms = args.observed_at_unix_ms.unwrap_or_else(now_unix_ms);
    let stale_after_ms = args.stale_after_days.saturating_mul(DAY_MS);
    let (issues, jsonl_warnings) = load_in_progress_beads(&args.issues_jsonl)?;
    let lock_paths = if args.lock_paths.is_empty() {
        default_beads_lock_paths(&args.issues_jsonl)
    } else {
        args.lock_paths.clone()
    };
    let lock_evidence = observe_beads_locks(&lock_paths);
    let lock_blocking = lock_evidence.iter().any(|lock| lock.present);
    let process_snapshot = load_process_snapshot(args);

    let mut items = issues
        .iter()
        .map(|issue| {
            evaluate_stalled_bead(
                issue,
                observed_at_unix_ms,
                stale_after_ms,
                lock_blocking,
                &process_snapshot,
            )
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| {
        left.recommended_action
            .cmp(&right.recommended_action)
            .then_with(|| left.id.cmp(&right.id))
    });

    let safe_commands = items
        .iter()
        .filter_map(|item| item.safe_command.clone())
        .collect::<Vec<_>>();
    let summary = summarize_stalled_beads(&items, lock_blocking, safe_commands.len());
    let report = StalledBeadsReport {
        status: "ok",
        command: "agent-readiness",
        subcommand: "stalled-beads",
        schema: STALLED_BEADS_REPORT_SCHEMA,
        issues_jsonl: args.issues_jsonl.display().to_string(),
        observed_at_unix_ms,
        stale_after_days: args.stale_after_days,
        process_scan: process_snapshot.report,
        lock_evidence,
        jsonl_warnings,
        summary,
        safe_commands,
        items,
        safety: StalledBeadsSafetyContract::default(),
        message: "Generated a read-only stalled in-progress Beads recovery report.",
    };
    let mut payload = serde_json::to_value(&report)?;
    insert_toon(&mut payload, format_stalled_beads_toon(&report));
    Ok(AgentReadinessCommandResult {
        payload,
        success: true,
    })
}

#[derive(Debug, Clone, Serialize)]
struct StalledBeadsReport {
    status: &'static str,
    command: &'static str,
    subcommand: &'static str,
    schema: &'static str,
    issues_jsonl: String,
    observed_at_unix_ms: u64,
    stale_after_days: u64,
    process_scan: ProcessScanReport,
    lock_evidence: Vec<BeadsLockEvidence>,
    jsonl_warnings: Vec<JsonlWarning>,
    summary: StalledBeadsSummary,
    safe_commands: Vec<String>,
    items: Vec<StalledBeadItem>,
    safety: StalledBeadsSafetyContract,
    message: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct StalledBeadsSummary {
    total_in_progress: usize,
    stale_candidates: usize,
    action_counts: BTreeMap<String, usize>,
    lock_blocking: bool,
    safe_reopen_command_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct StalledBeadItem {
    id: String,
    title: String,
    assignee: Option<String>,
    updated_at: String,
    activity: StalledBeadActivity,
    process_evidence: Vec<ProcessEvidence>,
    lock_blocking: bool,
    recommended_action: StalledBeadRecommendedAction,
    reasons: Vec<String>,
    safe_command: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct StalledBeadActivity {
    last_activity_unix_ms: u64,
    age_days: u64,
    stale: bool,
    latest_comment: Option<CommentActivity>,
}

#[derive(Debug, Clone, Serialize)]
struct CommentActivity {
    author: String,
    created_at: String,
    created_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ProcessEvidence {
    matched_field: &'static str,
    matched_value: String,
    match_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct ProcessScanReport {
    status: ProcessScanStatus,
    source: Option<String>,
    line_count: usize,
}

#[derive(Debug, Clone)]
struct ProcessSnapshot {
    report: ProcessScanReport,
    lines: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProcessScanStatus {
    Fixture,
    LiveReadOnly,
    Disabled,
    Unavailable,
}

impl ProcessScanStatus {
    const fn observed(self) -> bool {
        matches!(self, Self::Fixture | Self::LiveReadOnly)
    }
}

#[derive(Debug, Clone, Serialize)]
struct BeadsLockEvidence {
    path: String,
    present: bool,
    blocking: bool,
}

#[derive(Debug, Clone, Serialize)]
struct JsonlWarning {
    line: usize,
    reason: String,
}

#[derive(Debug, Clone, Serialize)]
struct StalledBeadsSafetyContract {
    read_only: bool,
    edits_beads_jsonl_directly: bool,
    removes_lock_files: bool,
    kills_processes: bool,
    emitted_commands_mutate_only_when_operator_runs_them: bool,
}

impl Default for StalledBeadsSafetyContract {
    fn default() -> Self {
        Self {
            read_only: true,
            edits_beads_jsonl_directly: false,
            removes_lock_files: false,
            kills_processes: false,
            emitted_commands_mutate_only_when_operator_runs_them: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum StalledBeadRecommendedAction {
    Reopen,
    BlockedByLock,
    Investigate,
    LeaveClaimed,
}

impl StalledBeadRecommendedAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Reopen => "reopen",
            Self::BlockedByLock => "blocked_by_lock",
            Self::Investigate => "investigate",
            Self::LeaveClaimed => "leave_claimed",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RawBeadIssue {
    id: String,
    title: String,
    #[serde(default)]
    assignee: Option<String>,
    updated_at: String,
    #[serde(default)]
    comments: Option<Vec<RawBeadComment>>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawBeadComment {
    author: String,
    created_at: String,
}

fn load_in_progress_beads(path: &Path) -> Result<(Vec<RawBeadIssue>, Vec<JsonlWarning>)> {
    let file = File::open(path).with_context(|| format!("open Beads JSONL {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        let line_no = idx + 1;
        let line = line
            .with_context(|| format!("read Beads JSONL line {line_no} from {}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let value = match serde_json::from_str::<Value>(&line) {
            Ok(value) => value,
            Err(error) => {
                warnings.push(JsonlWarning {
                    line: line_no,
                    reason: format!("invalid JSON: {error}"),
                });
                continue;
            }
        };
        if value.get("status").and_then(Value::as_str) != Some("in_progress") {
            continue;
        }
        match serde_json::from_value::<RawBeadIssue>(value) {
            Ok(issue) => issues.push(issue),
            Err(error) => warnings.push(JsonlWarning {
                line: line_no,
                reason: format!("invalid in-progress issue record: {error}"),
            }),
        }
    }
    Ok((issues, warnings))
}

fn evaluate_stalled_bead(
    issue: &RawBeadIssue,
    observed_at_unix_ms: u64,
    stale_after_ms: u64,
    lock_blocking: bool,
    process_snapshot: &ProcessSnapshot,
) -> StalledBeadItem {
    let updated_at_unix_ms = parse_rfc3339_unix_ms(&issue.updated_at).unwrap_or(0);
    let latest_comment = latest_comment_activity(issue);
    let latest_comment_unix_ms = latest_comment
        .as_ref()
        .map_or(0, |comment| comment.created_at_unix_ms);
    let last_activity_unix_ms = updated_at_unix_ms.max(latest_comment_unix_ms);
    let age_ms = observed_at_unix_ms.saturating_sub(last_activity_unix_ms);
    let stale = age_ms > stale_after_ms;
    let activity = StalledBeadActivity {
        last_activity_unix_ms,
        age_days: age_ms / DAY_MS,
        stale,
        latest_comment,
    };
    let assignee = normalized_assignee(issue.assignee.as_deref());
    let process_evidence =
        process_evidence_for_issue(&issue.id, assignee.as_deref(), process_snapshot);
    let has_active_process = !process_evidence.is_empty();
    let (recommended_action, reasons) = recommend_stalled_bead_action(
        stale,
        lock_blocking,
        assignee.is_some(),
        has_active_process,
        process_snapshot.report.status.observed(),
        updated_at_unix_ms != 0,
    );
    let safe_command = (recommended_action == StalledBeadRecommendedAction::Reopen)
        .then(|| format!("br update {} --status open", issue.id));

    StalledBeadItem {
        id: issue.id.clone(),
        title: issue.title.clone(),
        assignee,
        updated_at: issue.updated_at.clone(),
        activity,
        process_evidence,
        lock_blocking,
        recommended_action,
        reasons,
        safe_command,
    }
}

fn recommend_stalled_bead_action(
    stale: bool,
    lock_blocking: bool,
    has_assignee: bool,
    has_active_process: bool,
    process_scan_observed: bool,
    updated_at_parsed: bool,
) -> (StalledBeadRecommendedAction, Vec<String>) {
    let mut reasons = Vec::new();
    if !updated_at_parsed {
        reasons.push("updated_at_unparseable".to_owned());
    }
    if !stale {
        reasons.push("recent_activity_within_threshold".to_owned());
        return (StalledBeadRecommendedAction::LeaveClaimed, reasons);
    }
    reasons.push("stale_in_progress".to_owned());
    if has_active_process {
        reasons.push("active_matching_process_evidence".to_owned());
        return (StalledBeadRecommendedAction::LeaveClaimed, reasons);
    }
    if lock_blocking {
        reasons.push("beads_lock_present".to_owned());
        return (StalledBeadRecommendedAction::BlockedByLock, reasons);
    }
    if !process_scan_observed {
        reasons.push("process_scan_unavailable".to_owned());
        return (StalledBeadRecommendedAction::Investigate, reasons);
    }
    if has_assignee {
        reasons.push("assigned_agent_not_observed".to_owned());
        return (StalledBeadRecommendedAction::Investigate, reasons);
    }
    reasons.push("missing_assignee".to_owned());
    reasons.push("no_recent_comment".to_owned());
    (StalledBeadRecommendedAction::Reopen, reasons)
}

fn latest_comment_activity(issue: &RawBeadIssue) -> Option<CommentActivity> {
    issue
        .comments
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter_map(|comment| {
            parse_rfc3339_unix_ms(&comment.created_at).map(|created_at_unix_ms| CommentActivity {
                author: comment.author.clone(),
                created_at: comment.created_at.clone(),
                created_at_unix_ms,
            })
        })
        .max_by_key(|comment| comment.created_at_unix_ms)
}

fn process_evidence_for_issue(
    issue_id: &str,
    assignee: Option<&str>,
    process_snapshot: &ProcessSnapshot,
) -> Vec<ProcessEvidence> {
    let mut evidence = Vec::new();
    push_process_match(&mut evidence, "issue_id", issue_id, &process_snapshot.lines);
    if let Some(assignee) = assignee {
        push_process_match(&mut evidence, "assignee", assignee, &process_snapshot.lines);
    }
    evidence
}

fn push_process_match(
    evidence: &mut Vec<ProcessEvidence>,
    matched_field: &'static str,
    matched_value: &str,
    lines: &[String],
) {
    let needle = matched_value.to_ascii_lowercase();
    if needle.is_empty() {
        return;
    }
    let match_count = lines
        .iter()
        .filter(|line| line.to_ascii_lowercase().contains(&needle))
        .count();
    if match_count > 0 {
        evidence.push(ProcessEvidence {
            matched_field,
            matched_value: matched_value.to_owned(),
            match_count,
        });
    }
}

fn normalized_assignee(assignee: Option<&str>) -> Option<String> {
    assignee
        .map(str::trim)
        .filter(|assignee| !assignee.is_empty())
        .map(str::to_owned)
}

fn parse_rfc3339_unix_ms(value: &str) -> Option<u64> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .and_then(|timestamp| u64::try_from(timestamp.with_timezone(&Utc).timestamp_millis()).ok())
}

fn load_process_snapshot(args: &AgentReadinessStalledBeadsArgs) -> ProcessSnapshot {
    if let Some(path) = &args.process_snapshot {
        return match fs::read_to_string(path) {
            Ok(raw) => process_snapshot_from_lines(
                ProcessScanStatus::Fixture,
                Some(path.display().to_string()),
                raw.lines(),
            ),
            Err(error) => ProcessSnapshot {
                report: ProcessScanReport {
                    status: ProcessScanStatus::Unavailable,
                    source: Some(path.display().to_string()),
                    line_count: 0,
                },
                lines: vec![format!("process snapshot unavailable: {error}")],
            },
        };
    }
    if args.no_process_scan {
        return ProcessSnapshot {
            report: ProcessScanReport {
                status: ProcessScanStatus::Disabled,
                source: None,
                line_count: 0,
            },
            lines: Vec::new(),
        };
    }
    match Command::new("ps")
        .args(["-axo", "pid=,ppid=,command="])
        .output()
    {
        Ok(output) if output.status.success() => {
            let raw = String::from_utf8_lossy(&output.stdout);
            process_snapshot_from_lines(
                ProcessScanStatus::LiveReadOnly,
                Some("ps".to_owned()),
                raw.lines(),
            )
        }
        Ok(output) => ProcessSnapshot {
            report: ProcessScanReport {
                status: ProcessScanStatus::Unavailable,
                source: Some(format!("ps exited with {}", output.status)),
                line_count: 0,
            },
            lines: Vec::new(),
        },
        Err(error) => ProcessSnapshot {
            report: ProcessScanReport {
                status: ProcessScanStatus::Unavailable,
                source: Some(format!("ps failed: {error}")),
                line_count: 0,
            },
            lines: Vec::new(),
        },
    }
}

fn process_snapshot_from_lines<'a>(
    status: ProcessScanStatus,
    source: Option<String>,
    lines: impl Iterator<Item = &'a str>,
) -> ProcessSnapshot {
    let lines = lines.map(str::to_owned).collect::<Vec<_>>();
    ProcessSnapshot {
        report: ProcessScanReport {
            status,
            source,
            line_count: lines.len(),
        },
        lines,
    }
}

fn default_beads_lock_paths(issues_jsonl: &Path) -> Vec<PathBuf> {
    let beads_dir = issues_jsonl.parent().unwrap_or_else(|| Path::new("."));
    vec![beads_dir.join(".write.lock"), beads_dir.join(".sync.lock")]
}

fn observe_beads_locks(paths: &[PathBuf]) -> Vec<BeadsLockEvidence> {
    paths
        .iter()
        .map(|path| {
            let present = path.exists();
            BeadsLockEvidence {
                path: path.display().to_string(),
                present,
                blocking: present,
            }
        })
        .collect()
}

fn summarize_stalled_beads(
    items: &[StalledBeadItem],
    lock_blocking: bool,
    safe_reopen_command_count: usize,
) -> StalledBeadsSummary {
    let mut action_counts = BTreeMap::new();
    for item in items {
        *action_counts
            .entry(item.recommended_action.as_str().to_owned())
            .or_insert(0) += 1;
    }
    StalledBeadsSummary {
        total_in_progress: items.len(),
        stale_candidates: items.iter().filter(|item| item.activity.stale).count(),
        action_counts,
        lock_blocking,
        safe_reopen_command_count,
    }
}

fn format_stalled_beads_toon(report: &StalledBeadsReport) -> String {
    let mut out = format!(
        "\
stalled beads recovery report
schema: {schema}
issues_jsonl: {issues_jsonl}
observed_at_unix_ms: {observed_at}
stale_after_days: {stale_after_days}
in_progress: {total}
stale_candidates: {stale}
safe_reopen_commands: {commands}
lock_blocking: {lock_blocking}
process_scan: {process_status}
",
        schema = report.schema,
        issues_jsonl = report.issues_jsonl,
        observed_at = report.observed_at_unix_ms,
        stale_after_days = report.stale_after_days,
        total = report.summary.total_in_progress,
        stale = report.summary.stale_candidates,
        commands = report.summary.safe_reopen_command_count,
        lock_blocking = report.summary.lock_blocking,
        process_status =
            serde_tag(&report.process_scan.status).unwrap_or_else(|_| "unknown".to_owned()),
    );
    out.push_str("items:\n");
    out.push_str("id | action | assignee | age_days | reasons | safe_command\n");
    for item in &report.items {
        out.push_str(&format!(
            "{} | {} | {} | {} | {} | {}\n",
            item.id,
            item.recommended_action.as_str(),
            item.assignee.as_deref().unwrap_or(""),
            item.activity.age_days,
            item.reasons.join("+"),
            item.safe_command.as_deref().unwrap_or("")
        ));
    }
    out
}

fn default_run_id() -> String {
    format!("agent-readiness-{}", now_unix_ms())
}

fn default_agent_name() -> String {
    std::env::var("AGENT_NAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown-agent".to_owned())
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fixture_args(out_dir: PathBuf) -> AgentReadinessArgs {
        fixture_args_for_scenario(out_dir, FixtureScenarioArg::AgentMailUnavailable)
    }

    fn fixture_args_for_scenario(
        out_dir: PathBuf,
        scenario: FixtureScenarioArg,
    ) -> AgentReadinessArgs {
        AgentReadinessArgs {
            command: AgentReadinessCommand::Fixture(AgentReadinessFixtureArgs {
                scenario,
                run_id: Some("agent-readiness-test".to_owned()),
                agent: Some("GreenLake".to_owned()),
                observed_at_unix_ms: Some(1_893_456_000_000),
                owned_path_globs: vec!["crates/fcp-evidence/**".to_owned()],
                out_dir,
            }),
        }
    }

    #[test]
    fn fixture_command_writes_redaction_safe_handoff_bundle() {
        let tmp = TempDir::new().expect("tempdir");
        let result = run(&fixture_args(tmp.path().to_path_buf())).expect("fixture run");
        assert!(result.success);
        assert_eq!(result.payload["status"], "ok");
        assert_eq!(result.payload["handoff"]["decision"]["mode"], "beads_only");
        assert_eq!(
            result.payload["handoff"]["active_blocker_beads"][0],
            "flywheel_connectors-d5yeb"
        );

        for file in [
            REPORT_FILENAME,
            EVENTS_FILENAME,
            HANDOFF_FILENAME,
            HANDOFF_MARKDOWN_FILENAME,
        ] {
            assert!(tmp.path().join(file).is_file(), "{file} should exist");
        }

        let handoff_text =
            fs::read_to_string(tmp.path().join(HANDOFF_FILENAME)).expect("handoff json");
        assert!(!handoff_text.contains(tmp.path().to_string_lossy().as_ref()));
        assert!(handoff_text.contains("agent-readiness-test"));
        assert!(handoff_text.contains("flywheel_connectors-d5yeb"));
        assert!(handoff_text.contains("agent_mail_repair"));
        assert!(handoff_text.contains("disk_cleanup"));
        assert!(handoff_text.contains("worker_fleet_repair"));
        assert!(handoff_text.contains("destructive_git"));

        let markdown_text =
            fs::read_to_string(tmp.path().join(HANDOFF_MARKDOWN_FILENAME)).expect("handoff md");
        assert!(markdown_text.contains("operator_approval_gates"));
        assert!(markdown_text.contains("do not repair, reconstruct, restart, or kill Agent Mail"));
    }

    #[test]
    fn fixture_command_writes_rch_blocker_troubleshooting_packet() {
        let tmp = TempDir::new().expect("tempdir");
        let result = run(&fixture_args_for_scenario(
            tmp.path().to_path_buf(),
            FixtureScenarioArg::RchUnavailable,
        ))
        .expect("fixture run");

        assert!(result.success);
        assert_eq!(
            result.payload["handoff"]["decision"]["mode"],
            "proof_blocked"
        );
        assert_eq!(
            result.payload["handoff"]["active_blocker_beads"][0],
            "flywheel_connectors-rfbrc"
        );
        let refused_next_actions = result.payload["handoff"]["refused_next_actions"]
            .as_array()
            .expect("refused actions are an array");
        assert!(refused_next_actions.iter().any(|action| {
            action
                .as_str()
                .is_some_and(|action| action.starts_with("cargo_proof:"))
        }));
        assert!(refused_next_actions.iter().any(|action| {
            action
                .as_str()
                .is_some_and(|action| action.starts_with("push:"))
        }));
        let approval_gates = result.payload["handoff"]["operator_approval_gates"]
            .as_array()
            .expect("approval gates are an array");
        assert!(approval_gates.iter().any(|gate| {
            gate.as_str()
                .is_some_and(|gate| gate.starts_with("disk_cleanup:"))
        }));
        assert!(approval_gates.iter().any(|gate| {
            gate.as_str()
                .is_some_and(|gate| gate.starts_with("worker_fleet_repair:"))
        }));
    }

    #[test]
    fn fixture_command_preserves_rch_admission_taxonomy() {
        let tmp = TempDir::new().expect("tempdir");
        let result = run(&fixture_args_for_scenario(
            tmp.path().to_path_buf(),
            FixtureScenarioArg::RchActiveProjectExclusion,
        ))
        .expect("fixture run");

        assert!(result.success);
        assert_eq!(
            result.payload["handoff"]["decision"]["mode"],
            "proof_blocked"
        );
        assert_eq!(
            result.payload["handoff"]["decision"]["primary_reason_code"],
            "proof-blocked-rch-active-project-exclusion"
        );
        assert_eq!(
            result.payload["report"]["jsonl_event_count"],
            Value::from(18)
        );

        let report_text =
            fs::read_to_string(tmp.path().join(REPORT_FILENAME)).expect("report json");
        let report: Value = serde_json::from_str(&report_text).expect("report parses");
        assert_eq!(
            report["probes"]["rch"]["admission_decision"],
            "wait_for_project_slot"
        );
        assert_eq!(
            report["probes"]["rch"]["admission_reason_code"],
            "active_project_exclusion"
        );
    }

    #[test]
    fn fixture_command_refuses_rch_local_fallback() {
        let tmp = TempDir::new().expect("tempdir");
        let result = run(&fixture_args_for_scenario(
            tmp.path().to_path_buf(),
            FixtureScenarioArg::RchLocalFallbackDetected,
        ))
        .expect("fixture run");

        assert!(result.success);
        assert_eq!(
            result.payload["handoff"]["decision"]["mode"],
            "proof_blocked"
        );
        assert_eq!(
            result.payload["handoff"]["decision"]["primary_reason_code"],
            "proof-blocked-rch-local-fallback-refused"
        );
        let refused_next_actions = result.payload["handoff"]["refused_next_actions"]
            .as_array()
            .expect("refused actions are an array");
        assert!(refused_next_actions.iter().any(|action| {
            action.as_str()
                == Some("cargo_proof: do not treat local Cargo or sync chatter as proof")
        }));

        let report_text =
            fs::read_to_string(tmp.path().join(REPORT_FILENAME)).expect("report json");
        let report: Value = serde_json::from_str(&report_text).expect("report parses");
        assert_eq!(
            report["probes"]["rch"]["admission_decision"],
            "refuse_local_fallback"
        );
        assert_eq!(
            report["probes"]["rch"]["admission_reason_code"],
            "local_fallback_detected"
        );
    }

    #[test]
    fn fixture_command_preserves_rch_topology_preflight_failure() {
        let tmp = TempDir::new().expect("tempdir");
        let result = run(&fixture_args_for_scenario(
            tmp.path().to_path_buf(),
            FixtureScenarioArg::RchTopologyPreflightFailure,
        ))
        .expect("fixture run");

        assert!(result.success);
        assert_eq!(
            result.payload["handoff"]["decision"]["primary_reason_code"],
            "proof-blocked-rch-topology-preflight"
        );
        assert_eq!(
            result.payload["handoff"]["active_blocker_beads"][0],
            "flywheel_connectors-ylexc"
        );

        let report_text =
            fs::read_to_string(tmp.path().join(REPORT_FILENAME)).expect("report json");
        let report: Value = serde_json::from_str(&report_text).expect("report parses");
        assert_eq!(
            report["probes"]["rch"]["admission_decision"],
            "rch_infra_failure"
        );
        assert_eq!(
            report["probes"]["rch"]["admission_reason_code"],
            "topology_preflight_failure"
        );
        assert_eq!(
            report["probes"]["beads"]["blocked_infra_bead_ids"][0],
            "flywheel_connectors-ylexc"
        );
    }

    #[test]
    fn fixture_command_preserves_disk_pressure_blocker() {
        let tmp = TempDir::new().expect("tempdir");
        let result = run(&fixture_args_for_scenario(
            tmp.path().to_path_buf(),
            FixtureScenarioArg::DiskPressure,
        ))
        .expect("fixture run");

        assert!(result.success);
        assert_eq!(
            result.payload["handoff"]["decision"]["mode"],
            "proof_blocked"
        );
        assert_eq!(
            result.payload["handoff"]["decision"]["primary_reason_code"],
            "proof-blocked-disk-pressure"
        );
        assert_eq!(
            result.payload["handoff"]["active_blocker_beads"][0],
            "flywheel_connectors-rfbrc"
        );
        assert!(
            result.payload["handoff"]["refused_next_actions"]
                .as_array()
                .expect("refused actions")
                .iter()
                .any(|action| {
                    action
                        .as_str()
                        .is_some_and(|action| action.starts_with("cargo_proof:"))
                })
        );
        assert!(
            result.payload["handoff"]["operator_approval_gates"]
                .as_array()
                .expect("approval gates")
                .iter()
                .any(|gate| {
                    gate.as_str()
                        .is_some_and(|gate| gate.starts_with("disk_cleanup:"))
                })
        );

        let report_text =
            fs::read_to_string(tmp.path().join(REPORT_FILENAME)).expect("report json");
        let report: Value = serde_json::from_str(&report_text).expect("report parses");
        assert_eq!(
            report["probes"]["disk"]["check_result"]["status"],
            "blocked"
        );
        assert_eq!(
            report["probes"]["disk"]["check_result"]["reason_code"],
            "disk-pressure"
        );
        assert_eq!(
            report["probes"]["disk"]["external_scratch_available"],
            Value::Bool(false)
        );
    }

    #[test]
    fn replay_command_validates_jsonl_fixture_events() {
        let tmp = TempDir::new().expect("tempdir");
        run(&fixture_args(tmp.path().to_path_buf())).expect("fixture run");
        let args = AgentReadinessArgs {
            command: AgentReadinessCommand::Replay(AgentReadinessReplayArgs {
                report: tmp.path().join(REPORT_FILENAME),
                jsonl: Some(tmp.path().join(EVENTS_FILENAME)),
                out_dir: None,
            }),
        };

        let result = run(&args).expect("replay run");
        assert!(result.success);
        assert_eq!(result.payload["jsonl_replay"]["status"], "ok");
        assert_eq!(
            result.payload["handoff"]["exact_allowed_next_actions"][0],
            "claim_bead: update the selected Beads issue before editing"
        );
    }

    #[test]
    fn plan_command_snapshots_non_destructive_contract() {
        let args = AgentReadinessArgs {
            command: AgentReadinessCommand::Plan(AgentReadinessPlanArgs {
                mode: ProbePlanModeArg::NoNetworkFixture,
            }),
        };
        let result = run(&args).expect("plan run");
        assert!(result.success);
        assert_eq!(result.payload["status"], "ok");
        assert_eq!(
            result.payload["plan"]["beads_disposable_write_only"],
            Value::Bool(true)
        );
        assert_eq!(
            result.payload["plan"]["git_disposable_write_only"],
            Value::Bool(true)
        );
        assert!(
            result.payload["toon"]
                .as_str()
                .unwrap()
                .contains("commands:")
        );
    }

    fn stalled_args(
        issues_jsonl: PathBuf,
        process_snapshot: PathBuf,
        lock_paths: Vec<PathBuf>,
    ) -> AgentReadinessArgs {
        AgentReadinessArgs {
            command: AgentReadinessCommand::StalledBeads(AgentReadinessStalledBeadsArgs {
                issues_jsonl,
                stale_after_days: DEFAULT_STALE_AFTER_DAYS,
                observed_at_unix_ms: Some(
                    parse_rfc3339_unix_ms("2026-05-13T00:00:00Z").expect("observed timestamp"),
                ),
                process_snapshot: Some(process_snapshot),
                no_process_scan: false,
                lock_paths,
            }),
        }
    }

    fn write_issues(path: &Path, records: &[Value]) {
        let mut jsonl = records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        jsonl.push('\n');
        fs::write(path, jsonl).expect("write issues jsonl");
    }

    fn stalled_item<'a>(payload: &'a Value, id: &str) -> &'a Value {
        payload["items"]
            .as_array()
            .expect("items array")
            .iter()
            .find(|item| item["id"] == id)
            .expect("stalled item")
    }

    #[test]
    fn stalled_beads_report_recommends_reopen_only_for_unassigned_stale_idle_beads() {
        let tmp = TempDir::new().expect("tempdir");
        let issues = tmp.path().join("issues.jsonl");
        let process_snapshot = tmp.path().join("ps.txt");
        fs::write(
            &process_snapshot,
            "123 1 codex worker flywheel_connectors-active\n",
        )
        .expect("write process snapshot");
        write_issues(
            &issues,
            &[
                json!({
                    "id": "flywheel_connectors-stale",
                    "title": "stale unassigned parent",
                    "status": "in_progress",
                    "assignee": null,
                    "updated_at": "2026-05-07T00:00:00Z",
                    "comments": []
                }),
                json!({
                    "id": "flywheel_connectors-recent",
                    "title": "recently touched parent",
                    "status": "in_progress",
                    "assignee": null,
                    "updated_at": "2026-05-12T00:00:00Z",
                    "comments": []
                }),
                json!({
                    "id": "flywheel_connectors-assigned",
                    "title": "assigned but no process evidence",
                    "status": "in_progress",
                    "assignee": "BlueLake",
                    "updated_at": "2026-05-07T00:00:00Z",
                    "comments": []
                }),
                json!({
                    "id": "flywheel_connectors-active",
                    "title": "active process still mentions issue",
                    "status": "in_progress",
                    "assignee": null,
                    "updated_at": "2026-05-07T00:00:00Z",
                    "comments": []
                }),
                json!({
                    "id": "flywheel_connectors-open",
                    "title": "open issue ignored",
                    "status": "open",
                    "assignee": null,
                    "updated_at": "2026-05-07T00:00:00Z",
                    "comments": []
                }),
            ],
        );

        let result = run(&stalled_args(
            issues,
            process_snapshot,
            vec![tmp.path().join("missing.write.lock")],
        ))
        .expect("stalled-beads run");

        assert!(result.success);
        assert_eq!(result.payload["schema"], STALLED_BEADS_REPORT_SCHEMA);
        assert_eq!(result.payload["summary"]["total_in_progress"], 4);
        assert_eq!(
            stalled_item(&result.payload, "flywheel_connectors-stale")["recommended_action"],
            "reopen"
        );
        assert_eq!(
            stalled_item(&result.payload, "flywheel_connectors-stale")["safe_command"],
            "br update flywheel_connectors-stale --status open"
        );
        assert_eq!(
            stalled_item(&result.payload, "flywheel_connectors-recent")["recommended_action"],
            "leave_claimed"
        );
        assert_eq!(
            stalled_item(&result.payload, "flywheel_connectors-assigned")["recommended_action"],
            "investigate"
        );
        assert_eq!(
            stalled_item(&result.payload, "flywheel_connectors-active")["recommended_action"],
            "leave_claimed"
        );
        assert!(
            result.payload["toon"]
                .as_str()
                .expect("toon")
                .contains("br update flywheel_connectors-stale --status open")
        );
    }

    #[test]
    fn stalled_beads_report_blocks_reopen_commands_when_beads_lock_exists() {
        let tmp = TempDir::new().expect("tempdir");
        let issues = tmp.path().join("issues.jsonl");
        let process_snapshot = tmp.path().join("ps.txt");
        let lock = tmp.path().join(".write.lock");
        fs::write(&process_snapshot, "").expect("write process snapshot");
        fs::write(&lock, "").expect("write lock fixture");
        write_issues(
            &issues,
            &[json!({
                "id": "flywheel_connectors-locked",
                "title": "stale but lock held",
                "status": "in_progress",
                "assignee": null,
                "updated_at": "2026-05-07T00:00:00Z",
                "comments": []
            })],
        );

        let result =
            run(&stalled_args(issues, process_snapshot, vec![lock])).expect("stalled-beads run");

        assert!(result.success);
        assert_eq!(
            stalled_item(&result.payload, "flywheel_connectors-locked")["recommended_action"],
            "blocked_by_lock"
        );
        assert!(
            stalled_item(&result.payload, "flywheel_connectors-locked")["safe_command"].is_null()
        );
        assert_eq!(result.payload["summary"]["safe_reopen_command_count"], 0);
        assert_eq!(result.payload["safety"]["removes_lock_files"], false);
        assert_eq!(result.payload["safety"]["kills_processes"], false);
    }

    #[test]
    fn stalled_beads_report_treats_recent_comments_as_activity() {
        let tmp = TempDir::new().expect("tempdir");
        let issues = tmp.path().join("issues.jsonl");
        let process_snapshot = tmp.path().join("ps.txt");
        fs::write(&process_snapshot, "").expect("write process snapshot");
        write_issues(
            &issues,
            &[json!({
                "id": "flywheel_connectors-commented",
                "title": "recent comment keeps parent active",
                "status": "in_progress",
                "assignee": null,
                "updated_at": "2026-05-07T00:00:00Z",
                "comments": [{
                    "author": "jemanuel",
                    "text": "still active",
                    "created_at": "2026-05-12T00:00:00Z"
                }]
            })],
        );

        let result = run(&stalled_args(
            issues,
            process_snapshot,
            vec![tmp.path().join("missing.write.lock")],
        ))
        .expect("stalled-beads run");

        let item = stalled_item(&result.payload, "flywheel_connectors-commented");
        assert_eq!(item["recommended_action"], "leave_claimed");
        assert_eq!(item["activity"]["stale"], false);
        assert_eq!(item["activity"]["latest_comment"]["author"], "jemanuel");
    }
}
