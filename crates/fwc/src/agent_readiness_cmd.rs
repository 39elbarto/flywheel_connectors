//! Operator command surface for agent-session readiness handoff bundles.
//!
//! The command family stays offline by default: fixture mode synthesizes the
//! redaction-safe evidence schema from `fcp-evidence`, replay mode validates
//! stored report/JSONL artifacts, and plan mode renders the non-destructive
//! probe plan an operator can audit before wiring live collection.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand, ValueEnum};
use fcp_evidence::{
    AgentReadinessJsonlEvent, AgentReadinessReport, AgentStartupProbePlan, NoNetworkProbeFixture,
    NoNetworkProbeScenario, ReadinessAction,
};
use serde::Serialize;
use serde_json::{Value, json};

const AGENT_READINESS_HANDOFF_SCHEMA: &str = "fcp.agent-readiness-handoff.v1";
const REPORT_FILENAME: &str = "report.json";
const EVENTS_FILENAME: &str = "events.jsonl";
const HANDOFF_FILENAME: &str = "handoff.json";
const HANDOFF_MARKDOWN_FILENAME: &str = "handoff.md";

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
    /// The remote branch mirror does not match the primary branch.
    BranchMirrorMismatch,
    /// The shared checkout has unrelated dirty files.
    DirtySharedTree,
}

impl From<FixtureScenarioArg> for NoNetworkProbeScenario {
    fn from(value: FixtureScenarioArg) -> Self {
        match value {
            FixtureScenarioArg::Healthy => Self::Healthy,
            FixtureScenarioArg::AgentMailUnavailable => Self::AgentMailUnavailable,
            FixtureScenarioArg::RchUnavailable => Self::RchUnavailable,
            FixtureScenarioArg::BranchMirrorMismatch => Self::BranchMirrorMismatch,
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
        AgentReadinessArgs {
            command: AgentReadinessCommand::Fixture(AgentReadinessFixtureArgs {
                scenario: FixtureScenarioArg::AgentMailUnavailable,
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
}
