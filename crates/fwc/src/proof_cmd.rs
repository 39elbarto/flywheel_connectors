//! `fwc proof` command family backed by the redaction-safe ProofGraph schema.
//!
//! This module is intentionally corpus-driven. It does not scrape Markdown,
//! Beads JSONL, or shell transcripts directly; callers hand it a structured
//! `ProofGraphCorpus` so the command surface can stay deterministic and
//! redaction-safe.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use fcp_evidence::{
    ClaimId, ClaimNode, ClaimStatus, ProofGapStatus, ProofGraph, ProofGraphCorpus,
    ProofGraphIndexer, RerunCommand, SupportRelationship,
};
use serde::Serialize;
use serde_json::{Value, json};

const DEFAULT_NEXT_LIMIT: usize = 10;
const DEFAULT_OUTPUT_PREVIEW_BYTES: usize = 16 * 1024;

/// Arguments for `fwc proof`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofArgs {
    #[command(subcommand)]
    pub command: ProofCommand,
}

/// `fwc proof` subcommands.
#[derive(Subcommand, Debug, Clone, Serialize)]
pub enum ProofCommand {
    /// Render the indexed ProofGraph as machine-readable JSON.
    Graph(ProofGraphArgs),
    /// Rank proof gaps and rerunnable next actions deterministically.
    Next(ProofNextArgs),
    /// Explain one claim's proof state with source-linked evidence.
    Explain(ProofExplainArgs),
    /// Plan or explicitly execute one known redaction-safe rerun command.
    Run(ProofRunArgs),
}

/// Shared corpus loader arguments.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofCorpusArgs {
    /// Structured `ProofGraphCorpus` JSON file.
    #[arg(long, value_name = "PATH")]
    pub corpus: PathBuf,

    /// Evaluation time in Unix milliseconds. Defaults to the current clock.
    #[arg(long = "now-unix-ms")]
    pub now_unix_ms: Option<u64>,
}

/// Arguments for `fwc proof graph`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofGraphArgs {
    #[command(flatten)]
    pub corpus: ProofCorpusArgs,
}

/// Arguments for `fwc proof next`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofNextArgs {
    #[command(flatten)]
    pub corpus: ProofCorpusArgs,

    /// Maximum ranked proof actions to return.
    #[arg(long, default_value_t = DEFAULT_NEXT_LIMIT)]
    pub limit: usize,
}

/// Arguments for `fwc proof explain`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofExplainArgs {
    /// Claim id, with or without the `claim:` prefix.
    pub claim: String,

    #[command(flatten)]
    pub corpus: ProofCorpusArgs,
}

/// Arguments for `fwc proof run`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofRunArgs {
    /// Claim id or rerun command id. Arbitrary commands are refused.
    pub target: String,

    #[command(flatten)]
    pub corpus: ProofCorpusArgs,

    /// Execute the known command. Omit this for a dry-run plan.
    #[arg(long, default_value_t = false)]
    pub execute: bool,

    /// Maximum stdout/stderr preview bytes retained in JSON output.
    #[arg(long, default_value_t = DEFAULT_OUTPUT_PREVIEW_BYTES)]
    pub max_output_bytes: usize,
}

/// Structured result returned to the main dispatcher.
#[derive(Debug)]
pub(crate) struct ProofCommandResult {
    pub payload: Value,
    pub success: bool,
}

#[derive(Debug)]
struct LoadedProofGraph {
    source: PathBuf,
    now_unix_ms: u64,
    graph: ProofGraph,
}

#[derive(Debug, Clone)]
struct KnownProofCommand {
    claim_id: ClaimId,
    source_kind: &'static str,
    source_id: String,
    command: RerunCommand,
}

#[derive(Debug, Clone, Serialize)]
struct RankedProofAction {
    rank: usize,
    claim_id: String,
    title: String,
    status: &'static str,
    owner_bead_id: Option<String>,
    required_truth_source: String,
    proof_gap_count: usize,
    strongest_gap_status: Option<&'static str>,
    supporting_evidence_count: usize,
    known_rerun_command: Option<String>,
    score: u32,
    score_inputs: RankedScoreInputs,
    summary: String,
    next_command: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
struct RankedScoreInputs {
    status_weight: u32,
    gap_weight: u32,
    freshness_debt: u32,
    truth_source_weight: u32,
    rerun_weight: u32,
    owner_weight: u32,
}

#[derive(Debug, Clone, Serialize)]
struct PlannedRerunCommand {
    target: String,
    claim_id: String,
    source_kind: &'static str,
    source_id: String,
    command_id: String,
    dry_run: bool,
    requires_remote: bool,
    argv: Vec<String>,
    working_directory: Option<String>,
    required_env_keys: BTreeSet<String>,
    refusal_boundary: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ExecutedProofCommand {
    status_code: Option<i32>,
    success: bool,
    stdout_preview: String,
    stderr_preview: String,
}

/// Run a `fwc proof` subcommand.
pub fn run(args: &ProofArgs) -> Result<ProofCommandResult> {
    match &args.command {
        ProofCommand::Graph(args) => graph(args),
        ProofCommand::Next(args) => next(args),
        ProofCommand::Explain(args) => explain(args),
        ProofCommand::Run(args) => run_known_command(args),
    }
}

fn graph(args: &ProofGraphArgs) -> Result<ProofCommandResult> {
    let loaded = load_graph(&args.corpus)?;
    let source = loaded.source.display().to_string();
    let mut payload = json!({
        "status": "ok",
        "command": "proof",
        "subcommand": "graph",
        "source": source,
        "now_unix_ms": loaded.now_unix_ms,
        "summary": graph_summary(&loaded.graph),
        "graph": loaded.graph,
        "next_actions": [
            "Run `fwc proof next --corpus <path>` to rank the open proof debt.",
            "Run `fwc proof explain <claim> --corpus <path>` to inspect one claim."
        ],
    });
    insert_toon(
        &mut payload,
        "Indexed ProofGraph corpus into a machine-readable graph.",
    );
    Ok(ok(payload))
}

fn next(args: &ProofNextArgs) -> Result<ProofCommandResult> {
    let loaded = load_graph(&args.corpus)?;
    let source = loaded.source.display().to_string();
    let ranked = ranked_actions(&loaded.graph, loaded.now_unix_ms, args.limit);
    let mut payload = json!({
        "status": "ok",
        "command": "proof",
        "subcommand": "next",
        "source": source,
        "now_unix_ms": loaded.now_unix_ms,
        "summary": graph_summary(&loaded.graph),
        "ranking": {
            "limit": args.limit,
            "returned": ranked.len(),
            "deterministic_tie_breakers": [
                "score descending",
                "claim id ascending",
                "rerun command id ascending"
            ],
            "inputs": [
                "claim status",
                "proof gaps",
                "freshness window",
                "truth source rank",
                "owner bead",
                "known redaction-safe rerun command"
            ],
        },
        "actions": ranked,
    });
    insert_toon(
        &mut payload,
        "Ranked ProofGraph proof debt deterministically.",
    );
    Ok(ok(payload))
}

fn explain(args: &ProofExplainArgs) -> Result<ProofCommandResult> {
    let loaded = load_graph(&args.corpus)?;
    let Some(claim_id) = resolve_claim_id(&loaded.graph, &args.claim) else {
        return Ok(validation_error(
            "unknown-claim",
            format!("No ProofGraph claim matches `{}`.", args.claim),
            &loaded.graph,
            &[
                "Use `fwc proof graph --corpus <path> --json` to list claim ids.",
                "Pass either the full `claim:<id>` value or the id without the prefix.",
            ],
        ));
    };
    let claim = loaded
        .graph
        .claims
        .get(claim_id)
        .expect("resolved claim id must exist");
    let evidence = explain_evidence(&loaded.graph, claim_id);
    let evidence_count = evidence.len();
    let actions = actions_for_claim(&loaded.graph, claim_id);
    let source = loaded.source.display().to_string();
    let mut payload = json!({
        "status": "ok",
        "command": "proof",
        "subcommand": "explain",
        "source": source,
        "now_unix_ms": loaded.now_unix_ms,
        "claim": claim,
        "status": status_label(&claim.status),
        "evidence": evidence,
        "suggested_actions": actions,
        "message": format!(
            "Claim `{}` is {} with {} evidence pointer(s) and {} proof gap(s).",
            claim.id,
            status_label(&claim.status),
            evidence_count,
            claim.proof_gaps.len()
        ),
    });
    insert_toon(
        &mut payload,
        "Explained one ProofGraph claim from source-linked evidence.",
    );
    Ok(ok(payload))
}

fn run_known_command(args: &ProofRunArgs) -> Result<ProofCommandResult> {
    let loaded = load_graph(&args.corpus)?;
    let known_commands = known_commands_by_id(&loaded.graph);
    let Some(known) = resolve_known_command(&loaded.graph, &known_commands, &args.target) else {
        return Ok(validation_error(
            "unknown-proof-target",
            format!(
                "`{}` is not a known claim id or redaction-safe rerun command id.",
                args.target
            ),
            &loaded.graph,
            &[
                "Use `fwc proof next --corpus <path> --json` to find runnable proof debt.",
                "Use `fwc proof explain <claim> --corpus <path> --json` to inspect known rerun command ids.",
                "Do not pass arbitrary shell commands; only commands already recorded in the ProofGraph corpus can run.",
            ],
        ));
    };
    let mut plan = build_rerun_plan(&args.target, &known);
    plan.dry_run = !args.execute;
    let execution = if args.execute {
        Some(execute_plan(&plan, args.max_output_bytes)?)
    } else {
        None
    };
    let success = execution.as_ref().map_or(true, |result| result.success);
    let source = loaded.source.display().to_string();
    let mut payload = json!({
        "status": if success { "ok" } else { "error" },
        "command": "proof",
        "subcommand": "run",
        "source": source,
        "now_unix_ms": loaded.now_unix_ms,
        "plan": plan,
        "execution": execution,
        "message": if args.execute {
            "Executed a known redaction-safe ProofGraph rerun command."
        } else {
            "Dry-run only. Re-run with `--execute` to execute this known command."
        },
    });
    insert_toon(
        &mut payload,
        "Prepared a fail-closed ProofGraph rerun plan.",
    );
    Ok(ProofCommandResult { payload, success })
}

fn load_graph(args: &ProofCorpusArgs) -> Result<LoadedProofGraph> {
    let file = File::open(&args.corpus)
        .with_context(|| format!("opening ProofGraph corpus `{}`", args.corpus.display()))?;
    let corpus: ProofGraphCorpus = serde_json::from_reader(file)
        .with_context(|| format!("parsing ProofGraph corpus `{}`", args.corpus.display()))?;
    let now_unix_ms = args.now_unix_ms.unwrap_or_else(current_unix_ms);
    let graph = ProofGraphIndexer::new(now_unix_ms)
        .index(&corpus)
        .with_context(|| format!("indexing ProofGraph corpus `{}`", args.corpus.display()))?;
    Ok(LoadedProofGraph {
        source: args.corpus.clone(),
        now_unix_ms,
        graph,
    })
}

fn current_unix_ms() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

fn graph_summary(graph: &ProofGraph) -> Value {
    let mut statuses = BTreeMap::<&'static str, usize>::new();
    for claim in graph.claims.values() {
        *statuses.entry(status_label(&claim.status)).or_default() += 1;
    }
    json!({
        "schema": graph.schema.as_str(),
        "claims": graph.claims.len(),
        "evidence": graph.evidence.len(),
        "support_edges": graph.support_edges.len(),
        "suggested_next_actions": graph.suggested_next_actions.len(),
        "claim_statuses": statuses,
    })
}

fn ranked_actions(graph: &ProofGraph, now_unix_ms: u64, limit: usize) -> Vec<RankedProofAction> {
    let commands = known_commands_by_claim(graph);
    let mut ranked = graph
        .claims
        .values()
        .map(|claim| ranked_action(graph, &commands, claim, now_unix_ms))
        .collect::<Vec<_>>();
    ranked.sort_by_key(|action| {
        (
            Reverse(action.score),
            action.claim_id.clone(),
            action.known_rerun_command.clone(),
        )
    });
    ranked.truncate(limit);
    for (index, action) in ranked.iter_mut().enumerate() {
        action.rank = index + 1;
    }
    ranked
}

fn ranked_action(
    graph: &ProofGraph,
    commands: &BTreeMap<ClaimId, Vec<KnownProofCommand>>,
    claim: &ClaimNode,
    now_unix_ms: u64,
) -> RankedProofAction {
    let status_weight = status_weight(&claim.status);
    let gap_weight = claim
        .proof_gaps
        .iter()
        .map(|gap| gap_status_weight(gap.status))
        .max()
        .unwrap_or(0);
    let freshness_debt = if claim.freshness.is_fresh_at(now_unix_ms) {
        0
    } else {
        15
    };
    let truth_source_weight = u32::from(claim.required_truth_source.rank()) * 4;
    let command = commands.get(&claim.id).and_then(|items| items.first());
    let rerun_weight = command.map_or(0, |_| 12);
    let owner_weight = claim.owner.as_ref().map_or(0, |_| 3);
    let inputs = RankedScoreInputs {
        status_weight,
        gap_weight,
        freshness_debt,
        truth_source_weight,
        rerun_weight,
        owner_weight,
    };
    let score = inputs.status_weight
        + inputs.gap_weight
        + inputs.freshness_debt
        + inputs.truth_source_weight
        + inputs.rerun_weight
        + inputs.owner_weight;
    let strongest_gap_status = claim
        .proof_gaps
        .iter()
        .max_by_key(|gap| gap_status_weight(gap.status))
        .map(|gap| gap_status_label(gap.status));

    RankedProofAction {
        rank: 0,
        claim_id: claim.id.to_string(),
        title: claim.title.clone(),
        status: status_label(&claim.status),
        owner_bead_id: claim.owner.as_ref().map(|owner| owner.bead_id.clone()),
        required_truth_source: claim.required_truth_source.as_str().to_owned(),
        proof_gap_count: claim.proof_gaps.len(),
        strongest_gap_status,
        supporting_evidence_count: supporting_evidence_count(graph, &claim.id),
        known_rerun_command: command.map(|known| known.command.id.to_string()),
        score,
        score_inputs: inputs,
        summary: next_summary(claim, command),
        next_command: command.map(|known| build_rerun_plan(claim.id.as_str(), known).argv),
    }
}

fn next_summary(claim: &ClaimNode, command: Option<&KnownProofCommand>) -> String {
    if let Some(gap) = claim.proof_gaps.first() {
        return command.map_or_else(
            || format!("Close proof gap `{}`: {}", gap.id, gap.summary),
            |known| {
                format!(
                    "Rerun `{}` to close proof gap `{}`: {}",
                    known.command.id, gap.id, gap.summary
                )
            },
        );
    }
    command.map_or_else(
        || {
            format!(
                "Review claim `{}` status `{}`.",
                claim.id,
                status_label(&claim.status)
            )
        },
        |known| {
            format!(
                "Rerun `{}` to refresh claim `{}`.",
                known.command.id, claim.id
            )
        },
    )
}

fn explain_evidence(graph: &ProofGraph, claim_id: &ClaimId) -> Vec<Value> {
    graph
        .support_edges
        .iter()
        .filter(|edge| &edge.claim_id == claim_id)
        .filter_map(|edge| {
            graph.evidence.get(&edge.evidence_id).map(|evidence| {
                json!({
                    "evidence_id": evidence.id,
                    "relationship": relationship_label(edge.relationship),
                    "rationale": edge.rationale,
                    "kind": evidence.kind,
                    "truth_source": evidence.truth_source,
                    "source_ref": evidence.source_ref,
                    "summary": evidence.summary,
                    "rerun_command": evidence.rerun_command,
                })
            })
        })
        .collect()
}

fn actions_for_claim(graph: &ProofGraph, claim_id: &ClaimId) -> Vec<Value> {
    graph
        .suggested_next_actions
        .iter()
        .filter(|action| &action.claim_id == claim_id)
        .map(|action| {
            json!({
                "id": action.id,
                "summary": action.summary,
                "rerun_command": action.rerun_command,
            })
        })
        .collect()
}

fn supporting_evidence_count(graph: &ProofGraph, claim_id: &ClaimId) -> usize {
    graph
        .support_edges
        .iter()
        .filter(|edge| {
            &edge.claim_id == claim_id
                && matches!(
                    edge.relationship,
                    SupportRelationship::Supports | SupportRelationship::PartiallySupports
                )
        })
        .count()
}

fn known_commands_by_id(graph: &ProofGraph) -> BTreeMap<String, KnownProofCommand> {
    let mut commands = BTreeMap::new();
    for command in known_commands(graph) {
        commands
            .entry(command.command.id.to_string())
            .or_insert(command);
    }
    commands
}

fn known_commands_by_claim(graph: &ProofGraph) -> BTreeMap<ClaimId, Vec<KnownProofCommand>> {
    let mut commands = BTreeMap::<ClaimId, Vec<KnownProofCommand>>::new();
    for command in known_commands(graph) {
        commands
            .entry(command.claim_id.clone())
            .or_default()
            .push(command);
    }
    for per_claim in commands.values_mut() {
        per_claim.sort_by_key(|known| {
            (
                Reverse(command_priority(&known.command)),
                known.command.id.clone(),
            )
        });
    }
    commands
}

fn known_commands(graph: &ProofGraph) -> Vec<KnownProofCommand> {
    let mut commands = Vec::new();
    for action in &graph.suggested_next_actions {
        if let Some(command) = &action.rerun_command {
            commands.push(KnownProofCommand {
                claim_id: action.claim_id.clone(),
                source_kind: "suggested_action",
                source_id: action.id.to_string(),
                command: command.clone(),
            });
        }
    }
    for edge in &graph.support_edges {
        if let Some(evidence) = graph.evidence.get(&edge.evidence_id) {
            if let Some(command) = &evidence.rerun_command {
                commands.push(KnownProofCommand {
                    claim_id: edge.claim_id.clone(),
                    source_kind: "evidence",
                    source_id: evidence.id.to_string(),
                    command: command.clone(),
                });
            }
        }
    }
    commands.sort_by_key(|known| {
        (
            known.claim_id.clone(),
            Reverse(command_priority(&known.command)),
            known.command.id.clone(),
            known.source_id.clone(),
        )
    });
    commands
}

fn resolve_known_command(
    graph: &ProofGraph,
    commands: &BTreeMap<String, KnownProofCommand>,
    target: &str,
) -> Option<KnownProofCommand> {
    if let Some(command) = commands.get(target) {
        return Some(command.clone());
    }
    let claim_id = resolve_claim_id(graph, target)?;
    known_commands(graph)
        .into_iter()
        .find(|known| &known.claim_id == claim_id)
}

fn build_rerun_plan(target: &str, known: &KnownProofCommand) -> PlannedRerunCommand {
    let requires_remote = known.command.requires_rch || is_cargo_command(&known.command.argv);
    let argv = if requires_remote && !already_rch_wrapped(&known.command.argv) {
        remote_argv(
            &known.command.argv,
            &safe_target_slug(&known.claim_id.to_string()),
        )
    } else {
        known.command.argv.clone()
    };
    PlannedRerunCommand {
        target: target.to_owned(),
        claim_id: known.claim_id.to_string(),
        source_kind: known.source_kind,
        source_id: known.source_id.clone(),
        command_id: known.command.id.to_string(),
        dry_run: true,
        requires_remote,
        argv,
        working_directory: known.command.working_directory.clone(),
        required_env_keys: known.command.required_env_keys.clone(),
        refusal_boundary: "Only redaction-safe commands already present in the ProofGraph corpus are accepted.",
    }
}

fn remote_argv(original: &[String], target_slug: &str) -> Vec<String> {
    let mut argv = vec![
        "env".to_owned(),
        "RCH_FORCE_REMOTE=true".to_owned(),
        "RCH_VISIBILITY=summary".to_owned(),
        "rch".to_owned(),
        "exec".to_owned(),
        "--".to_owned(),
        "env".to_owned(),
        format!("CARGO_TARGET_DIR=/tmp/fwc-proof-{target_slug}"),
        "CARGO_INCREMENTAL=0".to_owned(),
    ];
    argv.extend(original.iter().cloned());
    argv
}

fn execute_plan(
    plan: &PlannedRerunCommand,
    max_output_bytes: usize,
) -> Result<ExecutedProofCommand> {
    let Some(program) = plan.argv.first() else {
        bail!("ProofGraph rerun plan had an empty argv vector");
    };
    let mut command = ProcessCommand::new(program);
    command.args(&plan.argv[1..]);
    if let Some(working_directory) = &plan.working_directory {
        command.current_dir(Path::new(working_directory));
    }
    let output = command.output().with_context(|| {
        format!(
            "executing known ProofGraph rerun command `{}`",
            plan.command_id
        )
    })?;
    Ok(ExecutedProofCommand {
        status_code: output.status.code(),
        success: output.status.success(),
        stdout_preview: preview_bytes(&output.stdout, max_output_bytes),
        stderr_preview: preview_bytes(&output.stderr, max_output_bytes),
    })
}

fn preview_bytes(bytes: &[u8], limit: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.len() <= limit {
        return text.into_owned();
    }
    let mut preview = text.chars().take(limit).collect::<String>();
    preview.push_str("\n[truncated]");
    preview
}

fn resolve_claim_id<'a>(graph: &'a ProofGraph, target: &str) -> Option<&'a ClaimId> {
    graph
        .claims
        .keys()
        .find(|id| id.as_str() == target || id.as_str().strip_prefix("claim:") == Some(target))
}

fn validation_error(
    error_type: &'static str,
    message: String,
    graph: &ProofGraph,
    next_actions: &[&str],
) -> ProofCommandResult {
    let mut payload = json!({
        "status": "error",
        "command": "proof",
        "error": {
            "type": error_type,
            "message": message,
            "recoverable": true,
            "known_claim_ids": graph.claims.keys().map(ToString::to_string).collect::<Vec<_>>(),
            "known_rerun_command_ids": known_commands_by_id(graph).keys().cloned().collect::<Vec<_>>(),
            "next_actions": next_actions,
        },
    });
    insert_toon(
        &mut payload,
        "Proof command refused an unknown or unsafe target.",
    );
    ProofCommandResult {
        payload,
        success: false,
    }
}

fn ok(payload: Value) -> ProofCommandResult {
    ProofCommandResult {
        payload,
        success: true,
    }
}

fn insert_toon(payload: &mut Value, message: &str) {
    if let Some(object) = payload.as_object_mut() {
        object.insert("toon".to_owned(), Value::String(message.to_owned()));
    }
}

fn status_label(status: &ClaimStatus) -> &'static str {
    match status {
        ClaimStatus::Proven => "proven",
        ClaimStatus::Failed { .. } => "failed",
        ClaimStatus::Stale { .. } => "stale",
        ClaimStatus::Missing => "missing",
        ClaimStatus::Blocked { .. } => "blocked",
        ClaimStatus::SkippedWithReason { .. } => "skipped_with_reason",
    }
}

fn status_weight(status: &ClaimStatus) -> u32 {
    match status {
        ClaimStatus::Failed { .. } => 100,
        ClaimStatus::Missing => 90,
        ClaimStatus::Stale { .. } => 80,
        ClaimStatus::Blocked { .. } => 70,
        ClaimStatus::SkippedWithReason { .. } => 50,
        ClaimStatus::Proven => 5,
    }
}

fn gap_status_label(status: ProofGapStatus) -> &'static str {
    match status {
        ProofGapStatus::Failed => "failed",
        ProofGapStatus::Missing => "missing",
        ProofGapStatus::Stale => "stale",
        ProofGapStatus::Blocked => "blocked",
        ProofGapStatus::SkippedWithReason => "skipped_with_reason",
    }
}

fn gap_status_weight(status: ProofGapStatus) -> u32 {
    match status {
        ProofGapStatus::Failed => 70,
        ProofGapStatus::Missing => 60,
        ProofGapStatus::Stale => 50,
        ProofGapStatus::Blocked => 40,
        ProofGapStatus::SkippedWithReason => 20,
    }
}

fn relationship_label(relationship: SupportRelationship) -> &'static str {
    match relationship {
        SupportRelationship::Supports => "supports",
        SupportRelationship::Contradicts => "contradicts",
        SupportRelationship::PartiallySupports => "partially_supports",
        SupportRelationship::DoesNotSupport => "does_not_support",
    }
}

fn is_cargo_command(argv: &[String]) -> bool {
    argv.iter().any(|arg| arg == "cargo")
}

fn already_rch_wrapped(argv: &[String]) -> bool {
    argv.iter().any(|arg| arg == "rch")
}

fn command_priority(command: &RerunCommand) -> u8 {
    if command.requires_rch || is_cargo_command(&command.argv) {
        2
    } else if !command.argv.is_empty() {
        1
    } else {
        0
    }
}

fn safe_target_slug(value: &str) -> String {
    let slug = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned();
    if slug.is_empty() {
        "proof".to_owned()
    } else {
        slug
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use fcp_evidence::{
        BeadIssueRecord, EvidenceBundleRecord, PROOF_GRAPH_INDEXER_CORPUS_SCHEMA,
        ReadinessMatrixRow, ReadmeFeatureRow, SourceLocation, TruthSource,
        VerificationScriptRecord,
    };
    use tempfile::NamedTempFile;

    use super::*;

    const NOW: u64 = 1_750_000_000_000;
    const DAY_MS: u64 = 24 * 60 * 60 * 1_000;

    fn corpus_args(path: &Path) -> ProofCorpusArgs {
        ProofCorpusArgs {
            corpus: path.to_path_buf(),
            now_unix_ms: Some(NOW),
        }
    }

    fn source(path: &str, line: u32) -> SourceLocation {
        SourceLocation {
            source_id: format!("source:{line}"),
            path: path.to_owned(),
            line: Some(line),
        }
    }

    fn readme_row(claim_key: &str, feature: &str, status: &str, line: u32) -> ReadmeFeatureRow {
        ReadmeFeatureRow {
            claim_key: claim_key.to_owned(),
            feature: feature.to_owned(),
            status: status.to_owned(),
            summary: format!("{feature} proof status"),
            evidence_summary: "redaction-safe evidence summary".to_owned(),
            source: source("README.md", line),
        }
    }

    fn issue(claim_key: &str, id: &str, updated_at_unix_ms: u64) -> BeadIssueRecord {
        BeadIssueRecord {
            id: id.to_owned(),
            claim_key: claim_key.to_owned(),
            title: format!("{claim_key} proof bead"),
            status: "open".to_owned(),
            priority: 1,
            acceptance_summary: "Acceptance requires rerunnable proof".to_owned(),
            labels: BTreeSet::from(["proofgraph".to_owned()]),
            assignee: Some("Codex".to_owned()),
            updated_at_unix_ms,
            source: source(".beads/issues.jsonl", 10),
            proof_comments: Vec::new(),
        }
    }

    fn fixture_corpus() -> ProofGraphCorpus {
        ProofGraphCorpus {
            schema: PROOF_GRAPH_INDEXER_CORPUS_SCHEMA.to_owned(),
            readme_rows: vec![
                readme_row("latency-proof", "Latency Proof", "NOT YET", 10),
                readme_row("stable-proof", "Stable Proof", "PROVEN", 11),
            ],
            bead_issues: vec![issue(
                "latency-proof",
                "flywheel_connectors-b88ec.3",
                NOW - DAY_MS,
            )],
            verification_scripts: vec![VerificationScriptRecord {
                claim_key: "latency-proof".to_owned(),
                script_path: "crates/fwc/tests/proof_latency.rs".to_owned(),
                purpose: "Run latency proof command".to_owned(),
                rerun_argv: vec![
                    "cargo".to_owned(),
                    "test".to_owned(),
                    "-p".to_owned(),
                    "fcp-evidence".to_owned(),
                    "proof_graph_indexer".to_owned(),
                    "--lib".to_owned(),
                ],
                required_env_keys: BTreeSet::new(),
                source: source("crates/fwc/tests/proof_latency.rs", 1),
            }],
            readiness_rows: vec![ReadinessMatrixRow {
                claim_key: "stable-proof".to_owned(),
                subject: "stable-proof-readiness".to_owned(),
                state: "pass".to_owned(),
                truth_source: TruthSource::HostBacked,
                rerun_argv: None,
                source: source("crates/fwc/tests/readiness.rs", 2),
            }],
            evidence_bundles: vec![EvidenceBundleRecord {
                claim_key: "latency-proof".to_owned(),
                scenario_id: "latency-proof-bundle".to_owned(),
                bundle_path: "artifacts/e2e/latency-proof/latest".to_owned(),
                redaction_safe: true,
                command_count: 1,
                live_count: 0,
                offline_count: 1,
                validation_argv: None,
                source: source("artifacts/e2e/latency-proof/manifest.json", 1),
            }],
        }
    }

    fn write_corpus(corpus: &ProofGraphCorpus) -> NamedTempFile {
        let file = NamedTempFile::new().expect("create temp corpus");
        let bytes = serde_json::to_vec_pretty(corpus).expect("serialize corpus");
        std::fs::write(file.path(), bytes).expect("write corpus");
        file
    }

    #[test]
    fn graph_outputs_machine_readable_claim_ids_and_evidence_counts() {
        let file = write_corpus(&fixture_corpus());
        let result = run(&ProofArgs {
            command: ProofCommand::Graph(ProofGraphArgs {
                corpus: corpus_args(file.path()),
            }),
        })
        .expect("run proof graph");

        assert!(result.success);
        assert_eq!(result.payload["status"], "ok");
        assert!(result.payload["graph"]["claims"]["claim:latency-proof"].is_object());
        assert_eq!(result.payload["summary"]["claims"], 2);
    }

    #[test]
    fn next_ranking_is_deterministic_and_prioritizes_missing_claims() {
        let file = write_corpus(&fixture_corpus());
        let args = ProofArgs {
            command: ProofCommand::Next(ProofNextArgs {
                corpus: corpus_args(file.path()),
                limit: 2,
            }),
        };

        let first = run(&args).expect("first next");
        let second = run(&args).expect("second next");

        assert_eq!(first.payload["actions"], second.payload["actions"]);
        assert_eq!(
            first.payload["actions"][0]["claim_id"],
            "claim:latency-proof"
        );
    }

    #[test]
    fn explain_unknown_claim_returns_validation_payload() {
        let file = write_corpus(&fixture_corpus());
        let result = run(&ProofArgs {
            command: ProofCommand::Explain(ProofExplainArgs {
                claim: "missing-claim".to_owned(),
                corpus: corpus_args(file.path()),
            }),
        })
        .expect("run proof explain");

        assert!(!result.success);
        assert_eq!(result.payload["error"]["type"], "unknown-claim");
        assert!(
            result.payload["error"]["known_claim_ids"]
                .as_array()
                .expect("known claims array")
                .iter()
                .any(|value| value == "claim:latency-proof")
        );
    }

    #[test]
    fn run_refuses_unknown_arbitrary_command_target() {
        let file = write_corpus(&fixture_corpus());
        let result = run(&ProofArgs {
            command: ProofCommand::Run(ProofRunArgs {
                target: "cargo test --workspace".to_owned(),
                corpus: corpus_args(file.path()),
                execute: false,
                max_output_bytes: DEFAULT_OUTPUT_PREVIEW_BYTES,
            }),
        })
        .expect("run proof run");

        assert!(!result.success);
        assert_eq!(result.payload["error"]["type"], "unknown-proof-target");
    }

    #[test]
    fn run_constructs_remote_rch_wrapper_for_cargo_rerun() {
        let file = write_corpus(&fixture_corpus());
        let result = run(&ProofArgs {
            command: ProofCommand::Run(ProofRunArgs {
                target: "claim:latency-proof".to_owned(),
                corpus: corpus_args(file.path()),
                execute: false,
                max_output_bytes: DEFAULT_OUTPUT_PREVIEW_BYTES,
            }),
        })
        .expect("run proof run");

        assert!(result.success);
        assert_eq!(result.payload["plan"]["requires_remote"], true);
        let argv = result.payload["plan"]["argv"]
            .as_array()
            .expect("argv array")
            .iter()
            .map(|value| value.as_str().expect("argv string"))
            .collect::<Vec<_>>();
        assert_eq!(argv[0], "env");
        assert!(argv.contains(&"rch"));
        assert!(argv.contains(&"CARGO_INCREMENTAL=0"));
        assert!(
            argv.iter()
                .any(|arg| arg.starts_with("CARGO_TARGET_DIR=/tmp/fwc-proof-"))
        );
    }
}
