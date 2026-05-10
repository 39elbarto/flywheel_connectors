//! `fwc proof` command family backed by the redaction-safe ProofGraph schema.
//!
//! This module is intentionally corpus-driven. It does not scrape Markdown,
//! Beads JSONL, or shell transcripts directly; callers hand it a structured
//! `ProofGraphCorpus` so the command surface can stay deterministic and
//! redaction-safe.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use fcp_evidence::{
    ClaimId, ClaimNode, ClaimStatus, EvidenceKind, EvidenceNode, ProofGapStatus, ProofGraph,
    ProofGraphCorpus, ProofGraphIndexer, RerunCommand, SupportEdge, SupportRelationship,
};
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode, OperationSection};
use serde::Serialize;
use serde_json::{Value, json};

use crate::readiness::{idempotency_label, risk_level_label, safety_tier_label};

const CAPABILITY_PASSPORT_SCHEMA: &str = "fcp.capability-passport.v1";
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
    /// Generate connector capability passports from manifests and proof state.
    Passport(ProofPassportArgs),
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

/// Arguments for `fwc proof passport`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct ProofPassportArgs {
    #[command(flatten)]
    pub corpus: ProofCorpusArgs,

    /// Connector manifest files to summarize into passports.
    #[arg(long = "manifest", value_name = "PATH", required = true)]
    pub manifests: Vec<PathBuf>,

    /// Optional connector selector. Matches manifest slug, connector id, or name.
    #[arg(long, value_name = "CONNECTOR")]
    pub connector: Option<String>,
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

#[derive(Debug, Clone)]
struct LoadedManifest {
    path: PathBuf,
    manifest: ConnectorManifest,
}

#[derive(Debug, Clone, Serialize)]
struct CapabilityPassport {
    schema_version: &'static str,
    connector: PassportConnector,
    provenance: Vec<PassportProvenance>,
    capabilities: PassportCapabilities,
    zones: PassportZones,
    sandbox: PassportSandbox,
    operations: Vec<PassportOperation>,
    proof_state: PassportProofState,
    proof_signals: PassportProofSignals,
    risk_summary: PassportRiskSummary,
    gaps: Vec<PassportGap>,
}

#[derive(Debug, Clone, Serialize)]
struct PassportConnector {
    id: String,
    slug: String,
    name: String,
    version: String,
    status: String,
    runtime_format: String,
    archetypes: Vec<String>,
    state_model: Value,
    hidden_by_default: bool,
    non_live_rationale: Option<&'static str>,
    graduation_guidance: Option<&'static str>,
    manifest_path: String,
}

#[derive(Debug, Clone, Serialize)]
struct PassportProvenance {
    field: &'static str,
    source: &'static str,
    source_ref: String,
}

#[derive(Debug, Clone, Serialize)]
struct PassportCapabilities {
    required: Vec<String>,
    optional: Vec<String>,
    forbidden: Vec<String>,
    operation_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PassportZones {
    home: String,
    allowed_sources: Vec<String>,
    allowed_targets: Vec<String>,
    forbidden: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PassportSandbox {
    profile: String,
    memory_mb: u32,
    cpu_percent: u8,
    wall_clock_timeout_ms: u64,
    readonly_path_count: usize,
    writable_path_count: usize,
    deny_exec: bool,
    deny_ptrace: bool,
    posture: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct PassportOperation {
    id: String,
    capability: String,
    risk_level: &'static str,
    safety_tier: &'static str,
    requires_approval: &'static str,
    idempotency: &'static str,
    input_schema_state: &'static str,
    output_schema_state: &'static str,
    network_posture: PassportNetworkPosture,
    ai_hints_state: PassportAiHintsState,
}

#[derive(Debug, Clone, Serialize)]
struct PassportNetworkPosture {
    state: &'static str,
    host_allow_count: usize,
    port_allow: Vec<u16>,
    deny_localhost: Option<bool>,
    deny_private_ranges: Option<bool>,
    deny_tailnet_ranges: Option<bool>,
    require_sni: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
struct PassportAiHintsState {
    state: &'static str,
    has_when_to_use: bool,
    common_mistake_count: usize,
    example_count: usize,
    related_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct PassportProofState {
    state: String,
    matched_claim_ids: Vec<String>,
    required_truth_sources: Vec<String>,
    fresh_claim_ids: Vec<String>,
    stale_claim_ids: Vec<String>,
    evidence_by_kind: BTreeMap<String, usize>,
    proof_gap_count: usize,
    supporting_evidence_count: usize,
    known_rerun_command_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PassportProofSignals {
    readme_contract: PassportProofSignal,
    secretless_readiness: PassportProofSignal,
    host_or_introspection: PassportProofSignal,
}

#[derive(Debug, Clone, Serialize)]
struct PassportProofSignal {
    state: &'static str,
    matched_claim_ids: Vec<String>,
    evidence_count: usize,
    source_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PassportRiskSummary {
    max_risk_level: &'static str,
    max_safety_tier: &'static str,
    operation_count: usize,
    approval_required_count: usize,
    network_posture_gap_count: usize,
    ai_hints_gap_count: usize,
    proof_gap_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct PassportGap {
    category: &'static str,
    status: &'static str,
    summary: String,
    target_truth_source: String,
    provenance: PassportProvenance,
}

/// Run a `fwc proof` subcommand.
pub fn run(args: &ProofArgs) -> Result<ProofCommandResult> {
    match &args.command {
        ProofCommand::Graph(args) => graph(args),
        ProofCommand::Next(args) => next(args),
        ProofCommand::Explain(args) => explain(args),
        ProofCommand::Run(args) => run_known_command(args),
        ProofCommand::Passport(args) => passport(args),
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

fn passport(args: &ProofPassportArgs) -> Result<ProofCommandResult> {
    let loaded = load_graph(&args.corpus)?;
    let manifests = load_passport_manifests(&args.manifests)?;
    let selected = select_passport_manifests(&manifests, args.connector.as_deref());
    if selected.is_empty() {
        return Ok(passport_selection_error(
            args.connector.as_deref(),
            &manifests,
            &loaded.graph,
        ));
    }

    let passports = selected
        .into_iter()
        .map(|manifest| build_capability_passport(manifest, &loaded.graph, loaded.now_unix_ms))
        .collect::<Result<Vec<_>>>()?;
    let summary = passport_summary(&passports);
    let source = loaded.source.display().to_string();
    let mut payload = json!({
        "status": "ok",
        "command": "proof",
        "subcommand": "passport",
        "schema_version": CAPABILITY_PASSPORT_SCHEMA,
        "source": source,
        "now_unix_ms": loaded.now_unix_ms,
        "summary": summary,
        "passports": passports,
        "next_actions": [
            "Use `fwc proof explain <claim> --corpus <path> --json` for detailed proof evidence.",
            "Treat every passport gap as proof debt; do not infer missing schema, network, or runtime state."
        ],
    });
    insert_toon(
        &mut payload,
        "Generated manifest-backed connector capability passports with ProofGraph gap routing.",
    );
    Ok(ok(payload))
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

fn load_passport_manifests(paths: &[PathBuf]) -> Result<Vec<LoadedManifest>> {
    paths
        .iter()
        .map(|path| {
            let raw = fs::read_to_string(path)
                .with_context(|| format!("reading connector manifest `{}`", path.display()))?;
            let manifest = ConnectorManifest::parse_str_unchecked(&raw)
                .with_context(|| format!("parsing connector manifest `{}`", path.display()))?;
            Ok(LoadedManifest {
                path: path.clone(),
                manifest,
            })
        })
        .collect()
}

fn select_passport_manifests<'a>(
    manifests: &'a [LoadedManifest],
    connector: Option<&str>,
) -> Vec<&'a LoadedManifest> {
    let Some(connector) = connector else {
        return manifests.iter().collect();
    };
    let selector = normalize_passport_selector(connector);
    manifests
        .iter()
        .filter(|manifest| passport_manifest_selectors(manifest).contains(&selector))
        .collect()
}

fn passport_selection_error(
    connector: Option<&str>,
    manifests: &[LoadedManifest],
    graph: &ProofGraph,
) -> ProofCommandResult {
    let mut payload = json!({
        "status": "error",
        "command": "proof",
        "subcommand": "passport",
        "schema_version": CAPABILITY_PASSPORT_SCHEMA,
        "error": {
            "type": "unknown-connector",
            "message": connector.map_or_else(
                || "No connector manifests were supplied.".to_owned(),
                |value| format!("No supplied manifest matches connector selector `{value}`.")
            ),
            "recoverable": true,
            "known_connectors": manifests
                .iter()
                .map(|manifest| manifest.manifest.connector.id.as_str().to_owned())
                .collect::<Vec<_>>(),
            "known_claim_ids": graph.claims.keys().map(ToString::to_string).collect::<Vec<_>>(),
            "next_actions": [
                "Pass one or more `--manifest <path>` values.",
                "Use a connector id, slug, or connector name already present in the supplied manifests."
            ],
        },
    });
    insert_toon(
        &mut payload,
        "Proof passport refused an unknown connector selector.",
    );
    ProofCommandResult {
        payload,
        success: false,
    }
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

fn build_capability_passport(
    loaded: &LoadedManifest,
    graph: &ProofGraph,
    now_unix_ms: u64,
) -> Result<CapabilityPassport> {
    let manifest = &loaded.manifest;
    let manifest_path = loaded.path.display().to_string();
    let slug = connector_slug(manifest.connector.id.as_str());
    let operations = manifest
        .provides
        .operations
        .iter()
        .map(|(operation_id, operation)| passport_operation(operation_id, operation))
        .collect::<Result<Vec<_>>>()?;
    let selectors = passport_manifest_selectors(loaded);
    let proof_state = passport_proof_state(graph, &selectors, now_unix_ms);
    let proof_signals = passport_proof_signals(graph, &selectors);
    let capabilities = PassportCapabilities {
        required: capability_strings(&manifest.capabilities.required),
        optional: capability_strings(&manifest.capabilities.optional),
        forbidden: capability_strings(&manifest.capabilities.forbidden),
        operation_capabilities: operation_capabilities(&operations),
    };
    let zones = PassportZones {
        home: manifest.zones.home.as_str().to_owned(),
        allowed_sources: manifest
            .zones
            .allowed_sources
            .iter()
            .map(|zone| zone.as_str().to_owned())
            .collect(),
        allowed_targets: manifest
            .zones
            .allowed_targets
            .iter()
            .map(|zone| zone.as_str().to_owned())
            .collect(),
        forbidden: manifest
            .zones
            .forbidden
            .iter()
            .map(|zone| zone.as_str().to_owned())
            .collect(),
    };
    let sandbox = PassportSandbox {
        profile: manifest_enum_label(&manifest.sandbox.profile)?,
        memory_mb: manifest.sandbox.memory_mb,
        cpu_percent: manifest.sandbox.cpu_percent,
        wall_clock_timeout_ms: manifest.sandbox.wall_clock_timeout_ms,
        readonly_path_count: manifest.sandbox.fs_readonly_paths.len(),
        writable_path_count: manifest.sandbox.fs_writable_paths.len(),
        deny_exec: manifest.sandbox.deny_exec,
        deny_ptrace: manifest.sandbox.deny_ptrace,
        posture: sandbox_posture(manifest),
    };
    let mut provenance = vec![
        PassportProvenance {
            field: "connector",
            source: "manifest",
            source_ref: manifest_path.clone(),
        },
        PassportProvenance {
            field: "capabilities",
            source: "manifest",
            source_ref: manifest_path.clone(),
        },
        PassportProvenance {
            field: "proof_state",
            source: "proof_graph",
            source_ref: graph.schema.clone(),
        },
    ];
    provenance.sort_by_key(|item| (item.field, item.source, item.source_ref.clone()));

    let gaps = passport_gaps(loaded, graph, &operations, &proof_state);
    let risk_summary = passport_risk_summary(&operations, proof_state.proof_gap_count);
    let state_model = manifest
        .connector
        .state
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?
        .unwrap_or_else(|| json!({"status": "not_declared"}));

    Ok(CapabilityPassport {
        schema_version: CAPABILITY_PASSPORT_SCHEMA,
        connector: PassportConnector {
            id: manifest.connector.id.as_str().to_owned(),
            slug,
            name: manifest.connector.name.clone(),
            version: manifest.connector.version.to_string(),
            status: manifest.connector.status.to_string(),
            runtime_format: runtime_format_label(&manifest.connector.format)?,
            archetypes: manifest
                .connector
                .archetypes
                .iter()
                .map(|archetype| archetype.as_str().to_owned())
                .collect(),
            state_model,
            hidden_by_default: manifest.connector.status.is_hidden_by_default(),
            non_live_rationale: manifest.connector.status.non_live_rationale(),
            graduation_guidance: manifest.connector.status.graduation_guidance(),
            manifest_path,
        },
        provenance,
        capabilities,
        zones,
        sandbox,
        operations,
        proof_state,
        proof_signals,
        risk_summary,
        gaps,
    })
}

fn passport_operation(
    operation_id: &str,
    operation: &OperationSection,
) -> Result<PassportOperation> {
    Ok(PassportOperation {
        id: operation_id.to_owned(),
        capability: operation.capability.as_str().to_owned(),
        risk_level: risk_level_label(operation.risk_level),
        safety_tier: safety_tier_label(operation.safety_tier),
        requires_approval: approval_mode_label(operation.requires_approval),
        idempotency: idempotency_label(operation.idempotency),
        input_schema_state: schema_state(&operation.input_schema),
        output_schema_state: schema_state(&operation.output_schema),
        network_posture: network_posture(operation),
        ai_hints_state: ai_hints_state(operation),
    })
}

fn passport_proof_state(
    graph: &ProofGraph,
    selectors: &BTreeSet<String>,
    now_unix_ms: u64,
) -> PassportProofState {
    let matched_claims = graph
        .claims
        .values()
        .filter(|claim| claim_matches_connector(claim, selectors))
        .collect::<Vec<_>>();
    let commands = known_commands_by_claim(graph);
    let mut claim_ids = Vec::new();
    let mut truth_sources = BTreeSet::new();
    let mut known_rerun_command_ids = BTreeSet::new();
    let mut fresh_claim_ids = Vec::new();
    let mut stale_claim_ids = Vec::new();
    let mut proof_gap_count = 0;
    let mut supporting_count = 0;
    let mut evidence_by_kind = BTreeMap::new();
    let state = matched_claims
        .iter()
        .max_by_key(|claim| status_weight(&claim.status))
        .map_or_else(
            || "unmatched".to_owned(),
            |claim| status_label(&claim.status).to_owned(),
        );

    for claim in matched_claims {
        claim_ids.push(claim.id.to_string());
        truth_sources.insert(claim.required_truth_source.as_str().to_owned());
        if claim.freshness.is_fresh_at(now_unix_ms) {
            fresh_claim_ids.push(claim.id.to_string());
        } else {
            stale_claim_ids.push(claim.id.to_string());
        }
        proof_gap_count += claim.proof_gaps.len();
        supporting_count += supporting_evidence_count(graph, &claim.id);
        for edge in graph
            .support_edges
            .iter()
            .filter(|edge| edge.claim_id == claim.id)
        {
            if let Some(evidence) = graph.evidence.get(&edge.evidence_id) {
                *evidence_by_kind
                    .entry(evidence_kind_label(evidence.kind).to_owned())
                    .or_insert(0) += 1;
            }
        }
        if let Some(per_claim) = commands.get(&claim.id) {
            for command in per_claim {
                known_rerun_command_ids.insert(command.command.id.to_string());
            }
        }
    }

    claim_ids.sort();
    fresh_claim_ids.sort();
    stale_claim_ids.sort();
    PassportProofState {
        state,
        matched_claim_ids: claim_ids,
        required_truth_sources: truth_sources.into_iter().collect(),
        fresh_claim_ids,
        stale_claim_ids,
        evidence_by_kind,
        proof_gap_count,
        supporting_evidence_count: supporting_count,
        known_rerun_command_ids: known_rerun_command_ids.into_iter().collect(),
    }
}

fn passport_proof_signals(
    graph: &ProofGraph,
    selectors: &BTreeSet<String>,
) -> PassportProofSignals {
    PassportProofSignals {
        readme_contract: proof_signal(
            graph,
            selectors,
            |claim| {
                claim.tags.contains("readme")
                    || claim.tags.contains("feature-status")
                    || normalized_claim_text(claim).contains("readme")
            },
            |evidence| evidence.kind == EvidenceKind::Documentation,
        ),
        secretless_readiness: proof_signal(
            graph,
            selectors,
            |claim| normalized_claim_text(claim).contains("secretless"),
            |evidence| normalized_evidence_text(evidence).contains("secretless"),
        ),
        host_or_introspection: proof_signal(
            graph,
            selectors,
            |claim| {
                normalized_claim_text(claim).contains("introspection")
                    || normalized_claim_text(claim).contains("readiness")
                    || claim.required_truth_source.as_str() == "host_backed"
            },
            |evidence| {
                evidence.kind == EvidenceKind::HostIntegration
                    || normalized_evidence_text(evidence).contains("introspection")
            },
        ),
    }
}

fn proof_signal<C, E>(
    graph: &ProofGraph,
    selectors: &BTreeSet<String>,
    claim_filter: C,
    evidence_filter: E,
) -> PassportProofSignal
where
    C: Fn(&ClaimNode) -> bool,
    E: Fn(&EvidenceNode) -> bool,
{
    let mut matched_claim_ids = BTreeSet::new();
    let mut source_refs = BTreeSet::new();
    let mut evidence_count = 0;
    let mut strongest_relationship = None;

    for claim in graph
        .claims
        .values()
        .filter(|claim| claim_matches_connector(claim, selectors) && claim_filter(claim))
    {
        matched_claim_ids.insert(claim.id.to_string());
        for edge in graph
            .support_edges
            .iter()
            .filter(|edge| edge.claim_id == claim.id)
        {
            record_signal_evidence(
                graph,
                edge,
                &evidence_filter,
                &mut evidence_count,
                &mut source_refs,
                &mut strongest_relationship,
            );
        }
    }

    if matched_claim_ids.is_empty() {
        for edge in graph.support_edges.iter().filter(|edge| {
            graph
                .claims
                .get(&edge.claim_id)
                .is_some_and(|claim| claim_matches_connector(claim, selectors))
        }) {
            if let Some(evidence) = graph.evidence.get(&edge.evidence_id) {
                if evidence_filter(evidence) {
                    matched_claim_ids.insert(edge.claim_id.to_string());
                    record_signal_evidence(
                        graph,
                        edge,
                        &evidence_filter,
                        &mut evidence_count,
                        &mut source_refs,
                        &mut strongest_relationship,
                    );
                }
            }
        }
    }

    PassportProofSignal {
        state: signal_state(strongest_relationship, evidence_count),
        matched_claim_ids: matched_claim_ids.into_iter().collect(),
        evidence_count,
        source_refs: source_refs.into_iter().collect(),
    }
}

fn record_signal_evidence<E>(
    graph: &ProofGraph,
    edge: &SupportEdge,
    evidence_filter: &E,
    evidence_count: &mut usize,
    source_refs: &mut BTreeSet<String>,
    strongest_relationship: &mut Option<SupportRelationship>,
) where
    E: Fn(&EvidenceNode) -> bool,
{
    let Some(evidence) = graph.evidence.get(&edge.evidence_id) else {
        return;
    };
    if !evidence_filter(evidence) {
        return;
    }
    *evidence_count += 1;
    source_refs.insert(evidence.source_ref.clone());
    if strongest_relationship.map_or(true, |current| {
        relationship_rank(edge.relationship) > relationship_rank(current)
    }) {
        *strongest_relationship = Some(edge.relationship);
    }
}

fn signal_state(relationship: Option<SupportRelationship>, evidence_count: usize) -> &'static str {
    match relationship {
        Some(SupportRelationship::Supports) => "supported",
        Some(SupportRelationship::PartiallySupports) => "partial",
        Some(SupportRelationship::Contradicts) => "contradicted",
        Some(SupportRelationship::DoesNotSupport) => "unsupported",
        None if evidence_count > 0 => "observed",
        None => "missing",
    }
}

fn relationship_rank(relationship: SupportRelationship) -> u8 {
    match relationship {
        SupportRelationship::Contradicts => 4,
        SupportRelationship::Supports => 3,
        SupportRelationship::PartiallySupports => 2,
        SupportRelationship::DoesNotSupport => 1,
    }
}

fn passport_gaps(
    loaded: &LoadedManifest,
    graph: &ProofGraph,
    operations: &[PassportOperation],
    proof_state: &PassportProofState,
) -> Vec<PassportGap> {
    let manifest_path = loaded.path.display().to_string();
    let mut gaps = Vec::new();
    if proof_state.matched_claim_ids.is_empty() {
        gaps.push(PassportGap {
            category: "proof-state",
            status: "missing",
            summary: format!(
                "No ProofGraph claim matched connector `{}`.",
                loaded.manifest.connector.id.as_str()
            ),
            target_truth_source: "operator_record".to_owned(),
            provenance: PassportProvenance {
                field: "proof_state",
                source: "proof_graph",
                source_ref: graph.schema.clone(),
            },
        });
    }

    for claim_id in &proof_state.matched_claim_ids {
        let Some(claim) = graph
            .claims
            .values()
            .find(|candidate| candidate.id.as_str() == claim_id)
        else {
            continue;
        };
        for gap in &claim.proof_gaps {
            gaps.push(PassportGap {
                category: "proof",
                status: gap_status_label(gap.status),
                summary: format!("{}: {}", gap.id, gap.summary),
                target_truth_source: gap.target_truth_source.as_str().to_owned(),
                provenance: PassportProvenance {
                    field: "proof_state",
                    source: "proof_graph",
                    source_ref: claim.id.to_string(),
                },
            });
        }
    }

    if let Some(rationale) = loaded.manifest.connector.status.non_live_rationale() {
        gaps.push(PassportGap {
            category: "connector-status",
            status: "blocked",
            summary: format!(
                "Manifest status `{}` is hidden or non-live: {rationale}.",
                loaded.manifest.connector.status
            ),
            target_truth_source: "manifest".to_owned(),
            provenance: PassportProvenance {
                field: "connector.status",
                source: "manifest",
                source_ref: manifest_path.clone(),
            },
        });
    }

    if loaded.manifest.sandbox.deny_exec {
        if !loaded.manifest.sandbox.deny_ptrace {
            gaps.push(sandbox_gap(
                "ptrace is not denied",
                "sandbox.deny_ptrace",
                &manifest_path,
            ));
        }
    } else {
        gaps.push(sandbox_gap(
            "process execution is not denied",
            "sandbox.deny_exec",
            &manifest_path,
        ));
    }

    let proof_signals = passport_proof_signals(graph, &passport_manifest_selectors(loaded));
    if proof_signals.readme_contract.state == "missing" {
        gaps.push(signal_gap(
            "readme-contract",
            "README contract status is not represented in the matched ProofGraph claims",
            graph,
        ));
    }
    if proof_signals.secretless_readiness.state == "missing" {
        gaps.push(signal_gap(
            "secretless-readiness",
            "Secretless readiness is not represented in the matched ProofGraph claims",
            graph,
        ));
    }
    if proof_signals.host_or_introspection.state == "missing" {
        gaps.push(signal_gap(
            "host-introspection",
            "Host-backed readiness or introspection evidence is not represented in the matched ProofGraph claims",
            graph,
        ));
    }

    for operation in operations {
        if operation.input_schema_state != "declared" {
            gaps.push(operation_gap(
                "input-schema",
                operation.input_schema_state,
                operation,
                "input schema is not fully declared",
                &manifest_path,
            ));
        }
        if operation.output_schema_state != "declared" {
            gaps.push(operation_gap(
                "output-schema",
                operation.output_schema_state,
                operation,
                "output schema is not fully declared",
                &manifest_path,
            ));
        }
        if operation.network_posture.state != "declared" {
            gaps.push(operation_gap(
                "network-posture",
                operation.network_posture.state,
                operation,
                "network posture is missing from the manifest",
                &manifest_path,
            ));
        }
        if operation.ai_hints_state.state != "declared" {
            gaps.push(operation_gap(
                "ai-hints",
                operation.ai_hints_state.state,
                operation,
                "agent usage hints are incomplete",
                &manifest_path,
            ));
        }
    }

    gaps.sort_by_key(|gap| (gap.category, gap.status, gap.summary.clone()));
    gaps
}

fn signal_gap(category: &'static str, summary: &str, graph: &ProofGraph) -> PassportGap {
    PassportGap {
        category,
        status: "missing",
        summary: summary.to_owned(),
        target_truth_source: "proof_graph".to_owned(),
        provenance: PassportProvenance {
            field: "proof_signals",
            source: "proof_graph",
            source_ref: graph.schema.clone(),
        },
    }
}

fn sandbox_gap(summary: &str, field: &'static str, manifest_path: &str) -> PassportGap {
    PassportGap {
        category: "sandbox-posture",
        status: "weak",
        summary: format!("Manifest sandbox posture is weak: {summary}."),
        target_truth_source: "manifest".to_owned(),
        provenance: PassportProvenance {
            field,
            source: "manifest",
            source_ref: manifest_path.to_owned(),
        },
    }
}

fn operation_gap(
    category: &'static str,
    status: &'static str,
    operation: &PassportOperation,
    reason: &str,
    manifest_path: &str,
) -> PassportGap {
    PassportGap {
        category,
        status,
        summary: format!("Operation `{}` {reason}.", operation.id),
        target_truth_source: "manifest".to_owned(),
        provenance: PassportProvenance {
            field: "operations",
            source: "manifest",
            source_ref: manifest_path.to_owned(),
        },
    }
}

fn passport_risk_summary(
    operations: &[PassportOperation],
    proof_gap_count: usize,
) -> PassportRiskSummary {
    PassportRiskSummary {
        max_risk_level: operations
            .iter()
            .map(|operation| operation.risk_level)
            .max_by_key(|risk| risk_label_rank(risk))
            .unwrap_or("low"),
        max_safety_tier: operations
            .iter()
            .map(|operation| operation.safety_tier)
            .max_by_key(|tier| safety_tier_rank(tier))
            .unwrap_or("safe"),
        operation_count: operations.len(),
        approval_required_count: operations
            .iter()
            .filter(|operation| operation.requires_approval != "none")
            .count(),
        network_posture_gap_count: operations
            .iter()
            .filter(|operation| operation.network_posture.state != "declared")
            .count(),
        ai_hints_gap_count: operations
            .iter()
            .filter(|operation| operation.ai_hints_state.state != "declared")
            .count(),
        proof_gap_count,
    }
}

fn passport_summary(passports: &[CapabilityPassport]) -> Value {
    json!({
        "passports": passports.len(),
        "connectors": passports
            .iter()
            .map(|passport| passport.connector.id.clone())
            .collect::<Vec<_>>(),
        "operations": passports
            .iter()
            .map(|passport| passport.operations.len())
            .sum::<usize>(),
        "gaps": passports
            .iter()
            .map(|passport| passport.gaps.len())
            .sum::<usize>(),
        "connectors_with_unmatched_proof_state": passports
            .iter()
            .filter(|passport| passport.proof_state.matched_claim_ids.is_empty())
            .count(),
    })
}

fn passport_manifest_selectors(manifest: &LoadedManifest) -> BTreeSet<String> {
    let connector_id = manifest.manifest.connector.id.as_str();
    let slug = connector_slug(connector_id);
    [
        connector_id,
        connector_id.strip_prefix("fcp.").unwrap_or(connector_id),
        slug.as_str(),
        manifest.manifest.connector.name.as_str(),
    ]
    .into_iter()
    .map(normalize_passport_selector)
    .collect()
}

fn claim_matches_connector(claim: &ClaimNode, selectors: &BTreeSet<String>) -> bool {
    let haystacks = std::iter::once(claim.id.as_str())
        .chain(std::iter::once(claim.title.as_str()))
        .chain(std::iter::once(claim.statement.as_str()))
        .chain(claim.tags.iter().map(String::as_str))
        .map(normalize_passport_selector)
        .collect::<Vec<_>>();

    selectors.iter().any(|selector| {
        haystacks
            .iter()
            .any(|haystack| haystack == selector || haystack.contains(selector))
    })
}

fn connector_slug(connector_id: &str) -> String {
    connector_id
        .strip_prefix("fcp.")
        .unwrap_or(connector_id)
        .to_owned()
}

fn normalize_passport_selector(value: &str) -> String {
    let mut normalized = String::new();
    let mut last_was_dash = false;
    for ch in value.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch);
            last_was_dash = false;
        } else if !last_was_dash {
            normalized.push('-');
            last_was_dash = true;
        }
    }
    normalized.trim_matches('-').to_owned()
}

fn capability_strings(caps: &[fcp_core::CapabilityId]) -> Vec<String> {
    caps.iter()
        .map(|capability| capability.as_str().to_owned())
        .collect()
}

fn operation_capabilities(operations: &[PassportOperation]) -> Vec<String> {
    operations
        .iter()
        .map(|operation| operation.capability.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn schema_state(value: &Value) -> &'static str {
    if value.is_null() {
        return "missing";
    }
    if value.as_object().is_some_and(serde_json::Map::is_empty) {
        return "unknown";
    }
    "declared"
}

fn network_posture(operation: &OperationSection) -> PassportNetworkPosture {
    if let Some(network) = &operation.network_constraints {
        PassportNetworkPosture {
            state: "declared",
            host_allow_count: network.host_allow.len(),
            port_allow: network.port_allow.clone(),
            deny_localhost: Some(network.deny_localhost),
            deny_private_ranges: Some(network.deny_private_ranges),
            deny_tailnet_ranges: Some(network.deny_tailnet_ranges),
            require_sni: Some(network.require_sni),
        }
    } else {
        PassportNetworkPosture {
            state: "missing",
            host_allow_count: 0,
            port_allow: Vec::new(),
            deny_localhost: None,
            deny_private_ranges: None,
            deny_tailnet_ranges: None,
            require_sni: None,
        }
    }
}

fn ai_hints_state(operation: &OperationSection) -> PassportAiHintsState {
    let has_when_to_use = !operation.ai_hints.when_to_use.trim().is_empty();
    let has_examples = !operation.ai_hints.examples.is_empty();
    PassportAiHintsState {
        state: if has_when_to_use && has_examples {
            "declared"
        } else {
            "missing"
        },
        has_when_to_use,
        common_mistake_count: operation.ai_hints.common_mistakes.len(),
        example_count: operation.ai_hints.examples.len(),
        related_count: operation.ai_hints.related.len(),
    }
}

fn runtime_format_label(format: &fcp_manifest::ConnectorRuntimeFormat) -> Result<String> {
    manifest_enum_label(format).context("serializing connector runtime format")
}

fn manifest_enum_label<T>(value: &T) -> Result<String>
where
    T: Serialize,
{
    serde_json::to_value(value)
        .context("serializing manifest enum")?
        .as_str()
        .map(std::borrow::ToOwned::to_owned)
        .context("manifest enum did not serialize as a string")
}

fn approval_mode_label(mode: ManifestApprovalMode) -> &'static str {
    match mode {
        ManifestApprovalMode::None => "none",
        ManifestApprovalMode::Policy => "policy",
        ManifestApprovalMode::Interactive => "interactive",
        ManifestApprovalMode::ElevationToken => "elevation-token",
    }
}

fn risk_label_rank(label: &str) -> u8 {
    match label {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn safety_tier_rank(label: &str) -> u8 {
    match label {
        "forbidden" => 5,
        "critical" => 4,
        "dangerous" => 3,
        "risky" => 2,
        "safe" => 1,
        _ => 0,
    }
}

fn sandbox_posture(manifest: &ConnectorManifest) -> &'static str {
    if manifest.sandbox.deny_exec
        && manifest.sandbox.deny_ptrace
        && matches!(
            manifest.sandbox.profile,
            fcp_manifest::SandboxProfile::Strict | fcp_manifest::SandboxProfile::StrictPlus
        )
    {
        "strict"
    } else if manifest.sandbox.deny_exec && manifest.sandbox.deny_ptrace {
        "constrained"
    } else {
        "weak"
    }
}

fn evidence_kind_label(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::MeshExecution => "mesh_execution",
        EvidenceKind::HostIntegration => "host_integration",
        EvidenceKind::NodeLocalRun => "node_local_run",
        EvidenceKind::OfflineArtifact => "offline_artifact",
        EvidenceKind::RepositoryObject => "repository_object",
        EvidenceKind::OperatorRecord => "operator_record",
        EvidenceKind::Documentation => "documentation",
    }
}

fn normalized_claim_text(claim: &ClaimNode) -> String {
    let mut text = format!("{} {} {}", claim.id, claim.title, claim.statement);
    for tag in &claim.tags {
        text.push(' ');
        text.push_str(tag);
    }
    normalize_passport_selector(&text)
}

fn normalized_evidence_text(evidence: &EvidenceNode) -> String {
    normalize_passport_selector(&format!("{} {}", evidence.summary, evidence.source_ref))
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

    fn write_manifest(raw: &str) -> NamedTempFile {
        let file = NamedTempFile::new().expect("create temp manifest");
        std::fs::write(file.path(), raw).expect("write manifest");
        file
    }

    fn github_passport_corpus() -> ProofGraphCorpus {
        ProofGraphCorpus {
            schema: PROOF_GRAPH_INDEXER_CORPUS_SCHEMA.to_owned(),
            readme_rows: vec![readme_row("github", "GitHub Connector", "PROVEN", 20)],
            bead_issues: vec![issue("github", "flywheel_connectors-b88ec.4", NOW - DAY_MS)],
            verification_scripts: vec![VerificationScriptRecord {
                claim_key: "github".to_owned(),
                script_path: "connectors/github/tests/passport.rs".to_owned(),
                purpose: "Run GitHub connector passport proof".to_owned(),
                rerun_argv: vec![
                    "cargo".to_owned(),
                    "test".to_owned(),
                    "-p".to_owned(),
                    "fcp-github".to_owned(),
                    "passport".to_owned(),
                ],
                required_env_keys: BTreeSet::new(),
                source: source("connectors/github/tests/passport.rs", 1),
            }],
            readiness_rows: vec![
                ReadinessMatrixRow {
                    claim_key: "github-secretless".to_owned(),
                    subject: "GitHub secretless readiness".to_owned(),
                    state: "pass".to_owned(),
                    truth_source: TruthSource::HostBacked,
                    rerun_argv: None,
                    source: source("crates/fwc/tests/github_secretless.rs", 4),
                },
                ReadinessMatrixRow {
                    claim_key: "github-introspection".to_owned(),
                    subject: "GitHub manifest introspection".to_owned(),
                    state: "pass".to_owned(),
                    truth_source: TruthSource::HostBacked,
                    rerun_argv: None,
                    source: source("crates/fwc/tests/github_introspection.rs", 5),
                },
            ],
            evidence_bundles: Vec::new(),
        }
    }

    fn representative_manifest(
        connector_id: &str,
        name: &str,
        operation_id: &str,
        capability: &str,
        extra_operation_sections: &str,
    ) -> String {
        let interface_hash = format!("blake3-256:fcp.interface.v2:{}", "0".repeat(64));
        format!(
            r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 65000
interface_hash = "{interface_hash}"

[connector]
id = "{connector_id}"
name = "{name}"
version = "0.1.0"
description = "FCP connector for {name}"
archetypes = ["operational"]
format = "wasi"

[zones]
home = "z:work"
allowed_sources = ["z:owner", "z:work"]
allowed_targets = ["z:work"]
forbidden = ["z:public"]

[capabilities]
required = ["network.dns"]
optional = ["{capability}"]
forbidden = ["system.exec"]

[sandbox]
profile = "strict"
memory_mb = 256
cpu_percent = 50
wall_clock_timeout_ms = 120000
fs_readonly_paths = ["/usr", "/lib"]
deny_exec = true
deny_ptrace = true

[provides.operations."{operation_id}"]
description = "Get a single issue"
capability = "{capability}"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
revocation_freshness = "safe"

[provides.operations."{operation_id}".input_schema]
type = "object"

[provides.operations."{operation_id}".output_schema]
type = "object"

{extra_operation_sections}
"#
        )
    }

    fn github_manifest(extra_operation_sections: &str) -> String {
        representative_manifest(
            "fcp.github",
            "GitHub Connector",
            "github.get_issue",
            "github.read",
            extra_operation_sections,
        )
    }

    fn network_and_ai_hints(operation_id: &str, host: &str, usage: &str) -> String {
        format!(
            r#"[provides.operations."{operation_id}".network_constraints]
host_allow = ["{host}"]
port_allow = [443]
deny_localhost = true
deny_private_ranges = true
deny_tailnet_ranges = true
require_sni = true

[provides.operations."{operation_id}".ai_hints]
when_to_use = "{usage}"
common_mistakes = ["Treating stale proof as current proof"]
examples = ['{{"example":true}}']
related = []
"#
        )
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

    #[test]
    fn passport_outputs_manifest_backed_connector_proof_state() {
        let corpus = write_corpus(&github_passport_corpus());
        let manifest = write_manifest(&github_manifest(&network_and_ai_hints(
            "github.get_issue",
            "api.github.com",
            "Read a GitHub issue by owner, repo, and issue number.",
        )));

        let result = run(&ProofArgs {
            command: ProofCommand::Passport(ProofPassportArgs {
                corpus: corpus_args(corpus.path()),
                manifests: vec![manifest.path().to_path_buf()],
                connector: Some("github".to_owned()),
            }),
        })
        .expect("run proof passport");

        assert!(result.success);
        assert_eq!(result.payload["schema_version"], CAPABILITY_PASSPORT_SCHEMA);
        let passport = &result.payload["passports"][0];
        assert_eq!(passport["connector"]["id"], "fcp.github");
        assert_eq!(passport["operations"][0]["capability"], "github.read");
        assert_eq!(passport["sandbox"]["posture"], "strict");
        assert_eq!(
            passport["operations"][0]["network_posture"]["state"],
            "declared"
        );
        assert_eq!(
            passport["operations"][0]["ai_hints_state"]["state"],
            "declared"
        );
        assert!(
            passport["proof_state"]["matched_claim_ids"]
                .as_array()
                .expect("matched claim ids")
                .iter()
                .any(|value| value == "claim:github")
        );
        assert_eq!(passport["proof_state"]["state"], "missing");
        assert_eq!(
            passport["proof_state"]["evidence_by_kind"]["host_integration"],
            2
        );
        assert_eq!(
            passport["proof_signals"]["readme_contract"]["state"],
            "partial"
        );
        assert_eq!(
            passport["proof_signals"]["secretless_readiness"]["state"],
            "supported"
        );
        assert_eq!(
            passport["proof_signals"]["host_or_introspection"]["state"],
            "supported"
        );
        assert_eq!(passport["risk_summary"]["network_posture_gap_count"], 0);
        assert_eq!(passport["risk_summary"]["ai_hints_gap_count"], 0);
    }

    #[test]
    fn passport_reports_missing_network_hints_and_unmatched_proof_as_gaps() {
        let corpus = write_corpus(&ProofGraphCorpus::default());
        let manifest = write_manifest(&github_manifest(""));

        let result = run(&ProofArgs {
            command: ProofCommand::Passport(ProofPassportArgs {
                corpus: corpus_args(corpus.path()),
                manifests: vec![manifest.path().to_path_buf()],
                connector: Some("github".to_owned()),
            }),
        })
        .expect("run proof passport");

        assert!(result.success);
        let passport = &result.payload["passports"][0];
        let categories = passport["gaps"]
            .as_array()
            .expect("gaps array")
            .iter()
            .map(|gap| gap["category"].as_str().expect("gap category"))
            .collect::<BTreeSet<_>>();

        assert!(categories.contains("proof-state"));
        assert!(categories.contains("network-posture"));
        assert!(categories.contains("ai-hints"));
        assert!(categories.contains("readme-contract"));
        assert!(categories.contains("secretless-readiness"));
        assert!(categories.contains("host-introspection"));
        assert_eq!(
            passport["operations"][0]["network_posture"]["state"],
            "missing"
        );
        assert_eq!(
            passport["operations"][0]["ai_hints_state"]["state"],
            "missing"
        );
        assert_eq!(
            result.payload["summary"]["connectors_with_unmatched_proof_state"],
            1
        );
    }

    #[test]
    fn passport_reports_incubating_connector_and_weak_sandbox_posture() {
        let corpus = write_corpus(&github_passport_corpus());
        let manifest_body = github_manifest(&network_and_ai_hints(
            "github.get_issue",
            "api.github.com",
            "Read a GitHub issue by owner, repo, and issue number.",
        ))
        .replace(
            "format = \"wasi\"",
            "format = \"wasi\"\nstatus = \"incubating\"",
        )
        .replace("deny_exec = true", "deny_exec = false");
        let manifest = write_manifest(&manifest_body);

        let result = run(&ProofArgs {
            command: ProofCommand::Passport(ProofPassportArgs {
                corpus: corpus_args(corpus.path()),
                manifests: vec![manifest.path().to_path_buf()],
                connector: Some("github".to_owned()),
            }),
        })
        .expect("run proof passport");

        assert!(result.success);
        let passport = &result.payload["passports"][0];
        assert_eq!(passport["connector"]["hidden_by_default"], true);
        assert_eq!(passport["connector"]["status"], "incubating");
        assert_eq!(passport["sandbox"]["posture"], "weak");

        let categories = passport["gaps"]
            .as_array()
            .expect("gaps array")
            .iter()
            .map(|gap| gap["category"].as_str().expect("gap category"))
            .collect::<BTreeSet<_>>();

        assert!(categories.contains("connector-status"));
        assert!(categories.contains("sandbox-posture"));
    }

    #[test]
    fn passport_records_stale_claims_and_denied_network_posture() {
        let mut corpus = github_passport_corpus();
        corpus.bead_issues.push(issue(
            "github-stale-proof",
            "flywheel_connectors-b88ec.4.stale",
            NOW - (30 * DAY_MS),
        ));
        let corpus = write_corpus(&corpus);
        let manifest = write_manifest(&github_manifest(&network_and_ai_hints(
            "github.get_issue",
            "api.github.com",
            "Read a GitHub issue by owner, repo, and issue number.",
        )));

        let result = run(&ProofArgs {
            command: ProofCommand::Passport(ProofPassportArgs {
                corpus: corpus_args(corpus.path()),
                manifests: vec![manifest.path().to_path_buf()],
                connector: Some("github".to_owned()),
            }),
        })
        .expect("run proof passport");

        assert!(result.success);
        let passport = &result.payload["passports"][0];
        let stale_claim_ids = passport["proof_state"]["stale_claim_ids"]
            .as_array()
            .expect("stale claim ids")
            .iter()
            .map(|value| value.as_str().expect("stale claim id"))
            .collect::<BTreeSet<_>>();
        assert!(stale_claim_ids.contains("claim:github-stale-proof"));

        let proof_gap_statuses = passport["gaps"]
            .as_array()
            .expect("gaps array")
            .iter()
            .filter(|gap| gap["category"] == "proof")
            .map(|gap| gap["status"].as_str().expect("proof gap status"))
            .collect::<BTreeSet<_>>();
        assert!(proof_gap_statuses.contains("stale"));

        let network = &passport["operations"][0]["network_posture"];
        assert_eq!(network["state"], "declared");
        assert_eq!(network["host_allow_count"], 1);
        assert_eq!(network["port_allow"][0], 443);
        assert!(network["deny_localhost"].as_bool().expect("deny localhost"));
        assert!(
            network["deny_private_ranges"]
                .as_bool()
                .expect("deny private ranges")
        );
        assert!(
            network["deny_tailnet_ranges"]
                .as_bool()
                .expect("deny tailnet ranges")
        );
        assert!(network["require_sni"].as_bool().expect("require sni"));
        assert_eq!(passport["risk_summary"]["network_posture_gap_count"], 0);
    }

    #[test]
    fn passport_outputs_stable_representative_connector_fixture_matrix() {
        let connectors = [
            (
                "fcp.github",
                "GitHub Connector",
                "github.get_issue",
                "github.read",
                "api.github.com",
            ),
            (
                "fcp.slack",
                "Slack Connector",
                "slack.post_message",
                "slack.write",
                "slack.com",
            ),
            (
                "fcp.gmail",
                "Gmail Connector",
                "gmail.get_message",
                "gmail.read",
                "gmail.googleapis.com",
            ),
            (
                "fcp.browser",
                "Browser Connector",
                "browser.navigate",
                "browser.control",
                "browser-control.example.test",
            ),
            (
                "fcp.aws-bedrock",
                "AWS Bedrock Connector",
                "aws_bedrock.converse",
                "aws.bedrock.invoke",
                "bedrock.us-east-1.amazonaws.com",
            ),
        ];
        let corpus = write_corpus(&ProofGraphCorpus {
            schema: PROOF_GRAPH_INDEXER_CORPUS_SCHEMA.to_owned(),
            readme_rows: connectors
                .iter()
                .enumerate()
                .map(|(index, (id, name, ..))| {
                    let claim_key = connector_slug(id);
                    readme_row(
                        &claim_key,
                        name,
                        "PROVEN",
                        100 + u32::try_from(index).expect("fixture index fits in u32"),
                    )
                })
                .collect(),
            bead_issues: connectors
                .iter()
                .map(|(id, ..)| {
                    let claim_key = connector_slug(id);
                    issue(
                        &claim_key,
                        &format!("flywheel_connectors-b88ec.4.{claim_key}"),
                        NOW - DAY_MS,
                    )
                })
                .collect(),
            verification_scripts: connectors
                .iter()
                .enumerate()
                .map(|(index, (id, name, ..))| {
                    let claim_key = connector_slug(id);
                    VerificationScriptRecord {
                        claim_key,
                        script_path: format!(
                            "connectors/{}/tests/passport_fixture.rs",
                            connector_slug(id)
                        ),
                        purpose: format!("Run {name} passport fixture proof"),
                        rerun_argv: vec![
                            "cargo".to_owned(),
                            "test".to_owned(),
                            "-p".to_owned(),
                            format!("fcp-{}", connector_slug(id)),
                            "passport".to_owned(),
                        ],
                        required_env_keys: BTreeSet::new(),
                        source: source(
                            "crates/fwc/tests/representative_passport.rs",
                            150 + u32::try_from(index).expect("fixture index fits in u32"),
                        ),
                    }
                })
                .collect(),
            readiness_rows: connectors
                .iter()
                .enumerate()
                .flat_map(|(index, (id, name, ..))| {
                    let slug = connector_slug(id);
                    [
                        ReadinessMatrixRow {
                            claim_key: format!("{slug}-introspection"),
                            subject: format!("{name} manifest introspection"),
                            state: "pass".to_owned(),
                            truth_source: TruthSource::HostBacked,
                            rerun_argv: Some(vec![
                                "fwc".to_owned(),
                                "proof".to_owned(),
                                "passport".to_owned(),
                                "--connector".to_owned(),
                                slug.clone(),
                            ]),
                            source: source(
                                "crates/fwc/tests/representative_passport.rs",
                                200 + u32::try_from(index).expect("fixture index fits in u32"),
                            ),
                        },
                        ReadinessMatrixRow {
                            claim_key: format!("{slug}-secretless"),
                            subject: format!("{name} secretless readiness"),
                            state: "pass".to_owned(),
                            truth_source: TruthSource::HostBacked,
                            rerun_argv: Some(vec![
                                "fwc".to_owned(),
                                "proof".to_owned(),
                                "passport".to_owned(),
                                "--connector".to_owned(),
                                slug,
                            ]),
                            source: source(
                                "crates/fwc/tests/representative_passport.rs",
                                300 + u32::try_from(index).expect("fixture index fits in u32"),
                            ),
                        },
                    ]
                })
                .collect(),
            evidence_bundles: Vec::new(),
        });
        let manifests = connectors
            .iter()
            .map(|(id, name, operation_id, capability, host)| {
                write_manifest(&representative_manifest(
                    id,
                    name,
                    operation_id,
                    capability,
                    &network_and_ai_hints(
                        operation_id,
                        host,
                        &format!("Use {name} through the connector passport fixture."),
                    ),
                ))
            })
            .collect::<Vec<_>>();
        let manifest_paths = manifests
            .iter()
            .map(|manifest| manifest.path().to_path_buf())
            .collect::<Vec<_>>();

        let result = run(&ProofArgs {
            command: ProofCommand::Passport(ProofPassportArgs {
                corpus: corpus_args(corpus.path()),
                manifests: manifest_paths,
                connector: None,
            }),
        })
        .expect("run proof passport");

        assert!(result.success);
        assert_eq!(result.payload["summary"]["passports"], connectors.len());
        assert_eq!(result.payload["summary"]["operations"], connectors.len());
        assert_eq!(result.payload["summary"]["gaps"], 0);
        assert_eq!(
            result.payload["summary"]["connectors"],
            json!([
                "fcp.github",
                "fcp.slack",
                "fcp.gmail",
                "fcp.browser",
                "fcp.aws-bedrock"
            ])
        );

        let passport_json =
            serde_json::to_string(&result.payload["passports"]).expect("stable passports json");
        assert!(!passport_json.contains("xoxb"));
        assert!(!passport_json.contains("ghp_"));
        assert!(!passport_json.contains("ya29."));
        assert!(passport_json.contains("fcp.aws-bedrock"));
        assert!(passport_json.contains("fcp.browser"));
    }
}
