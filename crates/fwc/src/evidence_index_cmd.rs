use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{CliExitCode, CommandAvailability, CommandEnvelope, DispatchOutcome};

const SCHEMA_VERSION: &str = "fwc.evidence.index.v1";
const REPLAY_TRACE_FILE: &str = "trace.jsonl";
const REPLAY_SUMMARY_FILE: &str = "summary.json";
const REPLAY_ENVIRONMENT_FILE: &str = "environment.json";
const REPLAY_SCRIPT_FILE: &str = "replay.sh";

#[derive(Args, Debug, Serialize)]
pub(crate) struct EvidenceArgs {
    #[command(subcommand)]
    command: EvidenceCommand,
}

#[derive(Subcommand, Debug, Serialize)]
#[serde(tag = "subcommand", content = "args", rename_all = "kebab-case")]
enum EvidenceCommand {
    /// Scan evidence roots and return deterministic index records.
    Index(EvidenceIndexArgs),

    /// Query evidence records by connector, bead, command, status, or age.
    Find(EvidenceFindArgs),
}

#[derive(Args, Debug, Serialize)]
struct EvidenceIndexArgs {
    /// Evidence root to scan. Repeat to merge multiple roots.
    #[arg(long = "root", value_name = "DIR")]
    roots: Vec<PathBuf>,

    /// Maximum directory depth to scan below each root.
    #[arg(long, default_value_t = 8)]
    max_depth: usize,
}

#[derive(Args, Debug, Serialize)]
struct EvidenceFindArgs {
    /// Evidence root to scan. Repeat to merge multiple roots.
    #[arg(long = "root", value_name = "DIR")]
    roots: Vec<PathBuf>,

    /// Filter by connector id.
    #[arg(long)]
    connector: Option<String>,

    /// Filter by bead id.
    #[arg(long)]
    bead: Option<String>,

    /// Filter by command string.
    #[arg(long)]
    command: Option<String>,

    /// Filter by proof status, for example accepted, infra-blocked, or stale.
    #[arg(long = "proof-status")]
    proof_status: Option<String>,

    /// Filter by truth source.
    #[arg(long = "truth-source")]
    truth_source: Option<String>,

    /// Filter by failure class.
    #[arg(long = "failure-class")]
    failure_class: Option<String>,

    /// Filter by artifact kind.
    #[arg(long = "kind")]
    artifact_kind: Option<String>,

    /// Only include records created within an age window like 7d, 24h, or 30m.
    #[arg(long)]
    since: Option<String>,

    /// Maximum result count. 0 means unlimited.
    #[arg(long, default_value_t = 50)]
    limit: usize,

    /// Maximum directory depth to scan below each root.
    #[arg(long, default_value_t = 8)]
    max_depth: usize,
}

#[derive(Clone, Debug, Serialize)]
struct EvidenceIndexRecord {
    schema_version: &'static str,
    artifact_kind: String,
    path: String,
    external_path: bool,
    valid: bool,
    correlation_id: Option<String>,
    connector_id: Option<String>,
    command: Option<String>,
    bead_id: Option<String>,
    truth_source: Option<String>,
    proof_status: String,
    created_at: Option<String>,
    git_revision: Option<String>,
    redaction_status: RedactionStatus,
    replay_command: Option<ReplayCommandEvidence>,
    failure_class: Option<String>,
    invalid_reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RedactionStatus {
    Clean,
    Redacted,
}

#[derive(Clone, Debug, Serialize)]
struct ReplayCommandEvidence {
    command: String,
    runnable: bool,
    non_runnable_reason: Option<String>,
}

#[derive(Debug)]
struct EvidenceIndex {
    records: Vec<EvidenceIndexRecord>,
    scanned_count: usize,
    invalid_count: usize,
    redacted_count: usize,
    elapsed_ms: u128,
}

#[derive(Debug, Default)]
struct EvidenceMetadata {
    correlation_id: Option<String>,
    connector_id: Option<String>,
    command: Option<String>,
    bead_id: Option<String>,
    truth_source: Option<String>,
    proof_status: Option<String>,
    created_at: Option<String>,
    git_revision: Option<String>,
    failure_class: Option<String>,
    redaction_status: RedactionStatus,
    replay_command: Option<ReplayCommandEvidence>,
}

impl Default for RedactionStatus {
    fn default() -> Self {
        Self::Clean
    }
}

pub(crate) fn dispatch(args: &EvidenceArgs) -> Result<DispatchOutcome> {
    match &args.command {
        EvidenceCommand::Index(index_args) => dispatch_index(index_args),
        EvidenceCommand::Find(find_args) => dispatch_find(find_args),
    }
}

fn dispatch_index(args: &EvidenceIndexArgs) -> Result<DispatchOutcome> {
    let roots = normalized_roots(&args.roots);
    let index = build_index(&roots, args.max_depth)?;
    let payload = index_payload("index", &roots, &index, None);

    tracing::info!(
        event = "fwc.evidence.index",
        scanned_count = index.scanned_count,
        indexed_count = index.records.len(),
        invalid_count = index.invalid_count,
        redacted_count = index.redacted_count,
        elapsed_ms = index.elapsed_ms,
        "indexed evidence artifacts"
    );

    Ok(success(payload))
}

fn dispatch_find(args: &EvidenceFindArgs) -> Result<DispatchOutcome> {
    let roots = normalized_roots(&args.roots);
    let index = build_index(&roots, args.max_depth)?;
    let filter = EvidenceFindFilter::try_from(args)?;
    let query_count = index.records.len();
    let mut records = index
        .records
        .iter()
        .filter(|record| filter.matches(record))
        .cloned()
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.artifact_kind.cmp(&right.artifact_kind))
    });
    if args.limit > 0 {
        records.truncate(args.limit);
    }

    tracing::info!(
        event = "fwc.evidence.find",
        query_count,
        result_count = records.len(),
        "queried evidence index"
    );

    let payload = index_payload(
        "find",
        &roots,
        &EvidenceIndex {
            records,
            scanned_count: index.scanned_count,
            invalid_count: index.invalid_count,
            redacted_count: index.redacted_count,
            elapsed_ms: index.elapsed_ms,
        },
        Some(json!({
            "connector": args.connector,
            "bead": args.bead,
            "command": args.command,
            "proof_status": args.proof_status,
            "truth_source": args.truth_source,
            "failure_class": args.failure_class,
            "artifact_kind": args.artifact_kind,
            "since": args.since,
            "limit": args.limit,
            "query_count": query_count,
        })),
    );

    Ok(success(payload))
}

#[derive(Debug)]
struct EvidenceFindFilter {
    connector: Option<String>,
    bead: Option<String>,
    command: Option<String>,
    proof_status: Option<String>,
    truth_source: Option<String>,
    failure_class: Option<String>,
    artifact_kind: Option<String>,
    created_after: Option<DateTime<Utc>>,
}

impl TryFrom<&EvidenceFindArgs> for EvidenceFindFilter {
    type Error = anyhow::Error;

    fn try_from(args: &EvidenceFindArgs) -> Result<Self> {
        Ok(Self {
            connector: args.connector.as_deref().map(normalize_filter),
            bead: args.bead.as_deref().map(normalize_filter),
            command: args.command.as_deref().map(normalize_filter),
            proof_status: args.proof_status.as_deref().map(normalize_filter),
            truth_source: args.truth_source.as_deref().map(normalize_filter),
            failure_class: args.failure_class.as_deref().map(normalize_filter),
            artifact_kind: args.artifact_kind.as_deref().map(normalize_filter),
            created_after: args.since.as_deref().map(parse_since_cutoff).transpose()?,
        })
    }
}

impl EvidenceFindFilter {
    fn matches(&self, record: &EvidenceIndexRecord) -> bool {
        matches_optional(self.connector.as_deref(), record.connector_id.as_deref())
            && matches_optional(self.bead.as_deref(), record.bead_id.as_deref())
            && matches_optional(self.command.as_deref(), record.command.as_deref())
            && matches_text(self.proof_status.as_deref(), &record.proof_status)
            && matches_optional(self.truth_source.as_deref(), record.truth_source.as_deref())
            && matches_optional(
                self.failure_class.as_deref(),
                record.failure_class.as_deref(),
            )
            && matches_text(self.artifact_kind.as_deref(), &record.artifact_kind)
            && matches_created_after(self.created_after, record.created_at.as_deref())
    }
}

fn success(mut payload: Value) -> DispatchOutcome {
    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "evidence");
    envelope.inject_into(&mut payload);
    DispatchOutcome {
        payload,
        exit_code: CliExitCode::Success,
    }
}

fn index_payload(
    subcommand: &str,
    roots: &[PathBuf],
    index: &EvidenceIndex,
    query: Option<Value>,
) -> Value {
    let mut payload = json!({
        "schema_version": SCHEMA_VERSION,
        "command": "evidence",
        "subcommand": subcommand,
        "roots": roots.iter().map(|root| root.display().to_string()).collect::<Vec<_>>(),
        "summary": {
            "scanned_count": index.scanned_count,
            "indexed_count": index.records.len(),
            "invalid_count": index.invalid_count,
            "redacted_count": index.redacted_count,
            "elapsed_ms": index.elapsed_ms,
        },
        "events": [{
            "event": format!("fwc.evidence.{subcommand}"),
            "scanned_count": index.scanned_count,
            "indexed_count": index.records.len(),
            "invalid_count": index.invalid_count,
            "redacted_count": index.redacted_count,
            "elapsed_ms": index.elapsed_ms,
        }],
        "record_schema": evidence_record_schema(),
        "records": index.records,
    });
    if let Some(query) = query {
        payload["query"] = query;
    }
    payload
}

fn evidence_record_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": [
            "schema_version",
            "artifact_kind",
            "path",
            "external_path",
            "valid",
            "proof_status",
            "redaction_status"
        ],
        "properties": {
            "schema_version": {"const": SCHEMA_VERSION},
            "artifact_kind": {"type": "string"},
            "path": {"type": "string"},
            "external_path": {"type": "boolean"},
            "valid": {"type": "boolean"},
            "correlation_id": {"type": ["string", "null"]},
            "connector_id": {"type": ["string", "null"]},
            "command": {"type": ["string", "null"]},
            "bead_id": {"type": ["string", "null"]},
            "truth_source": {"type": ["string", "null"]},
            "proof_status": {"type": "string"},
            "created_at": {"type": ["string", "null"]},
            "git_revision": {"type": ["string", "null"]},
            "redaction_status": {"enum": ["clean", "redacted"]},
            "replay_command": {
                "type": ["object", "null"],
                "required": ["command", "runnable"],
                "properties": {
                    "command": {"type": "string"},
                    "runnable": {"type": "boolean"},
                    "non_runnable_reason": {"type": ["string", "null"]}
                }
            },
            "failure_class": {"type": ["string", "null"]},
            "invalid_reason": {"type": ["string", "null"]}
        }
    })
}

fn build_index(roots: &[PathBuf], max_depth: usize) -> Result<EvidenceIndex> {
    let started = Instant::now();
    let workspace_root = std::env::current_dir().context("failed to resolve current directory")?;
    let mut records = Vec::new();
    let mut scanned_count = 0_usize;

    for root in roots {
        if !root.exists() {
            records.push(invalid_record(
                "missing_root",
                root,
                &workspace_root,
                format!("evidence root does not exist: {}", root.display()),
            ));
            continue;
        }
        scan_path(
            root,
            root,
            &workspace_root,
            0,
            max_depth,
            &mut scanned_count,
            &mut records,
        )?;
    }

    records.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.artifact_kind.cmp(&right.artifact_kind))
    });
    let invalid_count = records.iter().filter(|record| !record.valid).count();
    let redacted_count = records
        .iter()
        .filter(|record| record.redaction_status == RedactionStatus::Redacted)
        .count();

    Ok(EvidenceIndex {
        records,
        scanned_count,
        invalid_count,
        redacted_count,
        elapsed_ms: started.elapsed().as_millis(),
    })
}

fn scan_path(
    path: &Path,
    root: &Path,
    workspace_root: &Path,
    depth: usize,
    max_depth: usize,
    scanned_count: &mut usize,
    records: &mut Vec<EvidenceIndexRecord>,
) -> Result<()> {
    if depth > max_depth {
        return Ok(());
    }

    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            records.push(invalid_record(
                "unreadable_path",
                path,
                workspace_root,
                format!("failed to stat evidence path: {error}"),
            ));
            return Ok(());
        }
    };

    if metadata.is_file() {
        *scanned_count = scanned_count.saturating_add(1);
        scan_file(path, workspace_root, records);
        return Ok(());
    }
    if !metadata.is_dir() {
        return Ok(());
    }

    let mut children = match fs::read_dir(path) {
        Ok(children) => children
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .collect::<Vec<_>>(),
        Err(error) => {
            records.push(invalid_record(
                "unreadable_directory",
                path,
                workspace_root,
                format!("failed to read evidence directory: {error}"),
            ));
            return Ok(());
        }
    };
    children.sort();

    for child in children {
        if child == root && depth > 0 {
            continue;
        }
        scan_path(
            &child,
            root,
            workspace_root,
            depth.saturating_add(1),
            max_depth,
            scanned_count,
            records,
        )?;
    }
    Ok(())
}

fn scan_file(path: &Path, workspace_root: &Path, records: &mut Vec<EvidenceIndexRecord>) {
    let file_name = path.file_name().and_then(OsStr::to_str).unwrap_or_default();
    match file_name {
        REPLAY_TRACE_FILE => records.push(artifact_record("trace_jsonl", path, workspace_root)),
        REPLAY_SUMMARY_FILE => records.push(artifact_record("summary_json", path, workspace_root)),
        REPLAY_ENVIRONMENT_FILE => {
            records.push(artifact_record("environment_json", path, workspace_root));
        }
        REPLAY_SCRIPT_FILE => records.push(artifact_record("replay_script", path, workspace_root)),
        _ if path.extension() == Some(OsStr::new("jsonl")) => {
            records.extend(verifier_records(path, workspace_root));
        }
        _ => {}
    }
}

fn artifact_record(
    artifact_kind: impl Into<String>,
    path: &Path,
    workspace_root: &Path,
) -> EvidenceIndexRecord {
    let mut metadata = read_bundle_metadata(path.parent().unwrap_or_else(|| Path::new(".")));
    merge_file_metadata(path, &mut metadata);
    record_from_metadata(artifact_kind.into(), path, workspace_root, metadata, None)
}

fn verifier_records(path: &Path, workspace_root: &Path) -> Vec<EvidenceIndexRecord> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) => {
            return vec![invalid_record(
                "unreadable_jsonl",
                path,
                workspace_root,
                format!("failed to read JSONL evidence record: {error}"),
            )];
        }
    };

    let mut records = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let line_path = line_path(path, index + 1);
        match serde_json::from_str::<Value>(line) {
            Ok(value) => {
                let mut metadata = metadata_from_value(&value);
                metadata.proof_status =
                    metadata.proof_status.or_else(|| Some("unknown".to_owned()));
                records.push(record_from_metadata(
                    "connector_verifier_record".to_owned(),
                    &line_path,
                    workspace_root,
                    metadata,
                    None,
                ));
            }
            Err(error) => records.push(invalid_record(
                "invalid_jsonl_record",
                &line_path,
                workspace_root,
                format!("failed to parse JSONL evidence record: {error}"),
            )),
        }
    }
    records
}

fn read_bundle_metadata(bundle_dir: &Path) -> EvidenceMetadata {
    let mut metadata = EvidenceMetadata::default();
    let summary_path = bundle_dir.join(REPLAY_SUMMARY_FILE);
    if let Ok(summary) = read_json_file(&summary_path) {
        metadata.merge(metadata_from_value(&summary));
    }
    let environment_path = bundle_dir.join(REPLAY_ENVIRONMENT_FILE);
    if let Ok(environment) = read_json_file(&environment_path) {
        metadata.merge(metadata_from_value(&environment));
    }
    let replay_path = bundle_dir.join(REPLAY_SCRIPT_FILE);
    if let Ok(replay) = fs::read_to_string(&replay_path) {
        metadata.replay_command = Some(replay_command_evidence(&replay));
        if contains_secret_like(&replay) {
            metadata.redaction_status = RedactionStatus::Redacted;
        }
    }
    metadata
}

fn merge_file_metadata(path: &Path, metadata: &mut EvidenceMetadata) {
    match path.file_name().and_then(OsStr::to_str) {
        Some(REPLAY_SUMMARY_FILE | REPLAY_ENVIRONMENT_FILE) => {
            if let Ok(value) = read_json_file(path) {
                metadata.merge(metadata_from_value(&value));
            }
        }
        Some(REPLAY_SCRIPT_FILE) => {
            if let Ok(replay) = fs::read_to_string(path) {
                metadata.replay_command = Some(replay_command_evidence(&replay));
                if contains_secret_like(&replay) {
                    metadata.redaction_status = RedactionStatus::Redacted;
                }
            }
        }
        Some(REPLAY_TRACE_FILE) => {
            if let Ok(trace_metadata) = metadata_from_jsonl_first_value(path) {
                metadata.merge(trace_metadata);
            }
        }
        _ => {}
    }
}

fn metadata_from_jsonl_first_value(path: &Path) -> Result<EvidenceMetadata> {
    let contents = fs::read_to_string(path)?;
    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let value = serde_json::from_str::<Value>(line)?;
        return Ok(metadata_from_value(&value));
    }
    Ok(EvidenceMetadata::default())
}

fn read_json_file(path: &Path) -> Result<Value> {
    let contents = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&contents)?)
}

fn metadata_from_value(value: &Value) -> EvidenceMetadata {
    let mut metadata = EvidenceMetadata {
        correlation_id: first_string(value, &["correlation_id", "request_id", "run_id", "id"]),
        connector_id: first_string(value, &["connector_id", "connector", "connector_slug"]),
        command: first_string(value, &["command", "cmd", "operation_id", "operation"]),
        bead_id: first_string(value, &["bead_id", "bead", "issue_id", "thread_id"])
            .or_else(|| find_bead_id(value)),
        truth_source: first_string(value, &["truth_source", "_truth_source", "source"]),
        proof_status: first_string(value, &["proof_status", "status", "result"]),
        created_at: first_string(value, &["created_at", "timestamp", "generated_at"]),
        git_revision: first_string(value, &["git_revision", "git_sha", "commit", "sha"]),
        failure_class: first_string(value, &["failure_class", "error_code", "failure"]),
        redaction_status: RedactionStatus::Clean,
        replay_command: None,
    };
    if value_contains_secret_like(value) {
        metadata.redaction_status = RedactionStatus::Redacted;
    }
    metadata
}

impl EvidenceMetadata {
    fn merge(&mut self, other: Self) {
        self.correlation_id = self.correlation_id.take().or(other.correlation_id);
        self.connector_id = self.connector_id.take().or(other.connector_id);
        self.command = self.command.take().or(other.command);
        self.bead_id = self.bead_id.take().or(other.bead_id);
        self.truth_source = self.truth_source.take().or(other.truth_source);
        self.proof_status = self.proof_status.take().or(other.proof_status);
        self.created_at = self.created_at.take().or(other.created_at);
        self.git_revision = self.git_revision.take().or(other.git_revision);
        self.failure_class = self.failure_class.take().or(other.failure_class);
        self.replay_command = self.replay_command.take().or(other.replay_command);
        if other.redaction_status == RedactionStatus::Redacted {
            self.redaction_status = RedactionStatus::Redacted;
        }
    }
}

fn record_from_metadata(
    artifact_kind: String,
    path: &Path,
    workspace_root: &Path,
    metadata: EvidenceMetadata,
    invalid_reason: Option<String>,
) -> EvidenceIndexRecord {
    let (path, external_path) = display_path(path, workspace_root);
    EvidenceIndexRecord {
        schema_version: SCHEMA_VERSION,
        artifact_kind,
        path,
        external_path,
        valid: invalid_reason.is_none(),
        correlation_id: metadata.correlation_id.map(redact_if_secret),
        connector_id: metadata.connector_id.map(redact_if_secret),
        command: metadata.command.map(redact_if_secret),
        bead_id: metadata.bead_id.map(redact_if_secret),
        truth_source: metadata.truth_source.map(redact_if_secret),
        proof_status: metadata
            .proof_status
            .map(|status| redact_if_secret(&status))
            .unwrap_or_else(|| "unknown".to_owned()),
        created_at: metadata.created_at.map(redact_if_secret),
        git_revision: metadata.git_revision.map(redact_if_secret),
        redaction_status: metadata.redaction_status,
        replay_command: metadata.replay_command,
        failure_class: metadata.failure_class.map(redact_if_secret),
        invalid_reason,
    }
}

fn invalid_record(
    artifact_kind: impl Into<String>,
    path: &Path,
    workspace_root: &Path,
    reason: String,
) -> EvidenceIndexRecord {
    record_from_metadata(
        artifact_kind.into(),
        path,
        workspace_root,
        EvidenceMetadata {
            proof_status: Some("invalid".to_owned()),
            redaction_status: RedactionStatus::Clean,
            ..EvidenceMetadata::default()
        },
        Some(reason),
    )
}

fn replay_command_evidence(script: &str) -> ReplayCommandEvidence {
    let command = sanitize_replay_command(script);
    let non_runnable_reason = if contains_destructive_command(script) {
        Some(
            "replay script contains a destructive command and requires operator approval"
                .to_owned(),
        )
    } else if contains_secret_like(script) {
        Some("replay script contains redacted secret-like material".to_owned())
    } else {
        None
    };
    ReplayCommandEvidence {
        command,
        runnable: non_runnable_reason.is_none(),
        non_runnable_reason,
    }
}

fn sanitize_replay_command(script: &str) -> String {
    script
        .lines()
        .map(redact_if_secret)
        .collect::<Vec<_>>()
        .join("\n")
}

fn contains_destructive_command(script: &str) -> bool {
    let lowered = script.to_ascii_lowercase();
    [
        "rm -",
        "git reset --hard",
        "git clean",
        "am service restart",
        "am service stop",
        "doctor repair",
        "doctor reconstruct",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

fn first_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| find_string_by_key(value, key))
        .filter(|value| !value.trim().is_empty())
}

fn find_string_by_key(value: &Value, key: &str) -> Option<String> {
    match value {
        Value::Object(map) => {
            if let Some(found) = map.get(key).and_then(value_as_index_string) {
                return Some(found);
            }
            map.values()
                .find_map(|value| find_string_by_key(value, key))
        }
        Value::Array(values) => values
            .iter()
            .find_map(|value| find_string_by_key(value, key)),
        _ => None,
    }
}

fn value_as_index_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Array(values) => {
            let parts = values
                .iter()
                .filter_map(value_as_index_string)
                .collect::<Vec<_>>();
            (!parts.is_empty()).then(|| parts.join(" "))
        }
        _ => None,
    }
}

fn find_bead_id(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => find_bead_id_in_str(value),
        Value::Array(values) => values.iter().find_map(find_bead_id),
        Value::Object(map) => map.values().find_map(find_bead_id),
        _ => None,
    }
}

fn find_bead_id_in_str(value: &str) -> Option<String> {
    ["flywheel_connectors-", "br-", "bd-"]
        .iter()
        .filter_map(|prefix| {
            value.find(prefix).map(|offset| {
                value[offset..]
                    .chars()
                    .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
                    .collect::<String>()
            })
        })
        .find(|candidate| candidate.len() > 3)
}

fn value_contains_secret_like(value: &Value) -> bool {
    match value {
        Value::String(value) => contains_secret_like(value),
        Value::Array(values) => values.iter().any(value_contains_secret_like),
        Value::Object(map) => map
            .iter()
            .any(|(key, value)| secret_key_like(key) || value_contains_secret_like(value)),
        _ => false,
    }
}

fn contains_secret_like(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    secret_key_like(&lowered)
        || [
            "bearer ",
            "api_key=",
            "access_token",
            "refresh_token",
            "secret=",
            "password=",
            "authorization:",
        ]
        .iter()
        .any(|needle| lowered.contains(needle))
}

fn secret_key_like(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "authorization",
        "private_key",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

fn redact_if_secret(value: impl AsRef<str>) -> String {
    let value = value.as_ref();
    if contains_secret_like(value) {
        "[REDACTED]".to_owned()
    } else {
        value.to_owned()
    }
}

fn normalized_roots(roots: &[PathBuf]) -> Vec<PathBuf> {
    if roots.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        roots.to_vec()
    }
}

fn display_path(path: &Path, workspace_root: &Path) -> (String, bool) {
    let clean_path = strip_line_suffix(path);
    if clean_path.is_relative() {
        let display = clean_path
            .display()
            .to_string()
            .trim_start_matches("./")
            .to_owned();
        if let Some(line) = line_suffix(path) {
            return (format!("{display}:{line}"), false);
        }
        return (display, false);
    }
    if let Ok(relative) = clean_path.strip_prefix(workspace_root) {
        let display = relative.display().to_string();
        if let Some(line) = line_suffix(path) {
            (format!("{display}:{line}"), false)
        } else {
            (display, false)
        }
    } else {
        (path.display().to_string(), true)
    }
}

fn line_path(path: &Path, line: usize) -> PathBuf {
    PathBuf::from(format!("{}:{line}", path.display()))
}

fn strip_line_suffix(path: &Path) -> PathBuf {
    let display = path.display().to_string();
    if let Some((file, line)) = display.rsplit_once(':') {
        if line.chars().all(|ch| ch.is_ascii_digit()) {
            return PathBuf::from(file);
        }
    }
    path.to_path_buf()
}

fn line_suffix(path: &Path) -> Option<String> {
    let display = path.display().to_string();
    display
        .rsplit_once(':')
        .filter(|(_, line)| line.chars().all(|ch| ch.is_ascii_digit()))
        .map(|(_, line)| line.to_owned())
}

fn normalize_filter(value: &str) -> String {
    value.to_ascii_lowercase()
}

fn matches_optional(filter: Option<&str>, value: Option<&str>) -> bool {
    match filter {
        Some(filter) => value
            .map(|value| value.to_ascii_lowercase().contains(filter))
            .unwrap_or(false),
        None => true,
    }
}

fn matches_text(filter: Option<&str>, value: &str) -> bool {
    filter
        .map(|filter| value.to_ascii_lowercase().contains(filter))
        .unwrap_or(true)
}

fn matches_created_after(cutoff: Option<DateTime<Utc>>, created_at: Option<&str>) -> bool {
    match cutoff {
        Some(cutoff) => created_at
            .and_then(parse_created_at)
            .map(|created_at| created_at >= cutoff)
            .unwrap_or(false),
        None => true,
    }
}

fn parse_created_at(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .ok()
}

fn parse_since_cutoff(value: &str) -> Result<DateTime<Utc>> {
    if let Ok(datetime) = DateTime::parse_from_rfc3339(value) {
        return Ok(datetime.with_timezone(&Utc));
    }

    let (amount, unit) = value.split_at(value.len().saturating_sub(1));
    let amount = amount.parse::<i64>().with_context(|| {
        format!("invalid --since value `{value}`; expected 7d, 24h, 30m, or RFC3339")
    })?;
    let duration = match unit {
        "d" => ChronoDuration::days(amount),
        "h" => ChronoDuration::hours(amount),
        "m" => ChronoDuration::minutes(amount),
        "s" => ChronoDuration::seconds(amount),
        _ => anyhow::bail!(
            "invalid --since value `{value}`; supported duration units are d, h, m, and s"
        ),
    };
    Ok(Utc::now() - duration)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use jsonschema::validator_for;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn evidence_index_covers_replay_bundle_and_verifier_records() {
        let root = fixture_root();
        let index = build_index(&[root.path().to_path_buf()], 8).expect("index should build");
        let kinds = index
            .records
            .iter()
            .map(|record| record.artifact_kind.as_str())
            .collect::<std::collections::BTreeSet<_>>();

        assert!(kinds.contains("trace_jsonl"));
        assert!(kinds.contains("summary_json"));
        assert!(kinds.contains("environment_json"));
        assert!(kinds.contains("replay_script"));
        assert!(kinds.contains("connector_verifier_record"));
        assert_eq!(index.invalid_count, 1);
    }

    #[test]
    fn evidence_find_filters_by_connector_bead_status_and_age() {
        let root = fixture_root();
        let args = EvidenceFindArgs {
            roots: vec![root.path().to_path_buf()],
            connector: Some("github".to_owned()),
            bead: Some("flywheel_connectors-ql87d.5".to_owned()),
            command: Some("fwc invoke".to_owned()),
            proof_status: Some("accepted".to_owned()),
            truth_source: Some("host-backed".to_owned()),
            failure_class: None,
            artifact_kind: None,
            since: Some("2026-06-01T00:00:00Z".to_owned()),
            limit: 10,
            max_depth: 8,
        };
        let filter = EvidenceFindFilter::try_from(&args).expect("filter should parse");
        let index = build_index(&args.roots, args.max_depth).expect("index should build");
        let matches = index
            .records
            .iter()
            .filter(|record| filter.matches(record))
            .collect::<Vec<_>>();

        assert!(
            matches
                .iter()
                .any(|record| record.artifact_kind == "summary_json")
        );
        assert!(
            matches
                .iter()
                .all(|record| record.connector_id.as_deref() == Some("github"))
        );
    }

    #[test]
    fn evidence_index_redacts_secret_like_values_and_marks_replay_non_runnable() {
        let root = fixture_root();
        let index = build_index(&[root.path().to_path_buf()], 8).expect("index should build");
        let replay = index
            .records
            .iter()
            .find(|record| record.artifact_kind == "replay_script")
            .expect("replay script should be indexed");

        assert_eq!(replay.redaction_status, RedactionStatus::Redacted);
        let command = replay
            .replay_command
            .as_ref()
            .expect("replay command should be present");
        assert!(!command.runnable);
        assert!(command.command.contains("[REDACTED]"));
        assert!(!command.command.contains("super-secret"));
    }

    #[test]
    fn evidence_record_schema_validates_fixture_records() {
        let root = fixture_root();
        let index = build_index(&[root.path().to_path_buf()], 8).expect("index should build");
        let validator = validator_for(&evidence_record_schema()).expect("schema should compile");

        for record in index.records {
            let value = serde_json::to_value(record).expect("record should serialize");
            validator.validate(&value).expect("record should validate");
        }
    }

    #[test]
    fn missing_root_returns_invalid_record_without_panicking() {
        let root = TempDir::new().expect("tempdir");
        let missing = root.path().join("missing");
        let index = build_index(&[missing], 8).expect("index should build");

        assert_eq!(index.records.len(), 1);
        assert!(!index.records[0].valid);
        assert_eq!(index.records[0].artifact_kind, "missing_root");
    }

    fn fixture_root() -> TempDir {
        let root = TempDir::new().expect("tempdir");
        let bundle = root.path().join("bundle-a");
        fs::create_dir_all(&bundle).expect("bundle dir");
        fs::write(
            bundle.join(REPLAY_SUMMARY_FILE),
            serde_json::to_vec_pretty(&json!({
                "correlation_id": "corr-123",
                "connector_id": "github",
                "command": "fwc invoke github issues.create",
                "bead_id": "flywheel_connectors-ql87d.5",
                "truth_source": "host-backed",
                "proof_status": "accepted",
                "created_at": "2026-06-05T12:00:00Z",
                "git_revision": "abc123",
            }))
            .expect("summary json"),
        )
        .expect("write summary");
        fs::write(
            bundle.join(REPLAY_ENVIRONMENT_FILE),
            serde_json::to_vec_pretty(&json!({
                "generated_at": "2026-06-05T12:00:01Z",
                "git_sha": "abc123",
                "SECRET_TOKEN": "super-secret",
            }))
            .expect("environment json"),
        )
        .expect("write env");
        fs::write(
            bundle.join(REPLAY_TRACE_FILE),
            "{\"event\":\"start\",\"correlation_id\":\"corr-123\"}\n",
        )
        .expect("write trace");
        fs::write(
            bundle.join(REPLAY_SCRIPT_FILE),
            "FWC_TOKEN=super-secret fwc invoke github issues.create\n",
        )
        .expect("write replay");

        let verifier = root.path().join("connector-verifier.jsonl");
        let mut file = fs::File::create(&verifier).expect("verifier jsonl");
        writeln!(
            file,
            "{}",
            json!({
                "connector_id": "slack",
                "command": "scripts/e2e/slack_connector_verification.sh",
                "bead_id": "flywheel_connectors-ql87d.5",
                "proof_status": "infra-blocked",
                "failure_class": "missing-token",
                "created_at": "2026-06-04T12:00:00Z"
            })
        )
        .expect("write verifier");
        writeln!(file, "{{not-json").expect("write invalid line");
        root
    }
}
