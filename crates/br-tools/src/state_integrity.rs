//! Read-only Beads DB/JSONL state-integrity reporting.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Write as _},
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use chrono::{DateTime, Duration, Utc};
use rusqlite::{Connection, OpenFlags, Row};
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};

/// Default age threshold for suspicious Beads write locks.
pub const DEFAULT_LOCK_STALE_AFTER_SECONDS: i64 = 300;

/// Full read-only report for Beads state integrity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateIntegrityReport {
    /// Report generation timestamp.
    pub generated_at: DateTime<Utc>,
    /// Whether the report attempted any mutation. Always false by contract.
    pub mutation_attempted: bool,
    /// Overall machine-readable status.
    pub overall_status: StateIntegrityStatus,
    /// JSONL source summary.
    pub jsonl: SourceSummary,
    /// DB snapshot summary, if supplied.
    pub db: Option<SourceSummary>,
    /// `bv --robot-graph --graph-format=json` source summary, if supplied.
    pub bv: Option<SourceSummary>,
    /// Beads write-lock health.
    pub lock: LockHealth,
    /// Optional compact single-issue query result.
    pub query: Option<IssueQueryReport>,
    /// Issue-level projection differences.
    pub issue_findings: Vec<IssueProjectionFinding>,
    /// `bv` graph projection differences relative to JSONL.
    pub bv_findings: Vec<BvProjectionFinding>,
    /// Report-level reason codes.
    pub reason_codes: Vec<String>,
    /// Non-destructive suggested next actions.
    pub recommended_actions: Vec<String>,
}

/// Overall state of the checked projections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateIntegrityStatus {
    /// All supplied sources agree and no lock concern was found.
    Healthy,
    /// A non-fatal divergence or lock warning exists.
    Warning,
    /// A source cannot be parsed or projections are unsafe to trust.
    Blocked,
}

impl StateIntegrityStatus {
    /// Stable string representation for table output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Blocked => "blocked",
        }
    }
}

/// Summary for one Beads issue source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSummary {
    /// Source role, e.g. `jsonl`, `db`, or `db_snapshot`.
    pub source: String,
    /// Source path when available.
    pub path: Option<PathBuf>,
    /// Whether parsing succeeded.
    pub parsed: bool,
    /// Number of issue records parsed from this source.
    pub issue_count: usize,
    /// Stable hash of issue projections when parsing succeeded.
    pub projection_hash: Option<String>,
    /// Source-level error, if any.
    pub error: Option<SourceError>,
}

/// Source-level parse or load failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceError {
    /// Machine-readable error kind.
    pub kind: SourceErrorKind,
    /// Redaction-safe message.
    pub message: String,
}

/// Stable source error classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceErrorKind {
    /// Source file could not be read.
    ReadFailed,
    /// Live `SQLite` DB could not be opened read-only.
    DbOpenFailed,
    /// Live `SQLite` DB query failed.
    DbQueryFailed,
    /// JSONL contained merge-conflict markers.
    JsonlConflictMarkers,
    /// A JSONL line did not parse.
    JsonlParseError,
    /// DB snapshot JSON had an unsupported shape.
    SnapshotShapeUnsupported,
    /// DB snapshot JSON did not parse.
    SnapshotParseError,
    /// `bv` graph JSON had an unsupported shape.
    BvGraphShapeUnsupported,
    /// `bv` graph JSON did not parse.
    BvGraphParseError,
}

/// Write-lock classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockHealth {
    /// Lock path checked by the report.
    pub path: Option<PathBuf>,
    /// Stable lock state.
    pub state: LockState,
    /// Whether the lock file exists.
    pub present: bool,
    /// Lock age in seconds when known.
    pub age_seconds: Option<i64>,
    /// Process evidence mentioning the lock.
    pub matching_processes: Vec<LockProcessEvidence>,
    /// Non-destructive recommendation for operators.
    pub recommendation: String,
}

/// Stable lock states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockState {
    /// No lock is present.
    Missing,
    /// Lock exists and a live process appears to reference it.
    Held,
    /// Lock exists, no process evidence was supplied, and age is below threshold.
    PresentUnknown,
    /// Lock exists, no process evidence was supplied, and age exceeds threshold.
    StaleSuspected,
}

/// Redaction-safe process evidence for a lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockProcessEvidence {
    /// Process id when known.
    pub pid: Option<u32>,
    /// Redacted process command.
    pub command: String,
}

/// One issue-level projection difference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueProjectionFinding {
    /// Beads issue id.
    pub id: String,
    /// Finding kind.
    pub kind: ProjectionFindingKind,
    /// JSONL issue status when present.
    pub jsonl_status: Option<String>,
    /// DB issue status when present.
    pub db_status: Option<String>,
    /// Projection fields that differ for issues present in both sources.
    pub diverged_fields: Vec<String>,
    /// Redaction-safe recommendation.
    pub recommendation: String,
}

/// Stable issue projection finding classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionFindingKind {
    /// Same id exists in both sources but projected fields differ.
    IssueProjectionDiverged,
    /// Issue exists only in JSONL.
    JsonlOnly,
    /// Issue exists only in DB snapshot.
    DbOnly,
}

/// One `bv` graph projection difference relative to JSONL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BvProjectionFinding {
    /// Beads issue id.
    pub id: String,
    /// Finding kind.
    pub kind: BvProjectionFindingKind,
    /// JSONL issue status when present.
    pub jsonl_status: Option<String>,
    /// `bv` issue status when present.
    pub bv_status: Option<String>,
    /// Projection fields that differ for issues present in both sources.
    pub diverged_fields: Vec<String>,
    /// Redaction-safe recommendation.
    pub recommendation: String,
}

/// Stable `bv` projection finding classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BvProjectionFindingKind {
    /// Same id exists in both sources but projected fields differ.
    BvProjectionDiverged,
    /// Issue exists only in JSONL.
    JsonlOnly,
    /// Issue exists only in the `bv` graph snapshot.
    BvOnly,
}

/// Compact answer for one requested issue id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueQueryReport {
    /// Beads issue id requested by the operator.
    pub id: String,
    /// Query-specific agreement state.
    pub status: IssueQueryStatus,
    /// JSONL projection for this issue when available.
    pub jsonl: Option<IssueProjection>,
    /// DB projection for this issue when available.
    pub db: Option<IssueProjection>,
    /// `bv` graph projection for this issue when available.
    pub bv: Option<IssueProjection>,
    /// Difference for this issue when one exists.
    pub finding: Option<IssueProjectionFinding>,
    /// `bv` difference for this issue when one exists.
    pub bv_finding: Option<BvProjectionFinding>,
    /// Redaction-safe recommendation for this issue.
    pub recommendation: String,
}

/// Stable single-issue query states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueQueryStatus {
    /// Both sources parsed and the selected issue agrees.
    SourcesAgree,
    /// Source parsing failed or no DB source was supplied.
    SourceUnavailable,
    /// The selected issue exists only in JSONL.
    JsonlOnly,
    /// The selected issue exists only in DB.
    DbOnly,
    /// The selected issue exists only in the `bv` graph snapshot.
    BvOnly,
    /// The selected issue exists in more than one source, but not every supplied source.
    SourceSetMismatch,
    /// Both sources contain the issue but projected fields diverge.
    Diverged,
    /// Both parsed sources are missing the selected issue.
    NotFound,
}

impl fmt::Display for IssueQueryStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::SourcesAgree => "sources_agree",
            Self::SourceUnavailable => "source_unavailable",
            Self::JsonlOnly => "jsonl_only",
            Self::DbOnly => "db_only",
            Self::BvOnly => "bv_only",
            Self::SourceSetMismatch => "source_set_mismatch",
            Self::Diverged => "diverged",
            Self::NotFound => "not_found",
        };
        f.write_str(value)
    }
}

/// Process snapshot used for read-only lock correlation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSnapshot {
    /// Process id when available.
    pub pid: Option<u32>,
    /// Command line observed for the process.
    pub command: String,
}

impl ProcessSnapshot {
    /// Build a process snapshot.
    #[must_use]
    pub fn new(pid: Option<u32>, command: impl Into<String>) -> Self {
        Self {
            pid,
            command: command.into(),
        }
    }
}

/// Configuration for state-integrity reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateIntegrityConfig {
    /// Report generation timestamp.
    pub now: DateTime<Utc>,
    /// Optional lock path to inspect.
    pub lock_path: Option<PathBuf>,
    /// Lock age that changes present/unknown into stale-suspected.
    pub lock_stale_after: Duration,
    /// Process command lines to match against the lock path.
    pub active_processes: Vec<ProcessSnapshot>,
    /// Optional issue id for compact per-issue comparison output.
    pub query_issue_id: Option<String>,
}

impl StateIntegrityConfig {
    /// Build a default configuration for the current repository.
    #[must_use]
    pub fn default_with_now(now: DateTime<Utc>) -> Self {
        Self {
            now,
            lock_path: Some(default_write_lock_path()),
            lock_stale_after: Duration::seconds(DEFAULT_LOCK_STALE_AFTER_SECONDS),
            active_processes: Vec::new(),
            query_issue_id: None,
        }
    }
}

/// Parsed issue source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueSource {
    /// Source summary.
    pub summary: SourceSummary,
    /// Parsed projections keyed by issue id.
    pub issues: BTreeMap<String, IssueProjection>,
}

/// Minimal issue projection used for cross-source comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueProjection {
    /// Beads issue id.
    pub id: String,
    /// Issue title.
    pub title: String,
    /// Issue status.
    pub status: String,
    /// Issue priority, if present.
    pub priority: Option<u8>,
    /// Issue update timestamp, if present.
    pub updated_at: Option<String>,
    /// Number of comments projected for this issue.
    pub comment_count: usize,
    /// Stable hash of projected comment records.
    pub comment_projection_hash: String,
    /// Number of dependency edges projected for this issue.
    pub dependency_count: usize,
    /// Stable hash of projected dependency records.
    pub dependency_projection_hash: String,
    /// Stable hash of important fields.
    pub projection_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NestedProjection {
    count: usize,
    hash: String,
}

/// Return the default repository-relative issues export path.
#[must_use]
pub fn default_issues_jsonl_path() -> PathBuf {
    PathBuf::from(".beads/issues.jsonl")
}

/// Return the default repository-relative Beads `SQLite` DB path.
#[must_use]
pub fn default_beads_db_path() -> PathBuf {
    PathBuf::from(".beads/beads.db")
}

/// Return the default repository-relative Beads write lock path.
#[must_use]
pub fn default_write_lock_path() -> PathBuf {
    PathBuf::from(".beads/.write.lock")
}

/// Load issue projections from a Beads JSONL export.
#[must_use]
pub fn load_jsonl_source(path: &Path) -> IssueSource {
    let source = "jsonl";
    let Ok(raw) = fs::read_to_string(path) else {
        return failed_source(
            source,
            Some(path),
            SourceErrorKind::ReadFailed,
            "could not read issues JSONL",
        );
    };
    parse_jsonl_source(source, Some(path.to_path_buf()), &raw)
}

/// Parse issue projections from JSONL text.
#[must_use]
pub fn parse_jsonl_source(source: &str, path: Option<PathBuf>, raw: &str) -> IssueSource {
    if raw.lines().any(is_conflict_marker) {
        return failed_source(
            source,
            path.as_deref(),
            SourceErrorKind::JsonlConflictMarkers,
            "issues JSONL contains merge-conflict markers",
        );
    }

    let mut issues = BTreeMap::new();
    for (line_index, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value = match serde_json::from_str::<Value>(line) {
            Ok(value) => value,
            Err(error) => {
                return failed_source(
                    source,
                    path.as_deref(),
                    SourceErrorKind::JsonlParseError,
                    format!("line {} did not parse as JSON: {error}", line_index + 1),
                );
            }
        };
        if let Some(issue) = projection_from_value(&value) {
            issues.insert(issue.id.clone(), issue);
        }
    }

    source_from_issues(source, path, issues)
}

/// Load issue projections from the live Beads `SQLite` DB in read-only mode.
#[must_use]
pub fn load_live_db_source(path: &Path) -> IssueSource {
    let source = "db";
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = match Connection::open_with_flags(path, flags) {
        Ok(connection) => connection,
        Err(error) => {
            return failed_source(
                source,
                Some(path),
                SourceErrorKind::DbOpenFailed,
                format!("could not open Beads SQLite DB read-only: {error}"),
            );
        }
    };
    let comments = match load_comment_projections(&connection) {
        Ok(comments) => comments,
        Err(error) => {
            return failed_source(
                source,
                Some(path),
                SourceErrorKind::DbQueryFailed,
                format!("could not query Beads SQLite comments: {error}"),
            );
        }
    };
    let dependencies = match load_dependency_projections(&connection) {
        Ok(dependencies) => dependencies,
        Err(error) => {
            return failed_source(
                source,
                Some(path),
                SourceErrorKind::DbQueryFailed,
                format!("could not query Beads SQLite dependencies: {error}"),
            );
        }
    };

    let issues = match load_live_issue_projections(&connection, &comments, &dependencies) {
        Ok(issues) => issues,
        Err(error) => {
            return failed_source(
                source,
                Some(path),
                SourceErrorKind::DbQueryFailed,
                format!("could not query Beads SQLite issues: {error}"),
            );
        }
    };

    source_from_issues(source, Some(path.to_path_buf()), issues)
}

/// Load issue projections from a captured `br list --json` snapshot.
#[must_use]
pub fn load_db_snapshot_source(path: &Path) -> IssueSource {
    let source = "db_snapshot";
    let Ok(raw) = fs::read_to_string(path) else {
        return failed_source(
            source,
            Some(path),
            SourceErrorKind::ReadFailed,
            "could not read DB snapshot JSON",
        );
    };
    parse_db_snapshot_source(source, Some(path.to_path_buf()), &raw)
}

/// Load issue projections from a captured `bv --robot-graph --graph-format=json` snapshot.
#[must_use]
pub fn load_bv_graph_source(path: &Path) -> IssueSource {
    let source = "bv_graph";
    let Ok(raw) = fs::read_to_string(path) else {
        return failed_source(
            source,
            Some(path),
            SourceErrorKind::ReadFailed,
            "could not read bv graph JSON",
        );
    };
    parse_bv_graph_source(source, Some(path.to_path_buf()), &raw)
}

/// Parse issue projections from a captured DB snapshot JSON.
#[must_use]
pub fn parse_db_snapshot_source(source: &str, path: Option<PathBuf>, raw: &str) -> IssueSource {
    let value = match serde_json::from_str::<Value>(raw) {
        Ok(value) => value,
        Err(error) => {
            return failed_source(
                source,
                path.as_deref(),
                SourceErrorKind::SnapshotParseError,
                format!("DB snapshot did not parse as JSON: {error}"),
            );
        }
    };

    let Some(values) = issue_values_from_snapshot(&value) else {
        return failed_source(
            source,
            path.as_deref(),
            SourceErrorKind::SnapshotShapeUnsupported,
            "DB snapshot must be an array or an object with an `issues` array",
        );
    };

    let issues = values
        .iter()
        .filter_map(projection_from_value)
        .map(|issue| (issue.id.clone(), issue))
        .collect();

    source_from_issues(source, path, issues)
}

/// Parse issue projections from a captured `bv --robot-graph --graph-format=json` snapshot.
#[must_use]
pub fn parse_bv_graph_source(source: &str, path: Option<PathBuf>, raw: &str) -> IssueSource {
    let value = match serde_json::from_str::<Value>(raw) {
        Ok(value) => value,
        Err(error) => {
            return failed_source(
                source,
                path.as_deref(),
                SourceErrorKind::BvGraphParseError,
                format!("bv graph did not parse as JSON: {error}"),
            );
        }
    };

    let Some(values) = value
        .get("adjacency")
        .and_then(|adjacency| adjacency.get("nodes"))
        .and_then(Value::as_array)
    else {
        return failed_source(
            source,
            path.as_deref(),
            SourceErrorKind::BvGraphShapeUnsupported,
            "bv graph must contain an `adjacency.nodes` array",
        );
    };

    let issues = values
        .iter()
        .filter_map(projection_from_value)
        .map(|issue| (issue.id.clone(), issue))
        .collect();

    source_from_issues(source, path, issues)
}

/// Build a state-integrity report from parsed sources.
#[must_use]
pub fn build_state_integrity_report(
    jsonl: IssueSource,
    db: Option<IssueSource>,
    bv: Option<IssueSource>,
    config: &StateIntegrityConfig,
) -> StateIntegrityReport {
    let lock = inspect_lock(config);
    let mut issue_findings = db
        .as_ref()
        .map_or_else(Vec::new, |db_source| compare_sources(&jsonl, db_source));
    let mut bv_findings = bv
        .as_ref()
        .map_or_else(Vec::new, |bv_source| compare_bv_source(&jsonl, bv_source));
    let query = config.query_issue_id.as_ref().map(|issue_id| {
        build_issue_query(
            issue_id,
            &jsonl,
            db.as_ref(),
            bv.as_ref(),
            &issue_findings,
            &bv_findings,
        )
    });
    if let Some(issue_id) = &config.query_issue_id {
        issue_findings.retain(|finding| finding.id == *issue_id);
        bv_findings.retain(|finding| finding.id == *issue_id);
    }

    let mut reason_codes = Vec::new();
    collect_source_reasons(&jsonl.summary, &mut reason_codes);
    if let Some(db_source) = &db {
        collect_source_reasons(&db_source.summary, &mut reason_codes);
        if jsonl.summary.parsed
            && db_source.summary.parsed
            && jsonl.summary.issue_count != db_source.summary.issue_count
        {
            reason_codes.push("issue_count_mismatch".to_string());
        }
    } else {
        reason_codes.push("db_snapshot_not_supplied".to_string());
    }
    if let Some(bv_source) = &bv {
        collect_source_reasons(&bv_source.summary, &mut reason_codes);
        if jsonl.summary.parsed
            && bv_source.summary.parsed
            && jsonl.summary.issue_count != bv_source.summary.issue_count
        {
            reason_codes.push("bv_issue_count_mismatch".to_string());
        }
    }
    if !issue_findings.is_empty() {
        reason_codes.push("issue_projection_diverged".to_string());
    }
    if !bv_findings.is_empty() {
        reason_codes.push("bv_projection_diverged".to_string());
    }
    match lock.state {
        LockState::Missing => {}
        LockState::Held => reason_codes.push("write_lock_held".to_string()),
        LockState::PresentUnknown => reason_codes.push("write_lock_present_unknown".to_string()),
        LockState::StaleSuspected => reason_codes.push("write_lock_stale_suspected".to_string()),
    }

    reason_codes.sort();
    reason_codes.dedup();
    let overall_status = overall_status(
        &jsonl,
        db.as_ref(),
        bv.as_ref(),
        &issue_findings,
        &bv_findings,
        &lock,
    );
    let recommended_actions = recommended_actions(overall_status, &reason_codes);

    StateIntegrityReport {
        generated_at: config.now,
        mutation_attempted: false,
        overall_status,
        jsonl: jsonl.summary,
        db: db.map(|source| source.summary),
        bv: bv.map(|source| source.summary),
        lock,
        query,
        issue_findings,
        bv_findings,
        reason_codes,
        recommended_actions,
    }
}

/// Render the report as a compact operator table.
#[must_use]
pub fn render_table(report: &StateIntegrityReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "overall_status\tmutation_attempted\tjsonl_count\tdb_count\tbv_count\tlock_state\treasons"
    );
    let db_count = report.db.as_ref().map_or_else(
        || "-".to_string(),
        |summary| summary.issue_count.to_string(),
    );
    let bv_count = report.bv.as_ref().map_or_else(
        || "-".to_string(),
        |summary| summary.issue_count.to_string(),
    );
    let _ = writeln!(
        out,
        "{}\t{}\t{}\t{}\t{}\t{:?}\t{}",
        report.overall_status.as_str(),
        report.mutation_attempted,
        report.jsonl.issue_count,
        db_count,
        bv_count,
        report.lock.state,
        report.reason_codes.join(",")
    );

    if let Some(query) = &report.query {
        let _ = writeln!(
            out,
            "\nquery_issue\tstatus\tjsonl_status\tdb_status\tbv_status\trecommendation"
        );
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}",
            query.id,
            query.status,
            query
                .jsonl
                .as_ref()
                .map_or("-", |issue| issue.status.as_str()),
            query.db.as_ref().map_or("-", |issue| issue.status.as_str()),
            query.bv.as_ref().map_or("-", |issue| issue.status.as_str()),
            query.recommendation
        );
    }

    if !report.issue_findings.is_empty() {
        let _ = writeln!(
            out,
            "id\tkind\tjsonl_status\tdb_status\tdiverged_fields\trecommendation"
        );
        for finding in &report.issue_findings {
            let _ = writeln!(
                out,
                "{}\t{:?}\t{}\t{}\t{}\t{}",
                finding.id,
                finding.kind,
                finding.jsonl_status.as_deref().unwrap_or("-"),
                finding.db_status.as_deref().unwrap_or("-"),
                finding.diverged_fields.join(","),
                finding.recommendation
            );
        }
    }

    if !report.bv_findings.is_empty() {
        let _ = writeln!(
            out,
            "id\tkind\tjsonl_status\tbv_status\tdiverged_fields\trecommendation"
        );
        for finding in &report.bv_findings {
            let _ = writeln!(
                out,
                "{}\t{:?}\t{}\t{}\t{}\t{}",
                finding.id,
                finding.kind,
                finding.jsonl_status.as_deref().unwrap_or("-"),
                finding.bv_status.as_deref().unwrap_or("-"),
                finding.diverged_fields.join(","),
                finding.recommendation
            );
        }
    }

    out
}

fn build_issue_query(
    issue_id: &str,
    jsonl: &IssueSource,
    db: Option<&IssueSource>,
    bv: Option<&IssueSource>,
    issue_findings: &[IssueProjectionFinding],
    bv_findings: &[BvProjectionFinding],
) -> IssueQueryReport {
    let jsonl_issue = jsonl.issues.get(issue_id).cloned();
    let db_issue = db.and_then(|source| source.issues.get(issue_id)).cloned();
    let bv_issue = bv.and_then(|source| source.issues.get(issue_id)).cloned();
    let finding = issue_findings
        .iter()
        .find(|finding| finding.id == issue_id)
        .cloned();
    let bv_finding = bv_findings
        .iter()
        .find(|finding| finding.id == issue_id)
        .cloned();

    let status = if !jsonl.summary.parsed
        || db.is_none_or(|source| !source.summary.parsed)
        || bv.is_some_and(|source| !source.summary.parsed)
    {
        IssueQueryStatus::SourceUnavailable
    } else {
        let supplied_sources = 1 + usize::from(db.is_some()) + usize::from(bv.is_some());
        issue_query_status(
            supplied_sources,
            issue_query_presence(jsonl_issue.as_ref(), db_issue.as_ref(), bv_issue.as_ref()),
            finding.as_ref(),
            bv_finding.as_ref(),
        )
    };

    IssueQueryReport {
        id: issue_id.to_string(),
        status,
        jsonl: jsonl_issue,
        db: db_issue,
        bv: bv_issue,
        finding,
        bv_finding,
        recommendation: issue_query_recommendation(status),
    }
}

#[derive(Clone, Copy)]
enum IssueQueryPresence {
    None,
    JsonlOnly,
    DbOnly,
    BvOnly,
    Multiple(usize),
}

impl IssueQueryPresence {
    const fn count(self) -> usize {
        match self {
            Self::None => 0,
            Self::JsonlOnly | Self::DbOnly | Self::BvOnly => 1,
            Self::Multiple(count) => count,
        }
    }
}

fn issue_query_presence(
    jsonl_issue: Option<&IssueProjection>,
    db_issue: Option<&IssueProjection>,
    bv_issue: Option<&IssueProjection>,
) -> IssueQueryPresence {
    match (
        jsonl_issue.is_some(),
        db_issue.is_some(),
        bv_issue.is_some(),
    ) {
        (false, false, false) => IssueQueryPresence::None,
        (true, false, false) => IssueQueryPresence::JsonlOnly,
        (false, true, false) => IssueQueryPresence::DbOnly,
        (false, false, true) => IssueQueryPresence::BvOnly,
        (jsonl_present, db_present, bv_present) => IssueQueryPresence::Multiple(
            usize::from(jsonl_present) + usize::from(db_present) + usize::from(bv_present),
        ),
    }
}

fn issue_query_status(
    supplied_sources: usize,
    issue_presence: IssueQueryPresence,
    finding: Option<&IssueProjectionFinding>,
    bv_finding: Option<&BvProjectionFinding>,
) -> IssueQueryStatus {
    let db_diverged = finding.is_some_and(|finding| {
        matches!(finding.kind, ProjectionFindingKind::IssueProjectionDiverged)
    });
    let bv_diverged = bv_finding.is_some_and(|finding| {
        matches!(finding.kind, BvProjectionFindingKind::BvProjectionDiverged)
    });
    if db_diverged || bv_diverged {
        return IssueQueryStatus::Diverged;
    }

    let present_sources = issue_presence.count();
    if present_sources == supplied_sources && supplied_sources > 1 {
        return IssueQueryStatus::SourcesAgree;
    }
    if present_sources == 0 {
        return IssueQueryStatus::NotFound;
    }
    match issue_presence {
        IssueQueryPresence::JsonlOnly => IssueQueryStatus::JsonlOnly,
        IssueQueryPresence::DbOnly => IssueQueryStatus::DbOnly,
        IssueQueryPresence::BvOnly => IssueQueryStatus::BvOnly,
        IssueQueryPresence::None | IssueQueryPresence::Multiple(_) => {
            IssueQueryStatus::SourceSetMismatch
        }
    }
}

fn issue_query_recommendation(status: IssueQueryStatus) -> String {
    match status {
        IssueQueryStatus::SourcesAgree => {
            "selected issue agrees across supplied sources; normal issue-specific tracker reads are safe"
        }
        IssueQueryStatus::SourceUnavailable => {
            "selected issue cannot be verified because at least one source is unavailable"
        }
        IssueQueryStatus::JsonlOnly => {
            "selected issue is only in JSONL; do not use DB-backed writes until reconciled"
        }
        IssueQueryStatus::DbOnly => {
            "selected issue is only in DB; do not flush or close without human review"
        }
        IssueQueryStatus::BvOnly => {
            "selected issue is only in bv; refresh the graph source before trusting robot triage"
        }
        IssueQueryStatus::SourceSetMismatch => {
            "selected issue exists in only some supplied sources; treat tracker truth as unsafe"
        }
        IssueQueryStatus::Diverged => {
            "selected issue differs across sources; treat it as unsafe to claim or close"
        }
        IssueQueryStatus::NotFound => "selected issue was not found in any parsed source",
    }
    .to_string()
}

fn source_from_issues(
    source: &str,
    path: Option<PathBuf>,
    issues: BTreeMap<String, IssueProjection>,
) -> IssueSource {
    let projection_hash = hash_issue_projection(&issues);
    IssueSource {
        summary: SourceSummary {
            source: source.to_string(),
            path,
            parsed: true,
            issue_count: issues.len(),
            projection_hash: Some(projection_hash),
            error: None,
        },
        issues,
    }
}

fn failed_source(
    source: &str,
    path: Option<&Path>,
    kind: SourceErrorKind,
    message: impl Into<String>,
) -> IssueSource {
    IssueSource {
        summary: SourceSummary {
            source: source.to_string(),
            path: path.map(Path::to_path_buf),
            parsed: false,
            issue_count: 0,
            projection_hash: None,
            error: Some(SourceError {
                kind,
                message: message.into(),
            }),
        },
        issues: BTreeMap::new(),
    }
}

fn load_comment_projections(
    connection: &Connection,
) -> rusqlite::Result<BTreeMap<String, NestedProjection>> {
    let mut statement = connection.prepare(
        "SELECT issue_id, id, author, text, created_at FROM comments \
         ORDER BY issue_id, id",
    )?;
    let rows = statement.query_map([], |row| {
        let issue_id = row.get::<_, String>(0)?;
        let id = row.get::<_, i64>(1)?.to_string();
        let author = row.get::<_, String>(2)?;
        let text = row.get::<_, String>(3)?;
        let created_at = row.get::<_, String>(4)?;
        Ok((
            issue_id,
            record_line(&[
                ("id", id),
                ("author", author),
                ("text", text),
                ("created_at", created_at),
            ]),
        ))
    })?;

    collect_nested_rows(rows)
}

fn load_live_issue_projections(
    connection: &Connection,
    comments: &BTreeMap<String, NestedProjection>,
    dependencies: &BTreeMap<String, NestedProjection>,
) -> rusqlite::Result<BTreeMap<String, IssueProjection>> {
    let mut statement = connection.prepare(
        "SELECT id, title, status, priority, updated_at FROM issues \
         WHERE deleted_at IS NULL ORDER BY id",
    )?;
    let rows = statement.query_map([], |row| {
        live_issue_projection_from_row(row, comments, dependencies)
    })?;

    let mut issues = BTreeMap::new();
    for row in rows {
        let issue = row?;
        issues.insert(issue.id.clone(), issue);
    }
    Ok(issues)
}

fn live_issue_projection_from_row(
    row: &Row<'_>,
    comments: &BTreeMap<String, NestedProjection>,
    dependencies: &BTreeMap<String, NestedProjection>,
) -> rusqlite::Result<IssueProjection> {
    let id = row.get::<_, String>(0)?;
    let title = row.get::<_, String>(1)?;
    let status = row.get::<_, String>(2)?;
    let priority = row
        .get::<_, Option<i64>>(3)?
        .and_then(|value| u8::try_from(value).ok());
    let updated_at = row.get::<_, Option<String>>(4)?;
    let comments = comments
        .get(&id)
        .cloned()
        .unwrap_or_else(empty_nested_projection);
    let dependencies = dependencies
        .get(&id)
        .cloned()
        .unwrap_or_else(empty_nested_projection);
    Ok(projection_from_parts(
        id,
        title,
        status,
        priority,
        updated_at,
        comments,
        dependencies,
    ))
}

fn load_dependency_projections(
    connection: &Connection,
) -> rusqlite::Result<BTreeMap<String, NestedProjection>> {
    let mut statement = connection.prepare(
        "SELECT issue_id, depends_on_id, type, created_at, created_by, metadata, thread_id \
         FROM dependencies ORDER BY issue_id, depends_on_id, type",
    )?;
    let rows = statement.query_map([], |row| {
        let issue_id = row.get::<_, String>(0)?;
        let depends_on_id = row.get::<_, String>(1)?;
        let dependency_type = row.get::<_, String>(2)?;
        let created_at = row.get::<_, String>(3)?;
        let created_by = row.get::<_, String>(4)?;
        let metadata = row.get::<_, Option<String>>(5)?.unwrap_or_default();
        let thread_id = row.get::<_, Option<String>>(6)?.unwrap_or_default();
        Ok((
            issue_id.clone(),
            record_line(&[
                ("issue_id", issue_id),
                ("depends_on_id", depends_on_id),
                ("type", dependency_type),
                ("created_at", created_at),
                ("created_by", created_by),
                ("metadata", metadata),
                ("thread_id", thread_id),
            ]),
        ))
    })?;

    collect_nested_rows(rows)
}

fn collect_nested_rows(
    rows: impl Iterator<Item = rusqlite::Result<(String, String)>>,
) -> rusqlite::Result<BTreeMap<String, NestedProjection>> {
    let mut records_by_issue = BTreeMap::<String, Vec<String>>::new();
    for row in rows {
        let (issue_id, record) = row?;
        records_by_issue.entry(issue_id).or_default().push(record);
    }

    Ok(records_by_issue
        .into_iter()
        .map(|(issue_id, records)| (issue_id, nested_projection_from_records(records)))
        .collect())
}

fn is_conflict_marker(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("<<<<<<<")
        || trimmed.starts_with("=======")
        || trimmed.starts_with(">>>>>>>")
}

fn issue_values_from_snapshot(value: &Value) -> Option<Vec<Value>> {
    if let Some(array) = value.as_array() {
        return Some(array.clone());
    }
    value.get("issues").and_then(Value::as_array).cloned()
}

fn projection_from_value(value: &Value) -> Option<IssueProjection> {
    let id = value.get("id")?.as_str()?.to_string();
    let title = value
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let priority = value
        .get("priority")
        .and_then(Value::as_u64)
        .and_then(|priority| u8::try_from(priority).ok());
    let updated_at = value
        .get("updated_at")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let comments =
        nested_projection_from_value(value, "comments", &["id", "author", "text", "created_at"]);
    let dependencies = nested_projection_from_value(
        value,
        "dependencies",
        &[
            "issue_id",
            "depends_on_id",
            "type",
            "created_at",
            "created_by",
            "metadata",
            "thread_id",
        ],
    );

    Some(projection_from_parts(
        id,
        title,
        status,
        priority,
        updated_at,
        comments,
        dependencies,
    ))
}

fn projection_from_parts(
    id: String,
    title: String,
    status: String,
    priority: Option<u8>,
    updated_at: Option<String>,
    comments: NestedProjection,
    dependencies: NestedProjection,
) -> IssueProjection {
    let mut value = serde_json::Map::new();
    value.insert("id".to_string(), Value::String(id.clone()));
    value.insert("title".to_string(), Value::String(title.clone()));
    value.insert("status".to_string(), Value::String(status.clone()));
    if let Some(priority) = priority {
        value.insert(
            "priority".to_string(),
            Value::Number(Number::from(priority)),
        );
    }
    if let Some(updated_at) = &updated_at {
        value.insert("updated_at".to_string(), Value::String(updated_at.clone()));
    }
    value.insert(
        "comment_count".to_string(),
        Value::Number(number_from_usize(comments.count)),
    );
    value.insert(
        "comment_projection_hash".to_string(),
        Value::String(comments.hash.clone()),
    );
    value.insert(
        "dependency_count".to_string(),
        Value::Number(number_from_usize(dependencies.count)),
    );
    value.insert(
        "dependency_projection_hash".to_string(),
        Value::String(dependencies.hash.clone()),
    );
    let projection_hash = hash_value_fields(
        &Value::Object(value),
        &[
            "id",
            "title",
            "status",
            "priority",
            "updated_at",
            "comment_count",
            "comment_projection_hash",
            "dependency_count",
            "dependency_projection_hash",
        ],
    );

    IssueProjection {
        id,
        title,
        status,
        priority,
        updated_at,
        comment_count: comments.count,
        comment_projection_hash: comments.hash,
        dependency_count: dependencies.count,
        dependency_projection_hash: dependencies.hash,
        projection_hash,
    }
}

fn nested_projection_from_value(
    value: &Value,
    field: &str,
    projected_fields: &[&str],
) -> NestedProjection {
    let records = value
        .get(field)
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |records| {
            records
                .iter()
                .map(|record| {
                    let fields = projected_fields
                        .iter()
                        .map(|projected_field| {
                            (
                                *projected_field,
                                record
                                    .get(*projected_field)
                                    .map_or_else(String::new, canonical_json_value),
                            )
                        })
                        .collect::<Vec<_>>();
                    record_line(&fields)
                })
                .collect()
        });
    nested_projection_from_records(records)
}

fn empty_nested_projection() -> NestedProjection {
    nested_projection_from_records(Vec::new())
}

fn nested_projection_from_records(mut records: Vec<String>) -> NestedProjection {
    records.sort();
    let mut hasher = blake3::Hasher::new();
    for record in &records {
        hasher.update(record.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(record.as_bytes());
        hasher.update(b"\n");
    }
    NestedProjection {
        count: records.len(),
        hash: format!("blake3:{}", hasher.finalize().to_hex()),
    }
}

fn record_line(fields: &[(&str, String)]) -> String {
    let mut out = String::new();
    for (name, value) in fields {
        let _ = writeln!(out, "{name}:{}:{value}", value.len());
    }
    out
}

fn canonical_json_value(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), ToOwned::to_owned)
}

fn number_from_usize(value: usize) -> Number {
    Number::from(u64::try_from(value).unwrap_or(u64::MAX))
}

fn hash_value_fields(value: &Value, fields: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    for field in fields {
        hasher.update(field.as_bytes());
        hasher.update(b"=");
        if let Some(field_value) = value.get(*field) {
            hasher.update(field_value.to_string().as_bytes());
        }
        hasher.update(b"\n");
    }
    format!("blake3:{}", hasher.finalize().to_hex())
}

fn hash_issue_projection(issues: &BTreeMap<String, IssueProjection>) -> String {
    let mut hasher = blake3::Hasher::new();
    for (id, issue) in issues {
        hasher.update(id.as_bytes());
        hasher.update(b"\t");
        hasher.update(issue.projection_hash.as_bytes());
        hasher.update(b"\n");
    }
    format!("blake3:{}", hasher.finalize().to_hex())
}

fn compare_sources(jsonl: &IssueSource, db: &IssueSource) -> Vec<IssueProjectionFinding> {
    if !jsonl.summary.parsed || !db.summary.parsed {
        return Vec::new();
    }

    let ids = jsonl
        .issues
        .keys()
        .chain(db.issues.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    ids.into_iter()
        .filter_map(|id| match (jsonl.issues.get(&id), db.issues.get(&id)) {
            (Some(jsonl_issue), Some(db_issue))
                if jsonl_issue.projection_hash != db_issue.projection_hash =>
            {
                let diverged_fields = diverged_fields(jsonl_issue, db_issue);
                Some(IssueProjectionFinding {
                    id,
                    kind: ProjectionFindingKind::IssueProjectionDiverged,
                    jsonl_status: Some(jsonl_issue.status.clone()),
                    db_status: Some(db_issue.status.clone()),
                    recommendation: divergence_recommendation(&diverged_fields),
                    diverged_fields,
                })
            }
            (Some(jsonl_issue), None) => Some(IssueProjectionFinding {
                id,
                kind: ProjectionFindingKind::JsonlOnly,
                jsonl_status: Some(jsonl_issue.status.clone()),
                db_status: None,
                diverged_fields: Vec::new(),
                recommendation:
                    "do not force-export DB state over JSONL; inspect why the DB is missing this issue"
                        .to_string(),
            }),
            (None, Some(db_issue)) => Some(IssueProjectionFinding {
                id,
                kind: ProjectionFindingKind::DbOnly,
                jsonl_status: None,
                db_status: Some(db_issue.status.clone()),
                diverged_fields: Vec::new(),
                recommendation:
                    "do not flush a DB snapshot that would drop or resurrect this issue without human review"
                        .to_string(),
            }),
            _ => None,
        })
        .collect()
}

fn diverged_fields(jsonl_issue: &IssueProjection, db_issue: &IssueProjection) -> Vec<String> {
    let mut fields = Vec::new();
    if jsonl_issue.title != db_issue.title {
        fields.push("title".to_string());
    }
    if jsonl_issue.status != db_issue.status {
        fields.push("status".to_string());
    }
    if jsonl_issue.priority != db_issue.priority {
        fields.push("priority".to_string());
    }
    if jsonl_issue.updated_at != db_issue.updated_at {
        fields.push("updated_at".to_string());
    }
    if jsonl_issue.comment_projection_hash != db_issue.comment_projection_hash {
        fields.push("comments".to_string());
    }
    if jsonl_issue.dependency_projection_hash != db_issue.dependency_projection_hash {
        fields.push("dependencies".to_string());
    }
    fields
}

fn compare_bv_source(jsonl: &IssueSource, bv: &IssueSource) -> Vec<BvProjectionFinding> {
    if !jsonl.summary.parsed || !bv.summary.parsed {
        return Vec::new();
    }

    let ids = jsonl
        .issues
        .keys()
        .chain(bv.issues.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    ids.into_iter()
        .filter_map(|id| match (jsonl.issues.get(&id), bv.issues.get(&id)) {
            (Some(jsonl_issue), Some(bv_issue))
                if bv_diverged_fields(jsonl_issue, bv_issue).is_empty() =>
            {
                None
            }
            (Some(jsonl_issue), Some(bv_issue)) => {
                let diverged_fields = bv_diverged_fields(jsonl_issue, bv_issue);
                Some(BvProjectionFinding {
                    id,
                    kind: BvProjectionFindingKind::BvProjectionDiverged,
                    jsonl_status: Some(jsonl_issue.status.clone()),
                    bv_status: Some(bv_issue.status.clone()),
                    recommendation: bv_divergence_recommendation(&diverged_fields),
                    diverged_fields,
                })
            }
            (Some(jsonl_issue), None) => Some(BvProjectionFinding {
                id,
                kind: BvProjectionFindingKind::JsonlOnly,
                jsonl_status: Some(jsonl_issue.status.clone()),
                bv_status: None,
                diverged_fields: Vec::new(),
                recommendation:
                    "bv graph snapshot is missing this JSONL issue; refresh bv before trusting robot queues"
                        .to_string(),
            }),
            (None, Some(bv_issue)) => Some(BvProjectionFinding {
                id,
                kind: BvProjectionFindingKind::BvOnly,
                jsonl_status: None,
                bv_status: Some(bv_issue.status.clone()),
                diverged_fields: Vec::new(),
                recommendation:
                    "bv graph snapshot contains an issue absent from JSONL; inspect for stale graph input"
                        .to_string(),
            }),
            _ => None,
        })
        .collect()
}

fn bv_diverged_fields(jsonl_issue: &IssueProjection, bv_issue: &IssueProjection) -> Vec<String> {
    let mut fields = Vec::new();
    if jsonl_issue.title != bv_issue.title {
        fields.push("title".to_string());
    }
    if jsonl_issue.status != bv_issue.status {
        fields.push("status".to_string());
    }
    if jsonl_issue.priority != bv_issue.priority {
        fields.push("priority".to_string());
    }
    fields
}

fn bv_divergence_recommendation(fields: &[String]) -> String {
    if fields.iter().any(|field| field == "status") {
        return "bv graph status disagrees with JSONL; refresh robot graph before claiming or closing"
            .to_string();
    }
    "bv graph projection disagrees with JSONL; refresh bv snapshot before trusting robot triage"
        .to_string()
}

fn divergence_recommendation(fields: &[String]) -> String {
    if fields
        .iter()
        .any(|field| field == "comments" || field == "dependencies")
    {
        return "treat comments/dependencies as unsafe to rely on until DB/JSONL truth is reconciled"
            .to_string();
    }
    "treat this issue as unsafe to claim until DB/JSONL truth is reconciled".to_string()
}

fn inspect_lock(config: &StateIntegrityConfig) -> LockHealth {
    let Some(path) = &config.lock_path else {
        return LockHealth {
            path: None,
            state: LockState::Missing,
            present: false,
            age_seconds: None,
            matching_processes: Vec::new(),
            recommendation: "no lock path configured".to_string(),
        };
    };

    if !path.exists() {
        return LockHealth {
            path: Some(path.clone()),
            state: LockState::Missing,
            present: false,
            age_seconds: None,
            matching_processes: Vec::new(),
            recommendation: "no Beads write lock is present".to_string(),
        };
    }

    let age_seconds = lock_age_seconds(path, config.now);
    let matching_processes = matching_lock_processes(path, &config.active_processes);
    let state = if !matching_processes.is_empty() {
        LockState::Held
    } else if age_seconds.is_some_and(|age| age >= config.lock_stale_after.num_seconds()) {
        LockState::StaleSuspected
    } else {
        LockState::PresentUnknown
    };
    let recommendation = match state {
        LockState::Missing => "no Beads write lock is present",
        LockState::Held => "wait for the active Beads writer or coordinate with the holder",
        LockState::PresentUnknown => {
            "avoid tracker writes until the lock owner is understood; do not delete the lock"
        }
        LockState::StaleSuspected => {
            "stale lock suspected; ask the human before any lock removal or repair action"
        }
    }
    .to_string();

    LockHealth {
        path: Some(path.clone()),
        state,
        present: true,
        age_seconds,
        matching_processes,
        recommendation,
    }
}

fn lock_age_seconds(path: &Path, now: DateTime<Utc>) -> Option<i64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    let modified_at = DateTime::<Utc>::from(modified);
    Some(now.signed_duration_since(modified_at).num_seconds().max(0))
}

fn matching_lock_processes(path: &Path, processes: &[ProcessSnapshot]) -> Vec<LockProcessEvidence> {
    let path_text = path.to_string_lossy();
    processes
        .iter()
        .filter(|process| process.command.contains(path_text.as_ref()))
        .map(|process| LockProcessEvidence {
            pid: process.pid,
            command: redact_command(&process.command),
        })
        .collect()
}

fn collect_source_reasons(summary: &SourceSummary, reason_codes: &mut Vec<String>) {
    if summary.parsed {
        return;
    }
    if let Some(error) = &summary.error {
        reason_codes.push(format!(
            "{}_{}",
            summary.source,
            error_kind_code(error.kind)
        ));
    }
}

const fn error_kind_code(kind: SourceErrorKind) -> &'static str {
    match kind {
        SourceErrorKind::ReadFailed => "read_failed",
        SourceErrorKind::DbOpenFailed => "db_open_failed",
        SourceErrorKind::DbQueryFailed => "db_query_failed",
        SourceErrorKind::JsonlConflictMarkers => "jsonl_conflict_markers",
        SourceErrorKind::JsonlParseError => "jsonl_parse_error",
        SourceErrorKind::SnapshotShapeUnsupported => "snapshot_shape_unsupported",
        SourceErrorKind::SnapshotParseError => "snapshot_parse_error",
        SourceErrorKind::BvGraphShapeUnsupported => "bv_graph_shape_unsupported",
        SourceErrorKind::BvGraphParseError => "bv_graph_parse_error",
    }
}

fn overall_status(
    jsonl: &IssueSource,
    db: Option<&IssueSource>,
    bv: Option<&IssueSource>,
    findings: &[IssueProjectionFinding],
    bv_findings: &[BvProjectionFinding],
    lock: &LockHealth,
) -> StateIntegrityStatus {
    if !jsonl.summary.parsed
        || db.is_some_and(|db_source| !db_source.summary.parsed)
        || bv.is_some_and(|bv_source| !bv_source.summary.parsed)
        || findings.iter().any(|finding| {
            matches!(
                finding.kind,
                ProjectionFindingKind::IssueProjectionDiverged | ProjectionFindingKind::DbOnly
            )
        })
        || !bv_findings.is_empty()
    {
        return StateIntegrityStatus::Blocked;
    }

    if !findings.is_empty()
        || db.is_none()
        || matches!(
            lock.state,
            LockState::Held | LockState::PresentUnknown | LockState::StaleSuspected
        )
    {
        return StateIntegrityStatus::Warning;
    }

    StateIntegrityStatus::Healthy
}

fn recommended_actions(status: StateIntegrityStatus, reason_codes: &[String]) -> Vec<String> {
    let mut actions = Vec::new();
    match status {
        StateIntegrityStatus::Healthy => {
            actions.push("tracker projections agree; normal br/bv workflow is safe".to_string());
        }
        StateIntegrityStatus::Warning | StateIntegrityStatus::Blocked => {
            actions.push(
                "prefer direct JSONL inspection for tracker decisions until sources agree"
                    .to_string(),
            );
            actions.push(
                "do not run force export, DB reconstruction, lock deletion, or destructive git cleanup without explicit human approval"
                    .to_string(),
            );
        }
    }

    if reason_codes.iter().any(|code| code.contains("write_lock")) {
        actions.push("coordinate around .beads/.write.lock instead of deleting it".to_string());
    }
    if reason_codes
        .iter()
        .any(|code| code == "issue_count_mismatch" || code == "bv_issue_count_mismatch")
    {
        actions.push("capture source counts in the Beads or Agent Mail status note".to_string());
    }
    if reason_codes.iter().any(|code| code.contains("bv_")) {
        actions.push(
            "refresh bv robot graph output before trusting ready-queue decisions".to_string(),
        );
    }

    actions
}

fn redact_command(command: &str) -> String {
    let mut redacted = Vec::new();
    let mut redact_next = false;

    for token in command.split_whitespace() {
        if redact_next {
            redacted.push("<redacted>".to_string());
            redact_next = false;
            continue;
        }

        if let Some((name, _value)) = token.split_once('=') {
            if is_sensitive_name(name) {
                redacted.push(format!("{name}=<redacted>"));
            } else {
                redacted.push(token.to_string());
            }
        } else if token.starts_with("--") && is_sensitive_name(token.trim_start_matches('-')) {
            redacted.push(token.to_string());
            redact_next = true;
        } else {
            redacted.push(token.to_string());
        }
    }

    truncate_command(&redacted.join(" "))
}

fn is_sensitive_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "api_key",
        "apikey",
        "auth",
        "bearer",
        "credential",
        "key",
        "password",
        "secret",
        "token",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn truncate_command(command: &str) -> String {
    const MAX_COMMAND_CHARS: usize = 240;
    if command.chars().count() <= MAX_COMMAND_CHARS {
        return command.to_string();
    }

    let mut truncated = command.chars().take(MAX_COMMAND_CHARS).collect::<String>();
    truncated.push_str("...");
    truncated
}

/// Convert a [`SystemTime`] into a UTC timestamp.
#[must_use]
pub fn system_time_to_utc(time: SystemTime) -> DateTime<Utc> {
    DateTime::<Utc>::from(time)
}
