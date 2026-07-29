//! Read-only reconciliation for `bv` ready-queue recommendations.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Stable schema marker for ready-queue reconciliation reports.
pub const READY_QUEUE_RECONCILER_SCHEMA: &str = "fcp.ready-queue-reconciler.v1";

/// Full read-only report comparing `bv` recommendations with Beads truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadyQueueReport {
    /// Schema version for downstream robot consumers.
    pub schema_version: String,
    /// Report generation timestamp.
    pub generated_at: DateTime<Utc>,
    /// Whether the report attempted any mutation. Always false by contract.
    pub mutation_attempted: bool,
    /// Source summaries for the inputs used by the report.
    pub sources: ReadyQueueSources,
    /// Reconciled rows in original `bv` rank order.
    pub recommendations: Vec<ReadyQueueRecommendation>,
    /// Report-level status.
    pub overall_status: ReadyQueueStatus,
    /// Stable reason codes present in the report.
    pub reason_codes: Vec<String>,
    /// Non-destructive suggested next actions.
    pub recommended_actions: Vec<String>,
}

/// Source summaries for the ready-queue report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadyQueueSources {
    /// Beads JSONL source.
    pub jsonl: SourceSummary,
    /// Captured `bv --robot-triage` source.
    pub bv_triage: SourceSummary,
    /// Optional captured DB-backed `br list --json` source.
    pub br_snapshot: Option<SourceSummary>,
}

/// Summary for one parsed source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSummary {
    /// Source role, for example `jsonl`, `bv_triage`, or `br_snapshot`.
    pub source: String,
    /// Source path when one exists.
    pub path: Option<PathBuf>,
    /// Whether parsing succeeded.
    pub parsed: bool,
    /// Number of issue or recommendation records parsed.
    pub record_count: usize,
    /// Redaction-safe error message when parsing failed.
    pub error: Option<String>,
}

/// Overall status for the ready-queue report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadyQueueStatus {
    /// Every recommendation is directly claimable.
    Healthy,
    /// Some recommendations need filtering, but at least one is claimable.
    Warning,
    /// No supplied recommendation is safe to claim without more context.
    Blocked,
}

impl ReadyQueueStatus {
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

/// One reconciled `bv` recommendation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadyQueueRecommendation {
    /// Original `bv` rank, starting at 1.
    pub rank: usize,
    /// Beads issue id.
    pub id: String,
    /// Recommendation title.
    pub title: String,
    /// Status reported by `bv`, if present.
    pub bv_status: Option<String>,
    /// Status in `.beads/issues.jsonl`, if present.
    pub jsonl_status: Option<String>,
    /// Status in a DB-backed `br list --json` snapshot, if supplied.
    pub br_snapshot_status: Option<String>,
    /// Whether an agent can safely claim this row.
    pub claimable: bool,
    /// Reconciled state.
    pub state: ReadyQueueState,
    /// Machine-readable reason codes for this row.
    pub reason_codes: Vec<String>,
    /// Better issue to inspect or claim when this row is an umbrella/blocker.
    pub suggested_issue_id: Option<String>,
    /// Safe next command for an operator or agent.
    pub suggested_next_command: String,
}

/// Per-row reconciliation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadyQueueState {
    /// JSONL and optional DB snapshot agree this issue is open and claimable.
    Claimable,
    /// Recommendation points at stale or missing projection data.
    StaleProjection,
    /// Recommendation is real but blocked by live/hardware/proof prerequisites.
    BlockedLivePrereq,
    /// JSONL says the issue is closed.
    ClosedInJsonl,
    /// DB-backed snapshot and JSONL disagree on projected fields.
    DbJsonlDiverged,
    /// Tracker inputs are incomplete or issue state needs human review.
    NeedsHumanTrackerRefresh,
}

impl ReadyQueueState {
    /// Stable string representation for table output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claimable => "claimable",
            Self::StaleProjection => "stale_projection",
            Self::BlockedLivePrereq => "blocked_live_prereq",
            Self::ClosedInJsonl => "closed_in_jsonl",
            Self::DbJsonlDiverged => "db_jsonl_diverged",
            Self::NeedsHumanTrackerRefresh => "needs_human_tracker_refresh",
        }
    }
}

/// Parsed issue projection from a Beads source.
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
    /// Issue type, if present.
    pub issue_type: Option<String>,
    /// Issue update timestamp, if present.
    pub updated_at: Option<String>,
    /// Labels projected from the issue.
    pub labels: Vec<String>,
    /// Dependency records projected from the issue.
    pub dependencies: Vec<DependencyProjection>,
}

/// Parsed dependency projection from `.beads/issues.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyProjection {
    /// The dependent issue id.
    pub issue_id: String,
    /// The issue this dependency points at.
    pub depends_on_id: String,
    /// Dependency type, for example `blocks` or `parent-child`.
    pub dependency_type: String,
}

/// Parsed `bv` recommendation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BvRecommendation {
    /// Recommendation rank.
    pub rank: usize,
    /// Issue id.
    pub id: String,
    /// Recommendation title.
    pub title: String,
    /// `bv` status, if present.
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueSource {
    pub summary: SourceSummary,
    pub issues: BTreeMap<String, IssueProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BvTriageSource {
    pub summary: SourceSummary,
    pub recommendations: Vec<BvRecommendation>,
}

/// Configuration for ready-queue reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyQueueConfig {
    /// Report generation timestamp.
    pub now: DateTime<Utc>,
}

impl ReadyQueueConfig {
    /// Build a default config at the supplied time.
    #[must_use]
    pub const fn default_with_now(now: DateTime<Utc>) -> Self {
        Self { now }
    }
}

/// Load issue projections from a Beads JSONL export.
#[must_use]
pub fn load_jsonl_source(path: &Path) -> IssueSource {
    let Ok(raw) = fs::read_to_string(path) else {
        return failed_issue_source("jsonl", Some(path), "could not read issues JSONL");
    };
    parse_jsonl_source(Some(path.to_path_buf()), &raw)
}

/// Parse issue projections from a Beads JSONL string.
#[must_use]
pub fn parse_jsonl_source(path: Option<PathBuf>, raw: &str) -> IssueSource {
    let mut issues = BTreeMap::new();
    for (line_index, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            return failed_issue_source(
                "jsonl",
                path.as_deref(),
                &format!("line {} did not parse as JSON", line_index + 1),
            );
        };
        if let Some(issue) = issue_projection_from_value(&value) {
            issues.insert(issue.id.clone(), issue);
        }
    }
    issue_source("jsonl", path, issues)
}

/// Load issue projections from a captured DB-backed `br list --json` snapshot.
#[must_use]
pub fn load_br_snapshot_source(path: &Path) -> IssueSource {
    let Ok(raw) = fs::read_to_string(path) else {
        return failed_issue_source("br_snapshot", Some(path), "could not read br snapshot");
    };
    parse_br_snapshot_source(Some(path.to_path_buf()), &raw)
}

/// Parse issue projections from a captured DB-backed `br list --json` snapshot.
#[must_use]
pub fn parse_br_snapshot_source(path: Option<PathBuf>, raw: &str) -> IssueSource {
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return failed_issue_source(
            "br_snapshot",
            path.as_deref(),
            "br snapshot did not parse as JSON",
        );
    };
    let Some(values) = issue_values_from_snapshot(&value) else {
        return failed_issue_source(
            "br_snapshot",
            path.as_deref(),
            "br snapshot must be an issue object, an array, or an object with an `issues` array",
        );
    };
    let issues = values
        .into_iter()
        .filter_map(issue_projection_from_value)
        .map(|issue| (issue.id.clone(), issue))
        .collect();
    issue_source("br_snapshot", path, issues)
}

/// Load recommendations from captured `bv --robot-triage` JSON.
#[must_use]
pub fn load_bv_triage_source(path: &Path) -> BvTriageSource {
    let Ok(raw) = fs::read_to_string(path) else {
        return failed_bv_source(Some(path), "could not read bv triage JSON");
    };
    parse_bv_triage_source(Some(path.to_path_buf()), &raw)
}

/// Parse recommendations from captured `bv --robot-triage` JSON.
#[must_use]
pub fn parse_bv_triage_source(path: Option<PathBuf>, raw: &str) -> BvTriageSource {
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return failed_bv_source(path.as_deref(), "bv triage did not parse as JSON");
    };
    let Some(values) = value
        .get("triage")
        .and_then(|triage| triage.get("recommendations"))
        .and_then(Value::as_array)
    else {
        return failed_bv_source(
            path.as_deref(),
            "bv triage must contain `triage.recommendations` array",
        );
    };
    let recommendations = values
        .iter()
        .enumerate()
        .filter_map(|(index, value)| bv_recommendation_from_value(index + 1, value))
        .collect::<Vec<_>>();
    let record_count = recommendations.len();
    BvTriageSource {
        summary: SourceSummary {
            source: "bv_triage".to_string(),
            path,
            parsed: true,
            record_count,
            error: None,
        },
        recommendations,
    }
}

/// Build a read-only ready-queue reconciliation report.
#[must_use]
pub fn build_ready_queue_report(
    jsonl: IssueSource,
    bv: BvTriageSource,
    br_snapshot: Option<IssueSource>,
    config: &ReadyQueueConfig,
) -> ReadyQueueReport {
    let recommendations = bv
        .recommendations
        .iter()
        .map(|recommendation| {
            reconcile_recommendation(recommendation, &jsonl, br_snapshot.as_ref())
        })
        .collect::<Vec<_>>();
    let mut reason_codes = BTreeSet::new();
    collect_source_reason(&jsonl.summary, &mut reason_codes);
    collect_source_reason(&bv.summary, &mut reason_codes);
    if let Some(source) = &br_snapshot {
        collect_source_reason(&source.summary, &mut reason_codes);
    }
    for recommendation in &recommendations {
        reason_codes.extend(recommendation.reason_codes.iter().cloned());
    }
    let overall_status = overall_status(&recommendations, &jsonl, &bv, br_snapshot.as_ref());
    let recommended_actions = recommended_actions(overall_status, &recommendations);

    ReadyQueueReport {
        schema_version: READY_QUEUE_RECONCILER_SCHEMA.to_string(),
        generated_at: config.now,
        mutation_attempted: false,
        sources: ReadyQueueSources {
            jsonl: jsonl.summary,
            bv_triage: bv.summary,
            br_snapshot: br_snapshot.map(|source| source.summary),
        },
        recommendations,
        overall_status,
        reason_codes: reason_codes.into_iter().collect(),
        recommended_actions,
    }
}

/// Render a compact operator table.
#[must_use]
pub fn render_table(report: &ReadyQueueReport) -> String {
    let mut out =
        String::from("rank\tid\tstate\tclaimable\tjsonl\tbr_snapshot\tsuggested_issue\tnext\n");
    for row in &report.recommendations {
        let suggested_issue = row.suggested_issue_id.as_deref().unwrap_or("-");
        let jsonl_status = row.jsonl_status.as_deref().unwrap_or("-");
        let br_status = row.br_snapshot_status.as_deref().unwrap_or("-");
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            row.rank,
            row.id,
            row.state.as_str(),
            row.claimable,
            jsonl_status,
            br_status,
            suggested_issue,
            row.suggested_next_command
        );
    }
    out
}

fn reconcile_recommendation(
    recommendation: &BvRecommendation,
    jsonl: &IssueSource,
    br_snapshot: Option<&IssueSource>,
) -> ReadyQueueRecommendation {
    let jsonl_issue = jsonl.issues.get(&recommendation.id);
    let br_issue = br_snapshot.and_then(|source| source.issues.get(&recommendation.id));
    let mut reason_codes = Vec::new();

    let (state, suggested_issue_id) = if !jsonl.summary.parsed {
        reason_codes.push("jsonl_source_unavailable".to_string());
        (ReadyQueueState::NeedsHumanTrackerRefresh, None)
    } else if jsonl_issue.is_none() {
        reason_codes.push("missing_in_jsonl".to_string());
        (ReadyQueueState::StaleProjection, None)
    } else if let Some(issue) = jsonl_issue.filter(|issue| issue.status == "closed") {
        reason_codes.push(format!("jsonl_status:{}", issue.status));
        (ReadyQueueState::ClosedInJsonl, None)
    } else if br_snapshot.is_some_and(|source| !source.summary.parsed) {
        reason_codes.push("br_snapshot_unavailable".to_string());
        (ReadyQueueState::NeedsHumanTrackerRefresh, None)
    } else if jsonl_issue
        .zip(br_issue)
        .is_some_and(|(jsonl_issue, br_issue)| projections_diverge(jsonl_issue, br_issue))
    {
        reason_codes.push("db_jsonl_diverged".to_string());
        (ReadyQueueState::DbJsonlDiverged, None)
    } else if let Some(issue) = jsonl_issue.filter(|issue| issue.status == "blocked") {
        let child = suggested_open_child(issue, &jsonl.issues);
        if child.is_some() {
            reason_codes.push("blocked_parent_has_open_child".to_string());
        } else {
            reason_codes.push("blocked_issue".to_string());
        }
        if looks_like_live_prereq(issue) {
            reason_codes.push("live_or_remote_prereq".to_string());
        }
        (
            ReadyQueueState::BlockedLivePrereq,
            child.map(|issue| issue.id.clone()),
        )
    } else if let Some(issue) = jsonl_issue.filter(|issue| looks_like_live_prereq(issue)) {
        reason_codes.push("live_or_remote_prereq".to_string());
        (
            ReadyQueueState::BlockedLivePrereq,
            suggested_open_child(issue, &jsonl.issues).map(|issue| issue.id.clone()),
        )
    } else if let Some(issue) = jsonl_issue.filter(|issue| issue.status == "open") {
        if has_open_blocking_dependency(issue, &jsonl.issues) {
            reason_codes.push("open_blocking_dependency".to_string());
            (ReadyQueueState::BlockedLivePrereq, None)
        } else {
            reason_codes.push("sources_agree_open".to_string());
            (ReadyQueueState::Claimable, None)
        }
    } else {
        reason_codes.push(format!(
            "jsonl_status:{}",
            jsonl_issue.map_or("unknown", |issue| issue.status.as_str())
        ));
        (ReadyQueueState::NeedsHumanTrackerRefresh, None)
    };

    reason_codes.sort();
    reason_codes.dedup();
    let claimable = state == ReadyQueueState::Claimable;
    let suggested_next_command =
        suggested_next_command(&recommendation.id, state, suggested_issue_id.as_deref());

    ReadyQueueRecommendation {
        rank: recommendation.rank,
        id: recommendation.id.clone(),
        title: jsonl_issue
            .map_or_else(|| recommendation.title.clone(), |issue| issue.title.clone()),
        bv_status: recommendation.status.clone(),
        jsonl_status: jsonl_issue.map(|issue| issue.status.clone()),
        br_snapshot_status: br_issue.map(|issue| issue.status.clone()),
        claimable,
        state,
        reason_codes,
        suggested_issue_id,
        suggested_next_command,
    }
}

fn issue_projection_from_value(value: &Value) -> Option<IssueProjection> {
    let id = value.get("id")?.as_str()?.to_string();
    let title = value
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let priority = value
        .get("priority")
        .and_then(Value::as_u64)
        .and_then(|value| u8::try_from(value).ok());
    let issue_type = value
        .get("issue_type")
        .or_else(|| value.get("type"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let updated_at = value
        .get("updated_at")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let labels = value
        .get("labels")
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |labels| {
            labels
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        });
    let dependencies = value
        .get("dependencies")
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |dependencies| {
            dependencies
                .iter()
                .filter_map(dependency_from_value)
                .collect()
        });

    Some(IssueProjection {
        id,
        title,
        status,
        priority,
        issue_type,
        updated_at,
        labels,
        dependencies,
    })
}

fn dependency_from_value(value: &Value) -> Option<DependencyProjection> {
    Some(DependencyProjection {
        issue_id: value
            .get("issue_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        depends_on_id: value
            .get("depends_on_id")
            .or_else(|| value.get("depends_on"))
            .and_then(Value::as_str)?
            .to_string(),
        dependency_type: value
            .get("type")
            .or_else(|| value.get("dependency_type"))
            .and_then(Value::as_str)
            .unwrap_or("blocks")
            .to_string(),
    })
}

fn bv_recommendation_from_value(rank: usize, value: &Value) -> Option<BvRecommendation> {
    Some(BvRecommendation {
        rank,
        id: value.get("id")?.as_str()?.to_string(),
        title: value
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        status: value
            .get("status")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    })
}

fn issue_values_from_snapshot(value: &Value) -> Option<Vec<&Value>> {
    if let Some(values) = value.as_array() {
        return Some(values.iter().collect());
    }
    if let Some(values) = value.get("issues").and_then(Value::as_array) {
        return Some(values.iter().collect());
    }
    value.get("id").is_some().then_some(vec![value])
}

fn suggested_open_child<'a>(
    issue: &IssueProjection,
    issues: &'a BTreeMap<String, IssueProjection>,
) -> Option<&'a IssueProjection> {
    issues
        .values()
        .filter(|candidate| candidate.status == "open")
        .filter(|candidate| {
            candidate.dependencies.iter().any(|dependency| {
                dependency.depends_on_id == issue.id && dependency.dependency_type == "parent-child"
            })
        })
        .min_by_key(|candidate| (candidate.priority.unwrap_or(u8::MAX), candidate.id.clone()))
}

fn has_open_blocking_dependency(
    issue: &IssueProjection,
    issues: &BTreeMap<String, IssueProjection>,
) -> bool {
    issue.dependencies.iter().any(|dependency| {
        dependency.dependency_type == "blocks"
            && issues
                .get(&dependency.depends_on_id)
                .is_some_and(|dependency_issue| dependency_issue.status != "closed")
    })
}

fn looks_like_live_prereq(issue: &IssueProjection) -> bool {
    let mut haystack = issue.title.to_ascii_lowercase();
    if let Some(issue_type) = &issue.issue_type {
        haystack.push(' ');
        haystack.push_str(&issue_type.to_ascii_lowercase());
    }
    for label in &issue.labels {
        haystack.push(' ');
        haystack.push_str(&label.to_ascii_lowercase());
    }
    [
        "live-proof",
        "live proof",
        "live endpoint",
        "hardware",
        "sandbox suite",
        "remote proof",
        "rch",
        "windows",
        "external review",
        "sandbox_run",
    ]
    .iter()
    .any(|needle| haystack.contains(needle))
}

fn projections_diverge(left: &IssueProjection, right: &IssueProjection) -> bool {
    left.status != right.status
        || left.title != right.title
        || left.priority != right.priority
        || left.issue_type != right.issue_type
}

fn suggested_next_command(
    id: &str,
    state: ReadyQueueState,
    suggested_issue_id: Option<&str>,
) -> String {
    match state {
        ReadyQueueState::Claimable => format!("br update {id} --status in_progress"),
        ReadyQueueState::BlockedLivePrereq => suggested_issue_id.map_or_else(
            || format!("br show {id} --json"),
            |child| format!("br show {child} --json"),
        ),
        ReadyQueueState::ClosedInJsonl => format!("br show {id} --json --no-db"),
        ReadyQueueState::DbJsonlDiverged => {
            format!("br show {id} --json && br show {id} --json --no-db")
        }
        ReadyQueueState::StaleProjection | ReadyQueueState::NeedsHumanTrackerRefresh => {
            "refresh tracker snapshots before claiming".to_string()
        }
    }
}

fn collect_source_reason(summary: &SourceSummary, reason_codes: &mut BTreeSet<String>) {
    if !summary.parsed {
        reason_codes.insert(format!("{}_parse_failed", summary.source));
    }
}

fn overall_status(
    recommendations: &[ReadyQueueRecommendation],
    jsonl: &IssueSource,
    bv: &BvTriageSource,
    br_snapshot: Option<&IssueSource>,
) -> ReadyQueueStatus {
    if !jsonl.summary.parsed
        || !bv.summary.parsed
        || br_snapshot.is_some_and(|source| !source.summary.parsed)
        || recommendations.is_empty()
    {
        return ReadyQueueStatus::Blocked;
    }
    let claimable_count = recommendations
        .iter()
        .filter(|recommendation| recommendation.claimable)
        .count();
    if claimable_count == recommendations.len() {
        ReadyQueueStatus::Healthy
    } else if claimable_count > 0 {
        ReadyQueueStatus::Warning
    } else {
        ReadyQueueStatus::Blocked
    }
}

fn recommended_actions(
    overall_status: ReadyQueueStatus,
    recommendations: &[ReadyQueueRecommendation],
) -> Vec<String> {
    match overall_status {
        ReadyQueueStatus::Healthy => {
            vec!["Claim the highest-ranked reconciled row.".to_string()]
        }
        ReadyQueueStatus::Warning => recommendations
            .iter()
            .find(|recommendation| recommendation.claimable)
            .map_or_else(
                || vec!["Refresh tracker snapshots before claiming.".to_string()],
                |recommendation| {
                    vec![format!(
                        "Prefer reconciled claimable item {}: {}",
                        recommendation.id, recommendation.suggested_next_command
                    )]
                },
            ),
        ReadyQueueStatus::Blocked => {
            vec![
                "Do not claim raw bv recommendations until tracker state is refreshed.".to_string(),
            ]
        }
    }
}

fn issue_source(
    source: &str,
    path: Option<PathBuf>,
    issues: BTreeMap<String, IssueProjection>,
) -> IssueSource {
    let record_count = issues.len();
    IssueSource {
        summary: SourceSummary {
            source: source.to_string(),
            path,
            parsed: true,
            record_count,
            error: None,
        },
        issues,
    }
}

fn failed_issue_source(source: &str, path: Option<&Path>, error: &str) -> IssueSource {
    IssueSource {
        summary: SourceSummary {
            source: source.to_string(),
            path: path.map(Path::to_path_buf),
            parsed: false,
            record_count: 0,
            error: Some(error.to_string()),
        },
        issues: BTreeMap::new(),
    }
}

fn failed_bv_source(path: Option<&Path>, error: &str) -> BvTriageSource {
    BvTriageSource {
        summary: SourceSummary {
            source: "bv_triage".to_string(),
            path: path.map(Path::to_path_buf),
            parsed: false,
            record_count: 0,
            error: Some(error.to_string()),
        },
        recommendations: Vec::new(),
    }
}
