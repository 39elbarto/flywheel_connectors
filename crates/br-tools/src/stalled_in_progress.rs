//! Read-only stale `in_progress` Beads reporting.

use std::{
    collections::BTreeSet,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Default staleness threshold for claimed Beads work.
pub const DEFAULT_STALE_AFTER_HOURS: i64 = 72;
/// Default recent-comment window that blocks automatic reopen recommendations.
pub const DEFAULT_RECENT_COMMENT_HOURS: i64 = 24;

/// Beads recovery report with one finding per `in_progress` issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StalledInProgressReport {
    /// Report generation timestamp.
    pub generated_at: DateTime<Utc>,
    /// Age threshold used to consider an issue stale.
    pub stale_after_hours: i64,
    /// Comment recency threshold used to avoid overwriting live handoffs.
    pub recent_comment_hours: i64,
    /// Lock file checked by the report, when configured.
    pub lock_path: Option<PathBuf>,
    /// Whether the checked lock file currently exists.
    pub lock_present: bool,
    /// Classified `in_progress` issue findings.
    pub findings: Vec<StalledInProgressFinding>,
}

/// One classified `in_progress` issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StalledInProgressFinding {
    /// Beads issue id.
    pub id: String,
    /// Issue title.
    pub title: String,
    /// Current assignee, if any.
    pub assignee: Option<String>,
    /// Issue `updated_at` timestamp.
    pub updated_at: DateTime<Utc>,
    /// Most recent comment timestamp, if any comments parsed.
    pub last_comment_at: Option<DateTime<Utc>>,
    /// Issue age in whole hours at report generation time.
    pub age_hours: i64,
    /// Whether `updated_at` exceeded the configured staleness threshold.
    pub stale: bool,
    /// Matching process evidence found by the caller.
    pub active_process_evidence: Vec<ActiveProcessEvidence>,
    /// Recommended operator action.
    pub recommended_action: RecommendedAction,
    /// Machine-readable reasons for the recommendation.
    pub reason_codes: Vec<String>,
    /// Safe command for operator review when reopening is recommended.
    pub safe_reopen_command: Option<String>,
}

/// Process evidence that mentions an issue id or assignee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveProcessEvidence {
    /// Process id when available.
    pub pid: Option<u32>,
    /// Redaction-safe process command line as observed by the caller.
    pub command: String,
    /// What caused this process to match the issue.
    pub matched_on: String,
}

/// Operator action recommendation for a stale `in_progress` issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    /// Reopen the issue with a reviewed `br update` command.
    Reopen,
    /// Human or agent should inspect before changing tracker state.
    Investigate,
    /// Evidence suggests the claim is still live.
    LeaveClaimed,
    /// The issue looks reopenable, but a Beads write lock is present.
    BlockedByLock,
}

impl RecommendedAction {
    /// Stable string representation for table output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reopen => "reopen",
            Self::Investigate => "investigate",
            Self::LeaveClaimed => "leave_claimed",
            Self::BlockedByLock => "blocked_by_lock",
        }
    }
}

/// Configuration for `in_progress` recovery classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportConfig {
    /// Report generation timestamp.
    pub now: DateTime<Utc>,
    /// Age threshold used to consider an issue stale.
    pub stale_after: Duration,
    /// Comment recency threshold used to avoid overwriting live handoffs.
    pub recent_comment_after: Duration,
    /// Optional lock path checked before recommending tracker writes.
    pub lock_path: Option<PathBuf>,
    /// Whether the configured lock path exists.
    pub lock_present: bool,
    /// Active process command lines to match against issue ids and assignees.
    pub active_processes: Vec<ProcessSnapshot>,
    /// Known active agent names from an external roster, when available.
    pub known_agents: BTreeSet<String>,
}

impl ReportConfig {
    /// Build a configuration using the repository defaults.
    #[must_use]
    pub fn default_with_now(now: DateTime<Utc>) -> Self {
        let lock_path = Some(default_write_lock_path());
        let lock_present = lock_path.as_deref().is_some_and(Path::exists);
        Self {
            now,
            stale_after: Duration::hours(DEFAULT_STALE_AFTER_HOURS),
            recent_comment_after: Duration::hours(DEFAULT_RECENT_COMMENT_HOURS),
            lock_path,
            lock_present,
            active_processes: Vec::new(),
            known_agents: BTreeSet::new(),
        }
    }
}

/// Process snapshot used as read-only evidence.
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

/// Load Beads issue records from a JSONL export.
///
/// Lines that are not issue records are ignored to tolerate future record
/// variants in the export.
///
/// # Errors
///
/// Returns an error when the JSONL file cannot be read.
pub fn load_issue_records(path: &Path) -> Result<Vec<IssueRecord>, std::io::Error> {
    let raw = fs::read_to_string(path)?;
    Ok(raw
        .lines()
        .filter_map(|line| serde_json::from_str::<IssueRecord>(line).ok())
        .collect())
}

/// Generate a read-only stale `in_progress` report.
#[must_use]
pub fn build_report(issues: &[IssueRecord], config: &ReportConfig) -> StalledInProgressReport {
    let findings = issues
        .iter()
        .filter(|issue| issue.status == "in_progress")
        .filter_map(|issue| classify_issue(issue, config))
        .collect();

    StalledInProgressReport {
        generated_at: config.now,
        stale_after_hours: config.stale_after.num_hours(),
        recent_comment_hours: config.recent_comment_after.num_hours(),
        lock_path: config.lock_path.clone(),
        lock_present: config.lock_present,
        findings,
    }
}

/// Render the report as a compact operator table.
#[must_use]
pub fn render_table(report: &StalledInProgressReport) -> String {
    let mut out =
        String::from("id\tassignee\tupdated_at\tage_hours\taction\treasons\tsafe_reopen_command\n");
    for finding in &report.findings {
        let assignee = finding.assignee.as_deref().unwrap_or("-");
        let command = finding.safe_reopen_command.as_deref().unwrap_or("-");
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            finding.id,
            assignee,
            finding.updated_at.to_rfc3339(),
            finding.age_hours,
            finding.recommended_action.as_str(),
            finding.reason_codes.join(","),
            command
        );
    }
    out
}

/// Return the default repository-relative Beads write lock path.
#[must_use]
pub fn default_write_lock_path() -> PathBuf {
    PathBuf::from(".beads/.write.lock")
}

fn classify_issue(issue: &IssueRecord, config: &ReportConfig) -> Option<StalledInProgressFinding> {
    let updated_at = parse_timestamp(&issue.updated_at)?;
    let last_comment_at = issue
        .comments
        .iter()
        .filter_map(|comment| parse_timestamp(&comment.created_at))
        .max();
    let age = config.now.signed_duration_since(updated_at);
    let age_hours = age.num_hours();
    let stale = age >= config.stale_after;
    let recent_comment = last_comment_at.is_some_and(|commented_at| {
        config.now.signed_duration_since(commented_at) <= config.recent_comment_after
    });
    let assignee = clean_assignee(issue.assignee.as_deref());
    let active_process_evidence = active_process_evidence(issue, assignee.as_deref(), config);

    let (recommended_action, reason_codes) = recommendation(
        stale,
        recent_comment,
        assignee.as_deref(),
        &active_process_evidence,
        config,
    );
    let safe_reopen_command = (recommended_action == RecommendedAction::Reopen)
        .then(|| format!("br update {} --status open --assignee ''", issue.id));

    Some(StalledInProgressFinding {
        id: issue.id.clone(),
        title: issue.title.clone(),
        assignee,
        updated_at,
        last_comment_at,
        age_hours,
        stale,
        active_process_evidence,
        recommended_action,
        reason_codes,
        safe_reopen_command,
    })
}

fn recommendation(
    stale: bool,
    recent_comment: bool,
    assignee: Option<&str>,
    active_process_evidence: &[ActiveProcessEvidence],
    config: &ReportConfig,
) -> (RecommendedAction, Vec<String>) {
    let mut reasons = Vec::new();
    if stale {
        reasons.push("stale_updated_at".to_string());
    } else {
        reasons.push("recently_updated".to_string());
    }

    if recent_comment {
        reasons.push("recent_comment".to_string());
    }

    if active_process_evidence.is_empty() {
        reasons.push("no_active_process_evidence".to_string());
    } else {
        reasons.push("active_process_evidence".to_string());
    }

    let assignee_known = assignee.is_some_and(|name| config.known_agents.contains(name));
    match assignee {
        Some(name) if assignee_known => reasons.push(format!("known_assignee:{name}")),
        Some(name) => reasons.push(format!("unknown_assignee:{name}")),
        None => reasons.push("missing_assignee".to_string()),
    }

    let action = if !stale || !active_process_evidence.is_empty() {
        RecommendedAction::LeaveClaimed
    } else if recent_comment || assignee.is_some() {
        RecommendedAction::Investigate
    } else if config.lock_present {
        reasons.push("beads_write_lock_present".to_string());
        RecommendedAction::BlockedByLock
    } else {
        RecommendedAction::Reopen
    };

    (action, reasons)
}

fn active_process_evidence(
    issue: &IssueRecord,
    assignee: Option<&str>,
    config: &ReportConfig,
) -> Vec<ActiveProcessEvidence> {
    config
        .active_processes
        .iter()
        .filter_map(|process| {
            match_process(process, &issue.id, assignee).map(|matched_on| ActiveProcessEvidence {
                pid: process.pid,
                command: redact_command(&process.command),
                matched_on,
            })
        })
        .collect()
}

fn match_process(
    process: &ProcessSnapshot,
    issue_id: &str,
    assignee: Option<&str>,
) -> Option<String> {
    if process.command.contains(issue_id) {
        return Some(format!("issue_id:{issue_id}"));
    }

    assignee
        .filter(|name| !name.is_empty() && process.command.contains(name))
        .map(|name| format!("assignee:{name}"))
}

fn clean_assignee(assignee: Option<&str>) -> Option<String> {
    assignee
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw).map(DateTime::from).ok()
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

/// Minimal Beads issue record used by stale-claim reporting.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct IssueRecord {
    /// Beads issue id.
    pub id: String,
    /// Issue title.
    pub title: String,
    /// Current issue status.
    pub status: String,
    /// Current assignee, if any.
    #[serde(default)]
    pub assignee: Option<String>,
    /// Issue update timestamp.
    pub updated_at: String,
    /// Issue comments.
    #[serde(default)]
    pub comments: Vec<CommentRecord>,
}

/// Minimal Beads comment record used by stale-claim reporting.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CommentRecord {
    /// Comment creation timestamp.
    pub created_at: String,
}
