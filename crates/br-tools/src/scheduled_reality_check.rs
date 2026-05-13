//! Monthly reality-check cadence detection and bead proposal helpers.

use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use chrono::{Datelike, NaiveDate};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, info_span};

const REALITY_CHECK_LABEL: &str = "reality-check";
const CADENCE_LABEL: &str = "cadence";
const BEAD_TYPE: &str = "task";
const PRIORITY_P2: u8 = 2;

/// A Beads issue proposal emitted by the monthly cadence check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedBead {
    /// Proposed issue title.
    pub title: String,
    /// Beads priority value, where `0` is highest and `4` is lowest.
    pub priority: u8,
    /// Beads issue type.
    pub issue_type: String,
    /// Operator-facing description for the proposed issue.
    pub description: String,
    /// Labels to attach to the proposed issue.
    pub labels: Vec<String>,
}

/// Minimal existing-bead state needed to prevent duplicate monthly filings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingBead {
    /// Existing issue title.
    pub title: String,
    /// Existing issue status.
    pub status: ExistingBeadStatus,
    /// Whether the existing issue was explicitly marked stale.
    pub stale: bool,
}

/// Status categories used by the cadence idempotency check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExistingBeadStatus {
    /// Existing issue is open.
    Open,
    /// Existing issue is currently claimed.
    InProgress,
    /// Existing issue is blocked but still active.
    Blocked,
    /// Existing issue is closed.
    Closed,
    /// Unknown status preserved for conservative duplicate handling.
    Other(String),
}

impl ExistingBead {
    /// Build an active open issue record.
    #[must_use]
    pub fn open(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            status: ExistingBeadStatus::Open,
            stale: false,
        }
    }

    /// Build a closed issue record.
    #[must_use]
    pub fn closed(title: impl Into<String>, stale: bool) -> Self {
        Self {
            title: title.into(),
            status: ExistingBeadStatus::Closed,
            stale,
        }
    }
}

impl ExistingBeadStatus {
    fn from_status(status: &str) -> Self {
        match status {
            "open" => Self::Open,
            "in_progress" => Self::InProgress,
            "blocked" => Self::Blocked,
            "closed" => Self::Closed,
            other => Self::Other(other.to_string()),
        }
    }

    const fn is_active(&self) -> bool {
        matches!(self, Self::Open | Self::InProgress | Self::Blocked)
    }
}

/// Check the current monthly cadence and propose a reality-check bead when the
/// month has no corresponding reality document.
///
/// This public entry point only inspects files. Call
/// [`check_monthly_cadence_with_existing`] when the caller can also provide the
/// current Beads issue set for duplicate prevention.
#[must_use]
pub fn check_monthly_cadence(today: NaiveDate, reality_dir: &Path) -> Vec<ProposedBead> {
    check_monthly_cadence_with_existing(today, reality_dir, &[])
}

/// Check the current monthly cadence while considering already-filed beads.
///
/// Active matching beads suppress new proposals. Closed matching beads suppress
/// new proposals unless they are explicitly marked stale.
#[must_use]
pub fn check_monthly_cadence_with_existing(
    today: NaiveDate,
    reality_dir: &Path,
    existing_beads: &[ExistingBead],
) -> Vec<ProposedBead> {
    let span = info_span!("fcp.cadence.reality_check");
    let _entered = span.enter();
    let month = month_key(today);
    let title = overdue_title(&month);

    if today.day() != 1 {
        debug!(
            date = %today,
            month,
            file_present = false,
            existing_bead_id = "",
            action = "skip_not_month_boundary",
            "monthly reality-check cadence decision"
        );
        info!(
            date = %today,
            months_checked = 0_u8,
            beads_proposed_count = 0_u8,
            "monthly reality-check cadence complete"
        );
        return Vec::new();
    }

    let file_present = has_reality_check_for_month(reality_dir, &month);
    let duplicate_suppressed = existing_beads
        .iter()
        .any(|bead| bead.title == title && (bead.status.is_active() || !bead.stale));

    let action = if file_present {
        "skip_file_present"
    } else if duplicate_suppressed {
        "skip_existing_bead"
    } else {
        "propose_bead"
    };
    debug!(
        date = %today,
        month,
        file_present,
        existing_bead_id = title,
        action,
        "monthly reality-check cadence decision"
    );

    let proposed = if file_present || duplicate_suppressed {
        Vec::new()
    } else {
        vec![ProposedBead::monthly_reality_check(&month, today)]
    };

    info!(
        date = %today,
        months_checked = 1_u8,
        beads_proposed_count = proposed.len(),
        "monthly reality-check cadence complete"
    );
    proposed
}

/// Load existing Beads issue state from a JSONL export.
///
/// Lines that do not parse as Beads issue records are ignored so the helper can
/// tolerate comments or future record variants.
///
/// # Errors
///
/// Returns an error when the JSONL file cannot be read.
pub fn load_existing_beads(path: &Path) -> Result<Vec<ExistingBead>, std::io::Error> {
    let raw = fs::read_to_string(path)?;
    Ok(raw
        .lines()
        .filter_map(|line| serde_json::from_str::<IssueRecord>(line).ok())
        .map(ExistingBead::from)
        .collect())
}

fn has_reality_check_for_month(reality_dir: &Path, month: &str) -> bool {
    let prefix = format!("{month}-");
    fs::read_dir(reality_dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .any(|path| is_monthly_reality_doc(&path, &prefix))
}

fn is_monthly_reality_doc(path: &Path, prefix: &str) -> bool {
    path.extension().and_then(OsStr::to_str) == Some("md")
        && path
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.starts_with(prefix))
}

fn month_key(today: NaiveDate) -> String {
    format!("{:04}-{:02}", today.year(), today.month())
}

fn overdue_title(month: &str) -> String {
    format!("[reality-check] {month} reality-check pass overdue")
}

impl ProposedBead {
    fn monthly_reality_check(month: &str, today: NaiveDate) -> Self {
        let title = overdue_title(month);
        Self {
            title,
            priority: PRIORITY_P2,
            issue_type: BEAD_TYPE.to_string(),
            description: format!(
                "Monthly reality-check cadence fired on {today}. No docs/reality/{month}-*.md artifact was found. Run /reality-check-for-project, persist the result under docs/reality/, then close this bead with the artifact path and verifier evidence."
            ),
            labels: vec![REALITY_CHECK_LABEL.to_string(), CADENCE_LABEL.to_string()],
        }
    }
}

#[derive(Debug, Deserialize)]
struct IssueRecord {
    title: String,
    status: String,
    #[serde(default)]
    labels: Vec<String>,
    #[serde(default)]
    close_reason: Option<String>,
}

impl From<IssueRecord> for ExistingBead {
    fn from(record: IssueRecord) -> Self {
        let stale = record
            .labels
            .iter()
            .any(|label| label.eq_ignore_ascii_case("stale"))
            || record
                .close_reason
                .as_deref()
                .is_some_and(|reason| reason.to_ascii_lowercase().contains("stale"));
        Self {
            title: record.title,
            status: ExistingBeadStatus::from_status(&record.status),
            stale,
        }
    }
}

/// Return the default repository-relative reality directory used by the CLI.
#[must_use]
pub fn default_reality_dir() -> PathBuf {
    PathBuf::from("docs/reality")
}

/// Return the default repository-relative Beads JSONL path used by the CLI.
#[must_use]
pub fn default_issues_jsonl() -> PathBuf {
    PathBuf::from(".beads/issues.jsonl")
}
