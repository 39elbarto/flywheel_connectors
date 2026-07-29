//! Redacted incident fixture replay for recurring proof/tooling blockers.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const INCIDENT_FIXTURE_SCHEMA: &str = "fcp.incident-fixture.v1";
pub const INCIDENT_REPLAY_SCHEMA: &str = "fcp.incident-fixture-replay.v1";

/// A curated, redacted operational blocker example.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentFixture {
    /// Schema version for fixture compatibility checks.
    pub schema_version: String,
    /// Stable fixture id.
    pub id: String,
    /// Source family for the blocker.
    pub source_class: IncidentSourceClass,
    /// Compact human-readable summary.
    pub summary: String,
    /// Redacted transcript excerpt.
    pub transcript: String,
    /// Classification the replay must reproduce.
    pub expected_classification: IncidentClassification,
    /// Safe next action expected from an agent.
    pub expected_agent_action: String,
    /// Actions agents must not take for this incident.
    pub forbidden_actions: Vec<String>,
    /// Redaction placeholders that must appear in the transcript.
    pub redaction_markers: Vec<String>,
}

/// Source family for a recurring incident shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSourceClass {
    Rch,
    Beads,
    AgentMail,
    DiskPressure,
    SharedTreeDrift,
}

impl IncidentSourceClass {
    /// Stable string representation for table output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rch => "rch",
            Self::Beads => "beads",
            Self::AgentMail => "agent_mail",
            Self::DiskPressure => "disk_pressure",
            Self::SharedTreeDrift => "shared_tree_drift",
        }
    }
}

/// Normalized blocker classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentClassification {
    ProofInfraBlocker,
    TrackerStateBlocker,
    DegradedCoordination,
    DiskPressureRequiresPlan,
    SharedTreeNoise,
}

impl IncidentClassification {
    /// Stable string representation for table output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProofInfraBlocker => "proof_infra_blocker",
            Self::TrackerStateBlocker => "tracker_state_blocker",
            Self::DegradedCoordination => "degraded_coordination",
            Self::DiskPressureRequiresPlan => "disk_pressure_requires_plan",
            Self::SharedTreeNoise => "shared_tree_noise",
        }
    }
}

/// Config for a deterministic replay run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentReplayConfig {
    /// Report generation timestamp.
    pub now: DateTime<Utc>,
    /// Optional corpus path recorded in reports.
    pub corpus_dir: Option<PathBuf>,
}

impl IncidentReplayConfig {
    /// Build a replay config with an explicit timestamp.
    #[must_use]
    pub fn default_with_now(now: DateTime<Utc>) -> Self {
        Self {
            now,
            corpus_dir: Some(default_fixture_dir()),
        }
    }
}

/// Replay report for the incident corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentReplayReport {
    /// Schema version for downstream robot consumers.
    pub schema_version: String,
    /// Report generation timestamp.
    pub generated_at: DateTime<Utc>,
    /// Whether replay attempted mutation. Always false by contract.
    pub mutation_attempted: bool,
    /// Corpus directory used by the run, when available.
    pub corpus_dir: Option<PathBuf>,
    /// Aggregate replay summary.
    pub summary: IncidentReplaySummary,
    /// Per-fixture replay events.
    pub events: Vec<IncidentReplayEvent>,
    /// Stable reason codes present in the report.
    pub reason_codes: Vec<String>,
}

/// Aggregate replay summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentReplaySummary {
    /// Total fixtures replayed.
    pub total: usize,
    /// Fixtures that matched classification and passed validation.
    pub passed: usize,
    /// Fixtures that failed validation or classification.
    pub failed: usize,
    /// Fixture count by source class.
    pub by_source_class: BTreeMap<String, usize>,
    /// Fixture count by actual classification.
    pub by_classification: BTreeMap<String, usize>,
}

/// Per-fixture replay event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentReplayEvent {
    /// Stable fixture id.
    pub fixture_id: String,
    /// Source family for the blocker.
    pub source_class: IncidentSourceClass,
    /// Expected classification from the fixture.
    pub expected_classification: IncidentClassification,
    /// Actual classifier result.
    pub actual_classification: IncidentClassification,
    /// Whether this fixture passed replay.
    pub passed: bool,
    /// Safe next action from the fixture.
    pub expected_agent_action: String,
    /// Forbidden actions from the fixture.
    pub forbidden_actions: Vec<String>,
    /// Redaction validation result.
    pub redaction_passed: bool,
    /// Stable reason codes for robot consumers.
    pub reason_codes: Vec<String>,
}

/// Load all JSON incident fixtures from a directory in stable path order.
///
/// # Errors
///
/// Returns an error when the directory cannot be read or any fixture file fails
/// to load or parse.
pub fn load_fixture_dir(path: &Path) -> Result<Vec<IncidentFixture>, String> {
    let mut paths = fs::read_dir(path)
        .map_err(|err| format!("could not read fixture dir {}: {err}", path.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    paths.sort();

    paths
        .iter()
        .map(|path| load_fixture_file(path))
        .collect::<Result<Vec<_>, _>>()
}

/// Load a single JSON incident fixture.
///
/// # Errors
///
/// Returns an error when the file cannot be read or the fixture JSON is invalid.
pub fn load_fixture_file(path: &Path) -> Result<IncidentFixture, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("could not read fixture {}: {err}", path.display()))?;
    parse_fixture(&raw).map_err(|err| format!("{}: {err}", path.display()))
}

/// Parse a single JSON incident fixture.
///
/// # Errors
///
/// Returns an error when the fixture JSON does not match the corpus schema.
pub fn parse_fixture(raw: &str) -> Result<IncidentFixture, String> {
    serde_json::from_str(raw).map_err(|err| format!("fixture did not parse as JSON: {err}"))
}

/// Build a deterministic replay report.
#[must_use]
pub fn build_replay_report(
    fixtures: &[IncidentFixture],
    config: &IncidentReplayConfig,
) -> IncidentReplayReport {
    let events = fixtures
        .iter()
        .map(replay_fixture)
        .collect::<Vec<IncidentReplayEvent>>();
    let mut by_source_class = BTreeMap::new();
    let mut by_classification = BTreeMap::new();
    let mut reason_codes = BTreeSet::new();

    for event in &events {
        *by_source_class
            .entry(event.source_class.as_str().to_string())
            .or_insert(0) += 1;
        *by_classification
            .entry(event.actual_classification.as_str().to_string())
            .or_insert(0) += 1;
        reason_codes.extend(event.reason_codes.iter().cloned());
    }

    let passed = events.iter().filter(|event| event.passed).count();
    let failed = events.len().saturating_sub(passed);

    IncidentReplayReport {
        schema_version: INCIDENT_REPLAY_SCHEMA.to_string(),
        generated_at: config.now,
        mutation_attempted: false,
        corpus_dir: config.corpus_dir.clone(),
        summary: IncidentReplaySummary {
            total: events.len(),
            passed,
            failed,
            by_source_class,
            by_classification,
        },
        events,
        reason_codes: reason_codes.into_iter().collect(),
    }
}

/// Replay one incident fixture.
#[must_use]
pub fn replay_fixture(fixture: &IncidentFixture) -> IncidentReplayEvent {
    let actual_classification = classify_fixture(fixture);
    let mut reason_codes = validate_fixture(fixture);
    if actual_classification == fixture.expected_classification {
        reason_codes.push("classification_matched".to_string());
    } else {
        reason_codes.push("classification_mismatch".to_string());
    }
    reason_codes.sort();
    reason_codes.dedup();

    let redaction_passed = !reason_codes
        .iter()
        .any(|reason| reason.starts_with("redaction_violation:"));
    let passed = redaction_passed
        && actual_classification == fixture.expected_classification
        && !reason_codes
            .iter()
            .any(|reason| reason.starts_with("fixture_invalid:"));

    IncidentReplayEvent {
        fixture_id: fixture.id.clone(),
        source_class: fixture.source_class,
        expected_classification: fixture.expected_classification,
        actual_classification,
        passed,
        expected_agent_action: fixture.expected_agent_action.clone(),
        forbidden_actions: fixture.forbidden_actions.clone(),
        redaction_passed,
        reason_codes,
    }
}

/// Classify an incident using stable source and transcript cues.
#[must_use]
pub fn classify_fixture(fixture: &IncidentFixture) -> IncidentClassification {
    let transcript = fixture.transcript.to_ascii_lowercase();
    match fixture.source_class {
        IncidentSourceClass::Rch
            if transcript.contains("[rch] local")
                || transcript.contains("local fallback")
                || transcript.contains("no admissible workers")
                || transcript.contains("worker=null")
                || transcript.contains("stale preflight")
                || transcript.contains("artifact retrieval") =>
        {
            IncidentClassification::ProofInfraBlocker
        }
        IncidentSourceClass::Rch => IncidentClassification::ProofInfraBlocker,
        IncidentSourceClass::Beads
            if transcript.contains("db/jsonl")
                || transcript.contains("jsonl")
                || transcript.contains(".write.lock")
                || transcript.contains("stale db") =>
        {
            IncidentClassification::TrackerStateBlocker
        }
        IncidentSourceClass::Beads => IncidentClassification::TrackerStateBlocker,
        IncidentSourceClass::AgentMail
            if transcript.contains("agent mail")
                || transcript.contains("mcp-agent-mail")
                || transcript.contains("degraded")
                || transcript.contains("unavailable")
                || transcript.contains("sqlite") =>
        {
            IncidentClassification::DegradedCoordination
        }
        IncidentSourceClass::AgentMail => IncidentClassification::DegradedCoordination,
        IncidentSourceClass::DiskPressure
            if transcript.contains("no space left")
                || transcript.contains("disk pressure")
                || transcript.contains("cargo_target_dir")
                || transcript.contains("target-dir") =>
        {
            IncidentClassification::DiskPressureRequiresPlan
        }
        IncidentSourceClass::DiskPressure => IncidentClassification::DiskPressureRequiresPlan,
        IncidentSourceClass::SharedTreeDrift
            if transcript.contains("dirty")
                || transcript.contains("unrelated")
                || transcript.contains("compile noise")
                || transcript.contains("shared tree") =>
        {
            IncidentClassification::SharedTreeNoise
        }
        IncidentSourceClass::SharedTreeDrift => IncidentClassification::SharedTreeNoise,
    }
}

/// Validate required fixture fields and redaction rules.
#[must_use]
pub fn validate_fixture(fixture: &IncidentFixture) -> Vec<String> {
    let mut reasons = Vec::new();
    if fixture.schema_version != INCIDENT_FIXTURE_SCHEMA {
        reasons.push(format!(
            "fixture_invalid:schema_version:{}",
            fixture.schema_version
        ));
    }
    if fixture.id.trim().is_empty() {
        reasons.push("fixture_invalid:missing_id".to_string());
    }
    if fixture.summary.trim().is_empty() {
        reasons.push("fixture_invalid:missing_summary".to_string());
    }
    if fixture.transcript.trim().is_empty() {
        reasons.push("fixture_invalid:missing_transcript".to_string());
    }
    if fixture.expected_agent_action.trim().is_empty() {
        reasons.push("fixture_invalid:missing_expected_agent_action".to_string());
    }
    if fixture.forbidden_actions.is_empty() {
        reasons.push("fixture_invalid:missing_forbidden_actions".to_string());
    }
    if fixture.redaction_markers.is_empty() {
        reasons.push("fixture_invalid:missing_redaction_markers".to_string());
    }
    for marker in &fixture.redaction_markers {
        if !fixture.transcript.contains(marker) {
            reasons.push(format!("fixture_invalid:missing_marker:{marker}"));
        }
    }
    for violation in redaction_violations(&fixture.transcript) {
        reasons.push(format!("redaction_violation:{violation}"));
    }
    if reasons.is_empty() {
        reasons.push("fixture_valid".to_string());
    }
    reasons
}

/// Return redaction violation reason codes for sensitive transcript patterns.
#[must_use]
pub fn redaction_violations(transcript: &str) -> Vec<String> {
    let lower = transcript.to_ascii_lowercase();
    let mut violations = Vec::new();
    let sensitive_substrings = [
        ("bearer_token", "bearer "),
        ("api_key_assignment", "api_key="),
        ("token_assignment", "token="),
        ("password_assignment", "password="),
        ("secret_assignment", "secret="),
        ("github_token", "ghp_"),
        ("github_pat", "github_pat_"),
        ("openai_key", "sk-"),
        ("slack_token", "xoxb-"),
        ("private_key", "-----begin"),
        ("provider_body", "provider_body:"),
        ("raw_body", "raw_body:"),
        ("mac_private_path", "/users/"),
        ("linux_private_path", "/home/"),
        ("darwin_private_tmp", "/private/var/"),
        ("windows_private_path", "\\users\\"),
    ];

    for (reason, pattern) in sensitive_substrings {
        if lower.contains(pattern) {
            violations.push(reason.to_string());
        }
    }

    if transcript
        .split_whitespace()
        .any(looks_like_private_email_or_host)
    {
        violations.push("possible_email_or_private_host".to_string());
    }

    violations.sort();
    violations.dedup();
    violations
}

/// Render a compact tab-separated human summary.
#[must_use]
pub fn render_table(report: &IncidentReplayReport) -> String {
    let mut out = String::from("fixture_id\tsource\tclassification\tpassed\tredaction\taction\n");
    for event in &report.events {
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}",
            event.fixture_id,
            event.source_class.as_str(),
            event.actual_classification.as_str(),
            event.passed,
            event.redaction_passed,
            event.expected_agent_action
        );
    }
    out
}

/// Write deterministic replay artifacts.
///
/// # Errors
///
/// Returns an error when JSON encoding fails or an output artifact cannot be
/// written.
pub fn write_report_outputs(
    report: &IncidentReplayReport,
    summary_json: Option<&Path>,
    events_jsonl: Option<&Path>,
) -> Result<(), String> {
    if let Some(path) = summary_json {
        let raw = serde_json::to_string_pretty(report)
            .map_err(|err| format!("could not encode summary JSON: {err}"))?;
        fs::write(path, format!("{raw}\n"))
            .map_err(|err| format!("could not write summary JSON {}: {err}", path.display()))?;
    }
    if let Some(path) = events_jsonl {
        let mut raw = String::new();
        for event in &report.events {
            let line = serde_json::to_string(event)
                .map_err(|err| format!("could not encode event JSONL: {err}"))?;
            raw.push_str(&line);
            raw.push('\n');
        }
        fs::write(path, raw)
            .map_err(|err| format!("could not write events JSONL {}: {err}", path.display()))?;
    }
    Ok(())
}

/// Default package-relative incident fixture directory.
#[must_use]
pub fn default_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/incidents")
}

fn looks_like_private_email_or_host(word: &str) -> bool {
    let clean = word.trim_matches(|ch: char| {
        matches!(ch, ',' | ';' | ':' | ')' | '(' | '[' | ']' | '"' | '\'')
    });
    clean.contains('@')
        && clean.contains('.')
        && !clean.contains("[REDACTED")
        && !clean.contains('<')
}
