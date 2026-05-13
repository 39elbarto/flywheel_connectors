//! Conformance gate for the Phase H coverage scanner
//! (`flywheel_connectors-angoc.18.3`).
//!
//! Asserts that `scripts/ci/coverage_scanner.sh` correctly classifies every
//! connector as `covered` (has `tests/local_non_mock.rs` OR
//! `tests/live_verification.rs`) or `gap` (has neither), AND that no
//! previously-covered connector regresses into the gap set. Mirrors the
//! ratchet-style approach used by `test_coverage_workspace.rs` —
//! `EXPECTED_GAP_CONNECTORS` is the current baseline; the test fails if a
//! connector NOT in this list regresses (loses both files) OR a connector
//! IS in this list but actually has at least one of the two files (the
//! baseline is stale and should shrink).

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Connectors that currently have neither `tests/local_non_mock.rs` nor
/// `tests/live_verification.rs`. The Phase G graduation epic
/// (`flywheel_connectors-angoc.16`) shrinks this list batch by batch.
/// Adding a new connector to the workspace WITHOUT adding one of the two
/// files is a regression: this test fails until either the file lands or
/// the connector is added here with an explicit graduation reference.
const EXPECTED_GAP_CONNECTORS: &[&str] = &[
    "1password",
    "_adversarial",
    "algolia",
    "amplitude",
    "annas-archive",
    "anthropic-vertex",
    "asana",
    "azure-speech",
    "bitwarden",
    "browser",
    "calendly",
    "cerebras",
    "circleci",
    "clickup",
    "coda",
    "confluence",
    "cron",
    "datadog",
    "dingtalk",
    "discord",
    "docusign",
    "duckduckgo",
    "email-generic",
    "evernote",
    "exa",
    "fal",
    "feishu",
    "figma",
    "firecrawl",
    "gitlab",
    "glm",
    "google-admin-reports",
    "google-ai",
    "google-calendar",
    "google-chat",
    "google-docs",
    "google-meet",
    "google-people",
    "google-sheets",
    "google-workspace-events",
    "grafana",
    "groq",
    "homeassistant",
    "hubspot",
    "huggingface",
    "intercom",
    "inworld",
    "jira",
    "line",
    "linear",
    "linkedin",
    "llm-router",
    "lm-studio",
    "logseq",
    "mailchimp",
    "make",
    "mastodon",
    "matrix",
    "mattermost",
    "mcp-bridge",
    "microsoft-foundry",
    "mistral",
    "mixpanel",
    "monday",
    "n8n",
    "netlify",
    "nextcloud-talk",
    "nostr",
    "notion",
    "nvidia-nim",
    "obsidian",
    "ollama",
    "openrouter",
    "outlook",
    "pandadoc",
    "perplexity-search",
    "plivo",
    "posthog",
    "qq",
    "retool",
    "roam",
    "runway",
    "salesforce",
    "searxng",
    "segment",
    "sendgrid",
    "sentry",
    "spotify",
    "tavily",
    "teams",
    "telnyx",
    "tlon",
    "todoist",
    "trello",
    "twilio",
    "twitch",
    "vectordb",
    "vercel",
    "voyage",
    "webhook-receiver",
    "wecom",
    "whatsapp",
    "xai",
    "zalo",
    "zalouser",
    "zapier",
    "zendesk",
    "zoom",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("CARGO_MANIFEST_DIR has a parent")
        .parent()
        .expect("workspace root exists")
        .to_path_buf()
}

fn connectors_dir() -> PathBuf {
    repo_root().join("connectors")
}

fn scanner_path() -> PathBuf {
    repo_root()
        .join("scripts")
        .join("ci")
        .join("coverage_scanner.sh")
}

#[derive(Debug, Clone)]
struct ScannerRow {
    connector: String,
    has_local_non_mock: bool,
    has_live_verification: bool,
    verdict: String,
}

fn parse_scanner_output(stdout: &str) -> Vec<ScannerRow> {
    stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let value: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("scanner emitted non-JSON line `{line}`: {e}"));
            // Field-level `.as_str()` / `.as_bool()` may return None if the
            // scanner emits a partially-malformed object. Panic with the
            // specific field + offending line so the failure points at the
            // scanner, not at a generic unwrap site in this test.
            let field_str = |field: &str| -> String {
                value[field]
                    .as_str()
                    .unwrap_or_else(|| {
                        panic!("scanner row missing string field `{field}` in line `{line}`")
                    })
                    .to_string()
            };
            let field_bool = |field: &str| -> bool {
                value[field].as_bool().unwrap_or_else(|| {
                    panic!("scanner row missing bool field `{field}` in line `{line}`")
                })
            };
            ScannerRow {
                connector: field_str("connector"),
                has_local_non_mock: field_bool("has_local_non_mock"),
                has_live_verification: field_bool("has_live_verification"),
                verdict: field_str("verdict"),
            }
        })
        .collect()
}

fn run_scanner() -> (i32, Vec<ScannerRow>) {
    let scanner = scanner_path();
    assert!(
        scanner.exists(),
        "scripts/ci/coverage_scanner.sh must exist at {}",
        scanner.display()
    );
    let output = Command::new("bash")
        .arg(&scanner)
        .output()
        .expect("scanner script must execute");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let rows = parse_scanner_output(&stdout);
    (output.status.code().unwrap_or(-1), rows)
}

fn enumerate_connectors() -> BTreeSet<String> {
    let dir = connectors_dir();
    fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read connectors/ dir {}: {e}", dir.display()))
        .filter_map(|entry| {
            let entry = entry.ok()?;
            if entry.file_type().ok()?.is_dir() {
                Some(entry.file_name().to_string_lossy().to_string())
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn test_scanner_enumerates_every_connector() {
    let (_, rows) = run_scanner();
    let scanner_connectors: BTreeSet<String> = rows.iter().map(|r| r.connector.clone()).collect();
    let filesystem_connectors = enumerate_connectors();
    let missing_from_scanner: Vec<&String> = filesystem_connectors
        .difference(&scanner_connectors)
        .collect();
    let phantom_in_scanner: Vec<&String> = scanner_connectors
        .difference(&filesystem_connectors)
        .collect();
    assert!(
        missing_from_scanner.is_empty(),
        "scanner missed connectors that exist on disk: {missing_from_scanner:?}"
    );
    assert!(
        phantom_in_scanner.is_empty(),
        "scanner reported connectors that do not exist on disk: {phantom_in_scanner:?}"
    );
}

#[test]
fn test_scanner_classifies_correctly() {
    let (_, rows) = run_scanner();
    for row in &rows {
        let connector_dir = connectors_dir().join(&row.connector);
        let actual_local = connector_dir
            .join("tests")
            .join("local_non_mock.rs")
            .exists();
        let actual_live = connector_dir
            .join("tests")
            .join("live_verification.rs")
            .exists();
        assert_eq!(
            row.has_local_non_mock, actual_local,
            "scanner has_local_non_mock={} disagrees with filesystem={} for `{}`",
            row.has_local_non_mock, actual_local, row.connector
        );
        assert_eq!(
            row.has_live_verification, actual_live,
            "scanner has_live_verification={} disagrees with filesystem={} for `{}`",
            row.has_live_verification, actual_live, row.connector
        );
        let expected_verdict = if actual_local || actual_live {
            "covered"
        } else {
            "gap"
        };
        assert_eq!(
            row.verdict, expected_verdict,
            "scanner verdict={} disagrees with computed={} for `{}`",
            row.verdict, expected_verdict, row.connector
        );
    }
}

#[test]
fn test_scanner_exit_reflects_gap_presence() {
    let (exit_code, rows) = run_scanner();
    let any_gap = rows.iter().any(|r| r.verdict == "gap");
    if any_gap {
        assert_eq!(
            exit_code, 1,
            "scanner must exit 1 when at least one connector is in gap state; got {exit_code}"
        );
    } else {
        assert_eq!(
            exit_code, 0,
            "scanner must exit 0 when every connector is covered; got {exit_code}"
        );
    }
}

#[test]
fn test_no_new_gap_connectors() {
    let (_, rows) = run_scanner();
    let baseline: BTreeSet<String> = EXPECTED_GAP_CONNECTORS
        .iter()
        .map(|s| s.to_string())
        .collect();
    let actual_gaps: BTreeSet<String> = rows
        .iter()
        .filter(|r| r.verdict == "gap")
        .map(|r| r.connector.clone())
        .collect();
    let regressions: Vec<&String> = actual_gaps.difference(&baseline).collect();
    assert!(
        regressions.is_empty(),
        "new connectors regressed into the gap set (neither local_non_mock.rs nor live_verification.rs): {regressions:?}; \
         either add one of the two test files or update EXPECTED_GAP_CONNECTORS in this test"
    );
}

#[test]
fn test_no_stale_gap_entries_in_baseline() {
    let (_, rows) = run_scanner();
    let baseline: BTreeSet<String> = EXPECTED_GAP_CONNECTORS
        .iter()
        .map(|s| s.to_string())
        .collect();
    let actual_gaps: BTreeSet<String> = rows
        .iter()
        .filter(|r| r.verdict == "gap")
        .map(|r| r.connector.clone())
        .collect();
    let graduated: Vec<&String> = baseline.difference(&actual_gaps).collect();
    assert!(
        graduated.is_empty(),
        "EXPECTED_GAP_CONNECTORS lists connectors that already have coverage (baseline is stale): {graduated:?}; \
         remove them from the baseline to ratchet the coverage gate"
    );
}

#[test]
fn test_baseline_alphabetically_sorted() {
    let baseline: Vec<&&str> = EXPECTED_GAP_CONNECTORS.iter().collect();
    let mut sorted_baseline = baseline.clone();
    sorted_baseline.sort();
    assert_eq!(
        baseline, sorted_baseline,
        "EXPECTED_GAP_CONNECTORS must stay alphabetically sorted for stable diffs"
    );
}
