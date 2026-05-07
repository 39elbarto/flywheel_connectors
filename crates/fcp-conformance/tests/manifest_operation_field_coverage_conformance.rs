//! Raw manifest per-operation metadata coverage for the live connector corpus.
//!
//! This complements `manifest_operations_conformance`: that test tracks
//! connectors with no canonical `[provides.operations.*]` entries at all, while
//! this test tracks connectors that do declare operations but still miss the
//! fields the host and `fwc` need for per-operation policy and introspection.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::json;

const INPUT_SCHEMA: &str = "input_schema";
const OUTPUT_SCHEMA: &str = "output_schema";
const NETWORK_CONSTRAINTS: &str = "network_constraints";
const AI_HINTS: &str = "ai_hints";
const SANDBOX: &str = "sandbox";
const INVALID_INPUT_SCHEMA: &str = "invalid_input_schema";
const INVALID_OUTPUT_SCHEMA: &str = "invalid_output_schema";
const EXPECTED_SCHEMA_GAPS: &[&str] = &[
    "bluebubbles",
    "confluence",
    "dingtalk",
    "email-generic",
    "google-places",
    "google-workspace-events",
    "hue",
    "imessage",
    "mastodon",
    "netlify",
    "nostr",
    "qq",
    "sonos",
    "twitch",
    "vercel",
    "wecom",
    "whatsapp",
];
const EXPECTED_NETWORK_CONSTRAINT_GAPS: &[&str] = &[
    "anthropic",
    "apple-notes",
    "apple-reminders",
    "dingtalk",
    "email-generic",
    "google-ai",
    "google-chat",
    "google-workspace-events",
    "hue",
    "irc",
    "linear",
    "llm-router",
    "mastodon",
    "mattermost",
    "microsoft365",
    "nextcloud-talk",
    "nostr",
    "openai",
    "plivo",
    "qq",
    "sonos",
    "synology-chat",
    "teams",
    "telnyx",
    "tlon",
    "twilio",
    "vectordb",
    "wecom",
    "whatsapp",
    "zalo",
];
const EXPECTED_AI_HINT_GAPS: &[&str] = &[
    "anthropic",
    "aws-bedrock",
    "dingtalk",
    "email-generic",
    "firebase",
    "google-people",
    "google-workspace-events",
    "mastodon",
    "mattermost",
    "nostr",
    "plivo",
    "qq",
    "telnyx",
    "wecom",
];
const EXPECTED_SANDBOX_GAPS: &[&str] = &[];

#[derive(Debug, Clone)]
struct ManifestFieldCoverageRecord {
    connector: String,
    connector_id: String,
    manifest_path: String,
    operation_count: usize,
    missing_fields: BTreeSet<&'static str>,
    invalid_schema_errors: Vec<String>,
}

impl ManifestFieldCoverageRecord {
    fn to_json(&self, command_line: &str, git_revision: &str) -> serde_json::Value {
        json!({
            "command_line": command_line,
            "git_revision": git_revision,
            "connector": self.connector,
            "connector_id": self.connector_id,
            "manifest_path": self.manifest_path,
            "operation_count": self.operation_count,
            "missing_fields": self.missing_fields,
            "invalid_schema_errors": self.invalid_schema_errors,
            "redaction_decision": "manifest paths, connector ids, operation ids, and field names only; schema bodies and provider data are not logged",
            "cleanup_result": "not_applicable_no_temp_resources",
            "skip_reason": "runtime execution skipped; raw TOML field coverage is sufficient for this conformance gate",
        })
    }
}

fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot derive workspace root from CARGO_MANIFEST_DIR".to_owned())
}

fn connectors_dir(root: &Path) -> PathBuf {
    root.join("connectors")
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).map_or_else(
        |_| path.display().to_string(),
        |relative| relative.display().to_string(),
    )
}

fn current_command_line() -> String {
    let mut joined = String::new();
    for arg in env::args() {
        if !joined.is_empty() {
            joined.push(' ');
        }
        joined.push_str(&arg);
    }
    joined
}

fn current_git_revision(root: &Path) -> String {
    let Ok(output) = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(root)
        .output()
    else {
        return "unknown".to_owned();
    };
    if !output.status.success() {
        return "unknown".to_owned();
    }
    String::from_utf8(output.stdout)
        .map(|stdout| stdout.trim().to_owned())
        .ok()
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn discover_manifests_in(connectors: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let entries = fs::read_dir(connectors)
        .map_err(|err| format!("cannot read {}: {err}", connectors.display()))?;
    let mut manifests = Vec::new();
    for entry_result in entries {
        let entry =
            entry_result.map_err(|err| format!("cannot read connector directory entry: {err}"))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest = path.join("manifest.toml");
        if !manifest.exists() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        manifests.push((name.to_owned(), manifest));
    }
    manifests.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(manifests)
}

fn parse_manifest(body: &str) -> Result<toml::Value, String> {
    toml::from_str::<toml::Table>(body)
        .map(toml::Value::Table)
        .map_err(|err| err.to_string())
}

fn manifest_connector_id(connector: &str, manifest: &toml::Value) -> String {
    manifest
        .get("connector")
        .and_then(|table| table.get("id"))
        .and_then(toml::Value::as_str)
        .map_or_else(|| format!("fcp.{connector}"), str::to_owned)
}

fn operations_table(manifest: &toml::Value) -> Option<&toml::map::Map<String, toml::Value>> {
    manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
}

fn string_array_is_non_empty(value: Option<&toml::Value>) -> bool {
    value.and_then(toml::Value::as_array).is_some_and(|values| {
        values
            .iter()
            .any(|value| value.as_str().is_some_and(|text| !text.trim().is_empty()))
    })
}

fn integer_array_is_non_empty(value: Option<&toml::Value>) -> bool {
    value
        .and_then(toml::Value::as_array)
        .is_some_and(|values| values.iter().any(|value| value.as_integer().is_some()))
}

fn schema_compile_error(schema: &toml::Value) -> Option<String> {
    let json_schema = match serde_json::to_value(schema) {
        Ok(value) => value,
        Err(error) => return Some(format!("schema_toml_to_json_failed: {error}")),
    };
    jsonschema::Validator::new(&json_schema)
        .err()
        .map(|error| error.to_string())
}

fn operation_has_ai_guidance(operation_table: &toml::map::Map<String, toml::Value>) -> bool {
    operation_table
        .get(AI_HINTS)
        .and_then(toml::Value::as_table)
        .and_then(|ai_hints| ai_hints.get("when_to_use"))
        .and_then(toml::Value::as_str)
        .is_some_and(|when_to_use| !when_to_use.trim().is_empty())
}

fn operation_missing_fields(
    operation_id: &str,
    operation: &toml::Value,
    missing_fields: &mut BTreeSet<&'static str>,
    invalid_schema_errors: &mut Vec<String>,
) {
    let Some(operation_table) = operation.as_table() else {
        missing_fields.extend([INPUT_SCHEMA, OUTPUT_SCHEMA, NETWORK_CONSTRAINTS, AI_HINTS]);
        return;
    };

    match operation_table.get(INPUT_SCHEMA) {
        Some(schema) => {
            if let Some(error) = schema_compile_error(schema) {
                missing_fields.insert(INVALID_INPUT_SCHEMA);
                invalid_schema_errors.push(format!("{operation_id}: input_schema: {error}"));
            }
        }
        None => {
            missing_fields.insert(INPUT_SCHEMA);
        }
    }

    match operation_table.get(OUTPUT_SCHEMA) {
        Some(schema) => {
            if let Some(error) = schema_compile_error(schema) {
                missing_fields.insert(INVALID_OUTPUT_SCHEMA);
                invalid_schema_errors.push(format!("{operation_id}: output_schema: {error}"));
            }
        }
        None => {
            missing_fields.insert(OUTPUT_SCHEMA);
        }
    }

    let Some(network_constraints) = operation_table
        .get(NETWORK_CONSTRAINTS)
        .and_then(toml::Value::as_table)
    else {
        missing_fields.insert(NETWORK_CONSTRAINTS);
        if !operation_has_ai_guidance(operation_table) {
            missing_fields.insert(AI_HINTS);
        }
        return;
    };
    if !string_array_is_non_empty(network_constraints.get("host_allow"))
        || !integer_array_is_non_empty(network_constraints.get("port_allow"))
    {
        missing_fields.insert(NETWORK_CONSTRAINTS);
    }

    if !operation_has_ai_guidance(operation_table) {
        missing_fields.insert(AI_HINTS);
    }
}

fn scan_manifest_field_coverage_body(
    root: &Path,
    connector: &str,
    path: &Path,
    body: &str,
) -> Result<ManifestFieldCoverageRecord, String> {
    let manifest = parse_manifest(body)?;
    let connector_id = manifest_connector_id(connector, &manifest);
    let mut missing_fields = BTreeSet::new();
    let mut invalid_schema_errors = Vec::new();

    if manifest
        .get(SANDBOX)
        .and_then(toml::Value::as_table)
        .is_none()
    {
        missing_fields.insert(SANDBOX);
    }

    let operation_count = operations_table(&manifest).map_or(0, |operations| {
        for (operation_id, operation) in operations {
            operation_missing_fields(
                operation_id,
                operation,
                &mut missing_fields,
                &mut invalid_schema_errors,
            );
        }
        operations.len()
    });

    Ok(ManifestFieldCoverageRecord {
        connector: connector.to_owned(),
        connector_id,
        manifest_path: display_path(root, path),
        operation_count,
        missing_fields,
        invalid_schema_errors,
    })
}

fn scan_manifest_field_coverage_records(
    root: &Path,
) -> Result<Vec<ManifestFieldCoverageRecord>, String> {
    let manifests = discover_manifests_in(&connectors_dir(root))?;
    let mut records = Vec::new();
    for (connector, path) in manifests {
        let body = fs::read_to_string(&path)
            .map_err(|err| format!("cannot read manifest {}: {err}", path.display()))?;
        records.push(scan_manifest_field_coverage_body(
            root, &connector, &path, &body,
        )?);
    }
    Ok(records)
}

fn connectors_missing(records: &[ManifestFieldCoverageRecord], field: &str) -> Vec<String> {
    records
        .iter()
        .filter(|record| record.operation_count > 0 || field == SANDBOX)
        .filter(|record| record.missing_fields.contains(field))
        .map(|record| record.connector.clone())
        .collect()
}

fn expected(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn require_equal<T>(actual: &T, expected: &T, label: &str) -> Result<(), String>
where
    T: std::fmt::Debug + PartialEq + ?Sized,
{
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label}: expected {expected:?}, got {actual:?}"))
    }
}

fn emit_json_line(event: &str, details: &serde_json::Value) {
    let log = json!({
        "module": "manifest_operation_field_coverage_conformance",
        "event": event,
        "details": details,
    });
    match serde_json::to_string(&log) {
        Ok(line) => println!("{line}"),
        Err(error) => eprintln!("manifest field coverage JSONL encode failed: {error}"),
    }
}

#[test]
fn manifest_operation_field_coverage_matches_known_gap_sets() -> Result<(), String> {
    let root = workspace_root()?;
    let records = scan_manifest_field_coverage_records(&root)?;
    let command_line = current_command_line();
    let git_revision = current_git_revision(&root);

    for record in &records {
        if !record.missing_fields.is_empty() && record.operation_count > 0 {
            emit_json_line(
                "manifest_operation_field_coverage_gap",
                &record.to_json(&command_line, &git_revision),
            );
        }
    }

    require_equal(
        &connectors_missing(&records, INPUT_SCHEMA),
        &expected(EXPECTED_SCHEMA_GAPS),
        "connectors missing per-operation input_schema",
    )?;
    require_equal(
        &connectors_missing(&records, OUTPUT_SCHEMA),
        &expected(EXPECTED_SCHEMA_GAPS),
        "connectors missing per-operation output_schema",
    )?;
    require_equal(
        &connectors_missing(&records, NETWORK_CONSTRAINTS),
        &expected(EXPECTED_NETWORK_CONSTRAINT_GAPS),
        "connectors missing per-operation network_constraints",
    )?;
    require_equal(
        &connectors_missing(&records, AI_HINTS),
        &expected(EXPECTED_AI_HINT_GAPS),
        "connectors missing per-operation ai_hints.when_to_use",
    )?;
    require_equal(
        &connectors_missing(&records, SANDBOX),
        &expected(EXPECTED_SANDBOX_GAPS),
        "connectors missing top-level sandbox section",
    )?;
    require_equal(
        &connectors_missing(&records, INVALID_INPUT_SCHEMA),
        &Vec::<String>::new(),
        "connectors with invalid input_schema JSON Schema",
    )?;
    require_equal(
        &connectors_missing(&records, INVALID_OUTPUT_SCHEMA),
        &Vec::<String>::new(),
        "connectors with invalid output_schema JSON Schema",
    )
}

#[test]
fn manifest_field_coverage_scan_detects_missing_fields() -> Result<(), String> {
    let record = scan_manifest_field_coverage_body(
        Path::new("."),
        "demo",
        Path::new("connectors/demo/manifest.toml"),
        r#"
[connector]
id = "fcp.demo"

[provides.operations."demo.search"]
description = "Search"

[provides.operations."demo.search".input_schema]
type = "object"
"#,
    )?;

    require_equal(&record.operation_count, &1, "operation count")?;
    require_equal(&record.connector_id, &"fcp.demo".to_owned(), "connector id")?;
    require_equal(
        &record.missing_fields,
        &BTreeSet::from([OUTPUT_SCHEMA, NETWORK_CONSTRAINTS, AI_HINTS, SANDBOX]),
        "missing field detection",
    )
}

#[test]
fn manifest_field_coverage_scan_accepts_complete_operation() -> Result<(), String> {
    let record = scan_manifest_field_coverage_body(
        Path::new("."),
        "demo",
        Path::new("connectors/demo/manifest.toml"),
        r#"
[connector]
id = "fcp.demo"

[sandbox]
profile = "strict"

[provides.operations."demo.search"]
description = "Search"

[provides.operations."demo.search".input_schema]
type = "object"

[provides.operations."demo.search".output_schema]
type = "object"

[provides.operations."demo.search".network_constraints]
host_allow = ["api.example.com"]
port_allow = [443]

[provides.operations."demo.search".ai_hints]
when_to_use = "Use for deterministic fixture search."
"#,
    )?;

    require_equal(&record.operation_count, &1, "operation count")?;
    require_equal(
        &record.missing_fields,
        &BTreeSet::new(),
        "complete operation should have no field gaps",
    )
}
