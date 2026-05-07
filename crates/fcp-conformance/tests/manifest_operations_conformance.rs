//! Raw manifest operation conformance for the live connector corpus.
//!
//! The strict `ConnectorManifest::parse_str` path currently rejects broad live
//! manifest drift before it can report empty canonical operation catalogs. This
//! harness parses raw TOML and checks `[provides.operations.*]` directly so
//! zero-operation manifests stay visible until each connector is repaired.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
struct ManifestOperationRecord {
    connector: String,
    connector_id: String,
    manifest_path: String,
    manifest_operation_ids: Vec<String>,
    legacy_operation_ids: Vec<String>,
    code_operation_ids: Option<Vec<String>>,
    status: &'static str,
    mismatch_reason: Option<&'static str>,
    parse_error: Option<String>,
    skip_reason: Option<&'static str>,
}

impl ManifestOperationRecord {
    fn to_json(&self, command_line: &str, git_revision: &str) -> serde_json::Value {
        serde_json::json!({
            "command_line": command_line,
            "git_revision": git_revision,
            "connector": &self.connector,
            "connector_id": &self.connector_id,
            "manifest_path": &self.manifest_path,
            "manifest_operation_count": self.manifest_operation_ids.len(),
            "manifest_operation_ids": &self.manifest_operation_ids,
            "legacy_operation_count": self.legacy_operation_ids.len(),
            "legacy_operation_ids": &self.legacy_operation_ids,
            "runtime_introspection_operation_count": self.code_operation_ids.as_ref().map(Vec::len),
            "runtime_introspection_operation_ids": &self.code_operation_ids,
            "status": self.status,
            "mismatch_reason": self.mismatch_reason,
            "parse_error": &self.parse_error,
            "redaction_decision": "manifest paths and operation ids only; no credentials, payloads, or PII read",
            "cleanup_result": "not_applicable_no_temp_resources",
            "skip_reason": self.skip_reason,
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
    let Ok(stdout) = String::from_utf8(output.stdout) else {
        return "unknown".to_owned();
    };
    let revision = stdout.trim();
    if revision.is_empty() {
        "unknown".to_owned()
    } else {
        revision.to_owned()
    }
}

fn parse_manifest(body: &str) -> Result<toml::Value, String> {
    toml::from_str::<toml::Table>(body)
        .map(toml::Value::Table)
        .map_err(|err| err.to_string())
}

fn manifest_connector_id(connector: &str, manifest: &toml::Value) -> String {
    let connector_table = manifest.get("connector");
    if let Some(id) = connector_table
        .and_then(|table| table.get("id"))
        .and_then(toml::Value::as_str)
    {
        return id.to_owned();
    }
    if let Some(name) = connector_table
        .and_then(|table| table.get("name"))
        .and_then(toml::Value::as_str)
        .filter(|name| name.starts_with("fcp."))
    {
        return name.to_owned();
    }
    format!("fcp.{connector}")
}

fn canonical_operation_ids(manifest: &toml::Value) -> Vec<String> {
    let mut ids = Vec::new();
    if let Some(operations) = manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
    {
        for id in operations.keys().filter(|id| !id.trim().is_empty()) {
            ids.push(id.to_owned());
        }
    }
    ids.sort();
    ids
}

fn ids_from_array_tables(value: Option<&toml::Value>) -> Vec<String> {
    let mut ids = Vec::new();
    let Some(entries) = value.and_then(toml::Value::as_array) else {
        return ids;
    };
    for entry in entries {
        let Some(id) = entry
            .as_table()
            .and_then(|table| table.get("id"))
            .and_then(toml::Value::as_str)
            .filter(|id| !id.trim().is_empty())
        else {
            continue;
        };
        ids.push(id.to_owned());
    }
    ids.sort();
    ids
}

fn legacy_operation_ids(manifest: &toml::Value) -> Vec<String> {
    let mut ids = ids_from_array_tables(manifest.get("operations"));
    ids.extend(ids_from_array_tables(manifest.get("provides")));
    ids.sort();
    ids.dedup();
    ids
}

fn extract_quoted_literal(input: &str) -> Option<String> {
    let mut chars = input.trim_start().chars();
    if chars.next()? != '"' {
        return None;
    }
    let mut literal = String::new();
    let mut escaped = false;
    for ch in chars {
        if escaped {
            literal.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            return Some(literal);
        }
        literal.push(ch);
    }
    None
}

fn const_operation_ids(source: &str) -> BTreeMap<String, String> {
    let mut ids = BTreeMap::new();
    for line in source.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("const OP_") else {
            continue;
        };
        let Some((name, value)) = rest.split_once(':') else {
            continue;
        };
        let Some((_, literal)) = value.split_once('=') else {
            continue;
        };
        let Some(id) = extract_quoted_literal(literal) else {
            continue;
        };
        ids.insert(format!("OP_{}", name.trim()), id);
    }
    ids
}

fn direct_json_operation_ids(source: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for segment in source.split("\"id\"").skip(1) {
        let Some((_, after_colon)) = segment.split_once(':') else {
            continue;
        };
        let Some(id) = extract_quoted_literal(after_colon).filter(|id| id.contains('.')) else {
            continue;
        };
        ids.insert(id);
    }
    ids
}

fn operation_id_from_static_ids(
    source: &str,
    constants: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for segment in source.split("OperationId::from_static(").skip(1) {
        if let Some(id) = extract_quoted_literal(segment) {
            ids.insert(id);
            continue;
        }
        let Some((symbol, _)) = segment.split_once(')') else {
            continue;
        };
        let Some(id) = constants.get(symbol.trim()) else {
            continue;
        };
        ids.insert(id.to_owned());
    }
    ids
}

fn source_operation_ids(manifest_path: &Path) -> Result<Option<Vec<String>>, String> {
    let Some(connector_dir) = manifest_path.parent() else {
        return Ok(None);
    };
    let source_path = connector_dir.join("src/connector.rs");
    let source = match fs::read_to_string(&source_path) {
        Ok(source) => source,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("cannot read {}: {err}", source_path.display())),
    };
    if !source.contains("operations_info")
        && !source.contains("handle_introspect")
        && !source.contains("OperationInfo")
    {
        return Ok(None);
    }

    let constants = const_operation_ids(&source);
    let mut ids = BTreeSet::new();
    ids.extend(constants.values().cloned());
    ids.extend(direct_json_operation_ids(&source));
    ids.extend(operation_id_from_static_ids(&source, &constants));

    if ids.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ids.into_iter().collect()))
    }
}

fn scan_manifest_operations_body(
    root: &Path,
    connector: &str,
    path: &Path,
    body: &str,
    code_operation_ids: Option<Vec<String>>,
) -> ManifestOperationRecord {
    let manifest_path = display_path(root, path);
    let manifest = match parse_manifest(body) {
        Ok(manifest) => manifest,
        Err(err) => {
            return ManifestOperationRecord {
                connector: connector.to_owned(),
                connector_id: format!("fcp.{connector}"),
                manifest_path,
                manifest_operation_ids: Vec::new(),
                legacy_operation_ids: Vec::new(),
                code_operation_ids,
                status: "fail",
                mismatch_reason: Some("malformed_manifest_toml"),
                parse_error: Some(err),
                skip_reason: Some(
                    "runtime introspection skipped because manifest TOML could not be parsed",
                ),
            };
        }
    };

    let manifest_operation_ids = canonical_operation_ids(&manifest);
    let legacy_operation_ids = legacy_operation_ids(&manifest);
    let connector_id = manifest_connector_id(connector, &manifest);
    let missing_canonical_operations = manifest_operation_ids.is_empty();
    let status = if missing_canonical_operations {
        "fail"
    } else {
        "pass"
    };
    let mismatch_reason =
        missing_canonical_operations.then_some("canonical_provides_operations_missing");
    let skip_reason = if code_operation_ids.is_some() {
        Some("runtime execution skipped; static credential-free connector metadata was available")
    } else {
        Some("runtime introspection skipped; connector cannot be loaded without credentials here")
    };

    ManifestOperationRecord {
        connector: connector.to_owned(),
        connector_id,
        manifest_path,
        manifest_operation_ids,
        legacy_operation_ids,
        code_operation_ids,
        status,
        mismatch_reason,
        parse_error: None,
        skip_reason,
    }
}

fn scan_manifest_operation_records(root: &Path) -> Result<Vec<ManifestOperationRecord>, String> {
    let manifests = discover_manifests_in(&connectors_dir(root))?;
    let mut records = Vec::new();
    for (connector, path) in manifests {
        let body = fs::read_to_string(&path)
            .map_err(|err| format!("cannot read manifest {}: {err}", path.display()))?;
        let code_operation_ids = source_operation_ids(&path)?;
        records.push(scan_manifest_operations_body(
            root,
            &connector,
            &path,
            &body,
            code_operation_ids,
        ));
    }
    Ok(records)
}

fn emit_json_line(event: &str, details: &serde_json::Value) {
    let log = serde_json::json!({
        "module": "manifest_operations_conformance",
        "event": event,
        "details": details,
    });
    match serde_json::to_string(&log) {
        Ok(line) => println!("{line}"),
        Err(err) => eprintln!("manifest_operations_conformance JSONL encode failed: {err}"),
    }
}

fn expected_zero_operation_connectors() -> Vec<&'static str> {
    vec![
        "brave-search",
        "deepgram",
        "duckduckgo",
        "elevenlabs",
        "exa",
        "firecrawl",
        "matrix",
        "mistral",
        "outlook",
        "perplexity-search",
        "searxng",
        "tavily",
        "teams",
        "wolfram",
    ]
}

fn require(condition: bool, message: impl Into<String>) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
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

#[test]
fn raw_manifest_operation_harness_reports_known_zero_operation_connectors() -> Result<(), String> {
    let root = workspace_root()?;
    let records = scan_manifest_operation_records(&root)?;
    let command_line = current_command_line();
    let git_revision = current_git_revision(&root);
    let expected_candidates = expected_zero_operation_connectors();
    let expected_candidate_set = expected_candidates.iter().copied().collect::<BTreeSet<_>>();

    let mut zero_operation_connectors = Vec::new();
    for record in &records {
        if record.status == "fail" {
            emit_json_line(
                "manifest_operation_conformance",
                &record.to_json(&command_line, &git_revision),
            );
        }
        if record.manifest_operation_ids.is_empty() && record.parse_error.is_none() {
            zero_operation_connectors.push(record.connector.clone());
        }
    }
    let expected_current_zero_operation_connectors = records
        .iter()
        .filter(|record| expected_candidate_set.contains(record.connector.as_str()))
        .filter(|record| record.manifest_operation_ids.is_empty() && record.parse_error.is_none())
        .map(|record| record.connector.clone())
        .collect::<Vec<_>>();

    require_equal(
        zero_operation_connectors.as_slice(),
        expected_current_zero_operation_connectors.as_slice(),
        "unexpected canonical zero-operation manifest set",
    )?;

    for expected_connector in expected_current_zero_operation_connectors {
        let Some(record) = records
            .iter()
            .find(|record| record.connector == expected_connector)
        else {
            return Err(format!("missing record for {expected_connector}"));
        };
        require_equal(
            &record.mismatch_reason,
            &Some("canonical_provides_operations_missing"),
            expected_connector.as_str(),
        )?;
        let has_metadata = !record.legacy_operation_ids.is_empty()
            || record
                .code_operation_ids
                .as_ref()
                .is_some_and(|ids| !ids.is_empty());
        require(
            has_metadata,
            format!(
                "{expected_connector} should expose legacy manifest operations or static code metadata"
            ),
        )?;
    }

    Ok(())
}

#[test]
fn canonical_operation_ids_are_sorted_from_raw_toml() -> Result<(), String> {
    let manifest = parse_manifest(
        r#"
[connector]
id = "fcp.example"

[provides.operations.beta]
summary = "Beta"

[provides.operations.alpha]
summary = "Alpha"
"#,
    )?;

    require_equal(
        &canonical_operation_ids(&manifest),
        &vec!["alpha".to_owned(), "beta".to_owned()],
        "canonical operation ordering",
    )
}

#[test]
fn legacy_operation_ids_do_not_count_as_canonical_operations() -> Result<(), String> {
    let manifest = parse_manifest(
        r#"
[connector]
name = "fcp.legacy"

[[operations]]
id = "legacy.one"

[[provides]]
id = "legacy.two"
"#,
    )?;

    require(
        canonical_operation_ids(&manifest).is_empty(),
        "legacy operations should not satisfy canonical provides.operations",
    )?;
    require_equal(
        &legacy_operation_ids(&manifest),
        &vec!["legacy.one".to_owned(), "legacy.two".to_owned()],
        "legacy operation discovery",
    )
}

#[test]
fn manifest_operation_scan_reports_malformed_toml() -> Result<(), String> {
    let root = Path::new(".");
    let record = scan_manifest_operations_body(
        root,
        "broken",
        Path::new("connectors/broken/manifest.toml"),
        "[connector\nid = \"fcp.broken\"",
        None,
    );

    require_equal(&record.status, &"fail", "malformed status")?;
    require_equal(
        &record.mismatch_reason,
        &Some("malformed_manifest_toml"),
        "malformed reason",
    )?;
    require(
        record.parse_error.is_some(),
        "malformed parse error missing",
    )?;
    require(
        record.manifest_operation_ids.is_empty(),
        "malformed manifest should have zero canonical operation ids",
    )
}

#[test]
fn source_operation_scan_resolves_constants_and_direct_json_ids() -> Result<(), String> {
    let source = r#"
const OP_ALPHA: &str = "example.alpha";
const OP_DELTA: &str = "example.delta";

fn operations_info() {
    let _ = OperationId::from_static(OP_ALPHA);
    let _ = OperationId::from_static("example.beta");
    let _ = operation_schema(OP_DELTA, "Delta");
    let _ = serde_json::json!({ "id": "example.gamma" });
}
"#;
    let constants = const_operation_ids(source);
    let mut ids = BTreeSet::new();
    ids.extend(constants.values().cloned());
    ids.extend(direct_json_operation_ids(source));
    ids.extend(operation_id_from_static_ids(source, &constants));

    require_equal(
        &ids.into_iter().collect::<Vec<_>>(),
        &vec![
            "example.alpha".to_owned(),
            "example.beta".to_owned(),
            "example.delta".to_owned(),
            "example.gamma".to_owned(),
        ],
        "source operation id extraction",
    )
}
