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

#[derive(Debug, Clone)]
struct ManifestFieldCoverageRecord {
    connector: String,
    connector_id: String,
    manifest_path: String,
    operation_count: usize,
    missing_input_schema_ids: Vec<String>,
    invalid_input_schema_ids: Vec<String>,
    missing_output_schema_ids: Vec<String>,
    invalid_output_schema_ids: Vec<String>,
    missing_network_constraints_ids: Vec<String>,
    wildcard_network_constraints_ids: Vec<String>,
    missing_network_port_allow_ids: Vec<String>,
    missing_network_require_sni_ids: Vec<String>,
    missing_network_deny_private_ranges_ids: Vec<String>,
    missing_ai_hints_ids: Vec<String>,
    missing_sandbox: bool,
    missing_top_level_fields: Vec<String>,
    parse_error: Option<String>,
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

impl ManifestFieldCoverageRecord {
    fn has_gap(&self) -> bool {
        self.parse_error.is_some()
            || self.missing_sandbox
            || !self.missing_input_schema_ids.is_empty()
            || !self.invalid_input_schema_ids.is_empty()
            || !self.missing_output_schema_ids.is_empty()
            || !self.invalid_output_schema_ids.is_empty()
            || !self.missing_network_constraints_ids.is_empty()
            || !self.wildcard_network_constraints_ids.is_empty()
            || !self.missing_network_port_allow_ids.is_empty()
            || !self.missing_network_require_sni_ids.is_empty()
            || !self.missing_network_deny_private_ranges_ids.is_empty()
            || !self.missing_ai_hints_ids.is_empty()
            || !self.missing_top_level_fields.is_empty()
    }

    fn to_json(&self, command_line: &str, git_revision: &str) -> serde_json::Value {
        serde_json::json!({
            "command_line": command_line,
            "git_revision": git_revision,
            "connector": &self.connector,
            "connector_id": &self.connector_id,
            "manifest_path": &self.manifest_path,
            "operation_count": self.operation_count,
            "missing_input_schema_count": self.missing_input_schema_ids.len(),
            "missing_input_schema_ids": &self.missing_input_schema_ids,
            "invalid_input_schema_count": self.invalid_input_schema_ids.len(),
            "invalid_input_schema_ids": &self.invalid_input_schema_ids,
            "missing_output_schema_count": self.missing_output_schema_ids.len(),
            "missing_output_schema_ids": &self.missing_output_schema_ids,
            "invalid_output_schema_count": self.invalid_output_schema_ids.len(),
            "invalid_output_schema_ids": &self.invalid_output_schema_ids,
            "missing_network_constraints_count": self.missing_network_constraints_ids.len(),
            "missing_network_constraints_ids": &self.missing_network_constraints_ids,
            "wildcard_network_constraints_count": self.wildcard_network_constraints_ids.len(),
            "wildcard_network_constraints_ids": &self.wildcard_network_constraints_ids,
            "missing_network_port_allow_count": self.missing_network_port_allow_ids.len(),
            "missing_network_port_allow_ids": &self.missing_network_port_allow_ids,
            "missing_network_require_sni_count": self.missing_network_require_sni_ids.len(),
            "missing_network_require_sni_ids": &self.missing_network_require_sni_ids,
            "missing_network_deny_private_ranges_count": self.missing_network_deny_private_ranges_ids.len(),
            "missing_network_deny_private_ranges_ids": &self.missing_network_deny_private_ranges_ids,
            "missing_ai_hints_count": self.missing_ai_hints_ids.len(),
            "missing_ai_hints_ids": &self.missing_ai_hints_ids,
            "missing_sandbox": self.missing_sandbox,
            "missing_top_level_field_count": self.missing_top_level_fields.len(),
            "missing_top_level_fields": &self.missing_top_level_fields,
            "parse_error": &self.parse_error,
            "redaction_decision": "manifest paths, operation ids, and field names only; no credentials, payloads, prompts, transcripts, or PII read",
            "cleanup_result": "not_applicable_no_temp_resources",
            "skip_reason": "runtime execution skipped; raw manifest field coverage is credential-free",
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

fn operation_table<'a>(
    manifest: &'a toml::Value,
    operation_id: &str,
) -> Option<&'a toml::map::Map<String, toml::Value>> {
    manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .and_then(|operations| operations.get(operation_id))
        .and_then(toml::Value::as_table)
}

fn operation_ids_missing_table(manifest: &toml::Value, table_name: &str) -> Vec<String> {
    let mut missing = Vec::new();
    for operation_id in canonical_operation_ids(manifest) {
        let present = operation_table(manifest, &operation_id)
            .and_then(|operation| operation.get(table_name))
            .and_then(toml::Value::as_table)
            .is_some_and(|table| !table.is_empty());
        if !present {
            missing.push(operation_id);
        }
    }
    missing
}

fn operation_ids_with_invalid_schema(manifest: &toml::Value, table_name: &str) -> Vec<String> {
    let mut invalid = Vec::new();
    for operation_id in canonical_operation_ids(manifest) {
        let Some(schema) = operation_table(manifest, &operation_id)
            .and_then(|operation| operation.get(table_name))
        else {
            continue;
        };
        let has_table = schema.as_table().is_some_and(|table| !table.is_empty());
        if !has_table {
            continue;
        }
        let Ok(schema_json) = serde_json::to_value(schema) else {
            invalid.push(operation_id);
            continue;
        };
        if jsonschema::validator_for(&schema_json).is_err() {
            invalid.push(operation_id);
        }
    }
    invalid
}

fn operation_network_constraints<'a>(
    manifest: &'a toml::Value,
    operation_id: &str,
) -> Option<&'a toml::map::Map<String, toml::Value>> {
    operation_table(manifest, operation_id)
        .and_then(|operation| operation.get("network_constraints"))
        .and_then(toml::Value::as_table)
}

fn operation_ids_missing_network_constraints(manifest: &toml::Value) -> Vec<String> {
    let mut missing = Vec::new();
    for operation_id in canonical_operation_ids(manifest) {
        let host_allow_present = operation_network_constraints(manifest, &operation_id)
            .and_then(|network_constraints| network_constraints.get("host_allow"))
            .and_then(toml::Value::as_array)
            .is_some_and(|hosts| {
                hosts
                    .iter()
                    .any(|host| host.as_str().is_some_and(|host| !host.trim().is_empty()))
            });
        if !host_allow_present {
            missing.push(operation_id);
        }
    }
    missing
}

fn operation_ids_with_wildcard_network_constraints(manifest: &toml::Value) -> Vec<String> {
    let mut wildcard = Vec::new();
    for operation_id in canonical_operation_ids(manifest) {
        let wildcard_present = operation_network_constraints(manifest, &operation_id)
            .and_then(|network_constraints| network_constraints.get("host_allow"))
            .and_then(toml::Value::as_array)
            .is_some_and(|hosts| {
                hosts
                    .iter()
                    .any(|host| host.as_str().is_some_and(|host| host.trim() == "*"))
            });
        if wildcard_present {
            wildcard.push(operation_id);
        }
    }
    wildcard
}

fn operation_ids_missing_network_port_allow(manifest: &toml::Value) -> Vec<String> {
    let mut missing = Vec::new();
    for operation_id in canonical_operation_ids(manifest) {
        let valid_port_allow = operation_network_constraints(manifest, &operation_id)
            .and_then(|network_constraints| network_constraints.get("port_allow"))
            .and_then(toml::Value::as_array)
            .is_some_and(|ports| {
                !ports.is_empty()
                    && ports.iter().all(|port| {
                        port.as_integer()
                            .is_some_and(|port| (1..=65_535).contains(&port))
                    })
            });
        if !valid_port_allow {
            missing.push(operation_id);
        }
    }
    missing
}

fn operation_ids_missing_network_bool(manifest: &toml::Value, field_name: &str) -> Vec<String> {
    let mut missing = Vec::new();
    for operation_id in canonical_operation_ids(manifest) {
        let present = operation_network_constraints(manifest, &operation_id)
            .and_then(|network_constraints| network_constraints.get(field_name))
            .and_then(toml::Value::as_bool)
            .is_some();
        if !present {
            missing.push(operation_id);
        }
    }
    missing
}

fn private_range_exempt_connector(connector: &str) -> bool {
    matches!(connector, "comfyui" | "lm-studio" | "ollama" | "searxng")
}

fn operation_ids_missing_network_deny_private_ranges(
    manifest: &toml::Value,
    connector: &str,
) -> Vec<String> {
    let mut missing = Vec::new();
    for operation_id in canonical_operation_ids(manifest) {
        let Some(deny_private_ranges) = operation_network_constraints(manifest, &operation_id)
            .and_then(|network_constraints| network_constraints.get("deny_private_ranges"))
            .and_then(toml::Value::as_bool)
        else {
            missing.push(operation_id);
            continue;
        };
        if !deny_private_ranges && !private_range_exempt_connector(connector) {
            missing.push(operation_id);
        }
    }
    missing
}

fn operation_ids_missing_ai_hints(manifest: &toml::Value) -> Vec<String> {
    let mut missing = Vec::new();
    for operation_id in canonical_operation_ids(manifest) {
        let when_to_use_present = operation_table(manifest, &operation_id)
            .and_then(|operation| operation.get("ai_hints"))
            .and_then(toml::Value::as_table)
            .and_then(|ai_hints| ai_hints.get("when_to_use"))
            .and_then(toml::Value::as_str)
            .is_some_and(|when_to_use| !when_to_use.trim().is_empty());
        if !when_to_use_present {
            missing.push(operation_id);
        }
    }
    missing
}

fn table_string_field_present(manifest: &toml::Value, table_name: &str, field_name: &str) -> bool {
    manifest
        .get(table_name)
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get(field_name))
        .and_then(toml::Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
}

fn table_positive_integer_field_present(
    manifest: &toml::Value,
    table_name: &str,
    field_name: &str,
) -> bool {
    manifest
        .get(table_name)
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get(field_name))
        .and_then(toml::Value::as_integer)
        .is_some_and(|value| value > 0)
}

fn table_array_field_present(manifest: &toml::Value, table_name: &str, field_name: &str) -> bool {
    manifest
        .get(table_name)
        .and_then(toml::Value::as_table)
        .and_then(|table| table.get(field_name))
        .and_then(toml::Value::as_array)
        .is_some()
}

fn missing_top_level_fields(manifest: &toml::Value, operation_count: usize) -> Vec<String> {
    if operation_count == 0 {
        return Vec::new();
    }

    let mut missing = Vec::new();
    if !table_string_field_present(manifest, "sandbox", "profile") {
        missing.push("sandbox.profile".to_owned());
    }
    if !table_positive_integer_field_present(manifest, "sandbox", "memory_mb") {
        missing.push("sandbox.memory_mb".to_owned());
    }
    if !table_positive_integer_field_present(manifest, "sandbox", "cpu_percent") {
        missing.push("sandbox.cpu_percent".to_owned());
    }
    if !table_positive_integer_field_present(manifest, "sandbox", "wall_clock_timeout_ms") {
        missing.push("sandbox.wall_clock_timeout_ms".to_owned());
    }
    if !table_array_field_present(manifest, "capabilities", "required") {
        missing.push("capabilities.required".to_owned());
    }
    if !table_array_field_present(manifest, "capabilities", "forbidden") {
        missing.push("capabilities.forbidden".to_owned());
    }
    if !table_string_field_present(manifest, "zones", "home") {
        missing.push("zones.home".to_owned());
    }
    missing
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

fn scan_manifest_field_coverage_body(
    root: &Path,
    connector: &str,
    path: &Path,
    body: &str,
) -> ManifestFieldCoverageRecord {
    let manifest_path = display_path(root, path);
    let manifest = match parse_manifest(body) {
        Ok(manifest) => manifest,
        Err(err) => {
            return ManifestFieldCoverageRecord {
                connector: connector.to_owned(),
                connector_id: format!("fcp.{connector}"),
                manifest_path,
                operation_count: 0,
                missing_input_schema_ids: Vec::new(),
                invalid_input_schema_ids: Vec::new(),
                missing_output_schema_ids: Vec::new(),
                invalid_output_schema_ids: Vec::new(),
                missing_network_constraints_ids: Vec::new(),
                wildcard_network_constraints_ids: Vec::new(),
                missing_network_port_allow_ids: Vec::new(),
                missing_network_require_sni_ids: Vec::new(),
                missing_network_deny_private_ranges_ids: Vec::new(),
                missing_ai_hints_ids: Vec::new(),
                missing_sandbox: false,
                missing_top_level_fields: Vec::new(),
                parse_error: Some(err),
            };
        }
    };

    let operation_count = canonical_operation_ids(&manifest).len();
    ManifestFieldCoverageRecord {
        connector: connector.to_owned(),
        connector_id: manifest_connector_id(connector, &manifest),
        manifest_path,
        operation_count,
        missing_input_schema_ids: operation_ids_missing_table(&manifest, "input_schema"),
        invalid_input_schema_ids: operation_ids_with_invalid_schema(&manifest, "input_schema"),
        missing_output_schema_ids: operation_ids_missing_table(&manifest, "output_schema"),
        invalid_output_schema_ids: operation_ids_with_invalid_schema(&manifest, "output_schema"),
        missing_network_constraints_ids: operation_ids_missing_network_constraints(&manifest),
        wildcard_network_constraints_ids: operation_ids_with_wildcard_network_constraints(
            &manifest,
        ),
        missing_network_port_allow_ids: operation_ids_missing_network_port_allow(&manifest),
        missing_network_require_sni_ids: operation_ids_missing_network_bool(
            &manifest,
            "require_sni",
        ),
        missing_network_deny_private_ranges_ids: operation_ids_missing_network_deny_private_ranges(
            &manifest, connector,
        ),
        missing_ai_hints_ids: operation_ids_missing_ai_hints(&manifest),
        missing_sandbox: operation_count > 0 && manifest.get("sandbox").is_none(),
        missing_top_level_fields: missing_top_level_fields(&manifest, operation_count),
        parse_error: None,
    }
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

fn connector_names(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

fn expected_input_schema_gap_connectors() -> Vec<String> {
    Vec::new()
}

fn expected_output_schema_gap_connectors() -> Vec<String> {
    expected_input_schema_gap_connectors()
}

fn expected_network_constraints_gap_connectors() -> Vec<String> {
    connector_names(&[
        "dingtalk",
        "google-ai",
        "google-chat",
        "google-workspace-events",
        "hue",
        "inworld",
        "irc",
        "llm-router",
        "mastodon",
        "mattermost",
        "microsoft365",
        "nostr",
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
    ])
}

fn expected_sandbox_gap_connectors() -> Vec<String> {
    connector_names(&["anthropic-vertex", "inworld"])
}

fn expected_ai_hints_gap_connectors() -> Vec<String> {
    connector_names(&[
        "dingtalk",
        "google-people",
        "google-workspace-events",
        "mastodon",
        "mattermost",
        "nostr",
        "qq",
        "telnyx",
        "wecom",
    ])
}

fn connectors_with_gap<F>(records: &[ManifestFieldCoverageRecord], gap: F) -> Vec<String>
where
    F: Fn(&ManifestFieldCoverageRecord) -> bool,
{
    records
        .iter()
        .filter(|record| record.operation_count > 0)
        .filter(|record| gap(record))
        .map(|record| record.connector.clone())
        .collect()
}

fn push_operation_gap(failures: &mut Vec<String>, connector: &str, field_name: &str, count: usize) {
    if count == 0 {
        return;
    }
    failures.push(format!(
        "{connector} missing_field=provides.operations[*].{field_name} affected_ops={count}"
    ));
}

fn push_invalid_operation_gap(
    failures: &mut Vec<String>,
    connector: &str,
    field_name: &str,
    count: usize,
) {
    if count == 0 {
        return;
    }
    failures.push(format!(
        "{connector} invalid_field=provides.operations[*].{field_name} affected_ops={count}"
    ));
}

fn manifest_field_coverage_failures(records: &[ManifestFieldCoverageRecord]) -> Vec<String> {
    let mut failures = Vec::new();
    for record in records.iter().filter(|record| record.operation_count > 0) {
        if let Some(parse_error) = &record.parse_error {
            failures.push(format!("{} parse_error={parse_error}", record.connector));
        }
        if record.missing_sandbox {
            failures.push(format!(
                "{} missing_field=sandbox affected_ops={}",
                record.connector, record.operation_count
            ));
        }
        push_operation_gap(
            &mut failures,
            &record.connector,
            "input_schema",
            record.missing_input_schema_ids.len(),
        );
        push_invalid_operation_gap(
            &mut failures,
            &record.connector,
            "input_schema",
            record.invalid_input_schema_ids.len(),
        );
        push_operation_gap(
            &mut failures,
            &record.connector,
            "output_schema",
            record.missing_output_schema_ids.len(),
        );
        push_invalid_operation_gap(
            &mut failures,
            &record.connector,
            "output_schema",
            record.invalid_output_schema_ids.len(),
        );
        push_operation_gap(
            &mut failures,
            &record.connector,
            "network_constraints.host_allow",
            record.missing_network_constraints_ids.len(),
        );
        push_invalid_operation_gap(
            &mut failures,
            &record.connector,
            "network_constraints.host_allow",
            record.wildcard_network_constraints_ids.len(),
        );
        push_operation_gap(
            &mut failures,
            &record.connector,
            "network_constraints.port_allow",
            record.missing_network_port_allow_ids.len(),
        );
        push_operation_gap(
            &mut failures,
            &record.connector,
            "network_constraints.require_sni",
            record.missing_network_require_sni_ids.len(),
        );
        push_operation_gap(
            &mut failures,
            &record.connector,
            "network_constraints.deny_private_ranges",
            record.missing_network_deny_private_ranges_ids.len(),
        );
        push_operation_gap(
            &mut failures,
            &record.connector,
            "ai_hints.when_to_use",
            record.missing_ai_hints_ids.len(),
        );
        for field_name in &record.missing_top_level_fields {
            failures.push(format!("{} missing_field={field_name}", record.connector));
        }
    }
    failures
}

#[test]
fn raw_manifest_field_coverage_reports_known_connector_metadata_gaps() -> Result<(), String> {
    let root = workspace_root()?;
    let records = scan_manifest_field_coverage_records(&root)?;
    let command_line = current_command_line();
    let git_revision = current_git_revision(&root);

    for record in &records {
        if record.has_gap() {
            emit_json_line(
                "manifest_field_coverage",
                &record.to_json(&command_line, &git_revision),
            );
        }
    }

    require_equal(
        connectors_with_gap(&records, |record| {
            !record.missing_input_schema_ids.is_empty()
        })
        .as_slice(),
        expected_input_schema_gap_connectors().as_slice(),
        "connectors with missing per-op input_schema",
    )?;
    require_equal(
        connectors_with_gap(&records, |record| {
            !record.missing_output_schema_ids.is_empty()
        })
        .as_slice(),
        expected_output_schema_gap_connectors().as_slice(),
        "connectors with missing per-op output_schema",
    )?;
    require_equal(
        connectors_with_gap(&records, |record| {
            !record.missing_network_constraints_ids.is_empty()
        })
        .as_slice(),
        expected_network_constraints_gap_connectors().as_slice(),
        "connectors with missing per-op network_constraints.host_allow",
    )?;
    require_equal(
        connectors_with_gap(&records, |record| !record.missing_ai_hints_ids.is_empty()).as_slice(),
        expected_ai_hints_gap_connectors().as_slice(),
        "connectors with missing per-op ai_hints.when_to_use",
    )?;
    require_equal(
        connectors_with_gap(&records, |record| record.missing_sandbox).as_slice(),
        expected_sandbox_gap_connectors().as_slice(),
        "connectors with missing top-level sandbox section",
    )?;

    Ok(())
}

#[test]
#[ignore = "known manifest metadata debt is tracked by flywheel_connectors-4kw5f.9.*"]
fn raw_manifest_field_coverage_rejects_connector_metadata_gaps() -> Result<(), String> {
    let root = workspace_root()?;
    let records = scan_manifest_field_coverage_records(&root)?;
    let failures = manifest_field_coverage_failures(&records);

    require(
        failures.is_empty(),
        format!("manifest field coverage failures: {}", failures.join(", ")),
    )
}

#[test]
fn raw_manifest_operation_harness_rejects_zero_operation_connectors() -> Result<(), String> {
    let root = workspace_root()?;
    let records = scan_manifest_operation_records(&root)?;
    let command_line = current_command_line();
    let git_revision = current_git_revision(&root);

    let mut failures = Vec::new();
    for record in &records {
        if record.status == "fail" {
            emit_json_line(
                "manifest_operation_conformance",
                &record.to_json(&command_line, &git_revision),
            );
            failures.push(format!(
                "{} ({})",
                record.connector,
                record.mismatch_reason.unwrap_or("unknown")
            ));
        }
    }

    require(
        failures.is_empty(),
        format!(
            "manifest operation conformance failures: {}",
            failures.join(", ")
        ),
    )
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

#[test]
fn manifest_field_coverage_reports_schema_network_and_top_level_failures() -> Result<(), String> {
    let manifest = r#"
[connector]
id = "fcp.fixture"

[provides.operations."fixture.op"]
description = "Fixture operation"

[provides.operations."fixture.op".input_schema]
type = "not-a-json-schema-type"

[provides.operations."fixture.op".network_constraints]
host_allow = ["*"]
port_allow = [0]
deny_private_ranges = false

[provides.operations."fixture.op".ai_hints]
when_to_use = ""
"#;

    let record = scan_manifest_field_coverage_body(
        Path::new("."),
        "fixture",
        Path::new("connectors/fixture/manifest.toml"),
        manifest,
    );
    let failures = manifest_field_coverage_failures(&[record]);

    require(
        failures.iter().any(|failure| {
            failure == "fixture invalid_field=provides.operations[*].input_schema affected_ops=1"
        }),
        format!("invalid input_schema failure missing from {failures:?}"),
    )?;
    require(
        failures.iter().any(|failure| {
            failure == "fixture missing_field=provides.operations[*].output_schema affected_ops=1"
        }),
        format!("missing output_schema failure missing from {failures:?}"),
    )?;
    require(
        failures.iter().any(|failure| {
            failure
                == "fixture invalid_field=provides.operations[*].network_constraints.host_allow affected_ops=1"
        }),
        format!("wildcard host_allow failure missing from {failures:?}"),
    )?;
    require(
        failures.iter().any(|failure| {
            failure
                == "fixture missing_field=provides.operations[*].network_constraints.port_allow affected_ops=1"
        }),
        format!("invalid port_allow failure missing from {failures:?}"),
    )?;
    require(
        failures.iter().any(|failure| {
            failure
                == "fixture missing_field=provides.operations[*].network_constraints.require_sni affected_ops=1"
        }),
        format!("missing require_sni failure missing from {failures:?}"),
    )?;
    require(
        failures.iter().any(|failure| {
            failure
                == "fixture missing_field=provides.operations[*].network_constraints.deny_private_ranges affected_ops=1"
        }),
        format!("deny_private_ranges failure missing from {failures:?}"),
    )?;
    require(
        failures.iter().any(|failure| {
            failure == "fixture missing_field=provides.operations[*].ai_hints.when_to_use affected_ops=1"
        }),
        format!("missing ai_hints.when_to_use failure missing from {failures:?}"),
    )?;
    require(
        failures
            .iter()
            .any(|failure| failure == "fixture missing_field=sandbox affected_ops=1"),
        format!("missing sandbox failure missing from {failures:?}"),
    )?;
    require(
        failures
            .iter()
            .any(|failure| failure == "fixture missing_field=capabilities.required"),
        format!("missing capabilities.required failure missing from {failures:?}"),
    )?;
    require(
        failures
            .iter()
            .any(|failure| failure == "fixture missing_field=zones.home"),
        format!("missing zones.home failure missing from {failures:?}"),
    )
}

#[test]
fn manifest_field_coverage_allows_documented_private_range_exemption() -> Result<(), String> {
    let manifest = r#"
[connector]
id = "fcp.searxng"

[zones]
home = "z:private"

[capabilities]
required = []
forbidden = []

[sandbox]
profile = "strict"
memory_mb = 128
cpu_percent = 25
wall_clock_timeout_ms = 30000

[provides.operations."searxng.search.query"]
description = "Search"

[provides.operations."searxng.search.query".input_schema]
type = "object"

[provides.operations."searxng.search.query".output_schema]
type = "object"

[provides.operations."searxng.search.query".network_constraints]
host_allow = ["operator-configured"]
port_allow = [80, 443, 8080, 8888]
require_sni = false
deny_private_ranges = false

[provides.operations."searxng.search.query".ai_hints]
when_to_use = "Use for operator-configured metasearch."
"#;

    let record = scan_manifest_field_coverage_body(
        Path::new("."),
        "searxng",
        Path::new("connectors/searxng/manifest.toml"),
        manifest,
    );
    let failures = manifest_field_coverage_failures(&[record]);

    require(
        failures.is_empty(),
        format!("searxng exemption fixture should not fail: {failures:?}"),
    )
}
