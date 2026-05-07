//! Manifest operation inventory audit for connector manifests.
//!
//! The audit intentionally reads manifest TOML without full manifest validation:
//! this harness is meant to catch empty or missing operation declarations even
//! when a manifest has unrelated validation drift.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const SCRIPT_NAME: &str = "fcp-manifest-ops-audit";
const LOG_VERSION: &str = "v2";
const REDACTION_DECISION: &str =
    "redaction-safe: logs omit API keys, operation arguments, provider payloads, and error bodies";

/// A whole-repository manifest operation audit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestOperationsAuditReport {
    pub repo_root: String,
    pub connector_count: usize,
    pub failed_count: usize,
    pub skipped_count: usize,
    pub entries: Vec<ConnectorManifestOperationAudit>,
}

impl ManifestOperationsAuditReport {
    /// Return true when every connector passes the manifest operation check.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.failed_count == 0
    }

    /// Connector ids that failed the audit.
    #[must_use]
    pub fn failed_connector_ids(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| entry.result == AuditResult::Fail)
            .map(|entry| entry.connector_id.clone())
            .collect()
    }

    /// Connector ids with zero manifest operations but runtime operation evidence.
    #[must_use]
    pub fn zero_manifest_runtime_connector_ids(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.result == AuditResult::Fail
                    && entry.manifest_operation_count == 0
                    && entry.runtime_operation_count.unwrap_or_default() > 0
            })
            .map(|entry| entry.connector_id.clone())
            .collect()
    }
}

/// Per-connector manifest operation audit result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectorManifestOperationAudit {
    pub connector_id: String,
    pub connector_slug: String,
    pub manifest_path: String,
    pub manifest_operation_count: usize,
    pub runtime_operation_count: Option<usize>,
    pub runtime_operation_ids: Vec<String>,
    pub result: AuditResult,
    pub mismatch_reason: Option<String>,
    pub redaction_decision: String,
    pub cleanup_result: String,
    pub skip_reason: Option<String>,
}

/// Audit result for a connector.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Pass,
    Fail,
    Skip,
}

impl AuditResult {
    #[must_use]
    const fn as_log_result(self) -> &'static str {
        match self {
            Self::Pass | Self::Skip => "pass",
            Self::Fail => "fail",
        }
    }
}

/// Error returned by the manifest operations audit.
#[derive(Debug)]
pub enum ManifestOperationsAuditError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    MissingConnectorsDir {
        path: PathBuf,
    },
    Json(serde_json::Error),
}

impl fmt::Display for ManifestOperationsAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to access {}: {source}", path.display())
            }
            Self::MissingConnectorsDir { path } => {
                write!(f, "connectors directory does not exist: {}", path.display())
            }
            Self::Json(source) => write!(f, "failed to serialize audit JSONL: {source}"),
        }
    }
}

impl Error for ManifestOperationsAuditError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json(source) => Some(source),
            Self::MissingConnectorsDir { .. } => None,
        }
    }
}

impl From<serde_json::Error> for ManifestOperationsAuditError {
    fn from(source: serde_json::Error) -> Self {
        Self::Json(source)
    }
}

/// Audit all connector manifests under `<repo_root>/connectors`.
///
/// # Errors
///
/// Returns an error if the connector tree cannot be read or JSONL serialization
/// fails.
pub fn audit_connector_manifests(
    repo_root: &Path,
) -> Result<ManifestOperationsAuditReport, ManifestOperationsAuditError> {
    let connectors_dir = repo_root.join("connectors");
    if !connectors_dir.is_dir() {
        return Err(ManifestOperationsAuditError::MissingConnectorsDir {
            path: connectors_dir,
        });
    }

    let mut connector_dirs = Vec::new();
    for entry in read_dir_sorted(&connectors_dir)? {
        let file_type = entry
            .file_type()
            .map_err(|source| ManifestOperationsAuditError::Io {
                path: entry.path(),
                source,
            })?;
        if file_type.is_dir() && entry.path().join("manifest.toml").is_file() {
            connector_dirs.push(entry.path());
        }
    }
    connector_dirs.sort();

    let mut entries = Vec::with_capacity(connector_dirs.len());
    for connector_dir in connector_dirs {
        entries.push(audit_connector_directory(&connector_dir)?);
    }
    entries.sort_by(|left, right| left.connector_id.cmp(&right.connector_id));

    let failed_count = entries
        .iter()
        .filter(|entry| entry.result == AuditResult::Fail)
        .count();
    let skipped_count = entries
        .iter()
        .filter(|entry| entry.result == AuditResult::Skip)
        .count();

    Ok(ManifestOperationsAuditReport {
        repo_root: repo_root.display().to_string(),
        connector_count: entries.len(),
        failed_count,
        skipped_count,
        entries,
    })
}

fn audit_connector_directory(
    connector_dir: &Path,
) -> Result<ConnectorManifestOperationAudit, ManifestOperationsAuditError> {
    let manifest_path = connector_dir.join("manifest.toml");
    let manifest_raw =
        fs::read_to_string(&manifest_path).map_err(|source| ManifestOperationsAuditError::Io {
            path: manifest_path.clone(),
            source,
        })?;
    let mut sources = Vec::new();
    for source_path in rust_source_paths(&connector_dir.join("src"))? {
        sources.push(fs::read_to_string(&source_path).map_err(|source| {
            ManifestOperationsAuditError::Io {
                path: source_path,
                source,
            }
        })?);
    }
    let source_refs = sources.iter().map(String::as_str).collect::<Vec<_>>();
    Ok(audit_connector_text(
        connector_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown"),
        &manifest_path,
        &manifest_raw,
        &source_refs,
    ))
}

/// Audit a single connector from manifest text and source snippets.
#[must_use]
pub fn audit_connector_text(
    connector_slug_hint: &str,
    manifest_path: &Path,
    manifest_raw: &str,
    source_texts: &[&str],
) -> ConnectorManifestOperationAudit {
    let manifest_value = toml::from_str::<toml::Value>(manifest_raw);
    let (connector_id, connector_slug, manifest_operation_count, parse_error) = match manifest_value
    {
        Ok(value) => (
            connector_id(&value).unwrap_or_else(|| format!("fcp.{connector_slug_hint}")),
            connector_slug(&value).unwrap_or_else(|| connector_slug_hint.to_owned()),
            manifest_operation_count(&value),
            None,
        ),
        Err(error) => (
            format!("fcp.{connector_slug_hint}"),
            connector_slug_hint.to_owned(),
            0,
            Some(error.to_string()),
        ),
    };

    let runtime_operation_ids =
        runtime_operation_ids_from_sources(&connector_slug, &connector_id, source_texts);
    let runtime_operation_count =
        (!runtime_operation_ids.is_empty()).then_some(runtime_operation_ids.len());

    let (result, mismatch_reason, skip_reason) = connector_result(
        manifest_operation_count,
        runtime_operation_count,
        parse_error.as_deref(),
    );

    ConnectorManifestOperationAudit {
        connector_id,
        connector_slug,
        manifest_path: manifest_path.display().to_string(),
        manifest_operation_count,
        runtime_operation_count,
        runtime_operation_ids,
        result,
        mismatch_reason,
        redaction_decision: REDACTION_DECISION.to_owned(),
        cleanup_result: "no cleanup required; read-only audit".to_owned(),
        skip_reason,
    }
}

fn connector_id(value: &toml::Value) -> Option<String> {
    value
        .get("connector")
        .and_then(|connector| connector.get("id"))
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
}

fn connector_slug(value: &toml::Value) -> Option<String> {
    connector_id(value).map(|id| {
        id.strip_prefix("fcp.")
            .unwrap_or(id.as_str())
            .replace('.', "-")
    })
}

fn manifest_operation_count(value: &toml::Value) -> usize {
    value
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .map_or(0, toml::map::Map::len)
}

fn runtime_operation_ids_from_sources(
    connector_slug: &str,
    connector_id: &str,
    source_texts: &[&str],
) -> Vec<String> {
    let mut prefixes = BTreeSet::new();
    prefixes.insert(format!("{connector_slug}."));
    prefixes.insert(format!("{}.", connector_slug.replace('-', "_")));
    if let Some(short_id) = connector_id.strip_prefix("fcp.") {
        prefixes.insert(format!("{short_id}."));
        prefixes.insert(format!("{}.", short_id.replace('.', "-")));
    }

    let mut ids = BTreeSet::new();
    for source in source_texts {
        for candidate in json_id_string_literals(source) {
            if prefixes
                .iter()
                .any(|prefix| candidate.starts_with(prefix.as_str()))
                && looks_like_operation_id(&candidate)
            {
                ids.insert(candidate);
            }
        }
    }
    ids.into_iter().collect()
}

fn json_id_string_literals(source: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut offset = 0;
    while let Some(relative_id_pos) = source[offset..].find("\"id\"") {
        let id_pos = offset + relative_id_pos;
        let mut remainder = source[id_pos + "\"id\"".len()..].trim_start();
        if !remainder.starts_with(':') {
            offset = id_pos + "\"id\"".len();
            continue;
        }
        remainder = remainder[1..].trim_start();
        let Some((literal, consumed)) = parse_jsonish_string_literal(remainder) else {
            offset = id_pos + "\"id\"".len();
            continue;
        };
        literals.push(literal);
        offset = source.len() - remainder.len() + consumed;
    }
    literals
}

fn parse_jsonish_string_literal(input: &str) -> Option<(String, usize)> {
    if !input.starts_with('"') {
        return None;
    }
    let mut literal = String::new();
    let mut escaped = false;
    for (index, ch) in input[1..].char_indices() {
        if escaped {
            literal.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => return Some((literal, index + 2)),
            other => literal.push(other),
        }
    }
    None
}

fn looks_like_operation_id(candidate: &str) -> bool {
    candidate.contains('.')
        && candidate.len() <= 128
        && candidate
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
}

fn connector_result(
    manifest_operation_count: usize,
    runtime_operation_count: Option<usize>,
    parse_error: Option<&str>,
) -> (AuditResult, Option<String>, Option<String>) {
    if let Some(error) = parse_error {
        return (
            AuditResult::Fail,
            Some(format!("manifest_toml_parse_error: {error}")),
            None,
        );
    }
    if manifest_operation_count == 0 {
        return match runtime_operation_count {
            Some(count) if count > 0 => (
                AuditResult::Fail,
                Some(format!(
                    "manifest declares zero operations but runtime/source metadata exposes {count}"
                )),
                None,
            ),
            _ => (
                AuditResult::Fail,
                Some(
                    "manifest declares zero operations and no static runtime operation metadata was detected"
                        .to_owned(),
                ),
                Some(
                    "live_runtime_introspection_not_loaded; static source operation ids were not detected"
                        .to_owned(),
                ),
            ),
        };
    }
    (AuditResult::Pass, None, None)
}

fn rust_source_paths(src_dir: &Path) -> Result<Vec<PathBuf>, ManifestOperationsAuditError> {
    if !src_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    collect_rust_source_paths(src_dir, &mut paths)?;
    paths.sort();
    Ok(paths)
}

fn collect_rust_source_paths(
    dir: &Path,
    paths: &mut Vec<PathBuf>,
) -> Result<(), ManifestOperationsAuditError> {
    for entry in read_dir_sorted(dir)? {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|source| ManifestOperationsAuditError::Io {
                path: path.clone(),
                source,
            })?;
        if file_type.is_dir() {
            collect_rust_source_paths(&path, paths)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            paths.push(path);
        }
    }
    Ok(())
}

fn read_dir_sorted(dir: &Path) -> Result<Vec<fs::DirEntry>, ManifestOperationsAuditError> {
    let mut entries = fs::read_dir(dir)
        .map_err(|source| ManifestOperationsAuditError::Io {
            path: dir.to_path_buf(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| ManifestOperationsAuditError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
    entries.sort_by_key(fs::DirEntry::path);
    Ok(entries)
}

/// Build schema-valid JSONL logs for an audit report.
///
/// # Errors
///
/// Returns an error if any log entry cannot be serialized.
pub fn audit_report_jsonl(
    report: &ManifestOperationsAuditReport,
    command_line: &[String],
    git_revision: &str,
    correlation_id: &str,
    timestamp: &str,
) -> Result<String, ManifestOperationsAuditError> {
    let mut lines = Vec::with_capacity(report.entries.len() + 1);
    for (index, entry) in report.entries.iter().enumerate() {
        lines.push(log_line(
            "connector_scan",
            u64::try_from(index).unwrap_or(u64::MAX),
            entry.result,
            correlation_id,
            timestamp,
            json!({
                "command_line": command_line,
                "git_revision": git_revision,
                "connector_id": entry.connector_id,
                "connector_slug": entry.connector_slug,
                "manifest_path": entry.manifest_path,
                "manifest_operation_count": entry.manifest_operation_count,
                "runtime_introspection_operation_count": entry.runtime_operation_count,
                "runtime_operation_ids": entry.runtime_operation_ids,
                "mismatch_reason": entry.mismatch_reason,
                "redaction_decision": entry.redaction_decision,
                "cleanup_result": entry.cleanup_result,
                "skip_reason": entry.skip_reason,
                "source": "manifest.toml plus static Rust source operation metadata",
            }),
            None,
        )?);
    }
    lines.push(log_line(
        "summary",
        u64::try_from(report.entries.len()).unwrap_or(u64::MAX),
        if report.passed() {
            AuditResult::Pass
        } else {
            AuditResult::Fail
        },
        correlation_id,
        timestamp,
        json!({
            "command_line": command_line,
            "git_revision": git_revision,
            "repo_root": report.repo_root,
            "connector_count": report.connector_count,
            "failed_count": report.failed_count,
            "skipped_count": report.skipped_count,
            "failing_connectors": report.failed_connector_ids(),
            "zero_manifest_runtime_connectors": report.zero_manifest_runtime_connector_ids(),
            "redaction_decision": REDACTION_DECISION,
            "cleanup_result": "no cleanup required; read-only audit",
            "skip_reason": Value::Null,
        }),
        None,
    )?);
    Ok(format!("{}\n", lines.join("\n")))
}

fn log_line(
    step: &str,
    step_number: u64,
    result: AuditResult,
    correlation_id: &str,
    timestamp: &str,
    details: Value,
    assertions: Option<Value>,
) -> Result<String, ManifestOperationsAuditError> {
    let mut value = json!({
        "timestamp": timestamp,
        "log_version": LOG_VERSION,
        "script": SCRIPT_NAME,
        "step": step,
        "step_number": step_number,
        "correlation_id": correlation_id,
        "duration_ms": 0,
        "result": result.as_log_result(),
    });
    if let Some(object) = value.as_object_mut() {
        object.insert("details".to_owned(), details);
    }
    if let Some(assertions) = assertions
        && let Some(object) = value.as_object_mut()
    {
        object.insert("assertions".to_owned(), assertions);
    }
    serde_json::to_string(&value).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_WITH_OPERATION: &str = r#"
[connector]
id = "fcp.demo"

[provides.operations.echo]
description = "Echo"
"#;

    const VALID_WITHOUT_OPERATION: &str = r#"
[connector]
id = "fcp.demo"
"#;

    #[test]
    fn counts_manifest_operation_sections() {
        let entry = audit_connector_text(
            "demo",
            Path::new("connectors/demo/manifest.toml"),
            VALID_WITH_OPERATION,
            &[],
        );

        assert_eq!(entry.connector_id, "fcp.demo");
        assert_eq!(entry.manifest_operation_count, 1);
        assert_eq!(entry.result, AuditResult::Pass);
    }

    #[test]
    fn detects_zero_manifest_operations_with_runtime_source_ids() {
        let source = r#"json!({"id": "demo.echo"}); json!({"id": "other.echo"});"#;
        let entry = audit_connector_text(
            "demo",
            Path::new("connectors/demo/manifest.toml"),
            VALID_WITHOUT_OPERATION,
            &[source],
        );

        assert_eq!(entry.manifest_operation_count, 0);
        assert_eq!(entry.runtime_operation_count, Some(1));
        assert_eq!(entry.runtime_operation_ids, vec!["demo.echo"]);
        assert_eq!(entry.result, AuditResult::Fail);
        assert!(
            entry
                .mismatch_reason
                .as_deref()
                .unwrap_or_default()
                .contains("manifest declares zero operations")
        );
    }

    #[test]
    fn zero_manifest_without_runtime_metadata_fails_with_structured_skip_reason() {
        let entry = audit_connector_text(
            "demo",
            Path::new("connectors/demo/manifest.toml"),
            VALID_WITHOUT_OPERATION,
            &[],
        );

        assert_eq!(entry.result, AuditResult::Fail);
        assert!(entry.skip_reason.is_some());
    }

    #[test]
    fn malformed_manifest_is_failure() {
        let entry = audit_connector_text(
            "demo",
            Path::new("connectors/demo/manifest.toml"),
            "{{{{invalid toml}}}}",
            &[],
        );

        assert_eq!(entry.result, AuditResult::Fail);
        assert!(
            entry
                .mismatch_reason
                .as_deref()
                .unwrap_or_default()
                .contains("manifest_toml_parse_error")
        );
    }

    #[test]
    fn source_operation_ids_are_deterministic_and_deduplicated() {
        let ids = runtime_operation_ids_from_sources(
            "demo-connector",
            "fcp.demo-connector",
            &[
                r#""id": "demo-connector.beta", "id": "demo-connector.alpha", "id": "demo-connector.alpha""#,
                r#""id": "demo_connector.gamma", "capability": "demo-connector.not_an_operation""#,
            ],
        );

        assert_eq!(
            ids,
            vec![
                "demo-connector.alpha",
                "demo-connector.beta",
                "demo_connector.gamma"
            ]
        );
    }

    #[test]
    fn jsonl_contains_required_redaction_and_count_fields() {
        let entry = audit_connector_text(
            "demo",
            Path::new("connectors/demo/manifest.toml"),
            VALID_WITHOUT_OPERATION,
            &[r#""id": "demo.echo""#],
        );
        let report = ManifestOperationsAuditReport {
            repo_root: ".".to_owned(),
            connector_count: 1,
            failed_count: 1,
            skipped_count: 0,
            entries: vec![entry],
        };
        let jsonl = audit_report_jsonl(
            &report,
            &["fcp-manifest-ops-audit".to_owned()],
            "test-rev",
            "test-correlation",
            "2026-05-07T00:00:00Z",
        )
        .expect("jsonl");

        assert!(jsonl.contains("\"manifest_operation_count\":0"));
        assert!(jsonl.contains("redaction-safe"));
        assert!(jsonl.contains("\"failing_connectors\":[\"fcp.demo\"]"));
        assert!(jsonl.contains("\"zero_manifest_runtime_connectors\":[\"fcp.demo\"]"));
        crate::schemas::validate_e2e_log_jsonl(&jsonl).expect("audit JSONL validates");
    }
}
