//! Per-connector performance-budget conformance gate.
//!
//! The rollout is intentionally two-stage: declared budgets are always checked
//! against workspace ceilings, while requiring every mature connector to declare
//! a budget is gated by `CONNECTOR_BUDGET_REQUIRED=1` until the manifest
//! migration batch lands.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::json;
use tracing::{Level, info_span};

const BUDGET_REQUIRED_ENV: &str = "CONNECTOR_BUDGET_REQUIRED";
const DEFAULT_COLD_START_MAX_MS: f64 = 500.0;
const DEFAULT_LOCAL_INVOKE_MAX_MS: f64 = 10.0;
const DEFAULT_MEMORY_USS_MAX_MB: f64 = 10.0;
const DEFAULT_IDLE_CPU_MAX_PCT: f64 = 1.0;

#[derive(Debug, Clone, Copy)]
struct BudgetCeilings {
    cold_start_max_ms: f64,
    local_invoke_max_ms: f64,
    memory_uss_max_mb: f64,
    idle_cpu_max_pct: f64,
}

impl Default for BudgetCeilings {
    fn default() -> Self {
        Self {
            cold_start_max_ms: DEFAULT_COLD_START_MAX_MS,
            local_invoke_max_ms: DEFAULT_LOCAL_INVOKE_MAX_MS,
            memory_uss_max_mb: DEFAULT_MEMORY_USS_MAX_MB,
            idle_cpu_max_pct: DEFAULT_IDLE_CPU_MAX_PCT,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PerformanceBudgetValues {
    cold_start_max_ms: Option<f64>,
    local_invoke_max_ms: Option<f64>,
    memory_uss_max_mb: Option<f64>,
    idle_cpu_max_pct: Option<f64>,
}

#[derive(Debug, Clone)]
struct BudgetRecord {
    connector: String,
    connector_id: String,
    manifest_path: String,
    status: String,
    budget: Option<PerformanceBudgetValues>,
    parse_error: Option<String>,
}

impl BudgetRecord {
    const fn budget_declared(&self) -> bool {
        self.budget.is_some()
    }

    fn is_mature(&self) -> bool {
        self.status.eq_ignore_ascii_case("mature")
    }

    fn ceiling_violations(&self, ceilings: BudgetCeilings) -> Vec<String> {
        let Some(budget) = self.budget else {
            return Vec::new();
        };
        let mut violations = Vec::new();
        push_ceiling_violation(
            &mut violations,
            "cold_start_max_ms",
            budget.cold_start_max_ms,
            ceilings.cold_start_max_ms,
        );
        push_ceiling_violation(
            &mut violations,
            "local_invoke_max_ms",
            budget.local_invoke_max_ms,
            ceilings.local_invoke_max_ms,
        );
        push_ceiling_violation(
            &mut violations,
            "memory_uss_max_mb",
            budget.memory_uss_max_mb,
            ceilings.memory_uss_max_mb,
        );
        push_ceiling_violation(
            &mut violations,
            "idle_cpu_max_pct",
            budget.idle_cpu_max_pct,
            ceilings.idle_cpu_max_pct,
        );
        violations
    }

    fn to_log_json(
        &self,
        command_line: &str,
        git_revision: &str,
        ceilings: BudgetCeilings,
    ) -> serde_json::Value {
        let violations = self.ceiling_violations(ceilings);
        json!({
            "command_line": command_line,
            "git_revision": git_revision,
            "connector": self.connector,
            "connector_id": self.connector_id,
            "manifest_path": self.manifest_path,
            "status": self.status,
            "budget_declared": self.budget_declared(),
            "ceiling_compliant": violations.is_empty(),
            "ceiling_violations": violations,
            "redaction_decision": "connector names, manifest paths, status, and numeric budget ceilings only; no credentials, payloads, prompts, or PII read",
            "cleanup_result": "not_applicable_no_temp_resources",
            "skip_reason": "runtime execution skipped; raw manifest performance-budget conformance is credential-free",
        })
    }
}

fn install_test_subscriber() -> tracing::subscriber::DefaultGuard {
    tracing::subscriber::set_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(Level::INFO)
            .with_test_writer()
            .finish(),
    )
}

fn push_ceiling_violation(
    violations: &mut Vec<String>,
    field: &str,
    value: Option<f64>,
    ceiling: f64,
) {
    if let Some(value) = value
        && value > ceiling
    {
        violations.push(format!(
            "{field}={value} exceeds workspace ceiling {ceiling}"
        ));
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
        .map_err(|error| format!("cannot read {}: {error}", connectors.display()))?;
    let mut manifests = Vec::new();
    for entry_result in entries {
        let entry_result = entry_result
            .map_err(|error| format!("cannot read connector directory entry: {error}"))?;
        let path = entry_result.path();
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
    String::from_utf8(output.stdout)
        .map(|stdout| stdout.trim().to_owned())
        .ok()
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn env_budget_required() -> bool {
    env::var(BUDGET_REQUIRED_ENV).is_ok_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn parse_manifest(body: &str) -> Result<toml::Value, String> {
    toml::from_str::<toml::Table>(body)
        .map(toml::Value::Table)
        .map_err(|error| error.to_string())
}

fn manifest_connector_id(connector: &str, manifest: &toml::Value) -> String {
    manifest
        .get("connector")
        .and_then(|table| table.get("id"))
        .and_then(toml::Value::as_str)
        .map_or_else(|| format!("fcp.{connector}"), str::to_owned)
}

fn manifest_status(manifest: &toml::Value) -> String {
    manifest
        .get("connector")
        .and_then(|table| table.get("status"))
        .and_then(toml::Value::as_str)
        .unwrap_or("ready")
        .to_owned()
}

fn toml_number(value: &toml::Value) -> Option<f64> {
    value.as_float().or_else(|| {
        value
            .as_integer()
            .and_then(|integer| integer.to_string().parse::<f64>().ok())
    })
}

fn budget_value(
    table: &toml::map::Map<String, toml::Value>,
    field: &str,
) -> Result<Option<f64>, String> {
    let Some(value) = table.get(field) else {
        return Ok(None);
    };
    let Some(number) = toml_number(value) else {
        return Err(format!("performance_budget.{field} must be numeric"));
    };
    if !number.is_finite() || number < 0.0 {
        return Err(format!(
            "performance_budget.{field} must be a finite non-negative number"
        ));
    }
    Ok(Some(number))
}

fn performance_budget(manifest: &toml::Value) -> Result<Option<PerformanceBudgetValues>, String> {
    let Some(table) = manifest
        .get("performance_budget")
        .and_then(toml::Value::as_table)
    else {
        return Ok(None);
    };
    Ok(Some(PerformanceBudgetValues {
        cold_start_max_ms: budget_value(table, "cold_start_max_ms")?,
        local_invoke_max_ms: budget_value(table, "local_invoke_max_ms")?,
        memory_uss_max_mb: budget_value(table, "memory_uss_max_mb")?,
        idle_cpu_max_pct: budget_value(table, "idle_cpu_max_pct")?,
    }))
}

fn scan_manifest_body(root: &Path, connector: &str, path: &Path, body: &str) -> BudgetRecord {
    match parse_manifest(body) {
        Ok(manifest) => {
            let connector_id = manifest_connector_id(connector, &manifest);
            let status = manifest_status(&manifest);
            match performance_budget(&manifest) {
                Ok(budget) => BudgetRecord {
                    connector: connector.to_owned(),
                    connector_id,
                    manifest_path: display_path(root, path),
                    status,
                    budget,
                    parse_error: None,
                },
                Err(error) => BudgetRecord {
                    connector: connector.to_owned(),
                    connector_id,
                    manifest_path: display_path(root, path),
                    status,
                    budget: None,
                    parse_error: Some(error),
                },
            }
        }
        Err(error) => BudgetRecord {
            connector: connector.to_owned(),
            connector_id: format!("fcp.{connector}"),
            manifest_path: display_path(root, path),
            status: "unknown".to_owned(),
            budget: None,
            parse_error: Some(error),
        },
    }
}

fn scan_manifest_records(root: &Path) -> Result<Vec<BudgetRecord>, String> {
    let manifests = discover_manifests_in(&connectors_dir(root))?;
    let mut records = Vec::new();
    for (connector, path) in manifests {
        let body = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read manifest {}: {error}", path.display()))?;
        records.push(scan_manifest_body(root, &connector, &path, &body));
    }
    Ok(records)
}

fn table_number(manifest: &toml::Value, table: &str, field: &str) -> Option<f64> {
    manifest
        .get(table)
        .and_then(|value| value.get(field))
        .and_then(toml_number)
}

fn workspace_ceilings(root: &Path) -> BudgetCeilings {
    let path = root.join("docs/perf/perf-targets.toml");
    let Ok(body) = fs::read_to_string(path) else {
        return BudgetCeilings::default();
    };
    let Ok(manifest) = parse_manifest(&body) else {
        return BudgetCeilings::default();
    };
    BudgetCeilings {
        cold_start_max_ms: table_number(&manifest, "cold_start", "target_p99_ms")
            .unwrap_or(DEFAULT_COLD_START_MAX_MS),
        local_invoke_max_ms: table_number(&manifest, "local_invoke", "target_p99_ms")
            .unwrap_or(DEFAULT_LOCAL_INVOKE_MAX_MS),
        memory_uss_max_mb: table_number(&manifest, "memory_uss", "target_max_mb")
            .or_else(|| table_number(&manifest, "memory_overhead", "target_max_mb"))
            .unwrap_or(DEFAULT_MEMORY_USS_MAX_MB),
        idle_cpu_max_pct: table_number(&manifest, "idle_cpu", "target_max_pct")
            .or_else(|| table_number(&manifest, "cpu_overhead", "target_max_pct"))
            .unwrap_or(DEFAULT_IDLE_CPU_MAX_PCT),
    }
}

fn emit_json_line(event: &str, details: &serde_json::Value) {
    let line = json!({
        "module": "per_connector_budget_assertion",
        "event": event,
        "details": details,
    });
    match serde_json::to_string(&line) {
        Ok(line) => println!("{line}"),
        Err(error) => eprintln!("performance-budget JSONL encode failed: {error}"),
    }
}

fn assert_required_budgets(records: &[BudgetRecord], required: bool) -> Result<(), String> {
    if !required {
        return Ok(());
    }
    let missing = records
        .iter()
        .filter(|record| record.is_mature())
        .filter(|record| !record.budget_declared())
        .map(|record| record.connector.clone())
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "missing performance_budget for mature connectors: {}",
            missing.join(", ")
        ))
    }
}

fn assert_no_invalid_or_over_budget(
    records: &[BudgetRecord],
    ceilings: BudgetCeilings,
) -> Result<(), String> {
    let mut failures = Vec::new();
    for record in records {
        if let Some(error) = &record.parse_error {
            failures.push(format!("{}: {error}", record.connector));
        }
        let violations = record.ceiling_violations(ceilings);
        if !violations.is_empty() {
            failures.push(format!("{}: {}", record.connector, violations.join("; ")));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

#[test]
fn test_every_mature_connector_declares_budget() -> Result<(), String> {
    let _guard = install_test_subscriber();
    let root = workspace_root()?;
    let records = scan_manifest_records(&root)?;
    let ceilings = workspace_ceilings(&root);
    let command_line = current_command_line();
    let git_revision = current_git_revision(&root);
    let required = env_budget_required();

    for record in records.iter().filter(|record| record.is_mature()) {
        let violations = record.ceiling_violations(ceilings);
        let _span = info_span!(
            "fcp.conformance.budget_check",
            connector = record.connector.as_str(),
            status = record.status.as_str(),
            budget_declared = record.budget_declared(),
            ceiling_compliant = violations.is_empty()
        )
        .entered();
        emit_json_line(
            "performance_budget_manifest_status",
            &record.to_log_json(&command_line, &git_revision, ceilings),
        );
    }
    if !required {
        emit_json_line(
            "performance_budget_requirement_skipped",
            &json!({
                "env": BUDGET_REQUIRED_ENV,
                "required": false,
                "skip_reason": "budget block rollout is gated until existing mature connectors are migrated",
            }),
        );
    }

    assert_required_budgets(&records, required)
}

#[test]
fn test_budget_within_workspace_ceiling() -> Result<(), String> {
    let _guard = install_test_subscriber();
    let root = workspace_root()?;
    let records = scan_manifest_records(&root)?;
    let ceilings = workspace_ceilings(&root);
    let command_line = current_command_line();
    let git_revision = current_git_revision(&root);

    for record in records.iter().filter(|record| record.budget_declared()) {
        let violations = record.ceiling_violations(ceilings);
        let _span = info_span!(
            "fcp.conformance.budget_check",
            connector = record.connector.as_str(),
            status = record.status.as_str(),
            budget_declared = record.budget_declared(),
            ceiling_compliant = violations.is_empty()
        )
        .entered();
        emit_json_line(
            "performance_budget_ceiling_check",
            &record.to_log_json(&command_line, &git_revision, ceilings),
        );
    }

    assert_no_invalid_or_over_budget(&records, ceilings)
}

#[test]
fn test_missing_block_under_required_env() {
    let record = scan_manifest_body(
        Path::new("."),
        "mature-fixture",
        Path::new("connectors/mature-fixture/manifest.toml"),
        r#"
[connector]
id = "fcp.mature_fixture"
status = "MATURE"
"#,
    );

    let err = assert_required_budgets(&[record], true)
        .expect_err("mature connector without budget should fail required gate");
    assert!(
        err.contains("mature-fixture"),
        "expected connector name in error, got {err}"
    );
}

#[test]
#[should_panic(expected = "missing performance_budget")]
fn test_missing_mature_budget_fixture_panics() {
    let record = scan_manifest_body(
        Path::new("."),
        "mature-fixture",
        Path::new("connectors/mature-fixture/manifest.toml"),
        r#"
[connector]
id = "fcp.mature_fixture"
status = "MATURE"
"#,
    );

    assert_required_budgets(&[record], true).expect("missing performance_budget");
}
