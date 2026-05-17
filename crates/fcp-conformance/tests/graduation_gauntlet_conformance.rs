use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

const EXPECTED_CHECKS: [(&str, i32); 12] = [
    ("connector_path", 1),
    ("operations_info", 2),
    ("manifest_present", 3),
    ("readme_present", 4),
    ("verification_script_declared", 5),
    ("manifest_operations", 6),
    ("local_non_mock", 7),
    ("readme_status_match", 8),
    ("operation_inventory", 9),
    ("network_policy", 10),
    ("sandbox_profile", 11),
    ("operator_guidance", 12),
];

#[derive(Clone, Copy)]
struct FixtureOptions {
    status: &'static str,
    manifest_status: &'static str,
    include_operations_info: bool,
    include_local_non_mock: bool,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        Self {
            status: "PROVEN",
            manifest_status: "proven",
            include_operations_info: true,
            include_local_non_mock: true,
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("fcp-conformance manifest should live below crates/")
        .to_path_buf()
}

fn gauntlet_runner() -> PathBuf {
    workspace_root().join("scripts/graduation/run_gauntlet.sh")
}

fn run_gauntlet<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Command::new("bash")
        .current_dir(workspace_root())
        .arg(gauntlet_runner())
        .args(args)
        .output()
        .expect("graduation gauntlet runner should execute")
}

fn unique_fixture_root(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after UNIX epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "fcp-graduation-gauntlet-{test_name}-{}-{nanos}",
        std::process::id()
    ))
}

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("fixture parent directory should be creatable");
    }
    fs::write(path, contents).expect("fixture file should be writable");
}

fn write_fixture_connector(root: &Path, options: FixtureOptions) -> PathBuf {
    let connector = root.join("fixture-connector");
    fs::create_dir_all(&connector).expect("fixture connector directory should be creatable");

    write_file(
        &connector.join("manifest.toml"),
        &format!(
            r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"

[connector]
id = "fcp.fixture"
name = "Fixture Connector"
version = "0.1.0"
status = "{}"

[provides.operations."fixture.health"]
description = "Fixture health proof."
capability = "fixture.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"

[provides.operations."fixture.health".input_schema]
type = "object"

[provides.operations."fixture.health".output_schema]
type = "object"

[provides.operations."fixture.health".network_constraints]
host_allow = ["fixture.invalid"]
port_allow = [443]
deny_localhost = true
deny_private_ranges = true
deny_tailnet_ranges = true
deny_ip_literals = true

[sandbox]
profile = "connector-default"
"#,
            options.manifest_status
        ),
    );

    write_file(
        &connector.join("README.md"),
        &format!(
            r"# Fixture Connector

> **Status**: {}
> **Bead**: `fixture-gauntlet`
> **Verification script**: `scripts/e2e/fixture_connector_verification.sh`

## Purpose

Fixture connector for graduation gauntlet conformance tests.

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency |
|-----------|----------------|------------|------------|-----------|-------------|
| `fixture.health` | `GET /health` | `fixture.read` | `Safe` | `Low` | `Strict` |

## Operator Guidance

Prerequisites:
- Use the local fixture only.

Rerun commands:
- `scripts/e2e/fixture_connector_verification.sh`
",
            options.status
        ),
    );

    if options.include_operations_info {
        write_file(
            &connector.join("src/connector.rs"),
            "pub fn operations_info() -> Vec<&'static str> { vec![\"fixture.health\"] }\n",
        );
    }

    if options.include_local_non_mock {
        write_file(
            &connector.join("tests/local_non_mock.rs"),
            "#[test]\nfn local_non_mock_fixture() { assert!(true); }\n",
        );
    }

    connector
}

fn assert_failed_with(output: &Output, expected_code: i32, expected_check: &str) {
    assert_eq!(
        output.status.code(),
        Some(expected_code),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("check={expected_check}")),
        "stderr should name failed check {expected_check}, got:\n{stderr}"
    );
}

#[test]
fn test_gauntlet_recognizes_all_12_checks() {
    let output = run_gauntlet(["--list-checks"]);
    assert!(
        output.status.success(),
        "list-checks failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let records = stdout.lines().collect::<Vec<_>>();
    assert_eq!(records.len(), EXPECTED_CHECKS.len());

    for ((expected_name, expected_code), record) in EXPECTED_CHECKS.iter().zip(records) {
        let parts = record.split('|').collect::<Vec<_>>();
        assert_eq!(
            parts.len(),
            3,
            "record should be id|exit|description: {record}"
        );
        assert_eq!(parts[0], *expected_name);
        assert_eq!(parts[1].parse::<i32>(), Ok(*expected_code));
        assert!(!parts[2].is_empty(), "description should be non-empty");
    }

    let fixture_root = unique_fixture_root("passing");
    let connector = write_fixture_connector(&fixture_root, FixtureOptions::default());
    let output = run_gauntlet([connector.as_os_str()]);
    assert!(
        output.status.success(),
        "passing fixture should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_gauntlet_fail_on_missing_operations_info() {
    let fixture_root = unique_fixture_root("missing-operations-info");
    let connector = write_fixture_connector(
        &fixture_root,
        FixtureOptions {
            include_operations_info: false,
            ..FixtureOptions::default()
        },
    );

    let output = run_gauntlet([connector.as_os_str()]);
    assert_failed_with(&output, 2, "operations_info");
}

#[test]
fn test_gauntlet_fail_on_missing_local_non_mock() {
    let fixture_root = unique_fixture_root("missing-local-non-mock");
    let connector = write_fixture_connector(
        &fixture_root,
        FixtureOptions {
            include_local_non_mock: false,
            ..FixtureOptions::default()
        },
    );

    let output = run_gauntlet([connector.as_os_str()]);
    assert_failed_with(&output, 7, "local_non_mock");
}

#[test]
fn test_gauntlet_fail_on_readme_status_mismatch() {
    let fixture_root = unique_fixture_root("status-mismatch");
    let connector = write_fixture_connector(
        &fixture_root,
        FixtureOptions {
            manifest_status: "ready",
            ..FixtureOptions::default()
        },
    );

    let output = run_gauntlet([connector.as_os_str()]);
    assert_failed_with(&output, 8, "readme_status_match");
}

#[test]
fn batch1_status_runner_writes_status_markdown() {
    let fixture_root = unique_fixture_root("batch1-status");
    fs::create_dir_all(&fixture_root).expect("fixture root should be creatable");
    let status_path = fixture_root.join("batch1_status.md");
    let jsonl_path = fixture_root.join("batch1_status.jsonl");
    let output = run_gauntlet(vec![
        OsString::from("--jsonl"),
        jsonl_path.as_os_str().to_os_string(),
        OsString::from("--batch"),
        OsString::from("batch1"),
        OsString::from("--status-md"),
        status_path.as_os_str().to_os_string(),
    ]);
    assert!(
        output.status.success(),
        "batch1 status run failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let status_doc =
        fs::read_to_string(&status_path).expect("batch1 status markdown should be written");
    assert!(status_doc.contains("# Batch 1 Graduation Status"));
    assert!(status_doc.contains("scripts/graduation/run_gauntlet.sh --batch batch1"));
    assert!(status_doc.contains("Summary: `7/7` Batch 1 connectors currently pass"));
    assert!(status_doc.contains("PROVEN promotion proof bundle"));
    assert!(status_doc.contains("not just the presence-only gauntlet checks"));
    assert!(status_doc.contains("all_proven_connectors_pass_gauntlet"));
    assert!(
        !status_doc.contains("Add connector-local `tests/local_non_mock.rs` acceptance coverage"),
        "7/7 mechanical status should not emit stale pre-gauntlet blocker guidance"
    );
    for connector in [
        "connectors/postgresql",
        "connectors/stripe",
        "connectors/github",
        "connectors/gmail",
        "connectors/telegram",
        "connectors/slack",
        "connectors/kubernetes",
    ] {
        assert!(
            status_doc.contains(connector),
            "status doc should mention {connector}"
        );
    }

    let jsonl = fs::read_to_string(&jsonl_path).expect("batch1 JSONL should be written");
    let records = jsonl
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("valid JSONL record"))
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 7 * EXPECTED_CHECKS.len());
    assert!(
        records
            .iter()
            .all(|record| record["verdict"].as_str() == Some("pass")),
        "Batch 1 status JSONL should have no failed mechanical gauntlet rows: {jsonl}"
    );

    let connectors = records
        .iter()
        .filter_map(|record| record["connector"].as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        connectors,
        BTreeSet::from([
            "connectors/github",
            "connectors/gmail",
            "connectors/kubernetes",
            "connectors/postgresql",
            "connectors/slack",
            "connectors/stripe",
            "connectors/telegram",
        ])
    );

    let checks = records
        .iter()
        .filter_map(|record| record["check"].as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        checks,
        EXPECTED_CHECKS
            .iter()
            .map(|(check, _)| *check)
            .collect::<BTreeSet<_>>()
    );
}

#[test]
fn all_proven_connectors_pass_gauntlet() {
    let connectors_dir = workspace_root().join("connectors");
    let mut proven_connectors = Vec::new();

    for entry in fs::read_dir(&connectors_dir).expect("connectors directory should be readable") {
        let entry = entry.expect("connector directory entry should be readable");
        let readme = entry.path().join("README.md");
        if !readme.is_file() {
            continue;
        }
        let readme_contents =
            fs::read_to_string(&readme).expect("connector README should be readable");
        if readme_contents
            .lines()
            .any(|line| line.starts_with("> **Status**:") && line.contains("PROVEN"))
        {
            proven_connectors.push(entry.path());
        }
    }

    if proven_connectors.is_empty() {
        eprintln!("no literal PROVEN connector README statuses found");
    }

    for connector in proven_connectors {
        let output = run_gauntlet([connector.as_os_str()]);
        assert!(
            output.status.success(),
            "{} failed graduation gauntlet\nstdout:\n{}\nstderr:\n{}",
            connector.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
