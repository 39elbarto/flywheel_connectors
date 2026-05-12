use fcp_manifest::{ConnectorManifest, ManifestError};

const PLACEHOLDER_HASH: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

fn manifest_toml(interface_hash: &str, performance_budget: &str) -> String {
    format!(
        r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
interface_hash = "{interface_hash}"

[connector]
id = "fcp.perf_budget_fixture"
name = "Performance Budget Fixture"
version = "1.0.0"
description = "Manifest performance budget parser fixture"
archetypes = ["operational"]
format = "native"

[zones]
home = "z:work"
allowed_sources = ["z:work"]
allowed_targets = ["z:work"]
forbidden = []

[capabilities]
required = ["fixture.invoke"]
optional = []
forbidden = ["system.exec"]

[provides.operations.fixture_invoke]
description = "Invoke the parser fixture"
capability = "fixture.invoke"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "none"
input_schema = {{ type = "object" }}
output_schema = {{ type = "object" }}

{performance_budget}
[sandbox]
profile = "strict"
memory_mb = 64
cpu_percent = 20
wall_clock_timeout_ms = 1000
fs_readonly_paths = ["/usr"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true
"#
    )
}

fn manifest_with_computed_hash(performance_budget: &str) -> String {
    let unchecked = ConnectorManifest::parse_str_unchecked(&manifest_toml(
        PLACEHOLDER_HASH,
        performance_budget,
    ))
    .expect("fixture manifest should parse unchecked");
    let computed = unchecked
        .compute_interface_hash()
        .expect("fixture interface hash should compute");
    manifest_toml(&computed.to_string(), performance_budget)
}

fn parse_fixture(performance_budget: &str) -> ConnectorManifest {
    ConnectorManifest::parse_str(&manifest_with_computed_hash(performance_budget))
        .expect("fixture manifest should validate")
}

fn assert_budget_value(value: Option<f64>, expected: f64) {
    let value = value.expect("budget field should be present");
    assert!(
        (value - expected).abs() < f64::EPSILON,
        "expected {expected}, got {value}"
    );
}

#[test]
fn test_budget_parses_all_fields() {
    let manifest = parse_fixture(
        r"[performance_budget]
cold_start_max_ms = 200
local_invoke_max_ms = 10
memory_uss_max_mb = 10
idle_cpu_max_pct = 1

",
    );
    let budget = manifest
        .performance_budget
        .expect("performance budget should parse");

    assert_budget_value(budget.cold_start_max_ms, 200.0);
    assert_budget_value(budget.local_invoke_max_ms, 10.0);
    assert_budget_value(budget.memory_uss_max_mb, 10.0);
    assert_budget_value(budget.idle_cpu_max_pct, 1.0);
}

#[test]
fn test_budget_partial_ok() {
    let manifest = parse_fixture(
        r"[performance_budget]
local_invoke_max_ms = 7.5

",
    );
    let budget = manifest
        .performance_budget
        .expect("performance budget should parse");

    assert_eq!(budget.cold_start_max_ms, None);
    assert_budget_value(budget.local_invoke_max_ms, 7.5);
    assert_eq!(budget.memory_uss_max_mb, None);
    assert_eq!(budget.idle_cpu_max_pct, None);
}

#[test]
fn test_budget_validates_nonnegative() {
    let err = ConnectorManifest::parse_str(&manifest_with_computed_hash(
        r"[performance_budget]
cold_start_max_ms = -1

",
    ))
    .expect_err("negative performance budget should be rejected");

    assert!(
        matches!(
            err,
            ManifestError::InvalidPerformanceBudget { field, .. }
                if field == "performance_budget.cold_start_max_ms"
        ),
        "expected InvalidPerformanceBudget for cold start, got {err:?}"
    );
}
