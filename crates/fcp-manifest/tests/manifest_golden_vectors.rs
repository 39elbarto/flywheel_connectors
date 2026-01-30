//! Golden vector tests for connector manifest parsing and validation.
//!
//! These tests complement the inline tests in `src/lib.rs` by covering additional
//! edge cases and providing structured test logging.

use chrono::Utc;
use fcp_manifest::{ConnectorManifest, ManifestError};
use serde_json::json;
use std::path::Path;
use std::time::Instant;
use uuid::Uuid;

const PLACEHOLDER_HASH: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

struct TestLog {
    test_name: &'static str,
    module: &'static str,
    correlation_id: String,
    started_at: Instant,
    connector_id: Option<&'static str>,
    version: Option<&'static str>,
    capabilities_count: Option<usize>,
}

impl TestLog {
    fn new(
        test_name: &'static str,
        module: &'static str,
        connector_id: Option<&'static str>,
        version: Option<&'static str>,
        capabilities_count: Option<usize>,
    ) -> Self {
        let correlation_id = Uuid::new_v4().to_string();
        let log = Self {
            test_name,
            module,
            correlation_id,
            started_at: Instant::now(),
            connector_id,
            version,
            capabilities_count,
        };
        log.emit("execute", Some("start"), 0);
        log
    }

    fn emit(&self, phase: &str, result: Option<&str>, duration_ms: u128) {
        let payload = json!({
            "timestamp": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "test_name": self.test_name,
            "module": self.module,
            "phase": phase,
            "correlation_id": self.correlation_id,
            "connector_id": self.connector_id,
            "version": self.version,
            "capabilities_count": self.capabilities_count,
            "duration_ms": duration_ms,
            "result": result,
        });
        println!("{payload}");
    }
}

impl Drop for TestLog {
    fn drop(&mut self) {
        let duration_ms = self.started_at.elapsed().as_millis();
        let result = if std::thread::panicking() {
            "fail"
        } else {
            "pass"
        };
        self.emit("verify", Some(result), duration_ms);
    }
}

fn vector_manifest_path(name: &str) -> std::path::PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    root.join("../../tests/vectors/manifest").join(name)
}

fn read_vector_manifest(name: &str) -> String {
    let path = vector_manifest_path(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read manifest vector {}: {err}", path.display()))
}

fn with_computed_hash(raw: &str) -> String {
    let unchecked =
        ConnectorManifest::parse_str_unchecked(raw).expect("vector must parse unchecked");
    let computed = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");
    raw.replace(PLACEHOLDER_HASH, &computed.to_string())
}

fn base_manifest_toml(interface_hash: &str) -> String {
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
id = "fcp.test"
name = "Test Connector"
version = "1.0.0"
description = "Test connector"
archetypes = ["operational"]
format = "native"

[zones]
home = "z:work"
allowed_sources = ["z:work"]
allowed_targets = ["z:work"]
forbidden = []

[capabilities]
required = ["network.dns"]
optional = []
forbidden = ["system.exec"]

[provides.operations.test_op]
description = "Test operation"
capability = "test.op"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "none"
input_schema = {{ type = "object" }}
output_schema = {{ type = "object" }}

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

// =============================================================================
// TOML Parsing Tests
// =============================================================================

#[test]
fn rejects_missing_manifest_section() {
    let _log = TestLog::new(
        "rejects_missing_manifest_section",
        "fcp-manifest",
        None,
        None,
        None,
    );
    let toml = r#"
[connector]
id = "fcp.test"
name = "Test"
version = "1.0.0"
description = "test"
archetypes = ["operational"]
format = "native"

[zones]
home = "z:work"
allowed_sources = ["z:work"]
allowed_targets = ["z:work"]
forbidden = []

[capabilities]
required = ["network.dns"]
optional = []
forbidden = ["system.exec"]

[provides.operations.test_op]
description = "Test"
capability = "test.op"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "none"
input_schema = { type = "object" }
output_schema = { type = "object" }

[sandbox]
profile = "strict"
memory_mb = 64
cpu_percent = 20
wall_clock_timeout_ms = 1000
fs_readonly_paths = ["/usr"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true
"#;
    let err = ConnectorManifest::parse_str(toml).unwrap_err();
    assert!(matches!(err, ManifestError::Toml(_)));
    assert!(err.to_string().contains("manifest"));
}

#[test]
fn rejects_missing_connector_section() {
    let _log = TestLog::new(
        "rejects_missing_connector_section",
        "fcp-manifest",
        None,
        None,
        None,
    );
    let toml = format!(
        r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
interface_hash = "{PLACEHOLDER_HASH}"

[zones]
home = "z:work"
allowed_sources = ["z:work"]
allowed_targets = ["z:work"]
forbidden = []

[capabilities]
required = ["network.dns"]
optional = []
forbidden = ["system.exec"]

[provides.operations.test_op]
description = "Test"
capability = "test.op"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "none"
input_schema = {{ type = "object" }}
output_schema = {{ type = "object" }}

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
    );
    let err = ConnectorManifest::parse_str(&toml).unwrap_err();
    assert!(matches!(err, ManifestError::Toml(_)));
    assert!(err.to_string().contains("connector"));
}

#[test]
fn rejects_missing_zones_section() {
    let _log = TestLog::new(
        "rejects_missing_zones_section",
        "fcp-manifest",
        None,
        None,
        None,
    );
    let toml = format!(
        r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
interface_hash = "{PLACEHOLDER_HASH}"

[connector]
id = "fcp.test"
name = "Test"
version = "1.0.0"
description = "test"
archetypes = ["operational"]
format = "native"

[capabilities]
required = ["network.dns"]
optional = []
forbidden = ["system.exec"]

[provides.operations.test_op]
description = "Test"
capability = "test.op"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "none"
input_schema = {{ type = "object" }}
output_schema = {{ type = "object" }}

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
    );
    let err = ConnectorManifest::parse_str(&toml).unwrap_err();
    assert!(matches!(err, ManifestError::Toml(_)));
    assert!(err.to_string().contains("zones"));
}

#[test]
fn rejects_unknown_field_in_manifest() {
    let _log = TestLog::new(
        "rejects_unknown_field_in_manifest",
        "fcp-manifest",
        None,
        None,
        None,
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH)
        .replace("[manifest]", "[manifest]\nunknown_field = \"bad\"");
    let err = ConnectorManifest::parse_str(&toml).unwrap_err();
    assert!(matches!(err, ManifestError::Toml(_)));
    assert!(err.to_string().contains("unknown"));
}

#[test]
fn rejects_invalid_toml_syntax() {
    let _log = TestLog::new(
        "rejects_invalid_toml_syntax",
        "fcp-manifest",
        None,
        None,
        None,
    );
    let toml = "[manifest\nformat = \"broken";
    let err = ConnectorManifest::parse_str(toml).unwrap_err();
    assert!(matches!(err, ManifestError::Toml(_)));
}

// =============================================================================
// Field Validation Tests
// =============================================================================

#[test]
fn rejects_invalid_connector_id_format() {
    let _log = TestLog::new(
        "rejects_invalid_connector_id_format",
        "fcp-manifest",
        None,
        None,
        None,
    );
    // Connector ID with uppercase is invalid
    let toml = base_manifest_toml(PLACEHOLDER_HASH).replace("fcp.test", "FCP.Test");
    let err = ConnectorManifest::parse_str(&toml).unwrap_err();
    assert!(matches!(err, ManifestError::Toml(_) | ManifestError::Id(_)));
}

#[test]
fn rejects_connector_id_with_spaces() {
    let _log = TestLog::new(
        "rejects_connector_id_with_spaces",
        "fcp-manifest",
        None,
        None,
        None,
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH).replace("fcp.test", "fcp test");
    let err = ConnectorManifest::parse_str(&toml).unwrap_err();
    assert!(matches!(err, ManifestError::Toml(_) | ManifestError::Id(_)));
}

#[test]
fn rejects_invalid_manifest_format() {
    let _log = TestLog::new(
        "rejects_invalid_manifest_format",
        "fcp-manifest",
        None,
        None,
        None,
    );
    let toml =
        base_manifest_toml(PLACEHOLDER_HASH).replace("fcp-connector-manifest", "invalid-format");
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash =
        base_manifest_toml(&hash.to_string()).replace("fcp-connector-manifest", "invalid-format");
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    assert!(matches!(err, ManifestError::Invalid { field, .. } if field == "manifest.format"));
}

#[test]
fn rejects_unsupported_schema_version() {
    let _log = TestLog::new(
        "rejects_unsupported_schema_version",
        "fcp-manifest",
        None,
        None,
        None,
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH)
        .replace("schema_version = \"2.1\"", "schema_version = \"3.0\"");
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash = base_manifest_toml(&hash.to_string())
        .replace("schema_version = \"2.1\"", "schema_version = \"3.0\"");
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    assert!(
        matches!(err, ManifestError::Invalid { field, .. } if field == "manifest.schema_version")
    );
}

#[test]
fn rejects_zero_max_datagram_bytes() {
    let _log = TestLog::new(
        "rejects_zero_max_datagram_bytes",
        "fcp-manifest",
        None,
        None,
        None,
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH)
        .replace("max_datagram_bytes = 1200", "max_datagram_bytes = 0");
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash = base_manifest_toml(&hash.to_string())
        .replace("max_datagram_bytes = 1200", "max_datagram_bytes = 0");
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    assert!(
        matches!(err, ManifestError::Invalid { field, .. } if field == "manifest.max_datagram_bytes")
    );
}

#[test]
fn rejects_invalid_risk_level() {
    let _log = TestLog::new(
        "rejects_invalid_risk_level",
        "fcp-manifest",
        None,
        None,
        None,
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH)
        .replace("risk_level = \"low\"", "risk_level = \"extreme\"");
    let err = ConnectorManifest::parse_str(&toml).unwrap_err();
    assert!(matches!(err, ManifestError::Toml(_)));
}

#[test]
fn rejects_invalid_safety_tier() {
    let _log = TestLog::new(
        "rejects_invalid_safety_tier",
        "fcp-manifest",
        None,
        None,
        None,
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH)
        .replace("safety_tier = \"safe\"", "safety_tier = \"super_safe\"");
    let err = ConnectorManifest::parse_str(&toml).unwrap_err();
    assert!(matches!(err, ManifestError::Toml(_)));
}

#[test]
fn rejects_invalid_idempotency_class() {
    let _log = TestLog::new(
        "rejects_invalid_idempotency_class",
        "fcp-manifest",
        None,
        None,
        None,
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH)
        .replace("idempotency = \"none\"", "idempotency = \"always\"");
    let err = ConnectorManifest::parse_str(&toml).unwrap_err();
    assert!(matches!(err, ManifestError::Toml(_)));
}

#[test]
fn rejects_invalid_approval_mode() {
    let _log = TestLog::new(
        "rejects_invalid_approval_mode",
        "fcp-manifest",
        None,
        None,
        None,
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH).replace(
        "requires_approval = \"none\"",
        "requires_approval = \"maybe\"",
    );
    let err = ConnectorManifest::parse_str(&toml).unwrap_err();
    assert!(matches!(err, ManifestError::Toml(_)));
}

// =============================================================================
// Zone Validation Tests
// =============================================================================

#[test]
fn rejects_home_zone_in_forbidden() {
    let _log = TestLog::new(
        "rejects_home_zone_in_forbidden",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml =
        base_manifest_toml(PLACEHOLDER_HASH).replace("forbidden = []", "forbidden = [\"z:work\"]");
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash =
        base_manifest_toml(&hash.to_string()).replace("forbidden = []", "forbidden = [\"z:work\"]");
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    assert!(matches!(err, ManifestError::Invalid { field, .. } if field == "zones.forbidden"));
}

#[test]
fn rejects_invalid_zone_id() {
    let _log = TestLog::new("rejects_invalid_zone_id", "fcp-manifest", None, None, None);
    // Zone IDs must start with z:
    let toml = base_manifest_toml(PLACEHOLDER_HASH).replace("z:work", "invalid_zone");
    let err = ConnectorManifest::parse_str(&toml).unwrap_err();
    assert!(matches!(
        err,
        ManifestError::Toml(_) | ManifestError::ZoneId(_)
    ));
}

// =============================================================================
// Sandbox Validation Tests
// =============================================================================

#[test]
fn accepts_minimal_memory_mb() {
    let _log = TestLog::new(
        "accepts_minimal_memory_mb",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    // Note: memory_mb = 0 is currently allowed by validation (no minimum check)
    let toml = base_manifest_toml(PLACEHOLDER_HASH).replace("memory_mb = 64", "memory_mb = 1");
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash =
        base_manifest_toml(&hash.to_string()).replace("memory_mb = 64", "memory_mb = 1");
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid manifest");
    assert_eq!(parsed.sandbox.memory_mb, 1);
}

#[test]
fn rejects_zero_wall_clock_timeout() {
    let _log = TestLog::new(
        "rejects_zero_wall_clock_timeout",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH)
        .replace("wall_clock_timeout_ms = 1000", "wall_clock_timeout_ms = 0");
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash = base_manifest_toml(&hash.to_string())
        .replace("wall_clock_timeout_ms = 1000", "wall_clock_timeout_ms = 0");
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    assert!(
        matches!(err, ManifestError::Invalid { field, .. } if field == "sandbox.wall_clock_timeout_ms")
    );
}

#[test]
fn accepts_high_cpu_percent() {
    let _log = TestLog::new(
        "accepts_high_cpu_percent",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    // Note: cpu_percent is u8, values > 100 are allowed (no upper bound validation)
    let toml =
        base_manifest_toml(PLACEHOLDER_HASH).replace("cpu_percent = 20", "cpu_percent = 100");
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash =
        base_manifest_toml(&hash.to_string()).replace("cpu_percent = 20", "cpu_percent = 100");
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid manifest");
    assert_eq!(parsed.sandbox.cpu_percent, 100);
}

// =============================================================================
// Supply Chain Metadata Tests
// =============================================================================

#[test]
fn supply_chain_with_valid_attestations() {
    let _log = TestLog::new(
        "supply_chain_with_valid_attestations",
        "fcp-manifest",
        Some("fcp.valid"),
        Some("1.2.3"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_valid.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed =
        ConnectorManifest::parse_str(&with_hash).expect("valid manifest with supply chain");

    let supply_chain = parsed.supply_chain.expect("supply_chain present");
    assert_eq!(supply_chain.attestations.len(), 2);

    let types: Vec<_> = supply_chain
        .attestations
        .iter()
        .map(|a| &a.attestation_type)
        .collect();
    assert!(
        types
            .iter()
            .any(|t| matches!(t, fcp_manifest::AttestationType::InToto))
    );
    assert!(
        types
            .iter()
            .any(|t| matches!(t, fcp_manifest::AttestationType::ReproducibleBuild))
    );
}

#[test]
fn policy_validates_trusted_builders() {
    let _log = TestLog::new(
        "policy_validates_trusted_builders",
        "fcp-manifest",
        Some("fcp.valid"),
        Some("1.2.3"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_valid.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid manifest");

    let policy = parsed.policy.expect("policy present");
    assert!(
        policy
            .trusted_builders
            .contains(&"github-actions".to_string())
    );
    assert!(policy.trusted_builders.contains(&"internal-ci".to_string()));
    assert_eq!(policy.min_slsa_level, Some(2));
}

#[test]
fn policy_require_transparency_log() {
    let _log = TestLog::new(
        "policy_require_transparency_log",
        "fcp-manifest",
        Some("fcp.valid"),
        Some("1.2.3"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_valid.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid manifest");

    let policy = parsed.policy.expect("policy present");
    assert!(policy.require_transparency_log);

    let signatures = parsed.signatures.expect("signatures present");
    assert!(signatures.transparency_log_entry.is_some());
}

#[test]
fn rejects_slsa_level_too_high() {
    let _log = TestLog::new(
        "rejects_slsa_level_too_high",
        "fcp-manifest",
        Some("fcp.valid"),
        Some("1.2.3"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_valid.toml");
    // SLSA levels are 0-4
    let with_hash = with_computed_hash(&raw).replace("min_slsa_level = 2", "min_slsa_level = 5");
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    assert!(
        matches!(err, ManifestError::Invalid { field, .. } if field == "policy.min_slsa_level")
    );
}

// =============================================================================
// Signatures Section Tests
// =============================================================================

#[test]
fn signatures_with_valid_threshold() {
    let _log = TestLog::new(
        "signatures_with_valid_threshold",
        "fcp-manifest",
        Some("fcp.valid"),
        Some("1.2.3"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_valid.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid manifest");

    let signatures = parsed.signatures.expect("signatures present");
    assert_eq!(signatures.publisher_signatures.len(), 2);
    assert!(signatures.registry_signature.is_some());
}

#[test]
fn rejects_threshold_exceeding_signatures() {
    let _log = TestLog::new(
        "rejects_threshold_exceeding_signatures",
        "fcp-manifest",
        Some("fcp.valid"),
        Some("1.2.3"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_valid.toml");
    // 5-of-2 is invalid (required > total)
    let with_hash = with_computed_hash(&raw).replace("2-of-2", "5-of-2");
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    assert!(
        matches!(err, ManifestError::Invalid { field, .. } if field == "signatures.publisher_threshold")
    );
}

// =============================================================================
// Network Constraints Tests
// =============================================================================

#[test]
fn network_constraints_with_cidr_deny() {
    let _log = TestLog::new(
        "network_constraints_with_cidr_deny",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH).replace(
        "output_schema = { type = \"object\" }",
        r#"output_schema = { type = "object" }
network_constraints = { host_allow = ["api.example.com"], port_allow = [443], require_sni = true, cidr_deny = ["10.0.0.0/8", "192.168.0.0/16"] }"#,
    );
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash = toml.replace(PLACEHOLDER_HASH, &hash.to_string());
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid manifest with cidr_deny");

    let op = parsed
        .provides
        .operations
        .get("test_op")
        .expect("test_op exists");
    let nc = op
        .network_constraints
        .as_ref()
        .expect("network_constraints present");
    assert_eq!(nc.cidr_deny.len(), 2);
}

#[test]
fn network_constraints_deny_private_ranges_default() {
    let _log = TestLog::new(
        "network_constraints_deny_private_ranges_default",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH).replace(
        "output_schema = { type = \"object\" }",
        r#"output_schema = { type = "object" }
network_constraints = { host_allow = ["api.example.com"], port_allow = [443], require_sni = true }"#,
    );
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash = toml.replace(PLACEHOLDER_HASH, &hash.to_string());
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid manifest");

    let op = parsed
        .provides
        .operations
        .get("test_op")
        .expect("test_op exists");
    let nc = op
        .network_constraints
        .as_ref()
        .expect("network_constraints present");
    // Default should be true for security
    assert!(nc.deny_private_ranges);
}

// =============================================================================
// Multiple Operations Tests
// =============================================================================

#[test]
fn multiple_operations_with_different_risk_levels() {
    let _log = TestLog::new(
        "multiple_operations_with_different_risk_levels",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(2),
    );
    let toml = format!(
        r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = []
max_datagram_bytes = 1200
interface_hash = "{PLACEHOLDER_HASH}"

[connector]
id = "fcp.multi"
name = "Multi Operation Connector"
version = "1.0.0"
description = "Connector with multiple operations"
archetypes = ["operational"]
format = "native"

[zones]
home = "z:work"
allowed_sources = ["z:work"]
allowed_targets = ["z:work"]
forbidden = []

[capabilities]
required = ["network.dns", "network.egress"]
optional = []
forbidden = ["system.exec"]

[provides.operations.read_data]
description = "Read data (low risk)"
capability = "data.read"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
input_schema = {{ type = "object" }}
output_schema = {{ type = "object" }}

[provides.operations.write_data]
description = "Write data (medium risk)"
capability = "data.write"
risk_level = "medium"
safety_tier = "risky"
requires_approval = "policy"
rate_limit = "10/min"
idempotency = "best_effort"
input_schema = {{ type = "object", required = ["data"] }}
output_schema = {{ type = "object" }}
network_constraints = {{ host_allow = ["api.example.com"], port_allow = [443], require_sni = true }}

[provides.operations.delete_data]
description = "Delete data (high risk)"
capability = "data.delete"
risk_level = "high"
safety_tier = "dangerous"
requires_approval = "interactive"
idempotency = "none"
input_schema = {{ type = "object", required = ["id"] }}
output_schema = {{ type = "object" }}

[sandbox]
profile = "strict"
memory_mb = 128
cpu_percent = 30
wall_clock_timeout_ms = 5000
fs_readonly_paths = ["/usr"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true
"#
    );

    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash = toml.replace(PLACEHOLDER_HASH, &hash.to_string());
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid multi-op manifest");

    assert_eq!(parsed.provides.operations.len(), 3);

    let read_op = parsed
        .provides
        .operations
        .get("read_data")
        .expect("read_data exists");
    assert_eq!(read_op.risk_level, fcp_core::RiskLevel::Low);

    let write_op = parsed
        .provides
        .operations
        .get("write_data")
        .expect("write_data exists");
    assert_eq!(write_op.risk_level, fcp_core::RiskLevel::Medium);
    assert!(write_op.rate_limit.is_some());

    let delete_op = parsed
        .provides
        .operations
        .get("delete_data")
        .expect("delete_data exists");
    assert_eq!(delete_op.risk_level, fcp_core::RiskLevel::High);
}

// =============================================================================
// Optional Fields Default Tests
// =============================================================================

#[test]
fn optional_event_caps_section_omitted() {
    let _log = TestLog::new(
        "optional_event_caps_section_omitted",
        "fcp-manifest",
        Some("fcp.minimal"),
        Some("0.1.0"),
        Some(1),
    );
    let raw = read_vector_manifest("manifest_minimal.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("minimal manifest");

    // event_caps is optional
    assert!(parsed.event_caps.is_none());
}

#[test]
fn optional_signatures_section_omitted() {
    let _log = TestLog::new(
        "optional_signatures_section_omitted",
        "fcp-manifest",
        Some("fcp.minimal"),
        Some("0.1.0"),
        Some(1),
    );
    let raw = read_vector_manifest("manifest_minimal.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("minimal manifest");

    // signatures is optional
    assert!(parsed.signatures.is_none());
}

#[test]
fn optional_supply_chain_section_omitted() {
    let _log = TestLog::new(
        "optional_supply_chain_section_omitted",
        "fcp-manifest",
        Some("fcp.minimal"),
        Some("0.1.0"),
        Some(1),
    );
    let raw = read_vector_manifest("manifest_minimal.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("minimal manifest");

    // supply_chain is optional
    assert!(parsed.supply_chain.is_none());
}

#[test]
fn optional_policy_section_omitted() {
    let _log = TestLog::new(
        "optional_policy_section_omitted",
        "fcp-manifest",
        Some("fcp.minimal"),
        Some("0.1.0"),
        Some(1),
    );
    let raw = read_vector_manifest("manifest_minimal.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("minimal manifest");

    // policy is optional
    assert!(parsed.policy.is_none());
}

// =============================================================================
// Interface Hash Tests
// =============================================================================

#[test]
fn interface_hash_is_deterministic() {
    let _log = TestLog::new(
        "interface_hash_is_deterministic",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH);
    let unchecked1 = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse 1");
    let hash1 = unchecked1.compute_interface_hash().expect("compute hash 1");

    let unchecked2 = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse 2");
    let hash2 = unchecked2.compute_interface_hash().expect("compute hash 2");

    assert_eq!(hash1, hash2, "interface hash must be deterministic");
}

#[test]
fn interface_hash_changes_with_connector_id() {
    let _log = TestLog::new(
        "interface_hash_changes_with_connector_id",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml1 = base_manifest_toml(PLACEHOLDER_HASH);
    let toml2 = base_manifest_toml(PLACEHOLDER_HASH).replace("fcp.test", "fcp.other");

    let unchecked1 = ConnectorManifest::parse_str_unchecked(&toml1).expect("unchecked parse 1");
    let hash1 = unchecked1.compute_interface_hash().expect("compute hash 1");

    let unchecked2 = ConnectorManifest::parse_str_unchecked(&toml2).expect("unchecked parse 2");
    let hash2 = unchecked2.compute_interface_hash().expect("compute hash 2");

    assert_ne!(hash1, hash2, "interface hash must change with connector_id");
}

#[test]
fn interface_hash_changes_with_operations() {
    let _log = TestLog::new(
        "interface_hash_changes_with_operations",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml1 = base_manifest_toml(PLACEHOLDER_HASH);
    let toml2 = base_manifest_toml(PLACEHOLDER_HASH).replace("test.op", "other.op");

    let unchecked1 = ConnectorManifest::parse_str_unchecked(&toml1).expect("unchecked parse 1");
    let hash1 = unchecked1.compute_interface_hash().expect("compute hash 1");

    let unchecked2 = ConnectorManifest::parse_str_unchecked(&toml2).expect("unchecked parse 2");
    let hash2 = unchecked2.compute_interface_hash().expect("compute hash 2");

    assert_ne!(hash1, hash2, "interface hash must change with operations");
}

#[test]
fn interface_hash_excludes_supply_chain() {
    let _log = TestLog::new(
        "interface_hash_excludes_supply_chain",
        "fcp-manifest",
        Some("fcp.valid"),
        Some("1.2.3"),
        Some(3),
    );
    // Interface hash should be the same regardless of supply chain metadata
    let raw = read_vector_manifest("manifest_valid.toml");
    let unchecked1 = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked parse");
    let hash1 = unchecked1.compute_interface_hash().expect("compute hash 1");

    // Remove supply_chain section
    let without_supply_chain = raw
        .lines()
        .take_while(|line| !line.starts_with("[supply_chain]"))
        .collect::<Vec<_>>()
        .join("\n");

    // Also remove policy section (after supply_chain)
    let minimal = without_supply_chain
        .lines()
        .take_while(|line| !line.starts_with("[policy]"))
        .collect::<Vec<_>>()
        .join("\n");

    let unchecked2 = ConnectorManifest::parse_str_unchecked(&minimal).expect("unchecked parse 2");
    let hash2 = unchecked2.compute_interface_hash().expect("compute hash 2");

    assert_eq!(
        hash1, hash2,
        "interface hash should exclude supply chain metadata"
    );
}

// =============================================================================
// Archetype Tests
// =============================================================================

#[test]
fn parses_all_valid_archetypes() {
    let _log = TestLog::new(
        "parses_all_valid_archetypes",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let archetypes = [
        "operational",
        "bidirectional",
        "streaming",
        "storage",
        "knowledge",
    ];

    for archetype in archetypes {
        let toml = base_manifest_toml(PLACEHOLDER_HASH).replace(
            "archetypes = [\"operational\"]",
            &format!("archetypes = [\"{archetype}\"]"),
        );
        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash = toml.replace(PLACEHOLDER_HASH, &hash.to_string());
        let parsed = ConnectorManifest::parse_str(&with_hash)
            .unwrap_or_else(|_| panic!("archetype {archetype} should be valid"));
        assert!(!parsed.connector.archetypes.is_empty());
    }
}

#[test]
fn rejects_invalid_archetype() {
    let _log = TestLog::new(
        "rejects_invalid_archetype",
        "fcp-manifest",
        None,
        None,
        None,
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH).replace(
        "archetypes = [\"operational\"]",
        "archetypes = [\"invalid_archetype\"]",
    );
    let err = ConnectorManifest::parse_str(&toml).unwrap_err();
    assert!(matches!(err, ManifestError::Toml(_)));
}

// =============================================================================
// State Model Tests
// =============================================================================

#[test]
fn parses_stateless_state_model() {
    let _log = TestLog::new(
        "parses_stateless_state_model",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH);
    // Default base manifest has no state section, which means stateless
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash = toml.replace(PLACEHOLDER_HASH, &hash.to_string());
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid manifest");
    assert!(parsed.connector.state.is_none());
}

#[test]
fn parses_singleton_writer_state_model() {
    let _log = TestLog::new(
        "parses_singleton_writer_state_model",
        "fcp-manifest",
        Some("fcp.valid"),
        Some("1.2.3"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_valid.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid manifest");

    let state = parsed.connector.state.expect("state section present");
    let model = state.to_state_model().expect("valid state model");
    assert!(matches!(
        model,
        fcp_manifest::ConnectorStateModel::SingletonWriter
    ));
}

// =============================================================================
// Rate Limit Validation Tests
// =============================================================================

#[test]
fn accepts_valid_rate_limit_shorthand() {
    let _log = TestLog::new(
        "accepts_valid_rate_limit_shorthand",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH).replace(
        "idempotency = \"none\"",
        "rate_limit = \"60/min\"\nidempotency = \"none\"",
    );
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash = toml.replace(PLACEHOLDER_HASH, &hash.to_string());
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid manifest with rate limit");

    let op = parsed
        .provides
        .operations
        .get("test_op")
        .expect("test_op exists");
    let rate = op.rate_limit.as_ref().expect("rate_limit present");
    assert_eq!(rate.as_inner().max, 60);
    assert_eq!(rate.as_inner().per_ms, 60_000);
}

#[test]
fn accepts_valid_rate_limit_structured() {
    let _log = TestLog::new(
        "accepts_valid_rate_limit_structured",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH).replace(
        "idempotency = \"none\"",
        r#"rate_limit = { max = 100, per_ms = 60000, burst = 10, scope = "per_zone" }
idempotency = "none""#,
    );
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash = toml.replace(PLACEHOLDER_HASH, &hash.to_string());
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid manifest");

    let op = parsed
        .provides
        .operations
        .get("test_op")
        .expect("test_op exists");
    let rate = op.rate_limit.as_ref().expect("rate_limit present");
    assert_eq!(rate.as_inner().max, 100);
    assert_eq!(rate.as_inner().per_ms, 60_000);
    assert_eq!(rate.as_inner().burst, Some(10));
    assert_eq!(rate.as_inner().scope.as_deref(), Some("per_zone"));
}

#[test]
fn accepts_rate_limit_with_pool_name() {
    let _log = TestLog::new(
        "accepts_rate_limit_with_pool_name",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH).replace(
        "idempotency = \"none\"",
        r#"rate_limit = { max = 10, per_ms = 1000, pool_name = "api.global" }
idempotency = "none""#,
    );
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash = toml.replace(PLACEHOLDER_HASH, &hash.to_string());
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid manifest");

    let op = parsed
        .provides
        .operations
        .get("test_op")
        .expect("test_op exists");
    let rate = op.rate_limit.as_ref().expect("rate_limit present");
    assert_eq!(rate.as_inner().pool_name.as_deref(), Some("api.global"));
}

#[test]
fn rejects_rate_limit_zero_max() {
    let _log = TestLog::new(
        "rejects_rate_limit_zero_max",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH).replace(
        "idempotency = \"none\"",
        r#"rate_limit = { max = 0, per_ms = 60000 }
idempotency = "none""#,
    );
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash = toml.replace(PLACEHOLDER_HASH, &hash.to_string());
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    assert!(matches!(err, ManifestError::RateLimit(_)));
    assert!(err.to_string().contains("max"));
}

#[test]
fn rejects_rate_limit_zero_period() {
    let _log = TestLog::new(
        "rejects_rate_limit_zero_period",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH).replace(
        "idempotency = \"none\"",
        r#"rate_limit = { max = 60, per_ms = 0 }
idempotency = "none""#,
    );
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash = toml.replace(PLACEHOLDER_HASH, &hash.to_string());
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    assert!(matches!(err, ManifestError::RateLimit(_)));
    assert!(err.to_string().contains("per_ms"));
}

#[test]
fn rejects_rate_limit_invalid_scope() {
    let _log = TestLog::new(
        "rejects_rate_limit_invalid_scope",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH).replace(
        "idempotency = \"none\"",
        r#"rate_limit = { max = 60, per_ms = 60000, scope = "invalid_scope" }
idempotency = "none""#,
    );
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash = toml.replace(PLACEHOLDER_HASH, &hash.to_string());
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    assert!(matches!(err, ManifestError::RateLimit(_)));
    assert!(err.to_string().contains("scope"));
}

#[test]
fn rejects_rate_limit_empty_pool_name() {
    let _log = TestLog::new(
        "rejects_rate_limit_empty_pool_name",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH).replace(
        "idempotency = \"none\"",
        r#"rate_limit = { max = 60, per_ms = 60000, pool_name = "" }
idempotency = "none""#,
    );
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash = toml.replace(PLACEHOLDER_HASH, &hash.to_string());
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    assert!(matches!(err, ManifestError::RateLimit(_)));
    assert!(err.to_string().contains("pool_name"));
}

#[test]
fn rejects_rate_limit_invalid_pool_name() {
    let _log = TestLog::new(
        "rejects_rate_limit_invalid_pool_name",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH).replace(
        "idempotency = \"none\"",
        r#"rate_limit = { max = 60, per_ms = 60000, pool_name = "pool with spaces!" }
idempotency = "none""#,
    );
    let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
    let hash = unchecked.compute_interface_hash().expect("compute hash");
    let with_hash = toml.replace(PLACEHOLDER_HASH, &hash.to_string());
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    assert!(matches!(err, ManifestError::RateLimit(_)));
    assert!(err.to_string().contains("pool_name"));
}

#[test]
fn accepts_all_valid_rate_limit_scopes() {
    let _log = TestLog::new(
        "accepts_all_valid_rate_limit_scopes",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    for scope in ["per_connector", "per_zone", "per_principal"] {
        let toml = base_manifest_toml(PLACEHOLDER_HASH).replace(
            "idempotency = \"none\"",
            &format!(
                r#"rate_limit = {{ max = 60, per_ms = 60000, scope = "{scope}" }}
idempotency = "none""#
            ),
        );
        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash = toml.replace(PLACEHOLDER_HASH, &hash.to_string());
        let parsed = ConnectorManifest::parse_str(&with_hash)
            .unwrap_or_else(|_| panic!("scope {scope} should be valid"));

        let op = parsed
            .provides
            .operations
            .get("test_op")
            .expect("test_op exists");
        let rate = op.rate_limit.as_ref().expect("rate_limit present");
        assert_eq!(rate.as_inner().scope.as_deref(), Some(scope));
    }
}

#[test]
fn accepts_rate_limit_shorthand_units() {
    let _log = TestLog::new(
        "accepts_rate_limit_shorthand_units",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let test_cases = [
        ("10/sec", 10, 1_000),
        ("10/s", 10, 1_000),
        ("60/min", 60, 60_000),
        ("60/m", 60, 60_000),
        ("100/hour", 100, 3_600_000),
        ("100/h", 100, 3_600_000),
        ("1000/day", 1000, 86_400_000),
        ("1000/d", 1000, 86_400_000),
    ];

    for (shorthand, expected_max, expected_per_ms) in test_cases {
        let toml = base_manifest_toml(PLACEHOLDER_HASH).replace(
            "idempotency = \"none\"",
            &format!(
                r#"rate_limit = "{shorthand}"
idempotency = "none""#
            ),
        );
        let unchecked = ConnectorManifest::parse_str_unchecked(&toml).expect("unchecked parse");
        let hash = unchecked.compute_interface_hash().expect("compute hash");
        let with_hash = toml.replace(PLACEHOLDER_HASH, &hash.to_string());
        let parsed = ConnectorManifest::parse_str(&with_hash)
            .unwrap_or_else(|_| panic!("shorthand {shorthand} should be valid"));

        let op = parsed
            .provides
            .operations
            .get("test_op")
            .expect("test_op exists");
        let rate = op.rate_limit.as_ref().expect("rate_limit present");
        assert_eq!(rate.as_inner().max, expected_max, "shorthand: {shorthand}");
        assert_eq!(
            rate.as_inner().per_ms,
            expected_per_ms,
            "shorthand: {shorthand}"
        );
    }
}

#[test]
fn rejects_invalid_rate_limit_shorthand() {
    let _log = TestLog::new(
        "rejects_invalid_rate_limit_shorthand",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let invalid_cases = [
        "invalid", // no slash
        "60/week", // invalid unit
        "abc/min", // non-numeric max
        "/min",    // missing max
        "60/",     // missing unit
    ];

    for shorthand in invalid_cases {
        let toml = base_manifest_toml(PLACEHOLDER_HASH).replace(
            "idempotency = \"none\"",
            &format!(
                r#"rate_limit = "{shorthand}"
idempotency = "none""#
            ),
        );
        let err = ConnectorManifest::parse_str(&toml).unwrap_err();
        assert!(
            matches!(err, ManifestError::Toml(_)),
            "shorthand {shorthand} should fail: got {err}"
        );
    }
}

// =============================================================================
// Rate Limit Declarations Tests (bd-zxfr)
// =============================================================================

#[test]
fn accepts_valid_rate_limits_section() {
    let _log = TestLog::new(
        "accepts_valid_rate_limits_section",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH)
        + r#"
[rate_limits]
[[rate_limits.pools]]
id = "api_global"
description = "Global API rate limit"
requests = 100
window_ms = 60000
burst = 10
unit = "requests"
enforcement = "hard"
scope = "credential"

[[rate_limits.pools]]
id = "token_budget"
description = "Token usage limit"
requests = 10000
window_ms = 3600000
unit = "tokens"
enforcement = "soft"
scope = "instance"

[rate_limits.operation_pools]
test_op = ["api_global", "token_budget"]
"#;
    let toml = with_computed_hash(&toml);
    let manifest = ConnectorManifest::parse_str(&toml).expect("should parse valid rate_limits");
    let rate_limits = manifest.rate_limits.expect("rate_limits should be present");
    assert_eq!(rate_limits.pools.len(), 2);
    assert_eq!(rate_limits.pools[0].id, "api_global");
    assert_eq!(rate_limits.pools[1].id, "token_budget");
    assert_eq!(rate_limits.operation_pools.get("test_op").unwrap().len(), 2);
}

#[test]
fn accepts_minimal_rate_limits_section() {
    let _log = TestLog::new(
        "accepts_minimal_rate_limits_section",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH)
        + r#"
[rate_limits]
[[rate_limits.pools]]
id = "api"
requests = 60
window_ms = 60000

[rate_limits.operation_pools]
test_op = ["api"]
"#;
    let toml = with_computed_hash(&toml);
    let manifest = ConnectorManifest::parse_str(&toml).expect("should parse minimal rate_limits");
    let rate_limits = manifest.rate_limits.expect("rate_limits should be present");
    assert_eq!(rate_limits.pools.len(), 1);
    assert_eq!(rate_limits.pools[0].requests, 60);
    assert!(rate_limits.pools[0].burst.is_none());
}

#[test]
fn rejects_rate_limits_zero_requests() {
    let _log = TestLog::new(
        "rejects_rate_limits_zero_requests",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH)
        + r#"
[rate_limits]
[[rate_limits.pools]]
id = "bad_pool"
requests = 0
window_ms = 60000

[rate_limits.operation_pools]
test_op = ["bad_pool"]
"#;
    let toml = with_computed_hash(&toml);
    let err = ConnectorManifest::parse_str(&toml).unwrap_err();
    assert!(
        matches!(err, ManifestError::RateLimitDeclaration(_)),
        "should reject zero requests: got {err}"
    );
}

#[test]
fn rejects_rate_limits_zero_window() {
    let _log = TestLog::new(
        "rejects_rate_limits_zero_window",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH)
        + r#"
[rate_limits]
[[rate_limits.pools]]
id = "bad_pool"
requests = 100
window_ms = 0

[rate_limits.operation_pools]
test_op = ["bad_pool"]
"#;
    let toml = with_computed_hash(&toml);
    let err = ConnectorManifest::parse_str(&toml).unwrap_err();
    assert!(
        matches!(err, ManifestError::RateLimitDeclaration(_)),
        "should reject zero window: got {err}"
    );
}

#[test]
fn rejects_rate_limits_empty_pool_id() {
    let _log = TestLog::new(
        "rejects_rate_limits_empty_pool_id",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH)
        + r#"
[rate_limits]
[[rate_limits.pools]]
id = ""
requests = 100
window_ms = 60000

[rate_limits.operation_pools]
test_op = [""]
"#;
    let toml = with_computed_hash(&toml);
    let err = ConnectorManifest::parse_str(&toml).unwrap_err();
    assert!(
        matches!(err, ManifestError::RateLimitDeclaration(_)),
        "should reject empty pool id: got {err}"
    );
}

#[test]
fn rejects_rate_limits_duplicate_pool_ids() {
    let _log = TestLog::new(
        "rejects_rate_limits_duplicate_pool_ids",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH)
        + r#"
[rate_limits]
[[rate_limits.pools]]
id = "duplicate"
requests = 100
window_ms = 60000

[[rate_limits.pools]]
id = "duplicate"
requests = 200
window_ms = 60000

[rate_limits.operation_pools]
test_op = ["duplicate"]
"#;
    let toml = with_computed_hash(&toml);
    let err = ConnectorManifest::parse_str(&toml).unwrap_err();
    assert!(
        matches!(err, ManifestError::RateLimitDeclaration(_)),
        "should reject duplicate pool ids: got {err}"
    );
}

#[test]
fn rejects_rate_limits_unknown_pool_reference() {
    let _log = TestLog::new(
        "rejects_rate_limits_unknown_pool_reference",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH)
        + r#"
[rate_limits]
[[rate_limits.pools]]
id = "existing_pool"
requests = 100
window_ms = 60000

[rate_limits.operation_pools]
test_op = ["nonexistent_pool"]
"#;
    let toml = with_computed_hash(&toml);
    let err = ConnectorManifest::parse_str(&toml).unwrap_err();
    assert!(
        matches!(err, ManifestError::RateLimitDeclaration(_)),
        "should reject unknown pool reference: got {err}"
    );
}

#[test]
fn accepts_rate_limits_all_enforcement_levels() {
    let _log = TestLog::new(
        "accepts_rate_limits_all_enforcement_levels",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    for enforcement in ["hard", "soft", "advisory"] {
        let toml = base_manifest_toml(PLACEHOLDER_HASH)
            + &format!(
                r#"
[rate_limits]
[[rate_limits.pools]]
id = "pool"
requests = 100
window_ms = 60000
enforcement = "{enforcement}"

[rate_limits.operation_pools]
test_op = ["pool"]
"#
            );
        let toml = with_computed_hash(&toml);
        let manifest = ConnectorManifest::parse_str(&toml)
            .unwrap_or_else(|e| panic!("enforcement={enforcement} should parse: {e}"));
        let rate_limits = manifest.rate_limits.expect("rate_limits should be present");
        assert_eq!(
            rate_limits.pools[0].enforcement.as_deref(),
            Some(enforcement)
        );
    }
}

#[test]
fn accepts_rate_limits_all_scopes() {
    let _log = TestLog::new(
        "accepts_rate_limits_all_scopes",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    for scope in ["instance", "credential", "global"] {
        let toml = base_manifest_toml(PLACEHOLDER_HASH)
            + &format!(
                r#"
[rate_limits]
[[rate_limits.pools]]
id = "pool"
requests = 100
window_ms = 60000
scope = "{scope}"

[rate_limits.operation_pools]
test_op = ["pool"]
"#
            );
        let toml = with_computed_hash(&toml);
        let manifest = ConnectorManifest::parse_str(&toml)
            .unwrap_or_else(|e| panic!("scope={scope} should parse: {e}"));
        let rate_limits = manifest.rate_limits.expect("rate_limits should be present");
        assert_eq!(rate_limits.pools[0].scope.as_deref(), Some(scope));
    }
}

#[test]
fn accepts_rate_limits_all_units() {
    let _log = TestLog::new(
        "accepts_rate_limits_all_units",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    for unit in ["requests", "tokens", "bytes", "custom"] {
        let toml = base_manifest_toml(PLACEHOLDER_HASH)
            + &format!(
                r#"
[rate_limits]
[[rate_limits.pools]]
id = "pool"
requests = 100
window_ms = 60000
unit = "{unit}"

[rate_limits.operation_pools]
test_op = ["pool"]
"#
            );
        let toml = with_computed_hash(&toml);
        let manifest = ConnectorManifest::parse_str(&toml)
            .unwrap_or_else(|e| panic!("unit={unit} should parse: {e}"));
        let rate_limits = manifest.rate_limits.expect("rate_limits should be present");
        assert_eq!(rate_limits.pools[0].unit.as_deref(), Some(unit));
    }
}

#[test]
fn rate_limits_to_declarations_conversion() {
    let _log = TestLog::new(
        "rate_limits_to_declarations_conversion",
        "fcp-manifest",
        Some("fcp.test"),
        Some("1.0.0"),
        Some(1),
    );
    let toml = base_manifest_toml(PLACEHOLDER_HASH)
        + r#"
[rate_limits]
[[rate_limits.pools]]
id = "api"
description = "API limit"
requests = 100
window_ms = 60000
burst = 20
unit = "requests"
enforcement = "hard"
scope = "credential"

[rate_limits.operation_pools]
test_op = ["api"]
"#;
    let toml = with_computed_hash(&toml);
    let manifest = ConnectorManifest::parse_str(&toml).expect("should parse");
    let rate_limits = manifest.rate_limits.expect("rate_limits present");
    let decls = rate_limits.to_declarations();

    assert_eq!(decls.limits.len(), 1);
    let pool = &decls.limits[0];
    assert_eq!(pool.id, "api");
    assert_eq!(pool.description, "API limit");
    assert_eq!(pool.config.requests, 100);
    assert_eq!(pool.config.window.as_millis(), 60000);
    assert_eq!(pool.config.burst, Some(20));
    assert_eq!(pool.config.unit, fcp_core::RateLimitUnit::Requests);
    assert_eq!(pool.enforcement, fcp_core::RateLimitEnforcement::Hard);
    assert_eq!(pool.scope, fcp_core::RateLimitScope::Credential);

    assert!(decls.tool_pool_map.contains_key("test_op"));
    assert_eq!(
        decls.tool_pool_map.get("test_op").unwrap(),
        &vec!["api".to_string()]
    );
}
