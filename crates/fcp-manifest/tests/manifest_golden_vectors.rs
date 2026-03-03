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

#[test]
fn anthropic_good_manifest_vector_parses_and_maps_capabilities() {
    let _log = TestLog::new(
        "anthropic_good_manifest_vector_parses_and_maps_capabilities",
        "fcp-manifest",
        Some("fcp.anthropic"),
        Some("0.1.0"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_anthropic_good.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid anthropic manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.anthropic");
    let message_op = parsed
        .provides
        .operations
        .get("anthropic.message")
        .expect("anthropic.message operation");
    let chat_op = parsed
        .provides
        .operations
        .get("anthropic.chat")
        .expect("anthropic.chat operation");
    let usage_op = parsed
        .provides
        .operations
        .get("anthropic.get_usage")
        .expect("anthropic.get_usage operation");

    assert_eq!(message_op.capability.as_str(), "anthropic.message");
    assert_eq!(chat_op.capability.as_str(), "anthropic.chat");
    assert_eq!(usage_op.capability.as_str(), "anthropic.get_usage");
}

#[test]
fn anthropic_bad_manifest_vector_is_rejected() {
    let _log = TestLog::new(
        "anthropic_bad_manifest_vector_is_rejected",
        "fcp-manifest",
        Some("fcp.anthropic"),
        Some("0.1.0"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_anthropic_bad.toml");
    let with_hash = with_computed_hash(&raw);
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    assert!(matches!(err, ManifestError::Invalid { .. }));
    assert!(
        err.to_string().contains("capabilities"),
        "expected capability validation failure, got: {err}"
    );
}

// =============================================================================
// Jira Connector Vector Tests
// =============================================================================

#[test]
fn jira_good_manifest_vector_parses_and_maps_capabilities() {
    let _log = TestLog::new(
        "jira_good_manifest_vector_parses_and_maps_capabilities",
        "fcp-manifest",
        Some("fcp.jira"),
        Some("0.1.0"),
        Some(4),
    );
    let raw = read_vector_manifest("manifest_jira_good.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid jira manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.jira");
    assert_eq!(parsed.connector.archetypes.len(), 2);
    assert_eq!(parsed.connector.archetypes[0].as_str(), "operational");
    assert_eq!(parsed.connector.archetypes[1].as_str(), "streaming");

    // Verify singleton_writer state model
    let state = parsed.connector.state.as_ref().expect("state section");
    let model = state.to_state_model().expect("valid state model");
    assert!(matches!(
        model,
        fcp_manifest::ConnectorStateModel::SingletonWriter
    ));

    // Verify operations
    let create_op = parsed
        .provides
        .operations
        .get("jira.create_issue")
        .expect("jira.create_issue operation");
    assert_eq!(create_op.capability.as_str(), "jira.write");

    let search_op = parsed
        .provides
        .operations
        .get("jira.search_jql")
        .expect("jira.search_jql operation");
    assert_eq!(search_op.capability.as_str(), "jira.read");

    // Verify network constraints use wildcard host
    let nc = create_op
        .network_constraints
        .as_ref()
        .expect("network_constraints");
    assert!(nc.host_allow.iter().any(|h| h == "*.atlassian.net"));
    assert!(nc.port_allow.contains(&443));
    assert!(nc.require_sni);

    // Verify rate limit pools
    let pools = parsed.rate_limits.as_ref().expect("rate_limits section");
    assert!(pools.pools.iter().any(|p| p.id == "jira.read"));
    assert!(pools.pools.iter().any(|p| p.id == "jira.write"));

    // Verify event_caps
    let events = parsed.event_caps.as_ref().expect("event_caps section");
    assert!(events.streaming);
    assert!(!events.replay);
    assert_eq!(events.min_buffer_events, 50);

    // Verify required capabilities
    assert!(
        parsed
            .capabilities
            .required
            .iter()
            .any(|c| c.as_str() == "storage.state")
    );
}

#[test]
fn jira_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "jira_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.jira"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/jira/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read jira manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full jira manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.jira");

    // Verify all 12 operations present
    let ops = &parsed.provides.operations;
    let expected_ops = [
        "jira.create_issue",
        "jira.get_issue",
        "jira.update_issue",
        "jira.delete_issue",
        "jira.search_jql",
        "jira.list_transitions",
        "jira.transition_issue",
        "jira.list_sprints",
        "jira.move_to_sprint",
        "jira.add_comment",
        "jira.list_comments",
        "jira.add_attachment",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    // Print the computed interface hash for updating the manifest
    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("JIRA_INTERFACE_HASH={hash}");

    // Verify rate limit pool mapping covers all operations
    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 4); // read, write, delete, attachment
    let pool_map = &pools.operation_pools;
    for op_name in &expected_ops {
        assert!(
            pool_map.contains_key(*op_name),
            "missing rate limit pool mapping for: {op_name}"
        );
    }
}

#[test]
fn jira_bad_manifest_vector_is_rejected() {
    let _log = TestLog::new(
        "jira_bad_manifest_vector_is_rejected",
        "fcp-manifest",
        Some("fcp.jira"),
        Some("0.1.0"),
        Some(4),
    );
    let raw = read_vector_manifest("manifest_jira_bad.toml");
    let with_hash = with_computed_hash(&raw);
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    // Should fail on one of: capability duplication, zone conflict, or addressing in cap ID
    let msg = err.to_string();
    assert!(
        msg.contains("capabilities") || msg.contains("zone") || msg.contains("forbidden"),
        "expected validation failure on capabilities or zones, got: {msg}"
    );
}

// =============================================================================
// Figma Connector Vector Tests
// =============================================================================

#[test]
fn figma_good_manifest_vector_parses_and_maps_capabilities() {
    let _log = TestLog::new(
        "figma_good_manifest_vector_parses_and_maps_capabilities",
        "fcp-manifest",
        Some("fcp.figma"),
        Some("0.1.0"),
        Some(4),
    );
    let raw = read_vector_manifest("manifest_figma_good.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid figma manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.figma");
    assert_eq!(parsed.connector.archetypes.len(), 3);
    assert_eq!(parsed.connector.archetypes[0].as_str(), "knowledge");
    assert_eq!(parsed.connector.archetypes[1].as_str(), "operational");
    assert_eq!(parsed.connector.archetypes[2].as_str(), "streaming");

    let get_file = parsed
        .provides
        .operations
        .get("figma.get_file")
        .expect("figma.get_file operation");
    assert_eq!(get_file.capability.as_str(), "figma.read");

    let export = parsed
        .provides
        .operations
        .get("figma.export_images")
        .expect("figma.export_images operation");
    // Verify CDN hosts in export constraints
    let nc = export
        .network_constraints
        .as_ref()
        .expect("network_constraints");
    assert!(nc.host_allow.iter().any(|h| h == "api.figma.com"));
    assert!(
        nc.host_allow
            .iter()
            .any(|h| h.contains("s3.us-west-2.amazonaws.com"))
    );
    assert!(nc.host_allow.iter().any(|h| h == "*.figma.com"));
    // Export has 100MB response limit
    assert_eq!(nc.max_response_bytes, 104_857_600);
}

#[test]
fn figma_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "figma_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.figma"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/figma/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read figma manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full figma manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.figma");

    // Verify all 17 operations present
    let ops = &parsed.provides.operations;
    let expected_ops = [
        "figma.list_team_projects",
        "figma.list_project_files",
        "figma.get_file_meta",
        "figma.get_file",
        "figma.get_file_nodes",
        "figma.get_file_components",
        "figma.get_file_styles",
        "figma.styles.list",
        "figma.tokens.export",
        "figma.export_images",
        "figma.list_file_versions",
        "figma.list_comments",
        "figma.post_comment",
        "figma.delete_comment",
        "figma.create_webhook",
        "figma.list_webhooks",
        "figma.delete_webhook",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    // Print the computed interface hash for updating the manifest
    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("FIGMA_INTERFACE_HASH={hash}");

    // Verify 5 rate limit pools
    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 5);

    // Verify pool mapping for all ops
    let pool_map = &pools.operation_pools;
    for op_name in &expected_ops {
        assert!(
            pool_map.contains_key(*op_name),
            "missing rate limit pool mapping for: {op_name}"
        );
    }
}

#[test]
fn figma_bad_manifest_vector_is_rejected() {
    let _log = TestLog::new(
        "figma_bad_manifest_vector_is_rejected",
        "fcp-manifest",
        Some("fcp.figma"),
        Some("0.1.0"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_figma_bad.toml");
    let with_hash = with_computed_hash(&raw);
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("capabilities") || msg.contains("zone") || msg.contains("forbidden"),
        "expected validation failure on capabilities or zones, got: {msg}"
    );
}

// =============================================================================
// Twilio Connector Vector Tests
// =============================================================================

#[test]
fn twilio_good_manifest_vector_parses_and_maps_capabilities() {
    let _log = TestLog::new(
        "twilio_good_manifest_vector_parses_and_maps_capabilities",
        "fcp-manifest",
        Some("fcp.twilio"),
        Some("0.1.0"),
        Some(4),
    );
    let raw = read_vector_manifest("manifest_twilio_good.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid twilio manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.twilio");
    assert_eq!(parsed.connector.archetypes.len(), 3);
    assert_eq!(parsed.connector.archetypes[0].as_str(), "operational");
    assert_eq!(parsed.connector.archetypes[1].as_str(), "streaming");
    assert_eq!(parsed.connector.archetypes[2].as_str(), "bidirectional");

    let send_op = parsed
        .provides
        .operations
        .get("twilio.send_message")
        .expect("twilio.send_message operation");
    assert_eq!(send_op.capability.as_str(), "twilio.message");
    // send_message has max_redirects=0 (deny redirects)
    let nc = send_op.network_constraints.as_ref().expect("nc");
    assert_eq!(nc.max_redirects, 0);
}

#[test]
fn twilio_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "twilio_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.twilio"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/twilio/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read twilio manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full twilio manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.twilio");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "twilio.send_message",
        "twilio.get_message",
        "twilio.list_messages",
        "twilio.create_call",
        "twilio.get_call",
        "twilio.list_recordings",
        "twilio.download_recording",
        "twilio.download_media",
        "twilio.get_account",
        "twilio.list_phone_numbers",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    // Print computed hash
    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("TWILIO_INTERFACE_HASH={hash}");

    // Verify media CDN host in download operations
    let dl_rec = ops
        .get("twilio.download_recording")
        .expect("download_recording");
    let nc = dl_rec.network_constraints.as_ref().expect("nc");
    assert!(nc.host_allow.iter().any(|h| h == "media.twiliocdn.com"));

    // Verify 4 rate limit pools
    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 4);
}

#[test]
fn twilio_bad_manifest_vector_is_rejected() {
    let _log = TestLog::new(
        "twilio_bad_manifest_vector_is_rejected",
        "fcp-manifest",
        Some("fcp.twilio"),
        Some("0.1.0"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_twilio_bad.toml");
    let with_hash = with_computed_hash(&raw);
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("capabilities") || msg.contains("zone") || msg.contains("forbidden"),
        "expected validation failure, got: {msg}"
    );
}

// =============================================================================
// Zendesk Connector Vector Tests
// =============================================================================

#[test]
fn zendesk_good_manifest_vector_parses_and_maps_capabilities() {
    let _log = TestLog::new(
        "zendesk_good_manifest_vector_parses_and_maps_capabilities",
        "fcp-manifest",
        Some("fcp.zendesk"),
        Some("0.1.0"),
        Some(4),
    );
    let raw = read_vector_manifest("manifest_zendesk_good.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid zendesk manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.zendesk");
    assert_eq!(parsed.connector.archetypes.len(), 3);
    assert_eq!(parsed.connector.archetypes[2].as_str(), "knowledge");

    let create_op = parsed
        .provides
        .operations
        .get("zendesk.create_ticket")
        .expect("zendesk.create_ticket");
    assert_eq!(create_op.capability.as_str(), "zendesk.write");
}

#[test]
fn zendesk_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "zendesk_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.zendesk"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/zendesk/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read zendesk manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full zendesk manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.zendesk");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "zendesk.create_ticket",
        "zendesk.get_ticket",
        "zendesk.update_ticket",
        "zendesk.delete_ticket",
        "zendesk.search_tickets",
        "zendesk.list_ticket_comments",
        "zendesk.search_articles",
        "zendesk.get_article",
        "zendesk.search_users",
        "zendesk.apply_macro",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("ZENDESK_INTERFACE_HASH={hash}");

    // Verify 4 rate limit pools
    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 4);
}

#[test]
fn zendesk_bad_manifest_vector_is_rejected() {
    let _log = TestLog::new(
        "zendesk_bad_manifest_vector_is_rejected",
        "fcp-manifest",
        Some("fcp.zendesk"),
        Some("0.1.0"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_zendesk_bad.toml");
    let with_hash = with_computed_hash(&raw);
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("capabilities") || msg.contains("zone") || msg.contains("forbidden"),
        "expected validation failure, got: {msg}"
    );
}

// =============================================================================
// GitHub connector tests
// =============================================================================

#[test]
fn github_good_manifest_vector_parses_and_maps_capabilities() {
    let _log = TestLog::new(
        "github_good_manifest_vector_parses_and_maps_capabilities",
        "fcp-manifest",
        Some("fcp.github"),
        Some("0.1.0"),
        Some(4),
    );
    let raw = read_vector_manifest("manifest_github_good.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid github manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.github");
    assert_eq!(parsed.connector.archetypes.len(), 3);
    assert_eq!(parsed.connector.archetypes[2].as_str(), "knowledge");

    let create_op = parsed
        .provides
        .operations
        .get("github.create_issue")
        .expect("github.create_issue");
    assert_eq!(create_op.capability.as_str(), "github.write");
}

#[test]
fn github_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "github_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.github"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/github/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read github manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full github manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.github");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "github.create_issue",
        "github.get_issue",
        "github.search_issues",
        "github.create_pull_request",
        "github.get_pull_request",
        "github.merge_pull_request",
        "github.get_repo",
        "github.search_repos",
        "github.list_workflows",
        "github.trigger_workflow",
        "github.get_file_content",
        "github.search_code",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("GITHUB_INTERFACE_HASH={hash}");

    // Verify 4 rate limit pools
    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 4);
}

#[test]
fn github_bad_manifest_vector_is_rejected() {
    let _log = TestLog::new(
        "github_bad_manifest_vector_is_rejected",
        "fcp-manifest",
        Some("fcp.github"),
        Some("0.1.0"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_github_bad.toml");
    let with_hash = with_computed_hash(&raw);
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("capabilities") || msg.contains("zone") || msg.contains("forbidden"),
        "expected validation failure, got: {msg}"
    );
}

// =============================================================================
// Slack connector tests
// =============================================================================

#[test]
fn slack_good_manifest_vector_parses_and_maps_capabilities() {
    let _log = TestLog::new(
        "slack_good_manifest_vector_parses_and_maps_capabilities",
        "fcp-manifest",
        Some("fcp.slack"),
        Some("0.1.0"),
        Some(4),
    );
    let raw = read_vector_manifest("manifest_slack_good.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid slack manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.slack");
    assert_eq!(parsed.connector.archetypes.len(), 3);
    assert_eq!(parsed.connector.archetypes[2].as_str(), "bidirectional");

    let post_op = parsed
        .provides
        .operations
        .get("slack.post_message")
        .expect("slack.post_message");
    assert_eq!(post_op.capability.as_str(), "slack.write");
}

#[test]
fn slack_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "slack_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.slack"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/slack/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read slack manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full slack manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.slack");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "slack.post_message",
        "slack.reply_thread",
        "slack.get_channel_history",
        "slack.search_messages",
        "slack.list_channels",
        "slack.get_user_info",
        "slack.upload_file",
        "slack.add_reaction",
        "slack.set_channel_topic",
        "slack.download_file",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("SLACK_INTERFACE_HASH={hash}");

    // Verify 4 rate limit pools
    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 4);
}

#[test]
fn slack_bad_manifest_vector_is_rejected() {
    let _log = TestLog::new(
        "slack_bad_manifest_vector_is_rejected",
        "fcp-manifest",
        Some("fcp.slack"),
        Some("0.1.0"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_slack_bad.toml");
    let with_hash = with_computed_hash(&raw);
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("capabilities") || msg.contains("zone") || msg.contains("forbidden"),
        "expected validation failure, got: {msg}"
    );
}

// =============================================================================
// Stripe connector tests
// =============================================================================

#[test]
fn stripe_good_manifest_vector_parses_and_maps_capabilities() {
    let _log = TestLog::new(
        "stripe_good_manifest_vector_parses_and_maps_capabilities",
        "fcp-manifest",
        Some("fcp.stripe"),
        Some("0.1.0"),
        Some(4),
    );
    let raw = read_vector_manifest("manifest_stripe_good.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid stripe manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.stripe");
    assert_eq!(parsed.connector.archetypes.len(), 2);
    assert_eq!(parsed.connector.archetypes[1].as_str(), "streaming");

    let pay_op = parsed
        .provides
        .operations
        .get("stripe.create_payment_intent")
        .expect("stripe.create_payment_intent");
    assert_eq!(pay_op.capability.as_str(), "stripe.payment");
    assert!(matches!(
        pay_op.safety_tier,
        fcp_core::SafetyTier::Dangerous
    ));
}

#[test]
fn stripe_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "stripe_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.stripe"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/stripe/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read stripe manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full stripe manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.stripe");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "stripe.create_customer",
        "stripe.get_customer",
        "stripe.list_customers",
        "stripe.update_customer",
        "stripe.delete_customer",
        "stripe.create_payment_intent",
        "stripe.get_payment_intent",
        "stripe.create_refund",
        "stripe.create_subscription",
        "stripe.get_subscription",
        "stripe.list_subscriptions",
        "stripe.cancel_subscription",
        "stripe.list_invoices",
        "stripe.get_invoice",
        "stripe.get_balance",
        "stripe.ingest_webhook_event",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("STRIPE_INTERFACE_HASH={hash}");

    // Verify 4 rate limit pools
    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 4);
}

#[test]
fn stripe_bad_manifest_vector_is_rejected() {
    let _log = TestLog::new(
        "stripe_bad_manifest_vector_is_rejected",
        "fcp-manifest",
        Some("fcp.stripe"),
        Some("0.1.0"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_stripe_bad.toml");
    let with_hash = with_computed_hash(&raw);
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("capabilities") || msg.contains("zone") || msg.contains("forbidden"),
        "expected validation failure, got: {msg}"
    );
}

// =============================================================================
// Notion connector tests
// =============================================================================

#[test]
fn notion_good_manifest_vector_parses_and_maps_capabilities() {
    let _log = TestLog::new(
        "notion_good_manifest_vector_parses_and_maps_capabilities",
        "fcp-manifest",
        Some("fcp.notion"),
        Some("0.1.0"),
        Some(4),
    );
    let raw = read_vector_manifest("manifest_notion_good.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid notion manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.notion");
    assert_eq!(parsed.connector.archetypes.len(), 3);
    assert_eq!(parsed.connector.archetypes[1].as_str(), "knowledge");

    let create_op = parsed
        .provides
        .operations
        .get("notion.create_page")
        .expect("notion.create_page");
    assert_eq!(create_op.capability.as_str(), "notion.write");
}

#[test]
fn notion_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "notion_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.notion"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/notion/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read notion manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full notion manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.notion");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "notion.create_page",
        "notion.get_page",
        "notion.update_page",
        "notion.delete_page",
        "notion.get_database",
        "notion.create_database",
        "notion.update_database",
        "notion.query_database",
        "notion.search",
        "notion.get_block",
        "notion.update_block",
        "notion.delete_block",
        "notion.get_block_children",
        "notion.append_blocks",
        "notion.add_comment",
        "notion.list_comments",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("NOTION_INTERFACE_HASH={hash}");

    // Verify 4 rate limit pools (read, write, delete, search)
    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 4);
}

#[test]
fn notion_bad_manifest_vector_is_rejected() {
    let _log = TestLog::new(
        "notion_bad_manifest_vector_is_rejected",
        "fcp-manifest",
        Some("fcp.notion"),
        Some("0.1.0"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_notion_bad.toml");
    let with_hash = with_computed_hash(&raw);
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("capabilities") || msg.contains("zone") || msg.contains("forbidden"),
        "expected validation failure, got: {msg}"
    );
}

// =============================================================================
// Linear connector tests
// =============================================================================

#[test]
fn linear_good_manifest_vector_parses_and_maps_capabilities() {
    let _log = TestLog::new(
        "linear_good_manifest_vector_parses_and_maps_capabilities",
        "fcp-manifest",
        Some("fcp.linear"),
        Some("0.1.0"),
        Some(4),
    );
    let raw = read_vector_manifest("manifest_linear_good.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid linear manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.linear");
    assert_eq!(parsed.connector.archetypes.len(), 2);
    assert_eq!(parsed.connector.archetypes[1].as_str(), "streaming");

    let create_op = parsed
        .provides
        .operations
        .get("linear.create_issue")
        .expect("linear.create_issue");
    assert_eq!(create_op.capability.as_str(), "linear.write");
}

#[test]
fn linear_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "linear_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.linear"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/linear/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read linear manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full linear manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.linear");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "linear.create_issue",
        "linear.get_issue",
        "linear.update_issue",
        "linear.search_issues",
        "linear.list_teams",
        "linear.list_cycles",
        "linear.add_comment",
        "linear.list_projects",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("LINEAR_INTERFACE_HASH={hash}");

    // Verify 2 rate limit pools
    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 2);
}

#[test]
fn linear_bad_manifest_vector_is_rejected() {
    let _log = TestLog::new(
        "linear_bad_manifest_vector_is_rejected",
        "fcp-manifest",
        Some("fcp.linear"),
        Some("0.1.0"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_linear_bad.toml");
    let with_hash = with_computed_hash(&raw);
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("capabilities") || msg.contains("zone") || msg.contains("forbidden"),
        "expected validation failure, got: {msg}"
    );
}

// =============================================================================
// S3 connector tests
// =============================================================================

#[test]
fn s3_good_manifest_vector_parses_and_maps_capabilities() {
    let _log = TestLog::new(
        "s3_good_manifest_vector_parses_and_maps_capabilities",
        "fcp-manifest",
        Some("fcp.s3"),
        Some("0.1.0"),
        Some(4),
    );
    let raw = read_vector_manifest("manifest_s3_good.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid s3 manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.s3");
    assert_eq!(parsed.connector.archetypes.len(), 2);
    assert_eq!(parsed.connector.archetypes[0].as_str(), "storage");

    let put_op = parsed
        .provides
        .operations
        .get("s3.put_object")
        .expect("s3.put_object");
    assert_eq!(put_op.capability.as_str(), "s3.write");
}

#[test]
fn s3_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "s3_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.s3"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/s3/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read s3 manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full s3 manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.s3");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "s3.put_object",
        "s3.get_object",
        "s3.delete_object",
        "s3.create_bucket",
        "s3.delete_bucket",
        "s3.list_objects",
        "s3.head_object",
        "s3.copy_object",
        "s3.list_buckets",
        "s3.generate_presigned_url",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("S3_INTERFACE_HASH={hash}");

    // Verify 3 rate limit pools
    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 3);
}

#[test]
fn s3_bad_manifest_vector_is_rejected() {
    let _log = TestLog::new(
        "s3_bad_manifest_vector_is_rejected",
        "fcp-manifest",
        Some("fcp.s3"),
        Some("0.1.0"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_s3_bad.toml");
    let with_hash = with_computed_hash(&raw);
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("capabilities") || msg.contains("zone") || msg.contains("forbidden"),
        "expected validation failure, got: {msg}"
    );
}

// =============================================================================
// Gmail connector tests
// =============================================================================

#[test]
fn gmail_good_manifest_vector_parses_and_maps_capabilities() {
    let _log = TestLog::new(
        "gmail_good_manifest_vector_parses_and_maps_capabilities",
        "fcp-manifest",
        Some("fcp.gmail"),
        Some("0.1.0"),
        Some(4),
    );
    let raw = read_vector_manifest("manifest_gmail_good.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid gmail manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.gmail");
    assert_eq!(parsed.connector.archetypes.len(), 3);
    assert_eq!(parsed.connector.archetypes[2].as_str(), "knowledge");

    let send_op = parsed
        .provides
        .operations
        .get("gmail.send_message")
        .expect("gmail.send_message");
    assert_eq!(send_op.capability.as_str(), "gmail.send");
}

#[test]
fn gmail_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "gmail_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.gmail"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/gmail/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read gmail manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full gmail manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.gmail");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "gmail.send_message",
        "gmail.get_message",
        "gmail.list_messages",
        "gmail.search_messages",
        "gmail.create_draft",
        "gmail.modify_labels",
        "gmail.list_labels",
        "gmail.trash_message",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("GMAIL_INTERFACE_HASH={hash}");

    // Verify 4 rate limit pools
    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 4);
}

#[test]
fn gmail_bad_manifest_vector_is_rejected() {
    let _log = TestLog::new(
        "gmail_bad_manifest_vector_is_rejected",
        "fcp-manifest",
        Some("fcp.gmail"),
        Some("0.1.0"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_gmail_bad.toml");
    let with_hash = with_computed_hash(&raw);
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("capabilities") || msg.contains("zone") || msg.contains("forbidden"),
        "expected validation failure, got: {msg}"
    );
}

// =============================================================================
// Google Calendar connector tests
// =============================================================================

#[test]
fn google_calendar_good_manifest_vector_parses_and_maps_capabilities() {
    let _log = TestLog::new(
        "google_calendar_good_manifest_vector_parses_and_maps_capabilities",
        "fcp-manifest",
        Some("fcp.google-calendar"),
        Some("0.1.0"),
        Some(4),
    );
    let raw = read_vector_manifest("manifest_google_calendar_good.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid google-calendar manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.google-calendar");
    assert_eq!(parsed.connector.archetypes.len(), 2);

    let create_op = parsed
        .provides
        .operations
        .get("gcal.create_event")
        .expect("gcal.create_event");
    assert_eq!(create_op.capability.as_str(), "gcal.write");
}

#[test]
fn google_calendar_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "google_calendar_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.google-calendar"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/google-calendar/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read google-calendar manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed =
        ConnectorManifest::parse_str(&with_hash).expect("valid full google-calendar manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.google-calendar");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "gcal.create_event",
        "gcal.get_event",
        "gcal.update_event",
        "gcal.delete_event",
        "gcal.list_events",
        "gcal.list_calendars",
        "gcal.freebusy",
        "gcal.list_event_instances",
        "gcal.quick_add",
        "gcal.get_calendar",
        "gcal.sync_events",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("GCAL_INTERFACE_HASH={hash}");

    // Verify 3 rate limit pools
    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 3);
}

#[test]
fn google_calendar_bad_manifest_vector_is_rejected() {
    let _log = TestLog::new(
        "google_calendar_bad_manifest_vector_is_rejected",
        "fcp-manifest",
        Some("fcp.google-calendar"),
        Some("0.1.0"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_google_calendar_bad.toml");
    let with_hash = with_computed_hash(&raw);
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("capabilities") || msg.contains("zone") || msg.contains("forbidden"),
        "expected validation failure, got: {msg}"
    );
}

// =============================================================================
// YouTube connector tests
// =============================================================================

#[test]
fn youtube_good_manifest_vector_parses_and_maps_capabilities() {
    let _log = TestLog::new(
        "youtube_good_manifest_vector_parses_and_maps_capabilities",
        "fcp-manifest",
        Some("fcp.youtube"),
        Some("0.1.0"),
        Some(4),
    );
    let raw = read_vector_manifest("manifest_youtube_good.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid youtube manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.youtube");
    assert_eq!(parsed.connector.archetypes.len(), 2);
    assert_eq!(parsed.connector.archetypes[0].as_str(), "knowledge");

    let search_op = parsed
        .provides
        .operations
        .get("youtube.search")
        .expect("youtube.search");
    assert_eq!(search_op.capability.as_str(), "youtube.read");
}

#[test]
fn youtube_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "youtube_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.youtube"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/youtube/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read youtube manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full youtube manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.youtube");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "youtube.search",
        "youtube.get_video",
        "youtube.list_videos",
        "youtube.get_channel",
        "youtube.list_playlists",
        "youtube.list_playlist_items",
        "youtube.list_comments",
        "youtube.post_comment",
        "youtube.get_captions",
        "youtube.get_caption_transcript",
        "youtube.upload_caption",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("YOUTUBE_INTERFACE_HASH={hash}");

    // Verify 2 rate limit pools
    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 2);
}

#[test]
fn youtube_bad_manifest_vector_is_rejected() {
    let _log = TestLog::new(
        "youtube_bad_manifest_vector_is_rejected",
        "fcp-manifest",
        Some("fcp.youtube"),
        Some("0.1.0"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_youtube_bad.toml");
    let with_hash = with_computed_hash(&raw);
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("capabilities") || msg.contains("zone") || msg.contains("forbidden"),
        "expected validation failure, got: {msg}"
    );
}

// =============================================================================
// Twitter connector tests
// =============================================================================

#[test]
fn twitter_good_manifest_vector_parses_and_maps_capabilities() {
    let _log = TestLog::new(
        "twitter_good_manifest_vector_parses_and_maps_capabilities",
        "fcp-manifest",
        Some("fcp.twitter"),
        Some("0.1.0"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_twitter_good.toml");
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid twitter manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.twitter");
    assert_eq!(parsed.connector.archetypes.len(), 3);
    assert_eq!(parsed.connector.archetypes[0].as_str(), "operational");
    assert_eq!(parsed.connector.archetypes[1].as_str(), "streaming");
    assert_eq!(parsed.connector.archetypes[2].as_str(), "bidirectional");

    let search_op = parsed
        .provides
        .operations
        .get("twitter.tweet.search")
        .expect("twitter.tweet.search");
    assert_eq!(search_op.capability.as_str(), "twitter.read");
    let search_nc = search_op
        .network_constraints
        .as_ref()
        .expect("search network constraints");
    assert!(search_nc.host_allow.iter().any(|h| h == "api.twitter.com"));
    assert!(
        search_nc
            .host_allow
            .iter()
            .any(|h| h == "stream.twitter.com")
    );

    let stream_op = parsed
        .provides
        .operations
        .get("twitter.stream.rules.list")
        .expect("twitter.stream.rules.list");
    assert_eq!(stream_op.capability.as_str(), "twitter.stream");
}

#[test]
fn twitter_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "twitter_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.twitter"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/twitter/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read twitter manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full twitter manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.twitter");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "twitter.dm.events",
        "twitter.dm.send",
        "twitter.stream.rules.add",
        "twitter.stream.rules.delete",
        "twitter.stream.rules.list",
        "twitter.trends.place",
        "twitter.tweet.create",
        "twitter.tweet.delete",
        "twitter.tweet.get",
        "twitter.tweet.get_many",
        "twitter.tweet.like",
        "twitter.tweet.reply",
        "twitter.tweet.retweet",
        "twitter.tweet.search",
        "twitter.tweet.unlike",
        "twitter.tweet.unretweet",
        "twitter.user.by_username",
        "twitter.user.get",
        "twitter.user.me",
        "twitter.user.mentions",
        "twitter.user.timeline",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("TWITTER_INTERFACE_HASH={hash}");

    // Verify stream host is allowed in stream rules operation.
    let stream_add = ops
        .get("twitter.stream.rules.add")
        .expect("twitter.stream.rules.add");
    let stream_nc = stream_add.network_constraints.as_ref().expect("stream nc");
    assert!(
        stream_nc
            .host_allow
            .iter()
            .any(|h| h == "stream.twitter.com")
    );
    assert!(stream_nc.host_allow.iter().any(|h| h == "api.x.com"));

    // Verify 4 rate limit pools (read, write, delete, stream).
    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 4);
}

#[test]
fn twitter_bad_manifest_vector_is_rejected() {
    let _log = TestLog::new(
        "twitter_bad_manifest_vector_is_rejected",
        "fcp-manifest",
        Some("fcp.twitter"),
        Some("0.1.0"),
        Some(3),
    );
    let raw = read_vector_manifest("manifest_twitter_bad.toml");
    let with_hash = with_computed_hash(&raw);
    let err = ConnectorManifest::parse_str(&with_hash).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("capabilities") || msg.contains("zone") || msg.contains("forbidden"),
        "expected validation failure, got: {msg}"
    );
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

// =============================================================================
// OpenAI connector tests
// =============================================================================

#[test]
fn openai_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "openai_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.openai"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/openai/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read openai manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full openai manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.openai");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "chat",
        "simple_chat",
        "get_usage",
        "embeddings",
        "images_generate",
        "audio_transcribe",
        "audio_tts",
        "finetune_create",
        "finetune_list",
        "finetune_get",
        "finetune_cancel",
        "finetune_events",
        "assistants_create",
        "assistants_list",
        "assistants_get",
        "assistants_delete",
        "threads_create",
        "threads_get",
        "threads_messages_create",
        "threads_messages_list",
        "threads_runs_create",
        "threads_runs_get",
        "threads_runs_cancel",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("OPENAI_INTERFACE_HASH={hash}");

    // Verify 9 rate limit pools
    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 9);

    // Verify operation pool mappings exist for all pooled operations
    let op_pools = &pools.operation_pools;
    assert!(op_pools.contains_key("openai.assistants.create"));
    assert!(op_pools.contains_key("openai.threads.runs.create"));
    assert!(op_pools.contains_key("openai.finetune.create"));
}

// =============================================================================
// LLM Router connector tests
// =============================================================================

#[test]
fn llm_router_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "llm_router_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.llm-router"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/llm-router/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read llm-router manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full llm-router manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.llm-router");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "llm-router.route",
        "llm-router.estimate_cost",
        "llm-router.list_providers",
        "llm-router.get_usage",
        "llm-router.get_budget",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("LLM_ROUTER_INTERFACE_HASH={hash}");

    // Verify 3 rate limit pools
    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 3);

    // Verify operation pool mappings
    let op_pools = &pools.operation_pools;
    assert!(op_pools.contains_key("llm-router.route"));
    assert!(op_pools.contains_key("llm-router.estimate_cost"));
    assert!(op_pools.contains_key("llm-router.get_budget"));
}

// =============================================================================
// Anthropic connector tests
// =============================================================================

#[test]
fn anthropic_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "anthropic_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.anthropic"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/anthropic/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read anthropic manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full anthropic manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.anthropic");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "anthropic.chat",
        "anthropic.get_usage",
        "anthropic.message",
        "anthropic.message.stream",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("ANTHROPIC_INTERFACE_HASH={hash}");
}

// =============================================================================
// Browser connector tests
// =============================================================================

#[test]
fn browser_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "browser_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.browser"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/browser/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read browser manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full browser manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.browser");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "browser.click",
        "browser.clear_proxy",
        "browser.evaluate_js",
        "browser.extract_links",
        "browser.extract_text",
        "browser.fill_form",
        "browser.get_cookies",
        "browser.navigate",
        "browser.render_pdf",
        "browser.screenshot",
        "browser.session.describe",
        "browser.session.restore",
        "browser.session.save",
        "browser.set_cookies",
        "browser.set_proxy",
        "browser.wait_for_selector",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("BROWSER_INTERFACE_HASH={hash}");

    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 8);

    let op_pools = &pools.operation_pools;
    assert!(op_pools.contains_key("browser.navigate"));
    assert!(op_pools.contains_key("browser.click"));
    assert!(op_pools.contains_key("browser.screenshot"));
}

// =============================================================================
// Microsoft365 connector tests
// =============================================================================

#[test]
fn microsoft365_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "microsoft365_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.microsoft365"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/microsoft365/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read microsoft365 manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed =
        ConnectorManifest::parse_str(&with_hash).expect("valid full microsoft365 manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.microsoft365");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "m365.calendar.create_event",
        "m365.calendar.delete_event",
        "m365.calendar.get_event",
        "m365.calendar.get_freebusy",
        "m365.calendar.list_events",
        "m365.calendar.update_event",
        "m365.delta.sync",
        "m365.files.create_share_link",
        "m365.files.delete_item",
        "m365.files.download_file",
        "m365.files.get_item",
        "m365.files.list_items",
        "m365.files.search",
        "m365.files.upload_file",
        "m365.mail.add_attachment",
        "m365.mail.create_draft",
        "m365.mail.forward_message",
        "m365.mail.get_message",
        "m365.mail.list_attachments",
        "m365.mail.list_messages",
        "m365.mail.list_threads",
        "m365.mail.reply_message",
        "m365.mail.search_messages",
        "m365.mail.send_message",
        "m365.subscriptions.create",
        "m365.subscriptions.delete",
        "m365.subscriptions.renew",
        "m365.tasks.create_task",
        "m365.tasks.list_task_lists",
        "m365.tasks.list_tasks",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("MICROSOFT365_INTERFACE_HASH={hash}");

    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 11);

    let op_pools = &pools.operation_pools;
    assert!(op_pools.contains_key("m365.mail.search_messages"));
    assert!(op_pools.contains_key("m365.calendar.create_event"));
    assert!(op_pools.contains_key("m365.files.upload_file"));
}

// =============================================================================
// Google AI (Gemini) connector tests
// =============================================================================

#[test]
fn google_ai_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "google_ai_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.google-ai"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/google-ai/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read google-ai manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full google-ai manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.google-ai");

    // Verify all 8 operations present
    let ops = &parsed.provides.operations;
    let expected_ops = [
        "google-ai.batch_embed_contents",
        "google-ai.count_tokens",
        "google-ai.embed_content",
        "google-ai.generate_content",
        "google-ai.generate_content_stream",
        "google-ai.get_model",
        "google-ai.get_usage",
        "google-ai.list_models",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("GOOGLE_AI_INTERFACE_HASH={hash}");

    // Verify 3 rate limit pools
    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 3);

    // Verify operation pool mappings exist for all operations
    let op_pools = &pools.operation_pools;
    for op_name in &expected_ops {
        assert!(
            op_pools.contains_key(*op_name),
            "missing rate limit pool mapping for: {op_name}"
        );
    }
}

// =============================================================================
// VectorDB connector tests
// =============================================================================

#[test]
fn vectordb_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "vectordb_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.vectordb"),
        Some("0.1.0"),
        Some(6),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/vectordb/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read vectordb manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full vectordb manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.vectordb");

    // Verify all 9 operations present
    let ops = &parsed.provides.operations;
    let expected_ops = [
        "create_collection",
        "delete_collection",
        "delete_vectors",
        "describe_collection",
        "fetch_vectors",
        "list_collections",
        "query_vectors",
        "update_vector_metadata",
        "upsert_vectors",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("unchecked");
    let hash = unchecked.compute_interface_hash().expect("hash");
    println!("VECTORDB_INTERFACE_HASH={hash}");

    // Verify 3 rate limit pools
    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 3);
}

// =============================================================================
// Discord connector tests (generic TOML validation)
// =============================================================================

#[test]
fn discord_manifest_parses_as_valid_toml_with_expected_structure() {
    let _log = TestLog::new(
        "discord_manifest_parses_as_valid_toml_with_expected_structure",
        "fcp-manifest",
        Some("fcp.discord"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/discord/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read discord manifest: {err}"));
    let parsed: toml::Value = toml::from_str(&raw).expect("valid TOML");

    // Verify manifest structure
    let manifest = parsed.get("manifest").expect("manifest section");
    assert_eq!(
        manifest.get("format").and_then(|v| v.as_str()),
        Some("fcp-connector-manifest")
    );

    let connector = parsed.get("connector").expect("connector section");
    assert_eq!(
        connector.get("id").and_then(|v| v.as_str()),
        Some("fcp.discord")
    );

    // Verify 9 operations
    let provides = parsed.get("provides").expect("provides section");
    let operations = provides
        .get("operations")
        .expect("operations")
        .as_table()
        .expect("table");
    let expected_ops = [
        "send_message",
        "edit_message",
        "delete_message",
        "get_channel",
        "get_guild",
        "trigger_typing",
        "add_reaction",
        "list_channels",
        "create_thread",
    ];
    for op_name in &expected_ops {
        assert!(
            operations.contains_key(*op_name),
            "missing discord operation: {op_name}"
        );
    }
    assert_eq!(operations.len(), expected_ops.len());

    // Verify streaming section exists (not yet supported by fcp-manifest parser)
    assert!(
        provides.get("streaming").is_some(),
        "discord manifest should have streaming section"
    );
}

// =============================================================================
// Telegram connector tests (generic TOML validation)
// =============================================================================

#[test]
fn telegram_manifest_parses_as_valid_toml_with_expected_structure() {
    let _log = TestLog::new(
        "telegram_manifest_parses_as_valid_toml_with_expected_structure",
        "fcp-manifest",
        Some("fcp.telegram"),
        Some("0.1.0"),
        Some(2),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/telegram/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read telegram manifest: {err}"));
    let parsed: toml::Value = toml::from_str(&raw).expect("valid TOML");

    // Verify manifest structure
    let manifest = parsed.get("manifest").expect("manifest section");
    assert_eq!(
        manifest.get("format").and_then(|v| v.as_str()),
        Some("fcp-connector-manifest")
    );

    let connector = parsed.get("connector").expect("connector section");
    assert_eq!(
        connector.get("id").and_then(|v| v.as_str()),
        Some("fcp.telegram")
    );

    // Verify 4 operations
    let provides = parsed.get("provides").expect("provides section");
    let operations = provides
        .get("operations")
        .expect("operations")
        .as_table()
        .expect("table");
    let expected_ops = [
        "telegram.send_message",
        "telegram.send_media",
        "telegram.get_file",
        "telegram.answer_callback_query",
    ];
    for op_name in &expected_ops {
        assert!(
            operations.contains_key(*op_name),
            "missing telegram operation: {op_name}"
        );
    }
    assert_eq!(operations.len(), expected_ops.len());
}

// =============================================================================
// Sentry connector tests
// =============================================================================

#[test]
fn sentry_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "sentry_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.sentry"),
        Some("0.1.0"),
        Some(4),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/sentry/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read sentry manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full sentry manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.sentry");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "sentry.create_alert_rule",
        "sentry.delete_alert_rule",
        "sentry.delete_issue",
        "sentry.discover_query",
        "sentry.get_event",
        "sentry.get_issue",
        "sentry.get_release",
        "sentry.get_transaction",
        "sentry.list_alert_rules",
        "sentry.list_issue_events",
        "sentry.list_issues",
        "sentry.list_projects",
        "sentry.list_release_deploys",
        "sentry.list_releases",
        "sentry.stream_webhook_events",
        "sentry.update_alert_rule",
        "sentry.update_issue",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 4);
}

// =============================================================================
// Kubernetes connector tests
// =============================================================================

#[test]
fn kubernetes_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "kubernetes_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.kubernetes"),
        Some("0.1.0"),
        Some(2),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/kubernetes/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read kubernetes manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed =
        ConnectorManifest::parse_str(&with_hash).expect("valid full kubernetes manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.kubernetes");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "kubernetes.delete_pod",
        "kubernetes.get_configmap",
        "kubernetes.get_deployment",
        "kubernetes.get_pod",
        "kubernetes.get_pod_logs",
        "kubernetes.get_secret",
        "kubernetes.get_service",
        "kubernetes.list_deployments",
        "kubernetes.list_pods",
        "kubernetes.rollout_restart",
        "kubernetes.scale_deployment",
        "kubernetes.stream_pod_logs",
        "kubernetes.update_configmap",
        "kubernetes.watch_events",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 4);
}

// =============================================================================
// Airtable connector tests
// =============================================================================

#[test]
fn airtable_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "airtable_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.airtable"),
        Some("0.1.0"),
        Some(2),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/airtable/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read airtable manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed =
        ConnectorManifest::parse_str(&with_hash).expect("valid full airtable manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.airtable");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "create_record",
        "create_records",
        "delete_record",
        "download_attachment",
        "get_base_schema",
        "get_record",
        "get_table",
        "list_bases",
        "list_fields",
        "list_records",
        "list_tables",
        "replace_record",
        "update_record",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 3);
}

// =============================================================================
// Spotify connector tests
// =============================================================================

#[test]
fn spotify_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "spotify_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.spotify"),
        Some("0.1.0"),
        Some(3),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/spotify/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read spotify manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed =
        ConnectorManifest::parse_str(&with_hash).expect("valid full spotify manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.spotify");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "spotify.album.get",
        "spotify.artist.get",
        "spotify.library.list_saved_tracks",
        "spotify.library.remove_track",
        "spotify.library.save_track",
        "spotify.media.download_cover",
        "spotify.playback.get_state",
        "spotify.playback.pause",
        "spotify.playback.play",
        "spotify.player.stream",
        "spotify.playlist.get",
        "spotify.search",
        "spotify.track.get",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 5);
}

// =============================================================================
// HubSpot connector tests
// =============================================================================

#[test]
fn hubspot_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "hubspot_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.hubspot"),
        Some("0.1.0"),
        Some(3),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/hubspot/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read hubspot manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed =
        ConnectorManifest::parse_str(&with_hash).expect("valid full hubspot manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.hubspot");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "hubspot.analytics.report",
        "hubspot.companies.list",
        "hubspot.contacts.create",
        "hubspot.contacts.delete",
        "hubspot.contacts.get",
        "hubspot.contacts.list",
        "hubspot.contacts.update",
        "hubspot.deals.create",
        "hubspot.deals.list",
        "hubspot.events.stream",
        "hubspot.pipelines.list",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 8);
}

// =============================================================================
// Reddit connector tests
// =============================================================================

#[test]
fn reddit_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "reddit_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.reddit"),
        Some("0.1.0"),
        Some(3),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/reddit/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read reddit manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed = ConnectorManifest::parse_str(&with_hash).expect("valid full reddit manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.reddit");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "reddit.create_comment",
        "reddit.create_post",
        "reddit.download_media",
        "reddit.get_post_thread",
        "reddit.list_subreddit_new",
        "reddit.mod_remove",
        "reddit.search_posts",
        "reddit.send_message",
        "reddit.stream_subreddit_new",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 5);
}

// =============================================================================
// MongoDB connector tests
// =============================================================================

#[test]
fn mongodb_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "mongodb_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.mongodb"),
        Some("0.1.0"),
        Some(2),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/mongodb/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read mongodb manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed =
        ConnectorManifest::parse_str(&with_hash).expect("valid full mongodb manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.mongodb");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "mongodb.aggregate",
        "mongodb.collections.list",
        "mongodb.databases.list",
        "mongodb.documents.delete",
        "mongodb.documents.find",
        "mongodb.documents.insert",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 3);
}

// =============================================================================
// GitLab connector tests
// =============================================================================

#[test]
fn gitlab_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "gitlab_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.gitlab"),
        Some("0.1.0"),
        Some(2),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/gitlab/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read gitlab manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed =
        ConnectorManifest::parse_str(&with_hash).expect("valid full gitlab manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.gitlab");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "gitlab.issues.create",
        "gitlab.issues.list",
        "gitlab.merge_requests.list",
        "gitlab.pipelines.list",
        "gitlab.projects.list",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 5);
}

// =============================================================================
// Dropbox connector tests
// =============================================================================

#[test]
fn dropbox_full_manifest_parses_with_all_operations() {
    let _log = TestLog::new(
        "dropbox_full_manifest_parses_with_all_operations",
        "fcp-manifest",
        Some("fcp.dropbox"),
        Some("0.1.0"),
        Some(2),
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../../connectors/dropbox/manifest.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read dropbox manifest: {err}"));
    let with_hash = with_computed_hash(&raw);
    let parsed =
        ConnectorManifest::parse_str(&with_hash).expect("valid full dropbox manifest");

    assert_eq!(parsed.connector.id.as_str(), "fcp.dropbox");

    let ops = &parsed.provides.operations;
    let expected_ops = [
        "dropbox.files.delete",
        "dropbox.files.get_metadata",
        "dropbox.files.list",
        "dropbox.sharing.list",
    ];
    for op_name in &expected_ops {
        assert!(ops.contains_key(*op_name), "missing operation: {op_name}");
    }
    assert_eq!(ops.len(), expected_ops.len());

    let pools = parsed.rate_limits.as_ref().expect("rate_limits");
    assert_eq!(pools.pools.len(), 3);
}
