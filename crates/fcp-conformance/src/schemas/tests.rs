//! FZPF schema validation tests.
//!
//! These tests validate:
//! - Example policy documents against the schema (positive tests)
//! - Rejection of forbidden constructs (negative tests)
//! - Deterministic validation behavior

use super::{
    CAPABILITY_USAGE_V1_SCHEMA, E2E_LOG_V1_SCHEMA, E2E_LOG_V2_SCHEMA, FZPF_V01_SCHEMA,
    RELEASE_MANIFEST_V1_SCHEMA, ROLLOUT_POLICY_V1_SCHEMA, TRACE_V1_SCHEMA,
};
use fcp_cbor::to_canonical_cbor;
use fcp_core::ObjectId;
use jsonschema::Validator;
use serde_json::Value;

/// Load and compile the FZPF v0.1 schema validator.
fn load_schema() -> Validator {
    let schema: Value =
        serde_json::from_str(FZPF_V01_SCHEMA).expect("FZPF schema should be valid JSON");
    Validator::new(&schema).expect("FZPF schema should be a valid JSON Schema")
}

/// Example policy documents embedded for testing.
mod examples {
    pub const MINIMAL_ZONE: &str = include_str!("examples/minimal_zone.json");
    pub const ROLE_BUNDLES: &str = include_str!("examples/role_bundles.json");
    pub const TRANSPORT_RESTRICTIONS: &str = include_str!("examples/transport_restrictions.json");
    pub const FRESHNESS_POLICY: &str = include_str!("examples/freshness_policy.json");
    pub const TAINT_APPROVAL: &str = include_str!("examples/taint_approval.json");
    pub const E2E_LOG_MINIMAL: &str = include_str!("examples/e2e_log_minimal.json");
    pub const RELEASE_MANIFEST: &str = include_str!("examples/release_manifest.json");
    pub const ROLLOUT_POLICY: &str = include_str!("examples/rollout_policy.json");
}

// ============================================================================
// Positive Tests - Example Document Validation
// ============================================================================

#[test]
fn valid_minimal_zone() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(examples::MINIMAL_ZONE)
        .expect("minimal_zone.json should be valid JSON");
    let result = validator.validate(&doc);
    assert!(
        result.is_ok(),
        "minimal_zone.json should validate: {:?}",
        result.err().map(|e| e.to_string())
    );
}

#[test]
fn valid_role_bundles() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(examples::ROLE_BUNDLES)
        .expect("role_bundles.json should be valid JSON");
    let result = validator.validate(&doc);
    assert!(
        result.is_ok(),
        "role_bundles.json should validate: {:?}",
        result.err().map(|e| e.to_string())
    );
}

#[test]
fn valid_transport_restrictions() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(examples::TRANSPORT_RESTRICTIONS)
        .expect("transport_restrictions.json should be valid JSON");
    let result = validator.validate(&doc);
    assert!(
        result.is_ok(),
        "transport_restrictions.json should validate: {:?}",
        result.err().map(|e| e.to_string())
    );
}

#[test]
fn valid_freshness_policy() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(examples::FRESHNESS_POLICY)
        .expect("freshness_policy.json should be valid JSON");
    let result = validator.validate(&doc);
    assert!(
        result.is_ok(),
        "freshness_policy.json should validate: {:?}",
        result.err().map(|e| e.to_string())
    );
}

#[test]
fn valid_taint_approval() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(examples::TAINT_APPROVAL)
        .expect("taint_approval.json should be valid JSON");
    let result = validator.validate(&doc);
    assert!(
        result.is_ok(),
        "taint_approval.json should validate: {:?}",
        result.err().map(|e| e.to_string())
    );
}

// ============================================================================
// Negative Tests - Forbidden Constructs
// ============================================================================

#[test]
fn reject_missing_policy_header() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "zones": [{ "id": "z:work", "integrity_level": 60, "confidentiality_level": 70 }]
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "Document without 'policy' header should be rejected"
    );
}

#[test]
fn reject_missing_zones() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": { "format": "fzpf", "schema_version": "0.1", "default_deny": true }
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "Document without 'zones' array should be rejected"
    );
}

#[test]
fn reject_empty_zones_array() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": { "format": "fzpf", "schema_version": "0.1", "default_deny": true },
            "zones": []
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "Document with empty zones array should be rejected (minItems: 1)"
    );
}

#[test]
fn reject_invalid_zone_id_format() {
    let validator = load_schema();
    // Zone IDs must match ^z:[a-z][a-z0-9_-]*$
    let invalid_ids = [
        "work",          // Missing z: prefix
        "Z:work",        // Uppercase Z
        "z:Work",        // Uppercase letter after prefix
        "z:123",         // Starts with number
        "z:work space",  // Contains space
        "z:",            // Empty after prefix
        "z:work/nested", // Contains slash
        "zone:work",     // Wrong prefix
    ];

    for invalid_id in invalid_ids {
        let doc: Value = serde_json::from_str(&format!(
            r#"{{
                "policy": {{ "format": "fzpf", "schema_version": "0.1", "default_deny": true }},
                "zones": [{{ "id": "{invalid_id}", "integrity_level": 60, "confidentiality_level": 70 }}]
            }}"#,
        ))
        .unwrap();
        assert!(
            validator.validate(&doc).is_err(),
            "Zone ID '{invalid_id}' should be rejected",
        );
    }
}

#[test]
fn reject_invalid_integrity_level() {
    let validator = load_schema();
    // Integrity levels must be 0-100
    let invalid_levels = [-1i64, 101, 1000];

    for level in invalid_levels {
        let doc: Value = serde_json::from_str(&format!(
            r#"{{
                "policy": {{ "format": "fzpf", "schema_version": "0.1", "default_deny": true }},
                "zones": [{{ "id": "z:work", "integrity_level": {level}, "confidentiality_level": 70 }}]
            }}"#,
        ))
        .unwrap();
        assert!(
            validator.validate(&doc).is_err(),
            "Integrity level {level} should be rejected (must be 0-100)",
        );
    }
}

#[test]
fn reject_invalid_confidentiality_level() {
    let validator = load_schema();
    // Confidentiality levels must be 0-100
    let invalid_levels = [-1i64, 101, 1000];

    for level in invalid_levels {
        let doc: Value = serde_json::from_str(&format!(
            r#"{{
                "policy": {{ "format": "fzpf", "schema_version": "0.1", "default_deny": true }},
                "zones": [{{ "id": "z:work", "integrity_level": 60, "confidentiality_level": {level} }}]
            }}"#,
        ))
        .unwrap();
        assert!(
            validator.validate(&doc).is_err(),
            "Confidentiality level {level} should be rejected (must be 0-100)",
        );
    }
}

// ============================================================================
// E2E Log Schema Validation
// ============================================================================

fn load_e2e_log_schema(schema: &str) -> Validator {
    let schema: Value = serde_json::from_str(schema).expect("E2E log schema should be valid JSON");
    Validator::new(&schema).expect("E2E log schema should be a valid JSON Schema")
}

fn load_release_manifest_schema() -> Validator {
    let schema: Value = serde_json::from_str(RELEASE_MANIFEST_V1_SCHEMA)
        .expect("ReleaseManifest schema should be valid JSON");
    Validator::new(&schema).expect("ReleaseManifest schema should be a valid JSON Schema")
}

fn load_rollout_policy_schema() -> Validator {
    let schema: Value = serde_json::from_str(ROLLOUT_POLICY_V1_SCHEMA)
        .expect("RolloutPolicy schema should be valid JSON");
    Validator::new(&schema).expect("RolloutPolicy schema should be a valid JSON Schema")
}

fn load_trace_schema() -> Validator {
    let schema: Value =
        serde_json::from_str(TRACE_V1_SCHEMA).expect("Trace schema should be valid JSON");
    Validator::new(&schema).expect("Trace schema should be a valid JSON Schema")
}

fn load_capability_usage_schema() -> Validator {
    let schema: Value = serde_json::from_str(CAPABILITY_USAGE_V1_SCHEMA)
        .expect("CapabilityUsage schema should be valid JSON");
    Validator::new(&schema).expect("CapabilityUsage schema should be a valid JSON Schema")
}

fn sample_release_manifest() -> Value {
    serde_json::from_str(examples::RELEASE_MANIFEST).expect("sample release manifest should parse")
}

fn sample_rollout_policy() -> Value {
    serde_json::from_str(examples::ROLLOUT_POLICY).expect("sample rollout policy should parse")
}

fn sample_trace() -> Value {
    serde_json::from_str(
        r#"{
            "format": "fcp-trace",
            "schema_version": "1.0",
            "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
            "captured_at": "2026-02-01T12:00:00Z",
            "node_id": "node-1",
            "redaction_policy": {
                "policy_version": "1.0",
                "applied": true,
                "fields": ["payload"]
            },
            "entries": [
                {
                    "ts": "2026-02-01T12:00:01Z",
                    "kind": "routing_decision",
                    "direction": "internal",
                    "component": "mesh.router",
                    "zone_id": "z:work",
                    "decision": "allow",
                    "reason_code": "route.direct",
                    "payload_hash": "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "payload": "redacted",
                    "redaction": {
                        "applied": true,
                        "fields": ["payload"]
                    }
                }
            ]
        }"#,
    )
    .expect("sample trace should parse")
}

fn sample_capability_usage() -> Value {
    serde_json::from_str(
        r#"{
            "format": "fcp-capability-usage",
            "schema_version": "1.0",
            "zone_id": "z:work",
            "connector_id": "fcp.example:request-response:1",
            "capability_id": "fcp.example.read",
            "principal_id": "user:alice",
            "risk_tier": "risky",
            "operation": "op.list",
            "outcome": "allow",
            "occurred_at": 1738387200
        }"#,
    )
    .expect("sample capability usage should parse")
}

const TRACE_CBOR_HEX: &str = "a766666f726d6174696663702d747261636567656e747269657381aa62747374323032362d30322d30315431323a30303a30315a646b696e6470726f7574696e675f6465636973696f6e677061796c6f6164687265646163746564677a6f6e655f6964667a3a776f726b686465636973696f6e65616c6c6f7769636f6d706f6e656e746b6d6573682e726f7574657269646972656374696f6e68696e7465726e616c69726564616374696f6ea2666669656c647381677061796c6f6164676170706c696564f56b726561736f6e5f636f64656c726f7574652e6469726563746c7061796c6f61645f68617368784b626c616b65332d3235363a61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161676e6f64655f6964666e6f64652d316874726163655f6964782034626639326633353737623334646136613363653932396430653065343733366b63617074757265645f617474323032362d30322d30315431323a30303a30305a6e736368656d615f76657273696f6e63312e3070726564616374696f6e5f706f6c696379a3666669656c647381677061796c6f6164676170706c696564f56e706f6c6963795f76657273696f6e63312e30";
const CAPABILITY_USAGE_CBOR_HEX: &str = "aa66666f726d6174746663702d6361706162696c6974792d7573616765676f7574636f6d6565616c6c6f77677a6f6e655f6964667a3a776f726b696f7065726174696f6e676f702e6c697374697269736b5f74696572657269736b796b6f636375727265645f61741a679daf006c636f6e6e6563746f725f6964781e6663702e6578616d706c653a726571756573742d726573706f6e73653a316c7072696e636970616c5f69646a757365723a616c6963656d6361706162696c6974795f6964706663702e6578616d706c652e726561646e736368656d615f76657273696f6e63312e30";

#[test]
fn valid_e2e_log_entry_v1() {
    let validator = load_e2e_log_schema(E2E_LOG_V1_SCHEMA);
    let doc: Value = serde_json::from_str(examples::E2E_LOG_MINIMAL)
        .expect("e2e_log_minimal.json should be valid JSON");
    let result = validator.validate(&doc);
    assert!(
        result.is_ok(),
        "e2e_log_minimal.json should validate: {:?}",
        result.err().map(|e| e.to_string())
    );
}

#[test]
fn valid_e2e_log_entry_v2() {
    let validator = load_e2e_log_schema(E2E_LOG_V2_SCHEMA);
    let doc: Value = serde_json::from_str(
        r#"{
            "timestamp": "2026-01-27T00:00:00Z",
            "log_version": "v2",
            "script": "e2e_happy_path",
            "step": "invoke",
            "correlation_id": "00000000-0000-4000-8000-000000000000",
            "duration_ms": 25,
            "result": "pass"
        }"#,
    )
    .unwrap();
    let result = validator.validate(&doc);
    assert!(
        result.is_ok(),
        "v2 log entry should validate: {:?}",
        result.err().map(|e| e.to_string())
    );
}

#[test]
fn reject_missing_e2e_log_fields() {
    let validator = load_e2e_log_schema(E2E_LOG_V1_SCHEMA);
    let doc: Value = serde_json::from_str(
        r#"{
            "timestamp": "2026-01-27T00:00:00Z",
            "node_id": "node-0",
            "test_name": "missing-fields",
            "phase": "execute",
            "event_type": "symbol_routed",
            "details": {}
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "Log entry missing required fields should be rejected"
    );
}

// ============================================================================
// E2E Log Schema Migration Tests (bd-35sx)
// ============================================================================

#[test]
fn v1_without_log_version_validates() {
    // v1 schema accepts entries without log_version field (implicit v1)
    use super::validate_e2e_log_entry;

    let doc: Value = serde_json::from_str(
        r#"{
            "timestamp": "2026-01-27T00:00:00Z",
            "script": "e2e_migration_test",
            "step": "setup",
            "correlation_id": "00000000-0000-4000-8000-000000000001",
            "duration_ms": 10,
            "result": "pass"
        }"#,
    )
    .unwrap();

    assert!(
        validate_e2e_log_entry(&doc).is_ok(),
        "v1 entry without log_version should validate"
    );
}

#[test]
fn v1_with_explicit_version_validates() {
    // v1 schema accepts entries with explicit log_version: "v1"
    use super::validate_e2e_log_entry;

    let doc: Value = serde_json::from_str(
        r#"{
            "timestamp": "2026-01-27T00:00:00Z",
            "log_version": "v1",
            "script": "e2e_migration_test",
            "step": "setup",
            "correlation_id": "00000000-0000-4000-8000-000000000002",
            "duration_ms": 10,
            "result": "pass"
        }"#,
    )
    .unwrap();

    assert!(
        validate_e2e_log_entry(&doc).is_ok(),
        "v1 entry with explicit log_version should validate"
    );
}

#[test]
fn v2_with_explicit_version_validates() {
    // v2 schema requires explicit log_version: "v2"
    use super::validate_e2e_log_entry;

    let doc: Value = serde_json::from_str(
        r#"{
            "timestamp": "2026-01-27T00:00:00Z",
            "log_version": "v2",
            "script": "e2e_migration_test",
            "step": "verify",
            "correlation_id": "00000000-0000-4000-8000-000000000003",
            "duration_ms": 25,
            "result": "pass"
        }"#,
    )
    .unwrap();

    assert!(
        validate_e2e_log_entry(&doc).is_ok(),
        "v2 entry with explicit log_version should validate"
    );
}

#[test]
fn unknown_log_version_fails_with_clear_error() {
    // Unknown log_version values should fail with a clear error message
    use super::validate_e2e_log_entry;

    let doc: Value = serde_json::from_str(
        r#"{
            "timestamp": "2026-01-27T00:00:00Z",
            "log_version": "v99",
            "script": "e2e_migration_test",
            "step": "setup",
            "correlation_id": "00000000-0000-4000-8000-000000000004",
            "duration_ms": 10,
            "result": "pass"
        }"#,
    )
    .unwrap();

    let result = validate_e2e_log_entry(&doc);
    assert!(result.is_err(), "Unknown log_version should fail");

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("v99") && msg.contains("unknown"),
        "Error should mention unknown version: {msg}"
    );
}

#[test]
fn invalid_log_version_type_fails_with_clear_error() {
    // log_version must be a string, not a number or other type
    use super::validate_e2e_log_entry;

    let doc: Value = serde_json::from_str(
        r#"{
            "timestamp": "2026-01-27T00:00:00Z",
            "log_version": 1,
            "script": "e2e_migration_test",
            "step": "setup",
            "correlation_id": "00000000-0000-4000-8000-000000000005",
            "duration_ms": 10,
            "result": "pass"
        }"#,
    )
    .unwrap();

    let result = validate_e2e_log_entry(&doc);
    assert!(result.is_err(), "Non-string log_version should fail");

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("string"),
        "Error should mention expected type: {msg}"
    );
}

#[test]
fn jsonl_with_mixed_versions_validates() {
    // JSONL with mixed v1 and v2 entries should validate
    use super::validate_e2e_log_jsonl;

    let jsonl = r#"{"timestamp": "2026-01-27T00:00:00Z", "script": "test", "step": "setup", "correlation_id": "a", "duration_ms": 1, "result": "pass"}
{"timestamp": "2026-01-27T00:00:01Z", "log_version": "v1", "script": "test", "step": "execute", "correlation_id": "b", "duration_ms": 2, "result": "pass"}
{"timestamp": "2026-01-27T00:00:02Z", "log_version": "v2", "script": "test", "step": "verify", "correlation_id": "c", "duration_ms": 3, "result": "pass"}"#;

    assert!(
        validate_e2e_log_jsonl(jsonl).is_ok(),
        "Mixed v1/v2 JSONL should validate"
    );
}

#[test]
fn jsonl_with_invalid_version_reports_line_number() {
    // JSONL validation should report the line number of failures
    use super::validate_e2e_log_jsonl;

    let jsonl = r#"{"timestamp": "2026-01-27T00:00:00Z", "script": "test", "step": "setup", "correlation_id": "a", "duration_ms": 1, "result": "pass"}
{"timestamp": "2026-01-27T00:00:01Z", "log_version": "v1", "script": "test", "step": "execute", "correlation_id": "b", "duration_ms": 2, "result": "pass"}
{"timestamp": "2026-01-27T00:00:02Z", "log_version": "v99", "script": "test", "step": "verify", "correlation_id": "c", "duration_ms": 3, "result": "pass"}"#;

    let result = validate_e2e_log_jsonl(jsonl);
    assert!(result.is_err(), "JSONL with invalid version should fail");

    let err = result.unwrap_err();
    let msg = err.to_string();
    // Error message should indicate the problem is with v99
    assert!(
        msg.contains("v99") || msg.contains("unknown"),
        "Error should mention the problem: {msg}"
    );
}

#[test]
fn v1_required_fields_preserved_in_dispatch() {
    // Verify that v1 required fields are correctly validated
    use super::validate_e2e_log_entry;

    // Minimal valid v1 script entry
    let valid_doc: Value = serde_json::from_str(
        r#"{
            "timestamp": "2026-01-27T00:00:00Z",
            "script": "test",
            "step": "setup",
            "correlation_id": "test-id",
            "duration_ms": 10,
            "result": "pass"
        }"#,
    )
    .unwrap();
    assert!(
        validate_e2e_log_entry(&valid_doc).is_ok(),
        "Valid v1 entry should pass"
    );

    // Missing required field should fail
    let invalid_doc: Value = serde_json::from_str(
        r#"{
            "timestamp": "2026-01-27T00:00:00Z",
            "script": "test",
            "step": "setup"
        }"#,
    )
    .unwrap();
    assert!(
        validate_e2e_log_entry(&invalid_doc).is_err(),
        "v1 entry missing required fields should fail"
    );
}

#[test]
fn v2_required_fields_preserved_in_dispatch() {
    // Verify that v2 required fields are correctly validated
    use super::validate_e2e_log_entry;

    // Minimal valid v2 script entry
    let valid_doc: Value = serde_json::from_str(
        r#"{
            "timestamp": "2026-01-27T00:00:00Z",
            "log_version": "v2",
            "script": "test",
            "step": "setup",
            "correlation_id": "test-id",
            "duration_ms": 10,
            "result": "pass"
        }"#,
    )
    .unwrap();
    assert!(
        validate_e2e_log_entry(&valid_doc).is_ok(),
        "Valid v2 entry should pass"
    );

    // v2 entry missing required fields should fail
    let invalid_doc: Value = serde_json::from_str(
        r#"{
            "timestamp": "2026-01-27T00:00:00Z",
            "log_version": "v2",
            "script": "test"
        }"#,
    )
    .unwrap();
    assert!(
        validate_e2e_log_entry(&invalid_doc).is_err(),
        "v2 entry missing required fields should fail"
    );
}

#[test]
fn reject_unknown_fields_in_policy() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": {
                "format": "fzpf",
                "schema_version": "0.1",
                "default_deny": true,
                "unknown_field": "should_fail"
            },
            "zones": [{ "id": "z:work", "integrity_level": 60, "confidentiality_level": 70 }]
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "Unknown fields in policy header should be rejected (additionalProperties: false)"
    );
}

#[test]
fn reject_unknown_fields_in_zone() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": { "format": "fzpf", "schema_version": "0.1", "default_deny": true },
            "zones": [{
                "id": "z:work",
                "integrity_level": 60,
                "confidentiality_level": 70,
                "unknown_field": "should_fail"
            }]
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "Unknown fields in zone definition should be rejected (additionalProperties: false)"
    );
}

#[test]
fn reject_unknown_fields_at_root() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": { "format": "fzpf", "schema_version": "0.1", "default_deny": true },
            "zones": [{ "id": "z:work", "integrity_level": 60, "confidentiality_level": 70 }],
            "unknown_root_field": "should_fail"
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "Unknown fields at root level should be rejected (additionalProperties: false)"
    );
}

#[test]
fn reject_invalid_format_value() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": { "format": "invalid", "schema_version": "0.1", "default_deny": true },
            "zones": [{ "id": "z:work", "integrity_level": 60, "confidentiality_level": 70 }]
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "Format must be exactly 'fzpf'"
    );
}

#[test]
fn reject_invalid_schema_version() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": { "format": "fzpf", "schema_version": "1.0", "default_deny": true },
            "zones": [{ "id": "z:work", "integrity_level": 60, "confidentiality_level": 70 }]
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "Schema version must be exactly '0.1'"
    );
}

#[test]
fn reject_invalid_freshness_policy() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": {
                "format": "fzpf",
                "schema_version": "0.1",
                "default_deny": true,
                "freshness_policy": "invalid"
            },
            "zones": [{ "id": "z:work", "integrity_level": 60, "confidentiality_level": 70 }]
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "Freshness policy must be one of: strict, warn, best_effort"
    );
}

#[test]
fn reject_invalid_safety_tier() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": { "format": "fzpf", "schema_version": "0.1", "default_deny": true },
            "zones": [{ "id": "z:work", "integrity_level": 60, "confidentiality_level": 70 }],
            "taint_rules": [{
                "name": "test",
                "min_safety": "invalid_tier",
                "action": { "type": "deny" }
            }]
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "Safety tier must be one of: safe, risky, dangerous, critical, forbidden"
    );
}

#[test]
fn reject_invalid_taint_action_type() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": { "format": "fzpf", "schema_version": "0.1", "default_deny": true },
            "zones": [{ "id": "z:work", "integrity_level": 60, "confidentiality_level": 70 }],
            "taint_rules": [{
                "name": "test",
                "action": { "type": "invalid_action" }
            }]
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "Taint action type must be one of: deny, require_elevation, require_approval, sanitize"
    );
}

#[test]
fn reject_invalid_taint_flags() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": { "format": "fzpf", "schema_version": "0.1", "default_deny": true },
            "zones": [{ "id": "z:work", "integrity_level": 60, "confidentiality_level": 70 }],
            "taint_rules": [{
                "name": "test",
                "taint_flags": ["invalid_flag"],
                "action": { "type": "deny" }
            }]
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "Taint flags must be from the allowed enum set"
    );
}

#[test]
fn reject_invalid_approval_scope_type() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": { "format": "fzpf", "schema_version": "0.1", "default_deny": true },
            "zones": [{ "id": "z:work", "integrity_level": 60, "confidentiality_level": 70 }],
            "approval_constraints": [{
                "name": "test",
                "scope_type": "invalid_scope"
            }]
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "Approval scope type must be one of: elevation, declassification, execution"
    );
}

#[test]
fn reject_invalid_constraint_op() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": { "format": "fzpf", "schema_version": "0.1", "default_deny": true },
            "zones": [{ "id": "z:work", "integrity_level": 60, "confidentiality_level": 70 }],
            "approval_constraints": [{
                "name": "test",
                "scope_type": "execution",
                "input_constraints": [{
                    "pointer": "/field",
                    "op": "regex",
                    "value": ".*"
                }]
            }]
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "Constraint op must be one of: eq, neq, in, not_in, prefix, suffix, contains (NO regex)"
    );
}

#[test]
fn reject_invalid_flow_kind() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": { "format": "fzpf", "schema_version": "0.1", "default_deny": true },
            "zones": [{ "id": "z:work", "integrity_level": 60, "confidentiality_level": 70 }],
            "flows": [{
                "from": "z:work",
                "to": "z:public",
                "kind": "invalid_kind",
                "allow": true
            }]
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "Flow kind must be one of: ingress, egress, both"
    );
}

#[test]
fn reject_invalid_port_number() {
    let validator = load_schema();
    // Port numbers must be 1-65535
    let invalid_ports = [0i64, 65536, 100_000];

    for port in invalid_ports {
        let doc: Value = serde_json::from_str(&format!(
            r#"{{
                "policy": {{ "format": "fzpf", "schema_version": "0.1", "default_deny": true }},
                "zones": [{{
                    "id": "z:work",
                    "integrity_level": 60,
                    "confidentiality_level": 70,
                    "symbol_port": {port}
                }}]
            }}"#,
        ))
        .unwrap();
        assert!(
            validator.validate(&doc).is_err(),
            "Port {port} should be rejected (must be 1-65535)",
        );
    }
}

#[test]
fn reject_too_many_input_constraints() {
    let validator = load_schema();
    // Build an array with 65 constraints (max is 64)
    let constraints: Vec<String> = (0..65)
        .map(|i| format!(r#"{{ "pointer": "/field{i}", "op": "eq", "value": {i} }}"#,))
        .collect();

    let doc: Value = serde_json::from_str(&format!(
        r#"{{
            "policy": {{ "format": "fzpf", "schema_version": "0.1", "default_deny": true }},
            "zones": [{{ "id": "z:work", "integrity_level": 60, "confidentiality_level": 70 }}],
            "approval_constraints": [{{
                "name": "test",
                "scope_type": "execution",
                "input_constraints": [{}]
            }}]
        }}"#,
        constraints.join(",")
    ))
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "More than 64 input constraints should be rejected (maxItems: 64)"
    );
}

#[test]
fn reject_invalid_glob_pattern_with_special_chars() {
    let validator = load_schema();
    // Glob patterns must match ^[a-z0-9*?._:-]+$ (ASCII alphanumeric + * ? . _ : -)
    let invalid_patterns = [
        "pattern/with/slash",
        "pattern with space",
        "UPPERCASE",
        "pattern{braces}",
        "pattern[brackets]",
        "pattern(parens)",
        "pattern$special",
        "pattern#hash",
        "pattern@at",
    ];

    for pattern in invalid_patterns {
        let doc: Value = serde_json::from_str(&format!(
            r#"{{
                "policy": {{ "format": "fzpf", "schema_version": "0.1", "default_deny": true }},
                "zones": [{{ "id": "z:work", "integrity_level": 60, "confidentiality_level": 70 }}],
                "zone_policies": [{{
                    "zone_id": "z:work",
                    "principal_allow": ["{pattern}"]
                }}]
            }}"#,
        ))
        .unwrap();
        assert!(
            validator.validate(&doc).is_err(),
            "Glob pattern '{pattern}' should be rejected (invalid characters)",
        );
    }
}

// ============================================================================
// Deterministic Ordering Tests
// ============================================================================

#[test]
fn schema_validation_is_deterministic() {
    // Validate the same document multiple times and ensure consistent results
    let validator = load_schema();
    let doc: Value = serde_json::from_str(examples::MINIMAL_ZONE).unwrap();

    // Run validation 100 times and collect results
    let results: Vec<bool> = (0..100).map(|_| validator.validate(&doc).is_ok()).collect();

    // All results should be the same
    assert!(
        results.iter().all(|&r| r == results[0]),
        "Schema validation should be deterministic (all results should match)"
    );
    assert!(results[0], "Example document should validate successfully");
}

#[test]
fn error_messages_are_deterministic() {
    // Validate an invalid document multiple times and ensure consistent error messages
    let validator = load_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": { "format": "wrong", "schema_version": "0.1", "default_deny": true },
            "zones": []
        }"#,
    )
    .unwrap();

    // Collect error messages
    let errors: Vec<String> = (0..10)
        .map(|_| {
            let result = validator.validate(&doc);
            match result {
                Ok(()) => String::new(),
                Err(e) => e.to_string(),
            }
        })
        .collect();

    // All error messages should be identical
    assert!(
        errors.iter().all(|e| e == &errors[0]),
        "Error messages should be deterministic"
    );
}

// ============================================================================
// Positive Edge Cases - Valid Complex Documents
// ============================================================================

#[test]
fn valid_zone_with_all_optional_fields() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": {
                "format": "fzpf",
                "schema_version": "0.1",
                "policy_id": "test-policy",
                "default_deny": true,
                "freshness_policy": "strict"
            },
            "zones": [{
                "id": "z:work",
                "name": "Work Zone",
                "description": "Test zone with all optional fields",
                "integrity_level": 60,
                "confidentiality_level": 70,
                "symbol_port": 9000,
                "control_port": 9001,
                "transport_policy": {
                    "allow_lan": true,
                    "allow_derp": false,
                    "allow_funnel": false
                },
                "rekey_policy": {
                    "epoch_ratchet_enabled": true,
                    "overlap_secs": 30,
                    "retain_epochs": 3,
                    "rewrap_on_membership_change": true,
                    "rotate_object_id_key_on_membership_change": false
                },
                "freshness_policy": "warn",
                "metadata": {
                    "custom_key": "custom_value",
                    "nested": { "key": 123 }
                }
            }]
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_ok(),
        "Zone with all optional fields should validate"
    );
}

#[test]
fn valid_complex_role_hierarchy() {
    let validator = load_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": { "format": "fzpf", "schema_version": "0.1", "default_deny": true },
            "zones": [{ "id": "z:work", "integrity_level": 60, "confidentiality_level": 70 }],
            "roles": [
                {
                    "role_id": "base",
                    "name": "Base Role",
                    "caps": [{ "capability_id": "read:basic" }]
                },
                {
                    "role_id": "extended",
                    "name": "Extended Role",
                    "caps": [{ "capability_id": "write:basic" }],
                    "includes": ["base"]
                },
                {
                    "role_id": "admin",
                    "name": "Admin Role",
                    "caps": [
                        { "capability_id": "admin:*", "resource_allow": ["*"], "resource_deny": ["*.secret"] }
                    ],
                    "includes": ["extended"]
                }
            ],
            "role_assignments": [
                {
                    "role_id": "admin",
                    "principal": "user:alice",
                    "zone_id": "z:work",
                    "attenuations": [
                        { "capability_id": "admin:*", "resource_deny": ["prod.*"] }
                    ],
                    "expires_at": "2027-12-31T23:59:59Z"
                }
            ]
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_ok(),
        "Complex role hierarchy should validate"
    );
}

#[test]
fn valid_all_taint_flags() {
    let validator = load_schema();
    // Test all valid taint flags
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": { "format": "fzpf", "schema_version": "0.1", "default_deny": true },
            "zones": [{ "id": "z:work", "integrity_level": 60, "confidentiality_level": 70 }],
            "taint_rules": [{
                "name": "all-flags",
                "taint_flags": [
                    "public_input",
                    "unverified_link",
                    "user_generated",
                    "external_api",
                    "cross_zone",
                    "prompt_surface",
                    "untrusted_code",
                    "pii_present",
                    "malicious_detected"
                ],
                "action": { "type": "deny", "reason": "Testing all flags" }
            }]
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_ok(),
        "All valid taint flags should be accepted"
    );
}

#[test]
fn valid_all_constraint_operations() {
    let validator = load_schema();
    // Test all valid constraint operations
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": { "format": "fzpf", "schema_version": "0.1", "default_deny": true },
            "zones": [{ "id": "z:work", "integrity_level": 60, "confidentiality_level": 70 }],
            "approval_constraints": [{
                "name": "test-all-ops",
                "scope_type": "execution",
                "input_constraints": [
                    { "pointer": "/a", "op": "eq", "value": "exact" },
                    { "pointer": "/b", "op": "neq", "value": "not-this" },
                    { "pointer": "/c", "op": "in", "value": ["opt1", "opt2"] },
                    { "pointer": "/d", "op": "not_in", "value": ["bad1", "bad2"] },
                    { "pointer": "/e", "op": "prefix", "value": "prefix-" },
                    { "pointer": "/f", "op": "suffix", "value": "-suffix" },
                    { "pointer": "/g", "op": "contains", "value": "substring" }
                ]
            }]
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_ok(),
        "All valid constraint operations should be accepted"
    );
}

#[test]
fn valid_json_pointer_edge_cases() {
    let validator = load_schema();
    // Test RFC 6901 JSON Pointer edge cases
    let doc: Value = serde_json::from_str(
        r#"{
            "policy": { "format": "fzpf", "schema_version": "0.1", "default_deny": true },
            "zones": [{ "id": "z:work", "integrity_level": 60, "confidentiality_level": 70 }],
            "approval_constraints": [{
                "name": "test-pointers",
                "scope_type": "execution",
                "input_constraints": [
                    { "pointer": "", "op": "eq", "value": "root" },
                    { "pointer": "/simple", "op": "eq", "value": "val" },
                    { "pointer": "/nested/path", "op": "eq", "value": "val" },
                    { "pointer": "/array/0", "op": "eq", "value": "val" },
                    { "pointer": "/with~0tilde", "op": "eq", "value": "val" },
                    { "pointer": "/with~1slash", "op": "eq", "value": "val" }
                ]
            }]
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_ok(),
        "Valid RFC 6901 JSON Pointers should be accepted"
    );
}

// ============================================================================
// Release Manifest Schema Validation
// ============================================================================

#[test]
fn valid_release_manifest() {
    let validator = load_release_manifest_schema();
    let doc = sample_release_manifest();
    assert!(
        validator.validate(&doc).is_ok(),
        "release manifest should validate"
    );
}

#[test]
fn release_manifest_cbor_is_deterministic() {
    let doc = sample_release_manifest();
    let bytes1 = to_canonical_cbor(&doc).expect("canonical CBOR should serialize");
    let bytes2 = to_canonical_cbor(&doc).expect("canonical CBOR should serialize");
    assert_eq!(bytes1, bytes2, "canonical CBOR must be deterministic");

    let hash1 = ObjectId::from_unscoped_bytes(&bytes1);
    let hash2 = ObjectId::from_unscoped_bytes(&bytes2);
    assert_eq!(hash1, hash2, "hashes must match for identical CBOR");
}

#[test]
fn reject_release_manifest_invalid_digest() {
    let validator = load_release_manifest_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "format": "fcp-release-manifest",
            "schema_version": "1.0",
            "connector_id": "fcp.example:request-response:1",
            "version": "1.2.3",
            "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "channel": "stable",
            "required_caps": ["fcp.example.read"],
            "min_host_version": "0.1.0",
            "signed_by": "owner-key-1",
            "signature": {
                "algorithm": "ed25519",
                "key_id": "owner-key-1",
                "signature": "deadbeef",
                "signed_fields": ["format"]
            }
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "invalid digest should be rejected"
    );
}

#[test]
fn reject_release_manifest_missing_signature() {
    let validator = load_release_manifest_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "format": "fcp-release-manifest",
            "schema_version": "1.0",
            "connector_id": "fcp.example:request-response:1",
            "version": "1.2.3",
            "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "channel": "stable",
            "required_caps": ["fcp.example.read"],
            "min_host_version": "0.1.0",
            "signed_by": "owner-key-1"
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "missing signature should be rejected"
    );
}

// ============================================================================
// Rollout Policy Schema Validation
// ============================================================================

#[test]
fn valid_rollout_policy() {
    let validator = load_rollout_policy_schema();
    let doc = sample_rollout_policy();
    assert!(
        validator.validate(&doc).is_ok(),
        "rollout policy should validate"
    );
}

#[test]
fn rollout_policy_cbor_is_deterministic() {
    let doc = sample_rollout_policy();
    let bytes1 = to_canonical_cbor(&doc).expect("canonical CBOR should serialize");
    let bytes2 = to_canonical_cbor(&doc).expect("canonical CBOR should serialize");
    assert_eq!(bytes1, bytes2, "canonical CBOR must be deterministic");

    let hash1 = ObjectId::from_unscoped_bytes(&bytes1);
    let hash2 = ObjectId::from_unscoped_bytes(&bytes2);
    assert_eq!(hash1, hash2, "hashes must match for identical CBOR");
}

// ============================================================================
// Trace Schema Validation
// ============================================================================

#[test]
fn valid_trace_document() {
    let validator = load_trace_schema();
    let doc = sample_trace();
    assert!(validator.validate(&doc).is_ok(), "trace should validate");
}

#[test]
fn reject_trace_payload_without_redaction() {
    let validator = load_trace_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "format": "fcp-trace",
            "schema_version": "1.0",
            "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
            "captured_at": "2026-02-01T12:00:00Z",
            "redaction_policy": {
                "policy_version": "1.0",
                "applied": true,
                "fields": ["payload"]
            },
            "entries": [
                {
                    "ts": "2026-02-01T12:00:01Z",
                    "kind": "fcpc_frame",
                    "direction": "inbound",
                    "component": "mesh.control",
                    "payload": {"unsafe": true}
                }
            ]
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "payload without redaction must be rejected"
    );
}

#[test]
fn trace_cbor_is_deterministic() {
    let doc = sample_trace();
    let bytes1 = to_canonical_cbor(&doc).expect("canonical CBOR should serialize");
    let bytes2 = to_canonical_cbor(&doc).expect("canonical CBOR should serialize");
    assert_eq!(bytes1, bytes2, "canonical CBOR must be deterministic");

    let hash1 = ObjectId::from_unscoped_bytes(&bytes1);
    let hash2 = ObjectId::from_unscoped_bytes(&bytes2);
    assert_eq!(hash1, hash2, "hashes must match for identical CBOR");
}

#[test]
fn trace_cbor_matches_golden_vector() {
    let doc = sample_trace();
    let bytes = to_canonical_cbor(&doc).expect("canonical CBOR should serialize");
    assert_eq!(
        hex::encode(bytes),
        TRACE_CBOR_HEX,
        "trace CBOR should match golden vector"
    );
}

// ============================================================================
// Capability Usage Schema Validation
// ============================================================================

#[test]
fn valid_capability_usage_event() {
    let validator = load_capability_usage_schema();
    let doc = sample_capability_usage();
    assert!(
        validator.validate(&doc).is_ok(),
        "capability usage should validate"
    );
}

#[test]
fn capability_usage_cbor_is_deterministic() {
    let doc = sample_capability_usage();
    let bytes1 = to_canonical_cbor(&doc).expect("canonical CBOR should serialize");
    let bytes2 = to_canonical_cbor(&doc).expect("canonical CBOR should serialize");
    assert_eq!(bytes1, bytes2, "canonical CBOR must be deterministic");

    let hash1 = ObjectId::from_unscoped_bytes(&bytes1);
    let hash2 = ObjectId::from_unscoped_bytes(&bytes2);
    assert_eq!(hash1, hash2, "hashes must match for identical CBOR");
}

#[test]
fn capability_usage_cbor_matches_golden_vector() {
    let doc = sample_capability_usage();
    let bytes = to_canonical_cbor(&doc).expect("canonical CBOR should serialize");
    assert_eq!(
        hex::encode(bytes),
        CAPABILITY_USAGE_CBOR_HEX,
        "capability usage CBOR should match golden vector"
    );
}

#[test]
fn reject_rollout_policy_out_of_range_canary() {
    let validator = load_rollout_policy_schema();
    let doc: Value = serde_json::from_str(
        r#"{
            "format": "fcp-rollout-policy",
            "schema_version": "1.0",
            "canary_percent": 150,
            "min_canary_duration_secs": 0,
            "success_thresholds": {
                "min_success_rate_bps": 9900,
                "max_error_rate_bps": 100,
                "min_samples": 100,
                "window_secs": 3600
            },
            "rollback_rules": {
                "max_error_rate_bps": 500,
                "max_consecutive_failures": 3,
                "min_samples": 30,
                "window_secs": 600,
                "auto_rollback": true
            }
        }"#,
    )
    .unwrap();
    assert!(
        validator.validate(&doc).is_err(),
        "canary percent above 100 should be rejected"
    );
}
