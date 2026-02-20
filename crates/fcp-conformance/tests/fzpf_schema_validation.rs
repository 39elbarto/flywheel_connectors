//! FZPF v0.1 JSON Schema validation tests.
//!
//! This test module validates the FZPF (Flywheel Zone Policy Format) JSON schema
//! against example policy documents. It includes:
//! - Positive tests: Valid policy documents that should pass validation
//! - Negative tests: Invalid documents that should be rejected (fail-closed)
//!
//! NORMATIVE: The schema enforces fail-closed validation - unknown/extra fields
//! are rejected.

use jsonschema::Validator;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("schemas")
        .join("FZPF_v0.1.schema.json")
}

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("schemas")
        .join("examples")
}

fn invalid_examples_dir() -> PathBuf {
    examples_dir().join("invalid")
}

fn load_schema() -> Value {
    let schema_content =
        fs::read_to_string(schema_path()).expect("Failed to read FZPF schema file");
    serde_json::from_str(&schema_content).expect("Failed to parse FZPF schema JSON")
}

fn create_validator() -> Validator {
    let schema = load_schema();
    Validator::new(&schema).expect("Failed to create JSON schema validator")
}

/// Helper to validate a JSON file against the FZPF schema
fn validate_file(validator: &Validator, path: &PathBuf) -> Result<(), Vec<String>> {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read file {}: {e}", path.display()));
    let instance: Value = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse JSON in {}: {e}", path.display()));

    let result = validator.validate(&instance);
    if result.is_ok() {
        Ok(())
    } else {
        let errors: Vec<String> = validator
            .iter_errors(&instance)
            .map(|e| format!("{} at {}", e, e.instance_path()))
            .collect();
        Err(errors)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Positive Tests (Valid Documents)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_valid_minimal_zone() {
    let validator = create_validator();
    let path = examples_dir().join("minimal_zone.json");
    let result = validate_file(&validator, &path);
    assert!(
        result.is_ok(),
        "minimal_zone.json should be valid, got errors: {:?}",
        result.err()
    );
}

#[test]
fn test_valid_role_bundles() {
    let validator = create_validator();
    let path = examples_dir().join("role_bundles.json");
    let result = validate_file(&validator, &path);
    assert!(
        result.is_ok(),
        "role_bundles.json should be valid, got errors: {:?}",
        result.err()
    );
}

#[test]
fn test_valid_transport_restrictions() {
    let validator = create_validator();
    let path = examples_dir().join("transport_restrictions.json");
    let result = validate_file(&validator, &path);
    assert!(
        result.is_ok(),
        "transport_restrictions.json should be valid, got errors: {:?}",
        result.err()
    );
}

#[test]
fn test_valid_freshness_policy() {
    let validator = create_validator();
    let path = examples_dir().join("freshness_policy.json");
    let result = validate_file(&validator, &path);
    assert!(
        result.is_ok(),
        "freshness_policy.json should be valid, got errors: {:?}",
        result.err()
    );
}

#[test]
fn test_valid_taint_approvals() {
    let validator = create_validator();
    let path = examples_dir().join("taint_approvals.json");
    let result = validate_file(&validator, &path);
    assert!(
        result.is_ok(),
        "taint_approvals.json should be valid, got errors: {:?}",
        result.err()
    );
}

#[test]
fn test_valid_comprehensive() {
    let validator = create_validator();
    let path = examples_dir().join("comprehensive.json");
    let result = validate_file(&validator, &path);
    assert!(
        result.is_ok(),
        "comprehensive.json should be valid, got errors: {:?}",
        result.err()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Negative Tests (Invalid Documents - Must Be Rejected)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_invalid_regex_pattern() {
    let validator = create_validator();
    let path = invalid_examples_dir().join("regex_pattern.json");
    let result = validate_file(&validator, &path);
    assert!(
        result.is_err(),
        "regex_pattern.json should be INVALID (regex patterns forbidden)"
    );
}

#[test]
fn test_invalid_jsonpath_constraint() {
    let validator = create_validator();
    let path = invalid_examples_dir().join("jsonpath_constraint.json");
    let result = validate_file(&validator, &path);
    assert!(
        result.is_err(),
        "jsonpath_constraint.json should be INVALID (JSONPath forbidden, use JSON Pointer)"
    );
}

#[test]
fn test_invalid_unknown_fields() {
    let validator = create_validator();
    let path = invalid_examples_dir().join("unknown_fields.json");
    let result = validate_file(&validator, &path);
    assert!(
        result.is_err(),
        "unknown_fields.json should be INVALID (unknown fields rejected, fail-closed)"
    );
}

#[test]
fn test_invalid_zone_id() {
    let validator = create_validator();
    let path = invalid_examples_dir().join("invalid_zone_id.json");
    let result = validate_file(&validator, &path);
    assert!(
        result.is_err(),
        "invalid_zone_id.json should be INVALID (zone ID must match ^z:[a-z][a-z0-9_-]*$)"
    );
}

#[test]
fn test_invalid_integrity_range() {
    let validator = create_validator();
    let path = invalid_examples_dir().join("invalid_integrity_range.json");
    let result = validate_file(&validator, &path);
    assert!(
        result.is_err(),
        "invalid_integrity_range.json should be INVALID (integrity level must be 0-100)"
    );
}

#[test]
fn test_invalid_missing_required() {
    let validator = create_validator();
    let path = invalid_examples_dir().join("missing_required.json");
    let result = validate_file(&validator, &path);
    assert!(
        result.is_err(),
        "missing_required.json should be INVALID (missing required 'policy' and 'zones' fields)"
    );
}

#[test]
fn test_invalid_safety_tier() {
    let validator = create_validator();
    let path = invalid_examples_dir().join("invalid_safety_tier.json");
    let result = validate_file(&validator, &path);
    assert!(
        result.is_err(),
        "invalid_safety_tier.json should be INVALID (invalid safety tier enum value)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Schema Structure Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_schema_is_valid_json() {
    let schema = load_schema();
    assert!(schema.is_object(), "Schema should be a JSON object");
    assert!(
        schema.get("$schema").is_some(),
        "Schema should have $schema field"
    );
    assert!(
        schema.get("$defs").is_some(),
        "Schema should have $defs for reusable definitions"
    );
}

#[test]
fn test_schema_has_required_defs() {
    let schema = load_schema();
    let defs = schema.get("$defs").expect("Schema should have $defs");

    let required_defs = [
        "zone_id",
        "zone_definition",
        "zone_policy",
        "role_definition",
        "role_assignment",
        "capability_grant",
        "flow_rule",
        "taint_rule",
        "approval_constraint",
        "input_constraint",
        "json_pointer",
        "glob_pattern",
        "resource_uri_pattern",
        "integrity_level",
        "confidentiality_level",
        "safety_tier",
        "freshness_policy",
        "transport_policy",
    ];

    for def_name in required_defs {
        assert!(
            defs.get(def_name).is_some(),
            "Schema should define '{def_name}' in $defs",
        );
    }
}

#[test]
fn test_schema_fail_closed_enforcement() {
    let schema = load_schema();

    // Top-level should have additionalProperties: false
    let additional = schema.get("additionalProperties");
    assert_eq!(
        additional,
        Some(&Value::Bool(false)),
        "Top-level should have additionalProperties: false for fail-closed validation"
    );
}

#[test]
fn test_schema_normative_constraints() {
    let schema = load_schema();
    let defs = schema.get("$defs").unwrap();

    // zone_id should have pattern constraint
    let zone_id = defs.get("zone_id").unwrap();
    assert!(
        zone_id.get("pattern").is_some(),
        "zone_id should have pattern constraint (NORMATIVE)"
    );

    // json_pointer should have pattern constraint (RFC 6901)
    let json_pointer = defs.get("json_pointer").unwrap();
    assert!(
        json_pointer.get("pattern").is_some(),
        "json_pointer should have pattern constraint for RFC 6901"
    );

    // glob_pattern should have pattern constraint (no regex)
    let glob_pattern = defs.get("glob_pattern").unwrap();
    assert!(
        glob_pattern.get("pattern").is_some(),
        "glob_pattern should have pattern constraint to forbid regex"
    );

    // integrity_level should have min/max constraints
    let integrity = defs.get("integrity_level").unwrap();
    assert_eq!(
        integrity.get("minimum"),
        Some(&Value::Number(0.into())),
        "integrity_level should have minimum: 0"
    );
    assert_eq!(
        integrity.get("maximum"),
        Some(&Value::Number(100.into())),
        "integrity_level should have maximum: 100"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic Validation Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_validation_is_deterministic() {
    let validator = create_validator();
    let path = examples_dir().join("comprehensive.json");

    // Run validation multiple times - should always produce same result
    let results: Vec<_> = (0..5).map(|_| validate_file(&validator, &path)).collect();

    for (i, result) in results.iter().enumerate() {
        assert!(result.is_ok(), "Validation run {} should succeed", i + 1);
    }
}

#[test]
fn test_error_messages_are_stable() {
    let validator = create_validator();
    let path = invalid_examples_dir().join("invalid_zone_id.json");

    // Run validation multiple times - error messages should be consistent
    let errors: Vec<Vec<String>> = (0..3)
        .map(|_| validate_file(&validator, &path).err().unwrap_or_default())
        .collect();

    // All error sets should be identical
    for (i, error_set) in errors.iter().enumerate().skip(1) {
        assert_eq!(
            &errors[0], error_set,
            "Error messages should be deterministic (run 0 vs run {i})",
        );
    }
}
