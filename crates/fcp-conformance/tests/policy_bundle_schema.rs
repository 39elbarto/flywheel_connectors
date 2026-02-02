//! `PolicyBundle` schema validation tests with structured JSONL logging.

use std::time::Instant;

use chrono::Utc;
use fcp_conformance::schemas::validate_policy_bundle;
use fcp_testkit::LogCapture;
use serde_json::{Value, json};
use uuid::Uuid;

const MODULE: &str = "fcp-conformance::policy_bundle_schema";

fn elapsed_ms(start: &Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn emit_log(
    capture: &LogCapture,
    test_name: &str,
    correlation_id: &str,
    bundle_id: &str,
    result: &str,
    duration_ms: u64,
    details: Option<Value>,
) {
    let mut entry = json!({
        "timestamp": Utc::now().to_rfc3339(),
        "test_name": test_name,
        "module": MODULE,
        "phase": "validate",
        "correlation_id": correlation_id,
        "result": result,
        "duration_ms": duration_ms,
        "assertions": {
            "passed": i32::from(result == "pass"),
            "failed": i32::from(result != "pass"),
        },
        "bundle_id": bundle_id,
    });
    if let Some(extra) = details {
        entry["details"] = extra;
    }

    capture
        .push_value(&entry)
        .expect("failed to push log entry");
}

fn base_bundle(bundle_id: &str) -> Value {
    json!({
        "format": "fcp-policy-bundle",
        "schema_version": "1.0",
        "bundle_id": bundle_id,
        "zone_id": "z:work",
        "policy_seq": 1,
        "hash_algo": "blake3-256",
        "bundle_hash": "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "policies": [{
            "object_id": "obj-001",
            "schema_id": "fcp.core:ZonePolicy@1.0",
            "object_hash": "blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }],
        "signature": {
            "algorithm": "ed25519",
            "key_id": "key-001",
            "signature": "sig-data",
            "signed_fields": [
                "bundle_id",
                "zone_id",
                "policy_seq",
                "bundle_hash"
            ]
        }
    })
}

#[test]
fn policy_bundle_schema_accepts_minimal() {
    let capture = LogCapture::new();
    let correlation_id = Uuid::new_v4().to_string();
    let test_name = "policy_bundle_schema_accepts_minimal";
    let start = Instant::now();

    let bundle = base_bundle("bundle-minimal");
    let result = validate_policy_bundle(&bundle);
    assert!(result.is_ok(), "expected policy bundle to be valid");

    emit_log(
        &capture,
        test_name,
        &correlation_id,
        "bundle-minimal",
        "pass",
        elapsed_ms(&start),
        None,
    );

    capture
        .validate_jsonl()
        .expect("log schema validation failed");
}

#[test]
fn policy_bundle_schema_rejects_bad_hash() {
    let capture = LogCapture::new();
    let correlation_id = Uuid::new_v4().to_string();
    let test_name = "policy_bundle_schema_rejects_bad_hash";
    let start = Instant::now();

    let mut bundle = base_bundle("bundle-bad-hash");
    bundle["bundle_hash"] = json!("sha256:deadbeef");

    let result = validate_policy_bundle(&bundle);
    assert!(result.is_err(), "expected invalid policy bundle hash");

    emit_log(
        &capture,
        test_name,
        &correlation_id,
        "bundle-bad-hash",
        "pass",
        elapsed_ms(&start),
        Some(json!({"error": result.err().unwrap().to_string()})),
    );

    capture
        .validate_jsonl()
        .expect("log schema validation failed");
}
