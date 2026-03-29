//! Supply-chain schema validation tests with structured JSONL logging.

use std::time::Instant;

use chrono::Utc;
use fcp_conformance::schemas::{validate_sbom, validate_supply_chain_attestation};
use fcp_conformance::LogCapture;
use serde_json::{Value, json};
use uuid::Uuid;

const MODULE: &str = "fcp-conformance::supply_chain_schema";

fn elapsed_ms(start: &Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn emit_log(
    capture: &LogCapture,
    test_name: &str,
    schema_id: &str,
    vector_id: &str,
    result: &str,
    duration_ms: u64,
    details: Option<Value>,
) {
    let mut entry = json!({
        "timestamp": Utc::now().to_rfc3339(),
        "log_version": "v2",
        "test_name": test_name,
        "module": MODULE,
        "phase": "validate",
        "correlation_id": Uuid::new_v4().to_string(),
        "result": result,
        "duration_ms": duration_ms,
        "assertions": {
            "passed": i32::from(result == "pass"),
            "failed": i32::from(result != "pass")
        },
        "details": {
            "test": test_name,
            "schema_id": schema_id,
            "vector_id": vector_id,
            "result": result,
            "duration_ms": duration_ms
        }
    });

    if let Some(extra) = details {
        entry["details"]["context"] = extra;
    }

    capture
        .push_value(&entry)
        .expect("failed to push log entry");
}

fn attestation_vector(vector_id: &str) -> Value {
    json!({
        "format": "fcp-supply-chain-attestation",
        "schema_version": "1.0",
        "subject_digest": "blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "predicate_type": "https://slsa.dev/provenance/v1",
        "builder_id": "builder://github/actions",
        "build_type": "https://slsa.dev/container-based-build/v1",
        "materials": [
            {
                "uri": "git+https://github.com/flywheel/connectors@refs/heads/main",
                "digest": "blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }
        ],
        "metadata": {
            "build_started_at": "2026-02-01T12:00:00Z",
            "build_finished_at": "2026-02-01T12:05:00Z",
            "invocation_id": format!("gh-run-{vector_id}")
        },
        "slsa_level": 3,
        "provenance_hash": "blake3-256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "trust_root": {
            "root_type": "sigstore",
            "root_id": "sigstore-public-good"
        },
        "builder_allowlist": ["builder://github/actions"],
        "signature": {
            "algorithm": "ed25519",
            "key_id": "owner-key-1",
            "signature": "deadbeef",
            "signed_fields": [
                "format",
                "schema_version",
                "subject_digest",
                "predicate_type",
                "builder_id",
                "build_type",
                "materials",
                "metadata",
                "slsa_level",
                "provenance_hash",
                "trust_root",
                "builder_allowlist"
            ]
        }
    })
}

fn sbom_vector(vector_id: &str) -> Value {
    json!({
        "format": "fcp-sbom",
        "schema_version": "1.0",
        "bom_format": "cyclonedx",
        "bom_version": "1.6",
        "tool_chain": ["cargo 1.86.0-nightly", "fcp-cli package"],
        "components": [
            {
                "component_id": format!("connector-root-{vector_id}"),
                "name": "fcp-connector-openai",
                "version": "1.2.3",
                "hashes": [
                    "blake3-256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                ],
                "licenses": ["Apache-2.0"]
            },
            {
                "component_id": "dep-serde",
                "name": "serde",
                "version": "1.0.210",
                "hashes": ["sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],
                "licenses": ["MIT", "Apache-2.0"]
            }
        ],
        "dependencies": [
            {
                "component_id": format!("connector-root-{vector_id}"),
                "depends_on": ["dep-serde"]
            },
            {
                "component_id": "dep-serde",
                "depends_on": []
            }
        ],
        "trust_root": {
            "root_type": "sigstore",
            "root_id": "sigstore-public-good"
        },
        "signature": {
            "algorithm": "ed25519",
            "key_id": "owner-key-1",
            "signature": "cafebabe",
            "signed_fields": [
                "format",
                "schema_version",
                "bom_format",
                "bom_version",
                "tool_chain",
                "components",
                "dependencies",
                "trust_root"
            ]
        }
    })
}

#[test]
fn supply_chain_attestation_vector_validates_and_logs() {
    let capture = LogCapture::new();
    let start = Instant::now();
    let test_name = "supply_chain_attestation_vector_validates_and_logs";
    let schema_id = "fcp://schemas/supply-chain-attestation/v1";
    let vector_id = "attestation-valid-001";
    let vector = attestation_vector(vector_id);

    let validation = validate_supply_chain_attestation(&vector);
    assert!(
        validation.is_ok(),
        "expected attestation vector to validate"
    );

    emit_log(
        &capture,
        test_name,
        schema_id,
        vector_id,
        "pass",
        elapsed_ms(&start),
        None,
    );
    capture
        .validate_jsonl()
        .expect("schema log output must validate");
}

#[test]
fn sbom_vector_validates_and_logs() {
    let capture = LogCapture::new();
    let start = Instant::now();
    let test_name = "sbom_vector_validates_and_logs";
    let schema_id = "fcp://schemas/sbom/v1";
    let vector_id = "sbom-valid-001";
    let vector = sbom_vector(vector_id);

    let validation = validate_sbom(&vector);
    assert!(validation.is_ok(), "expected sbom vector to validate");

    emit_log(
        &capture,
        test_name,
        schema_id,
        vector_id,
        "pass",
        elapsed_ms(&start),
        None,
    );
    capture
        .validate_jsonl()
        .expect("schema log output must validate");
}

#[test]
fn invalid_attestation_vector_logs_failure_details() {
    let capture = LogCapture::new();
    let start = Instant::now();
    let test_name = "invalid_attestation_vector_logs_failure_details";
    let schema_id = "fcp://schemas/supply-chain-attestation/v1";
    let vector_id = "attestation-invalid-unknown-predicate";
    let mut vector = attestation_vector(vector_id);
    vector["predicate_type"] = json!("https://example.invalid/predicate");

    let validation = validate_supply_chain_attestation(&vector);
    let error = validation
        .expect_err("unknown predicate type should fail validation")
        .to_string();

    emit_log(
        &capture,
        test_name,
        schema_id,
        vector_id,
        "pass",
        elapsed_ms(&start),
        Some(json!({
            "validation_outcome": "expected_failure",
            "error": error
        })),
    );
    capture
        .validate_jsonl()
        .expect("schema log output must validate");
}
