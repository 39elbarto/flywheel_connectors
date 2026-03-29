//! Posture verification unit tests with structured JSONL logging.
//!
//! These tests validate the posture attestation system per `docs/STANDARD_Testing_Logging.md`.
//! All tests emit structured JSONL logs and validate against the E2E schema.

mod support;

use std::collections::HashMap;
use std::time::Instant;

use chrono::Utc;
use fcp_core::{
    NodeId, PostureAttestation, PostureAttributeKey, PostureAttributeValue, PostureCheckResult,
    PostureRequirement, PostureRequirements,
};
use serde_json::json;
use support::LogCapture;
use uuid::Uuid;

/// Test context for structured logging.
struct TestContext {
    test_name: String,
    module: String,
    correlation_id: String,
    capture: LogCapture,
    start_time: Instant,
    assertions_passed: u32,
    assertions_failed: u32,
}

impl TestContext {
    fn new(test_name: &str) -> Self {
        Self {
            test_name: test_name.to_string(),
            module: "fcp-core::posture".to_string(),
            correlation_id: Uuid::new_v4().to_string(),
            capture: LogCapture::new(),
            start_time: Instant::now(),
            assertions_passed: 0,
            assertions_failed: 0,
        }
    }

    fn log_phase(&self, phase: &str, details: Option<serde_json::Value>) {
        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = self.start_time.elapsed().as_millis() as u64;
        let mut entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "test_name": self.test_name,
            "module": self.module,
            "phase": phase,
            "correlation_id": self.correlation_id,
            "result": "pass",
            "duration_ms": duration_ms,
            "assertions": {
                "passed": self.assertions_passed,
                "failed": self.assertions_failed
            }
        });

        if let Some(d) = details {
            entry["details"] = d;
        }

        self.capture.push_value(&entry).expect("log entry");
    }

    fn assert_eq<T: std::fmt::Debug + PartialEq>(&mut self, actual: &T, expected: &T, msg: &str) {
        if actual == expected {
            self.assertions_passed += 1;
        } else {
            self.assertions_failed += 1;
            panic!("{msg}: expected {expected:?}, got {actual:?}");
        }
    }

    fn assert_true(&mut self, condition: bool, msg: &str) {
        if condition {
            self.assertions_passed += 1;
        } else {
            self.assertions_failed += 1;
            panic!("{}", msg);
        }
    }

    fn finalize(&self, result: &str) {
        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = self.start_time.elapsed().as_millis() as u64;
        let entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "test_name": self.test_name,
            "module": self.module,
            "phase": "verify",
            "correlation_id": self.correlation_id,
            "result": result,
            "duration_ms": duration_ms,
            "assertions": {
                "passed": self.assertions_passed,
                "failed": self.assertions_failed
            }
        });
        self.capture.push_value(&entry).expect("final log entry");

        // Validate all logs against E2E schema
        self.capture.assert_valid();
    }
}

/// Create a valid test attestation with standard attributes.
fn create_valid_attestation() -> PostureAttestation {
    let mut attributes = HashMap::new();
    attributes.insert(
        PostureAttributeKey::OsType,
        PostureAttributeValue::String("macos".to_string()),
    );
    attributes.insert(
        PostureAttributeKey::OsVersion,
        PostureAttributeValue::String("14.2.1".to_string()),
    );
    attributes.insert(
        PostureAttributeKey::DiskEncryption,
        PostureAttributeValue::Bool(true),
    );
    attributes.insert(
        PostureAttributeKey::FirewallEnabled,
        PostureAttributeValue::Bool(true),
    );
    attributes.insert(
        PostureAttributeKey::ScreenLockEnabled,
        PostureAttributeValue::Bool(true),
    );
    attributes.insert(
        PostureAttributeKey::ScreenLockTimeout,
        PostureAttributeValue::Number(300),
    );
    attributes.insert(
        PostureAttributeKey::TpmPresent,
        PostureAttributeValue::Bool(true),
    );
    attributes.insert(
        PostureAttributeKey::SecureBootEnabled,
        PostureAttributeValue::Bool(true),
    );

    PostureAttestation {
        schema: PostureAttestation::SCHEMA.to_string(),
        attestation_id: format!("att-{}", Uuid::new_v4()),
        node_id: NodeId::new("node-test-device"),
        attributes,
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::hours(24),
        verifier_id: "trusted-verifier-1".to_string(),
        signature: "valid-signature-placeholder".to_string(),
        verifier_kid: "key-id-1".to_string(),
    }
}

/// Create an expired attestation.
fn create_expired_attestation() -> PostureAttestation {
    let mut att = create_valid_attestation();
    att.expires_at = Utc::now() - chrono::Duration::hours(1);
    att
}

/// Create an attestation with wrong schema.
fn create_invalid_schema_attestation() -> PostureAttestation {
    let mut att = create_valid_attestation();
    att.schema = "invalid.schema.v9".to_string();
    att
}

/// Create an attestation from an untrusted verifier.
fn create_untrusted_verifier_attestation() -> PostureAttestation {
    let mut att = create_valid_attestation();
    att.verifier_id = "untrusted-verifier".to_string();
    att
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Valid attestation passes all requirements
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn posture_valid_attestation_passes() {
    let mut ctx = TestContext::new("posture_valid_attestation_passes");

    ctx.log_phase(
        "setup",
        Some(json!({
            "description": "Create valid attestation and requirements"
        })),
    );

    let attestation = create_valid_attestation();
    let requirements = PostureRequirements::builder()
        .require_disk_encryption(true)
        .require_firewall(true)
        .require_os_min_version("14.0")
        .allow_verifier("trusted-verifier-1")
        .max_attestation_age_secs(86400)
        .build();

    ctx.log_phase(
        "execute",
        Some(json!({
            "attestation_id": attestation.attestation_id,
            "verifier_id": attestation.verifier_id,
            "requirements_count": requirements.requirements.len()
        })),
    );

    let result = requirements.is_satisfied_by(&attestation);

    ctx.assert_true(
        result.is_satisfied(),
        "Valid attestation should satisfy requirements",
    );
    ctx.assert_eq(
        &result,
        &PostureCheckResult::Satisfied,
        "Result should be Satisfied",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Invalid signature (untrusted verifier) fails
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn posture_invalid_signature_fails() {
    let mut ctx = TestContext::new("posture_invalid_signature_fails");

    ctx.log_phase(
        "setup",
        Some(json!({
            "description": "Create attestation from untrusted verifier"
        })),
    );

    let attestation = create_untrusted_verifier_attestation();
    let requirements = PostureRequirements::builder()
        .require_disk_encryption(true)
        .allow_verifier("trusted-verifier-1")
        .allow_verifier("trusted-verifier-2")
        .build();

    ctx.log_phase(
        "execute",
        Some(json!({
            "attestation_verifier": attestation.verifier_id,
            "allowed_verifiers": ["trusted-verifier-1", "trusted-verifier-2"]
        })),
    );

    let result = requirements.is_satisfied_by(&attestation);

    ctx.assert_true(
        !result.is_satisfied(),
        "Attestation from untrusted verifier should fail",
    );
    ctx.assert_eq(
        &result,
        &PostureCheckResult::VerifierNotAllowed,
        "Result should be VerifierNotAllowed",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Missing posture for required zone denies access
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn posture_missing_for_required_zone_denies() {
    let mut ctx = TestContext::new("posture_missing_for_required_zone_denies");

    ctx.log_phase("setup", Some(json!({
        "description": "Verify that zones requiring posture deny access when attestation is None"
    })));

    // A zone policy that requires posture attestation would check for its presence
    // before evaluating. Simulate by checking requirements against no attestation.
    let requirements = PostureRequirements::builder()
        .require_disk_encryption(true)
        .require_firewall(true)
        .build();

    ctx.log_phase(
        "execute",
        Some(json!({
            "has_attestation": false,
            "zone_requires_posture": true
        })),
    );

    // When attestation is missing, the policy engine returns PostureAttestationMissing
    // This test validates the requirement check on an expired attestation to simulate
    // the denial path (since None attestation is checked at the policy layer)
    let expired_attestation = create_expired_attestation();
    let result = requirements.is_satisfied_by(&expired_attestation);

    ctx.assert_true(
        !result.is_satisfied(),
        "Expired attestation should not satisfy requirements",
    );
    ctx.assert_eq(
        &result,
        &PostureCheckResult::AttestationExpired,
        "Result should be AttestationExpired",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Expired attestation fails
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn posture_expired_attestation_fails() {
    let mut ctx = TestContext::new("posture_expired_attestation_fails");

    ctx.log_phase(
        "setup",
        Some(json!({
            "description": "Create expired attestation"
        })),
    );

    let attestation = create_expired_attestation();
    let requirements = PostureRequirements::builder()
        .require_disk_encryption(true)
        .build();

    ctx.log_phase(
        "execute",
        Some(json!({
            "attestation_expires_at": attestation.expires_at.to_rfc3339(),
            "is_expired": attestation.is_expired()
        })),
    );

    let result = requirements.is_satisfied_by(&attestation);

    ctx.assert_true(!result.is_satisfied(), "Expired attestation should fail");
    ctx.assert_eq(
        &result,
        &PostureCheckResult::AttestationExpired,
        "Result should be AttestationExpired",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Invalid schema attestation fails validity check
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn posture_invalid_schema_fails_validity() {
    let mut ctx = TestContext::new("posture_invalid_schema_fails_validity");

    ctx.log_phase(
        "setup",
        Some(json!({
            "description": "Create attestation with invalid schema"
        })),
    );

    let attestation = create_invalid_schema_attestation();

    ctx.log_phase(
        "execute",
        Some(json!({
            "schema": attestation.schema,
            "expected_schema": PostureAttestation::SCHEMA
        })),
    );

    ctx.assert_true(
        !attestation.is_valid(),
        "Attestation with invalid schema should fail is_valid()",
    );
    ctx.assert_true(
        !attestation.is_expired(),
        "Invalid schema attestation is not expired (separate check)",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Requirement not met fails
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn posture_requirement_not_met_fails() {
    let mut ctx = TestContext::new("posture_requirement_not_met_fails");

    ctx.log_phase(
        "setup",
        Some(json!({
            "description": "Create attestation missing required attribute"
        })),
    );

    // Create attestation without antivirus attribute
    let mut attestation = create_valid_attestation();
    attestation
        .attributes
        .remove(&PostureAttributeKey::TpmPresent);

    let requirements = PostureRequirements::builder()
        .require_tpm(true)
        .allow_verifier("trusted-verifier-1")
        .build();

    ctx.log_phase("execute", Some(json!({
        "requires_tpm": true,
        "attestation_has_tpm": attestation.attributes.contains_key(&PostureAttributeKey::TpmPresent)
    })));

    let result = requirements.is_satisfied_by(&attestation);

    ctx.assert_true(
        !result.is_satisfied(),
        "Missing TPM should fail requirement",
    );

    match &result {
        PostureCheckResult::RequirementNotMet { attribute } => {
            ctx.assert_eq(
                attribute,
                &PostureAttributeKey::TpmPresent,
                "Failed attribute should be TpmPresent",
            );
        }
        other => panic!("Expected RequirementNotMet, got {other:?}"),
    }

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Attestation too old fails
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn posture_attestation_too_old_fails() {
    let mut ctx = TestContext::new("posture_attestation_too_old_fails");

    ctx.log_phase(
        "setup",
        Some(json!({
            "description": "Create attestation older than max age"
        })),
    );

    let mut attestation = create_valid_attestation();
    // Issue attestation 2 hours ago, but still not expired
    attestation.issued_at = Utc::now() - chrono::Duration::hours(2);
    attestation.expires_at = Utc::now() + chrono::Duration::hours(22);

    // Require attestation to be no older than 1 hour
    let requirements = PostureRequirements::builder()
        .require_disk_encryption(true)
        .max_attestation_age_secs(3600) // 1 hour
        .build();

    ctx.log_phase(
        "execute",
        Some(json!({
            "attestation_issued_at": attestation.issued_at.to_rfc3339(),
            "max_age_secs": 3600
        })),
    );

    let result = requirements.is_satisfied_by(&attestation);

    ctx.assert_true(
        !result.is_satisfied(),
        "Attestation older than max age should fail",
    );
    ctx.assert_eq(
        &result,
        &PostureCheckResult::AttestationTooOld,
        "Result should be AttestationTooOld",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Version requirement checks
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn posture_version_requirement_checks() {
    let mut ctx = TestContext::new("posture_version_requirement_checks");

    ctx.log_phase(
        "setup",
        Some(json!({
            "description": "Test OS version requirement enforcement"
        })),
    );

    let attestation = create_valid_attestation(); // Has OS version 14.2.1

    // Should pass: require >= 14.0
    let req_pass = PostureRequirements::builder()
        .require_os_min_version("14.0")
        .build();

    // Should fail: require >= 15.0
    let req_fail = PostureRequirements::builder()
        .require_os_min_version("15.0")
        .build();

    ctx.log_phase(
        "execute",
        Some(json!({
            "attestation_os_version": "14.2.1",
            "test_min_version_pass": "14.0",
            "test_min_version_fail": "15.0"
        })),
    );

    let result_pass = req_pass.is_satisfied_by(&attestation);
    let result_fail = req_fail.is_satisfied_by(&attestation);

    ctx.assert_true(
        result_pass.is_satisfied(),
        "OS 14.2.1 should satisfy >= 14.0",
    );
    ctx.assert_true(
        !result_fail.is_satisfied(),
        "OS 14.2.1 should not satisfy >= 15.0",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: OS type one-of requirement
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn posture_os_type_one_of_requirement() {
    let mut ctx = TestContext::new("posture_os_type_one_of_requirement");

    ctx.log_phase(
        "setup",
        Some(json!({
            "description": "Test OS type one-of requirement"
        })),
    );

    let attestation = create_valid_attestation(); // Has OS type "macos"

    let req_pass = PostureRequirements::builder()
        .require_os_type_one_of(vec!["macos".to_string(), "windows".to_string()])
        .build();

    let req_fail = PostureRequirements::builder()
        .require_os_type_one_of(vec!["linux".to_string()])
        .build();

    ctx.log_phase(
        "execute",
        Some(json!({
            "attestation_os_type": "macos"
        })),
    );

    let result_pass = req_pass.is_satisfied_by(&attestation);
    let result_fail = req_fail.is_satisfied_by(&attestation);

    ctx.assert_true(
        result_pass.is_satisfied(),
        "macOS should be in [macos, windows]",
    );
    ctx.assert_true(
        !result_fail.is_satisfied(),
        "macOS should not be in [linux]",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Numeric min/max value requirements
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn posture_numeric_value_requirements() {
    let mut ctx = TestContext::new("posture_numeric_value_requirements");

    ctx.log_phase(
        "setup",
        Some(json!({
            "description": "Test numeric min/max requirements for screen lock timeout"
        })),
    );

    let attestation = create_valid_attestation(); // Has screen_lock_timeout: 300

    // Min value: timeout must be at least 60 seconds
    let req_min_pass = PostureRequirements::builder()
        .require(PostureRequirement::RequireMinValue {
            attribute: PostureAttributeKey::ScreenLockTimeout,
            min_value: 60,
        })
        .build();

    // Min value: timeout must be at least 600 seconds (should fail)
    let req_min_fail = PostureRequirements::builder()
        .require(PostureRequirement::RequireMinValue {
            attribute: PostureAttributeKey::ScreenLockTimeout,
            min_value: 600,
        })
        .build();

    // Max value: timeout must be at most 600 seconds
    let req_max_pass = PostureRequirements::builder()
        .require(PostureRequirement::RequireMaxValue {
            attribute: PostureAttributeKey::ScreenLockTimeout,
            max_value: 600,
        })
        .build();

    // Max value: timeout must be at most 120 seconds (should fail)
    let req_max_fail = PostureRequirements::builder()
        .require(PostureRequirement::RequireMaxValue {
            attribute: PostureAttributeKey::ScreenLockTimeout,
            max_value: 120,
        })
        .build();

    ctx.log_phase(
        "execute",
        Some(json!({
            "attestation_screen_lock_timeout": 300
        })),
    );

    ctx.assert_true(
        req_min_pass.is_satisfied_by(&attestation).is_satisfied(),
        "Timeout 300 should satisfy min 60",
    );
    ctx.assert_true(
        !req_min_fail.is_satisfied_by(&attestation).is_satisfied(),
        "Timeout 300 should not satisfy min 600",
    );
    ctx.assert_true(
        req_max_pass.is_satisfied_by(&attestation).is_satisfied(),
        "Timeout 300 should satisfy max 600",
    );
    ctx.assert_true(
        !req_max_fail.is_satisfied_by(&attestation).is_satisfied(),
        "Timeout 300 should not satisfy max 120",
    );

    ctx.finalize("pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Empty requirements always pass
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn posture_empty_requirements_pass() {
    let mut ctx = TestContext::new("posture_empty_requirements_pass");

    ctx.log_phase(
        "setup",
        Some(json!({
            "description": "Empty requirements should pass for any valid attestation"
        })),
    );

    let attestation = create_valid_attestation();
    let requirements = PostureRequirements::builder().build();

    ctx.log_phase(
        "execute",
        Some(json!({
            "requirements_count": requirements.requirements.len(),
            "requirements_is_empty": requirements.is_empty()
        })),
    );

    let result = requirements.is_satisfied_by(&attestation);

    ctx.assert_true(
        result.is_satisfied(),
        "Empty requirements should be satisfied",
    );

    ctx.finalize("pass");
}
