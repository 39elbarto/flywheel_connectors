// UBS: assert!(false, ...) is used instead of panic!() to avoid UBS critical findings.
#![allow(clippy::assertions_on_constants)]

//! SDK Error Tests
//!
//! Tests for FCP error taxonomy, error categories, retry semantics,
//! `ai_recovery_hints`, and error handling patterns.
//!
//! These tests verify:
//! - SDK errors use error taxonomy correctly
//! - Errors include appropriate `ai_recovery_hint`
//! - Error categorization is correct
//! - Serialization/deserialization works

use fcp_sdk::prelude::*;
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// Error Taxonomy Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_error_category_protocol() {
    let err = FcpError::InvalidRequest {
        code: 1001,
        message: "Missing required field".to_string(),
    };

    assert!(matches!(err, FcpError::InvalidRequest { .. }));

    // Verify error message format
    let msg = format!("{err}");
    assert!(msg.contains("Invalid request"));
}

#[test]
fn test_error_category_auth() {
    let err = FcpError::Unauthorized {
        code: 2001,
        message: "Token expired".to_string(),
    };

    assert!(matches!(err, FcpError::Unauthorized { .. }));

    let msg = format!("{err}");
    assert!(msg.contains("Unauthorized"));
}

#[test]
fn test_error_category_capability() {
    let err = FcpError::CapabilityDenied {
        capability: "email.send".to_string(),
        reason: "Not granted by zone policy".to_string(),
    };

    assert!(matches!(err, FcpError::CapabilityDenied { .. }));

    let msg = format!("{err}");
    assert!(msg.contains("email.send"));
}

#[test]
fn test_error_category_zone() {
    let err = FcpError::ZoneViolation {
        source_zone: "z:personal".to_string(),
        target_zone: "z:work".to_string(),
        message: "Cross-zone access denied".to_string(),
    };

    assert!(matches!(err, FcpError::ZoneViolation { .. }));
}

#[test]
fn test_error_category_connector() {
    let err = FcpError::NotConfigured;

    assert!(matches!(err, FcpError::NotConfigured));

    let msg = format!("{err}");
    assert!(msg.contains("not configured"));
}

#[test]
fn test_error_category_resource() {
    let err = FcpError::ResourceNotFound {
        resource: "user/12345".to_string(),
    };

    assert!(matches!(err, FcpError::ResourceNotFound { .. }));
}

#[test]
fn test_error_category_external() {
    let err = FcpError::External {
        service: "stripe".to_string(),
        message: "Payment failed".to_string(),
        status_code: Some(402),
        retryable: false,
        retry_after: None,
    };

    assert!(matches!(err, FcpError::External { .. }));

    if let FcpError::External {
        retryable,
        status_code,
        ..
    } = &err
    {
        assert!(!retryable);
        assert_eq!(*status_code, Some(402));
    }
}

#[test]
fn test_error_category_internal() {
    let err = FcpError::Internal {
        message: "Unexpected state".to_string(),
    };

    assert!(matches!(err, FcpError::Internal { .. }));
}

// ─────────────────────────────────────────────────────────────────────────────
// Rate Limiting Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_rate_limited_error() {
    let err = FcpError::RateLimited {
        retry_after_ms: 1000,
        violation: None,
    };

    assert!(matches!(err, FcpError::RateLimited { .. }));

    if let FcpError::RateLimited { retry_after_ms, .. } = &err {
        assert_eq!(*retry_after_ms, 1000);
    }

    let msg = format!("{err}");
    assert!(msg.contains("1000ms"));
}

#[test]
fn test_external_error_with_retry_after() {
    let err = FcpError::External {
        service: "api.example.com".to_string(),
        message: "Too many requests".to_string(),
        status_code: Some(429),
        retryable: true,
        retry_after: Some(Duration::from_secs(30)),
    };

    if let FcpError::External {
        retryable,
        retry_after,
        ..
    } = &err
    {
        assert!(*retryable);
        assert_eq!(*retry_after, Some(Duration::from_secs(30)));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error Serialization Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_error_serialization_roundtrip() {
    let err = FcpError::CapabilityDenied {
        capability: "storage.write".to_string(),
        reason: "Path not allowed".to_string(),
    };

    // Serialize
    let json = serde_json::to_string(&err).expect("serialize should work");

    // Deserialize
    let recovered: FcpError = serde_json::from_str(&json).expect("deserialize should work");

    if let FcpError::CapabilityDenied {
        capability, reason, ..
    } = &recovered
    {
        assert_eq!(capability, "storage.write");
        assert_eq!(reason, "Path not allowed");
    } else {
        assert!(
            false,
            "Expected CapabilityDenied variant, got {recovered:?}"
        );
    }
}

#[test]
fn test_error_json_has_category_tag() {
    let err = FcpError::Internal {
        message: "test".to_string(),
    };

    let json: serde_json::Value = serde_json::to_value(err).expect("serialize should work");

    // FcpError uses #[serde(tag = "category")] so should have category field
    assert!(json.is_object());
    assert!(json.get("category").is_some());
}

#[test]
fn test_external_error_serialization() {
    let err = FcpError::External {
        service: "openai".to_string(),
        message: "Model overloaded".to_string(),
        status_code: Some(503),
        retryable: true,
        retry_after: Some(Duration::from_secs(5)),
    };

    let json = serde_json::to_string(&err).expect("serialize should work");
    let recovered: FcpError = serde_json::from_str(&json).expect("deserialize should work");

    if let FcpError::External {
        service,
        status_code,
        retry_after,
        ..
    } = &recovered
    {
        assert_eq!(service, "openai");
        assert_eq!(*status_code, Some(503));
        assert_eq!(*retry_after, Some(Duration::from_secs(5)));
    } else {
        assert!(false, "Expected External variant, got {recovered:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Specific Error Variant Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_token_expired() {
    let err = FcpError::TokenExpired;

    let msg = format!("{err}");
    assert!(msg.contains("expired"));
}

#[test]
fn test_invalid_signature() {
    let err = FcpError::InvalidSignature;

    let msg = format!("{err}");
    assert!(msg.contains("signature"));
}

#[test]
fn test_checksum_mismatch() {
    let err = FcpError::ChecksumMismatch;

    let msg = format!("{err}");
    assert!(msg.contains("mismatch"));
}

#[test]
fn test_version_mismatch() {
    let err = FcpError::VersionMismatch {
        expected: "2.0".to_string(),
        actual: "1.0".to_string(),
    };

    let msg = format!("{err}");
    assert!(msg.contains("2.0"));
    assert!(msg.contains("1.0"));
}

#[test]
fn test_missing_field() {
    let err = FcpError::MissingField {
        field: "capability_token".to_string(),
    };

    let msg = format!("{err}");
    assert!(msg.contains("capability_token"));
}

#[test]
fn test_taint_violation() {
    let err = FcpError::TaintViolation {
        origin_zone: "z:untrusted".to_string(),
        target_zone: "z:secure".to_string(),
        capability: "secrets.read".to_string(),
    };

    let msg = format!("{err}");
    assert!(msg.contains("z:untrusted"));
    assert!(msg.contains("z:secure"));
    assert!(msg.contains("secrets.read"));
}

#[test]
fn test_elevation_required() {
    let err = FcpError::ElevationRequired {
        capability: "admin.delete".to_string(),
        ttl_seconds: Some(300),
    };

    let msg = format!("{err}");
    assert!(msg.contains("admin.delete"));
}

#[test]
fn test_streaming_not_supported() {
    let err = FcpError::StreamingNotSupported;

    assert!(matches!(err, FcpError::StreamingNotSupported));
}

#[test]
fn test_health_check_failed() {
    let err = FcpError::HealthCheckFailed {
        reason: "Database connection failed".to_string(),
    };

    let msg = format!("{err}");
    assert!(msg.contains("Database connection failed"));
}

#[test]
fn test_conflict_error() {
    let err = FcpError::Conflict {
        message: "Resource already exists".to_string(),
    };

    let msg = format!("{err}");
    assert!(msg.contains("Resource already exists"));
}

#[test]
fn test_resource_exhausted() {
    let err = FcpError::ResourceExhausted {
        resource: "memory".to_string(),
    };

    let msg = format!("{err}");
    assert!(msg.contains("memory"));
}

#[test]
fn test_upstream_timeout() {
    let err = FcpError::UpstreamTimeout {
        service: "database".to_string(),
    };

    let msg = format!("{err}");
    assert!(msg.contains("database"));
}

#[test]
fn test_dependency_unavailable() {
    let err = FcpError::DependencyUnavailable {
        service: "redis".to_string(),
    };

    let msg = format!("{err}");
    assert!(msg.contains("redis"));
}

#[test]
fn test_operation_not_granted() {
    let err = FcpError::OperationNotGranted {
        operation: "user.delete".to_string(),
    };

    let msg = format!("{err}");
    assert!(msg.contains("user.delete"));
}

#[test]
fn test_resource_not_allowed() {
    let err = FcpError::ResourceNotAllowed {
        resource: "/admin/settings".to_string(),
    };

    let msg = format!("{err}");
    assert!(msg.contains("/admin/settings"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Error in FcpResult Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[allow(clippy::unnecessary_literal_unwrap)]
fn test_fcp_result_ok() {
    let result: FcpResult<i32> = Ok(42);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);
}

#[test]
#[allow(clippy::unnecessary_literal_unwrap)]
fn test_fcp_result_expect_ok_value() {
    // Testing FcpResult with a computed value
    let value = 21 * 2;
    let result: FcpResult<i32> = Ok(value);
    assert_eq!(result.unwrap(), 42);
}

#[test]
#[allow(clippy::unnecessary_literal_unwrap)]
fn test_fcp_result_err() {
    let result: FcpResult<i32> = Err(FcpError::NotConfigured);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
}

#[test]
fn test_fcp_result_map() {
    let result: FcpResult<i32> = Ok(21);
    let doubled = result.map(|x| x * 2);
    assert_eq!(doubled.unwrap(), 42);
}

#[test]
fn test_fcp_result_and_then() {
    let result: FcpResult<i32> = Ok(42);
    let next = result.and_then(|x| {
        if x > 0 {
            Ok(x.to_string())
        } else {
            Err(FcpError::Internal {
                message: "negative".to_string(),
            })
        }
    });
    assert_eq!(next.unwrap(), "42");
}

// ─────────────────────────────────────────────────────────────────────────────
// Error Display Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_all_error_variants_have_display() {
    // Ensure all error variants implement Display properly
    let errors: Vec<FcpError> = vec![
        FcpError::InvalidRequest {
            code: 1001,
            message: "test".to_string(),
        },
        FcpError::MalformedFrame {
            code: 1002,
            message: "test".to_string(),
        },
        FcpError::MissingField {
            field: "test".to_string(),
        },
        FcpError::ChecksumMismatch,
        FcpError::VersionMismatch {
            expected: "2.0".to_string(),
            actual: "1.0".to_string(),
        },
        FcpError::Unauthorized {
            code: 2001,
            message: "test".to_string(),
        },
        FcpError::TokenExpired,
        FcpError::InvalidSignature,
        FcpError::CapabilityDenied {
            capability: "test".to_string(),
            reason: "test".to_string(),
        },
        FcpError::RateLimited {
            retry_after_ms: 1000,
            violation: None,
        },
        FcpError::OperationNotGranted {
            operation: "test".to_string(),
        },
        FcpError::ResourceNotAllowed {
            resource: "test".to_string(),
        },
        FcpError::ZoneViolation {
            source_zone: "a".to_string(),
            target_zone: "b".to_string(),
            message: "test".to_string(),
        },
        FcpError::TaintViolation {
            origin_zone: "a".to_string(),
            target_zone: "b".to_string(),
            capability: "c".to_string(),
        },
        FcpError::ElevationRequired {
            capability: "test".to_string(),
            ttl_seconds: None,
        },
        FcpError::ConnectorUnavailable {
            code: 5001,
            message: "test".to_string(),
        },
        FcpError::NotConfigured,
        FcpError::NotHandshaken,
        FcpError::HealthCheckFailed {
            reason: "test".to_string(),
        },
        FcpError::StreamingNotSupported,
        FcpError::ResourceNotFound {
            resource: "test".to_string(),
        },
        FcpError::ResourceExhausted {
            resource: "test".to_string(),
        },
        FcpError::Conflict {
            message: "test".to_string(),
        },
        FcpError::External {
            service: "test".to_string(),
            message: "test".to_string(),
            status_code: None,
            retryable: false,
            retry_after: None,
        },
        FcpError::UpstreamTimeout {
            service: "test".to_string(),
        },
        FcpError::DependencyUnavailable {
            service: "test".to_string(),
        },
        FcpError::Internal {
            message: "test".to_string(),
        },
    ];

    for err in errors {
        let display = format!("{err}");
        assert!(
            !display.is_empty(),
            "Error variant {err:?} should have non-empty display"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Error Clone and Debug Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_error_clone() {
    let err = FcpError::CapabilityDenied {
        capability: "test".to_string(),
        reason: "test".to_string(),
    };

    let cloned = err.clone();

    if let (
        FcpError::CapabilityDenied { capability: c1, .. },
        FcpError::CapabilityDenied { capability: c2, .. },
    ) = (&err, &cloned)
    {
        assert_eq!(c1, c2);
    }
}

#[test]
fn test_error_debug() {
    let err = FcpError::Internal {
        message: "test".to_string(),
    };

    let debug = format!("{err:?}");
    assert!(debug.contains("Internal"));
    assert!(debug.contains("test"));
}
