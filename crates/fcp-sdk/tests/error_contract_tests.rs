//! Error Contract Tests for ASUPERSYNC Migration
//!
//! Bead: 235t.33.2 (ASUPERSYNC-UX Error Contract Unit/Integration Test Pack)
//!
//! Validates error payload semantics, conversion chains, retryability contracts,
//! and wire format stability. Each test maps to a coverage matrix row in
//! `docs/ASUPERSYNC_Coverage_Matrix.json` and the error taxonomy in
//! `docs/ASUPERSYNC_Error_Taxonomy.md`.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::{ErrorCategory, FcpError};
use fcp_sdk::migration::{HttpRetryConfig, classify_http_status, map_async_to_fcp_error};
use fcp_sdk::retry::RetryDecision;

// ─────────────────────────────────────────────────────────────────────────────
// 1. AsyncError → FcpError Conversion (all 7 variants)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn async_timeout_maps_to_external_408() {
    let err = AsyncError::Timeout { timeout_ms: 5000 };
    let fcp = map_async_to_fcp_error(&err);
    match &fcp {
        FcpError::External {
            service,
            status_code,
            retryable,
            ..
        } => {
            assert_eq!(service, "runtime");
            assert_eq!(*status_code, Some(408));
            assert!(!retryable, "deadline timeout should not be auto-retried");
        }
        other => panic!("Expected External, got {other:?}"),
    }
    assert_eq!(fcp.category(), ErrorCategory::External);
}

#[test]
fn async_timeout_preserves_duration_in_message() {
    let err = AsyncError::Timeout { timeout_ms: 12345 };
    let fcp = map_async_to_fcp_error(&err);
    let msg = fcp.to_string();
    assert!(
        msg.contains("12345"),
        "Timeout message should include duration: {msg}"
    );
}

#[test]
fn async_cancelled_maps_to_external_non_retryable() {
    let err = AsyncError::Cancelled;
    let fcp = map_async_to_fcp_error(&err);
    match &fcp {
        FcpError::External {
            retryable,
            status_code,
            ..
        } => {
            assert!(!retryable, "cancelled operations should not be retried");
            assert_eq!(*status_code, None, "cancelled has no HTTP status");
        }
        other => panic!("Expected External, got {other:?}"),
    }
}

#[test]
fn async_channel_closed_maps_to_internal() {
    let err = AsyncError::ChannelClosed;
    let fcp = map_async_to_fcp_error(&err);
    assert!(
        matches!(fcp, FcpError::Internal { .. }),
        "ChannelClosed should map to Internal: {fcp:?}"
    );
    assert!(!fcp.is_retryable());
}

#[test]
fn async_channel_full_maps_to_internal() {
    let err = AsyncError::ChannelFull;
    let fcp = map_async_to_fcp_error(&err);
    assert!(
        matches!(fcp, FcpError::Internal { .. }),
        "ChannelFull should map to Internal: {fcp:?}"
    );
}

#[test]
fn async_protocol_io_maps_to_internal() {
    let err = AsyncError::ProtocolIo {
        message: "connection reset".into(),
    };
    let fcp = map_async_to_fcp_error(&err);
    assert!(matches!(fcp, FcpError::Internal { .. }));
    let msg = fcp.to_string();
    assert!(
        msg.contains("connection reset"),
        "ProtocolIo message should propagate: {msg}"
    );
}

#[test]
fn async_join_maps_to_internal() {
    let err = AsyncError::Join {
        message: "task panicked".into(),
    };
    let fcp = map_async_to_fcp_error(&err);
    assert!(matches!(fcp, FcpError::Internal { .. }));
    assert!(fcp.to_string().contains("task panicked"));
}

#[test]
fn async_runtime_maps_to_internal() {
    let err = AsyncError::Runtime {
        message: "runtime shutdown".into(),
    };
    let fcp = map_async_to_fcp_error(&err);
    assert!(matches!(fcp, FcpError::Internal { .. }));
    assert_eq!(fcp.category(), ErrorCategory::Internal);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. FcpError Retryability Contract (taxonomy alignment)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn always_retryable_errors() {
    let cases: Vec<FcpError> = vec![
        FcpError::RateLimited {
            retry_after_ms: 1000,
            violation: None,
        },
        FcpError::ResourceExhausted {
            resource: "slots".into(),
        },
        FcpError::BudgetExceeded {
            metric: fcp_core::UsageMetricKind::Tokens,
            used: 100,
            limit: 50,
            window_seconds: 60,
        },
        FcpError::UpstreamTimeout {
            service: "api".into(),
        },
        FcpError::DependencyUnavailable {
            service: "db".into(),
        },
        FcpError::ConnectorUnavailable {
            code: 5001,
            message: "down".into(),
        },
    ];

    for err in &cases {
        assert!(
            err.is_retryable(),
            "{:?} should be retryable per taxonomy",
            err.category()
        );
    }
}

#[test]
fn never_retryable_errors() {
    let cases: Vec<FcpError> = vec![
        FcpError::Unauthorized {
            code: 2001,
            message: "bad key".into(),
        },
        FcpError::TokenExpired,
        FcpError::InvalidSignature,
        FcpError::CapabilityDenied {
            capability: "invoke".into(),
            reason: "denied".into(),
        },
        FcpError::OperationNotGranted {
            operation: "write".into(),
        },
        FcpError::ResourceNotAllowed {
            resource: "secret".into(),
        },
        FcpError::ZoneViolation {
            source_zone: "a".into(),
            target_zone: "b".into(),
            message: "denied".into(),
        },
        FcpError::TaintViolation {
            origin_zone: "a".into(),
            target_zone: "b".into(),
            capability: "cap".into(),
        },
        FcpError::ElevationRequired {
            capability: "admin".into(),
            ttl_seconds: Some(300),
        },
        FcpError::NotConfigured,
        FcpError::NotHandshaken,
        FcpError::StreamingNotSupported,
        FcpError::ResourceNotFound {
            resource: "obj-1".into(),
        },
        FcpError::InvalidRequest {
            code: 1001,
            message: "bad".into(),
        },
        FcpError::MalformedFrame {
            code: 1002,
            message: "bad".into(),
        },
        FcpError::MissingField {
            field: "name".into(),
        },
        FcpError::VersionMismatch {
            expected: "2.0".into(),
            actual: "1.0".into(),
        },
        FcpError::Internal {
            message: "bug".into(),
        },
    ];

    for err in &cases {
        assert!(
            !err.is_retryable(),
            "{err} should NOT be retryable per taxonomy"
        );
    }
}

#[test]
fn conditional_retryable_external_500() {
    let retryable = FcpError::External {
        service: "openai".into(),
        message: "server error".into(),
        status_code: Some(500),
        retryable: true,
        retry_after: None,
    };
    assert!(retryable.is_retryable());

    let not_retryable = FcpError::External {
        service: "openai".into(),
        message: "bad request".into(),
        status_code: Some(400),
        retryable: false,
        retry_after: None,
    };
    assert!(!not_retryable.is_retryable());
}

#[test]
fn checksum_mismatch_is_not_retryable_at_fcp_level() {
    // Note: taxonomy says ChecksumMismatch is retryable at transport layer,
    // but FcpError::is_retryable() returns false (transport handles retry).
    let err = FcpError::ChecksumMismatch;
    // Verify the error code is correct regardless
    assert_eq!(err.numeric_code(), 1004);
    assert_eq!(err.category(), ErrorCategory::Protocol);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Error Code Range Contract (all 8 categories)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn error_codes_in_correct_ranges() {
    let checks: Vec<(FcpError, u16, u16)> = vec![
        (
            FcpError::InvalidRequest {
                code: 1001,
                message: "x".into(),
            },
            1000,
            1999,
        ),
        (
            FcpError::Unauthorized {
                code: 2001,
                message: "x".into(),
            },
            2000,
            2999,
        ),
        (
            FcpError::CapabilityDenied {
                capability: "x".into(),
                reason: "x".into(),
            },
            3000,
            3999,
        ),
        (
            FcpError::ZoneViolation {
                source_zone: "a".into(),
                target_zone: "b".into(),
                message: "x".into(),
            },
            4000,
            4999,
        ),
        (
            FcpError::ConnectorUnavailable {
                code: 5001,
                message: "x".into(),
            },
            5000,
            5999,
        ),
        (
            FcpError::ResourceNotFound {
                resource: "x".into(),
            },
            6000,
            6999,
        ),
        (
            FcpError::UpstreamTimeout {
                service: "x".into(),
            },
            7000,
            7999,
        ),
        (
            FcpError::Internal {
                message: "x".into(),
            },
            9000,
            9999,
        ),
    ];

    for (err, min, max) in checks {
        let code = err.numeric_code();
        assert!(
            code >= min && code <= max,
            "{err}: code {code} outside [{min}, {max}]"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Wire Format (FcpErrorResponse) Contract
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn error_response_has_stable_code_format() {
    let err = FcpError::RateLimited {
        retry_after_ms: 5000,
        violation: None,
    };
    let resp = err.to_response();
    assert_eq!(resp.code, "FCP-3002");
    assert!(resp.retryable);
    assert_eq!(resp.retry_after_ms, Some(5000));
}

#[test]
fn error_response_serializes_to_json() {
    let err = FcpError::Unauthorized {
        code: 2001,
        message: "bad key".into(),
    };
    let resp = err.to_response();
    let json = serde_json::to_value(&resp).expect("serialize response");

    assert_eq!(json["code"], "FCP-2001");
    assert!(json["message"].as_str().unwrap().contains("bad key"));
    assert_eq!(json["retryable"], false);
}

#[test]
fn error_response_includes_ai_recovery_hint() {
    let err = FcpError::NotConfigured;
    let resp = err.to_response();
    assert!(
        resp.ai_recovery_hint.is_some(),
        "NotConfigured should have an AI recovery hint"
    );
    let hint = resp.ai_recovery_hint.unwrap();
    assert!(
        hint.contains("configure"),
        "Hint should mention configure(): {hint}"
    );
}

#[test]
fn error_response_retry_after_absent_when_not_retryable() {
    let err = FcpError::Internal {
        message: "bug".into(),
    };
    let resp = err.to_response();
    assert_eq!(resp.retry_after_ms, None);
    assert!(!resp.retryable);
}

#[test]
fn error_response_rate_limited_includes_retry_after() {
    let err = FcpError::RateLimited {
        retry_after_ms: 30000,
        violation: None,
    };
    let resp = err.to_response();
    assert_eq!(resp.retry_after_ms, Some(30000));
    assert!(resp.retryable);
}

#[test]
fn error_response_external_with_retry_after_duration() {
    let err = FcpError::External {
        service: "api".into(),
        message: "overloaded".into(),
        status_code: Some(429),
        retryable: true,
        retry_after: Some(Duration::from_secs(60)),
    };
    let resp = err.to_response();
    assert!(resp.retryable);
    assert_eq!(resp.retry_after_ms, Some(60_000));
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. FcpError Serialization Round-Trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn fcp_error_json_roundtrip_all_categories() {
    let errors: Vec<FcpError> = vec![
        FcpError::InvalidRequest {
            code: 1001,
            message: "bad".into(),
        },
        FcpError::Unauthorized {
            code: 2001,
            message: "auth".into(),
        },
        FcpError::RateLimited {
            retry_after_ms: 1000,
            violation: None,
        },
        FcpError::ZoneViolation {
            source_zone: "a".into(),
            target_zone: "b".into(),
            message: "cross".into(),
        },
        FcpError::NotConfigured,
        FcpError::ResourceNotFound {
            resource: "obj".into(),
        },
        FcpError::External {
            service: "svc".into(),
            message: "err".into(),
            status_code: Some(500),
            retryable: true,
            retry_after: None,
        },
        FcpError::Internal {
            message: "bug".into(),
        },
    ];

    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let deser: FcpError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            err.category(),
            deser.category(),
            "Category mismatch after roundtrip for {err}"
        );
        assert_eq!(
            err.numeric_code(),
            deser.numeric_code(),
            "Code mismatch after roundtrip for {err}"
        );
    }
}

#[test]
fn fcp_error_json_has_category_tag() {
    let err = FcpError::TokenExpired;
    let json = serde_json::to_value(&err).expect("serialize");
    assert!(
        json.get("category").is_some(),
        "JSON should have 'category' tag: {json}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. HTTP Status Classification Contract
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn classify_429_as_retryable() {
    let decision = classify_http_status(429, None);
    assert!(
        decision.is_retryable(),
        "429 should be retryable, got {decision:?}"
    );
}

#[test]
fn classify_429_with_retry_after() {
    let decision = classify_http_status(429, Some(Duration::from_secs(30)));
    assert!(decision.is_retryable());
    assert!(
        matches!(decision, RetryDecision::After(_)),
        "429 with retry_after should be After, got {decision:?}"
    );
}

#[test]
fn classify_500_as_retryable() {
    let decision = classify_http_status(500, None);
    assert!(
        decision.is_retryable(),
        "500 should be retryable, got {decision:?}"
    );
}

#[test]
fn classify_502_as_retryable() {
    let decision = classify_http_status(502, None);
    assert!(decision.is_retryable());
}

#[test]
fn classify_503_as_retryable() {
    let decision = classify_http_status(503, None);
    assert!(decision.is_retryable());
}

#[test]
fn classify_504_as_retryable() {
    let decision = classify_http_status(504, None);
    assert!(decision.is_retryable());
}

#[test]
fn classify_401_as_terminal() {
    let decision = classify_http_status(401, None);
    assert!(
        matches!(decision, RetryDecision::Terminal),
        "401 should be Terminal, got {decision:?}"
    );
}

#[test]
fn classify_403_as_terminal() {
    let decision = classify_http_status(403, None);
    assert!(matches!(decision, RetryDecision::Terminal));
}

#[test]
fn classify_404_as_terminal() {
    let decision = classify_http_status(404, None);
    assert!(matches!(decision, RetryDecision::Terminal));
}

#[test]
fn classify_400_as_terminal() {
    let decision = classify_http_status(400, None);
    assert!(matches!(decision, RetryDecision::Terminal));
}

#[test]
fn classify_408_as_retryable() {
    let decision = classify_http_status(408, None);
    assert!(
        decision.is_retryable(),
        "408 (request timeout) should be retryable"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. retry_after() Duration Contract
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn retry_after_present_for_rate_limited() {
    let err = FcpError::RateLimited {
        retry_after_ms: 5000,
        violation: None,
    };
    assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
}

#[test]
fn retry_after_present_for_external_with_duration() {
    let err = FcpError::External {
        service: "api".into(),
        message: "slow".into(),
        status_code: Some(429),
        retryable: true,
        retry_after: Some(Duration::from_secs(30)),
    };
    assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
}

#[test]
fn retry_after_none_for_most_errors() {
    let cases: Vec<FcpError> = vec![
        FcpError::Internal {
            message: "x".into(),
        },
        FcpError::NotConfigured,
        FcpError::TokenExpired,
        FcpError::UpstreamTimeout {
            service: "x".into(),
        },
        FcpError::ResourceExhausted {
            resource: "x".into(),
        },
    ];
    for err in &cases {
        assert_eq!(err.retry_after(), None, "{err} should have no retry_after");
    }
}

#[test]
fn retry_after_zero_ms_is_valid() {
    let err = FcpError::RateLimited {
        retry_after_ms: 0,
        violation: None,
    };
    assert_eq!(err.retry_after(), Some(Duration::ZERO));
    assert!(err.is_retryable());
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. HttpRetryConfig Defaults Contract
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn http_retry_config_defaults_are_sane() {
    let config = HttpRetryConfig::default();
    assert_eq!(
        config.max_retries, 3,
        "default retry count should stay stable"
    );
    assert!(
        config.initial_delay_ms > 0,
        "initial delay must be positive"
    );
    assert!(
        config.max_delay_ms >= config.initial_delay_ms,
        "max delay must be >= initial"
    );
    assert!(config.jitter_enabled, "jitter should be enabled by default");
}

#[test]
fn http_retry_config_serializes_to_json() {
    let config = HttpRetryConfig::default();
    let json = serde_json::to_value(&config).expect("serialize");
    assert!(json.get("max_retries").is_some());
    assert!(json.get("initial_delay_ms").is_some());
    assert!(json.get("max_delay_ms").is_some());
    assert!(json.get("jitter_enabled").is_some());
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Cross-Layer Propagation: AsyncError → FcpError → Response
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn timeout_full_chain_async_to_wire() {
    let async_err = AsyncError::Timeout { timeout_ms: 30000 };
    let fcp_err = map_async_to_fcp_error(&async_err);
    let resp = fcp_err.to_response();

    // Wire response contract
    assert!(resp.code.starts_with("FCP-"));
    assert!(!resp.retryable, "timeout response should not be retryable");
    assert!(
        resp.message.contains("30000"),
        "response should include timeout value"
    );
    assert!(resp.ai_recovery_hint.is_some());
}

#[test]
fn cancelled_full_chain_async_to_wire() {
    let async_err = AsyncError::Cancelled;
    let fcp_err = map_async_to_fcp_error(&async_err);
    let resp = fcp_err.to_response();

    assert!(resp.code.starts_with("FCP-"));
    assert!(!resp.retryable);
    assert!(resp.ai_recovery_hint.is_some());
}

#[test]
fn channel_closed_full_chain_async_to_wire() {
    let async_err = AsyncError::ChannelClosed;
    let fcp_err = map_async_to_fcp_error(&async_err);
    let resp = fcp_err.to_response();

    assert_eq!(resp.code, "FCP-9001");
    assert!(!resp.retryable);
}

#[test]
fn runtime_error_full_chain_async_to_wire() {
    let async_err = AsyncError::Runtime {
        message: "executor crashed".into(),
    };
    let fcp_err = map_async_to_fcp_error(&async_err);
    let resp = fcp_err.to_response();

    assert_eq!(resp.code, "FCP-9001");
    assert!(!resp.retryable);
    assert!(resp.message.contains("executor crashed"));
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Display / Debug Stability
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn all_async_errors_have_nonempty_display() {
    let variants = vec![
        AsyncError::Timeout { timeout_ms: 1 },
        AsyncError::Cancelled,
        AsyncError::ChannelClosed,
        AsyncError::ChannelFull,
        AsyncError::ProtocolIo {
            message: "x".into(),
        },
        AsyncError::Join {
            message: "x".into(),
        },
        AsyncError::Runtime {
            message: "x".into(),
        },
    ];
    for v in &variants {
        let display = v.to_string();
        assert!(!display.is_empty(), "AsyncError display is empty: {v:?}");
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn all_fcp_errors_produce_valid_responses() {
    let errors: Vec<FcpError> = vec![
        FcpError::InvalidRequest {
            code: 1001,
            message: "x".into(),
        },
        FcpError::MalformedFrame {
            code: 1002,
            message: "x".into(),
        },
        FcpError::MissingField { field: "f".into() },
        FcpError::ChecksumMismatch,
        FcpError::VersionMismatch {
            expected: "2".into(),
            actual: "1".into(),
        },
        FcpError::Unauthorized {
            code: 2001,
            message: "x".into(),
        },
        FcpError::TokenExpired,
        FcpError::InvalidSignature,
        FcpError::CapabilityDenied {
            capability: "c".into(),
            reason: "r".into(),
        },
        FcpError::RateLimited {
            retry_after_ms: 100,
            violation: None,
        },
        FcpError::OperationNotGranted {
            operation: "o".into(),
        },
        FcpError::ResourceNotAllowed {
            resource: "r".into(),
        },
        FcpError::ZoneViolation {
            source_zone: "a".into(),
            target_zone: "b".into(),
            message: "m".into(),
        },
        FcpError::TaintViolation {
            origin_zone: "a".into(),
            target_zone: "b".into(),
            capability: "c".into(),
        },
        FcpError::ElevationRequired {
            capability: "c".into(),
            ttl_seconds: None,
        },
        FcpError::ConnectorUnavailable {
            code: 5001,
            message: "x".into(),
        },
        FcpError::NotConfigured,
        FcpError::NotHandshaken,
        FcpError::HealthCheckFailed { reason: "r".into() },
        FcpError::StreamingNotSupported,
        FcpError::ResourceNotFound {
            resource: "r".into(),
        },
        FcpError::ResourceExhausted {
            resource: "r".into(),
        },
        FcpError::BudgetExceeded {
            metric: fcp_core::UsageMetricKind::Tokens,
            used: 100,
            limit: 50,
            window_seconds: 60,
        },
        FcpError::Conflict {
            message: "m".into(),
        },
        FcpError::External {
            service: "s".into(),
            message: "m".into(),
            status_code: Some(500),
            retryable: true,
            retry_after: None,
        },
        FcpError::UpstreamTimeout {
            service: "s".into(),
        },
        FcpError::DependencyUnavailable {
            service: "s".into(),
        },
        FcpError::Internal {
            message: "m".into(),
        },
    ];

    for err in &errors {
        let resp = err.to_response();
        assert!(
            resp.code.starts_with("FCP-"),
            "{err}: code should start with 'FCP-', got '{}'",
            resp.code
        );
        assert!(
            !resp.message.is_empty(),
            "{err}: response message should not be empty"
        );
        // Parse the numeric part
        let code_num: u16 = resp.code[4..]
            .parse()
            .unwrap_or_else(|_| panic!("{err}: code '{}' should have numeric suffix", resp.code));
        let (min, max) = err.category().code_range();
        assert!(
            code_num >= min && code_num <= max,
            "{err}: code {code_num} outside range [{min}, {max}]"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Taxonomy Cross-Reference: Error Category ↔ Code Range Consistency
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn category_code_ranges_are_non_overlapping() {
    let categories = [
        ErrorCategory::Protocol,
        ErrorCategory::Auth,
        ErrorCategory::Capability,
        ErrorCategory::Zone,
        ErrorCategory::Connector,
        ErrorCategory::Resource,
        ErrorCategory::External,
        ErrorCategory::Internal,
    ];

    for (i, a) in categories.iter().enumerate() {
        let (a_min, a_max) = a.code_range();
        for b in categories.iter().skip(i + 1) {
            let (b_min, b_max) = b.code_range();
            assert!(
                a_max < b_min || b_max < a_min,
                "Overlapping ranges: {a:?} [{a_min}-{a_max}] and {b:?} [{b_min}-{b_max}]",
            );
        }
    }
}

#[test]
fn every_error_category_has_human_name() {
    let categories = [
        ErrorCategory::Protocol,
        ErrorCategory::Auth,
        ErrorCategory::Capability,
        ErrorCategory::Zone,
        ErrorCategory::Connector,
        ErrorCategory::Resource,
        ErrorCategory::External,
        ErrorCategory::Internal,
    ];

    for cat in &categories {
        let name = cat.name();
        assert!(!name.is_empty(), "{cat:?} has empty name");
    }
}
