//! `FcpError` stable numeric codes + `is_retryable` + `retry_after`
//! conformance.
//!
//! `fcp_core::FcpError` is the unified error type that crosses every
//! crate boundary in FCP. Three contracts that downstream consumers
//! key on:
//!
//! 1. **Stable numeric codes** (FCP-1xxx protocol, FCP-2xxx auth,
//!    FCP-3xxx capability, FCP-4xxx zone, FCP-5xxx connector,
//!    FCP-6xxx resource, FCP-7xxx external, FCP-9xxx internal).
//!    Admin tooling, CLI, and triage dashboards filter on these.
//! 2. **`error_code()` string format** = `"FCP-NNNN"` zero-padded
//!    to 4 digits.
//! 3. **`is_retryable` partition** + **`retry_after` extraction**
//!    — the contract callers use to drive automatic retry loops.
//!    Wrong classifications cause either tight retry storms (false
//!    positive) or premature give-ups (false negative).

use std::time::Duration;

use fcp_prelude::{FcpError, UsageMetricKind};

#[test]
fn token_expired_code_is_2002() {
    let err = FcpError::TokenExpired;
    assert_eq!(err.numeric_code(), 2002);
    assert_eq!(err.error_code(), "FCP-2002");
}

#[test]
fn token_not_yet_valid_code_is_2005() {
    let err = FcpError::TokenNotYetValid;
    assert_eq!(err.numeric_code(), 2005);
    assert_eq!(err.error_code(), "FCP-2005");
}

#[test]
fn invalid_signature_code_is_2003() {
    let err = FcpError::InvalidSignature;
    assert_eq!(err.numeric_code(), 2003);
    assert_eq!(err.error_code(), "FCP-2003");
}

#[test]
fn capability_denied_code_is_3001() {
    let err = FcpError::CapabilityDenied {
        capability: "cap.x".into(),
        reason: "no grant".into(),
    };
    assert_eq!(err.numeric_code(), 3001);
    assert_eq!(err.error_code(), "FCP-3001");
}

#[test]
fn rate_limited_code_is_3002() {
    let err = FcpError::RateLimited {
        retry_after_ms: 1500,
        violation: None,
    };
    assert_eq!(err.numeric_code(), 3002);
    assert_eq!(err.error_code(), "FCP-3002");
}

#[test]
fn operation_not_granted_code_is_3003() {
    let err = FcpError::OperationNotGranted {
        operation: "op.delete".into(),
    };
    assert_eq!(err.numeric_code(), 3003);
    assert_eq!(err.error_code(), "FCP-3003");
}

#[test]
fn resource_not_allowed_code_is_3004() {
    let err = FcpError::ResourceNotAllowed {
        resource: "notion://page/secret".into(),
    };
    assert_eq!(err.numeric_code(), 3004);
    assert_eq!(err.error_code(), "FCP-3004");
}

#[test]
fn zone_violation_code_is_4001() {
    let err = FcpError::ZoneViolation {
        source_zone: "z:public".into(),
        target_zone: "z:work".into(),
        message: "cross-zone".into(),
    };
    assert_eq!(err.numeric_code(), 4001);
    assert_eq!(err.error_code(), "FCP-4001");
}

#[test]
fn budget_exceeded_code_is_6004() {
    let err = FcpError::BudgetExceeded {
        metric: UsageMetricKind::Tokens,
        used: 100,
        limit: 50,
        window_seconds: 3600,
    };
    assert_eq!(err.numeric_code(), 6004);
    assert_eq!(err.error_code(), "FCP-6004");
}

#[test]
fn internal_code_is_9001() {
    let err = FcpError::Internal {
        message: "boom".into(),
    };
    assert_eq!(err.numeric_code(), 9001);
    assert_eq!(err.error_code(), "FCP-9001");
}

#[test]
fn error_code_string_format_is_fcp_dash_zero_padded_4_digits() {
    // The format!("FCP-{code:04}") must produce zero-padded 4
    // digits. Pin literal forms across two-digit and four-digit
    // numeric codes to catch any drift in the format string.
    let two_digit_input = FcpError::InvalidRequest {
        code: 42,
        message: "bad".into(),
    };
    assert_eq!(
        two_digit_input.error_code(),
        "FCP-0042",
        "numeric_code=42 MUST format as FCP-0042 (zero-padded 4 digits)"
    );

    let four_digit_input = FcpError::InvalidRequest {
        code: 1234,
        message: "bad".into(),
    };
    assert_eq!(
        four_digit_input.error_code(),
        "FCP-1234",
        "numeric_code=1234 MUST format as FCP-1234"
    );
}

#[test]
fn is_retryable_classifies_retryable_subset_correctly() {
    // Documented retryable variants: RateLimited, ResourceExhausted,
    // BudgetExceeded, UpstreamTimeout, DependencyUnavailable,
    // ConnectorUnavailable.
    let retryable = [
        FcpError::RateLimited {
            retry_after_ms: 1000,
            violation: None,
        },
        FcpError::ResourceExhausted {
            resource: "cpu".into(),
        },
        FcpError::BudgetExceeded {
            metric: UsageMetricKind::Tokens,
            used: 1,
            limit: 1,
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
    for err in retryable {
        assert!(
            err.is_retryable(),
            "{err:?} MUST be classified as retryable — drift here causes premature \
             give-ups in caller retry loops"
        );
    }
}

#[test]
fn is_retryable_classifies_non_retryable_correctly() {
    // Permanent errors that MUST NOT be retried automatically.
    // Retrying these causes tight error loops without any chance
    // of success.
    let non_retryable = [
        FcpError::TokenExpired,
        FcpError::TokenNotYetValid,
        FcpError::InvalidSignature,
        FcpError::CapabilityDenied {
            capability: "x".into(),
            reason: "no".into(),
        },
        FcpError::ZoneViolation {
            source_zone: "z:a".into(),
            target_zone: "z:b".into(),
            message: "no".into(),
        },
        FcpError::OperationNotGranted {
            operation: "op".into(),
        },
        FcpError::ChecksumMismatch,
        FcpError::Internal {
            message: "boom".into(),
        },
    ];
    for err in non_retryable {
        assert!(
            !err.is_retryable(),
            "{err:?} MUST NOT be classified as retryable — automatic retry would loop"
        );
    }
}

#[test]
fn external_error_is_retryable_uses_explicit_field() {
    // External.retryable is the explicit override — caller-
    // supplied. We pin BOTH branches so a regression that, e.g.,
    // hard-coded to true would be caught.
    let retryable = FcpError::External {
        service: "api".into(),
        message: "503".into(),
        status_code: Some(503),
        retryable: true,
        retry_after: None,
    };
    assert!(retryable.is_retryable());

    let non_retryable = FcpError::External {
        service: "api".into(),
        message: "404".into(),
        status_code: Some(404),
        retryable: false,
        retry_after: None,
    };
    assert!(
        !non_retryable.is_retryable(),
        "External.retryable=false MUST surface as is_retryable()=false (caller controls policy)"
    );
}

#[test]
fn retry_after_for_rate_limited_returns_configured_duration() {
    let err = FcpError::RateLimited {
        retry_after_ms: 2500,
        violation: None,
    };
    assert_eq!(
        err.retry_after(),
        Some(Duration::from_millis(2500)),
        "RateLimited.retry_after MUST extract retry_after_ms as a Duration"
    );
}

#[test]
fn retry_after_for_external_passes_through_explicit_field() {
    let with_delay = FcpError::External {
        service: "api".into(),
        message: "rate limited".into(),
        status_code: Some(429),
        retryable: true,
        retry_after: Some(Duration::from_secs(5)),
    };
    assert_eq!(with_delay.retry_after(), Some(Duration::from_secs(5)));

    let without_delay = FcpError::External {
        service: "api".into(),
        message: "transient".into(),
        status_code: Some(503),
        retryable: true,
        retry_after: None,
    };
    assert_eq!(without_delay.retry_after(), None);
}

#[test]
fn retry_after_returns_none_for_non_retry_errors() {
    let errors = [
        FcpError::TokenExpired,
        FcpError::CapabilityDenied {
            capability: "x".into(),
            reason: "no".into(),
        },
        FcpError::Internal {
            message: "boom".into(),
        },
        FcpError::UpstreamTimeout {
            service: "api".into(),
        },
        FcpError::ResourceExhausted {
            resource: "cpu".into(),
        },
    ];
    for err in errors {
        assert!(
            err.retry_after().is_none(),
            "{err:?}::retry_after MUST be None — only RateLimited and External \
             carry an explicit duration"
        );
    }
}

#[test]
fn parameterized_code_field_drives_format_for_invalid_request() {
    // InvalidRequest carries `code: u16`. Pin that the field
    // value drives the resulting error_code so callers can
    // distinguish sub-categories.
    for code in [1001_u16, 1002, 1006, 1099] {
        let err = FcpError::InvalidRequest {
            code,
            message: "x".into(),
        };
        assert_eq!(err.numeric_code(), code);
        assert_eq!(err.error_code(), format!("FCP-{code:04}"));
    }
}

#[test]
fn external_error_status_code_drives_numeric_mapping() {
    // External errors map status_code 429 → 7001, 504 → 7002,
    // others → 7003. This is the documented backpressure /
    // timeout / generic split that admin dashboards filter on.
    let mappings = [
        (Some(429_u16), 7001_u16),
        (Some(504), 7002),
        (Some(500), 7003),
        (None, 7003),
    ];
    for (status, expected) in mappings {
        let err = FcpError::External {
            service: "api".into(),
            message: "x".into(),
            status_code: status,
            retryable: true,
            retry_after: None,
        };
        assert_eq!(
            err.numeric_code(),
            expected,
            "External status_code={status:?} MUST map to numeric {expected}"
        );
    }
}

#[test]
fn missing_field_code_is_1006() {
    let err = FcpError::MissingField {
        field: "principal".into(),
    };
    assert_eq!(err.numeric_code(), 1006);
    assert_eq!(err.error_code(), "FCP-1006");
}

#[test]
fn taint_violation_code_is_4002() {
    let err = FcpError::TaintViolation {
        origin_zone: "z:public".into(),
        target_zone: "z:work".into(),
        capability: "send".into(),
    };
    assert_eq!(err.numeric_code(), 4002);
    assert_eq!(err.error_code(), "FCP-4002");
}

#[test]
fn elevation_required_code_is_4003() {
    let err = FcpError::ElevationRequired {
        capability: "admin".into(),
        ttl_seconds: Some(300),
    };
    assert_eq!(err.numeric_code(), 4003);
    assert_eq!(err.error_code(), "FCP-4003");
}
