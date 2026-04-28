use std::time::Duration;

use fcp_core::{FcpError, UsageMetricKind};

struct DisplaySnapshot {
    variant: &'static str,
    variant_label: &'static str,
    error: FcpError,
    expected_message: &'static str,
    context_fragments: Vec<&'static str>,
}

fn snapshot(
    variant: &'static str,
    variant_label: &'static str,
    error: FcpError,
    expected_message: &'static str,
    context_fragments: &[&'static str],
) -> DisplaySnapshot {
    DisplaySnapshot {
        variant,
        variant_label,
        error,
        expected_message,
        context_fragments: context_fragments.to_vec(),
    }
}

fn display_snapshots() -> Vec<DisplaySnapshot> {
    vec![
        snapshot(
            "InvalidRequest",
            "Invalid request",
            FcpError::InvalidRequest {
                code: 1001,
                message: "missing payload".into(),
            },
            "Invalid request: missing payload",
            &["missing payload"],
        ),
        snapshot(
            "MalformedFrame",
            "Malformed frame",
            FcpError::MalformedFrame {
                code: 1002,
                message: "invalid length prefix".into(),
            },
            "Malformed frame: invalid length prefix",
            &["invalid length prefix"],
        ),
        snapshot(
            "MissingField",
            "Missing required field",
            FcpError::MissingField {
                field: "zone_id".into(),
            },
            "Missing required field: zone_id",
            &["zone_id"],
        ),
        snapshot(
            "ChecksumMismatch",
            "Checksum mismatch",
            FcpError::ChecksumMismatch,
            "Checksum mismatch",
            &[],
        ),
        snapshot(
            "VersionMismatch",
            "Protocol version mismatch",
            FcpError::VersionMismatch {
                expected: "3.0".into(),
                actual: "2.1".into(),
            },
            "Protocol version mismatch: expected 3.0, got 2.1",
            &["3.0", "2.1"],
        ),
        snapshot(
            "Unauthorized",
            "Unauthorized",
            FcpError::Unauthorized {
                code: 2001,
                message: "principal not allowed".into(),
            },
            "Unauthorized: principal not allowed",
            &["principal not allowed"],
        ),
        snapshot(
            "TokenExpired",
            "Token expired",
            FcpError::TokenExpired,
            "Token expired",
            &[],
        ),
        snapshot(
            "TokenNotYetValid",
            "Token not yet valid",
            FcpError::TokenNotYetValid,
            "Token not yet valid",
            &[],
        ),
        snapshot(
            "InvalidSignature",
            "Invalid signature",
            FcpError::InvalidSignature,
            "Invalid signature",
            &[],
        ),
        snapshot(
            "CapabilityDenied",
            "Capability denied",
            FcpError::CapabilityDenied {
                capability: "cap.mail.send".into(),
                reason: "policy denied".into(),
            },
            "Capability denied: cap.mail.send",
            &["cap.mail.send"],
        ),
        snapshot(
            "RateLimited",
            "Rate limited",
            FcpError::RateLimited {
                retry_after_ms: 2500,
                violation: None,
            },
            "Rate limited: retry after 2500ms",
            &["2500ms"],
        ),
        snapshot(
            "OperationNotGranted",
            "Operation not granted",
            FcpError::OperationNotGranted {
                operation: "op.delete".into(),
            },
            "Operation not granted: op.delete",
            &["op.delete"],
        ),
        snapshot(
            "ResourceNotAllowed",
            "Resource not allowed",
            FcpError::ResourceNotAllowed {
                resource: "resource:secret".into(),
            },
            "Resource not allowed: resource:secret",
            &["resource:secret"],
        ),
        snapshot(
            "ZoneViolation",
            "Zone violation",
            FcpError::ZoneViolation {
                source_zone: "z:public".into(),
                target_zone: "z:owner".into(),
                message: "cross-zone request denied".into(),
            },
            "Zone violation: cross-zone request denied",
            &["cross-zone request denied"],
        ),
        snapshot(
            "TaintViolation",
            "Taint violation",
            FcpError::TaintViolation {
                origin_zone: "z:public".into(),
                target_zone: "z:owner".into(),
                capability: "cap.owner.write".into(),
            },
            "Taint violation: origin z:public cannot invoke cap.owner.write in z:owner",
            &["z:public", "cap.owner.write", "z:owner"],
        ),
        snapshot(
            "ElevationRequired",
            "Elevation required",
            FcpError::ElevationRequired {
                capability: "cap.owner.write".into(),
                ttl_seconds: Some(120),
            },
            "Elevation required for cap.owner.write",
            &["cap.owner.write"],
        ),
        snapshot(
            "ConnectorUnavailable",
            "Connector unavailable",
            FcpError::ConnectorUnavailable {
                code: 5001,
                message: "overloaded".into(),
            },
            "Connector unavailable: overloaded",
            &["overloaded"],
        ),
        snapshot(
            "NotConfigured",
            "Connector not configured",
            FcpError::NotConfigured,
            "Connector not configured",
            &[],
        ),
        snapshot(
            "NotHandshaken",
            "Connector not handshaken",
            FcpError::NotHandshaken,
            "Connector not handshaken",
            &[],
        ),
        snapshot(
            "HealthCheckFailed",
            "Health check failed",
            FcpError::HealthCheckFailed {
                reason: "connection refused".into(),
            },
            "Health check failed: connection refused",
            &["connection refused"],
        ),
        snapshot(
            "StreamingNotSupported",
            "Streaming not supported",
            FcpError::StreamingNotSupported,
            "Streaming not supported",
            &[],
        ),
        snapshot(
            "ResourceNotFound",
            "Resource not found",
            FcpError::ResourceNotFound {
                resource: "object:abc".into(),
            },
            "Resource not found: object:abc",
            &["object:abc"],
        ),
        snapshot(
            "ResourceExhausted",
            "Resource exhausted",
            FcpError::ResourceExhausted {
                resource: "worker-slots".into(),
            },
            "Resource exhausted: worker-slots",
            &["worker-slots"],
        ),
        snapshot(
            "BudgetExceeded",
            "Budget exceeded",
            FcpError::BudgetExceeded {
                metric: UsageMetricKind::ApiCredits,
                used: 120,
                limit: 100,
                window_seconds: 3600,
            },
            "Budget exceeded for ApiCredits: used 120 of 100 per 3600s",
            &["ApiCredits", "120", "100", "3600s"],
        ),
        snapshot(
            "Conflict",
            "Conflict",
            FcpError::Conflict {
                message: "etag mismatch".into(),
            },
            "Conflict: etag mismatch",
            &["etag mismatch"],
        ),
        snapshot(
            "External",
            "External service error",
            FcpError::External {
                service: "stripe".into(),
                message: "payment failed".into(),
                status_code: Some(402),
                retryable: false,
                retry_after: Some(Duration::from_millis(500)),
            },
            "External service error: stripe - payment failed",
            &["stripe", "payment failed"],
        ),
        snapshot(
            "UpstreamTimeout",
            "Upstream timeout",
            FcpError::UpstreamTimeout {
                service: "db-primary".into(),
            },
            "Upstream timeout: db-primary",
            &["db-primary"],
        ),
        snapshot(
            "DependencyUnavailable",
            "Dependency unavailable",
            FcpError::DependencyUnavailable {
                service: "redis-cache".into(),
            },
            "Dependency unavailable: redis-cache",
            &["redis-cache"],
        ),
        snapshot(
            "Internal",
            "Internal error",
            FcpError::Internal {
                message: "invariant broken".into(),
            },
            "Internal error: invariant broken",
            &["invariant broken"],
        ),
    ]
}

#[test]
fn fcp_error_display_messages_match_snapshots() {
    for snapshot in display_snapshots() {
        assert_eq!(
            snapshot.error.to_string(),
            snapshot.expected_message,
            "{} Display output changed",
            snapshot.variant
        );
    }
}

#[test]
fn fcp_error_display_messages_include_variant_label_and_context() {
    for snapshot in display_snapshots() {
        let message = snapshot.error.to_string();

        assert!(
            message.contains(snapshot.variant_label),
            "{} Display output missing human-readable variant label {label:?}: {message}",
            snapshot.variant,
            label = snapshot.variant_label,
        );

        for fragment in snapshot.context_fragments {
            assert!(
                message.contains(fragment),
                "{} Display output missing context fragment {fragment:?}: {message}",
                snapshot.variant
            );
        }
    }
}
