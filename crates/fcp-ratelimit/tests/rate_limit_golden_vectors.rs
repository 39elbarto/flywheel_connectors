//! Golden vector tests for rate limiting.
//!
//! Golden vectors are stored in `tests/vectors/rate_limiting/`:
//! - `throttle_violation.cbor`
//! - `backpressure_signal.cbor`
//! - `quota_state.cbor`

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use fcp_prelude::{
    BackpressureLevel, BackpressureSignal, ConnectorId, LimitType, OperationId, ThrottleViolation,
    ThrottleViolationInput, ZoneId,
};
use fcp_ratelimit::RateLimitState;

/// Test logging structure per FCP2 requirements.
#[derive(Debug, serde::Serialize)]
struct TestLogEntry {
    timestamp: String,
    test_name: String,
    phase: String,
    correlation_id: String,
    connector_id: String,
    quota_used: u32,
    quota_limit: u32,
    throttled: bool,
    result: String,
}

impl TestLogEntry {
    fn new(test_name: &str, connector_id: &str, quota_used: u32, quota_limit: u32) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_name: test_name.to_string(),
            phase: "execute".to_string(),
            correlation_id: uuid::Uuid::new_v4().to_string(),
            connector_id: connector_id.to_string(),
            quota_used,
            quota_limit,
            throttled: false,
            result: "pending".to_string(),
        }
    }

    fn pass(mut self, throttled: bool) -> Self {
        self.throttled = throttled;
        self.result = "pass".to_string();
        self
    }

    fn log(&self) {
        eprintln!("{}", serde_json::to_string(self).unwrap());
    }
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/rate_limiting")
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct ThrottleViolationVector {
    violation_id: String,
    timestamp_ms: u64,
    zone_id: String,
    connector_id: Option<String>,
    operation_id: Option<String>,
    limit_type: LimitType,
    limit_value: u32,
    current_value: u32,
    retry_after_ms: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct BackpressureSignalVector {
    level: BackpressureLevel,
    utilization_bps: u16,
    retry_after_ms: Option<u64>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct QuotaStateVector {
    limit: u32,
    remaining: u32,
    reset_after_ms: u64,
    is_limited: bool,
}

#[test]
fn test_throttle_violation_vector_roundtrip() {
    let mut log = TestLogEntry::new(
        "test_throttle_violation_vector_roundtrip",
        "fcp.test:rate_limit:0.1.0",
        120,
        100,
    );

    let violation = ThrottleViolation::new(ThrottleViolationInput {
        timestamp_ms: 1_704_067_200_000,
        zone_id: ZoneId::work(),
        connector_id: Some(ConnectorId::from_static("fcp.test:rate_limit:0.1.0")),
        operation_id: Some(OperationId::from_static("rate.limit")),
        limit_type: LimitType::Quota,
        limit_value: 100,
        current_value: 120,
        retry_after_ms: 1_000,
    });

    let vector = ThrottleViolationVector {
        violation_id: violation.violation_id.to_string(),
        timestamp_ms: violation.timestamp_ms,
        zone_id: violation.zone_id.to_string(),
        connector_id: violation.connector_id.map(|id| id.to_string()),
        operation_id: violation.operation_id.map(|id| id.to_string()),
        limit_type: violation.limit_type,
        limit_value: violation.limit_value,
        current_value: violation.current_value,
        retry_after_ms: violation.retry_after_ms,
    };

    let cbor_bytes = {
        let mut buf = Vec::new();
        ciborium::into_writer(&vector, &mut buf).expect("CBOR serialization failed");
        buf
    };

    let path = vectors_dir().join("throttle_violation.cbor");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, &cbor_bytes).expect("Failed to write golden vector");

    // Verify
    let loaded: ThrottleViolationVector =
        ciborium::from_reader(&cbor_bytes[..]).expect("CBOR deserialization failed");
    assert_eq!(loaded, vector);

    assert_eq!(loaded.limit_type, LimitType::Quota);
    assert_eq!(loaded.limit_value, 100);
    assert_eq!(loaded.current_value, 120);

    log = log.pass(true);
    log.log();
}

#[test]
fn test_backpressure_signal_vector_roundtrip() {
    let mut log = TestLogEntry::new(
        "test_backpressure_signal_vector_roundtrip",
        "fcp.test:rate_limit:0.1.0",
        95,
        100,
    );

    let signal = BackpressureSignal {
        level: BackpressureLevel::SoftLimit,
        utilization_bps: 9_500,
        retry_after_ms: Some(750),
    };

    let vector = BackpressureSignalVector {
        level: signal.level,
        utilization_bps: signal.utilization_bps,
        retry_after_ms: signal.retry_after_ms,
    };

    let cbor_bytes = {
        let mut buf = Vec::new();
        ciborium::into_writer(&vector, &mut buf).expect("CBOR serialization failed");
        buf
    };

    let path = vectors_dir().join("backpressure_signal.cbor");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, &cbor_bytes).expect("Failed to write golden vector");

    // Verify
    let loaded: BackpressureSignalVector =
        ciborium::from_reader(&cbor_bytes[..]).expect("CBOR deserialization failed");
    assert_eq!(loaded, vector);

    assert_eq!(loaded.level, BackpressureLevel::SoftLimit);
    assert_eq!(loaded.utilization_bps, 9_500);
    assert!(loaded.retry_after_ms.is_some());

    log = log.pass(false);
    log.log();
}

#[test]
fn test_quota_state_vector_roundtrip() {
    let mut log = TestLogEntry::new(
        "test_quota_state_vector_roundtrip",
        "fcp.test:rate_limit:0.1.0",
        95,
        100,
    );

    let state = RateLimitState {
        limit: 100,
        remaining: 5,
        reset_after: Duration::from_secs(60),
        is_limited: false,
    };

    let vector = QuotaStateVector {
        limit: state.limit,
        remaining: state.remaining,
        reset_after_ms: u64::try_from(state.reset_after.as_millis()).unwrap_or(u64::MAX),
        is_limited: state.is_limited,
    };

    let cbor_bytes = {
        let mut buf = Vec::new();
        ciborium::into_writer(&vector, &mut buf).expect("CBOR serialization failed");
        buf
    };

    let path = vectors_dir().join("quota_state.cbor");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, &cbor_bytes).expect("Failed to write golden vector");

    // Verify
    let loaded: QuotaStateVector =
        ciborium::from_reader(&cbor_bytes[..]).expect("CBOR deserialization failed");
    assert_eq!(loaded, vector);

    assert_eq!(loaded.limit, 100);
    assert_eq!(loaded.remaining, 5);
    assert_eq!(loaded.reset_after_ms, 60_000);
    assert!(!loaded.is_limited);

    log = log.pass(false);
    log.log();
}
