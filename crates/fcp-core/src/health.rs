//! Health types for FCP - health checks and status.
//!
//! Based on FCP Specification Section 13 (Lifecycle Management).

use serde::{Deserialize, Serialize};

use crate::FcpError;

/// Health snapshot for a connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSnapshot {
    /// Current health state
    pub status: HealthState,

    /// Uptime in milliseconds
    pub uptime_ms: u64,

    /// Current load (0.0 to 1.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load: Option<f32>,

    /// Additional health details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,

    /// Rate limit status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitStatus>,
}

/// Result of a connector self-check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfCheckReport {
    /// Overall self-check status.
    pub status: SelfCheckStatus,

    /// Stable reason code for degraded/failed states.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,

    /// Human-readable message for operators.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Optional structured details from the connector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl SelfCheckReport {
    /// Self-check completed successfully.
    #[must_use]
    pub const fn ok() -> Self {
        Self {
            status: SelfCheckStatus::Ok,
            reason_code: None,
            message: None,
            details: None,
        }
    }

    /// Self-check completed but with degraded status.
    #[must_use]
    pub fn degraded(reason_code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: SelfCheckStatus::Degraded,
            reason_code: Some(reason_code.into()),
            message: Some(message.into()),
            details: None,
        }
    }

    /// Self-check failed.
    #[must_use]
    pub fn failed(reason_code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: SelfCheckStatus::Failed,
            reason_code: Some(reason_code.into()),
            message: Some(message.into()),
            details: None,
        }
    }

    /// Self-check is not supported by the connector.
    #[must_use]
    pub fn unsupported() -> Self {
        Self {
            status: SelfCheckStatus::Unsupported,
            reason_code: Some("self_check_unsupported".to_string()),
            message: Some("connector does not implement self-check".to_string()),
            details: None,
        }
    }

    /// Create a failed report from an `FcpError`.
    #[must_use]
    pub fn from_error(error: &FcpError) -> Self {
        Self {
            status: SelfCheckStatus::Failed,
            reason_code: Some(error.error_code()),
            message: Some(error.to_string()),
            details: None,
        }
    }
}

/// Self-check status indicator.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SelfCheckStatus {
    /// Self-check completed successfully.
    Ok,
    /// Self-check completed with issues.
    Degraded,
    /// Self-check failed.
    Failed,
    /// Self-check not supported by the connector.
    Unsupported,
}

impl Default for HealthSnapshot {
    fn default() -> Self {
        Self {
            status: HealthState::Starting,
            uptime_ms: 0,
            load: None,
            details: None,
            rate_limit: None,
        }
    }
}

impl HealthSnapshot {
    /// Create a healthy snapshot.
    #[must_use]
    pub fn ready() -> Self {
        Self {
            status: HealthState::Ready,
            ..Default::default()
        }
    }

    /// Create a degraded snapshot.
    #[must_use]
    pub fn degraded(reason: impl Into<String>) -> Self {
        Self {
            status: HealthState::Degraded {
                reason: reason.into(),
            },
            ..Default::default()
        }
    }

    /// Create an error snapshot.
    #[must_use]
    pub fn error(reason: impl Into<String>) -> Self {
        Self {
            status: HealthState::Error {
                reason: reason.into(),
            },
            ..Default::default()
        }
    }

    /// Check if the connector is ready.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self.status, HealthState::Ready)
    }

    /// Check if the connector is healthy (ready or degraded).
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(
            self.status,
            HealthState::Ready | HealthState::Degraded { .. }
        )
    }
}

/// Health state enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum HealthState {
    /// Connector is starting up
    Starting,

    /// Connector is ready to accept requests
    Ready,

    /// Connector is operational but with issues
    Degraded {
        /// Reason for degradation
        reason: String,
    },

    /// Connector is in error state
    Error {
        /// Reason for error
        reason: String,
    },

    /// Connector is shutting down
    Stopping,
}

/// Connector health status (external-facing health for discovery/registry).
///
/// This is distinct from `HealthState` which represents internal lifecycle state.
/// `ConnectorHealth` is used in:
/// - Discovery responses (`ConnectorSummary.health`)
/// - Health API (`/rpc/health`)
/// - CLI status (`fcp connector list`)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ConnectorHealth {
    /// Connector is healthy and accepting requests.
    Healthy,

    /// Connector is operational but with reduced performance or partial functionality.
    Degraded {
        /// Reason for degradation.
        reason: String,
    },

    /// Connector is unavailable (not responding or in error state).
    Unavailable {
        /// Reason for unavailability.
        reason: String,
        /// When the connector became unavailable.
        since: chrono::DateTime<chrono::Utc>,
    },
}

impl ConnectorHealth {
    /// Create a healthy status.
    #[must_use]
    pub const fn healthy() -> Self {
        Self::Healthy
    }

    /// Create a degraded status.
    #[must_use]
    pub fn degraded(reason: impl Into<String>) -> Self {
        Self::Degraded {
            reason: reason.into(),
        }
    }

    /// Create an unavailable status.
    #[must_use]
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
            since: chrono::Utc::now(),
        }
    }

    /// Check if the connector is healthy.
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Check if the connector is available (healthy or degraded).
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded { .. })
    }
}

impl From<&HealthState> for ConnectorHealth {
    fn from(state: &HealthState) -> Self {
        match state {
            HealthState::Ready => Self::Healthy,
            HealthState::Degraded { reason } => Self::Degraded {
                reason: reason.clone(),
            },
            HealthState::Starting | HealthState::Stopping => Self::Unavailable {
                reason: format!("Connector is {}", state.as_str()),
                since: chrono::Utc::now(),
            },
            HealthState::Error { reason } => Self::Unavailable {
                reason: reason.clone(),
                since: chrono::Utc::now(),
            },
        }
    }
}

impl HealthState {
    /// Get the string representation of the state.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Degraded { .. } => "degraded",
            Self::Error { .. } => "error",
            Self::Stopping => "stopping",
        }
    }
}

/// Rate limit status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitStatus {
    /// Maximum requests per window
    pub limit: u32,

    /// Remaining requests in current window
    pub remaining: u32,

    /// Window reset timestamp (Unix seconds)
    pub reset_at: u64,

    /// Window duration in seconds
    pub window_seconds: u32,
}

impl RateLimitStatus {
    /// Check if rate limited.
    #[must_use]
    pub const fn is_limited(&self) -> bool {
        self.remaining == 0
    }

    /// Get seconds until reset.
    #[must_use]
    pub fn seconds_until_reset(&self) -> u64 {
        // Use try_from to safely handle negative timestamps (before Unix epoch)
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        self.reset_at.saturating_sub(now)
    }
}

/// Liveness check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessResponse {
    /// Whether the connector is alive
    pub alive: bool,

    /// Timestamp of the check
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Default for LivenessResponse {
    fn default() -> Self {
        Self {
            alive: true,
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Readiness check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessResponse {
    /// Whether the connector is ready
    pub ready: bool,

    /// Components and their readiness
    #[serde(default)]
    pub components: std::collections::HashMap<String, bool>,

    /// Timestamp of the check
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Default for ReadinessResponse {
    fn default() -> Self {
        Self {
            ready: true,
            components: std::collections::HashMap::new(),
            timestamp: chrono::Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ─────────────────────────────────────────────────────────────────────────────
    // HealthState tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_state_starting_serialization() {
        let state = HealthState::Starting;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, r#"{"state":"starting"}"#);

        let parsed: HealthState = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, HealthState::Starting));
    }

    #[test]
    fn health_state_ready_serialization() {
        let state = HealthState::Ready;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, r#"{"state":"ready"}"#);

        let parsed: HealthState = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, HealthState::Ready));
    }

    #[test]
    fn health_state_degraded_serialization() {
        let state = HealthState::Degraded {
            reason: "high latency".to_string(),
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains(r#""state":"degraded""#));
        assert!(json.contains(r#""reason":"high latency""#));

        let parsed: HealthState = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(&parsed, HealthState::Degraded { reason } if reason == "high latency"),
            "expected Degraded state, got {parsed:?}"
        );
    }

    #[test]
    fn health_state_error_serialization() {
        let state = HealthState::Error {
            reason: "connection failed".to_string(),
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains(r#""state":"error""#));
        assert!(json.contains(r#""reason":"connection failed""#));

        let parsed: HealthState = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(&parsed, HealthState::Error { reason } if reason == "connection failed"),
            "expected Error state, got {parsed:?}"
        );
    }

    #[test]
    fn health_state_stopping_serialization() {
        let state = HealthState::Stopping;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, r#"{"state":"stopping"}"#);

        let parsed: HealthState = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, HealthState::Stopping));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // HealthSnapshot tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_snapshot_default() {
        let snapshot = HealthSnapshot::default();

        assert!(matches!(snapshot.status, HealthState::Starting));
        assert_eq!(snapshot.uptime_ms, 0);
        assert!(snapshot.load.is_none());
        assert!(snapshot.details.is_none());
        assert!(snapshot.rate_limit.is_none());
    }

    #[test]
    fn health_snapshot_ready() {
        let snapshot = HealthSnapshot::ready();

        assert!(matches!(snapshot.status, HealthState::Ready));
        assert!(snapshot.is_ready());
        assert!(snapshot.is_healthy());
    }

    #[test]
    fn health_snapshot_degraded() {
        let snapshot = HealthSnapshot::degraded("upstream slow");

        assert!(
            matches!(&snapshot.status, HealthState::Degraded { reason } if reason == "upstream slow"),
            "expected Degraded state, got {:?}",
            snapshot.status
        );
        assert!(!snapshot.is_ready());
        assert!(snapshot.is_healthy());
    }

    #[test]
    fn health_snapshot_error() {
        let snapshot = HealthSnapshot::error("database down");

        assert!(
            matches!(&snapshot.status, HealthState::Error { reason } if reason == "database down"),
            "expected Error state, got {:?}",
            snapshot.status
        );
        assert!(!snapshot.is_ready());
        assert!(!snapshot.is_healthy());
    }

    #[test]
    fn health_snapshot_is_ready_variants() {
        assert!(HealthSnapshot::ready().is_ready());
        assert!(!HealthSnapshot::degraded("x").is_ready());
        assert!(!HealthSnapshot::error("x").is_ready());
        assert!(!HealthSnapshot::default().is_ready()); // Starting
    }

    #[test]
    fn health_snapshot_is_healthy_variants() {
        assert!(HealthSnapshot::ready().is_healthy());
        assert!(HealthSnapshot::degraded("x").is_healthy());
        assert!(!HealthSnapshot::error("x").is_healthy());
        assert!(!HealthSnapshot::default().is_healthy()); // Starting
    }

    #[test]
    fn health_snapshot_serialization_minimal() {
        let snapshot = HealthSnapshot::ready();
        let json = serde_json::to_string(&snapshot).unwrap();

        // Optional fields should be omitted
        assert!(!json.contains("load"));
        assert!(!json.contains("details"));
        assert!(!json.contains("rate_limit"));
    }

    #[test]
    fn health_snapshot_serialization_roundtrip() {
        let mut snapshot = HealthSnapshot::ready();
        snapshot.uptime_ms = 3_600_000;
        snapshot.load = Some(0.75);
        snapshot.details = Some(json!({"connections": 42}));

        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: HealthSnapshot = serde_json::from_str(&json).unwrap();

        assert!(matches!(parsed.status, HealthState::Ready));
        assert_eq!(parsed.uptime_ms, 3_600_000);
        assert!((parsed.load.unwrap() - 0.75).abs() < f32::EPSILON);
        assert_eq!(parsed.details.unwrap()["connections"], 42);
    }

    #[test]
    fn health_snapshot_with_rate_limit() {
        let mut snapshot = HealthSnapshot::ready();
        snapshot.rate_limit = Some(RateLimitStatus {
            limit: 1000,
            remaining: 500,
            reset_at: 1_700_000_000,
            window_seconds: 3600,
        });

        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: HealthSnapshot = serde_json::from_str(&json).unwrap();

        let rl = parsed.rate_limit.unwrap();
        assert_eq!(rl.limit, 1000);
        assert_eq!(rl.remaining, 500);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // RateLimitStatus tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn rate_limit_status_is_limited() {
        let limited = RateLimitStatus {
            limit: 100,
            remaining: 0,
            reset_at: 1_700_000_000,
            window_seconds: 60,
        };
        assert!(limited.is_limited());

        let not_limited = RateLimitStatus {
            limit: 100,
            remaining: 50,
            reset_at: 1_700_000_000,
            window_seconds: 60,
        };
        assert!(!not_limited.is_limited());
    }

    #[test]
    fn rate_limit_status_seconds_until_reset_future() {
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        let status = RateLimitStatus {
            limit: 100,
            remaining: 0,
            reset_at: now + 300, // 5 minutes in future
            window_seconds: 3600,
        };

        let seconds = status.seconds_until_reset();
        // Should be approximately 300 (allow some slack for test execution)
        assert!((298..=302).contains(&seconds));
    }

    #[test]
    fn rate_limit_status_seconds_until_reset_past() {
        let status = RateLimitStatus {
            limit: 100,
            remaining: 0,
            reset_at: 0, // Way in the past
            window_seconds: 3600,
        };

        // Should saturate to 0, not underflow
        assert_eq!(status.seconds_until_reset(), 0);
    }

    #[test]
    fn rate_limit_status_serialization_roundtrip() {
        let status = RateLimitStatus {
            limit: 500,
            remaining: 123,
            reset_at: 1_700_000_000,
            window_seconds: 3600,
        };

        let json = serde_json::to_string(&status).unwrap();
        let parsed: RateLimitStatus = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.limit, 500);
        assert_eq!(parsed.remaining, 123);
        assert_eq!(parsed.reset_at, 1_700_000_000);
        assert_eq!(parsed.window_seconds, 3600);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // LivenessResponse tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn liveness_response_default() {
        let resp = LivenessResponse::default();

        assert!(resp.alive);
        // Timestamp should be recent (within last second)
        let now = chrono::Utc::now();
        let diff = (now - resp.timestamp).num_seconds();
        assert!(diff.abs() < 2);
    }

    #[test]
    fn liveness_response_serialization_roundtrip() {
        let resp = LivenessResponse::default();

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: LivenessResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.alive, resp.alive);
        assert_eq!(parsed.timestamp, resp.timestamp);
    }

    #[test]
    fn liveness_response_not_alive() {
        let resp = LivenessResponse {
            alive: false,
            timestamp: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: LivenessResponse = serde_json::from_str(&json).unwrap();

        assert!(!parsed.alive);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ReadinessResponse tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn readiness_response_default() {
        let resp = ReadinessResponse::default();

        assert!(resp.ready);
        assert!(resp.components.is_empty());
    }

    #[test]
    fn readiness_response_with_components() {
        let mut components = std::collections::HashMap::new();
        components.insert("database".to_string(), true);
        components.insert("cache".to_string(), true);
        components.insert("queue".to_string(), false);

        let resp = ReadinessResponse {
            ready: false, // Not ready due to queue
            components,
            timestamp: chrono::Utc::now(),
        };

        assert!(!resp.ready);
        assert_eq!(resp.components.len(), 3);
        assert!(resp.components["database"]);
        assert!(!resp.components["queue"]);
    }

    #[test]
    fn readiness_response_serialization_roundtrip() {
        let mut components = std::collections::HashMap::new();
        components.insert("api".to_string(), true);
        components.insert("auth".to_string(), true);

        let resp = ReadinessResponse {
            ready: true,
            components,
            timestamp: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ReadinessResponse = serde_json::from_str(&json).unwrap();

        assert!(parsed.ready);
        assert_eq!(parsed.components.len(), 2);
        assert!(parsed.components["api"]);
        assert!(parsed.components["auth"]);
    }

    #[test]
    fn readiness_response_components_default_empty() {
        // Verify the #[serde(default)] annotation works
        let json = r#"{
            "ready": true,
            "timestamp": "2024-01-01T00:00:00Z"
        }"#;

        let resp: ReadinessResponse = serde_json::from_str(json).unwrap();
        assert!(resp.components.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ConnectorHealth tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_health_healthy() {
        let health = ConnectorHealth::healthy();
        assert!(health.is_healthy());
        assert!(health.is_available());
    }

    #[test]
    fn connector_health_degraded() {
        let health = ConnectorHealth::degraded("high latency");
        assert!(!health.is_healthy());
        assert!(health.is_available());

        assert!(
            matches!(&health, ConnectorHealth::Degraded { reason } if reason == "high latency"),
            "expected Degraded variant, got {health:?}"
        );
    }

    #[test]
    fn connector_health_unavailable() {
        let health = ConnectorHealth::unavailable("connection refused");
        assert!(!health.is_healthy());
        assert!(!health.is_available());

        assert!(
            matches!(&health, ConnectorHealth::Unavailable { reason, .. } if reason == "connection refused"),
            "expected Unavailable variant, got {health:?}"
        );
    }

    #[test]
    fn connector_health_serialization_healthy() {
        let health = ConnectorHealth::healthy();
        let json = serde_json::to_string(&health).unwrap();
        assert_eq!(json, r#"{"status":"healthy"}"#);

        let parsed: ConnectorHealth = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_healthy());
    }

    #[test]
    fn connector_health_serialization_degraded() {
        let health = ConnectorHealth::degraded("rate limited");
        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains(r#""status":"degraded""#));
        assert!(json.contains(r#""reason":"rate limited""#));

        let parsed: ConnectorHealth = serde_json::from_str(&json).unwrap();
        assert!(!parsed.is_healthy());
        assert!(parsed.is_available());
    }

    #[test]
    fn connector_health_serialization_unavailable() {
        let health = ConnectorHealth::unavailable("service down");
        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains(r#""status":"unavailable""#));
        assert!(json.contains(r#""reason":"service down""#));
        assert!(json.contains(r#""since":"#)); // Has timestamp

        let parsed: ConnectorHealth = serde_json::from_str(&json).unwrap();
        assert!(!parsed.is_healthy());
        assert!(!parsed.is_available());
    }

    #[test]
    fn connector_health_from_health_state_ready() {
        let state = HealthState::Ready;
        let health = ConnectorHealth::from(&state);
        assert!(health.is_healthy());
    }

    #[test]
    fn connector_health_from_health_state_degraded() {
        let state = HealthState::Degraded {
            reason: "slow upstream".to_string(),
        };
        let health = ConnectorHealth::from(&state);
        assert!(!health.is_healthy());
        assert!(health.is_available());

        assert!(
            matches!(&health, ConnectorHealth::Degraded { reason } if reason == "slow upstream"),
            "expected Degraded variant, got {health:?}"
        );
    }

    #[test]
    fn connector_health_from_health_state_error() {
        let state = HealthState::Error {
            reason: "crash".to_string(),
        };
        let health = ConnectorHealth::from(&state);
        assert!(!health.is_healthy());
        assert!(!health.is_available());

        assert!(
            matches!(&health, ConnectorHealth::Unavailable { reason, .. } if reason == "crash"),
            "expected Unavailable variant, got {health:?}"
        );
    }

    #[test]
    fn connector_health_from_health_state_starting() {
        let state = HealthState::Starting;
        let health = ConnectorHealth::from(&state);
        assert!(!health.is_available());
    }

    #[test]
    fn connector_health_from_health_state_stopping() {
        let state = HealthState::Stopping;
        let health = ConnectorHealth::from(&state);
        assert!(!health.is_available());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // SelfCheckStatus tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn self_check_status_copy() {
        let a = SelfCheckStatus::Ok;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn self_check_status_serde_all_variants() {
        for status in [
            SelfCheckStatus::Ok,
            SelfCheckStatus::Degraded,
            SelfCheckStatus::Failed,
            SelfCheckStatus::Unsupported,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let decoded: SelfCheckStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, decoded);
        }
    }

    #[test]
    fn self_check_status_inequality() {
        assert_ne!(SelfCheckStatus::Ok, SelfCheckStatus::Failed);
        assert_ne!(SelfCheckStatus::Degraded, SelfCheckStatus::Unsupported);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // SelfCheckReport tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn self_check_report_ok() {
        let report = SelfCheckReport::ok();
        assert_eq!(report.status, SelfCheckStatus::Ok);
        assert!(report.reason_code.is_none());
        assert!(report.message.is_none());
        assert!(report.details.is_none());
    }

    #[test]
    fn self_check_report_degraded() {
        let report = SelfCheckReport::degraded("SLOW_UPSTREAM", "upstream latency is high");
        assert_eq!(report.status, SelfCheckStatus::Degraded);
        assert_eq!(report.reason_code.as_deref(), Some("SLOW_UPSTREAM"));
        assert_eq!(report.message.as_deref(), Some("upstream latency is high"));
    }

    #[test]
    fn self_check_report_failed() {
        let report = SelfCheckReport::failed("DB_DOWN", "database unreachable");
        assert_eq!(report.status, SelfCheckStatus::Failed);
        assert_eq!(report.reason_code.as_deref(), Some("DB_DOWN"));
        assert_eq!(report.message.as_deref(), Some("database unreachable"));
    }

    #[test]
    fn self_check_report_unsupported() {
        let report = SelfCheckReport::unsupported();
        assert_eq!(report.status, SelfCheckStatus::Unsupported);
        assert!(report.reason_code.is_some());
        assert!(report.message.is_some());
    }

    #[test]
    fn self_check_report_from_error() {
        let error = FcpError::Unauthorized {
            code: 2001,
            message: "bad token".into(),
        };
        let report = SelfCheckReport::from_error(&error);
        assert_eq!(report.status, SelfCheckStatus::Failed);
        assert!(report.reason_code.is_some());
        assert!(report.message.is_some());
        assert!(report.message.unwrap().contains("bad token"));
    }

    #[test]
    fn self_check_report_serde_roundtrip_ok() {
        let report = SelfCheckReport::ok();
        let json = serde_json::to_string(&report).unwrap();
        let decoded: SelfCheckReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.status, SelfCheckStatus::Ok);
    }

    #[test]
    fn self_check_report_serde_roundtrip_degraded() {
        let report = SelfCheckReport::degraded("CODE", "msg");
        let json = serde_json::to_string(&report).unwrap();
        let decoded: SelfCheckReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.status, SelfCheckStatus::Degraded);
        assert_eq!(decoded.reason_code.as_deref(), Some("CODE"));
    }

    #[test]
    fn self_check_report_serde_omits_none_fields() {
        let report = SelfCheckReport::ok();
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("reason_code"));
        assert!(!json.contains("message"));
        assert!(!json.contains("details"));
    }

    #[test]
    fn self_check_report_clone() {
        let report = SelfCheckReport::degraded("R", "M");
        let cloned = report.clone();
        assert_eq!(cloned.status, report.status);
        assert_eq!(cloned.reason_code, report.reason_code);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Clone tests for types
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_state_clone() {
        let state = HealthState::Degraded {
            reason: "test".to_string(),
        };
        let cloned = Clone::clone(&state);
        assert_eq!(cloned.as_str(), "degraded");
    }

    #[test]
    fn health_snapshot_clone() {
        let snapshot = HealthSnapshot::ready();
        let cloned = Clone::clone(&snapshot);
        assert!(cloned.is_ready());
    }

    #[test]
    fn connector_health_clone() {
        let health = ConnectorHealth::degraded("slow");
        let cloned = Clone::clone(&health);
        assert!(cloned.is_available());
        assert!(!cloned.is_healthy());
    }

    #[test]
    fn rate_limit_status_clone() {
        let status = RateLimitStatus {
            limit: 100,
            remaining: 50,
            reset_at: 1_700_000_000,
            window_seconds: 60,
        };
        let cloned = Clone::clone(&status);
        assert_eq!(cloned.limit, 100);
        assert_eq!(cloned.remaining, 50);
    }

    #[test]
    fn liveness_response_clone() {
        let resp = LivenessResponse::default();
        let cloned = resp.clone();
        assert_eq!(cloned.alive, resp.alive);
    }

    #[test]
    fn readiness_response_clone() {
        let resp = ReadinessResponse::default();
        let cloned = resp.clone();
        assert_eq!(cloned.ready, resp.ready);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // HealthSnapshot with non-default uptime
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_snapshot_with_uptime() {
        let mut snapshot = HealthSnapshot::ready();
        snapshot.uptime_ms = 86_400_000; // 1 day
        assert_eq!(snapshot.uptime_ms, 86_400_000);
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("86400000"));
    }

    #[test]
    fn health_state_as_str() {
        assert_eq!(HealthState::Starting.as_str(), "starting");
        assert_eq!(HealthState::Ready.as_str(), "ready");
        assert_eq!(
            HealthState::Degraded {
                reason: "x".to_string()
            }
            .as_str(),
            "degraded"
        );
        assert_eq!(
            HealthState::Error {
                reason: "y".to_string()
            }
            .as_str(),
            "error"
        );
        assert_eq!(HealthState::Stopping.as_str(), "stopping");
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // HealthState – additional
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_state_debug_starting() {
        let s = format!("{:?}", HealthState::Starting);
        assert!(s.contains("Starting"));
    }

    #[test]
    fn health_state_debug_ready() {
        let s = format!("{:?}", HealthState::Ready);
        assert!(s.contains("Ready"));
    }

    #[test]
    fn health_state_debug_degraded_includes_reason() {
        let state = HealthState::Degraded {
            reason: "mem_pressure".to_string(),
        };
        let s = format!("{state:?}");
        assert!(s.contains("Degraded"));
        assert!(s.contains("mem_pressure"));
    }

    #[test]
    fn health_state_debug_error_includes_reason() {
        let state = HealthState::Error {
            reason: "disk_full".to_string(),
        };
        let s = format!("{state:?}");
        assert!(s.contains("Error"));
        assert!(s.contains("disk_full"));
    }

    #[test]
    fn health_state_debug_stopping() {
        let s = format!("{:?}", HealthState::Stopping);
        assert!(s.contains("Stopping"));
    }

    #[test]
    fn health_state_clone_starting() {
        let state = HealthState::Starting;
        let cloned = Clone::clone(&state);
        assert_eq!(cloned.as_str(), "starting");
    }

    #[test]
    fn health_state_clone_ready() {
        let state = HealthState::Ready;
        let cloned = Clone::clone(&state);
        assert_eq!(cloned.as_str(), "ready");
    }

    #[test]
    fn health_state_clone_stopping() {
        let state = HealthState::Stopping;
        let cloned = Clone::clone(&state);
        assert_eq!(cloned.as_str(), "stopping");
    }

    #[test]
    fn health_state_clone_error_preserves_reason() {
        let state = HealthState::Error {
            reason: "oops".to_string(),
        };
        let cloned = Clone::clone(&state);
        assert!(matches!(&cloned, HealthState::Error { reason } if reason == "oops"));
    }

    #[test]
    fn health_state_degraded_empty_reason() {
        let state = HealthState::Degraded {
            reason: String::new(),
        };
        assert_eq!(state.as_str(), "degraded");
        let json = serde_json::to_string(&state).unwrap();
        let decoded: HealthState = serde_json::from_str(&json).unwrap();
        assert!(matches!(&decoded, HealthState::Degraded { reason } if reason.is_empty()));
    }

    #[test]
    fn health_state_error_empty_reason() {
        let state = HealthState::Error {
            reason: String::new(),
        };
        assert_eq!(state.as_str(), "error");
    }

    #[test]
    fn health_state_roundtrip_all_variants() {
        let states = vec![
            HealthState::Starting,
            HealthState::Ready,
            HealthState::Degraded {
                reason: "slow".to_string(),
            },
            HealthState::Error {
                reason: "crash".to_string(),
            },
            HealthState::Stopping,
        ];
        for state in &states {
            let json = serde_json::to_string(state).unwrap();
            let decoded: HealthState = serde_json::from_str(&json).unwrap();
            assert_eq!(state.as_str(), decoded.as_str());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // HealthSnapshot – additional
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_snapshot_default_not_ready() {
        let snap = HealthSnapshot::default();
        assert!(!snap.is_ready());
    }

    #[test]
    fn health_snapshot_default_not_healthy() {
        let snap = HealthSnapshot::default();
        assert!(!snap.is_healthy());
    }

    #[test]
    fn health_snapshot_ready_uptime_zero() {
        let snap = HealthSnapshot::ready();
        assert_eq!(snap.uptime_ms, 0);
    }

    #[test]
    fn health_snapshot_ready_no_load() {
        let snap = HealthSnapshot::ready();
        assert!(snap.load.is_none());
    }

    #[test]
    fn health_snapshot_ready_no_details() {
        let snap = HealthSnapshot::ready();
        assert!(snap.details.is_none());
    }

    #[test]
    fn health_snapshot_ready_no_rate_limit() {
        let snap = HealthSnapshot::ready();
        assert!(snap.rate_limit.is_none());
    }

    #[test]
    fn health_snapshot_degraded_has_correct_reason() {
        let snap = HealthSnapshot::degraded("latency spike");
        assert!(
            matches!(&snap.status, HealthState::Degraded { reason } if reason == "latency spike")
        );
    }

    #[test]
    fn health_snapshot_error_has_correct_reason() {
        let snap = HealthSnapshot::error("timeout");
        assert!(matches!(&snap.status, HealthState::Error { reason } if reason == "timeout"));
    }

    #[test]
    fn health_snapshot_with_load() {
        let mut snap = HealthSnapshot::ready();
        snap.load = Some(0.5);
        let json = serde_json::to_string(&snap).unwrap();
        assert!(json.contains("\"load\""));
        let decoded: HealthSnapshot = serde_json::from_str(&json).unwrap();
        assert!((decoded.load.unwrap() - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn health_snapshot_load_zero() {
        let mut snap = HealthSnapshot::ready();
        snap.load = Some(0.0);
        let json = serde_json::to_string(&snap).unwrap();
        let decoded: HealthSnapshot = serde_json::from_str(&json).unwrap();
        assert!((decoded.load.unwrap()).abs() < f32::EPSILON);
    }

    #[test]
    fn health_snapshot_load_one() {
        let mut snap = HealthSnapshot::ready();
        snap.load = Some(1.0);
        let json = serde_json::to_string(&snap).unwrap();
        let decoded: HealthSnapshot = serde_json::from_str(&json).unwrap();
        assert!((decoded.load.unwrap() - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn health_snapshot_with_details_json() {
        let mut snap = HealthSnapshot::ready();
        snap.details = Some(json!({"version": "1.2.3", "active": true}));
        let json = serde_json::to_string(&snap).unwrap();
        assert!(json.contains("\"details\""));
        let decoded: HealthSnapshot = serde_json::from_str(&json).unwrap();
        let details = decoded.details.unwrap();
        assert_eq!(details["version"], "1.2.3");
        assert_eq!(details["active"], true);
    }

    #[test]
    fn health_snapshot_max_uptime() {
        let mut snap = HealthSnapshot::ready();
        snap.uptime_ms = u64::MAX;
        let json = serde_json::to_string(&snap).unwrap();
        let decoded: HealthSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.uptime_ms, u64::MAX);
    }

    #[test]
    fn health_snapshot_debug_format() {
        let snap = HealthSnapshot::ready();
        let debug = format!("{snap:?}");
        assert!(debug.contains("HealthSnapshot"));
    }

    #[test]
    fn health_snapshot_clone_preserves_fields() {
        let mut snap = HealthSnapshot::ready();
        snap.uptime_ms = 12345;
        snap.load = Some(0.42);
        let cloned = Clone::clone(&snap);
        assert!(cloned.is_ready());
        assert_eq!(cloned.uptime_ms, 12345);
        assert!((cloned.load.unwrap() - 0.42).abs() < f32::EPSILON);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // RateLimitStatus – additional
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn rate_limit_status_not_limited_when_remaining_positive() {
        let status = RateLimitStatus {
            limit: 1000,
            remaining: 1,
            reset_at: 0,
            window_seconds: 60,
        };
        assert!(!status.is_limited());
    }

    #[test]
    fn rate_limit_status_limited_at_zero_remaining() {
        let status = RateLimitStatus {
            limit: 100,
            remaining: 0,
            reset_at: 0,
            window_seconds: 60,
        };
        assert!(status.is_limited());
    }

    #[test]
    fn rate_limit_status_debug_format() {
        let status = RateLimitStatus {
            limit: 50,
            remaining: 25,
            reset_at: 1_000_000,
            window_seconds: 120,
        };
        let debug = format!("{status:?}");
        assert!(debug.contains("RateLimitStatus"));
        assert!(debug.contains("50"));
        assert!(debug.contains("25"));
    }

    #[test]
    fn rate_limit_status_clone_preserves_all_fields() {
        let status = RateLimitStatus {
            limit: 200,
            remaining: 150,
            reset_at: 9_999_999,
            window_seconds: 3600,
        };
        let cloned = Clone::clone(&status);
        assert_eq!(cloned.limit, 200);
        assert_eq!(cloned.remaining, 150);
        assert_eq!(cloned.reset_at, 9_999_999);
        assert_eq!(cloned.window_seconds, 3600);
    }

    #[test]
    fn rate_limit_status_json_field_names() {
        let status = RateLimitStatus {
            limit: 10,
            remaining: 5,
            reset_at: 100,
            window_seconds: 30,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"limit\""));
        assert!(json.contains("\"remaining\""));
        assert!(json.contains("\"reset_at\""));
        assert!(json.contains("\"window_seconds\""));
    }

    #[test]
    fn rate_limit_status_max_values() {
        let status = RateLimitStatus {
            limit: u32::MAX,
            remaining: u32::MAX,
            reset_at: u64::MAX,
            window_seconds: u32::MAX,
        };
        let json = serde_json::to_string(&status).unwrap();
        let decoded: RateLimitStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.limit, u32::MAX);
        assert_eq!(decoded.remaining, u32::MAX);
        assert_eq!(decoded.reset_at, u64::MAX);
        assert_eq!(decoded.window_seconds, u32::MAX);
    }

    #[test]
    fn rate_limit_status_zero_values() {
        let status = RateLimitStatus {
            limit: 0,
            remaining: 0,
            reset_at: 0,
            window_seconds: 0,
        };
        assert!(status.is_limited());
        let json = serde_json::to_string(&status).unwrap();
        let decoded: RateLimitStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.limit, 0);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ConnectorHealth – additional
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_health_healthy_debug() {
        let h = ConnectorHealth::healthy();
        let debug = format!("{h:?}");
        assert!(debug.contains("Healthy"));
    }

    #[test]
    fn connector_health_degraded_debug() {
        let h = ConnectorHealth::degraded("slow");
        let debug = format!("{h:?}");
        assert!(debug.contains("Degraded"));
        assert!(debug.contains("slow"));
    }

    #[test]
    fn connector_health_unavailable_debug() {
        let h = ConnectorHealth::unavailable("down");
        let debug = format!("{h:?}");
        assert!(debug.contains("Unavailable"));
        assert!(debug.contains("down"));
    }

    #[test]
    fn connector_health_clone_healthy() {
        let h = ConnectorHealth::healthy();
        let cloned = Clone::clone(&h);
        assert!(cloned.is_healthy());
        assert!(cloned.is_available());
    }

    #[test]
    fn connector_health_clone_unavailable() {
        let h = ConnectorHealth::unavailable("err");
        let cloned = Clone::clone(&h);
        assert!(!cloned.is_healthy());
        assert!(!cloned.is_available());
    }

    #[test]
    fn connector_health_unavailable_has_since() {
        let h = ConnectorHealth::unavailable("test");
        match &h {
            ConnectorHealth::Unavailable { since, .. } => {
                let now = chrono::Utc::now();
                let diff = (now - *since).num_seconds();
                assert!(diff.abs() < 2);
            }
            _ => panic!("expected Unavailable"),
        }
    }

    #[test]
    fn connector_health_degraded_empty_reason() {
        let h = ConnectorHealth::degraded("");
        assert!(h.is_available());
        assert!(!h.is_healthy());
        assert!(matches!(&h, ConnectorHealth::Degraded { reason } if reason.is_empty()));
    }

    #[test]
    fn connector_health_from_health_state_degraded_preserves_reason() {
        let state = HealthState::Degraded {
            reason: "high_latency".to_string(),
        };
        let ch = ConnectorHealth::from(&state);
        assert!(matches!(&ch, ConnectorHealth::Degraded { reason } if reason == "high_latency"));
    }

    #[test]
    fn connector_health_from_health_state_error_preserves_reason() {
        let state = HealthState::Error {
            reason: "segfault".to_string(),
        };
        let ch = ConnectorHealth::from(&state);
        assert!(matches!(&ch, ConnectorHealth::Unavailable { reason, .. } if reason == "segfault"));
    }

    #[test]
    fn connector_health_from_starting_reason_contains_starting() {
        let state = HealthState::Starting;
        let ch = ConnectorHealth::from(&state);
        match &ch {
            ConnectorHealth::Unavailable { reason, .. } => {
                assert!(reason.contains("starting"));
            }
            _ => panic!("expected Unavailable, got {ch:?}"),
        }
    }

    #[test]
    fn connector_health_from_stopping_reason_contains_stopping() {
        let state = HealthState::Stopping;
        let ch = ConnectorHealth::from(&state);
        match &ch {
            ConnectorHealth::Unavailable { reason, .. } => {
                assert!(reason.contains("stopping"));
            }
            _ => panic!("expected Unavailable, got {ch:?}"),
        }
    }

    #[test]
    fn connector_health_serde_roundtrip_degraded() {
        let h = ConnectorHealth::degraded("throttled");
        let json = serde_json::to_string(&h).unwrap();
        let decoded: ConnectorHealth = serde_json::from_str(&json).unwrap();
        assert!(decoded.is_available());
        assert!(!decoded.is_healthy());
    }

    #[test]
    fn connector_health_serde_roundtrip_unavailable() {
        let h = ConnectorHealth::unavailable("network");
        let json = serde_json::to_string(&h).unwrap();
        let decoded: ConnectorHealth = serde_json::from_str(&json).unwrap();
        assert!(!decoded.is_available());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // SelfCheckStatus – additional
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn self_check_status_debug() {
        assert_eq!(format!("{:?}", SelfCheckStatus::Ok), "Ok");
        assert_eq!(format!("{:?}", SelfCheckStatus::Degraded), "Degraded");
        assert_eq!(format!("{:?}", SelfCheckStatus::Failed), "Failed");
        assert_eq!(format!("{:?}", SelfCheckStatus::Unsupported), "Unsupported");
    }

    #[test]
    fn self_check_status_serde_ok() {
        let json = serde_json::to_string(&SelfCheckStatus::Ok).unwrap();
        assert_eq!(json, "\"ok\"");
    }

    #[test]
    fn self_check_status_serde_degraded() {
        let json = serde_json::to_string(&SelfCheckStatus::Degraded).unwrap();
        assert_eq!(json, "\"degraded\"");
    }

    #[test]
    fn self_check_status_serde_failed() {
        let json = serde_json::to_string(&SelfCheckStatus::Failed).unwrap();
        assert_eq!(json, "\"failed\"");
    }

    #[test]
    fn self_check_status_serde_unsupported() {
        let json = serde_json::to_string(&SelfCheckStatus::Unsupported).unwrap();
        assert_eq!(json, "\"unsupported\"");
    }

    #[test]
    fn self_check_status_reject_unknown() {
        let result = serde_json::from_str::<SelfCheckStatus>("\"unknown\"");
        assert!(result.is_err());
    }

    #[test]
    fn self_check_status_eq_reflexive() {
        let s = SelfCheckStatus::Ok;
        assert_eq!(s, s);
    }

    #[test]
    fn self_check_status_all_ne_pairs() {
        let all = [
            SelfCheckStatus::Ok,
            SelfCheckStatus::Degraded,
            SelfCheckStatus::Failed,
            SelfCheckStatus::Unsupported,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // SelfCheckReport – additional
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn self_check_report_ok_no_details() {
        let report = SelfCheckReport::ok();
        assert!(report.details.is_none());
    }

    #[test]
    fn self_check_report_degraded_no_details() {
        let report = SelfCheckReport::degraded("CODE", "msg");
        assert!(report.details.is_none());
    }

    #[test]
    fn self_check_report_failed_no_details() {
        let report = SelfCheckReport::failed("CODE", "msg");
        assert!(report.details.is_none());
    }

    #[test]
    fn self_check_report_unsupported_reason_code() {
        let report = SelfCheckReport::unsupported();
        assert_eq!(
            report.reason_code.as_deref(),
            Some("self_check_unsupported")
        );
    }

    #[test]
    fn self_check_report_unsupported_message() {
        let report = SelfCheckReport::unsupported();
        assert_eq!(
            report.message.as_deref(),
            Some("connector does not implement self-check")
        );
    }

    #[test]
    fn self_check_report_from_error_checksum_mismatch() {
        let error = FcpError::ChecksumMismatch;
        let report = SelfCheckReport::from_error(&error);
        assert_eq!(report.status, SelfCheckStatus::Failed);
        assert!(report.reason_code.is_some());
    }

    #[test]
    fn self_check_report_from_error_token_expired() {
        let error = FcpError::TokenExpired;
        let report = SelfCheckReport::from_error(&error);
        assert_eq!(report.status, SelfCheckStatus::Failed);
        assert!(report.message.unwrap().contains("expired"));
    }

    #[test]
    fn self_check_report_from_error_not_configured() {
        let error = FcpError::NotConfigured;
        let report = SelfCheckReport::from_error(&error);
        assert_eq!(report.status, SelfCheckStatus::Failed);
    }

    #[test]
    fn self_check_report_from_error_health_check_failed() {
        let error = FcpError::HealthCheckFailed {
            reason: "timeout".to_string(),
        };
        let report = SelfCheckReport::from_error(&error);
        assert_eq!(report.status, SelfCheckStatus::Failed);
        assert!(report.message.unwrap().contains("timeout"));
    }

    #[test]
    fn self_check_report_serde_roundtrip_failed() {
        let report = SelfCheckReport::failed("NET_ERR", "network error");
        let json = serde_json::to_string(&report).unwrap();
        let decoded: SelfCheckReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.status, SelfCheckStatus::Failed);
        assert_eq!(decoded.reason_code.as_deref(), Some("NET_ERR"));
        assert_eq!(decoded.message.as_deref(), Some("network error"));
    }

    #[test]
    fn self_check_report_serde_roundtrip_unsupported() {
        let report = SelfCheckReport::unsupported();
        let json = serde_json::to_string(&report).unwrap();
        let decoded: SelfCheckReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.status, SelfCheckStatus::Unsupported);
    }

    #[test]
    fn self_check_report_debug_format() {
        let report = SelfCheckReport::ok();
        let debug = format!("{report:?}");
        assert!(debug.contains("SelfCheckReport"));
    }

    #[test]
    fn self_check_report_clone_all_fields() {
        let report = SelfCheckReport::failed("X", "Y");
        let cloned = report.clone();
        assert_eq!(cloned.status, SelfCheckStatus::Failed);
        assert_eq!(cloned.reason_code, report.reason_code);
        assert_eq!(cloned.message, report.message);
        assert_eq!(cloned.details.is_none(), report.details.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // LivenessResponse – additional
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn liveness_response_debug() {
        let resp = LivenessResponse::default();
        let debug = format!("{resp:?}");
        assert!(debug.contains("LivenessResponse"));
    }

    #[test]
    fn liveness_response_alive_field_in_json() {
        let resp = LivenessResponse::default();
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"alive\":true"));
    }

    #[test]
    fn liveness_response_not_alive_in_json() {
        let resp = LivenessResponse {
            alive: false,
            timestamp: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"alive\":false"));
    }

    #[test]
    fn liveness_response_timestamp_in_json() {
        let resp = LivenessResponse::default();
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"timestamp\""));
    }

    #[test]
    fn liveness_response_clone_preserves_timestamp() {
        let resp = LivenessResponse::default();
        let cloned = resp.clone();
        assert_eq!(resp.timestamp, cloned.timestamp);
        assert_eq!(resp.alive, cloned.alive);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ReadinessResponse – additional
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn readiness_response_debug() {
        let resp = ReadinessResponse::default();
        let debug = format!("{resp:?}");
        assert!(debug.contains("ReadinessResponse"));
    }

    #[test]
    fn readiness_response_not_ready() {
        let resp = ReadinessResponse {
            ready: false,
            components: std::collections::HashMap::new(),
            timestamp: chrono::Utc::now(),
        };
        assert!(!resp.ready);
    }

    #[test]
    fn readiness_response_single_component() {
        let mut components = std::collections::HashMap::new();
        components.insert("db".to_string(), true);
        let resp = ReadinessResponse {
            ready: true,
            components,
            timestamp: chrono::Utc::now(),
        };
        assert_eq!(resp.components.len(), 1);
        assert!(resp.components["db"]);
    }

    #[test]
    fn readiness_response_many_components() {
        let mut components = std::collections::HashMap::new();
        for i in 0..10 {
            components.insert(format!("svc_{i}"), i % 2 == 0);
        }
        let resp = ReadinessResponse {
            ready: false,
            components,
            timestamp: chrono::Utc::now(),
        };
        assert_eq!(resp.components.len(), 10);
    }

    #[test]
    fn readiness_response_serde_with_components() {
        let mut components = std::collections::HashMap::new();
        components.insert("cache".to_string(), true);
        components.insert("queue".to_string(), false);
        let resp = ReadinessResponse {
            ready: true,
            components,
            timestamp: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: ReadinessResponse = serde_json::from_str(&json).unwrap();
        assert!(decoded.ready);
        assert_eq!(decoded.components.len(), 2);
        assert!(decoded.components["cache"]);
        assert!(!decoded.components["queue"]);
    }

    #[test]
    fn readiness_response_clone_preserves_components() {
        let mut components = std::collections::HashMap::new();
        components.insert("x".to_string(), true);
        let resp = ReadinessResponse {
            ready: true,
            components,
            timestamp: chrono::Utc::now(),
        };
        let cloned = Clone::clone(&resp);
        assert_eq!(cloned.components.len(), 1);
        assert!(cloned.components["x"]);
    }

    #[test]
    fn readiness_response_json_ready_field() {
        let resp = ReadinessResponse::default();
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"ready\":true"));
    }

    #[test]
    fn readiness_response_from_raw_json_no_components() {
        let raw = r#"{
            "ready": false,
            "timestamp": "2025-01-01T00:00:00Z"
        }"#;
        let resp: ReadinessResponse = serde_json::from_str(raw).unwrap();
        assert!(!resp.ready);
        assert!(resp.components.is_empty());
    }
}
