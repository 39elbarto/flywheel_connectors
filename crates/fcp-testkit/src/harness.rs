//! Test harness for FCP connectors.
//!
//! The [`ConnectorTestHarness`] wraps a connector and provides:
//! - Automatic logging and request/response recording
//! - Convenience methods for common test flows
//! - Built-in assertions for connector state

use std::time::Instant;

use fcp_sdk::{FcpConnector, FcpResult, HealthSnapshot};
use tracing::{debug, info};

/// Recorded operation for test inspection.
#[derive(Debug, Clone)]
pub struct RecordedOperation {
    /// Operation name
    pub operation: String,
    /// Input parameters (as JSON)
    pub input: Option<serde_json::Value>,
    /// Result (success value or error message)
    pub result: Result<serde_json::Value, String>,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Test harness that wraps an FCP connector with testing utilities.
///
/// Provides:
/// - Request/response recording for assertions
/// - Timing measurements
/// - Convenience methods for common test flows
/// - State tracking
pub struct ConnectorTestHarness<C> {
    connector: C,
    operations: Vec<RecordedOperation>,
    configured: bool,
    handshaken: bool,
}

impl<C: FcpConnector> ConnectorTestHarness<C> {
    /// Create a new test harness wrapping the given connector.
    pub const fn new(connector: C) -> Self {
        Self {
            connector,
            operations: Vec::new(),
            configured: false,
            handshaken: false,
        }
    }

    /// Get a reference to the inner connector.
    pub const fn connector(&self) -> &C {
        &self.connector
    }

    /// Get a mutable reference to the inner connector.
    pub const fn connector_mut(&mut self) -> &mut C {
        &mut self.connector
    }

    /// Get all recorded operations.
    #[must_use]
    pub fn operations(&self) -> &[RecordedOperation] {
        &self.operations
    }

    /// Get the last recorded operation.
    #[must_use]
    pub fn last_operation(&self) -> Option<&RecordedOperation> {
        self.operations.last()
    }

    /// Clear recorded operations.
    pub fn clear_operations(&mut self) {
        self.operations.clear();
    }

    /// Check if the harness has been configured.
    #[must_use]
    pub const fn is_configured(&self) -> bool {
        self.configured
    }

    /// Check if the harness has completed handshake.
    #[must_use]
    pub const fn is_handshaken(&self) -> bool {
        self.handshaken
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Configuration
    // ─────────────────────────────────────────────────────────────────────────────

    /// Configure the connector with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if configuration fails.
    pub async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let start = Instant::now();
        info!("Configuring connector with: {:?}", config);

        let result = self.connector.configure(config.clone()).await;

        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        self.operations.push(RecordedOperation {
            operation: "configure".to_string(),
            input: Some(config),
            result: result
                .as_ref()
                .map(|()| serde_json::json!({}))
                .map_err(ToString::to_string),
            duration_ms,
            timestamp: chrono::Utc::now(),
        });

        if result.is_ok() {
            self.configured = true;
        }

        result
    }

    /// Configure with an empty configuration object.
    ///
    /// # Errors
    ///
    /// Returns an error if configuration fails.
    pub async fn configure_default(&mut self) -> FcpResult<()> {
        self.configure(serde_json::json!({})).await
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Health
    // ─────────────────────────────────────────────────────────────────────────────

    /// Get the connector's health status.
    pub async fn health(&mut self) -> HealthSnapshot {
        let start = Instant::now();
        debug!("Getting health status");

        let result = self.connector.health().await;

        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        self.operations.push(RecordedOperation {
            operation: "health".to_string(),
            input: None,
            result: Ok(serde_json::to_value(&result).unwrap_or_default()),
            duration_ms,
            timestamp: chrono::Utc::now(),
        });

        result
    }

    /// Get the connector's introspection data.
    pub fn introspect(&mut self) -> fcp_core::Introspection {
        let start = Instant::now();
        debug!("Getting introspection");

        let result = self.connector.introspect();

        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        self.operations.push(RecordedOperation {
            operation: "introspect".to_string(),
            input: None,
            result: Ok(serde_json::to_value(&result).unwrap_or_default()),
            duration_ms,
            timestamp: chrono::Utc::now(),
        });

        result
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Assertions
    // ─────────────────────────────────────────────────────────────────────────────

    /// Assert that the last operation succeeded.
    ///
    /// # Panics
    ///
    /// Panics if the last operation failed or no operations recorded.
    pub fn assert_last_success(&self) {
        let op = self.last_operation().expect("No operations recorded");
        assert!(op.result.is_ok(), "Last operation failed: {:?}", op.result);
    }

    /// Assert that the last operation failed.
    ///
    /// # Panics
    ///
    /// Panics if the last operation succeeded or no operations recorded.
    pub fn assert_last_failure(&self) {
        let op = self.last_operation().expect("No operations recorded");
        assert!(
            op.result.is_err(),
            "Expected failure but got: {:?}",
            op.result
        );
    }

    /// Assert the connector is ready.
    ///
    /// # Panics
    ///
    /// Panics if the connector is not ready.
    pub async fn assert_ready(&mut self) {
        let health = self.health().await;
        assert!(
            health.is_ready(),
            "Connector not ready: {:?}",
            health.status
        );
    }

    /// Assert the connector is healthy (ready or degraded).
    ///
    /// # Panics
    ///
    /// Panics if the connector is not healthy.
    pub async fn assert_healthy(&mut self) {
        let health = self.health().await;
        assert!(
            health.is_healthy(),
            "Connector not healthy: {:?}",
            health.status
        );
    }

    /// Assert total operation count.
    ///
    /// # Panics
    ///
    /// Panics if count doesn't match.
    pub fn assert_operation_count(&self, expected: usize) {
        assert_eq!(
            self.operations.len(),
            expected,
            "Expected {} operations but got {}",
            expected,
            self.operations.len()
        );
    }

    /// Assert all operations completed under the given duration.
    ///
    /// # Panics
    ///
    /// Panics if any operation exceeded the duration.
    pub fn assert_all_under_duration(&self, max_ms: u64) {
        for op in &self.operations {
            assert!(
                op.duration_ms <= max_ms,
                "Operation '{}' took {}ms, exceeding limit of {}ms",
                op.operation,
                op.duration_ms,
                max_ms
            );
        }
    }

    /// Get statistics about recorded operations.
    #[must_use]
    pub fn stats(&self) -> HarnessStats {
        let total = self.operations.len();
        let successes = self
            .operations
            .iter()
            .filter(|op| op.result.is_ok())
            .count();
        let failures = total - successes;
        let total_duration_ms: u64 = self.operations.iter().map(|op| op.duration_ms).sum();
        let avg_duration_ms = if total > 0 {
            total_duration_ms / total as u64
        } else {
            0
        };
        let max_duration_ms = self
            .operations
            .iter()
            .map(|op| op.duration_ms)
            .max()
            .unwrap_or(0);

        HarnessStats {
            total_operations: total,
            successes,
            failures,
            total_duration_ms,
            avg_duration_ms,
            max_duration_ms,
        }
    }
}

/// Statistics about harness operations.
#[derive(Debug, Clone)]
pub struct HarnessStats {
    /// Total operations executed
    pub total_operations: usize,
    /// Successful operations
    pub successes: usize,
    /// Failed operations
    pub failures: usize,
    /// Total duration in milliseconds
    pub total_duration_ms: u64,
    /// Average duration in milliseconds
    pub avg_duration_ms: u64,
    /// Maximum duration in milliseconds
    pub max_duration_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::catch_unwind;

    // ── RecordedOperation ──────────────────────────────────────────────

    #[test]
    fn recorded_operation_success() {
        let op = RecordedOperation {
            operation: "test_op".to_string(),
            input: Some(serde_json::json!({"key": "value"})),
            result: Ok(serde_json::json!({"status": "ok"})),
            duration_ms: 42,
            timestamp: chrono::Utc::now(),
        };
        assert!(op.result.is_ok());
        assert_eq!(op.operation, "test_op");
        assert_eq!(op.duration_ms, 42);
    }

    #[test]
    fn recorded_operation_failure() {
        let op = RecordedOperation {
            operation: "failing_op".to_string(),
            input: None,
            result: Err("something went wrong".to_string()),
            duration_ms: 100,
            timestamp: chrono::Utc::now(),
        };
        assert!(op.result.is_err());
        assert_eq!(op.result.unwrap_err(), "something went wrong");
    }

    #[test]
    fn recorded_operation_debug() {
        let op = RecordedOperation {
            operation: "debug_op".to_string(),
            input: None,
            result: Ok(serde_json::json!(null)),
            duration_ms: 0,
            timestamp: chrono::Utc::now(),
        };
        let dbg = format!("{op:?}");
        assert!(dbg.contains("RecordedOperation"));
        assert!(dbg.contains("debug_op"));
    }

    #[test]
    fn recorded_operation_clone() {
        let op = RecordedOperation {
            operation: "clone_op".to_string(),
            input: Some(serde_json::json!(42)),
            result: Ok(serde_json::json!("done")),
            duration_ms: 5,
            timestamp: chrono::Utc::now(),
        };
        let cloned = op.clone();
        assert_eq!(op.operation, cloned.operation);
        assert_eq!(op.duration_ms, cloned.duration_ms);
    }

    // ── HarnessStats ───────────────────────────────────────────────────

    #[test]
    fn harness_stats_debug() {
        let stats = HarnessStats {
            total_operations: 10,
            successes: 8,
            failures: 2,
            total_duration_ms: 500,
            avg_duration_ms: 50,
            max_duration_ms: 100,
        };
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("HarnessStats"));
        assert!(dbg.contains("10"));
    }

    #[test]
    fn harness_stats_clone() {
        let stats = HarnessStats {
            total_operations: 5,
            successes: 5,
            failures: 0,
            total_duration_ms: 100,
            avg_duration_ms: 20,
            max_duration_ms: 30,
        };
        let cloned = stats.clone();
        assert_eq!(stats.total_operations, cloned.total_operations);
        assert_eq!(stats.successes, cloned.successes);
        assert_eq!(stats.failures, cloned.failures);
    }

    #[test]
    fn harness_stats_all_failures() {
        let stats = HarnessStats {
            total_operations: 3,
            successes: 0,
            failures: 3,
            total_duration_ms: 300,
            avg_duration_ms: 100,
            max_duration_ms: 150,
        };
        assert_eq!(stats.successes, 0);
        assert_eq!(stats.failures, 3);
    }

    #[test]
    fn harness_stats_zero_operations() {
        let stats = HarnessStats {
            total_operations: 0,
            successes: 0,
            failures: 0,
            total_duration_ms: 0,
            avg_duration_ms: 0,
            max_duration_ms: 0,
        };
        assert_eq!(stats.total_operations, 0);
        assert_eq!(stats.avg_duration_ms, 0);
    }

    // ── ConnectorTestHarness (state machine, no real connector) ────────

    // Minimal mock connector for testing the harness itself
    struct StubConnector {
        configure_should_fail: bool,
    }

    impl StubConnector {
        fn ok() -> Self {
            Self {
                configure_should_fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                configure_should_fail: true,
            }
        }
    }

fcp_core::impl_fcp_sealed!(StubConnector);

    #[async_trait::async_trait]
    impl FcpConnector for StubConnector {
        fn id(&self) -> &fcp_core::ConnectorId {
            static ID: std::sync::LazyLock<fcp_core::ConnectorId> =
                std::sync::LazyLock::new(|| {
                    fcp_core::ConnectorId::from_static("stub:connector:v1")
                });
            &ID
        }

        async fn configure(&mut self, _config: serde_json::Value) -> FcpResult<()> {
            if self.configure_should_fail {
                Err(fcp_core::FcpError::InvalidRequest {
                    code: 1001,
                    message: "stub failure".to_string(),
                })
            } else {
                Ok(())
            }
        }

        async fn handshake(
            &mut self,
            _req: fcp_core::HandshakeRequest,
        ) -> FcpResult<fcp_core::HandshakeResponse> {
            Ok(fcp_core::HandshakeResponse {
                status: "accepted".to_string(),
                capabilities_granted: vec![],
                session_id: fcp_core::SessionId::new(),
                manifest_hash: String::new(),
                nonce: _req.nonce,
                event_caps: None,
                auth_caps: None,
                op_catalog_hash: None,
            })
        }

        async fn health(&self) -> HealthSnapshot {
            HealthSnapshot::ready()
        }

        fn metrics(&self) -> fcp_core::ConnectorMetrics {
            fcp_core::ConnectorMetrics::default()
        }

        async fn shutdown(&mut self, _req: fcp_core::ShutdownRequest) -> FcpResult<()> {
            Ok(())
        }

        fn introspect(&self) -> fcp_core::Introspection {
            fcp_core::Introspection {
                operations: vec![],
                events: vec![],
                resource_types: vec![],
                auth_caps: None,
                event_caps: None,
            }
        }

        async fn invoke(
            &self,
            _req: fcp_core::InvokeRequest,
        ) -> FcpResult<fcp_core::InvokeResponse> {
            Err(fcp_core::FcpError::OperationNotGranted {
                operation: "stub".to_string(),
            })
        }

        async fn subscribe(
            &self,
            _req: fcp_core::SubscribeRequest,
        ) -> FcpResult<fcp_core::SubscribeResponse> {
            Ok(fcp_core::SubscribeResponse {
                r#type: "response".to_string(),
                id: fcp_core::RequestId::new("sub-stub"),
                result: fcp_core::SubscribeResult {
                    confirmed_topics: vec![],
                    cursors: std::collections::HashMap::new(),
                    replay_supported: false,
                    buffer: None,
                },
            })
        }

        async fn unsubscribe(&self, _req: fcp_core::UnsubscribeRequest) -> FcpResult<()> {
            Ok(())
        }
    }

    #[fcp_async_core::runtime::test]
    async fn harness_initial_state() {
        let harness = ConnectorTestHarness::new(StubConnector::ok());
        assert!(!harness.is_configured());
        assert!(!harness.is_handshaken());
        assert!(harness.operations().is_empty());
        assert!(harness.last_operation().is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn harness_configure_success() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        let result = harness.configure(serde_json::json!({"key": "val"})).await;
        assert!(result.is_ok());
        assert!(harness.is_configured());
        assert_eq!(harness.operations().len(), 1);
        harness.assert_last_success();
        harness.assert_operation_count(1);
    }

    #[fcp_async_core::runtime::test]
    async fn harness_configure_failure() {
        let mut harness = ConnectorTestHarness::new(StubConnector::failing());
        let result = harness.configure(serde_json::json!({})).await;
        assert!(result.is_err());
        assert!(!harness.is_configured());
        harness.assert_last_failure();
    }

    #[fcp_async_core::runtime::test]
    async fn harness_configure_default() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        harness.configure_default().await.unwrap();
        assert!(harness.is_configured());
    }

    #[fcp_async_core::runtime::test]
    async fn harness_health() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        let health = harness.health().await;
        assert!(health.is_ready());
        assert_eq!(harness.operations().len(), 1);
        assert_eq!(harness.operations()[0].operation, "health");
    }

    #[fcp_async_core::runtime::test]
    async fn harness_introspect() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        let _intro = harness.introspect();
        assert_eq!(harness.operations().len(), 1);
        assert_eq!(harness.operations()[0].operation, "introspect");
    }

    #[fcp_async_core::runtime::test]
    async fn harness_connector_ref() {
        let harness = ConnectorTestHarness::new(StubConnector::ok());
        let _c = harness.connector();
    }

    #[fcp_async_core::runtime::test]
    async fn harness_connector_mut_ref() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        let _c = harness.connector_mut();
    }

    #[fcp_async_core::runtime::test]
    async fn harness_clear_operations() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        harness.configure_default().await.unwrap();
        harness.health().await;
        assert_eq!(harness.operations().len(), 2);
        harness.clear_operations();
        assert!(harness.operations().is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn harness_stats_empty() {
        let harness = ConnectorTestHarness::new(StubConnector::ok());
        let stats = harness.stats();
        assert_eq!(stats.total_operations, 0);
        assert_eq!(stats.successes, 0);
        assert_eq!(stats.failures, 0);
        assert_eq!(stats.avg_duration_ms, 0);
        assert_eq!(stats.max_duration_ms, 0);
    }

    #[fcp_async_core::runtime::test]
    async fn harness_stats_mixed() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        harness.configure_default().await.unwrap();
        harness.health().await;

        // Manually push a failure
        harness.operations.push(RecordedOperation {
            operation: "manual_fail".to_string(),
            input: None,
            result: Err("oops".to_string()),
            duration_ms: 50,
            timestamp: chrono::Utc::now(),
        });

        let stats = harness.stats();
        assert_eq!(stats.total_operations, 3);
        assert_eq!(stats.successes, 2);
        assert_eq!(stats.failures, 1);
        assert!(stats.max_duration_ms >= 50);
    }

    #[fcp_async_core::runtime::test]
    async fn harness_assert_all_under_duration() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        harness.configure_default().await.unwrap();
        harness.health().await;
        // All fast operations should be under 5000ms
        harness.assert_all_under_duration(5000);
    }

    #[test]
    fn harness_assert_last_success_panics_without_operations() {
        let harness = ConnectorTestHarness::new(StubConnector::ok());

        let panic = catch_unwind(|| harness.assert_last_success());

        assert!(panic.is_err());
    }

    #[test]
    fn harness_assert_last_failure_panics_without_operations() {
        let harness = ConnectorTestHarness::new(StubConnector::ok());

        let panic = catch_unwind(|| harness.assert_last_failure());

        assert!(panic.is_err());
    }

    #[test]
    fn harness_assert_operation_count_panics_on_mismatch() {
        let harness = ConnectorTestHarness::new(StubConnector::ok());

        let panic = catch_unwind(|| harness.assert_operation_count(1));

        assert!(panic.is_err());
    }

    #[test]
    fn harness_assert_all_under_duration_panics_when_limit_is_exceeded() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        harness.operations.push(RecordedOperation {
            operation: "slow".to_string(),
            input: None,
            result: Ok(serde_json::json!({})),
            duration_ms: 15,
            timestamp: chrono::Utc::now(),
        });

        let panic = catch_unwind(|| harness.assert_all_under_duration(10));

        assert!(panic.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn harness_assert_ready() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        harness.assert_ready().await;
    }

    #[fcp_async_core::runtime::test]
    async fn harness_assert_healthy() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        harness.assert_healthy().await;
    }

    #[fcp_async_core::runtime::test]
    async fn harness_last_operation_records_input() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        let config = serde_json::json!({"port": 8080});
        harness.configure(config.clone()).await.unwrap();
        let last = harness.last_operation().unwrap();
        assert_eq!(last.input, Some(config));
    }

    // ---- Additional RecordedOperation tests ----

    #[test]
    fn recorded_operation_with_no_input() {
        let op = RecordedOperation {
            operation: "health_check".to_string(),
            input: None,
            result: Ok(serde_json::json!({"status": "ready"})),
            duration_ms: 10,
            timestamp: chrono::Utc::now(),
        };
        assert!(op.input.is_none());
        assert!(op.result.is_ok());
    }

    #[test]
    fn recorded_operation_error_message_preserved() {
        let op = RecordedOperation {
            operation: "configure".to_string(),
            input: Some(serde_json::json!({})),
            result: Err("invalid config".to_string()),
            duration_ms: 1,
            timestamp: chrono::Utc::now(),
        };
        assert_eq!(op.result.unwrap_err(), "invalid config");
    }

    #[test]
    fn recorded_operation_zero_duration() {
        let op = RecordedOperation {
            operation: "fast_op".to_string(),
            input: None,
            result: Ok(serde_json::json!(null)),
            duration_ms: 0,
            timestamp: chrono::Utc::now(),
        };
        assert_eq!(op.duration_ms, 0);
    }

    #[test]
    fn recorded_operation_clone_preserves_timestamp() {
        let now = chrono::Utc::now();
        let op = RecordedOperation {
            operation: "timed_op".to_string(),
            input: None,
            result: Ok(serde_json::json!({})),
            duration_ms: 25,
            timestamp: now,
        };
        let cloned = op.clone();
        assert_eq!(op.timestamp, cloned.timestamp);
    }

    // ---- Additional HarnessStats tests ----

    #[test]
    fn harness_stats_all_successes() {
        let stats = HarnessStats {
            total_operations: 10,
            successes: 10,
            failures: 0,
            total_duration_ms: 200,
            avg_duration_ms: 20,
            max_duration_ms: 45,
        };
        assert_eq!(stats.failures, 0);
        assert_eq!(stats.successes, stats.total_operations);
    }

    #[test]
    fn harness_stats_debug_contains_field_names() {
        let stats = HarnessStats {
            total_operations: 1,
            successes: 1,
            failures: 0,
            total_duration_ms: 5,
            avg_duration_ms: 5,
            max_duration_ms: 5,
        };
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("total_operations"));
        assert!(dbg.contains("successes"));
        assert!(dbg.contains("failures"));
    }

    #[test]
    fn harness_stats_clone_preserves_all_fields() {
        let stats = HarnessStats {
            total_operations: 7,
            successes: 4,
            failures: 3,
            total_duration_ms: 700,
            avg_duration_ms: 100,
            max_duration_ms: 250,
        };
        let cloned = stats.clone();
        assert_eq!(stats.total_operations, cloned.total_operations);
        assert_eq!(stats.successes, cloned.successes);
        assert_eq!(stats.failures, cloned.failures);
        assert_eq!(stats.total_duration_ms, cloned.total_duration_ms);
        assert_eq!(stats.avg_duration_ms, cloned.avg_duration_ms);
        assert_eq!(stats.max_duration_ms, cloned.max_duration_ms);
    }

    // ---- Additional ConnectorTestHarness tests ----

    #[test]
    fn harness_new_has_empty_stats() {
        let harness = ConnectorTestHarness::new(StubConnector::ok());
        let stats = harness.stats();
        assert_eq!(stats.total_operations, 0);
        assert_eq!(stats.total_duration_ms, 0);
    }

    #[fcp_async_core::runtime::test]
    async fn harness_multiple_operations_tracked() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        harness.configure_default().await.unwrap();
        harness.health().await;
        let _ = harness.introspect();

        assert_eq!(harness.operations().len(), 3);
        assert_eq!(harness.operations()[0].operation, "configure");
        assert_eq!(harness.operations()[1].operation, "health");
        assert_eq!(harness.operations()[2].operation, "introspect");
    }

    #[fcp_async_core::runtime::test]
    async fn harness_stats_after_configure_and_health() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        harness.configure_default().await.unwrap();
        harness.health().await;

        let stats = harness.stats();
        assert_eq!(stats.total_operations, 2);
        assert_eq!(stats.successes, 2);
        assert_eq!(stats.failures, 0);
    }

    #[fcp_async_core::runtime::test]
    async fn harness_clear_then_re_record() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        harness.configure_default().await.unwrap();
        assert_eq!(harness.operations().len(), 1);

        harness.clear_operations();
        assert!(harness.operations().is_empty());

        harness.health().await;
        assert_eq!(harness.operations().len(), 1);
        assert_eq!(harness.operations()[0].operation, "health");
    }

    // ---- Additional RecordedOperation edge case tests ----

    #[test]
    fn recorded_operation_with_large_input() {
        let large_json = serde_json::json!({
            "items": (0..50).map(|i| serde_json::json!({"id": i})).collect::<Vec<_>>()
        });
        let op = RecordedOperation {
            operation: "bulk_op".to_string(),
            input: Some(large_json),
            result: Ok(serde_json::json!({"count": 50})),
            duration_ms: 200,
            timestamp: chrono::Utc::now(),
        };
        assert_eq!(
            op.input.as_ref().unwrap()["items"]
                .as_array()
                .unwrap()
                .len(),
            50
        );
    }

    #[test]
    fn recorded_operation_result_ok_null() {
        let op = RecordedOperation {
            operation: "void_op".to_string(),
            input: None,
            result: Ok(serde_json::Value::Null),
            duration_ms: 0,
            timestamp: chrono::Utc::now(),
        };
        assert!(op.result.is_ok());
        assert!(op.result.unwrap().is_null());
    }

    #[test]
    fn recorded_operation_result_err_preserves_full_message() {
        let msg = "Connection refused: 127.0.0.1:5432 - authentication failed for user 'admin'";
        let op = RecordedOperation {
            operation: "db_connect".to_string(),
            input: None,
            result: Err(msg.to_string()),
            duration_ms: 15,
            timestamp: chrono::Utc::now(),
        };
        assert_eq!(op.result.unwrap_err(), msg);
    }

    // ---- Additional HarnessStats edge case tests ----

    #[test]
    fn harness_stats_high_duration_values() {
        let stats = HarnessStats {
            total_operations: 1,
            successes: 1,
            failures: 0,
            total_duration_ms: u64::MAX,
            avg_duration_ms: u64::MAX,
            max_duration_ms: u64::MAX,
        };
        assert_eq!(stats.total_duration_ms, u64::MAX);
        assert_eq!(stats.max_duration_ms, u64::MAX);
    }

    #[test]
    fn harness_stats_successes_plus_failures_equals_total() {
        let stats = HarnessStats {
            total_operations: 15,
            successes: 9,
            failures: 6,
            total_duration_ms: 1500,
            avg_duration_ms: 100,
            max_duration_ms: 250,
        };
        assert_eq!(stats.successes + stats.failures, stats.total_operations);
    }

    // ---- Additional ConnectorTestHarness tests ----

    #[fcp_async_core::runtime::test]
    async fn harness_configure_does_not_set_handshaken() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        harness.configure_default().await.unwrap();
        assert!(harness.is_configured());
        assert!(!harness.is_handshaken());
    }

    #[fcp_async_core::runtime::test]
    async fn harness_stats_after_failure() {
        let mut harness = ConnectorTestHarness::new(StubConnector::failing());
        let _ = harness.configure(serde_json::json!({})).await;
        let stats = harness.stats();
        assert_eq!(stats.total_operations, 1);
        assert_eq!(stats.successes, 0);
        assert_eq!(stats.failures, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn harness_last_operation_after_health_is_health() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        harness.configure_default().await.unwrap();
        harness.health().await;
        let last = harness.last_operation().unwrap();
        assert_eq!(last.operation, "health");
        assert!(last.result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn harness_operations_ordering_preserved() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        harness.configure_default().await.unwrap();
        let _ = harness.introspect();
        harness.health().await;

        let ops: Vec<&str> = harness
            .operations()
            .iter()
            .map(|o| o.operation.as_str())
            .collect();
        assert_eq!(ops, ["configure", "introspect", "health"]);
    }

    #[fcp_async_core::runtime::test]
    async fn harness_connector_ref_stable() {
        let harness = ConnectorTestHarness::new(StubConnector::ok());
        let c = harness.connector();
        // StubConnector has configure_should_fail = false
        assert!(!c.configure_should_fail);
    }

    #[fcp_async_core::runtime::test]
    async fn harness_connector_mut_can_toggle_flag() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        harness.connector_mut().configure_should_fail = true;
        let result = harness.configure_default().await;
        assert!(result.is_err());
        assert!(!harness.is_configured());
    }

    #[fcp_async_core::runtime::test]
    async fn harness_clear_preserves_configured_state() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        harness.configure_default().await.unwrap();
        assert!(harness.is_configured());
        harness.clear_operations();
        assert!(harness.operations().is_empty());
        // configured flag should still be true
        assert!(harness.is_configured());
    }

    #[fcp_async_core::runtime::test]
    async fn harness_stats_avg_duration_is_reasonable() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        harness.configure_default().await.unwrap();
        harness.health().await;
        let stats = harness.stats();
        // avg should be <= total
        assert!(stats.avg_duration_ms <= stats.total_duration_ms);
    }

    #[fcp_async_core::runtime::test]
    async fn harness_introspect_records_ok_result() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        let _ = harness.introspect();
        let last = harness.last_operation().unwrap();
        assert_eq!(last.operation, "introspect");
        assert!(last.result.is_ok());
        assert!(last.input.is_none());
    }

    // ---- RecordedOperation edge cases ----

    #[test]
    fn recorded_operation_empty_operation_name() {
        let op = RecordedOperation {
            operation: String::new(),
            input: None,
            result: Ok(serde_json::json!(null)),
            duration_ms: 0,
            timestamp: chrono::Utc::now(),
        };
        assert!(op.operation.is_empty());
    }

    #[test]
    fn recorded_operation_unicode_operation_name() {
        let op = RecordedOperation {
            operation: "op-caf\u{00e9}".to_string(),
            input: Some(serde_json::json!({"key": "\u{2603}"})),
            result: Ok(serde_json::json!("\u{2764}")),
            duration_ms: 1,
            timestamp: chrono::Utc::now(),
        };
        assert!(op.operation.contains("caf\u{00e9}"));
        let dbg = format!("{op:?}");
        assert!(dbg.contains("caf\u{00e9}"));
    }

    #[test]
    fn recorded_operation_max_duration() {
        let op = RecordedOperation {
            operation: "long_op".to_string(),
            input: None,
            result: Ok(serde_json::json!(null)),
            duration_ms: u64::MAX,
            timestamp: chrono::Utc::now(),
        };
        assert_eq!(op.duration_ms, u64::MAX);
    }

    #[test]
    fn recorded_operation_clone_result_err() {
        let op = RecordedOperation {
            operation: "fail_clone".to_string(),
            input: None,
            result: Err("cloned error".to_string()),
            duration_ms: 7,
            timestamp: chrono::Utc::now(),
        };
        let cloned = op.clone();
        assert_eq!(op.result, cloned.result);
    }

    // ---- HarnessStats edge cases ----

    #[test]
    fn harness_stats_single_failure() {
        let stats = HarnessStats {
            total_operations: 1,
            successes: 0,
            failures: 1,
            total_duration_ms: 42,
            avg_duration_ms: 42,
            max_duration_ms: 42,
        };
        assert_eq!(stats.successes + stats.failures, stats.total_operations);
        assert_eq!(stats.avg_duration_ms, stats.max_duration_ms);
    }

    #[test]
    fn harness_stats_large_values() {
        let stats = HarnessStats {
            total_operations: usize::MAX,
            successes: usize::MAX / 2,
            failures: usize::MAX - usize::MAX / 2,
            total_duration_ms: u64::MAX,
            avg_duration_ms: u64::MAX,
            max_duration_ms: u64::MAX,
        };
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("HarnessStats"));
    }

    // ---- ConnectorTestHarness additional tests ----

    #[fcp_async_core::runtime::test]
    async fn harness_stats_total_duration_accumulates() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        harness.configure_default().await.unwrap();
        harness.health().await;
        let _ = harness.introspect();
        let stats = harness.stats();
        assert_eq!(stats.total_operations, 3);
        // Each op's duration contributes to total
        assert_eq!(
            stats.total_duration_ms,
            harness
                .operations()
                .iter()
                .map(|op| op.duration_ms)
                .sum::<u64>()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn harness_stats_max_duration_geq_avg() {
        let mut harness = ConnectorTestHarness::new(StubConnector::ok());
        harness.configure_default().await.unwrap();
        harness.health().await;
        let stats = harness.stats();
        assert!(stats.max_duration_ms >= stats.avg_duration_ms);
    }

    #[test]
    fn harness_assert_all_under_duration_empty_operations() {
        let harness = ConnectorTestHarness::new(StubConnector::ok());
        // No operations recorded, so nothing to fail
        harness.assert_all_under_duration(0);
    }
}
