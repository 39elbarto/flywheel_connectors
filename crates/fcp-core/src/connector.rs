//! Connector trait and base types.
//!
//! Based on FCP Specification Section 4 (System Architecture).

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use futures_util::Stream;
use serde::{Deserialize, Serialize};

use crate::{
    CapabilityToken, ConnectorId, EventAck, EventEnvelope, EventNack, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, InstanceId, Introspection, InvokeRequest, InvokeResponse,
    RateLimitDeclarations, SelfCheckReport, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
};

/// Type alias for event streams.
pub type EventStream = Pin<Box<dyn Stream<Item = FcpResult<EventEnvelope>> + Send>>;

/// Core connector trait - all FCP connectors must implement this.
#[async_trait]
pub trait FcpConnector: Send + Sync {
    /// Get the connector's unique identifier.
    fn id(&self) -> &ConnectorId;

    /// Configure the connector with the given settings.
    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()>;

    /// Perform the FCP handshake.
    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse>;

    /// Get the current health status.
    async fn health(&self) -> HealthSnapshot;

    /// Run a connector self-check (read-only, bounded).
    ///
    /// **Contract:**
    /// - MUST NOT perform side effects (read-only checks only).
    /// - MUST be bounded by timeouts in the caller/host.
    /// - SHOULD return stable `reason_code` values for degraded/failed states.
    ///
    /// Default implementation reports `unsupported`.
    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        Ok(SelfCheckReport::unsupported())
    }

    /// Get connector metrics.
    fn metrics(&self) -> ConnectorMetrics;

    /// Gracefully shutdown the connector.
    async fn shutdown(&mut self, req: ShutdownRequest) -> FcpResult<()>;

    /// Get introspection data describing capabilities.
    fn introspect(&self) -> Introspection;

    /// Declare connector rate limits for planning and observability.
    ///
    /// Default: no limits declared.
    fn rate_limits(&self) -> RateLimitDeclarations {
        RateLimitDeclarations::default()
    }

    /// Invoke an operation.
    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse>;

    /// Simulate an operation (preflight check).
    ///
    /// Per FCP Specification Section 9.4:
    /// Allows callers to check if an operation would succeed (capability check,
    /// resource availability, cost estimation) without executing it.
    ///
    /// **Hard Requirements:**
    /// - **No side effects:** simulate MUST NOT perform external writes or mutate external state.
    /// - **Policy-aware:** simulate must reflect capability/policy gating as closely as invoke.
    /// - **Deterministic & bounded:** checks must be bounded (timeouts, size limits).
    ///
    /// Connectors SHOULD implement simulate for expensive or dangerous operations.
    /// The default implementation returns "allowed" with no cost estimate.
    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        // Default implementation: operation would succeed, no cost/availability info
        Ok(SimulateResponse::allowed(req.id))
    }

    /// Subscribe to event topics.
    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse>;

    /// Unsubscribe from event topics.
    async fn unsubscribe(&self, req: UnsubscribeRequest) -> FcpResult<()>;

    /// Acknowledge delivery of events (when `requires_ack=true`).
    ///
    /// Connectors that track delivery state should override this to
    /// update their replay buffers and pending-ack sets.
    async fn ack(&self, _ack: EventAck) -> FcpResult<()> {
        Ok(())
    }

    /// Negative acknowledgment (request redelivery).
    ///
    /// Connectors that support redelivery should override this.
    async fn nack(&self, _nack: EventNack) -> FcpResult<()> {
        Ok(())
    }
}

/// Connector metrics for monitoring.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectorMetrics {
    /// Total requests received
    pub requests_total: u64,
    /// Successful requests
    pub requests_success: u64,
    /// Failed requests
    pub requests_error: u64,
    /// Active connections/sessions
    pub connections_active: u64,
    /// Events emitted
    pub events_emitted: u64,
    /// Current request latency (p50) in milliseconds
    pub latency_p50_ms: u64,
    /// Current request latency (p99) in milliseconds
    pub latency_p99_ms: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Archetype Traits
// ─────────────────────────────────────────────────────────────────────────────

/// Request-response archetype (e.g., REST API, GraphQL).
#[async_trait]
pub trait RequestResponse: FcpConnector {
    /// Send a request and wait for a response.
    async fn request(&self, req: InvokeRequest) -> FcpResult<InvokeResponse>;
}

/// Streaming archetype (e.g., WebSocket, SSE).
#[async_trait]
pub trait Streaming: FcpConnector {
    /// Subscribe to a stream.
    async fn stream_subscribe(&self, topic: &str) -> FcpResult<EventStream>;

    /// Get event stream.
    fn events(&self) -> EventStream;
}

/// Bidirectional archetype (e.g., WebSocket chat).
#[async_trait]
pub trait Bidirectional: Streaming {
    /// Send a message to the stream.
    async fn send(&self, message: serde_json::Value) -> FcpResult<()>;
}

/// Polling archetype (e.g., IMAP, RSS).
#[async_trait]
pub trait Polling: FcpConnector {
    /// Start polling a target.
    async fn start_polling(
        &self,
        target: &str,
        interval: Option<std::time::Duration>,
        token: &CapabilityToken,
    ) -> FcpResult<()>;

    /// Stop polling a target.
    async fn stop_polling(&self, target: &str, token: &CapabilityToken) -> FcpResult<()>;

    /// Trigger immediate poll.
    async fn poll_now(&self, target: &str, token: &CapabilityToken) -> FcpResult<usize>;

    /// Get event stream.
    fn events(&self) -> EventStream;
}

/// Webhook archetype (e.g., GitHub, Stripe).
#[async_trait]
pub trait Webhook: FcpConnector {
    /// Register a webhook handler.
    async fn register_handler(&self, source: &str, token: &CapabilityToken) -> FcpResult<()>;

    /// Get the webhook URL.
    ///
    /// # Errors
    ///
    /// Returns an error if the connector cannot produce a webhook URL for `source`.
    fn webhook_url(&self, source: &str) -> FcpResult<String>;

    /// Get event stream.
    fn events(&self) -> EventStream;
}

// ─────────────────────────────────────────────────────────────────────────────
// Base Connector Implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Base connector state that can be reused by implementations.
#[derive(Debug)]
pub struct BaseConnector {
    /// Connector ID
    pub id: ConnectorId,
    /// Instance ID (unique per run)
    pub instance_id: InstanceId,
    /// Whether configured
    pub configured: AtomicBool,
    /// Whether handshake completed
    pub handshaken: AtomicBool,
    /// Metrics (internal atomic storage)
    metrics: AtomicConnectorMetrics,
}

#[derive(Debug, Default)]
struct AtomicConnectorMetrics {
    requests_total: AtomicU64,
    requests_success: AtomicU64,
    requests_error: AtomicU64,
    connections_active: AtomicU64,
    events_emitted: AtomicU64,
    latency_p50_ms: AtomicU64,
    latency_p99_ms: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
}

impl BaseConnector {
    /// Create a new base connector.
    #[must_use]
    pub fn new(id: impl Into<ConnectorId>) -> Self {
        Self {
            id: id.into(),
            instance_id: InstanceId::new(),
            configured: AtomicBool::new(false),
            handshaken: AtomicBool::new(false),
            metrics: AtomicConnectorMetrics::default(),
        }
    }

    /// Check if the connector is ready.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - `FcpError::NotConfigured` if `configure` has not completed.
    /// - `FcpError::NotHandshaken` if `handshake` has not completed.
    pub fn check_ready(&self) -> FcpResult<()> {
        if !self.configured.load(Ordering::Acquire) {
            return Err(crate::FcpError::NotConfigured);
        }
        if !self.handshaken.load(Ordering::Acquire) {
            return Err(crate::FcpError::NotHandshaken);
        }
        Ok(())
    }

    /// Set configured state.
    pub fn set_configured(&self, configured: bool) {
        self.configured.store(configured, Ordering::Release);
    }

    /// Set handshaken state.
    pub fn set_handshaken(&self, handshaken: bool) {
        self.handshaken.store(handshaken, Ordering::Release);
    }

    /// Increment request count.
    pub fn record_request(&self, success: bool) {
        self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
        if success {
            self.metrics
                .requests_success
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics.requests_error.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Increment event count.
    pub fn record_event(&self) {
        self.metrics.events_emitted.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a snapshot of current metrics.
    pub fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics {
            requests_total: self.metrics.requests_total.load(Ordering::Relaxed),
            requests_success: self.metrics.requests_success.load(Ordering::Relaxed),
            requests_error: self.metrics.requests_error.load(Ordering::Relaxed),
            connections_active: self.metrics.connections_active.load(Ordering::Relaxed),
            events_emitted: self.metrics.events_emitted.load(Ordering::Relaxed),
            latency_p50_ms: self.metrics.latency_p50_ms.load(Ordering::Relaxed),
            latency_p99_ms: self.metrics.latency_p99_ms.load(Ordering::Relaxed),
            bytes_sent: self.metrics.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.metrics.bytes_received.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────────────
    // ConnectorMetrics tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_metrics_default() {
        let metrics = ConnectorMetrics::default();

        assert_eq!(metrics.requests_total, 0);
        assert_eq!(metrics.requests_success, 0);
        assert_eq!(metrics.requests_error, 0);
        assert_eq!(metrics.connections_active, 0);
        assert_eq!(metrics.events_emitted, 0);
        assert_eq!(metrics.latency_p50_ms, 0);
        assert_eq!(metrics.latency_p99_ms, 0);
        assert_eq!(metrics.bytes_sent, 0);
        assert_eq!(metrics.bytes_received, 0);
    }

    #[test]
    fn connector_metrics_clone() {
        let metrics = ConnectorMetrics {
            requests_total: 100,
            requests_success: 95,
            ..Default::default()
        };

        // Clone and verify both copies have correct values
        let cloned = metrics.clone();
        assert_eq!(metrics.requests_total, 100);
        assert_eq!(cloned.requests_total, 100);
        assert_eq!(cloned.requests_success, 95);
    }

    #[test]
    fn connector_metrics_debug() {
        let metrics = ConnectorMetrics::default();
        let debug = format!("{metrics:?}");

        assert!(debug.contains("ConnectorMetrics"));
        assert!(debug.contains("requests_total"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // BaseConnector tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn base_connector_new() {
        let id = ConnectorId::from_static("my:connector:v1");
        let base = BaseConnector::new(id);

        assert_eq!(base.id.as_str(), "my:connector:v1");
        assert!(!base.configured.load(std::sync::atomic::Ordering::Relaxed));
        assert!(!base.handshaken.load(std::sync::atomic::Ordering::Relaxed));
        assert_eq!(base.metrics().requests_total, 0);
    }

    #[test]
    fn base_connector_new_with_connector_id() {
        let id = ConnectorId::new("test", "streaming", "v1").unwrap();
        let base = BaseConnector::new(id);

        assert_eq!(base.id.as_str(), "test:streaming:v1");
    }

    fn test_connector_id() -> ConnectorId {
        ConnectorId::from_static("test:base:v1")
    }

    #[test]
    fn base_connector_check_ready_not_configured() {
        let base = BaseConnector::new(test_connector_id());

        let result = base.check_ready();

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::FcpError::NotConfigured
        ));
    }

    #[test]
    fn base_connector_check_ready_not_handshaken() {
        let base = BaseConnector::new(test_connector_id());
        base.set_configured(true);

        let result = base.check_ready();

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::FcpError::NotHandshaken
        ));
    }

    #[test]
    fn base_connector_check_ready_success() {
        let base = BaseConnector::new(test_connector_id());
        base.set_configured(true);
        base.set_handshaken(true);

        let result = base.check_ready();

        assert!(result.is_ok());
    }

    #[test]
    fn base_connector_record_request_success() {
        let base = BaseConnector::new(test_connector_id());

        base.record_request(true);

        assert_eq!(base.metrics().requests_total, 1);
        assert_eq!(base.metrics().requests_success, 1);
        assert_eq!(base.metrics().requests_error, 0);
    }

    #[test]
    fn base_connector_record_request_failure() {
        let base = BaseConnector::new(test_connector_id());

        base.record_request(false);

        assert_eq!(base.metrics().requests_total, 1);
        assert_eq!(base.metrics().requests_success, 0);
        assert_eq!(base.metrics().requests_error, 1);
    }

    #[test]
    fn base_connector_record_request_multiple() {
        let base = BaseConnector::new(test_connector_id());

        base.record_request(true);
        base.record_request(true);
        base.record_request(false);
        base.record_request(true);
        base.record_request(false);

        assert_eq!(base.metrics().requests_total, 5);
        assert_eq!(base.metrics().requests_success, 3);
        assert_eq!(base.metrics().requests_error, 2);
    }

    #[test]
    fn base_connector_record_event() {
        let base = BaseConnector::new(test_connector_id());

        base.record_event();
        base.record_event();
        base.record_event();

        assert_eq!(base.metrics().events_emitted, 3);
    }

    #[test]
    fn base_connector_debug() {
        let base = BaseConnector::new(ConnectorId::from_static("debug:test:v1"));
        let debug = format!("{base:?}");

        assert!(debug.contains("BaseConnector"));
        assert!(debug.contains("debug:test:v1"));
        assert!(debug.contains("configured"));
        assert!(debug.contains("handshaken"));
    }

    #[test]
    fn base_connector_lifecycle() {
        // Test typical connector lifecycle
        let base = BaseConnector::new(ConnectorId::from_static("lifecycle:connector:v1"));

        // Initially not ready
        assert!(base.check_ready().is_err());

        // After configuration
        base.set_configured(true);
        assert!(base.check_ready().is_err());

        // After handshake
        base.set_handshaken(true);
        assert!(base.check_ready().is_ok());

        // Record some activity
        base.record_request(true);
        base.record_request(true);
        base.record_request(false);
        base.record_event();
        base.record_event();

        assert_eq!(base.metrics().requests_total, 3);
        assert_eq!(base.metrics().requests_success, 2);
        assert_eq!(base.metrics().requests_error, 1);
        assert_eq!(base.metrics().events_emitted, 2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional ConnectorMetrics tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_metrics_serde_roundtrip() {
        let metrics = ConnectorMetrics {
            requests_total: 1000,
            requests_success: 950,
            requests_error: 50,
            connections_active: 12,
            events_emitted: 500,
            latency_p50_ms: 45,
            latency_p99_ms: 250,
            bytes_sent: 1_000_000,
            bytes_received: 2_000_000,
        };
        let json = serde_json::to_string(&metrics).unwrap();
        let decoded: ConnectorMetrics = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.requests_total, 1000);
        assert_eq!(decoded.requests_success, 950);
        assert_eq!(decoded.requests_error, 50);
        assert_eq!(decoded.connections_active, 12);
        assert_eq!(decoded.events_emitted, 500);
        assert_eq!(decoded.latency_p50_ms, 45);
        assert_eq!(decoded.latency_p99_ms, 250);
        assert_eq!(decoded.bytes_sent, 1_000_000);
        assert_eq!(decoded.bytes_received, 2_000_000);
    }

    #[test]
    fn connector_metrics_partial_init() {
        let metrics = ConnectorMetrics {
            requests_total: 42,
            latency_p99_ms: 100,
            ..Default::default()
        };
        assert_eq!(metrics.requests_total, 42);
        assert_eq!(metrics.latency_p99_ms, 100);
        assert_eq!(metrics.requests_success, 0);
        assert_eq!(metrics.bytes_sent, 0);
    }

    #[test]
    fn connector_metrics_json_fields() {
        let metrics = ConnectorMetrics::default();
        let value = serde_json::to_value(&metrics).unwrap();
        for field in [
            "requests_total",
            "requests_success",
            "requests_error",
            "connections_active",
            "events_emitted",
            "latency_p50_ms",
            "latency_p99_ms",
            "bytes_sent",
            "bytes_received",
        ] {
            assert!(value.get(field).is_some(), "missing field: {field}");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional BaseConnector tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn base_connector_instance_id_unique() {
        let a = BaseConnector::new(test_connector_id());
        let b = BaseConnector::new(test_connector_id());
        // Instance IDs should be unique for each BaseConnector
        assert_ne!(
            a.instance_id.as_str(),
            b.instance_id.as_str(),
            "instance IDs should be unique"
        );
    }

    #[test]
    fn base_connector_metrics_initially_zero() {
        let base = BaseConnector::new(test_connector_id());
        let m = base.metrics();
        assert_eq!(m.requests_total, 0);
        assert_eq!(m.requests_success, 0);
        assert_eq!(m.requests_error, 0);
        assert_eq!(m.connections_active, 0);
        assert_eq!(m.events_emitted, 0);
        assert_eq!(m.latency_p50_ms, 0);
        assert_eq!(m.latency_p99_ms, 0);
        assert_eq!(m.bytes_sent, 0);
        assert_eq!(m.bytes_received, 0);
    }

    #[test]
    fn base_connector_set_configured_toggle() {
        let base = BaseConnector::new(test_connector_id());
        assert!(!base.configured.load(Ordering::Relaxed));

        base.set_configured(true);
        assert!(base.configured.load(Ordering::Relaxed));

        base.set_configured(false);
        assert!(!base.configured.load(Ordering::Relaxed));
    }

    #[test]
    fn base_connector_set_handshaken_toggle() {
        let base = BaseConnector::new(test_connector_id());
        assert!(!base.handshaken.load(Ordering::Relaxed));

        base.set_handshaken(true);
        assert!(base.handshaken.load(Ordering::Relaxed));

        base.set_handshaken(false);
        assert!(!base.handshaken.load(Ordering::Relaxed));
    }

    #[test]
    fn base_connector_metrics_snapshot_independent() {
        let base = BaseConnector::new(test_connector_id());
        base.record_request(true);

        let snapshot1 = base.metrics();
        base.record_request(true);
        let snapshot2 = base.metrics();

        // Snapshot values are independent
        assert_eq!(snapshot1.requests_total, 1);
        assert_eq!(snapshot2.requests_total, 2);
    }

    #[test]
    fn base_connector_check_ready_reconfigure() {
        let base = BaseConnector::new(test_connector_id());
        base.set_configured(true);
        base.set_handshaken(true);
        assert!(base.check_ready().is_ok());

        // Deconfigure -> no longer ready
        base.set_configured(false);
        assert!(base.check_ready().is_err());

        // Reconfigure -> ready again
        base.set_configured(true);
        assert!(base.check_ready().is_ok());
    }

    #[test]
    fn base_connector_mixed_success_failure() {
        let base = BaseConnector::new(test_connector_id());
        for i in 0..100 {
            base.record_request(i % 3 != 0);
        }
        let m = base.metrics();
        assert_eq!(m.requests_total, 100);
        // i=0,3,6,...,99 => failures = 34 (0..100 step 3)
        assert_eq!(m.requests_error, 34);
        assert_eq!(m.requests_success, 66);
    }

    #[test]
    fn base_connector_many_events() {
        let base = BaseConnector::new(test_connector_id());
        for _ in 0..1000 {
            base.record_event();
        }
        assert_eq!(base.metrics().events_emitted, 1000);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ConnectorMetrics – boundary values
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_metrics_max_values() {
        let metrics = ConnectorMetrics {
            requests_total: u64::MAX,
            requests_success: u64::MAX,
            requests_error: u64::MAX,
            connections_active: u64::MAX,
            events_emitted: u64::MAX,
            latency_p50_ms: u64::MAX,
            latency_p99_ms: u64::MAX,
            bytes_sent: u64::MAX,
            bytes_received: u64::MAX,
        };
        let json = serde_json::to_string(&metrics).unwrap();
        let decoded: ConnectorMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.requests_total, u64::MAX);
        assert_eq!(decoded.bytes_received, u64::MAX);
    }

    #[test]
    fn connector_metrics_deserialize_from_literal() {
        let raw = r#"{
            "requests_total": 42,
            "requests_success": 40,
            "requests_error": 2,
            "connections_active": 5,
            "events_emitted": 100,
            "latency_p50_ms": 10,
            "latency_p99_ms": 200,
            "bytes_sent": 9999,
            "bytes_received": 8888
        }"#;
        let m: ConnectorMetrics = serde_json::from_str(raw).unwrap();
        assert_eq!(m.requests_total, 42);
        assert_eq!(m.connections_active, 5);
        assert_eq!(m.latency_p50_ms, 10);
        assert_eq!(m.bytes_sent, 9999);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BaseConnector – edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn base_connector_from_string_id() {
        let base = BaseConnector::new(ConnectorId::from_static("fcp.slack:streaming:1"));
        assert_eq!(base.id.as_str(), "fcp.slack:streaming:1");
    }

    #[test]
    fn base_connector_check_ready_sequence_matters() {
        let base = BaseConnector::new(test_connector_id());
        // Only handshaken, not configured → still not ready
        base.set_handshaken(true);
        let err = base.check_ready().unwrap_err();
        assert!(matches!(err, crate::FcpError::NotConfigured));
    }

    #[test]
    fn base_connector_record_only_failures() {
        let base = BaseConnector::new(test_connector_id());
        for _ in 0..50 {
            base.record_request(false);
        }
        let m = base.metrics();
        assert_eq!(m.requests_total, 50);
        assert_eq!(m.requests_success, 0);
        assert_eq!(m.requests_error, 50);
    }

    #[test]
    fn base_connector_record_only_successes() {
        let base = BaseConnector::new(test_connector_id());
        for _ in 0..50 {
            base.record_request(true);
        }
        let m = base.metrics();
        assert_eq!(m.requests_total, 50);
        assert_eq!(m.requests_success, 50);
        assert_eq!(m.requests_error, 0);
    }

    #[test]
    fn base_connector_events_independent_of_requests() {
        let base = BaseConnector::new(test_connector_id());
        base.record_request(true);
        base.record_event();
        base.record_event();
        let m = base.metrics();
        assert_eq!(m.requests_total, 1);
        assert_eq!(m.events_emitted, 2);
    }

    #[test]
    fn base_connector_multiple_metrics_snapshots_diverge() {
        let base = BaseConnector::new(test_connector_id());
        let snap1 = base.metrics();
        base.record_request(true);
        base.record_request(true);
        base.record_request(true);
        let snap2 = base.metrics();
        base.record_event();
        let snap3 = base.metrics();
        assert_eq!(snap1.requests_total, 0);
        assert_eq!(snap2.requests_total, 3);
        assert_eq!(snap3.requests_total, 3);
        assert_eq!(snap3.events_emitted, 1);
        assert_eq!(snap2.events_emitted, 0);
    }

    #[test]
    fn connector_id_equality_in_base_connector() {
        let a = BaseConnector::new(ConnectorId::from_static("fcp.a:rr:1"));
        let b = BaseConnector::new(ConnectorId::from_static("fcp.a:rr:1"));
        assert_eq!(a.id, b.id);
        // But instance IDs differ
        assert_ne!(a.instance_id.as_str(), b.instance_id.as_str());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // New tests – deeper coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_metrics_clone_is_independent() {
        let original = ConnectorMetrics {
            requests_total: 10,
            requests_success: 8,
            requests_error: 2,
            connections_active: 3,
            events_emitted: 50,
            latency_p50_ms: 15,
            latency_p99_ms: 120,
            bytes_sent: 4096,
            bytes_received: 8192,
        };
        let mut cloned = original.clone();
        cloned.requests_total = 999;
        cloned.bytes_sent = 0;
        // Original unaffected by mutation of clone
        assert_eq!(original.requests_total, 10);
        assert_eq!(original.bytes_sent, 4096);
        assert_eq!(cloned.requests_total, 999);
        assert_eq!(cloned.bytes_sent, 0);
    }

    #[test]
    fn connector_metrics_all_fields_populated() {
        let metrics = ConnectorMetrics {
            requests_total: 1,
            requests_success: 2,
            requests_error: 3,
            connections_active: 4,
            events_emitted: 5,
            latency_p50_ms: 6,
            latency_p99_ms: 7,
            bytes_sent: 8,
            bytes_received: 9,
        };
        assert_eq!(metrics.requests_total, 1);
        assert_eq!(metrics.requests_success, 2);
        assert_eq!(metrics.requests_error, 3);
        assert_eq!(metrics.connections_active, 4);
        assert_eq!(metrics.events_emitted, 5);
        assert_eq!(metrics.latency_p50_ms, 6);
        assert_eq!(metrics.latency_p99_ms, 7);
        assert_eq!(metrics.bytes_sent, 8);
        assert_eq!(metrics.bytes_received, 9);
    }

    #[test]
    fn connector_metrics_serde_extra_fields_ignored() {
        // serde default: unknown fields are ignored during deserialization
        let raw = r#"{
            "requests_total": 5,
            "requests_success": 4,
            "requests_error": 1,
            "connections_active": 0,
            "events_emitted": 0,
            "latency_p50_ms": 0,
            "latency_p99_ms": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "extra_field": 42
        }"#;
        let m: ConnectorMetrics = serde_json::from_str(raw).unwrap();
        assert_eq!(m.requests_total, 5);
        assert_eq!(m.requests_success, 4);
        assert_eq!(m.requests_error, 1);
    }

    #[test]
    fn connector_metrics_serde_missing_field_fails() {
        // All fields are required (no #[serde(default)])
        let raw = r#"{"requests_total": 5}"#;
        let result = serde_json::from_str::<ConnectorMetrics>(raw);
        assert!(result.is_err());
    }

    #[test]
    fn connector_metrics_debug_contains_all_fields() {
        let metrics = ConnectorMetrics {
            requests_total: 11,
            requests_success: 22,
            requests_error: 33,
            connections_active: 44,
            events_emitted: 55,
            latency_p50_ms: 66,
            latency_p99_ms: 77,
            bytes_sent: 88,
            bytes_received: 99,
        };
        let dbg = format!("{metrics:?}");
        assert!(dbg.contains("requests_success"));
        assert!(dbg.contains("requests_error"));
        assert!(dbg.contains("connections_active"));
        assert!(dbg.contains("events_emitted"));
        assert!(dbg.contains("latency_p50_ms"));
        assert!(dbg.contains("latency_p99_ms"));
        assert!(dbg.contains("bytes_sent"));
        assert!(dbg.contains("bytes_received"));
    }

    #[test]
    fn connector_metrics_serde_roundtrip_zeros() {
        let metrics = ConnectorMetrics::default();
        let json = serde_json::to_string(&metrics).unwrap();
        let decoded: ConnectorMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.requests_total, 0);
        assert_eq!(decoded.latency_p99_ms, 0);
        assert_eq!(decoded.bytes_received, 0);
    }

    #[test]
    fn connector_metrics_json_value_types() {
        let metrics = ConnectorMetrics {
            requests_total: 7,
            ..Default::default()
        };
        let value = serde_json::to_value(&metrics).unwrap();
        // All fields should serialize as numbers
        assert!(value["requests_total"].is_number());
        assert!(value["latency_p50_ms"].is_number());
        assert!(value["bytes_sent"].is_number());
        assert_eq!(value["requests_total"].as_u64(), Some(7));
    }

    #[test]
    fn base_connector_check_ready_error_display() {
        let base = BaseConnector::new(test_connector_id());
        let err = base.check_ready().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not configured") || msg.contains("NotConfigured"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn base_connector_check_ready_not_handshaken_error_display() {
        let base = BaseConnector::new(test_connector_id());
        base.set_configured(true);
        let err = base.check_ready().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not handshaken") || msg.contains("NotHandshaken"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn base_connector_dehandshake_reverts_ready() {
        let base = BaseConnector::new(test_connector_id());
        base.set_configured(true);
        base.set_handshaken(true);
        assert!(base.check_ready().is_ok());

        // Remove handshake
        base.set_handshaken(false);
        let err = base.check_ready().unwrap_err();
        assert!(matches!(err, crate::FcpError::NotHandshaken));
    }

    #[test]
    fn base_connector_repeated_set_configured_idempotent() {
        let base = BaseConnector::new(test_connector_id());
        base.set_configured(true);
        base.set_configured(true);
        base.set_configured(true);
        assert!(base.configured.load(Ordering::Relaxed));

        base.set_configured(false);
        base.set_configured(false);
        assert!(!base.configured.load(Ordering::Relaxed));
    }

    #[test]
    fn base_connector_repeated_set_handshaken_idempotent() {
        let base = BaseConnector::new(test_connector_id());
        base.set_handshaken(true);
        base.set_handshaken(true);
        assert!(base.handshaken.load(Ordering::Relaxed));

        base.set_handshaken(false);
        base.set_handshaken(false);
        assert!(!base.handshaken.load(Ordering::Relaxed));
    }

    #[test]
    fn base_connector_metrics_unaffected_by_state_changes() {
        let base = BaseConnector::new(test_connector_id());
        base.record_request(true);
        base.record_event();

        // Changing configured/handshaken should not reset metrics
        base.set_configured(true);
        base.set_handshaken(true);
        base.set_configured(false);
        base.set_handshaken(false);

        let m = base.metrics();
        assert_eq!(m.requests_total, 1);
        assert_eq!(m.requests_success, 1);
        assert_eq!(m.events_emitted, 1);
    }

    #[test]
    fn base_connector_instance_id_format() {
        let base = BaseConnector::new(test_connector_id());
        let iid = base.instance_id.as_str();
        // InstanceId should be non-empty
        assert!(!iid.is_empty(), "instance ID should not be empty");
    }

    #[test]
    fn base_connector_debug_includes_metrics() {
        let base = BaseConnector::new(test_connector_id());
        base.record_request(true);
        let dbg = format!("{base:?}");
        assert!(dbg.contains("instance_id"));
        assert!(dbg.contains("metrics"));
    }

    #[test]
    fn base_connector_interleaved_requests_and_events() {
        let base = BaseConnector::new(test_connector_id());
        base.record_request(true);
        base.record_event();
        base.record_request(false);
        base.record_event();
        base.record_event();
        base.record_request(true);

        let m = base.metrics();
        assert_eq!(m.requests_total, 3);
        assert_eq!(m.requests_success, 2);
        assert_eq!(m.requests_error, 1);
        assert_eq!(m.events_emitted, 3);
    }

    #[test]
    fn base_connector_high_volume_requests() {
        let base = BaseConnector::new(test_connector_id());
        let count: u64 = 10_000;
        for _ in 0..count {
            base.record_request(true);
        }
        let m = base.metrics();
        assert_eq!(m.requests_total, count);
        assert_eq!(m.requests_success, count);
        assert_eq!(m.requests_error, 0);
    }

    #[test]
    fn base_connector_high_volume_events() {
        let base = BaseConnector::new(test_connector_id());
        let count: u64 = 10_000;
        for _ in 0..count {
            base.record_event();
        }
        assert_eq!(base.metrics().events_emitted, count);
    }

    #[test]
    fn base_connector_zero_requests_zero_events() {
        let base = BaseConnector::new(test_connector_id());
        let m = base.metrics();
        assert_eq!(m.requests_total, 0);
        assert_eq!(m.events_emitted, 0);
        assert_eq!(m.connections_active, 0);
    }

    #[test]
    fn base_connector_check_ready_returns_unit() {
        let base = BaseConnector::new(test_connector_id());
        base.set_configured(true);
        base.set_handshaken(true);
        let result: FcpResult<()> = base.check_ready();
        assert_eq!(result.unwrap(), ());
    }

    #[test]
    fn base_connector_different_ids_different_connectors() {
        let a = BaseConnector::new(ConnectorId::from_static("alpha:rr:v1"));
        let b = BaseConnector::new(ConnectorId::from_static("beta:streaming:v2"));
        assert_ne!(a.id.as_str(), b.id.as_str());
        assert_ne!(a.instance_id.as_str(), b.instance_id.as_str());
    }

    #[test]
    fn base_connector_new_does_not_start_ready() {
        let base = BaseConnector::new(ConnectorId::from_static("fresh:connector:v1"));
        assert!(base.check_ready().is_err());
        assert!(!base.configured.load(Ordering::Relaxed));
        assert!(!base.handshaken.load(Ordering::Relaxed));
    }

    #[test]
    fn connector_metrics_serde_via_value() {
        let metrics = ConnectorMetrics {
            requests_total: 500,
            requests_success: 490,
            requests_error: 10,
            connections_active: 7,
            events_emitted: 200,
            latency_p50_ms: 25,
            latency_p99_ms: 180,
            bytes_sent: 65_536,
            bytes_received: 131_072,
        };
        let json = serde_json::to_value(&metrics).unwrap();
        let decoded: ConnectorMetrics = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.requests_total, 500);
        assert_eq!(decoded.requests_success, 490);
        assert_eq!(decoded.requests_error, 10);
        assert_eq!(decoded.connections_active, 7);
        assert_eq!(decoded.events_emitted, 200);
        assert_eq!(decoded.latency_p50_ms, 25);
        assert_eq!(decoded.latency_p99_ms, 180);
        assert_eq!(decoded.bytes_sent, 65_536);
        assert_eq!(decoded.bytes_received, 131_072);
    }

    #[test]
    fn base_connector_metrics_snapshot_after_no_activity() {
        let base = BaseConnector::new(test_connector_id());
        // Taking multiple snapshots without activity should all be zero
        let s1 = base.metrics();
        let s2 = base.metrics();
        let s3 = base.metrics();
        assert_eq!(s1.requests_total, 0);
        assert_eq!(s2.requests_total, 0);
        assert_eq!(s3.requests_total, 0);
    }

    #[test]
    fn base_connector_check_ready_configured_false_handshaken_false() {
        let base = BaseConnector::new(test_connector_id());
        // Both false: should get NotConfigured (checked first)
        let err = base.check_ready().unwrap_err();
        assert!(matches!(err, crate::FcpError::NotConfigured));
    }

    #[test]
    fn base_connector_full_state_cycle() {
        let base = BaseConnector::new(test_connector_id());

        // Phase 1: unconfigured
        assert!(base.check_ready().is_err());

        // Phase 2: configure
        base.set_configured(true);
        assert!(base.check_ready().is_err());

        // Phase 3: handshake -> ready
        base.set_handshaken(true);
        assert!(base.check_ready().is_ok());

        // Phase 4: do work
        base.record_request(true);
        base.record_request(false);
        base.record_event();

        // Phase 5: deconfigure (simulating shutdown)
        base.set_configured(false);
        base.set_handshaken(false);
        assert!(base.check_ready().is_err());

        // Phase 6: metrics survive state changes
        let m = base.metrics();
        assert_eq!(m.requests_total, 2);
        assert_eq!(m.events_emitted, 1);

        // Phase 7: reconfigure
        base.set_configured(true);
        base.set_handshaken(true);
        assert!(base.check_ready().is_ok());

        // Phase 8: more work accumulates
        base.record_request(true);
        let m = base.metrics();
        assert_eq!(m.requests_total, 3);
    }
}
