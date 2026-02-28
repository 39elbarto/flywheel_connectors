//! SDK Simulate Tests
//!
//! Detailed tests for simulate/CostEstimate/Availability functionality.
//! These tests verify that simulate operations:
//! - Never call write paths
//! - Return deterministic cost estimates
//! - Handle capability checks correctly
//! - Never leak secrets in error messages

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use fcp_sdk::prelude::*;
use serde_json::json;

// ─────────────────────────────────────────────────────────────────────────────
// Mock Connector with Write Detection
// ─────────────────────────────────────────────────────────────────────────────

/// Mock connector that tracks if write paths are called during simulate.
#[derive(Debug)]
struct WriteDetectingConnector {
    base: BaseConnector,
    write_called: Arc<AtomicBool>,
    #[allow(dead_code)]
    simulate_count: Arc<AtomicU64>,
}

impl WriteDetectingConnector {
    fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("test:write-detect:v1")),
            write_called: Arc::new(AtomicBool::new(false)),
            simulate_count: Arc::new(AtomicU64::new(0)),
        }
    }

    fn was_write_called(&self) -> bool {
        self.write_called.load(Ordering::SeqCst)
    }

    /// Simulates a write operation - should never be called during simulate.
    fn do_write(&self) {
        self.write_called.store(true, Ordering::SeqCst);
    }
}

fn test_capability_token() -> CapabilityToken {
    CapabilityToken::test_token()
}

fn test_simulate_request(operation: &'static str) -> SimulateRequest {
    SimulateRequest {
        r#type: "simulate".to_string(),
        id: fcp_sdk::RequestId::new("sim-test-1"),
        connector_id: ConnectorId::from_static("test:write-detect:v1"),
        operation: fcp_sdk::OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input: json!({"test": "data"}),
        capability_token: test_capability_token(),
        estimate_cost: false,
        check_availability: false,
        context: None,
        correlation_id: None,
    }
}

#[async_trait]
impl FcpConnector for WriteDetectingConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, _config: serde_json::Value) -> FcpResult<()> {
        self.base.set_configured(true);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        Ok(HandshakeResponse {
            status: "accepted".to_string(),
            capabilities_granted: vec![],
            session_id: fcp_sdk::SessionId::new(),
            manifest_hash: "sha256:test".to_string(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        HealthSnapshot::ready()
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        // This actually performs the write
        self.do_write();
        self.base.record_request(true);
        Ok(InvokeResponse::ok(req.id, json!({"written": true})))
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        self.simulate_count.fetch_add(1, Ordering::SeqCst);

        // CRITICAL: simulate MUST NOT call do_write()
        // We verify capabilities and return a preflight response
        // WITHOUT performing any actual write operations

        let mut response = SimulateResponse::allowed(req.id);

        if req.estimate_cost {
            // Deterministic cost estimate based on input
            let input_size = req.input.to_string().len() as u64;
            response = response.with_cost_estimate(
                CostEstimate::with_credits(input_size / 10 + 1).and_duration_ms(50),
            );
        }

        if req.check_availability {
            response = response.with_availability(
                ResourceAvailability::available().with_rate_limit(1000, Some(60000)),
            );
        }

        Ok(response)
    }

    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Ok(SubscribeResponse {
            r#type: "response".to_string(),
            id: req.id,
            result: fcp_sdk::SubscribeResult {
                confirmed_topics: req.topics,
                cursors: std::collections::HashMap::new(),
                replay_supported: false,
                buffer: None,
            },
        })
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core Simulate Tests
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn test_simulate_never_calls_write() {
    let connector = WriteDetectingConnector::new();
    let req = test_simulate_request("db.insert");

    // Call simulate
    let result = connector.simulate(req).await;

    // Verify simulate succeeded
    assert!(result.is_ok());
    let response = result.unwrap();
    assert!(response.would_succeed);

    // CRITICAL: Write path should NOT have been called
    assert!(
        !connector.was_write_called(),
        "simulate called write path - this is a critical violation!"
    );
}

#[fcp_async_core::runtime::test]
async fn test_invoke_does_call_write() {
    let connector = WriteDetectingConnector::new();
    let req = fcp_sdk::InvokeRequest {
        r#type: "invoke".to_string(),
        id: fcp_sdk::RequestId::new("invoke-test-1"),
        connector_id: ConnectorId::from_static("test:write-detect:v1"),
        operation: fcp_sdk::OperationId::from_static("db.insert"),
        zone_id: ZoneId::work(),
        input: json!({"data": "to_write"}),
        capability_token: test_capability_token(),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: vec![],
    };

    // Call invoke (which should write)
    let result = connector.invoke(req).await;
    assert!(result.is_ok());

    // Verify write WAS called for invoke
    assert!(
        connector.was_write_called(),
        "invoke should call write path"
    );
}

#[fcp_async_core::runtime::test]
async fn test_cost_estimate_deterministic() {
    let connector = WriteDetectingConnector::new();

    let mut req = test_simulate_request("email.send");
    req.estimate_cost = true;
    req.input = json!({"to": "test@example.com", "subject": "Test"});

    // Call simulate twice with same input
    let result1 = connector.simulate(req.clone()).await.unwrap();
    let result2 = connector.simulate(req).await.unwrap();

    // Cost estimates must be identical for same input
    // Compare fields individually since CostEstimate doesn't impl PartialEq
    let cost1 = result1.estimated_cost.unwrap();
    let cost2 = result2.estimated_cost.unwrap();
    assert_eq!(cost1.api_credits, cost2.api_credits);
    assert_eq!(cost1.estimated_duration_ms, cost2.estimated_duration_ms);
    assert_eq!(cost1.estimated_bytes, cost2.estimated_bytes);
}

#[fcp_async_core::runtime::test]
async fn test_cost_estimate_varies_with_input() {
    let connector = WriteDetectingConnector::new();

    let mut req_small = test_simulate_request("process.data");
    req_small.estimate_cost = true;
    req_small.input = json!({"x": 1});

    let mut req_large = test_simulate_request("process.data");
    req_large.estimate_cost = true;
    req_large.input =
        json!({"x": 1, "y": 2, "z": 3, "data": "much more content here for processing"});

    let result_small = connector.simulate(req_small).await.unwrap();
    let result_large = connector.simulate(req_large).await.unwrap();

    // Different inputs should produce different cost estimates
    // Compare fields individually since CostEstimate doesn't impl PartialEq
    let cost_small = result_small.estimated_cost.unwrap();
    let cost_large = result_large.estimated_cost.unwrap();
    // Larger input should have higher api_credits cost
    assert!(cost_large.api_credits > cost_small.api_credits);
}

#[fcp_async_core::runtime::test]
async fn test_availability_check_returns_rate_limit_info() {
    let connector = WriteDetectingConnector::new();

    let mut req = test_simulate_request("api.call");
    req.check_availability = true;

    let result = connector.simulate(req).await.unwrap();

    assert!(result.availability.is_some());
    let avail = result.availability.unwrap();
    assert!(avail.available);
    assert!(avail.rate_limit_remaining.is_some());
    assert!(avail.rate_limit_reset_at.is_some());
}

// ─────────────────────────────────────────────────────────────────────────────
// Missing Capability Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Connector that checks capabilities and returns missing ones.
#[derive(Debug)]
struct CapabilityCheckingConnector {
    base: BaseConnector,
    required_capabilities: Vec<String>,
}

impl CapabilityCheckingConnector {
    fn new(required: Vec<&str>) -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("test:cap-check:v1")),
            required_capabilities: required.into_iter().map(String::from).collect(),
        }
    }
}

#[async_trait]
impl FcpConnector for CapabilityCheckingConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, _config: serde_json::Value) -> FcpResult<()> {
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        Ok(HandshakeResponse {
            status: "accepted".to_string(),
            capabilities_granted: vec![],
            session_id: fcp_sdk::SessionId::new(),
            manifest_hash: "sha256:test".to_string(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        HealthSnapshot::ready()
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        Ok(InvokeResponse::ok(req.id, json!({})))
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        // Check if token has required capabilities
        // For test purposes, we simulate missing capabilities
        let missing = self.required_capabilities.clone();

        if missing.is_empty() {
            Ok(SimulateResponse::allowed(req.id))
        } else {
            Ok(SimulateResponse::denied(
                req.id,
                format!("Missing required capabilities: {missing:?}"),
                "FCP-3001",
            )
            .with_missing_capabilities(missing))
        }
    }

    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Ok(SubscribeResponse {
            r#type: "response".to_string(),
            id: req.id,
            result: fcp_sdk::SubscribeResult {
                confirmed_topics: vec![],
                cursors: std::collections::HashMap::new(),
                replay_supported: false,
                buffer: None,
            },
        })
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Ok(())
    }
}

#[fcp_async_core::runtime::test]
async fn test_simulate_reports_missing_capabilities() {
    let connector = CapabilityCheckingConnector::new(vec!["email.send", "email.read"]);

    let req = SimulateRequest {
        r#type: "simulate".to_string(),
        id: fcp_sdk::RequestId::new("sim-cap-1"),
        connector_id: ConnectorId::from_static("test:cap-check:v1"),
        operation: fcp_sdk::OperationId::from_static("email.send"),
        zone_id: ZoneId::work(),
        input: json!({"to": "test@example.com"}),
        capability_token: test_capability_token(),
        estimate_cost: false,
        check_availability: false,
        context: None,
        correlation_id: None,
    };

    let result = connector.simulate(req).await.unwrap();

    assert!(!result.would_succeed);
    assert_eq!(result.missing_capabilities.len(), 2);
    assert!(
        result
            .missing_capabilities
            .contains(&"email.send".to_string())
    );
    assert!(
        result
            .missing_capabilities
            .contains(&"email.read".to_string())
    );
}

#[fcp_async_core::runtime::test]
async fn test_simulate_missing_capabilities_ordering_stable() {
    let connector = CapabilityCheckingConnector::new(vec!["b.cap", "a.cap", "c.cap"]);

    let req = SimulateRequest {
        r#type: "simulate".to_string(),
        id: fcp_sdk::RequestId::new("sim-order-1"),
        connector_id: ConnectorId::from_static("test:cap-check:v1"),
        operation: fcp_sdk::OperationId::from_static("test.op"),
        zone_id: ZoneId::work(),
        input: json!({}),
        capability_token: test_capability_token(),
        estimate_cost: false,
        check_availability: false,
        context: None,
        correlation_id: None,
    };

    // Call multiple times
    let result1 = connector.simulate(req.clone()).await.unwrap();
    let result2 = connector.simulate(req).await.unwrap();

    // Ordering must be stable
    assert_eq!(result1.missing_capabilities, result2.missing_capabilities);
}

// ─────────────────────────────────────────────────────────────────────────────
// Secret Leakage Prevention Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Connector that simulates timeout with secret in input.
#[derive(Debug)]
struct TimeoutConnector {
    base: BaseConnector,
}

impl TimeoutConnector {
    fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("test:timeout:v1")),
        }
    }
}

#[async_trait]
impl FcpConnector for TimeoutConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, _config: serde_json::Value) -> FcpResult<()> {
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        Ok(HandshakeResponse {
            status: "accepted".to_string(),
            capabilities_granted: vec![],
            session_id: fcp_sdk::SessionId::new(),
            manifest_hash: "sha256:test".to_string(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        HealthSnapshot::ready()
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        Ok(InvokeResponse::ok(req.id, json!({})))
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        // Simulate a policy denial - error message must NOT contain input data
        Ok(SimulateResponse::denied(
            req.id,
            "Operation timed out during preflight check",
            "FCP-5003",
        ))
    }

    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Ok(SubscribeResponse {
            r#type: "response".to_string(),
            id: req.id,
            result: fcp_sdk::SubscribeResult {
                confirmed_topics: vec![],
                cursors: std::collections::HashMap::new(),
                replay_supported: false,
                buffer: None,
            },
        })
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Ok(())
    }
}

#[fcp_async_core::runtime::test]
async fn test_simulate_timeout_no_secret_leak() {
    let connector = TimeoutConnector::new();

    let secret_api_key = "sk-super-secret-key-12345";
    let req = SimulateRequest {
        r#type: "simulate".to_string(),
        id: fcp_sdk::RequestId::new("sim-secret-1"),
        connector_id: ConnectorId::from_static("test:timeout:v1"),
        operation: fcp_sdk::OperationId::from_static("api.call"),
        zone_id: ZoneId::work(),
        input: json!({"secret_api_key": secret_api_key}),
        capability_token: test_capability_token(),
        estimate_cost: false,
        check_availability: false,
        context: None,
        correlation_id: None,
    };

    let result = connector.simulate(req).await.unwrap();

    // Response should not contain the secret
    let response_str = format!("{result:?}");
    assert!(
        !response_str.contains(secret_api_key),
        "Response contains secret API key - security violation!"
    );

    // Check failure_reason specifically
    if let Some(reason) = &result.failure_reason {
        assert!(
            !reason.contains(secret_api_key),
            "Failure reason contains secret API key - security violation!"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy Denial Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Connector that denies based on path policy.
#[derive(Debug)]
struct PolicyConnector {
    base: BaseConnector,
    restricted_paths: Vec<String>,
}

impl PolicyConnector {
    fn new(restricted: Vec<&str>) -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("test:policy:v1")),
            restricted_paths: restricted.into_iter().map(String::from).collect(),
        }
    }
}

#[async_trait]
impl FcpConnector for PolicyConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, _config: serde_json::Value) -> FcpResult<()> {
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        Ok(HandshakeResponse {
            status: "accepted".to_string(),
            capabilities_granted: vec![],
            session_id: fcp_sdk::SessionId::new(),
            manifest_hash: "sha256:test".to_string(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        HealthSnapshot::ready()
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        Ok(InvokeResponse::ok(req.id, json!({})))
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        // Check if path is restricted
        if let Some(path) = req.input.get("path").and_then(|v| v.as_str()) {
            for restricted in &self.restricted_paths {
                if path.starts_with(restricted) {
                    return Ok(SimulateResponse::denied(
                        req.id,
                        "POLICY_DENIED: path_restricted",
                        "FCP-4002",
                    ));
                }
            }
        }

        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Ok(SubscribeResponse {
            r#type: "response".to_string(),
            id: req.id,
            result: fcp_sdk::SubscribeResult {
                confirmed_topics: vec![],
                cursors: std::collections::HashMap::new(),
                replay_supported: false,
                buffer: None,
            },
        })
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Ok(())
    }
}

#[fcp_async_core::runtime::test]
async fn test_simulate_policy_denied_for_restricted_path() {
    let connector = PolicyConnector::new(vec!["/sensitive/", "/secrets/"]);

    let req = SimulateRequest {
        r#type: "simulate".to_string(),
        id: fcp_sdk::RequestId::new("sim-policy-1"),
        connector_id: ConnectorId::from_static("test:policy:v1"),
        operation: fcp_sdk::OperationId::from_static("storage.write"),
        zone_id: ZoneId::work(),
        input: json!({"path": "/sensitive/secrets.txt"}),
        capability_token: test_capability_token(),
        estimate_cost: false,
        check_availability: false,
        context: None,
        correlation_id: None,
    };

    let result = connector.simulate(req).await.unwrap();

    assert!(!result.would_succeed);
    assert_eq!(
        result.failure_reason,
        Some("POLICY_DENIED: path_restricted".to_string())
    );
    assert_eq!(result.denial_code, Some("FCP-4002".to_string()));
}

#[fcp_async_core::runtime::test]
async fn test_simulate_policy_allowed_for_safe_path() {
    let connector = PolicyConnector::new(vec!["/sensitive/", "/secrets/"]);

    let req = SimulateRequest {
        r#type: "simulate".to_string(),
        id: fcp_sdk::RequestId::new("sim-policy-2"),
        connector_id: ConnectorId::from_static("test:policy:v1"),
        operation: fcp_sdk::OperationId::from_static("storage.write"),
        zone_id: ZoneId::work(),
        input: json!({"path": "/public/data.txt"}),
        capability_token: test_capability_token(),
        estimate_cost: false,
        check_availability: false,
        context: None,
        correlation_id: None,
    };

    let result = connector.simulate(req).await.unwrap();

    assert!(result.would_succeed);
    assert!(result.failure_reason.is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// CostEstimate Boundary Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_cost_estimate_no_currency_by_default() {
    let cost = CostEstimate::with_credits(100);

    // By default, no currency cost (we don't embed pricing tables)
    assert!(cost.currency.is_none());
}

#[test]
fn test_cost_estimate_with_explicit_currency() {
    let cost = CostEstimate::with_credits(100).and_currency(CurrencyCost::usd_cents(50));

    assert!(cost.currency.is_some());
    let currency = cost.currency.unwrap();
    assert_eq!(currency.amount_cents, 50);
    assert_eq!(currency.currency_code, "USD");
}

#[test]
fn test_resource_availability_no_rate_limit() {
    // Using available() creates an availability without rate limit info
    let avail = ResourceAvailability::available();

    assert!(avail.available);
    assert!(avail.rate_limit_remaining.is_none());
    assert!(avail.rate_limit_reset_at.is_none());
}

#[test]
fn test_resource_availability_with_rate_limit() {
    let avail = ResourceAvailability::available().with_rate_limit(50, Some(30000));

    assert!(avail.available);
    assert_eq!(avail.rate_limit_remaining, Some(50));
    assert_eq!(avail.rate_limit_reset_at, Some(30000));
}
