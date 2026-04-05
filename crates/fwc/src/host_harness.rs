//! Host integration harness with connector archetype fixture matrix.
//!
//! Provides a test harness for host integration testing.  Defines six connector
//! archetypes (request-response, streaming, event-driven, batch-processor,
//! gateway, storage), each with a pre-built fixture carrying default
//! capabilities, operations, and mock responses.  The harness can auto-generate
//! integration test cases from fixtures and format results for human review.

use std::fmt::Write as _;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

// ── Archetype ────────────────────────────────────────────────────────

/// High-level connector archetype.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorArchetype {
    /// Simple request / response connectors (REST APIs, RPC).
    RequestResponse,
    /// Connectors that produce a stream of data (SSE, WebSocket, gRPC stream).
    Streaming,
    /// Connectors driven by external events (webhooks, message queues).
    EventDriven,
    /// Connectors that process items in batch (ETL, bulk import/export).
    BatchProcessor,
    /// Gateway / proxy connectors that forward to downstream services.
    Gateway,
    /// Connectors that persist or retrieve data (databases, object stores).
    Storage,
}

impl std::fmt::Display for ConnectorArchetype {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestResponse => f.write_str("request-response"),
            Self::Streaming => f.write_str("streaming"),
            Self::EventDriven => f.write_str("event-driven"),
            Self::BatchProcessor => f.write_str("batch-processor"),
            Self::Gateway => f.write_str("gateway"),
            Self::Storage => f.write_str("storage"),
        }
    }
}

impl ConnectorArchetype {
    /// All archetype variants.
    pub const ALL: [Self; 6] = [
        Self::RequestResponse,
        Self::Streaming,
        Self::EventDriven,
        Self::BatchProcessor,
        Self::Gateway,
        Self::Storage,
    ];
}

// ── Mock operation ───────────────────────────────────────────────────

/// A mock operation for testing, including a response template and fault injection knobs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MockOperation {
    /// Operation name.
    pub operation: String,
    /// JSON template for the response body.
    pub response_template: Value,
    /// Simulated latency.
    #[serde(with = "duration_serde")]
    pub latency: Duration,
    /// Fraction of calls that should return an error (0.0 .. 1.0).
    pub error_rate: f64,
    /// Whether the operation is idempotent.
    pub idempotent: bool,
}

// ── Archetype fixture ────────────────────────────────────────────────

/// A fixture representing a specific archetype instance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArchetypeFixture {
    /// Which archetype this fixture represents.
    pub archetype: ConnectorArchetype,
    /// Connector ID used in tests.
    pub connector_id: String,
    /// Capability strings this connector declares.
    pub capabilities: Vec<String>,
    /// Operations supported.
    pub supported_operations: Vec<String>,
    /// Mock responses for each operation.
    pub mock_responses: Vec<MockOperation>,
}

// ── Harness config ───────────────────────────────────────────────────

/// Configuration for a harness run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HarnessConfig {
    /// Fixtures to test against.
    pub fixtures: Vec<ArchetypeFixture>,
    /// Global timeout per test case.
    #[serde(with = "duration_serde")]
    pub timeout: Duration,
    /// Whether to run test cases in parallel.
    pub parallel: bool,
    /// Verbose output.
    pub verbose: bool,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        Self {
            fixtures: get_archetype_fixtures(),
            timeout: Duration::from_secs(30),
            parallel: false,
            verbose: false,
        }
    }
}

// ── Harness step ─────────────────────────────────────────────────────

/// A single step in an integration test case.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessStep {
    /// Run discovery on the connector.
    Discover,
    /// Invoke a specific operation.
    Invoke { operation: String, input: Value },
    /// Check connector health.
    CheckHealth,
    /// Perform a lifecycle transition.
    Lifecycle(String),
    /// Verify an assertion against the last step output.
    Verify(HarnessAssertion),
}

/// Assertion used in harness steps (simplified compared to playbook assertions).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HarnessAssertion {
    pub field_path: Option<String>,
    pub expected: Value,
    pub message: String,
}

// ── Integration test case ────────────────────────────────────────────

/// A complete integration test case generated from a fixture.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntegrationTestCase {
    /// Test case name.
    pub name: String,
    /// Archetype under test.
    pub archetype: ConnectorArchetype,
    /// Ordered steps.
    pub steps: Vec<HarnessStep>,
    /// Human-readable description of expected behavior.
    pub expected_behavior: String,
}

// ── Harness result ───────────────────────────────────────────────────

/// Result of running integration tests for one archetype.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HarnessResult {
    /// Archetype tested.
    pub archetype: ConnectorArchetype,
    /// Number of tests passed.
    pub passed: usize,
    /// Number of tests failed.
    pub failed: usize,
    /// Number of tests skipped.
    pub skipped: usize,
    /// Total wall-clock duration.
    #[serde(with = "duration_serde")]
    pub duration: Duration,
    /// Per-test detail messages.
    pub details: Vec<String>,
}

// ── Duration serde helper ────────────────────────────────────────────

mod duration_serde {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct DurationRepr {
        secs: u64,
        nanos: u32,
    }

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        DurationRepr {
            secs: d.as_secs(),
            nanos: d.subsec_nanos(),
        }
        .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let r = DurationRepr::deserialize(d)?;
        Ok(Duration::new(r.secs, r.nanos))
    }
}

// ── Default capabilities per archetype ───────────────────────────────

/// Return the default capabilities for a connector archetype.
#[must_use]
pub fn default_capabilities(archetype: ConnectorArchetype) -> Vec<String> {
    match archetype {
        ConnectorArchetype::RequestResponse => vec![
            "invoke".into(),
            "introspect".into(),
            "schema".into(),
            "health".into(),
        ],
        ConnectorArchetype::Streaming => vec![
            "invoke".into(),
            "introspect".into(),
            "schema".into(),
            "health".into(),
            "stream".into(),
            "subscribe".into(),
        ],
        ConnectorArchetype::EventDriven => vec![
            "invoke".into(),
            "introspect".into(),
            "schema".into(),
            "health".into(),
            "webhook".into(),
            "subscribe".into(),
            "acknowledge".into(),
        ],
        ConnectorArchetype::BatchProcessor => vec![
            "invoke".into(),
            "introspect".into(),
            "schema".into(),
            "health".into(),
            "batch".into(),
            "progress".into(),
        ],
        ConnectorArchetype::Gateway => vec![
            "invoke".into(),
            "introspect".into(),
            "schema".into(),
            "health".into(),
            "proxy".into(),
            "route".into(),
            "transform".into(),
        ],
        ConnectorArchetype::Storage => vec![
            "invoke".into(),
            "introspect".into(),
            "schema".into(),
            "health".into(),
            "read".into(),
            "write".into(),
            "delete".into(),
            "list".into(),
        ],
    }
}

/// Return the default operations for a connector archetype.
#[must_use]
pub fn archetype_operations(archetype: ConnectorArchetype) -> Vec<String> {
    match archetype {
        ConnectorArchetype::RequestResponse => vec![
            "get_resource".into(),
            "create_resource".into(),
            "update_resource".into(),
            "delete_resource".into(),
            "list_resources".into(),
        ],
        ConnectorArchetype::Streaming => vec![
            "open_stream".into(),
            "close_stream".into(),
            "read_events".into(),
            "get_stream_status".into(),
        ],
        ConnectorArchetype::EventDriven => vec![
            "register_webhook".into(),
            "deregister_webhook".into(),
            "list_events".into(),
            "acknowledge_event".into(),
            "replay_event".into(),
        ],
        ConnectorArchetype::BatchProcessor => vec![
            "create_batch".into(),
            "submit_batch".into(),
            "get_batch_status".into(),
            "cancel_batch".into(),
            "get_batch_results".into(),
        ],
        ConnectorArchetype::Gateway => vec![
            "forward_request".into(),
            "list_routes".into(),
            "add_route".into(),
            "remove_route".into(),
            "get_metrics".into(),
        ],
        ConnectorArchetype::Storage => vec![
            "read_object".into(),
            "write_object".into(),
            "delete_object".into(),
            "list_objects".into(),
            "get_metadata".into(),
        ],
    }
}

// ── Fixture matrix ───────────────────────────────────────────────────

/// Build the default archetype fixture matrix (one per archetype).
#[must_use]
pub fn get_archetype_fixtures() -> Vec<ArchetypeFixture> {
    ConnectorArchetype::ALL
        .iter()
        .map(|&archetype| {
            let ops = archetype_operations(archetype);
            let mock_responses: Vec<MockOperation> = ops
                .iter()
                .map(|op| mock_for_operation(archetype, op))
                .collect();

            ArchetypeFixture {
                archetype,
                connector_id: format!("test-{archetype}"),
                capabilities: default_capabilities(archetype),
                supported_operations: ops,
                mock_responses,
            }
        })
        .collect()
}

fn mock_for_operation(archetype: ConnectorArchetype, op: &str) -> MockOperation {
    let (response_template, latency_ms, idempotent) = match archetype {
        ConnectorArchetype::RequestResponse => match op {
            "get_resource" => (
                json!({"id": "res-001", "name": "Example Resource", "status": "active"}),
                50,
                true,
            ),
            "create_resource" => (json!({"id": "res-002", "created": true}), 100, false),
            "update_resource" => (json!({"id": "res-001", "updated": true}), 80, true),
            "delete_resource" => (json!({"id": "res-001", "deleted": true}), 60, true),
            "list_resources" => (
                json!({"items": [{"id": "res-001"}, {"id": "res-002"}], "total": 2}),
                120,
                true,
            ),
            _ => (json!({"ok": true}), 50, false),
        },
        ConnectorArchetype::Streaming => match op {
            "open_stream" => (
                json!({"stream_id": "strm-001", "status": "open"}),
                200,
                false,
            ),
            "close_stream" => (
                json!({"stream_id": "strm-001", "status": "closed"}),
                50,
                true,
            ),
            "read_events" => (
                json!({"events": [{"id": "evt-1", "data": "payload"}], "count": 1}),
                150,
                true,
            ),
            "get_stream_status" => (
                json!({"stream_id": "strm-001", "active": true, "messages_buffered": 42}),
                30,
                true,
            ),
            _ => (json!({"ok": true}), 50, false),
        },
        ConnectorArchetype::EventDriven => match op {
            "register_webhook" => (
                json!({"webhook_id": "wh-001", "url": "https://example.com/hook", "registered": true}),
                100,
                false,
            ),
            "deregister_webhook" => (
                json!({"webhook_id": "wh-001", "deregistered": true}),
                50,
                true,
            ),
            "list_events" => (
                json!({"events": [{"id": "evt-1", "type": "order.created"}], "total": 1}),
                80,
                true,
            ),
            "acknowledge_event" => (json!({"event_id": "evt-1", "acknowledged": true}), 30, true),
            "replay_event" => (
                json!({"event_id": "evt-1", "replayed": true, "output": {}}),
                150,
                false,
            ),
            _ => (json!({"ok": true}), 50, false),
        },
        ConnectorArchetype::BatchProcessor => match op {
            "create_batch" => (
                json!({"batch_id": "batch-001", "item_count": 100, "status": "created"}),
                80,
                false,
            ),
            "submit_batch" => (
                json!({"batch_id": "batch-001", "status": "running"}),
                200,
                false,
            ),
            "get_batch_status" => (
                json!({"batch_id": "batch-001", "status": "completed", "processed": 100, "failed": 0}),
                30,
                true,
            ),
            "cancel_batch" => (
                json!({"batch_id": "batch-001", "status": "cancelled"}),
                50,
                true,
            ),
            "get_batch_results" => (
                json!({"batch_id": "batch-001", "results": [{"id": "item-1", "ok": true}], "total": 100}),
                150,
                true,
            ),
            _ => (json!({"ok": true}), 50, false),
        },
        ConnectorArchetype::Gateway => match op {
            "forward_request" => (
                json!({"status": 200, "body": {"forwarded": true}, "latency_ms": 45}),
                100,
                false,
            ),
            "list_routes" => (
                json!({"routes": [{"path": "/api/v1", "target": "svc-a"}], "count": 1}),
                30,
                true,
            ),
            "add_route" => (
                json!({"path": "/api/v2", "target": "svc-b", "added": true}),
                60,
                false,
            ),
            "remove_route" => (json!({"path": "/api/v1", "removed": true}), 40, true),
            "get_metrics" => (
                json!({"requests_total": 1000, "errors_total": 5, "p99_latency_ms": 120}),
                50,
                true,
            ),
            _ => (json!({"ok": true}), 50, false),
        },
        ConnectorArchetype::Storage => match op {
            "read_object" => (
                json!({"key": "data/file.json", "content": "{}", "size_bytes": 2, "content_type": "application/json"}),
                80,
                true,
            ),
            "write_object" => (
                json!({"key": "data/file.json", "written": true, "version": "v2"}),
                120,
                false,
            ),
            "delete_object" => (json!({"key": "data/file.json", "deleted": true}), 50, true),
            "list_objects" => (
                json!({"objects": [{"key": "data/file.json"}, {"key": "data/other.json"}], "total": 2}),
                100,
                true,
            ),
            "get_metadata" => (
                json!({"key": "data/file.json", "size_bytes": 2, "created_at": "2026-01-01T00:00:00Z", "content_type": "application/json"}),
                40,
                true,
            ),
            _ => (json!({"ok": true}), 50, false),
        },
    };

    MockOperation {
        operation: op.into(),
        response_template,
        latency: Duration::from_millis(latency_ms),
        error_rate: 0.0,
        idempotent,
    }
}

// ── Mock operation response ──────────────────────────────────────────

/// Produce a mock response for an operation, merging template with input context.
#[must_use]
pub fn mock_operation_response(mock: &MockOperation, input: &Value) -> Value {
    let mut response = mock.response_template.clone();

    // Inject a `request_id` from input if present.
    if let Some(req_id) = input.get("request_id") {
        if let Some(obj) = response.as_object_mut() {
            obj.insert("request_id".into(), req_id.clone());
        }
    }

    // Copy operation name into the response.
    if let Some(obj) = response.as_object_mut() {
        obj.insert("operation".into(), Value::String(mock.operation.clone()));
    }

    response
}

// ── Test case generation ─────────────────────────────────────────────

/// Auto-generate integration test cases from a fixture.
#[must_use]
pub fn generate_test_cases(fixture: &ArchetypeFixture) -> Vec<IntegrationTestCase> {
    let mut cases = Vec::new();

    // 1. Discovery test
    cases.push(IntegrationTestCase {
        name: format!("{}-discovery", fixture.connector_id),
        archetype: fixture.archetype,
        steps: vec![
            HarnessStep::Discover,
            HarnessStep::Verify(HarnessAssertion {
                field_path: Some("/connector_id".into()),
                expected: Value::String(fixture.connector_id.clone()),
                message: "Discovery should return the connector ID".into(),
            }),
        ],
        expected_behavior: "Connector is discovered with correct ID and capabilities".into(),
    });

    // 2. Health check test
    cases.push(IntegrationTestCase {
        name: format!("{}-health", fixture.connector_id),
        archetype: fixture.archetype,
        steps: vec![
            HarnessStep::CheckHealth,
            HarnessStep::Verify(HarnessAssertion {
                field_path: Some("/healthy".into()),
                expected: json!(true),
                message: "Connector should report healthy".into(),
            }),
        ],
        expected_behavior: "Connector reports healthy status".into(),
    });

    // 3. Lifecycle test
    cases.push(IntegrationTestCase {
        name: format!("{}-lifecycle", fixture.connector_id),
        archetype: fixture.archetype,
        steps: vec![
            HarnessStep::Lifecycle("enable".into()),
            HarnessStep::Lifecycle("start".into()),
            HarnessStep::CheckHealth,
            HarnessStep::Lifecycle("stop".into()),
            HarnessStep::Lifecycle("disable".into()),
        ],
        expected_behavior: "Connector transitions through full lifecycle correctly".into(),
    });

    // 4. Per-operation invoke tests
    for op in &fixture.supported_operations {
        cases.push(IntegrationTestCase {
            name: format!("{}-invoke-{}", fixture.connector_id, op),
            archetype: fixture.archetype,
            steps: vec![
                HarnessStep::Invoke {
                    operation: op.clone(),
                    input: json!({"test": true}),
                },
                HarnessStep::Verify(HarnessAssertion {
                    field_path: Some("/operation".into()),
                    expected: Value::String(op.clone()),
                    message: format!("Response should include operation '{op}'"),
                }),
            ],
            expected_behavior: format!("Operation '{op}' returns expected response shape"),
        });
    }

    cases
}

// ── Validation ───────────────────────────────────────────────────────

/// Validate a harness config, returning issues (empty = valid).
#[must_use]
pub fn validate_harness_config(config: &HarnessConfig) -> Vec<String> {
    let mut issues = Vec::new();

    if config.fixtures.is_empty() {
        issues.push("No fixtures configured".into());
    }

    if config.timeout.is_zero() {
        issues.push("Global timeout is zero".into());
    }

    for fixture in &config.fixtures {
        if fixture.connector_id.is_empty() {
            issues.push(format!(
                "Fixture for {:?} has empty connector_id",
                fixture.archetype
            ));
        }
        if fixture.supported_operations.is_empty() {
            issues.push(format!(
                "Fixture '{}' has no supported operations",
                fixture.connector_id
            ));
        }
        if fixture.capabilities.is_empty() {
            issues.push(format!(
                "Fixture '{}' has no capabilities",
                fixture.connector_id
            ));
        }

        // Check that every supported operation has a mock.
        for op in &fixture.supported_operations {
            if !fixture.mock_responses.iter().any(|m| m.operation == *op) {
                issues.push(format!(
                    "Fixture '{}' missing mock for operation '{}'",
                    fixture.connector_id, op
                ));
            }
        }
    }

    issues
}

// ── TOON formatting ──────────────────────────────────────────────────

/// Format a [`HarnessResult`] as a human-readable summary (TOON style).
#[must_use]
pub fn format_harness_result_toon(result: &HarnessResult) -> String {
    let mut out = String::new();
    let total = result.passed + result.failed + result.skipped;
    let verdict = if result.failed == 0 { "PASS" } else { "FAIL" };

    let _ = writeln!(
        out,
        "Harness: {} [{verdict}] ({:.2}s)",
        result.archetype,
        result.duration.as_secs_f64()
    );
    let _ = writeln!(
        out,
        "  Tests: {} total, {} passed, {} failed, {} skipped",
        total, result.passed, result.failed, result.skipped
    );

    if !result.details.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "  Details:");
        for detail in &result.details {
            let _ = writeln!(out, "    - {detail}");
        }
    }

    out
}

/// Format the full fixture matrix as a human-readable table (TOON style).
#[must_use]
pub fn format_fixture_matrix_toon(fixtures: &[ArchetypeFixture]) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "Archetype Fixture Matrix");
    let _ = writeln!(out, "{}", "=".repeat(72));
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "{:<22}{:<20}{:<12}{:<10}Mocks",
        "Archetype", "Connector ID", "Caps", "Ops"
    );
    let _ = writeln!(out, "{}", "-".repeat(72));

    for f in fixtures {
        let _ = writeln!(
            out,
            "{:<22}{:<20}{:<12}{:<10}{}",
            f.archetype.to_string(),
            f.connector_id,
            f.capabilities.len(),
            f.supported_operations.len(),
            f.mock_responses.len(),
        );
    }

    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Total: {} fixtures, {} operations",
        fixtures.len(),
        fixtures
            .iter()
            .map(|f| f.supported_operations.len())
            .sum::<usize>(),
    );

    out
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Archetype basics ─────────────────────────────────────────────

    #[test]
    fn archetype_all_has_six_variants() {
        assert_eq!(ConnectorArchetype::ALL.len(), 6);
    }

    #[test]
    fn archetype_display_request_response() {
        assert_eq!(
            ConnectorArchetype::RequestResponse.to_string(),
            "request-response"
        );
    }

    #[test]
    fn archetype_display_streaming() {
        assert_eq!(ConnectorArchetype::Streaming.to_string(), "streaming");
    }

    #[test]
    fn archetype_display_event_driven() {
        assert_eq!(ConnectorArchetype::EventDriven.to_string(), "event-driven");
    }

    #[test]
    fn archetype_display_batch_processor() {
        assert_eq!(
            ConnectorArchetype::BatchProcessor.to_string(),
            "batch-processor"
        );
    }

    #[test]
    fn archetype_display_gateway() {
        assert_eq!(ConnectorArchetype::Gateway.to_string(), "gateway");
    }

    #[test]
    fn archetype_display_storage() {
        assert_eq!(ConnectorArchetype::Storage.to_string(), "storage");
    }

    #[test]
    fn archetype_serde_roundtrip() {
        for arch in ConnectorArchetype::ALL {
            let json = serde_json::to_string(&arch).unwrap();
            let arch2: ConnectorArchetype = serde_json::from_str(&json).unwrap();
            assert_eq!(arch, arch2);
        }
    }

    // ── Default capabilities ─────────────────────────────────────────

    #[test]
    fn capabilities_request_response_has_invoke() {
        let caps = default_capabilities(ConnectorArchetype::RequestResponse);
        assert!(caps.contains(&"invoke".to_string()));
    }

    #[test]
    fn capabilities_all_have_introspect() {
        for arch in ConnectorArchetype::ALL {
            let caps = default_capabilities(arch);
            assert!(
                caps.contains(&"introspect".to_string()),
                "{:?} missing introspect",
                arch
            );
        }
    }

    #[test]
    fn capabilities_all_have_health() {
        for arch in ConnectorArchetype::ALL {
            let caps = default_capabilities(arch);
            assert!(
                caps.contains(&"health".to_string()),
                "{:?} missing health",
                arch
            );
        }
    }

    #[test]
    fn capabilities_streaming_has_stream() {
        let caps = default_capabilities(ConnectorArchetype::Streaming);
        assert!(caps.contains(&"stream".to_string()));
    }

    #[test]
    fn capabilities_event_driven_has_webhook() {
        let caps = default_capabilities(ConnectorArchetype::EventDriven);
        assert!(caps.contains(&"webhook".to_string()));
    }

    #[test]
    fn capabilities_batch_has_batch() {
        let caps = default_capabilities(ConnectorArchetype::BatchProcessor);
        assert!(caps.contains(&"batch".to_string()));
    }

    #[test]
    fn capabilities_gateway_has_proxy() {
        let caps = default_capabilities(ConnectorArchetype::Gateway);
        assert!(caps.contains(&"proxy".to_string()));
    }

    #[test]
    fn capabilities_storage_has_read_write() {
        let caps = default_capabilities(ConnectorArchetype::Storage);
        assert!(caps.contains(&"read".to_string()));
        assert!(caps.contains(&"write".to_string()));
    }

    // ── Archetype operations ─────────────────────────────────────────

    #[test]
    fn ops_request_response_count() {
        let ops = archetype_operations(ConnectorArchetype::RequestResponse);
        assert_eq!(ops.len(), 5);
    }

    #[test]
    fn ops_streaming_count() {
        let ops = archetype_operations(ConnectorArchetype::Streaming);
        assert_eq!(ops.len(), 4);
    }

    #[test]
    fn ops_event_driven_count() {
        let ops = archetype_operations(ConnectorArchetype::EventDriven);
        assert_eq!(ops.len(), 5);
    }

    #[test]
    fn ops_batch_processor_count() {
        let ops = archetype_operations(ConnectorArchetype::BatchProcessor);
        assert_eq!(ops.len(), 5);
    }

    #[test]
    fn ops_gateway_count() {
        let ops = archetype_operations(ConnectorArchetype::Gateway);
        assert_eq!(ops.len(), 5);
    }

    #[test]
    fn ops_storage_count() {
        let ops = archetype_operations(ConnectorArchetype::Storage);
        assert_eq!(ops.len(), 5);
    }

    #[test]
    fn ops_all_nonempty() {
        for arch in ConnectorArchetype::ALL {
            assert!(
                !archetype_operations(arch).is_empty(),
                "{:?} has no ops",
                arch
            );
        }
    }

    #[test]
    fn ops_all_unique_within_archetype() {
        for arch in ConnectorArchetype::ALL {
            let ops = archetype_operations(arch);
            let mut sorted = ops.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(ops.len(), sorted.len(), "{:?} has duplicate ops", arch);
        }
    }

    // ── Fixture matrix ───────────────────────────────────────────────

    #[test]
    fn fixture_matrix_has_six_entries() {
        let fixtures = get_archetype_fixtures();
        assert_eq!(fixtures.len(), 6);
    }

    #[test]
    fn fixture_matrix_covers_all_archetypes() {
        let fixtures = get_archetype_fixtures();
        for arch in ConnectorArchetype::ALL {
            assert!(
                fixtures.iter().any(|f| f.archetype == arch),
                "Missing fixture for {:?}",
                arch
            );
        }
    }

    #[test]
    fn fixture_connector_ids_unique() {
        let fixtures = get_archetype_fixtures();
        let mut ids: Vec<&str> = fixtures.iter().map(|f| f.connector_id.as_str()).collect();
        let orig = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(orig, ids.len());
    }

    #[test]
    fn fixture_connector_ids_prefixed() {
        let fixtures = get_archetype_fixtures();
        for f in &fixtures {
            assert!(
                f.connector_id.starts_with("test-"),
                "Fixture '{}' not prefixed",
                f.connector_id
            );
        }
    }

    #[test]
    fn fixture_mock_count_matches_ops() {
        let fixtures = get_archetype_fixtures();
        for f in &fixtures {
            assert_eq!(
                f.supported_operations.len(),
                f.mock_responses.len(),
                "Fixture '{}' mock count mismatch",
                f.connector_id
            );
        }
    }

    #[test]
    fn fixture_every_op_has_mock() {
        let fixtures = get_archetype_fixtures();
        for f in &fixtures {
            for op in &f.supported_operations {
                assert!(
                    f.mock_responses.iter().any(|m| m.operation == *op),
                    "Fixture '{}' missing mock for '{}'",
                    f.connector_id,
                    op
                );
            }
        }
    }

    #[test]
    fn fixture_serde_roundtrip() {
        let fixtures = get_archetype_fixtures();
        let json = serde_json::to_string(&fixtures).unwrap();
        let fixtures2: Vec<ArchetypeFixture> = serde_json::from_str(&json).unwrap();
        assert_eq!(fixtures.len(), fixtures2.len());
    }

    // ── Mock operation response ──────────────────────────────────────

    #[test]
    fn mock_response_includes_operation_name() {
        let mock = MockOperation {
            operation: "get_resource".into(),
            response_template: json!({"id": "r1"}),
            latency: Duration::from_millis(50),
            error_rate: 0.0,
            idempotent: true,
        };
        let resp = mock_operation_response(&mock, &json!({}));
        assert_eq!(
            resp.get("operation").unwrap().as_str().unwrap(),
            "get_resource"
        );
    }

    #[test]
    fn mock_response_passes_through_request_id() {
        let mock = MockOperation {
            operation: "test".into(),
            response_template: json!({"ok": true}),
            latency: Duration::from_millis(10),
            error_rate: 0.0,
            idempotent: false,
        };
        let resp = mock_operation_response(&mock, &json!({"request_id": "req-123"}));
        assert_eq!(resp.get("request_id").unwrap().as_str().unwrap(), "req-123");
    }

    #[test]
    fn mock_response_without_request_id() {
        let mock = MockOperation {
            operation: "test".into(),
            response_template: json!({"ok": true}),
            latency: Duration::from_millis(10),
            error_rate: 0.0,
            idempotent: false,
        };
        let resp = mock_operation_response(&mock, &json!({}));
        assert!(resp.get("request_id").is_none());
    }

    #[test]
    fn mock_response_preserves_template_fields() {
        let mock = MockOperation {
            operation: "get_resource".into(),
            response_template: json!({"id": "r1", "name": "Resource", "status": "active"}),
            latency: Duration::from_millis(50),
            error_rate: 0.0,
            idempotent: true,
        };
        let resp = mock_operation_response(&mock, &json!({}));
        assert_eq!(resp.get("id").unwrap(), "r1");
        assert_eq!(resp.get("name").unwrap(), "Resource");
        assert_eq!(resp.get("status").unwrap(), "active");
    }

    #[test]
    fn mock_all_fixtures_respond() {
        let fixtures = get_archetype_fixtures();
        for f in &fixtures {
            for mock in &f.mock_responses {
                let resp = mock_operation_response(mock, &json!({"test": true}));
                assert!(
                    resp.is_object(),
                    "Response for '{}' should be an object",
                    mock.operation
                );
            }
        }
    }

    // ── Test case generation ─────────────────────────────────────────

    #[test]
    fn generate_test_cases_not_empty() {
        let fixtures = get_archetype_fixtures();
        for f in &fixtures {
            let cases = generate_test_cases(f);
            assert!(!cases.is_empty(), "No test cases for '{}'", f.connector_id);
        }
    }

    #[test]
    fn generate_test_cases_includes_discovery() {
        let fixture = &get_archetype_fixtures()[0];
        let cases = generate_test_cases(fixture);
        assert!(cases.iter().any(|c| c.name.contains("discovery")));
    }

    #[test]
    fn generate_test_cases_includes_health() {
        let fixture = &get_archetype_fixtures()[0];
        let cases = generate_test_cases(fixture);
        assert!(cases.iter().any(|c| c.name.contains("health")));
    }

    #[test]
    fn generate_test_cases_includes_lifecycle() {
        let fixture = &get_archetype_fixtures()[0];
        let cases = generate_test_cases(fixture);
        assert!(cases.iter().any(|c| c.name.contains("lifecycle")));
    }

    #[test]
    fn generate_test_cases_includes_invoke_per_op() {
        let fixture = &get_archetype_fixtures()[0];
        let cases = generate_test_cases(fixture);
        for op in &fixture.supported_operations {
            assert!(
                cases.iter().any(|c| c.name.contains(op.as_str())),
                "Missing test case for op '{}'",
                op
            );
        }
    }

    #[test]
    fn generate_test_cases_count() {
        let fixture = &get_archetype_fixtures()[0]; // request-response: 5 ops + 3 base = 8
        let cases = generate_test_cases(fixture);
        let expected = 3 + fixture.supported_operations.len(); // discovery + health + lifecycle + per-op
        assert_eq!(cases.len(), expected);
    }

    #[test]
    fn generate_test_cases_archetype_matches() {
        for f in &get_archetype_fixtures() {
            for case in generate_test_cases(f) {
                assert_eq!(case.archetype, f.archetype);
            }
        }
    }

    #[test]
    fn generate_test_cases_names_unique() {
        for f in &get_archetype_fixtures() {
            let cases = generate_test_cases(f);
            let mut names: Vec<&str> = cases.iter().map(|c| c.name.as_str()).collect();
            let orig = names.len();
            names.sort_unstable();
            names.dedup();
            assert_eq!(
                orig,
                names.len(),
                "Duplicate test case names for '{}'",
                f.connector_id
            );
        }
    }

    // ── Validation ───────────────────────────────────────────────────

    #[test]
    fn validate_default_config_is_valid() {
        let config = HarnessConfig::default();
        let issues = validate_harness_config(&config);
        assert!(issues.is_empty(), "Default config issues: {:?}", issues);
    }

    #[test]
    fn validate_empty_fixtures() {
        let config = HarnessConfig {
            fixtures: vec![],
            timeout: Duration::from_secs(30),
            parallel: false,
            verbose: false,
        };
        let issues = validate_harness_config(&config);
        assert!(issues.iter().any(|i| i.contains("No fixtures")));
    }

    #[test]
    fn validate_zero_timeout() {
        let config = HarnessConfig {
            fixtures: get_archetype_fixtures(),
            timeout: Duration::ZERO,
            parallel: false,
            verbose: false,
        };
        let issues = validate_harness_config(&config);
        assert!(issues.iter().any(|i| i.contains("timeout")));
    }

    #[test]
    fn validate_empty_connector_id() {
        let mut config = HarnessConfig::default();
        config.fixtures[0].connector_id = String::new();
        let issues = validate_harness_config(&config);
        assert!(issues.iter().any(|i| i.contains("empty connector_id")));
    }

    #[test]
    fn validate_empty_operations() {
        let mut config = HarnessConfig::default();
        config.fixtures[0].supported_operations.clear();
        let issues = validate_harness_config(&config);
        assert!(issues.iter().any(|i| i.contains("no supported operations")));
    }

    #[test]
    fn validate_empty_capabilities() {
        let mut config = HarnessConfig::default();
        config.fixtures[0].capabilities.clear();
        let issues = validate_harness_config(&config);
        assert!(issues.iter().any(|i| i.contains("no capabilities")));
    }

    #[test]
    fn validate_missing_mock() {
        let mut config = HarnessConfig::default();
        config.fixtures[0].mock_responses.pop(); // Remove last mock
        let issues = validate_harness_config(&config);
        assert!(issues.iter().any(|i| i.contains("missing mock")));
    }

    // ── TOON formatting ──────────────────────────────────────────────

    #[test]
    fn format_harness_result_pass() {
        let result = HarnessResult {
            archetype: ConnectorArchetype::RequestResponse,
            passed: 5,
            failed: 0,
            skipped: 0,
            duration: Duration::from_millis(1200),
            details: vec![],
        };
        let out = format_harness_result_toon(&result);
        assert!(out.contains("PASS"));
        assert!(out.contains("request-response"));
    }

    #[test]
    fn format_harness_result_fail() {
        let result = HarnessResult {
            archetype: ConnectorArchetype::Streaming,
            passed: 3,
            failed: 2,
            skipped: 1,
            duration: Duration::from_millis(800),
            details: vec!["stream timeout".into()],
        };
        let out = format_harness_result_toon(&result);
        assert!(out.contains("FAIL"));
        assert!(out.contains("6 total"));
        assert!(out.contains("3 passed"));
        assert!(out.contains("2 failed"));
    }

    #[test]
    fn format_harness_result_with_details() {
        let result = HarnessResult {
            archetype: ConnectorArchetype::Storage,
            passed: 4,
            failed: 1,
            skipped: 0,
            duration: Duration::from_secs(2),
            details: vec!["write timed out".into(), "read slow".into()],
        };
        let out = format_harness_result_toon(&result);
        assert!(out.contains("Details:"));
        assert!(out.contains("write timed out"));
        assert!(out.contains("read slow"));
    }

    #[test]
    fn format_harness_result_empty_details() {
        let result = HarnessResult {
            archetype: ConnectorArchetype::Gateway,
            passed: 3,
            failed: 0,
            skipped: 0,
            duration: Duration::from_millis(500),
            details: vec![],
        };
        let out = format_harness_result_toon(&result);
        assert!(!out.contains("Details:"));
    }

    #[test]
    fn format_fixture_matrix_header() {
        let fixtures = get_archetype_fixtures();
        let out = format_fixture_matrix_toon(&fixtures);
        assert!(out.contains("Archetype Fixture Matrix"));
        assert!(out.contains("Archetype"));
        assert!(out.contains("Connector ID"));
    }

    #[test]
    fn format_fixture_matrix_all_archetypes_present() {
        let fixtures = get_archetype_fixtures();
        let out = format_fixture_matrix_toon(&fixtures);
        assert!(out.contains("request-response"));
        assert!(out.contains("streaming"));
        assert!(out.contains("event-driven"));
        assert!(out.contains("batch-processor"));
        assert!(out.contains("gateway"));
        assert!(out.contains("storage"));
    }

    #[test]
    fn format_fixture_matrix_total_line() {
        let fixtures = get_archetype_fixtures();
        let out = format_fixture_matrix_toon(&fixtures);
        assert!(out.contains("Total: 6 fixtures"));
    }

    #[test]
    fn format_fixture_matrix_empty() {
        let out = format_fixture_matrix_toon(&[]);
        assert!(out.contains("Total: 0 fixtures"));
    }

    // ── HarnessConfig default ────────────────────────────────────────

    #[test]
    fn harness_config_default_has_fixtures() {
        let config = HarnessConfig::default();
        assert_eq!(config.fixtures.len(), 6);
    }

    #[test]
    fn harness_config_default_timeout_nonzero() {
        let config = HarnessConfig::default();
        assert!(!config.timeout.is_zero());
    }

    #[test]
    fn harness_config_default_not_parallel() {
        let config = HarnessConfig::default();
        assert!(!config.parallel);
    }

    #[test]
    fn harness_config_default_not_verbose() {
        let config = HarnessConfig::default();
        assert!(!config.verbose);
    }

    #[test]
    fn harness_config_serde_roundtrip() {
        let config = HarnessConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let config2: HarnessConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.fixtures.len(), config2.fixtures.len());
        assert_eq!(config.parallel, config2.parallel);
        assert_eq!(config.verbose, config2.verbose);
    }

    // ── HarnessStep serde ────────────────────────────────────────────

    #[test]
    fn harness_step_discover_serde() {
        let step = HarnessStep::Discover;
        let json = serde_json::to_string(&step).unwrap();
        let step2: HarnessStep = serde_json::from_str(&json).unwrap();
        matches!(step2, HarnessStep::Discover);
    }

    #[test]
    fn harness_step_invoke_serde() {
        let step = HarnessStep::Invoke {
            operation: "get_resource".into(),
            input: json!({"id": "r1"}),
        };
        let json = serde_json::to_string(&step).unwrap();
        let step2: HarnessStep = serde_json::from_str(&json).unwrap();
        if let HarnessStep::Invoke { operation, .. } = step2 {
            assert_eq!(operation, "get_resource");
        } else {
            panic!("Expected Invoke variant");
        }
    }

    #[test]
    fn harness_step_check_health_serde() {
        let step = HarnessStep::CheckHealth;
        let json = serde_json::to_string(&step).unwrap();
        let step2: HarnessStep = serde_json::from_str(&json).unwrap();
        matches!(step2, HarnessStep::CheckHealth);
    }

    #[test]
    fn harness_step_lifecycle_serde() {
        let step = HarnessStep::Lifecycle("enable".into());
        let json = serde_json::to_string(&step).unwrap();
        let step2: HarnessStep = serde_json::from_str(&json).unwrap();
        if let HarnessStep::Lifecycle(action) = step2 {
            assert_eq!(action, "enable");
        } else {
            panic!("Expected Lifecycle variant");
        }
    }

    #[test]
    fn harness_step_verify_serde() {
        let step = HarnessStep::Verify(HarnessAssertion {
            field_path: Some("/status".into()),
            expected: json!("ok"),
            message: "check".into(),
        });
        let json = serde_json::to_string(&step).unwrap();
        let step2: HarnessStep = serde_json::from_str(&json).unwrap();
        if let HarnessStep::Verify(a) = step2 {
            assert_eq!(a.message, "check");
        } else {
            panic!("Expected Verify variant");
        }
    }

    // ── HarnessResult serde ──────────────────────────────────────────

    #[test]
    fn harness_result_serde_roundtrip() {
        let result = HarnessResult {
            archetype: ConnectorArchetype::BatchProcessor,
            passed: 4,
            failed: 1,
            skipped: 2,
            duration: Duration::from_secs(5),
            details: vec!["detail".into()],
        };
        let json = serde_json::to_string(&result).unwrap();
        let result2: HarnessResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.archetype, result2.archetype);
        assert_eq!(result.passed, result2.passed);
        assert_eq!(result.failed, result2.failed);
        assert_eq!(result.skipped, result2.skipped);
    }

    // ── Integration test case structure ──────────────────────────────

    #[test]
    fn integration_test_case_serde_roundtrip() {
        let case = IntegrationTestCase {
            name: "test-case-1".into(),
            archetype: ConnectorArchetype::Storage,
            steps: vec![HarnessStep::Discover, HarnessStep::CheckHealth],
            expected_behavior: "should work".into(),
        };
        let json = serde_json::to_string(&case).unwrap();
        let case2: IntegrationTestCase = serde_json::from_str(&json).unwrap();
        assert_eq!(case.name, case2.name);
        assert_eq!(case.archetype, case2.archetype);
        assert_eq!(case.steps.len(), case2.steps.len());
    }

    // ── MockOperation fields ─────────────────────────────────────────

    #[test]
    fn mock_operation_serde_roundtrip() {
        let mock = MockOperation {
            operation: "test_op".into(),
            response_template: json!({"result": "ok"}),
            latency: Duration::from_millis(100),
            error_rate: 0.05,
            idempotent: true,
        };
        let json = serde_json::to_string(&mock).unwrap();
        let mock2: MockOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(mock.operation, mock2.operation);
        assert_eq!(mock.idempotent, mock2.idempotent);
    }

    #[test]
    fn mock_idempotent_flags_correct() {
        let fixtures = get_archetype_fixtures();
        // request-response: get is idempotent, create is not
        let rr = fixtures
            .iter()
            .find(|f| f.archetype == ConnectorArchetype::RequestResponse)
            .unwrap();
        let get_mock = rr
            .mock_responses
            .iter()
            .find(|m| m.operation == "get_resource")
            .unwrap();
        assert!(get_mock.idempotent);
        let create_mock = rr
            .mock_responses
            .iter()
            .find(|m| m.operation == "create_resource")
            .unwrap();
        assert!(!create_mock.idempotent);
    }

    #[test]
    fn mock_latencies_positive() {
        let fixtures = get_archetype_fixtures();
        for f in &fixtures {
            for mock in &f.mock_responses {
                assert!(
                    !mock.latency.is_zero(),
                    "Mock '{}' has zero latency",
                    mock.operation
                );
            }
        }
    }

    #[test]
    fn mock_error_rates_default_zero() {
        let fixtures = get_archetype_fixtures();
        for f in &fixtures {
            for mock in &f.mock_responses {
                assert!(
                    (mock.error_rate - 0.0).abs() < f64::EPSILON,
                    "Mock '{}' has non-zero default error rate",
                    mock.operation
                );
            }
        }
    }

    // ── Additional coverage ──────────────────────────────────────────

    #[test]
    fn generate_test_cases_streaming_archetype() {
        let fixtures = get_archetype_fixtures();
        let streaming = fixtures
            .iter()
            .find(|f| f.archetype == ConnectorArchetype::Streaming)
            .unwrap();
        let cases = generate_test_cases(streaming);
        // 3 base + 4 ops = 7
        assert_eq!(cases.len(), 7);
        assert!(cases.iter().any(|c| c.name.contains("open_stream")));
    }

    #[test]
    fn generate_test_cases_event_driven_archetype() {
        let fixtures = get_archetype_fixtures();
        let ed = fixtures
            .iter()
            .find(|f| f.archetype == ConnectorArchetype::EventDriven)
            .unwrap();
        let cases = generate_test_cases(ed);
        assert_eq!(cases.len(), 8); // 3 base + 5 ops
        assert!(cases.iter().any(|c| c.name.contains("register_webhook")));
    }

    #[test]
    fn generate_test_cases_batch_processor_archetype() {
        let fixtures = get_archetype_fixtures();
        let bp = fixtures
            .iter()
            .find(|f| f.archetype == ConnectorArchetype::BatchProcessor)
            .unwrap();
        let cases = generate_test_cases(bp);
        assert_eq!(cases.len(), 8);
        assert!(cases.iter().any(|c| c.name.contains("create_batch")));
    }

    #[test]
    fn generate_test_cases_gateway_archetype() {
        let fixtures = get_archetype_fixtures();
        let gw = fixtures
            .iter()
            .find(|f| f.archetype == ConnectorArchetype::Gateway)
            .unwrap();
        let cases = generate_test_cases(gw);
        assert_eq!(cases.len(), 8);
        assert!(cases.iter().any(|c| c.name.contains("forward_request")));
    }

    #[test]
    fn generate_test_cases_storage_archetype() {
        let fixtures = get_archetype_fixtures();
        let st = fixtures
            .iter()
            .find(|f| f.archetype == ConnectorArchetype::Storage)
            .unwrap();
        let cases = generate_test_cases(st);
        assert_eq!(cases.len(), 8);
        assert!(cases.iter().any(|c| c.name.contains("read_object")));
    }

    #[test]
    fn format_harness_result_shows_duration() {
        let result = HarnessResult {
            archetype: ConnectorArchetype::EventDriven,
            passed: 2,
            failed: 0,
            skipped: 0,
            duration: Duration::from_millis(3456),
            details: vec![],
        };
        let out = format_harness_result_toon(&result);
        assert!(out.contains("3.46"));
    }

    #[test]
    fn archetype_equality() {
        assert_eq!(
            ConnectorArchetype::RequestResponse,
            ConnectorArchetype::RequestResponse
        );
        assert_ne!(
            ConnectorArchetype::RequestResponse,
            ConnectorArchetype::Streaming
        );
    }

    #[test]
    fn harness_assertion_serde_roundtrip() {
        let a = HarnessAssertion {
            field_path: Some("/x".into()),
            expected: json!(42),
            message: "check x".into(),
        };
        let json = serde_json::to_string(&a).unwrap();
        let a2: HarnessAssertion = serde_json::from_str(&json).unwrap();
        assert_eq!(a.message, a2.message);
        assert_eq!(a.expected, a2.expected);
    }

    #[test]
    fn harness_assertion_no_field_path() {
        let a = HarnessAssertion {
            field_path: None,
            expected: json!("ok"),
            message: "root".into(),
        };
        let json = serde_json::to_string(&a).unwrap();
        let a2: HarnessAssertion = serde_json::from_str(&json).unwrap();
        assert!(a2.field_path.is_none());
    }

    #[test]
    fn mock_response_with_complex_input() {
        let mock = MockOperation {
            operation: "complex".into(),
            response_template: json!({"status": "ok"}),
            latency: Duration::from_millis(10),
            error_rate: 0.0,
            idempotent: false,
        };
        let input = json!({
            "request_id": "req-complex",
            "nested": {"deep": {"value": 42}},
            "list": [1, 2, 3]
        });
        let resp = mock_operation_response(&mock, &input);
        assert_eq!(resp.get("request_id").unwrap(), "req-complex");
        assert_eq!(resp.get("operation").unwrap(), "complex");
        assert_eq!(resp.get("status").unwrap(), "ok");
    }
}
