//! Minimal FCP connector binary for subprocess integration tests.
//!
//! This connector is intentionally simple and deterministic. It implements the
//! JSON-RPC loop used by other connectors and supports configure/handshake/
//! health/introspect/invoke/simulate so host integration tests can exercise
//! real subprocess flows without external dependencies.

#![forbid(unsafe_code)]

use std::io::{BufRead, Write};
use std::time::Instant;

use fcp_core::{
    AgentHint, ApprovalMode, CapabilityId, ConnectorId, EventCaps, FcpError, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, HealthState, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, ObjectId, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport,
    SessionId, ShutdownRequest, SimulateRequest, SimulateResponse,
};
use serde_json::json;

struct TestConnector {
    id: ConnectorId,
    start_time: Instant,
    configured: bool,
}

impl TestConnector {
    fn new(id: ConnectorId) -> Self {
        Self {
            id,
            start_time: Instant::now(),
            configured: false,
        }
    }

    fn handle_configure(
        &mut self,
        _params: serde_json::Value,
    ) -> Result<serde_json::Value, FcpError> {
        self.configured = true;
        Ok(json!({ "status": "ok" }))
    }

    fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, FcpError> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|err| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {err}"),
            })?;

        let response = HandshakeResponse {
            status: "accepted".to_string(),
            capabilities_granted: Vec::new(),
            session_id: SessionId::new(),
            manifest_hash: "sha256:fcp-test-connector".to_string(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize handshake response: {err}"),
        })
    }

    fn handle_health(&self) -> Result<serde_json::Value, FcpError> {
        let snapshot = HealthSnapshot {
            status: HealthState::Ready,
            uptime_ms: self.start_time.elapsed().as_millis() as u64,
            load: None,
            details: Some(json!({ "configured": self.configured })),
            rate_limit: None,
        };

        serde_json::to_value(snapshot).map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize health snapshot: {err}"),
        })
    }

    fn handle_self_check(&self) -> Result<serde_json::Value, FcpError> {
        let report = SelfCheckReport::ok();
        serde_json::to_value(report).map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {err}"),
        })
    }

    fn handle_introspect(&self) -> Result<serde_json::Value, FcpError> {
        let operation = OperationInfo {
            id: OperationId::from_static("test.echo"),
            summary: "Echo input payload".to_string(),
            description: Some("Returns the input payload as output.".to_string()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({ "type": "object" }),
            capability: CapabilityId::new("cap.test.echo").map_err(|err| FcpError::Internal {
                message: format!("Invalid capability id: {err}"),
            })?,
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use for subprocess integration testing.".to_string(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        };

        let introspection = Introspection {
            operations: vec![operation],
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize introspection: {err}"),
        })
    }

    fn handle_invoke(&self, params: serde_json::Value) -> Result<serde_json::Value, FcpError> {
        let req: InvokeRequest =
            serde_json::from_value(params).map_err(|err| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid invoke request: {err}"),
            })?;

        if req.connector_id != self.id {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!(
                    "Connector id mismatch: expected {}, got {}",
                    self.id.as_str(),
                    req.connector_id.as_str()
                ),
            });
        }

        let mut response = InvokeResponse::ok(req.id, json!({ "echo": req.input }));
        response.receipt_id = Some(ObjectId::from_unscoped_bytes(b"test-receipt"));

        serde_json::to_value(response).map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize invoke response: {err}"),
        })
    }

    fn handle_simulate(&self, params: serde_json::Value) -> Result<serde_json::Value, FcpError> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|err| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {err}"),
            })?;

        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize simulate response: {err}"),
        })
    }

    fn handle_shutdown(&self, params: serde_json::Value) -> Result<serde_json::Value, FcpError> {
        let _req: ShutdownRequest =
            serde_json::from_value(params).map_err(|err| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid shutdown request: {err}"),
            })?;
        Ok(json!({ "status": "ok" }))
    }
}

fn default_connector_id() -> ConnectorId {
    let default_id = "fcp.test.echo:utility:1.0.0";
    let id = std::env::var("FCP_TEST_CONNECTOR_ID").unwrap_or_else(|_| default_id.to_string());
    id.parse()
        .unwrap_or_else(|_| ConnectorId::from_static(default_id))
}

fn handle_message(connector: &mut TestConnector, message: &str) -> serde_json::Value {
    let request: serde_json::Value = match serde_json::from_str(message) {
        Ok(value) => value,
        Err(err) => {
            return json!({
                "error": {
                    "code": "FCP-1001",
                    "message": format!("Invalid JSON: {err}")
                }
            });
        }
    };

    let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let id = request.get("id").cloned();
    let params = request.get("params").cloned().unwrap_or(json!({}));

    let result = match method {
        "configure" => connector.handle_configure(params),
        "handshake" => connector.handle_handshake(params),
        "health" => connector.handle_health(),
        "self_check" => connector.handle_self_check(),
        "introspect" => connector.handle_introspect(),
        "invoke" => connector.handle_invoke(params),
        "simulate" => connector.handle_simulate(params),
        "shutdown" => connector.handle_shutdown(params),
        _ => Err(FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown method: {method}"),
        }),
    };

    match result {
        Ok(value) => {
            let mut response = json!({
                "jsonrpc": "2.0",
                "result": value,
            });
            if let Some(id) = id {
                response["id"] = id;
            }
            response
        }
        Err(err) => {
            let err_response = err.to_response();
            let mut response = json!({
                "jsonrpc": "2.0",
                "error": err_response,
            });
            if let Some(id) = id {
                response["id"] = id;
            }
            response
        }
    }
}

fn run_loop(mut connector: TestConnector) -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let response = handle_message(&mut connector, &line);
        let response_json = serde_json::to_string(&response)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        writeln!(stdout, "{response_json}")?;
        stdout.flush()?;
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let connector_id = default_connector_id();
    let connector = TestConnector::new(connector_id);
    run_loop(connector)?;
    Ok(())
}
