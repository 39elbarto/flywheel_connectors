//! Wolfram Alpha FCP connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel,
    SafetyTier, SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::json;
use tracing::{info, instrument};

use crate::client::WolframClient;
use crate::types::WolframConfig;

/// FCP Wolfram Alpha Connector.
pub struct WolframConnector {
    base: Arc<BaseConnector>,
    config: Option<WolframConfig>,
    client: Option<WolframClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    runtime: Option<ConnectorRuntime>,
}

impl Default for WolframConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl WolframConnector {
    /// Create a new Wolfram Alpha connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("wolfram"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            runtime: None,
        }
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config: WolframConfig =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid configuration: {e}"),
            })?;

        // Validate base_url doesn't include https:// protocol
        // (http:// is allowed for local development and testing)
        if config.base_url.starts_with("https://") {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "base_url should not include protocol prefix".into(),
            });
        }

        let client = WolframClient::new(&config);
        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);
        self.runtime = Some(ConnectorRuntime::new(ConnectorRuntimeConfig::default()));

        info!("Wolfram Alpha connector configured");
        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    #[allow(clippy::unused_async)]
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:wolfram-connector-v1".into(),
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

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize handshake response: {e}"),
        })
    }

    /// Handle health check.
    #[must_use]
    pub fn handle_health(&self) -> serde_json::Value {
        json!({
            "status": if self.config.is_some() { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": self.base.metrics().requests_total,
                "requests_error": self.base.metrics().requests_error,
            }
        })
    }

    /// Handle doctor checks.
    #[allow(clippy::unused_async)]
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // Check 1: Configuration
        let config_ok = self.config.is_some();
        checks.push(json!({
            "name": "configuration",
            "passed": config_ok,
            "message": if config_ok { "Configuration loaded" } else { "Not configured" },
            "critical": true
        }));

        if let Some(config) = &self.config {
            // Check 2: Base URL format
            let url_ok = config.base_url.contains("wolframalpha.com")
                || config.base_url.contains("wolfram.com")
                || config.base_url.contains("localhost");
            checks.push(json!({
                "name": "base_url",
                "passed": url_ok,
                "message": if url_ok {
                    format!("Base URL: {}", config.base_url)
                } else {
                    format!("Unexpected base URL: {}", config.base_url)
                },
                "critical": false
            }));

            // Check 3: Credential ID
            let cred_str = config.credential_id.to_string();
            let cred_prefix = if cred_str.len() >= 8 {
                &cred_str[..8]
            } else {
                &cred_str
            };
            checks.push(json!({
                "name": "credential",
                "passed": true,
                "message": format!("Credential ID: {cred_prefix}..."),
                "critical": true
            }));

            // Check 4: Runtime
            let runtime_ok = self.runtime.is_some();
            checks.push(json!({
                "name": "runtime",
                "passed": runtime_ok,
                "message": if runtime_ok { "Runtime initialised" } else { "Runtime not initialised" },
                "critical": true
            }));

            // Check 5: Client
            let client_ok = self.client.is_some();
            checks.push(json!({
                "name": "client",
                "passed": client_ok,
                "message": if client_ok { "HTTP client ready" } else { "HTTP client not initialised" },
                "critical": true
            }));
        }

        let all_critical_pass = checks
            .iter()
            .all(|c| !c["critical"].as_bool().unwrap_or(false) || c["passed"].as_bool().unwrap_or(false));

        Ok(json!({
            "status": if all_critical_pass { "healthy" } else { "unhealthy" },
            "checks": checks
        }))
    }

    /// Handle self-check.
    #[allow(clippy::unused_async)]
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        if self.session_id.is_none() {
            let report = SelfCheckReport::degraded(
                "not_handshaken",
                "Session not established — run handshake first",
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        }

        // Validate base URL
        let url_ok = config.base_url.contains("wolframalpha.com")
            || config.base_url.contains("wolfram.com");
        if !url_ok {
            let mut report = SelfCheckReport::failed(
                "base_url_mismatch",
                format!("Base URL '{}' does not match Wolfram Alpha", config.base_url),
            );
            report.details = Some(json!({"base_url": config.base_url}));
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        }

        let mut report = SelfCheckReport::ok();
        report.details = Some(json!({
            "base_url": config.base_url,
            "runtime_ready": self.runtime.is_some(),
            "client_ready": self.client.is_some(),
        }));

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle simulate.
    #[allow(clippy::unused_async)]
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        if self.config.is_none() {
            let mut resp = SimulateResponse::allowed(req.id);
            resp.would_succeed = false;
            resp.failure_reason = Some("Connector is not configured".into());
            resp.denial_code = Some("not_configured".into());
            return serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize simulate response: {e}"),
            });
        }

        let ops = wolfram_operations();
        let op_exists = ops.iter().any(|o| o.id.as_ref() == req.operation.as_ref());
        if !op_exists {
            let mut resp = SimulateResponse::allowed(req.id);
            resp.would_succeed = false;
            resp.failure_reason = Some(format!("Unknown operation: {}", req.operation));
            resp.denial_code = Some("unknown_operation".into());
            return serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize simulate response: {e}"),
            });
        }

        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize simulate response: {e}"),
        })
    }

    /// Handle invoke.
    #[allow(clippy::unused_async)]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }

        let operation = params
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        // Verify capability token if verifier is set
        if let (Some(verifier), Some(token)) = (&self.verifier, params.get("capability_token")) {
            let cap_token: CapabilityToken =
                serde_json::from_value(token.clone()).map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid capability token: {e}"),
                })?;
            let required_cap = required_capability_for_operation(operation)
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Unknown operation: {operation}"),
                })?;
            let op_id = OperationId::from_static(
                match operation {
                    "wolfram.query" => "wolfram.query",
                    "wolfram.short_answer" => "wolfram.short_answer",
                    "wolfram.spoken_result" => "wolfram.spoken_result",
                    _ => {
                        return Err(FcpError::InvalidRequest {
                            code: 1003,
                            message: format!("Unknown operation: {operation}"),
                        })
                    }
                },
            );
            verifier.verify(&cap_token, &required_cap, &op_id, &[])?;
        }

        let query = input
            .get("input")
            .or_else(|| input.get("query"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing 'input' or 'query' field".into(),
            })?;

        if query.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Query cannot be empty".into(),
            });
        }

        // Use a placeholder app_id — in production, the egress proxy injects credentials
        let app_id = input
            .get("app_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("CREDENTIAL_INJECTED");

        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        match operation {
            "wolfram.query" => {
                let qr = client.query(query, app_id).await.map_err(|e| {
                    use fcp_sdk::migration::ConnectorErrorMapping;
                    e.to_fcp_error()
                })?;
                serde_json::to_value(qr).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize query result: {e}"),
                })
            }
            "wolfram.short_answer" => {
                client.short_answer(query, app_id).await.map_err(|e| {
                    use fcp_sdk::migration::ConnectorErrorMapping;
                    e.to_fcp_error()
                })
            }
            "wolfram.spoken_result" => {
                client.spoken_result(query, app_id).await.map_err(|e| {
                    use fcp_sdk::migration::ConnectorErrorMapping;
                    e.to_fcp_error()
                })
            }
            _ => Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("Unknown operation: {operation}"),
            }),
        }
    }

    /// Handle introspect.
    #[must_use]
    pub fn handle_introspect(&self) -> Introspection {
        Introspection {
            operations: wolfram_operations(),
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    /// Graceful shutdown.
    pub fn shutdown(&self) {
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
    }
}

/// Define the Wolfram Alpha operations.
#[must_use]
pub fn wolfram_operations() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static("wolfram.query"),
            summary: "Full computational query with pods, subpods, and assumptions".into(),
            description: Some("Sends a query to the Wolfram Alpha Full Results API and returns structured pods with plain text and image representations".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "input": {"type": "string", "description": "Query to compute"}
                },
                "required": ["input"]
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "numpods": {"type": "integer"},
                    "pods": {"type": "array"},
                    "assumptions": {"type": "array"}
                }
            }),
            capability: CapabilityId::from_static("wolfram.query"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use for complex computations, data lookups, mathematical queries, unit conversions, and factual questions that need structured results".into(),
                common_mistakes: vec![
                    "Sending empty queries".into(),
                    "Not checking the 'success' field in the response".into(),
                ],
                examples: vec![
                    r#"{"input": "integrate x^2 dx"}"#.into(),
                    r#"{"input": "population of Tokyo"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("wolfram.short_answer"),
                    CapabilityId::from_static("wolfram.spoken_result"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("wolfram.short_answer"),
            summary: "Short text answer to a computational query".into(),
            description: Some("Returns a single-line text answer via the Short Answers API".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "input": {"type": "string", "description": "Query to answer"}
                },
                "required": ["input"]
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "answer": {"type": "string"}
                }
            }),
            capability: CapabilityId::from_static("wolfram.query"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use for quick factual answers, unit conversions, simple calculations".into(),
                common_mistakes: vec!["Sending empty queries".into()],
                examples: vec![
                    r#"{"input": "distance from Earth to Mars"}"#.into(),
                    r#"{"input": "100 USD to EUR"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("wolfram.query")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("wolfram.spoken_result"),
            summary: "Natural language spoken-word answer to a query".into(),
            description: Some("Returns a spoken-word text answer suitable for voice output via the Spoken Results API".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "input": {"type": "string", "description": "Query to answer in spoken form"}
                },
                "required": ["input"]
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "spoken": {"type": "string"}
                }
            }),
            capability: CapabilityId::from_static("wolfram.query"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use when you need a human-readable spoken answer for voice output or natural conversation".into(),
                common_mistakes: vec!["Sending empty queries".into()],
                examples: vec![
                    r#"{"input": "how far is the moon"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("wolfram.short_answer")],
            },
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

fn required_capability_for_operation(operation: &str) -> Option<CapabilityId> {
    match operation {
        "wolfram.query" | "wolfram.short_answer" | "wolfram.spoken_result" => {
            Some(CapabilityId::from_static("wolfram.query"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{InstanceId, ZoneId};
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use chrono::{Duration, Utc};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn generate_token(signing_key: &Ed25519SigningKey, cap: &str, ops: &[&str]) -> CapabilityToken {
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(ops)
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .sign(signing_key)
            .expect("token sign");
        CapabilityToken { raw: cose }
    }

    fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key,
            nonce: [7u8; 32],
            capabilities_requested: capabilities
                .iter()
                .map(|cap| cap.parse::<CapabilityId>().expect("capability id"))
                .collect(),
            host: None,
            transport_caps: None,
            requested_instance_id: Some(InstanceId::new()),
        }
    }

    async fn setup_connector(
        base_url: &str,
        caps: &[&str],
    ) -> (WolframConnector, Ed25519SigningKey) {
        let mut connector = WolframConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        connector
            .handle_configure(json!({
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "base_url": base_url
            }))
            .await
            .expect("configure should succeed");

        let hs = handshake_request(signing_key.verifying_key().to_bytes(), caps);
        connector
            .handle_handshake(serde_json::to_value(hs).expect("serialize"))
            .await
            .expect("handshake should succeed");

        (connector, signing_key)
    }

    #[fcp_async_core::runtime::test]
    async fn configure_success() {
        let mut connector = WolframConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await
            .expect("configure");
        assert_eq!(result["status"], "configured");
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_protocol_prefix() {
        let mut connector = WolframConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
                "base_url": "https://api.wolframalpha.com"
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn health_unconfigured() {
        let connector = WolframConnector::new();
        let health = connector.handle_health();
        assert_eq!(health["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn health_configured() {
        let mut connector = WolframConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await
            .expect("configure");
        let health = connector.handle_health();
        assert_eq!(health["status"], "healthy");
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_unconfigured() {
        let connector = WolframConnector::new();
        let result = connector.handle_doctor().await.expect("doctor");
        assert_eq!(result["status"], "unhealthy");
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_configured() {
        let mut connector = WolframConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await
            .expect("configure");
        let result = connector.handle_doctor().await.expect("doctor");
        assert_eq!(result["status"], "healthy");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_unconfigured() {
        let connector = WolframConnector::new();
        let result = connector.handle_self_check().await.expect("self_check");
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_no_handshake() {
        let mut connector = WolframConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await
            .expect("configure");
        let result = connector.handle_self_check().await.expect("self_check");
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "not_handshaken");
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_ok() {
        let (connector, _key) =
            setup_connector("api.wolframalpha.com", &["wolfram.query"]).await;
        let result = connector.handle_self_check().await.expect("self_check");
        assert_eq!(result["status"], "ok");
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_known_operation() {
        let (connector, signing_key) =
            setup_connector("api.wolframalpha.com", &["wolfram.query"]).await;
        let token = generate_token(&signing_key, "wolfram.query", &["wolfram.query"]);
        let result = connector
            .handle_simulate(json!({
                "type": "simulate",
                "id": "sim-001",
                "connector_id": "wolfram",
                "operation": "wolfram.query",
                "zone_id": "z:work",
                "input": {"input": "2+2"},
                "capability_token": token
            }))
            .await
            .expect("simulate");
        assert_eq!(result["would_succeed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_unknown_operation() {
        let (connector, signing_key) =
            setup_connector("api.wolframalpha.com", &["wolfram.query"]).await;
        let token = generate_token(&signing_key, "wolfram.query", &["wolfram.nonexistent"]);
        let result = connector
            .handle_simulate(json!({
                "type": "simulate",
                "id": "sim-002",
                "connector_id": "wolfram",
                "operation": "wolfram.nonexistent",
                "zone_id": "z:work",
                "input": {},
                "capability_token": token
            }))
            .await
            .expect("simulate");
        assert_eq!(result["would_succeed"], false);
        assert_eq!(result["denial_code"], "unknown_operation");
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_unconfigured() {
        let connector = WolframConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let token = generate_token(&signing_key, "wolfram.query", &["wolfram.query"]);
        let result = connector
            .handle_simulate(json!({
                "type": "simulate",
                "id": "sim-003",
                "connector_id": "wolfram",
                "operation": "wolfram.query",
                "zone_id": "z:work",
                "input": {},
                "capability_token": token
            }))
            .await
            .expect("simulate");
        assert_eq!(result["would_succeed"], false);
        assert_eq!(result["denial_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_query() {
        let server = MockServer::start().await;
        let body = json!({
            "queryresult": {
                "success": true,
                "numpods": 1,
                "pods": [{
                    "title": "Result",
                    "id": "Result",
                    "primary": true,
                    "subpods": [{"plaintext": "4"}]
                }],
                "assumptions": []
            }
        });
        Mock::given(method("GET"))
            .and(path("/v2/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&server)
            .await;

        // Use the server URI without the protocol for configure
        let base_url = server.uri();
        let (connector, signing_key) =
            setup_connector(&base_url, &["wolfram.query"]).await;

        // Override the client to use the mock server with protocol
        let token = generate_token(&signing_key, "wolfram.query", &["wolfram.query"]);
        let result = connector
            .handle_invoke(json!({
                "operation": "wolfram.query",
                "input": {"input": "2+2"},
                "capability_token": token
            }))
            .await
            .expect("invoke");
        assert_eq!(result["success"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_short_answer() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/result"))
            .respond_with(ResponseTemplate::new(200).set_body_string("42"))
            .mount(&server)
            .await;

        let base_url = server.uri();
        let (connector, signing_key) =
            setup_connector(&base_url, &["wolfram.query"]).await;
        let token = generate_token(&signing_key, "wolfram.query", &["wolfram.short_answer"]);
        let result = connector
            .handle_invoke(json!({
                "operation": "wolfram.short_answer",
                "input": {"input": "meaning of life"},
                "capability_token": token
            }))
            .await
            .expect("invoke");
        assert_eq!(result["answer"], "42");
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_spoken_result() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/spoken"))
            .respond_with(ResponseTemplate::new(200).set_body_string("The answer is 4"))
            .mount(&server)
            .await;

        let base_url = server.uri();
        let (connector, signing_key) =
            setup_connector(&base_url, &["wolfram.query"]).await;
        let token = generate_token(&signing_key, "wolfram.query", &["wolfram.spoken_result"]);
        let result = connector
            .handle_invoke(json!({
                "operation": "wolfram.spoken_result",
                "input": {"input": "2+2"},
                "capability_token": token
            }))
            .await
            .expect("invoke");
        assert_eq!(result["spoken"], "The answer is 4");
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_unconfigured() {
        let connector = WolframConnector::new();
        let result = connector
            .handle_invoke(json!({
                "operation": "wolfram.query",
                "input": {"input": "test"}
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_empty_query_rejected() {
        let (connector, signing_key) =
            setup_connector("api.wolframalpha.com", &["wolfram.query"]).await;
        let token = generate_token(&signing_key, "wolfram.query", &["wolfram.query"]);
        let result = connector
            .handle_invoke(json!({
                "operation": "wolfram.query",
                "input": {"input": ""},
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_unknown_operation() {
        let (connector, signing_key) =
            setup_connector("api.wolframalpha.com", &["wolfram.query"]).await;
        let token = generate_token(&signing_key, "wolfram.query", &["wolfram.nonexistent"]);
        let result = connector
            .handle_invoke(json!({
                "operation": "wolfram.nonexistent",
                "input": {"input": "test"},
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_returns_three_operations() {
        let connector = WolframConnector::new();
        let introspection = connector.handle_introspect();
        assert_eq!(introspection.operations.len(), 3);
        let op_ids: Vec<&str> = introspection.operations.iter().map(|o| o.id.as_ref()).collect();
        assert!(op_ids.contains(&"wolfram.query"));
        assert!(op_ids.contains(&"wolfram.short_answer"));
        assert!(op_ids.contains(&"wolfram.spoken_result"));
    }

    #[test]
    fn all_operations_are_safe() {
        let ops = wolfram_operations();
        for op in &ops {
            assert_eq!(op.safety_tier, SafetyTier::Safe, "op {} should be safe", op.id);
            assert_eq!(op.risk_level, RiskLevel::Low, "op {} should be low risk", op.id);
        }
    }

    #[test]
    fn all_operations_are_idempotent() {
        let ops = wolfram_operations();
        for op in &ops {
            assert_eq!(op.idempotency, IdempotencyClass::Strict, "op {} should be strict", op.id);
        }
    }

    #[test]
    fn all_operations_have_schemas() {
        let ops = wolfram_operations();
        for op in &ops {
            assert!(op.input_schema.is_object(), "op {} missing input schema", op.id);
            assert!(op.output_schema.is_object(), "op {} missing output schema", op.id);
        }
    }
}
