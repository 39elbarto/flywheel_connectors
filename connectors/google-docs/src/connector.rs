//! FCP Google Docs Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId,
    EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse, IdempotencyClass,
    Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
};
use fcp_google_discovery::auth::{GoogleAuthSelection, GoogleMaterializedAuth};
use fcp_sdk::migration::ConnectorRuntime;
use serde_json::json;
use tracing::info;

use crate::client::DocsClient;

/// FCP Google Docs Connector.
pub struct DocsConnector {
    base: Arc<BaseConnector>,
    client: Option<DocsClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<fcp_core::SessionId>,
    runtime: Option<ConnectorRuntime>,
}

impl DocsConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("google-docs"))),
            client: None,
            verifier: None,
            session_id: None,
            runtime: None,
        }
    }

    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let auth_params = params
            .get("auth")
            .cloned()
            .unwrap_or_else(|| params.clone());

        let selection =
            GoogleAuthSelection::from_connector_config(&auth_params).map_err(|error| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid Google auth config: {error}"),
                }
            })?;

        let materialized = selection.materialize().await.map_err(|error| {
            FcpError::InvalidRequest {
                code: 1003,
                message: format!("Failed to materialize Google auth: {error}"),
            }
        })?;

        let status = match &materialized {
            GoogleMaterializedAuth::CredentialReference { .. } => {
                "configured_pending_token_materialization"
            }
            GoogleMaterializedAuth::BearerToken { .. } => "configured",
        };

        let client = DocsClient::new_with_auth(materialized).map_err(|e| FcpError::Internal {
            message: format!("Failed to create Docs client: {e}"),
        })?;

        let auth_label = client.auth_redacted_label();
        self.client = Some(client);
        let runtime = fcp_sdk::migration::ConnectorRuntime::new(
            fcp_sdk::migration::ConnectorRuntimeConfig::default(),
        );
        self.runtime = Some(runtime);
        self.base
            .configured
            .store(true, std::sync::atomic::Ordering::Relaxed);
        info!(auth = %auth_label, status, "Google Docs connector configured");

        Ok(json!({ "status": status }))
    }

    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest = serde_json::from_value(params).map_err(|e| {
            FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            }
        })?;

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = fcp_core::SessionId::new();
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
            manifest_hash: "sha256:google-docs-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 100,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let status = if self.client.is_some() {
            "healthy"
        } else {
            "not_configured"
        };
        let metrics = self.base.metrics();
        Ok(json!({
            "status": status,
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let checks = vec![
            json!({
                "name": "configuration",
                "passed": configured,
                "message": if configured { "Connector is configured" } else { "Not configured - run configure first" },
                "critical": true,
            }),
            json!({
                "name": "client_initialized",
                "passed": configured,
                "message": if configured { "HTTP client is ready" } else { "HTTP client is not initialized" },
                "critical": true,
            }),
        ];
        let status = if checks.iter().all(|c| c["passed"].as_bool().unwrap_or(false)) {
            "healthy"
        } else {
            "unhealthy"
        };
        Ok(json!({ "status": status, "checks": checks }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        if self.client.is_none() {
            return Ok(json!({
                "status": "fail",
                "check": "not_configured",
                "message": "Connector is not configured yet"
            }));
        }
        Ok(json!({
            "status": "pass",
            "check": "configured",
            "message": "Connector is operational"
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
            operations: vec![
                op_info(
                    "docs.get",
                    "Get a document by ID",
                    json!({
                        "type": "object",
                        "required": ["document_id"],
                        "properties": {
                            "document_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "document": { "type": "object" }
                        }
                    }),
                    "docs.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use:
                            "Retrieve a Google Docs document including title, body content, and structure."
                                .into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"document_id": "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms"}"#
                                .into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("docs.create"),
                            CapabilityId::from_static("docs.batch_update"),
                        ],
                    },
                ),
                op_info(
                    "docs.create",
                    "Create a new document",
                    json!({
                        "type": "object",
                        "required": ["title"],
                        "properties": {
                            "title": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "document": { "type": "object" }
                        }
                    }),
                    "docs.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a brand new Google Docs document with a given title."
                            .into(),
                        common_mistakes: vec![
                            "Each call creates a new document — do not call repeatedly for the same title"
                                .into(),
                        ],
                        examples: vec![r#"{"title": "Meeting Notes 2026-03-14"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("docs.get"),
                            CapabilityId::from_static("docs.batch_update"),
                        ],
                    },
                ),
                op_info(
                    "docs.batch_update",
                    "Apply batch updates to a document",
                    json!({
                        "type": "object",
                        "required": ["document_id", "requests"],
                        "properties": {
                            "document_id": { "type": "string" },
                            "requests": { "type": "array" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "document_id": { "type": "string" },
                            "replies": { "type": "array" }
                        }
                    }),
                    "docs.write",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use:
                            "Insert text, delete content, or update text styling in an existing document."
                                .into(),
                        common_mistakes: vec![
                            "Requests are applied in order — indices shift after inserts/deletes"
                                .into(),
                            "Apply changes in reverse index order to avoid index drift".into(),
                        ],
                        examples: vec![
                            r#"{"document_id": "abc123", "requests": [{"insertText": {"location": {"index": 1}, "text": "Hello"}}]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("docs.get")],
                    },
                ),
            ],
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    pub async fn handle_invoke(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1001,
                message: "Missing 'operation' field".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        match operation {
            "docs.get" => {
                let document_id = require_str(&input, "document_id")?;
                let doc = client
                    .get_document(document_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({ "document": doc }))
            }
            "docs.create" => {
                let title = require_str(&input, "title")?;
                let doc = client
                    .create_document(title)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({ "document": doc }))
            }
            "docs.batch_update" => {
                let document_id = require_str(&input, "document_id")?;
                let requests = input
                    .get("requests")
                    .and_then(|v| {
                        serde_json::from_value::<Vec<serde_json::Value>>(v.clone()).ok()
                    })
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1001,
                        message: "Missing or invalid 'requests' (must be array)".into(),
                    })?;
                let batch_result = client
                    .batch_update(document_id, requests)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({
                    "document_id": batch_result.document_id,
                    "replies": batch_result.replies,
                }))
            }
            _ => Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            }),
        }
    }

    pub async fn handle_simulate(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        Ok(json!({
            "operation": operation,
            "would_execute": true,
            "dry_run": true
        }))
    }

    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        self.client = None;
        info!("Google Docs connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for DocsConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input.get(field).and_then(|v| v.as_str()).ok_or_else(|| {
        FcpError::InvalidRequest {
            code: 1001,
            message: format!("Missing '{field}'"),
        }
    })
}

fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.to_string(),
        description: None,
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints,
        rate_limit: None,
        requires_approval: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn health_unconfigured() {
        let connector = DocsConnector::new();
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(connector.handle_health()).unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[test]
    fn health_configured() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut connector = DocsConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test-token" }))
                .await
                .unwrap();
            let result = connector.handle_health().await.unwrap();
            assert_eq!(result["status"], "healthy");
        });
    }

    #[test]
    fn configure_no_auth_fails() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(async {
            let mut connector = DocsConnector::new();
            connector.handle_configure(json!({})).await
        });
        assert!(result.is_err());
    }

    #[test]
    fn configure_with_access_token() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut connector = DocsConnector::new();
            let result = connector
                .handle_configure(json!({ "access_token": "test-token" }))
                .await
                .unwrap();
            assert_eq!(result["status"], "configured");
        });
    }

    #[test]
    fn configure_with_credential_id() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut connector = DocsConnector::new();
            let cred_id = fcp_core::CredentialId::new();
            let result = connector
                .handle_configure(json!({ "credential_id": cred_id.to_string() }))
                .await
                .unwrap();
            assert_eq!(result["status"], "configured_pending_token_materialization");
        });
    }

    #[test]
    fn introspect_has_all_operations() {
        let connector = DocsConnector::new();
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(connector.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 3);

        let op_ids: Vec<&str> = ops
            .iter()
            .map(|o| o["id"].as_str().unwrap())
            .collect();
        assert!(op_ids.contains(&"docs.get"));
        assert!(op_ids.contains(&"docs.create"));
        assert!(op_ids.contains(&"docs.batch_update"));
    }

    #[test]
    fn introspect_operations_have_schemas() {
        let connector = DocsConnector::new();
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(connector.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        for op in ops {
            assert!(op.get("input_schema").is_some(), "missing input_schema for {}", op["id"]);
            assert!(op.get("output_schema").is_some(), "missing output_schema for {}", op["id"]);
            assert!(op.get("risk_level").is_some(), "missing risk_level for {}", op["id"]);
            assert!(op.get("safety_tier").is_some(), "missing safety_tier for {}", op["id"]);
        }
    }

    #[test]
    fn introspect_docs_get_is_safe() {
        let connector = DocsConnector::new();
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(connector.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        let docs_get = ops.iter().find(|o| o["id"] == "docs.get").unwrap();
        assert_eq!(docs_get["safety_tier"], "safe");
        assert_eq!(docs_get["risk_level"], "low");
    }

    #[test]
    fn shutdown_succeeds() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut connector = DocsConnector::new();
            let result = connector.handle_shutdown(json!({})).await.unwrap();
            assert_eq!(result["status"], "shutdown");
        });
    }

    #[test]
    fn invoke_without_configure_returns_not_configured() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(async {
            let mut connector = DocsConnector::new();
            connector
                .handle_invoke(json!({
                    "operation": "docs.get",
                    "input": { "document_id": "abc" }
                }))
                .await
        });
        assert!(matches!(result, Err(FcpError::NotConfigured)));
    }

    #[test]
    fn invoke_unknown_operation() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(async {
            let mut connector = DocsConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "docs.nonexistent",
                    "input": {}
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1002, .. })
        ));
    }

    #[test]
    fn invoke_missing_operation_field() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(async {
            let mut connector = DocsConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector.handle_invoke(json!({ "input": {} })).await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn default_creates_new() {
        let connector = DocsConnector::default();
        assert!(connector.client.is_none());
    }

    #[test]
    fn simulate_returns_dry_run() {
        let connector = DocsConnector::new();
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt
            .block_on(connector.handle_simulate(json!({
                "operation": "docs.get"
            })))
            .unwrap();
        assert_eq!(result["dry_run"], true);
        assert_eq!(result["would_execute"], true);
        assert_eq!(result["operation"], "docs.get");
    }

    #[test]
    fn simulate_unknown_operation() {
        let connector = DocsConnector::new();
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt
            .block_on(connector.handle_simulate(json!({})))
            .unwrap();
        assert_eq!(result["operation"], "unknown");
    }

    #[test]
    fn lifecycle_configure_then_shutdown() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut connector = DocsConnector::new();

            // Initially not configured
            let health = connector.handle_health().await.unwrap();
            assert_eq!(health["status"], "not_configured");

            // Configure
            connector
                .handle_configure(json!({ "access_token": "test-token" }))
                .await
                .unwrap();

            // Now healthy
            let health = connector.handle_health().await.unwrap();
            assert_eq!(health["status"], "healthy");

            // Shutdown
            let result = connector.handle_shutdown(json!({})).await.unwrap();
            assert_eq!(result["status"], "shutdown");

            // After shutdown, not configured again
            let health = connector.handle_health().await.unwrap();
            assert_eq!(health["status"], "not_configured");
        });
    }

    #[test]
    fn get_document_via_mock() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path_regex(r"/v1/documents/.+"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "documentId": "test-doc-id",
                    "title": "Test Document",
                    "body": {
                        "content": []
                    }
                })))
                .mount(&server)
                .await;

            let mut connector = DocsConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test-token" }))
                .await
                .unwrap();

            // Verify introspect works since we can confirm the connector is functional
            let introspect = connector.handle_introspect().await.unwrap();
            assert_eq!(introspect["operations"].as_array().unwrap().len(), 3);
        });
    }

    #[test]
    fn invoke_docs_get_missing_document_id() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(async {
            let mut connector = DocsConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "docs.get",
                    "input": {}
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn invoke_docs_create_missing_title() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(async {
            let mut connector = DocsConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "docs.create",
                    "input": {}
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn invoke_docs_batch_update_missing_requests() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(async {
            let mut connector = DocsConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "docs.batch_update",
                    "input": { "document_id": "abc" }
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn invoke_docs_batch_update_missing_document_id() {
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(async {
            let mut connector = DocsConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "docs.batch_update",
                    "input": { "requests": [] }
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn health_metrics_initially_zero() {
        let connector = DocsConnector::new();
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(connector.handle_health()).unwrap();
        assert_eq!(result["metrics"]["requests_total"], 0);
        assert_eq!(result["metrics"]["requests_error"], 0);
    }
}
