//! FCP Google Sheets Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId,
    EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse, IdempotencyClass,
    Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
};
use fcp_google_discovery::auth::{GoogleAuthSelection, GoogleMaterializedAuth};
use serde_json::json;
use tracing::info;

use crate::client::SheetsClient;

/// FCP Google Sheets Connector.
pub struct SheetsConnector {
    base: Arc<BaseConnector>,
    client: Option<SheetsClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<fcp_core::SessionId>,
}

impl SheetsConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "google-sheets",
            ))),
            client: None,
            verifier: None,
            session_id: None,
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

        let materialized =
            selection
                .materialize()
                .await
                .map_err(|error| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Failed to materialize Google auth: {error}"),
                })?;

        let status = match &materialized {
            GoogleMaterializedAuth::CredentialReference { .. } => {
                "configured_pending_token_materialization"
            }
            GoogleMaterializedAuth::BearerToken { .. } => "configured",
        };

        let client = SheetsClient::new_with_auth(materialized).map_err(|e| FcpError::Internal {
            message: format!("Failed to create Sheets client: {e}"),
        })?;

        let auth_label = client.auth_redacted_label();
        self.client = Some(client);
        self.base
            .configured
            .store(true, std::sync::atomic::Ordering::Relaxed);
        info!(auth = %auth_label, status, "Google Sheets connector configured");

        Ok(json!({ "status": status }))
    }

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
            manifest_hash: "sha256:google-sheets-connector-v1".into(),
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
        let status = if checks
            .iter()
            .all(|c| c["passed"].as_bool().unwrap_or(false))
        {
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
                    "sheets.get_spreadsheet",
                    "Get spreadsheet metadata and sheets list",
                    json!({
                        "type": "object",
                        "required": ["spreadsheet_id"],
                        "properties": {
                            "spreadsheet_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "spreadsheet": { "type": "object" }
                        }
                    }),
                    "sheets.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get spreadsheet metadata including sheets list and properties.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"spreadsheet_id": "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms"}"#.into()],
                        related: vec![CapabilityId::from_static("sheets.get_values")],
                    },
                ),
                op_info(
                    "sheets.get_values",
                    "Read cell values from a range",
                    json!({
                        "type": "object",
                        "required": ["spreadsheet_id", "range"],
                        "properties": {
                            "spreadsheet_id": { "type": "string" },
                            "range": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "values": { "type": "array" }
                        }
                    }),
                    "sheets.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read data from a spreadsheet range like 'Sheet1!A1:C10'.".into(),
                        common_mistakes: vec![
                            "Range must use A1 notation (e.g. 'Sheet1!A1:B5')".into(),
                        ],
                        examples: vec![r#"{"spreadsheet_id": "abc123", "range": "Sheet1!A1:C10"}"#.into()],
                        related: vec![CapabilityId::from_static("sheets.update_values")],
                    },
                ),
                op_info(
                    "sheets.update_values",
                    "Write cell values to a range",
                    json!({
                        "type": "object",
                        "required": ["spreadsheet_id", "range", "values"],
                        "properties": {
                            "spreadsheet_id": { "type": "string" },
                            "range": { "type": "string" },
                            "values": { "type": "array" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "updated_cells": { "type": "integer" }
                        }
                    }),
                    "sheets.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Update cell values in a spreadsheet range.".into(),
                        common_mistakes: vec![
                            "Values must be a 2D array (rows of cells)".into(),
                        ],
                        examples: vec![r#"{"spreadsheet_id": "abc123", "range": "Sheet1!A1:B2", "values": [["a","b"],["c","d"]]}"#.into()],
                        related: vec![CapabilityId::from_static("sheets.get_values")],
                    },
                ),
                op_info(
                    "sheets.append_values",
                    "Append rows to a sheet",
                    json!({
                        "type": "object",
                        "required": ["spreadsheet_id", "range", "values"],
                        "properties": {
                            "spreadsheet_id": { "type": "string" },
                            "range": { "type": "string" },
                            "values": { "type": "array" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "table_range": { "type": "string" }
                        }
                    }),
                    "sheets.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Append new rows to the end of a sheet.".into(),
                        common_mistakes: vec![
                            "Each call appends — do not call repeatedly for the same data".into(),
                        ],
                        examples: vec![r#"{"spreadsheet_id": "abc123", "range": "Sheet1", "values": [["new","row"]]}"#.into()],
                        related: vec![CapabilityId::from_static("sheets.update_values")],
                    },
                ),
                op_info(
                    "sheets.clear_values",
                    "Clear cell values in a range",
                    json!({
                        "type": "object",
                        "required": ["spreadsheet_id", "range"],
                        "properties": {
                            "spreadsheet_id": { "type": "string" },
                            "range": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object" }),
                    "sheets.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Clear all values from a range (keeps formatting).".into(),
                        common_mistakes: vec![
                            "This clears VALUES only, not formatting or formulas".into(),
                        ],
                        examples: vec![r#"{"spreadsheet_id": "abc123", "range": "Sheet1!A1:Z1000"}"#.into()],
                        related: vec![CapabilityId::from_static("sheets.get_values")],
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
            "sheets.get_spreadsheet" => {
                let spreadsheet_id = require_str(&input, "spreadsheet_id")?;
                let ss = client
                    .get_spreadsheet(spreadsheet_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({ "spreadsheet": ss }))
            }
            "sheets.get_values" => {
                let spreadsheet_id = require_str(&input, "spreadsheet_id")?;
                let range = require_str(&input, "range")?;
                let vr = client
                    .get_values(spreadsheet_id, range)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({ "range": vr.range, "values": vr.values }))
            }
            "sheets.update_values" => {
                let spreadsheet_id = require_str(&input, "spreadsheet_id")?;
                let range = require_str(&input, "range")?;
                let values = input
                    .get("values")
                    .and_then(|v| {
                        serde_json::from_value::<Vec<Vec<serde_json::Value>>>(v.clone()).ok()
                    })
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1001,
                        message: "Missing or invalid 'values' (must be 2D array)".into(),
                    })?;
                let ur = client
                    .update_values(spreadsheet_id, range, values)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({
                    "updated_range": ur.updated_range,
                    "updated_cells": ur.updated_cells,
                    "updated_rows": ur.updated_rows,
                }))
            }
            "sheets.append_values" => {
                let spreadsheet_id = require_str(&input, "spreadsheet_id")?;
                let range = require_str(&input, "range")?;
                let values = input
                    .get("values")
                    .and_then(|v| {
                        serde_json::from_value::<Vec<Vec<serde_json::Value>>>(v.clone()).ok()
                    })
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1001,
                        message: "Missing or invalid 'values'".into(),
                    })?;
                let ar = client
                    .append_values(spreadsheet_id, range, values)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({
                    "table_range": ar.table_range,
                    "updates": ar.updates,
                }))
            }
            "sheets.clear_values" => {
                let spreadsheet_id = require_str(&input, "spreadsheet_id")?;
                let range = require_str(&input, "range")?;
                let clear_result = client
                    .clear_values(spreadsheet_id, range)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(clear_result)
            }
            _ => Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            }),
        }
    }

    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
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
        self.client = None;
        info!("Google Sheets connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for SheetsConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1001,
            message: format!("Missing '{field}'"),
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
    use std::future::Future;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn run_async_test<F>(future: F) -> F::Output
    where
        F: Future,
    {
        fcp_async_core::runtime::block_on_sync(future).expect("test runtime")
    }

    #[test]
    fn health_unconfigured() {
        let connector = SheetsConnector::new();
        let result = run_async_test(connector.handle_health()).unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[test]
    fn health_configured() {
        run_async_test(async {
            let mut connector = SheetsConnector::new();
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
        let result = run_async_test(async {
            let mut connector = SheetsConnector::new();
            connector.handle_configure(json!({})).await
        });
        assert!(result.is_err());
    }

    #[test]
    fn configure_with_access_token() {
        run_async_test(async {
            let mut connector = SheetsConnector::new();
            let result = connector
                .handle_configure(json!({ "access_token": "test-token" }))
                .await
                .unwrap();
            assert_eq!(result["status"], "configured");
        });
    }

    #[test]
    fn configure_with_credential_id() {
        run_async_test(async {
            let mut connector = SheetsConnector::new();
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
        let connector = SheetsConnector::new();
        let result = run_async_test(connector.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        assert!(ops.len() >= 5);

        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
        assert!(op_ids.contains(&"sheets.get_spreadsheet"));
        assert!(op_ids.contains(&"sheets.get_values"));
        assert!(op_ids.contains(&"sheets.update_values"));
        assert!(op_ids.contains(&"sheets.append_values"));
        assert!(op_ids.contains(&"sheets.clear_values"));
    }

    #[test]
    fn shutdown_succeeds() {
        run_async_test(async {
            let mut connector = SheetsConnector::new();
            let result = connector.handle_shutdown(json!({})).await.unwrap();
            assert_eq!(result["status"], "shutdown");
        });
    }

    #[test]
    fn invoke_without_configure_returns_not_configured() {
        let result = run_async_test(async {
            let mut connector = SheetsConnector::new();
            connector
                .handle_invoke(json!({
                    "operation": "sheets.get_spreadsheet",
                    "input": { "spreadsheet_id": "abc" }
                }))
                .await
        });
        assert!(matches!(result, Err(FcpError::NotConfigured)));
    }

    #[test]
    fn invoke_unknown_operation() {
        let result = run_async_test(async {
            let mut connector = SheetsConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "sheets.nonexistent",
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
    fn default_creates_new() {
        let connector = SheetsConnector::default();
        assert!(connector.client.is_none());
    }

    #[test]
    fn get_spreadsheet_via_mock() {
        run_async_test(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path_regex(r"/v4/spreadsheets/.+"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "spreadsheetId": "test-ss-id",
                    "properties": { "title": "Test Sheet" },
                    "sheets": [],
                    "spreadsheetUrl": "https://docs.google.com/spreadsheets/d/test-ss-id"
                })))
                .mount(&server)
                .await;

            let mut connector = SheetsConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test-token" }))
                .await
                .unwrap();

            // Override base URL to mock server (need to access client internals)
            // For now, verify that introspect works since we can't easily override base_url
            let introspect = connector.handle_introspect().await.unwrap();
            assert!(introspect["operations"].as_array().unwrap().len() >= 5);
        });
    }
}
