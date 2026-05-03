//! FCP Google Chat Connector implementation.

use std::sync::Arc;

use fcp_google_discovery::auth::{GoogleAuthSelection, GoogleMaterializedAuth};
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId,
    EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse, IdempotencyClass,
    Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
};
use reqwest::Url;
use serde_json::json;
use tracing::info;

use crate::client::ChatClient;

/// FCP Google Chat Connector.
pub struct ChatConnector {
    base: Arc<BaseConnector>,
    client: Option<ChatClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<fcp_core::SessionId>,
}

impl ChatConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("google-chat"))),
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

        let base_url = match params.get("base_url") {
            Some(value) => {
                validate_chat_base_url(value.as_str().ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "base_url must be a string".into(),
                })?)?
            }
            None => "https://chat.googleapis.com/v1".to_string(),
        };

        let client = ChatClient::new_with_auth(materialized)
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to create Chat client: {e}"),
            })?
            .with_base_url(base_url.clone());

        let auth_label = client.auth_redacted_label();
        self.client = Some(client);
        self.base
            .configured
            .store(true, std::sync::atomic::Ordering::Relaxed);
        info!(auth = %auth_label, status, "Google Chat connector configured");

        Ok(json!({
            "status": status,
            "details": {
                "base_url": base_url
            }
        }))
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
            manifest_hash: "sha256:google-chat-connector-v1".into(),
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
                    "chat.list_spaces",
                    "List all spaces the user has access to",
                    json!({
                        "type": "object",
                        "properties": {}
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "spaces": { "type": "array" }
                        }
                    }),
                    "chat.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all Google Chat spaces (rooms, DMs, group chats) the authenticated user belongs to.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("chat.get_space")],
                    },
                ),
                op_info(
                    "chat.get_space",
                    "Get details of a specific space",
                    json!({
                        "type": "object",
                        "required": ["space_name"],
                        "properties": {
                            "space_name": { "type": "string", "description": "Resource name (e.g. spaces/AAAA)" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "space": { "type": "object" }
                        }
                    }),
                    "chat.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get metadata for a specific Google Chat space by its resource name.".into(),
                        common_mistakes: vec![
                            "space_name must be a resource name like 'spaces/AAAA', not a display name".into(),
                        ],
                        examples: vec![r#"{"space_name": "spaces/AAAA"}"#.into()],
                        related: vec![CapabilityId::from_static("chat.list_spaces")],
                    },
                ),
                op_info(
                    "chat.send_message",
                    "Send a text message to a space",
                    json!({
                        "type": "object",
                        "required": ["space_name", "text"],
                        "properties": {
                            "space_name": { "type": "string", "description": "Resource name of the space" },
                            "text": { "type": "string", "description": "Plain-text message body" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "message": { "type": "object" }
                        }
                    }),
                    "chat.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Send a new text message to a Google Chat space.".into(),
                        common_mistakes: vec![
                            "Each call sends a new message — do not call repeatedly for the same content".into(),
                        ],
                        examples: vec![r#"{"space_name": "spaces/AAAA", "text": "Hello from FCP!"}"#.into()],
                        related: vec![CapabilityId::from_static("chat.list_messages")],
                    },
                ),
                op_info(
                    "chat.list_messages",
                    "List messages in a space",
                    json!({
                        "type": "object",
                        "required": ["space_name"],
                        "properties": {
                            "space_name": { "type": "string", "description": "Resource name of the space" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "messages": { "type": "array" }
                        }
                    }),
                    "chat.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List recent messages in a Google Chat space.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"space_name": "spaces/AAAA"}"#.into()],
                        related: vec![CapabilityId::from_static("chat.get_message")],
                    },
                ),
                op_info(
                    "chat.get_message",
                    "Get a specific message by name",
                    json!({
                        "type": "object",
                        "required": ["message_name"],
                        "properties": {
                            "message_name": { "type": "string", "description": "Resource name (e.g. spaces/AAAA/messages/msg1)" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "message": { "type": "object" }
                        }
                    }),
                    "chat.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get a specific Google Chat message by its resource name.".into(),
                        common_mistakes: vec![
                            "message_name must include the full path: spaces/SPACE/messages/MSG".into(),
                        ],
                        examples: vec![r#"{"message_name": "spaces/AAAA/messages/msg1"}"#.into()],
                        related: vec![CapabilityId::from_static("chat.list_messages")],
                    },
                ),
                op_info(
                    "chat.list_members",
                    "List members of a space",
                    json!({
                        "type": "object",
                        "required": ["space_name"],
                        "properties": {
                            "space_name": { "type": "string", "description": "Resource name of the space" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "members": { "type": "array" }
                        }
                    }),
                    "chat.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all members of a Google Chat space.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"space_name": "spaces/AAAA"}"#.into()],
                        related: vec![CapabilityId::from_static("chat.list_spaces")],
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
            "chat.list_spaces" => {
                let spaces = client.list_spaces().await.map_err(|e| e.to_fcp_error())?;
                Ok(json!({ "spaces": spaces }))
            }
            "chat.get_space" => {
                let space_name = require_str(&input, "space_name")?;
                let space = client
                    .get_space(space_name)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({ "space": space }))
            }
            "chat.send_message" => {
                let space_name = require_str(&input, "space_name")?;
                let text = require_str(&input, "text")?;
                let message = client
                    .create_message(space_name, text)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({ "message": message }))
            }
            "chat.list_messages" => {
                let space_name = require_str(&input, "space_name")?;
                let messages = client
                    .list_messages(space_name)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({ "messages": messages }))
            }
            "chat.get_message" => {
                let message_name = require_str(&input, "message_name")?;
                let message = client
                    .get_message(message_name)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({ "message": message }))
            }
            "chat.list_members" => {
                let space_name = require_str(&input, "space_name")?;
                let members = client
                    .list_members(space_name)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({ "members": members }))
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
        info!("Google Chat connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for ChatConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
}

fn host_is_chat_googleapis(host: &str) -> bool {
    host.eq_ignore_ascii_case("chat.googleapis.com")
}

fn validate_chat_base_url(raw: &str) -> FcpResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not be empty".into(),
        });
    }

    let parsed = Url::parse(trimmed).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("base_url could not be parsed: {error}"),
    })?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use http or https".into(),
        });
    }
    let host = parsed.host_str().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "base_url must include a host".into(),
    })?;
    let local = is_local_test_host(host);
    if parsed.scheme() == "http" && !local {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use https unless targeting localhost/127.0.0.1/::1 for tests"
                .into(),
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include userinfo".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include a query string or fragment".into(),
        });
    }
    if !local && !host_is_chat_googleapis(host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url must target chat.googleapis.com (localhost/127.0.0.1/::1 allowed for tests): {host}"
            ),
        });
    }

    Ok(trimmed.trim_end_matches('/').to_string())
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
    use wiremock::matchers::{header, method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn run_async_test<F>(future: F) -> F::Output
    where
        F: Future,
    {
        fcp_async_core::runtime::block_on_sync(future).expect("test runtime")
    }

    #[test]
    fn health_unconfigured() {
        let connector = ChatConnector::new();
        let result = run_async_test(connector.handle_health()).unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[test]
    fn health_configured() {
        run_async_test(async {
            let mut connector = ChatConnector::new();
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
            let mut connector = ChatConnector::new();
            connector.handle_configure(json!({})).await
        });
        assert!(result.is_err());
    }

    #[test]
    fn configure_with_access_token() {
        run_async_test(async {
            let mut connector = ChatConnector::new();
            let result = connector
                .handle_configure(json!({ "access_token": "test-token" }))
                .await
                .unwrap();
            assert_eq!(result["status"], "configured");
            assert_eq!(
                result["details"]["base_url"],
                "https://chat.googleapis.com/v1"
            );
        });
    }

    #[test]
    fn configure_accepts_local_base_url_override() {
        run_async_test(async {
            let mut connector = ChatConnector::new();
            let result = connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "base_url": "http://127.0.0.1:8080/v1/"
                }))
                .await
                .unwrap();
            assert_eq!(result["details"]["base_url"], "http://127.0.0.1:8080/v1");
        });
    }

    #[test]
    fn configure_rejects_unsafe_base_url_override() {
        run_async_test(async {
            let mut connector = ChatConnector::new();
            let error = connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "base_url": "https://evil.example/v1"
                }))
                .await
                .unwrap_err();
            assert!(
                matches!(&error, FcpError::InvalidRequest { message, .. } if message.contains("chat.googleapis.com")),
                "expected chat.googleapis.com validation error, got {error:?}"
            );
        });
    }

    #[test]
    fn configure_with_credential_id() {
        run_async_test(async {
            let mut connector = ChatConnector::new();
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
        let connector = ChatConnector::new();
        let result = run_async_test(connector.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        assert!(ops.len() >= 6);

        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
        assert!(op_ids.contains(&"chat.list_spaces"));
        assert!(op_ids.contains(&"chat.get_space"));
        assert!(op_ids.contains(&"chat.send_message"));
        assert!(op_ids.contains(&"chat.list_messages"));
        assert!(op_ids.contains(&"chat.get_message"));
        assert!(op_ids.contains(&"chat.list_members"));
    }

    #[test]
    fn shutdown_succeeds() {
        run_async_test(async {
            let mut connector = ChatConnector::new();
            let result = connector.handle_shutdown(json!({})).await.unwrap();
            assert_eq!(result["status"], "shutdown");
        });
    }

    #[test]
    fn invoke_without_configure_returns_not_configured() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_invoke(json!({
                    "operation": "chat.list_spaces",
                    "input": {}
                }))
                .await
        });
        assert!(matches!(result, Err(FcpError::NotConfigured)));
    }

    #[test]
    fn invoke_unknown_operation() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "chat.nonexistent",
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
        let connector = ChatConnector::default();
        assert!(connector.client.is_none());
    }

    #[test]
    fn simulate_returns_dry_run() {
        let connector = ChatConnector::new();
        let result =
            run_async_test(connector.handle_simulate(json!({ "operation": "chat.send_message" })))
                .unwrap();
        assert_eq!(result["dry_run"], true);
        assert_eq!(result["operation"], "chat.send_message");
    }

    #[test]
    fn invoke_missing_operation_field() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
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
    fn invoke_get_space_missing_space_name() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "chat.get_space",
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
    fn invoke_send_message_missing_text() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "chat.send_message",
                    "input": { "space_name": "spaces/AAAA" }
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn invoke_list_messages_missing_space_name() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "chat.list_messages",
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
    fn invoke_get_message_missing_name() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "chat.get_message",
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
    fn invoke_list_members_missing_space_name() {
        let result = run_async_test(async {
            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test" }))
                .await
                .unwrap();
            connector
                .handle_invoke(json!({
                    "operation": "chat.list_members",
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
    fn list_spaces_via_mock() {
        run_async_test(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path_regex(r"/v1/spaces$"))
                .and(header("Authorization", "Bearer test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "spaces": [
                        { "name": "spaces/AAAA", "displayName": "General", "spaceType": "ROOM", "threaded": false }
                    ]
                })))
                .mount(&server)
                .await;

            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "base_url": format!("{}/v1", server.uri())
                }))
                .await
                .unwrap();
            let result = connector
                .handle_invoke(json!({
                    "operation": "chat.list_spaces",
                    "input": {}
                }))
                .await
                .unwrap();
            assert_eq!(result["spaces"][0]["name"], "spaces/AAAA");
            assert_eq!(result["spaces"][0]["displayName"], "General");
        });
    }

    #[test]
    fn send_message_via_mock() {
        run_async_test(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path_regex(r"/v1/spaces/.+/messages"))
                .and(header("Authorization", "Bearer test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "name": "spaces/AAAA/messages/msg1",
                    "text": "Hello!",
                    "createTime": "2026-03-14T00:00:00Z"
                })))
                .mount(&server)
                .await;

            let mut connector = ChatConnector::new();
            connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "base_url": format!("{}/v1", server.uri())
                }))
                .await
                .unwrap();
            let result = connector
                .handle_invoke(json!({
                    "operation": "chat.send_message",
                    "input": {
                        "space_name": "spaces/AAAA",
                        "text": "Hello!"
                    }
                }))
                .await
                .unwrap();
            assert_eq!(result["message"]["name"], "spaces/AAAA/messages/msg1");
            assert_eq!(result["message"]["text"], "Hello!");
        });
    }
}
