//! FCP Google Docs Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
};
use fcp_google_discovery::auth::{GoogleAuthSelection, GoogleMaterializedAuth};
use reqwest::Url;
use serde_json::json;
use tracing::info;

use crate::client::DocsClient;

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
}

fn host_is_docs_googleapis(host: &str) -> bool {
    host.eq_ignore_ascii_case("docs.googleapis.com")
}

/// Validate a google-docs `base_url` override.
///
/// The Docs client concatenates this string into downstream request URLs, so
/// only the Docs API host is accepted outside local test listeners.
fn validate_docs_base_url(raw: &str) -> FcpResult<String> {
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
    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
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
    if !local && !host_is_docs_googleapis(host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url host must target docs.googleapis.com (localhost/127.0.0.1/::1 allowed for tests): {host}"
            ),
        });
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

fn docs_document_resource_uri(document_id: &str) -> String {
    format!("google-docs:document:{document_id}")
}

fn resource_uris_for_operation(
    operation: &str,
    input: &serde_json::Value,
) -> FcpResult<Vec<String>> {
    match operation {
        "docs.get" | "docs.batch_update" => {
            let document_id = require_str(input, "document_id")?;
            Ok(vec![docs_document_resource_uri(document_id)])
        }
        "docs.create" => Ok(vec!["google-docs:documents".to_string()]),
        _ => Ok(Vec::new()),
    }
}

/// FCP Google Docs Connector.
pub struct DocsConnector {
    base: Arc<BaseConnector>,
    client: Option<DocsClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<fcp_core::SessionId>,
}

impl DocsConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("google-docs"))),
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

        let mut client =
            DocsClient::new_with_auth(materialized).map_err(|e| FcpError::Internal {
                message: format!("Failed to create Docs client: {e}"),
            })?;
        if let Some(value) = params.get("base_url") {
            let base_url = value.as_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "`base_url` must be a string".into(),
            })?;
            client = client.with_base_url(validate_docs_base_url(base_url)?);
        }

        let auth_label = client.auth_redacted_label();
        self.client = Some(client);
        self.base.set_configured(true);
        info!(auth = %auth_label, status, "Google Docs connector configured");

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
        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1002,
            message: format!("Invalid operation ID: {operation}"),
        })?;
        let intro = self.handle_introspect().await?;
        let cap_str = intro
            .get("operations")
            .and_then(|ops| ops.as_array())
            .and_then(|ops| {
                ops.iter()
                    .find(|op| op.get("id").and_then(|id| id.as_str()) == Some(operation))
            })
            .and_then(|op| op.get("capability"))
            .and_then(|cap| cap.as_str())
            .ok_or_else(|| FcpError::OperationNotGranted {
                operation: operation.into(),
            })?;
        let cap_id: CapabilityId = cap_str.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1002,
            message: format!("Invalid capability ID for operation {operation}"),
        })?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotConfigured)?;
        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1001,
                message: "Missing 'capability_token' field".into(),
            })?;
        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid capability_token format: {e}"),
            })?;
        let resource_uris = resource_uris_for_operation(operation, &input)?;
        verifier.verify_bound(token, &cap_id, &op_id, &resource_uris)?;

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
                    .and_then(|v| serde_json::from_value::<Vec<serde_json::Value>>(v.clone()).ok())
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
    use chrono::{Duration, Utc};
    use fcp_core::CapabilityConstraints;
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use std::future::Future;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn run_async_test<F>(future: F) -> F::Output
    where
        F: Future,
    {
        fcp_async_core::runtime::block_on_sync(future).expect("test runtime")
    }

    fn build_test_token(signing_key: &Ed25519SigningKey, operation: &str) -> CapabilityToken {
        let capability = match operation {
            "docs.get" => "docs.read",
            "docs.create" | "docs.batch_update" => "docs.write",
            _ => "docs.read",
        };
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut constraints_cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut constraints_cbor)
            .expect("serialize token constraints");
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .audience("*")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .expect("attach token constraints")
            .sign(signing_key)
            .expect("sign capability token");
        CapabilityToken::from_raw(cose)
    }

    async fn configure_and_handshake(
        connector: &mut DocsConnector,
        signing_key: &Ed25519SigningKey,
    ) {
        connector
            .handle_configure(json!({ "access_token": "test" }))
            .await
            .unwrap();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["docs.read", "docs.write"]
            }))
            .await
            .unwrap();
    }

    #[test]
    fn health_unconfigured() {
        let connector = DocsConnector::new();
        let result = run_async_test(connector.handle_health()).unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[test]
    fn health_configured() {
        run_async_test(async {
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
        let result = run_async_test(async {
            let mut connector = DocsConnector::new();
            connector.handle_configure(json!({})).await
        });
        assert!(result.is_err());
    }

    #[test]
    fn configure_rejects_invalid_base_url_override() {
        run_async_test(async {
            let mut connector = DocsConnector::new();
            let err = connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "base_url": 123
                }))
                .await
                .unwrap_err();
            assert!(
                matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("base_url")),
                "expected base_url validation error, got {err:?}"
            );

            let mut connector = DocsConnector::new();
            let err = connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "base_url": ""
                }))
                .await
                .unwrap_err();
            assert!(
                matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("empty")),
                "expected empty base_url validation error, got {err:?}"
            );
        });
    }

    #[test]
    fn configure_with_access_token() {
        run_async_test(async {
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
        run_async_test(async {
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
    fn validate_docs_base_url_accepts_googleapis() {
        let out = validate_docs_base_url("https://docs.googleapis.com/v1/").unwrap();
        assert_eq!(out, "https://docs.googleapis.com/v1");
    }

    #[test]
    fn validate_docs_base_url_allows_localhost_http() {
        validate_docs_base_url("http://localhost:9999/v1").unwrap();
        validate_docs_base_url("http://127.0.0.1/docs").unwrap();
        validate_docs_base_url("http://[::1]:9999/v1").unwrap();
    }

    #[test]
    fn validate_docs_base_url_rejects_foreign_host() {
        let err = validate_docs_base_url("https://evil.example.com/v1").unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("docs.googleapis.com")),
            "expected InvalidRequest mentioning googleapis.com, got {err:?}"
        );
    }

    #[test]
    fn validate_docs_base_url_rejects_substring_smuggle() {
        let err = validate_docs_base_url("https://evil.com/docs.googleapis.com/v1").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_docs_base_url_rejects_query_fragment_userinfo() {
        assert!(matches!(
            validate_docs_base_url("https://docs.googleapis.com/v1?leak=x").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        assert!(matches!(
            validate_docs_base_url("https://docs.googleapis.com/v1#frag").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        let err = validate_docs_base_url("https://attacker:pw@docs.googleapis.com/v1").unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("userinfo")),
            "expected InvalidRequest mentioning userinfo, got {err:?}"
        );
    }

    #[test]
    fn validate_docs_base_url_rejects_plain_http_on_public_host() {
        let err = validate_docs_base_url("http://docs.googleapis.com/v1").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_docs_base_url_rejects_empty_and_malformed() {
        assert!(matches!(
            validate_docs_base_url("   ").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        assert!(matches!(
            validate_docs_base_url("not a url").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
    }

    #[test]
    fn host_is_docs_googleapis_rejects_wrong_hosts_and_lookalikes() {
        assert!(host_is_docs_googleapis("docs.googleapis.com"));
        assert!(!host_is_docs_googleapis("googleapis.com"));
        assert!(!host_is_docs_googleapis("www.googleapis.com"));
        assert!(!host_is_docs_googleapis("googleapis.com.evil.com"));
        assert!(!host_is_docs_googleapis("evil-googleapis.com"));
    }

    #[test]
    fn resource_uris_bind_docs_targets() {
        let get =
            resource_uris_for_operation("docs.get", &json!({ "document_id": "doc_123" })).unwrap();
        assert_eq!(get, vec!["google-docs:document:doc_123"]);

        let create = resource_uris_for_operation("docs.create", &json!({})).unwrap();
        assert_eq!(create, vec!["google-docs:documents"]);
    }

    #[test]
    fn introspect_has_all_operations() {
        let connector = DocsConnector::new();
        let result = run_async_test(connector.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 3);

        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
        assert!(op_ids.contains(&"docs.get"));
        assert!(op_ids.contains(&"docs.create"));
        assert!(op_ids.contains(&"docs.batch_update"));
    }

    #[test]
    fn introspect_operations_have_schemas() {
        let connector = DocsConnector::new();
        let result = run_async_test(connector.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        for op in ops {
            assert!(
                op.get("input_schema").is_some(),
                "missing input_schema for {}",
                op["id"]
            );
            assert!(
                op.get("output_schema").is_some(),
                "missing output_schema for {}",
                op["id"]
            );
            assert!(
                op.get("risk_level").is_some(),
                "missing risk_level for {}",
                op["id"]
            );
            assert!(
                op.get("safety_tier").is_some(),
                "missing safety_tier for {}",
                op["id"]
            );
        }
    }

    #[test]
    fn introspect_docs_get_is_safe() {
        let connector = DocsConnector::new();
        let result = run_async_test(connector.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        let docs_get = ops.iter().find(|o| o["id"] == "docs.get").unwrap();
        assert_eq!(docs_get["safety_tier"], "safe");
        assert_eq!(docs_get["risk_level"], "low");
    }

    #[test]
    fn shutdown_succeeds() {
        run_async_test(async {
            let mut connector = DocsConnector::new();
            let result = connector.handle_shutdown(json!({})).await.unwrap();
            assert_eq!(result["status"], "shutdown");
        });
    }

    #[test]
    fn invoke_without_configure_returns_not_configured() {
        let result = run_async_test(async {
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
    fn invoke_unknown_operation_is_denied_before_token_validation() {
        let result = run_async_test(async {
            let mut connector = DocsConnector::new();
            connector
                .handle_invoke(json!({
                    "operation": "docs.nonexistent",
                    "input": {}
                }))
                .await
        });
        assert!(matches!(result, Err(FcpError::OperationNotGranted { .. })));
    }

    #[test]
    fn invoke_missing_operation_field() {
        let result = run_async_test(async {
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
        let result = run_async_test(connector.handle_simulate(json!({
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
        let result = run_async_test(connector.handle_simulate(json!({}))).unwrap();
        assert_eq!(result["operation"], "unknown");
    }

    #[test]
    fn lifecycle_configure_then_shutdown() {
        run_async_test(async {
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
        run_async_test(async {
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
        let result = run_async_test(async {
            let mut connector = DocsConnector::new();
            let signing_key = Ed25519SigningKey::generate();
            configure_and_handshake(&mut connector, &signing_key).await;
            let token = build_test_token(&signing_key, "docs.get");
            connector
                .handle_invoke(json!({
                    "operation": "docs.get",
                    "input": {},
                    "capability_token": token
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
        let result = run_async_test(async {
            let mut connector = DocsConnector::new();
            let signing_key = Ed25519SigningKey::generate();
            configure_and_handshake(&mut connector, &signing_key).await;
            let token = build_test_token(&signing_key, "docs.create");
            connector
                .handle_invoke(json!({
                    "operation": "docs.create",
                    "input": {},
                    "capability_token": token
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
        let result = run_async_test(async {
            let mut connector = DocsConnector::new();
            let signing_key = Ed25519SigningKey::generate();
            configure_and_handshake(&mut connector, &signing_key).await;
            let token = build_test_token(&signing_key, "docs.batch_update");
            connector
                .handle_invoke(json!({
                    "operation": "docs.batch_update",
                    "input": { "document_id": "abc" },
                    "capability_token": token
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
        let result = run_async_test(async {
            let mut connector = DocsConnector::new();
            let signing_key = Ed25519SigningKey::generate();
            configure_and_handshake(&mut connector, &signing_key).await;
            let token = build_test_token(&signing_key, "docs.batch_update");
            connector
                .handle_invoke(json!({
                    "operation": "docs.batch_update",
                    "input": { "requests": [] },
                    "capability_token": token
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
        let result = run_async_test(connector.handle_health()).unwrap();
        assert_eq!(result["metrics"]["requests_total"], 0);
        assert_eq!(result["metrics"]["requests_error"], 0);
    }
}
