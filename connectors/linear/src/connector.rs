//! FCP Linear Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::LinearClient, error::LinearError};

/// FCP Linear Connector.
pub struct LinearConnector {
    base: Arc<BaseConnector>,
    client: Option<LinearClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl LinearConnector {
    /// Create a new Linear connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("linear"))),
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let api_key =
            params
                .get("api_key")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key in configuration".into(),
                })?;

        let api_url = params.get("api_url").and_then(|v| v.as_str());

        let mut client = LinearClient::new(api_key).map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;

        if let Some(url) = api_url {
            client = client.with_api_url(url);
        }

        self.client = Some(client);
        self.base.set_configured(true);
        info!("Linear connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
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
            manifest_hash: "sha256:linear-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
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

    /// Handle health check.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle introspect method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                op_info(
                    "linear.create_issue",
                    "Create an issue in Linear",
                    json!({
                        "type": "object",
                        "required": ["title", "team_id"],
                        "properties": {
                            "title": { "type": "string" },
                            "team_id": { "type": "string" },
                            "description": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "issue": { "type": "object" } } }),
                    "linear.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new issue in Linear.".into(),
                        common_mistakes: vec!["Not specifying the team ID".into()],
                        examples: vec![
                            r#"{"title": "Fix login bug", "team_id": "TEAM-123"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("linear.get_issue"),
                            CapabilityId::from_static("linear.search_issues"),
                        ],
                    },
                ),
                op_info(
                    "linear.get_issue",
                    "Get a Linear issue by ID",
                    json!({
                        "type": "object",
                        "required": ["issue_id"],
                        "properties": {
                            "issue_id": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "issue": { "type": "object" } } }),
                    "linear.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Look up a specific issue by ID.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"issue_id": "LIN-123"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("linear.create_issue"),
                            CapabilityId::from_static("linear.update_issue"),
                        ],
                    },
                ),
                op_info(
                    "linear.update_issue",
                    "Update an issue's properties",
                    json!({
                        "type": "object",
                        "required": ["issue_id"],
                        "properties": {
                            "issue_id": { "type": "string" },
                            "title": { "type": "string" },
                            "state_id": { "type": "string" },
                            "description": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "issue": { "type": "object" } } }),
                    "linear.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Update issue title, status, assignee, or other fields."
                            .into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"issue_id": "LIN-123", "state_id": "done-state-id"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("linear.get_issue")],
                    },
                ),
                op_info(
                    "linear.search_issues",
                    "Search issues with text query",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "issues": { "type": "array" }
                        }
                    }),
                    "linear.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Search for issues matching a text query.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"query": "login bug"}"#.into()],
                        related: vec![CapabilityId::from_static("linear.get_issue")],
                    },
                ),
                op_info(
                    "linear.list_teams",
                    "List all teams in the workspace",
                    json!({
                        "type": "object",
                        "properties": {}
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "teams": { "type": "array" }
                        }
                    }),
                    "linear.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List available teams in the workspace.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("linear.create_issue")],
                    },
                ),
                op_info(
                    "linear.list_cycles",
                    "List cycles for a team",
                    json!({
                        "type": "object",
                        "required": ["team_id"],
                        "properties": {
                            "team_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "cycles": { "type": "array" }
                        }
                    }),
                    "linear.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List sprints/cycles for a team.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"team_id": "TEAM-123"}"#.into()],
                        related: vec![CapabilityId::from_static("linear.list_teams")],
                    },
                ),
                op_info(
                    "linear.add_comment",
                    "Add a comment to an issue",
                    json!({
                        "type": "object",
                        "required": ["issue_id", "body"],
                        "properties": {
                            "issue_id": { "type": "string" },
                            "body": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "comment": { "type": "object" } } }),
                    "linear.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Comment on an issue.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"issue_id": "LIN-123", "body": "Working on this now."}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("linear.get_issue")],
                    },
                ),
                op_info(
                    "linear.list_projects",
                    "List projects in the workspace",
                    json!({
                        "type": "object",
                        "properties": {}
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "projects": { "type": "array" }
                        }
                    }),
                    "linear.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List projects.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("linear.list_teams")],
                    },
                ),
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle simulate method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle invoke method.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation =
            params
                .get("operation")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id: CapabilityId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "linear.create_issue" => self.invoke_create_issue(input).await,
            "linear.get_issue" => self.invoke_get_issue(input).await,
            "linear.update_issue" => self.invoke_update_issue(input).await,
            "linear.search_issues" => self.invoke_search_issues(input).await,
            "linear.list_teams" => self.invoke_list_teams().await,
            "linear.list_cycles" => self.invoke_list_cycles(input).await,
            "linear.add_comment" => self.invoke_add_comment(input).await,
            "linear.list_projects" => self.invoke_list_projects().await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_create_issue(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let title = require_str(&input, "title")?;
        let team_id = require_str(&input, "team_id")?;
        let description = input.get("description").and_then(|v| v.as_str());

        let issue = client
            .create_issue(title, team_id, description)
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "issue": issue }))
    }

    async fn invoke_get_issue(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_id = require_str(&input, "issue_id")?;

        let issue = client
            .get_issue(issue_id)
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "issue": issue }))
    }

    async fn invoke_update_issue(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_id = require_str(&input, "issue_id")?;
        let title = input.get("title").and_then(|v| v.as_str());
        let state_id = input.get("state_id").and_then(|v| v.as_str());
        let description = input.get("description").and_then(|v| v.as_str());

        let issue = client
            .update_issue(issue_id, title, state_id, description)
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "issue": issue }))
    }

    async fn invoke_search_issues(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let query = require_str(&input, "query")?;

        let issues = client
            .search_issues(query)
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "issues": issues }))
    }

    async fn invoke_list_teams(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let teams = client
            .list_teams()
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "teams": teams }))
    }

    async fn invoke_list_cycles(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let team_id = require_str(&input, "team_id")?;

        let cycles = client
            .list_cycles(team_id)
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "cycles": cycles }))
    }

    async fn invoke_add_comment(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let issue_id = require_str(&input, "issue_id")?;
        let body = require_str(&input, "body")?;

        let comment = client
            .add_comment(issue_id, body)
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "comment": comment }))
    }

    async fn invoke_list_projects(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;

        let projects = client
            .list_projects()
            .await
            .map_err(|e: LinearError| e.to_fcp_error())?;

        Ok(json!({ "projects": projects }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Linear connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for LinearConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ──────────────────────────────────────────────

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

#[allow(clippy::fn_params_excessive_bools)]
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
        summary: summary.into(),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval: None,
        safety_tier,
        idempotency,
        ai_hints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::ConnectorManifest;
    use std::path::PathBuf;

    fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> CapabilityToken {
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[cap])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .sign(signing_key)
            .unwrap();
        CapabilityToken { raw: cose }
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = LinearConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["linear.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = LinearConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = LinearConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["linear.get_issue"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "linear.get_issue");

        let result = connector
            .handle_invoke(json!({
                "operation": "linear.get_issue",
                "input": { "issue_id": "LIN-123" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = LinearConnector::new();
        connector.client = Some(
            LinearClient::new("fake_key")
                .unwrap()
                .with_api_url("http://localhost:9999/graphql"),
        );

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["linear.create_issue"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "linear.create_issue");

        let result = connector
            .handle_invoke(json!({
                "operation": "linear.create_issue",
                "input": { "title": "Bug" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("team_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = LinearConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"linear.create_issue"));
        assert!(op_ids.contains(&"linear.get_issue"));
        assert!(op_ids.contains(&"linear.update_issue"));
        assert!(op_ids.contains(&"linear.search_issues"));
        assert!(op_ids.contains(&"linear.list_teams"));
        assert!(op_ids.contains(&"linear.list_cycles"));
        assert!(op_ids.contains(&"linear.add_comment"));
        assert!(op_ids.contains(&"linear.list_projects"));
        assert_eq!(ops.len(), 8);
    }

    #[test]
    fn manifest_interface_hash_is_deterministic() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        if !manifest_path.exists() {
            eprintln!("manifest.toml missing; skipping interface_hash check");
            return;
        }

        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let computed = manifest
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(computed, computed2);
    }
}
