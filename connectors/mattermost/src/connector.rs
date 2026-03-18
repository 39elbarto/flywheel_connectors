//! Mattermost connector implementation.

use std::sync::Arc;
use std::time::Duration;

use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityId, CapabilityVerifier, ConnectorId,
    EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse, HealthSnapshot,
    HealthState, IdempotencyClass, InvokeRequest, InvokeResponse, Introspection, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SessionId, ShutdownRequest,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use serde_json::json;
use tracing::{debug, warn};

use crate::client::MattermostClient;
use crate::types::{CreatePostRequest, MattermostAuth, MattermostConfig, SearchPostsRequest};

/// Mattermost connector state.
#[derive(Debug)]
pub struct MattermostConnector {
    base: Arc<BaseConnector>,
    config: Option<MattermostConfig>,
    client: Option<MattermostClient>,
    runtime: Option<ConnectorRuntime>,
    /// Retained for future retry policy enforcement.
    #[allow(dead_code)]
    retry_config: HttpRetryConfig,
    verifier: Option<CapabilityVerifier>,
}

impl MattermostConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "fcp.mattermost",
            ))),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            verifier: None,
        }
    }

    /// Connector ID.
    #[must_use]
    pub fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    /// Configure the connector.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration JSON is invalid or the client cannot be built.
    pub fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: MattermostConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 5001,
                message: format!("invalid configuration: {e}"),
            })?;

        let auth = if let Some(ref token) = config.token {
            MattermostAuth::Token(token.clone())
        } else if let Some(ref cred_id) = config.credential_id {
            MattermostAuth::CredentialId(cred_id.clone())
        } else {
            return Err(FcpError::InvalidRequest {
                code: 5001,
                message: "either 'token' or 'credential_id' must be provided".to_string(),
            });
        };

        let timeout = Duration::from_millis(config.request_timeout_ms);
        let client = MattermostClient::new(&config.base_url, auth, timeout)
            .map_err(|e| FcpError::Internal {
                message: format!("client initialization failed: {e}"),
            })?;

        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(timeout),
        ));
        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(())
    }

    /// Perform the handshake.
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake parameters are invalid.
    pub fn handshake(&mut self, req: &HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let capabilities_granted = req
            .capabilities_requested
            .iter()
            .map(|cap| fcp_core::CapabilityGrant {
                capability: cap.clone(),
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id: SessionId::new(),
            manifest_hash: String::new(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    /// Health check.
    #[must_use]
    pub const fn health(&self) -> HealthSnapshot {
        let status = if self.client.is_some() {
            HealthState::Ready
        } else {
            HealthState::Starting
        };
        HealthSnapshot {
            status,
            uptime_ms: 0,
            load: None,
            details: None,
            rate_limit: None,
        }
    }

    /// Introspect operations.
    #[must_use]
    pub fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    /// Invoke an operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the connector is not configured, the operation is unknown,
    /// required fields are missing, or the upstream API call fails.
    pub async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let operation = req.operation.as_str();

        debug!(operation = %operation, "invoking mattermost operation");

        let output = match operation {
            "mattermost.get_me" => invoke_get_me(client).await?,
            "mattermost.get_user" => invoke_get_user(client, &req.input).await?,
            "mattermost.get_my_teams" => invoke_get_my_teams(client).await?,
            "mattermost.get_channel" => invoke_get_channel(client, &req.input).await?,
            "mattermost.create_post" => invoke_create_post(client, &req.input).await?,
            "mattermost.get_post" => invoke_get_post(client, &req.input).await?,
            "mattermost.get_posts_for_channel" => {
                invoke_get_posts_for_channel(client, &req.input).await?
            }
            "mattermost.search_posts" => invoke_search_posts(client, &req.input).await?,
            "mattermost.delete_post" => invoke_delete_post(client, &req.input).await?,
            _ => {
                warn!(operation = %operation, "unknown operation");
                return Err(FcpError::InvalidRequest {
                    code: 1002,
                    message: format!("unknown operation: {operation}"),
                });
            }
        };

        Ok(InvokeResponse::ok(req.id, output))
    }

    /// Shutdown the connector.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown cleanup fails.
    pub fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        self.client = None;
        Ok(())
    }
}

impl Default for MattermostConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Per-operation invoke handlers ───────────────────────────────────────

fn to_json<T: serde::Serialize>(value: T) -> FcpResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|e| FcpError::Internal {
        message: e.to_string(),
    })
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("missing required field '{field}'"),
        })
}

/// Convert a Mattermost error to an FCP error.
///
/// Takes ownership to satisfy `Result::map_err` signature.
#[allow(clippy::needless_pass_by_value)]
fn map_mm_err(e: crate::error::MattermostError) -> FcpError {
    e.to_fcp_error()
}

async fn invoke_get_me(client: &MattermostClient) -> FcpResult<serde_json::Value> {
    let user = client.get_me().await.map_err(map_mm_err)?;
    to_json(user)
}

async fn invoke_get_user(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let user_id = require_str(input, "user_id")?;
    let user = client.get_user(user_id).await.map_err(map_mm_err)?;
    to_json(user)
}

async fn invoke_get_my_teams(client: &MattermostClient) -> FcpResult<serde_json::Value> {
    let teams = client.get_my_teams().await.map_err(map_mm_err)?;
    to_json(teams)
}

async fn invoke_get_channel(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let channel_id = require_str(input, "channel_id")?;
    let ch = client.get_channel(channel_id).await.map_err(map_mm_err)?;
    to_json(ch)
}

async fn invoke_create_post(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let create_req: CreatePostRequest =
        serde_json::from_value(input.clone()).map_err(|e| FcpError::InvalidRequest {
            code: 1003,
            message: format!("invalid create_post input: {e}"),
        })?;
    let post = client
        .create_post(&create_req)
        .await
        .map_err(map_mm_err)?;
    to_json(post)
}

async fn invoke_get_post(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let post_id = require_str(input, "post_id")?;
    let post = client.get_post(post_id).await.map_err(map_mm_err)?;
    to_json(post)
}

async fn invoke_get_posts_for_channel(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let channel_id = require_str(input, "channel_id")?;
    let page = input
        .get("page")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let page = u32::try_from(page).unwrap_or(u32::MAX);
    let per_page = input
        .get("per_page")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(60);
    let per_page = u32::try_from(per_page).unwrap_or(u32::MAX);
    let posts = client
        .get_posts_for_channel(channel_id, page, per_page)
        .await
        .map_err(map_mm_err)?;
    to_json(posts)
}

async fn invoke_search_posts(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let team_id = require_str(input, "team_id")?;
    let search_req: SearchPostsRequest =
        serde_json::from_value(input.clone()).map_err(|e| FcpError::InvalidRequest {
            code: 1003,
            message: format!("invalid search input: {e}"),
        })?;
    let results = client
        .search_posts(team_id, &search_req)
        .await
        .map_err(map_mm_err)?;
    to_json(results)
}

async fn invoke_delete_post(
    client: &MattermostClient,
    input: &serde_json::Value,
) -> FcpResult<serde_json::Value> {
    let post_id = require_str(input, "post_id")?;
    client.delete_post(post_id).await.map_err(map_mm_err)?;
    Ok(json!({"status": "deleted", "post_id": post_id}))
}

// ── Operation descriptors ───────────────────────────────────────────────

/// Typed operation descriptors for introspection.
#[must_use]
pub fn operations_info() -> Vec<OperationInfo> {
    let mut ops = user_and_team_operations();
    ops.extend(channel_and_post_read_operations());
    ops.extend(search_operations());
    ops.extend(write_operations());
    ops
}

fn user_and_team_operations() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static("mattermost.get_me"),
            summary: "Get the authenticated user's profile.".into(),
            description: Some(
                "Returns the user profile associated with the current token.".into(),
            ),
            input_schema: json!({"type": "object"}),
            output_schema: json!({"type": "object", "properties": {"id": {"type": "string"}, "username": {"type": "string"}}}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "Use to verify authentication and get the bot/user identity.".into(),
                common_mistakes: vec!["Using an expired token.".into()],
                examples: vec![r"{}".into()],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static("mattermost.get_user"),
            summary: "Get a user by ID.".into(),
            description: Some(
                "Retrieve a specific user's profile by their Mattermost user ID.".into(),
            ),
            input_schema: json!({"type": "object", "properties": {"user_id": {"type": "string"}}, "required": ["user_id"]}),
            output_schema: json!({"type": "object", "properties": {"id": {"type": "string"}, "username": {"type": "string"}}}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "Use to look up another user's profile by their ID.".into(),
                common_mistakes: vec!["Passing a username instead of user ID.".into()],
                examples: vec![r#"{"user_id": "abc123def456"}"#.into()],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static("mattermost.get_my_teams"),
            summary: "List teams the user belongs to.".into(),
            description: Some(
                "Returns all teams that the authenticated user is a member of.".into(),
            ),
            input_schema: json!({"type": "object"}),
            output_schema: json!({"type": "array", "items": {"type": "object"}}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "Use to discover available teams before listing channels.".into(),
                common_mistakes: vec![],
                examples: vec![r"{}".into()],
                related: vec![CapabilityId::from_static("mattermost.get_channel")],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fn channel_and_post_read_operations() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static("mattermost.get_channel"),
            summary: "Get a channel by ID.".into(),
            description: Some(
                "Retrieve channel details including header, purpose, and type.".into(),
            ),
            input_schema: json!({"type": "object", "properties": {"channel_id": {"type": "string"}}, "required": ["channel_id"]}),
            output_schema: json!({"type": "object", "properties": {"id": {"type": "string"}, "display_name": {"type": "string"}}}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "Use to get details about a specific channel.".into(),
                common_mistakes: vec!["Using channel name instead of channel ID.".into()],
                examples: vec![r#"{"channel_id": "abc123"}"#.into()],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static("mattermost.get_post"),
            summary: "Get a post by ID.".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"post_id": {"type": "string"}}, "required": ["post_id"]}),
            output_schema: json!({"type": "object"}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "Use to retrieve a specific post/message by its ID.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"post_id": "abc123"}"#.into()],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static("mattermost.get_posts_for_channel"),
            summary: "List posts in a channel (paginated).".into(),
            description: Some(
                "Returns posts in reverse chronological order with pagination support.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "channel_id": {"type": "string"},
                    "page": {"type": "integer", "default": 0},
                    "per_page": {"type": "integer", "default": 60}
                },
                "required": ["channel_id"]
            }),
            output_schema: json!({"type": "object", "properties": {"order": {"type": "array"}, "posts": {"type": "object"}}}),
            capability: CapabilityId::from_static("mattermost.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "Use to read message history in a channel.".into(),
                common_mistakes: vec!["Setting per_page too high (max 200).".into()],
                examples: vec![
                    r#"{"channel_id": "abc123", "page": 0, "per_page": 30}"#.into(),
                ],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fn search_operations() -> Vec<OperationInfo> {
    vec![OperationInfo {
        id: OperationId::from_static("mattermost.search_posts"),
        summary: "Search posts in a team.".into(),
        description: Some(
            "Full-text search across all channels the user can access in a team.".into(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "team_id": {"type": "string"},
                "terms": {"type": "string"},
                "is_or_search": {"type": "boolean", "default": false}
            },
            "required": ["team_id", "terms"]
        }),
        output_schema: json!({"type": "object", "properties": {"order": {"type": "array"}, "posts": {"type": "object"}}}),
        capability: CapabilityId::from_static("mattermost.read"),
        risk_level: RiskLevel::Low,
        safety_tier: SafetyTier::Safe,
        idempotency: IdempotencyClass::BestEffort,
        ai_hints: AgentHint {
            when_to_use: "Use to search messages across a team's channels.".into(),
            common_mistakes: vec!["Not specifying team_id.".into()],
            examples: vec![
                r#"{"team_id": "t1", "terms": "deployment issue"}"#.into(),
            ],
            related: vec![],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }]
}

fn write_operations() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static("mattermost.create_post"),
            summary: "Send a message to a channel.".into(),
            description: Some(
                "Create a new post (message) in a Mattermost channel. Can also reply to threads."
                    .into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "channel_id": {"type": "string"},
                    "message": {"type": "string"},
                    "root_id": {"type": "string", "description": "Thread root post ID for replies"}
                },
                "required": ["channel_id", "message"]
            }),
            output_schema: json!({"type": "object", "properties": {"id": {"type": "string"}, "message": {"type": "string"}}}),
            capability: CapabilityId::from_static("mattermost.write"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use to send a message to a channel or reply to a thread.".into(),
                common_mistakes: vec![
                    "Forgetting to set channel_id.".into(),
                    "Not using root_id when replying to a thread.".into(),
                ],
                examples: vec![
                    r#"{"channel_id": "abc123", "message": "Hello team!"}"#.into(),
                    r#"{"channel_id": "abc123", "message": "Reply here", "root_id": "post_id"}"#
                        .into(),
                ],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static("mattermost.delete_post"),
            summary: "Delete a post.".into(),
            description: Some(
                "Permanently delete a post. Requires appropriate permissions.".into(),
            ),
            input_schema: json!({"type": "object", "properties": {"post_id": {"type": "string"}}, "required": ["post_id"]}),
            output_schema: json!({"type": "object", "properties": {"status": {"type": "string"}}}),
            capability: CapabilityId::from_static("mattermost.write"),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "Use to delete a message. This is irreversible.".into(),
                common_mistakes: vec!["Deleting the wrong post — verify post_id first.".into()],
                examples: vec![r#"{"post_id": "abc123"}"#.into()],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_new() {
        let connector = MattermostConnector::new();
        assert_eq!(connector.id().as_str(), "fcp.mattermost");
    }

    #[test]
    fn connector_default() {
        let connector = MattermostConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.mattermost");
    }

    #[test]
    fn operations_info_has_entries() {
        let ops = operations_info();
        assert!(!ops.is_empty());
        assert!(ops.len() >= 9);
    }

    #[test]
    fn operations_info_ids_unique() {
        let ops = operations_info();
        let mut ids: Vec<&str> = ops.iter().map(|o| o.id.as_str()).collect();
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), count, "duplicate operation IDs found");
    }

    #[test]
    fn operations_info_all_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                !op.ai_hints.when_to_use.is_empty(),
                "operation {} missing when_to_use hint",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn write_operations_are_risky() {
        let ops = operations_info();
        for op in &ops {
            if op.capability.as_str().ends_with(".write") {
                assert!(
                    matches!(op.safety_tier, SafetyTier::Risky),
                    "write operation {} should be Risky, got {:?}",
                    op.id.as_str(),
                    op.safety_tier
                );
            }
        }
    }

    #[test]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in &ops {
            if op.capability.as_str().ends_with(".read") {
                assert!(
                    matches!(op.safety_tier, SafetyTier::Safe),
                    "read operation {} should be Safe, got {:?}",
                    op.id.as_str(),
                    op.safety_tier
                );
            }
        }
    }

    #[test]
    fn introspect_returns_operations() {
        let connector = MattermostConnector::new();
        let introspection = connector.introspect();
        assert!(introspection.operations.len() >= 9);
    }

    #[test]
    fn health_not_configured() {
        let connector = MattermostConnector::new();
        let health = connector.health();
        assert!(matches!(health.status, HealthState::Starting));
    }

    #[test]
    fn delete_requires_approval() {
        let ops = operations_info();
        let delete_op = ops
            .iter()
            .find(|o| o.id.as_str() == "mattermost.delete_post")
            .expect("delete operation should exist");
        assert!(
            matches!(
                delete_op.requires_approval,
                Some(ApprovalMode::Interactive)
            ),
            "delete should require interactive approval"
        );
    }
}
