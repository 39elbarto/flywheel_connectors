//! FCP `Reddit` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, Introspection, OAuthRecipe, OperationId, OperationInfo, ProvisioningRecipe,
    ProvisioningStep, ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, SelfCheckReport,
    StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client,
    client::{DEFAULT_BASE_URL, RedditAuth, RedditClient},
    error::RedditError,
};

/// Parsed and validated `Reddit` connector configuration.
#[derive(Debug, Clone)]
struct RedditConfig {
    auth: RedditAuth,
    base_url: String,
}

impl RedditConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let bearer_token = params
            .get("bearer_token")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let credential_id = match params.get("credential_id") {
            Some(value) => {
                let raw = value.as_str().ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "credential_id must be a string".into(),
                })?;
                Some(
                    CredentialId::parse(raw).map_err(|_| FcpError::InvalidRequest {
                        code: 1003,
                        message: "credential_id must be a valid UUID".into(),
                    })?,
                )
            }
            None => None,
        };

        let auth = match (bearer_token, credential_id) {
            (Some(token), None) => RedditAuth::BearerToken(token),
            (None, Some(cred_id)) => RedditAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of bearer_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing bearer_token or credential_id in configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        Ok(Self { auth, base_url })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                RedditAuth::BearerToken(_) => "bearer_token",
                RedditAuth::CredentialId(_) => "credential_id",
            },
            token_configured: matches!(&self.auth, RedditAuth::BearerToken(_)),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            base_url: self.base_url.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    token_configured: bool,
    credential_id_configured: bool,
    requires_credential_injection: bool,
    network_ok: bool,
    network_message: String,
    base_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    #[must_use]
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|c| c.critical && !c.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| !c.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self { status, checks }
    }
}

/// FCP `Reddit` Connector.
pub struct RedditConnector {
    base: Arc<BaseConnector>,
    config: Option<RedditConfig>,
    client: Option<Arc<RedditClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl RedditConnector {
    /// Create a new `Reddit` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("reddit"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for RedditConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl RedditConnector {
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = RedditConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Reddit connector");
        let client = RedditClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({}))
    }

    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.config.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Connector not configured".into(),
            });
        }
        self.session_id = params
            .get("session_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        self.base.set_handshaken(true);
        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.reddit",
            "connector_version": "0.1.0",
            "capabilities": [
                "reddit.read", "reddit.search", "reddit.post",
                "reddit.comment", "reddit.message", "reddit.moderate",
                "reddit.stream", "reddit.media.read"
            ]
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();
        let status = if configured && handshaken {
            "healthy"
        } else if configured {
            "degraded"
        } else {
            "unconfigured"
        };
        Ok(
            json!({ "status": status, "configured": configured, "handshaken": handshaken, "requests": self.request_count.load(Ordering::Relaxed), "errors": self.error_count.load(Ordering::Relaxed) }),
        )
    }

    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_none() {
                Some("Not configured".into())
            } else {
                None
            },
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: if self.client.is_none() {
                Some("API client not initialized".into())
            } else {
                None
            },
            critical: true,
        });
        let handshaken = self.session_id.is_some();
        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: handshaken,
            message: if handshaken {
                None
            } else {
                Some("Handshake not completed".into())
            },
            critical: false,
        });
        let result = DoctorResult::from_checks(checks);
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return Self::serialize_self_check_report(report);
        };

        let readiness = config.provisioning_readiness();
        if !readiness.network_ok {
            let mut report = SelfCheckReport::failed(
                "network_constraints_invalid",
                readiness.network_message.clone(),
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let Some(_client) = &self.client else {
            let mut report = SelfCheckReport::failed(
                "client_missing",
                "API client not initialized; re-run configure",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        };

        if readiness.requires_credential_injection {
            let mut report = SelfCheckReport::degraded(
                "credential_injection_required",
                "credential_id mode requires egress proxy injection; skipping live probe",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let mut report = SelfCheckReport::ok();
        report.details = Some(json!({ "provisioning": readiness }));
        Self::serialize_self_check_report(report)
    }

    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("reddit.search_posts"),
                    summary: "Search Reddit posts using query text and optional subreddit filters".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": { "type": "string", "description": "Search text, matching Reddit search syntax.", "minLength": 1, "maxLength": 512 },
                            "subreddit": { "type": "string", "description": "Optional subreddit name without r/ prefix.", "pattern": "^[A-Za-z0-9_]{2,21}$" },
                            "sort": { "type": "string", "description": "Sort mode for search results.", "enum": ["relevance", "hot", "new", "top", "comments"], "default": "relevance" },
                            "time_range": { "type": "string", "description": "Time window for ranking.", "enum": ["hour", "day", "week", "month", "year", "all"], "default": "all" },
                            "limit": { "type": "integer", "description": "Maximum posts to return.", "minimum": 1, "maximum": 100, "default": 25 },
                            "after": { "type": "string", "description": "Pagination cursor returned by a prior call." }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["posts"],
                        "properties": {
                            "posts": { "type": "array", "description": "Reddit post summaries.", "items": { "type": "object" } },
                            "next_after": { "type": "string", "description": "Pagination cursor for next page." }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.search"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use this for keyword discovery across Reddit.".into(),
                        common_mistakes: vec![
                            "Passing subreddit names with the r/ prefix.".into(),
                            "Using large limits without handling pagination.".into(),
                        ],
                        examples: vec![
                            r#"{"query":"agentic coding", "subreddit":"rust", "sort":"new", "limit":20}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.list_subreddit_new"),
                            CapabilityId::from_static("reddit.get_post_thread"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("reddit.list_subreddit_new"),
                    summary: "List newest posts from a subreddit".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["subreddit"],
                        "properties": {
                            "subreddit": { "type": "string", "description": "Subreddit name without r/ prefix.", "pattern": "^[A-Za-z0-9_]{2,21}$" },
                            "limit": { "type": "integer", "description": "Maximum posts to return.", "minimum": 1, "maximum": 100, "default": 25 },
                            "after": { "type": "string", "description": "Pagination cursor from a prior response." }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["posts"],
                        "properties": {
                            "posts": { "type": "array" },
                            "next_after": { "type": "string" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.read"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use this for incremental ingestion from one subreddit.".into(),
                        common_mistakes: vec![
                            "Forgetting to store and replay the `next_after` cursor.".into(),
                        ],
                        examples: vec![
                            r#"{"subreddit":"machinelearning", "limit":25}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.stream_subreddit_new"),
                            CapabilityId::from_static("reddit.search_posts"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("reddit.get_post_thread"),
                    summary: "Fetch a post and its comment tree".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["post_fullname"],
                        "properties": {
                            "post_fullname": { "type": "string", "description": "Thing fullname, typically prefixed with t3_.", "pattern": "^t3_[A-Za-z0-9]+$" },
                            "sort": { "type": "string", "description": "Comment sort mode.", "enum": ["confidence", "top", "new", "controversial", "old", "qa"], "default": "confidence" },
                            "comment_limit": { "type": "integer", "description": "Maximum comments to include.", "minimum": 1, "maximum": 500, "default": 100 }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["post", "comments"],
                        "properties": {
                            "post": { "type": "object" },
                            "comments": { "type": "array" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.read"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use this for full context around one post.".into(),
                        common_mistakes: vec![
                            "Passing a bare post ID instead of a fullname (t3_...).".into(),
                        ],
                        examples: vec![
                            r#"{"post_fullname":"t3_1abcde", "sort":"top", "comment_limit":50}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.search_posts"),
                            CapabilityId::from_static("reddit.list_subreddit_new"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("reddit.create_post"),
                    summary: "Submit a new Reddit post".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["subreddit", "kind", "title"],
                        "properties": {
                            "subreddit": { "type": "string", "description": "Target subreddit name.", "pattern": "^[A-Za-z0-9_]{2,21}$" },
                            "kind": { "type": "string", "description": "Post type.", "enum": ["self", "link"] },
                            "title": { "type": "string", "description": "Post title.", "minLength": 1, "maxLength": 300 },
                            "text": { "type": "string", "description": "Body for self-posts." },
                            "url": { "type": "string", "description": "URL for link posts.", "format": "uri" },
                            "nsfw": { "type": "boolean", "description": "Mark post NSFW." },
                            "spoiler": { "type": "boolean", "description": "Mark post as spoiler." },
                            "idempotency_key": { "type": "string", "description": "Client-provided key used to suppress duplicate submissions.", "maxLength": 128 }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["fullname", "permalink"],
                        "properties": {
                            "fullname": { "type": "string" },
                            "permalink": { "type": "string" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.post"),
                    risk_level: RiskLevel::High,
                    safety_tier: SafetyTier::Dangerous,
                    idempotency: IdempotencyClass::BestEffort,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use this to publish a new post after explicit human confirmation.".into(),
                        common_mistakes: vec![
                            "Providing `text` for a link post without `url`.".into(),
                            "Posting to a subreddit where the account lacks permission.".into(),
                        ],
                        examples: vec![
                            r#"{"subreddit":"agentflywheel", "kind":"self", "title":"Release notes", "text":"..."}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.create_comment"),
                            CapabilityId::from_static("reddit.send_message"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("reddit.create_comment"),
                    summary: "Add a comment to a post or comment".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["parent_fullname", "text"],
                        "properties": {
                            "parent_fullname": { "type": "string", "description": "Thing fullname, usually t3_... (post) or t1_... (comment).", "pattern": "^t[13]_[A-Za-z0-9]+$" },
                            "text": { "type": "string", "description": "Comment markdown text.", "minLength": 1, "maxLength": 10000 },
                            "idempotency_key": { "type": "string", "description": "Client key used to avoid duplicate comments.", "maxLength": 128 }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["fullname"],
                        "properties": {
                            "fullname": { "type": "string" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.comment"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::BestEffort,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use to reply to posts/comments with approval-gated write behavior.".into(),
                        common_mistakes: vec![
                            "Using post IDs instead of fullnames.".into(),
                            "Submitting duplicate comments during retries.".into(),
                        ],
                        examples: vec![
                            r#"{"parent_fullname":"t3_1abcde", "text":"Nice write-up.", "idempotency_key":"cmt-001"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.get_post_thread"),
                            CapabilityId::from_static("reddit.create_post"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("reddit.send_message"),
                    summary: "Send a private message through Reddit messaging".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["recipient", "subject", "message"],
                        "properties": {
                            "recipient": { "type": "string", "description": "Reddit username without u/ prefix.", "pattern": "^[A-Za-z0-9_-]{3,20}$" },
                            "subject": { "type": "string", "description": "Message subject.", "minLength": 1, "maxLength": 100 },
                            "message": { "type": "string", "description": "Message body.", "minLength": 1, "maxLength": 10000 },
                            "idempotency_key": { "type": "string", "description": "Client key used to avoid duplicate sends.", "maxLength": 128 }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["sent"],
                        "properties": {
                            "sent": { "type": "boolean" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.message"),
                    risk_level: RiskLevel::High,
                    safety_tier: SafetyTier::Dangerous,
                    idempotency: IdempotencyClass::BestEffort,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use this for direct user communication when an explicit human decision approved it.".into(),
                        common_mistakes: vec![
                            "Using a display name instead of exact Reddit username.".into(),
                        ],
                        examples: vec![
                            r#"{"recipient":"example_user", "subject":"Follow-up", "message":"Thanks for your report."}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.create_comment"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("reddit.mod_remove"),
                    summary: "Remove a post/comment via moderator privileges".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["thing_fullname"],
                        "properties": {
                            "thing_fullname": { "type": "string", "description": "Thing fullname to moderate, such as t3_... or t1_....", "pattern": "^t[13]_[A-Za-z0-9]+$" },
                            "spam": { "type": "boolean", "description": "Mark removed content as spam." },
                            "mod_note": { "type": "string", "description": "Optional moderation note.", "maxLength": 500 }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["removed"],
                        "properties": {
                            "removed": { "type": "boolean" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.moderate"),
                    risk_level: RiskLevel::High,
                    safety_tier: SafetyTier::Dangerous,
                    idempotency: IdempotencyClass::Strict,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use only for moderation workflows where dangerous actions are explicitly approved.".into(),
                        common_mistakes: vec![
                            "Removing the wrong thing due to truncated IDs.".into(),
                        ],
                        examples: vec![
                            r#"{"thing_fullname":"t1_xy12ab", "spam":false, "mod_note":"Rule 2 violation"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.get_post_thread"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("reddit.download_media"),
                    summary: "Download media referenced by Reddit posts from explicitly allowed media hosts".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["url"],
                        "properties": {
                            "url": { "type": "string", "description": "Media URL hosted on an explicitly allowlisted Reddit media domain.", "format": "uri" },
                            "max_bytes": { "type": "integer", "description": "Optional hard cap for downloaded content.", "minimum": 1024, "maximum": 26214400, "default": 10485760 }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["content_type", "bytes"],
                        "properties": {
                            "content_type": { "type": "string" },
                            "bytes": { "type": "integer" },
                            "sha256": { "type": "string" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.media.read"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use only when media artifacts are required for downstream processing.".into(),
                        common_mistakes: vec![
                            "Attempting to fetch arbitrary external URLs.".into(),
                            "Not enforcing max_bytes for large videos.".into(),
                        ],
                        examples: vec![
                            r#"{"url":"https://i.redd.it/example123.png", "max_bytes":5242880}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.get_post_thread"),
                            CapabilityId::from_static("reddit.search_posts"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("reddit.stream_subreddit_new"),
                    summary: "Poll new subreddit posts and emit streaming event batches".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["subreddit"],
                        "properties": {
                            "subreddit": { "type": "string", "description": "Subreddit name to poll.", "pattern": "^[A-Za-z0-9_]{2,21}$" },
                            "batch_limit": { "type": "integer", "description": "Maximum events to emit per polling cycle.", "minimum": 1, "maximum": 100, "default": 25 },
                            "poll_interval_ms": { "type": "integer", "description": "Polling interval in milliseconds.", "minimum": 5000, "maximum": 300000, "default": 30000 },
                            "checkpoint_key": { "type": "string", "description": "State key for persisted checkpoint cursor.", "maxLength": 128, "default": "subreddit:new" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["events", "next_checkpoint"],
                        "properties": {
                            "events": { "type": "array" },
                            "next_checkpoint": { "type": "string" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.stream"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use for incremental event ingestion from subreddit feeds.".into(),
                        common_mistakes: vec![
                            "Too-short polling intervals that trigger API throttling.".into(),
                            "Not persisting checkpoint keys across restarts.".into(),
                        ],
                        examples: vec![
                            r#"{"subreddit":"agentflywheel", "poll_interval_ms":30000, "batch_limit":20}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.list_subreddit_new"),
                            CapabilityId::from_static("reddit.search_posts"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("reddit.subreddit.get"),
                    summary: "Get subreddit metadata".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["subreddit"],
                        "properties": {
                            "subreddit": { "type": "string", "description": "Subreddit name without r/ prefix.", "pattern": "^[A-Za-z0-9_]{2,21}$" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["name"],
                        "properties": {
                            "name": { "type": "string" },
                            "subscribers": { "type": "integer" },
                            "description": { "type": "string" },
                            "public_description": { "type": "string" },
                            "over18": { "type": "boolean" },
                            "quarantine": { "type": "boolean" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.read"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use to retrieve subreddit metadata such as subscribers, description, and rules.".into(),
                        common_mistakes: vec![
                            "Including the r/ prefix in the subreddit name.".into(),
                        ],
                        examples: vec![
                            r#"{"subreddit":"rust"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.subreddit.search"),
                            CapabilityId::from_static("reddit.list_subreddit_new"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("reddit.subreddit.search"),
                    summary: "Search for subreddits".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": { "type": "string", "description": "Search query for subreddit names and descriptions.", "minLength": 1, "maxLength": 512 },
                            "limit": { "type": "integer", "description": "Maximum subreddits to return.", "minimum": 1, "maximum": 100, "default": 25 },
                            "after": { "type": "string", "description": "Pagination cursor from a prior response." }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["posts"],
                        "properties": {
                            "posts": { "type": "array" },
                            "next_after": { "type": "string" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.search"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use to discover subreddits matching a topic or keyword.".into(),
                        common_mistakes: vec![
                            "Confusing subreddit search with post search.".into(),
                        ],
                        examples: vec![
                            r#"{"query":"machine learning", "limit":10}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.subreddit.get"),
                            CapabilityId::from_static("reddit.search_posts"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("reddit.user.posts"),
                    summary: "List a user's post history".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["username"],
                        "properties": {
                            "username": { "type": "string", "description": "Reddit username without u/ prefix.", "pattern": "^[A-Za-z0-9_-]{3,20}$" },
                            "limit": { "type": "integer", "description": "Maximum posts to return.", "minimum": 1, "maximum": 100, "default": 25 },
                            "sort": { "type": "string", "description": "Sort mode.", "enum": ["hot", "new", "top", "controversial"], "default": "new" },
                            "after": { "type": "string", "description": "Pagination cursor from a prior response." }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["posts"],
                        "properties": {
                            "posts": { "type": "array" },
                            "next_after": { "type": "string" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.read"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use to view a user's submitted post history.".into(),
                        common_mistakes: vec![
                            "Including the u/ prefix in the username.".into(),
                        ],
                        examples: vec![
                            r#"{"username":"spez", "limit":10, "sort":"new"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.user.comments"),
                            CapabilityId::from_static("reddit.get_post_thread"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("reddit.user.comments"),
                    summary: "List a user's comment history".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["username"],
                        "properties": {
                            "username": { "type": "string", "description": "Reddit username without u/ prefix.", "pattern": "^[A-Za-z0-9_-]{3,20}$" },
                            "limit": { "type": "integer", "description": "Maximum comments to return.", "minimum": 1, "maximum": 100, "default": 25 },
                            "sort": { "type": "string", "description": "Sort mode.", "enum": ["hot", "new", "top", "controversial"], "default": "new" },
                            "after": { "type": "string", "description": "Pagination cursor from a prior response." }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["posts"],
                        "properties": {
                            "posts": { "type": "array" },
                            "next_after": { "type": "string" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.read"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use to view a user's comment history.".into(),
                        common_mistakes: vec![
                            "Including the u/ prefix in the username.".into(),
                        ],
                        examples: vec![
                            r#"{"username":"spez", "limit":10, "sort":"top"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.user.posts"),
                            CapabilityId::from_static("reddit.get_post_thread"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("reddit.edit_content"),
                    summary: "Edit the text of an existing post or comment".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["thing_fullname", "text"],
                        "properties": {
                            "thing_fullname": { "type": "string", "description": "Fullname of the post or comment to edit (t3_... or t1_...).", "pattern": "^t[13]_[A-Za-z0-9]+$" },
                            "text": { "type": "string", "description": "New markdown text for the post/comment body.", "minLength": 1, "maxLength": 40000 }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "json": { "type": "object" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.post"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::BestEffort,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use to edit the text of a post or comment you own.".into(),
                        common_mistakes: vec![
                            "Editing content owned by another user (will fail with 403).".into(),
                            "Using a bare ID instead of a fullname (t3_... or t1_...).".into(),
                        ],
                        examples: vec![
                            r#"{"thing_fullname":"t3_abc123", "text":"Updated post body text."}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.create_post"),
                            CapabilityId::from_static("reddit.delete_content"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("reddit.delete_content"),
                    summary: "Delete an existing post or comment".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["thing_fullname"],
                        "properties": {
                            "thing_fullname": { "type": "string", "description": "Fullname of the post or comment to delete (t3_... or t1_...).", "pattern": "^t[13]_[A-Za-z0-9]+$" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["deleted"],
                        "properties": {
                            "deleted": { "type": "boolean" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.post"),
                    risk_level: RiskLevel::High,
                    safety_tier: SafetyTier::Dangerous,
                    idempotency: IdempotencyClass::Strict,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use to permanently delete a post or comment you own.".into(),
                        common_mistakes: vec![
                            "Deleting content owned by another user (will fail).".into(),
                            "Deletion is irreversible; confirm before proceeding.".into(),
                        ],
                        examples: vec![
                            r#"{"thing_fullname":"t1_xyz789"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.edit_content"),
                            CapabilityId::from_static("reddit.mod_remove"),
                        ],
                    },
                },
                // ── Saved Items ──────────────────────────────────────────
                OperationInfo {
                    id: OperationId::from_static("reddit.saved.list"),
                    summary: "List saved posts and comments for a user".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["username"],
                        "properties": {
                            "username": { "type": "string", "description": "Reddit username without u/ prefix.", "pattern": "^[A-Za-z0-9_-]{3,20}$" },
                            "limit": { "type": "integer", "description": "Maximum items to return.", "minimum": 1, "maximum": 100, "default": 25 },
                            "after": { "type": "string", "description": "Pagination cursor from a prior response." }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["posts"],
                        "properties": {
                            "posts": { "type": "array" },
                            "next_after": { "type": "string" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.read"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use to retrieve a user's saved posts and comments.".into(),
                        common_mistakes: vec![
                            "Including the u/ prefix in the username.".into(),
                        ],
                        examples: vec![
                            r#"{"username":"myuser", "limit":25}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.saved.save"),
                            CapabilityId::from_static("reddit.saved.unsave"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("reddit.saved.save"),
                    summary: "Save a post or comment to your saved items".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["thing_fullname"],
                        "properties": {
                            "thing_fullname": { "type": "string", "description": "Fullname of the post or comment to save (t3_... or t1_...).", "pattern": "^t[13]_[A-Za-z0-9]+$" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["saved"],
                        "properties": {
                            "saved": { "type": "boolean" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.post"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use to bookmark a post or comment to your saved items list.".into(),
                        common_mistakes: vec![
                            "Using a bare ID instead of a fullname (t3_... or t1_...).".into(),
                        ],
                        examples: vec![
                            r#"{"thing_fullname":"t3_abc123"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.saved.unsave"),
                            CapabilityId::from_static("reddit.saved.list"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("reddit.saved.unsave"),
                    summary: "Remove a post or comment from your saved items".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["thing_fullname"],
                        "properties": {
                            "thing_fullname": { "type": "string", "description": "Fullname of the post or comment to unsave (t3_... or t1_...).", "pattern": "^t[13]_[A-Za-z0-9]+$" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["unsaved"],
                        "properties": {
                            "unsaved": { "type": "boolean" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.post"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use to remove a previously saved post or comment from your saved items.".into(),
                        common_mistakes: vec![
                            "Using a bare ID instead of a fullname (t3_... or t1_...).".into(),
                        ],
                        examples: vec![
                            r#"{"thing_fullname":"t3_abc123"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.saved.save"),
                            CapabilityId::from_static("reddit.saved.list"),
                        ],
                    },
                },
                // ── Moderation ───────────────────────────────────────────
                OperationInfo {
                    id: OperationId::from_static("reddit.mod.queue"),
                    summary: "List the moderation queue for a subreddit".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["subreddit"],
                        "properties": {
                            "subreddit": { "type": "string", "description": "Subreddit name without r/ prefix.", "pattern": "^[A-Za-z0-9_]{2,21}$" },
                            "limit": { "type": "integer", "description": "Maximum items to return.", "minimum": 1, "maximum": 100, "default": 25 },
                            "after": { "type": "string", "description": "Pagination cursor from a prior response." }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["posts"],
                        "properties": {
                            "posts": { "type": "array" },
                            "next_after": { "type": "string" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.moderate"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use to review flagged/reported items in a subreddit's moderation queue.".into(),
                        common_mistakes: vec![
                            "Including the r/ prefix in the subreddit name.".into(),
                        ],
                        examples: vec![
                            r#"{"subreddit":"rust", "limit":25}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.mod.approve"),
                            CapabilityId::from_static("reddit.mod_remove"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("reddit.mod.approve"),
                    summary: "Approve a flagged item in the moderation queue".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["thing_fullname"],
                        "properties": {
                            "thing_fullname": { "type": "string", "description": "Fullname of the item to approve (t3_... or t1_...).", "pattern": "^t[13]_[A-Za-z0-9]+$" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["approved"],
                        "properties": {
                            "approved": { "type": "boolean" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.moderate"),
                    risk_level: RiskLevel::Medium,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::Strict,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use to approve a flagged/reported item, clearing it from the moderation queue.".into(),
                        common_mistakes: vec![
                            "Approving the wrong item due to truncated IDs.".into(),
                        ],
                        examples: vec![
                            r#"{"thing_fullname":"t3_flagged1"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.mod.queue"),
                            CapabilityId::from_static("reddit.mod_remove"),
                        ],
                    },
                },
                // ── Inbox ────────────────────────────────────────────────
                OperationInfo {
                    id: OperationId::from_static("reddit.inbox.list"),
                    summary: "List inbox messages, mentions, or unread items".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "category": { "type": "string", "description": "Inbox category to list.", "enum": ["inbox", "unread", "messages", "mentions"], "default": "inbox" },
                            "limit": { "type": "integer", "description": "Maximum items to return.", "minimum": 1, "maximum": 100, "default": 25 },
                            "after": { "type": "string", "description": "Pagination cursor from a prior response." }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["posts"],
                        "properties": {
                            "posts": { "type": "array" },
                            "next_after": { "type": "string" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.message"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use to read inbox messages, mentions, or unread items.".into(),
                        common_mistakes: vec![
                            "Not specifying category; defaults to 'inbox' which includes all.".into(),
                        ],
                        examples: vec![
                            r#"{"category":"unread", "limit":10}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.inbox.mark_read"),
                            CapabilityId::from_static("reddit.send_message"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("reddit.inbox.mark_read"),
                    summary: "Mark one or more inbox messages as read".into(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["fullnames"],
                        "properties": {
                            "fullnames": { "type": "array", "description": "List of message fullnames to mark as read.", "items": { "type": "string" }, "minItems": 1, "maxItems": 25 }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["marked_read"],
                        "properties": {
                            "marked_read": { "type": "boolean" }
                        }
                    }),
                    capability: CapabilityId::from_static("reddit.message"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    rate_limit: None,
                    requires_approval: None,
                    ai_hints: AgentHint {
                        when_to_use: "Use to mark messages as read after processing them.".into(),
                        common_mistakes: vec![
                            "Passing a single string instead of an array of fullnames.".into(),
                        ],
                        examples: vec![
                            r#"{"fullnames":["t4_abc123","t4_def456"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("reddit.inbox.list"),
                            CapabilityId::from_static("reddit.send_message"),
                        ],
                    },
                },
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

    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;
        let operation = params
            .get("operation_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;
        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));
        self.request_count.fetch_add(1, Ordering::Relaxed);
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "reddit.search_posts" => self.invoke_search_posts(client, &input).await,
            "reddit.list_subreddit_new" => self.invoke_list_subreddit_new(client, &input).await,
            "reddit.get_post_thread" => self.invoke_get_post_thread(client, &input).await,
            "reddit.create_post" => self.invoke_create_post(client, &input).await,
            "reddit.create_comment" => self.invoke_create_comment(client, &input).await,
            "reddit.send_message" => self.invoke_send_message(client, &input).await,
            "reddit.mod_remove" => self.invoke_mod_remove(client, &input).await,
            "reddit.download_media" => self.invoke_download_media(client, &input).await,
            "reddit.stream_subreddit_new" => self.invoke_stream_subreddit_new(client, &input).await,
            "reddit.subreddit.get" => self.invoke_subreddit_get(client, &input).await,
            "reddit.subreddit.search" => self.invoke_subreddit_search(client, &input).await,
            "reddit.user.posts" => self.invoke_user_posts(client, &input).await,
            "reddit.user.comments" => self.invoke_user_comments(client, &input).await,
            "reddit.edit_content" => self.invoke_edit_content(client, &input).await,
            "reddit.delete_content" => self.invoke_delete_content(client, &input).await,
            "reddit.saved.list" => self.invoke_saved_list(client, &input).await,
            "reddit.saved.save" => self.invoke_saved_save(client, &input).await,
            "reddit.saved.unsave" => self.invoke_saved_unsave(client, &input).await,
            "reddit.mod.queue" => self.invoke_mod_queue(client, &input).await,
            "reddit.mod.approve" => self.invoke_mod_approve(client, &input).await,
            "reddit.inbox.list" => self.invoke_inbox_list(client, &input).await,
            "reddit.inbox.mark_read" => self.invoke_inbox_mark_read(client, &input).await,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1002,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        result.map_err(|e| {
            self.error_count.fetch_add(1, Ordering::Relaxed);
            e.to_fcp_error()
        })
    }

    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let allowed = operations_info().as_array().is_some_and(|ops| {
            ops.iter()
                .any(|o| o.get("id").and_then(|v| v.as_str()) == Some(operation))
        });
        Ok(
            json!({ "allowed": allowed, "reason": if allowed { "Operation supported" } else { "Unknown operation" } }),
        )
    }

    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Reddit connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // ── Operations ────────────────────────────────────────────────────

    async fn invoke_search_posts(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let query = require_str(input, "query")?;
        let subreddit = input.get("subreddit").and_then(|v| v.as_str());
        let sort = input.get("sort").and_then(|v| v.as_str());
        let time_range = input.get("time_range").and_then(|v| v.as_str());
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let after = input.get("after").and_then(|v| v.as_str());
        let data = client
            .search_posts(&client::SearchParams {
                query,
                subreddit,
                sort,
                time_range,
                limit,
                after,
            })
            .await?;
        Ok(extract_listing(&data))
    }

    async fn invoke_list_subreddit_new(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let subreddit = require_str(input, "subreddit")?;
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let after = input.get("after").and_then(|v| v.as_str());
        let data = client.list_subreddit_new(subreddit, limit, after).await?;
        Ok(extract_listing(&data))
    }

    async fn invoke_get_post_thread(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let post_fullname = require_str(input, "post_fullname")?;
        let sort = input.get("sort").and_then(|v| v.as_str());
        let comment_limit = input
            .get("comment_limit")
            .and_then(serde_json::Value::as_i64);
        let data = client
            .get_post_thread(post_fullname, sort, comment_limit)
            .await?;
        // Reddit returns an array of two listings: [post_listing, comments_listing]
        Ok(data.as_array().map_or_else(
            || json!({ "post": data, "comments": [] }),
            |arr| {
                let post = arr.first().cloned().unwrap_or(json!(null));
                let comments = arr.get(1).cloned().unwrap_or(json!(null));
                json!({ "post": post, "comments": comments })
            },
        ))
    }

    async fn invoke_create_post(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let subreddit = require_str(input, "subreddit")?;
        let kind = require_str(input, "kind")?;
        let title = require_str(input, "title")?;
        let text = input.get("text").and_then(|v| v.as_str());
        let url = input.get("url").and_then(|v| v.as_str());
        let nsfw = input
            .get("nsfw")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let spoiler = input
            .get("spoiler")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        client
            .create_post(&client::CreatePostParams {
                subreddit,
                kind,
                title,
                text,
                url,
                nsfw,
                spoiler,
            })
            .await
    }

    async fn invoke_create_comment(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let parent_fullname = require_str(input, "parent_fullname")?;
        let text = require_str(input, "text")?;
        client.create_comment(parent_fullname, text).await
    }

    async fn invoke_send_message(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let recipient = require_str(input, "recipient")?;
        let subject = require_str(input, "subject")?;
        let message = require_str(input, "message")?;
        client.send_message(recipient, subject, message).await
    }

    async fn invoke_mod_remove(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let thing_fullname = require_str(input, "thing_fullname")?;
        let spam = input
            .get("spam")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let data = client.mod_remove(thing_fullname, spam).await?;
        // Reddit returns empty on success
        Ok(json!({ "removed": true, "raw": data }))
    }

    async fn invoke_download_media(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let url = require_str(input, "url")?;
        let max_bytes = input.get("max_bytes").and_then(serde_json::Value::as_i64);
        client.download_media(url, max_bytes).await
    }

    async fn invoke_stream_subreddit_new(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        // Single-poll implementation: fetch new posts and return as events
        let subreddit = require_str(input, "subreddit")?;
        let batch_limit = input.get("batch_limit").and_then(serde_json::Value::as_i64);
        let data = client
            .list_subreddit_new(subreddit, batch_limit, None)
            .await?;
        let listing = extract_listing(&data);
        let events = listing.get("posts").cloned().unwrap_or_else(|| json!([]));
        let next_checkpoint = listing.get("next_after").cloned().unwrap_or(json!(null));
        Ok(json!({ "events": events, "next_checkpoint": next_checkpoint }))
    }

    async fn invoke_subreddit_get(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let subreddit = require_str(input, "subreddit")?;
        client.get_subreddit(subreddit).await
    }

    async fn invoke_subreddit_search(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let query = require_str(input, "query")?;
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let after = input.get("after").and_then(|v| v.as_str());
        let data = client.search_subreddits(query, limit, after).await?;
        Ok(extract_listing(&data))
    }

    async fn invoke_user_posts(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let username = require_str(input, "username")?;
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let sort = input.get("sort").and_then(|v| v.as_str());
        let after = input.get("after").and_then(|v| v.as_str());
        let data = client.get_user_posts(username, limit, sort, after).await?;
        Ok(extract_listing(&data))
    }

    async fn invoke_user_comments(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let username = require_str(input, "username")?;
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let sort = input.get("sort").and_then(|v| v.as_str());
        let after = input.get("after").and_then(|v| v.as_str());
        let data = client
            .get_user_comments(username, limit, sort, after)
            .await?;
        Ok(extract_listing(&data))
    }

    async fn invoke_edit_content(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let thing_fullname = require_str(input, "thing_fullname")?;
        let text = require_str(input, "text")?;
        client.edit_content(thing_fullname, text).await
    }

    async fn invoke_delete_content(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let thing_fullname = require_str(input, "thing_fullname")?;
        let data = client.delete_content(thing_fullname).await?;
        Ok(json!({ "deleted": true, "raw": data }))
    }

    async fn invoke_saved_list(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let username = require_str(input, "username")?;
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let after = input.get("after").and_then(|v| v.as_str());
        let data = client.get_saved(username, limit, after).await?;
        Ok(extract_listing(&data))
    }

    async fn invoke_saved_save(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let thing_fullname = require_str(input, "thing_fullname")?;
        let data = client.save_thing(thing_fullname).await?;
        Ok(json!({ "saved": true, "raw": data }))
    }

    async fn invoke_saved_unsave(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let thing_fullname = require_str(input, "thing_fullname")?;
        let data = client.unsave_thing(thing_fullname).await?;
        Ok(json!({ "unsaved": true, "raw": data }))
    }

    async fn invoke_mod_queue(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let subreddit = require_str(input, "subreddit")?;
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let after = input.get("after").and_then(|v| v.as_str());
        let data = client.get_mod_queue(subreddit, limit, after).await?;
        Ok(extract_listing(&data))
    }

    async fn invoke_mod_approve(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let thing_fullname = require_str(input, "thing_fullname")?;
        let data = client.mod_approve(thing_fullname).await?;
        Ok(json!({ "approved": true, "raw": data }))
    }

    async fn invoke_inbox_list(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let category = input
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("inbox");
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let after = input.get("after").and_then(|v| v.as_str());
        let data = client.get_inbox(category, limit, after).await?;
        Ok(extract_listing(&data))
    }

    async fn invoke_inbox_mark_read(
        &self,
        client: &RedditClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, RedditError> {
        let fullnames_val = input.get("fullnames").ok_or_else(|| RedditError::Api {
            status_code: 400,
            message: "Missing required field: fullnames".into(),
        })?;
        let fullnames_arr = fullnames_val.as_array().ok_or_else(|| RedditError::Api {
            status_code: 400,
            message: "fullnames must be an array of strings".into(),
        })?;
        let fullnames: Vec<&str> = fullnames_arr.iter().filter_map(|v| v.as_str()).collect();
        let data = client.mark_messages_read(&fullnames).await?;
        Ok(json!({ "marked_read": true, "raw": data }))
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "reddit.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Reddit self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }
}

/// Build the provisioning recipe for the Reddit connector.
///
/// Uses `OAuth2` Authorization Code with PKCE (Reddit supports this natively).
/// Scopes cover read-only research plus optional posting/messaging/moderation.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("reddit.oauth2_pkce"),
        "1",
        "Provision Reddit connector with OAuth2 Authorization Code + PKCE",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("oauth_authorize"),
        ProvisioningStepType::Oauth {
            flow: OAuthRecipe::AuthorizationCodePkce {
                authorization_url: "https://www.reddit.com/api/v1/authorize".into(),
                token_url: "https://www.reddit.com/api/v1/access_token".into(),
                scopes: vec![
                    "read".into(),
                    "identity".into(),
                    "history".into(),
                    "mysubreddits".into(),
                    "submit".into(),
                    "privatemessages".into(),
                ],
                auto_browser: true,
                callback_port: 8484,
            },
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_token"),
            ProvisioningStepType::StoreSecret {
                key: "bearer_token".into(),
                value_from: StepId::new("oauth_authorize"),
                scope: "connector:fcp.reddit".into(),
            },
        )
        .depends_on(StepId::new("oauth_authorize")),
    )
}

fn base_url_policy(base_url: &str) -> (bool, String) {
    let parsed = match Url::parse(base_url) {
        Ok(parsed) => parsed,
        Err(error) => {
            return (false, format!("base_url could not be parsed: {error}"));
        }
    };

    let Some(host) = parsed.host_str() else {
        return (false, "base_url must include a host".into());
    };

    let local = is_local_test_host(host);
    let allowed_host = host.eq_ignore_ascii_case("oauth.reddit.com")
        || host.eq_ignore_ascii_case("www.reddit.com")
        || local;
    let secure_or_local = parsed.scheme() == "https" || local;

    if allowed_host && secure_or_local {
        (
            true,
            format!("Endpoint accepted by policy checks: {base_url}"),
        )
    } else {
        (
            false,
            format!(
                "Endpoint must use https and oauth.reddit.com or www.reddit.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, RedditError> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RedditError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Extract posts and pagination from a `Reddit` listing response.
fn extract_listing(data: &serde_json::Value) -> serde_json::Value {
    let children = data
        .get("data")
        .and_then(|d| d.get("children"))
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    let posts: Vec<serde_json::Value> = children
        .into_iter()
        .filter_map(|c| c.get("data").cloned())
        .collect();
    let next_after = data
        .get("data")
        .and_then(|d| d.get("after"))
        .cloned()
        .unwrap_or(json!(null));
    json!({ "posts": posts, "next_after": next_after })
}

fn operations_info() -> serde_json::Value {
    json!([
        { "id": "reddit.search_posts", "summary": "Search Reddit posts", "capability": "reddit.search", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" },
        { "id": "reddit.list_subreddit_new", "summary": "List newest posts from a subreddit", "capability": "reddit.read", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" },
        { "id": "reddit.get_post_thread", "summary": "Fetch a post and its comment tree", "capability": "reddit.read", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" },
        { "id": "reddit.create_post", "summary": "Submit a new Reddit post", "capability": "reddit.post", "risk_level": "high", "safety_tier": "dangerous", "idempotency": "best_effort" },
        { "id": "reddit.create_comment", "summary": "Add a comment to a post or comment", "capability": "reddit.comment", "risk_level": "medium", "safety_tier": "risky", "idempotency": "best_effort" },
        { "id": "reddit.send_message", "summary": "Send a private message", "capability": "reddit.message", "risk_level": "high", "safety_tier": "dangerous", "idempotency": "best_effort" },
        { "id": "reddit.mod_remove", "summary": "Remove a post or comment (mod action)", "capability": "reddit.moderate", "risk_level": "high", "safety_tier": "dangerous", "idempotency": "strict" },
        { "id": "reddit.download_media", "summary": "Download media from Reddit hosts", "capability": "reddit.media.read", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" },
        { "id": "reddit.stream_subreddit_new", "summary": "Poll new subreddit posts as event stream", "capability": "reddit.stream", "risk_level": "medium", "safety_tier": "risky", "idempotency": "none" },
        { "id": "reddit.subreddit.get", "summary": "Get subreddit metadata", "capability": "reddit.read", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" },
        { "id": "reddit.subreddit.search", "summary": "Search for subreddits", "capability": "reddit.search", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" },
        { "id": "reddit.user.posts", "summary": "List a user's post history", "capability": "reddit.read", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" },
        { "id": "reddit.user.comments", "summary": "List a user's comment history", "capability": "reddit.read", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" },
        { "id": "reddit.edit_content", "summary": "Edit the text of a post or comment", "capability": "reddit.post", "risk_level": "medium", "safety_tier": "risky", "idempotency": "best_effort" },
        { "id": "reddit.delete_content", "summary": "Delete a post or comment", "capability": "reddit.post", "risk_level": "high", "safety_tier": "dangerous", "idempotency": "strict" },
        { "id": "reddit.saved.list", "summary": "List saved posts and comments", "capability": "reddit.read", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" },
        { "id": "reddit.saved.save", "summary": "Save a post or comment", "capability": "reddit.post", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" },
        { "id": "reddit.saved.unsave", "summary": "Unsave a post or comment", "capability": "reddit.post", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" },
        { "id": "reddit.mod.queue", "summary": "List the moderation queue", "capability": "reddit.moderate", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" },
        { "id": "reddit.mod.approve", "summary": "Approve a flagged item", "capability": "reddit.moderate", "risk_level": "medium", "safety_tier": "risky", "idempotency": "strict" },
        { "id": "reddit.inbox.list", "summary": "List inbox messages and mentions", "capability": "reddit.message", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" },
        { "id": "reddit.inbox.mark_read", "summary": "Mark messages as read", "capability": "reddit.message", "risk_level": "low", "safety_tier": "safe", "idempotency": "strict" },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_bearer_token() {
        let config = RedditConfig::from_params(&json!({ "bearer_token": "test-tok" })).unwrap();
        assert!(matches!(config.auth, RedditAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = RedditConfig::from_params(
            &json!({ "credential_id": "550e8400-e29b-41d4-a716-446655440000" }),
        )
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_rejects_both() {
        let result = RedditConfig::from_params(
            &json!({ "bearer_token": "tok", "credential_id": "550e8400-e29b-41d4-a716-446655440000" }),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("exactly one")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_rejects_none() {
        let result = RedditConfig::from_params(&json!({}));
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("Missing")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_rejects_empty_token() {
        assert!(RedditConfig::from_params(&json!({ "bearer_token": "" })).is_err());
    }

    #[test]
    fn config_rejects_whitespace_only_token() {
        assert!(RedditConfig::from_params(&json!({ "bearer_token": "   " })).is_err());
    }

    #[test]
    fn config_trims_token() {
        let config = RedditConfig::from_params(&json!({ "bearer_token": "  my-token  " })).unwrap();
        match &config.auth {
            RedditAuth::BearerToken(t) => assert_eq!(t, "my-token"),
            RedditAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn config_custom_base_url() {
        let config = RedditConfig::from_params(&json!({
            "bearer_token": "tok",
            "base_url": "https://custom.reddit.example/api"
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://custom.reddit.example/api");
    }

    #[test]
    fn config_rejects_invalid_credential_id() {
        let result = RedditConfig::from_params(&json!({ "credential_id": "not-a-uuid" }));
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("UUID")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = RedditConfig::from_params(&json!({ "credential_id": 42 }));
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("string")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    // ── DoctorResult ─────────────────────────────────────────────────

    #[test]
    fn doctor_result_healthy() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_degraded_non_critical_fails() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("warn".into()),
                critical: false,
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_result_unhealthy_critical_fails() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: false,
            message: Some("down".into()),
            critical: true,
        }]);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_unhealthy_overrides_degraded() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: None,
                critical: false,
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_empty_checks_is_healthy() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_serializes() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "config".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "healthy");
        assert!(v["checks"][0]["message"].is_null());
    }

    // ── require_str ──────────────────────────────────────────────────

    #[test]
    fn require_str_present() {
        let input = json!({ "query": "rust" });
        assert_eq!(require_str(&input, "query").unwrap(), "rust");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        let err = require_str(&input, "query").unwrap_err();
        match err {
            RedditError::Api {
                status_code,
                message,
            } => {
                assert_eq!(status_code, 400);
                assert!(message.contains("query"));
            }
            _ => panic!("expected Api error"),
        }
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({ "query": 42 });
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({ "query": null });
        assert!(require_str(&input, "query").is_err());
    }

    // ── extract_listing ──────────────────────────────────────────────

    #[test]
    fn extract_listing_basic() {
        let data = json!({
            "data": {
                "children": [
                    {"kind": "t3", "data": {"name": "t3_abc", "title": "Hello"}},
                    {"kind": "t3", "data": {"name": "t3_def", "title": "World"}}
                ],
                "after": "t3_def"
            }
        });
        let result = extract_listing(&data);
        assert_eq!(result["posts"].as_array().unwrap().len(), 2);
        assert_eq!(result["next_after"], "t3_def");
    }

    #[test]
    fn extract_listing_empty() {
        let data = json!({ "data": { "children": [], "after": null } });
        let result = extract_listing(&data);
        assert!(result["posts"].as_array().unwrap().is_empty());
        assert!(result["next_after"].is_null());
    }

    #[test]
    fn extract_listing_no_data() {
        let data = json!({});
        let result = extract_listing(&data);
        assert!(result["posts"].as_array().unwrap().is_empty());
        assert!(result["next_after"].is_null());
    }

    #[test]
    fn extract_listing_children_without_data() {
        let data = json!({
            "data": {
                "children": [{"kind": "t3"}],
                "after": null
            }
        });
        let result = extract_listing(&data);
        assert!(result["posts"].as_array().unwrap().is_empty());
    }

    // ── operations_info ──────────────────────────────────────────────

    #[test]
    fn operations_info_has_22_operations() {
        assert_eq!(operations_info().as_array().unwrap().len(), 22);
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.to_ascii_lowercase().ends_with(".read") {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "read op {} should be safe",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn all_operations_have_required_fields() {
        let required = [
            "id",
            "summary",
            "capability",
            "risk_level",
            "safety_tier",
            "idempotency",
        ];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            for field in &required {
                assert!(
                    op.get(field).is_some(),
                    "op {:?} missing field {field}",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_have_valid_risk_levels() {
        let valid = ["low", "medium", "high", "critical"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let level = op["risk_level"].as_str().unwrap();
            assert!(
                valid.contains(&level),
                "invalid risk_level {level} for {:?}",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_have_valid_safety_tiers() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let tier = op["safety_tier"].as_str().unwrap();
            assert!(
                valid.contains(&tier),
                "invalid safety_tier {tier} for {:?}",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        let expected = [
            "reddit.search_posts",
            "reddit.list_subreddit_new",
            "reddit.get_post_thread",
            "reddit.create_post",
            "reddit.create_comment",
            "reddit.send_message",
            "reddit.mod_remove",
            "reddit.download_media",
            "reddit.stream_subreddit_new",
            "reddit.subreddit.get",
            "reddit.subreddit.search",
            "reddit.user.posts",
            "reddit.user.comments",
            "reddit.edit_content",
            "reddit.delete_content",
            "reddit.saved.list",
            "reddit.saved.save",
            "reddit.saved.unsave",
            "reddit.mod.queue",
            "reddit.mod.approve",
            "reddit.inbox.list",
            "reddit.inbox.mark_read",
        ];
        for e in &expected {
            assert!(ids.contains(e), "missing expected operation {e}");
        }
    }

    // ── Connector default ────────────────────────────────────────────

    #[test]
    fn connector_default() {
        let c = RedditConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    // ── DoctorStatus serde ──────────────────────────────────────────

    #[test]
    fn doctor_status_healthy_serde() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let ds: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(ds, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_status_degraded_serde() {
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let ds: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(ds, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_status_unhealthy_serde() {
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
        let ds: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(ds, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_eq() {
        assert_eq!(DoctorStatus::Healthy, DoctorStatus::Healthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_status_copy() {
        let s = DoctorStatus::Healthy;
        let s2 = s;
        assert_eq!(s, s2);
    }

    // ── DoctorCheck serde ───────────────────────────────────────────

    #[test]
    fn doctor_check_skip_none_message() {
        let c = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_check_includes_some_message() {
        let c = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("fail".into()),
            critical: true,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["message"], "fail");
    }

    #[test]
    fn doctor_check_roundtrip() {
        let c = DoctorCheck {
            name: "cfg".into(),
            passed: true,
            message: None,
            critical: true,
        };
        let v = serde_json::to_value(&c).unwrap();
        let c2: DoctorCheck = serde_json::from_value(v).unwrap();
        assert_eq!(c2.name, "cfg");
        assert!(c2.passed);
        assert!(c2.critical);
    }

    // ── DoctorResult serde ──────────────────────────────────────────

    #[test]
    fn doctor_result_roundtrip() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        let r2: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r2.status, DoctorStatus::Healthy);
        assert_eq!(r2.checks.len(), 1);
    }

    // ── extract_listing edge cases ──────────────────────────────────

    #[test]
    fn extract_listing_null_after() {
        let data = json!({
            "data": { "children": [{"kind": "t3", "data": {"name": "t3_x"}}], "after": null }
        });
        let result = extract_listing(&data);
        assert!(result["next_after"].is_null());
        assert_eq!(result["posts"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn extract_listing_string_after() {
        let data = json!({
            "data": { "children": [], "after": "t3_cursor" }
        });
        let result = extract_listing(&data);
        assert_eq!(result["next_after"], "t3_cursor");
    }

    // ── require_str edge cases ──────────────────────────────────────

    #[test]
    fn require_str_empty_string() {
        let input = json!({"query": ""});
        // Empty string is a valid string, should succeed
        assert_eq!(require_str(&input, "query").unwrap(), "");
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"flag": true});
        assert!(require_str(&input, "flag").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"items": [1, 2, 3]});
        assert!(require_str(&input, "items").is_err());
    }

    // ── Config edge cases ───────────────────────────────────────────

    #[test]
    fn config_default_base_url() {
        let config = RedditConfig::from_params(&json!({ "bearer_token": "tok" })).unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_error_both_message_content() {
        let result = RedditConfig::from_params(&json!({
            "bearer_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }));
        match result.unwrap_err() {
            FcpError::InvalidRequest { code, .. } => assert_eq!(code, 1003),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_error_none_message_content() {
        let result = RedditConfig::from_params(&json!({}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { code, .. } => assert_eq!(code, 1003),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    // ── operations_info edge cases ──────────────────────────────────

    #[test]
    fn operations_search_is_idempotent() {
        let ops = operations_info();
        let search_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "reddit.search_posts")
            .unwrap();
        assert_eq!(search_op["idempotency"], "strict");
    }

    #[test]
    fn operations_create_post_is_dangerous() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "reddit.create_post")
            .unwrap();
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["risk_level"], "high");
    }

    #[test]
    fn operations_stream_is_risky() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "reddit.stream_subreddit_new")
            .unwrap();
        assert_eq!(op["safety_tier"], "risky");
    }

    #[test]
    fn operations_all_prefixed_reddit() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(id.starts_with("reddit."), "op {id} missing reddit. prefix");
        }
    }

    #[test]
    fn operations_valid_idempotency_values() {
        let valid = ["strict", "best_effort", "none"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let idem = op["idempotency"].as_str().unwrap();
            assert!(
                valid.contains(&idem),
                "invalid idempotency {idem} for {:?}",
                op["id"]
            );
        }
    }

    #[test]
    fn extract_listing_preserves_post_data_fields() {
        let data = json!({
            "data": {
                "children": [
                    {"kind": "t3", "data": {"name": "t3_test", "title": "My Title", "score": 42}}
                ],
                "after": null
            }
        });
        let result = extract_listing(&data);
        let posts = result["posts"].as_array().unwrap();
        assert_eq!(posts[0]["title"], "My Title");
        assert_eq!(posts[0]["score"], 42);
    }

    #[test]
    fn extract_listing_multiple_post_types() {
        let data = json!({
            "data": {
                "children": [
                    {"kind": "t3", "data": {"name": "t3_a"}},
                    {"kind": "t1", "data": {"name": "t1_b"}},
                    {"kind": "t3", "data": {"name": "t3_c"}}
                ],
                "after": "t3_c"
            }
        });
        let result = extract_listing(&data);
        assert_eq!(result["posts"].as_array().unwrap().len(), 3);
        assert_eq!(result["next_after"], "t3_c");
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"field": 1.23});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_nested_object() {
        let input = json!({"field": {"nested": "value"}});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn doctor_result_single_non_critical_pass() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "optional".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        assert_eq!(r.status, DoctorStatus::Healthy);
        assert_eq!(r.checks.len(), 1);
    }

    #[test]
    fn doctor_check_clone() {
        let c = DoctorCheck {
            name: "clonetest".into(),
            passed: true,
            message: Some("msg".into()),
            critical: false,
        };
        let c2 = c.clone();
        assert_eq!(c.name, "clonetest");
        assert_eq!(c2.message, Some("msg".into()));
    }

    #[test]
    fn doctor_check_debug() {
        let c = DoctorCheck {
            name: "dbgcheck".into(),
            passed: false,
            message: None,
            critical: true,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("dbgcheck"));
    }

    #[test]
    fn operations_mod_remove_is_dangerous() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "reddit.mod_remove")
            .unwrap();
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["risk_level"], "high");
    }

    #[test]
    fn operations_download_media_is_safe() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "reddit.download_media")
            .unwrap();
        assert_eq!(op["safety_tier"], "safe");
        assert_eq!(op["risk_level"], "low");
    }

    // ── Provisioning tests ────────────────────────────────────────

    #[test]
    fn provisioning_readiness_bearer_token_mode() {
        let config = RedditConfig::from_params(&json!({
            "bearer_token": "test-token",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "bearer_token");
        assert!(readiness.token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
        assert_eq!(readiness.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = RedditConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.token_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = RedditConfig::from_params(&json!({
            "bearer_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "bearer_token");
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_recipe_has_2_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "reddit.oauth2_pkce");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 2);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "oauth_authorize");
        assert_eq!(recipe.steps[1].id.as_str(), "store_token");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "oauth_authorize");
    }

    #[test]
    fn provisioning_recipe_oauth_has_scopes() {
        let recipe = provisioning_recipe();
        match &recipe.steps[0].kind {
            ProvisioningStepType::Oauth {
                flow: OAuthRecipe::AuthorizationCodePkce { scopes, .. },
            } => {
                assert!(scopes.contains(&"read".to_string()));
                assert!(scopes.contains(&"identity".to_string()));
                assert!(scopes.contains(&"history".to_string()));
                assert!(scopes.contains(&"mysubreddits".to_string()));
                assert!(scopes.contains(&"submit".to_string()));
                assert!(scopes.contains(&"privatemessages".to_string()));
                assert_eq!(scopes.len(), 6);
            }
            other => panic!("expected Oauth AuthorizationCodePkce, got {other:?}"),
        }
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "reddit.oauth2_pkce");
        assert!(v["steps"].as_array().unwrap().len() == 2);
    }

    #[test]
    fn base_url_policy_accepts_oauth_reddit_https() {
        let (ok, message) = base_url_policy("https://oauth.reddit.com");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_www_reddit_https() {
        let (ok, message) = base_url_policy("https://www.reddit.com");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:8080");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_127_0_0_1() {
        let (ok, _) = base_url_policy("http://127.0.0.1:9090");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_http_non_local() {
        let (ok, message) = base_url_policy("http://oauth.reddit.com");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("oauth.reddit.com"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = RedditConfig::from_params(&json!({
            "bearer_token": "tok",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("oauth.reddit.com"));
    }
}
