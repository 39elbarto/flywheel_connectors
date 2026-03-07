//! FCP `Reddit` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
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
        Ok(
            json!({ "connector_id": "fcp.reddit", "version": "0.1.0", "status": if self.config.is_some() { "ready" } else { "unconfigured" } }),
        )
    }

    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(
            json!({ "connector_id": "fcp.reddit", "version": "0.1.0", "operations": operations_info() }),
        )
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
    fn operations_info_has_9_operations() {
        assert_eq!(operations_info().as_array().unwrap().len(), 9);
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
}
