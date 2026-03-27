//! HTTP client for Synology Chat webhook delivery.

use reqwest::header::RETRY_AFTER;
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::error::{SynologyChatError, SynologyChatResult};
use crate::types::{SynologyChatConfig, SynologyChatDeliveryTarget};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SynologyChatResponseKind {
    Empty,
    Json,
    Text,
}

#[derive(Debug, Clone, Serialize)]
pub struct SynologyChatDispatchResult {
    pub status: &'static str,
    pub http_status: u16,
    pub response_kind: SynologyChatResponseKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_body: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynologyChatMessageRequest {
    text: String,
    user_ids: Vec<String>,
    bot_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynologyChatPayload {
    payload: Map<String, Value>,
}

#[derive(Clone)]
pub struct SynologyChatClient {
    client: reqwest::Client,
    target: SynologyChatDeliveryTarget,
    incoming_url: String,
}

impl std::fmt::Debug for SynologyChatClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SynologyChatClient")
            .field("target", &self.target)
            .field("incoming_url", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl SynologyChatDispatchResult {
    /// # Panics
    ///
    /// Panics if the dispatch result cannot be serialized into JSON.
    #[must_use]
    pub fn into_json(self) -> Value {
        serde_json::to_value(self).expect("SynologyChatDispatchResult must serialize")
    }
}

impl SynologyChatMessageRequest {
    pub fn new(
        text: &str,
        user_ids: &[String],
        bot_name: Option<&str>,
    ) -> SynologyChatResult<Self> {
        if text.trim().is_empty() {
            return Err(SynologyChatError::InvalidInput(
                "text must not be empty".into(),
            ));
        }

        let mut normalized_user_ids = Vec::with_capacity(user_ids.len());
        for user_id in user_ids {
            let trimmed = user_id.trim();
            if trimmed.is_empty() {
                return Err(SynologyChatError::InvalidInput(
                    "user_ids must not contain empty strings".into(),
                ));
            }
            if !normalized_user_ids
                .iter()
                .any(|existing| existing == trimmed)
            {
                normalized_user_ids.push(trimmed.to_string());
            }
        }

        Ok(Self {
            text: text.to_string(),
            user_ids: normalized_user_ids,
            bot_name: bot_name
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string),
        })
    }

    #[must_use]
    pub fn as_payload(&self) -> Value {
        let mut body = json!({ "text": self.text });
        if !self.user_ids.is_empty() {
            body["user_ids"] = json!(self.user_ids);
        }
        if let Some(bot_name) = &self.bot_name {
            body["username"] = json!(bot_name);
        }
        body
    }
}

impl SynologyChatPayload {
    pub fn from_value(payload: &Value) -> SynologyChatResult<Self> {
        let object = payload.as_object().ok_or_else(|| {
            SynologyChatError::InvalidInput("payload must be a JSON object".into())
        })?;
        Ok(Self {
            payload: object.clone(),
        })
    }

    #[must_use]
    pub fn as_value(&self) -> Value {
        Value::Object(self.payload.clone())
    }
}

impl SynologyChatClient {
    pub fn from_config(config: &SynologyChatConfig) -> SynologyChatResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(
                config.request_timeout_ms(),
            ))
            .danger_accept_invalid_certs(config.allow_insecure_ssl())
            .build()?;
        Ok(Self {
            client,
            target: config.delivery_target(),
            incoming_url: config.normalized_incoming_url(),
        })
    }

    #[must_use]
    pub const fn target(&self) -> &SynologyChatDeliveryTarget {
        &self.target
    }

    pub async fn send_message(
        &self,
        request: &SynologyChatMessageRequest,
    ) -> SynologyChatResult<SynologyChatDispatchResult> {
        self.send_payload(&SynologyChatPayload::from_value(&request.as_payload())?)
            .await
    }

    pub async fn send_payload(
        &self,
        payload: &SynologyChatPayload,
    ) -> SynologyChatResult<SynologyChatDispatchResult> {
        let response = self
            .client
            .post(&self.incoming_url)
            .json(&payload.as_value())
            .send()
            .await?;
        self.normalize_response(response).await
    }

    async fn normalize_response(
        &self,
        response: reqwest::Response,
    ) -> SynologyChatResult<SynologyChatDispatchResult> {
        let status = response.status();
        let retry_after_ms = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_retry_after_ms);
        let body = response.text().await?;
        if !status.is_success() {
            return Err(SynologyChatError::Api {
                status: status.as_u16(),
                message: body,
                retry_after_ms,
            });
        }
        if body.trim().is_empty() {
            return Ok(SynologyChatDispatchResult {
                status: "ok",
                http_status: status.as_u16(),
                response_kind: SynologyChatResponseKind::Empty,
                body: None,
                raw_body: None,
            });
        }
        serde_json::from_str::<Value>(&body).map_or_else(
            |_| {
                Ok(SynologyChatDispatchResult {
                    status: "ok",
                    http_status: status.as_u16(),
                    response_kind: SynologyChatResponseKind::Text,
                    body: None,
                    raw_body: Some(body),
                })
            },
            |json_body| {
                Ok(SynologyChatDispatchResult {
                    status: "ok",
                    http_status: status.as_u16(),
                    response_kind: SynologyChatResponseKind::Json,
                    body: Some(json_body),
                    raw_body: None,
                })
            },
        )
    }
}

/// Stringify a JSON value that might be a string or integer.
fn stringify_json_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Normalize an inbound webhook payload into a stable event envelope.
///
/// This function converts a raw Synology Chat outgoing-webhook callback
/// into a [`NormalizedInboundEvent`] with stringified identifiers and
/// optional token verification.
///
/// # Token verification
///
/// If `configured_token` is `Some`, the payload's `token` field is compared
/// against it. The result is recorded in `token_verified`:
/// - `Some(true)` if tokens match
/// - `Some(false)` if tokens mismatch or payload token is missing
/// - `None` if no `configured_token` is provided (verification skipped)
pub fn normalize_inbound_event(
    payload: &crate::types::InboundWebhookPayload,
    configured_token: Option<&str>,
    raw: serde_json::Value,
) -> (
    crate::types::NormalizedInboundEvent,
    crate::types::TokenVerification,
) {
    use crate::types::{NormalizedInboundEvent, TokenVerification};

    let channel_id = payload.channel_id.as_ref().and_then(stringify_json_value);
    let sender_id = payload.user_id.as_ref().and_then(stringify_json_value);
    let timestamp = payload.timestamp.as_ref().and_then(stringify_json_value);
    let thread_id = payload.thread_id.as_ref().and_then(stringify_json_value);
    let is_threaded = thread_id
        .as_deref()
        .is_some_and(|tid| !tid.is_empty() && tid != "0");

    let (token_verified, verification) = match (configured_token, payload.token.as_deref()) {
        (Some(expected), Some(actual)) => {
            if expected == actual {
                (Some(true), TokenVerification::Verified)
            } else {
                (Some(false), TokenVerification::Mismatch)
            }
        }
        (Some(_), None) => (Some(false), TokenVerification::MissingFromPayload),
        (None, _) => (None, TokenVerification::NotConfigured),
    };

    let event = NormalizedInboundEvent {
        event_type: "inbound_webhook".to_string(),
        channel_id,
        channel_name: payload
            .channel_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string),
        sender_id,
        sender_name: payload
            .username
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string),
        text: payload
            .text
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string),
        timestamp,
        trigger_word: payload
            .trigger_word
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string),
        is_threaded,
        thread_id,
        file_url: payload
            .file_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string),
        token_verified,
        raw,
    };

    (event, verification)
}

fn parse_retry_after_ms(value: &str) -> Option<u64> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .map(|seconds| seconds.saturating_mul(1000))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{body_json, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[test]
    fn message_request_normalizes_inputs() {
        let request = SynologyChatMessageRequest::new(
            "hello",
            &[
                String::from(" 123 "),
                String::from("123"),
                String::from("456"),
            ],
            Some("  Flywheel "),
        )
        .expect("message request should parse");
        assert_eq!(
            request.as_payload(),
            json!({
                "text": "hello",
                "user_ids": ["123", "456"],
                "username": "Flywheel"
            })
        );
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_posts_expected_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_json(json!({
                "text": "hello",
                "user_ids": ["123"],
                "username": "Flywheel"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true
            })))
            .mount(&server)
            .await;

        let config = SynologyChatConfig::from_value(json!({
            "incoming_url": server.uri()
        }))
        .expect("config should parse");
        let client = SynologyChatClient::from_config(&config).expect("client should build");
        let request =
            SynologyChatMessageRequest::new("hello", &[String::from("123")], Some("Flywheel"))
                .expect("message request should build");
        let result = client
            .send_message(&request)
            .await
            .expect("send should succeed");
        assert_eq!(result.response_kind, SynologyChatResponseKind::Json);
        assert_eq!(result.body.expect("json body")["success"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn send_payload_posts_raw_json() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_json(json!({
                "text": "hello",
                "attachments": [{ "text": "card" }]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true
            })))
            .mount(&server)
            .await;

        let config = SynologyChatConfig::from_value(json!({
            "incoming_url": server.uri()
        }))
        .expect("config should parse");
        let client = SynologyChatClient::from_config(&config).expect("client should build");
        let payload = SynologyChatPayload::from_value(&json!({
            "text": "hello",
            "attachments": [{ "text": "card" }]
        }))
        .expect("payload should parse");
        let result = client
            .send_payload(&payload)
            .await
            .expect("payload send should succeed");
        assert_eq!(result.response_kind, SynologyChatResponseKind::Json);
        assert_eq!(result.body.expect("json body")["success"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn send_payload_returns_text_body_metadata() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("queued"))
            .mount(&server)
            .await;

        let config = SynologyChatConfig::from_value(json!({
            "incoming_url": server.uri()
        }))
        .expect("config should parse");
        let client = SynologyChatClient::from_config(&config).expect("client should build");
        let payload = SynologyChatPayload::from_value(&json!({ "text": "hello" }))
            .expect("payload should parse");
        let result = client
            .send_payload(&payload)
            .await
            .expect("payload send should succeed");
        assert_eq!(result.response_kind, SynologyChatResponseKind::Text);
        assert_eq!(result.raw_body.as_deref(), Some("queued"));
    }

    #[fcp_async_core::runtime::test]
    async fn server_error_preserves_retry_after_hint() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "7")
                    .set_body_string("slow down"),
            )
            .mount(&server)
            .await;

        let config = SynologyChatConfig::from_value(json!({
            "incoming_url": server.uri()
        }))
        .expect("config should parse");
        let client = SynologyChatClient::from_config(&config).expect("client should build");
        let payload = SynologyChatPayload::from_value(&json!({ "text": "hello" }))
            .expect("payload should parse");
        let error = client
            .send_payload(&payload)
            .await
            .expect_err("429 must surface as an API error");
        match error {
            SynologyChatError::Api {
                status,
                message,
                retry_after_ms,
            } => {
                assert_eq!(status, 429);
                assert_eq!(message, "slow down");
                assert_eq!(retry_after_ms, Some(7000));
            }
            other => panic!("expected Api, got {other:?}"),
        }
    }

    #[test]
    fn normalize_inbound_event_full_payload() {
        use crate::types::{InboundWebhookPayload, TokenVerification};

        let payload = InboundWebhookPayload {
            user_id: Some(json!(4)),
            username: Some("mikael".into()),
            post_id: Some(json!("146028888128")),
            channel_id: Some(json!(34)),
            channel_name: Some("Labb".into()),
            channel_type: Some(json!(1)),
            text: Some("Tjena".into()),
            timestamp: Some(json!("1646827836131")),
            token: Some("shared-secret".into()),
            trigger_word: Some("Tjena".into()),
            thread_id: Some(json!("0")),
            file_url: None,
        };

        let raw = serde_json::to_value(&json!({
            "user_id": 4, "username": "mikael", "text": "Tjena"
        }))
        .unwrap();

        let (event, verification) =
            normalize_inbound_event(&payload, Some("shared-secret"), raw.clone());

        assert_eq!(event.event_type, "inbound_webhook");
        assert_eq!(event.channel_id.as_deref(), Some("34"));
        assert_eq!(event.channel_name.as_deref(), Some("Labb"));
        assert_eq!(event.sender_id.as_deref(), Some("4"));
        assert_eq!(event.sender_name.as_deref(), Some("mikael"));
        assert_eq!(event.text.as_deref(), Some("Tjena"));
        assert_eq!(event.timestamp.as_deref(), Some("1646827836131"));
        assert_eq!(event.trigger_word.as_deref(), Some("Tjena"));
        assert!(!event.is_threaded);
        assert_eq!(event.thread_id.as_deref(), Some("0"));
        assert_eq!(event.token_verified, Some(true));
        assert_eq!(verification, TokenVerification::Verified);
    }

    #[test]
    fn normalize_inbound_event_token_mismatch() {
        use crate::types::{InboundWebhookPayload, TokenVerification};

        let payload = InboundWebhookPayload {
            user_id: Some(json!(4)),
            username: Some("mikael".into()),
            post_id: None,
            channel_id: Some(json!(34)),
            channel_name: None,
            channel_type: None,
            text: Some("Hello".into()),
            timestamp: None,
            token: Some("wrong-token".into()),
            trigger_word: None,
            thread_id: None,
            file_url: None,
        };

        let (event, verification) =
            normalize_inbound_event(&payload, Some("correct-token"), json!({}));

        assert_eq!(event.token_verified, Some(false));
        assert_eq!(verification, TokenVerification::Mismatch);
    }

    #[test]
    fn normalize_inbound_event_token_missing_from_payload() {
        use crate::types::{InboundWebhookPayload, TokenVerification};

        let payload = InboundWebhookPayload {
            user_id: None,
            username: None,
            post_id: None,
            channel_id: None,
            channel_name: None,
            channel_type: None,
            text: Some("Hello".into()),
            timestamp: None,
            token: None,
            trigger_word: None,
            thread_id: None,
            file_url: None,
        };

        let (event, verification) =
            normalize_inbound_event(&payload, Some("configured-token"), json!({}));

        assert_eq!(event.token_verified, Some(false));
        assert_eq!(verification, TokenVerification::MissingFromPayload);
    }

    #[test]
    fn normalize_inbound_event_no_configured_token() {
        use crate::types::{InboundWebhookPayload, TokenVerification};

        let payload = InboundWebhookPayload {
            user_id: Some(json!("user-99")),
            username: Some("alice".into()),
            post_id: None,
            channel_id: Some(json!("chan-1")),
            channel_name: Some("general".into()),
            channel_type: None,
            text: Some("Hi there".into()),
            timestamp: Some(json!(1646827836131_i64)),
            token: Some("some-token".into()),
            trigger_word: None,
            thread_id: None,
            file_url: None,
        };

        let (event, verification) = normalize_inbound_event(&payload, None, json!({}));

        assert_eq!(event.token_verified, None);
        assert_eq!(verification, TokenVerification::NotConfigured);
        assert_eq!(event.channel_id.as_deref(), Some("chan-1"));
        assert_eq!(event.sender_id.as_deref(), Some("user-99"));
    }

    #[test]
    fn normalize_inbound_event_minimal_payload() {
        use crate::types::{InboundWebhookPayload, TokenVerification};

        let payload = InboundWebhookPayload {
            user_id: None,
            username: None,
            post_id: None,
            channel_id: None,
            channel_name: None,
            channel_type: None,
            text: None,
            timestamp: None,
            token: None,
            trigger_word: None,
            thread_id: None,
            file_url: None,
        };

        let (event, verification) = normalize_inbound_event(&payload, None, json!({}));

        assert_eq!(event.event_type, "inbound_webhook");
        assert!(event.channel_id.is_none());
        assert!(event.channel_name.is_none());
        assert!(event.sender_id.is_none());
        assert!(event.sender_name.is_none());
        assert!(event.text.is_none());
        assert!(event.timestamp.is_none());
        assert!(!event.is_threaded);
        assert!(event.thread_id.is_none());
        assert!(event.token_verified.is_none());
        assert_eq!(verification, TokenVerification::NotConfigured);
    }

    #[test]
    fn normalize_inbound_event_threaded_message() {
        use crate::types::InboundWebhookPayload;

        let payload = InboundWebhookPayload {
            user_id: Some(json!(7)),
            username: Some("bob".into()),
            post_id: Some(json!("post-123")),
            channel_id: Some(json!(42)),
            channel_name: Some("dev".into()),
            channel_type: Some(json!(1)),
            text: Some("Reply in thread".into()),
            timestamp: Some(json!("1700000000000")),
            token: None,
            trigger_word: None,
            thread_id: Some(json!("thread-456")),
            file_url: Some("https://nas.local/file.pdf".into()),
        };

        let (event, _verification) = normalize_inbound_event(&payload, None, json!({}));

        assert!(event.is_threaded);
        assert_eq!(event.thread_id.as_deref(), Some("thread-456"));
        assert_eq!(
            event.file_url.as_deref(),
            Some("https://nas.local/file.pdf")
        );
        assert_eq!(event.text.as_deref(), Some("Reply in thread"));
    }

    #[test]
    fn normalize_inbound_event_trims_whitespace() {
        use crate::types::InboundWebhookPayload;

        let payload = InboundWebhookPayload {
            user_id: None,
            username: Some("  alice  ".into()),
            post_id: None,
            channel_id: None,
            channel_name: Some("  general  ".into()),
            channel_type: None,
            text: Some("  hello  ".into()),
            timestamp: None,
            token: None,
            trigger_word: Some("  hello  ".into()),
            thread_id: None,
            file_url: Some("  https://example.com/file  ".into()),
        };

        let (event, _) = normalize_inbound_event(&payload, None, json!({}));

        assert_eq!(event.sender_name.as_deref(), Some("alice"));
        assert_eq!(event.channel_name.as_deref(), Some("general"));
        assert_eq!(event.text.as_deref(), Some("hello"));
        assert_eq!(event.trigger_word.as_deref(), Some("hello"));
        assert_eq!(event.file_url.as_deref(), Some("https://example.com/file"));
    }

    #[test]
    fn normalize_inbound_event_empty_strings_become_none() {
        use crate::types::InboundWebhookPayload;

        let payload = InboundWebhookPayload {
            user_id: None,
            username: Some("".into()),
            post_id: None,
            channel_id: None,
            channel_name: Some("   ".into()),
            channel_type: None,
            text: Some("".into()),
            timestamp: None,
            token: None,
            trigger_word: Some("  ".into()),
            thread_id: None,
            file_url: Some("".into()),
        };

        let (event, _) = normalize_inbound_event(&payload, None, json!({}));

        assert!(event.sender_name.is_none());
        assert!(event.channel_name.is_none());
        assert!(event.text.is_none());
        assert!(event.trigger_word.is_none());
        assert!(event.file_url.is_none());
    }
}
