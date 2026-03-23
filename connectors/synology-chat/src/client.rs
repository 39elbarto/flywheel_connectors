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

#[derive(Debug, Clone, PartialEq)]
pub struct SynologyChatPayload {
    payload: Map<String, Value>,
}

#[derive(Debug, Clone)]
pub struct SynologyChatClient {
    client: reqwest::Client,
    target: SynologyChatDeliveryTarget,
    incoming_url: String,
}

impl SynologyChatDispatchResult {
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
    pub fn target(&self) -> &SynologyChatDeliveryTarget {
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
        match serde_json::from_str::<Value>(&body) {
            Ok(json_body) => Ok(SynologyChatDispatchResult {
                status: "ok",
                http_status: status.as_u16(),
                response_kind: SynologyChatResponseKind::Json,
                body: Some(json_body),
                raw_body: None,
            }),
            Err(_) => Ok(SynologyChatDispatchResult {
                status: "ok",
                http_status: status.as_u16(),
                response_kind: SynologyChatResponseKind::Text,
                body: None,
                raw_body: Some(body),
            }),
        }
    }
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
}
