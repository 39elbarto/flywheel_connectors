//! HTTP client for Synology Chat webhook delivery.

use serde_json::{Value, json};

use crate::error::{SynologyChatError, SynologyChatResult};
use crate::types::SynologyChatConfig;

#[derive(Debug, Clone)]
pub struct SynologyChatClient {
    client: reqwest::Client,
    incoming_url: String,
}

impl SynologyChatClient {
    pub fn from_config(config: &SynologyChatConfig) -> SynologyChatResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.request_timeout_ms))
            .danger_accept_invalid_certs(config.allow_insecure_ssl)
            .build()?;
        Ok(Self {
            client,
            incoming_url: config.normalized_incoming_url(),
        })
    }

    #[must_use]
    pub fn incoming_url(&self) -> &str {
        &self.incoming_url
    }

    pub async fn send_message(
        &self,
        text: &str,
        user_id: Option<&str>,
        bot_name: Option<&str>,
    ) -> SynologyChatResult<Value> {
        if text.trim().is_empty() {
            return Err(SynologyChatError::Config(
                "text must not be empty".into(),
            ));
        }

        let mut body = json!({ "text": text });
        if let Some(user_id) = user_id {
            body["user_ids"] = json!([user_id]);
        }
        if let Some(bot_name) = bot_name {
            body["username"] = json!(bot_name);
        }

        let response = self.client.post(&self.incoming_url).json(&body).send().await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(SynologyChatError::Api {
                status: status.as_u16(),
                message: body,
            });
        }
        if body.trim().is_empty() {
            return Ok(json!({ "status": "ok" }));
        }
        serde_json::from_str(&body).or_else(|_| Ok(json!({ "status": "ok", "body": body })))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{body_json, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

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
        let result = client
            .send_message("hello", Some("123"), Some("Flywheel"))
            .await
            .expect("send should succeed");
        assert_eq!(result["success"], true);
    }
}

