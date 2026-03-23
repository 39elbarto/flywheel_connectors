//! HTTP client for the Hue bridge API.

use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::{Value, json};

use crate::error::{HueError, HueResult};
use crate::types::HueConfig;

#[derive(Debug, Clone)]
pub struct HueClient {
    client: reqwest::Client,
    bridge_url: String,
    app_key: String,
}

impl HueClient {
    pub fn from_config(config: &HueConfig) -> HueResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.request_timeout_ms))
            .danger_accept_invalid_certs(config.allow_insecure_ssl)
            .build()?;
        Ok(Self {
            client,
            bridge_url: config.normalized_bridge_url(),
            app_key: config.app_key.clone(),
        })
    }

    #[must_use]
    pub fn bridge_url(&self) -> &str {
        &self.bridge_url
    }

    fn headers(&self) -> HueResult<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "hue-application-key",
            HeaderValue::from_str(&self.app_key)
                .map_err(|error| HueError::Config(error.to_string()))?,
        );
        Ok(headers)
    }

    async fn decode_response(response: reqwest::Response) -> HueResult<Value> {
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(HueError::Api {
                status: status.as_u16(),
                message: body,
            });
        }
        Ok(serde_json::from_str(&body).unwrap_or_else(|_| json!({ "body": body })))
    }

    pub async fn health(&self) -> HueResult<Value> {
        let response = self
            .client
            .get(format!("{}/clip/v2/resource/bridge", self.bridge_url))
            .headers(self.headers()?)
            .send()
            .await?;
        Self::decode_response(response).await
    }

    pub async fn list_lights(&self) -> HueResult<Value> {
        let response = self
            .client
            .get(format!("{}/clip/v2/resource/light", self.bridge_url))
            .headers(self.headers()?)
            .send()
            .await?;
        Self::decode_response(response).await
    }

    pub async fn list_scenes(&self) -> HueResult<Value> {
        let response = self
            .client
            .get(format!("{}/clip/v2/resource/scene", self.bridge_url))
            .headers(self.headers()?)
            .send()
            .await?;
        Self::decode_response(response).await
    }

    pub async fn set_light_state(
        &self,
        light_id: &str,
        on: bool,
        brightness: Option<f64>,
    ) -> HueResult<Value> {
        if light_id.trim().is_empty() {
            return Err(HueError::Config("light_id must not be empty".into()));
        }
        let mut body = json!({ "on": { "on": on } });
        if let Some(brightness) = brightness {
            body["dimming"] = json!({ "brightness": brightness });
        }
        let response = self
            .client
            .put(format!(
                "{}/clip/v2/resource/light/{}",
                self.bridge_url, light_id
            ))
            .headers(self.headers()?)
            .json(&body)
            .send()
            .await?;
        Self::decode_response(response).await
    }

    pub async fn recall_scene(&self, scene_id: &str) -> HueResult<Value> {
        if scene_id.trim().is_empty() {
            return Err(HueError::Config("scene_id must not be empty".into()));
        }
        let response = self
            .client
            .put(format!(
                "{}/clip/v2/resource/scene/{}",
                self.bridge_url, scene_id
            ))
            .headers(self.headers()?)
            .json(&json!({ "recall": { "action": "active" } }))
            .send()
            .await?;
        Self::decode_response(response).await
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[fcp_async_core::runtime::test]
    async fn list_lights_uses_hue_application_key_header() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/clip/v2/resource/light"))
            .and(header("hue-application-key", "app-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": [] })))
            .mount(&server)
            .await;

        let config = HueConfig::from_value(json!({
            "bridge_url": server.uri(),
            "app_key": "app-key"
        }))
        .expect("config should parse");
        let client = HueClient::from_config(&config).expect("client should build");
        let result = client.list_lights().await.expect("list should succeed");
        assert_eq!(result["data"], json!([]));
    }

    #[fcp_async_core::runtime::test]
    async fn set_light_state_sends_expected_payload() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/clip/v2/resource/light/light-1"))
            .and(body_json(json!({
                "on": { "on": true },
                "dimming": { "brightness": 50.0 }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": [] })))
            .mount(&server)
            .await;

        let config = HueConfig::from_value(json!({
            "bridge_url": server.uri(),
            "app_key": "app-key"
        }))
        .expect("config should parse");
        let client = HueClient::from_config(&config).expect("client should build");
        client
            .set_light_state("light-1", true, Some(50.0))
            .await
            .expect("set should succeed");
    }
}
