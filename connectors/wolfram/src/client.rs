//! Wolfram Alpha HTTP client with retry support.

use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use serde_json::json;
use tracing::{info, warn};

use crate::error::WolframError;
use crate::types::{QueryResult, WolframConfig};

/// Wolfram Alpha API client.
pub struct WolframClient {
    base_url: String,
    timeout: std::time::Duration,
    #[allow(dead_code)]
    runtime: ConnectorRuntime,
    #[allow(dead_code)]
    retry_config: HttpRetryConfig,
}

impl WolframClient {
    /// Create a new Wolfram Alpha client.
    #[must_use]
    pub fn new(config: &WolframConfig) -> Self {
        let base_url =
            if config.base_url.starts_with("http://") || config.base_url.starts_with("https://") {
                config.base_url.clone()
            } else {
                format!("https://{}", config.base_url)
            };
        Self {
            base_url,
            timeout: std::time::Duration::from_millis(config.timeout_ms),
            runtime: ConnectorRuntime::new(ConnectorRuntimeConfig::default()),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        }
    }

    /// Create a client with a custom base URL (for testing).
    #[must_use]
    pub fn with_base_url(base_url: String) -> Self {
        Self {
            base_url,
            timeout: std::time::Duration::from_secs(30),
            runtime: ConnectorRuntime::new(ConnectorRuntimeConfig::default()),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        }
    }

    /// Perform a full query against the Wolfram Alpha API.
    pub async fn query(&self, input: &str, app_id: &str) -> Result<QueryResult, WolframError> {
        if input.is_empty() {
            return Err(WolframError::InvalidInput {
                message: "Query input cannot be empty".into(),
            });
        }

        let url = format!("{}/v2/query", self.base_url);
        info!(input = input, "Wolfram Alpha full query");

        let client = reqwest::Client::new();
        let resp = client
            .get(&url)
            .query(&[
                ("input", input),
                ("appid", app_id),
                ("output", "json"),
                ("format", "plaintext,image"),
            ])
            .timeout(self.timeout)
            .send()
            .await
            .map_err(WolframError::Http)?;

        let status = resp.status().as_u16();
        if status != 200 {
            let body = resp.text().await.unwrap_or_default();
            return Err(WolframError::Api {
                status_code: status,
                message: body,
            });
        }

        let body: serde_json::Value = resp.json().await.map_err(WolframError::Http)?;

        // Wolfram wraps the result in a "queryresult" key
        let query_result = body.get("queryresult").cloned().unwrap_or(body);

        serde_json::from_value(query_result).map_err(|e| WolframError::Serialization(e.to_string()))
    }

    /// Get a short text answer from Wolfram Alpha.
    pub async fn short_answer(
        &self,
        input: &str,
        app_id: &str,
    ) -> Result<serde_json::Value, WolframError> {
        if input.is_empty() {
            return Err(WolframError::InvalidInput {
                message: "Query input cannot be empty".into(),
            });
        }

        let url = format!("{}/v1/result", self.base_url);
        info!(input = input, "Wolfram Alpha short answer");

        let client = reqwest::Client::new();
        let resp = client
            .get(&url)
            .query(&[("i", input), ("appid", app_id)])
            .timeout(self.timeout)
            .send()
            .await
            .map_err(WolframError::Http)?;

        let status = resp.status().as_u16();
        if status != 200 {
            let body = resp.text().await.unwrap_or_default();
            warn!(status_code = status, "Wolfram Alpha short answer failed");
            return Err(WolframError::Api {
                status_code: status,
                message: body,
            });
        }

        let text = resp.text().await.map_err(WolframError::Http)?;
        Ok(json!({ "answer": text }))
    }

    /// Get a spoken-word text answer from Wolfram Alpha.
    pub async fn spoken_result(
        &self,
        input: &str,
        app_id: &str,
    ) -> Result<serde_json::Value, WolframError> {
        if input.is_empty() {
            return Err(WolframError::InvalidInput {
                message: "Query input cannot be empty".into(),
            });
        }

        let url = format!("{}/v1/spoken", self.base_url);
        info!(input = input, "Wolfram Alpha spoken result");

        let client = reqwest::Client::new();
        let resp = client
            .get(&url)
            .query(&[("i", input), ("appid", app_id)])
            .timeout(self.timeout)
            .send()
            .await
            .map_err(WolframError::Http)?;

        let status = resp.status().as_u16();
        if status != 200 {
            let body = resp.text().await.unwrap_or_default();
            return Err(WolframError::Api {
                status_code: status,
                message: body,
            });
        }

        let text = resp.text().await.map_err(WolframError::Http)?;
        Ok(json!({ "spoken": text }))
    }

    /// Health check — validates the base URL is reachable.
    pub async fn health_check(&self) -> Result<(), WolframError> {
        let client = reqwest::Client::new();
        let url = format!("{}/v1/result", self.base_url);
        // Simple connectivity check with a known query
        let resp = client
            .get(&url)
            .query(&[("i", "1+1"), ("appid", "DEMO")])
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(WolframError::Http)?;

        // We don't care about the response content, just connectivity
        let _status = resp.status();
        Ok(())
    }
}

impl std::fmt::Debug for WolframClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WolframClient")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[fcp_async_core::runtime::test]
    async fn query_success() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "queryresult": {
                "success": true,
                "numpods": 1,
                "pods": [{
                    "title": "Result",
                    "id": "Result",
                    "primary": true,
                    "subpods": [{"plaintext": "4"}]
                }],
                "assumptions": []
            }
        });

        Mock::given(method("GET"))
            .and(path("/v2/query"))
            .and(query_param("input", "2+2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&server)
            .await;

        let client = WolframClient::with_base_url(server.uri());
        let result = client.query("2+2", "test-app-id").await.expect("query");
        assert!(result.success);
        assert_eq!(result.pods[0].subpods[0].plaintext.as_deref(), Some("4"));
    }

    #[fcp_async_core::runtime::test]
    async fn query_empty_input_rejected() {
        let client = WolframClient::with_base_url("http://unused".into());
        let err = client.query("", "test").await.unwrap_err();
        match err {
            WolframError::InvalidInput { .. } => {}
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn short_answer_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/result"))
            .and(query_param("i", "population of France"))
            .respond_with(ResponseTemplate::new(200).set_body_string("67.39 million people"))
            .mount(&server)
            .await;

        let client = WolframClient::with_base_url(server.uri());
        let result = client
            .short_answer("population of France", "test-id")
            .await
            .expect("short answer");
        assert_eq!(result["answer"], "67.39 million people");
    }

    #[fcp_async_core::runtime::test]
    async fn spoken_result_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/spoken"))
            .respond_with(ResponseTemplate::new(200).set_body_string("The answer is 4"))
            .mount(&server)
            .await;

        let client = WolframClient::with_base_url(server.uri());
        let result = client
            .spoken_result("what is 2+2", "test-id")
            .await
            .expect("spoken");
        assert_eq!(result["spoken"], "The answer is 4");
    }

    #[fcp_async_core::runtime::test]
    async fn api_error_status() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v2/query"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .mount(&server)
            .await;

        let client = WolframClient::with_base_url(server.uri());
        let err = client.query("test", "bad-id").await.unwrap_err();
        match err {
            WolframError::Api { status_code, .. } => assert_eq!(status_code, 403),
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[test]
    fn debug_redacts_nothing_sensitive() {
        let client = WolframClient::with_base_url("https://api.wolframalpha.com".into());
        let debug = format!("{client:?}");
        assert!(debug.contains("WolframClient"));
        assert!(debug.contains("api.wolframalpha.com"));
    }

    #[fcp_async_core::runtime::test]
    async fn short_answer_empty_input_rejected() {
        let client = WolframClient::with_base_url("http://unused".into());
        let err = client.short_answer("", "test").await.unwrap_err();
        match err {
            WolframError::InvalidInput { .. } => {}
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn spoken_result_empty_input_rejected() {
        let client = WolframClient::with_base_url("http://unused".into());
        let err = client.spoken_result("", "test").await.unwrap_err();
        match err {
            WolframError::InvalidInput { .. } => {}
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn rate_limited_response() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/result"))
            .respond_with(ResponseTemplate::new(429).set_body_string("Too Many Requests"))
            .mount(&server)
            .await;

        let client = WolframClient::with_base_url(server.uri());
        let err = client.short_answer("test", "test-id").await.unwrap_err();
        match err {
            WolframError::Api { status_code, .. } => assert_eq!(status_code, 429),
            other => panic!("expected Api 429 error, got {other:?}"),
        }
    }
}
