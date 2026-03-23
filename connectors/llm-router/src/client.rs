//! HTTP client for LLM provider API calls.
//!
//! Provides [`LlmRouterClient`] which wraps `reqwest::Client` and
//! [`ConnectorRuntime`] for making authenticated requests to LLM
//! provider endpoints (OpenAI-compatible chat completions, etc.).

use std::time::Duration;

use reqwest::{Client, StatusCode};
use serde_json::json;
use tracing::debug;

use fcp_sdk::migration::{AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop};

use crate::error::{RouterError, RouterResult};
use crate::types::{ProviderAuth, ProviderConfig};

/// Validate a base URL to prevent path injection.
fn sanitize_base_url(url: &str) -> RouterResult<String> {
    let trimmed = url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(RouterError::ProviderError {
            provider: "unknown".into(),
            message: "base_url must not be empty".into(),
        });
    }
    if !trimmed.starts_with("https://") && !trimmed.starts_with("http://") {
        return Err(RouterError::ProviderError {
            provider: "unknown".into(),
            message: "base_url must start with http:// or https://".into(),
        });
    }
    Ok(trimmed.to_string())
}

/// HTTP client for making LLM provider API calls with retry support.
///
/// Each [`LlmRouterClient`] targets a single provider backend and handles
/// authentication header injection, request timeouts, and retry logic.
pub struct LlmRouterClient {
    client: Client,
    runtime: ConnectorRuntime,
    provider_name: String,
    base_url: String,
    auth: ProviderAuth,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for LlmRouterClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmRouterClient")
            .field("provider_name", &self.provider_name)
            .field("base_url", &self.base_url)
            .field("auth", &self.auth.redacted_label())
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

impl LlmRouterClient {
    /// Create a new client for the given provider configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the base URL is invalid or the HTTP client
    /// cannot be constructed.
    pub fn new(
        provider: &ProviderConfig,
        runtime: ConnectorRuntime,
        retry_config: HttpRetryConfig,
        request_timeout_ms: u64,
    ) -> RouterResult<Self> {
        let base_url = sanitize_base_url(&provider.base_url)?;

        let client = Client::builder()
            .timeout(Duration::from_millis(request_timeout_ms))
            .build()
            .map_err(|e| RouterError::ProviderError {
                provider: provider.name.clone(),
                message: format!("failed to build HTTP client: {e}"),
            })?;

        Ok(Self {
            client,
            runtime,
            provider_name: provider.name.clone(),
            base_url,
            auth: provider.auth.clone(),
            retry_config,
        })
    }

    /// Return the provider name this client targets.
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }

    /// Return the base URL for this provider.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Build a request with the provider's authentication header attached.
    fn authenticated_request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.client.request(method, url);
        match &self.auth {
            ProviderAuth::ApiKey(key) => {
                req = req.header("Authorization", format!("Bearer {key}"));
            }
            ProviderAuth::CredentialId(_cred_id) => {
                // Credential injection is handled by the egress proxy;
                // no Authorization header needed here.
            }
        }
        req
    }

    /// Send a chat completion request to the provider's OpenAI-compatible endpoint.
    ///
    /// # Arguments
    ///
    /// * `model` - The model identifier to use (e.g., "gpt-4", "claude-3-opus").
    /// * `messages` - Array of `{role, content}` message objects.
    /// * `max_tokens` - Maximum tokens to generate.
    /// * `temperature` - Optional sampling temperature.
    /// * `tools` - Optional tools/functions array for tool-use models.
    ///
    /// # Errors
    ///
    /// Returns an error if all retry attempts fail or the provider returns
    /// an unrecoverable error status.
    pub async fn chat_completion(
        &self,
        model: &str,
        messages: &[serde_json::Value],
        max_tokens: u64,
        temperature: Option<f64>,
        tools: Option<&[serde_json::Value]>,
    ) -> RouterResult<serde_json::Value> {
        let url = format!("{}/v1/chat/completions", self.base_url);
        let provider = self.provider_name.clone();

        let mut body = json!({
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
        });

        if let Some(temp) = temperature {
            body["temperature"] = json!(temp);
        }
        if let Some(t) = tools {
            if !t.is_empty() {
                body["tools"] = json!(t);
            }
        }

        debug!(
            provider = %provider,
            model = %model,
            url = %url,
            "Sending chat completion request"
        );

        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        let result = RetryLoop::execute(&ctx, &policy, |attempt| {
            let req = self
                .authenticated_request(reqwest::Method::POST, &url)
                .json(&body);
            let prov = provider.clone();

            async move {
                match req.send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        if status.is_success() {
                            match resp.json::<serde_json::Value>().await {
                                Ok(json) => AttemptOutcome::Success(json),
                                Err(e) => AttemptOutcome::Terminal(RouterError::ProviderError {
                                    provider: prov,
                                    message: format!("failed to parse response: {e}"),
                                }),
                            }
                        } else if status == StatusCode::TOO_MANY_REQUESTS
                            || status.is_server_error()
                        {
                            debug!(
                                attempt,
                                status = %status,
                                provider = %prov,
                                "Retryable provider error"
                            );
                            AttemptOutcome::Retryable {
                                error: RouterError::ProviderError {
                                    provider: prov,
                                    message: format!("HTTP {status}"),
                                },
                                retry_after: None,
                            }
                        } else {
                            AttemptOutcome::Terminal(RouterError::ProviderError {
                                provider: prov,
                                message: format!("HTTP {status}"),
                            })
                        }
                    }
                    Err(e) if e.is_timeout() || e.is_connect() => {
                        debug!(
                            attempt,
                            provider = %prov,
                            "Retryable network error: {e}"
                        );
                        AttemptOutcome::Retryable {
                            error: RouterError::ProviderError {
                                provider: prov,
                                message: format!("network error: {e}"),
                            },
                            retry_after: None,
                        }
                    }
                    Err(e) => AttemptOutcome::Terminal(RouterError::ProviderError {
                        provider: prov,
                        message: format!("request error: {e}"),
                    }),
                }
            }
        })
        .await;

        result
    }

    /// List available models from the provider's models endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn list_models(&self) -> RouterResult<serde_json::Value> {
        let url = format!("{}/v1/models", self.base_url);
        let provider = self.provider_name.clone();

        debug!(
            provider = %provider,
            url = %url,
            "Listing provider models"
        );

        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let req = self.authenticated_request(reqwest::Method::GET, &url);
            let prov = provider.clone();

            async move {
                match req.send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        if status.is_success() {
                            match resp.json::<serde_json::Value>().await {
                                Ok(json) => AttemptOutcome::Success(json),
                                Err(e) => AttemptOutcome::Terminal(RouterError::ProviderError {
                                    provider: prov,
                                    message: format!("failed to parse models response: {e}"),
                                }),
                            }
                        } else if status == StatusCode::TOO_MANY_REQUESTS
                            || status.is_server_error()
                        {
                            debug!(attempt, status = %status, "Retryable on list_models");
                            AttemptOutcome::Retryable {
                                error: RouterError::ProviderError {
                                    provider: prov,
                                    message: format!("HTTP {status}"),
                                },
                                retry_after: None,
                            }
                        } else {
                            AttemptOutcome::Terminal(RouterError::ProviderError {
                                provider: prov,
                                message: format!("HTTP {status}"),
                            })
                        }
                    }
                    Err(e) if e.is_timeout() || e.is_connect() => AttemptOutcome::Retryable {
                        error: RouterError::ProviderError {
                            provider: prov,
                            message: format!("network error: {e}"),
                        },
                        retry_after: None,
                    },
                    Err(e) => AttemptOutcome::Terminal(RouterError::ProviderError {
                        provider: prov,
                        message: format!("request error: {e}"),
                    }),
                }
            }
        })
        .await
    }

    /// Probe the provider endpoint for health/reachability.
    ///
    /// Returns `true` if the provider responds with a success or auth error
    /// (indicating the endpoint is reachable), `false` on network failure.
    pub async fn health_probe(&self) -> bool {
        let url = format!("{}/v1/models", self.base_url);

        match self
            .authenticated_request(reqwest::Method::GET, &url)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                // Even 401/403 means the endpoint is reachable
                !status.is_server_error()
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ModelCapability, ModelInfo};
    use fcp_sdk::migration::ConnectorRuntimeConfig;

    fn test_provider(name: &str, base_url: &str) -> ProviderConfig {
        ProviderConfig {
            name: name.into(),
            base_url: base_url.into(),
            auth: ProviderAuth::ApiKey("sk-test-1234567890abcdef".into()),
            models: vec![ModelInfo {
                id: "test-model".into(),
                capabilities: vec![ModelCapability::Code],
                context_window: 8192,
                cost_per_input_token: 0.001,
                cost_per_output_token: 0.002,
            }],
            priority: 1,
        }
    }

    fn test_runtime() -> ConnectorRuntime {
        ConnectorRuntime::new(ConnectorRuntimeConfig::default())
    }

    fn test_retry_config() -> HttpRetryConfig {
        HttpRetryConfig {
            max_retries: 2,
            initial_delay_ms: 10,
            max_delay_ms: 100,
            jitter_enabled: false,
        }
    }

    // ---- Constructor tests ----

    #[test]
    fn new_client_with_valid_config() {
        let provider = test_provider("openai", "https://api.openai.com");
        let client = LlmRouterClient::new(&provider, test_runtime(), test_retry_config(), 30_000);
        assert!(client.is_ok());
        let client = client.unwrap();
        assert_eq!(client.provider_name(), "openai");
        assert_eq!(client.base_url(), "https://api.openai.com");
    }

    #[test]
    fn new_client_strips_trailing_slash() {
        let provider = test_provider("openai", "https://api.openai.com/v1/");
        let client =
            LlmRouterClient::new(&provider, test_runtime(), test_retry_config(), 30_000).unwrap();
        assert_eq!(client.base_url(), "https://api.openai.com/v1");
    }

    #[test]
    fn new_client_rejects_empty_url() {
        let provider = test_provider("openai", "");
        let result = LlmRouterClient::new(&provider, test_runtime(), test_retry_config(), 30_000);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn new_client_rejects_non_http_url() {
        let provider = test_provider("openai", "ftp://api.openai.com");
        let result = LlmRouterClient::new(&provider, test_runtime(), test_retry_config(), 30_000);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("must start with http"));
    }

    #[test]
    fn new_client_accepts_http_url() {
        let provider = test_provider("local", "http://localhost:8080");
        let client = LlmRouterClient::new(&provider, test_runtime(), test_retry_config(), 30_000);
        assert!(client.is_ok());
    }

    // ---- Debug redaction tests ----

    #[test]
    fn debug_redacts_api_key() {
        let provider = test_provider("openai", "https://api.openai.com");
        let client =
            LlmRouterClient::new(&provider, test_runtime(), test_retry_config(), 30_000).unwrap();
        let debug_str = format!("{client:?}");
        assert!(debug_str.contains("LlmRouterClient"));
        assert!(debug_str.contains("openai"));
        // The raw API key should NOT appear
        assert!(!debug_str.contains("sk-test-1234567890abcdef"));
        // The redacted label should appear
        assert!(debug_str.contains("api_key:"));
    }

    #[test]
    fn debug_shows_credential_id_for_secretless() {
        let mut provider = test_provider("anthropic", "https://api.anthropic.com");
        provider.auth = ProviderAuth::CredentialId("cred-abc-123".into());
        let client =
            LlmRouterClient::new(&provider, test_runtime(), test_retry_config(), 30_000).unwrap();
        let debug_str = format!("{client:?}");
        assert!(debug_str.contains("credential_id:cred-abc-123"));
    }

    // ---- Base URL sanitization tests ----

    #[test]
    fn sanitize_base_url_valid() {
        assert_eq!(
            sanitize_base_url("https://api.openai.com").unwrap(),
            "https://api.openai.com"
        );
    }

    #[test]
    fn sanitize_base_url_strips_trailing_slash() {
        assert_eq!(
            sanitize_base_url("https://api.openai.com/").unwrap(),
            "https://api.openai.com"
        );
    }

    #[test]
    fn sanitize_base_url_strips_whitespace() {
        assert_eq!(
            sanitize_base_url("  https://api.openai.com  ").unwrap(),
            "https://api.openai.com"
        );
    }

    #[test]
    fn sanitize_base_url_rejects_empty() {
        assert!(sanitize_base_url("").is_err());
        assert!(sanitize_base_url("   ").is_err());
    }

    #[test]
    fn sanitize_base_url_rejects_non_http() {
        assert!(sanitize_base_url("ftp://example.com").is_err());
        assert!(sanitize_base_url("ws://example.com").is_err());
    }

    #[test]
    fn sanitize_base_url_accepts_http() {
        assert!(sanitize_base_url("http://localhost:8080").is_ok());
    }

    // ---- Provider accessor tests ----

    #[test]
    fn provider_name_accessor() {
        let provider = test_provider("my-provider", "https://api.example.com");
        let client =
            LlmRouterClient::new(&provider, test_runtime(), test_retry_config(), 30_000).unwrap();
        assert_eq!(client.provider_name(), "my-provider");
    }

    #[test]
    fn base_url_accessor() {
        let provider = test_provider("test", "https://llm.example.com/api");
        let client =
            LlmRouterClient::new(&provider, test_runtime(), test_retry_config(), 30_000).unwrap();
        assert_eq!(client.base_url(), "https://llm.example.com/api");
    }

    // ---- Multiple clients for different providers ----

    #[test]
    fn multiple_clients_independent() {
        let p1 = test_provider("openai", "https://api.openai.com");
        let p2 = test_provider("anthropic", "https://api.anthropic.com");
        let c1 = LlmRouterClient::new(&p1, test_runtime(), test_retry_config(), 30_000).unwrap();
        let c2 = LlmRouterClient::new(&p2, test_runtime(), test_retry_config(), 30_000).unwrap();
        assert_eq!(c1.provider_name(), "openai");
        assert_eq!(c2.provider_name(), "anthropic");
        assert_ne!(c1.base_url(), c2.base_url());
    }

    // ---- Retry config preserved ----

    #[test]
    fn retry_config_preserved_in_debug() {
        let provider = test_provider("test", "https://api.test.com");
        let retry = HttpRetryConfig {
            max_retries: 5,
            initial_delay_ms: 200,
            max_delay_ms: 5000,
            jitter_enabled: true,
        };
        let client = LlmRouterClient::new(&provider, test_runtime(), retry, 30_000).unwrap();
        let debug_str = format!("{client:?}");
        assert!(debug_str.contains("retry_config"));
    }

    // ---- Credential ID auth (secretless) ----

    #[test]
    fn secretless_provider_creates_client() {
        let mut provider = test_provider("proxy-provider", "https://egress.proxy.internal");
        provider.auth = ProviderAuth::CredentialId("vault-secret-123".into());
        let client = LlmRouterClient::new(&provider, test_runtime(), test_retry_config(), 30_000);
        assert!(client.is_ok());
    }
}
