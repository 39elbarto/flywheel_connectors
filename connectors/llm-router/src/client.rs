//! HTTP client for LLM provider API calls.
//!
//! Provides [`LlmRouterClient`] which wraps `reqwest::Client` and
//! [`ConnectorRuntime`] for making authenticated requests to LLM
//! provider endpoints (OpenAI-compatible chat completions, etc.).

use std::time::Duration;

use reqwest::{
    Client, StatusCode,
    header::{AUTHORIZATION, HeaderMap, HeaderValue, RETRY_AFTER},
};
use serde_json::json;
use tracing::debug;

use fcp_sdk::migration::{AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop};

use crate::error::{RouterError, RouterResult};
use crate::types::{ProviderApiPathMode, ProviderAuth, ProviderConfig, ProviderHttpHeader};

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
    api_path_mode: ProviderApiPathMode,
    authorization_header: Option<HeaderValue>,
    extra_headers: Vec<ProviderHttpHeader>,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for LlmRouterClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmRouterClient")
            .field("provider_name", &self.provider_name)
            .field("base_url", &self.base_url)
            .field("auth", &self.auth.redacted_label())
            .field("api_path_mode", &self.api_path_mode)
            .field(
                "extra_headers",
                &self
                    .extra_headers
                    .iter()
                    .map(ProviderHttpHeader::redacted_label)
                    .collect::<Vec<_>>(),
            )
            .field("retry_config", &self.retry_config)
            .finish_non_exhaustive()
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
        let authorization_header = provider.auth.bearer_authorization_header().map_err(|e| {
            RouterError::ProviderError {
                provider: provider.name.clone(),
                message: format!("api_key must be a valid HTTP Authorization header value: {e}"),
            }
        })?;

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
            api_path_mode: provider.api_path_mode,
            authorization_header,
            extra_headers: provider.extra_headers.clone(),
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
        let mut headers = HeaderMap::new();
        if let Some(header) = &self.authorization_header {
            headers.insert(AUTHORIZATION, header.clone());
        }
        for header in &self.extra_headers {
            headers.insert(header.name().clone(), header.value().clone());
        }
        if !headers.is_empty() {
            req = req.headers(headers);
        }
        req
    }

    fn endpoint_url(&self, endpoint: &str) -> String {
        match self.api_path_mode {
            ProviderApiPathMode::AppendV1 => format!("{}/v1/{}", self.base_url, endpoint),
            ProviderApiPathMode::OpenAiCompatibleBase => format!("{}/{}", self.base_url, endpoint),
        }
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
        let url = self.endpoint_url("chat/completions");
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

        RetryLoop::execute(&ctx, &policy, |attempt| {
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
                            let retry_after = retry_after_hint(resp.headers());
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
                                retry_after,
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
        .await
    }

    /// List available models from the provider's models endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn list_models(&self) -> RouterResult<serde_json::Value> {
        let url = self.endpoint_url("models");
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
                            let retry_after = retry_after_hint(resp.headers());
                            debug!(attempt, status = %status, "Retryable on list_models");
                            AttemptOutcome::Retryable {
                                error: RouterError::ProviderError {
                                    provider: prov,
                                    message: format!("HTTP {status}"),
                                },
                                retry_after,
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
        let url = self.endpoint_url("models");

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

fn retry_after_hint(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        CLOUDFLARE_AI_GATEWAY_AUTH_HEADER_NAME, ModelCapability, ModelInfo, ProviderHttpHeader,
        gateway_provider_descriptor,
    };
    use fcp_sdk::migration::ConnectorRuntimeConfig;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::Instant;

    fn test_provider(name: &str, base_url: &str) -> ProviderConfig {
        ProviderConfig {
            name: name.into(),
            base_url: base_url.into(),
            auth: ProviderAuth::ApiKey("sk-test-1234567890abcdef".into()),
            api_path_mode: ProviderApiPathMode::AppendV1,
            extra_headers: Vec::new(),
            models: vec![ModelInfo {
                id: "test-model".into(),
                capabilities: vec![ModelCapability::Code],
                context_window: 8192,
                cost_per_input_token: 0.001,
                cost_per_output_token: 0.002,
            }],
            priority: 1,
            passthrough_provider_models: false,
            image_generation_provider: false,
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

    fn immediate_retry_config(max_retries: u32) -> HttpRetryConfig {
        HttpRetryConfig {
            max_retries,
            initial_delay_ms: 0,
            max_delay_ms: 0,
            jitter_enabled: false,
        }
    }

    #[derive(Clone, Debug)]
    struct RecordedRequest {
        path: String,
        headers: Vec<(String, String)>,
        body: String,
    }

    #[derive(Clone, Debug)]
    struct LoopbackResponse {
        status: &'static str,
        headers: Vec<(&'static str, &'static str)>,
        body: &'static str,
        delay: Duration,
    }

    impl LoopbackResponse {
        fn json(status: &'static str, body: &'static str) -> Self {
            Self {
                status,
                headers: Vec::new(),
                body,
                delay: Duration::ZERO,
            }
        }

        fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
            self.headers.push((name, value));
            self
        }

        fn delayed(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
        }
    }

    struct LoopbackServer {
        base_url: String,
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
        handle: Option<JoinHandle<()>>,
    }

    impl LoopbackServer {
        fn spawn(responses: Vec<LoopbackResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&requests);
            let handle = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(3);
                let mut responses = responses.into_iter();
                while Instant::now() < deadline {
                    let Some(response) = responses.next() else {
                        break;
                    };
                    loop {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                handle_loopback_stream(stream, response, &recorded);
                                break;
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                if Instant::now() >= deadline {
                                    return;
                                }
                                thread::sleep(Duration::from_millis(5));
                            }
                            Err(_) => return,
                        }
                    }
                }
            });

            Self {
                base_url,
                requests,
                handle: Some(handle),
            }
        }

        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn requests(&self) -> Vec<RecordedRequest> {
            self.requests.lock().unwrap().clone()
        }

        fn wait(&mut self) {
            if let Some(handle) = self.handle.take() {
                handle.join().unwrap();
            }
        }
    }

    impl Drop for LoopbackServer {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn handle_loopback_stream(
        stream: TcpStream,
        response: LoopbackResponse,
        requests: &Arc<Mutex<Vec<RecordedRequest>>>,
    ) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            return;
        }
        let path = request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("")
            .to_string();

        let mut headers = Vec::new();
        let mut content_length = 0_usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() || matches!(line.as_str(), "\r\n" | "\n" | "") {
                break;
            }
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if let Some((name, value)) = trimmed.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap_or(0);
                }
                headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
            }
        }

        let mut body = vec![0_u8; content_length];
        if content_length > 0 && reader.read_exact(&mut body).is_err() {
            return;
        }
        requests.lock().unwrap().push(RecordedRequest {
            path,
            headers,
            body: String::from_utf8_lossy(&body).into_owned(),
        });

        if !response.delay.is_zero() {
            thread::sleep(response.delay);
        }

        let mut stream = reader.into_inner();
        let mut response_headers = String::new();
        for (name, value) in response.headers {
            response_headers.push_str(name);
            response_headers.push_str(": ");
            response_headers.push_str(value);
            response_headers.push_str("\r\n");
        }
        let wire = format!(
            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n{}",
            response.status,
            response.body.len(),
            response_headers,
            response.body
        );
        let _ = stream.write_all(wire.as_bytes());
        let _ = stream.flush();
    }

    fn header_value<'a>(request: &'a RecordedRequest, name: &str) -> Option<&'a str> {
        request
            .headers
            .iter()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn cloudflare_provider(base_url: &str) -> ProviderConfig {
        let mut provider = test_provider("cloudflare-ai-gateway", base_url);
        provider.api_path_mode = ProviderApiPathMode::OpenAiCompatibleBase;
        provider.extra_headers = vec![
            ProviderHttpHeader::cloudflare_ai_gateway_authorization("cf-gateway-secret").unwrap(),
        ];
        provider.passthrough_provider_models = true;
        provider
    }

    fn vercel_provider(base_url: &str) -> ProviderConfig {
        let mut provider = test_provider("vercel-ai-gateway", base_url);
        provider.api_path_mode = ProviderApiPathMode::OpenAiCompatibleBase;
        provider.passthrough_provider_models = true;
        provider
    }

    fn litellm_provider(base_url: &str) -> ProviderConfig {
        let mut provider = test_provider("litellm", base_url);
        provider.passthrough_provider_models = true;
        provider.image_generation_provider = true;
        provider
    }

    fn descriptor_provider(provider_id: &str, base_url: &str) -> ProviderConfig {
        let descriptor = gateway_provider_descriptor(provider_id).unwrap();
        let mut provider = test_provider(provider_id, base_url);
        provider.api_path_mode = descriptor.endpoint.api_path_mode();
        provider.passthrough_provider_models = descriptor.passthrough_provider_models;
        provider.image_generation_provider = descriptor.image_generation_provider;
        provider
    }

    #[fcp_async_core::runtime::test]
    async fn cloudflare_gateway_chat_uses_descriptor_base_path_headers_and_passthrough_model() {
        let mut server = LoopbackServer::spawn(vec![LoopbackResponse::json(
            "200 OK",
            r#"{"id":"chatcmpl-test","choices":[]}"#,
        )]);
        let base_url = format!("{}/v1/account_123/gateway-prod/openai", server.base_url());
        let provider = cloudflare_provider(&base_url);
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(0), 1_000)
                .unwrap();

        let result = client
            .chat_completion(
                "openrouter/openai/gpt-4o",
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(result["id"], "chatcmpl-test");

        server.wait();
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(
            request.path,
            "/v1/account_123/gateway-prod/openai/chat/completions"
        );
        assert_eq!(
            header_value(request, "authorization"),
            Some("Bearer sk-test-1234567890abcdef")
        );
        assert_eq!(
            header_value(request, CLOUDFLARE_AI_GATEWAY_AUTH_HEADER_NAME),
            Some("Bearer cf-gateway-secret")
        );

        let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
        assert_eq!(body["model"], "openrouter/openai/gpt-4o");
    }

    #[fcp_async_core::runtime::test]
    async fn cloudflare_gateway_auth_failure_is_terminal() {
        let mut server = LoopbackServer::spawn(vec![LoopbackResponse::json(
            "403 Forbidden",
            r#"{"error":"gateway auth failed"}"#,
        )]);
        let base_url = format!("{}/v1/account_123/gateway-prod/openai", server.base_url());
        let provider = cloudflare_provider(&base_url);
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(2), 1_000)
                .unwrap();

        let err = client
            .chat_completion(
                "openrouter/openai/gpt-4o",
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap_err()
            .to_string();
        server.wait();

        assert!(err.contains("HTTP 403"));
        assert_eq!(server.requests().len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn provider_auth_failure_is_terminal() {
        let mut server = LoopbackServer::spawn(vec![LoopbackResponse::json(
            "401 Unauthorized",
            r#"{"error":"bad provider auth"}"#,
        )]);
        let base_url = format!("{}/v1/account_123/gateway-prod/openai", server.base_url());
        let provider = cloudflare_provider(&base_url);
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(2), 1_000)
                .unwrap();

        let err = client
            .chat_completion(
                "openrouter/openai/gpt-4o",
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap_err()
            .to_string();
        server.wait();

        assert!(err.contains("HTTP 401"));
        assert_eq!(server.requests().len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn retry_after_header_is_respected_for_retryable_gateway_response() {
        let mut server = LoopbackServer::spawn(vec![
            LoopbackResponse::json("429 Too Many Requests", r#"{"error":"slow down"}"#)
                .with_header("Retry-After", "0"),
            LoopbackResponse::json("200 OK", r#"{"id":"retry-success","choices":[]}"#),
        ]);
        let base_url = format!("{}/v1/account_123/gateway-prod/openai", server.base_url());
        let provider = cloudflare_provider(&base_url);
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(1), 1_000)
                .unwrap();

        let result = client
            .chat_completion(
                "openrouter/openai/gpt-4o",
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap();
        server.wait();

        assert_eq!(result["id"], "retry-success");
        assert_eq!(server.requests().len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn malformed_gateway_response_is_terminal() {
        let mut server = LoopbackServer::spawn(vec![LoopbackResponse::json("200 OK", "{")]);
        let base_url = format!("{}/v1/account_123/gateway-prod/openai", server.base_url());
        let provider = cloudflare_provider(&base_url);
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(0), 1_000)
                .unwrap();

        let err = client
            .chat_completion(
                "openrouter/openai/gpt-4o",
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap_err()
            .to_string();
        server.wait();

        assert!(err.contains("failed to parse response"));
        assert_eq!(server.requests().len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn delayed_gateway_response_hits_request_timeout() {
        let mut server = LoopbackServer::spawn(vec![
            LoopbackResponse::json("200 OK", r#"{"id":"too-late","choices":[]}"#)
                .delayed(Duration::from_millis(120)),
        ]);
        let base_url = format!("{}/v1/account_123/gateway-prod/openai", server.base_url());
        let provider = cloudflare_provider(&base_url);
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(0), 20).unwrap();

        let err = client
            .chat_completion(
                "openrouter/openai/gpt-4o",
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap_err()
            .to_string();
        server.wait();

        assert!(err.contains("network error"));
        assert_eq!(server.requests().len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn vercel_gateway_chat_uses_fixed_base_path_auth_and_alias_normalized_model() {
        let mut server = LoopbackServer::spawn(vec![LoopbackResponse::json(
            "200 OK",
            r#"{"id":"vercel-chat","choices":[]}"#,
        )]);
        let base_url = format!("{}/v1", server.base_url());
        let provider = vercel_provider(&base_url);
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(0), 1_000)
                .unwrap();
        let model = gateway_provider_descriptor("vercel-ai-gateway")
            .unwrap()
            .normalize_model_id("sonnet-4.6");

        let result = client
            .chat_completion(
                &model,
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(result["id"], "vercel-chat");

        server.wait();
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.path, "/v1/chat/completions");
        assert_eq!(
            header_value(request, "authorization"),
            Some("Bearer sk-test-1234567890abcdef")
        );
        let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
        assert_eq!(body["model"], "anthropic/claude-sonnet-4-6");
    }

    #[fcp_async_core::runtime::test]
    async fn vercel_gateway_list_models_uses_fixed_base_models_path() {
        let mut server = LoopbackServer::spawn(vec![LoopbackResponse::json(
            "200 OK",
            r#"{"object":"list","data":[{"id":"openai/gpt-4o"}]}"#,
        )]);
        let base_url = format!("{}/v1", server.base_url());
        let provider = vercel_provider(&base_url);
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(0), 1_000)
                .unwrap();

        let result = client.list_models().await.unwrap();
        server.wait();

        assert_eq!(result["data"][0]["id"], "openai/gpt-4o");
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/models");
    }

    #[fcp_async_core::runtime::test]
    async fn vercel_gateway_auth_failure_is_terminal() {
        let mut server = LoopbackServer::spawn(vec![LoopbackResponse::json(
            "401 Unauthorized",
            r#"{"error":"bad gateway auth"}"#,
        )]);
        let base_url = format!("{}/v1", server.base_url());
        let provider = vercel_provider(&base_url);
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(2), 1_000)
                .unwrap();

        let err = client
            .chat_completion(
                "openai/gpt-4o",
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap_err()
            .to_string();
        server.wait();

        assert!(err.contains("HTTP 401"));
        assert_eq!(server.requests().len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn vercel_gateway_retry_after_retries_once() {
        let mut server = LoopbackServer::spawn(vec![
            LoopbackResponse::json("429 Too Many Requests", r#"{"error":"slow down"}"#)
                .with_header("Retry-After", "0"),
            LoopbackResponse::json("200 OK", r#"{"id":"vercel-retry","choices":[]}"#),
        ]);
        let base_url = format!("{}/v1", server.base_url());
        let provider = vercel_provider(&base_url);
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(1), 1_000)
                .unwrap();

        let result = client
            .chat_completion(
                "openai/gpt-4o",
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap();
        server.wait();

        assert_eq!(result["id"], "vercel-retry");
        assert_eq!(server.requests().len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn vercel_gateway_malformed_response_is_terminal() {
        let mut server = LoopbackServer::spawn(vec![LoopbackResponse::json("200 OK", "{")]);
        let base_url = format!("{}/v1", server.base_url());
        let provider = vercel_provider(&base_url);
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(0), 1_000)
                .unwrap();

        let err = client
            .chat_completion(
                "openai/gpt-4o",
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap_err()
            .to_string();
        server.wait();

        assert!(err.contains("failed to parse response"));
        assert_eq!(server.requests().len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn vercel_gateway_delayed_response_hits_request_timeout() {
        let mut server = LoopbackServer::spawn(vec![
            LoopbackResponse::json("200 OK", r#"{"id":"too-late","choices":[]}"#)
                .delayed(Duration::from_millis(120)),
        ]);
        let base_url = format!("{}/v1", server.base_url());
        let provider = vercel_provider(&base_url);
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(0), 20).unwrap();

        let err = client
            .chat_completion(
                "openai/gpt-4o",
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap_err()
            .to_string();
        server.wait();

        assert!(err.contains("network error"));
        assert_eq!(server.requests().len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn litellm_gateway_chat_uses_operator_root_path_and_passthrough_model() {
        let mut server = LoopbackServer::spawn(vec![LoopbackResponse::json(
            "200 OK",
            r#"{"id":"litellm-chat","choices":[]}"#,
        )]);
        let provider = litellm_provider(server.base_url());
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(0), 1_000)
                .unwrap();

        let result = client
            .chat_completion(
                "openrouter/openai/gpt-4o",
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(result["id"], "litellm-chat");

        server.wait();
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.path, "/v1/chat/completions");
        assert_eq!(
            header_value(request, "authorization"),
            Some("Bearer sk-test-1234567890abcdef")
        );
        let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
        assert_eq!(body["model"], "openrouter/openai/gpt-4o");
    }

    #[fcp_async_core::runtime::test]
    async fn litellm_gateway_list_models_uses_operator_v1_base_path() {
        let mut server = LoopbackServer::spawn(vec![LoopbackResponse::json(
            "200 OK",
            r#"{"object":"list","data":[{"id":"openai/gpt-image-1"}]}"#,
        )]);
        let base_url = format!("{}/v1", server.base_url());
        let mut provider = litellm_provider(&base_url);
        provider.api_path_mode = ProviderApiPathMode::OpenAiCompatibleBase;
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(0), 1_000)
                .unwrap();

        let result = client.list_models().await.unwrap();
        server.wait();

        assert_eq!(result["data"][0]["id"], "openai/gpt-image-1");
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/models");
    }

    #[fcp_async_core::runtime::test]
    async fn litellm_gateway_auth_failure_is_terminal() {
        let mut server = LoopbackServer::spawn(vec![LoopbackResponse::json(
            "401 Unauthorized",
            r#"{"error":"bad gateway auth"}"#,
        )]);
        let provider = litellm_provider(server.base_url());
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(2), 1_000)
                .unwrap();

        let err = client
            .chat_completion(
                "openai/gpt-4o",
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap_err()
            .to_string();
        server.wait();

        assert!(err.contains("HTTP 401"));
        assert_eq!(server.requests().len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn litellm_gateway_retry_after_retries_once() {
        let mut server = LoopbackServer::spawn(vec![
            LoopbackResponse::json("429 Too Many Requests", r#"{"error":"slow down"}"#)
                .with_header("Retry-After", "0"),
            LoopbackResponse::json("200 OK", r#"{"id":"litellm-retry","choices":[]}"#),
        ]);
        let provider = litellm_provider(server.base_url());
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(1), 1_000)
                .unwrap();

        let result = client
            .chat_completion(
                "openai/gpt-4o",
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap();
        server.wait();

        assert_eq!(result["id"], "litellm-retry");
        assert_eq!(server.requests().len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn litellm_gateway_malformed_response_is_terminal() {
        let mut server = LoopbackServer::spawn(vec![LoopbackResponse::json("200 OK", "{")]);
        let provider = litellm_provider(server.base_url());
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(0), 1_000)
                .unwrap();

        let err = client
            .chat_completion(
                "openai/gpt-4o",
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap_err()
            .to_string();
        server.wait();

        assert!(err.contains("failed to parse response"));
        assert_eq!(server.requests().len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn litellm_gateway_delayed_response_hits_request_timeout() {
        let mut server = LoopbackServer::spawn(vec![
            LoopbackResponse::json("200 OK", r#"{"id":"too-late","choices":[]}"#)
                .delayed(Duration::from_millis(120)),
        ]);
        let provider = litellm_provider(server.base_url());
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(0), 20).unwrap();

        let err = client
            .chat_completion(
                "openai/gpt-4o",
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap_err()
            .to_string();
        server.wait();

        assert!(err.contains("network error"));
        assert_eq!(server.requests().len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn deepseek_descriptor_root_base_appends_v1_chat_path() {
        let mut server = LoopbackServer::spawn(vec![LoopbackResponse::json(
            "200 OK",
            r#"{"id":"deepseek-chat","choices":[]}"#,
        )]);
        let provider = descriptor_provider("deepseek", server.base_url());
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(0), 1_000)
                .unwrap();

        let result = client
            .chat_completion(
                "deepseek-chat",
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(result["id"], "deepseek-chat");

        server.wait();
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/v1/chat/completions");
    }

    #[fcp_async_core::runtime::test]
    async fn groq_descriptor_openai_base_does_not_double_v1_path() {
        let mut server = LoopbackServer::spawn(vec![LoopbackResponse::json(
            "200 OK",
            r#"{"id":"groq-chat","choices":[]}"#,
        )]);
        let base_url = format!("{}/openai/v1", server.base_url());
        let provider = descriptor_provider("groq", &base_url);
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(0), 1_000)
                .unwrap();

        let result = client
            .chat_completion(
                "llama-3.3-70b-versatile",
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(result["id"], "groq-chat");

        server.wait();
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/openai/v1/chat/completions");
    }

    #[fcp_async_core::runtime::test]
    async fn openrouter_descriptor_preserves_provider_model_id_and_api_base_path() {
        let mut server = LoopbackServer::spawn(vec![LoopbackResponse::json(
            "200 OK",
            r#"{"id":"openrouter-chat","choices":[]}"#,
        )]);
        let base_url = format!("{}/api/v1", server.base_url());
        let provider = descriptor_provider("openrouter", &base_url);
        let client =
            LlmRouterClient::new(&provider, test_runtime(), immediate_retry_config(0), 1_000)
                .unwrap();

        let result = client
            .chat_completion(
                "anthropic/claude-sonnet-4",
                &[json!({"role": "user", "content": "hello"})],
                32,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(result["id"], "openrouter-chat");

        server.wait();
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/api/v1/chat/completions");
        let body: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
        assert_eq!(body["model"], "anthropic/claude-sonnet-4");
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

    #[test]
    fn new_client_rejects_header_unsafe_api_key() {
        let mut provider = test_provider("openai", "https://api.openai.com");
        provider.auth = ProviderAuth::ApiKey("sk-good\r\nx-injected: bad".into());
        let result = LlmRouterClient::new(&provider, test_runtime(), test_retry_config(), 30_000);
        let err = result.unwrap_err().to_string();
        assert!(err.contains("valid HTTP Authorization header value"));
        assert!(!err.contains("sk-good"));
        assert!(!err.contains("x-injected"));
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
        assert!(!debug_str.contains("sk-test"));
        assert!(!debug_str.contains("cdef"));
        // The redacted label should appear
        assert!(debug_str.contains("api_key:[redacted]"));
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
