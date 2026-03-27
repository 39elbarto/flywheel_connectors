//! Browser automation API client.
//!
//! Sends JSON POST commands to a Chrome DevTools Protocol HTTP endpoint.

use std::time::Duration;

use fcp_core::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig, RetryLoop,
};
use reqwest::{Client, StatusCode, header};

use crate::{
    error::{BrowserError, BrowserResult},
    types::{
        ApiErrorResponse, ClickResult, Cookie, FormResult, JsResult, LinksResult, NavigateResult,
        PdfResult, ProxyConfig, ProxyResult, ScreenshotResult, TextResult, WaitResult,
    },
};

/// Default browser CDP endpoint.
pub const DEFAULT_BROWSER_URL: &str = "http://localhost:9222";

/// Authentication mode for the Browser connector.
#[derive(Clone)]
pub enum BrowserAuth {
    /// No authentication (local browser, no API key required).
    None,
    /// Bearer API key for authenticated browser endpoints.
    ApiKey(String),
    /// Secretless mode – egress proxy injects credentials at runtime.
    CredentialId(CredentialId),
}

impl std::fmt::Debug for BrowserAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserAuth").finish_non_exhaustive()
    }
}

impl BrowserAuth {
    /// Human-readable label with secrets redacted.
    #[must_use]
    pub fn redacted_label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ApiKey(_) => "api_key:****",
            Self::CredentialId(_) => "credential_id",
        }
    }

    /// Whether this auth mode is secretless (egress proxy).
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

/// Browser automation HTTP client.
pub struct BrowserClient {
    http: Client,
    browser_url: String,
    max_retries: u32,
    auth: BrowserAuth,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for BrowserClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserClient").finish_non_exhaustive()
    }
}

impl BrowserClient {
    /// Create a new browser client with an optional API key.
    pub fn new(api_key: Option<&str>) -> BrowserResult<Self> {
        let auth = match api_key {
            Some(key) => BrowserAuth::ApiKey(key.to_string()),
            None => BrowserAuth::None,
        };
        Self::new_with_auth(auth)
    }

    /// Create a new browser client with the specified auth mode.
    pub fn new_with_auth(auth: BrowserAuth) -> BrowserResult<Self> {
        let mut headers = header::HeaderMap::new();
        match &auth {
            BrowserAuth::None => {}
            BrowserAuth::ApiKey(key) => {
                headers.insert(
                    header::AUTHORIZATION,
                    format!("Bearer {key}")
                        .parse()
                        .map_err(|_| BrowserError::Api {
                            message: "Invalid API key value for header".into(),
                            status_code: None,
                        })?,
                );
            }
            BrowserAuth::CredentialId(id) => {
                headers.insert(
                    "X-FCP-Credential-ID",
                    id.to_string().parse().map_err(|_| BrowserError::Api {
                        message: "Invalid credential_id value for header".into(),
                        status_code: None,
                    })?,
                );
            }
        }

        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-browser/0.1.0")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(BrowserError::Http)?;

        Ok(Self {
            http,
            browser_url: DEFAULT_BROWSER_URL.to_string(),
            max_retries: 2,
            auth,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Lightweight connectivity probe – check if the browser endpoint is reachable.
    pub async fn health_check(&self) -> BrowserResult<()> {
        let url = format!("{}/json/version", self.browser_url);
        self.execute(|| self.http.get(&url)).await?;
        Ok(())
    }

    /// Set a custom browser URL.
    #[must_use]
    pub fn with_browser_url(mut self, url: &str) -> Self {
        self.browser_url = url.to_string();
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self.retry_config = HttpRetryConfig {
            max_retries,
            ..self.retry_config
        };
        self
    }

    // -- Navigation --

    /// Navigate to a URL.
    pub async fn navigate(
        &self,
        url: &str,
        wait_until: Option<&str>,
        timeout_ms: Option<u64>,
        user_agent: Option<&str>,
    ) -> BrowserResult<NavigateResult> {
        let endpoint = format!("{}/navigate", self.browser_url);
        let mut body = serde_json::json!({ "url": url });
        if let Some(w) = wait_until {
            body["wait_until"] = serde_json::Value::String(w.to_string());
        }
        if let Some(t) = timeout_ms {
            body["timeout_ms"] = serde_json::Value::Number(t.into());
        }
        if let Some(ua) = user_agent {
            body["user_agent"] = serde_json::Value::String(ua.to_string());
        }
        let data = self.post_json(&endpoint, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- Screenshot --

    /// Capture a screenshot.
    pub async fn screenshot(
        &self,
        selector: Option<&str>,
        full_page: Option<bool>,
        format: Option<&str>,
        quality: Option<u32>,
    ) -> BrowserResult<ScreenshotResult> {
        let endpoint = format!("{}/screenshot", self.browser_url);
        let mut body = serde_json::json!({});
        if let Some(s) = selector {
            body["selector"] = serde_json::Value::String(s.to_string());
        }
        if let Some(fp) = full_page {
            body["full_page"] = serde_json::Value::Bool(fp);
        }
        if let Some(f) = format {
            body["format"] = serde_json::Value::String(f.to_string());
        }
        if let Some(q) = quality {
            body["quality"] = serde_json::Value::Number(q.into());
        }
        let data = self.post_json(&endpoint, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- PDF --

    /// Render the current page as PDF.
    pub async fn render_pdf(
        &self,
        format: Option<&str>,
        landscape: Option<bool>,
        print_background: Option<bool>,
    ) -> BrowserResult<PdfResult> {
        let endpoint = format!("{}/pdf", self.browser_url);
        let mut body = serde_json::json!({});
        if let Some(f) = format {
            body["format"] = serde_json::Value::String(f.to_string());
        }
        if let Some(l) = landscape {
            body["landscape"] = serde_json::Value::Bool(l);
        }
        if let Some(pb) = print_background {
            body["print_background"] = serde_json::Value::Bool(pb);
        }
        let data = self.post_json(&endpoint, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- Extraction --

    /// Extract text content from the page.
    pub async fn extract_text(
        &self,
        selector: Option<&str>,
        include_hidden: Option<bool>,
    ) -> BrowserResult<TextResult> {
        let endpoint = format!("{}/extract_text", self.browser_url);
        let mut body = serde_json::json!({});
        if let Some(s) = selector {
            body["selector"] = serde_json::Value::String(s.to_string());
        }
        if let Some(ih) = include_hidden {
            body["include_hidden"] = serde_json::Value::Bool(ih);
        }
        let data = self.post_json(&endpoint, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Extract links from the page.
    pub async fn extract_links(&self, selector: Option<&str>) -> BrowserResult<LinksResult> {
        let endpoint = format!("{}/extract_links", self.browser_url);
        let mut body = serde_json::json!({});
        if let Some(s) = selector {
            body["selector"] = serde_json::Value::String(s.to_string());
        }
        let data = self.post_json(&endpoint, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- Wait --

    /// Wait for a selector to appear.
    pub async fn wait_for_selector(
        &self,
        selector: &str,
        state: Option<&str>,
        timeout_ms: Option<u64>,
    ) -> BrowserResult<WaitResult> {
        let endpoint = format!("{}/wait_for_selector", self.browser_url);
        let mut body = serde_json::json!({ "selector": selector });
        if let Some(s) = state {
            body["state"] = serde_json::Value::String(s.to_string());
        }
        if let Some(t) = timeout_ms {
            body["timeout_ms"] = serde_json::Value::Number(t.into());
        }
        let data = self.post_json(&endpoint, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- Interaction --

    /// Click an element.
    pub async fn click(
        &self,
        selector: &str,
        timeout_ms: Option<u64>,
    ) -> BrowserResult<ClickResult> {
        let endpoint = format!("{}/click", self.browser_url);
        let mut body = serde_json::json!({ "selector": selector });
        if let Some(t) = timeout_ms {
            body["timeout_ms"] = serde_json::Value::Number(t.into());
        }
        let data = self.post_json(&endpoint, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Fill form fields.
    pub async fn fill_form(
        &self,
        fields: &serde_json::Value,
        submit_selector: Option<&str>,
    ) -> BrowserResult<FormResult> {
        let endpoint = format!("{}/fill_form", self.browser_url);
        let mut body = serde_json::json!({ "fields": fields });
        if let Some(ss) = submit_selector {
            body["submit_selector"] = serde_json::Value::String(ss.to_string());
        }
        let data = self.post_json(&endpoint, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- JavaScript --

    /// Evaluate JavaScript in the page context.
    pub async fn evaluate_js(&self, expression: &str) -> BrowserResult<JsResult> {
        let endpoint = format!("{}/evaluate", self.browser_url);
        let body = serde_json::json!({ "expression": expression });
        let data = self.post_json(&endpoint, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- Cookies --

    /// Get cookies.
    pub async fn get_cookies(&self, domain: Option<&str>) -> BrowserResult<Vec<Cookie>> {
        let endpoint = format!("{}/cookies", self.browser_url);
        let mut body = serde_json::json!({});
        if let Some(d) = domain {
            body["domain"] = serde_json::Value::String(d.to_string());
        }
        let data = self.post_json(&endpoint, &body).await?;
        let cookies: Vec<Cookie> = serde_json::from_value(
            data.get("cookies")
                .cloned()
                .unwrap_or(serde_json::Value::Array(vec![])),
        )?;
        Ok(cookies)
    }

    /// Set cookies.
    pub async fn set_cookies(&self, cookies: &[Cookie]) -> BrowserResult<u32> {
        let endpoint = format!("{}/set_cookies", self.browser_url);
        let body = serde_json::json!({ "cookies": cookies });
        let data = self.post_json(&endpoint, &body).await?;
        let count = data.get("set_count").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(count as u32)
    }

    // -- Proxy --

    /// Configure outbound proxy for browser traffic.
    pub async fn set_proxy(&self, proxy: &ProxyConfig) -> BrowserResult<ProxyResult> {
        let endpoint = format!("{}/proxy/set", self.browser_url);
        let body = serde_json::to_value(proxy)?;
        let data = self.post_json(&endpoint, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Clear outbound proxy configuration.
    pub async fn clear_proxy(&self) -> BrowserResult<ProxyResult> {
        let endpoint = format!("{}/proxy/clear", self.browser_url);
        let data = self.post_json(&endpoint, &serde_json::json!({})).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- HTTP helpers --

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> BrowserResult<serde_json::Value> {
        self.execute(|| self.http.post(url).json(body)).await
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> BrowserResult<serde_json::Value> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| {
            let req = build_request();
            async move {
                match req.send().await {
                    Ok(response) => {
                        let status = response.status();

                        if status == StatusCode::TOO_MANY_REQUESTS {
                            let err = BrowserError::Api {
                                message: "Rate limited by browser API".into(),
                                status_code: Some(429),
                            };
                            return AttemptOutcome::Retryable {
                                retry_after: err.retry_after(),
                                error: err,
                            };
                        }

                        if status.is_server_error() {
                            let body = response.text().await.unwrap_or_default();
                            let err = BrowserError::Api {
                                message: format!("Server error {status}: {body}"),
                                status_code: Some(status.as_u16()),
                            };
                            return AttemptOutcome::Retryable {
                                retry_after: None,
                                error: err,
                            };
                        }

                        if !status.is_success() {
                            let body = response.text().await.unwrap_or_default();
                            let api_err: Option<ApiErrorResponse> =
                                serde_json::from_str(&body).ok();
                            let message = api_err
                                .as_ref()
                                .and_then(|e| e.error.as_ref())
                                .and_then(|d| d.message.clone())
                                .unwrap_or(format!("HTTP {status}: {body}"));
                            return AttemptOutcome::Terminal(BrowserError::Api {
                                message,
                                status_code: Some(status.as_u16()),
                            });
                        }

                        match response.text().await {
                            Ok(body) => match serde_json::from_str(&body) {
                                Ok(data) => AttemptOutcome::Success(data),
                                Err(e) => AttemptOutcome::Terminal(BrowserError::Serialization(e)),
                            },
                            Err(e) => AttemptOutcome::Terminal(BrowserError::Http(e)),
                        }
                    }
                    Err(e) => {
                        let err = BrowserError::Http(e);
                        if err.is_retryable() {
                            AttemptOutcome::Retryable {
                                retry_after: None,
                                error: err,
                            }
                        } else {
                            AttemptOutcome::Terminal(err)
                        }
                    }
                }
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    #[fcp_async_core::runtime::test]
    async fn test_navigate() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/navigate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "url": "https://example.com",
                "status": 200,
                "title": "Example Domain"
            })))
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri());

        let result = client
            .navigate("https://example.com", None, None, None)
            .await
            .unwrap();
        assert_eq!(result.url, "https://example.com");
        assert_eq!(result.status, 200);
        assert_eq!(result.title.as_deref(), Some("Example Domain"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_screenshot() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/screenshot"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "image_data": "iVBOR...",
                "width": 1920,
                "height": 1080
            })))
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri());

        let result = client
            .screenshot(None, Some(true), None, None)
            .await
            .unwrap();
        assert_eq!(result.width, 1920);
        assert_eq!(result.height, 1080);
    }

    #[fcp_async_core::runtime::test]
    async fn test_extract_text() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/extract_text"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "text": "Hello, world!",
                "word_count": 2
            })))
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri());

        let result = client.extract_text(Some("body"), None).await.unwrap();
        assert_eq!(result.text, "Hello, world!");
        assert_eq!(result.word_count, Some(2));
    }

    #[fcp_async_core::runtime::test]
    async fn test_extract_links() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/extract_links"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "links": [
                    { "href": "https://example.com/a", "text": "Link A" },
                    { "href": "https://example.com/b", "text": "Link B" }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri());

        let result = client.extract_links(None).await.unwrap();
        assert_eq!(result.links.len(), 2);
        assert_eq!(result.links[0].href, "https://example.com/a");
    }

    #[fcp_async_core::runtime::test]
    async fn test_click() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/click"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "clicked": true,
                "navigation_url": null
            })))
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri());

        let result = client.click("button.submit", None).await.unwrap();
        assert!(result.clicked);
    }

    #[fcp_async_core::runtime::test]
    async fn test_evaluate_js() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/evaluate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": "Example Domain"
            })))
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri());

        let result = client.evaluate_js("document.title").await.unwrap();
        assert_eq!(result.result, "Example Domain");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_cookies() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/cookies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "cookies": [
                    { "name": "session", "value": "abc123", "domain": "example.com" }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri());

        let cookies = client.get_cookies(Some("example.com")).await.unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "session");
    }

    #[fcp_async_core::runtime::test]
    async fn test_set_cookies() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/set_cookies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "set_count": 1
            })))
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri());

        let cookies = vec![Cookie {
            name: "session".into(),
            value: "abc123".into(),
            domain: Some("example.com".into()),
            path: Some("/".into()),
            expires: None,
            http_only: None,
            secure: None,
            same_site: None,
        }];
        let count = client.set_cookies(&cookies).await.unwrap();
        assert_eq!(count, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_set_proxy() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/proxy/set"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "enabled": true,
                "mode": "fixed_servers",
                "server": "http://proxy.example.com:8080"
            })))
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri());

        let proxy = ProxyConfig {
            server: "http://proxy.example.com:8080".into(),
            bypass_list: Some(vec!["localhost".into()]),
            username: None,
            password: None,
        };
        let result = client.set_proxy(&proxy).await.unwrap();
        assert!(result.enabled);
        assert_eq!(result.mode, "fixed_servers");
        assert_eq!(
            result.server.as_deref(),
            Some("http://proxy.example.com:8080")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_clear_proxy() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/proxy/clear"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "enabled": false,
                "mode": "direct",
                "server": null
            })))
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri());

        let result = client.clear_proxy().await.unwrap();
        assert!(!result.enabled);
        assert_eq!(result.mode, "direct");
        assert!(result.server.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_server_error_retry() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/navigate"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client
            .navigate("https://example.com", None, None, None)
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.is_retryable());
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/navigate"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client
            .navigate("https://example.com", None, None, None)
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BrowserError::Api {
                status_code: Some(429),
                ..
            }
        ));
    }

    #[test]
    fn test_error_is_retryable() {
        let err = BrowserError::Timeout {
            message: "timed out".into(),
        };
        assert!(err.is_retryable());

        let err = BrowserError::InvalidConfig("bad config".into());
        assert!(!err.is_retryable());

        let err = BrowserError::Api {
            message: "Server error".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());
    }
}
