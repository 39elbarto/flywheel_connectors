//! Browser automation API client.
//!
//! Talks to the FCP browser-control plane. The control plane may use Chrome
//! DevTools Protocol internally, but this client does not treat a raw Chrome
//! `/json/version` endpoint as sufficient proof that FCP browser operations are
//! available.

use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig, RetryLoop,
};
use futures_util::StreamExt;
use reqwest::{Client, StatusCode, header};

use crate::{
    error::{BrowserError, BrowserResult},
    types::{
        ApiErrorResponse, ClickResult, Cookie, FormResult, JsResult, LinksResult, NavigateResult,
        PdfResult, ProxyConfig, ProxyResult, ScreenshotResult, TextResult, WaitResult,
    },
};

/// Default browser-control endpoint.
pub const DEFAULT_BROWSER_URL: &str = "http://localhost:9222";

/// Required FCP browser-control contract version.
pub const BROWSER_CONTROL_PROTOCOL_VERSION: u64 = 1;

#[cfg(not(test))]
const MAX_BROWSER_CONTROL_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
#[cfg(test)]
const MAX_BROWSER_CONTROL_RESPONSE_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy)]
struct BrowserControlOperation {
    id: &'static str,
    method: &'static str,
    path: &'static str,
    implementation: BrowserControlImplementation,
}

impl BrowserControlOperation {
    fn descriptor(self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "method": self.method,
            "path": self.path,
            "implementation": self.implementation.descriptor(),
        })
    }
}

#[derive(Clone, Copy)]
enum BrowserControlImplementation {
    Cdp { methods: &'static [&'static str] },
    WorkerPolicy { description: &'static str },
}

impl BrowserControlImplementation {
    fn descriptor(self) -> serde_json::Value {
        match self {
            Self::Cdp { methods } => serde_json::json!({
                "kind": "cdp",
                "protocol": "Chrome DevTools Protocol",
                "methods": methods,
            }),
            Self::WorkerPolicy { description } => serde_json::json!({
                "kind": "worker_policy",
                "description": description,
                "methods": [],
            }),
        }
    }

    fn summary(self) -> String {
        match self {
            Self::Cdp { methods } => format!("cdp methods [{}]", methods.join(", ")),
            Self::WorkerPolicy { .. } => "worker_policy".to_string(),
        }
    }
}

#[derive(Clone, Copy)]
struct BrowserConnectorOperation {
    id: &'static str,
    mapping: &'static str,
    worker_operation_ids: &'static [&'static str],
}

impl BrowserConnectorOperation {
    fn descriptor(self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "mapping": self.mapping,
            "worker_operation_ids": self.worker_operation_ids,
        })
    }
}

const WORKER_NAVIGATE: BrowserControlOperation = BrowserControlOperation {
    id: "browser.navigate",
    method: "POST",
    path: "/navigate",
    implementation: BrowserControlImplementation::Cdp {
        methods: &[
            "Page.enable",
            "Network.enable",
            "Network.setUserAgentOverride",
            "Page.navigate",
        ],
    },
};
const WORKER_SCREENSHOT: BrowserControlOperation = BrowserControlOperation {
    id: "browser.screenshot",
    method: "POST",
    path: "/screenshot",
    implementation: BrowserControlImplementation::Cdp {
        methods: &[
            "DOM.getDocument",
            "DOM.querySelector",
            "DOM.getBoxModel",
            "Page.getLayoutMetrics",
            "Page.captureScreenshot",
        ],
    },
};
const WORKER_RENDER_PDF: BrowserControlOperation = BrowserControlOperation {
    id: "browser.render_pdf",
    method: "POST",
    path: "/pdf",
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Page.printToPDF"],
    },
};
const WORKER_EXTRACT_TEXT: BrowserControlOperation = BrowserControlOperation {
    id: "browser.extract_text",
    method: "POST",
    path: "/extract_text",
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Runtime.evaluate"],
    },
};
const WORKER_EXTRACT_LINKS: BrowserControlOperation = BrowserControlOperation {
    id: "browser.extract_links",
    method: "POST",
    path: "/extract_links",
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Runtime.evaluate"],
    },
};
const WORKER_WAIT_FOR_SELECTOR: BrowserControlOperation = BrowserControlOperation {
    id: "browser.wait_for_selector",
    method: "POST",
    path: "/wait_for_selector",
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Runtime.evaluate"],
    },
};
const WORKER_CLICK: BrowserControlOperation = BrowserControlOperation {
    id: "browser.click",
    method: "POST",
    path: "/click",
    implementation: BrowserControlImplementation::Cdp {
        methods: &[
            "DOM.getDocument",
            "DOM.querySelector",
            "DOM.getBoxModel",
            "Input.dispatchMouseEvent",
        ],
    },
};
const WORKER_FILL_FORM: BrowserControlOperation = BrowserControlOperation {
    id: "browser.fill_form",
    method: "POST",
    path: "/fill_form",
    implementation: BrowserControlImplementation::Cdp {
        methods: &[
            "DOM.getDocument",
            "DOM.querySelector",
            "DOM.focus",
            "Input.insertText",
            "Runtime.evaluate",
        ],
    },
};
const WORKER_EVALUATE_JS: BrowserControlOperation = BrowserControlOperation {
    id: "browser.evaluate_js",
    method: "POST",
    path: "/evaluate",
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Runtime.evaluate"],
    },
};
const WORKER_GET_COOKIES: BrowserControlOperation = BrowserControlOperation {
    id: "browser.get_cookies",
    method: "POST",
    path: "/cookies",
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Network.getCookies"],
    },
};
const WORKER_SET_COOKIES: BrowserControlOperation = BrowserControlOperation {
    id: "browser.set_cookies",
    method: "POST",
    path: "/set_cookies",
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Network.setCookies"],
    },
};
const WORKER_SET_PROXY: BrowserControlOperation = BrowserControlOperation {
    id: "browser.set_proxy",
    method: "POST",
    path: "/proxy/set",
    implementation: BrowserControlImplementation::WorkerPolicy {
        description: "Apply connector-scoped proxy policy before browser target launch.",
    },
};
const WORKER_CLEAR_PROXY: BrowserControlOperation = BrowserControlOperation {
    id: "browser.clear_proxy",
    method: "POST",
    path: "/proxy/clear",
    implementation: BrowserControlImplementation::WorkerPolicy {
        description: "Clear connector-scoped proxy policy for future browser targets.",
    },
};

const REQUIRED_BROWSER_CONTROL_OPERATIONS: &[BrowserControlOperation] = &[
    WORKER_NAVIGATE,
    WORKER_SCREENSHOT,
    WORKER_RENDER_PDF,
    WORKER_EXTRACT_TEXT,
    WORKER_EXTRACT_LINKS,
    WORKER_WAIT_FOR_SELECTOR,
    WORKER_CLICK,
    WORKER_FILL_FORM,
    WORKER_EVALUATE_JS,
    WORKER_GET_COOKIES,
    WORKER_SET_COOKIES,
    WORKER_SET_PROXY,
    WORKER_CLEAR_PROXY,
];

const BROWSER_CONNECTOR_OPERATIONS: &[BrowserConnectorOperation] = &[
    BrowserConnectorOperation {
        id: "browser.navigate",
        mapping: "worker",
        worker_operation_ids: &["browser.navigate"],
    },
    BrowserConnectorOperation {
        id: "browser.screenshot",
        mapping: "worker",
        worker_operation_ids: &["browser.screenshot"],
    },
    BrowserConnectorOperation {
        id: "browser.render_pdf",
        mapping: "worker",
        worker_operation_ids: &["browser.render_pdf"],
    },
    BrowserConnectorOperation {
        id: "browser.extract_text",
        mapping: "worker",
        worker_operation_ids: &["browser.extract_text"],
    },
    BrowserConnectorOperation {
        id: "browser.extract_links",
        mapping: "worker",
        worker_operation_ids: &["browser.extract_links"],
    },
    BrowserConnectorOperation {
        id: "browser.wait_for_selector",
        mapping: "worker",
        worker_operation_ids: &["browser.wait_for_selector"],
    },
    BrowserConnectorOperation {
        id: "browser.click",
        mapping: "worker",
        worker_operation_ids: &["browser.click"],
    },
    BrowserConnectorOperation {
        id: "browser.fill_form",
        mapping: "worker",
        worker_operation_ids: &["browser.fill_form"],
    },
    BrowserConnectorOperation {
        id: "browser.evaluate_js",
        mapping: "worker",
        worker_operation_ids: &["browser.evaluate_js"],
    },
    BrowserConnectorOperation {
        id: "browser.get_cookies",
        mapping: "worker",
        worker_operation_ids: &["browser.get_cookies"],
    },
    BrowserConnectorOperation {
        id: "browser.set_cookies",
        mapping: "worker",
        worker_operation_ids: &["browser.set_cookies"],
    },
    BrowserConnectorOperation {
        id: "browser.session.save",
        mapping: "derived",
        worker_operation_ids: &["browser.get_cookies"],
    },
    BrowserConnectorOperation {
        id: "browser.session.restore",
        mapping: "derived",
        worker_operation_ids: &["browser.set_cookies"],
    },
    BrowserConnectorOperation {
        id: "browser.session.describe",
        mapping: "connector_state",
        worker_operation_ids: &[],
    },
    BrowserConnectorOperation {
        id: "browser.set_proxy",
        mapping: "worker",
        worker_operation_ids: &["browser.set_proxy"],
    },
    BrowserConnectorOperation {
        id: "browser.clear_proxy",
        mapping: "worker",
        worker_operation_ids: &["browser.clear_proxy"],
    },
];

/// FCP browser-control worker contract expected by this connector client.
pub(crate) fn browser_control_contract_descriptor() -> serde_json::Value {
    serde_json::json!({
        "control_plane": "fcp-browser-control",
        "protocol_version": BROWSER_CONTROL_PROTOCOL_VERSION,
        "operations": REQUIRED_BROWSER_CONTROL_OPERATIONS
            .iter()
            .map(|operation| operation.descriptor())
            .collect::<Vec<_>>(),
        "connector_operations": BROWSER_CONNECTOR_OPERATIONS
            .iter()
            .map(|operation| operation.descriptor())
            .collect::<Vec<_>>(),
    })
}

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

    /// Lightweight connectivity probe for the FCP browser-control plane.
    pub async fn health_check(&self) -> BrowserResult<()> {
        let url = format!("{}/health", self.browser_url);
        match self.execute(|| self.http.get(&url)).await {
            Ok(body) => validate_fcp_browser_control_health(&body).map_err(|reason| {
                BrowserError::InvalidConfig(format!(
                    "browser control-plane /health response is not compatible with fcp-browser-control contract v{BROWSER_CONTROL_PROTOCOL_VERSION}: {reason}"
                ))
            }),
            Err(err) => {
                if self.raw_chrome_cdp_endpoint_detected().await {
                    Err(BrowserError::InvalidConfig(
                        "browser_url points at a raw Chrome DevTools endpoint; configure an FCP browser-control endpoint for browser operations".into(),
                    ))
                } else {
                    Err(err)
                }
            }
        }
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
        self.retry_config.max_retries = max_retries;
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
        let endpoint = self.worker_endpoint(WORKER_NAVIGATE);
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
        let endpoint = self.worker_endpoint(WORKER_SCREENSHOT);
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
        let endpoint = self.worker_endpoint(WORKER_RENDER_PDF);
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
        let endpoint = self.worker_endpoint(WORKER_EXTRACT_TEXT);
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
        let endpoint = self.worker_endpoint(WORKER_EXTRACT_LINKS);
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
        let endpoint = self.worker_endpoint(WORKER_WAIT_FOR_SELECTOR);
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
        let endpoint = self.worker_endpoint(WORKER_CLICK);
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
        let endpoint = self.worker_endpoint(WORKER_FILL_FORM);
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
        let endpoint = self.worker_endpoint(WORKER_EVALUATE_JS);
        let body = serde_json::json!({ "expression": expression });
        let data = self.post_json(&endpoint, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- Cookies --

    /// Get cookies.
    pub async fn get_cookies(&self, domain: Option<&str>) -> BrowserResult<Vec<Cookie>> {
        let endpoint = self.worker_endpoint(WORKER_GET_COOKIES);
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
        let endpoint = self.worker_endpoint(WORKER_SET_COOKIES);
        let body = serde_json::json!({ "cookies": cookies });
        let data = self.post_json(&endpoint, &body).await?;
        let count = data.get("set_count").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(count as u32)
    }

    // -- Proxy --

    /// Configure outbound proxy for browser traffic.
    pub async fn set_proxy(&self, proxy: &ProxyConfig) -> BrowserResult<ProxyResult> {
        let endpoint = self.worker_endpoint(WORKER_SET_PROXY);
        let body = serde_json::to_value(proxy)?;
        let data = self.post_json(&endpoint, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Clear outbound proxy configuration.
    pub async fn clear_proxy(&self) -> BrowserResult<ProxyResult> {
        let endpoint = self.worker_endpoint(WORKER_CLEAR_PROXY);
        let data = self.post_json(&endpoint, &serde_json::json!({})).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- HTTP helpers --

    fn worker_endpoint(&self, operation: BrowserControlOperation) -> String {
        debug_assert_eq!(operation.method, "POST");
        format!("{}{}", self.browser_url, operation.path)
    }

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
                            let body = match read_limited_response_text(response).await {
                                Ok(body) => body,
                                Err(err) => return AttemptOutcome::Terminal(err),
                            };
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
                            let body = match read_limited_response_text(response).await {
                                Ok(body) => body,
                                Err(err) => return AttemptOutcome::Terminal(err),
                            };
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

                        match read_limited_response_text(response).await {
                            Ok(body) => match serde_json::from_str(&body) {
                                Ok(data) => AttemptOutcome::Success(data),
                                Err(e) => AttemptOutcome::Terminal(BrowserError::Serialization(e)),
                            },
                            Err(e) => AttemptOutcome::Terminal(e),
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

    async fn raw_chrome_cdp_endpoint_detected(&self) -> bool {
        let url = format!("{}/json/version", self.browser_url);
        match self.execute(|| self.http.get(&url)).await {
            Ok(body) => looks_like_chrome_cdp_version(&body),
            Err(_) => false,
        }
    }
}

async fn read_limited_response_text(response: reqwest::Response) -> BrowserResult<String> {
    let status = response.status();
    if let Some(content_length) = response.content_length() {
        if usize::try_from(content_length)
            .map_or(true, |length| length > MAX_BROWSER_CONTROL_RESPONSE_BYTES)
        {
            return Err(response_size_limit_error(status, Some(content_length)));
        }
    }

    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(BrowserError::Http)?;
        if body.len().saturating_add(chunk.len()) > MAX_BROWSER_CONTROL_RESPONSE_BYTES {
            return Err(response_size_limit_error(status, None));
        }
        body.extend_from_slice(&chunk);
    }

    String::from_utf8(body).map_err(|e| BrowserError::Api {
        message: format!("browser control response is not valid UTF-8 JSON: {e}"),
        status_code: Some(status.as_u16()),
    })
}

fn response_size_limit_error(status: StatusCode, content_length: Option<u64>) -> BrowserError {
    let message = match content_length {
        Some(content_length) => format!(
            "browser control response exceeds {MAX_BROWSER_CONTROL_RESPONSE_BYTES} byte limit: content-length {content_length}"
        ),
        None => {
            format!(
                "browser control response exceeds {MAX_BROWSER_CONTROL_RESPONSE_BYTES} byte limit"
            )
        }
    };

    BrowserError::Api {
        message,
        status_code: Some(status.as_u16()),
    }
}

fn validate_fcp_browser_control_health(body: &serde_json::Value) -> Result<(), String> {
    let control_plane = body
        .get("control_plane")
        .or_else(|| body.get("service"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing control_plane/service".to_string())?;
    if control_plane != "fcp-browser-control" && control_plane != "fcp.browser-control" {
        return Err(format!(
            "unexpected control_plane/service `{control_plane}`"
        ));
    }

    let protocol_version = body
        .get("protocol_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "missing numeric protocol_version".to_string())?;
    if protocol_version != BROWSER_CONTROL_PROTOCOL_VERSION {
        return Err(format!(
            "unsupported protocol_version {protocol_version}; expected {BROWSER_CONTROL_PROTOCOL_VERSION}"
        ));
    }

    let operations = body
        .get("operations")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "missing operations array".to_string())?;
    for required in REQUIRED_BROWSER_CONTROL_OPERATIONS {
        let operation = operations
            .iter()
            .find(|operation| {
                operation.get("id").and_then(serde_json::Value::as_str) == Some(required.id)
            })
            .ok_or_else(|| format!("missing required operation `{}`", required.id))?;
        validate_browser_control_operation(operation, required)?;
    }

    Ok(())
}

fn validate_browser_control_operation(
    operation: &serde_json::Value,
    required: &BrowserControlOperation,
) -> Result<(), String> {
    if operation
        .get("id")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|id| id == required.id)
        && operation
            .get("method")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|method| method == required.method)
        && operation
            .get("path")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|path| path == required.path)
        && browser_control_implementation_matches(operation, required)
    {
        Ok(())
    } else {
        Err(format!(
            "operation `{}` is incompatible; expected {} `{}` with implementation {}",
            required.id,
            required.method,
            required.path,
            required.implementation.summary()
        ))
    }
}

fn browser_control_implementation_matches(
    operation: &serde_json::Value,
    required: &BrowserControlOperation,
) -> bool {
    let implementation = &operation["implementation"];
    match required.implementation {
        BrowserControlImplementation::Cdp { methods } => {
            implementation
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|kind| kind == "cdp")
                && implementation
                    .get("methods")
                    .is_some_and(|advertised| advertised == &serde_json::json!(methods))
        }
        BrowserControlImplementation::WorkerPolicy { .. } => {
            implementation
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|kind| kind == "worker_policy")
                && implementation
                    .get("methods")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(Vec::is_empty)
                && implementation
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|description| !description.is_empty())
        }
    }
}

fn looks_like_chrome_cdp_version(body: &serde_json::Value) -> bool {
    body.get("webSocketDebuggerUrl")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value.starts_with("ws://") || value.starts_with("wss://"))
        || body
            .get("Browser")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| {
                value.starts_with("Chrome/") || value.starts_with("HeadlessChrome/")
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    #[fcp_async_core::runtime::test]
    async fn test_health_check_accepts_fcp_browser_control_plane() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(browser_control_contract_descriptor()),
            )
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri());

        client.health_check().await.unwrap();
    }

    #[test]
    fn test_worker_contract_advertises_every_client_route() {
        let descriptor = browser_control_contract_descriptor();
        let operations = descriptor["operations"].as_array().unwrap();

        for required in REQUIRED_BROWSER_CONTROL_OPERATIONS {
            assert!(
                operations.iter().any(|operation| {
                    operation["id"] == required.id
                        && operation["method"] == required.method
                        && operation["path"] == required.path
                }),
                "missing {} {} {}",
                required.method,
                required.path,
                required.id
            );
        }
        assert_eq!(operations.len(), REQUIRED_BROWSER_CONTROL_OPERATIONS.len());
    }

    #[test]
    fn test_worker_contract_pins_cdp_command_plan() {
        fn operation<'a>(operations: &'a [serde_json::Value], id: &str) -> &'a serde_json::Value {
            operations
                .iter()
                .find(|operation| operation["id"] == id)
                .unwrap()
        }

        let descriptor = browser_control_contract_descriptor();
        let operations = descriptor["operations"].as_array().unwrap();

        let navigate = operation(operations, "browser.navigate");
        assert_eq!(navigate["implementation"]["kind"], "cdp");
        assert_eq!(
            navigate["implementation"]["methods"],
            serde_json::json!([
                "Page.enable",
                "Network.enable",
                "Network.setUserAgentOverride",
                "Page.navigate"
            ])
        );

        let screenshot = operation(operations, "browser.screenshot");
        assert_eq!(screenshot["implementation"]["kind"], "cdp");
        assert_eq!(
            screenshot["implementation"]["methods"],
            serde_json::json!([
                "DOM.getDocument",
                "DOM.querySelector",
                "DOM.getBoxModel",
                "Page.getLayoutMetrics",
                "Page.captureScreenshot"
            ])
        );

        let click = operation(operations, "browser.click");
        assert_eq!(click["implementation"]["kind"], "cdp");
        assert_eq!(
            click["implementation"]["methods"],
            serde_json::json!([
                "DOM.getDocument",
                "DOM.querySelector",
                "DOM.getBoxModel",
                "Input.dispatchMouseEvent"
            ])
        );

        let get_cookies = operation(operations, "browser.get_cookies");
        assert_eq!(
            get_cookies["implementation"]["methods"],
            serde_json::json!(["Network.getCookies"])
        );

        let set_proxy = operation(operations, "browser.set_proxy");
        assert_eq!(set_proxy["implementation"]["kind"], "worker_policy");
        assert_eq!(
            set_proxy["implementation"]["methods"],
            serde_json::json!([])
        );
    }

    #[test]
    fn test_worker_contract_gives_every_worker_operation_an_execution_plan() {
        let descriptor = browser_control_contract_descriptor();
        let operations = descriptor["operations"].as_array().unwrap();

        for operation in operations {
            let id = operation["id"].as_str().unwrap();
            let implementation = &operation["implementation"];
            let kind = implementation["kind"].as_str().unwrap();
            let methods = implementation["methods"].as_array().unwrap();

            assert!(
                matches!(kind, "cdp" | "worker_policy"),
                "{id} has unknown implementation kind `{kind}`"
            );
            if kind == "cdp" {
                assert!(!methods.is_empty(), "{id} must list CDP methods");
                for method in methods {
                    let method = method.as_str().unwrap();
                    assert!(
                        method.split_once('.').is_some(),
                        "{id} has invalid CDP method `{method}`"
                    );
                }
            } else {
                assert!(
                    methods.is_empty(),
                    "{id} policy operations do not issue CDP"
                );
                assert!(
                    implementation["description"].as_str().is_some(),
                    "{id} policy operation must explain worker behavior"
                );
            }
        }
    }

    #[test]
    fn test_worker_contract_maps_session_operations_to_worker_primitives() {
        let descriptor = browser_control_contract_descriptor();
        let connector_operations = descriptor["connector_operations"].as_array().unwrap();
        assert_eq!(
            connector_operations.len(),
            BROWSER_CONNECTOR_OPERATIONS.len()
        );

        let session_save = connector_operations
            .iter()
            .find(|operation| operation["id"] == "browser.session.save")
            .unwrap();
        assert_eq!(session_save["mapping"], "derived");
        assert_eq!(
            session_save["worker_operation_ids"],
            serde_json::json!(["browser.get_cookies"])
        );

        let session_restore = connector_operations
            .iter()
            .find(|operation| operation["id"] == "browser.session.restore")
            .unwrap();
        assert_eq!(session_restore["mapping"], "derived");
        assert_eq!(
            session_restore["worker_operation_ids"],
            serde_json::json!(["browser.set_cookies"])
        );

        let session_describe = connector_operations
            .iter()
            .find(|operation| operation["id"] == "browser.session.describe")
            .unwrap();
        assert_eq!(session_describe["mapping"], "connector_state");
        assert_eq!(
            session_describe["worker_operation_ids"],
            serde_json::json!([])
        );
    }

    #[test]
    fn test_health_contract_rejects_missing_operation_advertisement() {
        let mut body = browser_control_contract_descriptor();
        body["operations"] = serde_json::Value::Array(vec![
            WORKER_NAVIGATE.descriptor(),
            WORKER_SCREENSHOT.descriptor(),
        ]);

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.render_pdf"));
    }

    #[test]
    fn test_health_contract_rejects_wrong_operation_path() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        operations[0]["path"] = serde_json::Value::String("/wrong-navigate".into());

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.navigate"));
        assert!(err.contains("/navigate"));
    }

    #[test]
    fn test_health_contract_rejects_wrong_operation_method() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        operations[0]["method"] = serde_json::Value::String("GET".into());

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.navigate"));
        assert!(err.contains("POST"));
    }

    #[test]
    fn test_health_contract_rejects_missing_operation_implementation() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        operations[0]
            .as_object_mut()
            .unwrap()
            .remove("implementation");

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.navigate"));
        assert!(err.contains("implementation"));
    }

    #[test]
    fn test_health_contract_rejects_wrong_cdp_command_plan() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        operations[0]["implementation"]["methods"] =
            serde_json::json!(["Page.enable", "Page.navigate"]);

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.navigate"));
        assert!(err.contains("Network.enable"));
    }

    #[test]
    fn test_health_contract_rejects_policy_operation_without_description() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        let set_proxy = operations
            .iter_mut()
            .find(|operation| operation["id"] == "browser.set_proxy")
            .unwrap();
        set_proxy["implementation"]
            .as_object_mut()
            .unwrap()
            .remove("description");

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.set_proxy"));
        assert!(err.contains("worker_policy"));
    }

    #[test]
    fn test_health_contract_rejects_wrong_protocol_version() {
        let mut body = browser_control_contract_descriptor();
        body["protocol_version"] = serde_json::Value::Number(2.into());

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("unsupported protocol_version 2"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_check_rejects_raw_chrome_cdp_endpoint() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/json/version"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Browser": "HeadlessChrome/123.0.0.0",
                "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/abc"
            })))
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri())
            .with_retry_config(0);

        let err = client.health_check().await.unwrap_err();
        let message = match err {
            BrowserError::InvalidConfig(message) => message,
            _ => String::new(),
        };
        assert!(message.contains("raw Chrome DevTools endpoint"));
    }

    #[test]
    fn test_chrome_cdp_version_detection_requires_cdp_shape() {
        assert!(looks_like_chrome_cdp_version(&serde_json::json!({
            "webSocketDebuggerUrl": "wss://browser.example/devtools/browser/abc"
        })));
        assert!(looks_like_chrome_cdp_version(&serde_json::json!({
            "Browser": "Chrome/123.0.0.0"
        })));
        assert!(!looks_like_chrome_cdp_version(&serde_json::json!({
            "control_plane": "fcp-browser-control",
            "protocol_version": 1,
            "operations": []
        })));
    }

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
    async fn test_oversized_browser_control_response_is_rejected() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/navigate"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![
                b'x';
                MAX_BROWSER_CONTROL_RESPONSE_BYTES
                    + 1
            ]))
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client
            .navigate("https://example.com", None, None, None)
            .await;
        let err = result.unwrap_err();
        assert!(format!("{err}").contains("browser control response exceeds"));
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
