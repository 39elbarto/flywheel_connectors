//! FCP Browser Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::BrowserClient, error::BrowserError, types::Cookie};

/// FCP Browser Connector.
pub struct BrowserConnector {
    base: Arc<BaseConnector>,
    client: Option<BrowserClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl BrowserConnector {
    /// Create a new Browser connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("fcp.browser"))),
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let api_key = params.get("api_key").and_then(|v| v.as_str());
        let browser_url = params.get("browser_url").and_then(|v| v.as_str());

        let mut client = BrowserClient::new(api_key).map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;

        if let Some(url) = browser_url {
            client = client.with_browser_url(url);
        }

        self.client = Some(client);
        self.base.set_configured(true);
        info!("Browser connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:browser-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle health check.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle introspect method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                op_info(
                    "browser.navigate",
                    "Navigate to a URL and wait for page load",
                    json!({
                        "type": "object",
                        "required": ["url"],
                        "properties": {
                            "url": { "type": "string" },
                            "wait_until": { "type": "string" },
                            "timeout_ms": { "type": "integer" },
                            "user_agent": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["url", "status"],
                        "properties": {
                            "url": { "type": "string" },
                            "status": { "type": "integer" },
                            "title": { "type": "string" }
                        }
                    }),
                    "browser.navigate",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Navigate the browser to a URL. Always call this before extraction or screenshot operations.".into(),
                        common_mistakes: vec![
                            "Not waiting for page load before extracting content.".into(),
                            "Navigating to internal/private IPs.".into(),
                        ],
                        examples: vec![
                            r#"{"url": "https://example.com", "wait_until": "networkidle"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("browser.screenshot"),
                            CapabilityId::from_static("browser.extract_text"),
                        ],
                    },
                ),
                op_info(
                    "browser.screenshot",
                    "Capture a screenshot of the current page or a specific element",
                    json!({
                        "type": "object",
                        "properties": {
                            "selector": { "type": "string" },
                            "full_page": { "type": "boolean" },
                            "format": { "type": "string" },
                            "quality": { "type": "integer" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["image_data", "width", "height"],
                        "properties": {
                            "image_data": { "type": "string" },
                            "width": { "type": "integer" },
                            "height": { "type": "integer" }
                        }
                    }),
                    "browser.capture",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Capture a visual screenshot of the current page or element for inspection.".into(),
                        common_mistakes: vec!["Taking screenshots before page fully loads.".into()],
                        examples: vec![r#"{"full_page": true, "format": "png"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("browser.navigate"),
                            CapabilityId::from_static("browser.render_pdf"),
                        ],
                    },
                ),
                op_info(
                    "browser.render_pdf",
                    "Render the current page as a PDF document",
                    json!({
                        "type": "object",
                        "properties": {
                            "format": { "type": "string" },
                            "landscape": { "type": "boolean" },
                            "print_background": { "type": "boolean" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["pdf_data", "page_count"],
                        "properties": {
                            "pdf_data": { "type": "string" },
                            "page_count": { "type": "integer" }
                        }
                    }),
                    "browser.capture",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Render the current page as a PDF for archival or offline reading.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"format": "a4", "print_background": true}"#.into()],
                        related: vec![CapabilityId::from_static("browser.screenshot")],
                    },
                ),
                op_info(
                    "browser.extract_text",
                    "Extract text content from the page or a specific element",
                    json!({
                        "type": "object",
                        "properties": {
                            "selector": { "type": "string" },
                            "include_hidden": { "type": "boolean" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["text"],
                        "properties": {
                            "text": { "type": "string" },
                            "word_count": { "type": "integer" }
                        }
                    }),
                    "browser.extract",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Extract text content from the currently loaded page.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"selector": "article"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("browser.extract_links"),
                            CapabilityId::from_static("browser.navigate"),
                        ],
                    },
                ),
                op_info(
                    "browser.extract_links",
                    "Extract all links from the page or a specific element",
                    json!({
                        "type": "object",
                        "properties": {
                            "selector": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["links"],
                        "properties": {
                            "links": { "type": "array" }
                        }
                    }),
                    "browser.extract",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Extract all hyperlinks from the current page.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"selector": "nav"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("browser.extract_text"),
                            CapabilityId::from_static("browser.navigate"),
                        ],
                    },
                ),
                op_info(
                    "browser.wait_for_selector",
                    "Wait for an element matching a CSS selector to appear",
                    json!({
                        "type": "object",
                        "required": ["selector"],
                        "properties": {
                            "selector": { "type": "string" },
                            "state": { "type": "string" },
                            "timeout_ms": { "type": "integer" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["found"],
                        "properties": {
                            "found": { "type": "boolean" }
                        }
                    }),
                    "browser.extract",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Wait for a dynamic element to appear before interacting with it.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"selector": ".results-loaded", "timeout_ms": 5000}"#.into()],
                        related: vec![
                            CapabilityId::from_static("browser.click"),
                            CapabilityId::from_static("browser.extract_text"),
                        ],
                    },
                ),
                op_info(
                    "browser.click",
                    "Click an element identified by CSS selector",
                    json!({
                        "type": "object",
                        "required": ["selector"],
                        "properties": {
                            "selector": { "type": "string" },
                            "timeout_ms": { "type": "integer" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["clicked"],
                        "properties": {
                            "clicked": { "type": "boolean" },
                            "navigation_url": { "type": "string" }
                        }
                    }),
                    "browser.interact",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Click a button, link, or interactive element on the page.".into(),
                        common_mistakes: vec!["Clicking before element is visible/interactable.".into()],
                        examples: vec![r#"{"selector": "button.submit"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("browser.fill_form"),
                            CapabilityId::from_static("browser.wait_for_selector"),
                        ],
                    },
                ),
                op_info(
                    "browser.fill_form",
                    "Fill form fields with provided values",
                    json!({
                        "type": "object",
                        "required": ["fields"],
                        "properties": {
                            "fields": { "type": "object" },
                            "submit_selector": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["filled_count"],
                        "properties": {
                            "filled_count": { "type": "integer" },
                            "submitted": { "type": "boolean" }
                        }
                    }),
                    "browser.interact",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Fill in form fields (inputs, textareas, selects) and optionally submit.".into(),
                        common_mistakes: vec![
                            "Filling fields before they are rendered.".into(),
                            "Not handling dynamic forms that add fields after interaction.".into(),
                        ],
                        examples: vec![
                            r##"{"fields": {"#email": "test@example.com"}, "submit_selector": "button[type=submit]"}"##.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("browser.click"),
                            CapabilityId::from_static("browser.wait_for_selector"),
                        ],
                    },
                ),
                op_info(
                    "browser.evaluate_js",
                    "Execute JavaScript in the page context and return the result",
                    json!({
                        "type": "object",
                        "required": ["expression"],
                        "properties": {
                            "expression": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["result"],
                        "properties": {
                            "result": { "type": "string" }
                        }
                    }),
                    "browser.execute",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Execute arbitrary JavaScript in page context. Dangerous - use only when extraction or interaction APIs are insufficient.".into(),
                        common_mistakes: vec![
                            "Injecting untrusted user input into expressions (XSS risk).".into(),
                            "Returning non-serializable objects (Promises, DOM nodes).".into(),
                        ],
                        examples: vec![r#"{"expression": "document.title"}"#.into()],
                        related: vec![CapabilityId::from_static("browser.extract_text")],
                    },
                ),
                op_info(
                    "browser.get_cookies",
                    "Get cookies for the current page or a specific domain",
                    json!({
                        "type": "object",
                        "properties": {
                            "domain": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["cookies"],
                        "properties": {
                            "cookies": { "type": "array" }
                        }
                    }),
                    "browser.cookies",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve cookies for session inspection or debugging.".into(),
                        common_mistakes: vec!["Leaking session cookies to untrusted contexts.".into()],
                        examples: vec![r#"{"domain": "example.com"}"#.into()],
                        related: vec![CapabilityId::from_static("browser.set_cookies")],
                    },
                ),
                op_info(
                    "browser.set_cookies",
                    "Set cookies in the browser session",
                    json!({
                        "type": "object",
                        "required": ["cookies"],
                        "properties": {
                            "cookies": { "type": "array" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["set_count"],
                        "properties": {
                            "set_count": { "type": "integer" }
                        }
                    }),
                    "browser.cookies",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Inject cookies for authenticated session setup.".into(),
                        common_mistakes: vec!["Setting cookies on wrong domain.".into()],
                        examples: vec![
                            r#"{"cookies": [{"name": "session", "value": "abc123", "domain": "example.com", "path": "/"}]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("browser.get_cookies")],
                    },
                ),
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle simulate method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle invoke method.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation =
            params
                .get("operation")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id: CapabilityId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "browser.navigate" => self.invoke_navigate(input).await,
            "browser.screenshot" => self.invoke_screenshot(input).await,
            "browser.render_pdf" => self.invoke_render_pdf(input).await,
            "browser.extract_text" => self.invoke_extract_text(input).await,
            "browser.extract_links" => self.invoke_extract_links(input).await,
            "browser.wait_for_selector" => self.invoke_wait_for_selector(input).await,
            "browser.click" => self.invoke_click(input).await,
            "browser.fill_form" => self.invoke_fill_form(input).await,
            "browser.evaluate_js" => self.invoke_evaluate_js(input).await,
            "browser.get_cookies" => self.invoke_get_cookies(input).await,
            "browser.set_cookies" => self.invoke_set_cookies(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // -- Operation implementations --

    async fn invoke_navigate(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let url = require_str(&input, "url")?;
        let wait_until = input.get("wait_until").and_then(|v| v.as_str());
        let timeout_ms = input.get("timeout_ms").and_then(|v| v.as_u64());
        let user_agent = input.get("user_agent").and_then(|v| v.as_str());
        let result = client
            .navigate(url, wait_until, timeout_ms, user_agent)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({ "url": result.url, "status": result.status, "title": result.title }))
    }

    async fn invoke_screenshot(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let selector = input.get("selector").and_then(|v| v.as_str());
        let full_page = input.get("full_page").and_then(|v| v.as_bool());
        let format = input.get("format").and_then(|v| v.as_str());
        let quality = input
            .get("quality")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let result = client
            .screenshot(selector, full_page, format, quality)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(
            json!({ "image_data": result.image_data, "width": result.width, "height": result.height }),
        )
    }

    async fn invoke_render_pdf(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let format = input.get("format").and_then(|v| v.as_str());
        let landscape = input.get("landscape").and_then(|v| v.as_bool());
        let print_background = input.get("print_background").and_then(|v| v.as_bool());
        let result = client
            .render_pdf(format, landscape, print_background)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({ "pdf_data": result.pdf_data, "page_count": result.page_count }))
    }

    async fn invoke_extract_text(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let selector = input.get("selector").and_then(|v| v.as_str());
        let include_hidden = input.get("include_hidden").and_then(|v| v.as_bool());
        let result = client
            .extract_text(selector, include_hidden)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({ "text": result.text, "word_count": result.word_count }))
    }

    async fn invoke_extract_links(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let selector = input.get("selector").and_then(|v| v.as_str());
        let result = client
            .extract_links(selector)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({ "links": result.links }))
    }

    async fn invoke_wait_for_selector(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let selector = require_str(&input, "selector")?;
        let state = input.get("state").and_then(|v| v.as_str());
        let timeout_ms = input.get("timeout_ms").and_then(|v| v.as_u64());
        let result = client
            .wait_for_selector(selector, state, timeout_ms)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({ "found": result.found }))
    }

    async fn invoke_click(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let selector = require_str(&input, "selector")?;
        let timeout_ms = input.get("timeout_ms").and_then(|v| v.as_u64());
        let result = client
            .click(selector, timeout_ms)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({ "clicked": result.clicked, "navigation_url": result.navigation_url }))
    }

    async fn invoke_fill_form(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let fields = input.get("fields").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: fields".into(),
        })?;
        let submit_selector = input.get("submit_selector").and_then(|v| v.as_str());
        let result = client
            .fill_form(fields, submit_selector)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({ "filled_count": result.filled_count, "submitted": result.submitted }))
    }

    async fn invoke_evaluate_js(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let expression = require_str(&input, "expression")?;
        let result = client
            .evaluate_js(expression)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({ "result": result.result }))
    }

    async fn invoke_get_cookies(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let domain = input.get("domain").and_then(|v| v.as_str());
        let cookies = client
            .get_cookies(domain)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({ "cookies": cookies }))
    }

    async fn invoke_set_cookies(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let cookies_value = input.get("cookies").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: cookies".into(),
        })?;
        let cookies: Vec<Cookie> = serde_json::from_value(cookies_value.clone()).map_err(|e| {
            FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid cookies format: {e}"),
            }
        })?;
        let count = client
            .set_cookies(&cookies)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({ "set_count": count }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Browser connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for BrowserConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

#[allow(clippy::fn_params_excessive_bools)]
fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval: None,
        safety_tier,
        idempotency,
        ai_hints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::ConnectorManifest;
    use std::path::PathBuf;

    fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> CapabilityToken {
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[cap])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .sign(signing_key)
            .unwrap();
        CapabilityToken { raw: cose }
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = BrowserConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["browser.navigate"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = BrowserConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = BrowserConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["browser.navigate"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "browser.navigate");
        let result = connector
            .handle_invoke(json!({
                "operation": "browser.navigate",
                "input": { "url": "https://example.com" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = BrowserConnector::new();
        connector.client = Some(
            BrowserClient::new(None)
                .unwrap()
                .with_browser_url("http://localhost:9999"),
        );

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["browser.click"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "browser.click");
        let result = connector
            .handle_invoke(json!({
                "operation": "browser.click",
                "input": {},
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("selector")),
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = BrowserConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"browser.navigate"));
        assert!(op_ids.contains(&"browser.screenshot"));
        assert!(op_ids.contains(&"browser.render_pdf"));
        assert!(op_ids.contains(&"browser.extract_text"));
        assert!(op_ids.contains(&"browser.extract_links"));
        assert!(op_ids.contains(&"browser.wait_for_selector"));
        assert!(op_ids.contains(&"browser.click"));
        assert!(op_ids.contains(&"browser.fill_form"));
        assert!(op_ids.contains(&"browser.evaluate_js"));
        assert!(op_ids.contains(&"browser.get_cookies"));
        assert!(op_ids.contains(&"browser.set_cookies"));
        assert_eq!(ops.len(), 11);
    }

    #[test]
    fn manifest_interface_hash_is_deterministic() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        if !manifest_path.exists() {
            eprintln!("manifest.toml missing; skipping interface_hash check");
            return;
        }

        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let computed = manifest
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(computed, computed2);
    }
}
