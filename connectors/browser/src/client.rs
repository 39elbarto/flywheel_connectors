//! Browser automation API client.
//!
//! Talks to the FCP browser-control plane. The control plane may use Chrome
//! DevTools Protocol internally, but this client does not treat a raw Chrome
//! `/json/version` endpoint as sufficient proof that FCP browser operations are
//! available.

use std::time::Duration;

use fcp_async_core::{
    Cx,
    net::TcpStream,
    websocket::{Message as WebSocketMessage, WebSocket, WsError},
};
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

const CONTROL_RESPONSE_BYTES_SMALL: usize = 1_048_576;
const CONTROL_RESPONSE_BYTES_STANDARD: usize = 10_485_760;
const CONTROL_RESPONSE_BYTES_CAPTURE: usize = 52_428_800;
const CONTROL_TIMEOUT_MS_SHORT: u64 = 10_000;
const CONTROL_TIMEOUT_MS_STANDARD: u64 = 30_000;
const CONTROL_TIMEOUT_MS_CAPTURE: u64 = 60_000;
const CONTROL_OPERATION_HEADER: &str = "X-FCP-Browser-Operation";
const CONTROL_RESPONSE_BUDGET_HEADER: &str = "X-FCP-Browser-Max-Response-Bytes";
const CONTROL_TIMEOUT_BUDGET_HEADER: &str = "X-FCP-Browser-Timeout-Ms";
const CONTROL_TARGET_SCOPE_HEADER: &str = "X-FCP-Browser-Target-Scope";
const CONTROL_TARGET_SELECTION_HEADER: &str = "X-FCP-Browser-Target-Selection";
const CONTROL_STALE_TARGET_RECOVERY_HEADER: &str = "X-FCP-Browser-Stale-Target-Recovery";
const CONTROL_CURRENT_TAB_GUARD_HEADER: &str = "X-FCP-Browser-Current-Tab-Guard";
const CONTROL_EXPORT_GUARD_HEADER: &str = "X-FCP-Browser-Export-Guard";

#[derive(Clone, Copy)]
struct BrowserControlOperation {
    id: &'static str,
    method: &'static str,
    path: &'static str,
    max_response_bytes: usize,
    timeout_ms: u64,
    target_policy: BrowserTargetPolicy,
    implementation: BrowserControlImplementation,
}

impl BrowserControlOperation {
    fn descriptor(self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "method": self.method,
            "path": self.path,
            "max_response_bytes": self.max_response_bytes,
            "timeout_ms": self.timeout_ms,
            "target_policy": self.target_policy.descriptor(),
            "request_headers": self.request_headers_descriptor(),
            "implementation": self.implementation.descriptor(),
        })
    }

    fn request_headers_descriptor(self) -> serde_json::Value {
        serde_json::json!([
            { "name": CONTROL_OPERATION_HEADER, "value": self.id },
            { "name": CONTROL_RESPONSE_BUDGET_HEADER, "value": self.max_response_bytes.to_string() },
            { "name": CONTROL_TIMEOUT_BUDGET_HEADER, "value": self.timeout_ms.to_string() },
            { "name": CONTROL_TARGET_SCOPE_HEADER, "value": self.target_policy.scope },
            { "name": CONTROL_TARGET_SELECTION_HEADER, "value": self.target_policy.selection },
            {
                "name": CONTROL_STALE_TARGET_RECOVERY_HEADER,
                "value": self.target_policy.stale_target_recovery.to_string()
            },
            {
                "name": CONTROL_CURRENT_TAB_GUARD_HEADER,
                "value": self.target_policy.current_tab_guard.to_string()
            },
            {
                "name": CONTROL_EXPORT_GUARD_HEADER,
                "value": self.target_policy.export_guard.to_string()
            },
        ])
    }

    fn request_headers_summary(self) -> String {
        format!(
            "{}={}, {}={}, {}={}, {}={}, {}={}, {}={}, {}={}, {}={}",
            CONTROL_OPERATION_HEADER,
            self.id,
            CONTROL_RESPONSE_BUDGET_HEADER,
            self.max_response_bytes,
            CONTROL_TIMEOUT_BUDGET_HEADER,
            self.timeout_ms,
            CONTROL_TARGET_SCOPE_HEADER,
            self.target_policy.scope,
            CONTROL_TARGET_SELECTION_HEADER,
            self.target_policy.selection,
            CONTROL_STALE_TARGET_RECOVERY_HEADER,
            self.target_policy.stale_target_recovery,
            CONTROL_CURRENT_TAB_GUARD_HEADER,
            self.target_policy.current_tab_guard,
            CONTROL_EXPORT_GUARD_HEADER,
            self.target_policy.export_guard
        )
    }
}

#[derive(Clone, Copy)]
struct BrowserTargetPolicy {
    scope: &'static str,
    selection: &'static str,
    stale_target_recovery: bool,
    current_tab_guard: bool,
    export_guard: bool,
}

impl BrowserTargetPolicy {
    fn descriptor(self) -> serde_json::Value {
        serde_json::json!({
            "scope": self.scope,
            "selection": self.selection,
            "stale_target_recovery": self.stale_target_recovery,
            "current_tab_guard": self.current_tab_guard,
            "export_guard": self.export_guard,
        })
    }

    fn summary(self) -> String {
        format!(
            "{}:{} stale_target_recovery={} current_tab_guard={} export_guard={}",
            self.scope,
            self.selection,
            self.stale_target_recovery,
            self.current_tab_guard,
            self.export_guard
        )
    }
}

const TARGET_CREATE_OR_REUSE_PAGE: BrowserTargetPolicy = BrowserTargetPolicy {
    scope: "page",
    selection: "create_or_reuse_active_page",
    stale_target_recovery: true,
    current_tab_guard: false,
    export_guard: false,
};
const TARGET_ACTIVE_PAGE_INTERACTION: BrowserTargetPolicy = BrowserTargetPolicy {
    scope: "page",
    selection: "active_page_required",
    stale_target_recovery: true,
    current_tab_guard: true,
    export_guard: false,
};
const TARGET_ACTIVE_PAGE_EXPORT: BrowserTargetPolicy = BrowserTargetPolicy {
    scope: "page",
    selection: "active_page_required",
    stale_target_recovery: true,
    current_tab_guard: true,
    export_guard: true,
};
const TARGET_BROWSER_CONTEXT: BrowserTargetPolicy = BrowserTargetPolicy {
    scope: "browser_context",
    selection: "active_context_required",
    stale_target_recovery: true,
    current_tab_guard: false,
    export_guard: false,
};
const TARGET_CONNECTOR_POLICY: BrowserTargetPolicy = BrowserTargetPolicy {
    scope: "connector_policy",
    selection: "no_browser_target",
    stale_target_recovery: false,
    current_tab_guard: false,
    export_guard: false,
};

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

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
struct CdpCommand {
    id: u64,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
}

impl CdpCommand {
    fn new(id: u64, method: impl Into<String>, params: Option<serde_json::Value>) -> Self {
        Self {
            id,
            method: method.into(),
            params,
        }
    }

    fn to_websocket_message(&self) -> BrowserResult<WebSocketMessage> {
        Ok(WebSocketMessage::Text(serde_json::to_string(self)?))
    }
}

#[derive(Debug, Clone, PartialEq)]
struct CdpNavigateResponse {
    frame_id: String,
    loader_id: Option<String>,
}

impl CdpNavigateResponse {
    fn from_result(result: &serde_json::Value) -> BrowserResult<Self> {
        if let Some(error_text) = result
            .get("errorText")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
        {
            return Err(BrowserError::Api {
                message: format!(
                    "Chrome DevTools Protocol navigation failed: {}",
                    redact_browser_control_error_text(error_text)
                ),
                status_code: None,
            });
        }

        let frame_id = result
            .get("frameId")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| BrowserError::Api {
                message: "Chrome DevTools Protocol Page.navigate response is missing frameId"
                    .into(),
                status_code: None,
            })?
            .to_string();
        let loader_id = result
            .get("loaderId")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string);

        Ok(Self {
            frame_id,
            loader_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
struct CdpEvaluateResponse {
    result: String,
}

impl CdpEvaluateResponse {
    fn from_result(result: &serde_json::Value) -> BrowserResult<Self> {
        if let Some(exception) = result.get("exceptionDetails") {
            let mut redacted_exception = exception.clone();
            redact_sensitive_json(&mut redacted_exception);
            return Err(BrowserError::Api {
                message: format!(
                    "Chrome DevTools Protocol Runtime.evaluate failed: {}",
                    serde_json::to_string(&redacted_exception)?
                ),
                status_code: None,
            });
        }

        let remote_object = result.get("result").ok_or_else(|| BrowserError::Api {
            message: "Chrome DevTools Protocol Runtime.evaluate response is missing result object"
                .into(),
            status_code: None,
        })?;

        let result = if let Some(value) = remote_object.get("value") {
            cdp_remote_value_to_result_string(value)?
        } else if let Some(value) = remote_object
            .get("unserializableValue")
            .and_then(serde_json::Value::as_str)
        {
            value.to_string()
        } else if remote_object
            .get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|kind| kind == "undefined")
        {
            "undefined".to_string()
        } else if let Some(description) = remote_object
            .get("description")
            .and_then(serde_json::Value::as_str)
        {
            description.to_string()
        } else {
            return Err(BrowserError::Api {
                message:
                    "Chrome DevTools Protocol Runtime.evaluate result has no serializable value"
                        .into(),
                status_code: None,
            });
        };

        Ok(Self { result })
    }
}

#[derive(Debug, Clone, PartialEq)]
struct CdpScreenshotResponse {
    image_data: String,
    width: u32,
    height: u32,
}

impl CdpScreenshotResponse {
    fn from_capture_result(
        result: &serde_json::Value,
        clip: CdpCaptureClip,
    ) -> BrowserResult<Self> {
        let image_data = result
            .get("data")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| BrowserError::Api {
                message: "Chrome DevTools Protocol Page.captureScreenshot response is missing data"
                    .into(),
                status_code: None,
            })?
            .to_string();

        Ok(Self {
            image_data,
            width: capture_dimension_to_u32("width", clip.width)?,
            height: capture_dimension_to_u32("height", clip.height)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
struct CdpCookieResponse {
    cookies: Vec<Cookie>,
}

impl CdpCookieResponse {
    fn from_result(result: &serde_json::Value, domain_filter: Option<&str>) -> BrowserResult<Self> {
        let cookies = result
            .get("cookies")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| BrowserError::Api {
                message: "Chrome DevTools Protocol Network.getCookies response is missing cookies"
                    .into(),
                status_code: None,
            })?;
        let mut parsed = Vec::new();
        for cookie in cookies {
            let cookie = cdp_cookie_from_value(cookie)?;
            if cookie_matches_domain_filter(cookie.domain.as_deref(), domain_filter) {
                parsed.push(cookie);
            }
        }

        Ok(Self { cookies: parsed })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CdpSetCookiesResponse {
    set_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct CdpCaptureClip {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

impl CdpCaptureClip {
    fn new(x: f64, y: f64, width: f64, height: f64) -> BrowserResult<Self> {
        for (name, value) in [("x", x), ("y", y), ("width", width), ("height", height)] {
            if !value.is_finite() {
                return Err(BrowserError::Api {
                    message: format!(
                        "Chrome DevTools Protocol screenshot clip {name} is not finite"
                    ),
                    status_code: None,
                });
            }
        }

        if width <= 0.0 || height <= 0.0 {
            return Err(BrowserError::Api {
                message: format!(
                    "Chrome DevTools Protocol screenshot clip must have positive dimensions: width={width}, height={height}"
                ),
                status_code: None,
            });
        }

        Ok(Self {
            x,
            y,
            width,
            height,
        })
    }

    fn from_box_model(result: &serde_json::Value) -> BrowserResult<Self> {
        let content = result
            .get("model")
            .and_then(|model| model.get("content"))
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| BrowserError::Api {
                message:
                    "Chrome DevTools Protocol DOM.getBoxModel response is missing model.content"
                        .into(),
                status_code: None,
            })?;
        if content.len() != 8 {
            return Err(BrowserError::Api {
                message: format!(
                    "Chrome DevTools Protocol DOM.getBoxModel content quad must have 8 coordinates, got {}",
                    content.len()
                ),
                status_code: None,
            });
        }

        let mut min_x = f64::INFINITY;
        let mut min_y = f64::INFINITY;
        let mut max_x = f64::NEG_INFINITY;
        let mut max_y = f64::NEG_INFINITY;
        for point in content.chunks_exact(2) {
            let [x_value, y_value] = point else {
                return Err(BrowserError::Api {
                    message: "Chrome DevTools Protocol DOM.getBoxModel content point is malformed"
                        .into(),
                    status_code: None,
                });
            };
            let x = cdp_required_number(x_value, "DOM.getBoxModel model.content x")?;
            let y = cdp_required_number(y_value, "DOM.getBoxModel model.content y")?;
            min_x = min_x.min(x);
            min_y = min_y.min(y);
            max_x = max_x.max(x);
            max_y = max_y.max(y);
        }

        Self::new(min_x, min_y, max_x - min_x, max_y - min_y)
    }

    fn from_layout_metrics(result: &serde_json::Value, full_page: bool) -> BrowserResult<Self> {
        if full_page {
            let content = result
                .get("cssContentSize")
                .or_else(|| result.get("contentSize"))
                .ok_or_else(|| BrowserError::Api {
                    message: "Chrome DevTools Protocol Page.getLayoutMetrics response is missing content size"
                        .into(),
                    status_code: None,
                })?;
            return Self::new(
                cdp_required_object_number(content, "x", "Page.getLayoutMetrics content x")?,
                cdp_required_object_number(content, "y", "Page.getLayoutMetrics content y")?,
                cdp_required_object_number(
                    content,
                    "width",
                    "Page.getLayoutMetrics content width",
                )?,
                cdp_required_object_number(
                    content,
                    "height",
                    "Page.getLayoutMetrics content height",
                )?,
            );
        }

        let viewport = result
            .get("cssVisualViewport")
            .or_else(|| result.get("visualViewport"))
            .or_else(|| result.get("cssLayoutViewport"))
            .or_else(|| result.get("layoutViewport"))
            .ok_or_else(|| BrowserError::Api {
                message: "Chrome DevTools Protocol Page.getLayoutMetrics response is missing viewport size"
                    .into(),
                status_code: None,
            })?;
        Self::new(
            cdp_required_object_number(viewport, "pageX", "Page.getLayoutMetrics viewport pageX")
                .or_else(|_| {
                cdp_required_object_number(viewport, "x", "Page.getLayoutMetrics viewport x")
            })?,
            cdp_required_object_number(viewport, "pageY", "Page.getLayoutMetrics viewport pageY")
                .or_else(|_| {
                cdp_required_object_number(viewport, "y", "Page.getLayoutMetrics viewport y")
            })?,
            cdp_required_object_number(
                viewport,
                "clientWidth",
                "Page.getLayoutMetrics viewport clientWidth",
            )
            .or_else(|_| {
                cdp_required_object_number(
                    viewport,
                    "width",
                    "Page.getLayoutMetrics viewport width",
                )
            })?,
            cdp_required_object_number(
                viewport,
                "clientHeight",
                "Page.getLayoutMetrics viewport clientHeight",
            )
            .or_else(|_| {
                cdp_required_object_number(
                    viewport,
                    "height",
                    "Page.getLayoutMetrics viewport height",
                )
            })?,
        )
    }

    fn descriptor(self) -> serde_json::Value {
        serde_json::json!({
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "scale": 1,
        })
    }
}

fn cdp_remote_value_to_result_string(value: &serde_json::Value) -> BrowserResult<String> {
    match value {
        serde_json::Value::String(text) => Ok(text.clone()),
        serde_json::Value::Null => Ok("null".to_string()),
        other => Ok(serde_json::to_string(other)?),
    }
}

fn cdp_required_object_number(
    object: &serde_json::Value,
    field: &str,
    label: &str,
) -> BrowserResult<f64> {
    cdp_required_number(object.get(field).unwrap_or(&serde_json::Value::Null), label)
}

fn cdp_required_number(value: &serde_json::Value, label: &str) -> BrowserResult<f64> {
    let number = value.as_f64().ok_or_else(|| BrowserError::Api {
        message: format!("Chrome DevTools Protocol response is missing numeric {label}"),
        status_code: None,
    })?;
    if number.is_finite() {
        Ok(number)
    } else {
        Err(BrowserError::Api {
            message: format!("Chrome DevTools Protocol response {label} is not finite"),
            status_code: None,
        })
    }
}

fn cdp_required_node_id(result: &serde_json::Value, path: &str) -> BrowserResult<u64> {
    result
        .pointer(path)
        .and_then(serde_json::Value::as_u64)
        .filter(|node_id| *node_id != 0)
        .ok_or_else(|| BrowserError::Api {
            message: format!("Chrome DevTools Protocol response is missing non-zero {path}"),
            status_code: None,
        })
}

fn capture_dimension_to_u32(name: &str, value: f64) -> BrowserResult<u32> {
    if !value.is_finite() || value <= 0.0 || value > f64::from(u32::MAX) {
        return Err(BrowserError::Api {
            message: format!("Chrome DevTools Protocol screenshot {name} is out of range: {value}"),
            status_code: None,
        });
    }

    let rounded = value.ceil();
    format!("{rounded:.0}")
        .parse::<u32>()
        .map_err(|err| BrowserError::Api {
            message: format!(
                "Chrome DevTools Protocol screenshot {name} cannot be represented as u32: {err}"
            ),
            status_code: None,
        })
}

fn cdp_screenshot_format(format: Option<&str>) -> BrowserResult<String> {
    let format = format.unwrap_or("png").to_ascii_lowercase();
    if matches!(format.as_str(), "jpeg" | "png" | "webp") {
        Ok(format)
    } else {
        Err(BrowserError::Api {
            message: format!(
                "Chrome DevTools Protocol Page.captureScreenshot does not support image format `{format}`"
            ),
            status_code: None,
        })
    }
}

fn cdp_cookie_from_value(value: &serde_json::Value) -> BrowserResult<Cookie> {
    let name = cdp_required_object_string(value, "name", "Network.Cookie name")?;
    let cookie_value = cdp_required_object_string(value, "value", "Network.Cookie value")?;

    Ok(Cookie {
        name,
        value: cookie_value,
        domain: cdp_optional_object_string(value, "domain"),
        path: cdp_optional_object_string(value, "path"),
        expires: value.get("expires").and_then(serde_json::Value::as_f64),
        http_only: value.get("httpOnly").and_then(serde_json::Value::as_bool),
        secure: value.get("secure").and_then(serde_json::Value::as_bool),
        same_site: cdp_optional_object_string(value, "sameSite"),
    })
}

fn cdp_cookie_param(cookie: &Cookie) -> serde_json::Value {
    let mut param = serde_json::Map::new();
    param.insert(
        "name".to_string(),
        serde_json::Value::String(cookie.name.clone()),
    );
    param.insert(
        "value".to_string(),
        serde_json::Value::String(cookie.value.clone()),
    );
    if let Some(domain) = &cookie.domain {
        param.insert(
            "domain".to_string(),
            serde_json::Value::String(domain.clone()),
        );
    }
    if let Some(path) = &cookie.path {
        param.insert("path".to_string(), serde_json::Value::String(path.clone()));
    }
    if let Some(expires) = cookie.expires {
        param.insert("expires".to_string(), serde_json::json!(expires));
    }
    if let Some(http_only) = cookie.http_only {
        param.insert("httpOnly".to_string(), serde_json::Value::Bool(http_only));
    }
    if let Some(secure) = cookie.secure {
        param.insert("secure".to_string(), serde_json::Value::Bool(secure));
    }
    if let Some(same_site) = &cookie.same_site {
        param.insert(
            "sameSite".to_string(),
            serde_json::Value::String(same_site.clone()),
        );
    }
    serde_json::Value::Object(param)
}

fn cdp_required_object_string(
    object: &serde_json::Value,
    field: &str,
    label: &str,
) -> BrowserResult<String> {
    object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| BrowserError::Api {
            message: format!("Chrome DevTools Protocol response is missing non-empty {label}"),
            status_code: None,
        })
}

fn cdp_optional_object_string(object: &serde_json::Value, field: &str) -> Option<String> {
    object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn cookie_matches_domain_filter(cookie_domain: Option<&str>, domain_filter: Option<&str>) -> bool {
    let Some(domain_filter) = domain_filter else {
        return true;
    };
    let Some(cookie_domain) = cookie_domain else {
        return false;
    };

    let normalized_cookie = cookie_domain.trim_start_matches('.').to_ascii_lowercase();
    let normalized_filter = domain_filter.trim_start_matches('.').to_ascii_lowercase();
    normalized_cookie == normalized_filter
        || normalized_cookie
            .strip_suffix(&normalized_filter)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

#[async_trait::async_trait]
trait CdpCommandTransport {
    async fn send_cdp_message(&mut self, cx: &Cx, message: WebSocketMessage) -> BrowserResult<()>;

    async fn recv_cdp_message(&mut self, cx: &Cx) -> BrowserResult<Option<WebSocketMessage>>;
}

#[async_trait::async_trait]
impl CdpCommandTransport for WebSocket<TcpStream> {
    async fn send_cdp_message(&mut self, cx: &Cx, message: WebSocketMessage) -> BrowserResult<()> {
        self.send(cx, message)
            .await
            .map_err(|err| cdp_websocket_error(&err))
    }

    async fn recv_cdp_message(&mut self, cx: &Cx) -> BrowserResult<Option<WebSocketMessage>> {
        self.recv(cx).await.map_err(|err| cdp_websocket_error(&err))
    }
}

async fn execute_cdp_command<T>(
    cx: &Cx,
    transport: &mut T,
    command: CdpCommand,
) -> BrowserResult<serde_json::Value>
where
    T: CdpCommandTransport + Send,
{
    let expected_command_id = command.id;
    cx.checkpoint().map_err(|err| BrowserError::Api {
        message: format!(
            "Chrome DevTools Protocol command {expected_command_id} cancelled before send: {err}"
        ),
        status_code: None,
    })?;

    transport
        .send_cdp_message(cx, command.to_websocket_message()?)
        .await?;

    loop {
        cx.checkpoint().map_err(|err| BrowserError::Api {
            message: format!(
                "Chrome DevTools Protocol command {expected_command_id} cancelled while waiting for response: {err}"
            ),
            status_code: None,
        })?;

        let Some(message) = transport.recv_cdp_message(cx).await? else {
            return Err(BrowserError::Api {
                message: format!(
                    "Chrome DevTools Protocol connection closed before command {expected_command_id} response"
                ),
                status_code: None,
            });
        };

        if let Some(result) = decode_cdp_response_message(message, expected_command_id)? {
            return Ok(result);
        }
    }
}

fn cdp_websocket_error(error: &WsError) -> BrowserError {
    BrowserError::Api {
        message: format!("Chrome DevTools Protocol WebSocket error: {error}"),
        status_code: None,
    }
}

struct CdpSession<T> {
    transport: T,
    next_command_id: u64,
}

impl<T> CdpSession<T>
where
    T: CdpCommandTransport + Send,
{
    fn new(transport: T) -> Self {
        Self {
            transport,
            next_command_id: 1,
        }
    }

    async fn call_method(
        &mut self,
        cx: &Cx,
        method: impl Into<String>,
        params: Option<serde_json::Value>,
    ) -> BrowserResult<serde_json::Value> {
        let command = self.next_command(method, params)?;
        execute_cdp_command(cx, &mut self.transport, command).await
    }

    async fn navigate_page(
        &mut self,
        cx: &Cx,
        url: &str,
        user_agent: Option<&str>,
    ) -> BrowserResult<CdpNavigateResponse> {
        self.call_method(cx, "Page.enable", None).await?;
        self.call_method(cx, "Network.enable", None).await?;

        if let Some(user_agent) = user_agent {
            self.call_method(
                cx,
                "Network.setUserAgentOverride",
                Some(serde_json::json!({ "userAgent": user_agent })),
            )
            .await?;
        }

        let result = self
            .call_method(cx, "Page.navigate", Some(serde_json::json!({ "url": url })))
            .await?;
        CdpNavigateResponse::from_result(&result)
    }

    async fn evaluate_expression(
        &mut self,
        cx: &Cx,
        expression: &str,
    ) -> BrowserResult<CdpEvaluateResponse> {
        let result = self
            .call_method(
                cx,
                "Runtime.evaluate",
                Some(serde_json::json!({
                    "expression": expression,
                    "awaitPromise": true,
                    "returnByValue": true,
                })),
            )
            .await?;
        CdpEvaluateResponse::from_result(&result)
    }

    async fn capture_screenshot(
        &mut self,
        cx: &Cx,
        selector: Option<&str>,
        full_page: bool,
        format: Option<&str>,
        quality: Option<u32>,
    ) -> BrowserResult<CdpScreenshotResponse> {
        let clip = if let Some(selector) = selector {
            let document = self
                .call_method(
                    cx,
                    "DOM.getDocument",
                    Some(serde_json::json!({ "depth": 0, "pierce": false })),
                )
                .await?;
            let root_node_id = cdp_required_node_id(&document, "/root/nodeId")?;
            let query = self
                .call_method(
                    cx,
                    "DOM.querySelector",
                    Some(serde_json::json!({
                        "nodeId": root_node_id,
                        "selector": selector,
                    })),
                )
                .await?;
            let node_id = query
                .get("nodeId")
                .and_then(serde_json::Value::as_u64)
                .filter(|node_id| *node_id != 0)
                .ok_or_else(|| BrowserError::Api {
                    message: format!(
                        "Chrome DevTools Protocol DOM.querySelector selector `{selector}` did not match any node"
                    ),
                    status_code: None,
                })?;
            let box_model = self
                .call_method(
                    cx,
                    "DOM.getBoxModel",
                    Some(serde_json::json!({ "nodeId": node_id })),
                )
                .await?;
            CdpCaptureClip::from_box_model(&box_model)?
        } else {
            let layout_metrics = self.call_method(cx, "Page.getLayoutMetrics", None).await?;
            CdpCaptureClip::from_layout_metrics(&layout_metrics, full_page)?
        };

        let format = cdp_screenshot_format(format)?;
        let mut params = serde_json::Map::new();
        params.insert(
            "captureBeyondViewport".to_string(),
            serde_json::json!(full_page || selector.is_some()),
        );
        params.insert("clip".to_string(), clip.descriptor());
        params.insert("format".to_string(), serde_json::Value::String(format));
        params.insert("fromSurface".to_string(), serde_json::Value::Bool(true));
        if let Some(quality) = quality {
            if quality > 100 {
                return Err(BrowserError::Api {
                    message: format!(
                        "Chrome DevTools Protocol Page.captureScreenshot quality must be <= 100, got {quality}"
                    ),
                    status_code: None,
                });
            }
            params.insert("quality".to_string(), serde_json::json!(quality));
        }

        let result = self
            .call_method(
                cx,
                "Page.captureScreenshot",
                Some(serde_json::Value::Object(params)),
            )
            .await?;
        CdpScreenshotResponse::from_capture_result(&result, clip)
    }

    async fn get_cookies(
        &mut self,
        cx: &Cx,
        domain_filter: Option<&str>,
    ) -> BrowserResult<CdpCookieResponse> {
        let result = self.call_method(cx, "Network.getCookies", None).await?;
        CdpCookieResponse::from_result(&result, domain_filter)
    }

    async fn set_cookies(
        &mut self,
        cx: &Cx,
        cookies: &[Cookie],
    ) -> BrowserResult<CdpSetCookiesResponse> {
        let set_count = u32::try_from(cookies.len()).map_err(|err| BrowserError::Api {
            message: format!(
                "Chrome DevTools Protocol Network.setCookies cookie count exceeds u32: {err}"
            ),
            status_code: None,
        })?;
        let cdp_cookies = cookies.iter().map(cdp_cookie_param).collect::<Vec<_>>();
        self.call_method(
            cx,
            "Network.setCookies",
            Some(serde_json::json!({ "cookies": cdp_cookies })),
        )
        .await?;

        Ok(CdpSetCookiesResponse { set_count })
    }

    fn next_command(
        &mut self,
        method: impl Into<String>,
        params: Option<serde_json::Value>,
    ) -> BrowserResult<CdpCommand> {
        let id = self.next_command_id;
        self.next_command_id =
            self.next_command_id
                .checked_add(1)
                .ok_or_else(|| BrowserError::Api {
                    message: "Chrome DevTools Protocol command id space exhausted".into(),
                    status_code: None,
                })?;
        Ok(CdpCommand::new(id, method, params))
    }

    #[cfg(test)]
    fn into_transport(self) -> T {
        self.transport
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
    max_response_bytes: CONTROL_RESPONSE_BYTES_CAPTURE,
    timeout_ms: CONTROL_TIMEOUT_MS_CAPTURE,
    target_policy: TARGET_CREATE_OR_REUSE_PAGE,
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
    max_response_bytes: CONTROL_RESPONSE_BYTES_CAPTURE,
    timeout_ms: CONTROL_TIMEOUT_MS_CAPTURE,
    target_policy: TARGET_ACTIVE_PAGE_EXPORT,
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
    max_response_bytes: CONTROL_RESPONSE_BYTES_CAPTURE,
    timeout_ms: CONTROL_TIMEOUT_MS_CAPTURE,
    target_policy: TARGET_ACTIVE_PAGE_EXPORT,
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Page.printToPDF"],
    },
};
const WORKER_EXTRACT_TEXT: BrowserControlOperation = BrowserControlOperation {
    id: "browser.extract_text",
    method: "POST",
    path: "/extract_text",
    max_response_bytes: CONTROL_RESPONSE_BYTES_STANDARD,
    timeout_ms: CONTROL_TIMEOUT_MS_STANDARD,
    target_policy: TARGET_ACTIVE_PAGE_EXPORT,
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Runtime.evaluate"],
    },
};
const WORKER_EXTRACT_LINKS: BrowserControlOperation = BrowserControlOperation {
    id: "browser.extract_links",
    method: "POST",
    path: "/extract_links",
    max_response_bytes: CONTROL_RESPONSE_BYTES_STANDARD,
    timeout_ms: CONTROL_TIMEOUT_MS_STANDARD,
    target_policy: TARGET_ACTIVE_PAGE_EXPORT,
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Runtime.evaluate"],
    },
};
const WORKER_WAIT_FOR_SELECTOR: BrowserControlOperation = BrowserControlOperation {
    id: "browser.wait_for_selector",
    method: "POST",
    path: "/wait_for_selector",
    max_response_bytes: CONTROL_RESPONSE_BYTES_SMALL,
    timeout_ms: CONTROL_TIMEOUT_MS_STANDARD,
    target_policy: TARGET_ACTIVE_PAGE_INTERACTION,
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Runtime.evaluate"],
    },
};
const WORKER_CLICK: BrowserControlOperation = BrowserControlOperation {
    id: "browser.click",
    method: "POST",
    path: "/click",
    max_response_bytes: CONTROL_RESPONSE_BYTES_STANDARD,
    timeout_ms: CONTROL_TIMEOUT_MS_STANDARD,
    target_policy: TARGET_ACTIVE_PAGE_INTERACTION,
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
    max_response_bytes: CONTROL_RESPONSE_BYTES_STANDARD,
    timeout_ms: CONTROL_TIMEOUT_MS_STANDARD,
    target_policy: TARGET_ACTIVE_PAGE_INTERACTION,
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
    max_response_bytes: CONTROL_RESPONSE_BYTES_STANDARD,
    timeout_ms: CONTROL_TIMEOUT_MS_STANDARD,
    target_policy: TARGET_ACTIVE_PAGE_INTERACTION,
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Runtime.evaluate"],
    },
};
const WORKER_GET_COOKIES: BrowserControlOperation = BrowserControlOperation {
    id: "browser.get_cookies",
    method: "POST",
    path: "/cookies",
    max_response_bytes: CONTROL_RESPONSE_BYTES_SMALL,
    timeout_ms: CONTROL_TIMEOUT_MS_SHORT,
    target_policy: TARGET_BROWSER_CONTEXT,
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Network.getCookies"],
    },
};
const WORKER_SET_COOKIES: BrowserControlOperation = BrowserControlOperation {
    id: "browser.set_cookies",
    method: "POST",
    path: "/set_cookies",
    max_response_bytes: CONTROL_RESPONSE_BYTES_SMALL,
    timeout_ms: CONTROL_TIMEOUT_MS_SHORT,
    target_policy: TARGET_BROWSER_CONTEXT,
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Network.setCookies"],
    },
};
const WORKER_SET_PROXY: BrowserControlOperation = BrowserControlOperation {
    id: "browser.set_proxy",
    method: "POST",
    path: "/proxy/set",
    max_response_bytes: CONTROL_RESPONSE_BYTES_SMALL,
    timeout_ms: CONTROL_TIMEOUT_MS_SHORT,
    target_policy: TARGET_CONNECTOR_POLICY,
    implementation: BrowserControlImplementation::WorkerPolicy {
        description: "Apply connector-scoped proxy policy before browser target launch.",
    },
};
const WORKER_CLEAR_PROXY: BrowserControlOperation = BrowserControlOperation {
    id: "browser.clear_proxy",
    method: "POST",
    path: "/proxy/clear",
    max_response_bytes: CONTROL_RESPONSE_BYTES_SMALL,
    timeout_ms: CONTROL_TIMEOUT_MS_SHORT,
    target_policy: TARGET_CONNECTOR_POLICY,
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
        let timeout = Duration::from_millis(CONTROL_TIMEOUT_MS_STANDARD);
        match self
            .execute(CONTROL_RESPONSE_BYTES_STANDARD, timeout, || {
                self.http.get(&url).timeout(timeout)
            })
            .await
        {
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
        let data = self.post_json(WORKER_NAVIGATE, &body).await?;
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
        let data = self.post_json(WORKER_SCREENSHOT, &body).await?;
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
        let data = self.post_json(WORKER_RENDER_PDF, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- Extraction --

    /// Extract text content from the page.
    pub async fn extract_text(
        &self,
        selector: Option<&str>,
        include_hidden: Option<bool>,
    ) -> BrowserResult<TextResult> {
        let mut body = serde_json::json!({});
        if let Some(s) = selector {
            body["selector"] = serde_json::Value::String(s.to_string());
        }
        if let Some(ih) = include_hidden {
            body["include_hidden"] = serde_json::Value::Bool(ih);
        }
        let data = self.post_json(WORKER_EXTRACT_TEXT, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Extract links from the page.
    pub async fn extract_links(&self, selector: Option<&str>) -> BrowserResult<LinksResult> {
        let mut body = serde_json::json!({});
        if let Some(s) = selector {
            body["selector"] = serde_json::Value::String(s.to_string());
        }
        let data = self.post_json(WORKER_EXTRACT_LINKS, &body).await?;
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
        let mut body = serde_json::json!({ "selector": selector });
        if let Some(s) = state {
            body["state"] = serde_json::Value::String(s.to_string());
        }
        if let Some(t) = timeout_ms {
            body["timeout_ms"] = serde_json::Value::Number(t.into());
        }
        let data = self.post_json(WORKER_WAIT_FOR_SELECTOR, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- Interaction --

    /// Click an element.
    pub async fn click(
        &self,
        selector: &str,
        timeout_ms: Option<u64>,
    ) -> BrowserResult<ClickResult> {
        let mut body = serde_json::json!({ "selector": selector });
        if let Some(t) = timeout_ms {
            body["timeout_ms"] = serde_json::Value::Number(t.into());
        }
        let data = self.post_json(WORKER_CLICK, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Fill form fields.
    pub async fn fill_form(
        &self,
        fields: &serde_json::Value,
        submit_selector: Option<&str>,
    ) -> BrowserResult<FormResult> {
        let mut body = serde_json::json!({ "fields": fields });
        if let Some(ss) = submit_selector {
            body["submit_selector"] = serde_json::Value::String(ss.to_string());
        }
        let data = self.post_json(WORKER_FILL_FORM, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- JavaScript --

    /// Evaluate JavaScript in the page context.
    pub async fn evaluate_js(&self, expression: &str) -> BrowserResult<JsResult> {
        let body = serde_json::json!({ "expression": expression });
        let data = self.post_json(WORKER_EVALUATE_JS, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- Cookies --

    /// Get cookies.
    pub async fn get_cookies(&self, domain: Option<&str>) -> BrowserResult<Vec<Cookie>> {
        let mut body = serde_json::json!({});
        if let Some(d) = domain {
            body["domain"] = serde_json::Value::String(d.to_string());
        }
        let data = self.post_json(WORKER_GET_COOKIES, &body).await?;
        let cookies: Vec<Cookie> = serde_json::from_value(
            data.get("cookies")
                .cloned()
                .unwrap_or(serde_json::Value::Array(vec![])),
        )?;
        Ok(cookies)
    }

    /// Set cookies.
    pub async fn set_cookies(&self, cookies: &[Cookie]) -> BrowserResult<u32> {
        let body = serde_json::json!({ "cookies": cookies });
        let data = self.post_json(WORKER_SET_COOKIES, &body).await?;
        let count = data.get("set_count").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(count as u32)
    }

    // -- Proxy --

    /// Configure outbound proxy for browser traffic.
    pub async fn set_proxy(&self, proxy: &ProxyConfig) -> BrowserResult<ProxyResult> {
        let body = serde_json::to_value(proxy)?;
        let data = self.post_json(WORKER_SET_PROXY, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Clear outbound proxy configuration.
    pub async fn clear_proxy(&self) -> BrowserResult<ProxyResult> {
        let data = self
            .post_json(WORKER_CLEAR_PROXY, &serde_json::json!({}))
            .await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- HTTP helpers --

    fn worker_endpoint(&self, operation: BrowserControlOperation) -> String {
        debug_assert_eq!(operation.method, "POST");
        format!("{}{}", self.browser_url, operation.path)
    }

    async fn post_json(
        &self,
        operation: BrowserControlOperation,
        body: &serde_json::Value,
    ) -> BrowserResult<serde_json::Value> {
        let url = self.worker_endpoint(operation);
        let timeout = Duration::from_millis(operation.timeout_ms);
        self.execute(operation.max_response_bytes, timeout, || {
            self.http
                .post(&url)
                .timeout(timeout)
                .header(CONTROL_OPERATION_HEADER, operation.id)
                .header(
                    CONTROL_RESPONSE_BUDGET_HEADER,
                    operation.max_response_bytes.to_string(),
                )
                .header(
                    CONTROL_TIMEOUT_BUDGET_HEADER,
                    operation.timeout_ms.to_string(),
                )
                .header(CONTROL_TARGET_SCOPE_HEADER, operation.target_policy.scope)
                .header(
                    CONTROL_TARGET_SELECTION_HEADER,
                    operation.target_policy.selection,
                )
                .header(
                    CONTROL_STALE_TARGET_RECOVERY_HEADER,
                    operation.target_policy.stale_target_recovery.to_string(),
                )
                .header(
                    CONTROL_CURRENT_TAB_GUARD_HEADER,
                    operation.target_policy.current_tab_guard.to_string(),
                )
                .header(
                    CONTROL_EXPORT_GUARD_HEADER,
                    operation.target_policy.export_guard.to_string(),
                )
                .json(body)
        })
        .await
    }

    async fn execute(
        &self,
        max_response_bytes: usize,
        timeout: Duration,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> BrowserResult<serde_json::Value> {
        let ctx = self.request_context_for_timeout(timeout);
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
                            let body = match read_limited_response_text(
                                response,
                                max_response_bytes,
                            )
                            .await
                            {
                                Ok(body) => body,
                                Err(err) => return AttemptOutcome::Terminal(err),
                            };
                            let body = redact_browser_control_error_text(&body);
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
                            let body = match read_limited_response_text(
                                response,
                                max_response_bytes,
                            )
                            .await
                            {
                                Ok(body) => body,
                                Err(err) => return AttemptOutcome::Terminal(err),
                            };
                            let api_err: Option<ApiErrorResponse> =
                                serde_json::from_str(&body).ok();
                            let redacted_body = redact_browser_control_error_text(&body);
                            let message = api_err
                                .as_ref()
                                .and_then(|e| e.error.as_ref())
                                .and_then(|d| d.message.clone())
                                .map(|message| redact_browser_control_error_text(&message))
                                .unwrap_or(format!("HTTP {status}: {redacted_body}"));
                            return AttemptOutcome::Terminal(BrowserError::Api {
                                message,
                                status_code: Some(status.as_u16()),
                            });
                        }

                        match read_limited_response_text(response, max_response_bytes).await {
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

    fn request_context_for_timeout(&self, timeout: Duration) -> fcp_async_core::ExecutionContext {
        self.runtime.request_context_with_timeout(timeout)
    }

    async fn raw_chrome_cdp_endpoint_detected(&self) -> bool {
        let url = format!("{}/json/version", self.browser_url);
        let timeout = Duration::from_millis(CONTROL_TIMEOUT_MS_STANDARD);
        match self
            .execute(CONTROL_RESPONSE_BYTES_STANDARD, timeout, || {
                self.http.get(&url).timeout(timeout)
            })
            .await
        {
            Ok(body) => looks_like_chrome_cdp_version(&body),
            Err(_) => false,
        }
    }
}

async fn read_limited_response_text(
    response: reqwest::Response,
    max_response_bytes: usize,
) -> BrowserResult<String> {
    let status = response.status();
    if let Some(content_length) = response.content_length() {
        if usize::try_from(content_length).map_or(true, |length| length > max_response_bytes) {
            return Err(response_size_limit_error(
                status,
                max_response_bytes,
                Some(content_length),
            ));
        }
    }

    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(BrowserError::Http)?;
        if body.len().saturating_add(chunk.len()) > max_response_bytes {
            return Err(response_size_limit_error(status, max_response_bytes, None));
        }
        body.extend_from_slice(&chunk);
    }

    String::from_utf8(body).map_err(|e| BrowserError::Api {
        message: format!("browser control response is not valid UTF-8 JSON: {e}"),
        status_code: Some(status.as_u16()),
    })
}

fn response_size_limit_error(
    status: StatusCode,
    max_response_bytes: usize,
    content_length: Option<u64>,
) -> BrowserError {
    let message = match content_length {
        Some(content_length) => format!(
            "browser control response exceeds {max_response_bytes} byte limit: content-length {content_length}"
        ),
        None => {
            format!("browser control response exceeds {max_response_bytes} byte limit")
        }
    };

    BrowserError::Api {
        message,
        status_code: Some(status.as_u16()),
    }
}

fn redact_browser_control_error_text(body: &str) -> String {
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(body) {
        redact_sensitive_json(&mut value);
        return serde_json::to_string(&value)
            .unwrap_or_else(|_| "[redacted browser-control error body]".to_string());
    }

    if contains_sensitive_marker(body) {
        "[redacted browser-control error body]".to_string()
    } else {
        body.to_string()
    }
}

fn redact_sensitive_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if is_sensitive_error_key(key) {
                    *child = redacted_json_value();
                } else {
                    redact_sensitive_json(child);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_sensitive_json(item);
            }
        }
        serde_json::Value::String(text) => {
            if contains_sensitive_marker(text) {
                *text = "[redacted]".to_string();
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn redacted_json_value() -> serde_json::Value {
    serde_json::Value::String("[redacted]".to_string())
}

fn is_sensitive_error_key(key: &str) -> bool {
    let normalized = key.replace(['-', '_'], "").to_ascii_lowercase();
    normalized.contains("token")
        || normalized.contains("secret")
        || normalized.contains("password")
        || normalized.contains("cookie")
        || normalized.contains("authorization")
        || normalized.contains("apikey")
        || normalized.contains("credential")
}

fn contains_sensitive_marker(text: &str) -> bool {
    let normalized = text.to_ascii_lowercase();
    normalized.contains("bearer ")
        || normalized.contains("authorization")
        || normalized.contains("access_token")
        || normalized.contains("refresh_token")
        || normalized.contains("id_token")
        || normalized.contains("api_key")
        || normalized.contains("apikey")
        || normalized.contains("password")
        || normalized.contains("secret")
        || normalized.contains("cookie")
        || normalized.contains("set-cookie")
        || normalized.contains("credential")
}

fn decode_cdp_response_message(
    message: WebSocketMessage,
    expected_command_id: u64,
) -> BrowserResult<Option<serde_json::Value>> {
    match message {
        WebSocketMessage::Text(text) => decode_cdp_response_text(&text, expected_command_id),
        WebSocketMessage::Binary(_) => Err(BrowserError::Api {
            message: "Chrome DevTools Protocol response must be UTF-8 text JSON".into(),
            status_code: None,
        }),
        WebSocketMessage::Close(_) => Err(BrowserError::Api {
            message: "Chrome DevTools Protocol connection closed before command response".into(),
            status_code: None,
        }),
        WebSocketMessage::Ping(_) | WebSocketMessage::Pong(_) => Ok(None),
    }
}

fn decode_cdp_response_text(
    text: &str,
    expected_command_id: u64,
) -> BrowserResult<Option<serde_json::Value>> {
    let mut value: serde_json::Value = serde_json::from_str(text)?;

    let Some(id) = value.get("id").and_then(serde_json::Value::as_u64) else {
        if value
            .get("method")
            .and_then(serde_json::Value::as_str)
            .is_some()
        {
            return Ok(None);
        }
        return Err(BrowserError::Api {
            message: "Chrome DevTools Protocol response is missing numeric command id".into(),
            status_code: None,
        });
    };

    if id != expected_command_id {
        return Ok(None);
    }

    if let Some(error) = value.get_mut("error") {
        redact_sensitive_json(error);
        return Err(BrowserError::Api {
            message: format!(
                "Chrome DevTools Protocol command {expected_command_id} failed: {}",
                serde_json::to_string(error)?
            ),
            status_code: None,
        });
    }

    Ok(Some(
        value
            .get("result")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
    ))
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
        && operation
            .get("max_response_bytes")
            .and_then(serde_json::Value::as_u64)
            .and_then(|limit| usize::try_from(limit).ok())
            .is_some_and(|limit| limit == required.max_response_bytes)
        && operation
            .get("timeout_ms")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|timeout_ms| timeout_ms == required.timeout_ms)
        && operation
            .get("target_policy")
            .is_some_and(|target_policy| target_policy == &required.target_policy.descriptor())
        && operation
            .get("request_headers")
            .is_some_and(|request_headers| {
                request_headers == &required.request_headers_descriptor()
            })
        && browser_control_implementation_matches(operation, required)
    {
        Ok(())
    } else {
        Err(format!(
            "operation `{}` is incompatible; expected {} `{}` with max_response_bytes {}, timeout_ms {}, target_policy {}, request_headers [{}], and implementation {}",
            required.id,
            required.method,
            required.path,
            required.max_response_bytes,
            required.timeout_ms,
            required.target_policy.summary(),
            required.request_headers_summary(),
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
    use std::collections::VecDeque;

    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    #[derive(Debug, Default)]
    struct FakeCdpTransport {
        sent: Vec<WebSocketMessage>,
        received: VecDeque<WebSocketMessage>,
    }

    impl FakeCdpTransport {
        fn with_received(messages: impl IntoIterator<Item = WebSocketMessage>) -> Self {
            Self {
                sent: Vec::new(),
                received: messages.into_iter().collect(),
            }
        }
    }

    fn assert_cdp_text_message(message: &WebSocketMessage, expected: &serde_json::Value) {
        assert!(
            matches!(message, WebSocketMessage::Text(_)),
            "expected CDP text WebSocket message, got {message:?}"
        );
        let WebSocketMessage::Text(text) = message else {
            return;
        };
        let actual = serde_json::from_str::<serde_json::Value>(text).unwrap();
        assert_eq!(&actual, expected);
    }

    #[async_trait::async_trait]
    impl CdpCommandTransport for FakeCdpTransport {
        async fn send_cdp_message(
            &mut self,
            _cx: &Cx,
            message: WebSocketMessage,
        ) -> BrowserResult<()> {
            self.sent.push(message);
            Ok(())
        }

        async fn recv_cdp_message(&mut self, _cx: &Cx) -> BrowserResult<Option<WebSocketMessage>> {
            Ok(self.received.pop_front())
        }
    }

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
                        && operation["max_response_bytes"]
                            == serde_json::json!(required.max_response_bytes)
                        && operation["timeout_ms"] == serde_json::json!(required.timeout_ms)
                        && operation["target_policy"] == required.target_policy.descriptor()
                        && operation["request_headers"] == required.request_headers_descriptor()
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
        assert_eq!(navigate["target_policy"]["scope"], "page");
        assert_eq!(
            navigate["target_policy"]["selection"],
            "create_or_reuse_active_page"
        );
        assert_eq!(navigate["target_policy"]["stale_target_recovery"], true);
        assert_eq!(navigate["target_policy"]["current_tab_guard"], false);
        assert_eq!(navigate["target_policy"]["export_guard"], false);
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
        assert_eq!(screenshot["target_policy"]["scope"], "page");
        assert_eq!(
            screenshot["target_policy"]["selection"],
            "active_page_required"
        );
        assert_eq!(screenshot["target_policy"]["stale_target_recovery"], true);
        assert_eq!(screenshot["target_policy"]["current_tab_guard"], true);
        assert_eq!(screenshot["target_policy"]["export_guard"], true);
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
        assert_eq!(click["target_policy"]["scope"], "page");
        assert_eq!(click["target_policy"]["selection"], "active_page_required");
        assert_eq!(click["target_policy"]["stale_target_recovery"], true);
        assert_eq!(click["target_policy"]["current_tab_guard"], true);
        assert_eq!(click["target_policy"]["export_guard"], false);
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
        assert_eq!(get_cookies["target_policy"]["scope"], "browser_context");
        assert_eq!(
            get_cookies["target_policy"]["selection"],
            "active_context_required"
        );
        assert_eq!(
            get_cookies["implementation"]["methods"],
            serde_json::json!(["Network.getCookies"])
        );

        let set_proxy = operation(operations, "browser.set_proxy");
        assert_eq!(set_proxy["implementation"]["kind"], "worker_policy");
        assert_eq!(set_proxy["target_policy"]["scope"], "connector_policy");
        assert_eq!(set_proxy["target_policy"]["selection"], "no_browser_target");
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
            let max_response_bytes = operation["max_response_bytes"].as_u64().unwrap();
            let timeout_ms = operation["timeout_ms"].as_u64().unwrap();
            let target_policy = &operation["target_policy"];
            let request_headers = operation["request_headers"].as_array().unwrap();
            assert!(max_response_bytes > 0, "{id} must expose a response cap");
            assert!(timeout_ms > 0, "{id} must expose a timeout budget");
            assert!(
                target_policy["scope"].as_str().is_some(),
                "{id} must expose a target scope"
            );
            assert!(
                target_policy["selection"].as_str().is_some(),
                "{id} must expose a target selection policy"
            );
            assert!(
                target_policy["stale_target_recovery"].as_bool().is_some(),
                "{id} must expose stale-target recovery policy"
            );
            assert!(
                target_policy["current_tab_guard"].as_bool().is_some(),
                "{id} must expose current-tab guard policy"
            );
            assert!(
                target_policy["export_guard"].as_bool().is_some(),
                "{id} must expose export guard policy"
            );
            assert!(
                request_headers
                    .iter()
                    .any(|header| header["name"] == CONTROL_OPERATION_HEADER),
                "{id} must advertise operation metadata header"
            );
            assert!(
                request_headers
                    .iter()
                    .any(|header| header["name"] == CONTROL_TARGET_SCOPE_HEADER),
                "{id} must advertise target-scope metadata header"
            );

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
    fn test_cdp_command_serializes_to_websocket_text_message() {
        let command = CdpCommand::new(
            7,
            "Page.navigate",
            Some(serde_json::json!({ "url": "https://example.com" })),
        );

        let message = command.to_websocket_message().unwrap();
        assert!(matches!(
            message,
            WebSocketMessage::Text(text)
                if text == r#"{"id":7,"method":"Page.navigate","params":{"url":"https://example.com"}}"#
        ));
    }

    #[test]
    fn test_cdp_command_omits_empty_params() {
        let command = CdpCommand::new(8, "Page.enable", None);

        let message = command.to_websocket_message().unwrap();
        assert!(matches!(
            message,
            WebSocketMessage::Text(text) if text == r#"{"id":8,"method":"Page.enable"}"#
        ));
    }

    #[test]
    fn test_cdp_response_decoder_correlates_command_result() {
        let result = decode_cdp_response_message(
            WebSocketMessage::Text(r#"{"id":7,"result":{"frameId":"abc"}}"#.into()),
            7,
        )
        .unwrap();

        assert_eq!(result, Some(serde_json::json!({ "frameId": "abc" })));
    }

    #[test]
    fn test_cdp_response_decoder_ignores_events_and_other_command_ids() {
        let event = decode_cdp_response_message(
            WebSocketMessage::Text(
                r#"{"method":"Page.loadEventFired","params":{"timestamp":1}}"#.into(),
            ),
            7,
        )
        .unwrap();
        let other_command = decode_cdp_response_message(
            WebSocketMessage::Text(r#"{"id":9,"result":{"ok":true}}"#.into()),
            7,
        )
        .unwrap();

        assert_eq!(event, None);
        assert_eq!(other_command, None);
    }

    #[test]
    fn test_cdp_response_decoder_redacts_error_payloads() {
        let err = decode_cdp_response_message(
            WebSocketMessage::Text(
                serde_json::json!({
                    "id": 7,
                    "error": {
                        "code": -32000,
                        "message": "Authorization failed for Bearer browser-token",
                        "data": {
                            "access_token": "secret-token",
                            "cookies": [{ "name": "session", "value": "secret-cookie" }]
                        }
                    }
                })
                .to_string(),
            ),
            7,
        )
        .unwrap_err();

        let message = format!("{err}");
        assert!(!message.contains("browser-token"));
        assert!(!message.contains("secret-token"));
        assert!(!message.contains("secret-cookie"));
        assert!(message.contains("[redacted]"));
    }

    #[test]
    fn test_cdp_response_decoder_rejects_non_text_messages() {
        let err =
            decode_cdp_response_message(WebSocketMessage::binary(vec![1_u8, 2, 3]), 7).unwrap_err();

        assert!(format!("{err}").contains("UTF-8 text JSON"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_execute_cdp_command_sends_request_and_waits_for_matching_response() {
        let cx = fcp_async_core::compatibility_cx();
        let mut transport = FakeCdpTransport::with_received([
            WebSocketMessage::Text(
                r#"{"method":"Page.frameStartedLoading","params":{"frameId":"abc"}}"#.into(),
            ),
            WebSocketMessage::Text(r#"{"id":99,"result":{"ignored":true}}"#.into()),
            WebSocketMessage::Text(r#"{"id":7,"result":{"frameId":"abc"}}"#.into()),
        ]);

        let result = execute_cdp_command(
            &cx,
            &mut transport,
            CdpCommand::new(
                7,
                "Page.navigate",
                Some(serde_json::json!({ "url": "https://example.com" })),
            ),
        )
        .await
        .unwrap();

        assert_eq!(result, serde_json::json!({ "frameId": "abc" }));
        assert_eq!(transport.sent.len(), 1);
        assert!(matches!(
            &transport.sent[0],
            WebSocketMessage::Text(text)
                if text == r#"{"id":7,"method":"Page.navigate","params":{"url":"https://example.com"}}"#
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_execute_cdp_command_reports_close_before_matching_response() {
        let cx = fcp_async_core::compatibility_cx();
        let mut transport = FakeCdpTransport::with_received([WebSocketMessage::Text(
            r#"{"method":"Page.frameStartedLoading"}"#.into(),
        )]);

        let err = execute_cdp_command(
            &cx,
            &mut transport,
            CdpCommand::new(7, "Page.navigate", None),
        )
        .await
        .unwrap_err();

        let message = format!("{err}");
        assert!(message.contains("closed before command 7 response"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_execute_cdp_command_checks_cancellation_before_send() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let mut transport = FakeCdpTransport::default();

        let err = execute_cdp_command(
            &cx,
            &mut transport,
            CdpCommand::new(7, "Page.navigate", None),
        )
        .await
        .unwrap_err();

        let message = format!("{err}");
        assert!(message.contains("cancelled before send"));
        assert!(transport.sent.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_allocates_monotonic_command_ids() {
        let cx = fcp_async_core::compatibility_cx();
        let mut session = CdpSession::new(FakeCdpTransport::with_received([
            WebSocketMessage::Text(r#"{"id":1,"result":{"enabled":true}}"#.into()),
            WebSocketMessage::Text(r#"{"id":2,"result":{"frameId":"abc"}}"#.into()),
        ]));

        let page_enable = session.call_method(&cx, "Page.enable", None).await.unwrap();
        let navigate = session
            .call_method(
                &cx,
                "Page.navigate",
                Some(serde_json::json!({ "url": "https://example.com" })),
            )
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(page_enable, serde_json::json!({ "enabled": true }));
        assert_eq!(navigate, serde_json::json!({ "frameId": "abc" }));
        assert_eq!(transport.sent.len(), 2);
        assert!(matches!(
            &transport.sent[0],
            WebSocketMessage::Text(text) if text == r#"{"id":1,"method":"Page.enable"}"#
        ));
        assert!(matches!(
            &transport.sent[1],
            WebSocketMessage::Text(text)
                if text == r#"{"id":2,"method":"Page.navigate","params":{"url":"https://example.com"}}"#
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_navigate_page_issues_documented_cdp_sequence() {
        let cx = fcp_async_core::compatibility_cx();
        let mut session = CdpSession::new(FakeCdpTransport::with_received([
            WebSocketMessage::Text(r#"{"id":1,"result":{}}"#.into()),
            WebSocketMessage::Text(r#"{"id":2,"result":{}}"#.into()),
            WebSocketMessage::Text(r#"{"id":3,"result":{}}"#.into()),
            WebSocketMessage::Text(
                r#"{"id":4,"result":{"frameId":"frame-1","loaderId":"loader-1"}}"#.into(),
            ),
        ]));

        let response = session
            .navigate_page(&cx, "https://example.com", Some("FCP Browser/1.0"))
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(
            response,
            CdpNavigateResponse {
                frame_id: "frame-1".to_string(),
                loader_id: Some("loader-1".to_string()),
            }
        );
        assert_eq!(transport.sent.len(), 4);
        assert!(matches!(
            &transport.sent[0],
            WebSocketMessage::Text(text) if text == r#"{"id":1,"method":"Page.enable"}"#
        ));
        assert!(matches!(
            &transport.sent[1],
            WebSocketMessage::Text(text) if text == r#"{"id":2,"method":"Network.enable"}"#
        ));
        assert!(matches!(
            &transport.sent[2],
            WebSocketMessage::Text(text)
                if text == r#"{"id":3,"method":"Network.setUserAgentOverride","params":{"userAgent":"FCP Browser/1.0"}}"#
        ));
        assert!(matches!(
            &transport.sent[3],
            WebSocketMessage::Text(text)
                if text == r#"{"id":4,"method":"Page.navigate","params":{"url":"https://example.com"}}"#
        ));
    }

    #[test]
    fn test_cdp_navigate_response_rejects_error_text_and_missing_frame() {
        let error = CdpNavigateResponse::from_result(&serde_json::json!({
            "errorText": "Authorization failed for Bearer browser-token",
            "frameId": "frame-1",
        }))
        .unwrap_err();
        let error_message = format!("{error}");
        assert!(!error_message.contains("browser-token"));
        assert!(error_message.contains("[redacted browser-control error body]"));

        let missing_frame = CdpNavigateResponse::from_result(&serde_json::json!({})).unwrap_err();
        assert!(format!("{missing_frame}").contains("missing frameId"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_evaluate_expression_issues_documented_command() {
        let cx = fcp_async_core::compatibility_cx();
        let mut session =
            CdpSession::new(FakeCdpTransport::with_received([WebSocketMessage::Text(
                r#"{"id":1,"result":{"result":{"type":"string","value":"Example Domain"}}}"#.into(),
            )]));

        let response = session
            .evaluate_expression(&cx, "document.title")
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(
            response,
            CdpEvaluateResponse {
                result: "Example Domain".to_string(),
            }
        );
        assert_eq!(transport.sent.len(), 1);
        assert!(matches!(
            &transport.sent[0],
            WebSocketMessage::Text(text)
                if text == r#"{"id":1,"method":"Runtime.evaluate","params":{"awaitPromise":true,"expression":"document.title","returnByValue":true}}"#
        ));
    }

    #[test]
    fn test_cdp_evaluate_response_serializes_non_string_values() {
        let object = CdpEvaluateResponse::from_result(&serde_json::json!({
            "result": { "type": "object", "value": { "ok": true } }
        }))
        .unwrap();
        let undefined = CdpEvaluateResponse::from_result(&serde_json::json!({
            "result": { "type": "undefined" }
        }))
        .unwrap();
        let unserializable = CdpEvaluateResponse::from_result(&serde_json::json!({
            "result": { "type": "number", "unserializableValue": "NaN" }
        }))
        .unwrap();

        assert_eq!(object.result, r#"{"ok":true}"#);
        assert_eq!(undefined.result, "undefined");
        assert_eq!(unserializable.result, "NaN");
    }

    #[test]
    fn test_cdp_evaluate_response_redacts_exception_details() {
        let token_field = ["access", "_token"].concat();
        let cookie_field = ["coo", "kie"].concat();
        let exception_description =
            format!("{token_field}=value-alpha; {cookie_field}=session-alpha");

        let error = CdpEvaluateResponse::from_result(&serde_json::json!({
            "exceptionDetails": {
                "text": "Uncaught Authorization failed for Bearer browser-token",
                "exception": {
                    "description": exception_description
                }
            }
        }))
        .unwrap_err();

        let message = format!("{error}");
        assert!(!message.contains("browser-token"));
        assert!(!message.contains("value-alpha"));
        assert!(!message.contains("session-alpha"));
        assert!(message.contains("[redacted]"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_capture_screenshot_issues_full_page_sequence() {
        let cx = fcp_async_core::compatibility_cx();
        let mut session = CdpSession::new(FakeCdpTransport::with_received([
            WebSocketMessage::Text(
                r#"{"id":1,"result":{"cssContentSize":{"x":0,"y":0,"width":1280,"height":2048}}}"#
                    .into(),
            ),
            WebSocketMessage::Text(r#"{"id":2,"result":{"data":"image-alpha"}}"#.into()),
        ]));

        let response = session
            .capture_screenshot(&cx, None, true, Some("jpeg"), Some(80))
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(
            response,
            CdpScreenshotResponse {
                image_data: "image-alpha".to_string(),
                width: 1280,
                height: 2048,
            }
        );
        assert_eq!(transport.sent.len(), 2);
        assert_cdp_text_message(
            &transport.sent[0],
            &serde_json::json!({
                "id": 1,
                "method": "Page.getLayoutMetrics",
            }),
        );
        assert_cdp_text_message(
            &transport.sent[1],
            &serde_json::json!({
                "id": 2,
                "method": "Page.captureScreenshot",
                "params": {
                    "captureBeyondViewport": true,
                    "clip": { "x": 0.0, "y": 0.0, "width": 1280.0, "height": 2048.0, "scale": 1 },
                    "format": "jpeg",
                    "fromSurface": true,
                    "quality": 80,
                }
            }),
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_capture_screenshot_uses_selector_clip() {
        let cx = fcp_async_core::compatibility_cx();
        let mut session = CdpSession::new(FakeCdpTransport::with_received([
            WebSocketMessage::Text(r#"{"id":1,"result":{"root":{"nodeId":1}}}"#.into()),
            WebSocketMessage::Text(r#"{"id":2,"result":{"nodeId":2}}"#.into()),
            WebSocketMessage::Text(
                r#"{"id":3,"result":{"model":{"content":[10.5,20,110.5,20,110.5,70.25,10.5,70.25]}}}"#
                    .into(),
            ),
            WebSocketMessage::Text(r#"{"id":4,"result":{"data":"image-beta"}}"#.into()),
        ]));

        let response = session
            .capture_screenshot(&cx, Some("#main"), false, None, None)
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(
            response,
            CdpScreenshotResponse {
                image_data: "image-beta".to_string(),
                width: 100,
                height: 51,
            }
        );
        assert_eq!(transport.sent.len(), 4);
        assert_cdp_text_message(
            &transport.sent[0],
            &serde_json::json!({
                "id": 1,
                "method": "DOM.getDocument",
                "params": { "depth": 0, "pierce": false },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[1],
            &serde_json::json!({
                "id": 2,
                "method": "DOM.querySelector",
                "params": { "nodeId": 1, "selector": "#main" },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[2],
            &serde_json::json!({
                "id": 3,
                "method": "DOM.getBoxModel",
                "params": { "nodeId": 2 },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[3],
            &serde_json::json!({
                "id": 4,
                "method": "Page.captureScreenshot",
                "params": {
                    "captureBeyondViewport": true,
                    "clip": { "x": 10.5, "y": 20.0, "width": 100.0, "height": 50.25, "scale": 1 },
                    "format": "png",
                    "fromSurface": true,
                }
            }),
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_capture_screenshot_rejects_missing_selector() {
        let cx = fcp_async_core::compatibility_cx();
        let mut session = CdpSession::new(FakeCdpTransport::with_received([
            WebSocketMessage::Text(r#"{"id":1,"result":{"root":{"nodeId":1}}}"#.into()),
            WebSocketMessage::Text(r#"{"id":2,"result":{"nodeId":0}}"#.into()),
        ]));

        let error = session
            .capture_screenshot(&cx, Some("#missing"), false, None, None)
            .await
            .unwrap_err();
        let transport = session.into_transport();

        assert!(format!("{error}").contains("selector `#missing` did not match"));
        assert_eq!(transport.sent.len(), 2);
    }

    #[test]
    fn test_cdp_screenshot_response_rejects_missing_data_and_bad_clip() {
        let clip = CdpCaptureClip::new(0.0, 0.0, 10.0, 20.0).unwrap();
        let missing_data =
            CdpScreenshotResponse::from_capture_result(&serde_json::json!({}), clip).unwrap_err();
        let empty_clip = CdpCaptureClip::new(0.0, 0.0, 0.0, 20.0).unwrap_err();

        assert!(format!("{missing_data}").contains("missing data"));
        assert!(format!("{empty_clip}").contains("positive dimensions"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_get_cookies_issues_documented_command_and_filters_domain() {
        let cx = fcp_async_core::compatibility_cx();
        let mut session = CdpSession::new(FakeCdpTransport::with_received([
            WebSocketMessage::Text(
                r#"{"id":1,"result":{"cookies":[{"name":"theme","value":"light","domain":".example.test","path":"/","httpOnly":true,"secure":true,"sameSite":"Lax"},{"name":"mode","value":"dense","domain":"app.example.test","path":"/app"},{"name":"outside","value":"skip","domain":"example.org","path":"/"},{"name":"host","value":"local","path":"/"}]}}"#
                    .into(),
            ),
        ]));

        let response = session
            .get_cookies(&cx, Some("example.test"))
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(response.cookies.len(), 2);
        assert_eq!(response.cookies[0].name, "theme");
        assert_eq!(response.cookies[0].value, "light");
        assert_eq!(response.cookies[0].domain.as_deref(), Some(".example.test"));
        assert_eq!(response.cookies[0].path.as_deref(), Some("/"));
        assert_eq!(response.cookies[0].http_only, Some(true));
        assert_eq!(response.cookies[0].secure, Some(true));
        assert_eq!(response.cookies[0].same_site.as_deref(), Some("Lax"));
        assert_eq!(response.cookies[1].name, "mode");
        assert_eq!(
            response.cookies[1].domain.as_deref(),
            Some("app.example.test")
        );
        assert_eq!(transport.sent.len(), 1);
        assert_cdp_text_message(
            &transport.sent[0],
            &serde_json::json!({
                "id": 1,
                "method": "Network.getCookies",
            }),
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_set_cookies_issues_documented_command_and_counts_input() {
        let cx = fcp_async_core::compatibility_cx();
        let mut session =
            CdpSession::new(FakeCdpTransport::with_received([WebSocketMessage::Text(
                r#"{"id":1,"result":{}}"#.into(),
            )]));
        let cookies = [
            Cookie {
                name: "theme".to_string(),
                value: "light".to_string(),
                domain: Some(".example.test".to_string()),
                path: Some("/".to_string()),
                expires: Some(4_102_444_800.0),
                http_only: Some(true),
                secure: Some(true),
                same_site: Some("Lax".to_string()),
            },
            Cookie {
                name: "mode".to_string(),
                value: "dense".to_string(),
                domain: Some("app.example.test".to_string()),
                path: Some("/app".to_string()),
                expires: None,
                http_only: None,
                secure: Some(false),
                same_site: None,
            },
        ];

        let response = session.set_cookies(&cx, &cookies).await.unwrap();
        let transport = session.into_transport();

        assert_eq!(response, CdpSetCookiesResponse { set_count: 2 });
        assert_eq!(transport.sent.len(), 1);
        assert_cdp_text_message(
            &transport.sent[0],
            &serde_json::json!({
                "id": 1,
                "method": "Network.setCookies",
                "params": {
                    "cookies": [
                        {
                            "name": "theme",
                            "value": "light",
                            "domain": ".example.test",
                            "path": "/",
                            "expires": 4_102_444_800.0,
                            "httpOnly": true,
                            "secure": true,
                            "sameSite": "Lax",
                        },
                        {
                            "name": "mode",
                            "value": "dense",
                            "domain": "app.example.test",
                            "path": "/app",
                            "secure": false,
                        },
                    ],
                },
            }),
        );
    }

    #[test]
    fn test_cdp_cookie_response_rejects_missing_name_or_value() {
        let missing_name = CdpCookieResponse::from_result(
            &serde_json::json!({ "cookies": [{ "value": "light" }] }),
            None,
        )
        .unwrap_err();
        let missing_value = CdpCookieResponse::from_result(
            &serde_json::json!({ "cookies": [{ "name": "theme" }] }),
            None,
        )
        .unwrap_err();
        let missing_list =
            CdpCookieResponse::from_result(&serde_json::json!({}), None).unwrap_err();

        assert!(format!("{missing_name}").contains("Network.Cookie name"));
        assert!(format!("{missing_value}").contains("Network.Cookie value"));
        assert!(format!("{missing_list}").contains("missing cookies"));
    }

    #[test]
    fn test_cdp_session_rejects_exhausted_command_ids() {
        let mut session = CdpSession {
            transport: FakeCdpTransport::default(),
            next_command_id: u64::MAX,
        };

        let err = session.next_command("Page.enable", None).unwrap_err();

        assert!(format!("{err}").contains("command id space exhausted"));
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
    fn test_health_contract_rejects_wrong_operation_response_budget() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        operations[0]["max_response_bytes"] = serde_json::json!(CONTROL_RESPONSE_BYTES_SMALL);

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.navigate"));
        assert!(err.contains("max_response_bytes"));
        assert!(err.contains(&CONTROL_RESPONSE_BYTES_CAPTURE.to_string()));
    }

    #[test]
    fn test_health_contract_rejects_wrong_operation_timeout_budget() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        operations[0]["timeout_ms"] = serde_json::json!(CONTROL_TIMEOUT_MS_SHORT);

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.navigate"));
        assert!(err.contains("timeout_ms"));
        assert!(err.contains(&CONTROL_TIMEOUT_MS_CAPTURE.to_string()));
    }

    #[test]
    fn test_health_contract_rejects_wrong_target_policy() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        operations[0]["target_policy"]["selection"] =
            serde_json::Value::String("active_page_required".into());

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.navigate"));
        assert!(err.contains("target_policy"));
        assert!(err.contains("create_or_reuse_active_page"));
    }

    #[test]
    fn test_health_contract_rejects_wrong_request_header_contract() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        operations[0]["request_headers"][0]["value"] =
            serde_json::Value::String("browser.screenshot".into());

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.navigate"));
        assert!(err.contains("request_headers"));
        assert!(err.contains(CONTROL_OPERATION_HEADER));
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
            .and(header(CONTROL_OPERATION_HEADER, "browser.navigate"))
            .and(header(
                CONTROL_RESPONSE_BUDGET_HEADER,
                CONTROL_RESPONSE_BYTES_CAPTURE.to_string(),
            ))
            .and(header(
                CONTROL_TIMEOUT_BUDGET_HEADER,
                CONTROL_TIMEOUT_MS_CAPTURE.to_string(),
            ))
            .and(header(CONTROL_TARGET_SCOPE_HEADER, "page"))
            .and(header(
                CONTROL_TARGET_SELECTION_HEADER,
                "create_or_reuse_active_page",
            ))
            .and(header(CONTROL_STALE_TARGET_RECOVERY_HEADER, "true"))
            .and(header(CONTROL_CURRENT_TAB_GUARD_HEADER, "false"))
            .and(header(CONTROL_EXPORT_GUARD_HEADER, "false"))
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
            .and(header(CONTROL_TARGET_SCOPE_HEADER, "page"))
            .and(header(
                CONTROL_TARGET_SELECTION_HEADER,
                "active_page_required",
            ))
            .and(header(CONTROL_STALE_TARGET_RECOVERY_HEADER, "true"))
            .and(header(CONTROL_CURRENT_TAB_GUARD_HEADER, "true"))
            .and(header(CONTROL_EXPORT_GUARD_HEADER, "true"))
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
    async fn test_worker_operation_timeout_budget_is_applied_to_request() {
        const SLOW_OPERATION: BrowserControlOperation = BrowserControlOperation {
            id: "browser.test_timeout",
            method: "POST",
            path: "/slow",
            max_response_bytes: CONTROL_RESPONSE_BYTES_SMALL,
            timeout_ms: 20,
            target_policy: TARGET_ACTIVE_PAGE_INTERACTION,
            implementation: BrowserControlImplementation::Cdp {
                methods: &["Runtime.evaluate"],
            },
        };

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/slow"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(250))
                    .set_body_json(serde_json::json!({ "ok": true })),
            )
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri())
            .with_retry_config(0);

        let err = client
            .post_json(SLOW_OPERATION, &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, BrowserError::Http(err) if err.is_timeout()));
    }

    #[test]
    fn test_worker_operation_timeout_budget_is_applied_to_runtime_context() {
        let client = BrowserClient::new(None).unwrap();
        let ctx =
            client.request_context_for_timeout(Duration::from_millis(WORKER_SCREENSHOT.timeout_ms));

        assert_eq!(ctx.scope(), fcp_async_core::ContextScope::Request);
        let remaining = ctx.remaining_budget().unwrap();
        assert!(
            remaining > Duration::from_secs(30),
            "capture operations must not inherit the default 30s runtime request budget"
        );
        assert!(remaining <= Duration::from_millis(WORKER_SCREENSHOT.timeout_ms));
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
    async fn test_server_error_redacts_sensitive_body_fields() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/navigate"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "upstream failed",
                "access_token": "browser-worker-token",
                "cookies": [{ "name": "session", "value": "cookie-secret" }]
            })))
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri())
            .with_retry_config(0);

        let err = client
            .navigate("https://example.com", None, None, None)
            .await
            .unwrap_err();
        let message = format!("{err}");
        assert!(!message.contains("browser-worker-token"));
        assert!(!message.contains("cookie-secret"));
        assert!(message.contains("[redacted]"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_client_error_redacts_sensitive_api_message() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/click"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": {
                    "message": "Authorization failed for Bearer browser-worker-token",
                    "code": "auth_failed"
                }
            })))
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri())
            .with_retry_config(0);

        let err = client.click(".submit", None).await.unwrap_err();
        let message = format!("{err}");
        assert!(!message.contains("browser-worker-token"));
        assert!(!message.contains("Bearer"));
        assert!(message.contains("[redacted browser-control error body]"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_oversized_browser_control_response_is_rejected() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/wait_for_selector"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![
                b'x';
                CONTROL_RESPONSE_BYTES_SMALL
                    + 1
            ]))
            .mount(&mock_server)
            .await;

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client
            .wait_for_selector(".ready", Some("visible"), Some(1_000))
            .await;
        let err = result.unwrap_err();
        assert!(format!("{err}").contains("browser control response exceeds"));
        assert!(format!("{err}").contains(&CONTROL_RESPONSE_BYTES_SMALL.to_string()));
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
