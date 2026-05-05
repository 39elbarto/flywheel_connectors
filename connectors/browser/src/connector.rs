//! FCP Browser Connector implementation.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fcp_prelude::ApprovalScope::Execution;
use fcp_prelude::{
    AgentHint, ApprovalMode, ApprovalToken, BaseConnector, CapabilityGrant, CapabilityId,
    CapabilityToken, CapabilityVerifier, ConnectorId, CredentialId, EventCaps, FcpError, FcpResult,
    HandshakeRequest, HandshakeResponse, IdempotencyClass, Introspection, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, SimulateRequest,
    SimulateResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{
        BrowserAuth, BrowserClient, DEFAULT_BROWSER_URL, browser_control_contract_descriptor,
    },
    error::BrowserError,
    types::{Cookie, ProxyConfig},
};

#[derive(Debug, Clone)]
struct ExecutionApprovalContext {
    token_id: String,
}

/// Validated configuration for the Browser connector.
struct BrowserConfig {
    auth: BrowserAuth,
    browser_url: String,
}

const BROWSER_CONTROL_HOST_ALLOWLIST: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "::1",
    "*.browser.mesh.internal",
    "*.browser.flywheel.internal",
];

const BROWSER_SANDBOX_PROFILE: &str = "strict";
const BROWSER_SANDBOX_MEMORY_MB: u32 = 1024;
const BROWSER_SANDBOX_CPU_PERCENT: u8 = 75;
const BROWSER_SANDBOX_WALL_CLOCK_TIMEOUT_MS: u64 = 300_000;
const BROWSER_SANDBOX_DENY_EXEC: bool = true;
const BROWSER_SANDBOX_DENY_PTRACE: bool = true;

#[derive(Debug, Clone, Serialize)]
struct BrowserNetworkGuardProfile {
    allowed_host_patterns: &'static [&'static str],
    require_https_for_non_loopback: bool,
    allow_http_for_loopback: bool,
}

#[derive(Debug, Clone, Serialize)]
struct BrowserExecutionPlannerProfile {
    memory_mb: u32,
    cpu_percent: u8,
    wall_clock_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct BrowserPlacementProfile {
    sandbox_profile: &'static str,
    sandbox_deny_exec: bool,
    sandbox_deny_ptrace: bool,
    network_guard: BrowserNetworkGuardProfile,
    execution_planner: BrowserExecutionPlannerProfile,
}

impl BrowserConfig {
    /// Parse and validate configuration from FCP params.
    ///
    /// Browser auth is optional: no auth, `api_key`, or `credential_id`.
    /// Cannot supply both `api_key` and `credential_id`.
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_key = params
            .get("api_key")
            .and_then(|v| v.as_str())
            .map(String::from);
        let credential_id = match params.get("credential_id") {
            Some(value) => {
                let raw = value.as_str().ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "credential_id must be a string".into(),
                })?;
                Some(
                    CredentialId::parse(raw).map_err(|_| FcpError::InvalidRequest {
                        code: 1003,
                        message: "credential_id must be a valid UUID".into(),
                    })?,
                )
            }
            None => None,
        };

        let auth = match (api_key, credential_id) {
            (Some(key), None) => BrowserAuth::ApiKey(key),
            (None, Some(cid)) => BrowserAuth::CredentialId(cid),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Supply at most one of `api_key` or `credential_id`, not both".into(),
                });
            }
            (None, None) => BrowserAuth::None,
        };

        let browser_url = params
            .get("browser_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_BROWSER_URL)
            .to_string();
        validate_browser_control_plane_url(&browser_url)?;

        Ok(Self { auth, browser_url })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrowserSessionStatePayload {
    schema_version: u32,
    captured_at: u64,
    domain: Option<String>,
    cookies: Vec<Cookie>,
}

#[derive(Debug, Clone)]
struct BrowserSessionStateObjectRecord {
    state_object_id: String,
    prev_state_object_id: Option<String>,
    seq: u64,
    lease_seq: u64,
    lease_object_id: String,
    payload_cbor: Vec<u8>,
    payload: BrowserSessionStatePayload,
}

#[derive(Debug, Default)]
struct BrowserSessionMeshStore {
    head_state_object_id: Option<String>,
    objects: BTreeMap<String, BrowserSessionStateObjectRecord>,
    last_seq: u64,
    last_lease_seq: u64,
}

/// Structured readiness diagnostic for the doctor command.
#[derive(Debug, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// FCP Browser Connector.
pub struct BrowserConnector {
    base: Arc<BaseConnector>,
    config: Option<BrowserConfig>,
    client: Option<BrowserClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    session_store: Mutex<BrowserSessionMeshStore>,
}

impl BrowserConnector {
    /// Create a new Browser connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("fcp.browser"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            session_store: Mutex::new(BrowserSessionMeshStore::default()),
        }
    }

    /// Connector instance ID used for bound capability-token verification.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.base.instance_id.as_str()
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = BrowserConfig::from_params(&params)?;

        let client = BrowserClient::new_with_auth(config.auth.clone())
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?
            .with_browser_url(&config.browser_url);

        info!(auth = %config.auth.redacted_label(), "Browser connector configured");

        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);

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
        let placement_profile =
            serde_json::to_value(browser_placement_profile()).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize browser placement profile: {e}"),
            })?;
        let mut health = json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            },
            "placement_profile": placement_profile,
            "browser_control_contract": browser_control_contract_descriptor(),
        });
        if let Some(config) = &self.config {
            let (allowlisted, host) = match reqwest::Url::parse(&config.browser_url) {
                Ok(url) => {
                    let host = url.host_str().unwrap_or("unknown");
                    (is_browser_control_host_allowlisted(host), host.to_string())
                }
                Err(_) => (false, "invalid".to_string()),
            };
            health["auth_mode"] = json!(config.auth.redacted_label());
            health["browser_url"] = json!(config.browser_url);
            health["network_guard"] = json!({
                "control_plane_host": host,
                "allowlisted": allowlisted,
            });
        }
        Ok(health)
    }

    /// Handle doctor readiness check.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // 1. Configuration
        checks.push(if self.config.is_some() {
            DoctorCheck {
                name: "configuration".into(),
                status: DoctorStatus::Healthy,
                message: "Connector is configured".into(),
            }
        } else {
            DoctorCheck {
                name: "configuration".into(),
                status: DoctorStatus::Unhealthy,
                message: "Connector is not configured – call `configure` first".into(),
            }
        });

        // 2. Client initialized
        checks.push(if self.client.is_some() {
            DoctorCheck {
                name: "client_initialized".into(),
                status: DoctorStatus::Healthy,
                message: "HTTP client is ready".into(),
            }
        } else {
            DoctorCheck {
                name: "client_initialized".into(),
                status: DoctorStatus::Unhealthy,
                message: "HTTP client is not initialized".into(),
            }
        });

        // 3. Browser URL
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Healthy,
                message: format!("Browser URL: {}", config.browser_url),
            });
        } else {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Unhealthy,
                message: "Browser URL not set (not configured)".into(),
            });
        }

        // 4. Auth mode
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Healthy,
                message: format!("Auth: {}", config.auth.redacted_label()),
            });
        } else {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Unhealthy,
                message: "Auth mode not set (not configured)".into(),
            });
        }

        // 5. Network guard constraints
        if let Some(config) = &self.config {
            let network_guard_check = match reqwest::Url::parse(&config.browser_url) {
                Ok(url) => match url.host_str() {
                    Some(host) => {
                        let allowlisted = is_browser_control_host_allowlisted(host);
                        let https_or_loopback = url.scheme() == "https" || is_loopback_host(host);
                        if allowlisted && https_or_loopback {
                            DoctorCheck {
                                name: "network_constraints".into(),
                                status: DoctorStatus::Healthy,
                                message: format!(
                                    "Network guard allowlist satisfied for control host '{host}'"
                                ),
                            }
                        } else {
                            DoctorCheck {
                                name: "network_constraints".into(),
                                status: DoctorStatus::Unhealthy,
                                message: format!(
                                    "Control host '{host}' violates allowlist or HTTPS policy"
                                ),
                            }
                        }
                    }
                    None => DoctorCheck {
                        name: "network_constraints".into(),
                        status: DoctorStatus::Unhealthy,
                        message: "Browser URL is missing a host".into(),
                    },
                },
                Err(err) => DoctorCheck {
                    name: "network_constraints".into(),
                    status: DoctorStatus::Unhealthy,
                    message: format!("Invalid browser URL for network guard checks: {err}"),
                },
            };
            checks.push(network_guard_check);
        } else {
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                status: DoctorStatus::Unhealthy,
                message: "Cannot assess – not configured".into(),
            });
        }

        // 6. Sandbox profile
        let placement_profile = browser_placement_profile();
        checks.push(DoctorCheck {
            name: "sandbox_profile".into(),
            status: if placement_profile.sandbox_profile == "strict"
                && placement_profile.sandbox_deny_exec
                && placement_profile.sandbox_deny_ptrace
            {
                DoctorStatus::Healthy
            } else {
                DoctorStatus::Unhealthy
            },
            message: format!(
                "profile={}, deny_exec={}, deny_ptrace={}",
                placement_profile.sandbox_profile,
                placement_profile.sandbox_deny_exec,
                placement_profile.sandbox_deny_ptrace
            ),
        });

        // 7. Execution planner requirements
        let planner = placement_profile.execution_planner;
        checks.push(DoctorCheck {
            name: "execution_planner_resources".into(),
            status: if planner.memory_mb > 0
                && planner.cpu_percent > 0
                && planner.wall_clock_timeout_ms > 0
            {
                DoctorStatus::Healthy
            } else {
                DoctorStatus::Unhealthy
            },
            message: format!(
                "memory_mb={}, cpu_percent={}, wall_clock_timeout_ms={}",
                planner.memory_mb, planner.cpu_percent, planner.wall_clock_timeout_ms
            ),
        });

        // 8. Credential injection
        if let Some(config) = &self.config {
            if config.auth.is_secretless() {
                checks.push(DoctorCheck {
                    name: "credential_injection".into(),
                    status: DoctorStatus::Healthy,
                    message: "Secretless mode – egress proxy will inject credentials".into(),
                });
            } else {
                checks.push(DoctorCheck {
                    name: "credential_injection".into(),
                    status: DoctorStatus::Healthy,
                    message: "Direct auth mode – no proxy injection needed".into(),
                });
            }
        } else {
            checks.push(DoctorCheck {
                name: "credential_injection".into(),
                status: DoctorStatus::Unhealthy,
                message: "Cannot assess – not configured".into(),
            });
        }

        let overall = if checks.iter().any(|c| c.status == DoctorStatus::Unhealthy) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| c.status == DoctorStatus::Degraded) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };

        let result = DoctorResult {
            status: overall,
            checks,
        };

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    /// Handle self-check connectivity probe.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report =
                SelfCheckReport::failed("not_configured", "Connector is not configured yet");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        // In credential_id mode, we can't verify connectivity without the egress proxy
        if let Some(config) = &self.config {
            if config.auth.is_secretless() {
                let report = SelfCheckReport::degraded(
                    "credential_injection_required",
                    "Configured with credential_id; egress proxy injection required for checks",
                );
                return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize self-check report: {e}"),
                });
            }
        }

        let report = match client.health_check().await {
            Ok(()) => SelfCheckReport::ok(),
            Err(err) => {
                if err.is_retryable() {
                    SelfCheckReport::degraded("self_check_retryable", err.to_string())
                } else {
                    SelfCheckReport::failed("self_check_failed", err.to_string())
                }
            }
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
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
                op_info(
                    "browser.session.save",
                    "Persist current browser cookies into a mesh state object",
                    json!({
                        "type": "object",
                        "required": ["lease_seq", "lease_object_id"],
                        "properties": {
                            "domain": { "type": "string" },
                            "lease_seq": { "type": "integer" },
                            "lease_object_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["state_object_id", "seq", "lease_seq", "cookie_count", "payload_cbor_size", "captured_at"],
                        "properties": {
                            "state_object_id": { "type": "string" },
                            "prev_state_object_id": { "type": "string" },
                            "seq": { "type": "integer" },
                            "lease_seq": { "type": "integer" },
                            "lease_object_id": { "type": "string" },
                            "cookie_count": { "type": "integer" },
                            "payload_cbor_size": { "type": "integer" },
                            "captured_at": { "type": "integer" },
                            "domain": { "type": "string" },
                            "audit": { "type": "object" }
                        }
                    }),
                    "browser.sessions",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Persist authenticated browser cookies as mesh state before failover or restart.".into(),
                        common_mistakes: vec![
                            "Omitting lease metadata for singleton-writer fencing.".into(),
                            "Persisting cookies from an unintended domain scope.".into(),
                        ],
                        examples: vec![
                            r#"{"domain":"example.com","lease_seq":12,"lease_object_id":"lease-obj-123"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("browser.session.restore"),
                            CapabilityId::from_static("browser.session.describe"),
                        ],
                    },
                ),
                op_info(
                    "browser.session.restore",
                    "Restore browser cookies from a saved mesh state object",
                    json!({
                        "type": "object",
                        "required": ["lease_seq", "lease_object_id"],
                        "properties": {
                            "state_object_id": { "type": "string" },
                            "lease_seq": { "type": "integer" },
                            "lease_object_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["state_object_id", "restored_count", "lease_seq", "cookie_count", "captured_at"],
                        "properties": {
                            "state_object_id": { "type": "string" },
                            "restored_count": { "type": "integer" },
                            "cookie_count": { "type": "integer" },
                            "seq": { "type": "integer" },
                            "saved_lease_seq": { "type": "integer" },
                            "lease_seq": { "type": "integer" },
                            "lease_object_id": { "type": "string" },
                            "captured_at": { "type": "integer" },
                            "domain": { "type": "string" },
                            "audit": { "type": "object" }
                        }
                    }),
                    "browser.sessions",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Restore a previously captured session on a fresh browser worker.".into(),
                        common_mistakes: vec![
                            "Using a stale lease_seq from a pre-failover writer.".into(),
                            "Assuming state_object_id defaults when no head exists.".into(),
                        ],
                        examples: vec![
                            r#"{"state_object_id":"state-obj-abc","lease_seq":13,"lease_object_id":"lease-obj-124"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("browser.session.save"),
                            CapabilityId::from_static("browser.get_cookies"),
                        ],
                    },
                ),
                op_info(
                    "browser.session.describe",
                    "Describe metadata for a saved browser session state object",
                    json!({
                        "type": "object",
                        "properties": {
                            "state_object_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["state_object_id", "seq", "lease_seq", "cookie_count", "captured_at", "payload_cbor_size", "is_head"],
                        "properties": {
                            "state_object_id": { "type": "string" },
                            "prev_state_object_id": { "type": "string" },
                            "seq": { "type": "integer" },
                            "lease_seq": { "type": "integer" },
                            "lease_object_id": { "type": "string" },
                            "cookie_count": { "type": "integer" },
                            "captured_at": { "type": "integer" },
                            "domain": { "type": "string" },
                            "payload_cbor_size": { "type": "integer" },
                            "is_head": { "type": "boolean" }
                        }
                    }),
                    "browser.sessions",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Inspect session metadata without exposing cookie values.".into(),
                        common_mistakes: vec!["Expecting raw cookie values in this operation output.".into()],
                        examples: vec![r#"{"state_object_id":"state-obj-abc"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("browser.session.save"),
                            CapabilityId::from_static("browser.session.restore"),
                        ],
                    },
                ),
                op_info(
                    "browser.set_proxy",
                    "Configure an outbound proxy for browser traffic",
                    json!({
                        "type": "object",
                        "required": ["server"],
                        "properties": {
                            "server": { "type": "string" },
                            "bypass_list": { "type": "array", "items": { "type": "string" } },
                            "username": { "type": "string" },
                            "password": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["enabled", "mode"],
                        "properties": {
                            "enabled": { "type": "boolean" },
                            "mode": { "type": "string" },
                            "server": { "type": "string" },
                            "audit": { "type": "object" }
                        }
                    }),
                    "browser.proxy",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Route browser requests through a controlled proxy. Dangerous because it changes outbound trust boundaries.".into(),
                        common_mistakes: vec![
                            "Sending credentials to untrusted proxy endpoints.".into(),
                            "Forgetting bypass rules for local callback URLs.".into(),
                        ],
                        examples: vec![
                            r#"{"server": "http://proxy.example.com:8080", "bypass_list": ["localhost"]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("browser.clear_proxy")],
                    },
                ),
                op_info(
                    "browser.clear_proxy",
                    "Clear outbound proxy configuration",
                    json!({
                        "type": "object",
                        "properties": {}
                    }),
                    json!({
                        "type": "object",
                        "required": ["enabled", "mode"],
                        "properties": {
                            "enabled": { "type": "boolean" },
                            "mode": { "type": "string" },
                            "server": { "type": "string" },
                            "audit": { "type": "object" }
                        }
                    }),
                    "browser.proxy",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Revert browser networking to direct mode after proxy-based workflows.".into(),
                        common_mistakes: vec!["Assuming proxy state is reset between sessions.".into()],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("browser.set_proxy")],
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
        let intro = self.handle_introspect().await?;
        let cap_str = intro
            .get("operations")
            .and_then(|ops| ops.as_array())
            .and_then(|ops| {
                ops.iter()
                    .find(|o| o.get("id").and_then(|id| id.as_str()) == Some(operation))
            })
            .and_then(|op| op.get("capability"))
            .and_then(|cap| cap.as_str())
            .ok_or_else(|| FcpError::OperationNotGranted {
                operation: operation.into(),
            })?;

        let cap_id: CapabilityId = cap_str.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            // dja9u.1.a: verify_bound returns CapabilityToken<BoundVerified>;
            // discarded here because invoke has no downstream that consumes
            // the typestate yet, but the call enforces the typestate handoff.
            let _bound = verifier.verify_bound(token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        let execution_approval = Self::require_execution_approval(operation, &input, &params)?;

        match operation {
            "browser.navigate" => self.invoke_navigate(input).await,
            "browser.screenshot" => self.invoke_screenshot(input).await,
            "browser.render_pdf" => self.invoke_render_pdf(input).await,
            "browser.extract_text" => self.invoke_extract_text(input).await,
            "browser.extract_links" => self.invoke_extract_links(input).await,
            "browser.wait_for_selector" => self.invoke_wait_for_selector(input).await,
            "browser.click" => self.invoke_click(input).await,
            "browser.fill_form" => {
                self.invoke_fill_form(input, execution_approval.as_ref())
                    .await
            }
            "browser.evaluate_js" => {
                self.invoke_evaluate_js(input, execution_approval.as_ref())
                    .await
            }
            "browser.get_cookies" => {
                self.invoke_get_cookies(input, execution_approval.as_ref())
                    .await
            }
            "browser.set_cookies" => {
                self.invoke_set_cookies(input, execution_approval.as_ref())
                    .await
            }
            "browser.session.save" => {
                self.invoke_session_save(input, execution_approval.as_ref())
                    .await
            }
            "browser.session.restore" => {
                self.invoke_session_restore(input, execution_approval.as_ref())
                    .await
            }
            "browser.session.describe" => self.invoke_session_describe(input).await,
            "browser.set_proxy" => {
                self.invoke_set_proxy(input, execution_approval.as_ref())
                    .await
            }
            "browser.clear_proxy" => {
                self.invoke_clear_proxy(input, execution_approval.as_ref())
                    .await
            }
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    fn require_execution_approval(
        operation: &str,
        input: &serde_json::Value,
        params: &serde_json::Value,
    ) -> FcpResult<Option<ExecutionApprovalContext>> {
        if !requires_execution_approval(operation) {
            return Ok(None);
        }

        let approval_value = params
            .get("approval_token")
            .ok_or(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: format!(
                    "Operation '{operation}' requires an ApprovalToken with execution scope"
                ),
            })?;

        let approval: ApprovalToken =
            serde_json::from_value(approval_value.clone()).map_err(|e| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid approval_token format: {e}"),
                }
            })?;

        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        if !approval.is_valid(now_ms) {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "approval_token is expired or not yet valid".into(),
            });
        }

        let Execution(scope) = &approval.scope else {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "approval_token must use execution scope".into(),
            });
        };

        if scope.connector_id != "fcp.browser" {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "approval_token connector_id does not match fcp.browser".into(),
            });
        }

        if !operation_pattern_matches(&scope.method_pattern, operation) {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "approval_token execution scope does not allow this operation".into(),
            });
        }

        if scope.request_object_id.is_some() || scope.input_hash.is_some() {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "approval_token binds request_object_id/input_hash, unsupported in direct connector invocation".into(),
            });
        }

        if !scope.input_constraints.is_empty()
            && !scope
                .input_constraints
                .iter()
                .all(|constraint| input.pointer(&constraint.pointer) == Some(&constraint.expected))
        {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "approval_token input constraints do not match this invocation".into(),
            });
        }

        Ok(Some(ExecutionApprovalContext {
            token_id: approval.token_id,
        }))
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
            .and_then(|v| u32::try_from(v).ok());
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

    async fn invoke_fill_form(
        &self,
        input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
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
        Ok(json!({
            "filled_count": result.filled_count,
            "submitted": result.submitted,
            "audit": dangerous_operation_audit("browser.fill_form", true, execution_approval),
        }))
    }

    async fn invoke_evaluate_js(
        &self,
        input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let expression = require_str(&input, "expression")?;
        let result = client
            .evaluate_js(expression)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({
            "result": result.result,
            "audit": dangerous_operation_audit("browser.evaluate_js", true, execution_approval),
        }))
    }

    async fn invoke_get_cookies(
        &self,
        input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let domain = input.get("domain").and_then(|v| v.as_str());
        let cookies = client
            .get_cookies(domain)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({
            "cookies": cookies,
            "audit": dangerous_operation_audit("browser.get_cookies", false, execution_approval),
        }))
    }

    async fn invoke_set_cookies(
        &self,
        input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
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
        Ok(json!({
            "set_count": count,
            "audit": dangerous_operation_audit("browser.set_cookies", true, execution_approval),
        }))
    }

    async fn invoke_set_proxy(
        &self,
        input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let server = require_str(&input, "server")?;
        let bypass_list = input
            .get("bypass_list")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .map(|v| {
                        v.as_str().ok_or(FcpError::InvalidRequest {
                            code: 1003,
                            message: "bypass_list values must be strings".into(),
                        })
                    })
                    .collect::<FcpResult<Vec<_>>>()
                    .map(|entries| entries.into_iter().map(str::to_string).collect::<Vec<_>>())
            })
            .transpose()?;
        let username = input
            .get("username")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let password = input
            .get("password")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let proxy = ProxyConfig {
            server: server.to_string(),
            bypass_list,
            username,
            password,
        };

        let result = client
            .set_proxy(&proxy)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({
            "enabled": result.enabled,
            "mode": result.mode,
            "server": result.server,
            "audit": dangerous_operation_audit("browser.set_proxy", true, execution_approval),
        }))
    }

    async fn invoke_clear_proxy(
        &self,
        _input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let result = client
            .clear_proxy()
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;
        Ok(json!({
            "enabled": result.enabled,
            "mode": result.mode,
            "server": result.server,
            "audit": dangerous_operation_audit("browser.clear_proxy", true, execution_approval),
        }))
    }

    async fn invoke_session_save(
        &self,
        input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let domain = input
            .get("domain")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let lease_seq = parse_required_u64_field(&input, "lease_seq")?;
        let lease_object_id = require_str(&input, "lease_object_id")?.to_string();

        let cookies = client
            .get_cookies(domain.as_deref())
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;

        let payload = BrowserSessionStatePayload {
            schema_version: 1,
            captured_at: current_unix_timestamp_secs(),
            domain: domain.clone(),
            cookies,
        };
        let payload_cbor =
            fcp_cbor::to_canonical_cbor(&payload).map_err(|e| FcpError::Internal {
                message: format!("Failed to encode browser session payload: {e}"),
            })?;

        let mut store = self.session_store.lock().map_err(|_| FcpError::Internal {
            message: "session state store mutex poisoned".into(),
        })?;
        if lease_seq < store.last_lease_seq {
            return Err(FcpError::Conflict {
                message: format!(
                    "stale lease_seq for browser session state: current={}, incoming={lease_seq}",
                    store.last_lease_seq
                ),
            });
        }

        let prev_state_object_id = store.head_state_object_id.clone();
        let seq = if store.head_state_object_id.is_some() {
            store.last_seq.saturating_add(1)
        } else {
            0
        };
        let state_object_id = derive_session_state_object_id(
            prev_state_object_id.as_deref(),
            lease_seq,
            &lease_object_id,
            &payload_cbor,
        );

        let record = BrowserSessionStateObjectRecord {
            state_object_id: state_object_id.clone(),
            prev_state_object_id: prev_state_object_id.clone(),
            seq,
            lease_seq,
            lease_object_id: lease_object_id.clone(),
            payload_cbor: payload_cbor.clone(),
            payload,
        };
        let cookie_count = record.payload.cookies.len();
        let captured_at = record.payload.captured_at;

        store.objects.insert(state_object_id.clone(), record);
        store.head_state_object_id = Some(state_object_id.clone());
        store.last_seq = seq;
        store.last_lease_seq = lease_seq;
        drop(store);

        Ok(json!({
            "state_object_id": state_object_id,
            "prev_state_object_id": prev_state_object_id,
            "seq": seq,
            "lease_seq": lease_seq,
            "lease_object_id": lease_object_id,
            "cookie_count": cookie_count,
            "payload_cbor_size": payload_cbor.len(),
            "captured_at": captured_at,
            "domain": domain,
            "audit": dangerous_operation_audit("browser.session.save", true, execution_approval),
        }))
    }

    async fn invoke_session_restore(
        &self,
        input: serde_json::Value,
        execution_approval: Option<&ExecutionApprovalContext>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let requested_state_object_id = input
            .get("state_object_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let lease_seq = parse_required_u64_field(&input, "lease_seq")?;
        let lease_object_id = require_str(&input, "lease_object_id")?.to_string();

        let record = {
            let mut store = self.session_store.lock().map_err(|_| FcpError::Internal {
                message: "session state store mutex poisoned".into(),
            })?;
            if lease_seq < store.last_lease_seq {
                return Err(FcpError::Conflict {
                    message: format!(
                        "stale lease_seq for browser session state: current={}, incoming={lease_seq}",
                        store.last_lease_seq
                    ),
                });
            }

            let state_object_id = match requested_state_object_id {
                Some(ref id) => id.clone(),
                None => store
                    .head_state_object_id
                    .clone()
                    .ok_or(FcpError::InvalidRequest {
                        code: 1003,
                        message: "No saved browser session state available".into(),
                    })?,
            };
            let record =
                store
                    .objects
                    .get(&state_object_id)
                    .cloned()
                    .ok_or(FcpError::InvalidRequest {
                        code: 1003,
                        message: format!(
                            "Unknown browser session state object_id: {state_object_id}"
                        ),
                    })?;
            store.last_lease_seq = lease_seq;
            record
        };

        let restored_count = client
            .set_cookies(&record.payload.cookies)
            .await
            .map_err(|e: BrowserError| e.to_fcp_error())?;

        Ok(json!({
            "state_object_id": record.state_object_id,
            "restored_count": restored_count,
            "cookie_count": record.payload.cookies.len(),
            "seq": record.seq,
            "saved_lease_seq": record.lease_seq,
            "lease_seq": lease_seq,
            "lease_object_id": lease_object_id,
            "captured_at": record.payload.captured_at,
            "domain": record.payload.domain,
            "audit": dangerous_operation_audit("browser.session.restore", true, execution_approval),
        }))
    }

    async fn invoke_session_describe(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let requested_state_object_id = input
            .get("state_object_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let (record, is_head) =
            {
                let store = self.session_store.lock().map_err(|_| FcpError::Internal {
                    message: "session state store mutex poisoned".into(),
                })?;
                let state_object_id = match requested_state_object_id {
                    Some(ref id) => id.clone(),
                    None => store
                        .head_state_object_id
                        .clone()
                        .ok_or(FcpError::InvalidRequest {
                            code: 1003,
                            message: "No saved browser session state available".into(),
                        })?,
                };
                let record = store.objects.get(&state_object_id).cloned().ok_or(
                    FcpError::InvalidRequest {
                        code: 1003,
                        message: format!(
                            "Unknown browser session state object_id: {state_object_id}"
                        ),
                    },
                )?;
                let is_head =
                    store.head_state_object_id.as_deref() == Some(state_object_id.as_str());
                drop(store);
                (record, is_head)
            };

        Ok(json!({
            "state_object_id": record.state_object_id,
            "prev_state_object_id": record.prev_state_object_id,
            "seq": record.seq,
            "lease_seq": record.lease_seq,
            "lease_object_id": record.lease_object_id,
            "cookie_count": record.payload.cookies.len(),
            "captured_at": record.payload.captured_at,
            "domain": record.payload.domain,
            "payload_cbor_size": record.payload_cbor.len(),
            "is_head": is_head,
        }))
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

fn requires_execution_approval(operation: &str) -> bool {
    matches!(
        operation,
        "browser.evaluate_js"
            | "browser.fill_form"
            | "browser.get_cookies"
            | "browser.set_cookies"
            | "browser.session.save"
            | "browser.session.restore"
            | "browser.set_proxy"
            | "browser.clear_proxy"
    )
}

fn parse_required_u64_field(input: &serde_json::Value, field: &str) -> FcpResult<u64> {
    input
        .get(field)
        .and_then(|v| v.as_u64())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

fn current_unix_timestamp_secs() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0)
}

fn browser_placement_profile() -> BrowserPlacementProfile {
    BrowserPlacementProfile {
        sandbox_profile: BROWSER_SANDBOX_PROFILE,
        sandbox_deny_exec: BROWSER_SANDBOX_DENY_EXEC,
        sandbox_deny_ptrace: BROWSER_SANDBOX_DENY_PTRACE,
        network_guard: BrowserNetworkGuardProfile {
            allowed_host_patterns: BROWSER_CONTROL_HOST_ALLOWLIST,
            require_https_for_non_loopback: true,
            allow_http_for_loopback: true,
        },
        execution_planner: BrowserExecutionPlannerProfile {
            memory_mb: BROWSER_SANDBOX_MEMORY_MB,
            cpu_percent: BROWSER_SANDBOX_CPU_PERCENT,
            wall_clock_timeout_ms: BROWSER_SANDBOX_WALL_CLOCK_TIMEOUT_MS,
        },
    }
}

fn validate_browser_control_plane_url(browser_url: &str) -> FcpResult<()> {
    let parsed = reqwest::Url::parse(browser_url).map_err(|e| FcpError::InvalidRequest {
        code: 1003,
        message: format!("browser_url must be an absolute URL: {e}"),
    })?;
    let redacted_url = redact_browser_endpoint_url(&parsed);

    if is_direct_cdp_websocket_endpoint(&parsed) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "browser_url points at a direct Chrome DevTools WebSocket endpoint ({redacted_url}); configure an FCP browser-control HTTP(S) endpoint"
            ),
        });
    }

    if matches!(parsed.scheme(), "ws" | "wss") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "browser_url must be an FCP browser-control HTTP(S) base URL, not a WebSocket endpoint ({redacted_url})"
            ),
        });
    }

    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "browser_url scheme must be http or https".into(),
        });
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("browser_url must not include userinfo ({redacted_url})"),
        });
    }

    if parsed.query().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("browser_url must not include query parameters ({redacted_url})"),
        });
    }

    if parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("browser_url must not include a URL fragment ({redacted_url})"),
        });
    }

    if is_chrome_cdp_discovery_path(parsed.path()) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "browser_url points at a raw Chrome DevTools discovery endpoint ({redacted_url}); configure the FCP browser-control base URL"
            ),
        });
    }

    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "browser_url must include a host".into(),
    })?;

    if !is_browser_control_host_allowlisted(host) {
        return Err(FcpError::ResourceNotAllowed {
            resource: format!("browser.control_plane.host:{host}"),
        });
    }

    if parsed.scheme() == "http" && !is_loopback_host(host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "browser_url must use https for non-loopback hosts (got host '{host}')"
            ),
        });
    }

    Ok(())
}

fn redact_browser_endpoint_url(parsed: &reqwest::Url) -> String {
    let mut redacted = parsed.clone();
    let _ = redacted.set_username("");
    let _ = redacted.set_password(None);
    redacted.set_query(None);
    redacted.set_fragment(None);
    redacted.to_string()
}

fn is_direct_cdp_websocket_endpoint(parsed: &reqwest::Url) -> bool {
    if !matches!(parsed.scheme(), "ws" | "wss") {
        return false;
    }

    let Some(mut segments) = parsed.path_segments() else {
        return false;
    };
    let Some("devtools") = segments.next() else {
        return false;
    };
    let Some(kind) = segments.next() else {
        return false;
    };
    if !matches!(
        kind,
        "browser" | "page" | "worker" | "shared_worker" | "service_worker"
    ) {
        return false;
    }
    let Some(target_id) = segments.next() else {
        return false;
    };
    !target_id.is_empty() && segments.next().is_none()
}

fn is_chrome_cdp_discovery_path(path: &str) -> bool {
    path == "/json" || path.starts_with("/json/")
}

fn is_browser_control_host_allowlisted(host: &str) -> bool {
    let normalized = host.to_ascii_lowercase();
    BROWSER_CONTROL_HOST_ALLOWLIST
        .iter()
        .any(|pattern| host_matches_pattern(&normalized, pattern))
}

fn is_loopback_host(host: &str) -> bool {
    let normalized = host.to_ascii_lowercase();
    matches!(normalized.as_str(), "localhost" | "127.0.0.1" | "::1")
}

fn host_matches_pattern(host: &str, pattern: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix
            || (host.len() > suffix.len()
                && host.ends_with(suffix)
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.')
    } else {
        host == pattern
    }
}

fn derive_session_state_object_id(
    prev_state_object_id: Option<&str>,
    lease_seq: u64,
    lease_object_id: &str,
    payload_cbor: &[u8],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fcp.browser.session_state.v1");
    if let Some(prev) = prev_state_object_id {
        hasher.update(prev.as_bytes());
    }
    hasher.update(&lease_seq.to_le_bytes());
    hasher.update(lease_object_id.as_bytes());
    hasher.update(payload_cbor);
    hasher.finalize().to_hex().to_string()
}

fn operation_pattern_matches(pattern: &str, operation: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        operation.starts_with(prefix)
    } else {
        pattern == operation
    }
}

fn dangerous_operation_audit(
    operation: &str,
    side_effect: bool,
    execution_approval: Option<&ExecutionApprovalContext>,
) -> serde_json::Value {
    json!({
        "operation": operation,
        "dangerous": true,
        "side_effect": side_effect,
        "approval_token_id": execution_approval.map(|ctx| ctx.token_id.clone()),
        "timestamp": chrono::Utc::now().to_rfc3339(),
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
    let requires_approval = match safety_tier {
        SafetyTier::Risky => Some(ApprovalMode::Policy),
        SafetyTier::Dangerous | SafetyTier::Critical | SafetyTier::Forbidden => {
            Some(ApprovalMode::ElevationToken)
        }
        SafetyTier::Safe => None,
    };

    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval,
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
    use fcp_prelude::CapabilityConstraints;
    use std::path::PathBuf;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    fn test_constraints_cbor() -> Vec<u8> {
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        cbor
    }

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        cap: &str,
        op: &str,
    ) -> CapabilityToken {
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .issuer("node:test")
            .target_instance(instance_id)
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
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

        let token = generate_valid_token(
            &signing_key,
            connector.base.instance_id.as_str(),
            "browser.navigate",
            "browser.navigate",
        );
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
        connector
            .handle_configure(json!({
                "browser_url": "http://localhost:9999"
            }))
            .await
            .unwrap();

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

        let token = generate_valid_token(
            &signing_key,
            connector.base.instance_id.as_str(),
            "browser.interact",
            "browser.click",
        );
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
        assert!(op_ids.contains(&"browser.session.save"));
        assert!(op_ids.contains(&"browser.session.restore"));
        assert!(op_ids.contains(&"browser.session.describe"));
        assert!(op_ids.contains(&"browser.set_proxy"));
        assert!(op_ids.contains(&"browser.clear_proxy"));
        assert_eq!(ops.len(), 16);
    }

    // ── Provisioning automation tests ─────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_no_auth() {
        let mut connector = BrowserConnector::new();
        let result = connector.handle_configure(json!({})).await.unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.client.is_some());
        assert!(connector.config.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_api_key() {
        let mut connector = BrowserConnector::new();
        let result = connector
            .handle_configure(json!({ "api_key": "browser-secret" }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id() {
        let mut connector = BrowserConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.config.as_ref().unwrap().auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_both_auth_modes() {
        let mut connector = BrowserConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "api_key": "browser-secret",
                "credential_id": cid
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("not both"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_browser_url() {
        let mut connector = BrowserConnector::new();
        let result = connector
            .handle_configure(json!({
                "browser_url": "https://control.browser.flywheel.internal:9222"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        let config = connector.config.as_ref().unwrap();
        assert_eq!(
            config.browser_url,
            "https://control.browser.flywheel.internal:9222"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_disallowed_browser_url_host() {
        let mut connector = BrowserConnector::new();
        let result = connector
            .handle_configure(json!({
                "browser_url": "https://evil.example.net:9222"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::ResourceNotAllowed { resource } => {
                assert!(resource.contains("browser.control_plane.host"));
            }
            e => panic!("Expected ResourceNotAllowed, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_http_on_non_loopback_host() {
        let mut connector = BrowserConnector::new();
        let result = connector
            .handle_configure(json!({
                "browser_url": "http://control.browser.flywheel.internal:9222"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("must use https"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_raw_chrome_cdp_discovery_url() {
        let mut connector = BrowserConnector::new();
        let result = connector
            .handle_configure(json!({
                "browser_url": "http://localhost:9222/json/version"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("raw Chrome DevTools discovery"));
                assert!(message.contains("http://localhost:9222/json/version"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_direct_cdp_websocket_url() {
        let mut connector = BrowserConnector::new();
        let result = connector
            .handle_configure(json!({
                "browser_url": "ws://localhost:9222/devtools/page/target-1"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("direct Chrome DevTools WebSocket"));
                assert!(message.contains("ws://localhost:9222/devtools/page/target-1"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_browser_url_userinfo_query_and_fragment() {
        for (browser_url, expected) in [
            (
                "https://user:private-value@control.browser.flywheel.internal:9222",
                "must not include userinfo",
            ),
            (
                "https://control.browser.flywheel.internal:9222?query=private-value",
                "must not include query parameters",
            ),
            (
                "https://control.browser.flywheel.internal:9222#private-value",
                "must not include a URL fragment",
            ),
        ] {
            let mut connector = BrowserConnector::new();
            let result = connector
                .handle_configure(json!({ "browser_url": browser_url }))
                .await;
            assert!(result.is_err());
            match result.unwrap_err() {
                FcpError::InvalidRequest { message, .. } => {
                    assert!(message.contains(expected));
                    assert!(!message.contains("private-value"));
                    assert!(!message.contains("query=private-value"));
                }
                e => panic!("Expected InvalidRequest, got: {e:?}"),
            }
        }
    }

    #[test]
    fn browser_endpoint_policy_identifies_direct_cdp_websocket_shapes() {
        let direct =
            reqwest::Url::parse("wss://localhost:9222/devtools/browser/browser-target").unwrap();
        assert!(is_direct_cdp_websocket_endpoint(&direct));

        let worker =
            reqwest::Url::parse("ws://localhost:9222/devtools/service_worker/sw-target").unwrap();
        assert!(is_direct_cdp_websocket_endpoint(&worker));

        let missing_target = reqwest::Url::parse("ws://localhost:9222/devtools/page/").unwrap();
        assert!(!is_direct_cdp_websocket_endpoint(&missing_target));

        let non_cdp_ws = reqwest::Url::parse("ws://localhost:9222/fcp-control").unwrap();
        assert!(!is_direct_cdp_websocket_endpoint(&non_cdp_ws));
    }

    #[test]
    fn browser_endpoint_redaction_strips_userinfo_query_and_fragment() {
        let parsed = reqwest::Url::parse(
            "https://user:private-value@control.browser.flywheel.internal:9222/json/version?query=private-value#frag",
        )
        .unwrap();
        let redacted = redact_browser_endpoint_url(&parsed);

        assert_eq!(
            redacted,
            "https://control.browser.flywheel.internal:9222/json/version"
        );
        assert!(!redacted.contains("user"));
        assert!(!redacted.contains("private-value"));
        assert!(!redacted.contains("query"));
        assert!(!redacted.contains("frag"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_includes_auth_info() {
        let mut connector = BrowserConnector::new();
        connector
            .handle_configure(json!({ "api_key": "test-key" }))
            .await
            .unwrap();
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "healthy");
        assert!(health["auth_mode"].as_str().unwrap().contains("api_key"));
        assert!(health["browser_url"].as_str().is_some());
        assert_eq!(health["placement_profile"]["sandbox_profile"], "strict");
        assert_eq!(
            health["placement_profile"]["execution_planner"]["memory_mb"],
            1024
        );
        assert_eq!(health["network_guard"]["allowlisted"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = BrowserConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 8);
        assert_eq!(checks[0]["name"], "configuration");
        assert_eq!(checks[0]["status"], "unhealthy");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_healthy() {
        let mut connector = BrowserConnector::new();
        connector.handle_configure(json!({})).await.unwrap();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 8);
        for check in checks {
            assert_eq!(check["status"], "healthy");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_credential_id_mode() {
        let mut connector = BrowserConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert_eq!(cred_check["status"], "healthy");
        assert!(
            cred_check["message"]
                .as_str()
                .unwrap()
                .contains("Secretless")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = BrowserConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_degraded() {
        let mut connector = BrowserConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "credential_injection_required");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_accepts_fcp_browser_control_plane_health() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(browser_control_contract_descriptor()),
            )
            .mount(&mock_server)
            .await;

        let mut connector = BrowserConnector::new();
        connector
            .handle_configure(json!({ "browser_url": mock_server.uri() }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "ok");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_rejects_raw_chrome_cdp_endpoint() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/json/version"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Browser": "Chrome/123.0.0.0",
                "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/abc"
            })))
            .mount(&mock_server)
            .await;

        let mut connector = BrowserConnector::new();
        connector
            .handle_configure(json!({ "browser_url": mock_server.uri() }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason_code"], "self_check_failed");
        assert!(
            result["message"]
                .as_str()
                .unwrap()
                .contains("raw Chrome DevTools endpoint")
        );
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

    // ── require_str sync tests ──────────────────────────────────────

    #[test]
    fn require_str_extracts_value() {
        let input = json!({"url": "https://example.com", "selector": "#main"});
        assert_eq!(require_str(&input, "url").unwrap(), "https://example.com");
        assert_eq!(require_str(&input, "selector").unwrap(), "#main");
    }

    #[test]
    fn require_str_missing_field() {
        let input = json!({"url": "https://example.com"});
        let err = require_str(&input, "selector").unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("selector")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn require_str_non_string_field() {
        let input = json!({"count": 42});
        assert!(require_str(&input, "count").is_err());
    }

    #[test]
    fn require_str_null_field() {
        let input = json!({"field": null});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"val": 1.23});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"val": {"nested": true}});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"val": [1, 2, 3]});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"val": true});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_nested_object_value() {
        let input = json!({"val": {"a": {"b": "c"}}});
        assert!(require_str(&input, "val").is_err());
    }

    #[test]
    fn require_str_empty_string_returns_ok() {
        let input = json!({"val": ""});
        assert_eq!(require_str(&input, "val").unwrap(), "");
    }

    #[test]
    fn require_str_error_code_is_1003() {
        let input = json!({});
        match require_str(&input, "x").unwrap_err() {
            FcpError::InvalidRequest { code, .. } => assert_eq!(code, 1003),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    // ── parse_required_u64_field sync tests ─────────────────────────

    #[test]
    fn parse_required_u64_extracts_value() {
        let input = json!({"timeout": 5000});
        assert_eq!(parse_required_u64_field(&input, "timeout").unwrap(), 5000);
    }

    #[test]
    fn parse_required_u64_missing_field() {
        let input = json!({});
        assert!(parse_required_u64_field(&input, "timeout").is_err());
    }

    #[test]
    fn parse_required_u64_string_value() {
        let input = json!({"timeout": "5000"});
        assert!(parse_required_u64_field(&input, "timeout").is_err());
    }

    #[test]
    fn parse_required_u64_null_value() {
        let input = json!({"timeout": null});
        assert!(parse_required_u64_field(&input, "timeout").is_err());
    }

    // ── requires_execution_approval sync tests ──────────────────────

    #[test]
    fn requires_execution_approval_js() {
        assert!(requires_execution_approval("browser.evaluate_js"));
    }

    #[test]
    fn requires_execution_approval_fill_form() {
        assert!(requires_execution_approval("browser.fill_form"));
    }

    #[test]
    fn requires_execution_approval_cookies() {
        assert!(requires_execution_approval("browser.get_cookies"));
        assert!(requires_execution_approval("browser.set_cookies"));
    }

    #[test]
    fn requires_execution_approval_session() {
        assert!(requires_execution_approval("browser.session.save"));
        assert!(requires_execution_approval("browser.session.restore"));
    }

    #[test]
    fn requires_execution_approval_proxy() {
        assert!(requires_execution_approval("browser.set_proxy"));
        assert!(requires_execution_approval("browser.clear_proxy"));
    }

    #[test]
    fn does_not_require_execution_approval_navigate() {
        assert!(!requires_execution_approval("browser.navigate"));
    }

    #[test]
    fn does_not_require_execution_approval_screenshot() {
        assert!(!requires_execution_approval("browser.screenshot"));
    }

    // ── DoctorResult / DoctorCheck / DoctorStatus serde ─────────────

    #[test]
    fn doctor_result_serde_roundtrip() {
        let r = DoctorResult {
            status: DoctorStatus::Healthy,
            checks: vec![DoctorCheck {
                name: "config".into(),
                status: DoctorStatus::Healthy,
                message: "ok".into(),
            }],
        };
        let v = serde_json::to_value(&r).unwrap();
        let r2: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r2.checks.len(), 1);
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult {
            status: DoctorStatus::Healthy,
            checks: vec![],
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_check_serde_roundtrip() {
        let c = DoctorCheck {
            name: "auth".into(),
            status: DoctorStatus::Healthy,
            message: "valid".into(),
        };
        let s = serde_json::to_string(&c).unwrap();
        let c2: DoctorCheck = serde_json::from_str(&s).unwrap();
        assert_eq!(c2.name, "auth");
        assert_eq!(c2.message, "valid");
    }

    #[test]
    fn doctor_check_debug() {
        let c = DoctorCheck {
            name: "dbgcheck".into(),
            status: DoctorStatus::Degraded,
            message: "warn".into(),
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("dbgcheck"));
    }

    #[test]
    fn doctor_status_serde_all_variants() {
        for status in [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ] {
            let v = serde_json::to_value(status).unwrap();
            let back: DoctorStatus = serde_json::from_value(v).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn doctor_status_debug() {
        let dbg = format!("{:?}", DoctorStatus::Unhealthy);
        assert!(dbg.contains("Unhealthy"));
    }

    #[test]
    fn doctor_status_copy() {
        let s = DoctorStatus::Degraded;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn doctor_status_eq_ne() {
        assert_eq!(DoctorStatus::Healthy, DoctorStatus::Healthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
        assert_ne!(DoctorStatus::Degraded, DoctorStatus::Unhealthy);
    }

    // ── Sandbox constants tests ─────────────────────────────────────

    #[test]
    fn sandbox_profile_is_strict() {
        assert_eq!(BROWSER_SANDBOX_PROFILE, "strict");
    }

    #[test]
    fn sandbox_memory_is_1024() {
        assert_eq!(BROWSER_SANDBOX_MEMORY_MB, 1024);
    }

    #[test]
    fn sandbox_deny_exec_is_true() {
        assert!(BROWSER_SANDBOX_DENY_EXEC);
    }

    #[test]
    fn sandbox_deny_ptrace_is_true() {
        assert!(BROWSER_SANDBOX_DENY_PTRACE);
    }
}
