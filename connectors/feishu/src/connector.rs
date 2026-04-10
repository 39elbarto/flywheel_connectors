//! Feishu connector implementation.

use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, AuthCaps, BaseConnector, CapabilityGrant, CapabilityId,
    CapabilityVerifier, ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, ResourceTypeInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use fcp_sdk::prelude::*;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::FeishuClient;
use crate::types::{ReplyMessageRequest, SendMessageRequest};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const FEISHU_CN_HOST: &str = "open.feishu.cn";
const FEISHU_GLOBAL_HOST: &str = "open.larksuite.com";
const FEISHU_TENANT_APP_BOUNDARY: &str = "This connector acts as one installed tenant app; it does not impersonate arbitrary users or cross tenant boundaries.";
const FEISHU_IMPLEMENTATION_STATUS: &str = "first_slice";
const FEISHU_BINDING_MODEL: &str = "single_tenant_app";
const FEISHU_AUTH_MODEL: &str = "tenant_app_credentials";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/feishu_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/feishu_connector/<timestamp>";
const VERIFY_COMMANDS: [&str; 7] = [
    "scripts/e2e/feishu_connector_verification.sh",
    "rch exec -- cargo run -q -p fwc -- manifest fix connectors/feishu/manifest.toml --check --json",
    "rch exec -- cargo check -p fcp-feishu --all-targets",
    "rch exec -- cargo fmt --manifest-path connectors/feishu/Cargo.toml --check",
    "rch exec -- cargo test -p fcp-feishu --test integration -- --nocapture",
    "rch exec -- cargo test -p fcp-feishu -- --nocapture",
    "rch exec -- cargo clippy -p fcp-feishu --all-targets -- -D warnings",
];
const MAX_CHATS_PAGE_SIZE: u32 = 200;
const ALLOWED_RECEIVE_ID_TYPES: &[&str] = &["open_id", "user_id", "union_id", "email", "chat_id"];
const ALLOWED_USER_ID_TYPES: &[&str] = &["open_id", "user_id", "union_id"];

// Operation IDs
const OP_MESSAGES_SEND: &str = "feishu.messages.send";
const OP_MESSAGES_REPLY: &str = "feishu.messages.reply";
const OP_MESSAGES_GET: &str = "feishu.messages.get";
const OP_CHATS_LIST: &str = "feishu.chats.list";
const OP_CHATS_GET: &str = "feishu.chats.get";
const OP_USERS_GET: &str = "feishu.users.get";
const OP_DOCS_GET: &str = "feishu.docs.get";
const OP_SHEETS_GET: &str = "feishu.sheets.get";
const OP_CALENDAR_EVENTS: &str = "feishu.calendar.events";
const OP_HEALTH: &str = "feishu.health";

// Capability IDs
const CAP_MSG_WRITE: &str = "feishu.messages.write";
const CAP_MSG_READ: &str = "feishu.messages.read";
const CAP_CHATS_READ: &str = "feishu.chats.read";
const CAP_USERS_READ: &str = "feishu.users.read";
const CAP_DOCS_READ: &str = "feishu.docs.read";
const CAP_CALENDAR_READ: &str = "feishu.calendar.read";

/// Feishu connector configuration.
#[derive(Clone, Deserialize)]
struct FeishuConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    app_id: String,
    app_secret: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl std::fmt::Debug for FeishuConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeishuConfig")
            .field("base_url", &self.base_url)
            .field("app_id", &self.app_id)
            .field("app_secret", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    "https://open.feishu.cn".into()
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1")
}

fn parse_base_url(base_url: &str) -> FcpResult<reqwest::Url> {
    reqwest::Url::parse(base_url).map_err(|err| FcpError::InvalidRequest {
        code: 1001,
        message: format!("Invalid base_url `{base_url}`: {err}"),
    })
}

fn validate_base_url(base_url: &reqwest::Url) -> FcpResult<()> {
    let host = base_url.host_str().ok_or(FcpError::InvalidRequest {
        code: 1001,
        message: "base_url must include a host".into(),
    })?;
    let is_local_host = is_local_test_host(host);

    if !base_url.username().is_empty() || base_url.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "base_url must not include embedded credentials".into(),
        });
    }

    if host != FEISHU_CN_HOST && host != FEISHU_GLOBAL_HOST && !is_local_host {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!(
                "base_url host `{host}` is not allowed; use https://{FEISHU_CN_HOST}, https://{FEISHU_GLOBAL_HOST}, or localhost/127.0.0.1 for tests"
            ),
        });
    }

    if !is_local_host && base_url.scheme() != "https" {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "Production Feishu/Lark base_url must use https".into(),
        });
    }

    if !is_local_host && base_url.port_or_known_default() != Some(443) {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "Production Feishu/Lark base_url must use port 443".into(),
        });
    }

    if base_url.path() != "/" && !base_url.path().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "base_url must not include a path segment".into(),
        });
    }

    if base_url.query().is_some() || base_url.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "base_url must not include query or fragment components".into(),
        });
    }

    Ok(())
}

fn validate_config(config: &FeishuConfig) -> FcpResult<()> {
    if config.app_id.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "app_id must not be empty".into(),
        });
    }

    if config.app_secret.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "app_secret must not be empty".into(),
        });
    }

    if config.request_timeout_ms == 0 {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "request_timeout_ms must be greater than zero".into(),
        });
    }

    let base_url = parse_base_url(&config.base_url)?;
    validate_base_url(&base_url)
}

fn base_url_diagnostic(base_url: &str) -> (bool, String) {
    match parse_base_url(base_url).and_then(|url| {
        validate_base_url(&url)?;
        Ok(url)
    }) {
        Ok(url) => {
            let host = url.host_str().unwrap_or_default();
            let message = if is_local_test_host(host) {
                "Base URL uses a localhost test override".into()
            } else {
                format!("Base URL matches allowed Feishu/Lark host `{host}`")
            };
            (true, message)
        }
        Err(FcpError::InvalidRequest { message, .. }) => (false, message),
        Err(err) => (false, err.to_string()),
    }
}

fn validate_receive_id_type(receive_id_type: &str) -> FcpResult<&str> {
    if ALLOWED_RECEIVE_ID_TYPES.contains(&receive_id_type) {
        Ok(receive_id_type)
    } else {
        Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!(
                "receive_id_type must be one of: {}",
                ALLOWED_RECEIVE_ID_TYPES.join(", ")
            ),
        })
    }
}

fn validate_user_id_type(user_id_type: &str) -> FcpResult<&str> {
    if ALLOWED_USER_ID_TYPES.contains(&user_id_type) {
        Ok(user_id_type)
    } else {
        Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!(
                "user_id_type must be one of: {}",
                ALLOWED_USER_ID_TYPES.join(", ")
            ),
        })
    }
}

fn validate_chats_page_size(page_size: u64) -> FcpResult<u32> {
    if !(1..=u64::from(MAX_CHATS_PAGE_SIZE)).contains(&page_size) {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("page_size must be between 1 and {MAX_CHATS_PAGE_SIZE}"),
        });
    }
    Ok(page_size as u32)
}

// Doctor types
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub ready: bool,
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning: Option<ProvisioningReadiness>,
    operator_guidance: OperatorGuidance,
    verification_script: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>, provisioning: Option<ProvisioningReadiness>) -> Self {
        let passed = checks.iter().filter(|c| c.critical).all(|c| c.passed);
        Self {
            ready: passed,
            passed,
            checks,
            provisioning,
            operator_guidance: operator_guidance(),
            verification_script: VERIFICATION_SCRIPT_PATH,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct RetryReadiness {
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    jitter_enabled: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ProvisioningReadiness {
    base_url: String,
    auth_mode: &'static str,
    request_timeout_ms: u64,
    retry: RetryReadiness,
    network_ok: bool,
    network_message: String,
    credentials_configured: bool,
    authenticated_identity_probe: &'static str,
    risky_mutations: Vec<&'static str>,
    supported_hosts: Vec<&'static str>,
    tenant_app_boundary: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OperatorGuidance {
    prerequisites: Vec<&'static str>,
    dedicated_environment: &'static str,
    redaction_rules: Vec<&'static str>,
    limitations: Vec<&'static str>,
    common_remediation: Vec<RemediationHint>,
    rerun_commands: Vec<&'static str>,
    artifact_root_hint: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RemediationHint {
    code: &'static str,
    symptom: &'static str,
    action: &'static str,
}

fn auth_mode_label(config: &FeishuConfig) -> &'static str {
    if config.app_id.trim().is_empty() || config.app_secret.trim().is_empty() {
        "unconfigured"
    } else {
        FEISHU_AUTH_MODEL
    }
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use a disposable Feishu/Lark tenant app or a localhost mock server before running readiness verification.",
            "Grant the tenant app the scopes needed for the message, chat, directory, docs, sheets, and calendar surfaces you plan to exercise.",
            "Configure exactly one app_id/app_secret pair per connector instance and keep base_url on the CN or global production host unless the verification bundle is pointed at localhost.",
        ],
        dedicated_environment: "Prefer a sandbox tenant or a localhost fixture. feishu.messages.send and feishu.messages.reply are live side effects and should not target production chats during verification.",
        redaction_rules: vec![
            "Never print app_secret, tenant access tokens, Authorization headers, or copied auth-endpoint payloads.",
            "Treat app_id, message IDs, chat IDs, user IDs, document IDs, spreadsheet tokens, calendar IDs, and raw content bodies as sensitive tenant metadata.",
            "If verification captures live Feishu/Lark responses, redact message content, display names, email addresses, and tenant-specific URLs before sharing artifacts.",
        ],
        limitations: vec![
            "This first slice is tenant-app bound and does not impersonate arbitrary users or cross tenant boundaries.",
            "Webhook ingestion, websocket event delivery, Drive search/export/write, and calendar mutations remain explicit non-goals.",
            "Known-token reads are supported for docs, sheets, and calendar events, but this connector does not discover or enumerate those resources globally.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "not_configured",
                symptom: "health or self_check reports that the connector is not configured",
                action: "Configure app_id, app_secret, request_timeout_ms, retry policy, and an allowed base_url, then rerun self_check.",
            },
            RemediationHint {
                code: "network_constraints_invalid",
                symptom: "doctor or self_check reports that base_url violates the Feishu/Lark host policy",
                action: "Use https://open.feishu.cn or https://open.larksuite.com for live verification, or an explicit localhost / 127.0.0.1 override for deterministic tests.",
            },
            RemediationHint {
                code: "feishu_auth_rejected",
                symptom: "the tenant-access-token probe returns 401 or 403",
                action: "Rotate the tenant app secret, confirm the app_id/app_secret pair is valid for the target tenant, and rerun the verification bundle.",
            },
            RemediationHint {
                code: "self_check_retryable",
                symptom: "self_check reports rate limiting, transport timeouts, or transient 5xx errors from Feishu/Lark",
                action: "Respect the upstream retry window or increase request_timeout_ms and retry settings before rerunning verification.",
            },
        ],
        rerun_commands: VERIFY_COMMANDS.to_vec(),
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

fn contract_details(config: Option<&FeishuConfig>) -> serde_json::Value {
    json!({
        "implementation": {
            "api": "feishu_open_platform",
            "status": FEISHU_IMPLEMENTATION_STATUS,
            "notes": [
                "The connector is bound to one installed tenant app and uses the tenant access token internal auth endpoint.",
                "Read operations cover messages, chats, users, known docs, known spreadsheets, and known calendar event lists.",
            ],
        },
        "auth_boundary": {
            "binding": FEISHU_BINDING_MODEL,
            "token_type": FEISHU_AUTH_MODEL,
            "credential_mode": config.map(auth_mode_label).unwrap_or("unconfigured"),
            "base_url": config.map(|cfg| cfg.base_url.clone()),
            "cross_tenant_supported": false,
            "user_impersonation_supported": false,
            "webhook_receiver_included": false,
            "websocket_events_included": false,
        },
        "service_inventory": {
            "messages": [OP_MESSAGES_SEND, OP_MESSAGES_REPLY, OP_MESSAGES_GET],
            "chats": [OP_CHATS_LIST, OP_CHATS_GET],
            "directory": [OP_USERS_GET],
            "docs": [OP_DOCS_GET, OP_SHEETS_GET],
            "calendar": [OP_CALENDAR_EVENTS],
            "health": [OP_HEALTH],
        },
        "non_goals": [
            "Webhook ingestion and websocket event delivery",
            "Cross-tenant brokering or arbitrary user impersonation",
            "Drive search, export, folder traversal, and write operations",
            "Calendar mutation or subscription setup"
        ]
    })
}

/// Feishu connector state.
#[derive(Debug)]
pub struct FeishuConnector {
    base: BaseConnector,
    config: Option<FeishuConfig>,
    client: Option<FeishuClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl FeishuConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.feishu")),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            started_at: Instant::now(),
            verifier: None,
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    fn provisioning_readiness(&self) -> Option<ProvisioningReadiness> {
        self.config.as_ref().map(|config| {
            let (network_ok, network_message) = base_url_diagnostic(&config.base_url);
            ProvisioningReadiness {
                base_url: config.base_url.clone(),
                auth_mode: auth_mode_label(config),
                request_timeout_ms: config.request_timeout_ms,
                retry: RetryReadiness {
                    max_retries: config.retry.max_retries,
                    initial_delay_ms: config.retry.initial_delay_ms,
                    max_delay_ms: config.retry.max_delay_ms,
                    jitter_enabled: config.retry.jitter_enabled,
                },
                network_ok,
                network_message,
                credentials_configured: !config.app_id.trim().is_empty()
                    && !config.app_secret.trim().is_empty(),
                authenticated_identity_probe: "POST /open-apis/auth/v3/tenant_access_token/internal",
                risky_mutations: vec![OP_MESSAGES_SEND, OP_MESSAGES_REPLY],
                supported_hosts: vec![FEISHU_CN_HOST, FEISHU_GLOBAL_HOST],
                tenant_app_boundary: FEISHU_TENANT_APP_BOUNDARY,
            }
        })
    }

    fn diagnostic_details(&self, live_probe: Option<serde_json::Value>) -> serde_json::Value {
        json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "runtime_initialized": self.runtime.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
            "auth_mode": self.config.as_ref().map(auth_mode_label),
            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
            "base_url_validation": self.config.as_ref().map(|config| {
                match parse_base_url(&config.base_url) {
                    Ok(url) => json!({
                        "host": url.host_str(),
                        "scheme": url.scheme(),
                        "local_test_host": url.host_str().is_some_and(is_local_test_host),
                    }),
                    Err(err) => json!({
                        "valid": false,
                        "error": err.to_string(),
                    }),
                }
            }),
            "request_timeout_ms": self.config.as_ref().map(|config| config.request_timeout_ms),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": self.provisioning_readiness(),
            "operator_guidance": operator_guidance(),
            "contract": contract_details(self.config.as_ref()),
            "live_probe": live_probe,
        })
    }

    fn attach_self_check_details(
        &self,
        mut report: SelfCheckReport,
        live_probe: Option<serde_json::Value>,
    ) -> SelfCheckReport {
        report.details = Some(self.diagnostic_details(live_probe));
        report
    }

    /// Run connector diagnostics.
    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();
        let provisioning = self.provisioning_readiness();

        let configured = self.config.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: configured,
            message: Some(if configured {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });

        let client_ok = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: client_ok,
            message: Some(if client_ok {
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            critical: true,
        });

        let runtime_ok = self.runtime.is_some();
        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: runtime_ok,
            message: Some(if runtime_ok {
                "ConnectorRuntime initialized".into()
            } else {
                "Runtime missing".into()
            }),
            critical: true,
        });

        if let Some(readiness) = &provisioning {
            checks.push(DoctorCheck {
                name: "endpoint_policy".into(),
                passed: readiness.network_ok,
                message: Some(readiness.network_message.clone()),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                passed: true,
                message: Some(format!("Auth mode: {}", readiness.auth_mode)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "secret_material".into(),
                passed: readiness.credentials_configured,
                message: Some(if readiness.credentials_configured {
                    "Concrete tenant app credentials configured".into()
                } else {
                    "App ID or secret missing".into()
                }),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "tenant_boundary".into(),
                passed: true,
                message: Some(readiness.tenant_app_boundary.into()),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks, provisioning)
    }
}

impl Default for FeishuConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn feishu_auth_caps() -> AuthCaps {
    AuthCaps {
        methods: vec![
            "app_id_secret".to_string(),
            "tenant_access_token_internal".to_string(),
        ],
        oauth: None,
    }
}

fn feishu_resource_types() -> Vec<ResourceTypeInfo> {
    vec![
        ResourceTypeInfo {
            name: "feishu.message".into(),
            uri_pattern: "feishu://messages/{message_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["message_id"],
                "properties": {
                    "message_id": { "type": "string" },
                    "chat_id": { "type": "string" },
                    "msg_type": { "type": "string" },
                    "body": { "type": "object" }
                }
            }),
        },
        ResourceTypeInfo {
            name: "feishu.chat".into(),
            uri_pattern: "feishu://chats/{chat_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["chat_id"],
                "properties": {
                    "chat_id": { "type": "string" },
                    "name": { "type": "string" },
                    "description": { "type": "string" }
                }
            }),
        },
        ResourceTypeInfo {
            name: "feishu.user".into(),
            uri_pattern: "feishu://users/{user_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "name": { "type": "string" },
                    "email": { "type": "string" }
                }
            }),
        },
        ResourceTypeInfo {
            name: "feishu.document".into(),
            uri_pattern: "feishu://docs/{document_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["document_id"],
                "properties": {
                    "document_id": { "type": "string" },
                    "document": { "type": "object" },
                    "body": { "type": "object" }
                }
            }),
        },
        ResourceTypeInfo {
            name: "feishu.spreadsheet".into(),
            uri_pattern: "feishu://sheets/{spreadsheet_token}".into(),
            schema: json!({
                "type": "object",
                "required": ["spreadsheet_token"],
                "properties": {
                    "spreadsheet_token": { "type": "string" },
                    "title": { "type": "string" },
                    "sheets": { "type": "array" }
                }
            }),
        },
        ResourceTypeInfo {
            name: "feishu.calendar_event".into(),
            uri_pattern: "feishu://calendars/{calendar_id}/events/{event_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["calendar_id", "event_id"],
                "properties": {
                    "calendar_id": { "type": "string" },
                    "event_id": { "type": "string" },
                    "summary": { "type": "string" },
                    "start_time": { "type": "string" },
                    "end_time": { "type": "string" }
                }
            }),
        },
    ]
}

/// Build the typed operations catalog.
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_MESSAGES_SEND),
            summary: "Send a message via Feishu".into(),
            description: Some(
                "Sends a bot-authored message through the installed tenant app to one visible user or chat; custom webhook bots, user impersonation, and cross-tenant fan-out are out of scope for this first slice.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["receive_id", "msg_type", "content"],
                "properties": {
                    "receive_id": { "type": "string", "description": "Receiver ID (user open_id or chat_id)" },
                    "receive_id_type": { "type": "string", "description": "Type: open_id, user_id, union_id, email, chat_id", "default": "open_id" },
                    "msg_type": { "type": "string", "description": "Message type: text, post, image, interactive, etc." },
                    "content": { "type": "string", "description": "JSON-encoded message content" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "message_id": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MSG_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to send a message to a Feishu user or group chat"
                    .into(),
                common_mistakes: vec![
                    "Content must be JSON-encoded string matching msg_type schema".into(),
                    "receive_id_type defaults to open_id if not specified".into(),
                    FEISHU_TENANT_APP_BOUNDARY.into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_MESSAGES_REPLY)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MESSAGES_REPLY),
            summary: "Reply to a Feishu message".into(),
            description: Some(
                "Replies to an existing message visible to the installed tenant app; this does not provide general thread syncing or inbound event delivery.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["message_id", "msg_type", "content"],
                "properties": {
                    "message_id": { "type": "string", "description": "Message ID to reply to" },
                    "msg_type": { "type": "string", "description": "Message type" },
                    "content": { "type": "string", "description": "JSON-encoded message content" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "message_id": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MSG_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When replying to an existing message in a thread".into(),
                common_mistakes: vec![
                    "message_id must be valid and accessible".into(),
                    FEISHU_TENANT_APP_BOUNDARY.into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_MESSAGES_SEND)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MESSAGES_GET),
            summary: "Get a Feishu message by ID".into(),
            description: Some(
                "Retrieves one message visible to the installed tenant app. Webhook and websocket delivery surfaces remain explicit non-goals in this first slice.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["message_id"],
                "properties": {
                    "message_id": { "type": "string", "description": "Message ID to retrieve" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "message_id": { "type": "string" },
                    "msg_type": { "type": "string" },
                    "body": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MSG_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to read the content of a specific message".into(),
                common_mistakes: vec![
                    "This first slice only reads messages already visible to the installed app."
                        .into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CHATS_LIST),
            summary: "List Feishu chats".into(),
            description: Some(
                "Lists chats visible to the installed tenant app with pagination. Direct-message discovery and global workspace search beyond bot visibility are out of scope.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "page_token": { "type": "string", "description": "Pagination token" },
                    "page_size": { "type": "integer", "description": "Page size (max 200)", "default": 20 }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "items": { "type": "array" },
                    "page_token": { "type": "string" },
                    "has_more": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static(CAP_CHATS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to list all chats the bot has access to".into(),
                common_mistakes: vec![
                    "Use page_token from response for subsequent pages".into(),
                    "The result set is limited to chats visible to the installed app.".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_CHATS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CHATS_GET),
            summary: "Get Feishu chat details".into(),
            description: Some(
                "Retrieves metadata for one chat visible to the installed tenant app.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["chat_id"],
                "properties": {
                    "chat_id": { "type": "string", "description": "Chat ID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "chat_id": { "type": "string" },
                    "name": { "type": "string" },
                    "description": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_CHATS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need details about a specific chat".into(),
                common_mistakes: vec![
                    "chat_id must refer to a conversation visible to the installed app.".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_CHATS_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_USERS_GET),
            summary: "Get Feishu user info".into(),
            description: Some(
                "Retrieves directory information for one tenant user identifier. Cross-tenant lookup, admin writes, and provisioning flows are out of scope.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string", "description": "User ID" },
                    "user_id_type": { "type": "string", "description": "Type: open_id, user_id, union_id", "default": "open_id" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "user_id": { "type": "string" },
                    "name": { "type": "string" },
                    "email": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_USERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to look up user information".into(),
                common_mistakes: vec![
                    "user_id_type must match the format of user_id provided".into(),
                    FEISHU_TENANT_APP_BOUNDARY.into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_DOCS_GET),
            summary: "Get Feishu document content".into(),
            description: Some(
                "Retrieves the raw content of one known Feishu docx document. Drive search, export, folder traversal, and writes are explicit non-goals for this first slice.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["document_id"],
                "properties": {
                    "document_id": { "type": "string", "description": "Document ID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "document": { "type": "object" },
                    "body": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_DOCS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to read a Feishu document's content".into(),
                common_mistakes: vec![
                    "This operation expects a known docx document token; it does not search Drive."
                        .into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_SHEETS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SHEETS_GET),
            summary: "Get Feishu spreadsheet info".into(),
            description: Some(
                "Retrieves spreadsheet metadata and sheet inventory for one known token. Cell mutation, formula writes, and bulk export remain out of scope.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["spreadsheet_token"],
                "properties": {
                    "spreadsheet_token": { "type": "string", "description": "Spreadsheet token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "spreadsheet_token": { "type": "string" },
                    "title": { "type": "string" },
                    "sheets": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static(CAP_DOCS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to read a Feishu spreadsheet's structure and data"
                    .into(),
                common_mistakes: vec![
                    "This first slice returns spreadsheet metadata and sheet inventory, not write handles."
                        .into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_DOCS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CALENDAR_EVENTS),
            summary: "List Feishu calendar events".into(),
            description: Some(
                "Lists events from one known calendar within the bound tenant app. Calendar mutations and push subscriptions are explicit non-goals for this first slice.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["calendar_id"],
                "properties": {
                    "calendar_id": { "type": "string", "description": "Calendar ID" },
                    "page_token": { "type": "string", "description": "Pagination token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "items": { "type": "array" },
                    "page_token": { "type": "string" },
                    "has_more": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static(CAP_CALENDAR_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to list events from a Feishu calendar".into(),
                common_mistakes: vec![
                    "calendar_id is required, not the same as user_id".into(),
                    "Event subscriptions are not part of this first implementation.".into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Feishu API health check".into(),
            description: Some(
                "Verifies that the configured app_id/app_secret can reach the internal tenant access token endpoint on the Feishu CN or Lark global API host.".into(),
            ),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_USERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When checking if the Feishu API connection is healthy".into(),
                common_mistakes: vec![
                    "Health proves host reachability and credential validity, not every optional product scope.".into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

#[async_trait]
impl FcpConnector for FeishuConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: FeishuConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Feishu config: {e}"),
            })?;
        validate_config(&config)?;

        self.retry_config = config.retry.clone();
        let request_timeout = Duration::from_millis(config.request_timeout_ms);
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
        ));

        let client = FeishuClient::new(
            &config.base_url,
            &config.app_id,
            &config.app_secret,
            config.retry.clone(),
            request_timeout,
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create Feishu client: {e}"),
        })?;

        // Attempt to obtain a tenant access token on configure
        if let Ok(token) = client.obtain_tenant_access_token().await {
            tracing::info!(
                "Feishu tenant access token obtained (length={})",
                token.len()
            );
        } else {
            tracing::warn!(
                "Failed to obtain Feishu tenant access token; will retry on first request"
            );
        }

        self.client = Some(client);
        self.config = Some(config);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: Some(feishu_auth_caps()),
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let provisioning = self.provisioning_readiness();
        let ready = self.config.is_some()
            && self.client.is_some()
            && self.runtime.is_some()
            && provisioning
                .as_ref()
                .is_none_or(|readiness| readiness.network_ok && readiness.credentials_configured);
        let mut snapshot = if ready {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot.details = Some(self.diagnostic_details(None));
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let provisioning = self.provisioning_readiness();
        let Some(client) = &self.client else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                None,
            ));
        };

        if let Some(readiness) = &provisioning {
            if !readiness.network_ok {
                return Ok(self.attach_self_check_details(
                    SelfCheckReport::failed(
                        "network_constraints_invalid",
                        readiness.network_message.clone(),
                    ),
                    None,
                ));
            }
            if !readiness.credentials_configured {
                return Ok(self.attach_self_check_details(
                    SelfCheckReport::degraded(
                        "missing_credentials",
                        "App ID or secret not configured",
                    ),
                    None,
                ));
            }
        }

        match client.health_check().await {
            Ok(()) => Ok(self.attach_self_check_details(
                SelfCheckReport::ok(),
                Some(json!({
                    "endpoint": "POST /open-apis/auth/v3/tenant_access_token/internal",
                    "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
                    "status": "ok",
                })),
            )),
            Err(err) => {
                if err.is_retryable() {
                    Ok(self.attach_self_check_details(
                        SelfCheckReport::degraded("self_check_retryable", err.to_string()),
                        Some(json!({
                            "endpoint": "POST /open-apis/auth/v3/tenant_access_token/internal",
                            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
                            "status": "retryable_error",
                            "retryable": true,
                            "retry_after_ms": err.retry_after().map(|duration| duration.as_millis() as u64),
                            "error": err.to_string(),
                        })),
                    ))
                } else {
                    let reason_code = if matches!(
                        err,
                        crate::error::FeishuError::Unauthorized(_)
                            | crate::error::FeishuError::HttpStatus {
                                status: 401 | 403,
                                ..
                            }
                    ) {
                        "feishu_auth_rejected"
                    } else {
                        "self_check_failed"
                    };
                    Ok(self.attach_self_check_details(
                        SelfCheckReport::failed(reason_code, err.to_string()),
                        Some(json!({
                            "endpoint": "POST /open-apis/auth/v3/tenant_access_token/internal",
                            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
                            "status": "error",
                            "retryable": false,
                            "error": err.to_string(),
                        })),
                    ))
                }
            }
        }
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        Ok(SimulateResponse::allowed(req.id))
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: Vec::new(),
            resource_types: feishu_resource_types(),
            auth_caps: Some(feishu_auth_caps()),
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(req).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

impl FeishuConnector {
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap = match operation {
            OP_MESSAGES_SEND | OP_MESSAGES_REPLY => CapabilityId::from_static(CAP_MSG_WRITE),
            OP_MESSAGES_GET => CapabilityId::from_static(CAP_MSG_READ),
            OP_CHATS_LIST | OP_CHATS_GET => CapabilityId::from_static(CAP_CHATS_READ),
            OP_USERS_GET | OP_HEALTH => CapabilityId::from_static(CAP_USERS_READ),
            OP_DOCS_GET | OP_SHEETS_GET => CapabilityId::from_static(CAP_DOCS_READ),
            OP_CALENDAR_EVENTS => CapabilityId::from_static(CAP_CALENDAR_READ),
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        verifier.verify(req.capability_token, &required_cap, &req.operation, &[])?;

        let runtime = self.runtime.as_ref().ok_or(FcpError::Internal {
            message: "Connector runtime missing after configure".into(),
        })?;
        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "Feishu client missing after configure".into(),
        })?;

        let output = match operation {
            OP_MESSAGES_SEND => {
                let receive_id = req.input.get("receive_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'receive_id' field".into(),
                    },
                )?;
                let msg_type = req.input.get("msg_type").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'msg_type' field".into(),
                    },
                )?;
                let content = req.input.get("content").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'content' field".into(),
                    },
                )?;
                let receive_id_type = req
                    .input
                    .get("receive_id_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("open_id");
                let receive_id_type = validate_receive_id_type(receive_id_type)?;

                let send_req = SendMessageRequest {
                    receive_id: receive_id.into(),
                    msg_type: msg_type.into(),
                    content: content.into(),
                };
                let resp = client
                    .send_message(runtime, receive_id_type, &send_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_MESSAGES_REPLY => {
                let message_id = req.input.get("message_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'message_id' field".into(),
                    },
                )?;
                let msg_type = req.input.get("msg_type").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'msg_type' field".into(),
                    },
                )?;
                let content = req.input.get("content").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'content' field".into(),
                    },
                )?;

                let reply_req = ReplyMessageRequest {
                    msg_type: msg_type.into(),
                    content: content.into(),
                };
                let resp = client
                    .reply_message(runtime, message_id, &reply_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_MESSAGES_GET => {
                let message_id = req.input.get("message_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'message_id' field".into(),
                    },
                )?;
                let resp = client
                    .get_message(runtime, message_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_CHATS_LIST => {
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let page_size = req
                    .input
                    .get("page_size")
                    .and_then(|v| v.as_u64())
                    .map(validate_chats_page_size)
                    .transpose()?;
                let resp = client
                    .list_chats(runtime, page_token, page_size)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_CHATS_GET => {
                let chat_id = req.input.get("chat_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'chat_id' field".into(),
                    },
                )?;
                let resp = client
                    .get_chat(runtime, chat_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_USERS_GET => {
                let user_id = req.input.get("user_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'user_id' field".into(),
                    },
                )?;
                let user_id_type = req
                    .input
                    .get("user_id_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("open_id");
                let user_id_type = validate_user_id_type(user_id_type)?;
                let resp = client
                    .get_user(runtime, user_id, user_id_type)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_DOCS_GET => {
                let document_id = req
                    .input
                    .get("document_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'document_id' field".into(),
                    })?;
                let resp = client
                    .get_document(runtime, document_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_SHEETS_GET => {
                let spreadsheet_token = req
                    .input
                    .get("spreadsheet_token")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'spreadsheet_token' field".into(),
                    })?;
                let resp = client
                    .get_spreadsheet(runtime, spreadsheet_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_CALENDAR_EVENTS => {
                let calendar_id = req
                    .input
                    .get("calendar_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'calendar_id' field".into(),
                    })?;
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_calendar_events(runtime, calendar_id, page_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_HEALTH => {
                client.health_check().await.map_err(|e| e.to_fcp_error())?;
                json!({ "status": "healthy" })
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        Ok(InvokeResponse::ok(req.id, output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_MSG_WRITE),
                CapabilityId::from_static(CAP_MSG_READ),
                CapabilityId::from_static(CAP_CHATS_READ),
                CapabilityId::from_static(CAP_USERS_READ),
                CapabilityId::from_static(CAP_DOCS_READ),
                CapabilityId::from_static(CAP_CALENDAR_READ),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn base_invoke(connector_id: &ConnectorId, operation: &'static str) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_1"),
            connector_id: connector_id.clone(),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = FeishuConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = FeishuConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_accepts_localhost_http_for_tests() {
        let mut connector = FeishuConnector::new();
        let result = connector
            .configure(json!({
                "base_url": "http://127.0.0.1:9",
                "app_id": "cli_test",
                "app_secret": "secret"
            }))
            .await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_zero_timeout() {
        let mut connector = FeishuConnector::new();
        let result = connector
            .configure(json!({
                "app_id": "cli_test",
                "app_secret": "secret",
                "request_timeout_ms": 0
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_base_url_path() {
        let mut connector = FeishuConnector::new();
        let result = connector
            .configure(json!({
                "base_url": "https://open.feishu.cn/open-apis",
                "app_id": "cli_test",
                "app_secret": "secret"
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = FeishuConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = FeishuConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = FeishuConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = FeishuConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_MESSAGES_SEND),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = FeishuConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 10);
        let op_ids: Vec<&str> = intro.operations.iter().map(|op| op.id.as_str()).collect();
        assert!(op_ids.contains(&OP_MESSAGES_SEND));
        assert!(op_ids.contains(&OP_MESSAGES_REPLY));
        assert!(op_ids.contains(&OP_MESSAGES_GET));
        assert!(op_ids.contains(&OP_CHATS_LIST));
        assert!(op_ids.contains(&OP_CHATS_GET));
        assert!(op_ids.contains(&OP_USERS_GET));
        assert!(op_ids.contains(&OP_DOCS_GET));
        assert!(op_ids.contains(&OP_SHEETS_GET));
        assert!(op_ids.contains(&OP_CALENDAR_EVENTS));
        assert!(op_ids.contains(&OP_HEALTH));
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 10);
    }

    #[test]
    fn test_introspection_advertises_tenant_app_auth() {
        let intro = FeishuConnector::new().introspect();
        let auth = intro.auth_caps.expect("auth caps");
        assert!(auth.methods.contains(&"app_id_secret".to_string()));
        assert!(
            auth.methods
                .contains(&"tenant_access_token_internal".to_string())
        );
        assert!(auth.oauth.is_none());
    }

    #[test]
    fn test_introspection_exposes_first_slice_resource_inventory() {
        let intro = FeishuConnector::new().introspect();
        let names: Vec<&str> = intro
            .resource_types
            .iter()
            .map(|ty| ty.name.as_str())
            .collect();
        assert!(names.contains(&"feishu.message"));
        assert!(names.contains(&"feishu.chat"));
        assert!(names.contains(&"feishu.user"));
        assert!(names.contains(&"feishu.document"));
        assert!(names.contains(&"feishu.spreadsheet"));
        assert!(names.contains(&"feishu.calendar_event"));
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_messages_send_is_risky() {
        let ops = operations_info();
        let send = ops
            .iter()
            .find(|op| op.id.as_str() == OP_MESSAGES_SEND)
            .unwrap();
        assert_eq!(send.safety_tier, SafetyTier::Risky);
        assert_eq!(send.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_messages_get_is_safe() {
        let ops = operations_info();
        let get = ops
            .iter()
            .find(|op| op.id.as_str() == OP_MESSAGES_GET)
            .unwrap();
        assert_eq!(get.safety_tier, SafetyTier::Safe);
    }

    #[test]
    fn test_health_op_is_safe_and_strict() {
        let ops = operations_info();
        let health = ops.iter().find(|op| op.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(health.safety_tier, SafetyTier::Safe);
        assert_eq!(health.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = FeishuConnector::manifest_hash();
        let hash2 = FeishuConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = FeishuConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
        assert!(intro.events.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let connector = FeishuConnector::new();
        // Can't test with full configure (needs network), just verify unconfigured case
        let req = base_invoke(connector.id(), "feishu.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err()); // Not configured
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = FeishuConnector::new();
        let req = base_invoke(connector.id(), OP_MESSAGES_SEND);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_default_impl() {
        let connector = FeishuConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.feishu");
    }

    #[test]
    fn test_config_debug_redacts_secret() {
        let config = FeishuConfig {
            base_url: "https://open.feishu.cn".into(),
            app_id: "cli_test".into(),
            app_secret: "secret_value_here".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: 30_000,
        };
        let debug_output = format!("{config:?}");
        assert!(!debug_output.contains("secret_value_here"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn test_chats_list_capability() {
        let ops = operations_info();
        let cl = ops
            .iter()
            .find(|op| op.id.as_str() == OP_CHATS_LIST)
            .unwrap();
        assert_eq!(cl.capability, CapabilityId::from_static(CAP_CHATS_READ));
    }

    #[test]
    fn test_docs_get_capability() {
        let ops = operations_info();
        let dg = ops.iter().find(|op| op.id.as_str() == OP_DOCS_GET).unwrap();
        assert_eq!(dg.capability, CapabilityId::from_static(CAP_DOCS_READ));
    }

    #[test]
    fn test_sheets_get_capability() {
        let ops = operations_info();
        let sg = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SHEETS_GET)
            .unwrap();
        assert_eq!(sg.capability, CapabilityId::from_static(CAP_DOCS_READ));
    }

    #[test]
    fn test_calendar_events_capability() {
        let ops = operations_info();
        let ce = ops
            .iter()
            .find(|op| op.id.as_str() == OP_CALENDAR_EVENTS)
            .unwrap();
        assert_eq!(ce.capability, CapabilityId::from_static(CAP_CALENDAR_READ));
    }

    #[test]
    fn test_users_get_capability() {
        let ops = operations_info();
        let ug = ops
            .iter()
            .find(|op| op.id.as_str() == OP_USERS_GET)
            .unwrap();
        assert_eq!(ug.capability, CapabilityId::from_static(CAP_USERS_READ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_grants_capabilities() {
        let mut connector = FeishuConnector::new();
        let result = connector.handshake(base_handshake()).await.unwrap();
        assert_eq!(result.capabilities_granted.len(), 6);
        assert!(result.auth_caps.is_some());
    }

    #[test]
    fn test_messages_reply_is_risky() {
        let ops = operations_info();
        let reply = ops
            .iter()
            .find(|op| op.id.as_str() == OP_MESSAGES_REPLY)
            .unwrap();
        assert_eq!(reply.safety_tier, SafetyTier::Risky);
        assert_eq!(reply.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_no_dangerous_operations() {
        // Feishu connector has no dangerous operations (no delete endpoints)
        let ops = operations_info();
        assert!(ops.iter().all(|op| op.safety_tier != SafetyTier::Dangerous));
    }

    #[test]
    fn test_all_safe_operations_are_low_risk() {
        let ops = operations_info();
        for op in &ops {
            if op.safety_tier == SafetyTier::Safe {
                assert_eq!(
                    op.risk_level,
                    RiskLevel::Low,
                    "Op {} should be low risk",
                    op.id.as_str()
                );
            }
        }
    }

    #[test]
    fn test_all_risky_operations_are_medium_risk() {
        let ops = operations_info();
        for op in &ops {
            if op.safety_tier == SafetyTier::Risky {
                assert_eq!(
                    op.risk_level,
                    RiskLevel::Medium,
                    "Op {} should be medium risk",
                    op.id.as_str()
                );
            }
        }
    }

    #[test]
    fn test_read_operations_are_strictly_idempotent() {
        let ops = operations_info();
        for operation_id in [
            OP_MESSAGES_GET,
            OP_CHATS_LIST,
            OP_CHATS_GET,
            OP_USERS_GET,
            OP_DOCS_GET,
            OP_SHEETS_GET,
            OP_CALENDAR_EVENTS,
            OP_HEALTH,
        ] {
            let op = ops
                .iter()
                .find(|candidate| candidate.id.as_str() == operation_id)
                .unwrap();
            assert_eq!(
                op.idempotency,
                IdempotencyClass::Strict,
                "operation {} should be strictly idempotent",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn test_doctor_accepts_larksuite_global_host() {
        let mut connector = FeishuConnector::new();
        connector.config = Some(FeishuConfig {
            base_url: "https://open.larksuite.com".into(),
            app_id: "app_id".into(),
            app_secret: "app_secret".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: default_request_timeout_ms(),
        });
        connector.client = Some(
            FeishuClient::new(
                "https://open.larksuite.com",
                "app_id",
                "app_secret",
                HttpRetryConfig::default(),
                Duration::from_millis(default_request_timeout_ms()),
            )
            .expect("client"),
        );
        connector.runtime = Some(ConnectorRuntime::new(ConnectorRuntimeConfig::default()));
        let report = connector.doctor();
        let host_check = report
            .checks
            .iter()
            .find(|check| check.name == "endpoint_policy")
            .expect("endpoint_policy check");
        assert!(host_check.passed);
    }

    #[test]
    fn test_validate_receive_id_type_rejects_unknown_value() {
        assert!(validate_receive_id_type("tenant_key").is_err());
    }

    #[test]
    fn test_validate_user_id_type_rejects_unknown_value() {
        assert!(validate_user_id_type("email").is_err());
    }

    #[test]
    fn test_validate_chats_page_size_bounds() {
        assert!(validate_chats_page_size(0).is_err());
        assert!(validate_chats_page_size(201).is_err());
        assert_eq!(validate_chats_page_size(200).unwrap(), 200);
    }
}
