//! `WeCom` enterprise messaging connector.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::time::Instant;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, EventData, EventEnvelope, FcpError, FcpResult,
    HandshakeRequest, HandshakeResponse, HealthSnapshot, HealthState, IdempotencyClass, InstanceId,
    Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo, OrderingPolicy,
    Principal, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest,
    SimulateResponse, SubscribeRequest, SubscribeResponse, TrustLevel, UnsubscribeRequest,
};
use fcp_sdk::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::client::WeComClient;
use crate::types::{
    WeComCallbackEnvelope, WeComCallbackIngestRequest, WeComCallbackVerifyRequest, WeComConfig,
    WeComDepartmentListRequest, WeComMediaDownloadRequest, WeComMediaUploadRequest,
    WeComMessageKind, WeComMessageRequest, WeComStateModel, WeComUserLookupRequest,
    base_url_diagnostic,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_SEND_TEXT: &str = "wecom.messages.send_text";
const OP_SEND_MARKDOWN: &str = "wecom.messages.send_markdown";
const OP_SEND_IMAGE: &str = "wecom.messages.send_image";
const OP_SEND_FILE: &str = "wecom.messages.send_file";
const OP_UPLOAD_MEDIA: &str = "wecom.media.upload";
const OP_DOWNLOAD_MEDIA: &str = "wecom.media.download";
const OP_GET_USER: &str = "wecom.users.get";
const OP_LIST_DEPARTMENTS: &str = "wecom.departments.list";
const OP_VERIFY_CALLBACK_URL: &str = "wecom.callback.verify_url";
const OP_INGEST_CALLBACK_EVENT: &str = "wecom.callback.ingest_event";
const OP_HEALTH: &str = "wecom.health";

const CAP_MESSAGES_WRITE: &str = "wecom.messages.write";
const CAP_MEDIA_WRITE: &str = "wecom.media.write";
const CAP_MEDIA_READ: &str = "wecom.media.read";
const CAP_USERS_READ: &str = "wecom.users.read";
const CAP_DEPARTMENTS_READ: &str = "wecom.departments.read";
const CAP_EVENTS_READ: &str = "wecom.events.read";
const CAP_HEALTH_READ: &str = "wecom.health.read";

const WECOM_IMPLEMENTATION_STATUS: &str = "first_slice";
const WECOM_BINDING_MODEL: &str = "single_enterprise_app";
const WECOM_AUTH_MODEL: &str = "corp_id_agent_secret";
const WECOM_TENANT_APP_BOUNDARY: &str = "This connector acts as one installed WeCom enterprise app for one tenant; it does not impersonate arbitrary users or cross tenant boundaries.";
const WECOM_CALLBACK_DELIVERY_MODEL: &str = "host_forwarded_http_callback";
const WECOM_TOKEN_PROBE: &str = "GET /cgi-bin/gettoken";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/wecom_connector/<timestamp>";
const VERIFY_COMMANDS: [&str; 5] = [
    "rch exec -- cargo fmt --manifest-path connectors/wecom/Cargo.toml --check",
    "rch exec -- cargo check --manifest-path connectors/wecom/Cargo.toml --all-targets",
    "rch exec -- cargo test --manifest-path connectors/wecom/Cargo.toml --lib",
    "rch exec -- cargo clippy --manifest-path connectors/wecom/Cargo.toml -p fcp-wecom --all-targets --no-deps -- -D warnings",
    "git diff --check -- connectors/wecom/src/{client,connector,error,types}.rs connectors/wecom/{manifest.toml,README.md}",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct WeComConversation {
    kind: &'static str,
    id: String,
    stream_key: String,
    resource_uri: String,
}

#[derive(Debug)]
struct WeComState {
    client: WeComClient,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    ready: bool,
    passed: bool,
    checks: Vec<DoctorCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning: Option<ProvisioningReadiness>,
    operator_guidance: OperatorGuidance,
}

#[derive(Debug, Clone, serde::Serialize)]
struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>, provisioning: Option<ProvisioningReadiness>) -> Self {
        let passed = checks
            .iter()
            .filter(|check| check.critical)
            .all(|check| check.passed);
        Self {
            ready: passed,
            passed,
            checks,
            provisioning,
            operator_guidance: operator_guidance(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct ProvisioningReadiness {
    base_url: String,
    request_timeout_ms: u64,
    network_ok: bool,
    network_message: String,
    callback_configured: bool,
    callback_receive_id_mode: &'static str,
    token_issuance_probe: &'static str,
    inbound_delivery_model: &'static str,
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

fn auth_mode_label(config: Option<&WeComConfig>) -> &'static str {
    config.map_or("unconfigured", |_| WECOM_AUTH_MODEL)
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use a sandbox WeCom tenant or a localhost fixture before running readiness verification against live credentials.",
            "Provision exactly one enterprise app per connector instance and load corp_id, agent_id, and agent_secret before invoking health or self_check.",
            "If inbound callbacks are required, configure callback_token plus callback_encoding_aes_key and ensure the host owns the public HTTPS endpoint that forwards GET/POST payloads into this connector.",
        ],
        dedicated_environment: "Prefer a disposable tenant or localhost harness. Message sends, media upload, and callback validation all involve live tenant-side effects or shared tenant secrets.",
        redaction_rules: vec![
            "Never log agent_secret, access tokens, callback_token, callback_encoding_aes_key, Authorization headers, or decrypted callback challenge material.",
            "Treat corp_id, agent_id, receive IDs, user IDs, party IDs, tag IDs, media IDs, and callback plaintext XML as sensitive tenant metadata.",
            "If verification captures live callback payloads, redact message content, display names, attachment metadata, and tenant-specific identifiers before sharing artifacts.",
        ],
        limitations: vec![
            "This first slice is bound to one WeCom enterprise app and does not impersonate arbitrary users or cross tenant boundaries.",
            "The connector does not host its own webhook or websocket listener; the Flywheel host must receive and forward signed HTTP callback traffic.",
            "Voice, video, news, template-card, task-card, recall flows, conversation history readback, and tenant-admin provisioning remain explicit non-goals.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "not_configured",
                symptom: "doctor or self_check reports that the connector is not configured",
                action: "Provide corp_id, agent_id, agent_secret, request_timeout_ms, and an allowed base_url, then rerun self_check.",
            },
            RemediationHint {
                code: "network_constraints_invalid",
                symptom: "doctor reports that base_url violates the WeCom host allowlist",
                action: "Use https://qyapi.weixin.qq.com for live verification, or localhost / 127.0.0.1 only for deterministic tests.",
            },
            RemediationHint {
                code: "callback_not_configured",
                symptom: "doctor reports that callback verification secrets are missing",
                action: "Configure callback_token plus callback_encoding_aes_key before routing host-forwarded callback GET/POST traffic into verify_url or ingest_event.",
            },
            RemediationHint {
                code: "self_check_retryable",
                symptom: "self_check reports timeouts, transient transport failures, or temporary WeCom API errors",
                action: "Respect the upstream retry window, confirm outbound reachability to qyapi.weixin.qq.com:443, and rerun self_check after the transient condition clears.",
            },
            RemediationHint {
                code: "self_check_failed",
                symptom: "self_check reports a non-retryable credential or API failure",
                action: "Rotate the app secret if needed, confirm the corp_id/agent_id/app secret belong to the same tenant app, and rerun self_check.",
            },
        ],
        rerun_commands: VERIFY_COMMANDS.to_vec(),
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

fn contract_details(config: Option<&WeComConfig>) -> Value {
    json!({
        "implementation": {
            "api": "wecom_enterprise_api",
            "status": WECOM_IMPLEMENTATION_STATUS,
            "notes": [
                "The connector is bound to one installed enterprise app and verifies outbound reachability by issuing access tokens.",
                "Inbound events use host-forwarded signed and encrypted HTTP callbacks; the connector verifies, decrypts, and normalizes payloads but does not own the public listener."
            ],
        },
        "auth_boundary": {
            "binding": WECOM_BINDING_MODEL,
            "credential_mode": auth_mode_label(config),
            "base_url": config.map(|cfg| cfg.base_url().to_string()),
            "callback_configured": config.map(WeComConfig::callback_configured),
            "callback_receive_id_mode": config.map(WeComConfig::callback_receive_id_mode),
            "cross_tenant_supported": false,
            "user_impersonation_supported": false,
            "callback_hosting_included": false,
            "websocket_events_included": false,
        },
        "service_inventory": {
            "messages": [OP_SEND_TEXT, OP_SEND_MARKDOWN, OP_SEND_IMAGE, OP_SEND_FILE],
            "media": [OP_UPLOAD_MEDIA, OP_DOWNLOAD_MEDIA],
            "directory": [OP_GET_USER, OP_LIST_DEPARTMENTS],
            "events": [OP_VERIFY_CALLBACK_URL, OP_INGEST_CALLBACK_EVENT],
            "health": [OP_HEALTH],
        },
        "non_goals": [
            "Webhook hosting or websocket event loops inside the connector",
            "Cross-tenant brokering or arbitrary user impersonation",
            "Conversation history readback, receipts, or durable chat-state indexing",
            "Voice, video, news, template-card, task-card, and recall message families",
            "Tenant-admin provisioning or enterprise policy management"
        ]
    })
}

#[derive(Debug)]
pub struct WeComConnector {
    base: BaseConnector,
    state: Option<WeComState>,
    verifier: Option<CapabilityVerifier>,
    started_at: Instant,
}

impl WeComConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.wecom")),
            state: None,
            verifier: None,
            started_at: Instant::now(),
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    fn provisioning_readiness(&self) -> Option<ProvisioningReadiness> {
        self.state.as_ref().map(|state| {
            let config = state.client.config();
            let (network_ok, network_message) = base_url_diagnostic(config.base_url());
            ProvisioningReadiness {
                base_url: config.base_url().to_string(),
                request_timeout_ms: config.request_timeout_ms(),
                network_ok,
                network_message,
                callback_configured: config.callback_configured(),
                callback_receive_id_mode: config.callback_receive_id_mode(),
                token_issuance_probe: WECOM_TOKEN_PROBE,
                inbound_delivery_model: WECOM_CALLBACK_DELIVERY_MODEL,
                risky_mutations: vec![
                    OP_SEND_TEXT,
                    OP_SEND_MARKDOWN,
                    OP_SEND_IMAGE,
                    OP_SEND_FILE,
                    OP_UPLOAD_MEDIA,
                ],
                supported_hosts: vec!["qyapi.weixin.qq.com", "localhost", "127.0.0.1"],
                tenant_app_boundary: WECOM_TENANT_APP_BOUNDARY,
            }
        })
    }

    fn health_details(&self, model: &WeComStateModel) -> Value {
        json!({
            "base_url": &model.base_url,
            "agent_id": model.agent_id,
            "token_cached": model.token_cached,
            "callback_configured": model.callback_configured,
            "configured": self.state.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
            "inbound_delivery_model": WECOM_CALLBACK_DELIVERY_MODEL,
            "state": model,
        })
    }

    fn diagnostic_details(
        &self,
        model: Option<&WeComStateModel>,
        live_probe: Option<&Value>,
    ) -> Value {
        json!({
            "configured": self.state.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
            "auth_mode": auth_mode_label(self.state.as_ref().map(|state| state.client.config())),
            "state": model,
            "provisioning": self.provisioning_readiness(),
            "operator_guidance": operator_guidance(),
            "contract": contract_details(self.state.as_ref().map(|state| state.client.config())),
            "live_probe": live_probe,
        })
    }

    fn attach_self_check_details(
        &self,
        mut report: SelfCheckReport,
        model: Option<&WeComStateModel>,
        live_probe: Option<&Value>,
    ) -> SelfCheckReport {
        report.details = Some(self.diagnostic_details(model, live_probe));
        report
    }

    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();
        let provisioning = self.provisioning_readiness();

        let configured = self.state.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: configured,
            message: Some(self.state.as_ref().map_or_else(
                || {
                    "Not configured - provide corp_id, agent_id, agent_secret, and an allowed base_url."
                        .into()
                },
                |state| {
                    let config = state.client.config();
                    format!(
                        "Configuration loaded for agent_id {} against {}.",
                        config.agent_id(),
                        config.base_url()
                    )
                },
            )),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: configured,
            message: Some(if configured {
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "endpoint_policy".into(),
            passed: provisioning
                .as_ref()
                .is_some_and(|readiness| readiness.network_ok),
            message: Some(provisioning.as_ref().map_or_else(
                || "Endpoint policy cannot be evaluated until configure runs".into(),
                |readiness| readiness.network_message.clone(),
            )),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "callback_crypto".into(),
            passed: provisioning
                .as_ref()
                .is_some_and(|readiness| readiness.callback_configured),
            message: Some(provisioning.as_ref().map_or_else(
                || "Callback verification secrets are unavailable until configure runs".into(),
                |readiness| {
                    if readiness.callback_configured {
                        "Callback token + AES key configured; host-forwarded verify_url and ingest_event are ready for live use.".into()
                    } else {
                        "Callback token + AES key not configured; outbound flows work, but verify_url and ingest_event are not ready for live traffic.".into()
                    }
                },
            )),
            critical: false,
        });

        checks.push(DoctorCheck {
            name: "tenant_boundary".into(),
            passed: true,
            message: Some(WECOM_TENANT_APP_BOUNDARY.into()),
            critical: false,
        });

        checks.push(DoctorCheck {
            name: "host_delivery_model".into(),
            passed: true,
            message: Some(
                "The host must receive the public HTTPS callback GET/POST and forward those payloads into wecom.callback.verify_url or wecom.callback.ingest_event."
                    .into(),
            ),
            critical: false,
        });

        checks.push(DoctorCheck {
            name: "capability_handshake".into(),
            passed: self.base.handshaken.load(Ordering::Acquire),
            message: Some(if self.base.handshaken.load(Ordering::Acquire) {
                "Capability handshake completed".into()
            } else {
                "Capability handshake has not been completed yet".into()
            }),
            critical: false,
        });

        checks.push(DoctorCheck {
            name: "first_slice_inventory".into(),
            passed: true,
            message: Some(
                "Supported today: outbound text/markdown/image/file sends, temporary media upload/download, one user lookup, department list, and host-forwarded callback verification plus event normalization."
                    .into(),
            ),
            critical: false,
        });

        DoctorResult::from_checks(checks, provisioning)
    }

    #[allow(clippy::too_many_lines)]
    fn operations() -> Vec<OperationInfo> {
        vec![
            operation(
                OP_SEND_TEXT,
                "Send a WeCom text message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["content"],
                    "properties": {
                        "content": { "type": "string" },
                        "touser": { "type": "string" },
                        "toparty": { "type": "string" },
                        "totag": { "type": "string" },
                        "safe": { "type": "boolean" },
                        "enable_duplicate_check": { "type": "boolean" },
                        "duplicate_check_interval": { "type": "integer", "minimum": 0 }
                    }
                }),
                "Use when a work-zone automation must proactively deliver plain text into WeCom.",
            ),
            operation(
                OP_SEND_MARKDOWN,
                "Send a WeCom markdown message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["content"],
                    "properties": {
                        "content": { "type": "string" },
                        "touser": { "type": "string" },
                        "toparty": { "type": "string" },
                        "totag": { "type": "string" },
                        "enable_duplicate_check": { "type": "boolean" },
                        "duplicate_check_interval": { "type": "integer", "minimum": 0 }
                    }
                }),
                "Use when the destination accepts WeCom markdown rendering and rich formatting matters.",
            ),
            operation(
                OP_SEND_IMAGE,
                "Send a WeCom image message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["media_id"],
                    "properties": {
                        "media_id": { "type": "string" },
                        "touser": { "type": "string" },
                        "toparty": { "type": "string" },
                        "totag": { "type": "string" },
                        "safe": { "type": "boolean" },
                        "enable_duplicate_check": { "type": "boolean" },
                        "duplicate_check_interval": { "type": "integer", "minimum": 0 }
                    }
                }),
                "Use after `wecom.media.upload` when you need to send one uploaded image by its temporary WeCom `media_id`.",
            ),
            operation(
                OP_SEND_FILE,
                "Send a WeCom file message",
                CAP_MESSAGES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["media_id"],
                    "properties": {
                        "media_id": { "type": "string" },
                        "touser": { "type": "string" },
                        "toparty": { "type": "string" },
                        "totag": { "type": "string" },
                        "safe": { "type": "boolean" },
                        "enable_duplicate_check": { "type": "boolean" },
                        "duplicate_check_interval": { "type": "integer", "minimum": 0 }
                    }
                }),
                "Use after `wecom.media.upload` when you need to send one uploaded file by its temporary WeCom `media_id`.",
            ),
            operation(
                OP_UPLOAD_MEDIA,
                "Upload temporary media to WeCom",
                CAP_MEDIA_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::BestEffort,
                json!({
                    "type": "object",
                    "required": ["media_type", "file_name", "content_base64"],
                    "properties": {
                        "media_type": { "type": "string", "enum": ["image", "voice", "video", "file"] },
                        "file_name": { "type": "string" },
                        "mime_type": { "type": "string" },
                        "content_base64": { "type": "string" }
                    }
                }),
                "Use before sending media messages that require a temporary WeCom media_id.",
            ),
            operation(
                OP_DOWNLOAD_MEDIA,
                "Download media bytes for a WeCom media_id",
                CAP_MEDIA_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({
                    "type": "object",
                    "required": ["media_id"],
                    "properties": {
                        "media_id": { "type": "string" }
                    }
                }),
                "Use after inbound callback normalization when a MediaId or ThumbMediaId must be resolved into bytes.",
            ),
            operation(
                OP_GET_USER,
                "Fetch a WeCom user profile",
                CAP_USERS_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({
                    "type": "object",
                    "required": ["userid"],
                    "properties": {
                        "userid": { "type": "string" }
                    }
                }),
                "Use for directory lookups when you already know the WeCom userid.",
            ),
            operation(
                OP_LIST_DEPARTMENTS,
                "List WeCom departments",
                CAP_DEPARTMENTS_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({
                    "type": "object",
                    "properties": {
                        "id": { "type": "integer" }
                    }
                }),
                "Use for read-only org hierarchy discovery inside the bound tenant.",
            ),
            operation(
                OP_VERIFY_CALLBACK_URL,
                "Verify a host-forwarded WeCom callback URL challenge",
                CAP_EVENTS_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({
                    "type": "object",
                    "required": ["msg_signature", "timestamp", "nonce", "echostr"],
                    "properties": {
                        "msg_signature": { "type": "string" },
                        "timestamp": { "type": "string" },
                        "nonce": { "type": "string" },
                        "echostr": { "type": "string" }
                    }
                }),
                "Use when the host receives WeCom's initial callback URL validation GET and needs the decrypted plaintext challenge.",
            ),
            operation(
                OP_INGEST_CALLBACK_EVENT,
                "Verify, decrypt, and normalize one host-forwarded WeCom callback event",
                CAP_EVENTS_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({
                    "type": "object",
                    "required": ["msg_signature", "timestamp", "nonce", "body"],
                    "properties": {
                        "msg_signature": { "type": "string" },
                        "timestamp": { "type": "string" },
                        "nonce": { "type": "string" },
                        "body": { "type": "string", "description": "Raw XML body from the WeCom HTTP POST callback" },
                        "body_xml": { "type": "string", "description": "Alias for body when the host already labels the payload as XML" }
                    }
                }),
                "Use when the host forwards a signed WeCom callback POST and needs a normalized EventEnvelope plus attachment references.",
            ),
            operation(
                OP_HEALTH,
                "Verify WeCom credentials and token issuance",
                CAP_HEALTH_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({ "type": "object" }),
                "Use before invoking mutations when you need a bounded credential and connectivity check.",
            ),
        ]
    }

    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let state = self.state.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let capability = required_capability(req.operation.as_str())?;
        let _bound =
            verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])?;

        let (output, resource_uris) = match req.operation.as_str() {
            OP_SEND_TEXT => {
                let request = WeComMessageRequest::from_value(&req.input, WeComMessageKind::Text)?;
                let output = state
                    .client
                    .send_message(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                (output, Vec::new())
            }
            OP_SEND_MARKDOWN => {
                let request =
                    WeComMessageRequest::from_value(&req.input, WeComMessageKind::Markdown)?;
                let output = state
                    .client
                    .send_message(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                (output, Vec::new())
            }
            OP_SEND_IMAGE => {
                let request = WeComMessageRequest::from_value(&req.input, WeComMessageKind::Image)?;
                let output = state
                    .client
                    .send_message(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                (output, Vec::new())
            }
            OP_SEND_FILE => {
                let request = WeComMessageRequest::from_value(&req.input, WeComMessageKind::File)?;
                let output = state
                    .client
                    .send_message(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                (output, Vec::new())
            }
            OP_UPLOAD_MEDIA => {
                let request = WeComMediaUploadRequest::from_value(&req.input)?;
                let output = state
                    .client
                    .upload_media(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                (output, Vec::new())
            }
            OP_DOWNLOAD_MEDIA => {
                let request = WeComMediaDownloadRequest::from_value(&req.input)?;
                let output = state
                    .client
                    .download_media(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                let resource_uris = vec![format!("wecom:media:{}", output.media_id)];
                let output = serde_json::to_value(&output).map_err(|error| FcpError::Internal {
                    message: format!("failed to serialize WeCom media download response: {error}"),
                })?;
                (output, resource_uris)
            }
            OP_GET_USER => {
                let request = WeComUserLookupRequest::from_value(&req.input)?;
                let output = state
                    .client
                    .get_user(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                (output, Vec::new())
            }
            OP_LIST_DEPARTMENTS => {
                let request = WeComDepartmentListRequest::from_value(&req.input)?;
                let output = state
                    .client
                    .list_departments(&request)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                (output, Vec::new())
            }
            OP_VERIFY_CALLBACK_URL => {
                let request = WeComCallbackVerifyRequest::from_value(&req.input)?;
                let challenge = state
                    .client
                    .verify_callback_url(&request)
                    .map_err(|error| error.to_fcp_error())?;
                (
                    json!({
                        "verified": true,
                        "transport": "callback_http_get",
                        "receive_id": state.client.config().callback_receive_id(),
                        "challenge": &challenge,
                        "http_response": {
                            "status": 200,
                            "content_type": "text/plain; charset=utf-8",
                            "body": &challenge,
                        }
                    }),
                    Vec::new(),
                )
            }
            OP_INGEST_CALLBACK_EVENT => {
                let request = WeComCallbackIngestRequest::from_value(&req.input)?;
                let callback = state
                    .client
                    .ingest_callback_event(&request)
                    .map_err(|error| error.to_fcp_error())?;
                let event = normalize_callback_event(
                    &callback,
                    verifier,
                    &self.base.id,
                    &self.base.instance_id,
                    state.client.config().agent_id(),
                );
                let resource_uris = event.data.resource_uris.clone();
                let output = json!({
                    "delivery": {
                        "id": callback_delivery_id(&callback),
                        "transport": "callback_http",
                        "verified": true,
                        "msg_signature": request.msg_signature(),
                        "timestamp": request.timestamp(),
                        "nonce": request.nonce(),
                        "receive_id": &callback.receive_id,
                    },
                    "callback": {
                        "outer": &callback.wrapper,
                        "message": &callback.message,
                        "plaintext_xml": &callback.plaintext_xml,
                    },
                    "event": &event,
                });
                (output, resource_uris)
            }
            OP_HEALTH => {
                state
                    .client
                    .access_token()
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                let model = state.client.state_model().await;
                let output = json!({
                    "status": "ok",
                    "token_issuance_probe": WECOM_TOKEN_PROBE,
                    "details": self.health_details(&model),
                });
                (output, Vec::new())
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("unknown operation: {}", req.operation),
                });
            }
        };

        let mut response = InvokeResponse::ok(req.id, output);
        response.resource_uris = resource_uris;
        Ok(response)
    }
}

impl Default for WeComConnector {
    fn default() -> Self {
        Self::new()
    }
}

fcp_core::impl_fcp_sealed!(WeComConnector);

#[async_trait]
impl FcpConnector for WeComConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: Value) -> FcpResult<()> {
        let config = WeComConfig::from_value(config)?;
        let client = WeComClient::new(config).map_err(|error| error.to_fcp_error())?;
        self.state = Some(WeComState { client });
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        self.verifier = None;
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        if let Some(requested_instance_id) = req.requested_instance_id.clone() {
            self.base.instance_id = requested_instance_id;
        }
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: granted_capabilities(req.capabilities_requested),
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let (status, details) = if let Some(state) = self.state.as_ref() {
            let token_probe = state.client.access_token().await;
            let model = state.client.state_model().await;
            let status = match token_probe {
                Ok(_) => HealthState::Ready,
                Err(error) => HealthState::Degraded {
                    reason: format!("token probe failed: {error}"),
                },
            };
            (status, Some(self.health_details(&model)))
        } else {
            (HealthState::Starting, None)
        };
        HealthSnapshot {
            status,
            uptime_ms: u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            load: None,
            details,
            rate_limit: None,
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(state) = self.state.as_ref() else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::failed(
                    "not_configured",
                    "configure must be called before WeCom self_check",
                ),
                None,
                None,
            ));
        };
        match state.client.access_token().await {
            Ok(_) => {
                let model = state.client.state_model().await;
                let live_probe = json!({
                    "reachable": true,
                    "retryable": false,
                    "token_issuance_probe": WECOM_TOKEN_PROBE,
                    "inbound_delivery_model": WECOM_CALLBACK_DELIVERY_MODEL,
                    "callback_ready": model.callback_configured,
                });
                Ok(self.attach_self_check_details(
                    SelfCheckReport::ok(),
                    Some(&model),
                    Some(&live_probe),
                ))
            }
            Err(error) => {
                let report = if error.is_retryable() {
                    SelfCheckReport::degraded("self_check_retryable", error.to_string())
                } else {
                    SelfCheckReport::failed("self_check_failed", error.to_string())
                };
                let live_probe = json!({
                    "reachable": false,
                    "retryable": error.is_retryable(),
                    "token_issuance_probe": WECOM_TOKEN_PROBE,
                });
                Ok(self.attach_self_check_details(report, None, Some(&live_probe)))
            }
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        self.state = None;
        self.verifier = None;
        self.base.set_handshaken(false);
        self.base.set_configured(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: Self::operations(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
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

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let capability = match required_capability(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return Ok(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };
        if self.state.is_none() {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            ));
        }
        let Some(verifier) = self.verifier.as_ref() else {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            ));
        };
        if let Err(error) =
            verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])
        {
            let mut response =
                SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            if error.error_code() == "FCP-3001" {
                response =
                    response.with_missing_capabilities(vec![capability.as_str().to_string()]);
            }
            return Ok(response);
        }
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

fn normalize_callback_event(
    callback: &WeComCallbackEnvelope,
    verifier: &CapabilityVerifier,
    connector_id: &ConnectorId,
    instance_id: &InstanceId,
    fallback_agent_id: u64,
) -> EventEnvelope {
    let agent_id = callback_agent_id(callback, fallback_agent_id);
    let conversation = callback_conversation(&callback.message, &agent_id);
    let attachments = callback_attachments(&callback.message);
    let delivery_id = callback_delivery_id(callback);
    let resource_uris = callback_resource_uris(
        callback,
        conversation.as_ref(),
        attachments.as_slice(),
        &agent_id,
    );
    let create_time = callback_create_time(&callback.message);
    let topic = callback_topic(&callback.message);
    let principal = callback_principal(&callback.message, &callback.receive_id);
    let cursor = delivery_id.clone();

    let payload = json!({
        "transport": "callback_http",
        "delivery_id": &delivery_id,
        "receive_id": callback.receive_id,
        "agent_id": agent_id,
        "msg_type": xml_field(&callback.message, "MsgType"),
        "event_type": xml_field(&callback.message, "Event"),
        "change_type": xml_field(&callback.message, "ChangeType"),
        "conversation": conversation.as_ref().map(|conversation| {
            json!({
                "kind": conversation.kind,
                "id": conversation.id,
                "resource_uri": conversation.resource_uri,
            })
        }),
        "attachments": attachments,
        "outer": &callback.wrapper,
        "message": &callback.message,
        "plaintext_xml": &callback.plaintext_xml,
    });

    let event_data = EventData::new(
        connector_id.clone(),
        instance_id.clone(),
        verifier.zone_id.clone(),
        principal,
        payload,
    )
    .with_resource_uris(resource_uris);

    let (seq, ordering) = callback_sequence(&delivery_id, create_time, conversation.is_some());
    let mut event = EventEnvelope::new(topic, event_data)
        .with_seq(seq)
        .with_cursor(cursor)
        .with_ordering(ordering);
    if let Some(conversation) = conversation {
        event = event.with_stream_key(conversation.stream_key);
    }
    if let Some(timestamp) = create_time {
        event.timestamp = timestamp;
    }
    event
}

fn callback_agent_id(callback: &WeComCallbackEnvelope, fallback_agent_id: u64) -> String {
    xml_field(&callback.message, "AgentID")
        .or_else(|| xml_field(&callback.wrapper, "AgentID"))
        .map_or_else(|| fallback_agent_id.to_string(), ToString::to_string)
}

fn callback_topic(message: &BTreeMap<String, String>) -> String {
    let msg_type =
        xml_field(message, "MsgType").map_or_else(|| "unknown".to_string(), topic_component);
    if msg_type == "event" {
        let event_type =
            xml_field(message, "Event").map_or_else(|| "unknown".to_string(), topic_component);
        xml_field(message, "ChangeType")
            .map(topic_component)
            .map_or_else(
                || format!("wecom.event.{event_type}"),
                |change_type| format!("wecom.event.{event_type}.{change_type}"),
            )
    } else {
        format!("wecom.message.{msg_type}")
    }
}

fn callback_principal(message: &BTreeMap<String, String>, receive_id: &str) -> Principal {
    if let Some(external_user_id) = xml_field(message, "ExternalUserID") {
        return Principal {
            kind: "external_user".into(),
            id: external_user_id.to_string(),
            trust: TrustLevel::Paired,
            display: Some(external_user_id.to_string()),
        };
    }
    if let Some(user_id) =
        xml_field(message, "FromUserName").or_else(|| xml_field(message, "UserID"))
    {
        return Principal {
            kind: "user".into(),
            id: user_id.to_string(),
            trust: TrustLevel::Paired,
            display: Some(user_id.to_string()),
        };
    }

    Principal {
        kind: "service".into(),
        id: format!("wecom:{receive_id}"),
        trust: TrustLevel::Paired,
        display: Some("WeCom callback".into()),
    }
}

fn callback_conversation(
    message: &BTreeMap<String, String>,
    agent_id: &str,
) -> Option<WeComConversation> {
    if xml_field(message, "MsgType").is_some_and(|msg_type| msg_type.eq_ignore_ascii_case("event"))
    {
        return None;
    }

    if let Some(chat_id) = xml_field(message, "OpenChatId").or_else(|| xml_field(message, "ChatId"))
    {
        let chat_id = chat_id.to_string();
        return Some(WeComConversation {
            kind: "room",
            stream_key: format!("agent:{agent_id}:chat:{chat_id}"),
            resource_uri: format!("wecom:chat:{chat_id}"),
            id: chat_id,
        });
    }

    if let Some(external_user_id) = xml_field(message, "ExternalUserID") {
        let external_user_id = external_user_id.to_string();
        return Some(WeComConversation {
            kind: "dm",
            stream_key: format!("agent:{agent_id}:external:{external_user_id}"),
            resource_uri: format!("wecom:external_user:{external_user_id}"),
            id: external_user_id,
        });
    }

    xml_field(message, "FromUserName")
        .or_else(|| xml_field(message, "UserID"))
        .map(|user_id| {
            let user_id = user_id.to_string();
            WeComConversation {
                kind: "dm",
                stream_key: format!("agent:{agent_id}:dm:{user_id}"),
                resource_uri: format!("wecom:user:{user_id}"),
                id: user_id,
            }
        })
}

fn callback_attachments(message: &BTreeMap<String, String>) -> Vec<Value> {
    let mut attachments = Vec::new();

    if let Some(media_id) = xml_field(message, "MediaId") {
        let mut attachment = json!({
            "kind": "media_id",
            "field": "MediaId",
            "media_id": media_id,
            "media_type": inferred_media_type(message),
            "download_operation": OP_DOWNLOAD_MEDIA,
        });
        if let Some(file_name) = xml_field(message, "FileName") {
            attachment["file_name"] = json!(file_name);
        }
        attachments.push(attachment);
    }

    if let Some(thumb_media_id) = xml_field(message, "ThumbMediaId") {
        attachments.push(json!({
            "kind": "media_id",
            "field": "ThumbMediaId",
            "media_id": thumb_media_id,
            "media_type": "thumbnail",
            "download_operation": OP_DOWNLOAD_MEDIA,
        }));
    }

    if let Some(pic_url) = xml_field(message, "PicUrl") {
        attachments.push(json!({
            "kind": "url",
            "field": "PicUrl",
            "url": pic_url,
            "media_type": "image",
        }));
    }

    if let Some(url) = xml_field(message, "Url") {
        attachments.push(json!({
            "kind": "url",
            "field": "Url",
            "url": url,
        }));
    }

    attachments
}

fn inferred_media_type(message: &BTreeMap<String, String>) -> &'static str {
    match xml_field(message, "MsgType")
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("image") => "image",
        Some("voice") => "voice",
        Some("video") => "video",
        Some("file") => "file",
        _ => "binary",
    }
}

fn callback_resource_uris(
    callback: &WeComCallbackEnvelope,
    conversation: Option<&WeComConversation>,
    attachments: &[Value],
    agent_id: &str,
) -> Vec<String> {
    let mut resource_uris = Vec::new();
    push_unique(
        &mut resource_uris,
        format!("wecom:tenant:{}", callback.receive_id),
    );
    push_unique(&mut resource_uris, format!("wecom:agent:{agent_id}"));

    if let Some(message_id) = xml_field(&callback.message, "MsgId") {
        push_unique(&mut resource_uris, format!("wecom:message:{message_id}"));
    }
    if let Some(conversation) = conversation {
        push_unique(&mut resource_uris, conversation.resource_uri.clone());
    }
    if let Some(user_id) = xml_field(&callback.message, "FromUserName")
        .or_else(|| xml_field(&callback.message, "UserID"))
    {
        push_unique(&mut resource_uris, format!("wecom:user:{user_id}"));
    }
    if let Some(external_user_id) = xml_field(&callback.message, "ExternalUserID") {
        push_unique(
            &mut resource_uris,
            format!("wecom:external_user:{external_user_id}"),
        );
    }

    for attachment in attachments {
        if let Some(media_id) = attachment.get("media_id").and_then(Value::as_str) {
            push_unique(&mut resource_uris, format!("wecom:media:{media_id}"));
        }
    }

    resource_uris
}

fn callback_delivery_id(callback: &WeComCallbackEnvelope) -> String {
    let mut hasher = Sha256::new();
    hasher.update(callback.receive_id.as_bytes());
    hasher.update([0]);
    if let Some(encrypt) = callback.wrapper.get("Encrypt") {
        hasher.update(encrypt.as_bytes());
        hasher.update([0]);
    }
    hasher.update(callback.plaintext_xml.as_bytes());
    hex::encode(hasher.finalize())
}

fn callback_sequence(
    delivery_id: &str,
    create_time: Option<DateTime<Utc>>,
    has_stream_key: bool,
) -> (u64, OrderingPolicy) {
    let digest = Sha256::digest(delivery_id.as_bytes());
    let hash_u64 = u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);

    if has_stream_key && let Some(create_time) = create_time {
        let suffix = hash_u64 % 10_000;
        let timestamp = u64::try_from(create_time.timestamp().max(0)).unwrap_or(0);
        let seq = timestamp * 10_000 + suffix;
        return (seq, OrderingPolicy::PerKey);
    }

    (hash_u64, OrderingPolicy::Unordered)
}

fn callback_create_time(message: &BTreeMap<String, String>) -> Option<DateTime<Utc>> {
    xml_field(message, "CreateTime")
        .and_then(|value| value.parse::<i64>().ok())
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
}

fn topic_component(raw: &str) -> String {
    let mut result = String::new();
    let mut last_was_separator = false;
    for ch in raw.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            result.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            result.push('_');
            last_was_separator = true;
        }
    }
    let normalized = result.trim_matches('_');
    if normalized.is_empty() {
        "unknown".to_string()
    } else {
        normalized.to_string()
    }
}

fn xml_field<'a>(fields: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    fields
        .get(name)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn push_unique(values: &mut Vec<String>, candidate: String) {
    if !values.iter().any(|existing| existing == &candidate) {
        values.push(candidate);
    }
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_SEND_TEXT | OP_SEND_MARKDOWN | OP_SEND_IMAGE | OP_SEND_FILE => CAP_MESSAGES_WRITE,
        OP_UPLOAD_MEDIA => CAP_MEDIA_WRITE,
        OP_DOWNLOAD_MEDIA => CAP_MEDIA_READ,
        OP_GET_USER => CAP_USERS_READ,
        OP_LIST_DEPARTMENTS => CAP_DEPARTMENTS_READ,
        OP_VERIFY_CALLBACK_URL | OP_INGEST_CALLBACK_EVENT => CAP_EVENTS_READ,
        OP_HEALTH => CAP_HEALTH_READ,
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("unknown operation: {operation}"),
            });
        }
    };
    Ok(CapabilityId::from_static(capability))
}

fn granted_capabilities(requested: Vec<CapabilityId>) -> Vec<CapabilityGrant> {
    requested
        .into_iter()
        .filter(|capability| {
            matches!(
                capability.as_str(),
                CAP_MESSAGES_WRITE
                    | CAP_MEDIA_WRITE
                    | CAP_MEDIA_READ
                    | CAP_USERS_READ
                    | CAP_DEPARTMENTS_READ
                    | CAP_EVENTS_READ
                    | CAP_HEALTH_READ
            )
        })
        .map(|capability| CapabilityGrant {
            capability,
            operation: None,
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn operation(
    id: &'static str,
    summary: &str,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    input_schema: Value,
    when_to_use: &str,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        description: Some(summary.into()),
        input_schema,
        output_schema: json!({ "type": "object" }),
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints: AgentHint {
            when_to_use: when_to_use.into(),
            common_mistakes: vec![
                "For send operations, WeCom requires at least one of touser, toparty, or totag."
                    .into(),
            ],
            examples: Vec::new(),
            related: vec![CapabilityId::from_static(CAP_HEALTH_READ)],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::{CapabilityConstraints, CapabilityToken, OrderingPolicy, RequestId, ZoneId};
    use serde_json::Value;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;
    use crate::types::DEFAULT_TIMEOUT_MS;

    fn handshake_request(
        host_public_key: [u8; 32],
        requested_instance_id: Option<InstanceId>,
    ) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key,
            nonce: [19_u8; 32],
            capabilities_requested: vec![CapabilityId::from_static(CAP_HEALTH_READ)],
            host: None,
            transport_caps: None,
            requested_instance_id,
        }
    }

    fn test_constraints_cbor() -> Vec<u8> {
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        cbor
    }

    fn capability_token(
        signing_key: &Ed25519SigningKey,
        capability: &'static str,
        operation: &'static str,
        instance_id: &InstanceId,
    ) -> CapabilityToken {
        let now = Utc::now();
        let raw = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("test constraints cbor should be valid")
            .target_instance(instance_id.as_str())
            .sign(signing_key)
            .expect("token should sign");
        CapabilityToken::from_raw(raw)
    }

    fn sample_callback_key() -> String {
        BASE64.encode([7_u8; 32]).trim_end_matches('=').to_string()
    }

    #[fcp_async_core::runtime::test]
    async fn health_performs_token_probe_and_reports_cached_state() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/cgi-bin/gettoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errcode": 0,
                "errmsg": "ok",
                "access_token": "token-123",
                "expires_in": 7200
            })))
            .mount(&server)
            .await;

        let mut connector = WeComConnector::new();
        connector
            .configure(json!({
                "base_url": server.uri(),
                "corp_id": "corp",
                "agent_id": 1_000_002_u64,
                "agent_secret": "secret",
                "request_timeout_ms": DEFAULT_TIMEOUT_MS
            }))
            .await
            .expect("configure should succeed");

        let health_before = connector.health().await;
        assert!(matches!(health_before.status, HealthState::Ready));
        assert_eq!(
            health_before
                .details
                .as_ref()
                .and_then(|details| details.get("token_cached"))
                .and_then(Value::as_bool),
            Some(true)
        );

        let report = connector
            .self_check()
            .await
            .expect("self_check should return");
        assert_eq!(
            report.status,
            fcp_core::SelfCheckStatus::Ok,
            "self_check should populate the token cache"
        );
        assert_eq!(
            report
                .details
                .as_ref()
                .and_then(|details| details.get("live_probe"))
                .and_then(|probe| probe.get("token_issuance_probe"))
                .and_then(Value::as_str),
            Some(WECOM_TOKEN_PROBE)
        );
        assert!(
            report
                .details
                .as_ref()
                .and_then(|details| details.get("operator_guidance"))
                .is_some(),
            "self_check should attach operator guidance details"
        );

        let health_after = connector.health().await;
        assert!(matches!(health_after.status, HealthState::Ready));
        assert_eq!(
            health_after
                .details
                .as_ref()
                .and_then(|details| details.get("token_cached"))
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn health_degrades_when_token_probe_fails() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/cgi-bin/gettoken"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "errcode": 40013,
                "errmsg": "invalid corpid"
            })))
            .mount(&server)
            .await;

        let mut connector = WeComConnector::new();
        connector
            .configure(json!({
                "base_url": server.uri(),
                "corp_id": "corp",
                "agent_id": 1_000_002_u64,
                "agent_secret": "wrong-secret",
                "request_timeout_ms": DEFAULT_TIMEOUT_MS
            }))
            .await
            .expect("configure should succeed");

        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
        assert_eq!(
            health
                .details
                .as_ref()
                .and_then(|details| details.get("token_cached"))
                .and_then(Value::as_bool),
            Some(false)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_health_returns_status_and_state() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/cgi-bin/gettoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "errcode": 0,
                "errmsg": "ok",
                "access_token": "token-123",
                "expires_in": 7200
            })))
            .mount(&server)
            .await;

        let mut connector = WeComConnector::new();
        connector
            .configure(json!({
                "base_url": server.uri(),
                "corp_id": "corp",
                "agent_id": 1_000_002_u64,
                "agent_secret": "secret",
                "request_timeout_ms": DEFAULT_TIMEOUT_MS
            }))
            .await
            .expect("configure should succeed");
        let signing_key = Ed25519SigningKey::generate();
        let requested_instance_id = InstanceId::new();
        connector
            .handshake(handshake_request(
                signing_key.verifying_key().to_bytes(),
                Some(requested_instance_id.clone()),
            ))
            .await
            .expect("handshake should succeed");

        let response = connector
            .invoke(InvokeRequest {
                r#type: "invoke".into(),
                id: RequestId::new("wecom-health"),
                connector_id: ConnectorId::from_static("fcp.wecom"),
                operation: OperationId::from_static(OP_HEALTH),
                zone_id: ZoneId::work(),
                input: json!({}),
                capability_token: capability_token(
                    &signing_key,
                    CAP_HEALTH_READ,
                    OP_HEALTH,
                    &requested_instance_id,
                ),
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            })
            .await
            .expect("health invoke should succeed");

        assert_eq!(response.result.as_ref().expect("result")["status"], "ok");
        assert_eq!(
            response.result.as_ref().expect("result")["details"]["token_cached"],
            json!(true)
        );
        assert_eq!(
            response.result.as_ref().expect("result")["details"]["manifest_hash"],
            json!(WeComConnector::manifest_hash())
        );
    }

    #[test]
    fn doctor_requires_configuration() {
        let report = WeComConnector::new().doctor();

        assert!(!report.ready);
        assert!(
            report
                .checks
                .iter()
                .find(|check| check.name == "configuration")
                .is_some_and(|check| !check.passed && check.critical),
            "doctor should fail the critical configuration check when unconfigured"
        );
        assert!(
            report
                .operator_guidance
                .rerun_commands
                .iter()
                .any(|command| command.contains("cargo clippy")),
            "doctor guidance should include rerun commands"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn doctor_reports_callback_readiness_and_localhost_override() {
        let server = MockServer::start().await;
        let mut connector = WeComConnector::new();
        connector
            .configure(json!({
                "base_url": server.uri(),
                "corp_id": "corp",
                "agent_id": 1_000_002_u64,
                "agent_secret": "secret",
                "request_timeout_ms": DEFAULT_TIMEOUT_MS,
                "callback_token": "token-123",
                "callback_encoding_aes_key": sample_callback_key(),
                "callback_receive_id": "rx-tenant"
            }))
            .await
            .expect("configure should succeed");

        let report = connector.doctor();

        assert!(report.ready, "configured doctor report should be ready");
        assert!(
            report
                .checks
                .iter()
                .find(|check| check.name == "endpoint_policy")
                .and_then(|check| check.message.as_deref())
                .is_some_and(|message| message.contains("localhost")),
            "doctor should explain the localhost test override"
        );
        assert!(
            report
                .checks
                .iter()
                .find(|check| check.name == "callback_crypto")
                .is_some_and(|check| check.passed),
            "doctor should report callback verification readiness when secrets are configured"
        );
        assert_eq!(
            report
                .provisioning
                .as_ref()
                .map(|readiness| readiness.callback_receive_id_mode),
            Some("explicit_override")
        );
    }

    #[test]
    fn operations_advertise_image_file_and_duplicate_check_inputs() {
        let operations = WeComConnector::operations();

        let send_text = operations
            .iter()
            .find(|operation| operation.id.as_str() == OP_SEND_TEXT)
            .expect("send_text operation should exist");
        assert!(
            send_text
                .input_schema
                .get("properties")
                .and_then(|value| value.get("enable_duplicate_check"))
                .is_some(),
            "send_text should advertise duplicate-check input"
        );

        let send_image = operations
            .iter()
            .find(|operation| operation.id.as_str() == OP_SEND_IMAGE)
            .expect("send_image operation should exist");
        assert_eq!(send_image.capability.as_str(), CAP_MESSAGES_WRITE);
        assert_eq!(send_image.idempotency, IdempotencyClass::None);
        assert_eq!(
            send_image
                .input_schema
                .get("required")
                .and_then(Value::as_array)
                .and_then(|required| required.first())
                .and_then(Value::as_str),
            Some("media_id")
        );

        let send_file = operations
            .iter()
            .find(|operation| operation.id.as_str() == OP_SEND_FILE)
            .expect("send_file operation should exist");
        assert_eq!(send_file.capability.as_str(), CAP_MESSAGES_WRITE);
        assert_eq!(send_file.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn normalize_callback_event_prefers_room_stream_and_attachment_refs() {
        let connector = WeComConnector::new();
        let verifier = CapabilityVerifier::new(
            [0_u8; 32],
            ZoneId::work(),
            connector.base.instance_id.clone(),
        );
        let callback = WeComCallbackEnvelope {
            receive_id: "corp".into(),
            wrapper: BTreeMap::from([
                ("ToUserName".into(), "corp".into()),
                ("AgentID".into(), "1000002".into()),
                ("Encrypt".into(), "ciphertext".into()),
            ]),
            message: BTreeMap::from([
                ("FromUserName".into(), "alice".into()),
                ("CreateTime".into(), "1710000000".into()),
                ("MsgType".into(), "image".into()),
                ("OpenChatId".into(), "room-1".into()),
                ("MediaId".into(), "MEDIA123".into()),
                ("ThumbMediaId".into(), "THUMB123".into()),
                ("PicUrl".into(), "https://example.test/pic.png".into()),
                ("MsgId".into(), "42".into()),
            ]),
            plaintext_xml: "<xml />".into(),
        };

        let event = normalize_callback_event(
            &callback,
            &verifier,
            &connector.base.id,
            &connector.base.instance_id,
            1_000_002,
        );

        assert_eq!(event.topic, "wecom.message.image");
        assert_eq!(
            event.stream_key.as_deref(),
            Some("agent:1000002:chat:room-1")
        );
        assert_eq!(event.ordering, Some(OrderingPolicy::PerKey));
        assert!(
            event
                .data
                .resource_uris
                .iter()
                .any(|uri| uri == "wecom:chat:room-1")
        );
        assert!(
            event
                .data
                .resource_uris
                .iter()
                .any(|uri| uri == "wecom:media:MEDIA123")
        );
        assert_eq!(
            event.data.payload["attachments"][0]["download_operation"],
            OP_DOWNLOAD_MEDIA
        );
    }

    #[test]
    fn normalize_callback_event_builds_change_event_topic() {
        let connector = WeComConnector::new();
        let verifier = CapabilityVerifier::new(
            [1_u8; 32],
            ZoneId::work(),
            connector.base.instance_id.clone(),
        );
        let callback = WeComCallbackEnvelope {
            receive_id: "corp".into(),
            wrapper: BTreeMap::from([("Encrypt".into(), "ciphertext".into())]),
            message: BTreeMap::from([
                ("MsgType".into(), "event".into()),
                ("Event".into(), "change_contact".into()),
                ("ChangeType".into(), "create_user".into()),
                ("UserID".into(), "bob".into()),
            ]),
            plaintext_xml: "<xml />".into(),
        };

        let event = normalize_callback_event(
            &callback,
            &verifier,
            &connector.base.id,
            &connector.base.instance_id,
            1_000_002,
        );

        assert_eq!(event.topic, "wecom.event.change_contact.create_user");
        assert!(event.stream_key.is_none());
        assert_eq!(event.ordering, Some(OrderingPolicy::Unordered));
        assert_eq!(event.data.principal.kind, "user");
        assert_eq!(event.data.principal.id, "bob");
        assert!(event.data.payload["conversation"].is_null());
        assert!(
            event
                .data
                .resource_uris
                .iter()
                .any(|uri| uri == "wecom:user:bob")
        );
    }
}
