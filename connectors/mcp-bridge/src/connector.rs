//! FCP MCP Bridge Connector implementation.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use fcp_manifest::{ConnectorManifest, HostEgressContext, ManifestApprovalMode, OperationSection};
use fcp_prelude::{
    ApprovalMode, ApprovalScope, ApprovalToken, BaseConnector, CapabilityGrant, CapabilityId,
    CapabilityToken, CapabilityVerifier, ConnectorId, CredentialId, EventCaps, FcpError, FcpResult,
    HandshakeRequest, HandshakeResponse, InputConstraint, OperationId, OperationInfo,
    ProvisioningRecipe, ProvisioningStep, ProvisioningStepType, RecipeId, SelfCheckReport,
    SessionId, StepId, Uuid, ZoneId, log_redaction::redact_url,
};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument};

use crate::{
    client::{McpAuth, McpClient, McpClientMetrics},
    error::{McpBridgeError, McpBridgeResult},
    protocol::{
        AuthMode, CapabilitySnapshot, MAX_TOOL_COUNT, ProtocolEra, ProtocolVersion, ServerId,
        ToolClass, ToolObservation,
    },
    security::{
        DescriptionScanMode, Severity, catalog_item_sha256, finding_log_payload, scan_description,
        tool_name_collides_with_builtin,
    },
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_TOOLS_LIST: &str = "mcp.tools.list";
const OP_TOOLS_CALL: &str = "mcp.tools.call";
const OP_RESOURCES_LIST: &str = "mcp.resources.list";
const OP_RESOURCES_READ: &str = "mcp.resources.read";
const OP_PROMPTS_LIST: &str = "mcp.prompts.list";
const OP_SAMPLING_HANDLE: &str = "mcp.sampling.handle";
const OP_SERVER_METRICS: &str = "mcp.server.metrics";
const OPERATION_ORDER: [&str; 7] = [
    OP_TOOLS_LIST,
    OP_TOOLS_CALL,
    OP_RESOURCES_LIST,
    OP_RESOURCES_READ,
    OP_PROMPTS_LIST,
    OP_SAMPLING_HANDLE,
    OP_SERVER_METRICS,
];

/// Parsed and validated MCP Bridge connector configuration.
#[derive(Debug, Clone)]
struct McpBridgeConfig {
    server_id: String,
    mcp_url: String,
    auth: McpAuth,
    description_scan: DescriptionScanMode,
    sampling: SamplingConfig,
    capability_policy: Option<CapabilityPolicy>,
}

#[derive(Debug, Clone)]
struct CapabilityPolicy {
    server_id: ServerId,
    n8n_version: String,
    auth_mode: AuthMode,
    api_scope_digest: String,
    approved_tools: Vec<ApprovedTool>,
    archive_workflow_schema: Option<ArchiveWorkflowSchemaBinding>,
    execute_workflow_schema: Option<ExecuteWorkflowSchemaBinding>,
}

#[derive(Debug, Clone)]
struct ArchiveWorkflowSchemaBinding {
    input_schema_digest: String,
    output_schema_digest: String,
}

#[derive(Debug, Clone)]
struct ExecuteWorkflowSchemaBinding {
    status: String,
    input_schema_digest: Option<String>,
    output_schema_digest: Option<String>,
}

#[derive(Debug, Clone)]
struct ApprovedTool {
    name: String,
    class: ToolClass,
    input_schema_digest: String,
    output_schema_digest: String,
}

#[derive(Debug, Clone)]
struct SamplingConfig {
    enabled: bool,
    llm_connector: Option<String>,
    max_rpm: u32,
    timeout_secs: u32,
    max_tokens_cap: u32,
    max_tool_rounds: u32,
    model_override: Option<String>,
    allowed_models: Vec<String>,
}

#[derive(Debug, Clone)]
struct ApprovalTarget {
    resource_uri: String,
    normalized_input: serde_json::Value,
    payload_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostRequestAttribution {
    request_id: String,
    correlation_id: Option<String>,
}

fn host_request_attribution(
    params: &serde_json::Value,
) -> FcpResult<Option<HostRequestAttribution>> {
    let correlation_id = match params.get("correlation_id") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) => Some(
            Uuid::parse_str(value)
                .map_err(|_| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Invalid host correlation ID".into(),
                })?
                .to_string(),
        ),
        Some(_) => {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid host correlation ID".into(),
            });
        }
    };

    let Some(request_id) = params.get("id") else {
        if correlation_id.is_some() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Host correlation requires a request ID".into(),
            });
        }
        return Ok(None);
    };
    let request_id = request_id.as_str().filter(|value| {
        !value.is_empty()
            && value.len() <= 256
            && value.trim() == *value
            && !value.chars().any(char::is_control)
    });
    let request_id = request_id.ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: "Invalid host request ID".into(),
    })?;
    Ok(Some(HostRequestAttribution {
        request_id: request_id.to_string(),
        correlation_id,
    }))
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            llm_connector: None,
            max_rpm: 10,
            timeout_secs: 30,
            max_tokens_cap: 4096,
            max_tool_rounds: 5,
            model_override: None,
            allowed_models: Vec::new(),
        }
    }
}

impl SamplingConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let Some(raw_sampling) = params.get("sampling") else {
            return Ok(Self::default());
        };
        let sampling = raw_sampling
            .as_object()
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "sampling must be an object".into(),
            })?;

        Ok(Self {
            enabled: sampling
                .get("enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            llm_connector: optional_string(
                sampling.get("llm_connector"),
                "sampling.llm_connector",
            )?,
            max_rpm: optional_u32(sampling.get("max_rpm"), "sampling.max_rpm")?.unwrap_or(10),
            timeout_secs: optional_u32(sampling.get("timeout_secs"), "sampling.timeout_secs")?
                .unwrap_or(30),
            max_tokens_cap: optional_u32(
                sampling.get("max_tokens_cap"),
                "sampling.max_tokens_cap",
            )?
            .unwrap_or(4096),
            max_tool_rounds: optional_u32(
                sampling.get("max_tool_rounds"),
                "sampling.max_tool_rounds",
            )?
            .unwrap_or(5),
            model_override: optional_string(
                sampling.get("model_override"),
                "sampling.model_override",
            )?,
            allowed_models: optional_string_vec(
                sampling.get("allowed_models"),
                "sampling.allowed_models",
            )?
            .unwrap_or_default(),
        })
    }
}

impl McpBridgeConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let server_id = params
            .get("server_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required server_id".into(),
            })?;
        validate_server_id(server_id)?;

        let api_key = params
            .get("api_key")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);
        let credential_id = match params.get("credential_id") {
            Some(value) => {
                let raw = value.as_str().ok_or_else(|| FcpError::InvalidRequest {
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
        if api_key.is_some() && credential_id.is_some() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Provide exactly one of api_key or credential_id".into(),
            });
        }

        let mcp_url = params
            .get("mcp_url")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing or empty mcp_url in configuration".into(),
            })?
            .to_string();
        let mcp_url = McpClient::canonicalize_base_url(&mcp_url)
            .map_err(|error| error.to_fcp_error())?
            .to_string();
        let capability_policy = CapabilityPolicy::from_params(
            params.get("capability_policy"),
            server_id,
            &McpAuth {
                api_key: api_key.clone(),
                credential_id,
            },
        )?;

        Ok(Self {
            server_id: server_id.to_string(),
            mcp_url,
            auth: McpAuth {
                api_key,
                credential_id,
            },
            description_scan: description_scan_mode_from_params(params)?,
            sampling: SamplingConfig::from_params(params)?,
            capability_policy,
        })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.mcp_url);

        ProvisioningReadiness {
            auth_mode: if self.auth.api_key.is_some() {
                "api_key"
            } else if self.auth.credential_id.is_some() {
                "credential_id"
            } else {
                "none"
            },
            api_key_configured: self.auth.api_key.is_some(),
            credential_id_configured: self.auth.credential_id.is_some(),
            requires_credential_injection: self.auth.credential_id.is_some(),
            network_ok,
            network_message,
            mcp_url: self.mcp_url.clone(),
            server_id: self.server_id.clone(),
            description_scan: self.description_scan,
            sampling_enabled: self.sampling.enabled,
        }
    }
}

impl CapabilityPolicy {
    fn from_params(
        raw_policy: Option<&serde_json::Value>,
        server_id: &str,
        auth: &McpAuth,
    ) -> FcpResult<Option<Self>> {
        let Some(raw_policy) = raw_policy else {
            return Ok(None);
        };
        let policy = raw_policy
            .as_object()
            .ok_or_else(|| invalid_policy("capability_policy must be an object"))?;
        if policy.keys().any(|key| {
            !matches!(
                key.as_str(),
                "n8n_version"
                    | "auth_mode"
                    | "api_scope_digest"
                    | "approved_tools"
                    | "archive_workflow_schema"
                    | "execute_workflow_schema"
            )
        }) {
            return Err(invalid_policy(
                "capability_policy contains an unsupported field",
            ));
        }
        let server_id = policy_server_id(server_id)?;
        let n8n_version =
            required_policy_string(policy.get("n8n_version"), "capability_policy.n8n_version")?;
        let auth_mode =
            match required_policy_string(policy.get("auth_mode"), "capability_policy.auth_mode")?
                .as_str()
            {
                "oauth" => AuthMode::OAuth,
                "access_token" => AuthMode::AccessToken,
                _ => return Err(invalid_policy("capability_policy.auth_mode is unsupported")),
            };
        if auth.api_key.is_some() && auth_mode != AuthMode::AccessToken {
            return Err(invalid_policy(
                "capability_policy.auth_mode must be access_token for api_key auth",
            ));
        }
        if auth.api_key.is_none() && auth.credential_id.is_none() {
            return Err(invalid_policy(
                "capability_policy requires configured authentication",
            ));
        }
        let api_scope_digest = required_policy_string(
            policy.get("api_scope_digest"),
            "capability_policy.api_scope_digest",
        )?;
        let approved_values = policy
            .get("approved_tools")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| invalid_policy("capability_policy.approved_tools must be an array"))?;
        if approved_values.len() > MAX_TOOL_COUNT {
            return Err(invalid_policy(
                "capability_policy.approved_tools exceeds the configured limit",
            ));
        }

        let mut approved_tools = Vec::with_capacity(approved_values.len());
        for value in approved_values {
            let object = value.as_object().ok_or_else(|| {
                invalid_policy("capability_policy.approved_tools entry must be an object")
            })?;
            if object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "name" | "class" | "input_schema_digest" | "output_schema_digest"
                )
            }) {
                return Err(invalid_policy(
                    "approved_tools contains an unsupported field",
                ));
            }
            let name = required_policy_string(object.get("name"), "approved_tools.name")?;
            let class = match required_policy_string(object.get("class"), "approved_tools.class")?
                .as_str()
            {
                "read" => ToolClass::Read,
                "write" => ToolClass::Write,
                "execution" => ToolClass::Execution,
                "credential" => ToolClass::Credential,
                "destructive" => ToolClass::Destructive,
                _ => return Err(invalid_policy("approved_tools.class is unsupported")),
            };
            let input_schema_digest = required_policy_string(
                object.get("input_schema_digest"),
                "approved_tools.input_schema_digest",
            )?;
            let output_schema_digest = required_policy_string(
                object.get("output_schema_digest"),
                "approved_tools.output_schema_digest",
            )?;
            if approved_tools
                .iter()
                .any(|tool: &ApprovedTool| tool.name == name)
            {
                return Err(invalid_policy(
                    "capability_policy.approved_tools contains duplicate names",
                ));
            }
            approved_tools.push(ApprovedTool {
                name,
                class,
                input_schema_digest,
                output_schema_digest,
            });
        }

        let archive_tool = approved_tools
            .iter()
            .find(|tool| tool.name == "archive_workflow");
        let archive_workflow_schema = match policy.get("archive_workflow_schema") {
            Some(value) => {
                let object = value
                    .as_object()
                    .ok_or_else(|| invalid_policy("archive_workflow_schema must be an object"))?;
                if object.len() != 2
                    || object.keys().any(|key| {
                        !matches!(key.as_str(), "input_schema_digest" | "output_schema_digest")
                    })
                {
                    return Err(invalid_policy(
                        "archive_workflow_schema contains an unsupported field",
                    ));
                }
                let input_schema_digest = required_policy_string(
                    object.get("input_schema_digest"),
                    "archive_workflow_schema.input_schema_digest",
                )?;
                let output_schema_digest = required_policy_string(
                    object.get("output_schema_digest"),
                    "archive_workflow_schema.output_schema_digest",
                )?;
                let Some(archive_tool) = archive_tool else {
                    return Err(invalid_policy(
                        "archive_workflow_schema requires an approved archive_workflow tool",
                    ));
                };
                if archive_tool.input_schema_digest != input_schema_digest
                    || archive_tool.output_schema_digest != output_schema_digest
                {
                    return Err(invalid_policy(
                        "archive_workflow_schema does not match approved archive_workflow",
                    ));
                }
                Some(ArchiveWorkflowSchemaBinding {
                    input_schema_digest,
                    output_schema_digest,
                })
            }
            None if archive_tool.is_some() => {
                return Err(invalid_policy(
                    "archive_workflow requires an exact schema binding",
                ));
            }
            None => None,
        };

        let execute_tool = approved_tools
            .iter()
            .find(|tool| tool.name == "execute_workflow");
        let execute_workflow_schema = match policy.get("execute_workflow_schema") {
            Some(value) => {
                let object = value
                    .as_object()
                    .ok_or_else(|| invalid_policy("execute_workflow_schema must be an object"))?;
                if object.len() != 3
                    || object.keys().any(|key| {
                        !matches!(
                            key.as_str(),
                            "status" | "input_schema_digest" | "output_schema_digest"
                        )
                    })
                {
                    return Err(invalid_policy(
                        "execute_workflow_schema contains an unsupported field",
                    ));
                }
                let status =
                    required_policy_string(object.get("status"), "execute_workflow_schema.status")?;
                match status.as_str() {
                    "owner_provisioned" => {
                        let input_schema_digest = required_policy_string(
                            object.get("input_schema_digest"),
                            "execute_workflow_schema.input_schema_digest",
                        )?;
                        let output_schema_digest = required_policy_string(
                            object.get("output_schema_digest"),
                            "execute_workflow_schema.output_schema_digest",
                        )?;
                        let Some(execute_tool) = execute_tool else {
                            return Err(invalid_policy(
                                "execute_workflow_schema requires an approved execute_workflow tool",
                            ));
                        };
                        if execute_tool.class != ToolClass::Write
                            || execute_tool.input_schema_digest != input_schema_digest
                            || execute_tool.output_schema_digest != output_schema_digest
                        {
                            return Err(invalid_policy(
                                "execute_workflow_schema does not match approved execute_workflow",
                            ));
                        }
                        Some(ExecuteWorkflowSchemaBinding {
                            status,
                            input_schema_digest: Some(input_schema_digest),
                            output_schema_digest: Some(output_schema_digest),
                        })
                    }
                    "unavailable_unproven_schema" => {
                        if object.get("input_schema_digest") != Some(&serde_json::Value::Null)
                            || object.get("output_schema_digest") != Some(&serde_json::Value::Null)
                            || execute_tool.is_some()
                        {
                            return Err(invalid_policy(
                                "execute_workflow_schema sentinel is incompatible with an approved execute_workflow tool",
                            ));
                        }
                        Some(ExecuteWorkflowSchemaBinding {
                            status,
                            input_schema_digest: None,
                            output_schema_digest: None,
                        })
                    }
                    _ => {
                        return Err(invalid_policy(
                            "execute_workflow_schema.status is unsupported",
                        ));
                    }
                }
            }
            None if execute_tool.is_some() => {
                return Err(invalid_policy(
                    "execute_workflow requires an exact schema binding",
                ));
            }
            None => None,
        };

        Ok(Some(Self {
            server_id,
            n8n_version,
            auth_mode,
            api_scope_digest,
            approved_tools,
            archive_workflow_schema,
            execute_workflow_schema,
        }))
    }
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    api_key_configured: bool,
    credential_id_configured: bool,
    requires_credential_injection: bool,
    network_ok: bool,
    network_message: String,
    mcp_url: String,
    server_id: String,
    description_scan: DescriptionScanMode,
    sampling_enabled: bool,
}

/// Doctor check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

/// Doctor status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Individual doctor check.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    #[must_use]
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|c| c.critical && !c.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| !c.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self { status, checks }
    }
}

/// FCP MCP Bridge Connector.
pub struct McpBridgeConnector {
    base: Arc<BaseConnector>,
    config: Option<McpBridgeConfig>,
    client: Option<Arc<McpClient>>,
    verifier: Option<CapabilityVerifier>,
    zone_id: Option<ZoneId>,
    session_id: Option<SessionId>,
    request_count: AtomicU64,
    error_count: AtomicU64,
    injection_scan_count: AtomicU64,
    injection_finding_count: AtomicU64,
    sampling_request_count: AtomicU64,
}

impl McpBridgeConnector {
    /// Create a new MCP Bridge connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("mcp-bridge"))),
            config: None,
            client: None,
            verifier: None,
            zone_id: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            injection_scan_count: AtomicU64::new(0),
            injection_finding_count: AtomicU64::new(0),
            sampling_request_count: AtomicU64::new(0),
        }
    }
}

impl Default for McpBridgeConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl McpBridgeConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = McpBridgeConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), mcp_url = %redact_url(&config.mcp_url), "Configuring MCP Bridge connector");

        let client =
            McpClient::new(config.auth.clone(), &config.mcp_url).map_err(|e| e.to_fcp_error())?;

        if let Some(old_client) = self.client.take() {
            old_client.shutdown();
        }
        self.verifier = None;
        self.zone_id = None;
        self.session_id = None;
        self.base.set_handshaken(false);
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({
            "configured": true,
            "server_id": self.config.as_ref().map(|value| value.server_id.as_str()),
        }))
    }

    /// Handle the `handshake` method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.config.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Connector not configured".into(),
            });
        }

        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {error}"),
            })?;
        if let Some(requested_instance_id) = req.requested_instance_id.clone() {
            let base = Arc::get_mut(&mut self.base).ok_or_else(|| FcpError::Internal {
                message: "Cannot assign requested instance ID after connector state is shared"
                    .into(),
            })?;
            base.instance_id = requested_instance_id;
        }
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        self.zone_id = Some(req.zone);
        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect();
        serde_json::to_value(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: manifest_hash(),
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
        .map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize handshake response: {error}"),
        })
    }

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some() && self.verifier.is_some();

        let status = if configured && handshaken {
            "healthy"
        } else if configured {
            "degraded"
        } else {
            "unconfigured"
        };

        Ok(json!({
            "status": status,
            "configured": configured,
            "handshaken": handshaken,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "injection_scans": self.injection_scan_count.load(Ordering::Relaxed),
            "injection_findings": self.injection_finding_count.load(Ordering::Relaxed),
            "sampling_requests": self.sampling_request_count.load(Ordering::Relaxed),
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_none() {
                Some("Not configured - call configure first".into())
            } else {
                None
            },
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: if self.client.is_none() {
                Some("MCP client not initialized".into())
            } else {
                None
            },
            critical: true,
        });

        let handshaken = self.session_id.is_some() && self.verifier.is_some();
        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: handshaken,
            message: if handshaken {
                None
            } else {
                Some("Handshake not completed".into())
            },
            critical: false,
        });

        let result = DoctorResult::from_checks(checks);
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return Self::serialize_self_check_report(report);
        };

        let readiness = config.provisioning_readiness();
        if !readiness.network_ok {
            let mut report = SelfCheckReport::failed(
                "network_constraints_invalid",
                readiness.network_message.clone(),
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let Some(client) = &self.client else {
            let mut report = SelfCheckReport::failed(
                "client_missing",
                "MCP client not initialized; re-run configure",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        };

        if config.auth.credential_id.is_some() {
            let mut report = SelfCheckReport::degraded(
                "provider_probe_unavailable",
                "Credential-backed provider probe requires verified invocation attribution",
            );
            report.details = Some(json!({
                "provisioning": readiness,
                "probe": "unavailable_without_verified_request_context",
            }));
            return Self::serialize_self_check_report(report);
        }

        let probe = match client.tools_list_with_context(None).await {
            Ok(_) => {
                let mut report = SelfCheckReport::ok();
                report.details = Some(json!({
                    "provisioning": readiness,
                    "probe": "POST configured MCP endpoint tools/list",
                }));
                report
            }
            Err(error) => {
                let mut report =
                    SelfCheckReport::failed("provider_probe_failed", error.safe_summary());
                report.details = Some(json!({
                    "provisioning": readiness,
                    "probe": "POST configured MCP endpoint tools/list",
                }));
                report
            }
        };
        Self::serialize_self_check_report(probe)
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let ops = typed_operations_info();
        Ok(json!({
            "connector_id": "fcp.mcp-bridge",
            "version": "0.1.0",
            "operations": serde_json::to_value(&ops).unwrap_or_default(),
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;
        let host_attribution = host_request_attribution(&params)?;

        let operation = params
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        let operation_id: OperationId =
            operation.parse().map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid operation ID format".into(),
            })?;
        let capability = required_capability(operation)?;
        let resources = self.resource_uris_for_operation(operation, &input)?;
        let token_value =
            params
                .get("capability_token")
                .cloned()
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing capability_token".into(),
                })?;
        let token: CapabilityToken =
            serde_json::from_value(token_value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token: {error}"),
            })?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let verified_token =
            verifier.verify_bound(token, &capability, &operation_id, &resources)?;

        if matches!(operation, OP_TOOLS_CALL | OP_SAMPLING_HANDLE) {
            let target = self.approval_target(operation, &input, &resources)?;
            self.require_execution_approval(operation, &target, &params)?;
        }

        if operation == OP_TOOLS_CALL
            && self
                .config
                .as_ref()
                .and_then(|config| config.capability_policy.as_ref())
                .is_none()
        {
            return Err(FcpError::CapabilityDenied {
                capability: "mcp.tools.write".into(),
                reason: "mcp.tools.call requires an explicit capability_policy".into(),
            });
        }

        let request_number = self.request_count.fetch_add(1, Ordering::Relaxed) + 1;
        let egress_context = if matches!(
            operation,
            OP_TOOLS_CALL | OP_TOOLS_LIST | OP_RESOURCES_LIST | OP_RESOURCES_READ | OP_PROMPTS_LIST
        ) {
            let [canonical_resource] = resources.as_slice() else {
                return Err(FcpError::Internal {
                    message: "MCP egress requires exactly one canonical resource URI".into(),
                });
            };
            Some(self.host_egress_context(
                operation,
                canonical_resource,
                &verified_token,
                request_number,
                host_attribution.as_ref(),
            )?)
        } else {
            None
        };

        if operation == OP_TOOLS_CALL {
            let context = egress_context.ok_or_else(|| FcpError::Internal {
                message: "MCP tools/call requires an exact host-egress context".into(),
            })?;
            let client = self.client_ref()?;
            let name = require_str(&input, "name").map_err(|error| error.to_fcp_error())?;
            if name.is_empty() || name.len() > crate::protocol::MAX_PUBLIC_ID_BYTES {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "MCP tool name is empty or exceeds the configured size limit".into(),
                });
            }
            let discovery = self
                .invoke_tools_list(client, Some(context.clone()))
                .await
                .map_err(|error| {
                    self.error_count.fetch_add(1, Ordering::Relaxed);
                    error.to_fcp_error()
                })?;
            let snapshot = discovery
                .get("capability_snapshot")
                .cloned()
                .ok_or_else(|| FcpError::Internal {
                    message: "MCP tools/list did not return a capability snapshot".into(),
                })
                .and_then(|value| {
                    serde_json::from_value::<CapabilitySnapshot>(value).map_err(|_| {
                        FcpError::Internal {
                            message: "MCP capability snapshot could not be validated".into(),
                        }
                    })
                })?;
            if snapshot.tool_call_is_blocked(name) {
                return Err(FcpError::CapabilityDenied {
                    capability: "mcp.tools.write".into(),
                    reason: "MCP tool is not exactly approved in the fresh capability snapshot"
                        .into(),
                });
            }
            return self
                .invoke_tools_call(client, &input, context)
                .await
                .map_err(|error| {
                    self.error_count.fetch_add(1, Ordering::Relaxed);
                    error.to_fcp_error()
                });
        }

        let result = match operation {
            OP_TOOLS_LIST => {
                self.invoke_tools_list(self.client_ref()?, egress_context.clone())
                    .await
            }
            OP_RESOURCES_LIST => {
                self.invoke_resources_list(self.client_ref()?, egress_context.clone())
                    .await
            }
            OP_RESOURCES_READ => {
                self.invoke_resources_read(self.client_ref()?, &input, egress_context.clone())
                    .await
            }
            OP_PROMPTS_LIST => {
                self.invoke_prompts_list(self.client_ref()?, egress_context)
                    .await
            }
            OP_SAMPLING_HANDLE => self.invoke_sampling_handle(&input).await,
            OP_SERVER_METRICS => self.invoke_server_metrics().await,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1002,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        result.map_err(|e| {
            self.error_count.fetch_add(1, Ordering::Relaxed);
            e.to_fcp_error()
        })
    }

    /// Handle the `simulate` method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let known = operations_info().as_array().is_some_and(|ops| {
            ops.iter()
                .any(|o| o.get("id").and_then(serde_json::Value::as_str) == Some(operation))
        });
        let policy_present = self
            .config
            .as_ref()
            .and_then(|config| config.capability_policy.as_ref())
            .is_some();
        let allowed = known && (operation != OP_TOOLS_CALL || policy_present);
        let reason = if operation == OP_TOOLS_CALL && policy_present {
            "Conditionally allowed: fresh capability discovery, mcp.tools.write, and exact execution approval are required"
        } else if operation == OP_TOOLS_CALL {
            "Denied: mcp.tools.call requires an explicit capability_policy"
        } else if allowed {
            "Operation supported"
        } else {
            "Unknown operation"
        };

        Ok(json!({
            "allowed": allowed,
            "reason": reason,
        }))
    }

    /// Handle the `shutdown` method.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("MCP Bridge connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.verifier = None;
        self.zone_id = None;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_tools_list(
        &self,
        client: &McpClient,
        context: Option<HostEgressContext>,
    ) -> Result<serde_json::Value, McpBridgeError> {
        let data = client.tools_list_with_context(context).await?;
        let data = self.annotate_catalog(data, "tools", "tool", true)?;
        self.attach_capability_snapshot(data, client).await
    }

    async fn invoke_tools_call(
        &self,
        client: &McpClient,
        input: &serde_json::Value,
        context: HostEgressContext,
    ) -> Result<serde_json::Value, McpBridgeError> {
        let name = require_str(input, "name")?;
        let arguments = input
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if !arguments.is_object() && !arguments.is_null() {
            return Err(McpBridgeError::McpError {
                code: -32602,
                message: "arguments must be an object".into(),
            });
        }
        let args = if arguments.is_null() {
            json!({})
        } else {
            arguments
        };
        let data = client.tools_call_with_context(name, &args, context).await?;
        Ok(data)
    }

    async fn invoke_resources_list(
        &self,
        client: &McpClient,
        context: Option<HostEgressContext>,
    ) -> Result<serde_json::Value, McpBridgeError> {
        let data = client.resources_list_with_context(context).await?;
        self.annotate_catalog(data, "resources", "resource", false)
    }

    async fn invoke_resources_read(
        &self,
        client: &McpClient,
        input: &serde_json::Value,
        context: Option<HostEgressContext>,
    ) -> Result<serde_json::Value, McpBridgeError> {
        let uri = require_str(input, "uri")?;
        let data = client.resources_read_with_context(uri, context).await?;
        Ok(data)
    }

    async fn invoke_prompts_list(
        &self,
        client: &McpClient,
        context: Option<HostEgressContext>,
    ) -> Result<serde_json::Value, McpBridgeError> {
        let data = client.prompts_list_with_context(context).await?;
        self.annotate_catalog(data, "prompts", "prompt", false)
    }

    async fn invoke_sampling_handle(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, McpBridgeError> {
        let config = self
            .config
            .as_ref()
            .ok_or_else(|| McpBridgeError::McpError {
                code: -32090,
                message: "Connector not configured".into(),
            })?;
        if !config.sampling.enabled {
            return Err(McpBridgeError::LocalPolicy {
                reason: "sampling is disabled by local configuration",
            });
        }

        let request = normalize_sampling_request(input);
        let params = request
            .get("params")
            .ok_or(McpBridgeError::LocalValidation {
                reason: "sampling request must include params",
            })?;
        let max_tokens = params
            .get("maxTokens")
            .and_then(serde_json::Value::as_u64)
            .ok_or(McpBridgeError::LocalValidation {
                reason: "sampling maxTokens must be an unsigned integer",
            })?;
        if max_tokens > u64::from(config.sampling.max_tokens_cap) {
            return Err(McpBridgeError::LocalPolicy {
                reason: "sampling request exceeds the local max_tokens cap",
            });
        }

        let messages_count = params
            .get("messages")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
        self.sampling_request_count.fetch_add(1, Ordering::Relaxed);
        info!(
            event = "mcp_sampling_request_received",
            messages_count,
            max_tokens,
            llm_connector = config
                .sampling
                .llm_connector
                .as_deref()
                .unwrap_or("agent-selected"),
            "MCP sampling request converted to FCP event fallback"
        );

        Ok(json!({
            "event": "mcp_sampling_request_received",
            "dispatch": "agent_event",
            "host_orchestrated": false,
            "requires_human_approval": true,
            "llm_connector": config.sampling.llm_connector.clone(),
            "limits": {
                "max_rpm": config.sampling.max_rpm,
                "timeout_secs": config.sampling.timeout_secs,
                "max_tokens_cap": config.sampling.max_tokens_cap,
                "max_tool_rounds": config.sampling.max_tool_rounds,
                "model_override": config.sampling.model_override.clone(),
                "allowed_models": config.sampling.allowed_models.clone(),
            },
            "request": {
                "method": "sampling/createMessage",
                "message_count": messages_count,
                "max_tokens": max_tokens,
            },
            "redaction": {
                "prompt_logged": false,
                "response_logged": false,
                "metadata_logged": false,
            }
        }))
    }

    async fn invoke_server_metrics(&self) -> Result<serde_json::Value, McpBridgeError> {
        let client_metrics = self
            .client
            .as_ref()
            .map_or(McpClientMetrics::default(), |client| client.metrics());
        Ok(json!({
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "injection_scans": self.injection_scan_count.load(Ordering::Relaxed),
            "injection_findings": self.injection_finding_count.load(Ordering::Relaxed),
            "sampling_requests": self.sampling_request_count.load(Ordering::Relaxed),
            "auth_retries": client_metrics.auth_retry_count,
            "session_expired_retries": client_metrics.session_expired_retry_count,
        }))
    }

    fn client_ref(&self) -> FcpResult<&McpClient> {
        self.client.as_deref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })
    }

    fn host_egress_context<S>(
        &self,
        operation: &str,
        resource_uri: &str,
        token: &CapabilityToken<S>,
        request_number: u64,
        host_attribution: Option<&HostRequestAttribution>,
    ) -> FcpResult<HostEgressContext> {
        let zone_id = self.zone_id.as_ref().ok_or(FcpError::NotHandshaken)?;
        let session_id = self.session_id.as_ref().ok_or(FcpError::NotHandshaken)?;
        let token_cbor = token.raw().to_cbor().map_err(|_| FcpError::Internal {
            message: "verified capability token could not be serialized".into(),
        })?;
        let request_id = host_attribution.map_or_else(
            || format!("{session_id}:{request_number}"),
            |attribution| attribution.request_id.clone(),
        );
        let correlation_id =
            host_attribution.and_then(|attribution| attribution.correlation_id.clone());
        Ok(HostEgressContext {
            connector_id: "fcp.mcp-bridge".into(),
            operation_id: operation.into(),
            resource_uri: resource_uri.into(),
            zone_id: zone_id.to_string(),
            request_id,
            correlation_id,
            capability_token_cbor_b64: base64::engine::general_purpose::STANDARD.encode(token_cbor),
        })
    }

    fn resource_uris_for_operation(
        &self,
        operation: &str,
        input: &serde_json::Value,
    ) -> FcpResult<Vec<String>> {
        let server_id = self
            .config
            .as_ref()
            .ok_or(FcpError::NotConfigured)?
            .server_id
            .as_str();
        let resource = match operation {
            OP_TOOLS_LIST | OP_RESOURCES_LIST | OP_PROMPTS_LIST | OP_SAMPLING_HANDLE
            | OP_SERVER_METRICS => instance_resource_uri(server_id),
            OP_TOOLS_CALL => {
                let name = require_str(input, "name").map_err(|error| error.to_fcp_error())?;
                tool_resource_uri(server_id, name).map_err(|error| error.to_fcp_error())?
            }
            OP_RESOURCES_READ => {
                let uri = require_str(input, "uri").map_err(|error| error.to_fcp_error())?;
                resource_resource_uri(server_id, uri).map_err(|error| error.to_fcp_error())?
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1002,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        Ok(vec![resource])
    }

    fn approval_target(
        &self,
        operation: &str,
        input: &serde_json::Value,
        resources: &[String],
    ) -> FcpResult<ApprovalTarget> {
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let resource_uri = resources
            .first()
            .cloned()
            .ok_or_else(|| FcpError::Internal {
                message: "MCP approval resource URI was not constructed".into(),
            })?;
        let canonical_payload = if operation == OP_TOOLS_CALL {
            normalize_tools_call_input(input).map_err(|error| error.to_fcp_error())?
        } else {
            normalize_sampling_request(input)
        };
        let payload_digest = canonical_payload_digest(&canonical_payload);
        let mut normalized_input = json!({
            "server_id": config.server_id,
            "resource_uri": resource_uri,
            "operation": operation,
            "provider": if operation == OP_SAMPLING_HANDLE { "local" } else { "mcp" },
            "payload_sha256": hex::encode(payload_digest),
        });
        if operation == OP_TOOLS_CALL {
            let name = require_str(input, "name").map_err(|error| error.to_fcp_error())?;
            normalized_input["tool_name"] = json!(name);
        } else {
            normalized_input["sampling_method"] = json!("sampling/createMessage");
        }
        Ok(ApprovalTarget {
            resource_uri,
            normalized_input,
            payload_digest,
        })
    }

    fn require_execution_approval(
        &self,
        operation: &str,
        target: &ApprovalTarget,
        params: &serde_json::Value,
    ) -> FcpResult<()> {
        let approval_values = params
            .get("approval_tokens")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "operation requires a non-empty approval_tokens collection".into(),
            })?;
        let approvals: Vec<ApprovalToken> = approval_values
            .iter()
            .map(|value| serde_json::from_value(value.clone()))
            .collect::<Result<_, _>>()
            .map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid approval token: {error}"),
            })?;
        let now_ms = current_time_ms();
        let matching = approvals
            .iter()
            .filter(|approval| {
                is_matching_execution_approval(
                    approval,
                    operation,
                    self.zone_id.as_ref(),
                    target,
                    now_ms,
                )
            })
            .count();
        if matching != 1 {
            return Err(FcpError::CapabilityDenied {
                capability: operation.to_string(),
                reason: "operation requires exactly one matching execution approval token".into(),
            });
        }
        Ok(())
    }

    fn annotate_catalog(
        &self,
        mut data: serde_json::Value,
        array_key: &str,
        catalog_kind: &str,
        filter_builtin_collisions: bool,
    ) -> Result<serde_json::Value, McpBridgeError> {
        let Some(config) = &self.config else {
            return Ok(data);
        };
        let Some(items) = data
            .get_mut(array_key)
            .and_then(serde_json::Value::as_array_mut)
        else {
            return Ok(data);
        };

        if filter_builtin_collisions {
            items.retain(|item| {
                let name = item
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                let collides = tool_name_collides_with_builtin(name);
                if collides {
                    info!(
                        event = "mcp_tool_collision_skipped",
                        server_id = %config.server_id,
                        item_sha256 = %catalog_item_sha256(&config.server_id, "tool", name, ""),
                        "Skipping MCP tool that collides with bridge operation namespace"
                    );
                }
                !collides
            });
        }

        for item in items {
            let Some(object) = item.as_object_mut() else {
                continue;
            };
            let name = object
                .get("name")
                .or_else(|| object.get("uri"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<unnamed>")
                .to_string();
            let description = object
                .get("description")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string();

            let findings = if config.description_scan.scans() {
                self.injection_scan_count.fetch_add(1, Ordering::Relaxed);
                scan_description(&config.server_id, &name, &description)
            } else {
                Vec::new()
            };
            self.injection_finding_count.fetch_add(
                u64::try_from(findings.len()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            let max_severity = max_severity_label(&findings);
            info!(
                event = "mcp_description_scanned",
                server_id = %config.server_id,
                catalog_kind,
                item_sha256 = %catalog_item_sha256(
                    &config.server_id,
                    catalog_kind,
                    &name,
                    &description,
                ),
                item_length = name.len().saturating_add(description.len()),
                finding_count = findings.len(),
                max_severity,
                "MCP catalog description scanned"
            );
            for finding in &findings {
                let payload = finding_log_payload(
                    &config.server_id,
                    catalog_kind,
                    &name,
                    &description,
                    finding,
                );
                tracing::warn!(event = "mcp_injection_finding", payload = %payload);
            }

            if config.description_scan == DescriptionScanMode::Block && !findings.is_empty() {
                return Err(McpBridgeError::LocalPolicy {
                    reason: "catalog description blocked by local scanner policy",
                });
            }

            object.insert(
                "injection_findings".to_string(),
                serde_json::to_value(&findings).unwrap_or_else(|_| json!([])),
            );
        }

        Ok(data)
    }

    async fn attach_capability_snapshot(
        &self,
        mut data: serde_json::Value,
        client: &McpClient,
    ) -> Result<serde_json::Value, McpBridgeError> {
        let Some(policy) = self
            .config
            .as_ref()
            .and_then(|config| config.capability_policy.as_ref())
            .cloned()
        else {
            return Ok(data);
        };
        let (era, version) = client.negotiated_profile().await;
        let snapshot = build_capability_snapshot(&data, &policy, era, version)?;
        data["capability_snapshot"] = serde_json::to_value(snapshot).map_err(|_| {
            McpBridgeError::InvalidInput("MCP capability snapshot could not be serialized".into())
        })?;
        Ok(data)
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "mcp_bridge.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "MCP Bridge self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }
}

fn build_capability_snapshot(
    data: &serde_json::Value,
    policy: &CapabilityPolicy,
    era: ProtocolEra,
    version: ProtocolVersion,
) -> McpBridgeResult<CapabilitySnapshot> {
    let observations = capability_observations(data, policy)?;
    let reviewed = reviewed_policy_snapshot(policy, era, version)?;
    CapabilitySnapshot::from_observations(
        policy.server_id,
        &policy.n8n_version,
        era,
        vec![version],
        policy.auth_mode,
        &policy.api_scope_digest,
        observations,
        Some(&reviewed),
    )
    .map_err(|_| McpBridgeError::InvalidInput("MCP capability snapshot is invalid".into()))
}

fn capability_observations(
    data: &serde_json::Value,
    policy: &CapabilityPolicy,
) -> McpBridgeResult<Vec<ToolObservation>> {
    let tools = data
        .get("tools")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            McpBridgeError::InvalidInput("MCP tools/list returned a malformed catalog".into())
        })?;
    if tools.len() > MAX_TOOL_COUNT {
        return Err(McpBridgeError::InvalidInput(
            "MCP tools/list returned too many tools".into(),
        ));
    }

    let mut observations = Vec::with_capacity(tools.len());
    let mut names = Vec::with_capacity(tools.len());
    for tool in tools {
        let object = tool.as_object().ok_or_else(|| {
            McpBridgeError::InvalidInput("MCP tools/list returned a malformed tool entry".into())
        })?;
        if object
            .get("description")
            .is_some_and(|value| !value.is_null() && !value.is_string())
        {
            return Err(McpBridgeError::InvalidInput(
                "MCP tools/list returned a malformed description".into(),
            ));
        }
        let name = object
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                McpBridgeError::InvalidInput("MCP tools/list returned a tool without a name".into())
            })?;
        if names.iter().any(|existing: &String| existing == name) {
            return Err(McpBridgeError::InvalidInput(
                "MCP tools/list returned duplicate tool names".into(),
            ));
        }
        let input_schema = object
            .get("inputSchema")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if !input_schema.is_null() && !input_schema.is_object() {
            return Err(McpBridgeError::InvalidInput(
                "MCP tools/list returned a malformed inputSchema".into(),
            ));
        }
        let output_schema = object
            .get("outputSchema")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if !output_schema.is_null() && !output_schema.is_object() {
            return Err(McpBridgeError::InvalidInput(
                "MCP tools/list returned a malformed outputSchema".into(),
            ));
        }
        let class = policy
            .approved_tools
            .iter()
            .find(|approved| approved.name == name)
            .map_or(ToolClass::Unknown, |approved| approved.class);
        let observation = ToolObservation::from_schemas(name, &input_schema, &output_schema, class)
            .map_err(|_| {
                McpBridgeError::InvalidInput("MCP tools/list returned invalid tool metadata".into())
            })?;
        names.push(name.to_string());
        observations.push(observation);
    }
    Ok(observations)
}

fn reviewed_policy_snapshot(
    policy: &CapabilityPolicy,
    era: ProtocolEra,
    version: ProtocolVersion,
) -> McpBridgeResult<CapabilitySnapshot> {
    if let Some(archive_tool) = policy
        .approved_tools
        .iter()
        .find(|tool| tool.name == "archive_workflow")
    {
        let Some(binding) = policy.archive_workflow_schema.as_ref() else {
            return Err(McpBridgeError::InvalidInput(
                "archive_workflow policy binding is missing".into(),
            ));
        };
        if binding.input_schema_digest != archive_tool.input_schema_digest
            || binding.output_schema_digest != archive_tool.output_schema_digest
        {
            return Err(McpBridgeError::InvalidInput(
                "archive_workflow policy binding is mismatched".into(),
            ));
        }
    }
    let observations = policy
        .approved_tools
        .iter()
        .map(|approved| {
            ToolObservation::from_digests(
                &approved.name,
                &approved.input_schema_digest,
                &approved.output_schema_digest,
                approved.class,
            )
            .map_err(|_| {
                McpBridgeError::InvalidInput(
                    "capability_policy contains invalid tool metadata".into(),
                )
            })
        })
        .collect::<McpBridgeResult<Vec<_>>>()?;
    let mut snapshot = CapabilitySnapshot::from_observations(
        policy.server_id,
        &policy.n8n_version,
        era,
        vec![version],
        policy.auth_mode,
        &policy.api_scope_digest,
        observations,
        None,
    )
    .map_err(|_| McpBridgeError::InvalidInput("capability_policy is invalid".into()))?;
    for approved in &policy.approved_tools {
        snapshot
            .approve_tool(
                &approved.name,
                approved.class,
                &approved.input_schema_digest,
                &approved.output_schema_digest,
            )
            .map_err(|_| {
                McpBridgeError::InvalidInput("capability_policy approval is invalid".into())
            })?;
    }
    Ok(snapshot)
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, McpBridgeError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| McpBridgeError::McpError {
            code: -32602,
            message: format!("Missing required field: {field}"),
        })
}

fn instance_resource_uri(server_id: &str) -> String {
    format!("fwc-mcp-bridge://{server_id}")
}

fn tool_resource_uri(server_id: &str, name: &str) -> McpBridgeResult<String> {
    let name = non_empty_resource_component(name, "tool name")?;
    let encoded = utf8_percent_encode(name, NON_ALPHANUMERIC);
    Ok(format!("fwc-mcp-bridge://{server_id}/tools/{encoded}"))
}

fn resource_resource_uri(server_id: &str, uri: &str) -> McpBridgeResult<String> {
    let uri = non_empty_resource_component(uri, "resource URI")?;
    let encoded = utf8_percent_encode(uri, NON_ALPHANUMERIC);
    Ok(format!("fwc-mcp-bridge://{server_id}/resources/{encoded}"))
}

fn non_empty_resource_component<'a>(value: &'a str, field: &str) -> McpBridgeResult<&'a str> {
    if value.trim().is_empty() {
        Err(McpBridgeError::InvalidInput(format!(
            "{field} must not be empty"
        )))
    } else {
        Ok(value)
    }
}

fn is_matching_execution_approval(
    approval: &ApprovalToken,
    operation: &str,
    zone_id: Option<&ZoneId>,
    target: &ApprovalTarget,
    now_ms: u64,
) -> bool {
    if approval.signature.as_ref().is_none_or(Vec::is_empty)
        || !approval.is_valid(now_ms)
        || zone_id != Some(&approval.zone_id)
    {
        return false;
    }
    let ApprovalScope::Execution(scope) = &approval.scope else {
        return false;
    };
    scope.connector_id == "fcp.mcp-bridge"
        && scope.method_pattern == operation
        && scope.request_object_id.is_none()
        && scope
            .input_hash
            .as_ref()
            .is_none_or(|input_hash| input_hash == &target.payload_digest)
        && has_exact_approval_constraints(&scope.input_constraints, &target.normalized_input)
}

fn has_exact_approval_constraints(
    constraints: &[InputConstraint],
    normalized_input: &serde_json::Value,
) -> bool {
    let required = normalized_input.as_object().map_or(0, serde_json::Map::len);
    constraints.len() == required
        && normalized_input.as_object().is_some_and(|values| {
            values.iter().all(|(field, expected)| {
                constraints.iter().any(|constraint| {
                    constraint.pointer == format!("/{field}") && &constraint.expected == expected
                })
            })
        })
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u128::from(u64::MAX)) as u64
        })
}

fn manifest_hash() -> String {
    let mut hasher = Sha256::new();
    hasher.update(MANIFEST_TOML.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    typed_operations_info()
        .into_iter()
        .find(|info| info.id.as_ref() == operation)
        .map(|info| info.capability)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown operation: {operation}"),
        })
}

fn description_scan_mode_from_params(params: &serde_json::Value) -> FcpResult<DescriptionScanMode> {
    let raw = params
        .get("description_scan")
        .or_else(|| {
            params
                .get("security")
                .and_then(|security| security.get("description_scan"))
        })
        .and_then(serde_json::Value::as_str);
    let Some(raw) = raw else {
        return Ok(DescriptionScanMode::Warn);
    };
    DescriptionScanMode::parse(raw).map_err(|message| FcpError::InvalidRequest {
        code: 1003,
        message,
    })
}

fn invalid_policy(message: &str) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn required_policy_string(value: Option<&serde_json::Value>, field: &str) -> FcpResult<String> {
    let raw = value
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid_policy(&format!("{field} must be a string")))?;
    if raw.is_empty()
        || raw.len() > crate::protocol::MAX_PUBLIC_ID_BYTES
        || raw.chars().any(char::is_control)
    {
        return Err(invalid_policy(&format!(
            "{field} is empty or exceeds the configured size limit"
        )));
    }
    Ok(raw.to_string())
}

fn policy_server_id(server_id: &str) -> FcpResult<ServerId> {
    match server_id {
        "eec" => Ok(ServerId::Eec),
        "hetzner" => Ok(ServerId::Hetzner),
        "legacy" => Ok(ServerId::Legacy),
        _ => Err(invalid_policy(
            "capability_policy is supported only for eec, hetzner, or legacy server_id",
        )),
    }
}

fn optional_string(value: Option<&serde_json::Value>, field: &str) -> FcpResult<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let raw = value.as_str().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be a string"),
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

fn optional_u32(value: Option<&serde_json::Value>, field: &str) -> FcpResult<Option<u32>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let raw = value.as_u64().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be an unsigned integer"),
    })?;
    u32::try_from(raw)
        .map(Some)
        .map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} exceeds u32 range"),
        })
}

fn optional_string_vec(
    value: Option<&serde_json::Value>,
    field: &str,
) -> FcpResult<Option<Vec<String>>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let values = value.as_array().ok_or_else(|| FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be an array of strings"),
    })?;
    let mut out = Vec::with_capacity(values.len());
    for item in values {
        let raw = item.as_str().ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must contain only strings"),
        })?;
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            out.push(trimmed.to_string());
        }
    }
    Ok(Some(out))
}

fn normalize_sampling_request(input: &serde_json::Value) -> serde_json::Value {
    let candidate = input.get("request").unwrap_or(input);
    let params = candidate
        .get("params")
        .cloned()
        .unwrap_or_else(|| candidate.clone());
    json!({
        "method": "sampling/createMessage",
        "params": params,
    })
}

fn normalize_tools_call_input(input: &serde_json::Value) -> McpBridgeResult<serde_json::Value> {
    let name = require_str(input, "name")?;
    let arguments = input.get("arguments").cloned().unwrap_or_else(|| json!({}));
    let arguments = if arguments.is_null() {
        json!({})
    } else if arguments.is_object() {
        arguments
    } else {
        return Err(McpBridgeError::McpError {
            code: -32602,
            message: "arguments must be an object".into(),
        });
    };
    Ok(json!({
        "name": name,
        "arguments": arguments,
    }))
}

fn canonical_payload_digest(payload: &serde_json::Value) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"FCP/MCP-Bridge/approval-payload/v1\0");
    hasher.update(canonical_json_bytes(payload));
    hasher.finalize().into()
}

fn canonical_json_bytes(value: &serde_json::Value) -> Vec<u8> {
    match value {
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => serde_json::to_vec(value).unwrap_or_default(),
        serde_json::Value::Array(values) => {
            let mut output = vec![b'['];
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                output.extend(canonical_json_bytes(item));
            }
            output.push(b']');
            output
        }
        serde_json::Value::Object(values) => {
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            let mut output = vec![b'{'];
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                output.extend(serde_json::to_vec(key).unwrap_or_default());
                output.push(b':');
                output.extend(canonical_json_bytes(item));
            }
            output.push(b'}');
            output
        }
    }
}

fn max_severity_label(findings: &[crate::security::InjectionFinding]) -> &'static str {
    if findings
        .iter()
        .any(|finding| finding.severity == Severity::Block)
    {
        "block"
    } else if findings.is_empty() {
        "none"
    } else {
        "warn"
    }
}

/// Build typed operations info for introspection.
fn typed_operations_info() -> Vec<OperationInfo> {
    ordered_manifest_operations()
        .into_iter()
        .map(|(id, operation)| operation_info_from_manifest(id, &operation))
        .collect()
}

fn ordered_manifest_operations() -> Vec<(String, OperationSection)> {
    let manifest = ConnectorManifest::parse_str(MANIFEST_TOML)
        .expect("embedded MCP Bridge manifest should validate");
    let mut operations: Vec<_> = manifest.provides.operations.into_iter().collect();
    operations.sort_by(|(left, _), (right, _)| {
        let left_index = operation_order(left);
        let right_index = operation_order(right);
        left_index.cmp(&right_index).then_with(|| left.cmp(right))
    });
    operations
}

fn operation_order(operation_id: &str) -> usize {
    OPERATION_ORDER
        .iter()
        .position(|known_id| *known_id == operation_id)
        .unwrap_or(OPERATION_ORDER.len())
}

fn approval_mode_from_manifest(mode: ManifestApprovalMode) -> Option<ApprovalMode> {
    match mode {
        ManifestApprovalMode::None => None,
        other => Some(ApprovalMode::from(other)),
    }
}

fn operation_info_from_manifest(id: String, operation: &OperationSection) -> OperationInfo {
    let description = operation.description.clone();
    OperationInfo {
        id: OperationId::new(id).expect("manifest operation id should be canonical"),
        summary: description.clone(),
        description: Some(description),
        input_schema: operation.input_schema.clone(),
        output_schema: operation.output_schema.clone(),
        capability: operation.capability.clone(),
        risk_level: operation.risk_level,
        safety_tier: operation.safety_tier,
        idempotency: operation.idempotency,
        ai_hints: operation.ai_hints.clone(),
        rate_limit: operation
            .rate_limit
            .as_ref()
            .map(|rate_limit| rate_limit.0.clone()),
        requires_approval: approval_mode_from_manifest(operation.requires_approval),
    }
}

/// Build the operations info for introspection (JSON format for simulate).
fn operations_info() -> serde_json::Value {
    static OPERATIONS: OnceLock<serde_json::Value> = OnceLock::new();
    OPERATIONS
        .get_or_init(|| serde_json::to_value(typed_operations_info()).unwrap_or_default())
        .clone()
}

/// Build the provisioning recipe for the MCP Bridge connector.
///
/// MCP Bridge provisioning never handles raw provider secrets. The recipe
/// collects trusted identity/endpoint metadata and a host-managed credential
/// reference only.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("mcp-bridge.host_credential"),
        "1",
        "Provision MCP Bridge with a canonical server identity, exact supported MCP endpoint, and host-managed credential reference",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("enter_server_id"),
        ProvisioningStepType::PromptUser {
            message: "Enter the trusted lowercase server_id slug (1-64 ASCII letters, digits, '-' or '_')".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_mcp_endpoint"),
            ProvisioningStepType::PromptUser {
                message: "Enter an exact supported MCP endpoint (/mcp or the official n8n /mcp-server/http path; only one trailing slash is normalized)".into(),
            },
        )
        .depends_on(StepId::new("enter_server_id")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_credential_id"),
            ProvisioningStepType::PromptUser {
                message: "Enter the host-managed credential_id UUID reference; never paste a raw API key (leave empty only for an unauthenticated loopback fixture)".into(),
            },
        )
        .depends_on(StepId::new("enter_mcp_endpoint")),
    )
}

/// Validate the MCP server URL.
///
/// Enforce the same exact-endpoint policy used by the client. Loopback HTTP
/// is reserved for deterministic local fixtures; production targets must pass
/// the client's HTTPS/443 and host policy before any provider traffic.
fn base_url_policy(mcp_url: &str) -> (bool, String) {
    match McpClient::canonicalize_base_url(mcp_url) {
        Ok(canonical) => (true, format!("Exact MCP endpoint accepted: {canonical}")),
        Err(error) => (false, error.safe_summary()),
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn validate_server_id(server_id: &str) -> FcpResult<()> {
    let bytes = server_id.as_bytes();
    let valid = (1..=64).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && server_id
            .chars()
            .all(|character| !character.is_ascii_uppercase());
    if valid {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: "server_id must be a lowercase canonical slug (1-64 ASCII letters, digits, '-' or '_')".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict_mcp_bridge_manifest() -> Result<ConnectorManifest, String> {
        ConnectorManifest::parse_str(MANIFEST_TOML).map_err(|error| error.to_string())
    }

    #[test]
    fn host_request_attribution_preserves_owned_invocation_identity() {
        let correlation_id = Uuid::new_v4().to_string();
        let attribution = host_request_attribution(&json!({
            "id": "outer-request-1",
            "correlation_id": correlation_id,
        }))
        .expect("valid host attribution")
        .expect("host attribution present");
        assert_eq!(attribution.request_id, "outer-request-1");
        assert_eq!(
            attribution.correlation_id.as_deref(),
            Some(correlation_id.as_str())
        );

        assert!(host_request_attribution(&json!({})).unwrap().is_none());
    }

    #[test]
    fn host_request_attribution_rejects_partial_or_malformed_identity() {
        let correlation_id = Uuid::new_v4().to_string();
        for value in [
            json!({"correlation_id": correlation_id}),
            json!({"id": ""}),
            json!({"id": " request"}),
            json!({"id": 7}),
            json!({"id": "request", "correlation_id": "not-a-uuid"}),
        ] {
            assert!(host_request_attribution(&value).is_err());
        }
    }

    #[test]
    fn config_from_valid_params() {
        let config = McpBridgeConfig::from_params(&json!({
            "server_id": "mcp-test",
            "mcp_url": "http://localhost:3000/mcp",
        }))
        .unwrap();
        assert_eq!(config.mcp_url, "http://localhost:3000/mcp");
        assert!(config.auth.api_key.is_none());
    }

    #[test]
    fn config_with_api_key() {
        let config = McpBridgeConfig::from_params(&json!({
            "server_id": "mcp-test",
            "mcp_url": "http://localhost:3000/mcp",
            "api_key": "sk-test-key",
        }))
        .unwrap();
        assert_eq!(config.mcp_url, "http://localhost:3000/mcp");
        assert_eq!(config.auth.api_key, Some("sk-test-key".into()));
    }

    #[test]
    fn config_rejects_missing_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({
            "api_key": "key",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({
            "mcp_url": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({
            "mcp_url": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_params() {
        let result = McpBridgeConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({
            "mcp_url": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_null_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({
            "mcp_url": null,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_mcp_url() {
        let config = McpBridgeConfig::from_params(&json!({
            "server_id": "mcp-test",
            "mcp_url": "  http://localhost:3000/mcp  ",
        }))
        .unwrap();
        assert_eq!(config.mcp_url, "http://localhost:3000/mcp");
    }

    #[test]
    fn config_ignores_empty_api_key() {
        let config = McpBridgeConfig::from_params(&json!({
            "server_id": "mcp-test",
            "mcp_url": "http://localhost:3000/mcp",
            "api_key": "",
        }))
        .unwrap();
        assert!(config.auth.api_key.is_none());
    }

    #[test]
    fn config_ignores_whitespace_api_key() {
        let config = McpBridgeConfig::from_params(&json!({
            "server_id": "mcp-test",
            "mcp_url": "http://localhost:3000/mcp",
            "api_key": "   ",
        }))
        .unwrap();
        assert!(config.auth.api_key.is_none());
    }

    #[test]
    fn config_trims_api_key() {
        let config = McpBridgeConfig::from_params(&json!({
            "server_id": "mcp-test",
            "mcp_url": "http://localhost:3000/mcp",
            "api_key": "  sk-key  ",
        }))
        .unwrap();
        assert_eq!(config.auth.api_key, Some("sk-key".into()));
    }

    #[test]
    fn require_str_present() {
        let input = json!({"name": "read_file"});
        assert_eq!(require_str(&input, "name").unwrap(), "read_file");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"name": 42});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"name": null});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"name": true});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"name": ["a", "b"]});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn operations_info_has_7_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 7);
    }

    #[test]
    fn runtime_operation_catalog_matches_manifest_metadata() -> Result<(), String> {
        let manifest = strict_mcp_bridge_manifest()?;
        let operations = typed_operations_info();

        assert_eq!(operations.len(), OPERATION_ORDER.len());
        assert_eq!(operations.len(), manifest.provides.operations.len());

        for (index, operation) in operations.iter().enumerate() {
            let operation_id = operation.id.as_str();
            assert_eq!(
                operation_id, OPERATION_ORDER[index],
                "operation order changed at index {index}"
            );

            let manifest_operation = manifest
                .provides
                .operations
                .get(operation_id)
                .ok_or_else(|| format!("manifest missing operation {operation_id}"))?;

            assert_eq!(operation.summary, manifest_operation.description);
            assert_eq!(
                operation.description.as_deref(),
                Some(manifest_operation.description.as_str())
            );
            assert_eq!(operation.input_schema, manifest_operation.input_schema);
            assert_eq!(operation.output_schema, manifest_operation.output_schema);
            assert_eq!(operation.capability, manifest_operation.capability);
            assert_eq!(operation.risk_level, manifest_operation.risk_level);
            assert_eq!(operation.safety_tier, manifest_operation.safety_tier);
            assert_eq!(operation.idempotency, manifest_operation.idempotency);
            assert_eq!(
                operation.requires_approval,
                approval_mode_from_manifest(manifest_operation.requires_approval)
            );
            assert_eq!(
                serde_json::to_value(&operation.ai_hints).map_err(|error| error.to_string())?,
                serde_json::to_value(&manifest_operation.ai_hints)
                    .map_err(|error| error.to_string())?
            );
            assert_eq!(
                serde_json::to_value(&operation.rate_limit).map_err(|error| error.to_string())?,
                serde_json::to_value(
                    manifest_operation
                        .rate_limit
                        .as_ref()
                        .map(|rate_limit| rate_limit.0.clone()),
                )
                .map_err(|error| error.to_string())?
            );
            assert!(
                manifest_operation.network_constraints.is_some(),
                "{operation_id} should retain manifest network constraints"
            );
        }

        Ok(())
    }

    #[test]
    fn operations_info_json_exposes_manifest_approval_modes() {
        let ops = operations_info();
        let tool_call_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|op| op["id"].as_str() == Some(OP_TOOLS_CALL))
            .unwrap();
        let sampling_handle_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|op| op["id"].as_str() == Some(OP_SAMPLING_HANDLE))
            .unwrap();

        assert_eq!(tool_call_op["requires_approval"], "policy");
        assert_eq!(sampling_handle_op["requires_approval"], "policy");
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(op.get("id").is_some(), "missing id");
            assert!(op.get("summary").is_some(), "missing summary");
            assert!(op.get("capability").is_some(), "missing capability");
            assert!(op.get("risk_level").is_some(), "missing risk_level");
            assert!(op.get("safety_tier").is_some(), "missing safety_tier");
        }
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_risk_levels_valid() {
        let valid = ["low", "medium", "high"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".read") {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "read op {} should be safe",
                    op["id"]
                );
                assert_eq!(
                    op["risk_level"].as_str().unwrap(),
                    "low",
                    "read op {} should be low risk",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        assert!(ids.contains(&"mcp.tools.list"));
        assert!(ids.contains(&"mcp.tools.call"));
        assert!(ids.contains(&"mcp.resources.list"));
        assert!(ids.contains(&"mcp.resources.read"));
        assert!(ids.contains(&"mcp.prompts.list"));
        assert!(ids.contains(&"mcp.sampling.handle"));
        assert!(ids.contains(&"mcp.server.metrics"));
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(
                op.get("idempotency").is_some(),
                "op {:?} missing idempotency",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_tools_call_is_risky() {
        let ops = operations_info();
        let call_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mcp.tools.call")
            .unwrap();
        assert_eq!(call_op["safety_tier"], "risky");
        assert_eq!(call_op["risk_level"], "high");
    }

    #[test]
    fn operations_tools_list_capability() {
        let ops = operations_info();
        let list_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mcp.tools.list")
            .unwrap();
        assert_eq!(list_op["capability"], "mcp.tools.read");
    }

    #[test]
    fn operations_tools_call_has_no_idempotency() {
        let ops = operations_info();
        let call_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mcp.tools.call")
            .unwrap();
        assert_eq!(call_op["idempotency"], "none");
    }

    #[test]
    fn operations_tools_call_requires_policy_approval() {
        let ops = operations_info();
        let call_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mcp.tools.call")
            .unwrap();
        assert_eq!(call_op["requires_approval"], "policy");
    }

    #[test]
    fn doctor_result_healthy_when_all_pass() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_degraded_when_non_critical_fails() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("warn".into()),
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_result_unhealthy_when_critical_fails() {
        let checks = vec![DoctorCheck {
            name: "config".into(),
            passed: false,
            message: Some("not configured".into()),
            critical: true,
        }];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_serializes() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "healthy");
        assert!(v["checks"][0]["message"].is_null());
    }

    #[test]
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("fail a".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("fail b".into()),
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 2);
    }

    #[test]
    fn connector_default() {
        let c = McpBridgeConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_no_config() {
        let c = McpBridgeConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[test]
    fn connector_new_zero_counters() {
        let c = McpBridgeConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn doctor_status_serde_roundtrip_healthy() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_status_serde_roundtrip_degraded() {
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_status_serde_roundtrip_unhealthy() {
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy() {
        let s = DoctorStatus::Healthy;
        let copied = s;
        assert_eq!(s, copied);
    }

    #[test]
    fn doctor_status_debug() {
        let dbg = format!("{:?}", DoctorStatus::Degraded);
        assert!(dbg.contains("Degraded"));
    }

    #[test]
    fn doctor_result_deserializes() {
        let v = json!({
            "status": "unhealthy",
            "checks": [
                {"name": "config", "passed": false, "message": "fail", "critical": true}
            ]
        });
        let r: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 1);
    }

    #[test]
    fn doctor_check_deserializes() {
        let v = json!({"name": "test", "passed": true, "critical": false});
        let c: DoctorCheck = serde_json::from_value(v).unwrap();
        assert_eq!(c.name, "test");
        assert!(c.passed);
        assert!(c.message.is_none());
    }

    #[test]
    fn doctor_check_clone() {
        let c = DoctorCheck {
            name: "cfg".into(),
            passed: true,
            message: Some("ok".into()),
            critical: true,
        };
        let cloned = DoctorCheck::clone(&c);
        assert_eq!(cloned.name, "cfg");
        assert_eq!(cloned.message, Some("ok".into()));
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = DoctorResult::clone(&r);
        assert_eq!(cloned.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
    }

    #[test]
    fn require_str_with_empty_string() {
        let input = json!({"name": ""});
        assert_eq!(require_str(&input, "name").unwrap(), "");
    }

    #[test]
    fn require_str_with_object_value() {
        let input = json!({"name": {"nested": true}});
        assert!(require_str(&input, "name").is_err());
    }

    #[test]
    fn operations_summaries_non_empty() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {} has empty summary", op["id"]);
        }
    }

    #[test]
    fn operations_resources_read_capability() {
        let ops = operations_info();
        let r_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mcp.resources.read")
            .unwrap();
        assert_eq!(r_op["capability"], "mcp.resources.read");
    }

    #[test]
    fn operations_prompts_list_capability() {
        let ops = operations_info();
        let p_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "mcp.prompts.list")
            .unwrap();
        assert_eq!(p_op["capability"], "mcp.prompts.read");
    }

    #[test]
    fn doctor_check_serializes_without_message_when_none() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_check_serializes_with_message_when_some() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failed".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "failed");
    }

    #[test]
    fn config_rejects_boolean_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({ "mcp_url": true }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_array_mcp_url() {
        let result = McpBridgeConfig::from_params(&json!({ "mcp_url": [1, 2, 3] }));
        assert!(result.is_err());
    }

    // -- Provisioning recipe tests -----------------------------------------------

    #[test]
    fn provisioning_recipe_has_3_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "mcp-bridge.host_credential");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 3);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "enter_server_id");
        assert_eq!(recipe.steps[1].id.as_str(), "enter_mcp_endpoint");
        assert_eq!(recipe.steps[2].id.as_str(), "enter_credential_id");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "enter_server_id");
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "enter_mcp_endpoint");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "mcp-bridge.host_credential");
        assert_eq!(v["steps"].as_array().unwrap().len(), 3);
        let serialized = v.to_string();
        assert!(!serialized.contains("prompt_secret"));
        assert!(!serialized.contains("store_secret"));
        assert!(!serialized.contains("api_key"));
    }

    #[test]
    fn provisioning_recipe_description_non_empty() {
        let recipe = provisioning_recipe();
        assert!(!recipe.description.is_empty());
    }

    #[test]
    fn provisioning_recipe_step1_is_prompt_user() {
        let recipe = provisioning_recipe();
        assert!(matches!(
            recipe.steps[0].kind,
            ProvisioningStepType::PromptUser { .. }
        ));
    }

    #[test]
    fn provisioning_recipe_step2_is_endpoint_prompt() {
        let recipe = provisioning_recipe();
        assert!(matches!(
            recipe.steps[1].kind,
            ProvisioningStepType::PromptUser { .. }
        ));
    }

    #[test]
    fn provisioning_recipe_step3_is_credential_reference_prompt() {
        let recipe = provisioning_recipe();
        assert!(matches!(
            recipe.steps[2].kind,
            ProvisioningStepType::PromptUser { .. }
        ));
    }

    #[test]
    fn provisioning_recipe_prompts_for_canonical_metadata_only() {
        let recipe = provisioning_recipe();
        let messages: Vec<_> = recipe
            .steps
            .iter()
            .filter_map(|step| match &step.kind {
                ProvisioningStepType::PromptUser { message } => Some(message.as_str()),
                _ => None,
            })
            .collect();
        assert!(messages.iter().any(|message| message.contains("server_id")));
        assert!(messages.iter().any(|message| message.contains("/mcp")));
        assert!(
            messages
                .iter()
                .any(|message| message.contains("credential_id"))
        );
    }

    #[test]
    fn provisioning_recipe_no_approval_required() {
        let recipe = provisioning_recipe();
        for step in &recipe.steps {
            assert!(!step.requires_approval);
        }
    }

    // -- base_url_policy tests ---------------------------------------------------

    #[test]
    fn base_url_policy_accepts_https() {
        let (ok, message) = base_url_policy("https://mcp.example.com/mcp");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_official_n8n_endpoint() {
        let (ok, message) = base_url_policy("https://n8n.example.com/mcp-server/http/");
        assert!(ok);
        assert!(message.contains("/mcp-server/http"));
    }

    #[test]
    fn base_url_policy_rejects_remote_http() {
        let (ok, message) = base_url_policy("http://mcp.example.com");
        assert!(!ok);
        assert!(!message.is_empty());
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:3000/mcp");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_127_0_0_1() {
        let (ok, _) = base_url_policy("http://127.0.0.1:9090/mcp");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_any_host() {
        let (ok, _) = base_url_policy("https://any-host.example.org/mcp");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(!message.is_empty());
    }

    #[test]
    fn base_url_policy_rejects_ftp_scheme() {
        let (ok, message) = base_url_policy("ftp://files.example.com/data");
        assert!(!ok);
        assert!(!message.is_empty());
    }

    #[test]
    fn base_url_policy_rejects_empty() {
        let (ok, _) = base_url_policy("");
        assert!(!ok);
    }

    #[test]
    fn base_url_policy_accepts_ipv6() {
        let (ok, _) = base_url_policy("http://[::1]:8080/mcp");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_non_mcp_path() {
        let (ok, _) = base_url_policy("https://mcp.example.com/api/v2");
        assert!(!ok);
    }

    // -- ProvisioningReadiness tests ---------------------------------------------

    #[test]
    fn provisioning_readiness_with_api_key() {
        let config = McpBridgeConfig::from_params(&json!({
            "server_id": "mcp-test",
            "mcp_url": "http://localhost:3000/mcp",
            "api_key": "test-key",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "api_key");
        assert!(readiness.api_key_configured);
        assert!(readiness.network_ok);
        assert_eq!(readiness.mcp_url, "http://localhost:3000/mcp");
    }

    #[test]
    fn provisioning_readiness_without_api_key() {
        let config = McpBridgeConfig::from_params(&json!({
            "server_id": "mcp-test",
            "mcp_url": "http://localhost:3000/mcp",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "none");
        assert!(!readiness.api_key_configured);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = McpBridgeConfig::from_params(&json!({
            "server_id": "mcp-test",
            "mcp_url": "https://mcp.example.com/mcp",
            "api_key": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "api_key");
        assert_eq!(v["api_key_configured"], true);
        assert_eq!(v["network_ok"], true);
        assert_eq!(v["mcp_url"], "https://mcp.example.com/mcp");
    }

    #[test]
    fn provisioning_readiness_network_message_contains_accepted() {
        let config = McpBridgeConfig::from_params(&json!({
            "server_id": "mcp-test",
            "mcp_url": "https://mcp.example.com/mcp",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_message.contains("accepted"));
    }

    #[test]
    fn config_defaults_security_warn_and_sampling_disabled() {
        let config = McpBridgeConfig::from_params(&json!({
            "server_id": "mcp-test",
            "mcp_url": "http://localhost:3000/mcp",
        }))
        .unwrap();
        assert_eq!(config.description_scan, DescriptionScanMode::Warn);
        assert!(!config.sampling.enabled);
        assert_eq!(config.sampling.max_tokens_cap, 4096);
    }

    fn policy_params(server_id: &str, approved_tools: serde_json::Value) -> serde_json::Value {
        json!({
            "server_id": server_id,
            "mcp_url": "http://localhost:3000/mcp",
            "api_key": "test-api-key",
            "capability_policy": {
                "n8n_version": "1.0.0",
                "auth_mode": "access_token",
                "api_scope_digest": "scope-digest",
                "approved_tools": approved_tools,
            },
        })
    }

    fn policy_tool(
        name: &str,
        class: &str,
        input_schema_digest: &str,
        output_schema_digest: &str,
    ) -> serde_json::Value {
        json!({
            "name": name,
            "class": class,
            "input_schema_digest": input_schema_digest,
            "output_schema_digest": output_schema_digest,
        })
    }

    fn schema_digests(
        input_schema: &serde_json::Value,
        output_schema: &serde_json::Value,
    ) -> (String, String) {
        let observation = ToolObservation::from_schemas(
            "digest-probe",
            input_schema,
            output_schema,
            ToolClass::Read,
        )
        .unwrap();
        let snapshot = CapabilitySnapshot::from_observations(
            ServerId::Eec,
            "1.0.0",
            ProtocolEra::Modern,
            vec![ProtocolVersion::V20260728],
            AuthMode::AccessToken,
            "scope-digest",
            vec![observation],
            None,
        )
        .unwrap();
        let tool = &snapshot.tools[0];
        (
            tool.input_schema_digest.clone(),
            tool.output_schema_digest.clone(),
        )
    }

    #[test]
    fn capability_policy_parses_provider_identity_and_auth_mode() {
        let eec = McpBridgeConfig::from_params(&policy_params("eec", json!([]))).unwrap();
        let hetzner = McpBridgeConfig::from_params(&policy_params("hetzner", json!([]))).unwrap();
        assert_eq!(
            eec.capability_policy.as_ref().unwrap().server_id,
            ServerId::Eec
        );
        assert_eq!(
            hetzner.capability_policy.as_ref().unwrap().server_id,
            ServerId::Hetzner
        );
        assert_ne!(
            eec.capability_policy.as_ref().unwrap().server_id,
            hetzner.capability_policy.as_ref().unwrap().server_id
        );
        assert_eq!(
            eec.capability_policy.as_ref().unwrap().auth_mode,
            AuthMode::AccessToken
        );
    }

    #[test]
    fn capability_policy_accepts_direct_api_key_access_token() {
        let config = McpBridgeConfig::from_params(&policy_params("eec", json!([]))).unwrap();
        assert!(config.auth.api_key.is_some());
        assert_eq!(
            config.capability_policy.as_ref().unwrap().auth_mode,
            AuthMode::AccessToken
        );
    }

    #[test]
    fn capability_policy_rejects_direct_api_key_oauth() {
        let mut params = policy_params("eec", json!([]));
        params["capability_policy"]["auth_mode"] = json!("oauth");
        assert!(McpBridgeConfig::from_params(&params).is_err());
    }

    #[test]
    fn capability_policy_requires_configured_auth() {
        let mut params = policy_params("eec", json!([]));
        params
            .as_object_mut()
            .expect("test parameters object")
            .remove("api_key");
        assert!(McpBridgeConfig::from_params(&params).is_err());
    }

    #[test]
    fn capability_policy_accepts_credential_id_with_either_declared_mode() {
        for auth_mode in ["oauth", "access_token"] {
            let mut params = policy_params("eec", json!([]));
            let object = params.as_object_mut().expect("test parameters object");
            object.remove("api_key");
            object.insert(
                "credential_id".into(),
                json!(CredentialId::new().to_string()),
            );
            params["capability_policy"]["auth_mode"] = json!(auth_mode);
            assert!(
                McpBridgeConfig::from_params(&params).is_ok(),
                "credential_id should accept {auth_mode} policy metadata"
            );
        }
    }

    #[test]
    fn capability_policy_rejects_unsupported_identity_and_malformed_values() {
        assert!(McpBridgeConfig::from_params(&policy_params("mcp-test", json!([]))).is_err());
        let mut invalid_auth = policy_params("eec", json!([]));
        invalid_auth["capability_policy"]["auth_mode"] = json!("bearer");
        assert!(McpBridgeConfig::from_params(&invalid_auth).is_err());
        let invalid_class = policy_params(
            "eec",
            json!([policy_tool("read", "unknown", "input", "output")]),
        );
        assert!(McpBridgeConfig::from_params(&invalid_class).is_err());
        let duplicate = policy_params(
            "eec",
            json!([
                policy_tool("read", "read", "input", "output"),
                policy_tool("read", "read", "input", "output")
            ]),
        );
        assert!(McpBridgeConfig::from_params(&duplicate).is_err());
        let oversized = policy_params(
            "eec",
            serde_json::Value::Array(
                (0..=MAX_TOOL_COUNT)
                    .map(|index| policy_tool(&format!("tool-{index}"), "read", "input", "output"))
                    .collect(),
            ),
        );
        assert!(McpBridgeConfig::from_params(&oversized).is_err());
    }

    #[test]
    fn archive_policy_requires_exact_owner_schema_binding() {
        let input_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let output_digest =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let archive = policy_tool("archive_workflow", "write", input_digest, output_digest);
        let mut valid = policy_params("eec", json!([archive.clone()]));
        valid["capability_policy"]["archive_workflow_schema"] = json!({
            "input_schema_digest": input_digest,
            "output_schema_digest": output_digest,
        });
        let config = McpBridgeConfig::from_params(&valid).expect("exact archive binding");
        let binding = config
            .capability_policy
            .as_ref()
            .and_then(|policy| policy.archive_workflow_schema.as_ref())
            .expect("archive schema binding");
        assert_eq!(binding.input_schema_digest, input_digest);
        assert_eq!(binding.output_schema_digest, output_digest);

        let missing = policy_params("eec", json!([archive.clone()]));
        assert!(McpBridgeConfig::from_params(&missing).is_err());

        let mut mismatched = valid;
        mismatched["capability_policy"]["archive_workflow_schema"]["output_schema_digest"] =
            json!("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        assert!(McpBridgeConfig::from_params(&mismatched).is_err());
        mismatched["capability_policy"]["archive_workflow_schema"] = json!({
            "input_schema_digest": input_digest,
            "output_schema_digest": output_digest,
        });
        mismatched["capability_policy"]["approved_tools"][0]["input_schema_digest"] =
            json!("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        assert!(McpBridgeConfig::from_params(&mismatched).is_err());
    }

    #[test]
    fn execute_policy_requires_exact_owner_schema_binding() {
        let input_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let output_digest =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let execute = policy_tool("execute_workflow", "write", input_digest, output_digest);
        let mut valid = policy_params("eec", json!([execute.clone()]));
        valid["capability_policy"]["execute_workflow_schema"] = json!({
            "status": "owner_provisioned",
            "input_schema_digest": input_digest,
            "output_schema_digest": output_digest,
        });
        let config = McpBridgeConfig::from_params(&valid).expect("exact execute binding");
        let binding = config
            .capability_policy
            .as_ref()
            .and_then(|policy| policy.execute_workflow_schema.as_ref())
            .expect("execute schema binding");
        assert_eq!(binding.status, "owner_provisioned");
        assert_eq!(binding.input_schema_digest.as_deref(), Some(input_digest));
        assert_eq!(binding.output_schema_digest.as_deref(), Some(output_digest));

        let missing = policy_params("eec", json!([execute.clone()]));
        assert!(McpBridgeConfig::from_params(&missing).is_err());

        let mut mismatched = valid;
        mismatched["capability_policy"]["execute_workflow_schema"]["output_schema_digest"] =
            json!("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        assert!(McpBridgeConfig::from_params(&mismatched).is_err());

        let mut sentinel = policy_params("eec", json!([]));
        sentinel["capability_policy"]["execute_workflow_schema"] = json!({
            "status": "unavailable_unproven_schema",
            "input_schema_digest": null,
            "output_schema_digest": null,
        });
        let sentinel_config =
            McpBridgeConfig::from_params(&sentinel).expect("sentinel execute binding");
        let sentinel_binding = sentinel_config
            .capability_policy
            .as_ref()
            .and_then(|policy| policy.execute_workflow_schema.as_ref())
            .expect("sentinel binding");
        assert_eq!(sentinel_binding.status, "unavailable_unproven_schema");
        assert!(sentinel_binding.input_schema_digest.is_none());
        assert!(sentinel_binding.output_schema_digest.is_none());
    }

    #[test]
    fn execute_policy_rejects_sentinel_with_approved_tool() {
        let execute = policy_tool(
            "execute_workflow",
            "write",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        let mut params = policy_params("eec", json!([execute]));
        params["capability_policy"]["execute_workflow_schema"] = json!({
            "status": "unavailable_unproven_schema",
            "input_schema_digest": null,
            "output_schema_digest": null,
        });
        assert!(McpBridgeConfig::from_params(&params).is_err());
    }

    #[test]
    fn capability_snapshot_exact_approval_and_unknown_classification() {
        let input_schema = json!({"type": "object"});
        let output_schema = serde_json::Value::Null;
        let (input_digest, output_digest) = schema_digests(&input_schema, &output_schema);
        let config = McpBridgeConfig::from_params(&policy_params(
            "eec",
            json!([policy_tool(
                "approved",
                "read",
                &input_digest,
                &output_digest
            )]),
        ))
        .unwrap();
        let policy = config.capability_policy.as_ref().unwrap();
        let snapshot = build_capability_snapshot(
            &json!({
                "tools": [
                    {"name": "approved", "inputSchema": input_schema, "outputSchema": null},
                    {"name": "unlisted", "description": "read this", "inputSchema": {"type": "object"}}
                ]
            }),
            policy,
            ProtocolEra::Modern,
            ProtocolVersion::V20260728,
        )
        .unwrap();
        assert_eq!(
            snapshot.tool_status("approved"),
            Some(crate::protocol::ToolStatus::Approved)
        );
        assert!(!snapshot.tool_call_is_blocked("approved"));
        assert_eq!(
            snapshot.tool_status("unlisted"),
            Some(crate::protocol::ToolStatus::Blocked)
        );
        assert!(snapshot.tool_call_is_blocked("unlisted"));
        assert_eq!(
            snapshot
                .tools
                .iter()
                .find(|tool| tool.name == "unlisted")
                .unwrap()
                .class,
            ToolClass::Unknown
        );
    }

    #[test]
    fn capability_snapshot_schema_drift_is_changed_and_blocked() {
        let original_input = json!({"type": "object"});
        let (input_digest, output_digest) =
            schema_digests(&original_input, &serde_json::Value::Null);
        let config = McpBridgeConfig::from_params(&policy_params(
            "eec",
            json!([policy_tool(
                "approved",
                "write",
                &input_digest,
                &output_digest
            )]),
        ))
        .unwrap();
        let snapshot = build_capability_snapshot(
            &json!({
                "tools": [{
                    "name": "approved",
                    "inputSchema": {"type": "array"},
                    "outputSchema": null
                }]
            }),
            config.capability_policy.as_ref().unwrap(),
            ProtocolEra::Modern,
            ProtocolVersion::V20260728,
        )
        .unwrap();
        assert_eq!(
            snapshot.tool_status("approved"),
            Some(crate::protocol::ToolStatus::Changed)
        );
        assert!(snapshot.tool_call_is_blocked("approved"));
    }

    #[test]
    fn archive_fresh_tools_list_requires_exact_owner_bound_digests() {
        let input_schema = json!({"type": "object", "required": ["workflowId"]});
        let output_schema = json!({"type": "object", "required": ["archived"]});
        let (input_digest, output_digest) = schema_digests(&input_schema, &output_schema);
        let archive = policy_tool("archive_workflow", "write", &input_digest, &output_digest);
        let mut params = policy_params("eec", json!([archive]));
        params["capability_policy"]["archive_workflow_schema"] = json!({
            "input_schema_digest": input_digest,
            "output_schema_digest": output_digest,
        });
        let config = McpBridgeConfig::from_params(&params).expect("exact archive policy");
        let policy = config.capability_policy.as_ref().expect("archive policy");
        let matching = build_capability_snapshot(
            &json!({
                "tools": [{
                    "name": "archive_workflow",
                    "inputSchema": input_schema,
                    "outputSchema": output_schema
                }]
            }),
            policy,
            ProtocolEra::Modern,
            ProtocolVersion::V20260728,
        )
        .expect("fresh matching tools/list");
        assert!(!matching.tool_call_is_blocked("archive_workflow"));

        let drifted = build_capability_snapshot(
            &json!({
                "tools": [{
                    "name": "archive_workflow",
                    "inputSchema": {"type": "array"},
                    "outputSchema": output_schema
                }]
            }),
            policy,
            ProtocolEra::Modern,
            ProtocolVersion::V20260728,
        )
        .expect("fresh drifted tools/list remains classifiable");
        assert!(drifted.tool_call_is_blocked("archive_workflow"));
    }

    #[test]
    fn capability_snapshot_rejects_duplicate_and_malformed_catalogs() {
        let config = McpBridgeConfig::from_params(&policy_params("eec", json!([]))).unwrap();
        let policy = config.capability_policy.as_ref().unwrap();
        assert!(
            build_capability_snapshot(
                &json!({"tools": [{"name": "same"}, {"name": "same"}]}),
                policy,
                ProtocolEra::Modern,
                ProtocolVersion::V20260728,
            )
            .is_err()
        );
        assert!(
            build_capability_snapshot(
                &json!({"tools": [{"name": "bad", "inputSchema": []}]}),
                policy,
                ProtocolEra::Modern,
                ProtocolVersion::V20260728,
            )
            .is_err()
        );
        assert!(
            build_capability_snapshot(
                &json!({"tools": [{"description": "missing name"}]}),
                policy,
                ProtocolEra::Modern,
                ProtocolVersion::V20260728,
            )
            .is_err()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_tools_call_is_conditionally_policy_gated_without_provider_io() {
        let connector = McpBridgeConnector::new();
        let denied = connector
            .handle_simulate(json!({"operation": OP_TOOLS_CALL}))
            .await
            .unwrap();
        assert_eq!(denied["allowed"], false);
        assert!(
            denied["reason"]
                .as_str()
                .unwrap()
                .contains("capability_policy")
        );

        let mut configured = McpBridgeConnector::new();
        configured
            .handle_configure(policy_params("eec", json!([])))
            .await
            .unwrap();
        let conditional = configured
            .handle_simulate(json!({"operation": OP_TOOLS_CALL}))
            .await
            .unwrap();
        assert_eq!(conditional["allowed"], true);
        assert!(
            conditional["reason"]
                .as_str()
                .unwrap()
                .contains("fresh capability discovery")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown_clears_capability_policy_and_client_state() {
        let mut connector = McpBridgeConnector::new();
        connector
            .handle_configure(policy_params("eec", json!([])))
            .await
            .unwrap();
        assert!(
            connector
                .config
                .as_ref()
                .and_then(|config| config.capability_policy.as_ref())
                .is_some()
        );
        connector.handle_shutdown(json!({})).await.unwrap();
        assert!(connector.config.is_none());
        assert!(connector.client.is_none());
    }

    #[test]
    fn config_accepts_nested_security_scan_mode() {
        let config = McpBridgeConfig::from_params(&json!({
            "server_id": "mcp-test",
            "mcp_url": "http://localhost:3000/mcp",
            "security": {"description_scan": "block"},
        }))
        .unwrap();
        assert_eq!(config.description_scan, DescriptionScanMode::Block);
    }

    #[test]
    fn config_rejects_invalid_security_scan_mode() {
        let result = McpBridgeConfig::from_params(&json!({
            "server_id": "mcp-test",
            "mcp_url": "http://localhost:3000/mcp",
            "description_scan": "audit",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_parses_sampling_settings() {
        let config = McpBridgeConfig::from_params(&json!({
            "server_id": "mcp-test",
            "mcp_url": "http://localhost:3000/mcp",
            "sampling": {
                "enabled": true,
                "llm_connector": "groq",
                "max_rpm": 7,
                "timeout_secs": 11,
                "max_tokens_cap": 512,
                "max_tool_rounds": 2,
                "model_override": "llama",
                "allowed_models": ["llama", "mixtral"]
            },
        }))
        .unwrap();
        assert!(config.sampling.enabled);
        assert_eq!(config.sampling.llm_connector.as_deref(), Some("groq"));
        assert_eq!(config.sampling.max_rpm, 7);
        assert_eq!(config.sampling.timeout_secs, 11);
        assert_eq!(config.sampling.max_tokens_cap, 512);
        assert_eq!(config.sampling.max_tool_rounds, 2);
        assert_eq!(config.sampling.model_override.as_deref(), Some("llama"));
        assert_eq!(config.sampling.allowed_models.len(), 2);
    }

    #[test]
    fn normalize_sampling_request_wraps_params() {
        let normalized = normalize_sampling_request(&json!({
            "messages": [],
            "maxTokens": 128
        }));
        assert_eq!(normalized["method"], "sampling/createMessage");
        assert_eq!(normalized["params"]["maxTokens"], 128);
    }

    #[test]
    fn normalize_sampling_request_preserves_request_envelope() {
        let normalized = normalize_sampling_request(&json!({
            "request": {
                "method": "sampling/createMessage",
                "params": {"messages": [], "maxTokens": 64}
            }
        }));
        assert_eq!(normalized["params"]["maxTokens"], 64);
    }

    // -- is_local_test_host tests ------------------------------------------------

    #[test]
    fn is_local_test_host_localhost() {
        assert!(is_local_test_host("localhost"));
    }

    #[test]
    fn is_local_test_host_127_0_0_1() {
        assert!(is_local_test_host("127.0.0.1"));
    }

    #[test]
    fn is_local_test_host_ipv6_loopback() {
        assert!(is_local_test_host("::1"));
    }

    #[test]
    fn is_local_test_host_rejects_remote() {
        assert!(!is_local_test_host("mcp.example.com"));
    }
}
