//! FCP n8n Connector implementation.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use fcp_manifest::HostEgressContext;
use fcp_prelude::{
    AgentHint, ApprovalMode, ApprovalScope, ApprovalToken, BaseConnector, CapabilityGrant,
    CapabilityId, CapabilityToken, CapabilityVerifier, ConnectorId, CredentialId, EventCaps,
    FcpError, FcpResult, HandshakeRequest, HandshakeResponse, IdempotencyClass, OperationId,
    OperationInfo, ProvisioningRecipe, ProvisioningStep, ProvisioningStepType, RecipeId, RiskLevel,
    SafetyTier, SelfCheckReport, SessionId, StepId, ZoneId,
};
use fcp_sdk::ConnectorRuntimeConfig;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{info, instrument};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

use crate::{
    client::{
        DEFAULT_LIST_LIMIT, ListQuery, MAX_CURSOR_BYTES, MAX_LIST_LIMIT, N8nAuth, N8nClient,
        sanitize_path_segment,
    },
    error::{N8nError, N8nResult},
    types::{
        ActiveVersionId, CredentialMetadataView, DraftMutationPrecondition, FolderListView,
        ListView, Workflow, WorkflowDetail, WorkflowDraftMutationInput, WorkflowGraphSummary,
        WorkflowLifecycleAction, WorkflowLifecycleInput, WorkflowStateView, WorkflowVersion,
    },
};

/// Parsed and validated n8n connector configuration.
#[derive(Debug, Clone)]
struct N8nConfig {
    auth: N8nAuth,
    base_url: String,
    server_id: String,
}

impl N8nConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let server_id = params
            .get("server_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required server_id (eec, hetzner, or legacy)".into(),
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

        let auth = match (api_key, credential_id) {
            (Some(key), None) => N8nAuth::ApiKey(key),
            (None, Some(cred_id)) => N8nAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_key or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key or credential_id in configuration".into(),
                });
            }
        };

        // n8n is self-hosted, so base_url is REQUIRED.
        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required base_url (n8n is self-hosted)".into(),
            })?;
        let base_url =
            N8nClient::canonicalize_base_url(base_url).map_err(|error| error.to_fcp_error())?;

        Ok(Self {
            auth,
            base_url,
            server_id: server_id.to_string(),
        })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                N8nAuth::ApiKey(_) => "api_key",
                N8nAuth::CredentialId(_) => "credential_id",
            },
            api_key_configured: matches!(&self.auth, N8nAuth::ApiKey(_)),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            base_url: self.base_url.clone(),
            server_id: self.server_id.clone(),
        }
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
    base_url: String,
    server_id: String,
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

const SERVER_IDS: [&str; 3] = ["eec", "hetzner", "legacy"];

#[derive(Debug, Clone)]
struct ActivationTarget {
    resource_uri: String,
    normalized_input: serde_json::Value,
}

#[derive(Debug, Clone)]
struct DraftWritePlan {
    workflow_id: Option<String>,
    graph_digest: String,
    provider_payload: Value,
}

const MAX_MCP_ACCESS_WORKFLOWS: usize = 1_000;
const MCP_ACCESS_LIST_LIMIT: u64 = 100;
const MCP_ACCESS_READBACK_DIGEST_DOMAIN_V2: &[u8] = b"fwc-n8n.mcp-access-readback.v2";
const MCP_ACCESS_RECEIPT_DIGEST_DOMAIN_V1: &[u8] = b"fwc-n8n.mcp-access-receipt.v1";
const MCP_ACCESS_RECEIPT_RESOURCE_DOMAIN_V1: &[u8] = b"fwc-n8n.mcp-access-resource.v1";
const MCP_ACCESS_RECEIPT_BINDING_DOMAIN_V1: &[u8] = b"fwc-n8n.mcp-access-binding.v1";
const MCP_ACCESS_RECEIPT_SCHEMA_V1: &str = "fwc.n8n.mcp-access-receipt.v1";
const MAX_MCP_ACCESS_RECEIPT_ITEMS: usize = MAX_MCP_ACCESS_WORKFLOWS;
const MAX_MCP_ACCESS_RECEIPT_BYTES: usize = 256 * 1024;
const MAX_MCP_ACCESS_RECEIPT_SERVER_ID_LENGTH: usize = 128;
const MAX_MCP_ACCESS_RECEIPT_SCOPE_LENGTH: usize = 32;
const MAX_MCP_ACCESS_RECEIPT_OUTCOME_LENGTH: usize = 96;
const MAX_MCP_ACCESS_RECEIPT_DIGEST_LENGTH: usize = 75;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum McpAccessScope {
    WorkflowIds,
    Project,
    Folder,
    AllCurrent,
}

impl McpAccessScope {
    const fn as_str(self) -> &'static str {
        match self {
            Self::WorkflowIds => "workflow_ids",
            Self::Project => "project",
            Self::Folder => "folder",
            Self::AllCurrent => "all_current",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct McpAccessReconcileGuard {
    #[serde(rename = "approvalRef")]
    approval_ref: String,
    #[serde(rename = "dryRunDigest")]
    dry_run_digest: String,
    #[serde(rename = "idempotencyKey")]
    idempotency_key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct McpAccessReconcileInput {
    scope: McpAccessScope,
    desired: bool,
    #[serde(rename = "dryRun")]
    dry_run: bool,
    #[serde(rename = "projectId")]
    project_id: Option<String>,
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    #[serde(rename = "workflowIds")]
    workflow_ids: Option<Vec<String>>,
    guard: Option<McpAccessReconcileGuard>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct McpAccessPlanItem {
    id: String,
    #[serde(rename = "availableInMCP")]
    available_in_mcp: Option<bool>,
    desired: bool,
    reason: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct McpAccessPlan {
    planned: Vec<McpAccessPlanItem>,
    changed: Vec<McpAccessPlanItem>,
    skipped: Vec<McpAccessPlanItem>,
    exceptions: Vec<McpAccessPlanItem>,
    #[serde(rename = "readbackDigest")]
    readback_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum McpAccessReceiptStatus {
    Planned,
    Applied,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct McpAccessReceiptItem {
    #[serde(rename = "resourceDigest")]
    resource_digest: String,
    #[serde(rename = "availableInMCP")]
    available_in_mcp: Option<bool>,
    desired: bool,
    outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// Redacted, deterministic result for one bounded reconciliation invocation.
///
/// This is intentionally a transient receipt contract. Durable ledger storage,
/// retention, and replay/readback persistence remain a separate host-owned
/// packet and are not implemented here.
struct McpAccessReceipt {
    schema: &'static str,
    operation: &'static str,
    #[serde(rename = "serverId")]
    server_id: String,
    scope: String,
    desired: bool,
    #[serde(rename = "dryRun")]
    dry_run: bool,
    status: McpAccessReceiptStatus,
    #[serde(rename = "planDigest")]
    plan_digest: String,
    #[serde(rename = "readbackDigest")]
    readback_digest: String,
    #[serde(rename = "approvalDigest", skip_serializing_if = "Option::is_none")]
    approval_digest: Option<String>,
    #[serde(rename = "idempotencyDigest", skip_serializing_if = "Option::is_none")]
    idempotency_digest: Option<String>,
    items: Vec<McpAccessReceiptItem>,
    #[serde(rename = "receiptDigest")]
    receipt_digest: String,
}

#[derive(Debug, Clone, Serialize)]
struct McpAccessResult {
    #[serde(flatten)]
    plan: McpAccessPlan,
    receipt: McpAccessReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct McpAccessInvariant {
    id: String,
    name: Option<String>,
    description: Option<String>,
    project_id: Option<String>,
    folder_id: Option<String>,
    version_id: String,
    active: bool,
    active_version_id: Option<String>,
    is_archived: bool,
    draft: WorkflowGraphSummary,
    published: Option<WorkflowGraphSummary>,
}

struct McpAccessLockGuard {
    locks: Arc<Mutex<BTreeSet<String>>>,
    key: String,
}

impl Drop for McpAccessLockGuard {
    fn drop(&mut self) {
        if let Ok(mut locks) = self.locks.lock() {
            locks.remove(&self.key);
        }
    }
}

#[derive(Debug, Clone)]
struct DraftBaseline {
    state: WorkflowStateView,
    name: Option<String>,
    settings: Option<Value>,
    static_data: Option<Value>,
    pin_data: Option<Value>,
}

struct HostRequestAttribution {
    request_id: String,
    correlation_id: Option<String>,
}

fn host_request_attribution(params: &Value) -> FcpResult<Option<HostRequestAttribution>> {
    let correlation_id = match params.get("correlation_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(
            uuid::Uuid::parse_str(value)
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

/// FCP n8n Connector.
pub struct N8nConnector {
    base: Arc<BaseConnector>,
    config: Option<N8nConfig>,
    client: Option<Arc<N8nClient>>,
    verifier: Option<CapabilityVerifier>,
    zone_id: Option<ZoneId>,
    session_id: Option<SessionId>,
    runtime_config: ConnectorRuntimeConfig,
    request_count: AtomicU64,
    error_count: AtomicU64,
    mcp_access_locks: Arc<Mutex<BTreeSet<String>>>,
}

impl N8nConnector {
    /// Create a new n8n connector without reading process environment.
    ///
    /// This compatibility constructor is intended for tests and callers that
    /// provide trusted runtime configuration separately. The production binary
    /// uses [`Self::try_new`] so malformed host-launch values fail closed.
    pub fn new() -> Self {
        Self::new_with_runtime_config(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(std::time::Duration::from_secs(30)),
        )
    }

    /// Create a connector from the fail-closed production host-launch loader.
    ///
    /// # Errors
    /// Returns one static redaction-safe error when host-launch transport
    /// variables are incomplete, conflicting, invalid, or unsupported.
    pub fn try_new() -> N8nResult<Self> {
        let runtime_config = ConnectorRuntimeConfig::default()
            .with_request_timeout(std::time::Duration::from_secs(30))
            .with_host_egress_from_env()
            .map_err(|_| {
                N8nError::InvalidInput("invalid host egress launch configuration".into())
            })?;
        Ok(Self::new_with_runtime_config(runtime_config))
    }

    /// Create a connector with trusted host-supplied runtime configuration.
    pub fn new_with_runtime_config(runtime_config: ConnectorRuntimeConfig) -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("n8n"))),
            config: None,
            client: None,
            verifier: None,
            zone_id: None,
            session_id: None,
            runtime_config,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            mcp_access_locks: Arc::new(Mutex::new(BTreeSet::new())),
        }
    }
}

impl Default for N8nConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl N8nConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = N8nConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring n8n connector");

        let client = N8nClient::new_with_runtime_config(
            config.auth.clone(),
            &config.base_url,
            self.runtime_config.clone(),
        )
        .map_err(|e| e.to_fcp_error())?;

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
                Some("API client not initialized".into())
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
                "API client not initialized; re-run configure",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        };

        let probe = match client.self_check().await {
            Ok(()) => {
                let mut report = SelfCheckReport::ok();
                report.details = Some(json!({
                    "provisioning": readiness,
                    "probe": "GET /workflows?limit=1",
                }));
                report
            }
            Err(error) => {
                let mut report =
                    SelfCheckReport::failed("provider_probe_failed", error.safe_summary());
                report.details = Some(json!({
                    "provisioning": readiness,
                    "probe": "GET /workflows?limit=1",
                }));
                report
            }
        };
        Self::serialize_self_check_report(probe)
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let ops = serde_json::to_value(operations_info()).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize operations: {e}"),
        })?;
        Ok(json!({
            "connector_id": "fcp.n8n",
            "version": "0.1.0",
            "operations": ops,
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;

        let operation = params
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));
        validate_operation_input(operation, &input).map_err(|error| error.to_fcp_error())?;
        let host_attribution = host_request_attribution(&params)?;

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
        let mediated_token = token.clone();
        verifier.verify_bound(token, &capability, &operation_id, &resources)?;
        let [canonical_resource] = resources.as_slice() else {
            return Err(FcpError::Internal {
                message: "Verified invocation must resolve exactly one canonical resource".into(),
            });
        };

        let activation_target = if operation == "n8n.workflows.activate" {
            Some(self.activation_target(&input, &resources)?)
        } else {
            None
        };
        if let Some(target) = &activation_target {
            self.require_execution_approval(operation, target, &params)?;
        }

        let draft_plan = if matches!(
            operation,
            "n8n.workflows.create_draft" | "n8n.workflows.update_draft"
        ) {
            let plan = Self::prepare_draft_write(operation, &input)?;
            self.require_draft_approval(operation, &input, &params)?;
            Some(plan)
        } else {
            None
        };

        if operation == "n8n.workflows.lifecycle" {
            let lifecycle =
                parse_workflow_lifecycle_input(&input).map_err(|error| error.to_fcp_error())?;
            self.require_workflow_lifecycle_approval(&lifecycle, &input, &params)?;
        }

        if operation == "n8n.workflows.activate" {
            return Err(FcpError::CapabilityDenied {
                capability: "n8n.workflows.write".into(),
                reason: "workflow activation lifecycle is deferred to the mediated n8n write path"
                    .into(),
            });
        }

        if operation == "n8n.mcp_access.reconcile" {
            let reconcile = parse_mcp_access_input(&input).map_err(|error| error.to_fcp_error())?;
            if !reconcile.dry_run {
                self.require_mcp_access_approval(&reconcile, &input, &params)?;
            }
        }

        let request_number = self.request_count.fetch_add(1, Ordering::Relaxed) + 1;

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;
        let context = self.host_egress_context(
            operation,
            canonical_resource,
            &mediated_token,
            request_number,
            host_attribution.as_ref(),
        )?;

        let result = match operation {
            "n8n.workflows.list" => {
                self.invoke_workflows_list(client, &input, Some(context.clone()))
                    .await
            }
            "n8n.workflows.get" => {
                self.invoke_workflows_get(client, &input, Some(context.clone()))
                    .await
            }
            "n8n.executions.list" => {
                self.invoke_executions_list(client, &input, Some(context.clone()))
                    .await
            }
            "n8n.executions.get" => {
                self.invoke_executions_get(client, &input, Some(context.clone()))
                    .await
            }
            "n8n.projects.list" => {
                self.invoke_projects_list(client, &input, Some(context.clone()))
                    .await
            }
            "n8n.credentials.list" => {
                self.invoke_credentials_list(client, &input, Some(context.clone()))
                    .await
            }
            "n8n.tags.list" => {
                self.invoke_tags_list(client, &input, Some(context.clone()))
                    .await
            }
            "n8n.folders.list" => {
                self.invoke_folders_list(client, &input, Some(context.clone()))
                    .await
            }
            "n8n.folders.get" => self.invoke_folders_get(client, &input, Some(context)).await,
            "n8n.mcp_access.reconcile" => {
                self.invoke_mcp_access_reconcile(client, &input, Some(context))
                    .await
            }
            "n8n.workflows.create_draft" | "n8n.workflows.update_draft" => {
                self.invoke_workflow_draft_write(
                    client,
                    operation,
                    &input,
                    draft_plan.as_ref().ok_or(FcpError::Internal {
                        message: "draft write plan was not prepared".into(),
                    })?,
                    Some(context),
                )
                .await
            }
            "n8n.workflows.lifecycle" => {
                self.invoke_workflow_lifecycle(client, &input, Some(context))
                    .await
            }
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

        let allowed = operations_info().iter().any(|o| o.id.as_ref() == operation);

        Ok(json!({
            "allowed": allowed,
            "reason": if allowed { "Operation supported" } else { "Unknown operation" },
        }))
    }

    /// Handle the `shutdown` method.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("n8n connector shutting down");
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

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "n8n.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "n8n self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    // -- Operation implementations --

    async fn invoke_workflows_list(
        &self,
        client: &N8nClient,
        input: &serde_json::Value,
        context: Option<HostEgressContext>,
    ) -> Result<serde_json::Value, N8nError> {
        let query = parse_list_query(input)?;
        let resp = client.list_workflows_typed(&query, context).await?;
        let data = resp
            .data
            .into_iter()
            .map(|workflow| workflow.into_view())
            .collect::<Vec<_>>();
        serde_json::to_value(ListView {
            data,
            next_cursor: resp.next_cursor,
        })
        .map_err(N8nError::from)
    }

    async fn invoke_mcp_access_reconcile(
        &self,
        client: &N8nClient,
        input: &Value,
        context: Option<HostEgressContext>,
    ) -> Result<Value, N8nError> {
        let reconcile = parse_mcp_access_input(input)?;
        let server_id = self.configured_server_id()?;
        let workflows = if reconcile.scope == McpAccessScope::WorkflowIds {
            let ids = reconcile
                .workflow_ids
                .as_ref()
                .ok_or(N8nError::MalformedProviderResponse)?;
            let mut workflows = Vec::with_capacity(ids.len());
            for id in ids {
                match client.get_workflow_typed(id, context.clone()).await {
                    Ok(workflow) if workflow.id == *id => {
                        workflows.push(workflow_summary_from_detail(workflow))
                    }
                    Ok(_) => return Err(N8nError::MalformedProviderResponse),
                    Err(N8nError::NotFound { .. }) => {}
                    Err(error) => return Err(error),
                }
            }
            workflows
        } else {
            self.list_mcp_access_workflows(client, context.clone())
                .await?
        };
        let plan = plan_mcp_access_reconcile(&reconcile, &workflows, server_id)?;
        if reconcile.dry_run {
            mcp_access_receipt_capacity_guard(
                &reconcile,
                server_id,
                &plan,
                &plan.readback_digest,
                None,
            )?;
            let receipt = McpAccessReceipt::from_plan(
                &reconcile,
                server_id,
                &plan,
                &plan.readback_digest,
                None,
            )?;
            return serde_json::to_value(McpAccessResult { plan, receipt }).map_err(N8nError::from);
        }

        let guard = reconcile
            .guard
            .as_ref()
            .ok_or(N8nError::MalformedProviderResponse)?;
        if guard.dry_run_digest != plan.readback_digest {
            return Err(N8nError::PreconditionFailed(
                "mcp access dry-run digest is stale",
            ));
        }

        // Validate a conservative terminal-outcome capacity before the first
        // provider write. Every planned item must become one terminal item;
        // the original planned entries are not included in apply receipts.
        mcp_access_receipt_capacity_guard(
            &reconcile,
            server_id,
            &plan,
            &guard.dry_run_digest,
            Some(guard),
        )?;

        let mut changed = Vec::new();
        let mut skipped = plan.skipped.clone();
        let mut exceptions = plan.exceptions.clone();
        for item in &plan.planned {
            let lock_key = format!("{server_id}:{}", item.id);
            let Some(_lock) = self.try_mcp_access_lock(lock_key)? else {
                exceptions.push(McpAccessPlanItem {
                    id: item.id.clone(),
                    available_in_mcp: item.available_in_mcp,
                    desired: reconcile.desired,
                    reason: "lock_conflict",
                });
                continue;
            };

            let baseline = match client.get_workflow_typed(&item.id, context.clone()).await {
                Ok(workflow) if workflow.id == item.id => workflow,
                Ok(_) => {
                    exceptions.push(mcp_access_exception(item, reconcile.desired, "id_mismatch"));
                    continue;
                }
                Err(error) => {
                    exceptions.push(mcp_access_exception(
                        item,
                        reconcile.desired,
                        mcp_access_error_reason(&error),
                    ));
                    continue;
                }
            };
            if baseline.is_archived {
                exceptions.push(mcp_access_exception(
                    item,
                    reconcile.desired,
                    "lifecycle_changed",
                ));
                continue;
            }
            if baseline.available_in_mcp() != item.available_in_mcp {
                exceptions.push(mcp_access_exception(
                    item,
                    reconcile.desired,
                    "state_changed_since_dry_run",
                ));
                continue;
            }
            if baseline.available_in_mcp() == Some(reconcile.desired) {
                skipped.push(McpAccessPlanItem {
                    id: item.id.clone(),
                    available_in_mcp: baseline.available_in_mcp(),
                    desired: reconcile.desired,
                    reason: "already_desired_on_recheck",
                });
                continue;
            }
            let baseline_invariant = match mcp_access_invariant(&baseline) {
                Ok(invariant) => invariant,
                Err(error) => {
                    exceptions.push(mcp_access_exception(
                        item,
                        reconcile.desired,
                        mcp_access_error_reason(&error),
                    ));
                    continue;
                }
            };

            if let Err(error) = client
                .update_workflow_mcp_access(&baseline, reconcile.desired, context.clone())
                .await
            {
                exceptions.push(mcp_access_exception(
                    item,
                    reconcile.desired,
                    mcp_access_error_reason(&error),
                ));
                continue;
            }

            let readback = match client.get_workflow_typed(&item.id, context.clone()).await {
                Ok(workflow) if workflow.id == item.id => workflow,
                Ok(_) => {
                    exceptions.push(mcp_access_exception(
                        item,
                        reconcile.desired,
                        "readback_id_mismatch",
                    ));
                    continue;
                }
                Err(_) => {
                    exceptions.push(mcp_access_exception(
                        item,
                        reconcile.desired,
                        "readback_unknown",
                    ));
                    continue;
                }
            };
            let Ok(readback_invariant) = mcp_access_invariant(&readback) else {
                exceptions.push(mcp_access_exception(
                    item,
                    reconcile.desired,
                    "readback_malformed",
                ));
                continue;
            };
            if readback.available_in_mcp() != Some(reconcile.desired) {
                exceptions.push(mcp_access_exception(
                    item,
                    reconcile.desired,
                    "readback_mismatch",
                ));
            } else if readback_invariant != baseline_invariant {
                exceptions.push(mcp_access_exception(
                    item,
                    reconcile.desired,
                    "readback_lifecycle_or_graph_mismatch",
                ));
            } else {
                changed.push(McpAccessPlanItem {
                    id: item.id.clone(),
                    available_in_mcp: readback.available_in_mcp(),
                    desired: reconcile.desired,
                    reason: "updated_and_verified",
                });
            }
        }

        let readback_digest = mcp_access_reconcile_digest(
            &reconcile,
            server_id,
            &plan.planned,
            &changed,
            &skipped,
            &exceptions,
        )?;
        let result_plan = McpAccessPlan {
            planned: plan.planned,
            changed,
            skipped,
            exceptions,
            readback_digest,
        };
        let receipt = McpAccessReceipt::from_plan(
            &reconcile,
            server_id,
            &result_plan,
            &guard.dry_run_digest,
            Some(guard),
        )?;
        serde_json::to_value(McpAccessResult {
            plan: result_plan,
            receipt,
        })
        .map_err(N8nError::from)
    }

    async fn list_mcp_access_workflows(
        &self,
        client: &N8nClient,
        context: Option<HostEgressContext>,
    ) -> Result<Vec<Workflow>, N8nError> {
        let mut workflows = Vec::new();
        let mut cursor = None;
        let mut seen_cursors = BTreeSet::new();
        loop {
            let query = ListQuery::new(MCP_ACCESS_LIST_LIMIT, cursor.clone())?;
            let page = client.list_workflows_typed(&query, context.clone()).await?;
            workflows.extend(page.data);
            if workflows.len() > MAX_MCP_ACCESS_WORKFLOWS {
                return Err(N8nError::InvalidInput(
                    "mcp access reconciliation exceeds the bounded workflow limit".into(),
                ));
            }
            let Some(next_cursor) = page.next_cursor else {
                break;
            };
            if !seen_cursors.insert(next_cursor.clone()) {
                return Err(N8nError::MalformedProviderResponse);
            }
            cursor = Some(next_cursor);
        }
        Ok(workflows)
    }

    fn try_mcp_access_lock(&self, key: String) -> Result<Option<McpAccessLockGuard>, N8nError> {
        let mut locks = self
            .mcp_access_locks
            .lock()
            .map_err(|_| N8nError::PreconditionFailed("mcp access lock is unavailable"))?;
        if !locks.insert(key.clone()) {
            return Ok(None);
        }
        drop(locks);
        Ok(Some(McpAccessLockGuard {
            locks: Arc::clone(&self.mcp_access_locks),
            key,
        }))
    }

    async fn invoke_workflows_get(
        &self,
        client: &N8nClient,
        input: &serde_json::Value,
        context: Option<HostEgressContext>,
    ) -> Result<serde_json::Value, N8nError> {
        let id = require_str(input, "id")?;
        let workflow = client.get_workflow_typed(id, context).await?;
        if workflow.id != id {
            return Err(N8nError::MalformedProviderResponse);
        }
        Ok(serde_json::to_value(normalize_workflow_state(workflow)?)?)
    }

    async fn invoke_workflow_draft_write(
        &self,
        client: &N8nClient,
        operation: &str,
        input: &Value,
        plan: &DraftWritePlan,
        context: Option<HostEgressContext>,
    ) -> Result<Value, N8nError> {
        let typed: WorkflowDraftMutationInput = serde_json::from_value(input.clone())
            .map_err(|_| N8nError::InvalidInput("invalid guarded workflow draft input".into()))?;
        let canonical_settings = canonical_draft_settings(operation, input)?;
        let settings_supplied = draft_settings_supplied(input);

        let (baseline, provider_payload) = if operation == "n8n.workflows.update_draft" {
            let workflow_id = plan
                .workflow_id
                .as_deref()
                .ok_or(N8nError::MalformedProviderResponse)?;
            let workflow = client
                .get_workflow_typed(workflow_id, context.clone())
                .await?;
            if workflow.id != workflow_id {
                return Err(N8nError::MalformedProviderResponse);
            }
            let state = normalize_workflow_state(workflow.clone())?;
            verify_draft_input_precondition(input, &state)?;
            let mut provider_payload = plan
                .provider_payload
                .as_object()
                .cloned()
                .ok_or(N8nError::MalformedProviderResponse)?;
            if !provider_payload.contains_key("name") {
                let name = workflow
                    .name
                    .clone()
                    .ok_or(N8nError::MalformedProviderResponse)?;
                provider_payload.insert("name".into(), Value::String(name));
            }
            if settings_supplied {
                let mut merged_settings = match workflow.settings.as_ref() {
                    None | Some(Value::Null) => serde_json::Map::new(),
                    Some(Value::Object(settings)) => settings.clone(),
                    Some(_) => return Err(N8nError::MalformedProviderResponse),
                };
                let Value::Object(requested_settings) = &canonical_settings else {
                    return Err(N8nError::MalformedProviderResponse);
                };
                merged_settings.extend(requested_settings.clone());
                provider_payload.insert("settings".into(), Value::Object(merged_settings));
            } else if !provider_payload.contains_key("settings") {
                if let Some(settings) = &workflow.settings {
                    provider_payload.insert("settings".into(), settings.clone());
                }
            }
            if !provider_payload.contains_key("staticData") {
                if let Some(static_data) = &workflow.static_data {
                    provider_payload.insert("staticData".into(), static_data.clone());
                }
            }
            if !provider_payload.contains_key("pinData") {
                if let Some(pin_data) = &workflow.pin_data {
                    provider_payload.insert("pinData".into(), pin_data.clone());
                }
            }
            (
                Some(DraftBaseline {
                    state,
                    name: workflow.name.clone(),
                    settings: workflow.settings.clone(),
                    static_data: workflow.static_data.clone(),
                    pin_data: workflow.pin_data,
                }),
                Value::Object(provider_payload),
            )
        } else {
            (None, plan.provider_payload.clone())
        };

        let workflow_id = match operation {
            "n8n.workflows.create_draft" => {
                client
                    .create_workflow_draft(&provider_payload, context.clone())
                    .await?
            }
            "n8n.workflows.update_draft" => {
                let workflow_id = plan
                    .workflow_id
                    .as_deref()
                    .ok_or(N8nError::MalformedProviderResponse)?;
                client
                    .update_workflow_draft(workflow_id, &provider_payload, context.clone())
                    .await?;
                workflow_id.to_owned()
            }
            _ => return Err(N8nError::InvalidInput("unsupported draft operation".into())),
        };

        let readback = client
            .get_workflow_typed(&workflow_id, context)
            .await
            .map_err(|_| N8nError::UnknownOutcome)?;
        if readback.id != workflow_id {
            return Err(N8nError::ReadbackMismatch);
        }
        let state = normalize_workflow_state(readback.clone())?;
        let expected_name = typed.name.as_deref().or_else(|| {
            baseline
                .as_ref()
                .and_then(|baseline| baseline.name.as_deref())
        });
        let expected_settings = if operation == "n8n.workflows.create_draft" || settings_supplied {
            provider_payload.get("settings")
        } else {
            baseline
                .as_ref()
                .and_then(|baseline| baseline.settings.as_ref())
        };
        let expected_static_data = typed.graph.static_data.as_ref().or_else(|| {
            baseline
                .as_ref()
                .and_then(|baseline| baseline.static_data.as_ref())
        });
        let expected_pin_data = typed.graph.pin_data.as_ref().or_else(|| {
            baseline
                .as_ref()
                .and_then(|baseline| baseline.pin_data.as_ref())
        });
        verify_draft_readback(
            operation,
            plan,
            baseline.as_ref(),
            &state,
            expected_name,
            expected_settings,
            expected_static_data,
            expected_pin_data,
            readback.settings.as_ref(),
            readback.static_data.as_ref(),
            readback.pin_data.as_ref(),
        )?;

        serde_json::to_value(json!({
            "status": "verified",
            "operation": operation,
            "provider": "rest",
            "lifecycle": "draft_only",
            "retry": "never_automatic",
            "readback": "independent_get",
            "id": state.id,
            "versionId": state.version_id,
            "graphDigest": state.draft.graph_digest,
            "stateDigest": state.state_digest,
            "active": state.active,
            "activeVersionId": state.active_version_id,
            "isArchived": state.is_archived,
            "published": state.published,
        }))
        .map_err(N8nError::from)
    }

    async fn invoke_workflow_lifecycle(
        &self,
        client: &N8nClient,
        input: &Value,
        context: Option<HostEgressContext>,
    ) -> Result<Value, N8nError> {
        let typed = parse_workflow_lifecycle_input(input)?;
        let baseline_workflow = client
            .get_workflow_typed(&typed.id, context.clone())
            .await?;
        if baseline_workflow.id != typed.id {
            return Err(N8nError::MalformedProviderResponse);
        }
        let baseline = normalize_workflow_state(baseline_workflow.clone())?;
        verify_workflow_lifecycle_precondition(
            &typed.guard.precondition,
            &baseline_workflow,
            &baseline,
        )?;
        if typed.action == WorkflowLifecycleAction::Publish && baseline.is_archived {
            return Err(N8nError::PreconditionFailed(
                "publishing an archived workflow would require an incidental restore",
            ));
        }

        let provider_workflow = match typed.action {
            WorkflowLifecycleAction::Publish => client
                .publish_workflow(&typed.id, typed.version_id.as_deref(), context.clone())
                .await
                .map_err(classify_lifecycle_attempt_error)?,
            WorkflowLifecycleAction::Unpublish => client
                .unpublish_workflow(&typed.id, context.clone())
                .await
                .map_err(classify_lifecycle_attempt_error)?,
        };
        if provider_workflow.id != typed.id {
            return Err(N8nError::UnknownOutcome);
        }
        let provider_state =
            normalize_workflow_state(provider_workflow).map_err(|_| N8nError::UnknownOutcome)?;

        let readback_workflow = client
            .get_workflow_typed(&typed.id, context)
            .await
            .map_err(|_| N8nError::UnknownOutcome)?;
        if readback_workflow.id != typed.id {
            return Err(N8nError::ReadbackMismatch);
        }
        let readback =
            normalize_workflow_state(readback_workflow).map_err(|_| N8nError::UnknownOutcome)?;

        verify_workflow_lifecycle_readback(
            typed.action,
            typed.version_id.as_deref(),
            &baseline,
            &provider_state,
            &readback,
        )?;

        serde_json::to_value(json!({
            "status": "verified",
            "operation": "n8n.workflows.lifecycle",
            "action": typed.action.as_str(),
            "provider": "rest",
            "retry": "never_automatic",
            "readback": "independent_get",
            "before": baseline,
            "after": readback,
        }))
        .map_err(N8nError::from)
    }

    async fn invoke_projects_list(
        &self,
        client: &N8nClient,
        input: &serde_json::Value,
        context: Option<HostEgressContext>,
    ) -> Result<serde_json::Value, N8nError> {
        let query = parse_list_query(input)?;
        let resp = client.list_projects_typed(&query, context).await?;
        let data = resp
            .data
            .into_iter()
            .map(|project| project.into_view())
            .collect::<Vec<_>>();
        serde_json::to_value(ListView {
            data,
            next_cursor: resp.next_cursor,
        })
        .map_err(N8nError::from)
    }

    async fn invoke_credentials_list(
        &self,
        client: &N8nClient,
        input: &serde_json::Value,
        context: Option<HostEgressContext>,
    ) -> Result<serde_json::Value, N8nError> {
        let query = parse_list_query(input)?;
        let resp = client.list_credentials_typed(&query, context).await?;
        let server_id = self.configured_server_id()?;
        let data = resp
            .data
            .into_iter()
            .map(|credential| {
                let resource_uri = credential_resource_uri(server_id, &credential.id)
                    .map_err(|_| N8nError::MalformedProviderResponse)?;
                Ok(credential.into_view(resource_uri))
            })
            .collect::<N8nResult<Vec<CredentialMetadataView>>>()?;
        serde_json::to_value(ListView {
            data,
            next_cursor: resp.next_cursor,
        })
        .map_err(N8nError::from)
    }

    fn host_egress_context(
        &self,
        operation: &str,
        resource_uri: &str,
        token: &CapabilityToken,
        request_number: u64,
        host_attribution: Option<&HostRequestAttribution>,
    ) -> FcpResult<HostEgressContext> {
        let zone_id = self.zone_id.as_ref().ok_or(FcpError::NotHandshaken)?;
        let session_id = self.session_id.as_ref().ok_or(FcpError::NotHandshaken)?;
        let token_cbor = token.raw().to_cbor().map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize verified capability token: {error}"),
        })?;
        let request_id = host_attribution.map_or_else(
            || format!("{session_id}:{request_number}"),
            |attribution| attribution.request_id.clone(),
        );
        let correlation_id =
            host_attribution.and_then(|attribution| attribution.correlation_id.clone());
        Ok(HostEgressContext {
            connector_id: "fcp.n8n".to_string(),
            operation_id: operation.to_string(),
            resource_uri: resource_uri.to_string(),
            zone_id: zone_id.to_string(),
            request_id,
            correlation_id,
            capability_token_cbor_b64: base64::engine::general_purpose::STANDARD.encode(token_cbor),
        })
    }

    async fn invoke_tags_list(
        &self,
        client: &N8nClient,
        input: &serde_json::Value,
        context: Option<HostEgressContext>,
    ) -> Result<serde_json::Value, N8nError> {
        let query = parse_list_query(input)?;
        let resp = client.list_tags_typed(&query, context).await?;
        let data = resp
            .data
            .into_iter()
            .map(|tag| tag.into_view())
            .collect::<Vec<_>>();
        serde_json::to_value(ListView {
            data,
            next_cursor: resp.next_cursor,
        })
        .map_err(N8nError::from)
    }

    async fn invoke_executions_list(
        &self,
        client: &N8nClient,
        input: &serde_json::Value,
        context: Option<HostEgressContext>,
    ) -> Result<serde_json::Value, N8nError> {
        let query = parse_list_query(input)?;
        let resp = client.list_executions_typed(&query, context).await?;
        let data = resp
            .data
            .into_iter()
            .map(|execution| execution.into_view())
            .collect::<Vec<_>>();
        serde_json::to_value(ListView {
            data,
            next_cursor: resp.next_cursor,
        })
        .map_err(N8nError::from)
    }

    async fn invoke_executions_get(
        &self,
        client: &N8nClient,
        input: &serde_json::Value,
        context: Option<HostEgressContext>,
    ) -> Result<serde_json::Value, N8nError> {
        let id = require_str(input, "id")?;
        let execution = client.get_execution_typed(id, context).await?;
        Ok(serde_json::to_value(execution.into_view())?)
    }

    async fn invoke_folders_list(
        &self,
        client: &N8nClient,
        input: &serde_json::Value,
        context: Option<HostEgressContext>,
    ) -> Result<serde_json::Value, N8nError> {
        let folder_input = parse_folder_list_input(input)?;
        let resp = client
            .list_folders_typed(
                folder_input.project_id,
                folder_input.parent_folder_id,
                folder_input.skip,
                folder_input.take,
                context,
            )
            .await?;
        let server_id = self.configured_server_id()?;
        let data = resp
            .data
            .into_iter()
            .map(|folder| {
                let resource_uri = folder_resource_uri(server_id, &folder.id)?;
                Ok(folder.into_view(resource_uri))
            })
            .collect::<N8nResult<Vec<_>>>()?;
        serde_json::to_value(FolderListView {
            count: resp.count,
            data,
        })
        .map_err(N8nError::from)
    }

    async fn invoke_folders_get(
        &self,
        client: &N8nClient,
        input: &serde_json::Value,
        context: Option<HostEgressContext>,
    ) -> Result<serde_json::Value, N8nError> {
        let folder_input = parse_folder_get_input(input)?;
        let folder = client
            .get_folder_typed(folder_input.project_id, folder_input.folder_id, context)
            .await?;
        if folder.id != folder_input.folder_id {
            return Err(N8nError::MalformedProviderResponse);
        }
        let resource_uri =
            folder_resource_uri(self.configured_server_id()?, folder_input.folder_id)?;
        Ok(serde_json::to_value(folder.into_view(resource_uri))?)
    }

    fn configured_server_id(&self) -> N8nResult<&str> {
        self.config
            .as_ref()
            .map(|config| config.server_id.as_str())
            .ok_or_else(|| N8nError::InvalidInput("connector is not configured".into()))
    }

    fn prepare_draft_write(operation: &str, input: &Value) -> FcpResult<DraftWritePlan> {
        let typed: WorkflowDraftMutationInput =
            serde_json::from_value(input.clone()).map_err(|_| FcpError::InvalidRequest {
                code: 1005,
                message: "Invalid guarded workflow draft input".into(),
            })?;
        validate_draft_input_presence(operation, input).map_err(|error| error.to_fcp_error())?;
        validate_draft_mutation(operation, &typed).map_err(|error| error.to_fcp_error())?;
        let canonical_settings =
            canonical_draft_settings(operation, input).map_err(|error| error.to_fcp_error())?;
        let graph_digest = workflow_graph_digest(&typed.graph.nodes, &typed.graph.connections)
            .map_err(|error| error.to_fcp_error())?;

        let mut provider_payload = serde_json::Map::new();
        if let Some(name) = typed.name.as_deref() {
            provider_payload.insert("name".into(), Value::String(name.to_owned()));
        }
        if let Some(project_id) = typed.project_id.as_deref() {
            provider_payload.insert("projectId".into(), Value::String(project_id.to_owned()));
        }
        if let Some(folder_id) = typed.parent_folder_id.as_deref() {
            provider_payload.insert("parentFolderId".into(), Value::String(folder_id.to_owned()));
        }
        provider_payload.insert("nodes".into(), Value::Array(typed.graph.nodes.clone()));
        provider_payload.insert("connections".into(), typed.graph.connections.clone());
        if operation == "n8n.workflows.create_draft" || draft_settings_supplied(input) {
            provider_payload.insert("settings".into(), canonical_settings);
        }
        if let Some(static_data) = &typed.graph.static_data {
            provider_payload.insert("staticData".into(), static_data.clone());
        }
        if let Some(pin_data) = &typed.graph.pin_data {
            provider_payload.insert("pinData".into(), pin_data.clone());
        }

        Ok(DraftWritePlan {
            workflow_id: typed.id,
            graph_digest,
            provider_payload: Value::Object(provider_payload),
        })
    }

    fn require_draft_approval(
        &self,
        operation: &str,
        input: &Value,
        params: &Value,
    ) -> FcpResult<()> {
        let typed: WorkflowDraftMutationInput =
            serde_json::from_value(input.clone()).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid guarded workflow draft input".into(),
            })?;
        let approval_values = params
            .get("approval_tokens")
            .and_then(Value::as_array)
            .ok_or_else(|| FcpError::CapabilityDenied {
                capability: "n8n.workflows.write".into(),
                reason: "draft mutation requires approval_tokens".into(),
            })?;
        let approvals: Vec<ApprovalToken> = approval_values
            .iter()
            .map(|value| serde_json::from_value(value.clone()))
            .collect::<Result<_, _>>()
            .map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid approval token".into(),
            })?;
        let matching = approvals
            .iter()
            .filter(|approval| {
                is_matching_draft_approval(
                    approval,
                    operation,
                    &typed.guard.approval_ref,
                    self.zone_id.as_ref(),
                    input,
                    current_time_ms(),
                )
            })
            .count();
        if matching != 1 {
            return Err(FcpError::CapabilityDenied {
                capability: "n8n.workflows.write".into(),
                reason: "draft mutation requires exactly one matching approval bound to resource, operation, version, graph, and expiry".into(),
            });
        }
        Ok(())
    }

    fn require_workflow_lifecycle_approval(
        &self,
        input: &WorkflowLifecycleInput,
        raw_input: &Value,
        params: &Value,
    ) -> FcpResult<()> {
        let approval_values = params
            .get("approval_tokens")
            .and_then(Value::as_array)
            .ok_or_else(|| FcpError::CapabilityDenied {
                capability: "n8n.workflows.lifecycle".into(),
                reason: "workflow lifecycle requires approval_tokens".into(),
            })?;
        let approvals: Vec<ApprovalToken> = approval_values
            .iter()
            .map(|value| serde_json::from_value(value.clone()))
            .collect::<Result<_, _>>()
            .map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid approval token".into(),
            })?;
        let matching = approvals
            .iter()
            .filter(|approval| {
                is_matching_draft_approval(
                    approval,
                    "n8n.workflows.lifecycle",
                    &input.guard.approval_ref,
                    self.zone_id.as_ref(),
                    raw_input,
                    current_time_ms(),
                )
            })
            .count();
        if matching != 1 {
            return Err(FcpError::CapabilityDenied {
                capability: "n8n.workflows.lifecycle".into(),
                reason: "workflow lifecycle requires exactly one matching approval bound to server, workflow, action, precondition, and expiry".into(),
            });
        }
        Ok(())
    }

    fn require_mcp_access_approval(
        &self,
        input: &McpAccessReconcileInput,
        raw_input: &Value,
        params: &Value,
    ) -> FcpResult<()> {
        let guard = input
            .guard
            .as_ref()
            .ok_or_else(|| FcpError::CapabilityDenied {
                capability: "n8n.mcp_access.write".into(),
                reason: "mcp access write requires a guard with approvalRef, dryRunDigest, and idempotencyKey".into(),
            })?;
        let approval_values = params
            .get("approval_tokens")
            .and_then(Value::as_array)
            .ok_or_else(|| FcpError::CapabilityDenied {
                capability: "n8n.mcp_access.write".into(),
                reason: "mcp access write requires approval_tokens".into(),
            })?;
        let approvals: Vec<ApprovalToken> = approval_values
            .iter()
            .map(|value| serde_json::from_value(value.clone()))
            .collect::<Result<_, _>>()
            .map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid approval token".into(),
            })?;
        let matching = approvals
            .iter()
            .filter(|approval| {
                is_matching_draft_approval(
                    approval,
                    "n8n.mcp_access.reconcile",
                    &guard.approval_ref,
                    self.zone_id.as_ref(),
                    raw_input,
                    current_time_ms(),
                )
            })
            .count();
        if matching != 1 {
            return Err(FcpError::CapabilityDenied {
                capability: "n8n.mcp_access.write".into(),
                reason: "mcp access write requires exactly one matching approval bound to the server scope and dry-run input".into(),
            });
        }
        Ok(())
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
            "n8n.workflows.list"
            | "n8n.executions.list"
            | "n8n.projects.list"
            | "n8n.credentials.list"
            | "n8n.tags.list"
            | "n8n.mcp_access.reconcile" => instance_resource_uri(server_id),
            "n8n.workflows.create_draft" => {
                if let Some(project_id) = input.get("project_id").and_then(Value::as_str) {
                    project_resource_uri(server_id, project_id)
                        .map_err(|error| error.to_fcp_error())?
                } else {
                    instance_resource_uri(server_id)
                }
            }
            "n8n.folders.list" => {
                let project_id = parse_folder_list_input(input)
                    .map_err(|error| error.to_fcp_error())?
                    .project_id
                    .to_string();
                project_resource_uri(server_id, &project_id)
                    .map_err(|error| error.to_fcp_error())?
            }
            "n8n.folders.get" => {
                let folder_input =
                    parse_folder_get_input(input).map_err(|error| error.to_fcp_error())?;
                folder_resource_uri(server_id, folder_input.folder_id)
                    .map_err(|error| error.to_fcp_error())?
            }
            "n8n.workflows.get"
            | "n8n.workflows.activate"
            | "n8n.workflows.update_draft"
            | "n8n.workflows.lifecycle" => {
                let workflow_id = require_str(input, "id").map_err(|error| error.to_fcp_error())?;
                workflow_resource_uri(server_id, workflow_id)
                    .map_err(|error| error.to_fcp_error())?
            }
            "n8n.executions.get" => {
                let workflow_id =
                    require_str(input, "workflow_id").map_err(|error| error.to_fcp_error())?;
                let execution_id =
                    require_str(input, "id").map_err(|error| error.to_fcp_error())?;
                execution_resource_uri(server_id, workflow_id, execution_id)
                    .map_err(|error| error.to_fcp_error())?
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

    fn activation_target(
        &self,
        input: &serde_json::Value,
        resources: &[String],
    ) -> FcpResult<ActivationTarget> {
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let workflow_id = require_str(input, "id").map_err(|error| error.to_fcp_error())?;
        let active = input
            .get("active")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: "Invalid input: Missing required field: active (boolean)".into(),
            })?;
        let resource_uri = resources
            .first()
            .cloned()
            .ok_or_else(|| FcpError::Internal {
                message: "Activation resource URI was not constructed".into(),
            })?;
        Ok(ActivationTarget {
            resource_uri: resource_uri.clone(),
            normalized_input: json!({
                "server_id": config.server_id,
                "resource_uri": resource_uri,
                "workflow_id": workflow_id,
                "active": active,
                "provider": "rest",
            }),
        })
    }

    fn require_execution_approval(
        &self,
        operation: &str,
        target: &ActivationTarget,
        params: &serde_json::Value,
    ) -> FcpResult<()> {
        let approval_values = params
            .get("approval_tokens")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| FcpError::CapabilityDenied {
                capability: "n8n.workflows.write".into(),
                reason: "activation requires a non-empty approval_tokens collection".into(),
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
                capability: "n8n.workflows.write".into(),
                reason: "activation requires exactly one matching execution approval token".into(),
            });
        }
        Ok(())
    }
}

fn is_matching_execution_approval(
    approval: &ApprovalToken,
    operation: &str,
    zone_id: Option<&ZoneId>,
    target: &ActivationTarget,
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
    scope.connector_id == "fcp.n8n"
        && scope.method_pattern == operation
        && scope.request_object_id.is_none()
        && has_exact_activation_constraints(&scope.input_constraints, &target.normalized_input)
}

fn draft_settings_supplied(input: &Value) -> bool {
    input
        .get("graph")
        .and_then(Value::as_object)
        .is_some_and(|graph| graph.contains_key("settings"))
}

fn canonical_draft_settings(operation: &str, input: &Value) -> N8nResult<Value> {
    let graph = input
        .get("graph")
        .and_then(Value::as_object)
        .ok_or_else(|| N8nError::InvalidInput("draft mutation graph must be an object".into()))?;
    let create = match operation {
        "n8n.workflows.create_draft" => true,
        "n8n.workflows.update_draft" => false,
        _ => {
            return Err(N8nError::InvalidInput(
                "unsupported draft settings operation".into(),
            ));
        }
    };
    let Some(raw_settings) = graph.get("settings") else {
        return Ok(if create {
            json!({"availableInMCP": false})
        } else {
            json!({})
        });
    };
    if raw_settings.is_null() {
        return Ok(if create {
            json!({"availableInMCP": false})
        } else {
            json!({})
        });
    }
    let Some(settings) = raw_settings.as_object() else {
        return Err(N8nError::InvalidInput(
            "graph.settings must be an object, null, or omitted".into(),
        ));
    };
    let mut canonical = settings.clone();
    match (create, canonical.get("availableInMCP")) {
        (true, None) => {
            canonical.insert("availableInMCP".into(), Value::Bool(false));
        }
        (true, Some(Value::Bool(false))) | (false, None) => {}
        (true, Some(Value::Bool(true))) => {
            return Err(N8nError::InvalidInput(
                "draft creation cannot enable MCP access; use the separately approved MCP access operation after activation and Webhook eligibility checks"
                    .into(),
            ));
        }
        (false, Some(_)) => {
            return Err(N8nError::InvalidInput(
                "draft update cannot change availableInMCP; use the separately approved MCP access operation"
                    .into(),
            ));
        }
        (true, Some(_)) => {
            return Err(N8nError::InvalidInput(
                "graph.settings.availableInMCP must be boolean false for draft creation".into(),
            ));
        }
    }
    Ok(Value::Object(canonical))
}

fn settings_include_expected(expected: Option<&Value>, actual: Option<&Value>) -> bool {
    match (expected, actual) {
        (None, None) => true,
        (Some(Value::Object(expected)), Some(Value::Object(actual))) => expected
            .iter()
            .all(|(key, expected_value)| actual.get(key) == Some(expected_value)),
        (Some(expected), Some(actual)) => expected == actual,
        _ => false,
    }
}

fn validate_draft_mutation(operation: &str, input: &WorkflowDraftMutationInput) -> N8nResult<()> {
    let guard = &input.guard;
    if guard.approval_ref.trim().is_empty()
        || guard.approval_ref.len() > 256
        || guard.approval_ref.chars().any(char::is_control)
    {
        return Err(N8nError::InvalidInput(
            "guard.approvalRef must be a bounded non-empty token reference".into(),
        ));
    }
    if uuid::Uuid::parse_str(&guard.idempotency_key).is_err() {
        return Err(N8nError::InvalidInput(
            "guard.idempotencyKey must be a UUID".into(),
        ));
    }
    if !input.graph.connections.is_object() {
        return Err(N8nError::InvalidInput(
            "graph.connections must be an object".into(),
        ));
    }
    if input.graph.nodes.len() > 10_000 {
        return Err(N8nError::InvalidInput(
            "graph.nodes exceeds the bounded draft limit".into(),
        ));
    }
    if input.graph.nodes.iter().any(|node| !node.is_object()) {
        return Err(N8nError::InvalidInput(
            "graph.nodes must contain objects".into(),
        ));
    }
    if input.name.as_deref().is_some_and(|name| {
        name.trim().is_empty() || name.len() > 256 || name.chars().any(char::is_control)
    }) {
        return Err(N8nError::InvalidInput(
            "name must be a bounded non-empty string".into(),
        ));
    }
    for (value, label) in [
        (input.id.as_deref(), "workflow id"),
        (input.project_id.as_deref(), "project id"),
        (input.parent_folder_id.as_deref(), "parent folder id"),
    ] {
        if let Some(value) = value {
            sanitize_path_segment(value, label)?;
        }
    }

    let precondition = &guard.precondition;
    match operation {
        "n8n.workflows.create_draft" => {
            if input.id.is_some() || input.name.as_deref().is_none_or(str::is_empty) {
                return Err(N8nError::InvalidInput(
                    "create_draft requires name and must not include id".into(),
                ));
            }
            if precondition.version_id.is_some()
                || precondition.state_digest.is_some()
                || precondition.active_version_id.is_some()
                || precondition.active.is_some_and(|active| active)
                || precondition.is_archived.is_some_and(|archived| archived)
            {
                return Err(N8nError::InvalidInput(
                    "create_draft cannot carry an existing workflow lifecycle precondition".into(),
                ));
            }
        }
        "n8n.workflows.update_draft" => {
            let Some(id) = input.id.as_deref() else {
                return Err(N8nError::InvalidInput("update_draft requires id".into()));
            };
            sanitize_path_segment(id, "workflow id")?;
            if precondition.version_id.is_none()
                || precondition.state_digest.is_none()
                || precondition.active.is_none()
                || precondition.is_archived.is_none()
            {
                return Err(N8nError::InvalidInput(
                    "update_draft requires the full version and lifecycle precondition".into(),
                ));
            }
        }
        _ => return Err(N8nError::InvalidInput("unsupported draft operation".into())),
    }
    Ok(())
}

fn validate_draft_input_presence(operation: &str, input: &Value) -> N8nResult<()> {
    if operation != "n8n.workflows.update_draft" {
        return Ok(());
    }
    let precondition = input
        .get("guard")
        .and_then(Value::as_object)
        .and_then(|guard| guard.get("precondition"))
        .and_then(Value::as_object)
        .ok_or_else(|| N8nError::InvalidInput("update_draft requires precondition".into()))?;
    if !precondition.contains_key("activeVersionId") {
        return Err(N8nError::InvalidInput(
            "update_draft requires explicit activeVersionId (null or value)".into(),
        ));
    }
    Ok(())
}

fn verify_draft_input_precondition(input: &Value, state: &WorkflowStateView) -> N8nResult<()> {
    let precondition = input
        .get("guard")
        .and_then(Value::as_object)
        .and_then(|guard| guard.get("precondition"))
        .and_then(Value::as_object)
        .ok_or_else(|| N8nError::InvalidInput("update_draft requires precondition".into()))?;
    let version_id = precondition
        .get("versionId")
        .and_then(Value::as_str)
        .ok_or_else(|| N8nError::InvalidInput("update_draft requires versionId".into()))?;
    let state_digest = precondition
        .get("stateDigest")
        .and_then(Value::as_str)
        .ok_or_else(|| N8nError::InvalidInput("update_draft requires stateDigest".into()))?;
    let active_version_id = match precondition.get("activeVersionId") {
        Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.as_str()),
        Some(_) => {
            return Err(N8nError::InvalidInput(
                "activeVersionId must be a string or explicit null".into(),
            ));
        }
        None => {
            return Err(N8nError::InvalidInput(
                "update_draft requires explicit activeVersionId".into(),
            ));
        }
    };
    let active = precondition
        .get("active")
        .and_then(Value::as_bool)
        .ok_or_else(|| N8nError::InvalidInput("update_draft requires active".into()))?;
    let is_archived = precondition
        .get("isArchived")
        .and_then(Value::as_bool)
        .ok_or_else(|| N8nError::InvalidInput("update_draft requires isArchived".into()))?;
    if version_id != state.version_id
        || state_digest != state.state_digest
        || active_version_id != state.active_version_id.as_deref()
        || active != state.active
        || is_archived != state.is_archived
    {
        return Err(N8nError::InvalidInput(
            "workflow draft lifecycle precondition is stale".into(),
        ));
    }
    Ok(())
}

fn verify_draft_precondition(
    precondition: &DraftMutationPrecondition,
    state: &WorkflowStateView,
) -> N8nResult<()> {
    if precondition.version_id.as_deref() != Some(state.version_id.as_str())
        || precondition.state_digest.as_deref() != Some(state.state_digest.as_str())
    {
        return Err(N8nError::InvalidInput(
            "workflow draft precondition is stale".into(),
        ));
    }
    if let Some(expected) = &precondition.active_version_id
        && expected.clone().into_option() != state.active_version_id
    {
        return Err(N8nError::InvalidInput(
            "workflow activeVersionId precondition does not match".into(),
        ));
    }
    if precondition
        .active
        .is_some_and(|active| active != state.active)
        || precondition
            .is_archived
            .is_some_and(|archived| archived != state.is_archived)
    {
        return Err(N8nError::InvalidInput(
            "workflow lifecycle precondition does not match".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_draft_readback(
    operation: &str,
    plan: &DraftWritePlan,
    baseline: Option<&DraftBaseline>,
    state: &WorkflowStateView,
    expected_name: Option<&str>,
    expected_settings: Option<&Value>,
    expected_static_data: Option<&Value>,
    expected_pin_data: Option<&Value>,
    actual_settings: Option<&Value>,
    actual_static_data: Option<&Value>,
    actual_pin_data: Option<&Value>,
) -> N8nResult<()> {
    if state.draft.graph_digest != plan.graph_digest
        || expected_name.is_some_and(|name| Some(name) != state.name.as_deref())
        || !settings_include_expected(expected_settings, actual_settings)
        || expected_static_data != actual_static_data
        || expected_pin_data != actual_pin_data
    {
        return Err(N8nError::ReadbackMismatch);
    }
    match (operation, baseline) {
        ("n8n.workflows.create_draft", None) => {
            if state.active
                || state.is_archived
                || state.active_version_id.is_some()
                || state.published.is_some()
            {
                return Err(N8nError::ReadbackMismatch);
            }
        }
        ("n8n.workflows.update_draft", Some(baseline)) => {
            // n8n may preserve versionId for metadata-only draft updates. The
            // requested graph/metadata match and independent lifecycle
            // readback are the authoritative success evidence.
            if state.published != baseline.state.published
                || state.active != baseline.state.active
                || state.is_archived != baseline.state.is_archived
                || state.active_version_id != baseline.state.active_version_id
            {
                return Err(N8nError::ReadbackMismatch);
            }
        }
        _ => return Err(N8nError::ReadbackMismatch),
    }
    Ok(())
}

/// Build the provisioning recipe for the `n8n` connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("n8n.credential_reference"),
        "1",
        "Provision n8n connector with a host-managed credential reference",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("enter_instance_url"),
        ProvisioningStepType::PromptUser {
            message: "Enter your n8n instance URL (e.g. https://n8n.example.com/api/v1)".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_credential_id"),
            ProvisioningStepType::PromptUser {
                message: "Enter the host-managed n8n credential reference (UUID); do not paste an API key".into(),
            },
        )
        .depends_on(StepId::new("enter_instance_url")),
    )
}

/// Validate the base URL against the `n8n` connector policy.
///
/// `n8n` is self-hosted, so any hostname is accepted as long as HTTPS is used
/// for non-local endpoints.
fn base_url_policy(base_url: &str) -> (bool, String) {
    match N8nClient::canonicalize_base_url(base_url) {
        Ok(canonical) => (true, format!("Endpoint accepted: {canonical}")),
        Err(error) => (false, error.safe_summary()),
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

fn validate_server_id(server_id: &str) -> FcpResult<()> {
    if SERVER_IDS.contains(&server_id) {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: "server_id must be exactly one of eec, hetzner, or legacy".into(),
        })
    }
}

fn instance_resource_uri(server_id: &str) -> String {
    format!("fwc-n8n://{server_id}")
}

fn project_resource_uri(server_id: &str, project_id: &str) -> N8nResult<String> {
    let project_id = encoded_resource_segment(project_id, "project id")?;
    Ok(format!("fwc-n8n://{server_id}/projects/{project_id}"))
}

fn folder_resource_uri(server_id: &str, folder_id: &str) -> N8nResult<String> {
    let folder_id = encoded_resource_segment(folder_id, "folder id")?;
    Ok(format!("fwc-n8n://{server_id}/folders/{folder_id}"))
}

fn credential_resource_uri(server_id: &str, credential_id: &str) -> N8nResult<String> {
    let credential_id = encoded_resource_segment(credential_id, "credential id")?;
    Ok(format!("fwc-n8n://{server_id}/credentials/{credential_id}"))
}

fn encoded_resource_segment(value: &str, field: &str) -> N8nResult<String> {
    let value = sanitize_path_segment(value, field)?;
    Ok(utf8_percent_encode(value, NON_ALPHANUMERIC).to_string())
}

fn workflow_resource_uri(server_id: &str, workflow_id: &str) -> N8nResult<String> {
    let encoded = encoded_resource_segment(workflow_id, "workflow id")?;
    Ok(format!("fwc-n8n://{server_id}/workflows/{encoded}"))
}

fn execution_resource_uri(
    server_id: &str,
    workflow_id: &str,
    execution_id: &str,
) -> N8nResult<String> {
    let workflow_id = encoded_resource_segment(workflow_id, "workflow id")?;
    let execution_id = encoded_resource_segment(execution_id, "execution id")?;
    Ok(format!(
        "fwc-n8n://{server_id}/workflows/{workflow_id}/executions/{execution_id}"
    ))
}

fn has_exact_activation_constraints(
    constraints: &[fcp_prelude::InputConstraint],
    normalized_input: &serde_json::Value,
) -> bool {
    const REQUIRED_POINTERS: [&str; 5] = [
        "/server_id",
        "/resource_uri",
        "/workflow_id",
        "/active",
        "/provider",
    ];
    constraints.len() == REQUIRED_POINTERS.len()
        && REQUIRED_POINTERS.iter().all(|pointer| {
            constraints.iter().any(|constraint| {
                constraint.pointer == *pointer
                    && normalized_input.pointer(pointer) == Some(&constraint.expected)
            })
        })
}

fn is_matching_draft_approval(
    approval: &ApprovalToken,
    operation: &str,
    approval_ref: &str,
    zone_id: Option<&ZoneId>,
    request_input: &Value,
    now_ms: u64,
) -> bool {
    if approval.token_id != approval_ref
        || approval.signature.as_ref().is_none_or(Vec::is_empty)
        || !approval.is_valid(now_ms)
        || zone_id != Some(&approval.zone_id)
    {
        return false;
    }
    let ApprovalScope::Execution(scope) = &approval.scope else {
        return false;
    };
    if scope.connector_id != "fcp.n8n"
        || scope.method_pattern != operation
        || scope.request_object_id.is_some()
    {
        return false;
    }
    let Some(expected_hash) = scope.input_hash else {
        return false;
    };
    scope.input_constraints.is_empty()
        && approval_input_hash(request_input).is_some_and(|actual| actual == expected_hash)
}

fn approval_input_hash(input: &Value) -> Option<[u8; 32]> {
    fcp_crypto::canonicalize::to_deterministic_cbor(input)
        .ok()
        .map(|bytes| *blake3::hash(&bytes).as_bytes())
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

const GRAPH_DIGEST_DOMAIN_V1: &[u8] = b"fwc-n8n.graph-digest.v1";
const STATE_DIGEST_DOMAIN_V1: &[u8] = b"fwc-n8n.state-digest.v1";
const MUTATION_DIGEST_DOMAIN_V1: &[u8] = b"fwc-n8n.mutation-digest.v1";

fn normalize_workflow_state(workflow: WorkflowDetail) -> N8nResult<WorkflowStateView> {
    let WorkflowDetail {
        id,
        name,
        description,
        active,
        version_id,
        active_version_id,
        is_archived,
        project_id,
        parent_folder_id,
        created_at,
        updated_at,
        nodes,
        connections,
        settings: _settings,
        static_data: _static_data,
        pin_data: _pin_data,
        active_version,
        tags,
    } = workflow;

    let active_version_id = active_version_id.into_option();
    let active_version = active_version.into_option();
    match (&active_version_id, &active_version) {
        (None, None) => {}
        (Some(expected), Some(published)) if expected == &published.version_id => {}
        _ => return Err(N8nError::MalformedProviderResponse),
    }

    let draft_graph_digest = workflow_graph_digest(&nodes, &connections)?;
    let published = if let Some(published) = active_version.as_ref() {
        Some(WorkflowGraphSummary {
            version_id: published.version_id.clone(),
            graph_digest: workflow_graph_digest(&published.nodes, &published.connections)?,
        })
    } else {
        None
    };
    let state_digest = workflow_state_digest(
        &id,
        name.as_deref(),
        description.as_deref(),
        project_id.as_deref(),
        parent_folder_id.as_deref(),
        &version_id,
        active,
        active_version_id.as_deref(),
        is_archived,
        created_at.as_deref(),
        updated_at.as_deref(),
        tags.as_deref(),
        &nodes,
        &connections,
        active_version.as_ref(),
    )?;

    Ok(WorkflowStateView {
        id,
        name,
        project_id,
        folder_id: parent_folder_id,
        version_id: version_id.clone(),
        active,
        active_version_id,
        is_archived,
        draft: WorkflowGraphSummary {
            version_id,
            graph_digest: draft_graph_digest,
        },
        published,
        state_digest,
        updated_at,
    })
}

fn workflow_graph_digest(nodes: &[Value], connections: &Value) -> N8nResult<String> {
    if !connections.is_object() {
        return Err(N8nError::MalformedProviderResponse);
    }

    let semantic_nodes = nodes
        .iter()
        .map(|node| {
            let mut node = node.clone();
            let Some(object) = node.as_object_mut() else {
                return Err(N8nError::MalformedProviderResponse);
            };
            object.remove("credentials");
            Ok(node)
        })
        .collect::<N8nResult<Vec<_>>>()?;
    digest_canonical_json(
        GRAPH_DIGEST_DOMAIN_V1,
        &json!({
            "nodes": semantic_nodes,
            "connections": connections,
        }),
    )
}

fn draft_mutation_digest(operation: &str, input: &Value) -> N8nResult<String> {
    let object = input
        .as_object()
        .ok_or_else(|| N8nError::InvalidInput("draft mutation input must be an object".into()))?;
    let graph = object
        .get("graph")
        .and_then(Value::as_object)
        .ok_or_else(|| N8nError::InvalidInput("draft mutation graph must be an object".into()))?;
    let settings = canonical_draft_settings(operation, input)?;
    digest_canonical_json(
        MUTATION_DIGEST_DOMAIN_V1,
        &json!({
            "id": object.get("id").cloned().unwrap_or(Value::Null),
            "name": object.get("name").cloned().unwrap_or(Value::Null),
            "project_id": object.get("project_id").cloned().unwrap_or(Value::Null),
            "parent_folder_id": object
                .get("parent_folder_id")
                .cloned()
                .unwrap_or(Value::Null),
            "graph": {
                "nodes": graph.get("nodes").cloned().unwrap_or(Value::Null),
                "connections": graph
                    .get("connections")
                    .cloned()
                    .unwrap_or(Value::Null),
                "settings": settings,
                "staticData": graph
                    .get("staticData")
                    .cloned()
                    .unwrap_or(Value::Null),
                "pinData": graph.get("pinData").cloned().unwrap_or(Value::Null),
            },
        }),
    )
}

#[allow(clippy::too_many_arguments)]
fn workflow_state_digest(
    id: &str,
    name: Option<&str>,
    description: Option<&str>,
    project_id: Option<&str>,
    folder_id: Option<&str>,
    version_id: &str,
    active: bool,
    active_version_id: Option<&str>,
    is_archived: bool,
    created_at: Option<&str>,
    updated_at: Option<&str>,
    tags: Option<&[crate::types::Tag]>,
    nodes: &[Value],
    connections: &Value,
    active_version: Option<&WorkflowVersion>,
) -> N8nResult<String> {
    let tags = tags.map(|tags| {
        tags.iter()
            .map(|tag| json!({"id": tag.id, "name": tag.name}))
            .collect::<Vec<_>>()
    });
    let published = active_version.map(|published| {
        json!({
            "versionId": published.version_id,
            "nodes": published.nodes,
            "connections": published.connections,
        })
    });
    digest_canonical_json(
        STATE_DIGEST_DOMAIN_V1,
        &json!({
            "schema": "fwc-n8n.workflow-state.v1",
            "id": id,
            "name": name,
            "description": description,
            "projectId": project_id,
            "folderId": folder_id,
            "versionId": version_id,
            "active": active,
            "activeVersionId": active_version_id,
            "isArchived": is_archived,
            "createdAt": created_at,
            "updatedAt": updated_at,
            "tags": tags,
            "draft": {
                "nodes": nodes,
                "connections": connections,
            },
            "published": published,
        }),
    )
}

fn digest_canonical_json(domain: &[u8], value: &Value) -> N8nResult<String> {
    let canonical = canonical_json(value);
    let bytes = serde_json::to_vec(&canonical)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(&bytes);
    Ok(format!("blake3-256:{}", hasher.finalize().to_hex()))
}

fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|(key, _)| *key);
            let mut canonical = serde_json::Map::new();
            for (key, child) in entries {
                canonical.insert(key.clone(), canonical_json(child));
            }
            Value::Object(canonical)
        }
        Value::Array(array) => Value::Array(array.iter().map(canonical_json).collect()),
        scalar => scalar.clone(),
    }
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    operations_info()
        .into_iter()
        .find(|info| info.id.as_ref() == operation)
        .map(|info| info.capability)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1002,
            message: format!("Unknown operation: {operation}"),
        })
}

fn parse_list_query(input: &serde_json::Value) -> N8nResult<ListQuery> {
    let object = require_exact_object(input, &["limit", "cursor"], "list input")?;

    let limit = object
        .get("limit")
        .map_or(Ok(DEFAULT_LIST_LIMIT), |value| {
            value
                .as_u64()
                .ok_or_else(|| N8nError::InvalidInput("list limit must be an integer".into()))
        })?;
    let cursor = object
        .get("cursor")
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| N8nError::InvalidInput("list cursor must be a string".into()))
        })
        .transpose()?;
    ListQuery::new(limit, cursor)
}

struct FolderListInput<'a> {
    project_id: &'a str,
    parent_folder_id: Option<&'a str>,
    skip: u64,
    take: u64,
}

struct FolderGetInput<'a> {
    project_id: &'a str,
    folder_id: &'a str,
}

fn parse_folder_list_input(input: &serde_json::Value) -> N8nResult<FolderListInput<'_>> {
    let object = require_exact_object(
        input,
        &["project_id", "parent_folder_id", "skip", "take"],
        "folder list input",
    )?;

    let project_id = require_path_str(input, "project_id", "project id")?;
    let parent_folder_id = object
        .get("parent_folder_id")
        .map(|value| {
            let parent_folder_id = value.as_str().ok_or_else(|| {
                N8nError::InvalidInput("parent_folder_id must be a string".into())
            })?;
            sanitize_path_segment(parent_folder_id, "parent folder id")
        })
        .transpose()?;
    let skip = object
        .get("skip")
        .map_or(Ok(0), |value| parse_u64_field(value, "skip"))?;
    let take = object
        .get("take")
        .map_or(Ok(50), |value| parse_u64_field(value, "take"))?;
    if !(1..=200).contains(&take) {
        return Err(N8nError::InvalidInput(
            "take must be an integer from 1 through 200".into(),
        ));
    }

    Ok(FolderListInput {
        project_id,
        parent_folder_id,
        skip,
        take,
    })
}

fn parse_folder_get_input(input: &serde_json::Value) -> N8nResult<FolderGetInput<'_>> {
    require_exact_object(input, &["project_id", "folder_id"], "folder get input")?;

    Ok(FolderGetInput {
        project_id: require_path_str(input, "project_id", "project id")?,
        folder_id: require_path_str(input, "folder_id", "folder id")?,
    })
}

fn validate_operation_input(operation: &str, input: &serde_json::Value) -> N8nResult<()> {
    match operation {
        "n8n.workflows.list"
        | "n8n.executions.list"
        | "n8n.projects.list"
        | "n8n.credentials.list"
        | "n8n.tags.list" => parse_list_query(input).map(|_| ()),
        "n8n.workflows.get" => {
            require_exact_object(input, &["id"], "workflow get input")?;
            require_str(input, "id")?;
            Ok(())
        }
        "n8n.workflows.activate" => {
            require_exact_object(input, &["id", "active"], "workflow activation input")?;
            require_str(input, "id")?;
            input
                .get("active")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| {
                    N8nError::InvalidInput("Missing required field: active (boolean)".into())
                })?;
            Ok(())
        }
        "n8n.workflows.lifecycle" => parse_workflow_lifecycle_input(input).map(|_| ()),
        "n8n.workflows.create_draft" | "n8n.workflows.update_draft" => {
            validate_draft_input_presence(operation, input)?;
            let typed: WorkflowDraftMutationInput =
                serde_json::from_value(input.clone()).map_err(|_| {
                    N8nError::InvalidInput("invalid guarded workflow draft input".into())
                })?;
            validate_draft_mutation(operation, &typed)
        }
        "n8n.executions.get" => {
            require_exact_object(input, &["workflow_id", "id"], "execution get input")?;
            require_str(input, "workflow_id")?;
            require_str(input, "id")?;
            Ok(())
        }
        "n8n.folders.list" => parse_folder_list_input(input).map(|_| ()),
        "n8n.folders.get" => parse_folder_get_input(input).map(|_| ()),
        "n8n.mcp_access.reconcile" => parse_mcp_access_input(input).map(|_| ()),
        _ => Ok(()),
    }
}

fn parse_mcp_access_input(input: &Value) -> N8nResult<McpAccessReconcileInput> {
    let typed: McpAccessReconcileInput = serde_json::from_value(input.clone()).map_err(|_| {
        N8nError::InvalidInput(
            "mcp access input requires scope, desired, dryRun, and only scope-specific filters"
                .into(),
        )
    })?;
    if typed.dry_run {
        if typed.guard.is_some() {
            return Err(N8nError::InvalidInput(
                "dryRun must not include a write guard".into(),
            ));
        }
    } else {
        let guard = typed.guard.as_ref().ok_or_else(|| {
            N8nError::InvalidInput("non-dry-run MCP access requires guard".into())
        })?;
        if guard.approval_ref.is_empty()
            || guard.approval_ref.len() > 256
            || guard.approval_ref.trim() != guard.approval_ref
            || guard.dry_run_digest.is_empty()
            || guard.dry_run_digest.len() > 256
            || guard.dry_run_digest.trim() != guard.dry_run_digest
            || !is_blake3_digest(&guard.dry_run_digest)
            || uuid::Uuid::parse_str(&guard.idempotency_key).is_err()
        {
            return Err(N8nError::InvalidInput(
                "guard approvalRef, dryRunDigest, and idempotencyKey are invalid".into(),
            ));
        }
    }

    match typed.scope {
        McpAccessScope::WorkflowIds => {
            let ids = typed.workflow_ids.as_ref().ok_or_else(|| {
                N8nError::InvalidInput("workflow_ids scope requires workflowIds".into())
            })?;
            if ids.is_empty() || ids.len() > MAX_MCP_ACCESS_WORKFLOWS {
                return Err(N8nError::InvalidInput(
                    "workflowIds must contain between 1 and 1000 IDs".into(),
                ));
            }
            if typed.project_id.is_some() || typed.folder_id.is_some() {
                return Err(N8nError::InvalidInput(
                    "workflow_ids scope cannot include projectId or folderId".into(),
                ));
            }
            let mut unique = BTreeSet::new();
            for id in ids {
                sanitize_path_segment(id, "workflow id")?;
                if !unique.insert(id) {
                    return Err(N8nError::InvalidInput(
                        "workflowIds must not contain duplicates".into(),
                    ));
                }
            }
        }
        McpAccessScope::Project => {
            let project_id = typed
                .project_id
                .as_deref()
                .ok_or_else(|| N8nError::InvalidInput("project scope requires projectId".into()))?;
            sanitize_path_segment(project_id, "project id")?;
            if typed.folder_id.is_some() || typed.workflow_ids.is_some() {
                return Err(N8nError::InvalidInput(
                    "project scope cannot include folderId or workflowIds".into(),
                ));
            }
        }
        McpAccessScope::Folder => {
            let folder_id = typed
                .folder_id
                .as_deref()
                .ok_or_else(|| N8nError::InvalidInput("folder scope requires folderId".into()))?;
            sanitize_path_segment(folder_id, "folder id")?;
            if typed.project_id.is_some() || typed.workflow_ids.is_some() {
                return Err(N8nError::InvalidInput(
                    "folder scope cannot include projectId or workflowIds".into(),
                ));
            }
        }
        McpAccessScope::AllCurrent => {
            if typed.project_id.is_some()
                || typed.folder_id.is_some()
                || typed.workflow_ids.is_some()
            {
                return Err(N8nError::InvalidInput(
                    "all_current scope cannot include projectId, folderId, or workflowIds".into(),
                ));
            }
        }
    }
    Ok(typed)
}

fn parse_workflow_lifecycle_input(input: &Value) -> N8nResult<WorkflowLifecycleInput> {
    let typed: WorkflowLifecycleInput = serde_json::from_value(input.clone()).map_err(|_| {
        N8nError::InvalidInput(
            "workflow lifecycle input requires id, action, and exact guard precondition".into(),
        )
    })?;
    sanitize_path_segment(&typed.id, "workflow id")?;
    if typed.guard.approval_ref.is_empty()
        || typed.guard.approval_ref.len() > 256
        || typed.guard.approval_ref.trim() != typed.guard.approval_ref
        || typed.guard.approval_ref.chars().any(char::is_control)
        || uuid::Uuid::parse_str(&typed.guard.idempotency_key).is_err()
    {
        return Err(N8nError::InvalidInput(
            "workflow lifecycle approvalRef and idempotencyKey are invalid".into(),
        ));
    }
    let precondition = &typed.guard.precondition;
    if precondition.version_id.is_empty()
        || precondition.version_id.len() > 256
        || precondition.version_id.trim() != precondition.version_id
        || precondition.state_digest.len() > 256
        || !is_blake3_digest(&precondition.state_digest)
    {
        return Err(N8nError::InvalidInput(
            "workflow lifecycle versionId and stateDigest are invalid".into(),
        ));
    }
    if let crate::types::RequiredNullable::Value(value) = &precondition.active_version_id
        && (value.is_empty() || value.len() > 256 || value.trim() != value)
    {
        return Err(N8nError::InvalidInput(
            "workflow lifecycle activeVersionId is invalid".into(),
        ));
    }
    if let Some(version_id) = typed.version_id.as_deref()
        && (version_id.is_empty() || version_id.len() > 256 || version_id.trim() != version_id)
    {
        return Err(N8nError::InvalidInput(
            "workflow lifecycle versionId is invalid".into(),
        ));
    }
    if typed.action == WorkflowLifecycleAction::Unpublish && typed.version_id.is_some() {
        return Err(N8nError::InvalidInput(
            "unpublish must not include a versionId".into(),
        ));
    }
    Ok(typed)
}

fn classify_lifecycle_attempt_error(error: N8nError) -> N8nError {
    match error {
        N8nError::Http(_)
        | N8nError::Json(_)
        | N8nError::MalformedProviderResponse
        | N8nError::UnknownOutcome
        | N8nError::RateLimited { .. } => N8nError::UnknownOutcome,
        N8nError::Api { status_code, .. } if status_code == 409 || status_code >= 500 => {
            N8nError::UnknownOutcome
        }
        other => other,
    }
}

fn verify_workflow_lifecycle_precondition(
    precondition: &crate::types::WorkflowLifecyclePrecondition,
    workflow: &WorkflowDetail,
    state: &WorkflowStateView,
) -> N8nResult<()> {
    if precondition.version_id != workflow.version_id
        || precondition.active_version_id != workflow.active_version_id
        || precondition.active != workflow.active
        || precondition.is_archived != workflow.is_archived
        || precondition.state_digest != state.state_digest
    {
        return Err(N8nError::PreconditionFailed(
            "workflow lifecycle precondition is stale",
        ));
    }
    Ok(())
}

fn verify_workflow_lifecycle_readback(
    action: WorkflowLifecycleAction,
    requested_version_id: Option<&str>,
    baseline: &WorkflowStateView,
    provider: &WorkflowStateView,
    readback: &WorkflowStateView,
) -> N8nResult<()> {
    if provider.draft != baseline.draft {
        return Err(N8nError::UnknownOutcome);
    }
    match action {
        WorkflowLifecycleAction::Publish => {
            let target_version_id = requested_version_id
                .or(provider.active_version_id.as_deref())
                .ok_or(N8nError::UnknownOutcome)?;
            if !provider.active
                || provider.active_version_id.as_deref() != Some(target_version_id)
                || provider
                    .published
                    .as_ref()
                    .is_none_or(|published| published.version_id.as_str() != target_version_id)
            {
                return Err(N8nError::UnknownOutcome);
            }
            if !readback.active
                || readback.is_archived
                || readback.active_version_id.as_deref() != Some(target_version_id)
                || readback.published != provider.published
                || readback
                    .published
                    .as_ref()
                    .is_none_or(|published| published.version_id.as_str() != target_version_id)
                || readback.draft != baseline.draft
            {
                return Err(N8nError::ReadbackMismatch);
            }
        }
        WorkflowLifecycleAction::Unpublish => {
            if provider.active || provider.active_version_id.is_some() {
                return Err(N8nError::UnknownOutcome);
            }
            if readback.active
                || readback.active_version_id.is_some()
                || readback.is_archived != baseline.is_archived
                || readback.published != provider.published
                || readback.draft != baseline.draft
            {
                return Err(N8nError::ReadbackMismatch);
            }
        }
    }
    Ok(())
}

fn is_blake3_digest(value: &str) -> bool {
    value.len() == "blake3-256:".len() + 64
        && value.starts_with("blake3-256:")
        && value["blake3-256:".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
}

fn mcp_access_exception(
    item: &McpAccessPlanItem,
    desired: bool,
    reason: &'static str,
) -> McpAccessPlanItem {
    McpAccessPlanItem {
        id: item.id.clone(),
        available_in_mcp: item.available_in_mcp,
        desired,
        reason,
    }
}

impl McpAccessReceipt {
    fn from_plan(
        input: &McpAccessReconcileInput,
        server_id: &str,
        plan: &McpAccessPlan,
        plan_digest: &str,
        guard: Option<&McpAccessReconcileGuard>,
    ) -> N8nResult<Self> {
        let items = mcp_access_receipt_items(server_id, plan, input.dry_run)?;

        let (approval_digest, idempotency_digest) = match guard {
            Some(guard) => (
                Some(mcp_access_guard_digest(
                    server_id,
                    "approval",
                    &guard.approval_ref,
                )?),
                Some(mcp_access_guard_digest(
                    server_id,
                    "idempotency",
                    &guard.idempotency_key,
                )?),
            ),
            None => (None, None),
        };
        let status = if input.dry_run {
            McpAccessReceiptStatus::Planned
        } else if plan.exceptions.is_empty() {
            McpAccessReceiptStatus::Applied
        } else if plan
            .exceptions
            .iter()
            .any(|item| matches!(item.reason, "provider_unknown_outcome" | "readback_unknown"))
        {
            McpAccessReceiptStatus::Unknown
        } else {
            McpAccessReceiptStatus::Partial
        };

        let mut receipt = Self {
            schema: MCP_ACCESS_RECEIPT_SCHEMA_V1,
            operation: "n8n.mcp_access.reconcile",
            server_id: server_id.to_owned(),
            scope: input.scope.as_str().to_owned(),
            desired: input.desired,
            dry_run: input.dry_run,
            status,
            plan_digest: plan_digest.to_owned(),
            readback_digest: plan.readback_digest.clone(),
            approval_digest,
            idempotency_digest,
            items,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.compute_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    fn compute_digest(&self) -> N8nResult<String> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .ok_or(N8nError::MalformedProviderResponse)?;
        object.insert("receiptDigest".into(), Value::Null);
        digest_canonical_json(MCP_ACCESS_RECEIPT_DIGEST_DOMAIN_V1, &value)
    }

    fn validate(&self) -> N8nResult<()> {
        if self.schema != MCP_ACCESS_RECEIPT_SCHEMA_V1
            || self.operation != "n8n.mcp_access.reconcile"
            || self.items.len() > MAX_MCP_ACCESS_RECEIPT_ITEMS
            || self.server_id.len() > MAX_MCP_ACCESS_RECEIPT_SERVER_ID_LENGTH
            || self.scope.len() > MAX_MCP_ACCESS_RECEIPT_SCOPE_LENGTH
            || !is_blake3_digest(&self.plan_digest)
            || !is_blake3_digest(&self.readback_digest)
            || !is_blake3_digest(&self.receipt_digest)
            || self.plan_digest.len() > MAX_MCP_ACCESS_RECEIPT_DIGEST_LENGTH
            || self.readback_digest.len() > MAX_MCP_ACCESS_RECEIPT_DIGEST_LENGTH
            || self.receipt_digest.len() > MAX_MCP_ACCESS_RECEIPT_DIGEST_LENGTH
            || self.approval_digest.as_deref().is_some_and(|digest| {
                !is_blake3_digest(digest) || digest.len() > MAX_MCP_ACCESS_RECEIPT_DIGEST_LENGTH
            })
            || self.idempotency_digest.as_deref().is_some_and(|digest| {
                !is_blake3_digest(digest) || digest.len() > MAX_MCP_ACCESS_RECEIPT_DIGEST_LENGTH
            })
            || self.items.iter().any(|item| {
                item.resource_digest.len() > MAX_MCP_ACCESS_RECEIPT_DIGEST_LENGTH
                    || item.outcome.len() > MAX_MCP_ACCESS_RECEIPT_OUTCOME_LENGTH
            })
        {
            return Err(N8nError::MalformedProviderResponse);
        }
        let encoded = serde_json::to_vec(self)?;
        if encoded.len() > MAX_MCP_ACCESS_RECEIPT_BYTES
            || self.compute_digest()? != self.receipt_digest
        {
            return Err(N8nError::InvalidInput(
                "mcp access receipt exceeds its deterministic bounds".into(),
            ));
        }
        Ok(())
    }
}

fn mcp_access_receipt_items(
    server_id: &str,
    plan: &McpAccessPlan,
    include_planned: bool,
) -> N8nResult<Vec<McpAccessReceiptItem>> {
    // The public plan intentionally keeps `planned` alongside final outcome
    // arrays for per-resource diagnostics. Dry-run receipts retain planned
    // representation; apply receipts contain only terminal outcomes. In both
    // cases one hashed resource may occur only once, with precedence
    // exception > changed > skipped > planned.
    let mut by_resource = BTreeMap::<String, (u8, McpAccessReceiptItem)>::new();
    let sources = if include_planned {
        vec![
            (0_u8, "planned", plan.planned.as_slice()),
            (1_u8, "skipped", plan.skipped.as_slice()),
            (2_u8, "changed", plan.changed.as_slice()),
            (3_u8, "exception", plan.exceptions.as_slice()),
        ]
    } else {
        vec![
            (1_u8, "skipped", plan.skipped.as_slice()),
            (2_u8, "changed", plan.changed.as_slice()),
            (3_u8, "exception", plan.exceptions.as_slice()),
        ]
    };
    for (priority, outcome, source) in sources {
        for item in source {
            let resource_digest = mcp_access_resource_digest(server_id, &item.id)?;
            let candidate = McpAccessReceiptItem {
                resource_digest: resource_digest.clone(),
                available_in_mcp: item.available_in_mcp,
                desired: item.desired,
                outcome: format!("{outcome}:{}", item.reason),
            };
            if by_resource
                .get(&resource_digest)
                .is_none_or(|(existing_priority, _)| priority >= *existing_priority)
            {
                by_resource.insert(resource_digest, (priority, candidate));
            }
        }
    }
    if by_resource.len() > MAX_MCP_ACCESS_RECEIPT_ITEMS {
        return Err(N8nError::InvalidInput(
            "mcp access receipt exceeds the bounded item limit".into(),
        ));
    }
    let mut items = by_resource
        .into_values()
        .map(|(_, item)| item)
        .collect::<Vec<_>>();
    items.sort_by(|left, right| {
        left.resource_digest
            .cmp(&right.resource_digest)
            .then_with(|| left.outcome.cmp(&right.outcome))
            .then_with(|| left.desired.cmp(&right.desired))
    });
    Ok(items)
}

fn mcp_access_receipt_capacity_guard(
    input: &McpAccessReconcileInput,
    server_id: &str,
    plan: &McpAccessPlan,
    plan_digest: &str,
    guard: Option<&McpAccessReconcileGuard>,
) -> N8nResult<()> {
    if server_id.len() > MAX_MCP_ACCESS_RECEIPT_SERVER_ID_LENGTH
        || input.scope.as_str().len() > MAX_MCP_ACCESS_RECEIPT_SCOPE_LENGTH
    {
        return Err(N8nError::InvalidInput(
            "mcp access receipt field exceeds its bounded length".into(),
        ));
    }
    let item_count = if input.dry_run {
        mcp_access_receipt_items(server_id, plan, true)?.len()
    } else {
        plan.planned
            .len()
            .saturating_add(plan.changed.len())
            .saturating_add(plan.skipped.len())
            .saturating_add(plan.exceptions.len())
    };
    if item_count > MAX_MCP_ACCESS_RECEIPT_ITEMS {
        return Err(N8nError::InvalidInput(
            "mcp access receipt exceeds the bounded item capacity".into(),
        ));
    }

    let (approval_digest, idempotency_digest) = match guard {
        Some(guard) => (
            Some(mcp_access_guard_digest(
                server_id,
                "approval",
                &guard.approval_ref,
            )?),
            Some(mcp_access_guard_digest(
                server_id,
                "idempotency",
                &guard.idempotency_key,
            )?),
        ),
        None => (None, None),
    };
    let worst_case = McpAccessReceipt {
        schema: MCP_ACCESS_RECEIPT_SCHEMA_V1,
        operation: "n8n.mcp_access.reconcile",
        server_id: server_id.to_owned(),
        scope: input.scope.as_str().to_owned(),
        desired: input.desired,
        dry_run: input.dry_run,
        status: McpAccessReceiptStatus::Unknown,
        plan_digest: plan_digest.to_owned(),
        readback_digest: plan.readback_digest.clone(),
        approval_digest,
        idempotency_digest,
        items: vec![
            McpAccessReceiptItem {
                resource_digest: format!("blake3-256:{}", "f".repeat(64)),
                available_in_mcp: Some(true),
                desired: true,
                outcome: "x".repeat(MAX_MCP_ACCESS_RECEIPT_OUTCOME_LENGTH),
            };
            item_count
        ],
        receipt_digest: format!("blake3-256:{}", "f".repeat(64)),
    };
    if serde_json::to_vec(&worst_case)?.len() > MAX_MCP_ACCESS_RECEIPT_BYTES {
        return Err(N8nError::InvalidInput(
            "mcp access receipt exceeds its bounded byte capacity".into(),
        ));
    }
    Ok(())
}

fn mcp_access_resource_digest(server_id: &str, workflow_id: &str) -> N8nResult<String> {
    digest_canonical_json(
        MCP_ACCESS_RECEIPT_RESOURCE_DOMAIN_V1,
        &json!({"serverId": server_id, "workflowId": workflow_id}),
    )
}

fn mcp_access_guard_digest(server_id: &str, kind: &str, value: &str) -> N8nResult<String> {
    digest_canonical_json(
        MCP_ACCESS_RECEIPT_BINDING_DOMAIN_V1,
        &json!({"kind": kind, "serverId": server_id, "value": value}),
    )
}

const fn mcp_access_error_reason(error: &N8nError) -> &'static str {
    match error {
        N8nError::UnknownOutcome => "provider_unknown_outcome",
        N8nError::ReadbackMismatch => "readback_mismatch",
        N8nError::Unauthorized => "provider_unauthorized",
        N8nError::Forbidden => "provider_forbidden",
        N8nError::NotFound { .. } => "provider_not_found",
        N8nError::RateLimited { .. } => "provider_rate_limited",
        N8nError::Api { .. } | N8nError::Http(_) => "provider_error",
        N8nError::Json(_) | N8nError::MalformedProviderResponse => "provider_malformed",
        N8nError::InvalidInput(_) => "provider_invalid_input",
        N8nError::PreconditionFailed(_) => "precondition_failed",
        N8nError::CapabilityUnavailable(_) => "provider_capability_unavailable",
    }
}

fn mcp_access_invariant(workflow: &WorkflowDetail) -> N8nResult<McpAccessInvariant> {
    let state = normalize_workflow_state(workflow.clone())?;
    Ok(McpAccessInvariant {
        id: state.id,
        name: state.name,
        description: workflow.description.clone(),
        project_id: state.project_id,
        folder_id: state.folder_id,
        version_id: state.version_id,
        active: state.active,
        active_version_id: state.active_version_id,
        is_archived: state.is_archived,
        draft: state.draft,
        published: state.published,
    })
}

fn sorted_mcp_access_items(items: &[McpAccessPlanItem]) -> Vec<McpAccessPlanItem> {
    let mut sorted = items.to_vec();
    sorted.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.reason.cmp(right.reason))
            .then_with(|| left.desired.cmp(&right.desired))
    });
    sorted
}

fn mcp_access_reconcile_digest(
    input: &McpAccessReconcileInput,
    server_id: &str,
    planned: &[McpAccessPlanItem],
    changed: &[McpAccessPlanItem],
    skipped: &[McpAccessPlanItem],
    exceptions: &[McpAccessPlanItem],
) -> N8nResult<String> {
    let mut workflow_ids = input.workflow_ids.clone().unwrap_or_default();
    workflow_ids.sort();
    let digest_input = json!({
        "serverId": server_id,
        "scope": input.scope.as_str(),
        "projectId": input.project_id,
        "folderId": input.folder_id,
        "workflowIds": workflow_ids,
        "desired": input.desired,
        "planned": sorted_mcp_access_items(planned),
        "changed": sorted_mcp_access_items(changed),
        "skipped": sorted_mcp_access_items(skipped),
        "exceptions": sorted_mcp_access_items(exceptions),
    });
    digest_canonical_json(MCP_ACCESS_READBACK_DIGEST_DOMAIN_V2, &digest_input)
}

fn workflow_summary_from_detail(detail: WorkflowDetail) -> Workflow {
    let active_version_id = match detail.active_version_id.into_option() {
        Some(value) => ActiveVersionId::Value(value),
        None => ActiveVersionId::Null,
    };
    Workflow {
        id: detail.id,
        name: detail.name,
        description: detail.description,
        active: Some(detail.active),
        version_id: Some(detail.version_id),
        active_version_id,
        is_archived: Some(detail.is_archived),
        project_id: detail.project_id,
        parent_folder_id: detail.parent_folder_id,
        created_at: detail.created_at,
        updated_at: detail.updated_at,
        settings: detail.settings,
        tags: detail.tags,
    }
}

fn plan_mcp_access_reconcile(
    input: &McpAccessReconcileInput,
    workflows: &[Workflow],
    server_id: &str,
) -> N8nResult<McpAccessPlan> {
    let requested_ids = input
        .workflow_ids
        .as_ref()
        .map(|ids| ids.iter().cloned().collect::<BTreeSet<_>>())
        .unwrap_or_default();
    let mut seen_requested = BTreeSet::new();
    let mut planned = Vec::new();
    let changed = Vec::new();
    let mut skipped = Vec::new();
    let mut exceptions = Vec::new();

    for workflow in workflows {
        let selected = match input.scope {
            McpAccessScope::WorkflowIds => requested_ids.contains(&workflow.id),
            McpAccessScope::Project => workflow.project_id == input.project_id,
            McpAccessScope::Folder => workflow.parent_folder_id == input.folder_id,
            McpAccessScope::AllCurrent => true,
        };
        if !selected {
            continue;
        }
        if input.scope == McpAccessScope::WorkflowIds {
            seen_requested.insert(workflow.id.clone());
        }
        let item = |reason| McpAccessPlanItem {
            id: workflow.id.clone(),
            available_in_mcp: workflow.available_in_mcp(),
            desired: input.desired,
            reason,
        };
        if workflow.is_archived != Some(false) {
            if workflow.is_archived == Some(true) {
                skipped.push(item("archived"));
            } else {
                exceptions.push(item("archive_state_unknown"));
            }
            continue;
        }
        let Some(current) = workflow.available_in_mcp() else {
            exceptions.push(item("availability_state_unknown"));
            continue;
        };
        if current == input.desired {
            skipped.push(item("already_desired"));
        } else {
            planned.push(item("requires_change"));
        }
    }

    for missing_id in requested_ids.difference(&seen_requested) {
        exceptions.push(McpAccessPlanItem {
            id: missing_id.clone(),
            available_in_mcp: None,
            desired: input.desired,
            reason: "not_found",
        });
    }

    let readback_digest =
        mcp_access_reconcile_digest(input, server_id, &planned, &changed, &skipped, &exceptions)?;
    Ok(McpAccessPlan {
        planned,
        changed,
        skipped,
        exceptions,
        readback_digest,
    })
}

fn require_exact_object<'a>(
    input: &'a serde_json::Value,
    allowed: &[&str],
    label: &str,
) -> N8nResult<&'a serde_json::Map<String, serde_json::Value>> {
    let object = input
        .as_object()
        .ok_or_else(|| N8nError::InvalidInput(format!("{label} must be an object")))?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(N8nError::InvalidInput(format!(
            "{label} contains an unsupported property"
        )));
    }
    Ok(object)
}

fn parse_u64_field(value: &serde_json::Value, field: &str) -> N8nResult<u64> {
    value
        .as_u64()
        .ok_or_else(|| N8nError::InvalidInput(format!("{field} must be a non-negative integer")))
}

fn require_path_str<'a>(
    input: &'a serde_json::Value,
    field: &str,
    label: &str,
) -> N8nResult<&'a str> {
    let value = require_str(input, field)?;
    sanitize_path_segment(value, label)
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, N8nError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| N8nError::InvalidInput(format!("Missing required field: {field}")))
}

/// Build a single [`OperationInfo`].
#[allow(clippy::fn_params_excessive_bools)]
#[allow(clippy::too_many_arguments)]
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
        description: Some(summary.into()),
        rate_limit: None,
        requires_approval: Some(match id {
            "n8n.workflows.activate" => ApprovalMode::Policy,
            "n8n.workflows.create_draft" | "n8n.workflows.update_draft" => {
                ApprovalMode::Interactive
            }
            "n8n.mcp_access.reconcile" | "n8n.workflows.lifecycle" => ApprovalMode::Interactive,
            _ => ApprovalMode::None,
        }),
        safety_tier,
        idempotency,
        ai_hints,
    }
}

fn tag_view_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "id": {"type": ["string", "null"]},
            "name": {"type": ["string", "null"]},
        },
    })
}

fn workflow_view_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "name"],
        "properties": {
            "id": {"type": "string"},
            "name": {"type": ["string", "null"]},
            "description": {"type": ["string", "null"]},
            "active": {"type": ["boolean", "null"]},
            "versionId": {"type": ["string", "null"]},
            "activeVersionId": {"type": ["string", "null"]},
            "isArchived": {"type": ["boolean", "null"]},
            "projectId": {"type": ["string", "null"]},
            "parentFolderId": {"type": ["string", "null"]},
            "createdAt": {"type": ["string", "null"]},
            "updatedAt": {"type": ["string", "null"]},
            "availableInMCP": {"type": ["boolean", "null"]},
            "tags": {
                "type": ["array", "null"],
                "items": tag_view_schema(),
            },
        },
    })
}

fn workflow_graph_summary_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["versionId", "graphDigest"],
        "properties": {
            "versionId": {"type": "string"},
            "graphDigest": {
                "type": "string",
                "pattern": "^blake3-256:[0-9a-f]{64}$",
            },
        },
    })
}

fn nullable_workflow_graph_summary_schema() -> serde_json::Value {
    json!({
        "type": ["object", "null"],
        "additionalProperties": false,
        "required": ["versionId", "graphDigest"],
        "properties": {
            "versionId": {"type": "string"},
            "graphDigest": {
                "type": "string",
                "pattern": "^blake3-256:[0-9a-f]{64}$",
            },
        },
    })
}

fn workflow_state_view_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "id",
            "name",
            "projectId",
            "folderId",
            "versionId",
            "active",
            "activeVersionId",
            "isArchived",
            "draft",
            "published",
            "stateDigest",
            "updatedAt",
        ],
        "properties": {
            "id": {"type": "string"},
            "name": {"type": ["string", "null"]},
            "projectId": {"type": ["string", "null"]},
            "folderId": {"type": ["string", "null"]},
            "versionId": {"type": "string"},
            "active": {"type": "boolean"},
            "activeVersionId": {"type": ["string", "null"]},
            "isArchived": {"type": "boolean"},
            "draft": workflow_graph_summary_schema(),
            "published": nullable_workflow_graph_summary_schema(),
            "stateDigest": {
                "type": "string",
                "pattern": "^blake3-256:[0-9a-f]{64}$",
            },
            "updatedAt": {"type": ["string", "null"]},
        },
    })
}

fn execution_view_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "finished"],
        "properties": {
            "id": {"type": "string"},
            "finished": {"type": ["boolean", "null"]},
            "mode": {"type": ["string", "null"]},
            "startedAt": {"type": ["string", "null"]},
            "stoppedAt": {"type": ["string", "null"]},
            "workflowId": {"type": ["string", "null"]},
            "status": {"type": ["string", "null"]},
            "retryOf": {"type": ["string", "null"]},
            "retrySuccessId": {"type": ["string", "null"]},
            "waitTill": {"type": ["string", "null"]},
        },
    })
}

fn project_view_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "name"],
        "properties": {
            "id": {"type": "string"},
            "name": {"type": "string"},
            "type": {"type": ["string", "null"]},
        },
    })
}

fn credential_metadata_view_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["resourceUri", "id", "name", "type"],
        "properties": {
            "resourceUri": {"type": "string"},
            "id": {"type": "string"},
            "name": {"type": "string"},
            "type": {"type": "string"},
        },
    })
}

fn folder_list_item_view_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["resourceUri", "id", "name", "parentFolderId"],
        "properties": {
            "resourceUri": {"type": "string"},
            "id": {"type": "string"},
            "name": {"type": "string"},
            "parentFolderId": {"type": ["string", "null"]},
        },
    })
}

fn folder_list_view_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["count", "data"],
        "properties": {
            "count": {"type": "integer"},
            "data": {
                "type": "array",
                "items": folder_list_item_view_schema(),
            },
        },
    })
}

fn folder_view_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "resourceUri",
            "id",
            "name",
            "parentFolderId",
            "createdAt",
            "updatedAt",
            "totalSubFolders",
            "totalWorkflows",
        ],
        "properties": {
            "resourceUri": {"type": "string"},
            "id": {"type": "string"},
            "name": {"type": "string"},
            "parentFolderId": {"type": ["string", "null"]},
            "createdAt": {"type": "string"},
            "updatedAt": {"type": "string"},
            "totalSubFolders": {"type": "integer"},
            "totalWorkflows": {"type": "integer"},
        },
    })
}

fn tag_record_view_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "name"],
        "properties": {
            "id": {"type": "string"},
            "name": {"type": "string"},
        },
    })
}

fn list_output_schema(item_schema: &serde_json::Value) -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["data"],
        "properties": {
            "data": {
                "type": "array",
                "items": item_schema,
            },
            "nextCursor": {"type": "string"},
        },
    })
}

fn list_input_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [],
        "properties": {
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_LIST_LIMIT,
                "default": DEFAULT_LIST_LIMIT,
            },
            "cursor": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_CURSOR_BYTES,
            },
        },
    })
}

fn workflow_draft_input_schema(update: bool) -> serde_json::Value {
    let mut required = vec!["graph", "guard"];
    let mut guard_required = vec!["approvalRef", "idempotencyKey"];
    if update {
        guard_required.push("precondition");
    }
    let precondition_required = if update {
        vec![
            "versionId",
            "activeVersionId",
            "active",
            "isArchived",
            "stateDigest",
        ]
    } else {
        Vec::new()
    };
    if update {
        required.push("id");
    } else {
        required.push("name");
    }
    let mut properties = serde_json::Map::from_iter([
        (
            "name".to_string(),
            json!({"type": "string", "minLength": 1, "maxLength": 256}),
        ),
        (
            "project_id".to_string(),
            json!({
                "type": "string",
                "description": if update {
                    "Optional project field; omitted preserves the workflow's existing project"
                } else {
                    "Optional target project; omitted means the API-key owner's personal project"
                }
            }),
        ),
        ("parent_folder_id".to_string(), json!({"type": "string"})),
        (
            "graph".to_string(),
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["nodes", "connections"],
                "properties": {
                    "nodes": {"type": "array", "maxItems": 10000},
                    "connections": {"type": "object"},
                    "settings": {
                        "type": ["object", "null"],
                        "description": if update {
                            "Optional settings patch merged with the current settings; availableInMCP cannot be changed by draft update"
                        } else {
                            "Optional settings for the inactive draft; availableInMCP is forced to false and must be enabled later by a separate eligible MCP-access operation"
                        }
                    },
                    "staticData": {},
                    "pinData": {},
                },
            }),
        ),
        (
            "guard".to_string(),
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": guard_required,
                "properties": {
                    "approvalRef": {"type": "string", "minLength": 1, "maxLength": 256},
                    "idempotencyKey": {"type": "string", "format": "uuid"},
                    "precondition": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": precondition_required,
                        "properties": {
                            "versionId": {"type": ["string", "null"]},
                            "activeVersionId": {"type": ["string", "null"]},
                            "active": {"type": "boolean"},
                            "isArchived": {"type": "boolean"},
                            "stateDigest": {"type": ["string", "null"]},
                        },
                    },
                },
            }),
        ),
    ]);
    if update {
        properties.insert("id".to_string(), json!({"type": "string"}));
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
    })
}

fn workflow_draft_output_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["status", "operation", "id", "versionId", "graphDigest", "stateDigest", "active", "activeVersionId", "isArchived", "lifecycle", "readback"],
        "properties": {
            "status": {"type": "string"},
            "operation": {"type": "string"},
            "provider": {"type": "string"},
            "lifecycle": {"type": "string"},
            "retry": {"type": "string"},
            "readback": {"type": "string"},
            "id": {"type": "string"},
            "versionId": {"type": "string"},
            "graphDigest": {"type": "string"},
            "stateDigest": {"type": "string"},
            "active": {"type": "boolean"},
            "activeVersionId": {"type": ["string", "null"]},
            "isArchived": {"type": "boolean"},
            "published": {"type": ["object", "null"]},
        },
    })
}

fn workflow_lifecycle_input_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "action", "guard"],
        "properties": {
            "id": {"type": "string", "minLength": 1, "maxLength": 256},
            "action": {"type": "string", "enum": ["publish", "unpublish"]},
            "versionId": {"type": "string", "minLength": 1, "maxLength": 256},
            "guard": {
                "type": "object",
                "additionalProperties": false,
                "required": ["approvalRef", "idempotencyKey", "precondition"],
                "properties": {
                    "approvalRef": {"type": "string", "minLength": 1, "maxLength": 256},
                    "idempotencyKey": {"type": "string", "format": "uuid"},
                    "precondition": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["versionId", "activeVersionId", "active", "isArchived", "stateDigest"],
                        "properties": {
                            "versionId": {"type": "string", "minLength": 1, "maxLength": 256},
                            "activeVersionId": {"type": ["string", "null"], "maxLength": 256},
                            "active": {"type": "boolean"},
                            "isArchived": {"type": "boolean"},
                            "stateDigest": {"type": "string", "pattern": "^blake3-256:[0-9a-f]{64}$", "maxLength": 75},
                        },
                    },
                },
            },
        },
    })
}

fn workflow_lifecycle_output_schema() -> serde_json::Value {
    let draft = workflow_lifecycle_graph_summary_schema(false);
    let published = workflow_lifecycle_graph_summary_schema(true);
    let state = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "versionId", "active", "activeVersionId", "isArchived", "draft", "published", "stateDigest", "updatedAt"],
        "properties": {
            "id": {"type": "string", "maxLength": 256},
            "name": {"type": ["string", "null"], "maxLength": 256},
            "projectId": {"type": ["string", "null"], "maxLength": 256},
            "folderId": {"type": ["string", "null"], "maxLength": 256},
            "versionId": {"type": "string", "maxLength": 256},
            "active": {"type": "boolean"},
            "activeVersionId": {"type": ["string", "null"], "maxLength": 256},
            "isArchived": {"type": "boolean"},
            "draft": draft,
            "published": published,
            "stateDigest": {"type": "string", "pattern": "^blake3-256:[0-9a-f]{64}$", "maxLength": 75},
            "updatedAt": {"type": ["string", "null"], "maxLength": 128},
        },
    });
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["status", "operation", "action", "provider", "retry", "readback", "before", "after"],
        "properties": {
            "status": {"type": "string", "enum": ["verified", "unknown"]},
            "operation": {"const": "n8n.workflows.lifecycle"},
            "action": {"type": "string", "enum": ["publish", "unpublish"]},
            "provider": {"type": "string", "enum": ["rest", "official_mcp"]},
            "retry": {"type": "string", "enum": ["never_automatic"]},
            "readback": {"type": "string", "enum": ["independent_get"]},
            "before": state.clone(),
            "after": state,
        },
    })
}

fn workflow_lifecycle_graph_summary_schema(nullable: bool) -> serde_json::Value {
    json!({
        "type": if nullable { json!(["object", "null"]) } else { json!("object") },
        "additionalProperties": false,
        "required": ["versionId", "graphDigest"],
        "properties": {
            "versionId": {"type": "string", "maxLength": 256},
            "graphDigest": {"type": "string", "pattern": "^blake3-256:[0-9a-f]{64}$", "maxLength": 75},
        },
    })
}

fn mcp_access_reconcile_input_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["scope", "desired", "dryRun"],
        "properties": {
            "scope": {
                "type": "string",
                "enum": ["workflow_ids", "project", "folder", "all_current"],
            },
            "desired": {"type": "boolean"},
            "dryRun": {"type": "boolean"},
            "projectId": {"type": "string", "minLength": 1, "maxLength": 256},
            "folderId": {"type": "string", "minLength": 1, "maxLength": 256},
            "workflowIds": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_MCP_ACCESS_WORKFLOWS,
                "items": {"type": "string", "minLength": 1, "maxLength": 256},
            },
            "guard": {
                "type": "object",
                "additionalProperties": false,
                "required": ["approvalRef", "dryRunDigest", "idempotencyKey"],
                "properties": {
                    "approvalRef": {"type": "string", "minLength": 1, "maxLength": 256},
                    "dryRunDigest": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 256,
                        "pattern": "^blake3-256:[0-9a-f]{64}$"
                    },
                    "idempotencyKey": {"type": "string", "format": "uuid"},
                },
            },
        },
    })
}

fn mcp_access_reconcile_output_schema() -> serde_json::Value {
    let item = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "availableInMCP", "desired", "reason"],
        "properties": {
            "id": {"type": "string"},
            "availableInMCP": {"type": ["boolean", "null"]},
            "desired": {"type": "boolean"},
            "reason": {"type": "string"},
        },
    });
    let receipt_item = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["resourceDigest", "availableInMCP", "desired", "outcome"],
        "properties": {
            "resourceDigest": {
                "type": "string",
                "maxLength": MAX_MCP_ACCESS_RECEIPT_DIGEST_LENGTH,
                "pattern": "^blake3-256:[0-9a-f]{64}$",
            },
            "availableInMCP": {"type": ["boolean", "null"]},
            "desired": {"type": "boolean"},
            "outcome": {
                "type": "string",
                "maxLength": MAX_MCP_ACCESS_RECEIPT_OUTCOME_LENGTH,
            },
        },
    });
    let receipt = json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema",
            "operation",
            "serverId",
            "scope",
            "desired",
            "dryRun",
            "status",
            "planDigest",
            "readbackDigest",
            "items",
            "receiptDigest",
        ],
        "properties": {
            "schema": {
                "const": MCP_ACCESS_RECEIPT_SCHEMA_V1,
                "maxLength": MCP_ACCESS_RECEIPT_SCHEMA_V1.len(),
            },
            "operation": {
                "const": "n8n.mcp_access.reconcile",
                "maxLength": "n8n.mcp_access.reconcile".len(),
            },
            "serverId": {
                "type": "string",
                "maxLength": MAX_MCP_ACCESS_RECEIPT_SERVER_ID_LENGTH,
            },
            "scope": {
                "type": "string",
                "maxLength": MAX_MCP_ACCESS_RECEIPT_SCOPE_LENGTH,
            },
            "desired": {"type": "boolean"},
            "dryRun": {"type": "boolean"},
            "status": {
                "type": "string",
                "enum": ["planned", "applied", "partial", "unknown"],
            },
            "planDigest": {
                "type": "string",
                "maxLength": MAX_MCP_ACCESS_RECEIPT_DIGEST_LENGTH,
                "pattern": "^blake3-256:[0-9a-f]{64}$",
            },
            "readbackDigest": {
                "type": "string",
                "maxLength": MAX_MCP_ACCESS_RECEIPT_DIGEST_LENGTH,
                "pattern": "^blake3-256:[0-9a-f]{64}$",
            },
            "approvalDigest": {
                "type": ["string", "null"],
                "maxLength": MAX_MCP_ACCESS_RECEIPT_DIGEST_LENGTH,
                "pattern": "^blake3-256:[0-9a-f]{64}$",
            },
            "idempotencyDigest": {
                "type": ["string", "null"],
                "maxLength": MAX_MCP_ACCESS_RECEIPT_DIGEST_LENGTH,
                "pattern": "^blake3-256:[0-9a-f]{64}$",
            },
            "items": {
                "type": "array",
                "maxItems": MAX_MCP_ACCESS_RECEIPT_ITEMS,
                "items": receipt_item,
            },
            "receiptDigest": {
                "type": "string",
                "maxLength": MAX_MCP_ACCESS_RECEIPT_DIGEST_LENGTH,
                "pattern": "^blake3-256:[0-9a-f]{64}$",
            },
        },
    });
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["planned", "changed", "skipped", "exceptions", "readbackDigest", "receipt"],
        "properties": {
            "planned": {"type": "array", "items": item},
            "changed": {"type": "array", "items": item},
            "skipped": {"type": "array", "items": item},
            "exceptions": {"type": "array", "items": item},
            "readbackDigest": {
                "type": "string",
                "pattern": "^blake3-256:[0-9a-f]{64}$",
            },
            "receipt": receipt,
        },
    })
}

/// Build the operations info for introspection.
fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "n8n.workflows.list",
            "List all workflows in the n8n instance",
            list_input_schema(),
            list_output_schema(&workflow_view_schema()),
            "n8n.workflows.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all workflows in the n8n instance.".into(),
                common_mistakes: vec![
                    "Assuming only active workflows are returned — inactive workflows are included in the list.".into(),
                    "Only one bounded page is returned; pass an opaque nextCursor unchanged to continue.".into(),
                ],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("n8n.workflows.get"),
                    CapabilityId::from_static("n8n.workflows.activate"),
                ],
            },
        ),
        op_info(
            "n8n.workflows.get",
            "Get a specific workflow by ID",
            json!({"type": "object", "additionalProperties": false, "required": ["id"], "properties": {"id": {"type": "string", "description": "Workflow identifier"}}}),
            workflow_state_view_schema(),
            "n8n.workflows.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve details of a specific n8n workflow by ID.".into(),
                common_mistakes: vec![
                    "Using the workflow name or slug instead of the numeric workflow ID.".into(),
                    "Treating graphDigest as a write precondition; stateDigest is the credential- and lifecycle-sensitive guard.".into(),
                    "Expecting raw nodes, Code source, credential references, or pinned data in the normalized output.".into(),
                ],
                examples: vec![r#"{"id": "1001"}"#.into()],
                related: vec![
                    CapabilityId::from_static("n8n.workflows.list"),
                    CapabilityId::from_static("n8n.workflows.activate"),
                ],
            },
        ),
        op_info(
            "n8n.workflows.create_draft",
            "Create an inactive n8n workflow draft and verify it by independent readback",
            workflow_draft_input_schema(false),
            workflow_draft_output_schema(),
            "n8n.workflows.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Create a draft only after current-chat approval is bound to the exact graph and server.".into(),
                common_mistakes: vec![
                    "This operation never publishes, activates, or archives a workflow.".into(),
                    "A new inactive draft is created with availableInMCP=false; MCP access requires a separate approval after n8n activation and Webhook eligibility checks.".into(),
                    "A timeout or malformed write response is unknown; reconcile with GET and never retry automatically.".into(),
                ],
                examples: vec![r#"{"name":"Daily report","project_id":"project-1","graph":{"nodes":[],"connections":{}},"guard":{"approvalRef":"approval-1","idempotencyKey":"00000000-0000-4000-8000-000000000001"}}"#.into()],
                related: vec![
                    CapabilityId::from_static("n8n.workflows.get"),
                    CapabilityId::from_static("n8n.workflows.update_draft"),
                ],
            },
        ),
        op_info(
            "n8n.workflows.update_draft",
            "Update an n8n workflow draft with full lifecycle preconditions and verify readback",
            workflow_draft_input_schema(true),
            workflow_draft_output_schema(),
            "n8n.workflows.write",
            RiskLevel::High,
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Update a draft only when current-chat approval matches the full version/lifecycle precondition and exact graph digest.".into(),
                common_mistakes: vec![
                    "The full versionId, explicit activeVersionId (null or value), active, isArchived, and stateDigest precondition is required.".into(),
                    "Draft update preserves availableInMCP and rejects attempts to change it; use the separate MCP-access operation.".into(),
                    "A successful draft update preserves published and lifecycle state; ambiguous writes are never retried automatically.".into(),
                ],
                examples: vec![r#"{"id":"1001","graph":{"nodes":[],"connections":{}},"guard":{"approvalRef":"approval-1","idempotencyKey":"00000000-0000-4000-8000-000000000002","precondition":{"versionId":"draft-v1","activeVersionId":null,"active":false,"isArchived":false,"stateDigest":"blake3-256:..."}}}"#.into()],
                related: vec![
                    CapabilityId::from_static("n8n.workflows.get"),
                    CapabilityId::from_static("n8n.workflows.create_draft"),
                ],
            },
        ),
        op_info(
            "n8n.workflows.activate",
            "Capability- and approval-gated activation boundary; packet 1 fails closed and defers provider lifecycle I/O",
            json!({"type": "object", "additionalProperties": false, "required": ["id", "active"], "properties": {"id": {"type": "string", "description": "Workflow identifier"}, "active": {"type": "boolean", "description": "Whether to activate (true) or deactivate (false)"}}}),
            json!({"type": "object", "additionalProperties": false, "required": ["id"], "properties": {"id": {"type": "string"}}}),
            "n8n.workflows.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Request activation or deactivation only when the host has the mediated lifecycle path; packet 1 verifies capability and approval, then fails closed before provider I/O.".into(),
                common_mistakes: vec![
                    "Expecting packet 1 to change provider lifecycle state; activation is deferred until the mediated write path is available.".into(),
                    "Passing the workflow name instead of the numeric workflow ID, or omitting the matching execution approval.".into(),
                ],
                examples: vec![r#"{"id": "1001", "active": true}"#.into()],
                related: vec![
                    CapabilityId::from_static("n8n.workflows.get"),
                    CapabilityId::from_static("n8n.workflows.list"),
                ],
            },
        ),
        op_info(
            "n8n.workflows.lifecycle",
            "Publish or unpublish through the exact official n8n MCP lifecycle tool only after fresh capability-policy validation, exact lifecycle approval, and independent REST GET readback",
            workflow_lifecycle_input_schema(),
            workflow_lifecycle_output_schema(),
            "n8n.workflows.lifecycle",
            RiskLevel::High,
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Use only for publish or unpublish with an exact workflow target, UUID idempotency key, full current lifecycle precondition, current-chat approval, and an owner-provisioned policy entry matching fresh official MCP tools/list schema digests.".into(),
                common_mistakes: vec![
                    "Archive, restore, activate, deactivate, version, execution, and credential operations are not part of this packet.".into(),
                    "Publish and unpublish use only the exact approved official MCP tools publish_workflow and unpublish_workflow after fresh tools/list discovery; direct REST lifecycle routes remain an explicit fail-closed fallback and no legacy route is guessed.".into(),
                    "A timeout, disconnect, conflict, server error, or ambiguous response is unknown and is never retried automatically; success requires an independent GET readback preserving the draft.".into(),
                    "activeVersionId must be present explicitly, including JSON null, and stateDigest must match the approved baseline.".into(),
                ],
                examples: vec![r#"{"id":"1001","action":"publish","versionId":"published-v1","guard":{"approvalRef":"approval-1","idempotencyKey":"00000000-0000-4000-8000-000000000003","precondition":{"versionId":"draft-v1","activeVersionId":null,"active":false,"isArchived":false,"stateDigest":"blake3-256:0000000000000000000000000000000000000000000000000000000000000000"}}}"#.into()],
                related: vec![
                    CapabilityId::from_static("n8n.workflows.get"),
                    CapabilityId::from_static("n8n.workflows.activate"),
                ],
            },
        ),
        op_info(
            "n8n.executions.list",
            "List recent workflow executions",
            list_input_schema(),
            list_output_schema(&execution_view_schema()),
            "n8n.executions.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List recent workflow executions in n8n.".into(),
                common_mistakes: vec![
                    "Expecting executions from all workflows — results may be limited to the most recent across the instance.".into(),
                    "Only one bounded page is returned; pass an opaque nextCursor unchanged to continue.".into(),
                ],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("n8n.executions.get"),
                    CapabilityId::from_static("n8n.workflows.list"),
                ],
            },
        ),
        op_info(
            "n8n.executions.get",
            "Get details of a specific execution",
            json!({"type": "object", "additionalProperties": false, "required": ["workflow_id", "id"], "properties": {"workflow_id": {"type": "string", "description": "Workflow identifier containing the execution"}, "id": {"type": "string", "description": "Execution identifier"}}}),
            execution_view_schema(),
            "n8n.executions.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve details of a specific workflow execution by ID.".into(),
                common_mistakes: vec![
                    "Using the workflow ID instead of the execution ID.".into(),
                    "Querying an execution before it has finished — check the 'finished' field in the response.".into(),
                ],
                examples: vec![r#"{"workflow_id": "1001", "id": "50001"}"#.into()],
                related: vec![
                    CapabilityId::from_static("n8n.executions.list"),
                    CapabilityId::from_static("n8n.workflows.get"),
                ],
            },
        ),
        op_info(
            "n8n.projects.list",
            "List safe project metadata in the n8n instance",
            list_input_schema(),
            list_output_schema(&project_view_schema()),
            "n8n.projects.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List safe project metadata in the n8n instance.".into(),
                common_mistakes: vec![
                    "Only one bounded page is returned; pass an opaque nextCursor unchanged to continue.".into(),
                    "Project output is limited to id, name, and optional type; memberships and provider metadata are discarded.".into(),
                ],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static("n8n.workflows.list")],
            },
        ),
        op_info(
            "n8n.credentials.list",
            "List safe credential metadata in the n8n instance",
            list_input_schema(),
            list_output_schema(&credential_metadata_view_schema()),
            "n8n.credentials.metadata.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List credential metadata without retrieving credential values.".into(),
                common_mistakes: vec![
                    "The upstream endpoint requires the credential:list scope and owner or admin access.".into(),
                    "Credential values, secret maps, auth headers, and configuration data are never returned.".into(),
                    "Availability and flags vary by n8n version and license; scopes and sharing state are not inferred.".into(),
                    "Only one bounded page is returned; pass an opaque nextCursor unchanged to continue.".into(),
                ],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static("n8n.projects.list")],
            },
        ),
        op_info(
            "n8n.tags.list",
            "List compact tag metadata in the n8n instance",
            list_input_schema(),
            list_output_schema(&tag_record_view_schema()),
            "n8n.tags.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List compact tag metadata in the n8n instance.".into(),
                common_mistakes: vec![
                    "Only one bounded page is returned; pass an opaque nextCursor unchanged to continue.".into(),
                    "Tag output contains only id and name; provider timestamps and metadata are discarded.".into(),
                ],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static("n8n.projects.list")],
            },
        ),
        op_info(
            "n8n.folders.list",
            "List safe folder metadata in an n8n project",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["project_id"],
                "properties": {
                    "project_id": {"type": "string", "description": "Project identifier containing the folders"},
                    "parent_folder_id": {"type": "string", "description": "Optional parent folder identifier filter"},
                    "skip": {"type": "integer", "minimum": 0, "default": 0},
                    "take": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
                },
            }),
            folder_list_view_schema(),
            "n8n.folders.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List safe folder metadata in an n8n project.".into(),
                common_mistakes: vec![
                    "Use project_id, not a redundant server_id; server identity comes from connector configuration.".into(),
                    "The provider returns {count,data}; folder list output is limited to the fixed safe projection.".into(),
                    "The upstream folder:list surface requires n8n 2.19.0 or newer with feat:folders.".into(),
                    "A provider 403 is ambiguous among folder license, API-key scope, and project RBAC; no current mechanical discriminator is claimed.".into(),
                    "Before n8n 2.19, or when the route is absent, expect 404; version/route inspection is a future non-mechanical OpenAPI probe.".into(),
                ],
                examples: vec![r#"{"project_id": "project-1"}"#.into()],
                related: vec![
                    CapabilityId::from_static("n8n.folders.get"),
                    CapabilityId::from_static("n8n.projects.list"),
                ],
            },
        ),
        op_info(
            "n8n.folders.get",
            "Get safe details of an n8n project folder",
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["project_id", "folder_id"],
                "properties": {
                    "project_id": {"type": "string", "description": "Project identifier containing the folder"},
                    "folder_id": {"type": "string", "description": "Folder identifier"},
                },
            }),
            folder_view_schema(),
            "n8n.folders.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve safe folder details from an n8n project.".into(),
                common_mistakes: vec![
                    "Use both project_id and folder_id; folder IDs are scoped to a project.".into(),
                    "The upstream folder:read surface requires n8n 2.19.0 or newer with feat:folders.".into(),
                    "A provider 403 is ambiguous among folder license, API-key scope, and project RBAC; no current mechanical discriminator is claimed.".into(),
                    "Before n8n 2.19, or when the route is absent, expect 404; version/route inspection is a future non-mechanical OpenAPI probe.".into(),
                ],
                examples: vec![r#"{"project_id": "project-1", "folder_id": "folder-1"}"#.into()],
                related: vec![
                    CapabilityId::from_static("n8n.folders.list"),
                    CapabilityId::from_static("n8n.projects.list"),
                ],
            },
        ),
        op_info(
            "n8n.mcp_access.reconcile",
            "Read and reconcile the official n8n MCP availability policy for the configured server",
            mcp_access_reconcile_input_schema(),
            mcp_access_reconcile_output_schema(),
            "n8n.mcp_access.write",
            RiskLevel::High,
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Run a bounded dry-run first; apply only the exact approved digest to explicit workflow MCP availability changes.".into(),
                common_mistakes: vec![
                    "The configured server identity is authoritative; never infer it from a workflow name.".into(),
                    "dryRun=true performs only bounded workflow metadata reads and does not require approval.".into(),
                    "dryRun=false requires a matching approval and exact current dry-run digest; writes contain only settings.availableInMCP.".into(),
                    "A provider timeout or ambiguous result is reported per workflow and is never retried automatically.".into(),
                    "Archived workflows are skipped and unknown archive or availability states are reported as exceptions.".into(),
                ],
                examples: vec![r#"{"scope":"all_current","desired":true,"dryRun":true}"#.into()],
                related: vec![
                    CapabilityId::from_static("n8n.workflows.list"),
                    CapabilityId::from_static("n8n.workflows.get"),
                ],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RequiredNullable;
    use fcp_prelude::ExecutionScope;

    fn digest_test_workflow() -> WorkflowDetail {
        serde_json::from_value(json!({
            "id": "workflow-1",
            "name": "Digest test",
            "description": "baseline",
            "active": false,
            "versionId": "draft-v1",
            "activeVersionId": null,
            "isArchived": false,
            "projectId": "project-1",
            "parentFolderId": "folder-1",
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-02T00:00:00Z",
            "tags": [{"id": "tag-1", "name": "baseline"}],
            "nodes": [{
                "id": "node-1",
                "type": "n8n-nodes-base.code",
                "parameters": {"jsCode": "return items;"},
                "credentials": {"api": {"id": "credential-1"}}
            }],
            "connections": {},
            "settings": {"availableInMCP": true},
            "activeVersion": null
        }))
        .unwrap()
    }

    fn normalized_state_digest(workflow: WorkflowDetail) -> String {
        normalize_workflow_state(workflow).unwrap().state_digest
    }

    fn mutation_digest_golden_input(credential_id: &str) -> Value {
        json!({
            "graph": {
                "connections": {},
                "nodes": [{
                    "credentials": {
                        "httpBasicAuth": {"id": credential_id}
                    },
                    "id": "http-node",
                    "type": "n8n-nodes-base.httpRequest"
                }],
                "pinData": null,
                "settings": null,
                "staticData": null
            },
            "id": null,
            "name": "Credential-bound workflow",
            "parent_folder_id": null,
            "project_id": "project-1"
        })
    }

    #[test]
    fn draft_mutation_digest_matches_host_golden_vectors() {
        let credential_one = draft_mutation_digest(
            "n8n.workflows.create_draft",
            &mutation_digest_golden_input("credential-1"),
        )
        .expect("credential-1 mutation digest");
        let credential_two = draft_mutation_digest(
            "n8n.workflows.create_draft",
            &mutation_digest_golden_input("credential-2"),
        )
        .expect("credential-2 mutation digest");

        assert_eq!(
            (credential_one.as_str(), credential_two.as_str()),
            (
                "blake3-256:d34cb28e2a1b6d54e559a6e2b25219b3ffc825daad1582e3a2fbde1ac69c80ad",
                "blake3-256:c1f951ef0958caacd4526da532b481f63eb2620b4fd1f6719a150a5f16997e64"
            )
        );
        assert_ne!(credential_one, credential_two);
    }

    #[test]
    fn canonical_draft_settings_separates_drafts_from_mcp_access() {
        let base = json!({"graph": {"nodes": [], "connections": {}}});
        assert_eq!(
            canonical_draft_settings("n8n.workflows.create_draft", &base).unwrap(),
            json!({"availableInMCP": false})
        );

        let mut explicit_null = base.clone();
        explicit_null["graph"]["settings"] = Value::Null;
        assert_eq!(
            canonical_draft_settings("n8n.workflows.create_draft", &explicit_null).unwrap(),
            json!({"availableInMCP": false})
        );

        let mut object = base.clone();
        object["graph"]["settings"] = json!({"executionOrder": "v1"});
        assert_eq!(
            canonical_draft_settings("n8n.workflows.create_draft", &object).unwrap(),
            json!({"executionOrder": "v1", "availableInMCP": false})
        );

        let mut explicit_false = base.clone();
        explicit_false["graph"]["settings"] = json!({"availableInMCP": false});
        assert!(canonical_draft_settings("n8n.workflows.create_draft", &explicit_false).is_ok());

        for value in [json!(true), json!("true"), Value::Null] {
            let mut rejected = json!({"graph": {"nodes": [], "connections": {}}});
            rejected["graph"]["settings"] = if value.is_null() {
                json!({"availableInMCP": null})
            } else {
                json!({"availableInMCP": value})
            };
            assert!(matches!(
                canonical_draft_settings("n8n.workflows.create_draft", &rejected),
                Err(N8nError::InvalidInput(_))
            ));
        }

        assert_eq!(
            canonical_draft_settings("n8n.workflows.update_draft", &base).unwrap(),
            json!({})
        );
        let mut update_settings = base;
        update_settings["graph"]["settings"] = json!({"executionOrder": "v1"});
        assert!(canonical_draft_settings("n8n.workflows.update_draft", &update_settings).is_ok());
        update_settings["graph"]["settings"] = json!({"availableInMCP": false});
        assert!(matches!(
            canonical_draft_settings("n8n.workflows.update_draft", &update_settings),
            Err(N8nError::InvalidInput(_))
        ));

        let mut non_object = json!({"graph": {"nodes": [], "connections": {}}});
        non_object["graph"]["settings"] = json!(true);
        assert!(matches!(
            canonical_draft_settings("n8n.workflows.create_draft", &non_object),
            Err(N8nError::InvalidInput(_))
        ));
    }

    #[test]
    fn host_request_attribution_preserves_outer_request_identity() {
        let attribution = host_request_attribution(&json!({
            "id": "req_00000000000000000001",
            "correlation_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        }))
        .unwrap()
        .unwrap();
        assert_eq!(attribution.request_id, "req_00000000000000000001");
        assert_eq!(
            attribution.correlation_id.as_deref(),
            Some("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
        );
    }

    #[test]
    fn host_request_attribution_keeps_legacy_fallback_when_absent() {
        assert!(host_request_attribution(&json!({})).unwrap().is_none());
        assert!(
            host_request_attribution(&json!({"correlation_id": null}))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn host_request_attribution_rejects_partial_or_malformed_identity() {
        for params in [
            json!({"id": ""}),
            json!({"id": " leading-space"}),
            json!({"id": "embedded\ncontrol"}),
            json!({"id": 42}),
            json!({"correlation_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}),
            json!({
                "id": "11111111-2222-4333-8444-555555555555",
                "correlation_id": "not-a-uuid"
            }),
            json!({
                "id": "11111111-2222-4333-8444-555555555555",
                "correlation_id": 42
            }),
        ] {
            assert!(host_request_attribution(&params).is_err());
        }
    }

    #[test]
    fn state_digest_covers_metadata_lifecycle_versions_and_graphs() {
        let baseline = digest_test_workflow();
        let expected = normalized_state_digest(baseline.clone());
        let mut variants = Vec::new();

        let mut variant = baseline.clone();
        variant.active = true;
        variants.push(variant);

        let mut variant = baseline.clone();
        variant.is_archived = true;
        variants.push(variant);

        let mut variant = baseline.clone();
        variant.version_id = "draft-v2".into();
        variants.push(variant);

        let mut variant = baseline.clone();
        variant.created_at = Some("2026-01-01T00:00:01Z".into());
        variants.push(variant);

        let mut variant = baseline.clone();
        variant.updated_at = Some("2026-01-02T00:00:01Z".into());
        variants.push(variant);

        let mut variant = baseline.clone();
        variant.name = Some("Changed name".into());
        variants.push(variant);

        let mut variant = baseline.clone();
        variant.description = Some("changed description".into());
        variants.push(variant);

        let mut variant = baseline.clone();
        variant.project_id = Some("project-2".into());
        variants.push(variant);

        let mut variant = baseline.clone();
        variant.parent_folder_id = Some("folder-2".into());
        variants.push(variant);

        let mut variant = baseline.clone();
        variant.tags = Some(vec![crate::types::Tag {
            id: Some("tag-2".into()),
            name: Some("changed".into()),
        }]);
        variants.push(variant);

        let mut variant = baseline.clone();
        variant.nodes[0]["credentials"]["api"]["id"] = json!("credential-2");
        variants.push(variant);

        let mut variant = baseline;
        variant.active_version_id = RequiredNullable::Value("published-v1".into());
        variant.active_version = RequiredNullable::Value(WorkflowVersion {
            version_id: "published-v1".into(),
            nodes: vec![json!({
                "id": "published-node",
                "parameters": {"jsCode": "return [];"},
                "credentials": {"api": {"id": "published-credential"}}
            })],
            connections: json!({}),
        });
        variants.push(variant);

        for variant in variants {
            assert_ne!(expected, normalized_state_digest(variant));
        }
    }

    #[test]
    fn code_source_changes_semantic_graph_digest() {
        let first = workflow_graph_digest(
            &[json!({
                "id": "code-node",
                "parameters": {"jsCode": "return items;"},
                "credentials": {"api": {"id": "credential-1"}}
            })],
            &json!({}),
        )
        .unwrap();
        let second = workflow_graph_digest(
            &[json!({
                "id": "code-node",
                "parameters": {"jsCode": "return [];"},
                "credentials": {"api": {"id": "credential-2"}}
            })],
            &json!({}),
        )
        .unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn graph_digest_preserves_semantic_array_order() {
        let first = workflow_graph_digest(
            &[json!({
                "id": "node-1",
                "parameters": {"values": ["first", "second"]}
            })],
            &json!({}),
        )
        .unwrap();
        let second = workflow_graph_digest(
            &[json!({
                "id": "node-1",
                "parameters": {"values": ["second", "first"]}
            })],
            &json!({}),
        )
        .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn published_graph_digest_excludes_credentials_but_state_digest_keeps_them() {
        let mut first = digest_test_workflow();
        first.active_version_id = RequiredNullable::Value("published-v1".into());
        first.active_version = RequiredNullable::Value(WorkflowVersion {
            version_id: "published-v1".into(),
            nodes: vec![json!({
                "id": "published-node",
                "parameters": {"jsCode": "return items;"},
                "credentials": {"api": {"id": "published-credential-1"}}
            })],
            connections: json!({}),
        });
        let mut second = first.clone();
        let RequiredNullable::Value(second_published) = &mut second.active_version else {
            unreachable!("test fixture has a published version");
        };
        second_published.nodes[0]["credentials"]["api"]["id"] = json!("published-credential-2");

        let first = normalize_workflow_state(first).unwrap();
        let second = normalize_workflow_state(second).unwrap();
        assert_eq!(
            first.published.as_ref().unwrap().graph_digest,
            second.published.as_ref().unwrap().graph_digest
        );
        assert_ne!(first.state_digest, second.state_digest);
    }

    #[test]
    fn config_from_api_key() {
        let config = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "api_key": "test-api-key",
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .unwrap();
        assert!(matches!(config.auth, N8nAuth::ApiKey(_)));
        assert_eq!(config.base_url, "https://n8n.example.com/api/v1");
    }

    #[test]
    fn config_from_credential_id() {
        let config = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "api_key": "key",
            "base_url": "http://localhost:5678/api/v1",
        }))
        .unwrap();
        assert_eq!(config.base_url, "http://localhost:5678/api/v1");
    }

    #[test]
    fn config_rejects_missing_server_id() {
        let result = N8nConfig::from_params(&json!({
            "api_key": "key",
            "base_url": "https://n8n.example.com/api/v1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_server_id() {
        let result = N8nConfig::from_params(&json!({
            "server_id": "other",
            "api_key": "key",
            "base_url": "https://n8n.example.com/api/v1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "api_key": "key",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://n8n.example.com/api/v1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "base_url": "https://n8n.example.com/api/v1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_key() {
        let result = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "api_key": "",
            "base_url": "https://n8n.example.com/api/v1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        let result = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "api_key": "   ",
            "base_url": "https://n8n.example.com/api/v1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "credential_id": 12345,
            "base_url": "https://n8n.example.com/api/v1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "credential_id": "not-a-uuid",
            "base_url": "https://n8n.example.com/api/v1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_missing_base_url() {
        let result = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "api_key": "key",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_base_url() {
        let result = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "api_key": "key",
            "base_url": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_base_url() {
        let result = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "api_key": "key",
            "base_url": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"id": "1001"});
        assert_eq!(require_str(&input, "id").unwrap(), "1001");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"id": 42});
        assert!(require_str(&input, "id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"id": null});
        assert!(require_str(&input, "id").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"id": true});
        assert!(require_str(&input, "id").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"id": [1, 2, 3]});
        assert!(require_str(&input, "id").is_err());
    }

    #[test]
    fn operations_info_has_14_operations() {
        let ops = operations_info();
        assert_eq!(ops.len(), 14);
        let operation_ids = ops
            .iter()
            .map(|operation| operation.id.as_ref())
            .collect::<Vec<_>>();
        assert!(operation_ids.contains(&"n8n.folders.list"));
        assert!(operation_ids.contains(&"n8n.folders.get"));
        assert!(operation_ids.contains(&"n8n.credentials.list"));
        assert!(operation_ids.contains(&"n8n.workflows.create_draft"));
        assert!(operation_ids.contains(&"n8n.workflows.update_draft"));
        assert!(operation_ids.contains(&"n8n.workflows.lifecycle"));
        assert!(operation_ids.contains(&"n8n.mcp_access.reconcile"));
    }

    #[test]
    fn mcp_access_dry_run_plans_only_explicit_non_archived_changes() {
        let input = parse_mcp_access_input(&json!({
            "scope": "all_current",
            "desired": true,
            "dryRun": true,
        }))
        .expect("valid dry-run input");
        let workflows: Vec<Workflow> = serde_json::from_value(json!([
            {
                "id": "already-enabled",
                "isArchived": false,
                "settings": {"availableInMCP": true}
            },
            {
                "id": "needs-enable",
                "isArchived": false,
                "settings": {"availableInMCP": false}
            },
            {
                "id": "archived",
                "isArchived": true,
                "settings": {"availableInMCP": false}
            },
            {
                "id": "unknown-availability",
                "isArchived": false,
                "settings": {"timeSavedMode": "fixed"}
            }
        ]))
        .unwrap();
        let plan = plan_mcp_access_reconcile(&input, &workflows, "eec").unwrap();
        assert_eq!(plan.planned.len(), 1);
        assert_eq!(plan.planned[0].id, "needs-enable");
        assert!(plan.changed.is_empty());
        assert_eq!(plan.skipped[0].reason, "already_desired");
        assert_eq!(plan.skipped[1].reason, "archived");
        assert_eq!(plan.exceptions[0].reason, "availability_state_unknown");
        assert!(plan.readback_digest.starts_with("blake3-256:"));
    }

    #[test]
    fn mcp_access_workflow_id_scope_reports_missing_ids() {
        let input = parse_mcp_access_input(&json!({
            "scope": "workflow_ids",
            "desired": false,
            "dryRun": true,
            "workflowIds": ["present", "missing"]
        }))
        .expect("valid workflow ID scope");
        let workflows: Vec<Workflow> = serde_json::from_value(json!([
            {
                "id": "present",
                "isArchived": false,
                "settings": {"availableInMCP": true}
            }
        ]))
        .unwrap();
        let plan = plan_mcp_access_reconcile(&input, &workflows, "eec").unwrap();
        assert_eq!(plan.planned.len(), 1);
        assert_eq!(plan.planned[0].id, "present");
        assert_eq!(plan.exceptions[0].id, "missing");
        assert_eq!(plan.exceptions[0].reason, "not_found");
    }

    #[test]
    fn mcp_access_input_rejects_write_without_guard_and_scope_smuggling() {
        assert!(
            parse_mcp_access_input(&json!({
                "scope": "all_current",
                "desired": true,
                "dryRun": false,
            }))
            .is_err()
        );
        assert!(
            parse_mcp_access_input(&json!({
                "scope": "folder",
                "desired": true,
                "dryRun": true,
                "folderId": "folder-1",
                "projectId": "project-1",
            }))
            .is_err()
        );
    }

    fn mcp_access_receipt_test_digest() -> String {
        format!("blake3-256:{}", "0".repeat(64))
    }

    fn mcp_access_receipt_test_plan(
        planned: Vec<McpAccessPlanItem>,
        changed: Vec<McpAccessPlanItem>,
        skipped: Vec<McpAccessPlanItem>,
        exceptions: Vec<McpAccessPlanItem>,
    ) -> McpAccessPlan {
        McpAccessPlan {
            planned,
            changed,
            skipped,
            exceptions,
            readback_digest: mcp_access_receipt_test_digest(),
        }
    }

    fn mcp_access_receipt_test_item(
        id: &str,
        available_in_mcp: Option<bool>,
        desired: bool,
        reason: &'static str,
    ) -> McpAccessPlanItem {
        McpAccessPlanItem {
            id: id.into(),
            available_in_mcp,
            desired,
            reason,
        }
    }

    #[test]
    fn mcp_access_receipt_preflight_rejects_oversized_before_provider_write() {
        let input = parse_mcp_access_input(&json!({
            "scope": "all_current",
            "desired": true,
            "dryRun": false,
            "guard": {
                "approvalRef": "approval-redacted",
                "dryRunDigest": mcp_access_receipt_test_digest(),
                "idempotencyKey": "00000000-0000-4000-8000-000000000010"
            }
        }))
        .unwrap();
        let oversized_plan = mcp_access_receipt_test_plan(
            (0..=MAX_MCP_ACCESS_RECEIPT_ITEMS)
                .map(|index| {
                    mcp_access_receipt_test_item(
                        &format!("wf-preflight-{index}"),
                        Some(false),
                        true,
                        "requires_change",
                    )
                })
                .collect(),
            vec![],
            vec![],
            vec![],
        );
        let guard = McpAccessReconcileGuard {
            approval_ref: "approval-redacted".into(),
            dry_run_digest: mcp_access_receipt_test_digest(),
            idempotency_key: "00000000-0000-4000-8000-000000000010".into(),
        };
        let mut provider_writes = 0;
        let preflight = mcp_access_receipt_capacity_guard(
            &input,
            "eec",
            &oversized_plan,
            &guard.dry_run_digest,
            Some(&guard),
        );
        // Keep the write counter explicit: a caller must not reach its first
        // provider write when the preflight receipt is rejected.
        if preflight.is_ok() {
            provider_writes += 1;
        }
        assert!(preflight.is_err());
        assert_eq!(provider_writes, 0);
    }

    #[test]
    fn mcp_access_receipt_is_redacted_bounded_and_deterministic() {
        let input = parse_mcp_access_input(&json!({
            "scope": "workflow_ids",
            "workflowIds": ["wf-sensitive"],
            "desired": true,
            "dryRun": true,
        }))
        .unwrap();
        let first = mcp_access_receipt_test_plan(
            vec![mcp_access_receipt_test_item(
                "wf-sensitive",
                Some(false),
                true,
                "requires_change",
            )],
            vec![],
            vec![],
            vec![],
        );
        let second = mcp_access_receipt_test_plan(
            vec![mcp_access_receipt_test_item(
                "wf-sensitive",
                Some(false),
                true,
                "requires_change",
            )],
            vec![],
            vec![],
            vec![],
        );
        let first_receipt =
            McpAccessReceipt::from_plan(&input, "eec", &first, &first.readback_digest, None)
                .unwrap();
        let second_receipt =
            McpAccessReceipt::from_plan(&input, "eec", &second, &second.readback_digest, None)
                .unwrap();
        assert_eq!(first_receipt, second_receipt);
        let encoded = serde_json::to_string(&first_receipt).unwrap();
        assert!(!encoded.contains("wf-sensitive"));
        assert!(!encoded.contains("credentials"));
        assert!(!encoded.contains("Code node"));
        assert!(encoded.contains("resourceDigest"));
        assert!(encoded.len() <= MAX_MCP_ACCESS_RECEIPT_BYTES);

        let mut oversized = first_receipt.clone();
        oversized.items[0].outcome = "x".repeat(MAX_MCP_ACCESS_RECEIPT_BYTES);
        assert!(oversized.validate().is_err());

        let too_many = mcp_access_receipt_test_plan(
            (0..=MAX_MCP_ACCESS_RECEIPT_ITEMS)
                .map(|index| {
                    mcp_access_receipt_test_item(
                        &format!("wf-too-many-{index}"),
                        Some(false),
                        true,
                        "requires_change",
                    )
                })
                .collect(),
            vec![],
            vec![],
            vec![],
        );
        assert!(
            McpAccessReceipt::from_plan(&input, "eec", &too_many, &too_many.readback_digest, None,)
                .is_err()
        );

        let overlapping = mcp_access_receipt_test_plan(
            (0..600)
                .map(|index| {
                    mcp_access_receipt_test_item(
                        &format!("wf-{index}"),
                        Some(false),
                        true,
                        "requires_change",
                    )
                })
                .collect(),
            (0..600)
                .map(|index| {
                    mcp_access_receipt_test_item(
                        &format!("wf-{index}"),
                        Some(true),
                        true,
                        "updated_and_verified",
                    )
                })
                .collect(),
            vec![],
            vec![],
        );
        let receipt = McpAccessReceipt::from_plan(
            &input,
            "eec",
            &overlapping,
            &overlapping.readback_digest,
            None,
        )
        .expect("overlapping planned/changed entries count once");
        assert_eq!(receipt.items.len(), 600);
        assert!(
            receipt
                .items
                .iter()
                .all(|item| item.outcome == "changed:updated_and_verified")
        );
    }

    #[test]
    fn mcp_access_receipt_apply_uses_terminal_accounting_only() {
        let input = parse_mcp_access_input(&json!({
            "scope": "workflow_ids",
            "workflowIds": ["wf-changed", "wf-skipped", "wf-exception"],
            "desired": true,
            "dryRun": false,
            "guard": {
                "approvalRef": "approval-redacted",
                "dryRunDigest": mcp_access_receipt_test_digest(),
                "idempotencyKey": "00000000-0000-4000-8000-000000000011"
            }
        }))
        .unwrap();
        let guard = McpAccessReconcileGuard {
            approval_ref: "approval-redacted".into(),
            dry_run_digest: mcp_access_receipt_test_digest(),
            idempotency_key: "00000000-0000-4000-8000-000000000011".into(),
        };
        let plan = mcp_access_receipt_test_plan(
            vec![mcp_access_receipt_test_item(
                "wf-changed",
                Some(false),
                true,
                "requires_change",
            )],
            vec![mcp_access_receipt_test_item(
                "wf-changed",
                Some(true),
                true,
                "updated_and_verified",
            )],
            vec![mcp_access_receipt_test_item(
                "wf-skipped",
                Some(true),
                true,
                "already_desired_on_recheck",
            )],
            vec![mcp_access_receipt_test_item(
                "wf-exception",
                Some(false),
                true,
                "provider_forbidden",
            )],
        );
        let receipt =
            McpAccessReceipt::from_plan(&input, "eec", &plan, &guard.dry_run_digest, Some(&guard))
                .unwrap();
        assert_eq!(receipt.items.len(), 3);
        assert!(receipt.items.iter().all(|item| {
            !item.outcome.starts_with("planned:")
                && (item.outcome.starts_with("changed:")
                    || item.outcome.starts_with("skipped:")
                    || item.outcome.starts_with("exception:"))
        }));
    }

    #[test]
    fn mcp_access_receipt_statuses_cover_success_partial_unknown_and_revoke() {
        let guard = McpAccessReconcileGuard {
            approval_ref: "approval-redacted".into(),
            dry_run_digest: mcp_access_receipt_test_digest(),
            idempotency_key: "00000000-0000-4000-8000-000000000009".into(),
        };
        let input = parse_mcp_access_input(&json!({
            "scope": "workflow_ids",
            "workflowIds": ["wf-revoke"],
            "desired": false,
            "dryRun": false,
            "guard": {
                "approvalRef": "approval-redacted",
                "dryRunDigest": mcp_access_receipt_test_digest(),
                "idempotencyKey": "00000000-0000-4000-8000-000000000009"
            }
        }))
        .unwrap();
        let success_plan = mcp_access_receipt_test_plan(
            vec![],
            vec![mcp_access_receipt_test_item(
                "wf-revoke",
                Some(false),
                false,
                "updated_and_verified",
            )],
            vec![],
            vec![],
        );
        let success = McpAccessReceipt::from_plan(
            &input,
            "eec",
            &success_plan,
            &guard.dry_run_digest,
            Some(&guard),
        )
        .unwrap();
        assert_eq!(success.status, McpAccessReceiptStatus::Applied);
        assert!(!success.dry_run);
        assert!(!success.desired);
        assert!(success.approval_digest.is_some());
        assert!(success.idempotency_digest.is_some());
        assert_eq!(success.items[0].available_in_mcp, Some(false));

        let partial_plan = mcp_access_receipt_test_plan(
            vec![],
            vec![],
            vec![],
            vec![mcp_access_receipt_test_item(
                "wf-partial",
                Some(true),
                false,
                "provider_forbidden",
            )],
        );
        let partial = McpAccessReceipt::from_plan(
            &input,
            "eec",
            &partial_plan,
            &guard.dry_run_digest,
            Some(&guard),
        )
        .unwrap();
        assert_eq!(partial.status, McpAccessReceiptStatus::Partial);

        let unknown_plan = mcp_access_receipt_test_plan(
            vec![],
            vec![],
            vec![],
            vec![mcp_access_receipt_test_item(
                "wf-unknown",
                Some(true),
                false,
                "provider_unknown_outcome",
            )],
        );
        let unknown = McpAccessReceipt::from_plan(
            &input,
            "eec",
            &unknown_plan,
            &guard.dry_run_digest,
            Some(&guard),
        )
        .unwrap();
        assert_eq!(unknown.status, McpAccessReceiptStatus::Unknown);
    }

    #[test]
    fn mcp_access_receipt_schema_exposes_only_hashed_resource_items() {
        let schema = mcp_access_reconcile_output_schema();
        let receipt = schema.pointer("/properties/receipt").unwrap();
        let item = receipt.pointer("/properties/items/items").unwrap();
        assert!(item.pointer("/properties/resourceDigest").is_some());
        assert!(item.pointer("/properties/id").is_none());
        assert!(
            receipt
                .get("required")
                .and_then(Value::as_array)
                .is_some_and(|required| required.iter().any(|field| field == "receiptDigest"))
        );
    }

    #[test]
    fn draft_operation_schemas_match_create_and_update_id_rules() {
        let operations = operations_info();
        let create = operations
            .iter()
            .find(|operation| operation.id.as_ref() == "n8n.workflows.create_draft")
            .expect("create draft operation");
        let update = operations
            .iter()
            .find(|operation| operation.id.as_ref() == "n8n.workflows.update_draft")
            .expect("update draft operation");

        assert!(create.input_schema.pointer("/properties/id").is_none());
        assert!(update.input_schema.pointer("/properties/id").is_some());
        assert!(
            create
                .input_schema
                .pointer("/properties/project_id")
                .is_some()
        );
        assert!(
            create.input_schema["required"]
                .as_array()
                .is_some_and(|required| !required.iter().any(|field| field == "project_id"))
        );
    }

    #[test]
    fn activation_introspection_describes_deferred_lifecycle() {
        let activation = operations_info()
            .into_iter()
            .find(|op| op.id.as_ref() == "n8n.workflows.activate")
            .expect("activation operation should be catalogued");
        assert!(activation.summary.contains("defer"));
        assert!(activation.summary.contains("fails closed"));
        assert!(activation.ai_hints.when_to_use.contains("fails closed"));
        assert!(
            activation
                .ai_hints
                .common_mistakes
                .iter()
                .any(|mistake| mistake.contains("deferred"))
        );
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.id.as_ref().is_empty(), "missing id");
            assert!(!op.summary.is_empty(), "missing summary");
            assert!(!op.capability.as_ref().is_empty(), "missing capability");
        }
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_risk_levels_valid() {
        // All RiskLevel variants are valid by construction with typed enums.
        let ops = operations_info();
        for op in &ops {
            // Just ensure serialization works
            let v = serde_json::to_value(op.risk_level).unwrap();
            let rl = v.as_str().unwrap();
            assert!(
                ["low", "medium", "high", "critical"].contains(&rl),
                "invalid risk_level: {rl}"
            );
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let ops = operations_info();
        for op in &ops {
            let v = serde_json::to_value(op.safety_tier).unwrap();
            let st = v.as_str().unwrap();
            assert!(
                ["safe", "risky", "dangerous"].contains(&st),
                "invalid safety_tier: {st}"
            );
        }
    }

    #[test]
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            if cap.ends_with(".read") {
                assert_eq!(
                    op.safety_tier,
                    SafetyTier::Safe,
                    "read op {} should be safe",
                    op.id.as_ref()
                );
                assert_eq!(
                    op.risk_level,
                    RiskLevel::Low,
                    "read op {} should be low risk",
                    op.id.as_ref()
                );
            }
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        assert!(ids.contains(&"n8n.workflows.list"));
        assert!(ids.contains(&"n8n.workflows.get"));
        assert!(ids.contains(&"n8n.workflows.activate"));
        assert!(ids.contains(&"n8n.executions.list"));
        assert!(ids.contains(&"n8n.executions.get"));
        assert!(ids.contains(&"n8n.projects.list"));
        assert!(ids.contains(&"n8n.credentials.list"));
        assert!(ids.contains(&"n8n.tags.list"));
    }

    #[test]
    fn operations_write_ops_are_risky() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            if cap.ends_with(".write") {
                assert_ne!(
                    op.safety_tier,
                    SafetyTier::Safe,
                    "write op {} should not be safe",
                    op.id.as_ref()
                );
            }
        }
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
    fn config_trims_api_key() {
        let config = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "api_key": "  key_test  ",
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .unwrap();
        match &config.auth {
            N8nAuth::ApiKey(k) => assert_eq!(k, "key_test"),
            N8nAuth::CredentialId(_) => panic!("expected ApiKey"),
        }
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in &ops {
            // Typed struct always has idempotency; verify serialization round-trips
            let v = serde_json::to_value(op.idempotency).unwrap();
            assert!(
                v.is_string(),
                "op {} idempotency should serialize",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = N8nConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn operations_and_rate_pools_match_parsed_manifest() {
        use std::collections::BTreeSet;

        let manifest = fcp_manifest::ConnectorManifest::parse_str_unchecked(MANIFEST_TOML)
            .expect("embedded n8n manifest should parse");
        let runtime_operations = operations_info();
        let manifest_ids = manifest
            .provides
            .operations
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let runtime_ids = runtime_operations
            .iter()
            .map(|operation| operation.id.as_ref().to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(runtime_ids, manifest_ids, "operation ID sets must match");

        for runtime in &runtime_operations {
            let id = runtime.id.as_ref();
            let declared = manifest
                .provides
                .operations
                .get(id)
                .expect("runtime operation should exist in parsed manifest");
            assert_eq!(runtime.summary, declared.description, "summary drift: {id}");
            assert_eq!(
                runtime.description.as_deref(),
                Some(declared.description.as_str()),
                "description drift: {id}"
            );
            assert_eq!(
                runtime.capability, declared.capability,
                "capability drift: {id}"
            );
            assert_eq!(
                serde_json::to_value(runtime.risk_level).unwrap(),
                serde_json::to_value(declared.risk_level).unwrap(),
                "risk drift: {id}"
            );
            assert_eq!(
                serde_json::to_value(runtime.safety_tier).unwrap(),
                serde_json::to_value(declared.safety_tier).unwrap(),
                "safety drift: {id}"
            );
            assert_eq!(
                serde_json::to_value(runtime.requires_approval).unwrap(),
                serde_json::to_value(declared.requires_approval).unwrap(),
                "approval drift: {id}"
            );
            assert_eq!(
                serde_json::to_value(runtime.idempotency).unwrap(),
                serde_json::to_value(declared.idempotency).unwrap(),
                "idempotency drift: {id}"
            );
            assert_eq!(
                runtime.input_schema, declared.input_schema,
                "input schema drift: {id}"
            );
            assert_eq!(
                runtime.output_schema, declared.output_schema,
                "output schema drift: {id}"
            );
            assert_eq!(
                serde_json::to_value(&runtime.ai_hints).unwrap(),
                serde_json::to_value(&declared.ai_hints).unwrap(),
                "AI hints drift: {id}"
            );
            assert_eq!(
                runtime.rate_limit.is_some(),
                declared.rate_limit.is_some(),
                "per-operation rate-limit drift: {id}"
            );
            assert!(
                manifest
                    .capabilities
                    .optional
                    .iter()
                    .any(|capability| capability == &runtime.capability),
                "operation capability must be optional in manifest: {id}"
            );
        }

        let rate_limits = manifest
            .rate_limits
            .as_ref()
            .expect("n8n manifest should declare rate-limit pools");
        let mapped_operation_ids = rate_limits
            .operation_pools
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            mapped_operation_ids, manifest_ids,
            "rate-pool mappings must cover exactly the operation set"
        );

        let pool_ids = rate_limits
            .pools
            .iter()
            .map(|pool| pool.id.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            pool_ids.len(),
            rate_limits.pools.len(),
            "rate-limit pool IDs must be unique"
        );
        let mut referenced_pool_ids = BTreeSet::new();
        for runtime in &runtime_operations {
            let id = runtime.id.as_ref();
            let mappings = rate_limits
                .operation_pools
                .get(id)
                .expect("every operation should have a rate-pool mapping");
            assert!(
                !mappings.is_empty(),
                "rate-pool mapping must not be empty: {id}"
            );
            for pool_id in mappings {
                assert!(
                    pool_ids.contains(pool_id),
                    "unknown rate-limit pool {pool_id}: {id}"
                );
                referenced_pool_ids.insert(pool_id.clone());
            }
            assert!(
                mappings
                    .iter()
                    .any(|pool_id| pool_id == runtime.capability.as_ref()),
                "operation must consume its capability-named pool: {id}"
            );
        }
        assert_eq!(
            referenced_pool_ids, pool_ids,
            "every declared rate-limit pool must be referenced"
        );
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("fail".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("fail".into()),
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
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
    fn config_base_url_trimmed() {
        let config = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "api_key": "key",
            "base_url": "  https://n8n.example.com/api/v1  ",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://n8n.example.com/api/v1");
    }

    #[test]
    fn connector_new_zero_counters() {
        let c = N8nConnector::new();
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
        assert!(!r.checks[0].passed);
    }

    #[test]
    fn doctor_check_deserializes() {
        let v = json!({"name": "test", "passed": true, "critical": false});
        let c: DoctorCheck = serde_json::from_value(v).unwrap();
        assert_eq!(c.name, "test");
        assert!(c.passed);
        assert!(!c.critical);
        assert!(c.message.is_none());
    }

    #[test]
    fn doctor_check_clone() {
        let c = DoctorCheck {
            name: "config".into(),
            passed: true,
            message: Some("ok".into()),
            critical: true,
        };
        let cloned = DoctorCheck::clone(&c);
        assert_eq!(cloned.name, "config");
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
    fn config_rejects_boolean_base_url() {
        let result = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "api_key": "key",
            "base_url": true,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_null_api_key() {
        let result = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "api_key": null,
            "base_url": "https://n8n.example.com/api/v1",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_with_empty_string() {
        let input = json!({"id": ""});
        // Empty strings are valid string values, require_str just checks type
        assert_eq!(require_str(&input, "id").unwrap(), "");
    }

    #[test]
    fn require_str_with_object_value() {
        let input = json!({"id": {"nested": "value"}});
        assert!(require_str(&input, "id").is_err());
    }

    #[test]
    fn operations_summaries_non_empty() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                !op.summary.is_empty(),
                "op {} has empty summary",
                op.id.as_ref()
            );
        }
    }

    #[test]
    fn require_str_with_float_value() {
        let input = json!({"id": 1.23});
        assert!(require_str(&input, "id").is_err());
    }

    #[test]
    fn operations_all_capabilities_prefixed() {
        let ops = operations_info();
        for op in &ops {
            let cap = op.capability.as_ref();
            assert!(
                cap.starts_with("n8n."),
                "capability {cap} should start with n8n."
            );
        }
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_check_debug() {
        let c = DoctorCheck {
            name: "test_check".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("DoctorCheck"));
        assert!(dbg.contains("test_check"));
    }

    // ── Provisioning tests ────────────────────────────────────────

    #[test]
    fn provisioning_readiness_api_key_mode() {
        let config = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "api_key": "test-key",
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "api_key");
        assert!(readiness.api_key_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
        assert_eq!(readiness.base_url, "https://n8n.example.com/api/v1");
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.api_key_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "api_key": "tok",
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "api_key");
        assert_eq!(v["api_key_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_http_non_local_rejected() {
        let (network_ok, network_message) = base_url_policy("http://n8n.example.com/api/v1");
        assert!(!network_ok);
        assert!(network_message.contains("HTTPS"));
    }

    #[test]
    fn provisioning_readiness_localhost_http_accepted() {
        let config = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "api_key": "tok",
            "base_url": "http://localhost:5678/api/v1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_recipe_has_2_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "n8n.credential_reference");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 2);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "enter_instance_url");
        assert_eq!(recipe.steps[1].id.as_str(), "enter_credential_id");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "enter_instance_url");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "n8n.credential_reference");
        assert_eq!(v["steps"].as_array().unwrap().len(), 2);
        assert!(!v.to_string().contains("api_key"));
    }

    #[test]
    fn provisioning_recipe_first_step_is_prompt_user() {
        let recipe = provisioning_recipe();
        assert!(matches!(
            &recipe.steps[0].kind,
            ProvisioningStepType::PromptUser { message } if message.contains("n8n instance URL")
        ));
    }

    #[test]
    fn provisioning_recipe_second_step_is_credential_reference_prompt() {
        let recipe = provisioning_recipe();
        assert!(matches!(
            &recipe.steps[1].kind,
            ProvisioningStepType::PromptUser { message }
                if message.contains("credential reference") && message.contains("do not paste")
        ));
    }

    #[test]
    fn base_url_policy_accepts_any_https_host() {
        let (ok, message) = base_url_policy("https://my-n8n.company.io/api/v1");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:5678/api/v1");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_127_0_0_1() {
        let (ok, _) = base_url_policy("http://127.0.0.1:5678/api/v1");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_ipv6_loopback() {
        let (ok, _) = base_url_policy("http://[::1]:5678/api/v1");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_http_non_local() {
        let (ok, message) = base_url_policy("http://n8n.example.com/api/v1");
        assert!(!ok);
        assert!(message.contains("HTTPS"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("absolute URL"));
    }

    #[test]
    fn base_url_policy_rejects_missing_host() {
        let (ok, message) = base_url_policy("file:///etc/passwd");
        assert!(!ok);
        assert!(message.contains("must include a host"));
    }

    #[test]
    fn provisioning_readiness_debug() {
        let config = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "api_key": "tok",
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let dbg = format!("{readiness:?}");
        assert!(dbg.contains("ProvisioningReadiness"));
    }

    #[test]
    fn provisioning_readiness_clone() {
        let config = N8nConfig::from_params(&json!({
            "server_id": "eec",
            "api_key": "tok",
            "base_url": "https://n8n.example.com/api/v1",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let cloned = ProvisioningReadiness::clone(&readiness);
        assert_eq!(cloned.auth_mode, readiness.auth_mode);
        assert_eq!(cloned.network_ok, readiness.network_ok);
        assert_eq!(cloned.base_url, readiness.base_url);
    }

    #[test]
    fn base_url_policy_accepts_https_custom_port() {
        let (ok, _) = base_url_policy("https://n8n.example.com:8443/api/v1");
        assert!(!ok);
    }

    #[test]
    fn is_local_test_host_localhost() {
        assert!(is_local_test_host("localhost"));
    }

    #[test]
    fn is_local_test_host_127() {
        assert!(is_local_test_host("127.0.0.1"));
    }

    #[test]
    fn is_local_test_host_ipv6() {
        assert!(is_local_test_host("::1"));
    }

    #[test]
    fn is_local_test_host_ipv6_bracketed() {
        assert!(is_local_test_host("[::1]"));
    }

    #[test]
    fn is_local_test_host_rejects_other() {
        assert!(!is_local_test_host("example.com"));
    }

    #[test]
    fn active_workflow_update_preserves_lifecycle_and_published_graph() {
        let mut baseline = digest_test_workflow();
        baseline.active = true;
        baseline.version_id = "draft-v2".into();
        baseline.active_version_id = RequiredNullable::Value("published-v1".into());
        baseline.active_version = RequiredNullable::Value(WorkflowVersion {
            version_id: "published-v1".into(),
            nodes: baseline.nodes.clone(),
            connections: baseline.connections.clone(),
        });
        let baseline_state = normalize_workflow_state(baseline.clone()).unwrap();

        let mut updated = baseline;
        updated.version_id = "draft-v3".into();
        updated.nodes[0]["position"] = json!([320, 180]);
        let updated_state = normalize_workflow_state(updated).unwrap();
        let plan = DraftWritePlan {
            workflow_id: Some("workflow-1".into()),
            graph_digest: updated_state.draft.graph_digest.clone(),
            provider_payload: json!({}),
        };

        verify_draft_readback(
            "n8n.workflows.update_draft",
            &plan,
            Some(&DraftBaseline {
                state: baseline_state.clone(),
                name: None,
                settings: Some(json!({"availableInMCP": true})),
                static_data: None,
                pin_data: None,
            }),
            &updated_state,
            None,
            Some(&json!({"availableInMCP": true})),
            None,
            None,
            Some(&json!({"availableInMCP": true})),
            None,
            None,
        )
        .expect("active lifecycle must remain unchanged");

        let mut deactivated = updated_state;
        deactivated.active = false;
        assert!(matches!(
            verify_draft_readback(
                "n8n.workflows.update_draft",
                &plan,
                Some(&DraftBaseline {
                    state: baseline_state,
                    name: None,
                    settings: Some(json!({"availableInMCP": true})),
                    static_data: None,
                    pin_data: None,
                }),
                &deactivated,
                None,
                Some(&json!({"availableInMCP": true})),
                None,
                None,
                Some(&json!({"availableInMCP": true})),
                None,
                None,
            ),
            Err(N8nError::ReadbackMismatch)
        ));
    }

    #[test]
    fn metadata_only_update_accepts_unchanged_provider_version_id() {
        let baseline = digest_test_workflow();
        let baseline_state = normalize_workflow_state(baseline.clone()).unwrap();

        let mut updated = baseline;
        updated.name = Some("Renamed workflow".into());
        updated.updated_at = Some("2026-01-03T00:00:00Z".into());
        let updated_state = normalize_workflow_state(updated).unwrap();
        assert_eq!(updated_state.version_id, baseline_state.version_id);

        let plan = DraftWritePlan {
            workflow_id: Some("workflow-1".into()),
            graph_digest: updated_state.draft.graph_digest.clone(),
            provider_payload: json!({}),
        };

        verify_draft_readback(
            "n8n.workflows.update_draft",
            &plan,
            Some(&DraftBaseline {
                state: baseline_state,
                name: Some("Digest test".into()),
                settings: Some(json!({"availableInMCP": true})),
                static_data: None,
                pin_data: None,
            }),
            &updated_state,
            Some("Renamed workflow"),
            Some(&json!({"availableInMCP": true})),
            None,
            None,
            Some(&json!({"availableInMCP": true})),
            None,
            None,
        )
        .expect("metadata-only update may keep the provider version id");
    }

    #[test]
    fn update_precondition_rejects_each_version_and_lifecycle_mismatch() {
        let mut workflow = digest_test_workflow();
        workflow.active = true;
        workflow.version_id = "draft-v2".into();
        workflow.active_version_id = RequiredNullable::Value("published-v1".into());
        workflow.active_version = RequiredNullable::Value(WorkflowVersion {
            version_id: "published-v1".into(),
            nodes: workflow.nodes.clone(),
            connections: workflow.connections.clone(),
        });
        let state = normalize_workflow_state(workflow).unwrap();
        let base = DraftMutationPrecondition {
            version_id: Some(state.version_id.clone()),
            active_version_id: Some(RequiredNullable::Value(
                state.active_version_id.clone().unwrap(),
            )),
            active: Some(state.active),
            is_archived: Some(state.is_archived),
            state_digest: Some(state.state_digest.clone()),
        };

        let mut mismatches = Vec::new();
        let mut wrong_version = base.clone();
        wrong_version.version_id = Some("stale-version".into());
        mismatches.push(wrong_version);
        let mut wrong_digest = base.clone();
        wrong_digest.state_digest = Some("blake3-256:stale".into());
        mismatches.push(wrong_digest);
        let mut wrong_active_version = base.clone();
        wrong_active_version.active_version_id = Some(RequiredNullable::Null);
        mismatches.push(wrong_active_version);
        let mut wrong_active = base.clone();
        wrong_active.active = Some(false);
        mismatches.push(wrong_active);
        let mut wrong_archived = base;
        wrong_archived.is_archived = Some(true);
        mismatches.push(wrong_archived);

        for mismatch in mismatches {
            assert!(matches!(
                verify_draft_precondition(&mismatch, &state),
                Err(N8nError::InvalidInput(_))
            ));
        }
    }

    #[test]
    fn create_readback_accepts_inactive_unpublished_draft() {
        let workflow = digest_test_workflow();
        let state = normalize_workflow_state(workflow).unwrap();
        let plan = DraftWritePlan {
            workflow_id: None,
            graph_digest: state.draft.graph_digest.clone(),
            provider_payload: json!({}),
        };
        verify_draft_readback(
            "n8n.workflows.create_draft",
            &plan,
            None,
            &state,
            None,
            Some(&json!({"availableInMCP": true})),
            None,
            None,
            Some(&json!({"availableInMCP": true})),
            None,
            None,
        )
        .expect("create readback should preserve draft-only lifecycle");
    }

    #[test]
    fn draft_approval_requires_exact_binding_and_expiry() {
        let request_input = json!({
            "id": "1001",
            "name": "Exact approved draft",
            "graph": {"nodes": [], "connections": {}},
            "guard": {
                "approvalRef": "approval-1",
                "idempotencyKey": "00000000-0000-4000-8000-000000000001",
                "precondition": {
                    "versionId": "draft-v1",
                    "activeVersionId": null,
                    "active": false,
                    "isArchived": false,
                    "stateDigest": "blake3-256:state"
                }
            }
        });
        let now = current_time_ms();
        let token = ApprovalToken::approved(
            "approval-1",
            now.saturating_sub(1_000),
            now.saturating_add(60_000),
            "operator:test",
            ApprovalScope::Execution(ExecutionScope {
                connector_id: "fcp.n8n".into(),
                method_pattern: "n8n.workflows.update_draft".into(),
                request_object_id: None,
                input_hash: approval_input_hash(&request_input),
                input_constraints: Vec::new(),
            }),
            ZoneId::work(),
            Some(vec![1]),
        );
        assert!(is_matching_draft_approval(
            &token,
            "n8n.workflows.update_draft",
            "approval-1",
            Some(&ZoneId::work()),
            &request_input,
            now,
        ));

        let mut mismatched = request_input.clone();
        mismatched["name"] = json!("Changed after approval");
        assert!(!is_matching_draft_approval(
            &token,
            "n8n.workflows.update_draft",
            "approval-1",
            Some(&ZoneId::work()),
            &mismatched,
            now,
        ));
        let constrained = ApprovalToken::approved(
            token.token_id.clone(),
            token.issued_at_ms,
            token.expires_at_ms,
            token.issuer.clone(),
            ApprovalScope::Execution(ExecutionScope {
                connector_id: "fcp.n8n".into(),
                method_pattern: "n8n.workflows.update_draft".into(),
                request_object_id: None,
                input_hash: approval_input_hash(&request_input),
                input_constraints: vec![fcp_prelude::InputConstraint {
                    pointer: "/name".into(),
                    expected: request_input["name"].clone(),
                }],
            }),
            token.zone_id.clone(),
            token.signature.clone(),
        );
        assert!(!is_matching_draft_approval(
            &constrained,
            "n8n.workflows.update_draft",
            "approval-1",
            Some(&ZoneId::work()),
            &request_input,
            now,
        ));
        let expired = ApprovalToken::approved(
            token.token_id.clone(),
            now.saturating_sub(2_000),
            now,
            token.issuer.clone(),
            token.scope.clone(),
            token.zone_id.clone(),
            token.signature,
        );
        assert!(!is_matching_draft_approval(
            &expired,
            "n8n.workflows.update_draft",
            "approval-1",
            Some(&ZoneId::work()),
            &request_input,
            now,
        ));
    }

    #[test]
    fn unknown_draft_write_outcome_is_not_retryable() {
        assert!(!N8nError::UnknownOutcome.is_retryable());
        assert!(
            N8nError::UnknownOutcome
                .safe_summary()
                .contains("do not retry")
        );
    }

    #[test]
    fn lifecycle_input_requires_full_explicit_precondition_and_uuid() {
        let input = json!({
            "id": "1001",
            "action": "publish",
            "guard": {
                "approvalRef": "approval-1",
                "idempotencyKey": "00000000-0000-4000-8000-000000000003",
                "precondition": {
                    "versionId": "draft-v1",
                    "activeVersionId": null,
                    "active": false,
                    "isArchived": false,
                    "stateDigest": "blake3-256:0000000000000000000000000000000000000000000000000000000000000000"
                }
            }
        });
        let parsed = parse_workflow_lifecycle_input(&input).expect("valid lifecycle input");
        assert_eq!(parsed.action.as_str(), "publish");
        assert!(matches!(
            parsed.guard.precondition.active_version_id,
            crate::types::RequiredNullable::Null
        ));

        let mut missing_pointer = input.clone();
        missing_pointer["guard"]["precondition"]
            .as_object_mut()
            .expect("precondition object")
            .remove("activeVersionId");
        assert!(parse_workflow_lifecycle_input(&missing_pointer).is_err());

        let mut bad_uuid = input;
        bad_uuid["guard"]["idempotencyKey"] = json!("not-a-uuid");
        assert!(parse_workflow_lifecycle_input(&bad_uuid).is_err());
    }

    #[test]
    fn lifecycle_rejects_out_of_scope_actions_and_is_fail_closed() {
        let input = json!({
            "id": "1001",
            "action": "archive",
            "guard": {
                "approvalRef": "approval-1",
                "idempotencyKey": "00000000-0000-4000-8000-000000000003",
                "precondition": {
                    "versionId": "draft-v1",
                    "activeVersionId": null,
                    "active": false,
                    "isArchived": false,
                    "stateDigest": "blake3-256:0000000000000000000000000000000000000000000000000000000000000000"
                }
            }
        });
        assert!(parse_workflow_lifecycle_input(&input).is_err());
        let error = N8nError::CapabilityUnavailable("unsupported lifecycle semantics");
        assert!(!error.is_retryable());
        assert!(matches!(
            error.to_fcp_error(),
            FcpError::CapabilityDenied { reason, .. }
                if reason.starts_with("capability_unavailable:")
        ));
    }
}
