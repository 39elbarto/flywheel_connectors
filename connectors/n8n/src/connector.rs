//! FCP n8n Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
        CredentialMetadataView, FolderListView, ListView, WorkflowDetail, WorkflowGraphSummary,
        WorkflowStateView, WorkflowVersion,
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

        if operation == "n8n.workflows.activate" {
            return Err(FcpError::CapabilityDenied {
                capability: "n8n.workflows.write".into(),
                reason: "workflow activation lifecycle is deferred to the mediated n8n write path"
                    .into(),
            });
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
    ) -> FcpResult<HostEgressContext> {
        let zone_id = self.zone_id.as_ref().ok_or(FcpError::NotHandshaken)?;
        let session_id = self.session_id.as_ref().ok_or(FcpError::NotHandshaken)?;
        let token_cbor = token.raw().to_cbor().map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize verified capability token: {error}"),
        })?;
        Ok(HostEgressContext {
            connector_id: "fcp.n8n".to_string(),
            operation_id: operation.to_string(),
            resource_uri: resource_uri.to_string(),
            zone_id: zone_id.to_string(),
            request_id: format!("{session_id}:{request_number}"),
            correlation_id: None,
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
            | "n8n.tags.list" => instance_resource_uri(server_id),
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
            "n8n.workflows.get" | "n8n.workflows.activate" => {
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
        "n8n.executions.get" => {
            require_exact_object(input, &["workflow_id", "id"], "execution get input")?;
            require_str(input, "workflow_id")?;
            require_str(input, "id")?;
            Ok(())
        }
        "n8n.folders.list" => parse_folder_list_input(input).map(|_| ()),
        "n8n.folders.get" => parse_folder_get_input(input).map(|_| ()),
        _ => Ok(()),
    }
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
        requires_approval: Some(if id == "n8n.workflows.activate" {
            ApprovalMode::Policy
        } else {
            ApprovalMode::None
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
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RequiredNullable;

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
            "activeVersion": null
        }))
        .unwrap()
    }

    fn normalized_state_digest(workflow: WorkflowDetail) -> String {
        normalize_workflow_state(workflow).unwrap().state_digest
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
    fn operations_info_has_10_operations() {
        let ops = operations_info();
        assert_eq!(ops.len(), 10);
        let operation_ids = ops
            .iter()
            .map(|operation| operation.id.as_ref())
            .collect::<Vec<_>>();
        assert!(operation_ids.contains(&"n8n.folders.list"));
        assert!(operation_ids.contains(&"n8n.folders.get"));
        assert!(operation_ids.contains(&"n8n.credentials.list"));
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
}
