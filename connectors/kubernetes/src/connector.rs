//! FCP Kubernetes Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, OperationId, OperationInfo, RiskLevel, SafetyTier,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, KubernetesAuth, KubernetesClient},
    error::KubernetesError,
};

/// Parsed and validated Kubernetes connector configuration.
#[derive(Debug, Clone)]
struct KubernetesConfig {
    auth: KubernetesAuth,
    base_url: String,
}

impl KubernetesConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let bearer_token = params
            .get("bearer_token")
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

        let auth = match (bearer_token, credential_id) {
            (Some(key), None) => KubernetesAuth::BearerToken(key),
            (None, Some(cred_id)) => KubernetesAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of bearer_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing bearer_token or credential_id in configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        Ok(Self { auth, base_url })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

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

/// FCP Kubernetes Connector.
pub struct KubernetesConnector {
    base: Arc<BaseConnector>,
    config: Option<KubernetesConfig>,
    client: Option<Arc<KubernetesClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl KubernetesConnector {
    /// Create a new Kubernetes connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("kubernetes"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for KubernetesConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl KubernetesConnector {
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = KubernetesConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Kubernetes connector");

        let client = KubernetesClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;

        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({}))
    }

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

        let session_id = params
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        self.session_id = session_id;
        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.kubernetes",
            "connector_version": "0.1.0",
            "capabilities": [
                "kubernetes.read",
                "kubernetes.write",
                "kubernetes.admin",
                "kubernetes.secrets"
            ]
        }))
    }

    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();

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

    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_none() {
                Some("Not configured -- call configure first".into())
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

        let handshaken = self.session_id.is_some();
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
        Ok(serde_json::to_value(result).unwrap_or(json!({"status": "error"})))
    }

    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.kubernetes",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.kubernetes",
            "version": "0.1.0",
            "operations": serde_json::to_value(operations_info()).unwrap_or_default(),
        }))
    }

    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;

        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "kubernetes.list_pods" => self.op_list_pods(client, &input).await,
            "kubernetes.get_pod" => self.op_get_pod(client, &input).await,
            "kubernetes.delete_pod" => self.op_delete_pod(client, &input).await,
            "kubernetes.get_pod_logs" => self.op_get_pod_logs(client, &input).await,
            "kubernetes.stream_pod_logs" => self.op_stream_pod_logs(client, &input).await,
            "kubernetes.list_deployments" => self.op_list_deployments(client, &input).await,
            "kubernetes.get_deployment" => self.op_get_deployment(client, &input).await,
            "kubernetes.scale_deployment" => self.op_scale_deployment(client, &input).await,
            "kubernetes.rollout_restart" => self.op_rollout_restart(client, &input).await,
            "kubernetes.get_service" => self.op_get_service(client, &input).await,
            "kubernetes.get_configmap" => self.op_get_configmap(client, &input).await,
            "kubernetes.update_configmap" => self.op_update_configmap(client, &input).await,
            "kubernetes.get_secret" => self.op_get_secret(client, &input).await,
            "kubernetes.watch_events" => self.op_watch_events(client, &input).await,
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

    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let allowed = operations_info()
            .iter()
            .any(|o| o.id.as_ref() == operation);

        Ok(json!({
            "allowed": allowed,
            "reason": if allowed { "Operation supported" } else { "Unknown operation" },
        }))
    }

    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Kubernetes connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    async fn op_list_pods(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let label_selector = input
            .get("label_selector")
            .and_then(serde_json::Value::as_str);
        let field_selector = input
            .get("field_selector")
            .and_then(serde_json::Value::as_str);
        let resp = client
            .list_pods(namespace, label_selector, field_selector)
            .await?;
        let items = resp.get("items").cloned().unwrap_or(json!([]));
        Ok(json!({ "pods": items }))
    }

    async fn op_get_pod(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let resp = client.get_pod(namespace, name).await?;
        Ok(json!({ "pod": resp }))
    }

    async fn op_delete_pod(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let grace_period = input
            .get("grace_period_seconds")
            .and_then(serde_json::Value::as_u64);
        let _resp = client.delete_pod(namespace, name, grace_period).await?;
        Ok(json!({ "deleted": true }))
    }

    async fn op_get_pod_logs(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let container = input.get("container").and_then(serde_json::Value::as_str);
        let tail_lines = input.get("tail_lines").and_then(serde_json::Value::as_u64);
        let since_seconds = input
            .get("since_seconds")
            .and_then(serde_json::Value::as_u64);
        let logs = client
            .get_pod_logs(namespace, name, container, tail_lines, since_seconds)
            .await?;
        Ok(json!({ "logs": logs }))
    }

    async fn op_stream_pod_logs(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let container = input.get("container").and_then(serde_json::Value::as_str);
        let tail_lines = input.get("tail_lines").and_then(serde_json::Value::as_u64);
        let log_line = client
            .stream_pod_logs(namespace, name, container, tail_lines)
            .await?;
        Ok(json!({ "log_line": log_line }))
    }

    async fn op_list_deployments(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let label_selector = input
            .get("label_selector")
            .and_then(serde_json::Value::as_str);
        let resp = client.list_deployments(namespace, label_selector).await?;
        let items = resp.get("items").cloned().unwrap_or(json!([]));
        Ok(json!({ "deployments": items }))
    }

    async fn op_get_deployment(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let resp = client.get_deployment(namespace, name).await?;
        Ok(json!({ "deployment": resp }))
    }

    async fn op_scale_deployment(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let replicas = input
            .get("replicas")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| KubernetesError::Api {
                status_code: 400,
                message: "Missing required field: replicas (must be an integer)".into(),
            })?;
        #[allow(clippy::cast_possible_truncation)]
        let replicas_u32 = replicas as u32;
        let resp = client
            .scale_deployment(namespace, name, replicas_u32)
            .await?;
        Ok(json!({ "deployment": resp }))
    }

    async fn op_rollout_restart(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let resp = client.rollout_restart(namespace, name).await?;
        Ok(json!({ "deployment": resp }))
    }

    async fn op_get_service(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let resp = client.get_service(namespace, name).await?;
        Ok(json!({ "service": resp }))
    }

    async fn op_get_configmap(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let resp = client.get_configmap(namespace, name).await?;
        Ok(json!({ "configmap": resp }))
    }

    async fn op_update_configmap(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let data = input.get("data").ok_or_else(|| KubernetesError::Api {
            status_code: 400,
            message: "Missing required field: data".into(),
        })?;
        let resp = client.update_configmap(namespace, name, data).await?;
        Ok(json!({ "configmap": resp }))
    }

    async fn op_get_secret(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let name = require_str(input, "name")?;
        let resp = client.get_secret(namespace, name).await?;

        let unmask = input
            .get("unmask")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        if unmask {
            Ok(json!({ "secret": resp }))
        } else {
            let mut redacted = resp;
            if let Some(obj) = redacted.as_object_mut() {
                if let Some(data) = obj.get("data") {
                    let keys: Vec<String> = data
                        .as_object()
                        .map(|d| d.keys().cloned().collect())
                        .unwrap_or_default();
                    obj.insert("data_keys".to_string(), json!(keys));
                    obj.remove("data");
                }
            }
            Ok(json!({ "secret": redacted }))
        }
    }

    async fn op_watch_events(
        &self,
        client: &KubernetesClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, KubernetesError> {
        let namespace = require_str(input, "namespace")?;
        let field_selector = input
            .get("field_selector")
            .and_then(serde_json::Value::as_str);
        let resource_version = input
            .get("resource_version")
            .and_then(serde_json::Value::as_str);
        let resp = client
            .list_events(namespace, field_selector, resource_version)
            .await?;
        let items = resp.get("items").cloned().unwrap_or(json!([]));
        Ok(json!({ "events": items }))
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, KubernetesError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| KubernetesError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "kubernetes.list_pods",
            "List pods in a namespace",
            json!({
                "type": "object",
                "required": ["namespace"],
                "properties": {
                    "namespace": { "type": "string" },
                    "label_selector": { "type": "string" },
                    "field_selector": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["pods"],
                "properties": { "pods": { "type": "array" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List pods in a namespace, optionally filtered by labels.".into(),
                common_mistakes: vec!["Not using label selectors on large namespaces".into()],
                examples: vec![
                    r#"{"namespace": "production", "label_selector": "app=api-server"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_pod"),
                    CapabilityId::from_static("kubernetes.get_deployment"),
                ],
            },
        ),
        op_info(
            "kubernetes.get_pod",
            "Get a pod by name",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["pod"],
                "properties": { "pod": { "type": "object" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve details about a specific pod.".into(),
                common_mistakes: vec![
                    "Forgetting to specify namespace (defaults to 'default')".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server-5f4b8c9-x7k2p"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.list_pods"),
                    CapabilityId::from_static("kubernetes.get_pod_logs"),
                ],
            },
        ),
        op_info(
            "kubernetes.delete_pod",
            "Delete a pod",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "grace_period_seconds": { "type": "integer" }
                }
            }),
            json!({
                "type": "object",
                "required": ["deleted"],
                "properties": { "deleted": { "type": "boolean" } }
            }),
            "kubernetes.admin",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Force-delete a pod to trigger rescheduling.".into(),
                common_mistakes: vec![
                    "Deleting pods managed by a Deployment (they respawn)".into(),
                    "Using grace_period_seconds=0 on stateful pods".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server-5f4b8c9-x7k2p"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_pod"),
                    CapabilityId::from_static("kubernetes.scale_deployment"),
                ],
            },
        ),
        op_info(
            "kubernetes.get_pod_logs",
            "Retrieve logs from a pod",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "container": { "type": "string" },
                    "tail_lines": { "type": "integer" },
                    "since_seconds": { "type": "integer" }
                }
            }),
            json!({
                "type": "object",
                "required": ["logs"],
                "properties": { "logs": { "type": "string" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Read container logs from a pod.".into(),
                common_mistakes: vec![
                    "Not specifying container in multi-container pods".into(),
                    "Requesting unbounded logs on high-throughput pods".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server-5f4b8c9-x7k2p", "tail_lines": 100}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_pod"),
                    CapabilityId::from_static("kubernetes.stream_pod_logs"),
                ],
            },
        ),
        op_info(
            "kubernetes.stream_pod_logs",
            "Stream live logs from a pod",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "container": { "type": "string" },
                    "tail_lines": { "type": "integer" }
                }
            }),
            json!({
                "type": "object",
                "required": ["log_line"],
                "properties": { "log_line": { "type": "string" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Follow live log output from a pod container.".into(),
                common_mistakes: vec![
                    "Not specifying container in multi-container pods".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server-5f4b8c9-x7k2p", "tail_lines": 50}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_pod_logs"),
                    CapabilityId::from_static("kubernetes.watch_events"),
                ],
            },
        ),
        op_info(
            "kubernetes.list_deployments",
            "List deployments in a namespace",
            json!({
                "type": "object",
                "required": ["namespace"],
                "properties": {
                    "namespace": { "type": "string" },
                    "label_selector": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["deployments"],
                "properties": { "deployments": { "type": "array" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all deployments in a namespace.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"namespace": "production"}"#.into()],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_deployment"),
                    CapabilityId::from_static("kubernetes.scale_deployment"),
                ],
            },
        ),
        op_info(
            "kubernetes.get_deployment",
            "Get a deployment by name",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["deployment"],
                "properties": { "deployment": { "type": "object" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve details about a specific deployment.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.list_deployments"),
                    CapabilityId::from_static("kubernetes.scale_deployment"),
                ],
            },
        ),
        op_info(
            "kubernetes.scale_deployment",
            "Scale a deployment",
            json!({
                "type": "object",
                "required": ["namespace", "name", "replicas"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "replicas": { "type": "integer" }
                }
            }),
            json!({
                "type": "object",
                "required": ["deployment"],
                "properties": { "deployment": { "type": "object" } }
            }),
            "kubernetes.write",
            RiskLevel::High,
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Scale a deployment up or down.".into(),
                common_mistakes: vec![
                    "Scaling to 0 unintentionally".into(),
                    "Not checking HPA before manual scaling".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server", "replicas": 3}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_deployment"),
                    CapabilityId::from_static("kubernetes.rollout_restart"),
                ],
            },
        ),
        op_info(
            "kubernetes.rollout_restart",
            "Trigger a rolling restart",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["deployment"],
                "properties": { "deployment": { "type": "object" } }
            }),
            "kubernetes.write",
            RiskLevel::High,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Restart all pods in a deployment with zero downtime.".into(),
                common_mistakes: vec!["Restarting during an active rollout".into()],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.scale_deployment"),
                    CapabilityId::from_static("kubernetes.get_deployment"),
                ],
            },
        ),
        op_info(
            "kubernetes.get_service",
            "Get a service by name",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["service"],
                "properties": { "service": { "type": "object" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve details about a Kubernetes service.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"namespace": "production", "name": "api-server"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("kubernetes.list_pods")],
            },
        ),
        op_info(
            "kubernetes.get_configmap",
            "Get a ConfigMap by name",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["configmap"],
                "properties": { "configmap": { "type": "object" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Read configuration data from a ConfigMap.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"namespace": "production", "name": "app-config"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.update_configmap"),
                    CapabilityId::from_static("kubernetes.get_secret"),
                ],
            },
        ),
        op_info(
            "kubernetes.update_configmap",
            "Update a ConfigMap",
            json!({
                "type": "object",
                "required": ["namespace", "name", "data"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "data": { "type": "object" }
                }
            }),
            json!({
                "type": "object",
                "required": ["configmap"],
                "properties": { "configmap": { "type": "object" } }
            }),
            "kubernetes.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Update configuration data in a ConfigMap.".into(),
                common_mistakes: vec![
                    "Overwriting all data instead of merging".into(),
                    "Not restarting pods that consume the ConfigMap".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "app-config", "data": {"LOG_LEVEL": "debug"}}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("kubernetes.get_configmap"),
                    CapabilityId::from_static("kubernetes.rollout_restart"),
                ],
            },
        ),
        op_info(
            "kubernetes.get_secret",
            "Get a Secret by name (redacted by default)",
            json!({
                "type": "object",
                "required": ["namespace", "name"],
                "properties": {
                    "namespace": { "type": "string" },
                    "name": { "type": "string" },
                    "unmask": { "type": "boolean" }
                }
            }),
            json!({
                "type": "object",
                "required": ["secret"],
                "properties": { "secret": { "type": "object" } }
            }),
            "kubernetes.secrets",
            RiskLevel::High,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Read a Kubernetes secret (metadata only by default).".into(),
                common_mistakes: vec![
                    "Logging or exposing secret data".into(),
                    "Not setting unmask=false for audit-only reads".into(),
                ],
                examples: vec![
                    r#"{"namespace": "production", "name": "db-credentials"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("kubernetes.get_configmap")],
            },
        ),
        op_info(
            "kubernetes.watch_events",
            "Watch events in a namespace",
            json!({
                "type": "object",
                "required": ["namespace"],
                "properties": {
                    "namespace": { "type": "string" },
                    "field_selector": { "type": "string" },
                    "resource_version": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["events"],
                "properties": { "events": { "type": "array" } }
            }),
            "kubernetes.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Stream cluster events for monitoring or debugging.".into(),
                common_mistakes: vec![
                    "Not handling resourceVersion for reconnection".into(),
                ],
                examples: vec![r#"{"namespace": "production"}"#.into()],
                related: vec![CapabilityId::from_static("kubernetes.stream_pod_logs")],
            },
        ),
    ]
}

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

    /// Serialize `operations_info()` to JSON for backward-compatible test assertions.
    fn operations_info_json() -> serde_json::Value {
        serde_json::to_value(operations_info()).unwrap()
    }

    #[test]
    fn config_from_bearer_token() {
        let config =
            KubernetesConfig::from_params(&json!({"bearer_token": "test-k8s-token"})).unwrap();
        assert!(matches!(config.auth, KubernetesAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = KubernetesConfig::from_params(
            &json!({"credential_id": "550e8400-e29b-41d4-a716-446655440000"}),
        )
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = KubernetesConfig::from_params(
            &json!({"bearer_token": "tok", "base_url": "https://k8s.example.com"}),
        )
        .unwrap();
        assert_eq!(config.base_url, "https://k8s.example.com");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        assert!(KubernetesConfig::from_params(&json!({"bearer_token": "tok", "credential_id": "550e8400-e29b-41d4-a716-446655440000"})).is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        assert!(KubernetesConfig::from_params(&json!({})).is_err());
    }

    #[test]
    fn config_rejects_empty_bearer_token() {
        assert!(KubernetesConfig::from_params(&json!({"bearer_token": ""})).is_err());
    }

    #[test]
    fn config_rejects_whitespace_bearer_token() {
        assert!(KubernetesConfig::from_params(&json!({"bearer_token": "   "})).is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        assert!(KubernetesConfig::from_params(&json!({"credential_id": 12345})).is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        assert!(KubernetesConfig::from_params(&json!({"credential_id": "not-a-uuid"})).is_err());
    }

    #[test]
    fn config_trims_bearer_token() {
        let config =
            KubernetesConfig::from_params(&json!({"bearer_token": "  my-token  "})).unwrap();
        match &config.auth {
            KubernetesAuth::BearerToken(t) => assert_eq!(t, "my-token"),
            KubernetesAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn require_str_present() {
        assert_eq!(
            require_str(&json!({"namespace": "default"}), "namespace").unwrap(),
            "default"
        );
    }

    #[test]
    fn require_str_missing() {
        assert!(require_str(&json!({}), "namespace").is_err());
    }

    #[test]
    fn require_str_not_string() {
        assert!(require_str(&json!({"namespace": 42}), "namespace").is_err());
    }

    #[test]
    fn require_str_null_value() {
        assert!(require_str(&json!({"namespace": null}), "namespace").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        assert!(require_str(&json!({"namespace": true}), "namespace").is_err());
    }

    #[test]
    fn operations_info_has_14_operations() {
        assert_eq!(operations_info().len(), 14);
    }

    #[test]
    fn operations_all_have_required_fields() {
        for op in operations_info_json().as_array().unwrap() {
            assert!(op.get("id").is_some());
            assert!(op.get("summary").is_some());
            assert!(op.get("capability").is_some());
            assert!(op.get("risk_level").is_some());
            assert!(op.get("safety_tier").is_some());
        }
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = operations_info_json();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn operations_risk_levels_valid() {
        let valid = ["low", "medium", "high"];
        for op in operations_info_json().as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        for op in operations_info_json().as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    fn read_operations_are_safe() {
        for op in operations_info_json().as_array().unwrap() {
            if op["capability"].as_str().unwrap() == "kubernetes.read" {
                assert_eq!(op["safety_tier"], "safe");
                assert_eq!(op["risk_level"], "low");
            }
        }
    }

    #[test]
    fn operations_contain_all_manifest_ids() {
        let ops = operations_info_json();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        for expected in &[
            "kubernetes.list_pods",
            "kubernetes.get_pod",
            "kubernetes.delete_pod",
            "kubernetes.get_pod_logs",
            "kubernetes.stream_pod_logs",
            "kubernetes.list_deployments",
            "kubernetes.get_deployment",
            "kubernetes.scale_deployment",
            "kubernetes.rollout_restart",
            "kubernetes.get_service",
            "kubernetes.get_configmap",
            "kubernetes.update_configmap",
            "kubernetes.get_secret",
            "kubernetes.watch_events",
        ] {
            assert!(ids.contains(expected), "missing: {expected}");
        }
    }

    #[test]
    fn operations_all_have_idempotency() {
        for op in operations_info_json().as_array().unwrap() {
            assert!(op.get("idempotency").is_some());
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
        assert_eq!(
            DoctorResult::from_checks(checks).status,
            DoctorStatus::Healthy
        );
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
        assert_eq!(
            DoctorResult::from_checks(checks).status,
            DoctorStatus::Degraded
        );
    }

    #[test]
    fn doctor_result_unhealthy_when_critical_fails() {
        let checks = vec![DoctorCheck {
            name: "config".into(),
            passed: false,
            message: Some("not configured".into()),
            critical: true,
        }];
        assert_eq!(
            DoctorResult::from_checks(checks).status,
            DoctorStatus::Unhealthy
        );
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
    }

    #[test]
    fn doctor_result_empty_checks() {
        assert_eq!(
            DoctorResult::from_checks(vec![]).status,
            DoctorStatus::Healthy
        );
    }

    #[test]
    fn connector_default() {
        let c = KubernetesConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn delete_pod_is_dangerous() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.delete_pod")
            .unwrap();
        assert_eq!(op["risk_level"], "high");
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["capability"], "kubernetes.admin");
    }

    #[test]
    fn scale_deployment_is_risky() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.scale_deployment")
            .unwrap();
        assert_eq!(op["risk_level"], "high");
        assert_eq!(op["safety_tier"], "risky");
    }

    #[test]
    fn get_secret_uses_secrets_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.get_secret")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.secrets");
        assert_eq!(op["risk_level"], "high");
    }

    #[test]
    fn rollout_restart_uses_write_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.rollout_restart")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.write");
        assert_eq!(op["idempotency"], "none");
    }

    #[test]
    fn update_configmap_is_risky() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.update_configmap")
            .unwrap();
        assert_eq!(op["risk_level"], "medium");
        assert_eq!(op["safety_tier"], "risky");
    }

    #[test]
    fn watch_events_is_safe() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.watch_events")
            .unwrap();
        assert_eq!(op["risk_level"], "low");
        assert_eq!(op["safety_tier"], "safe");
    }

    #[test]
    fn connector_new_has_zero_counters() {
        let c = KubernetesConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn operations_list_pods_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.list_pods")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.read");
    }

    #[test]
    fn operations_get_pod_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.get_pod")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.read");
    }

    #[test]
    fn operations_get_configmap_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.get_configmap")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.read");
    }

    #[test]
    fn operations_update_configmap_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.update_configmap")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.write");
    }

    #[test]
    fn operations_get_service_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.get_service")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.read");
    }

    #[test]
    fn operations_all_have_summary() {
        for op in operations_info_json().as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {:?} has empty summary", op["id"]);
        }
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("fail 1".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("fail 2".into()),
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 2);
    }

    #[test]
    fn doctor_check_skip_serializing_none_message() {
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
    fn doctor_check_serializes_some_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("warn".into()),
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "warn");
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        assert_eq!(
            serde_json::to_value(DoctorStatus::Healthy).unwrap(),
            "healthy"
        );
        assert_eq!(
            serde_json::to_value(DoctorStatus::Degraded).unwrap(),
            "degraded"
        );
        assert_eq!(
            serde_json::to_value(DoctorStatus::Unhealthy).unwrap(),
            "unhealthy"
        );
    }

    #[test]
    fn doctor_status_deserializes() {
        let s: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(s, DoctorStatus::Healthy);
        let s: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(s, DoctorStatus::Degraded);
        let s: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(s, DoctorStatus::Unhealthy);
    }

    #[test]
    fn require_str_empty_string_is_ok() {
        assert_eq!(
            require_str(&json!({"namespace": ""}), "namespace").unwrap(),
            ""
        );
    }

    #[test]
    fn operations_get_pod_logs_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.get_pod_logs")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.read");
        assert_eq!(op["risk_level"], "low");
    }

    #[test]
    fn operations_stream_pod_logs_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.stream_pod_logs")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.read");
    }

    #[test]
    fn operations_list_deployments_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.list_deployments")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.read");
    }

    #[test]
    fn operations_get_deployment_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.get_deployment")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.read");
    }

    #[test]
    fn operations_scale_deployment_idempotency() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.scale_deployment")
            .unwrap();
        assert_eq!(op["idempotency"], "best_effort");
    }

    #[test]
    fn operations_delete_pod_idempotency() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.delete_pod")
            .unwrap();
        assert_eq!(op["idempotency"], "best_effort");
    }

    #[test]
    fn operations_watch_events_capability() {
        let ops = operations_info_json();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "kubernetes.watch_events")
            .unwrap();
        assert_eq!(op["capability"], "kubernetes.read");
    }

    #[test]
    fn operations_write_ops_have_correct_capability() {
        for op in operations_info_json().as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            let cap = op["capability"].as_str().unwrap();
            if id.contains("scale") || id.contains("rollout") || id.contains("update") {
                assert_eq!(
                    cap, "kubernetes.write",
                    "op {id} should use kubernetes.write"
                );
            }
        }
    }

    #[test]
    fn require_str_object_value() {
        assert!(require_str(&json!({"namespace": {"nested": true}}), "namespace").is_err());
    }

    #[test]
    fn require_str_float_value() {
        assert!(require_str(&json!({"namespace": 1.23}), "namespace").is_err());
    }

    #[test]
    fn require_str_array_value() {
        assert!(require_str(&json!({"namespace": ["a", "b"]}), "namespace").is_err());
    }

    #[test]
    fn operations_all_capabilities_prefixed() {
        for op in operations_info_json().as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.starts_with("kubernetes."),
                "op {:?} capability {cap} should start with kubernetes.",
                op["id"]
            );
        }
    }

    #[test]
    fn doctor_status_copy_eq() {
        let a = DoctorStatus::Healthy;
        let b = a;
        assert_eq!(a, b);
        let c = DoctorStatus::Unhealthy;
        assert_ne!(a, c);
    }
}
