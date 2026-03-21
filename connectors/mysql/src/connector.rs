//! FCP `MySQL` connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError,
    FcpResult, IdempotencyClass, OperationId, OperationInfo, RiskLevel, SafetyTier,
};
use reqwest::Url;
use serde::Serialize;
use serde_json::{Value, json};
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, MysqlAuth, MysqlClient},
    error::MysqlError,
};

const CONNECTOR_ID: &str = "fcp.mysql";
const CONNECTOR_VERSION: &str = "0.1.0";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/mysql_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/mysql_connector/<timestamp>";
const HEALTH_ENDPOINT_PATH: &str = "/health";

/// Parsed and validated `MySQL` connector configuration.
#[derive(Debug, Clone)]
struct MysqlConfig {
    auth: MysqlAuth,
    base_url: String,
}

impl MysqlConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let provided_token = params
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

        let auth = match (provided_token, credential_id) {
            (Some(key), None) => MysqlAuth::ApiKey(key),
            (None, Some(cred_id)) => MysqlAuth::CredentialId(cred_id),
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

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        Ok(Self { auth, base_url })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message, endpoint) = base_url_policy(&self.base_url);
        ProvisioningReadiness {
            base_url: self.base_url.clone(),
            auth: AuthReadiness {
                mode: self.auth.mode_label(),
                secret_material_configured: !self.auth.is_secretless(),
                requires_credential_injection: self.auth.is_secretless(),
                permissions_guidance: self.auth.permissions_guidance(),
            },
            network: NetworkReadiness {
                valid: network_ok,
                message: network_message,
                endpoint,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct EndpointPolicy {
    scheme: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    path_prefix: String,
    localhost_allowed: bool,
}

#[derive(Debug, Clone, Serialize)]
struct AuthReadiness {
    mode: &'static str,
    secret_material_configured: bool,
    requires_credential_injection: bool,
    permissions_guidance: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct NetworkReadiness {
    valid: bool,
    message: String,
    endpoint: EndpointPolicy,
}

#[derive(Debug, Clone, Serialize)]
struct ProvisioningReadiness {
    base_url: String,
    auth: AuthReadiness,
    network: NetworkReadiness,
}

#[derive(Debug, Clone, Serialize)]
struct OperatorGuidance {
    prerequisites: Vec<&'static str>,
    dedicated_environment: &'static str,
    redaction_rules: Vec<&'static str>,
    common_remediation: Vec<RemediationHint>,
    rerun_commands: Vec<&'static str>,
    artifact_root_hint: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct RemediationHint {
    code: &'static str,
    symptom: &'static str,
    action: &'static str,
}

/// Doctor check result.
#[derive(Debug, Clone, Serialize)]
struct DoctorResult {
    ready: bool,
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning: Option<ProvisioningReadiness>,
    operator_guidance: OperatorGuidance,
    verification_script: &'static str,
}

/// Doctor status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Individual doctor check.
#[derive(Debug, Clone, Serialize)]
struct DoctorCheck {
    name: String,
    passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    #[must_use]
    fn from_checks(checks: Vec<DoctorCheck>, provisioning: Option<ProvisioningReadiness>) -> Self {
        let ready = checks
            .iter()
            .filter(|check| check.critical)
            .all(|check| check.passed);
        let status = if checks.iter().any(|c| c.critical && !c.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| !c.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self {
            ready,
            status,
            checks,
            provisioning,
            operator_guidance: operator_guidance(),
            verification_script: VERIFICATION_SCRIPT_PATH,
        }
    }
}

fn is_local_test_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host.ends_with(".localhost")
}

fn base_url_policy(base_url: &str) -> (bool, String, EndpointPolicy) {
    let parsed = match Url::parse(base_url) {
        Ok(url) => url,
        Err(error) => {
            return (
                false,
                format!("base_url must be an absolute HTTP(S) URL: {error}"),
                EndpointPolicy {
                    scheme: None,
                    host: None,
                    port: None,
                    path_prefix: String::new(),
                    localhost_allowed: false,
                },
            );
        }
    };

    let host = parsed.host_str().map(str::to_string);
    let localhost_allowed = host.as_deref().is_some_and(is_local_test_host);
    let endpoint = EndpointPolicy {
        scheme: Some(parsed.scheme().to_string()),
        host,
        port: parsed.port_or_known_default(),
        path_prefix: parsed.path().to_string(),
        localhost_allowed,
    };

    let Some(host) = parsed.host_str() else {
        return (false, "base_url must include a host".into(), endpoint);
    };

    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return (
            false,
            format!("base_url must use http or https, got {}", parsed.scheme()),
            endpoint,
        );
    }

    if parsed.query().is_some() || parsed.fragment().is_some() {
        return (
            false,
            "base_url must not contain a query string or fragment".into(),
            endpoint,
        );
    }

    if !localhost_allowed && parsed.scheme() != "https" {
        return (
            false,
            format!(
                "non-local proxy endpoints must use https, got {}",
                parsed.scheme()
            ),
            endpoint,
        );
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return (
            false,
            "base_url must not embed credentials; use api_key or credential_id instead".into(),
            endpoint,
        );
    }

    if is_local_test_host(host) {
        (
            true,
            format!("localhost test endpoint accepted for verification: {base_url}"),
            endpoint,
        )
    } else {
        (
            true,
            "HTTP(S) MySQL proxy endpoint accepted".into(),
            endpoint,
        )
    }
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Run verification against a dedicated MySQL or MariaDB staging database exposed through an HTTP proxy that implements /query, /execute, /explain, /schema/*, and /health.",
            "Choose exactly one auth path: a proxy-specific API token or credential_id-based host injection.",
            "Seed disposable tables, rows, and indexes before invoking write or schema verification flows.",
        ],
        dedicated_environment: "Use a disposable staging database and proxy. mysql.execute can mutate or delete rows, so verification must never target production data.",
        redaction_rules: vec![
            "Never print raw api_key values, bearer tokens, injected upstream credentials, or DSNs.",
            "Treat base_url hosts, schema names, and table names as environment metadata unless the environment is already disposable or public.",
            "Do not paste private row contents or live DDL statements into shared transcripts.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "base_url_invalid",
                symptom: "doctor or self_check reports malformed or policy-invalid base_url",
                action: "Use an absolute http(s) proxy URL. Non-local endpoints must use https and must not embed credentials, query strings, or fragments.",
            },
            RemediationHint {
                code: "credential_injection_required",
                symptom: "credential_id mode is configured but self_check cannot prove live auth",
                action: "Configure the host or egress proxy to inject the upstream MySQL credential before rerunning self_check.",
            },
            RemediationHint {
                code: "auth_invalid",
                symptom: "health probe returns 401",
                action: "Verify the proxy token or injected credential mapping, then rerun the verification bundle against the staging proxy.",
            },
            RemediationHint {
                code: "permissions_insufficient",
                symptom: "health probe or invoke returns 403 from the proxy",
                action: "Grant the staging credential access to the read, write, schema, and health surfaces required for this connector slice.",
            },
            RemediationHint {
                code: "health_probe_unreachable",
                symptom: "self_check cannot reach the /health endpoint",
                action: "Confirm the proxy is running, reachable from the host, and exposes the configured base_url path prefix.",
            },
        ],
        rerun_commands: vec![
            "scripts/e2e/mysql_connector_verification.sh",
            "fwc manifest fix connectors/mysql/manifest.toml --check --json",
            "rch exec -- cargo test -p fcp-mysql --test integration -- --nocapture",
            "rch exec -- cargo clippy -p fcp-mysql --all-targets -- -D warnings",
        ],
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

const fn error_status_code(error: &MysqlError) -> Option<u16> {
    match error {
        MysqlError::Auth(_) => Some(401),
        MysqlError::PermissionDenied(_) => Some(403),
        MysqlError::RateLimited { .. } => Some(429),
        MysqlError::Api { status_code, .. } => Some(*status_code),
        _ => None,
    }
}

const fn self_check_reason_code(error: &MysqlError) -> &'static str {
    match error {
        MysqlError::Auth(_) => "auth_invalid",
        MysqlError::PermissionDenied(_) => "permissions_insufficient",
        MysqlError::RateLimited { .. } => "rate_limited",
        MysqlError::Timeout(_) => "health_probe_timeout",
        MysqlError::Connection(_) | MysqlError::Http(_) => "health_probe_unreachable",
        MysqlError::Api { .. }
        | MysqlError::Json(_)
        | MysqlError::Query(_)
        | MysqlError::Transaction(_)
        | MysqlError::Schema(_)
        | MysqlError::ConstraintViolation(_)
        | MysqlError::InvalidInput(_) => "health_probe_failed",
    }
}

fn live_probe_success(base_url: &str, payload: &Value) -> Value {
    json!({
        "status": "ok",
        "endpoint": format!("{base_url}{HEALTH_ENDPOINT_PATH}"),
        "payload": payload,
    })
}

fn live_probe_failure(base_url: &str, error: &MysqlError) -> Value {
    json!({
        "status": "error",
        "endpoint": format!("{base_url}{HEALTH_ENDPOINT_PATH}"),
        "status_code": error_status_code(error),
        "retryable": error.is_retryable(),
        "message": error.to_string(),
    })
}

fn details_payload(
    provisioning: Option<&ProvisioningReadiness>,
    live_probe: Option<&Value>,
) -> Value {
    json!({
        "provisioning": provisioning,
        "live_probe": live_probe,
        "operator_guidance": operator_guidance(),
        "verification_script": VERIFICATION_SCRIPT_PATH,
        "artifact_root_hint": ARTIFACT_ROOT_HINT,
    })
}

fn self_check_response(
    ready: bool,
    status: &'static str,
    reason_code: Option<&'static str>,
    message: &str,
    provisioning: Option<&ProvisioningReadiness>,
    live_probe: Option<&Value>,
) -> Value {
    json!({
        "ready": ready,
        "status": status,
        "reason_code": reason_code,
        "message": message,
        "version": CONNECTOR_VERSION,
        "connector_id": CONNECTOR_ID,
        "details": details_payload(provisioning, live_probe),
    })
}

/// FCP `MySQL` connector.
pub struct MysqlConnector {
    base: Arc<BaseConnector>,
    config: Option<MysqlConfig>,
    client: Option<MysqlClient>,
    handshaken: bool,
    requests: AtomicU64,
    errors: AtomicU64,
}

#[allow(clippy::missing_errors_doc)]
impl MysqlConnector {
    /// Create a new unconfigured `MySQL` connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            config: None,
            client: None,
            handshaken: false,
            requests: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    fn require_str<'a>(params: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
        params
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: format!("missing required field: {field}"),
            })
    }

    /// Handle configure request.
    pub fn handle_configure(&mut self, params: &serde_json::Value) -> FcpResult<serde_json::Value> {
        let config = MysqlConfig::from_params(params)?;
        let client =
            MysqlClient::new(config.auth.clone(), Some(&config.base_url)).map_err(|e| {
                FcpError::Internal {
                    message: format!("Failed to create MySQL client: {e}"),
                }
            })?;

        info!(base_url = %config.base_url, auth = %config.auth.redacted_label(), "MySQL connector configured");

        self.config = Some(config);
        self.client = Some(client);

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake request.
    pub fn handle_handshake(
        &mut self,
        _params: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.handshaken = true;
        Ok(json!({
            "protocol_version": "2.0.0",
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
        }))
    }

    /// Handle health check.
    ///
    /// Reports truthful health: actually probes the database when configured
    /// rather than merely reporting config presence.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let provisioning = self
            .config
            .as_ref()
            .map(MysqlConfig::provisioning_readiness);
        let configured = provisioning.is_some();
        let mut ready = false;
        let mut status = "not_configured";
        let mut reason_code = Some("not_configured");
        let mut live_probe = None;

        if let Some(readiness) = provisioning.as_ref() {
            if !readiness.network.valid {
                status = "degraded";
                reason_code = Some("base_url_invalid");
            } else if readiness.auth.requires_credential_injection {
                status = "degraded";
                reason_code = Some("credential_injection_required");
            } else if let Some(client) = self.client.as_ref() {
                match client.probe_health().await {
                    Ok(payload) => {
                        status = "healthy";
                        ready = true;
                        reason_code = None;
                        live_probe = Some(live_probe_success(client.base_url(), &payload));
                    }
                    Err(error) => {
                        status = "degraded";
                        reason_code = Some(self_check_reason_code(&error));
                        live_probe = Some(live_probe_failure(client.base_url(), &error));
                    }
                }
            } else {
                status = "degraded";
                reason_code = Some("client_uninitialized");
            }
        }

        Ok(json!({
            "status": status,
            "ready": ready,
            "reason_code": reason_code,
            "configured": configured,
            "handshaken": self.handshaken,
            "requests": self.requests.load(Ordering::Relaxed),
            "errors": self.errors.load(Ordering::Relaxed),
            "details": details_payload(provisioning.as_ref(), live_probe.as_ref()),
        }))
    }

    /// Handle doctor check.
    pub fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let provisioning = self
            .config
            .as_ref()
            .map(MysqlConfig::provisioning_readiness);
        let mut checks = Vec::new();

        let configured = provisioning.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: configured,
            message: Some(if configured {
                "Configuration loaded".into()
            } else {
                "Not configured. Provide api_key or credential_id plus the HTTP(S) proxy base_url."
                    .into()
            }),
            critical: true,
        });

        let client_ok = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: client_ok,
            message: Some(if client_ok {
                "MySQL client initialized".into()
            } else {
                "MySQL client not initialized. Run configure first.".into()
            }),
            critical: true,
        });

        if let Some(readiness) = provisioning.as_ref() {
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: readiness.network.valid,
                message: Some(readiness.network.message.clone()),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "auth_surface".into(),
                passed: !readiness.auth.requires_credential_injection,
                message: Some(if readiness.auth.requires_credential_injection {
                    "credential_id mode is configured; the host must inject a concrete credential before live verification can pass.".into()
                } else {
                    format!(
                        "{} mode is configured for live verification.",
                        readiness.auth.mode
                    )
                }),
                critical: true,
            });
        }

        let handshake_ok = self.handshaken;
        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: handshake_ok,
            message: Some(if handshake_ok {
                "Handshake completed".into()
            } else {
                "Handshake not completed. Non-critical for basic operations.".into()
            }),
            critical: false,
        });

        let result = DoctorResult::from_checks(checks, provisioning);
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    /// Handle `self_check`.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let provisioning = self
            .config
            .as_ref()
            .map(MysqlConfig::provisioning_readiness);
        let Some(readiness) = provisioning.as_ref() else {
            return Ok(self_check_response(
                false,
                "error",
                Some("not_configured"),
                "Connector is not configured",
                provisioning.as_ref(),
                None,
            ));
        };

        if !readiness.network.valid {
            return Ok(self_check_response(
                false,
                "error",
                Some("network_constraints_invalid"),
                readiness.network.message.as_str(),
                provisioning.as_ref(),
                None,
            ));
        }

        if readiness.auth.requires_credential_injection {
            return Ok(self_check_response(
                false,
                "degraded",
                Some("credential_injection_required"),
                "credential_id mode requires host-side credential injection before live verification can prove connectivity.",
                provisioning.as_ref(),
                None,
            ));
        }

        let Some(client) = self.client.as_ref() else {
            return Ok(self_check_response(
                false,
                "error",
                Some("client_uninitialized"),
                "MySQL client is not initialized; rerun configure.",
                provisioning.as_ref(),
                None,
            ));
        };

        match client.probe_health().await {
            Ok(payload) => {
                let live_probe = live_probe_success(client.base_url(), &payload);
                Ok(self_check_response(
                    true,
                    "ready",
                    None,
                    "MySQL proxy health probe succeeded",
                    provisioning.as_ref(),
                    Some(&live_probe),
                ))
            }
            Err(error) => {
                let live_probe = live_probe_failure(client.base_url(), &error);
                let error_message = error.to_string();
                Ok(self_check_response(
                    false,
                    "error",
                    Some(self_check_reason_code(&error)),
                    error_message.as_str(),
                    provisioning.as_ref(),
                    Some(&live_probe),
                ))
            }
        }
    }

    /// Handle introspect request.
    pub fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let operations = operations_info();
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "archetypes": ["storage", "operational"],
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "operations": operations.iter().map(|op| {
                // Use serde serialization for enum values to get canonical snake_case
                let safety = serde_json::to_value(op.safety_tier)
                    .unwrap_or_else(|_| json!("unknown"));
                let risk = serde_json::to_value(op.risk_level)
                    .unwrap_or_else(|_| json!("unknown"));
                let idem = serde_json::to_value(op.idempotency)
                    .unwrap_or_else(|_| json!("unknown"));
                let approval = serde_json::to_value(op.requires_approval)
                    .unwrap_or(serde_json::Value::Null);
                json!({
                    "id": op.id.as_str(),
                    "summary": op.summary,
                    "description": op.description,
                    "safety_tier": safety,
                    "risk_level": risk,
                    "idempotency": idem,
                    "capability": op.capability.as_str(),
                    "requires_approval": approval,
                    "input_schema": op.input_schema,
                    "output_schema": op.output_schema,
                })
            }).collect::<Vec<_>>(),
            "operation_count": operations.len(),
        }))
    }

    /// Handle invoke request.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.requests.fetch_add(1, Ordering::Relaxed);

        let operation = Self::require_str(&params, "operation")?;
        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        let client = self
            .client
            .as_ref()
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 5001,
                message: "Connector not configured. Call configure first.".into(),
            })?;

        let result = match operation {
            "mysql.query" => {
                let sql = Self::require_str(&input, "sql")?;
                let params_arr = input
                    .get("params")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                client.query(sql, &params_arr).await
            }
            "mysql.execute" => {
                let sql = Self::require_str(&input, "sql")?;
                let params_arr = input
                    .get("params")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                client.execute(sql, &params_arr).await
            }
            "mysql.explain" => {
                let sql = Self::require_str(&input, "sql")?;
                client.explain(sql).await
            }
            "mysql.schema.tables" => client.list_tables().await,
            "mysql.schema.columns" => {
                let table = Self::require_str(&input, "table")?;
                client.list_columns(table).await
            }
            "mysql.schema.indexes" => {
                let table = Self::require_str(&input, "table")?;
                client.list_indexes(table).await
            }
            "mysql.health" => {
                let probe = client.probe_health().await.map_err(|error| {
                    self.errors.fetch_add(1, Ordering::Relaxed);
                    error.to_fcp_error()
                })?;
                Ok(json!({
                    "healthy": true,
                    "status": "healthy",
                    "probe": probe,
                }))
            }
            other => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {other}"),
                });
            }
        };

        result.map_err(|e: MysqlError| {
            self.errors.fetch_add(1, Ordering::Relaxed);
            e.to_fcp_error()
        })
    }

    /// Handle simulate request.
    pub fn handle_simulate(&self, params: &serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = Self::require_str(params, "operation")?;
        let configured = self.client.is_some();

        let ops = operations_info();
        let operation_known = ops.iter().any(|op| op.id.as_str() == operation);

        Ok(json!({
            "would_succeed": configured && operation_known,
            "configured": configured,
            "operation_known": operation_known,
        }))
    }

    /// Handle shutdown request.
    pub fn handle_shutdown(&mut self, _params: &serde_json::Value) -> FcpResult<serde_json::Value> {
        if let Some(ref client) = self.client {
            client.shutdown();
        }
        info!("MySQL connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for MysqlConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// All operations provided by the `MySQL` connector.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static("mysql.query"),
            summary: "Execute a read-only SQL query".into(),
            description: Some("Execute a parameterized SELECT query against the MySQL database. Returns rows, columns, and row count.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "sql": { "type": "string", "description": "SQL query (use ? placeholders)" },
                    "params": { "type": "array", "items": {}, "description": "Positional parameters" },
                    "timeout_ms": { "type": "integer", "description": "Query timeout in milliseconds" }
                },
                "required": ["sql"]
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "rows": { "type": "array" },
                    "columns": { "type": "array" },
                    "row_count": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static("mysql.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use for SELECT queries, read-only data retrieval".into(),
                common_mistakes: vec![
                    "Using string interpolation instead of parameterized queries".into(),
                    "Not setting a timeout for long-running queries".into(),
                ],
                examples: vec![],
                related: vec![CapabilityId::from_static("mysql.write")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("mysql.execute"),
            summary: "Execute a SQL statement (INSERT/UPDATE/DELETE)".into(),
            description: Some("Execute a parameterized mutation statement. Returns affected row count.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "sql": { "type": "string", "description": "SQL statement (use ? placeholders)" },
                    "params": { "type": "array", "items": {}, "description": "Positional parameters" }
                },
                "required": ["sql"]
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "affected_rows": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static("mysql.write"),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use for parameterized INSERT, UPDATE, or DELETE statements against a disposable staging database.".into(),
                common_mistakes: vec![
                    "Using raw SQL without parameterized queries (SQL injection risk)".into(),
                    "Pointing mutation traffic at a non-disposable database".into(),
                    "Executing DDL (CREATE/ALTER/DROP) through execute instead of a dedicated, audited maintenance path".into(),
                ],
                examples: vec![],
                related: vec![CapabilityId::from_static("mysql.read")],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static("mysql.explain"),
            summary: "Explain a query execution plan".into(),
            description: Some("Run EXPLAIN on a query to analyze its execution plan without executing it.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "sql": { "type": "string", "description": "SQL query to explain" }
                },
                "required": ["sql"]
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "plan": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static("mysql.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to analyze query performance before execution".into(),
                common_mistakes: vec!["Confusing EXPLAIN with actual query execution".into()],
                examples: vec![],
                related: vec![CapabilityId::from_static("mysql.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("mysql.schema.tables"),
            summary: "List database tables".into(),
            description: Some("List all tables in the current database with metadata (engine, row count estimate).".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "database": { "type": "string" },
                        "engine": { "type": "string" },
                        "row_count_estimate": { "type": "integer" }
                    }
                }
            }),
            capability: CapabilityId::from_static("mysql.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to discover tables in the database before querying".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![
                    CapabilityId::from_static("mysql.schema.columns"),
                    CapabilityId::from_static("mysql.schema.indexes"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("mysql.schema.columns"),
            summary: "List columns for a table".into(),
            description: Some("List all columns in a table with types, nullability, defaults, and primary key info.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "table": { "type": "string", "description": "Table name" }
                },
                "required": ["table"]
            }),
            output_schema: json!({
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "data_type": { "type": "string" },
                        "nullable": { "type": "boolean" },
                        "is_primary_key": { "type": "boolean" }
                    }
                }
            }),
            capability: CapabilityId::from_static("mysql.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to understand table structure before writing queries".into(),
                common_mistakes: vec!["Querying columns for a non-existent table".into()],
                examples: vec![],
                related: vec![CapabilityId::from_static("mysql.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("mysql.schema.indexes"),
            summary: "List indexes for a table".into(),
            description: Some("List all indexes on a table with columns, uniqueness, and index type.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "table": { "type": "string", "description": "Table name" }
                },
                "required": ["table"]
            }),
            output_schema: json!({
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "columns": { "type": "array", "items": { "type": "string" } },
                        "unique": { "type": "boolean" },
                        "type": { "type": "string" }
                    }
                }
            }),
            capability: CapabilityId::from_static("mysql.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to check query optimization opportunities".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![CapabilityId::from_static("mysql.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("mysql.health"),
            summary: "Check MySQL database health".into(),
            description: Some("Probe the MySQL database to verify connectivity and basic functionality.".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "healthy": { "type": "boolean" },
                    "status": { "type": "string" },
                    "probe": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static("mysql.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to verify database is accessible before running queries".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_new_defaults() {
        let connector = MysqlConnector::new();
        assert!(connector.config.is_none());
        assert!(connector.client.is_none());
        assert!(!connector.handshaken);
    }

    #[test]
    fn connector_default_same_as_new() {
        let connector = MysqlConnector::default();
        assert!(connector.config.is_none());
    }

    #[test]
    fn config_from_api_key() {
        let params = json!({ "api_key": "test-key-123" });
        let config = MysqlConfig::from_params(&params).unwrap();
        assert!(matches!(config.auth, MysqlAuth::ApiKey(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let params = json!({ "credential_id": "550e8400-e29b-41d4-a716-446655440000" });
        let config = MysqlConfig::from_params(&params).unwrap();
        assert!(matches!(config.auth, MysqlAuth::CredentialId(_)));
    }

    #[test]
    fn config_with_custom_base_url() {
        let params = json!({
            "api_key": "test-key",
            "base_url": "https://my-mysql-proxy.example.com"
        });
        let config = MysqlConfig::from_params(&params).unwrap();
        assert_eq!(config.base_url, "https://my-mysql-proxy.example.com");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let params = json!({
            "api_key": "key",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        });
        assert!(MysqlConfig::from_params(&params).is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let params = json!({});
        assert!(MysqlConfig::from_params(&params).is_err());
    }

    #[test]
    fn config_rejects_empty_api_key() {
        let params = json!({ "api_key": "" });
        assert!(MysqlConfig::from_params(&params).is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        let params = json!({ "api_key": "  " });
        assert!(MysqlConfig::from_params(&params).is_err());
    }

    #[test]
    fn config_trims_api_key() {
        let params = json!({ "api_key": "  test-key  " });
        let config = MysqlConfig::from_params(&params).unwrap();
        assert!(matches!(
            config.auth,
            MysqlAuth::ApiKey(ref key) if key == "test-key"
        ));
    }

    #[test]
    fn operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 7);
    }

    #[test]
    fn operations_all_have_ids() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.id.as_str().is_empty(), "operation must have an ID");
        }
    }

    #[test]
    fn operations_all_have_summaries() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                !op.summary.is_empty(),
                "operation {} must have a summary",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn operations_all_have_capabilities() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                !op.capability.as_str().is_empty(),
                "operation {} must have a capability",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn operations_read_ops_are_safe() {
        let ops = operations_info();
        let read_ops: Vec<&OperationInfo> = ops
            .iter()
            .filter(|op| op.capability.as_str() == "mysql.read")
            .collect();
        assert!(!read_ops.is_empty());
        for op in read_ops {
            assert_eq!(
                op.safety_tier,
                SafetyTier::Safe,
                "read operation {} should be Safe",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn operations_write_ops_are_risky() {
        let ops = operations_info();
        let write_ops: Vec<&OperationInfo> = ops
            .iter()
            .filter(|op| op.capability.as_str() == "mysql.write")
            .collect();
        assert!(!write_ops.is_empty());
        for op in write_ops {
            assert_eq!(
                op.safety_tier,
                SafetyTier::Risky,
                "write operation {} should be Risky",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn operations_no_dangerous_none_violation() {
        let ops = operations_info();
        for op in &ops {
            if op.safety_tier == SafetyTier::Dangerous {
                assert_ne!(
                    op.idempotency,
                    IdempotencyClass::None,
                    "Dangerous operation {} must not have IdempotencyClass::None",
                    op.id.as_str()
                );
            }
        }
    }

    #[test]
    fn operations_all_have_schemas() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                op.input_schema.is_object(),
                "operation {} must have input schema",
                op.id.as_str()
            );
            assert!(
                op.output_schema.is_object() || op.output_schema.is_array(),
                "operation {} must have output schema",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn provisioning_readiness_rejects_invalid_base_url() {
        let config = MysqlConfig::from_params(&json!({
            "api_key": "test-key",
            "base_url": "ftp://db.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network.valid);
        assert!(readiness.network.message.contains("http or https"));
    }

    #[test]
    fn provisioning_readiness_marks_secretless_mode() {
        let config = MysqlConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": "https://db.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.auth.requires_credential_injection);
        assert_eq!(readiness.auth.mode, "credential_id");
    }

    #[test]
    fn execute_operation_requires_interactive_approval() {
        let execute = operations_info()
            .into_iter()
            .find(|op| op.id.as_str() == "mysql.execute")
            .expect("mysql.execute present");
        assert_eq!(execute.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn doctor_unconfigured_includes_operator_guidance() {
        let connector = MysqlConnector::new();
        let doctor = connector.handle_doctor().unwrap();
        assert_eq!(doctor["ready"], false);
        assert_eq!(doctor["status"], "unhealthy");
        assert_eq!(
            doctor["verification_script"],
            "scripts/e2e/mysql_connector_verification.sh"
        );
        assert_eq!(
            doctor["operator_guidance"]["artifact_root_hint"],
            "artifacts/e2e/mysql_connector/<timestamp>"
        );
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
        let result = DoctorResult::from_checks(checks, None);
        assert!(result.ready);
        assert_eq!(result.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_unhealthy_when_critical_fails() {
        let checks = vec![DoctorCheck {
            name: "a".into(),
            passed: false,
            message: None,
            critical: true,
        }];
        let result = DoctorResult::from_checks(checks, None);
        assert!(!result.ready);
        assert_eq!(result.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_degraded_when_noncritical_fails() {
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
                message: None,
                critical: false,
            },
        ];
        let result = DoctorResult::from_checks(checks, None);
        assert!(result.ready);
        assert_eq!(result.status, DoctorStatus::Degraded);
    }

    #[test]
    fn require_str_returns_value() {
        let params = json!({ "sql": "SELECT 1" });
        let sql = MysqlConnector::require_str(&params, "sql").unwrap();
        assert_eq!(sql, "SELECT 1");
    }

    #[test]
    fn require_str_errors_on_missing() {
        let params = json!({});
        assert!(MysqlConnector::require_str(&params, "sql").is_err());
    }

    #[test]
    fn require_str_errors_on_non_string() {
        let params = json!({ "sql": 42 });
        assert!(MysqlConnector::require_str(&params, "sql").is_err());
    }
}
