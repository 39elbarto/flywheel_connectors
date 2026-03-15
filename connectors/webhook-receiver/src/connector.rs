//! FCP Webhook Receiver Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::DateTime;
use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, FcpError, FcpResult, IdempotencyClass,
    OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport,
};
use rand::RngCore;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_PUBLIC_BASE_URL, WebhookStore},
    error::WebhookReceiverError,
    types::WebhookProvider,
};

/// Parsed and validated webhook receiver configuration.
#[derive(Debug, Clone)]
struct WebhookReceiverConfig {
    public_base_url: String,
}

impl WebhookReceiverConfig {
    fn from_params(params: &serde_json::Value) -> Self {
        let public_base_url = params
            .get("public_base_url")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_PUBLIC_BASE_URL)
            .to_string();

        Self { public_base_url }
    }

    fn provisioning_readiness(&self, store: &WebhookStore) -> ProvisioningReadiness {
        let (public_base_url_accepted, publicly_routable, public_base_url_message) =
            public_base_url_policy(&self.public_base_url);
        let endpoints_with_issues = store
            .endpoint_snapshots()
            .into_iter()
            .filter_map(|endpoint| {
                let issues = endpoint.validation_issues();
                if issues.is_empty() {
                    None
                } else {
                    Some(EndpointProvisioningIssue {
                        endpoint_id: endpoint.endpoint_id,
                        provider: endpoint.provider.label().to_string(),
                        issues,
                    })
                }
            })
            .collect::<Vec<_>>();

        ProvisioningReadiness {
            public_base_url: self.public_base_url.clone(),
            public_base_url_accepted,
            publicly_routable,
            public_base_url_message,
            endpoint_count: store.endpoint_count(),
            active_endpoint_count: store.active_endpoint_count(),
            invalid_endpoint_count: endpoints_with_issues.len(),
            endpoints_with_issues,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct EndpointProvisioningIssue {
    endpoint_id: String,
    provider: String,
    issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ProvisioningReadiness {
    public_base_url: String,
    public_base_url_accepted: bool,
    publicly_routable: bool,
    public_base_url_message: String,
    endpoint_count: usize,
    active_endpoint_count: usize,
    invalid_endpoint_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    endpoints_with_issues: Vec<EndpointProvisioningIssue>,
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

/// FCP Webhook Receiver Connector.
pub struct WebhookReceiverConnector {
    base: Arc<BaseConnector>,
    config: Option<WebhookReceiverConfig>,
    store: WebhookStore,
    runtime: Option<fcp_sdk::migration::ConnectorRuntime>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl WebhookReceiverConnector {
    /// Create a new Webhook Receiver connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "webhook-receiver",
            ))),
            config: None,
            store: WebhookStore::new(),
            runtime: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for WebhookReceiverConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl WebhookReceiverConnector {
    /// Handle the `configure` method.
    ///
    /// The webhook receiver is a local meta-connector so configuration is
    /// minimal. No external API credentials are needed.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = WebhookReceiverConfig::from_params(&params);
        info!(public_base_url = %config.public_base_url, "Configuring Webhook Receiver connector");
        let runtime = fcp_sdk::migration::ConnectorRuntime::new(
            fcp_sdk::migration::ConnectorRuntimeConfig::default(),
        );
        self.runtime = Some(runtime);
        self.store.set_public_base_url(&config.public_base_url);
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({
            "public_base_url": self.store.public_base_url(),
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

        let session_id = params
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        self.session_id = session_id;
        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.webhook-receiver",
            "connector_version": "0.1.0",
            "capabilities": [
                "webhook.endpoints.read",
                "webhook.endpoints.write",
                "webhook.events.read"
            ]
        }))
    }

    /// Handle the `health` method.
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
            "endpoints": self.store.endpoint_count(),
            "events": self.store.total_event_count(),
            "public_base_url": self.config.as_ref().map(|config| config.public_base_url.clone()),
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_some() {
                None
            } else {
                Some("Not configured - call configure first".into())
            },
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "store_initialized".into(),
            passed: true,
            message: None,
            critical: true,
        });

        if let Some(config) = &self.config {
            let readiness = config.provisioning_readiness(&self.store);
            checks.push(DoctorCheck {
                name: "public_base_url".into(),
                passed: readiness.public_base_url_accepted,
                message: Some(readiness.public_base_url_message.clone()),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "public_reachability".into(),
                passed: readiness.publicly_routable,
                message: Some(readiness.public_base_url_message.clone()),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "endpoint_profiles".into(),
                passed: readiness.invalid_endpoint_count == 0,
                message: if readiness.invalid_endpoint_count == 0 {
                    Some(format!(
                        "{} endpoint profile(s) validated",
                        readiness.endpoint_count
                    ))
                } else {
                    Some(format!(
                        "{} endpoint profile(s) failed validation",
                        readiness.invalid_endpoint_count
                    ))
                },
                critical: true,
            });
        }

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
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return Self::serialize_self_check_report(report);
        };

        let readiness = config.provisioning_readiness(&self.store);
        if !readiness.public_base_url_accepted {
            let mut report = SelfCheckReport::failed(
                "public_base_url_invalid",
                readiness.public_base_url_message.clone(),
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        if readiness.invalid_endpoint_count > 0 {
            let mut report = SelfCheckReport::failed(
                "endpoint_profiles_invalid",
                format!(
                    "{} endpoint profile(s) failed validation",
                    readiness.invalid_endpoint_count
                ),
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        if !readiness.publicly_routable {
            let mut report = SelfCheckReport::degraded(
                "public_base_url_not_public",
                readiness.public_base_url_message.clone(),
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let mut report = SelfCheckReport::ok();
        report.details = Some(json!({ "provisioning": readiness }));
        Self::serialize_self_check_report(report)
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let ops = operations_info();
        Ok(json!({
            "connector_id": "fcp.webhook-receiver",
            "version": "0.1.0",
            "operations": serde_json::to_value(&ops).unwrap_or_default(),
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
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

        let result = match operation {
            "webhook.endpoints.create" => self.invoke_endpoints_create(&input),
            "webhook.endpoints.rotate_secret" => self.invoke_endpoints_rotate_secret(&input),
            "webhook.endpoints.delete" => self.invoke_endpoints_delete(&input),
            "webhook.endpoints.list" => self.invoke_endpoints_list(),
            "webhook.events.recent" => self.invoke_events_recent(&input),
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
            .get("operation_id")
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
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        info!("Webhook Receiver connector shutting down");
        self.store.clear();
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        self.session_id = None;
        Ok(json!({}))
    }

    // -- Operation implementations --

    fn invoke_endpoints_create(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, WebhookReceiverError> {
        let path = require_str(input, "path")?.trim();
        if path.is_empty() {
            return Err(WebhookReceiverError::InvalidInput {
                message: "path must not be empty".into(),
            });
        }

        let provider = parse_provider(input)?;
        let signing_secret = optional_str(input, "signing_secret")?
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let signing_secret_generated = signing_secret.is_none();
        let signing_secret = signing_secret.unwrap_or_else(|| generate_signing_secret(provider));
        let signature_header = optional_str(input, "signature_header")?
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map_or_else(|| provider.default_signature_header().to_string(), str::to_string);

        let signature_algorithm = optional_str(input, "signature_algorithm")?
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map_or_else(|| provider.default_signature_algorithm().to_string(), str::to_string);
        let allowed_sources = parse_string_array(input, "allowed_sources")?;

        let endpoint = self.store.create_endpoint_profile(
            path.to_string(),
            signing_secret,
            allowed_sources,
            provider,
            signature_header,
            signature_algorithm,
        )?;

        Ok(json!({
            "endpoint_id": endpoint.endpoint_id,
            "url": endpoint.url,
            "provider": endpoint.provider,
            "signature_header": endpoint.signature_header,
            "signature_algorithm": endpoint.signature_algorithm,
            "recommended_events": endpoint.provider.recommended_events(),
            "signing_secret": endpoint.signing_secret,
            "signing_secret_generated": signing_secret_generated,
            "secret_last_rotated_at": endpoint.secret_last_rotated_at.to_rfc3339(),
        }))
    }

    fn invoke_endpoints_rotate_secret(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, WebhookReceiverError> {
        let endpoint_id = require_str(input, "endpoint_id")?;
        let provider = self.store.get_endpoint(endpoint_id)?.provider;
        let signing_secret = optional_str(input, "signing_secret")?
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let signing_secret_generated = signing_secret.is_none();
        let signing_secret = signing_secret.unwrap_or_else(|| generate_signing_secret(provider));
        let endpoint = self
            .store
            .rotate_endpoint_secret(endpoint_id, signing_secret)?;

        Ok(json!({
            "endpoint_id": endpoint.endpoint_id,
            "url": endpoint.url,
            "provider": endpoint.provider,
            "signature_header": endpoint.signature_header,
            "signature_algorithm": endpoint.signature_algorithm,
            "recommended_events": endpoint.provider.recommended_events(),
            "signing_secret": endpoint.signing_secret,
            "signing_secret_generated": signing_secret_generated,
            "secret_last_rotated_at": endpoint.secret_last_rotated_at.to_rfc3339(),
        }))
    }

    fn invoke_endpoints_delete(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, WebhookReceiverError> {
        let endpoint_id = require_str(input, "endpoint_id")?;
        self.store.delete_endpoint(endpoint_id)?;
        Ok(json!({}))
    }

    #[allow(clippy::unnecessary_wraps)]
    fn invoke_endpoints_list(&self) -> Result<serde_json::Value, WebhookReceiverError> {
        let endpoints = self.store.list_endpoints();
        let endpoints_json: Vec<serde_json::Value> = endpoints
            .iter()
            .map(|ep| {
                json!({
                    "endpoint_id": ep.endpoint_id,
                    "path": ep.path,
                    "url": ep.url,
                    "provider": ep.provider,
                    "signature_header": ep.signature_header,
                    "signature_algorithm": ep.signature_algorithm,
                    "allowed_sources": ep.allowed_sources,
                    "signing_secret_configured": ep.signing_secret_configured,
                    "secret_last_rotated_at": ep.secret_last_rotated_at.to_rfc3339(),
                    "active": ep.active,
                    "created_at": ep.created_at.to_rfc3339(),
                    "event_count": ep.event_count,
                })
            })
            .collect();

        Ok(json!({ "endpoints": endpoints_json }))
    }

    fn invoke_events_recent(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, WebhookReceiverError> {
        let endpoint_id = input.get("endpoint_id").and_then(serde_json::Value::as_str);

        let limit = input
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .map(|v| v as usize);

        let since_ts = input
            .get("since_ts")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));

        let events = self.store.get_recent_events(endpoint_id, limit, since_ts)?;

        let events_json: Vec<serde_json::Value> = events
            .iter()
            .map(|evt| {
                json!({
                    "event_id": evt.event_id,
                    "endpoint_id": evt.endpoint_id,
                    "received_at": evt.received_at.to_rfc3339(),
                    "payload": evt.payload,
                    "signature_valid": evt.signature_valid,
                })
            })
            .collect();

        Ok(json!({ "events": events_json }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, WebhookReceiverError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| WebhookReceiverError::InvalidInput {
            message: format!("Missing required field: {field}"),
        })
}

/// Extract an optional string field from input, rejecting non-string values.
fn optional_str<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> Result<Option<&'a str>, WebhookReceiverError> {
    match input.get(field) {
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| WebhookReceiverError::InvalidInput {
                message: format!("{field} must be a string"),
            }),
        None => Ok(None),
    }
}

/// Parse a string array field, rejecting non-string or blank entries.
fn parse_string_array(
    input: &serde_json::Value,
    field: &str,
) -> Result<Vec<String>, WebhookReceiverError> {
    let Some(value) = input.get(field) else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| WebhookReceiverError::InvalidInput {
            message: format!("{field} must be an array of strings"),
        })?;

    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let entry = value
                .as_str()
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .ok_or_else(|| WebhookReceiverError::InvalidInput {
                    message: format!("{field}[{index}] must be a non-empty string"),
                })?;
            Ok(entry.to_string())
        })
        .collect()
}

/// Parse a provider preset from create input.
fn parse_provider(input: &serde_json::Value) -> Result<WebhookProvider, WebhookReceiverError> {
    let Some(provider) = optional_str(input, "provider")? else {
        return Ok(WebhookProvider::default());
    };

    WebhookProvider::from_label(provider).ok_or_else(|| WebhookReceiverError::InvalidInput {
        message: format!("Unsupported provider preset: {provider}"),
    })
}

/// Generate a high-entropy signing secret with a provider-specific prefix.
fn generate_signing_secret(provider: WebhookProvider) -> String {
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!(
        "{}{}",
        provider.secret_prefix(),
        URL_SAFE_NO_PAD.encode(bytes)
    )
}

fn public_base_url_policy(public_base_url: &str) -> (bool, bool, String) {
    let parsed = match Url::parse(public_base_url) {
        Ok(parsed) => parsed,
        Err(error) => {
            return (
                false,
                false,
                format!("public_base_url could not be parsed: {error}"),
            );
        }
    };

    let Some(host) = parsed.host_str() else {
        return (false, false, "public_base_url must include a host".into());
    };

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return (
            false,
            false,
            format!("public_base_url must use http or https, got: {scheme}"),
        );
    }

    if parsed.query().is_some() || parsed.fragment().is_some() {
        return (
            false,
            false,
            "public_base_url must not include query parameters or fragments".into(),
        );
    }

    let local = is_local_test_host(host);
    if scheme != "https" && !local {
        return (
            false,
            false,
            "public_base_url must use https unless it points to a local test host".into(),
        );
    }

    if local {
        (
            true,
            false,
            format!("Local test base URL accepted but not publicly routable: {public_base_url}"),
        )
    } else {
        (
            true,
            true,
            format!("Public base URL accepted: {public_base_url}"),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

impl WebhookReceiverConnector {
    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "webhook_receiver.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Webhook receiver self-check completed"
        );

        serde_json::to_value(report).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {error}"),
        })
    }
}

/// Build a single [`OperationInfo`].
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

/// Build the operations info for introspection.
fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "webhook.endpoints.create",
            "Register a new webhook endpoint with provider-aware verification defaults",
            json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string", "description": "URL path to listen on" },
                    "provider": { "type": "string", "description": "Provider preset: generic, github, stripe, slack, twilio" },
                    "signing_secret": { "type": "string", "description": "Optional signing secret; omitted values are generated in-memory" },
                    "signature_header": { "type": "string", "description": "Override the expected signature header for generic endpoints" },
                    "signature_algorithm": { "type": "string", "description": "Override the verification algorithm for generic endpoints" },
                    "allowed_sources": { "type": "array", "description": "IP CIDR ranges allowed to send webhooks" }
                }
            }),
            json!({
                "type": "object",
                "required": ["endpoint_id", "url", "provider", "signature_header", "signature_algorithm", "signing_secret", "signing_secret_generated", "secret_last_rotated_at"],
                "properties": {
                    "endpoint_id": { "type": "string" },
                    "url": { "type": "string" },
                    "provider": { "type": "string" },
                    "signature_header": { "type": "string" },
                    "signature_algorithm": { "type": "string" },
                    "recommended_events": { "type": "array" },
                    "signing_secret": { "type": "string" },
                    "signing_secret_generated": { "type": "boolean" },
                    "secret_last_rotated_at": { "type": "string" }
                }
            }),
            "webhook.endpoints.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Register a new webhook endpoint and auto-populate provider verification settings.".into(),
                common_mistakes: vec![
                    "Using a provider preset with a mismatched signature header or algorithm.".into(),
                    "Configuring a localhost public_base_url and expecting the endpoint to be reachable from external webhook providers.".into(),
                ],
                examples: vec![
                    r#"{"path": "/hooks/github", "provider": "github"}"#.into(),
                    r#"{"path": "/hooks/custom", "provider": "generic", "signature_header": "X-Signature", "signature_algorithm": "hmac-sha256"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("webhook.endpoints.rotate_secret"),
                    CapabilityId::from_static("webhook.endpoints.list"),
                    CapabilityId::from_static("webhook.endpoints.delete"),
                ],
            },
        ),
        op_info(
            "webhook.endpoints.rotate_secret",
            "Rotate the signing secret for an existing webhook endpoint",
            json!({
                "type": "object",
                "required": ["endpoint_id"],
                "properties": {
                    "endpoint_id": { "type": "string" },
                    "signing_secret": { "type": "string", "description": "Optional replacement signing secret; omitted values are generated in-memory" }
                }
            }),
            json!({
                "type": "object",
                "required": ["endpoint_id", "signing_secret", "signing_secret_generated", "secret_last_rotated_at"],
                "properties": {
                    "endpoint_id": { "type": "string" },
                    "url": { "type": "string" },
                    "provider": { "type": "string" },
                    "signature_header": { "type": "string" },
                    "signature_algorithm": { "type": "string" },
                    "recommended_events": { "type": "array" },
                    "signing_secret": { "type": "string" },
                    "signing_secret_generated": { "type": "boolean" },
                    "secret_last_rotated_at": { "type": "string" }
                }
            }),
            "webhook.endpoints.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Rotate a webhook signing secret after suspected exposure or during routine credential hygiene.".into(),
                common_mistakes: vec![
                    "Rotating the local secret without updating the upstream webhook provider configuration.".into(),
                ],
                examples: vec![r#"{"endpoint_id": "ep_abc123"}"#.into()],
                related: vec![
                    CapabilityId::from_static("webhook.endpoints.create"),
                    CapabilityId::from_static("webhook.endpoints.list"),
                ],
            },
        ),
        op_info(
            "webhook.endpoints.delete",
            "Remove a webhook endpoint",
            json!({
                "type": "object",
                "required": ["endpoint_id"],
                "properties": {
                    "endpoint_id": { "type": "string" }
                }
            }),
            json!({ "type": "object" }),
            "webhook.endpoints.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use:
                    "Remove a webhook endpoint. Incoming webhooks to this path will be rejected."
                        .into(),
                common_mistakes: vec![
                    "Forgetting to unregister the webhook URL at the sending service before deleting the endpoint.".into(),
                    "Using the endpoint path instead of endpoint_id.".into(),
                ],
                examples: vec![r#"{"endpoint_id": "ep_abc123"}"#.into()],
                related: vec![CapabilityId::from_static("webhook.endpoints.list")],
            },
        ),
        op_info(
            "webhook.endpoints.list",
            "List registered webhook endpoints",
            json!({
                "type": "object",
                "required": [],
                "properties": {}
            }),
            json!({
                "type": "object",
                "required": ["endpoints"],
                "properties": {
                    "endpoints": { "type": "array" }
                }
            }),
            "webhook.endpoints.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List configured webhook endpoints.".into(),
                common_mistakes: vec![
                    "Assuming the list reflects live registration status at the sending service — it only shows locally registered endpoints.".into(),
                ],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static("webhook.endpoints.create")],
            },
        ),
        op_info(
            "webhook.events.recent",
            "Get recent webhook events",
            json!({
                "type": "object",
                "required": [],
                "properties": {
                    "endpoint_id": { "type": "string" },
                    "limit": { "type": "integer", "maximum": 100 },
                    "since_ts": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["events"],
                "properties": {
                    "events": { "type": "array" }
                }
            }),
            "webhook.events.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get recent webhook events received on an endpoint.".into(),
                common_mistakes: vec![
                    "Not filtering by endpoint_id and receiving events from all endpoints mixed together.".into(),
                    "Expecting events that failed signature validation to appear in results — they are rejected before storage.".into(),
                ],
                examples: vec![r#"{"endpoint_id": "ep_abc123", "limit": 20}"#.into()],
                related: vec![CapabilityId::from_static("webhook.endpoints.list")],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_str_present() {
        let input = json!({"path": "/hooks/github"});
        assert_eq!(require_str(&input, "path").unwrap(), "/hooks/github");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"path": 42});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"path": null});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn operations_info_has_4_operations() {
        let ops = operations_info();
        assert_eq!(ops.len(), 5);
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
        let ops = operations_info();
        for op in &ops {
            // RiskLevel is a typed enum, always valid by construction
            let _ = op.risk_level;
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let ops = operations_info();
        for op in &ops {
            // SafetyTier is a typed enum, always valid by construction
            let _ = op.safety_tier;
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
        assert!(ids.contains(&"webhook.endpoints.create"));
        assert!(ids.contains(&"webhook.endpoints.rotate_secret"));
        assert!(ids.contains(&"webhook.endpoints.delete"));
        assert!(ids.contains(&"webhook.endpoints.list"));
        assert!(ids.contains(&"webhook.events.recent"));
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
        for op in &ops {
            // IdempotencyClass is a typed enum, always present by construction
            let _ = op.idempotency;
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
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = WebhookReceiverConnector::default();
        assert!(c.config.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_state() {
        let c = WebhookReceiverConnector::new();
        assert!(c.config.is_none());
        assert!(c.session_id.is_none());
        assert_eq!(c.store.endpoint_count(), 0);
        assert_eq!(c.store.total_event_count(), 0);
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"path": true});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"path": ["a", "b"]});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn operations_write_ops_are_not_safe() {
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
    fn require_str_object_value() {
        let input = json!({"path": {"nested": "val"}});
        assert!(require_str(&input, "path").is_err());
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"path": ""});
        // Empty string is still a valid string
        assert_eq!(require_str(&input, "path").unwrap(), "");
    }

    #[test]
    fn operations_endpoints_create_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "webhook.endpoints.create")
            .unwrap();
        assert_eq!(op.capability.as_ref(), "webhook.endpoints.write");
        assert_eq!(op.risk_level, RiskLevel::Medium);
        assert_eq!(op.safety_tier, SafetyTier::Risky);
    }

    #[test]
    fn operations_endpoints_rotate_secret_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "webhook.endpoints.rotate_secret")
            .unwrap();
        assert_eq!(op.capability.as_ref(), "webhook.endpoints.write");
        assert_eq!(op.risk_level, RiskLevel::Medium);
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn operations_endpoints_delete_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "webhook.endpoints.delete")
            .unwrap();
        assert_eq!(op.capability.as_ref(), "webhook.endpoints.write");
        assert_eq!(op.risk_level, RiskLevel::High);
        assert_eq!(op.safety_tier, SafetyTier::Dangerous);
    }

    #[test]
    fn operations_endpoints_list_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "webhook.endpoints.list")
            .unwrap();
        assert_eq!(op.capability.as_ref(), "webhook.endpoints.read");
    }

    #[test]
    fn operations_events_recent_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|o| o.id.as_ref() == "webhook.events.recent")
            .unwrap();
        assert_eq!(op.capability.as_ref(), "webhook.events.read");
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
    fn doctor_check_serializes_message_when_some() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("error detail".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "error detail");
    }

    #[test]
    fn doctor_check_skips_message_when_none() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert!(v.get("message").is_none());
    }

    #[test]
    fn doctor_status_serialize_lowercase() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
    }

    #[test]
    fn doctor_status_deserialize_lowercase() {
        let s: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(s, DoctorStatus::Healthy);
        let s: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(s, DoctorStatus::Degraded);
        let s: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(s, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        #[allow(clippy::redundant_clone)]
        let cloned = r.clone();
        assert_eq!(cloned.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_check_debug() {
        let check = DoctorCheck {
            name: "config".into(),
            passed: true,
            message: None,
            critical: true,
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    #[test]
    fn doctor_check_clone() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("msg".into()),
            critical: true,
        };
        #[allow(clippy::redundant_clone)]
        let cloned = check.clone();
        assert_eq!(cloned.name, "test");
        assert!(!cloned.passed);
        assert_eq!(cloned.message, Some("msg".into()));
        assert!(cloned.critical);
    }

    #[test]
    fn doctor_result_deserialize_roundtrip() {
        let r = DoctorResult::from_checks(vec![
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
        ]);
        let s = serde_json::to_string(&r).unwrap();
        let r2: DoctorResult = serde_json::from_str(&s).unwrap();
        assert_eq!(r2.status, DoctorStatus::Degraded);
        assert_eq!(r2.checks.len(), 2);
    }

    #[test]
    fn parse_provider_defaults_to_generic() {
        let input = json!({});
        assert_eq!(parse_provider(&input).unwrap(), WebhookProvider::Generic);
    }

    #[test]
    fn parse_provider_rejects_unknown_values() {
        let input = json!({"provider": "unknown"});
        assert!(parse_provider(&input).is_err());
    }

    #[test]
    fn parse_string_array_rejects_blank_entries() {
        let input = json!({"allowed_sources": ["10.0.0.0/8", "  "]});
        assert!(parse_string_array(&input, "allowed_sources").is_err());
    }

    #[test]
    fn public_base_url_policy_accepts_https_host() {
        let (accepted, routable, message) = public_base_url_policy("https://hooks.flywheel.test");
        assert!(accepted);
        assert!(routable);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn public_base_url_policy_marks_localhost_degraded() {
        let (accepted, routable, message) = public_base_url_policy("http://localhost:8080");
        assert!(accepted);
        assert!(!routable);
        assert!(message.contains("not publicly routable"));
    }
}
