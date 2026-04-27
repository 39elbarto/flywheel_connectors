//! FCP `Amplitude` Connector implementation.

#![allow(clippy::doc_markdown)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, FcpError, FcpResult, IdempotencyClass,
    Introspection, OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep,
    ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, SelfCheckReport, StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument};

use crate::{
    client::{AmplitudeAuth, AmplitudeClient, DEFAULT_BASE_URL},
    error::AmplitudeError,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/amplitude_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/amplitude_connector/<timestamp>";
const VERIFY_COMMANDS: [&str; 10] = [
    "scripts/e2e/amplitude_connector_verification.sh",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo run -q -p fwc -- manifest fix connectors/amplitude/manifest.toml --check --json",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo fmt --manifest-path connectors/amplitude/Cargo.toml --check",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo check -p fcp-amplitude --all-targets",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-amplitude --test integration health_unconfigured_includes_guidance -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-amplitude --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-amplitude --test integration self_check_ready_with_mock_amplitude_api_and_evidence -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-amplitude --test integration self_check_retryable_amplitude_failure_reports_degraded -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo test -p fcp-amplitude --test integration introspection_emits_v3_compliance_evidence -- --nocapture",
    "rch exec -- env RUSTUP_TOOLCHAIN=nightly-2026-02-19 cargo clippy -p fcp-amplitude --all-targets -- -D warnings",
];

const ALLOWED_AMPLITUDE_HOSTS: &[&str] = &[
    "amplitude.com",
    "analytics.amplitude.com",
    "analytics.eu.amplitude.com",
    "api.amplitude.com",
    "api.eu.amplitude.com",
    "api2.amplitude.com",
    "data.amplitude.com",
    "data.eu.amplitude.com",
];

/// Parsed and validated `Amplitude` connector configuration.
#[derive(Debug, Clone)]
struct AmplitudeConfig {
    auth: AmplitudeAuth,
    base_url: String,
}

impl AmplitudeConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_key = params
            .get("api_key")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing or empty api_key in configuration".into(),
            })?
            .to_string();

        let secret_key = params
            .get("secret_key")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing or empty secret_key in configuration".into(),
            })?
            .to_string();

        let base_url = validate_base_url(
            params
                .get("base_url")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(DEFAULT_BASE_URL),
        )?;

        Ok(Self {
            auth: AmplitudeAuth {
                api_key,
                secret_key,
            },
            base_url,
        })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: "basic_auth",
            api_key_configured: true,
            secret_key_configured: true,
            network_ok,
            network_message,
            base_url: self.base_url.clone(),
            charts_surface: true,
            cohorts_surface: true,
            events_export_surface: true,
            write_surface: false,
            host_policy_guidance: "Production verification must target one of the official Amplitude API hosts over HTTPS. Localhost overrides are allowed only for deterministic test fixtures.",
        }
    }
}

/// Provisioning readiness state for the `Amplitude` connector.
#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    api_key_configured: bool,
    secret_key_configured: bool,
    network_ok: bool,
    network_message: String,
    base_url: String,
    charts_surface: bool,
    cohorts_surface: bool,
    events_export_surface: bool,
    write_surface: bool,
    host_policy_guidance: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct OperatorGuidance {
    prerequisites: Vec<&'static str>,
    dedicated_environment: &'static str,
    redaction_rules: Vec<&'static str>,
    limitations: Vec<&'static str>,
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
    #[cfg(test)]
    #[must_use]
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        Self::from_checks_with_provisioning(checks, None)
    }

    #[must_use]
    fn from_checks_with_provisioning(
        checks: Vec<DoctorCheck>,
        provisioning: Option<ProvisioningReadiness>,
    ) -> Self {
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

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use a disposable Amplitude project or localhost fixture before running verification.",
            "Provide both the Amplitude API key and secret key for a project with read access to charts, cohorts, and event export endpoints.",
            "Seed deterministic chart IDs, cohort metadata, and event export fixtures before capturing evidence you plan to share.",
        ],
        dedicated_environment: "Prefer a disposable analytics workspace or a localhost fixture that mirrors the Amplitude export surface. Event exports and cohort metadata can contain sensitive behavioral analytics, so do not aim this harness at production without explicit approval and redaction.",
        redaction_rules: vec![
            "Never print raw Amplitude API keys, secret keys, Basic auth headers, or Authorization values.",
            "Treat chart identifiers, cohort names, cohort sizes, and exported event payloads as potentially sensitive analytics metadata.",
            "If a localhost or internal base_url override is used, capture it in the evidence bundle but redact internal hostnames before sharing artifacts.",
        ],
        limitations: vec![
            "This connector is read-only: chart query, cohort listing, and event export only.",
            "It does not ingest events, mutate cohorts, edit dashboards, manage experiments, or administer workspace settings.",
            "Localhost overrides are supported only for deterministic verification fixtures; production targets must stay on approved HTTPS hosts.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "network_constraints_invalid",
                symptom: "health or self_check reports that the configured base_url violates Amplitude host policy",
                action: "Use an official Amplitude API host over HTTPS, or a localhost test override that mirrors the Amplitude API surface.",
            },
            RemediationHint {
                code: "auth_invalid",
                symptom: "the Amplitude API returns 401 or 403 during self_check",
                action: "Verify the API key and secret key pair belongs to the intended Amplitude project and still has access to chart, cohort, and export reads.",
            },
            RemediationHint {
                code: "self_check_retryable",
                symptom: "the live Amplitude probe failed with rate limiting, timeout, or transient upstream errors",
                action: "Wait for the upstream service to recover or rerun verification after the retry window expires.",
            },
        ],
        rerun_commands: VERIFY_COMMANDS.to_vec(),
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

/// FCP `Amplitude` Connector.
pub struct AmplitudeConnector {
    base: Arc<BaseConnector>,
    config: Option<AmplitudeConfig>,
    client: Option<Arc<AmplitudeClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl AmplitudeConnector {
    /// Create a new `Amplitude` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("amplitude"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    fn doctor(&self) -> DoctorResult {
        let provisioning = self
            .config
            .as_ref()
            .map(AmplitudeConfig::provisioning_readiness);
        let handshaken = self.session_id.is_some();
        let mut checks = vec![
            DoctorCheck {
                name: "configuration".into(),
                passed: self.config.is_some(),
                message: self.config.as_ref().map_or_else(
                    || Some("Not configured; call configure before handshake or invoke".into()),
                    |config| {
                        Some(format!(
                            "Configured for {} via {}",
                            config.base_url,
                            config.auth.redacted_label()
                        ))
                    },
                ),
                critical: true,
            },
            DoctorCheck {
                name: "client_initialized".into(),
                passed: self.client.is_some(),
                message: if self.client.is_some() {
                    None
                } else {
                    Some("API client not initialized; re-run configure".into())
                },
                critical: true,
            },
            DoctorCheck {
                name: "handshake".into(),
                passed: handshaken,
                message: if handshaken {
                    None
                } else {
                    Some("Handshake not completed".into())
                },
                critical: false,
            },
        ];

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
                passed: readiness.api_key_configured && readiness.secret_key_configured,
                message: Some("Amplitude Basic auth credentials configured".into()),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "surface_scope".into(),
                passed: true,
                message: Some(
                    "Read-only analytics surface: chart query, cohort list, and event export"
                        .into(),
                ),
                critical: false,
            });
        }

        DoctorResult::from_checks_with_provisioning(checks, provisioning)
    }

    fn attach_self_check_details(
        &self,
        mut report: SelfCheckReport,
        provisioning: Option<&ProvisioningReadiness>,
        live_probe: Option<&serde_json::Value>,
    ) -> SelfCheckReport {
        report.details = Some(json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "handshaken": self.session_id.is_some(),
            "manifest_hash": Self::manifest_hash(),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": provisioning,
            "live_probe": live_probe,
            "operator_guidance": operator_guidance(),
        }));
        report
    }
}

impl Default for AmplitudeConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl AmplitudeConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = AmplitudeConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Amplitude connector");

        let client = AmplitudeClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;

        self.session_id = None;
        self.base.set_handshaken(false);
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({}))
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
            "connector_id": "fcp.amplitude",
            "connector_version": "0.1.0",
            "capabilities": [
                "amplitude.charts.read",
                "amplitude.cohorts.read",
                "amplitude.events.read"
            ]
        }))
    }

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let client_initialized = self.client.is_some();
        let handshaken = self.session_id.is_some();
        let provisioning = self
            .config
            .as_ref()
            .map(AmplitudeConfig::provisioning_readiness);
        let ready = configured
            && client_initialized
            && handshaken
            && provisioning
                .as_ref()
                .is_none_or(|readiness| readiness.network_ok);

        let status = if ready {
            "healthy"
        } else if configured {
            "degraded"
        } else {
            "unconfigured"
        };

        Ok(json!({
            "status": status,
            "configured": configured,
            "client_initialized": client_initialized,
            "handshaken": handshaken,
            "ready": ready,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "details": {
                "manifest_hash": Self::manifest_hash(),
                "verification_script": VERIFICATION_SCRIPT_PATH,
                "artifact_root_hint": ARTIFACT_ROOT_HINT,
                "provisioning": provisioning,
                "operator_guidance": operator_guidance(),
            }
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.doctor();
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let provisioning = self
            .config
            .as_ref()
            .map(AmplitudeConfig::provisioning_readiness);
        let report = match (&self.config, &self.client, provisioning.as_ref()) {
            (None, _, _) | (_, None, _) => self.attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                provisioning.as_ref(),
                None,
            ),
            (Some(_), Some(_), Some(readiness)) if !readiness.network_ok => self
                .attach_self_check_details(
                    SelfCheckReport::failed(
                        "network_constraints_invalid",
                        readiness.network_message.clone(),
                    ),
                    provisioning.as_ref(),
                    None,
                ),
            (Some(config), Some(client), Some(_)) => match client.list_cohorts().await {
                Ok(response) => {
                    let cohorts_count = response.cohorts.len();
                    let live_probe = json!({
                        "probe": "amplitude.cohorts.list",
                        "base_url": config.base_url.clone(),
                        "cohorts_count": cohorts_count,
                        "response": response,
                    });
                    self.attach_self_check_details(
                        SelfCheckReport::ok(),
                        provisioning.as_ref(),
                        Some(&live_probe),
                    )
                }
                Err(AmplitudeError::Unauthorized | AmplitudeError::Forbidden) => self
                    .attach_self_check_details(
                        SelfCheckReport::failed(
                            "auth_invalid",
                            "Amplitude credentials were rejected by the live probe",
                        ),
                        provisioning.as_ref(),
                        None,
                    ),
                Err(error) if error.is_retryable() => {
                    let live_probe = json!({
                        "probe": "amplitude.cohorts.list",
                        "base_url": config.base_url.clone(),
                        "retryable": true,
                        "retry_after_ms": error.retry_after().map(|duration| duration.as_millis() as u64),
                        "error": error.to_string(),
                    });
                    self.attach_self_check_details(
                        SelfCheckReport::degraded("self_check_retryable", error.to_string()),
                        provisioning.as_ref(),
                        Some(&live_probe),
                    )
                }
                Err(error) => self.attach_self_check_details(
                    SelfCheckReport::failed("self_check_failed", error.to_string()),
                    provisioning.as_ref(),
                    None,
                ),
            },
            (Some(_), Some(_), None) => self.attach_self_check_details(
                SelfCheckReport::failed(
                    "provisioning_unavailable",
                    "Provisioning readiness could not be computed",
                ),
                None,
                None,
            ),
        };
        Self::serialize_self_check_report(report)
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("amplitude.charts.query"),
                    summary: "Query a chart by ID".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["chart_id"],
                        "properties": {
                            "chart_id": {"type": "string", "description": "Chart ID to query"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["data"],
                        "properties": {"data": {"type": "object"}}
                    }),
                    capability: CapabilityId::from_static("amplitude.charts.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Query chart data from Amplitude by chart ID.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"chart_id": "abc123"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("amplitude.events.export"),
                            CapabilityId::from_static("amplitude.cohorts.list"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("amplitude.cohorts.list"),
                    summary: "List cohorts".into(),
                    input_schema: json!({"type": "object", "required": []}),
                    output_schema: json!({
                        "type": "object",
                        "required": ["cohorts"],
                        "properties": {"cohorts": {"type": "array"}}
                    }),
                    capability: CapabilityId::from_static("amplitude.cohorts.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List all cohorts in Amplitude.".into(),
                        common_mistakes: vec![],
                        examples: vec!["{}".into()],
                        related: vec![CapabilityId::from_static("amplitude.events.export")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("amplitude.events.export"),
                    summary: "Export events for a date range".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["start", "end"],
                        "properties": {
                            "start": {"type": "string", "description": "Start date (YYYYMMDDTHH)"},
                            "end": {"type": "string", "description": "End date (YYYYMMDDTHH)"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["data"],
                        "properties": {"data": {"type": "array"}}
                    }),
                    capability: CapabilityId::from_static("amplitude.events.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Export raw events from Amplitude for a date range.".into(),
                        common_mistakes: vec!["Date format must be YYYYMMDDTHH".into()],
                        examples: vec![r#"{"start": "20250101T00", "end": "20250102T00"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("amplitude.cohorts.list"),
                            CapabilityId::from_static("amplitude.charts.query"),
                        ],
                    },
                },
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        let mut value = serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })?;
        let object = value.as_object_mut().ok_or_else(|| FcpError::Internal {
            message: "Amplitude introspection payload was not an object".into(),
        })?;
        object.insert("connector_id".into(), json!("fcp.amplitude"));
        object.insert("version".into(), json!("0.1.0"));
        object.insert("manifest_hash".into(), json!(Self::manifest_hash()));
        object.insert(
            "verification_script".into(),
            json!(VERIFICATION_SCRIPT_PATH),
        );
        object.insert("artifact_root_hint".into(), json!(ARTIFACT_ROOT_HINT));
        object.insert(
            "provisioning".into(),
            json!(
                self.config
                    .as_ref()
                    .map(AmplitudeConfig::provisioning_readiness)
            ),
        );
        object.insert("operator_guidance".into(), json!(operator_guidance()));
        Ok(value)
    }

    /// Handle the `invoke` method.
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

        let input = params
            .get("input")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "amplitude.charts.query" => self.invoke_charts_query(client, &input).await,
            "amplitude.cohorts.list" => self.invoke_cohorts_list(client).await,
            "amplitude.events.export" => self.invoke_events_export(client, &input).await,
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
        let Some(operation) = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
        else {
            return Ok(simulate_denied("Missing operation_id", "FCP-1003"));
        };

        if !operation_supported(operation) {
            return Ok(simulate_denied(
                format!("Unknown operation: {operation}"),
                "FCP-1002",
            ));
        }

        if let Err(error) = self.base.check_ready() {
            return Ok(simulate_denied(error.to_string(), error.error_code()));
        }

        let empty_input = json!({});
        let input = params.get("input").unwrap_or(&empty_input);
        if let Err(error) = validate_simulate_input(operation, input) {
            let fcp_error = error.to_fcp_error();
            return Ok(simulate_denied(error.to_string(), fcp_error.error_code()));
        }

        Ok(json!({
            "allowed": true,
            "reason": "Operation supported",
        }))
    }

    /// Handle the `shutdown` method.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Amplitude connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "amplitude.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Amplitude self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    // -- Operation implementations --

    async fn invoke_charts_query(
        &self,
        client: &AmplitudeClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AmplitudeError> {
        let chart_id = require_str(input, "chart_id")?;
        let response = client.query_chart(chart_id).await?;
        serde_json::to_value(response).map_err(AmplitudeError::Json)
    }

    async fn invoke_cohorts_list(
        &self,
        client: &AmplitudeClient,
    ) -> Result<serde_json::Value, AmplitudeError> {
        let response = client.list_cohorts().await?;
        serde_json::to_value(response).map_err(AmplitudeError::Json)
    }

    async fn invoke_events_export(
        &self,
        client: &AmplitudeClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, AmplitudeError> {
        let start = require_str(input, "start")?;
        let end = require_str(input, "end")?;
        let response = client.export_events(start, end).await?;
        serde_json::to_value(response).map_err(AmplitudeError::Json)
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, AmplitudeError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AmplitudeError::InvalidInput(format!("Missing required field: {field}")))
}

fn operation_supported(operation: &str) -> bool {
    matches!(
        operation,
        "amplitude.charts.query" | "amplitude.cohorts.list" | "amplitude.events.export"
    )
}

fn validate_simulate_input(
    operation: &str,
    input: &serde_json::Value,
) -> Result<(), AmplitudeError> {
    match operation {
        "amplitude.charts.query" => {
            require_str(input, "chart_id")?;
        }
        "amplitude.cohorts.list" => {}
        "amplitude.events.export" => {
            require_str(input, "start")?;
            require_str(input, "end")?;
        }
        _ => {
            return Err(AmplitudeError::InvalidInput(format!(
                "Unknown operation: {operation}"
            )));
        }
    }
    Ok(())
}

fn simulate_denied(reason: impl Into<String>, denial_code: impl Into<String>) -> serde_json::Value {
    json!({
        "allowed": false,
        "reason": reason.into(),
        "denial_code": denial_code.into(),
    })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "amplitude.charts.query",
            "summary": "Query a chart by ID",
            "capability": "amplitude.charts.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "amplitude.cohorts.list",
            "summary": "List cohorts",
            "capability": "amplitude.cohorts.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "amplitude.events.export",
            "summary": "Export events for a date range",
            "capability": "amplitude.events.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
    ])
}

/// Build the provisioning recipe for the `Amplitude` connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("amplitude.basic_auth"),
        "1",
        "Provision `Amplitude` connector with API key and secret key (Basic auth)",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("enter_api_key"),
        ProvisioningStepType::PromptSecret {
            message: "Paste your `Amplitude` API key".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_secret_key"),
            ProvisioningStepType::PromptSecret {
                message: "Paste your `Amplitude` secret key".into(),
            },
        )
        .depends_on(StepId::new("enter_api_key")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_api_key"),
            ProvisioningStepType::StoreSecret {
                key: "api_key".into(),
                value_from: StepId::new("enter_api_key"),
                scope: "connector:fcp.amplitude".into(),
            },
        )
        .depends_on(StepId::new("enter_api_key")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_secret_key"),
            ProvisioningStepType::StoreSecret {
                key: "secret_key".into(),
                value_from: StepId::new("enter_secret_key"),
                scope: "connector:fcp.amplitude".into(),
            },
        )
        .depends_on(StepId::new("enter_secret_key")),
    )
}

fn base_url_policy(base_url: &str) -> (bool, String) {
    let parsed = match Url::parse(base_url) {
        Ok(parsed) => parsed,
        Err(error) => {
            return (false, format!("base_url could not be parsed: {error}"));
        }
    };

    let Some(host) = parsed.host_str() else {
        return (false, "base_url must include a host".into());
    };

    let local = is_local_test_host(host);
    let allowed_host = is_allowed_amplitude_host(host) || local;
    let secure_or_local = parsed.scheme() == "https" || local;

    if allowed_host && secure_or_local {
        (
            true,
            format!("Endpoint accepted by policy checks: {base_url}"),
        )
    } else {
        (
            false,
            format!(
                "Endpoint must use https and one of {ALLOWED_AMPLITUDE_HOSTS:?} (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn validate_base_url(raw_base_url: &str) -> FcpResult<String> {
    let trimmed = raw_base_url.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not be empty".into(),
        });
    }

    let parsed = Url::parse(trimmed).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("base_url could not be parsed: {error}"),
    })?;

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include embedded credentials".into(),
        });
    }

    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include a query string or fragment".into(),
        });
    }

    let canonical = parsed.to_string().trim_end_matches('/').to_string();
    let (allowed, message) = base_url_policy(&canonical);
    if !allowed {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message,
        });
    }

    Ok(canonical)
}

fn is_allowed_amplitude_host(host: &str) -> bool {
    ALLOWED_AMPLITUDE_HOSTS
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_valid_params() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "test-api-key",
            "secret_key": "test-secret",
        }))
        .unwrap();
        assert_eq!(config.auth.api_key, "test-api-key");
        assert_eq!(config.auth.secret_key, "test-secret");
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_with_custom_base_url() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "KEY",
            "secret_key": "SECRET",
            "base_url": "https://api.amplitude.com/api/2",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://api.amplitude.com/api/2");
    }

    #[test]
    fn config_accepts_eu_base_url() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "KEY",
            "secret_key": "SECRET",
            "base_url": "https://api.eu.amplitude.com/api/2",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://api.eu.amplitude.com/api/2");
    }

    #[test]
    fn config_rejects_missing_api_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "secret_key": "secret",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_missing_secret_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "",
            "secret_key": "secret",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_secret_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "   ",
            "secret_key": "secret",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_secret_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_params() {
        let result = AmplitudeConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_api_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": 12345,
            "secret_key": "secret",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_secret_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_api_key() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "  KEY  ",
            "secret_key": "secret",
        }))
        .unwrap();
        assert_eq!(config.auth.api_key, "KEY");
    }

    #[test]
    fn config_trims_secret_key() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": "  SECRET  ",
        }))
        .unwrap();
        assert_eq!(config.auth.secret_key, "SECRET");
    }

    #[test]
    fn config_rejects_null_api_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": null,
            "secret_key": "secret",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_null_secret_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": null,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_boolean_api_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": true,
            "secret_key": "secret",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_array_secret_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": ["a", "b"],
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_object_secret_key() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": {"nested": true},
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_off_policy_base_url() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": "secret",
            "base_url": "https://evil.example.com",
        }));
        let err = result.expect_err("off-policy base_url must be rejected");
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        assert!(err.to_string().contains("api.amplitude.com"));
    }

    #[test]
    fn config_rejects_base_url_query_string() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": "secret",
            "base_url": "https://api.amplitude.com/api/2?leak=1",
        }));
        let err = result.expect_err("query-bearing base_url must be rejected");
        assert!(err.to_string().contains("query string or fragment"));
    }

    #[test]
    fn config_rejects_base_url_with_userinfo() {
        let result = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": "secret",
            "base_url": "https://attacker:pw@api.amplitude.com/api/2",
        }));
        let err = result.expect_err("userinfo-bearing base_url must be rejected");
        assert!(err.to_string().contains("embedded credentials"));
    }

    #[test]
    fn require_str_present() {
        let input = json!({"chart_id": "chart123"});
        assert_eq!(require_str(&input, "chart_id").unwrap(), "chart123");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "chart_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"chart_id": 42});
        assert!(require_str(&input, "chart_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"chart_id": null});
        assert!(require_str(&input, "chart_id").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"chart_id": true});
        assert!(require_str(&input, "chart_id").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"chart_id": ["a", "b"]});
        assert!(require_str(&input, "chart_id").is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"chart_id": {"nested": true}});
        assert!(require_str(&input, "chart_id").is_err());
    }

    #[test]
    fn operations_info_has_3_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 3);
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
        assert!(ids.contains(&"amplitude.charts.query"));
        assert!(ids.contains(&"amplitude.cohorts.list"));
        assert!(ids.contains(&"amplitude.events.export"));
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
    fn operations_all_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert_eq!(op["safety_tier"], "safe");
            assert_eq!(op["risk_level"], "low");
        }
    }

    #[test]
    fn operations_charts_query_capability() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "amplitude.charts.query")
            .unwrap();
        assert_eq!(op["capability"], "amplitude.charts.read");
    }

    #[test]
    fn operations_cohorts_list_capability() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "amplitude.cohorts.list")
            .unwrap();
        assert_eq!(op["capability"], "amplitude.cohorts.read");
    }

    #[test]
    fn operations_events_export_capability() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "amplitude.events.export")
            .unwrap();
        assert_eq!(op["capability"], "amplitude.events.read");
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
        let c = AmplitudeConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_no_config() {
        let c = AmplitudeConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[test]
    fn doctor_check_serializes_with_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failure reason".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "failure reason");
    }

    #[test]
    fn doctor_check_omits_null_message() {
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
    fn doctor_status_serde_roundtrip() {
        let healthy = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(healthy, "healthy");
        let degraded = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(degraded, "degraded");
        let unhealthy = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(unhealthy, "unhealthy");
    }

    #[test]
    fn doctor_status_deserialize() {
        let h: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(h, DoctorStatus::Healthy);
        let d: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(d, DoctorStatus::Degraded);
        let u: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(u, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy_and_eq() {
        let s = DoctorStatus::Healthy;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn doctor_result_preserves_check_count() {
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
            DoctorCheck {
                name: "c".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.checks.len(), 3);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_new_zero_counters() {
        let c = AmplitudeConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn config_debug_format() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "test-key",
            "secret_key": "test-secret",
        }))
        .unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("AmplitudeConfig"));
        assert!(!dbg.contains("test-key"));
        assert!(!dbg.contains("test-secret"));
    }

    #[test]
    fn config_clone() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": "secret",
            "base_url": "https://custom.com",
        }))
        .unwrap();
        let cloned = config.clone();
        // Use original after clone
        assert_eq!(config.auth.api_key, "key");
        assert_eq!(cloned.auth.api_key, "key");
        assert_eq!(cloned.base_url, "https://custom.com");
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"chart_id": ""});
        assert_eq!(require_str(&input, "chart_id").unwrap(), "");
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"chart_id": 9.876});
        assert!(require_str(&input, "chart_id").is_err());
    }

    #[test]
    fn operations_all_have_summary() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {:?} has empty summary", op["id"]);
        }
    }

    #[test]
    fn operations_all_strict_idempotency() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert_eq!(
                op["idempotency"], "strict",
                "op {:?} should be strict",
                op["id"]
            );
        }
    }

    #[test]
    fn config_base_url_defaults_when_not_provided() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": "secret",
        }))
        .unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    // ── Provisioning tests ────────────────────────────────────────

    #[test]
    fn provisioning_readiness_basic_auth_mode() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "test-api-key",
            "secret_key": "test-secret",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.api_key_configured);
        assert!(readiness.secret_key_configured);
        assert!(readiness.network_ok);
        assert_eq!(readiness.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": "secret",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["api_key_configured"], true);
        assert_eq!(v["secret_key_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = AmplitudeConfig::from_params(&json!({
            "api_key": "key",
            "secret_key": "secret",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("amplitude.com"));
    }

    #[test]
    fn provisioning_recipe_has_4_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "amplitude.basic_auth");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 4);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "enter_api_key");
        assert_eq!(recipe.steps[1].id.as_str(), "enter_secret_key");
        assert_eq!(recipe.steps[2].id.as_str(), "store_api_key");
        assert_eq!(recipe.steps[3].id.as_str(), "store_secret_key");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "enter_api_key");
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "enter_api_key");
        assert_eq!(recipe.steps[3].depends_on.len(), 1);
        assert_eq!(recipe.steps[3].depends_on[0].as_str(), "enter_secret_key");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "amplitude.basic_auth");
        assert_eq!(v["steps"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn provisioning_recipe_prompt_steps_are_secret() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        let steps = v["steps"].as_array().unwrap();
        assert_eq!(steps[0]["type"], "prompt_secret");
        assert_eq!(steps[1]["type"], "prompt_secret");
    }

    #[test]
    fn provisioning_recipe_store_steps_have_scope() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        let steps = v["steps"].as_array().unwrap();
        assert_eq!(steps[2]["scope"], "connector:fcp.amplitude");
        assert_eq!(steps[3]["scope"], "connector:fcp.amplitude");
    }

    #[test]
    fn provisioning_recipe_store_api_key_references_prompt() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        let steps = v["steps"].as_array().unwrap();
        assert_eq!(steps[2]["key"], "api_key");
        assert_eq!(steps[2]["value_from"], "enter_api_key");
    }

    #[test]
    fn provisioning_recipe_store_secret_key_references_prompt() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        let steps = v["steps"].as_array().unwrap();
        assert_eq!(steps[3]["key"], "secret_key");
        assert_eq!(steps[3]["value_from"], "enter_secret_key");
    }

    #[test]
    fn base_url_policy_accepts_amplitude_https() {
        let (ok, message) = base_url_policy("https://amplitude.com/api/2");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_analytics_amplitude_https() {
        let (ok, message) = base_url_policy("https://analytics.amplitude.com");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_api_amplitude_https() {
        let (ok, message) = base_url_policy("https://api.amplitude.com/api/2");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_api_eu_amplitude_https() {
        let (ok, message) = base_url_policy("https://api.eu.amplitude.com/api/2");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:8080");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_127_0_0_1() {
        let (ok, _) = base_url_policy("http://127.0.0.1:9090");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_http_non_local() {
        let (ok, message) = base_url_policy("http://amplitude.com");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("amplitude.com"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn base_url_policy_accepts_ipv6_loopback() {
        let (ok, _) = base_url_policy("http://[::1]:3000");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_subdomain() {
        let (ok, _) = base_url_policy("https://evil.amplitude.com.evil.com");
        assert!(!ok);
    }

    #[test]
    fn is_local_test_host_true_cases() {
        assert!(is_local_test_host("localhost"));
        assert!(is_local_test_host("127.0.0.1"));
        assert!(is_local_test_host("::1"));
    }

    #[test]
    fn is_local_test_host_false_cases() {
        assert!(!is_local_test_host("amplitude.com"));
        assert!(!is_local_test_host("192.168.1.1"));
        assert!(!is_local_test_host(""));
    }
}
