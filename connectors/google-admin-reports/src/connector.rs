//! FCP Google Admin Reports Connector implementation.

use std::collections::BTreeSet;
use std::sync::Arc;

use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel,
    SafetyTier, SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use reqwest::Url;
use fcp_google_discovery::{
    ServiceAliasRegistry,
    auth::{GoogleAuthError, GoogleAuthSelection, GoogleMaterializedAuth},
    policy::{GooglePolicyCatalog, PolicyApprovalMode, PolicyRiskLevel, PolicySafetyTier},
    provisioning::load_default_google_provisioning_bundle,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, instrument};

use crate::{
    client::{
        AdminReportsClient, DEFAULT_BASE_URL, google_auth_is_secretless, google_auth_redacted_label,
    },
    error::AdminReportsError,
};

struct AdminReportsConfig {
    auth: GoogleMaterializedAuth,
    base_url: String,
    service_identity: String,
    required_scopes: Vec<String>,
}

impl AdminReportsConfig {
    async fn from_params(params: &Value) -> FcpResult<Self> {
        let service_selector = params
            .get("service_selector")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("admin-reports");
        let service = ServiceAliasRegistry::default()
            .resolve(service_selector)
            .map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid service_selector: {error}"),
            })?;
        if service.api_name != "admin" || service.api_version != "reports_v1" {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "service_selector must resolve to admin:reports_v1 (got {})",
                    service.identity()
                ),
            });
        }

        let required_scopes = resolve_admin_reports_required_scopes(params)?;
        let mut auth_params = params.clone();
        let auth_object = auth_params
            .as_object_mut()
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "configure params must be a JSON object".into(),
            })?;
        auth_object.insert(
            "required_scopes".to_string(),
            json!(required_scopes.clone()),
        );

        let selection =
            GoogleAuthSelection::from_connector_config(&auth_params).map_err(map_auth_error)?;
        let auth = selection
            .materialize()
            .await
            .map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Failed to materialize Google auth: {error}"),
            })?;

        let base_url = match params
            .get("base_url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            Some(raw) => validate_admin_reports_base_url(raw)?,
            None => DEFAULT_BASE_URL.to_string(),
        };

        Ok(Self {
            auth,
            base_url,
            service_identity: service.identity(),
            required_scopes,
        })
    }
}

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

fn host_is_googleapis(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    lower == "googleapis.com" || lower.ends_with(".googleapis.com")
}

/// Validate a google-admin-reports `base_url` override.
///
/// Pins the host to `*.googleapis.com` (localhost permitted for tests),
/// requires https on non-local hosts, and rejects userinfo / query /
/// fragment because AdminReportsClient concatenates the returned
/// string into downstream request URLs. Matches the hygiene of
/// google-calendar (ac44d18c) and google-drive (c9c141c2).
fn validate_admin_reports_base_url(raw: &str) -> FcpResult<String> {
    let trimmed = raw.trim();
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
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use http or https".into(),
        });
    }
    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "base_url must include a host".into(),
    })?;
    let local = is_local_test_host(host);
    if parsed.scheme() == "http" && !local {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message:
                "base_url must use https unless targeting localhost/127.0.0.1/::1 for tests"
                    .into(),
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include userinfo".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include a query string or fragment".into(),
        });
    }
    if !local && !host_is_googleapis(host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url must target googleapis.com (localhost/127.0.0.1/::1 allowed for tests): {trimmed}"
            ),
        });
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

fn parse_string_array_field(params: &Value, field: &str) -> FcpResult<Option<Vec<String>>> {
    let Some(value) = params.get(field) else {
        return Ok(None);
    };
    let values = value.as_array().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("`{field}` must be an array of strings"),
    })?;
    if values.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("`{field}` must not be empty"),
        });
    }

    let mut deduped = BTreeSet::new();
    for value in values {
        let item = value.as_str().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("`{field}` must contain only strings"),
        })?;
        let item = item.trim();
        if item.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("`{field}` entries must not be empty"),
            });
        }
        deduped.insert(item.to_string());
    }

    Ok(Some(deduped.into_iter().collect()))
}

fn resolve_admin_reports_required_scopes(params: &Value) -> FcpResult<Vec<String>> {
    let explicit_scopes = parse_string_array_field(params, "required_scopes")?;
    let scope_triggers = parse_string_array_field(params, "scope_triggers")?.unwrap_or_default();
    if explicit_scopes.is_some() && !scope_triggers.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Provide either `required_scopes` or `scope_triggers`, not both".into(),
        });
    }
    if let Some(scopes) = explicit_scopes {
        return Ok(scopes);
    }

    let bundle = load_default_google_provisioning_bundle("admin_reports").map_err(|error| {
        FcpError::Internal {
            message: format!(
                "Failed to load embedded Google Admin Reports provisioning bundle: {error}"
            ),
        }
    })?;
    bundle
        .scopes_for_triggers(scope_triggers)
        .map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid admin reports scope trigger selection: {error}"),
        })
}

#[allow(clippy::needless_pass_by_value)]
fn map_auth_error(error: GoogleAuthError) -> FcpError {
    match &error {
        GoogleAuthError::ExactlyOneSourceRequired { count: 0 } => FcpError::InvalidRequest {
            code: 1003,
            message: "Missing authentication: supply one Google auth source".into(),
        },
        GoogleAuthError::ExactlyOneSourceRequired { .. } => FcpError::InvalidRequest {
            code: 1003,
            message: format!("Provide exactly one Google auth source: {error}"),
        },
        _ => FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Google auth configuration: {error}"),
        },
    }
}

fn self_check_report_from_result(result: Result<(), AdminReportsError>) -> SelfCheckReport {
    match result {
        Ok(()) => SelfCheckReport::ok(),
        Err(error) => {
            if error.is_retryable() {
                SelfCheckReport::degraded("self_check_retryable", error.to_string())
            } else {
                SelfCheckReport::failed("self_check_failed", error.to_string())
            }
        }
    }
}

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

pub struct AdminReportsConnector {
    base: Arc<BaseConnector>,
    config: Option<AdminReportsConfig>,
    client: Option<AdminReportsClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl AdminReportsConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "google-admin-reports",
            ))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    #[instrument(skip(self, params))]
    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let config = AdminReportsConfig::from_params(&params).await?;

        let client = AdminReportsClient::new_with_auth(config.auth.clone())
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to create HTTP client: {error}"),
            })?
            .with_base_url(&config.base_url);

        info!(
            auth = %google_auth_redacted_label(&config.auth),
            service = %config.service_identity,
            "Admin Reports connector configured"
        );

        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);

        let config = self.config.as_ref().expect("config stored after configure");
        Ok(json!({
            "status": if google_auth_is_secretless(&config.auth) {
                "configured_pending_token_materialization"
            } else {
                "configured"
            },
            "details": {
                "service_identity": config.service_identity,
                "required_scopes": config.required_scopes,
                "auth_mode": google_auth_redacted_label(&config.auth),
                "base_url": config.base_url,
            }
        }))
    }

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
            manifest_hash: "sha256:google-admin-reports-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 100,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        let mut health = json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        });
        if let Some(config) = &self.config {
            health["auth_mode"] = json!(google_auth_redacted_label(&config.auth));
            health["base_url"] = json!(config.base_url);
            health["service_identity"] = json!(config.service_identity);
            health["required_scopes"] = json!(config.required_scopes);
        }
        Ok(health)
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        let mut checks = Vec::new();

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
                message: "Connector is not configured - call `configure` first".into(),
            }
        });

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

        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "service_identity".into(),
                status: DoctorStatus::Healthy,
                message: format!("Discovery service: {}", config.service_identity),
            });
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Healthy,
                message: format!("Auth: {}", google_auth_redacted_label(&config.auth)),
            });
            checks.push(DoctorCheck {
                name: "required_scopes".into(),
                status: DoctorStatus::Healthy,
                message: format!("Required scopes: {}", config.required_scopes.join(", ")),
            });
            checks.push(DoctorCheck {
                name: "admin_context".into(),
                status: DoctorStatus::Healthy,
                message:
                    "Connector expects Workspace admin or delegated-admin credentials for the target tenant"
                        .into(),
            });
        } else {
            for name in [
                "service_identity",
                "auth_mode",
                "required_scopes",
                "admin_context",
            ] {
                checks.push(DoctorCheck {
                    name: name.to_string(),
                    status: DoctorStatus::Unhealthy,
                    message: format!("{name} not set (not configured)"),
                });
            }
        }

        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            status: DoctorStatus::Healthy,
            message: "Egress target: admin.googleapis.com".into(),
        });

        let overall = if checks
            .iter()
            .any(|check| check.status == DoctorStatus::Unhealthy)
        {
            DoctorStatus::Unhealthy
        } else if checks
            .iter()
            .any(|check| check.status == DoctorStatus::Degraded)
        {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };

        serde_json::to_value(DoctorResult {
            status: overall,
            checks,
        })
        .map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {error}"),
        })
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        let Some(client) = &self.client else {
            let report =
                SelfCheckReport::failed("not_configured", "Connector is not configured yet");
            return serde_json::to_value(report).map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {error}"),
            });
        };

        if let Some(config) = &self.config
            && google_auth_is_secretless(&config.auth)
        {
            let report = SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with credential_id; egress proxy injection required for checks",
            );
            return serde_json::to_value(report).map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {error}"),
            });
        }

        let report = self_check_report_from_result(client.health_check().await);
        serde_json::to_value(report).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {error}"),
        })
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        let policy = load_admin_reports_policy_catalog()?;
        let introspection = Introspection {
            operations: vec![
                policy_backed_operation_info(
                    &policy,
                    "admin.list_activities",
                    "activities.list",
                    "List admin activity events for a Workspace application",
                    json!({
                        "type": "object",
                        "required": ["user_key", "application_name"],
                        "properties": {
                            "user_key": { "type": "string", "description": "User email, profile ID, or `all`." },
                            "application_name": { "type": "string", "description": "Workspace application name such as admin, login, drive, calendar, gmail, or chat." },
                            "start_time": { "type": "string", "description": "RFC 3339 timestamp." },
                            "end_time": { "type": "string", "description": "RFC 3339 timestamp." },
                            "event_name": { "type": "string" },
                            "filters": { "type": "string", "description": "Raw Admin Reports filter expression." },
                            "customer_id": { "type": "string" },
                            "org_unit_id": { "type": "string" },
                            "group_id_filter": { "type": "string" },
                            "max_results": { "type": "integer", "minimum": 1, "maximum": 1000 },
                            "page_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "items": { "type": "array", "items": { "type": "object" } },
                            "next_page_token": { "type": "string" }
                        }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read domain-wide Workspace audit logs for a specific product or admin surface.".into(),
                        common_mistakes: vec![
                            "This is an admin-only audit surface and requires admin.reports.audit.readonly.".into(),
                            "Some applications impose extra constraints such as Gmail requiring bounded start/end times.".into(),
                        ],
                        examples: vec![
                            r#"{"user_key":"all","application_name":"login","max_results":100}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("admin.reports.audit.read")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "admin.list_user_usage",
                    "userUsageReport.get",
                    "List user usage reports for a given date",
                    json!({
                        "type": "object",
                        "required": ["user_key", "date"],
                        "properties": {
                            "user_key": { "type": "string" },
                            "date": { "type": "string", "description": "YYYY-MM-DD format." },
                            "customer_id": { "type": "string" },
                            "parameters": { "type": "string", "description": "Comma-separated app:param selectors." },
                            "filters": { "type": "string", "description": "Comma-separated relational filters." },
                            "org_unit_id": { "type": "string" },
                            "group_id_filter": { "type": "string" },
                            "max_results": { "type": "integer", "minimum": 1, "maximum": 1000 },
                            "page_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "usage_reports": { "type": "array", "items": { "type": "object" } },
                            "next_page_token": { "type": "string" }
                        }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Inspect per-user Workspace usage metrics for a specific date.".into(),
                        common_mistakes: vec![
                            "Usage reports require admin.reports.usage.readonly, not the audit scope.".into(),
                            "Usage data often lags by roughly 1-2 days.".into(),
                        ],
                        examples: vec![
                            r#"{"user_key":"all","date":"2026-03-12"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("admin.reports.usage.read")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "admin.list_customer_usage",
                    "customerUsageReports.get",
                    "List customer-wide usage reports for a given date",
                    json!({
                        "type": "object",
                        "required": ["date"],
                        "properties": {
                            "date": { "type": "string", "description": "YYYY-MM-DD format." },
                            "customer_id": { "type": "string" },
                            "parameters": { "type": "string", "description": "Comma-separated app:param selectors." },
                            "page_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "usage_reports": { "type": "array", "items": { "type": "object" } },
                            "next_page_token": { "type": "string" }
                        }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read customer-wide Workspace usage totals for a specific date.".into(),
                        common_mistakes: vec![
                            "This is domain-level telemetry, not a personal-user analytics surface.".into(),
                        ],
                        examples: vec![
                            r#"{"date":"2026-03-12","parameters":"accounts:num_users,gmail:num_emails_sent"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("admin.reports.usage.read")],
                    },
                )?,
                policy_backed_operation_info(
                    &policy,
                    "admin.list_entity_usage",
                    "entityUsageReports.get",
                    "List entity usage reports for a date",
                    json!({
                        "type": "object",
                        "required": ["entity_type", "entity_key", "date"],
                        "properties": {
                            "entity_type": { "type": "string", "description": "Admin Reports entity type such as gplus_communities." },
                            "entity_key": { "type": "string" },
                            "date": { "type": "string", "description": "YYYY-MM-DD format." },
                            "customer_id": { "type": "string" },
                            "parameters": { "type": "string", "description": "Comma-separated app:param selectors." },
                            "filters": { "type": "string", "description": "Comma-separated relational filters." },
                            "max_results": { "type": "integer", "minimum": 1, "maximum": 1000 },
                            "page_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "usage_reports": { "type": "array", "items": { "type": "object" } },
                            "next_page_token": { "type": "string" }
                        }
                    }),
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Inspect entity-specific Workspace usage data for niche admin reports surfaces.".into(),
                        common_mistakes: vec![
                            "Entity usage is narrow and still requires the usage.readonly scope.".into(),
                        ],
                        examples: vec![
                            r#"{"entity_type":"gplus_communities","entity_key":"all","date":"2026-03-12"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("admin.reports.usage.read")],
                    },
                )?,
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize introspection: {error}"),
        })
    }

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
                message: format!("Invalid capability_token: {e}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID".into(),
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
            message: "Invalid capability ID".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            verifier.verify(token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "admin.list_activities" => self.invoke_list_activities(input).await,
            "admin.list_user_usage" => self.invoke_list_user_usage(input).await,
            "admin.list_customer_usage" => self.invoke_list_customer_usage(input).await,
            "admin.list_entity_usage" => self.invoke_list_entity_usage(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    async fn invoke_list_activities(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_key = require_str(&input, "user_key")?;
        let app_name = require_str(&input, "application_name")?;
        let start = input.get("start_time").and_then(|v| v.as_str());
        let end = input.get("end_time").and_then(|v| v.as_str());
        let event_name = input.get("event_name").and_then(|v| v.as_str());
        let filters = input.get("filters").and_then(|v| v.as_str());
        let customer_id = input.get("customer_id").and_then(|v| v.as_str());
        let org_unit_id = input.get("org_unit_id").and_then(|v| v.as_str());
        let group_id_filter = input.get("group_id_filter").and_then(|v| v.as_str());
        let max = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let page_token = input.get("page_token").and_then(|v| v.as_str());

        let result = client
            .list_activities(
                user_key,
                app_name,
                start,
                end,
                event_name,
                filters,
                max,
                page_token,
                customer_id,
                org_unit_id,
                group_id_filter,
            )
            .await
            .map_err(|e: AdminReportsError| e.to_fcp_error())?;

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_list_user_usage(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_key = require_str(&input, "user_key")?;
        let date = require_str(&input, "date")?;
        let customer_id = input.get("customer_id").and_then(|v| v.as_str());
        let parameters = input.get("parameters").and_then(|v| v.as_str());
        let filters = input.get("filters").and_then(|v| v.as_str());
        let org_unit_id = input.get("org_unit_id").and_then(|v| v.as_str());
        let group_id_filter = input.get("group_id_filter").and_then(|v| v.as_str());
        let max = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let page_token = input.get("page_token").and_then(|v| v.as_str());

        let result = client
            .list_user_usage(
                user_key,
                date,
                customer_id,
                parameters,
                filters,
                max,
                page_token,
                org_unit_id,
                group_id_filter,
            )
            .await
            .map_err(|e: AdminReportsError| e.to_fcp_error())?;

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_list_customer_usage(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let date = require_str(&input, "date")?;
        let customer_id = input.get("customer_id").and_then(|v| v.as_str());
        let parameters = input.get("parameters").and_then(|v| v.as_str());
        let page_token = input.get("page_token").and_then(|v| v.as_str());

        let result = client
            .list_customer_usage(date, customer_id, parameters, page_token)
            .await
            .map_err(|e: AdminReportsError| e.to_fcp_error())?;

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_list_entity_usage(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let entity_type = require_str(&input, "entity_type")?;
        let entity_key = require_str(&input, "entity_key")?;
        let date = require_str(&input, "date")?;
        let customer_id = input.get("customer_id").and_then(|v| v.as_str());
        let parameters = input.get("parameters").and_then(|v| v.as_str());
        let filters = input.get("filters").and_then(|v| v.as_str());
        let max = input
            .get("max_results")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let page_token = input.get("page_token").and_then(|v| v.as_str());

        let result = client
            .list_entity_usage(
                entity_type,
                entity_key,
                date,
                customer_id,
                parameters,
                filters,
                max,
                page_token,
            )
            .await
            .map_err(|e: AdminReportsError| e.to_fcp_error())?;

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        info!("Admin Reports connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for AdminReportsConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn load_admin_reports_policy_catalog() -> FcpResult<GooglePolicyCatalog> {
    let catalog = GooglePolicyCatalog::load_default().map_err(|error| FcpError::Internal {
        message: format!("Failed to load embedded Google policy catalog: {error}"),
    })?;
    catalog.service("admin").ok_or(FcpError::Internal {
        message: "Embedded Google policy catalog is missing admin:reports_v1 service rules".into(),
    })?;
    Ok(catalog)
}

fn require_str<'a>(input: &'a Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

fn policy_backed_operation_info(
    policy: &GooglePolicyCatalog,
    id: &'static str,
    discovery_method_key: &'static str,
    summary: &str,
    input_schema: Value,
    output_schema: Value,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> FcpResult<OperationInfo> {
    let resolved = policy
        .classify_operation("admin", discovery_method_key)
        .ok_or(FcpError::Internal {
            message: format!("Missing Admin Reports policy mapping for `{discovery_method_key}`"),
        })?;
    let capability = CapabilityId::new(resolved.rule.capability.clone()).map_err(|error| {
        FcpError::Internal {
            message: format!(
                "Invalid capability `{}` in Admin Reports policy catalog: {error}",
                resolved.rule.capability
            ),
        }
    })?;

    Ok(OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        input_schema,
        output_schema,
        capability,
        risk_level: map_policy_risk_level(resolved.rule.risk_level),
        description: None,
        rate_limit: None,
        requires_approval: map_policy_approval_mode(resolved.rule.approval_mode),
        safety_tier: map_policy_safety_tier(resolved.rule.safety_tier),
        idempotency,
        ai_hints,
    })
}

const fn map_policy_risk_level(level: PolicyRiskLevel) -> RiskLevel {
    match level {
        PolicyRiskLevel::Low => RiskLevel::Low,
        PolicyRiskLevel::Medium => RiskLevel::Medium,
        PolicyRiskLevel::High => RiskLevel::High,
        PolicyRiskLevel::Critical => RiskLevel::Critical,
    }
}

const fn map_policy_safety_tier(tier: PolicySafetyTier) -> SafetyTier {
    match tier {
        PolicySafetyTier::Safe => SafetyTier::Safe,
        PolicySafetyTier::Risky => SafetyTier::Risky,
        PolicySafetyTier::Dangerous => SafetyTier::Dangerous,
        PolicySafetyTier::Critical => SafetyTier::Critical,
        PolicySafetyTier::Forbidden => SafetyTier::Forbidden,
    }
}

const fn map_policy_approval_mode(mode: PolicyApprovalMode) -> Option<ApprovalMode> {
    match mode {
        PolicyApprovalMode::None => None,
        PolicyApprovalMode::Policy => Some(ApprovalMode::Policy),
        PolicyApprovalMode::Interactive => Some(ApprovalMode::Interactive),
        PolicyApprovalMode::ElevationToken => Some(ApprovalMode::ElevationToken),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_admin_reports_base_url_accepts_googleapis() {
        let out = validate_admin_reports_base_url("https://admin.googleapis.com/admin/reports/v1")
            .unwrap();
        assert_eq!(out, "https://admin.googleapis.com/admin/reports/v1");
    }

    #[test]
    fn validate_admin_reports_base_url_allows_localhost_http() {
        validate_admin_reports_base_url("http://localhost:9999").unwrap();
        validate_admin_reports_base_url("http://127.0.0.1/admin").unwrap();
    }

    #[test]
    fn validate_admin_reports_base_url_rejects_foreign_host() {
        let err = validate_admin_reports_base_url("https://evil.example.com/admin/reports/v1")
            .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("googleapis.com"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_admin_reports_base_url_rejects_substring_smuggle() {
        let err = validate_admin_reports_base_url(
            "https://evil.com/admin.googleapis.com/reports/v1",
        )
        .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_admin_reports_base_url_rejects_q_f_u() {
        assert!(matches!(
            validate_admin_reports_base_url("https://admin.googleapis.com/admin/reports/v1?leak=x")
                .unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        assert!(matches!(
            validate_admin_reports_base_url("https://admin.googleapis.com/admin/reports/v1#frag")
                .unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        let err = validate_admin_reports_base_url(
            "https://attacker:pw@admin.googleapis.com/admin/reports/v1",
        )
        .unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("userinfo"), "got: {message}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_admin_reports_base_url_rejects_plain_http_on_public_host() {
        let err =
            validate_admin_reports_base_url("http://admin.googleapis.com/admin/reports/v1")
                .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn host_is_googleapis_rejects_lookalikes_admin() {
        assert!(host_is_googleapis("googleapis.com"));
        assert!(host_is_googleapis("admin.googleapis.com"));
        assert!(!host_is_googleapis("googleapis.com.evil.com"));
        assert!(!host_is_googleapis("evil-googleapis.com"));
    }

    #[test]
    fn resolve_admin_reports_required_scopes_defaults_to_audit_readonly() {
        let scopes = resolve_admin_reports_required_scopes(&json!({})).unwrap();
        assert_eq!(
            scopes,
            vec!["https://www.googleapis.com/auth/admin.reports.audit.readonly".to_string()]
        );
    }

    #[test]
    fn resolve_admin_reports_required_scopes_applies_usage_trigger() {
        let scopes = resolve_admin_reports_required_scopes(&json!({
            "scope_triggers": [
                "User enables usage-report workflows (user, customer, or entity usage metrics)."
            ]
        }))
        .unwrap();
        assert!(
            scopes.contains(
                &"https://www.googleapis.com/auth/admin.reports.audit.readonly".to_string()
            )
        );
        assert!(
            scopes.contains(
                &"https://www.googleapis.com/auth/admin.reports.usage.readonly".to_string()
            )
        );
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_has_all_operations() {
        let connector = AdminReportsConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 4);
        let ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&"admin.list_activities"));
        assert!(ids.contains(&"admin.list_user_usage"));
        assert!(ids.contains(&"admin.list_customer_usage"));
        assert!(ids.contains(&"admin.list_entity_usage"));

        let activity = ops
            .iter()
            .find(|op| op["id"] == "admin.list_activities")
            .unwrap();
        assert_eq!(activity["capability"], "admin.reports.audit.read");
        assert_eq!(activity["requires_approval"], "policy");
    }

    #[fcp_async_core::runtime::test]
    async fn configure_with_access_token_and_admin_alias() {
        let mut connector = AdminReportsConnector::new();
        let result = connector
            .handle_configure(json!({
                "access_token": "ya29.test",
                "service_selector": "admin-reports"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert_eq!(result["details"]["service_identity"], "admin:reports_v1");
    }

    #[fcp_async_core::runtime::test]
    async fn configure_no_auth_fails() {
        let mut connector = AdminReportsConnector::new();
        assert!(connector.handle_configure(json!({})).await.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn health_unconfigured() {
        let connector = AdminReportsConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn shutdown() {
        let connector = AdminReportsConnector::new();
        let result = connector.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(result["status"], "shutdown");
    }

    #[test]
    fn default_impl() {
        let _c = AdminReportsConnector::default();
    }
}
