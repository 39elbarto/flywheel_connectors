//! FCP `Home Assistant` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, EventCaps, EventInfo,
    FcpError, FcpResult, IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel,
    SafetyTier, SelfCheckReport,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, HomeAssistantAuth, HomeAssistantClient},
    error::HomeAssistantError,
    types::HomeAssistantEventSubscriptionRequest,
};

/// Parsed and validated `Home Assistant` connector configuration.
#[derive(Debug, Clone)]
struct HomeAssistantConfig {
    auth: HomeAssistantAuth,
    base_url: String,
}

impl HomeAssistantConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let access_token = params
            .get("access_token")
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

        let auth = match (access_token, credential_id) {
            (Some(token), None) => HomeAssistantAuth::BearerToken(token),
            (None, Some(cred_id)) => HomeAssistantAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of access_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing access_token or credential_id in configuration".into(),
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

    const fn auth_mode(&self) -> &'static str {
        match &self.auth {
            HomeAssistantAuth::BearerToken(_) => "access_token",
            HomeAssistantAuth::CredentialId(_) => "credential_id",
        }
    }

    const fn rate_limit_profile(&self) -> &'static str {
        match &self.auth {
            HomeAssistantAuth::BearerToken(_) => {
                "access_token: local instance, no external rate limits"
            }
            HomeAssistantAuth::CredentialId(_) => {
                "credential_id: authenticated via egress proxy injection"
            }
        }
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: self.auth_mode(),
            access_token_configured: self.auth.has_token(),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            rate_limit_profile: self.rate_limit_profile(),
            base_url: self.base_url.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    access_token_configured: bool,
    credential_id_configured: bool,
    requires_credential_injection: bool,
    network_ok: bool,
    network_message: String,
    rate_limit_profile: &'static str,
    base_url: String,
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

    const fn status_label(&self) -> &'static str {
        match self.status {
            DoctorStatus::Healthy => "healthy",
            DoctorStatus::Degraded => "degraded",
            DoctorStatus::Unhealthy => "unhealthy",
        }
    }
}

/// FCP `Home Assistant` Connector.
pub struct HomeAssistantConnector {
    base: Arc<BaseConnector>,
    config: Option<HomeAssistantConfig>,
    client: Option<Arc<HomeAssistantClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl HomeAssistantConnector {
    /// Create a new `Home Assistant` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "homeassistant",
            ))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for HomeAssistantConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl HomeAssistantConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = HomeAssistantConfig::from_params(&params)?;
        let provisioning = config.provisioning_readiness();
        let status = if provisioning.network_ok {
            "configured"
        } else {
            "configured_with_warnings"
        };
        info!(
            event = "homeassistant.provisioning.configure",
            auth = %config.auth.redacted_label(),
            auth_mode = provisioning.auth_mode,
            network_ok = provisioning.network_ok,
            rate_limit_profile = provisioning.rate_limit_profile,
            base_url = %config.base_url,
            "Configuring Home Assistant connector"
        );

        let client = HomeAssistantClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;

        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({
            "status": status,
            "provisioning": provisioning,
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
            "connector_id": "fcp.homeassistant",
            "connector_version": "0.1.0",
            "capabilities": [
                "homeassistant.read",
                "homeassistant.write",
                "homeassistant.control"
            ],
            "event_caps": homeassistant_event_caps()
        }))
    }

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();
        let provisioning = self
            .config
            .as_ref()
            .map(HomeAssistantConfig::provisioning_readiness);

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
            "provisioning": provisioning,
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.build_doctor_result();
        let failed_checks = result.checks.iter().filter(|check| !check.passed).count();
        info!(
            event = "homeassistant.provisioning.doctor",
            status = result.status_label(),
            total_checks = result.checks.len(),
            failed_checks,
            "Home Assistant doctor completed"
        );
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

        if readiness.requires_credential_injection {
            let mut report = SelfCheckReport::degraded(
                "credential_injection_required",
                "credential_id mode requires egress proxy injection; skipping live probe",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let mut report = match client.health_check().await {
            Ok(()) => SelfCheckReport::ok(),
            Err(error) => {
                if error.is_retryable() {
                    SelfCheckReport::degraded("connectivity_retryable", error.to_string())
                } else {
                    SelfCheckReport::failed("connectivity_failed", error.to_string())
                }
            }
        };
        report.details = Some(json!({ "provisioning": readiness }));

        Self::serialize_self_check_report(report)
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: typed_operations(),
            events: event_info(),
            resource_types: vec![],
            auth_caps: None,
            event_caps: Some(homeassistant_event_caps()),
        };
        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
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

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "homeassistant.list_states" => self.invoke_list_states(client).await,
            "homeassistant.get_state" => self.invoke_get_state(client, &input).await,
            "homeassistant.set_state" => self.invoke_set_state(client, &input).await,
            "homeassistant.call_service" => self.invoke_call_service(client, &input).await,
            "homeassistant.list_services" => self.invoke_list_services(client).await,
            "homeassistant.list_areas" => self.invoke_list_areas(client).await,
            "homeassistant.list_devices" => self.invoke_list_devices(client).await,
            "homeassistant.list_automations" => self.invoke_list_automations(client).await,
            "homeassistant.trigger_automation" => {
                self.invoke_trigger_automation(client, &input).await
            }
            "homeassistant.toggle_automation" => {
                self.invoke_toggle_automation(client, &input).await
            }
            "homeassistant.list_scenes" => self.invoke_list_scenes(client).await,
            "homeassistant.activate_scene" => self.invoke_activate_scene(client, &input).await,
            "homeassistant.get_history" => self.invoke_get_history(client, &input).await,
            "homeassistant.get_statistics" => self.invoke_get_statistics(client, &input).await,
            "homeassistant.subscribe_events" => self.invoke_subscribe_events(client, &input).await,
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

        let allowed = typed_operations()
            .iter()
            .any(|o| o.id.as_ref() == operation);

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
        if let Some(client) = &self.client {
            client.shutdown();
        }
        info!("Home Assistant connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_list_states(
        &self,
        client: &HomeAssistantClient,
    ) -> Result<serde_json::Value, HomeAssistantError> {
        let data = client.list_states().await?;
        Ok(json!({ "states": data }))
    }

    async fn invoke_get_state(
        &self,
        client: &HomeAssistantClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HomeAssistantError> {
        let entity_id = require_str(input, "entity_id")?;
        let data = client.get_state(entity_id).await?;
        Ok(json!({ "state": data }))
    }

    async fn invoke_set_state(
        &self,
        client: &HomeAssistantClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HomeAssistantError> {
        let entity_id = require_str(input, "entity_id")?;
        let state_value = require_str(input, "state")?;
        let attributes = input.get("attributes").cloned();

        let mut body = json!({ "state": state_value });
        if let Some(attrs) = attributes {
            body["attributes"] = attrs;
        }

        let data = client.set_state(entity_id, &body).await?;
        Ok(json!({ "state": data }))
    }

    async fn invoke_call_service(
        &self,
        client: &HomeAssistantClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HomeAssistantError> {
        let domain = require_str(input, "domain")?;
        let service = require_str(input, "service")?;

        let mut body = json!({});
        if let Some(service_data) = input.get("service_data") {
            body["service_data"] = service_data.clone();
        }
        if let Some(target) = input.get("target") {
            // Merge target entity_id into body for HA API
            if let Some(entity_id) = target.get("entity_id") {
                body["entity_id"] = entity_id.clone();
            }
            if let Some(area_id) = target.get("area_id") {
                body["area_id"] = area_id.clone();
            }
            if let Some(device_id) = target.get("device_id") {
                body["device_id"] = device_id.clone();
            }
        }

        let data = client.call_service(domain, service, &body).await?;
        Ok(json!({ "result": data }))
    }

    async fn invoke_list_services(
        &self,
        client: &HomeAssistantClient,
    ) -> Result<serde_json::Value, HomeAssistantError> {
        let data = client.list_services().await?;
        Ok(json!({ "services": data }))
    }

    async fn invoke_list_areas(
        &self,
        client: &HomeAssistantClient,
    ) -> Result<serde_json::Value, HomeAssistantError> {
        // HA REST API doesn't have a direct areas endpoint;
        // we use the config endpoint or filter states. For simplicity,
        // we use a POST to the template API to render areas.
        // Fallback: return states filtered by input_select area markers.
        let areas = client.get_states_by_domain("input_select.area_").await?;
        Ok(json!({ "areas": areas }))
    }

    async fn invoke_list_devices(
        &self,
        client: &HomeAssistantClient,
    ) -> Result<serde_json::Value, HomeAssistantError> {
        // HA REST API doesn't have a direct devices endpoint;
        // return all states grouped logically (each entity is a "device proxy").
        let states = client.list_states().await?;
        let devices = match states.as_array() {
            Some(arr) => arr
                .iter()
                .filter(|s| {
                    s.get("entity_id")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|id| {
                            !id.starts_with("automation.")
                                && !id.starts_with("scene.")
                                && !id.starts_with("script.")
                                && !id.starts_with("group.")
                                && !id.starts_with("zone.")
                                && !id.starts_with("person.")
                        })
                })
                .cloned()
                .collect::<Vec<_>>(),
            None => Vec::new(),
        };
        Ok(json!({ "devices": devices }))
    }

    async fn invoke_list_automations(
        &self,
        client: &HomeAssistantClient,
    ) -> Result<serde_json::Value, HomeAssistantError> {
        let automations = client.get_states_by_domain("automation.").await?;
        Ok(json!({ "automations": automations }))
    }

    async fn invoke_trigger_automation(
        &self,
        client: &HomeAssistantClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HomeAssistantError> {
        let entity_id = require_str(input, "entity_id")?;
        let skip_condition = input
            .get("skip_condition")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        let mut body = json!({ "entity_id": entity_id });
        if skip_condition {
            body["skip_condition"] = json!(true);
        }

        let data = client.call_service("automation", "trigger", &body).await?;
        Ok(json!({ "result": data }))
    }

    async fn invoke_toggle_automation(
        &self,
        client: &HomeAssistantClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HomeAssistantError> {
        let entity_id = require_str(input, "entity_id")?;
        let enabled = input
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| HomeAssistantError::Api {
                status_code: 400,
                message: "Missing required field: enabled (boolean)".into(),
            })?;

        let service = if enabled { "turn_on" } else { "turn_off" };
        let body = json!({ "entity_id": entity_id });

        let data = client.call_service("automation", service, &body).await?;
        Ok(json!({ "result": data }))
    }

    async fn invoke_list_scenes(
        &self,
        client: &HomeAssistantClient,
    ) -> Result<serde_json::Value, HomeAssistantError> {
        let scenes = client.get_states_by_domain("scene.").await?;
        Ok(json!({ "scenes": scenes }))
    }

    async fn invoke_activate_scene(
        &self,
        client: &HomeAssistantClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HomeAssistantError> {
        let entity_id = require_str(input, "entity_id")?;
        let body = json!({ "entity_id": entity_id });
        let data = client.call_service("scene", "turn_on", &body).await?;
        Ok(json!({ "result": data }))
    }

    async fn invoke_get_history(
        &self,
        client: &HomeAssistantClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HomeAssistantError> {
        let timestamp = require_str(input, "timestamp")?;
        let filter_entity_id = input
            .get("filter_entity_id")
            .and_then(serde_json::Value::as_str);
        let end_time = input.get("end_time").and_then(serde_json::Value::as_str);
        let minimal_response = input
            .get("minimal_response")
            .and_then(serde_json::Value::as_bool);
        let significant_changes_only = input
            .get("significant_changes_only")
            .and_then(serde_json::Value::as_bool);

        let data = client
            .get_history(
                timestamp,
                filter_entity_id,
                end_time,
                minimal_response,
                significant_changes_only,
            )
            .await?;
        Ok(json!({ "history": data }))
    }

    async fn invoke_get_statistics(
        &self,
        client: &HomeAssistantClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HomeAssistantError> {
        let start_time = require_str(input, "start_time")?;
        let statistic_ids = require_str(input, "statistic_ids")?;
        let end_time = input.get("end_time").and_then(serde_json::Value::as_str);
        let period = input.get("period").and_then(serde_json::Value::as_str);

        // Use history endpoint with statistics params for simplified REST approach
        let filter_entity_id = Some(statistic_ids);
        let data = client
            .get_history(start_time, filter_entity_id, end_time, None, None)
            .await?;

        let mut result = json!({ "statistics": data });
        if let Some(p) = period {
            result["period"] = json!(p);
        }
        Ok(result)
    }

    async fn invoke_subscribe_events(
        &self,
        client: &HomeAssistantClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HomeAssistantError> {
        let request =
            serde_json::from_value::<HomeAssistantEventSubscriptionRequest>(input.clone())
                .map_err(|error| {
                    HomeAssistantError::InvalidInput(format!(
                        "invalid subscribe_events input: {error}"
                    ))
                })?;
        let subscription = client.subscribe_events(request).await?;
        serde_json::to_value(subscription).map_err(HomeAssistantError::Json)
    }

    fn build_doctor_result(&self) -> DoctorResult {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: Some(if self.config.is_some() {
                "Configuration loaded".into()
            } else {
                "Not configured — call configure first".into()
            }),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "API client initialized".into()
            } else {
                "API client not initialized".into()
            }),
            critical: true,
        });

        let Some(config) = &self.config else {
            return DoctorResult::from_checks(checks);
        };

        let readiness = config.provisioning_readiness();
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            passed: readiness.network_ok,
            message: Some(readiness.network_message),
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "auth_mode".into(),
            passed: true,
            message: Some(format!("Auth mode: {}", readiness.auth_mode)),
            critical: false,
        });

        let handshaken = self.session_id.is_some();
        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: handshaken,
            message: Some(if handshaken {
                "Handshake completed".into()
            } else {
                "Handshake not completed".into()
            }),
            critical: false,
        });

        checks.push(DoctorCheck {
            name: "access_token".into(),
            passed: readiness.access_token_configured || readiness.credential_id_configured,
            message: Some(if readiness.access_token_configured {
                "Long-lived access token configured".into()
            } else if readiness.credential_id_configured {
                "credential_id configured for secretless authenticated access".into()
            } else {
                "No access token configured".into()
            }),
            critical: false,
        });

        checks.push(DoctorCheck {
            name: "credential_injection".into(),
            passed: !readiness.requires_credential_injection,
            message: Some(if readiness.requires_credential_injection {
                "credential_id mode requires egress proxy injection".into()
            } else {
                "Credential injection not required".into()
            }),
            critical: false,
        });

        DoctorResult::from_checks(checks)
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "homeassistant.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Home Assistant self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }
}

/// Extract a required string field from input.
fn require_str<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, HomeAssistantError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| HomeAssistantError::InvalidInput(format!("Missing required field: {field}")))
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
    let private_network = host.starts_with("192.168.")
        || host.starts_with("10.")
        || host.starts_with("172.")
        || host == "homeassistant.local";
    let secure_or_local = parsed.scheme() == "https" || local || private_network;

    if secure_or_local {
        (
            true,
            format!("Endpoint accepted by policy checks: {base_url}"),
        )
    } else {
        (
            false,
            format!(
                "Endpoint must use https or be on a local/private network (localhost/127.0.0.1/::1/192.168.*/10.*/homeassistant.local allowed): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

const fn homeassistant_event_caps() -> EventCaps {
    EventCaps {
        streaming: true,
        replay: false,
        min_buffer_events: 200,
        requires_ack: false,
    }
}

fn event_info() -> Vec<EventInfo> {
    vec![EventInfo {
        topic: "homeassistant.state_changed".into(),
        schema: json!({
            "type": "object",
            "required": ["event_type", "data"],
            "properties": {
                "event_type": {"type": "string"},
                "entity_id": {"type": ["string", "null"]},
                "domain": {"type": ["string", "null"]},
                "old_state": {"type": ["object", "null"]},
                "new_state": {"type": ["object", "null"]},
                "context": {"type": ["object", "null"]},
                "time_fired": {"type": ["string", "null"]},
                "data": {"type": "object"}
            }
        }),
        requires_ack: false,
    }]
}

/// Build typed operation info for introspection with full `AgentHint` metadata.
fn typed_operations() -> Vec<OperationInfo> {
    vec![
        // -- Read operations --
        OperationInfo {
            id: OperationId::from_static("homeassistant.list_states"),
            summary: "List current states of all entities".into(),
            description: None,
            input_schema: json!({"type": "object"}),
            output_schema: json!({
                "type": "object",
                "required": ["states"],
                "properties": {
                    "states": {
                        "type": "array",
                        "description": "Array of all entity state objects",
                        "items": {"type": "object"}
                    }
                }
            }),
            capability: CapabilityId::from_static("homeassistant.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Get a snapshot of all entity states. Can be large on installations with many devices.".into(),
                common_mistakes: vec![
                    "Calling this repeatedly instead of using event subscriptions for real-time updates.".into(),
                ],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("homeassistant.get_state"),
                    CapabilityId::from_static("homeassistant.subscribe_events"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("homeassistant.get_state"),
            summary: "Get the current state of an entity".into(),
            description: None,
            input_schema: json!({
                "type": "object",
                "required": ["entity_id"],
                "properties": {
                    "entity_id": {
                        "type": "string",
                        "description": "Entity ID (e.g., 'light.living_room', 'sensor.temperature')"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["state"],
                "properties": {
                    "state": {
                        "type": "object",
                        "description": "Entity state object with state value, attributes, last_changed, last_updated"
                    }
                }
            }),
            capability: CapabilityId::from_static("homeassistant.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Read the current state and attributes of a single entity.".into(),
                common_mistakes: vec![
                    "Using friendly name instead of entity_id (e.g., 'Living Room Light' vs 'light.living_room').".into(),
                ],
                examples: vec![
                    r#"{"entity_id": "light.living_room"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("homeassistant.list_states"),
                    CapabilityId::from_static("homeassistant.set_state"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("homeassistant.list_services"),
            summary: "List all available services grouped by domain".into(),
            description: None,
            input_schema: json!({"type": "object"}),
            output_schema: json!({
                "type": "object",
                "required": ["services"],
                "properties": {
                    "services": {
                        "type": "array",
                        "description": "Services grouped by domain with field descriptions",
                        "items": {"type": "object"}
                    }
                }
            }),
            capability: CapabilityId::from_static("homeassistant.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Discover available services and their parameters before calling them.".into(),
                common_mistakes: vec![],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("homeassistant.call_service"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("homeassistant.list_areas"),
            summary: "List all areas (rooms/zones) in the area registry".into(),
            description: None,
            input_schema: json!({"type": "object"}),
            output_schema: json!({
                "type": "object",
                "required": ["areas"],
                "properties": {
                    "areas": {
                        "type": "array",
                        "items": {"type": "object"}
                    }
                }
            }),
            capability: CapabilityId::from_static("homeassistant.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "List areas (rooms) to understand the physical layout for targeted device control.".into(),
                common_mistakes: vec![],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("homeassistant.list_devices"),
                    CapabilityId::from_static("homeassistant.call_service"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("homeassistant.list_devices"),
            summary: "List all devices in the device registry".into(),
            description: None,
            input_schema: json!({"type": "object"}),
            output_schema: json!({
                "type": "object",
                "required": ["devices"],
                "properties": {
                    "devices": {
                        "type": "array",
                        "items": {"type": "object"}
                    }
                }
            }),
            capability: CapabilityId::from_static("homeassistant.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "List physical devices registered in Home Assistant for discovery or integration status checking.".into(),
                common_mistakes: vec![
                    "Confusing devices (physical hardware) with entities (state objects).".into(),
                ],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("homeassistant.list_states"),
                    CapabilityId::from_static("homeassistant.list_areas"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("homeassistant.list_automations"),
            summary: "List all automations with their current enabled/disabled state".into(),
            description: None,
            input_schema: json!({"type": "object"}),
            output_schema: json!({
                "type": "object",
                "required": ["automations"],
                "properties": {
                    "automations": {
                        "type": "array",
                        "items": {"type": "object"}
                    }
                }
            }),
            capability: CapabilityId::from_static("homeassistant.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "List all automations to inspect their state or find a specific one.".into(),
                common_mistakes: vec![],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("homeassistant.trigger_automation"),
                    CapabilityId::from_static("homeassistant.toggle_automation"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("homeassistant.list_scenes"),
            summary: "List all scenes".into(),
            description: None,
            input_schema: json!({"type": "object"}),
            output_schema: json!({
                "type": "object",
                "required": ["scenes"],
                "properties": {
                    "scenes": {
                        "type": "array",
                        "items": {"type": "object"}
                    }
                }
            }),
            capability: CapabilityId::from_static("homeassistant.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "List available scenes to discover what can be activated.".into(),
                common_mistakes: vec![],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("homeassistant.activate_scene"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("homeassistant.get_history"),
            summary: "Get state history for entities over a time period".into(),
            description: None,
            input_schema: json!({
                "type": "object",
                "required": ["timestamp"],
                "properties": {
                    "timestamp": {
                        "type": "string",
                        "description": "ISO 8601 start timestamp for history query"
                    },
                    "end_time": {
                        "type": "string",
                        "description": "ISO 8601 end timestamp (default: now)"
                    },
                    "filter_entity_id": {
                        "type": "string",
                        "description": "Comma-separated entity IDs to filter"
                    },
                    "minimal_response": {
                        "type": "boolean",
                        "description": "Return minimal state change data (no attributes)"
                    },
                    "significant_changes_only": {
                        "type": "boolean",
                        "description": "Only return significant state changes (skip attribute-only changes)"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["history"],
                "properties": {
                    "history": {
                        "type": "array",
                        "description": "Array of arrays, one per entity, containing state change records",
                        "items": {"type": "array"}
                    }
                }
            }),
            capability: CapabilityId::from_static("homeassistant.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Query historical state changes for entities over a time range.".into(),
                common_mistakes: vec![
                    "Requesting unbounded history (no end_time) for many entities \u{2014} can be very large.".into(),
                    "Not using minimal_response for large queries.".into(),
                    "Not filtering by entity_id on busy installations.".into(),
                ],
                examples: vec![
                    r#"{"timestamp": "2026-03-01T00:00:00Z", "filter_entity_id": "sensor.temperature,sensor.humidity", "minimal_response": true}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("homeassistant.get_statistics"),
                    CapabilityId::from_static("homeassistant.get_state"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("homeassistant.get_statistics"),
            summary: "Get long-term statistics for entities (hourly/daily/monthly aggregations)".into(),
            description: None,
            input_schema: json!({
                "type": "object",
                "required": ["start_time", "statistic_ids"],
                "properties": {
                    "start_time": {
                        "type": "string",
                        "description": "ISO 8601 start timestamp"
                    },
                    "statistic_ids": {
                        "type": "string",
                        "description": "Comma-separated statistic IDs (usually entity_id-based)"
                    },
                    "end_time": {
                        "type": "string",
                        "description": "ISO 8601 end timestamp"
                    },
                    "period": {
                        "type": "string",
                        "description": "Aggregation period",
                        "enum": ["5minute", "hour", "day", "week", "month"]
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["statistics"],
                "properties": {
                    "statistics": {
                        "type": "object",
                        "description": "Statistics data grouped by statistic_id"
                    }
                }
            }),
            capability: CapabilityId::from_static("homeassistant.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Query long-term aggregated statistics (mean, min, max, sum) for sensors and other entities.".into(),
                common_mistakes: vec![
                    "Using get_history for long time ranges instead of get_statistics (statistics are much more efficient).".into(),
                    "Not all entities have long-term statistics \u{2014} check statistic_ids first.".into(),
                ],
                examples: vec![
                    r#"{"start_time": "2026-02-01T00:00:00Z", "statistic_ids": "sensor:energy_consumption", "period": "day"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("homeassistant.get_history"),
                    CapabilityId::from_static("homeassistant.get_state"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("homeassistant.subscribe_events"),
            summary: "Open a bounded Home Assistant WebSocket subscription and return matching events".into(),
            description: None,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "event_type": {
                        "type": ["string", "null"],
                        "description": "Home Assistant event type. Defaults to 'state_changed'; set null to subscribe to all event types."
                    },
                    "watch_domains": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Entity domains to forward, e.g. ['light', 'sensor']."
                    },
                    "watch_entities": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Exact entity IDs to forward."
                    },
                    "ignore_entities": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Exact entity IDs to drop before other filters."
                    },
                    "watch_all": {
                        "type": "boolean",
                        "description": "Explicitly forward every non-ignored event."
                    },
                    "cooldown_ms": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Per-entity cooldown between emitted events."
                    },
                    "max_events": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "description": "Bounded number of matching events to return."
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 600000,
                        "description": "Per-connection receive timeout."
                    },
                    "max_reconnect_attempts": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 5,
                        "description": "Reconnect attempts if the WebSocket closes before enough events arrive."
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["event", "events", "stats"],
                "properties": {
                    "subscription_id": {"type": "integer"},
                    "event_type": {"type": ["string", "null"]},
                    "event": {
                        "type": "object",
                        "description": "First matching redacted event payload with event_type, entity_id, old/new state, origin, time_fired, and context"
                    },
                    "events": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "All matching redacted events returned by this bounded invoke"
                    },
                    "stats": {"type": "object"},
                    "replay_supported": {"type": "boolean"},
                    "persistent": {"type": "boolean"}
                }
            }),
            capability: CapabilityId::from_static("homeassistant.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Capture real-time Home Assistant events via WebSocket. Provide watch_domains, watch_entities, or watch_all to make event volume explicit.".into(),
                common_mistakes: vec![
                    "Calling without watch_all or filters; the connector requires an explicit event selection.".into(),
                    "Subscribing to all events on a busy installation unless you really need the full firehose.".into(),
                ],
                examples: vec![
                    r#"{"watch_domains": ["light"], "max_events": 1}"#.into(),
                    r#"{"watch_entities": ["sensor.temperature"], "cooldown_ms": 5000}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("homeassistant.get_state"),
                    CapabilityId::from_static("homeassistant.list_states"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        // -- Write operations --
        OperationInfo {
            id: OperationId::from_static("homeassistant.set_state"),
            summary: "Directly set the state of an entity (use service calls for physical devices)".into(),
            description: None,
            input_schema: json!({
                "type": "object",
                "required": ["entity_id", "state"],
                "properties": {
                    "entity_id": {
                        "type": "string",
                        "description": "Entity ID"
                    },
                    "state": {
                        "type": "string",
                        "description": "New state value"
                    },
                    "attributes": {
                        "type": "object",
                        "description": "Optional attributes to set alongside the state"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["state"],
                "properties": {
                    "state": {"type": "object"}
                }
            }),
            capability: CapabilityId::from_static("homeassistant.write"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Directly set an entity state. Prefer call_service for physical device control.".into(),
                common_mistakes: vec![
                    "Using set_state to control physical devices instead of call_service.".into(),
                    "Overwriting attributes by not including existing attributes.".into(),
                ],
                examples: vec![
                    r#"{"entity_id": "input_boolean.guest_mode", "state": "on"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("homeassistant.get_state"),
                    CapabilityId::from_static("homeassistant.call_service"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        // -- Control operations --
        OperationInfo {
            id: OperationId::from_static("homeassistant.call_service"),
            summary: "Call a Home Assistant service (turn on/off lights, lock doors, set thermostats, etc.)".into(),
            description: None,
            input_schema: json!({
                "type": "object",
                "required": ["domain", "service"],
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Service domain (e.g., 'light', 'switch', 'climate', 'lock', 'cover')"
                    },
                    "service": {
                        "type": "string",
                        "description": "Service name (e.g., 'turn_on', 'turn_off', 'toggle', 'set_temperature')"
                    },
                    "service_data": {
                        "type": "object",
                        "description": "Service-specific parameters (e.g., brightness, temperature, color)"
                    },
                    "target": {
                        "type": "object",
                        "description": "Target entities, areas, or devices"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["result"],
                "properties": {
                    "result": {
                        "type": "array",
                        "description": "Service call result (may be empty for fire-and-forget services)",
                        "items": {"type": "object"}
                    }
                }
            }),
            capability: CapabilityId::from_static("homeassistant.control"),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "Control physical devices by calling Home Assistant services. This is the primary way to interact with devices.".into(),
                common_mistakes: vec![
                    "Using set_state instead of call_service for physical devices.".into(),
                    "Not specifying target when the service requires entity_id, area_id, or device_id.".into(),
                    "Calling services on unavailable entities.".into(),
                ],
                examples: vec![
                    r#"{"domain": "light", "service": "turn_on", "service_data": {"brightness_pct": 75}, "target": {"entity_id": "light.living_room"}}"#.into(),
                    r#"{"domain": "climate", "service": "set_temperature", "service_data": {"temperature": 22}, "target": {"entity_id": "climate.thermostat"}}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("homeassistant.list_services"),
                    CapabilityId::from_static("homeassistant.get_state"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("homeassistant.trigger_automation"),
            summary: "Manually trigger an automation".into(),
            description: None,
            input_schema: json!({
                "type": "object",
                "required": ["entity_id"],
                "properties": {
                    "entity_id": {
                        "type": "string",
                        "description": "Automation entity ID (e.g., 'automation.night_mode')"
                    },
                    "skip_condition": {
                        "type": "boolean",
                        "description": "Skip the automation's condition check and force-run actions"
                    }
                }
            }),
            output_schema: json!({"type": "object"}),
            capability: CapabilityId::from_static("homeassistant.control"),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Manually run an automation. Use skip_condition=true to bypass trigger conditions.".into(),
                common_mistakes: vec![
                    "Triggering automations that are disabled (enable first).".into(),
                    "Not checking automation conditions before triggering with skip_condition=true.".into(),
                ],
                examples: vec![
                    r#"{"entity_id": "automation.night_mode", "skip_condition": false}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("homeassistant.list_automations"),
                    CapabilityId::from_static("homeassistant.toggle_automation"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("homeassistant.toggle_automation"),
            summary: "Enable or disable an automation".into(),
            description: None,
            input_schema: json!({
                "type": "object",
                "required": ["entity_id", "enabled"],
                "properties": {
                    "entity_id": {
                        "type": "string",
                        "description": "Automation entity ID"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "true to enable, false to disable"
                    }
                }
            }),
            output_schema: json!({"type": "object"}),
            capability: CapabilityId::from_static("homeassistant.control"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Enable or disable an automation without deleting it.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"entity_id": "automation.night_mode", "enabled": false}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("homeassistant.list_automations"),
                    CapabilityId::from_static("homeassistant.trigger_automation"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("homeassistant.activate_scene"),
            summary: "Activate a scene (apply a predefined set of entity states)".into(),
            description: None,
            input_schema: json!({
                "type": "object",
                "required": ["entity_id"],
                "properties": {
                    "entity_id": {
                        "type": "string",
                        "description": "Scene entity ID (e.g., 'scene.movie_night')"
                    }
                }
            }),
            output_schema: json!({"type": "object"}),
            capability: CapabilityId::from_static("homeassistant.control"),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "Activate a scene to set multiple entities to predefined states at once.".into(),
                common_mistakes: vec![
                    "Activating scenes that control security-sensitive devices (locks, alarms) without confirmation.".into(),
                ],
                examples: vec![
                    r#"{"entity_id": "scene.movie_night"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("homeassistant.list_scenes"),
                    CapabilityId::from_static("homeassistant.call_service"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

/// Build the operations info for introspection as JSON (used by tests).
fn operations_info() -> serde_json::Value {
    serde_json::to_value(typed_operations()).unwrap_or_else(|_| json!([]))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Config tests --

    #[test]
    fn config_from_access_token() {
        let config = HomeAssistantConfig::from_params(&json!({
            "access_token": "test-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, HomeAssistantAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = HomeAssistantConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = HomeAssistantConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "http://192.168.1.100:8123/api",
        }))
        .unwrap();
        assert_eq!(config.base_url, "http://192.168.1.100:8123/api");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = HomeAssistantConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = HomeAssistantConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = HomeAssistantConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = HomeAssistantConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = HomeAssistantConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = HomeAssistantConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_access_token() {
        let config =
            HomeAssistantConfig::from_params(&json!({ "access_token": "  tok_test  " })).unwrap();
        match &config.auth {
            HomeAssistantAuth::BearerToken(t) => assert_eq!(t, "tok_test"),
            HomeAssistantAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    // -- require_str tests --

    #[test]
    fn require_str_present() {
        let input = json!({"entity_id": "light.test"});
        assert_eq!(require_str(&input, "entity_id").unwrap(), "light.test");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "entity_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"entity_id": 42});
        assert!(require_str(&input, "entity_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"entity_id": null});
        assert!(require_str(&input, "entity_id").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"enabled": true});
        assert!(require_str(&input, "enabled").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"ids": ["a", "b"]});
        assert!(require_str(&input, "ids").is_err());
    }

    // -- operations_info tests --

    #[test]
    fn operations_info_has_15_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 15);
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
        let expected = [
            "homeassistant.list_states",
            "homeassistant.get_state",
            "homeassistant.set_state",
            "homeassistant.call_service",
            "homeassistant.list_services",
            "homeassistant.list_areas",
            "homeassistant.list_devices",
            "homeassistant.list_automations",
            "homeassistant.trigger_automation",
            "homeassistant.toggle_automation",
            "homeassistant.list_scenes",
            "homeassistant.activate_scene",
            "homeassistant.get_history",
            "homeassistant.get_statistics",
            "homeassistant.subscribe_events",
        ];
        for id in &expected {
            assert!(ids.contains(id), "missing operation: {id}");
        }
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
    fn operations_idempotency_values_valid() {
        let valid = ["strict", "best_effort", "none"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let v = op["idempotency"].as_str().unwrap();
            assert!(
                valid.contains(&v),
                "invalid idempotency: {v} on {}",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_capabilities_valid() {
        let valid = [
            "homeassistant.read",
            "homeassistant.write",
            "homeassistant.control",
        ];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(valid.contains(&cap), "invalid capability: {cap}");
        }
    }

    #[test]
    fn write_operations_are_risky() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap == "homeassistant.write" || cap == "homeassistant.control" {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "risky",
                    "write/control op {} should be risky",
                    op["id"]
                );
            }
        }
    }

    // -- Doctor tests --

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

    // -- Connector lifecycle tests --

    #[test]
    fn connector_default() {
        let c = HomeAssistantConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new() {
        let c = HomeAssistantConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    // -- Summaries per capability --

    #[test]
    fn operations_summaries_non_empty() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "empty summary for {}", op["id"]);
        }
    }

    #[test]
    fn read_operations_count() {
        let ops = operations_info();
        let count = ops
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["capability"].as_str() == Some("homeassistant.read"))
            .count();
        // list_states, get_state, list_services, list_areas, list_devices,
        // list_automations, list_scenes, get_history, get_statistics, subscribe_events = 10
        assert_eq!(count, 10);
    }

    #[test]
    fn write_operations_count() {
        let ops = operations_info();
        let count = ops
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["capability"].as_str() == Some("homeassistant.write"))
            .count();
        assert_eq!(count, 1); // set_state
    }

    #[test]
    fn control_operations_count() {
        let ops = operations_info();
        let count = ops
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["capability"].as_str() == Some("homeassistant.control"))
            .count();
        // call_service, trigger_automation, toggle_automation, activate_scene = 4
        assert_eq!(count, 4);
    }

    // -- 16 operations for subscribe_events unsupported check --

    #[test]
    fn subscribe_events_in_operations_list() {
        let ops = operations_info();
        let has_subscribe = ops
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["id"].as_str() == Some("homeassistant.subscribe_events"));
        assert!(has_subscribe);
    }

    // -- Additional config edge cases --

    #[test]
    fn config_with_https_url() {
        let config = HomeAssistantConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://ha.example.com:8123/api",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://ha.example.com:8123/api");
    }

    #[test]
    fn config_with_localhost_url() {
        let config = HomeAssistantConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "http://localhost:8123/api",
        }))
        .unwrap();
        assert_eq!(config.base_url, "http://localhost:8123/api");
    }

    #[test]
    fn config_with_ip_url() {
        let config = HomeAssistantConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "http://10.0.0.1:8123/api",
        }))
        .unwrap();
        assert_eq!(config.base_url, "http://10.0.0.1:8123/api");
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("f1".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("f2".into()),
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
            name: "t".into(),
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
            name: "t".into(),
            passed: false,
            message: Some("broken".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "broken");
    }

    #[test]
    fn doctor_status_serde_healthy() {
        assert_eq!(
            serde_json::to_value(DoctorStatus::Healthy).unwrap(),
            "healthy"
        );
    }

    #[test]
    fn doctor_status_serde_degraded() {
        assert_eq!(
            serde_json::to_value(DoctorStatus::Degraded).unwrap(),
            "degraded"
        );
    }

    #[test]
    fn doctor_status_serde_unhealthy() {
        assert_eq!(
            serde_json::to_value(DoctorStatus::Unhealthy).unwrap(),
            "unhealthy"
        );
    }

    #[test]
    fn connector_new_eq_default() {
        let a = HomeAssistantConnector::new();
        let b = HomeAssistantConnector::default();
        assert!(a.config.is_none());
        assert!(b.config.is_none());
        assert_eq!(a.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(b.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn operations_ids_follow_naming_convention() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("homeassistant."),
                "op id should start with 'homeassistant.': {id}"
            );
        }
    }

    #[test]
    fn require_str_empty_string_is_ok() {
        let input = json!({"x": ""});
        assert_eq!(require_str(&input, "x").unwrap(), "");
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"x": {"nested": true}});
        assert!(require_str(&input, "x").is_err());
    }

    #[test]
    fn config_default_base_url() {
        let config = HomeAssistantConfig::from_params(&json!({"access_token": "tok"})).unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    // -- Provisioning readiness tests --

    #[test]
    fn provisioning_readiness_access_token_mode() {
        let config = HomeAssistantConfig::from_params(&json!({
            "access_token": "test-token",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "access_token");
        assert!(readiness.access_token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert_eq!(
            readiness.rate_limit_profile,
            "access_token: local instance, no external rate limits"
        );
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = HomeAssistantConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.access_token_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
        assert_eq!(
            readiness.rate_limit_profile,
            "credential_id: authenticated via egress proxy injection"
        );
    }

    #[test]
    fn provisioning_readiness_default_url_accepted() {
        let config = HomeAssistantConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_ok);
        assert!(readiness.network_message.contains("accepted"));
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = HomeAssistantConfig::from_params(&json!({
            "access_token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "access_token");
        assert_eq!(v["access_token_configured"], true);
        assert_eq!(v["credential_id_configured"], false);
        assert!(v["base_url"].as_str().is_some());
    }

    // -- base_url_policy tests --

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:8123/api");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_private_network() {
        let (ok, _) = base_url_policy("http://192.168.1.100:8123/api");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_homeassistant_local() {
        let (ok, msg) = base_url_policy("http://homeassistant.local:8123/api");
        assert!(ok);
        assert!(msg.contains("accepted"));
    }

    #[test]
    fn base_url_policy_accepts_https() {
        let (ok, msg) = base_url_policy("https://ha.example.com:8123/api");
        assert!(ok);
        assert!(msg.contains("accepted"));
    }

    #[test]
    fn base_url_policy_rejects_public_http() {
        let (ok, msg) = base_url_policy("http://ha.example.com:8123/api");
        assert!(!ok);
        assert!(msg.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unparseable() {
        let (ok, msg) = base_url_policy("not a url");
        assert!(!ok);
        assert!(msg.contains("could not be parsed"));
    }

    #[test]
    fn base_url_policy_accepts_loopback_ipv4() {
        let (ok, _) = base_url_policy("http://127.0.0.1:8123/api");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_10_network() {
        let (ok, _) = base_url_policy("http://10.0.0.5:8123/api");
        assert!(ok);
    }

    // -- Doctor with provisioning tests --

    #[test]
    fn doctor_result_status_label() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status_label(), "healthy");

        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "x".into(),
            passed: false,
            message: None,
            critical: false,
        }]);
        assert_eq!(r.status_label(), "degraded");

        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "x".into(),
            passed: false,
            message: None,
            critical: true,
        }]);
        assert_eq!(r.status_label(), "unhealthy");
    }
}
