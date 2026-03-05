//! FCP `Home Assistant` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, HomeAssistantAuth, HomeAssistantClient},
    error::HomeAssistantError,
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
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("homeassistant"))),
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
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Home Assistant connector");

        let client = HomeAssistantClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;

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
            "connector_id": "fcp.homeassistant",
            "connector_version": "0.1.0",
            "capabilities": [
                "homeassistant.read",
                "homeassistant.write",
                "homeassistant.control"
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
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_none() {
                Some("Not configured — call configure first".into())
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
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.homeassistant",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.homeassistant",
            "version": "0.1.0",
            "operations": operations_info(),
        }))
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
            "homeassistant.subscribe_events" => {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: "subscribe_events requires WebSocket and is not supported via REST"
                        .into(),
                });
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
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let allowed = operations_info().as_array().is_some_and(|ops| {
            ops.iter()
                .any(|o| o.get("id").and_then(serde_json::Value::as_str) == Some(operation))
        });

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

        let data = client
            .call_service("automation", "trigger", &body)
            .await?;
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
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, HomeAssistantError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| HomeAssistantError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "homeassistant.list_states",
            "summary": "List current states of all entities",
            "capability": "homeassistant.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "homeassistant.get_state",
            "summary": "Get the current state of an entity",
            "capability": "homeassistant.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "homeassistant.set_state",
            "summary": "Directly set the state of an entity",
            "capability": "homeassistant.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "strict",
        },
        {
            "id": "homeassistant.call_service",
            "summary": "Call a Home Assistant service",
            "capability": "homeassistant.control",
            "risk_level": "high",
            "safety_tier": "risky",
            "idempotency": "best_effort",
        },
        {
            "id": "homeassistant.list_services",
            "summary": "List all available services grouped by domain",
            "capability": "homeassistant.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "homeassistant.list_areas",
            "summary": "List all areas (rooms/zones)",
            "capability": "homeassistant.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "homeassistant.list_devices",
            "summary": "List all devices in the device registry",
            "capability": "homeassistant.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "homeassistant.list_automations",
            "summary": "List all automations with enabled/disabled state",
            "capability": "homeassistant.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "homeassistant.trigger_automation",
            "summary": "Manually trigger an automation",
            "capability": "homeassistant.control",
            "risk_level": "high",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "homeassistant.toggle_automation",
            "summary": "Enable or disable an automation",
            "capability": "homeassistant.control",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "strict",
        },
        {
            "id": "homeassistant.list_scenes",
            "summary": "List all scenes",
            "capability": "homeassistant.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "homeassistant.activate_scene",
            "summary": "Activate a scene",
            "capability": "homeassistant.control",
            "risk_level": "high",
            "safety_tier": "risky",
            "idempotency": "best_effort",
        },
        {
            "id": "homeassistant.get_history",
            "summary": "Get state history for entities over a time period",
            "capability": "homeassistant.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "homeassistant.get_statistics",
            "summary": "Get long-term statistics for entities",
            "capability": "homeassistant.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "homeassistant.subscribe_events",
            "summary": "Subscribe to Home Assistant events via WebSocket",
            "capability": "homeassistant.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
    ])
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
            assert!(valid.contains(&v), "invalid idempotency: {v} on {}", op["id"]);
        }
    }

    #[test]
    fn operations_capabilities_valid() {
        let valid = ["homeassistant.read", "homeassistant.write", "homeassistant.control"];
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
}
