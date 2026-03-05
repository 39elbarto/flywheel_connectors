//! FCP `HubSpot` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, HubSpotAuth, HubSpotClient},
    error::HubSpotError,
};

/// Parsed and validated `HubSpot` connector configuration.
#[derive(Debug, Clone)]
struct HubSpotConfig {
    auth: HubSpotAuth,
    base_url: String,
}

impl HubSpotConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let access_token = params
            .get("access_token")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let credential_id = match params.get("credential_id") {
            Some(value) => {
                let raw = value.as_str().ok_or(FcpError::InvalidRequest {
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
            (Some(token), None) => HubSpotAuth::BearerToken(token),
            (None, Some(cred_id)) => HubSpotAuth::CredentialId(cred_id),
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
            .and_then(|v| v.as_str())
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

/// FCP `HubSpot` Connector.
pub struct HubSpotConnector {
    base: Arc<BaseConnector>,
    config: Option<HubSpotConfig>,
    client: Option<Arc<HubSpotClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl HubSpotConnector {
    /// Create a new `HubSpot` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("hubspot"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for HubSpotConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl HubSpotConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = HubSpotConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring HubSpot connector");

        let client = HubSpotClient::new(config.auth.clone(), Some(&config.base_url))
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
            .and_then(|v| v.as_str())
            .map(str::to_string);

        self.session_id = session_id;
        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.hubspot",
            "connector_version": "0.1.0",
            "capabilities": [
                "hubspot.contacts.read",
                "hubspot.contacts.write",
                "hubspot.companies.read",
                "hubspot.deals.read",
                "hubspot.deals.write",
                "hubspot.pipelines.read",
                "hubspot.analytics.read",
                "hubspot.events.read"
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
        Ok(serde_json::to_value(result).unwrap_or(json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.hubspot",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.hubspot",
            "version": "0.1.0",
            "operations": operations_info(),
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;

        let operation = params.get("operation_id").and_then(|v| v.as_str()).ok_or(
            FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            },
        )?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "hubspot.contacts.list" => self.invoke_contacts_list(client, &input).await,
            "hubspot.contacts.get" => self.invoke_contacts_get(client, &input).await,
            "hubspot.contacts.create" => self.invoke_contacts_create(client, &input).await,
            "hubspot.contacts.update" => self.invoke_contacts_update(client, &input).await,
            "hubspot.contacts.delete" => self.invoke_contacts_delete(client, &input).await,
            "hubspot.companies.list" => self.invoke_companies_list(client, &input).await,
            "hubspot.deals.list" => self.invoke_deals_list(client, &input).await,
            "hubspot.deals.create" => self.invoke_deals_create(client, &input).await,
            "hubspot.pipelines.list" => self.invoke_pipelines_list(client, &input).await,
            "hubspot.analytics.report" => self.invoke_analytics_report(client, &input).await,
            "hubspot.events.stream" => self.invoke_events_stream(client, &input).await,
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
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let allowed = operations_info().as_array().is_some_and(|ops| {
            ops.iter()
                .any(|o| o.get("id").and_then(|v| v.as_str()) == Some(operation))
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
        info!("HubSpot connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // ── Operation implementations ─────────────────────────────────────

    async fn invoke_contacts_list(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let limit = input.get("limit").and_then(|v| v.as_i64());
        let after = input.get("after").and_then(|v| v.as_str());
        let properties = extract_string_array(input, "properties");
        let props_ref: Option<Vec<String>> = properties;
        client
            .list_contacts(limit, after, props_ref.as_deref())
            .await
    }

    async fn invoke_contacts_get(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let contact_id = require_str(input, "contact_id")?;
        let properties = extract_string_array(input, "properties");
        let data = client
            .get_contact(contact_id, properties.as_deref())
            .await?;
        Ok(json!({ "contact": data }))
    }

    async fn invoke_contacts_create(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let properties = input.get("properties").ok_or(HubSpotError::Api {
            status_code: 400,
            message: "Missing required field: properties".into(),
        })?;
        let body = json!({ "properties": properties });
        let data = client.create_contact(&body).await?;
        Ok(json!({ "contact": data }))
    }

    async fn invoke_contacts_update(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let contact_id = require_str(input, "contact_id")?;
        let properties = input.get("properties").ok_or(HubSpotError::Api {
            status_code: 400,
            message: "Missing required field: properties".into(),
        })?;
        let body = json!({ "properties": properties });
        let data = client.update_contact(contact_id, &body).await?;
        Ok(json!({ "contact": data }))
    }

    async fn invoke_contacts_delete(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let contact_id = require_str(input, "contact_id")?;
        client.delete_contact(contact_id).await?;
        Ok(json!({ "deleted": true }))
    }

    async fn invoke_companies_list(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let limit = input.get("limit").and_then(|v| v.as_i64());
        let after = input.get("after").and_then(|v| v.as_str());
        let properties = extract_string_array(input, "properties");
        client
            .list_companies(limit, after, properties.as_deref())
            .await
    }

    async fn invoke_deals_list(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let limit = input.get("limit").and_then(|v| v.as_i64());
        let after = input.get("after").and_then(|v| v.as_str());
        let properties = extract_string_array(input, "properties");
        client
            .list_deals(limit, after, properties.as_deref())
            .await
    }

    async fn invoke_deals_create(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let properties = input.get("properties").ok_or(HubSpotError::Api {
            status_code: 400,
            message: "Missing required field: properties".into(),
        })?;
        let associations = input.get("associations");
        let mut body = json!({ "properties": properties });
        if let Some(assoc) = associations {
            body["associations"] = assoc.clone();
        }
        let data = client.create_deal(&body).await?;
        Ok(json!({ "deal": data }))
    }

    async fn invoke_pipelines_list(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let object_type = require_str(input, "object_type")?;
        client.list_pipelines(object_type).await
    }

    async fn invoke_analytics_report(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let report_type = require_str(input, "report_type")?;
        let mut body = json!({ "reportType": report_type });
        if let Some(pipeline_id) = input.get("pipeline_id") {
            body["pipelineId"] = pipeline_id.clone();
        }
        if let Some(date_range) = input.get("date_range") {
            body["dateRange"] = date_range.clone();
        }
        let data = client.analytics_report(&body).await?;
        Ok(json!({ "report": data }))
    }

    async fn invoke_events_stream(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let object_types = input.get("object_types").and_then(|v| v.as_array());
        let since_ts = input.get("since_ts").and_then(|v| v.as_str());
        let after_ms = since_ts
            .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
            .map(|dt| dt.timestamp_millis());
        let object_type = object_types
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str());
        let data = client.list_events(object_type, after_ms).await?;
        Ok(json!({ "events": data }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, HubSpotError> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| HubSpotError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Extract an optional array of strings from input.
fn extract_string_array(input: &serde_json::Value, field: &str) -> Option<Vec<String>> {
    input.get(field).and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect()
    })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "hubspot.contacts.list",
            "summary": "List contacts with optional filtering and property selection",
            "capability": "hubspot.contacts.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "hubspot.contacts.get",
            "summary": "Get a single contact by ID",
            "capability": "hubspot.contacts.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "hubspot.contacts.create",
            "summary": "Create a new contact",
            "capability": "hubspot.contacts.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "hubspot.contacts.update",
            "summary": "Update an existing contact's properties",
            "capability": "hubspot.contacts.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "strict",
        },
        {
            "id": "hubspot.contacts.delete",
            "summary": "Delete a contact from HubSpot",
            "capability": "hubspot.contacts.write",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "strict",
        },
        {
            "id": "hubspot.companies.list",
            "summary": "List companies",
            "capability": "hubspot.companies.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "hubspot.deals.list",
            "summary": "List deals with optional pipeline and stage filtering",
            "capability": "hubspot.deals.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "hubspot.deals.create",
            "summary": "Create a new deal",
            "capability": "hubspot.deals.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "hubspot.pipelines.list",
            "summary": "List pipelines and their stages",
            "capability": "hubspot.pipelines.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "hubspot.analytics.report",
            "summary": "Get pipeline analytics and reporting data",
            "capability": "hubspot.analytics.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "hubspot.events.stream",
            "summary": "Stream CRM webhook events",
            "capability": "hubspot.events.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_access_token() {
        let config = HubSpotConfig::from_params(&json!({
            "access_token": "pat-na1-test",
        }))
        .unwrap();
        assert!(matches!(config.auth, HubSpotAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = HubSpotConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = HubSpotConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://custom.hubspot.test",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://custom.hubspot.test");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = HubSpotConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = HubSpotConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_token() {
        let result = HubSpotConfig::from_params(&json!({ "access_token": "" }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_token() {
        let result = HubSpotConfig::from_params(&json!({ "access_token": "   " }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_extracts() {
        let input = json!({"contact_id": "123"});
        assert_eq!(require_str(&input, "contact_id").unwrap(), "123");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "contact_id").is_err());
    }

    #[test]
    fn extract_string_array_works() {
        let input = json!({"properties": ["email", "firstname"]});
        let arr = extract_string_array(&input, "properties").unwrap();
        assert_eq!(arr, vec!["email", "firstname"]);
    }

    #[test]
    fn extract_string_array_missing() {
        let input = json!({});
        assert!(extract_string_array(&input, "properties").is_none());
    }

    #[test]
    fn operations_info_has_11_operations() {
        let ops = operations_info();
        assert_eq!(ops.as_array().unwrap().len(), 11);
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
        assert_eq!(ids.len(), unique.len());
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
            }
        }
    }

    #[test]
    fn doctor_result_healthy() {
        let checks = vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: true,
        }];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_unhealthy() {
        let checks = vec![DoctorCheck {
            name: "a".into(),
            passed: false,
            message: Some("bad".into()),
            critical: true,
        }];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn connector_default() {
        let c = HubSpotConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }
}
