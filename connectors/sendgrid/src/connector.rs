//! FCP `SendGrid` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, SendGridAuth, SendGridClient},
    error::SendGridError,
};

/// Parsed and validated `SendGrid` connector configuration.
#[derive(Debug, Clone)]
struct SendGridConfig {
    auth: SendGridAuth,
    base_url: String,
}

impl SendGridConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
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
            (Some(key), None) => SendGridAuth::ApiKey(key),
            (None, Some(cred_id)) => SendGridAuth::CredentialId(cred_id),
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

/// FCP `SendGrid` Connector.
pub struct SendGridConnector {
    base: Arc<BaseConnector>,
    config: Option<SendGridConfig>,
    client: Option<Arc<SendGridClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl SendGridConnector {
    /// Create a new `SendGrid` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("sendgrid"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for SendGridConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl SendGridConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = SendGridConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring SendGrid connector");

        let client = SendGridClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.sendgrid",
            "connector_version": "0.1.0",
            "capabilities": [
                "sendgrid.mail.write",
                "sendgrid.contacts.read",
                "sendgrid.lists.read",
                "sendgrid.lists.write",
                "sendgrid.templates.read",
                "sendgrid.stats.read"
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
            "connector_id": "fcp.sendgrid",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.sendgrid",
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
            "sendgrid.mail.send" => self.invoke_mail_send(client, &input).await,
            "sendgrid.contacts.list" => self.invoke_contacts_list(client).await,
            "sendgrid.contacts.search" => self.invoke_contacts_search(client, &input).await,
            "sendgrid.contacts.get" => self.invoke_contacts_get(client, &input).await,
            "sendgrid.lists.list" => self.invoke_lists_list(client).await,
            "sendgrid.lists.create" => self.invoke_lists_create(client, &input).await,
            "sendgrid.lists.delete" => self.invoke_lists_delete(client, &input).await,
            "sendgrid.templates.list" => self.invoke_templates_list(client).await,
            "sendgrid.templates.get" => self.invoke_templates_get(client, &input).await,
            "sendgrid.stats.get" => self.invoke_stats_get(client, &input).await,
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
        info!("SendGrid connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_mail_send(
        &self,
        client: &SendGridClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SendGridError> {
        // Validate required top-level fields
        if input.get("personalizations").is_none() && input.get("to").is_none() {
            return Err(SendGridError::Api {
                status_code: 400,
                message: "Missing required field: personalizations or to".into(),
            });
        }
        client.send_mail(input).await
    }

    async fn invoke_contacts_list(
        &self,
        client: &SendGridClient,
    ) -> Result<serde_json::Value, SendGridError> {
        let resp = client.list_contacts().await?;
        let contacts = resp.get("result").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "contacts": contacts }))
    }

    async fn invoke_contacts_search(
        &self,
        client: &SendGridClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SendGridError> {
        let query = require_str(input, "query")?;
        let body = json!({ "query": query });
        let resp = client.search_contacts(&body).await?;
        let contacts = resp.get("result").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "contacts": contacts }))
    }

    async fn invoke_contacts_get(
        &self,
        client: &SendGridClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SendGridError> {
        let contact_id = require_str(input, "contact_id")?;
        client.get_contact(contact_id).await
    }

    async fn invoke_lists_list(
        &self,
        client: &SendGridClient,
    ) -> Result<serde_json::Value, SendGridError> {
        let resp = client.list_lists().await?;
        let lists = resp.get("result").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "lists": lists }))
    }

    async fn invoke_lists_create(
        &self,
        client: &SendGridClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SendGridError> {
        let name = require_str(input, "name")?;
        let body = json!({ "name": name });
        client.create_list(&body).await
    }

    async fn invoke_lists_delete(
        &self,
        client: &SendGridClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SendGridError> {
        let list_id = require_str(input, "list_id")?;
        client.delete_list(list_id).await
    }

    async fn invoke_templates_list(
        &self,
        client: &SendGridClient,
    ) -> Result<serde_json::Value, SendGridError> {
        let resp = client.list_templates().await?;
        let templates = resp.get("templates").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "templates": templates }))
    }

    async fn invoke_templates_get(
        &self,
        client: &SendGridClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SendGridError> {
        let template_id = require_str(input, "template_id")?;
        client.get_template(template_id).await
    }

    async fn invoke_stats_get(
        &self,
        client: &SendGridClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SendGridError> {
        let start_date = require_str(input, "start_date")?;
        let end_date = input
            .get("end_date")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let query = if end_date.is_empty() {
            format!("start_date={start_date}")
        } else {
            format!("start_date={start_date}&end_date={end_date}")
        };
        let resp = client.get_stats(&query).await?;
        Ok(json!({ "stats": resp }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, SendGridError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| SendGridError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "sendgrid.mail.send",
            "summary": "Send a transactional email",
            "capability": "sendgrid.mail.write",
            "risk_level": "high",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "sendgrid.contacts.list",
            "summary": "List marketing contacts",
            "capability": "sendgrid.contacts.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "sendgrid.contacts.search",
            "summary": "Search marketing contacts by query",
            "capability": "sendgrid.contacts.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "sendgrid.contacts.get",
            "summary": "Get a single contact by ID",
            "capability": "sendgrid.contacts.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "sendgrid.lists.list",
            "summary": "List marketing lists",
            "capability": "sendgrid.lists.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "sendgrid.lists.create",
            "summary": "Create a marketing list",
            "capability": "sendgrid.lists.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "sendgrid.lists.delete",
            "summary": "Delete a marketing list",
            "capability": "sendgrid.lists.write",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "none",
        },
        {
            "id": "sendgrid.templates.list",
            "summary": "List dynamic email templates",
            "capability": "sendgrid.templates.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "sendgrid.templates.get",
            "summary": "Get a single template by ID",
            "capability": "sendgrid.templates.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "sendgrid.stats.get",
            "summary": "Get email delivery statistics",
            "capability": "sendgrid.stats.read",
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
    fn config_from_api_key() {
        let config = SendGridConfig::from_params(&json!({
            "api_key": "SG.test-api-key-12345",
        }))
        .unwrap();
        assert!(matches!(config.auth, SendGridAuth::ApiKey(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = SendGridConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = SendGridConfig::from_params(&json!({
            "api_key": "SG.key",
            "base_url": "https://sendgrid.example.com/v3",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://sendgrid.example.com/v3");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = SendGridConfig::from_params(&json!({
            "api_key": "SG.key",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = SendGridConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_key() {
        let result = SendGridConfig::from_params(&json!({
            "api_key": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        let result = SendGridConfig::from_params(&json!({
            "api_key": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = SendGridConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = SendGridConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"contact_id": "contact_abc"});
        assert_eq!(require_str(&input, "contact_id").unwrap(), "contact_abc");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "contact_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"contact_id": 42});
        assert!(require_str(&input, "contact_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"contact_id": null});
        assert!(require_str(&input, "contact_id").is_err());
    }

    #[test]
    fn operations_info_has_10_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 10);
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
        assert!(ids.contains(&"sendgrid.mail.send"));
        assert!(ids.contains(&"sendgrid.contacts.list"));
        assert!(ids.contains(&"sendgrid.contacts.search"));
        assert!(ids.contains(&"sendgrid.contacts.get"));
        assert!(ids.contains(&"sendgrid.lists.list"));
        assert!(ids.contains(&"sendgrid.lists.create"));
        assert!(ids.contains(&"sendgrid.lists.delete"));
        assert!(ids.contains(&"sendgrid.templates.list"));
        assert!(ids.contains(&"sendgrid.templates.get"));
        assert!(ids.contains(&"sendgrid.stats.get"));
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
        let config = SendGridConfig::from_params(&json!({ "api_key": "  SG.test  " })).unwrap();
        match &config.auth {
            SendGridAuth::ApiKey(t) => assert_eq!(t, "SG.test"),
            SendGridAuth::CredentialId(_) => panic!("expected ApiKey"),
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
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = SendGridConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn mail_send_is_risky() {
        let ops = operations_info();
        let mail_send = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "sendgrid.mail.send")
            .unwrap();
        assert_eq!(mail_send["safety_tier"], "risky");
        assert_eq!(mail_send["risk_level"], "high");
    }

    #[test]
    fn lists_delete_is_dangerous() {
        let ops = operations_info();
        let delete = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "sendgrid.lists.delete")
            .unwrap();
        assert_eq!(delete["safety_tier"], "dangerous");
        assert_eq!(delete["risk_level"], "high");
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn doctor_check_clone() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: Some("ok".into()),
            critical: false,
        };
        let c = check.clone();
        assert_eq!(c.name, "test");
        assert!(c.passed);
    }

    #[test]
    fn doctor_check_debug() {
        let check = DoctorCheck {
            name: "check1".into(),
            passed: false,
            message: None,
            critical: true,
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![]);
        let c = r.clone();
        assert_eq!(c.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_status_serialize_all_variants() {
        assert_eq!(
            serde_json::to_value(DoctorStatus::Healthy).unwrap(),
            json!("healthy")
        );
        assert_eq!(
            serde_json::to_value(DoctorStatus::Degraded).unwrap(),
            json!("degraded")
        );
        assert_eq!(
            serde_json::to_value(DoctorStatus::Unhealthy).unwrap(),
            json!("unhealthy")
        );
    }

    #[test]
    fn doctor_status_deserialize_all_variants() {
        let h: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(h, DoctorStatus::Healthy);
        let d: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(d, DoctorStatus::Degraded);
        let u: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(u, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_check_skip_none_message() {
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
    fn doctor_check_with_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failure".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "failure");
    }

    #[test]
    fn require_str_empty_string_returns_ok() {
        let input = json!({"field": ""});
        assert_eq!(require_str(&input, "field").unwrap(), "");
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"field": true});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"field": ["a", "b"]});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn connector_new_equals_default() {
        let c1 = SendGridConnector::new();
        let c2 = SendGridConnector::default();
        assert!(c1.config.is_none());
        assert!(c2.config.is_none());
    }

    #[test]
    fn doctor_result_mixed_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("crit".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("non-crit".into()),
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_check_deserialize() {
        let v = json!({
            "name": "config",
            "passed": true,
            "message": "ok",
            "critical": false
        });
        let check: DoctorCheck = serde_json::from_value(v).unwrap();
        assert_eq!(check.name, "config");
        assert!(check.passed);
    }

    #[test]
    fn doctor_status_eq() {
        assert_eq!(DoctorStatus::Healthy, DoctorStatus::Healthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_status_copy() {
        let status = DoctorStatus::Degraded;
        let copied = status;
        assert_eq!(status, copied);
    }

    #[test]
    fn lists_create_is_risky() {
        let ops = operations_info();
        let create = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "sendgrid.lists.create")
            .unwrap();
        assert_eq!(create["safety_tier"], "risky");
        assert_eq!(create["risk_level"], "medium");
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn write_operations_are_not_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".write") {
                assert_ne!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "write op {} should not be safe",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn config_accepts_trimmed_api_key() {
        let config =
            SendGridConfig::from_params(&json!({ "api_key": "\t  SG.valid_key  \n" })).unwrap();
        match &config.auth {
            SendGridAuth::ApiKey(k) => assert_eq!(k, "SG.valid_key"),
            SendGridAuth::CredentialId(_) => panic!("expected ApiKey"),
        }
    }
}
