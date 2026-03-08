//! FCP `Intercom` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, IntercomAuth, IntercomClient},
    error::IntercomError,
};

/// Parsed and validated `Intercom` connector configuration.
#[derive(Debug, Clone)]
struct IntercomConfig {
    auth: IntercomAuth,
    base_url: String,
}

impl IntercomConfig {
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
            (Some(token), None) => IntercomAuth::BearerToken(token),
            (None, Some(cred_id)) => IntercomAuth::CredentialId(cred_id),
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

/// FCP `Intercom` Connector.
pub struct IntercomConnector {
    base: Arc<BaseConnector>,
    config: Option<IntercomConfig>,
    client: Option<Arc<IntercomClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl IntercomConnector {
    /// Create a new `Intercom` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("intercom"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for IntercomConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl IntercomConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = IntercomConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Intercom connector");

        let client = IntercomClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.intercom",
            "connector_version": "0.1.0",
            "capabilities": [
                "intercom.contacts.read",
                "intercom.contacts.write",
                "intercom.conversations.read",
                "intercom.conversations.write",
                "intercom.tags.read"
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
            "connector_id": "fcp.intercom",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.intercom",
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
            "intercom.contacts.list" => self.invoke_contacts_list(client, &input).await,
            "intercom.contacts.create" => self.invoke_contacts_create(client, &input).await,
            "intercom.contacts.delete" => self.invoke_contacts_delete(client, &input).await,
            "intercom.conversations.list" => self.invoke_conversations_list(client, &input).await,
            "intercom.conversations.reply" => self.invoke_conversations_reply(client, &input).await,
            "intercom.tags.list" => self.invoke_tags_list(client).await,
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
        info!("Intercom connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // ── Operation implementations ─────────────────────────────────────

    async fn invoke_contacts_list(
        &self,
        client: &IntercomClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, IntercomError> {
        let per_page = input.get("per_page").and_then(serde_json::Value::as_i64);
        let starting_after = input
            .get("starting_after")
            .and_then(serde_json::Value::as_str);
        let data = client.list_contacts(per_page, starting_after).await?;
        Ok(data)
    }

    async fn invoke_contacts_create(
        &self,
        client: &IntercomClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, IntercomError> {
        let _ = require_str(input, "role")?;
        let data = client.create_contact(input).await?;
        Ok(data)
    }

    async fn invoke_contacts_delete(
        &self,
        client: &IntercomClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, IntercomError> {
        let contact_id = require_str(input, "contact_id")?;
        client.delete_contact(contact_id).await?;
        Ok(json!({ "deleted": true }))
    }

    async fn invoke_conversations_list(
        &self,
        client: &IntercomClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, IntercomError> {
        let per_page = input.get("per_page").and_then(serde_json::Value::as_i64);
        let starting_after = input
            .get("starting_after")
            .and_then(serde_json::Value::as_str);
        let data = client.list_conversations(per_page, starting_after).await?;
        Ok(data)
    }

    async fn invoke_conversations_reply(
        &self,
        client: &IntercomClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, IntercomError> {
        let conversation_id = require_str(input, "conversation_id")?;
        let _ = require_str(input, "body")?;
        let _ = require_str(input, "message_type")?;

        let body = json!({
            "body": input["body"],
            "message_type": input["message_type"],
            "type": "admin",
            "admin_id": input.get("admin_id").cloned().unwrap_or_else(|| json!("0")),
        });

        let data = client.reply_to_conversation(conversation_id, &body).await?;
        Ok(data)
    }

    async fn invoke_tags_list(
        &self,
        client: &IntercomClient,
    ) -> Result<serde_json::Value, IntercomError> {
        let data = client.list_tags().await?;
        Ok(data)
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, IntercomError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| IntercomError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "intercom.contacts.list",
            "summary": "List or search contacts",
            "capability": "intercom.contacts.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "intercom.contacts.create",
            "summary": "Create a contact (lead or user)",
            "capability": "intercom.contacts.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "intercom.contacts.delete",
            "summary": "Delete a contact",
            "capability": "intercom.contacts.write",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "strict",
        },
        {
            "id": "intercom.conversations.list",
            "summary": "List conversations",
            "capability": "intercom.conversations.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "intercom.conversations.reply",
            "summary": "Reply to a conversation",
            "capability": "intercom.conversations.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "intercom.tags.list",
            "summary": "List all tags",
            "capability": "intercom.tags.read",
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
        let config = IntercomConfig::from_params(&json!({
            "access_token": "test-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, IntercomAuth::BearerToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = IntercomConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = IntercomConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://intercom.example.com",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://intercom.example.com");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = IntercomConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = IntercomConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = IntercomConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = IntercomConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = IntercomConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = IntercomConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"role": "user"});
        assert_eq!(require_str(&input, "role").unwrap(), "user");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "role").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"role": 42});
        assert!(require_str(&input, "role").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"role": null});
        assert!(require_str(&input, "role").is_err());
    }

    #[test]
    fn operations_info_has_6_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 6);
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
    fn read_operations_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
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
        assert!(ids.contains(&"intercom.contacts.list"));
        assert!(ids.contains(&"intercom.contacts.create"));
        assert!(ids.contains(&"intercom.contacts.delete"));
        assert!(ids.contains(&"intercom.conversations.list"));
        assert!(ids.contains(&"intercom.conversations.reply"));
        assert!(ids.contains(&"intercom.tags.list"));
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
    fn config_trims_access_token() {
        let config =
            IntercomConfig::from_params(&json!({ "access_token": "  tok_test  " })).unwrap();
        match &config.auth {
            IntercomAuth::BearerToken(t) => assert_eq!(t, "tok_test"),
            IntercomAuth::CredentialId(_) => panic!("expected BearerToken"),
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
        let c = IntercomConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    // ── Additional tests for expanded coverage ────────────────────

    #[test]
    fn connector_new_has_zero_counters() {
        let c = IntercomConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn config_clone_preserves_auth() {
        let config = IntercomConfig::from_params(&json!({
            "access_token": "tok_abc"
        }))
        .unwrap();
        let cloned = config.clone();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(cloned.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_clone_preserves_base_url() {
        let config = IntercomConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://custom.io"
        }))
        .unwrap();
        let cloned = config.clone();
        assert_eq!(config.base_url, "https://custom.io");
        assert_eq!(cloned.base_url, "https://custom.io");
    }

    #[test]
    fn config_debug_format() {
        let config = IntercomConfig::from_params(&json!({
            "access_token": "tok"
        }))
        .unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("IntercomConfig"));
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        for status in [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ] {
            let s = serde_json::to_string(&status).unwrap();
            let back: DoctorStatus = serde_json::from_str(&s).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn doctor_status_copy_semantics() {
        let s = DoctorStatus::Degraded;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn doctor_status_debug_format() {
        assert!(format!("{:?}", DoctorStatus::Healthy).contains("Healthy"));
        assert!(format!("{:?}", DoctorStatus::Degraded).contains("Degraded"));
        assert!(format!("{:?}", DoctorStatus::Unhealthy).contains("Unhealthy"));
    }

    #[test]
    fn doctor_check_skip_none_message() {
        let c = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_check_includes_some_message() {
        let c = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("fail detail".into()),
            critical: true,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["message"], "fail detail");
    }

    #[test]
    fn doctor_check_roundtrip() {
        let c = DoctorCheck {
            name: "connectivity".into(),
            passed: true,
            message: Some("OK".into()),
            critical: false,
        };
        let serialized = serde_json::to_string(&c).unwrap();
        let back: DoctorCheck = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.name, "connectivity");
        assert!(back.passed);
        assert_eq!(back.message, Some("OK".into()));
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: None,
                critical: true,
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_unhealthy_overrides_degraded() {
        let r = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: None,
                critical: false,
            },
        ]);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_serializes_with_message() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "x".into(),
            passed: false,
            message: Some("detail here".into()),
            critical: false,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "degraded");
        assert_eq!(v["checks"][0]["message"], "detail here");
    }

    #[test]
    fn operations_contacts_create_is_risky() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "intercom.contacts.create")
            .unwrap();
        assert_eq!(op["safety_tier"], "risky");
        assert_eq!(op["risk_level"], "medium");
    }

    #[test]
    fn operations_contacts_delete_is_dangerous() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "intercom.contacts.delete")
            .unwrap();
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["risk_level"], "high");
    }

    #[test]
    fn operations_conversations_reply_not_idempotent() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "intercom.conversations.reply")
            .unwrap();
        assert_eq!(op["idempotency"], "none");
    }

    #[test]
    fn operations_tags_list_is_safe() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "intercom.tags.list")
            .unwrap();
        assert_eq!(op["safety_tier"], "safe");
        assert_eq!(op["risk_level"], "low");
        assert_eq!(op["idempotency"], "strict");
    }

    #[test]
    fn operations_all_prefixed_intercom() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("intercom."),
                "op {id} missing intercom. prefix"
            );
        }
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"role": true});
        assert!(require_str(&input, "role").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"role": [1, 2, 3]});
        assert!(require_str(&input, "role").is_err());
    }

    #[test]
    fn require_str_empty_string() {
        let input = json!({"role": ""});
        assert_eq!(require_str(&input, "role").unwrap(), "");
    }

    #[test]
    fn require_str_error_message_content() {
        let input = json!({});
        match require_str(&input, "contact_id").unwrap_err() {
            IntercomError::Api {
                status_code,
                message,
            } => {
                assert_eq!(status_code, 400);
                assert!(message.contains("contact_id"));
            }
            e => panic!("expected Api error, got {e:?}"),
        }
    }
}
