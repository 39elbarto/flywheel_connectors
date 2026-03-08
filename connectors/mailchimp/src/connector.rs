//! FCP Mailchimp Connector implementation.

#![allow(clippy::doc_markdown)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{MailchimpAuth, MailchimpClient},
    error::MailchimpError,
};

/// Parsed and validated Mailchimp connector configuration.
#[derive(Debug, Clone)]
struct MailchimpConfig {
    auth: MailchimpAuth,
    base_url: Option<String>,
}

impl MailchimpConfig {
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
            (Some(key), None) => MailchimpAuth::ApiKey(key),
            (None, Some(cred_id)) => MailchimpAuth::CredentialId(cred_id),
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
            .map(str::to_string);

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

/// FCP Mailchimp Connector.
pub struct MailchimpConnector {
    base: Arc<BaseConnector>,
    config: Option<MailchimpConfig>,
    client: Option<Arc<MailchimpClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl MailchimpConnector {
    /// Create a new Mailchimp connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("mailchimp"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for MailchimpConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl MailchimpConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = MailchimpConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), "Configuring Mailchimp connector");

        let client = MailchimpClient::new(config.auth.clone(), config.base_url.as_deref())
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
            "connector_id": "fcp.mailchimp",
            "connector_version": "0.1.0",
            "capabilities": [
                "mailchimp.lists.read",
                "mailchimp.members.read",
                "mailchimp.members.write",
                "mailchimp.campaigns.read",
                "mailchimp.campaigns.write"
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
            "connector_id": "fcp.mailchimp",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.mailchimp",
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
            "mailchimp.lists.list" => self.invoke_lists_list(client).await,
            "mailchimp.members.list" => self.invoke_members_list(client, &input).await,
            "mailchimp.members.delete" => self.invoke_members_delete(client, &input).await,
            "mailchimp.campaigns.list" => self.invoke_campaigns_list(client).await,
            "mailchimp.campaigns.send" => self.invoke_campaigns_send(client, &input).await,
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
        info!("Mailchimp connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_lists_list(
        &self,
        client: &MailchimpClient,
    ) -> Result<serde_json::Value, MailchimpError> {
        let resp = client.list_lists().await?;
        let lists = resp
            .get("lists")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if lists.is_null() {
            return Ok(json!({ "lists": [] }));
        }
        Ok(json!({ "lists": lists }))
    }

    async fn invoke_members_list(
        &self,
        client: &MailchimpClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MailchimpError> {
        let list_id = require_str(input, "list_id")?;
        let resp = client.list_members(list_id).await?;
        let members = resp
            .get("members")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if members.is_null() {
            return Ok(json!({ "members": [] }));
        }
        Ok(json!({ "members": members }))
    }

    async fn invoke_members_delete(
        &self,
        client: &MailchimpClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MailchimpError> {
        let list_id = require_str(input, "list_id")?;
        let subscriber_hash = require_str(input, "subscriber_hash")?;
        client.delete_member(list_id, subscriber_hash).await
    }

    async fn invoke_campaigns_list(
        &self,
        client: &MailchimpClient,
    ) -> Result<serde_json::Value, MailchimpError> {
        let resp = client.list_campaigns().await?;
        let campaigns = resp
            .get("campaigns")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if campaigns.is_null() {
            return Ok(json!({ "campaigns": [] }));
        }
        Ok(json!({ "campaigns": campaigns }))
    }

    async fn invoke_campaigns_send(
        &self,
        client: &MailchimpClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, MailchimpError> {
        let campaign_id = require_str(input, "campaign_id")?;
        client.send_campaign(campaign_id).await
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, MailchimpError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| MailchimpError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "mailchimp.lists.list",
            "summary": "List audiences",
            "capability": "mailchimp.lists.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "mailchimp.members.list",
            "summary": "List members of an audience",
            "capability": "mailchimp.members.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "mailchimp.members.delete",
            "summary": "Delete a member from an audience",
            "capability": "mailchimp.members.write",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "strict",
        },
        {
            "id": "mailchimp.campaigns.list",
            "summary": "List campaigns",
            "capability": "mailchimp.campaigns.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "mailchimp.campaigns.send",
            "summary": "Send a campaign",
            "capability": "mailchimp.campaigns.write",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "none",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::MailchimpAuth;

    #[test]
    fn config_from_api_key() {
        let config = MailchimpConfig::from_params(&json!({
            "api_key": "testkey-us1",
        }))
        .unwrap();
        assert!(matches!(config.auth, MailchimpAuth::ApiKey(_)));
    }

    #[test]
    fn config_from_credential_id() {
        let config = MailchimpConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = MailchimpConfig::from_params(&json!({
            "api_key": "key-us1",
            "base_url": "https://mailchimp.example.com/3.0",
        }))
        .unwrap();
        assert_eq!(
            config.base_url,
            Some("https://mailchimp.example.com/3.0".into())
        );
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = MailchimpConfig::from_params(&json!({
            "api_key": "key-us1",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = MailchimpConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_key() {
        let result = MailchimpConfig::from_params(&json!({
            "api_key": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        let result = MailchimpConfig::from_params(&json!({
            "api_key": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = MailchimpConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = MailchimpConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"list_id": "list_abc"});
        assert_eq!(require_str(&input, "list_id").unwrap(), "list_abc");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "list_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"list_id": 42});
        assert!(require_str(&input, "list_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"list_id": null});
        assert!(require_str(&input, "list_id").is_err());
    }

    #[test]
    fn operations_info_has_5_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 5);
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
        assert!(ids.contains(&"mailchimp.lists.list"));
        assert!(ids.contains(&"mailchimp.members.list"));
        assert!(ids.contains(&"mailchimp.members.delete"));
        assert!(ids.contains(&"mailchimp.campaigns.list"));
        assert!(ids.contains(&"mailchimp.campaigns.send"));
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
        let config = MailchimpConfig::from_params(&json!({ "api_key": "  key-us1  " })).unwrap();
        match &config.auth {
            MailchimpAuth::ApiKey(t) => assert_eq!(t, "key-us1"),
            MailchimpAuth::CredentialId(_) => panic!("expected ApiKey"),
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
        let c = MailchimpConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    // -- Additional connector tests --

    #[test]
    fn connector_new_matches_default() {
        let c = MailchimpConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        let statuses = [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ];
        for s in &statuses {
            let v = serde_json::to_value(s).unwrap();
            let back: DoctorStatus = serde_json::from_value(v).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn doctor_status_lowercase_serialization() {
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
            message: Some("failed".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "failed");
        assert_eq!(v["critical"], true);
    }

    #[test]
    fn doctor_check_clone() {
        let check = DoctorCheck {
            name: "x".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let cloned = check.clone();
        assert!(check.passed);
        assert_eq!(cloned.name, "x");
    }

    #[test]
    fn doctor_check_debug() {
        let check = DoctorCheck {
            name: "x".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("DoctorCheck"));
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![]);
        let cloned = r.clone();
        assert_eq!(r.status, DoctorStatus::Healthy);
        assert!(cloned.checks.is_empty());
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_result_deserialize() {
        let v = json!({"status": "unhealthy", "checks": [{"name": "a", "passed": false, "critical": true}]});
        let r: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 1);
    }

    #[test]
    fn operations_all_have_mailchimp_prefix() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("mailchimp."),
                "op {id} missing mailchimp prefix"
            );
        }
    }

    #[test]
    fn operations_write_ops_not_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.to_ascii_lowercase().ends_with(".write") {
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
    fn operations_delete_is_dangerous() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            if id.contains("delete") {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "dangerous",
                    "delete op {id} should be dangerous"
                );
            }
        }
    }

    #[test]
    fn operations_send_is_dangerous() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            if id.contains("send") {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "dangerous",
                    "send op {id} should be dangerous"
                );
            }
        }
    }

    #[test]
    fn config_error_message_both_auth() {
        let result = MailchimpConfig::from_params(&json!({
            "api_key": "key-us1",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("exactly one")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_error_message_no_auth() {
        let result = MailchimpConfig::from_params(&json!({}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("Missing")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_error_non_string_credential() {
        let result = MailchimpConfig::from_params(&json!({"credential_id": 12345}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("string")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_error_invalid_uuid() {
        let result = MailchimpConfig::from_params(&json!({"credential_id": "not-a-uuid"}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("UUID")),
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_base_url_none_by_default() {
        let config = MailchimpConfig::from_params(&json!({"api_key": "key-us1"})).unwrap();
        assert!(config.base_url.is_none());
    }

    #[test]
    fn require_str_empty_string_is_valid() {
        let input = json!({"list_id": ""});
        assert_eq!(require_str(&input, "list_id").unwrap(), "");
    }

    #[test]
    fn require_str_error_message_contains_field_name() {
        let input = json!({});
        let err = require_str(&input, "campaign_id").unwrap_err();
        match err {
            MailchimpError::Api { message, .. } => assert!(message.contains("campaign_id")),
            _ => panic!("expected Api error"),
        }
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
    fn operations_idempotency_values_valid() {
        let valid = ["strict", "none", "idempotent"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let idem = op["idempotency"].as_str().unwrap();
            assert!(
                valid.contains(&idem),
                "invalid idempotency {idem} for {:?}",
                op["id"]
            );
        }
    }

    #[test]
    fn connector_default_impl() {
        let c = MailchimpConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn operations_have_mailchimp_prefix() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(
                op["id"].as_str().unwrap().starts_with("mailchimp."),
                "op {} missing mailchimp prefix",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_all_have_capability() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(
                op["capability"].as_str().is_some(),
                "op {} missing capability",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_all_have_safety_tier() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert!(
                op["safety_tier"].as_str().is_some(),
                "op {} missing safety_tier",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_summaries_are_non_empty() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty());
        }
    }

    #[test]
    fn doctor_check_with_message() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: Some("all good".into()),
            critical: false,
        };
        let json = serde_json::to_value(&check).unwrap();
        assert_eq!(json["message"], "all good");
    }

    #[test]
    fn doctor_result_serialize_roundtrip() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "c".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let json = serde_json::to_string(&r).unwrap();
        let r2: DoctorResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r.status, r2.status);
        assert_eq!(r.checks.len(), r2.checks.len());
    }

    #[test]
    fn doctor_status_debug_format() {
        let s = DoctorStatus::Degraded;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Degraded"));
    }

    #[test]
    fn require_str_object_value_fails() {
        let input = json!({"list_id": {"nested": "value"}});
        assert!(require_str(&input, "list_id").is_err());
    }

    #[test]
    fn require_str_array_value_fails() {
        let input = json!({"list_id": [1, 2, 3]});
        assert!(require_str(&input, "list_id").is_err());
    }
}
