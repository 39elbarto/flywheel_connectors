//! FCP LinkedIn Connector implementation.

#![allow(clippy::doc_markdown)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, LinkedInAuth, LinkedInClient},
    error::LinkedInError,
};

/// Parsed and validated LinkedIn connector configuration.
#[derive(Debug, Clone)]
struct LinkedInConfig {
    auth: LinkedInAuth,
    base_url: String,
}

impl LinkedInConfig {
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
            (Some(key), None) => LinkedInAuth::AccessToken(key),
            (None, Some(cred_id)) => LinkedInAuth::CredentialId(cred_id),
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

/// FCP LinkedIn Connector.
pub struct LinkedInConnector {
    base: Arc<BaseConnector>,
    config: Option<LinkedInConfig>,
    client: Option<Arc<LinkedInClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl LinkedInConnector {
    /// Create a new LinkedIn connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("linkedin"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for LinkedInConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkedInConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = LinkedInConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring LinkedIn connector");

        let client = LinkedInClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.linkedin",
            "connector_version": "0.1.0",
            "capabilities": [
                "linkedin.profile.read",
                "linkedin.connections.read",
                "linkedin.company.read",
                "linkedin.posts.read",
                "linkedin.posts.write",
                "linkedin.analytics.read",
                "linkedin.search.read"
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
            "connector_id": "fcp.linkedin",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.linkedin",
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
            "linkedin.profile.get" => self.invoke_profile_get(client).await,
            "linkedin.profile.get_by_id" => self.invoke_profile_get_by_id(client, &input).await,
            "linkedin.connections.list" => self.invoke_connections_list(client).await,
            "linkedin.company.get" => self.invoke_company_get(client, &input).await,
            "linkedin.company.followers" => self.invoke_company_followers(client, &input).await,
            "linkedin.posts.create" => self.invoke_posts_create(client, &input).await,
            "linkedin.posts.delete" => self.invoke_posts_delete(client, &input).await,
            "linkedin.posts.get" => self.invoke_posts_get(client, &input).await,
            "linkedin.analytics.shares" => self.invoke_analytics_shares(client, &input).await,
            "linkedin.search.companies" => self.invoke_search_companies(client, &input).await,
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
        info!("LinkedIn connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_profile_get(
        &self,
        client: &LinkedInClient,
    ) -> Result<serde_json::Value, LinkedInError> {
        client.get_profile().await
    }

    async fn invoke_profile_get_by_id(
        &self,
        client: &LinkedInClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, LinkedInError> {
        let person_id = require_str(input, "person_id")?;
        client.get_profile_by_id(person_id).await
    }

    async fn invoke_connections_list(
        &self,
        client: &LinkedInClient,
    ) -> Result<serde_json::Value, LinkedInError> {
        client.list_connections().await
    }

    async fn invoke_company_get(
        &self,
        client: &LinkedInClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, LinkedInError> {
        let company_id = require_str(input, "company_id")?;
        client.get_company(company_id).await
    }

    async fn invoke_company_followers(
        &self,
        client: &LinkedInClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, LinkedInError> {
        let company_id = require_str(input, "company_id")?;
        client.list_company_followers(company_id).await
    }

    async fn invoke_posts_create(
        &self,
        client: &LinkedInClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, LinkedInError> {
        let author = require_str(input, "author")?;
        let text = require_str(input, "text")?;
        let visibility = input
            .get("visibility")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("PUBLIC");

        let body = json!({
            "author": author,
            "lifecycleState": "PUBLISHED",
            "specificContent": {
                "com.linkedin.ugc.ShareContent": {
                    "shareCommentary": {
                        "text": text,
                    },
                    "shareMediaCategory": "NONE",
                }
            },
            "visibility": {
                "com.linkedin.ugc.MemberNetworkVisibility": visibility,
            }
        });
        client.create_post(&body).await
    }

    async fn invoke_posts_delete(
        &self,
        client: &LinkedInClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, LinkedInError> {
        let post_urn = require_str(input, "post_urn")?;
        client.delete_post(post_urn).await
    }

    async fn invoke_posts_get(
        &self,
        client: &LinkedInClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, LinkedInError> {
        let post_urn = require_str(input, "post_urn")?;
        client.get_post(post_urn).await
    }

    async fn invoke_analytics_shares(
        &self,
        client: &LinkedInClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, LinkedInError> {
        let share_urn = require_str(input, "share_urn")?;
        client.share_statistics(share_urn).await
    }

    async fn invoke_search_companies(
        &self,
        client: &LinkedInClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, LinkedInError> {
        let keywords = require_str(input, "keywords")?;
        client.search_companies(keywords).await
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, LinkedInError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| LinkedInError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "linkedin.profile.get",
            "summary": "Get the authenticated user's profile",
            "capability": "linkedin.profile.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "linkedin.profile.get_by_id",
            "summary": "Get a profile by person ID",
            "capability": "linkedin.profile.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "linkedin.connections.list",
            "summary": "List the authenticated user's connections",
            "capability": "linkedin.connections.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "linkedin.company.get",
            "summary": "Get a company/organization by ID",
            "capability": "linkedin.company.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "linkedin.company.followers",
            "summary": "Get follower statistics for a company",
            "capability": "linkedin.company.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "linkedin.posts.create",
            "summary": "Create a new LinkedIn post",
            "capability": "linkedin.posts.write",
            "risk_level": "high",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "linkedin.posts.delete",
            "summary": "Delete a LinkedIn post",
            "capability": "linkedin.posts.write",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "none",
        },
        {
            "id": "linkedin.posts.get",
            "summary": "Get a LinkedIn post by URN",
            "capability": "linkedin.posts.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "linkedin.analytics.shares",
            "summary": "Get share statistics for an organizational entity",
            "capability": "linkedin.analytics.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "linkedin.search.companies",
            "summary": "Search for companies by keywords",
            "capability": "linkedin.search.read",
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
        let config = LinkedInConfig::from_params(&json!({
            "access_token": "test-access-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, LinkedInAuth::AccessToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = LinkedInConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = LinkedInConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://linkedin.example.com/v2",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://linkedin.example.com/v2");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = LinkedInConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = LinkedInConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = LinkedInConfig::from_params(&json!({
            "access_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = LinkedInConfig::from_params(&json!({
            "access_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = LinkedInConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = LinkedInConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"company_id": "comp_abc"});
        assert_eq!(require_str(&input, "company_id").unwrap(), "comp_abc");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "company_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"company_id": 42});
        assert!(require_str(&input, "company_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"company_id": null});
        assert!(require_str(&input, "company_id").is_err());
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
        assert!(ids.contains(&"linkedin.profile.get"));
        assert!(ids.contains(&"linkedin.profile.get_by_id"));
        assert!(ids.contains(&"linkedin.connections.list"));
        assert!(ids.contains(&"linkedin.company.get"));
        assert!(ids.contains(&"linkedin.company.followers"));
        assert!(ids.contains(&"linkedin.posts.create"));
        assert!(ids.contains(&"linkedin.posts.delete"));
        assert!(ids.contains(&"linkedin.posts.get"));
        assert!(ids.contains(&"linkedin.analytics.shares"));
        assert!(ids.contains(&"linkedin.search.companies"));
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
            LinkedInConfig::from_params(&json!({ "access_token": "  AQVh_test_token  " })).unwrap();
        match &config.auth {
            LinkedInAuth::AccessToken(t) => assert_eq!(t, "AQVh_test_token"),
            LinkedInAuth::CredentialId(_) => panic!("expected AccessToken"),
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
        let c = LinkedInConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
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
        assert_eq!(c.message, Some("ok".into()));
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
        assert!(dbg.contains("check1"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![]);
        let c = r.clone();
        assert_eq!(c.status, DoctorStatus::Healthy);
        assert!(c.checks.is_empty());
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
    fn doctor_check_serializes_skip_none_message() {
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
    fn operations_posts_create_is_risky() {
        let ops = operations_info();
        let create = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "linkedin.posts.create")
            .unwrap();
        assert_eq!(create["safety_tier"], "risky");
        assert_eq!(create["risk_level"], "high");
    }

    #[test]
    fn operations_posts_delete_is_dangerous() {
        let ops = operations_info();
        let delete = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "linkedin.posts.delete")
            .unwrap();
        assert_eq!(delete["safety_tier"], "dangerous");
    }

    #[test]
    fn connector_new_equals_default() {
        let c1 = LinkedInConnector::new();
        let c2 = LinkedInConnector::default();
        assert!(c1.config.is_none());
        assert!(c2.config.is_none());
        assert_eq!(
            c1.request_count.load(Ordering::Relaxed),
            c2.request_count.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn doctor_result_mixed_critical_and_noncritical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("crit fail".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("non-crit fail".into()),
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        // Critical failure takes precedence
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_check_deserialize() {
        let v = json!({
            "name": "config",
            "passed": true,
            "message": "all good",
            "critical": false
        });
        let check: DoctorCheck = serde_json::from_value(v).unwrap();
        assert_eq!(check.name, "config");
        assert!(check.passed);
        assert_eq!(check.message, Some("all good".into()));
        assert!(!check.critical);
    }

    #[test]
    fn doctor_status_eq() {
        assert_eq!(DoctorStatus::Healthy, DoctorStatus::Healthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
        assert_ne!(DoctorStatus::Degraded, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy() {
        let status = DoctorStatus::Healthy;
        let copied = status;
        assert_eq!(status, copied);
    }

    #[test]
    fn config_accepts_trimmed_access_token() {
        let config =
            LinkedInConfig::from_params(&json!({ "access_token": "\t  valid_token  \n" }))
                .unwrap();
        match &config.auth {
            LinkedInAuth::AccessToken(t) => assert_eq!(t, "valid_token"),
            LinkedInAuth::CredentialId(_) => panic!("expected AccessToken"),
        }
    }
}
