//! FCP Semantic Scholar Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, SemanticScholarAuth, SemanticScholarClient},
    error::SemanticScholarError,
};

/// Parsed and validated Semantic Scholar connector configuration.
#[derive(Debug, Clone)]
struct SemanticScholarConfig {
    auth: SemanticScholarAuth,
    base_url: String,
}

impl SemanticScholarConfig {
    #[allow(clippy::unnecessary_wraps)]
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_key = params
            .get("api_key")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let auth = match api_key {
            Some(key) => SemanticScholarAuth::ApiKey(key),
            None => SemanticScholarAuth::None,
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

/// FCP Semantic Scholar Connector.
pub struct SemanticScholarConnector {
    base: Arc<BaseConnector>,
    config: Option<SemanticScholarConfig>,
    client: Option<Arc<SemanticScholarClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl SemanticScholarConnector {
    /// Create a new Semantic Scholar connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "semanticscholar",
            ))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for SemanticScholarConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticScholarConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = SemanticScholarConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Semantic Scholar connector");

        let client = SemanticScholarClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.semanticscholar",
            "connector_version": "0.1.0",
            "capabilities": [
                "semanticscholar.papers.read",
                "semanticscholar.authors.read"
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

        let has_key = self.config.as_ref().is_some_and(|c| c.auth.has_key());
        checks.push(DoctorCheck {
            name: "api_key".into(),
            passed: has_key,
            message: if has_key {
                None
            } else {
                Some("No API key configured — using free tier rate limits".into())
            },
            critical: false,
        });

        let result = DoctorResult::from_checks(checks);
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.semanticscholar",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.semanticscholar",
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
            "semanticscholar.paper.search" => self.invoke_paper_search(client, &input).await,
            "semanticscholar.paper.get" => self.invoke_paper_get(client, &input).await,
            "semanticscholar.paper.citations" => self.invoke_paper_citations(client, &input).await,
            "semanticscholar.paper.references" => {
                self.invoke_paper_references(client, &input).await
            }
            "semanticscholar.paper.recommendations" => {
                self.invoke_paper_recommendations(client, &input).await
            }
            "semanticscholar.author.get" => self.invoke_author_get(client, &input).await,
            "semanticscholar.author.papers" => self.invoke_author_papers(client, &input).await,
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
        info!("Semantic Scholar connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_paper_search(
        &self,
        client: &SemanticScholarClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SemanticScholarError> {
        let query = require_str(input, "query")?;
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let offset = input.get("offset").and_then(serde_json::Value::as_i64);
        let fields = input.get("fields").and_then(serde_json::Value::as_str);
        client.search_papers(query, limit, offset, fields).await
    }

    async fn invoke_paper_get(
        &self,
        client: &SemanticScholarClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SemanticScholarError> {
        let paper_id = require_str(input, "paper_id")?;
        let fields = input.get("fields").and_then(serde_json::Value::as_str);
        client.get_paper(paper_id, fields).await
    }

    async fn invoke_paper_citations(
        &self,
        client: &SemanticScholarClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SemanticScholarError> {
        let paper_id = require_str(input, "paper_id")?;
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let fields = input.get("fields").and_then(serde_json::Value::as_str);
        client.get_paper_citations(paper_id, limit, fields).await
    }

    async fn invoke_paper_references(
        &self,
        client: &SemanticScholarClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SemanticScholarError> {
        let paper_id = require_str(input, "paper_id")?;
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let fields = input.get("fields").and_then(serde_json::Value::as_str);
        client.get_paper_references(paper_id, limit, fields).await
    }

    async fn invoke_paper_recommendations(
        &self,
        client: &SemanticScholarClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SemanticScholarError> {
        let paper_id = require_str(input, "paper_id")?;
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let fields = input.get("fields").and_then(serde_json::Value::as_str);
        client
            .get_paper_recommendations(paper_id, limit, fields)
            .await
    }

    async fn invoke_author_get(
        &self,
        client: &SemanticScholarClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SemanticScholarError> {
        let author_id = require_str(input, "author_id")?;
        let fields = input.get("fields").and_then(serde_json::Value::as_str);
        client.get_author(author_id, fields).await
    }

    async fn invoke_author_papers(
        &self,
        client: &SemanticScholarClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SemanticScholarError> {
        let author_id = require_str(input, "author_id")?;
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let fields = input.get("fields").and_then(serde_json::Value::as_str);
        client.get_author_papers(author_id, limit, fields).await
    }
}

/// Extract a required string field from input.
fn require_str<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, SemanticScholarError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| SemanticScholarError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "semanticscholar.paper.search",
            "summary": "Search for papers by keyword",
            "capability": "semanticscholar.papers.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "semanticscholar.paper.get",
            "summary": "Get paper details by ID",
            "capability": "semanticscholar.papers.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "semanticscholar.paper.citations",
            "summary": "Get citations of a paper",
            "capability": "semanticscholar.papers.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "semanticscholar.paper.references",
            "summary": "Get references of a paper",
            "capability": "semanticscholar.papers.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "semanticscholar.paper.recommendations",
            "summary": "Get recommended papers based on a seed paper",
            "capability": "semanticscholar.papers.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "semanticscholar.author.get",
            "summary": "Get author details",
            "capability": "semanticscholar.authors.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "semanticscholar.author.papers",
            "summary": "Get papers by an author",
            "capability": "semanticscholar.authors.read",
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
    fn config_with_api_key() {
        let config = SemanticScholarConfig::from_params(&json!({
            "api_key": "test-key-123",
        }))
        .unwrap();
        assert!(config.auth.has_key());
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_without_api_key() {
        let config = SemanticScholarConfig::from_params(&json!({})).unwrap();
        assert!(!config.auth.has_key());
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_custom_base_url() {
        let config = SemanticScholarConfig::from_params(&json!({
            "base_url": "https://custom.example.com/v1",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://custom.example.com/v1");
    }

    #[test]
    fn config_with_key_and_custom_url() {
        let config = SemanticScholarConfig::from_params(&json!({
            "api_key": "mykey",
            "base_url": "https://custom.example.com",
        }))
        .unwrap();
        assert!(config.auth.has_key());
        assert_eq!(config.base_url, "https://custom.example.com");
    }

    #[test]
    fn config_empty_api_key_means_no_auth() {
        let config = SemanticScholarConfig::from_params(&json!({
            "api_key": "",
        }))
        .unwrap();
        assert!(!config.auth.has_key());
    }

    #[test]
    fn config_whitespace_api_key_means_no_auth() {
        let config = SemanticScholarConfig::from_params(&json!({
            "api_key": "   ",
        }))
        .unwrap();
        assert!(!config.auth.has_key());
    }

    #[test]
    fn config_trims_api_key() {
        let config = SemanticScholarConfig::from_params(&json!({
            "api_key": "  key_test  ",
        }))
        .unwrap();
        match &config.auth {
            SemanticScholarAuth::ApiKey(k) => assert_eq!(k, "key_test"),
            SemanticScholarAuth::None => panic!("expected ApiKey"),
        }
    }

    #[test]
    fn config_null_api_key_means_no_auth() {
        let config = SemanticScholarConfig::from_params(&json!({
            "api_key": null,
        }))
        .unwrap();
        assert!(!config.auth.has_key());
    }

    #[test]
    fn config_integer_api_key_means_no_auth() {
        let config = SemanticScholarConfig::from_params(&json!({
            "api_key": 12345,
        }))
        .unwrap();
        assert!(!config.auth.has_key());
    }

    // -- require_str tests --

    #[test]
    fn require_str_present() {
        let input = json!({"query": "transformers"});
        assert_eq!(require_str(&input, "query").unwrap(), "transformers");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"query": 42});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"query": null});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"query": ["a", "b"]});
        assert!(require_str(&input, "query").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"query": true});
        assert!(require_str(&input, "query").is_err());
    }

    // -- operations_info tests --

    #[test]
    fn operations_info_has_7_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 7);
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
        assert!(ids.contains(&"semanticscholar.paper.search"));
        assert!(ids.contains(&"semanticscholar.paper.get"));
        assert!(ids.contains(&"semanticscholar.paper.citations"));
        assert!(ids.contains(&"semanticscholar.paper.references"));
        assert!(ids.contains(&"semanticscholar.paper.recommendations"));
        assert!(ids.contains(&"semanticscholar.author.get"));
        assert!(ids.contains(&"semanticscholar.author.papers"));
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
    fn operations_paper_ops_use_papers_read_capability() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            if id.starts_with("semanticscholar.paper.") {
                assert_eq!(
                    op["capability"].as_str().unwrap(),
                    "semanticscholar.papers.read",
                    "paper op {id} should use papers.read capability"
                );
            }
        }
    }

    #[test]
    fn operations_author_ops_use_authors_read_capability() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            if id.starts_with("semanticscholar.author.") {
                assert_eq!(
                    op["capability"].as_str().unwrap(),
                    "semanticscholar.authors.read",
                    "author op {id} should use authors.read capability"
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

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("fail".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("fail".into()),
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
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(!v.contains("message"));
    }

    #[test]
    fn doctor_check_includes_message_when_present() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("something wrong".into()),
            critical: true,
        };
        let v = serde_json::to_string(&check).unwrap();
        assert!(v.contains("something wrong"));
    }

    // -- Connector lifecycle tests --

    #[test]
    fn connector_default() {
        let c = SemanticScholarConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new() {
        let c = SemanticScholarConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    // -- Input schema / ops info for all 7 ops --

    #[test]
    fn operations_all_low_risk() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert_eq!(op["risk_level"].as_str().unwrap(), "low");
        }
    }

    #[test]
    fn operations_all_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert_eq!(op["safety_tier"].as_str().unwrap(), "safe");
        }
    }

    #[test]
    fn operations_all_strict_idempotency() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert_eq!(op["idempotency"].as_str().unwrap(), "strict");
        }
    }

    #[test]
    fn operations_summaries_non_empty() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {} has empty summary", op["id"]);
        }
    }

    #[test]
    fn operations_capabilities_are_known() {
        let valid = [
            "semanticscholar.papers.read",
            "semanticscholar.authors.read",
        ];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(valid.contains(&cap), "unknown capability: {cap}");
        }
    }

    #[test]
    fn operations_paper_search_present() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        let search = arr
            .iter()
            .find(|o| o["id"].as_str() == Some("semanticscholar.paper.search"))
            .expect("paper.search not found");
        assert_eq!(search["capability"], "semanticscholar.papers.read");
    }

    #[test]
    fn operations_paper_get_present() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        let get = arr
            .iter()
            .find(|o| o["id"].as_str() == Some("semanticscholar.paper.get"))
            .expect("paper.get not found");
        assert_eq!(get["capability"], "semanticscholar.papers.read");
    }

    #[test]
    fn operations_paper_citations_present() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert!(
            arr.iter()
                .any(|o| o["id"].as_str() == Some("semanticscholar.paper.citations"))
        );
    }

    #[test]
    fn operations_paper_references_present() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert!(
            arr.iter()
                .any(|o| o["id"].as_str() == Some("semanticscholar.paper.references"))
        );
    }

    #[test]
    fn operations_paper_recommendations_present() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert!(
            arr.iter()
                .any(|o| o["id"].as_str() == Some("semanticscholar.paper.recommendations"))
        );
    }

    #[test]
    fn operations_author_get_present() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert!(
            arr.iter()
                .any(|o| o["id"].as_str() == Some("semanticscholar.author.get"))
        );
    }

    #[test]
    fn operations_author_papers_present() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert!(
            arr.iter()
                .any(|o| o["id"].as_str() == Some("semanticscholar.author.papers"))
        );
    }

    // --- DoctorStatus serde ---

    #[test]
    fn doctor_status_healthy_serde() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_status_degraded_serde() {
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
    }

    #[test]
    fn doctor_status_unhealthy_serde() {
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
    }

    // --- DoctorStatus clone and debug ---

    #[test]
    fn doctor_status_clone_and_drop() {
        let original = DoctorStatus::Healthy;
        let cloned = original;
        assert_eq!(cloned, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_status_debug() {
        let dbg = format!("{:?}", DoctorStatus::Degraded);
        assert!(dbg.contains("Degraded"));
    }

    // --- DoctorCheck clone and debug ---

    #[test]
    fn doctor_check_clone_and_drop() {
        let original = DoctorCheck {
            name: "test_check".into(),
            passed: true,
            message: Some("ok".into()),
            critical: false,
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.name, "test_check");
        assert!(cloned.passed);
        assert_eq!(cloned.message, Some("ok".into()));
    }

    #[test]
    fn doctor_check_debug() {
        let check = DoctorCheck {
            name: "dbg_check".into(),
            passed: false,
            message: None,
            critical: true,
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("DoctorCheck"));
        assert!(dbg.contains("dbg_check"));
    }

    // --- DoctorResult clone and debug ---

    #[test]
    fn doctor_result_clone_and_drop() {
        let original = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
    }

    #[test]
    fn doctor_result_debug() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    // --- require_str error message ---

    #[test]
    fn require_str_error_message_contains_field_name() {
        let input = json!({});
        let err = require_str(&input, "paper_id").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("paper_id"));
    }

    // --- SemanticScholarConfig clone and debug ---

    #[test]
    fn config_clone_and_drop() {
        let config = SemanticScholarConfig::from_params(&json!({
            "api_key": "test_key",
            "base_url": "https://example.com/v1",
        }))
        .unwrap();
        let cloned = config.clone();
        drop(config);
        assert!(cloned.auth.has_key());
        assert_eq!(cloned.base_url, "https://example.com/v1");
    }

    #[test]
    fn config_debug() {
        let config = SemanticScholarConfig::from_params(&json!({})).unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("SemanticScholarConfig"));
    }

    // --- Connector request/error counts ---

    #[test]
    fn connector_initial_counts_zero() {
        let c = SemanticScholarConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }
}
