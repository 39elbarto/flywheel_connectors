//! FCP `arXiv` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::ArxivClient, error::ArxivError, types::arxiv_categories};

/// Parsed and validated arXiv connector configuration.
#[derive(Debug, Clone)]
struct ArxivConfig {
    arxiv_base_url: String,
    scholar_base_url: String,
    scholar_api_key: Option<String>,
}

impl ArxivConfig {
    fn from_params(params: &serde_json::Value) -> Self {
        let arxiv_base_url = params
            .get("arxiv_base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(crate::client::DEFAULT_ARXIV_BASE_URL)
            .to_string();

        let scholar_base_url = params
            .get("scholar_base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(crate::client::DEFAULT_SCHOLAR_BASE_URL)
            .to_string();

        let scholar_api_key = params
            .get("scholar_api_key")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        Self {
            arxiv_base_url,
            scholar_base_url,
            scholar_api_key,
        }
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

/// FCP `arXiv` Connector.
pub struct ArxivConnector {
    base: Arc<BaseConnector>,
    config: Option<ArxivConfig>,
    client: Option<Arc<ArxivClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl ArxivConnector {
    /// Create a new arXiv connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("arxiv"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for ArxivConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl ArxivConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = ArxivConfig::from_params(&params);
        info!(
            arxiv_url = %config.arxiv_base_url,
            scholar_url = %config.scholar_base_url,
            has_scholar_key = config.scholar_api_key.is_some(),
            "Configuring arXiv connector"
        );

        let client = ArxivClient::new(
            Some(&config.arxiv_base_url),
            Some(&config.scholar_base_url),
            config.scholar_api_key.clone(),
        )
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
            "connector_id": "fcp.arxiv",
            "connector_version": "0.1.0",
            "capabilities": [
                "arxiv.search",
                "arxiv.read",
                "arxiv.citations",
                "arxiv.authors",
                "arxiv.categories",
                "arxiv.monitor"
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
                Some("Not configured - call configure first".into())
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
            "connector_id": "fcp.arxiv",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.arxiv",
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
            "arxiv.search_papers" => self.invoke_search_papers(client, &input).await,
            "arxiv.search_semantic" => self.invoke_search_semantic(client, &input).await,
            "arxiv.get_paper" => self.invoke_get_paper(client, &input).await,
            "arxiv.get_full_text" => self.invoke_get_full_text(client, &input).await,
            "arxiv.download_pdf" => self.invoke_download_pdf(client, &input).await,
            "arxiv.get_citations" => self.invoke_get_citations(client, &input).await,
            "arxiv.get_references" => self.invoke_get_references(client, &input).await,
            "arxiv.extract_references" => self.invoke_extract_references(client, &input).await,
            "arxiv.get_author" => self.invoke_get_author(client, &input).await,
            "arxiv.list_categories" => self.invoke_list_categories(&input).await,
            "arxiv.get_new_papers" => self.invoke_get_new_papers(client, &input).await,
            "arxiv.monitor_category" => self.invoke_monitor_category(client, &input).await,
            "arxiv.monitor_query" => self.invoke_monitor_query(client, &input).await,
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
        info!("arXiv connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // ── Operation implementations ─────────────────────────────────────

    async fn invoke_search_papers(
        &self,
        client: &ArxivClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ArxivError> {
        let query = require_str(input, "query")?;
        let max_results = input.get("max_results").and_then(serde_json::Value::as_i64);
        let start = input.get("start").and_then(serde_json::Value::as_i64);
        let sort_by = input.get("sort_by").and_then(serde_json::Value::as_str);
        let sort_order = input.get("sort_order").and_then(serde_json::Value::as_str);
        client
            .search_papers(query, max_results, start, sort_by, sort_order)
            .await
    }

    async fn invoke_search_semantic(
        &self,
        client: &ArxivClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ArxivError> {
        let query = require_str(input, "query")?;
        let max_results = input.get("max_results").and_then(serde_json::Value::as_i64);
        let categories: Option<Vec<String>> = input
            .get("categories")
            .and_then(serde_json::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_string)
                    .collect()
            });
        client
            .search_semantic(query, max_results, categories.as_deref())
            .await
    }

    async fn invoke_get_paper(
        &self,
        client: &ArxivClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ArxivError> {
        let arxiv_id = require_str(input, "arxiv_id")?;
        client.get_paper(arxiv_id).await
    }

    async fn invoke_get_full_text(
        &self,
        client: &ArxivClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ArxivError> {
        let arxiv_id = require_str(input, "arxiv_id")?;
        let format = input.get("format").and_then(serde_json::Value::as_str);
        client.get_full_text(arxiv_id, format).await
    }

    async fn invoke_download_pdf(
        &self,
        client: &ArxivClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ArxivError> {
        let arxiv_id = require_str(input, "arxiv_id")?;
        client.download_pdf(arxiv_id).await
    }

    async fn invoke_get_citations(
        &self,
        client: &ArxivClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ArxivError> {
        let arxiv_id = require_str(input, "arxiv_id")?;
        let max_results = input.get("max_results").and_then(serde_json::Value::as_i64);
        client.get_citations(arxiv_id, max_results).await
    }

    async fn invoke_get_references(
        &self,
        client: &ArxivClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ArxivError> {
        let arxiv_id = require_str(input, "arxiv_id")?;
        client.get_references(arxiv_id).await
    }

    async fn invoke_extract_references(
        &self,
        client: &ArxivClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ArxivError> {
        let arxiv_id = require_str(input, "arxiv_id")?;
        client.extract_references(arxiv_id).await
    }

    async fn invoke_get_author(
        &self,
        client: &ArxivClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ArxivError> {
        let author_name = require_str(input, "author_name")?;
        let max_papers = input.get("max_papers").and_then(serde_json::Value::as_i64);
        client.get_author(author_name, max_papers).await
    }

    async fn invoke_list_categories(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ArxivError> {
        let group = input.get("group").and_then(serde_json::Value::as_str);
        let mut categories = arxiv_categories();
        if let Some(g) = group {
            categories.retain(|c| c.group == g);
        }
        Ok(json!({
            "categories": categories,
        }))
    }

    async fn invoke_get_new_papers(
        &self,
        client: &ArxivClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ArxivError> {
        let category = require_str(input, "category")?;
        let max_results = input.get("max_results").and_then(serde_json::Value::as_i64);
        client.get_new_papers(category, max_results).await
    }

    async fn invoke_monitor_category(
        &self,
        client: &ArxivClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ArxivError> {
        let categories: Vec<String> = input
            .get("categories")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| ArxivError::InvalidInput {
                message: "Missing required field: categories".into(),
            })?
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_string)
            .collect();
        let keyword_filter = input
            .get("keyword_filter")
            .and_then(serde_json::Value::as_str);
        let since_ts = input.get("since_ts").and_then(serde_json::Value::as_str);
        client
            .monitor_category(&categories, keyword_filter, since_ts)
            .await
    }

    async fn invoke_monitor_query(
        &self,
        client: &ArxivClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, ArxivError> {
        let query = require_str(input, "query")?;
        let since_ts = input.get("since_ts").and_then(serde_json::Value::as_str);
        client.monitor_query(query, since_ts).await
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, ArxivError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ArxivError::InvalidInput {
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "arxiv.search_papers",
            "summary": "Search arXiv for papers by keyword, title, author, or abstract",
            "capability": "arxiv.search",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "arxiv.search_semantic",
            "summary": "Semantic search for papers using natural language queries",
            "capability": "arxiv.search",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "arxiv.get_paper",
            "summary": "Get detailed metadata for a paper by arXiv ID",
            "capability": "arxiv.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "arxiv.get_full_text",
            "summary": "Get extracted plain text from a paper",
            "capability": "arxiv.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "arxiv.download_pdf",
            "summary": "Download a paper's PDF content (base64-encoded)",
            "capability": "arxiv.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "arxiv.get_citations",
            "summary": "Get papers that cite a given paper",
            "capability": "arxiv.citations",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "arxiv.get_references",
            "summary": "Get papers referenced by a given paper",
            "capability": "arxiv.citations",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "arxiv.extract_references",
            "summary": "Extract and parse reference entries from a paper",
            "capability": "arxiv.citations",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "arxiv.get_author",
            "summary": "Get author information and publication history",
            "capability": "arxiv.authors",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "arxiv.list_categories",
            "summary": "List arXiv categories and their descriptions",
            "capability": "arxiv.categories",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "arxiv.get_new_papers",
            "summary": "Get recently submitted papers in a category",
            "capability": "arxiv.categories",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "arxiv.monitor_category",
            "summary": "Stream new paper notifications for monitored categories",
            "capability": "arxiv.monitor",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "arxiv.monitor_query",
            "summary": "Stream new papers matching a saved search query",
            "capability": "arxiv.monitor",
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
    fn config_defaults() {
        let config = ArxivConfig::from_params(&json!({}));
        assert_eq!(config.arxiv_base_url, crate::client::DEFAULT_ARXIV_BASE_URL);
        assert_eq!(
            config.scholar_base_url,
            crate::client::DEFAULT_SCHOLAR_BASE_URL
        );
        assert!(config.scholar_api_key.is_none());
    }

    #[test]
    fn config_custom_urls() {
        let config = ArxivConfig::from_params(&json!({
            "arxiv_base_url": "https://arxiv.test",
            "scholar_base_url": "https://scholar.test",
        }));
        assert_eq!(config.arxiv_base_url, "https://arxiv.test");
        assert_eq!(config.scholar_base_url, "https://scholar.test");
    }

    #[test]
    fn config_with_scholar_key() {
        let config = ArxivConfig::from_params(&json!({
            "scholar_api_key": "test-key-123",
        }));
        assert_eq!(config.scholar_api_key, Some("test-key-123".into()));
    }

    #[test]
    fn config_empty_scholar_key_treated_as_none() {
        let config = ArxivConfig::from_params(&json!({
            "scholar_api_key": "",
        }));
        assert!(config.scholar_api_key.is_none());
    }

    #[test]
    fn config_whitespace_scholar_key_treated_as_none() {
        let config = ArxivConfig::from_params(&json!({
            "scholar_api_key": "   ",
        }));
        assert!(config.scholar_api_key.is_none());
    }

    #[test]
    fn config_trims_scholar_key() {
        let config = ArxivConfig::from_params(&json!({
            "scholar_api_key": "  key123  ",
        }));
        assert_eq!(config.scholar_api_key, Some("key123".into()));
    }

    #[test]
    fn require_str_present() {
        let input = json!({"query": "attention"});
        assert_eq!(require_str(&input, "query").unwrap(), "attention");
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
    fn operations_info_has_13_operations() {
        let ops = operations_info();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 13);
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
    fn all_operations_are_safe() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            assert_eq!(
                op["safety_tier"].as_str().unwrap(),
                "safe",
                "op {} should be safe (read-only connector)",
                op["id"]
            );
            assert_eq!(
                op["risk_level"].as_str().unwrap(),
                "low",
                "op {} should be low risk",
                op["id"]
            );
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
    fn operations_contain_expected_ids() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        assert!(ids.contains(&"arxiv.search_papers"));
        assert!(ids.contains(&"arxiv.search_semantic"));
        assert!(ids.contains(&"arxiv.get_paper"));
        assert!(ids.contains(&"arxiv.get_full_text"));
        assert!(ids.contains(&"arxiv.download_pdf"));
        assert!(ids.contains(&"arxiv.get_citations"));
        assert!(ids.contains(&"arxiv.get_references"));
        assert!(ids.contains(&"arxiv.extract_references"));
        assert!(ids.contains(&"arxiv.get_author"));
        assert!(ids.contains(&"arxiv.list_categories"));
        assert!(ids.contains(&"arxiv.get_new_papers"));
        assert!(ids.contains(&"arxiv.monitor_category"));
        assert!(ids.contains(&"arxiv.monitor_query"));
    }

    #[test]
    fn operations_capabilities_are_valid() {
        let valid_caps = [
            "arxiv.search",
            "arxiv.read",
            "arxiv.citations",
            "arxiv.authors",
            "arxiv.categories",
            "arxiv.monitor",
        ];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(
                valid_caps.contains(&cap),
                "op {} has invalid capability: {cap}",
                op["id"]
            );
        }
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
    fn connector_default() {
        let c = ArxivConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_zero_counters() {
        let c = ArxivConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }
}
