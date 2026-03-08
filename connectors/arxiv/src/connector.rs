//! FCP `arXiv` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, FcpError, FcpResult, IdempotencyClass,
    OperationId, OperationInfo, RiskLevel, SafetyTier,
};
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
            "operations": serde_json::to_value(operations_info()).unwrap_or_default(),
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

        let allowed = operations_info()
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

#[allow(clippy::fn_params_excessive_bools)]
fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval: None,
        safety_tier,
        idempotency,
        ai_hints,
    }
}

/// Build the operations info for introspection.
fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "arxiv.search_papers",
            "Search arXiv for papers by keyword, title, author, or abstract",
            json!({
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": { "type": "string", "description": "Search query (supports arXiv query syntax: ti:, au:, abs:, cat:, all:)" },
                    "max_results": { "type": "integer", "minimum": 1, "maximum": 100, "description": "Maximum results to return (default 10, max 100)" },
                    "sort_by": { "type": "string", "description": "Sort order: relevance, lastUpdatedDate, submittedDate" },
                    "sort_order": { "type": "string", "description": "ascending or descending" },
                    "start": { "type": "integer", "description": "Pagination offset" }
                }
            }),
            json!({
                "type": "object",
                "required": ["papers", "total_results"],
                "properties": {
                    "papers": { "type": "array" },
                    "total_results": { "type": "integer" }
                }
            }),
            "arxiv.search",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Search for papers on arXiv. Use query syntax for targeted searches (ti: for title, au: for author, cat: for category).".into(),
                common_mistakes: vec![
                    "Searching with overly broad queries that return too many results.".into(),
                    "Not using arXiv query syntax for structured searches (e.g., au:Einstein AND cat:gr-qc).".into(),
                ],
                examples: vec![
                    r#"{"query": "ti:attention mechanism transformer", "max_results": 20, "sort_by": "relevance"}"#.into(),
                    r#"{"query": "au:Vaswani AND cat:cs.CL", "max_results": 10}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("arxiv.get_paper"),
                    CapabilityId::from_static("arxiv.search_semantic"),
                ],
            },
        ),
        op_info(
            "arxiv.search_semantic",
            "Semantic search for papers using natural language queries",
            json!({
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": { "type": "string", "description": "Natural language search query" },
                    "max_results": { "type": "integer", "minimum": 1, "maximum": 50, "description": "Maximum results (default 10)" },
                    "categories": { "type": "array", "description": "Restrict to arXiv categories (e.g., ['cs.AI', 'cs.CL'])" }
                }
            }),
            json!({
                "type": "object",
                "required": ["papers"],
                "properties": {
                    "papers": { "type": "array" }
                }
            }),
            "arxiv.search",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Search using natural language descriptions rather than keyword queries.".into(),
                common_mistakes: vec![
                    "Using arXiv query syntax (ti:, au:) instead of plain natural language — this endpoint expects free-text descriptions.".into(),
                ],
                examples: vec![
                    r#"{"query": "papers about using graph neural networks for drug discovery", "max_results": 10, "categories": ["cs.LG", "q-bio.QM"]}"#.into(),
                ],
                related: vec![CapabilityId::from_static("arxiv.search_papers")],
            },
        ),
        op_info(
            "arxiv.get_paper",
            "Get detailed metadata for a paper by arXiv ID",
            json!({
                "type": "object",
                "required": ["arxiv_id"],
                "properties": {
                    "arxiv_id": { "type": "string", "description": "arXiv paper ID (e.g., '2301.08745' or '2301.08745v2')" }
                }
            }),
            json!({
                "type": "object",
                "required": ["paper"],
                "properties": {
                    "paper": { "type": "object", "description": "Paper metadata: title, authors, abstract, categories, dates, DOI, comments" }
                }
            }),
            "arxiv.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get full metadata for a specific paper by its arXiv ID.".into(),
                common_mistakes: vec![
                    "Using the full URL instead of just the ID (use '2301.08745', not 'https://arxiv.org/abs/2301.08745').".into(),
                ],
                examples: vec![
                    r#"{"arxiv_id": "2301.08745"}"#.into(),
                    r#"{"arxiv_id": "1706.03762v7"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("arxiv.download_pdf"),
                    CapabilityId::from_static("arxiv.get_references"),
                    CapabilityId::from_static("arxiv.get_citations"),
                ],
            },
        ),
        op_info(
            "arxiv.get_full_text",
            "Get extracted plain text from a paper",
            json!({
                "type": "object",
                "required": ["arxiv_id"],
                "properties": {
                    "arxiv_id": { "type": "string", "description": "arXiv paper ID" },
                    "format": { "type": "string", "description": "Preferred format: text, html (default: text)" }
                }
            }),
            json!({
                "type": "object",
                "required": ["text"],
                "properties": {
                    "text": { "type": "string" }
                }
            }),
            "arxiv.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get the text content of a paper without downloading the raw PDF.".into(),
                common_mistakes: vec![
                    "Expecting perfect formatting — TeX-to-text conversion is lossy.".into(),
                ],
                examples: vec![r#"{"arxiv_id": "1706.03762"}"#.into()],
                related: vec![
                    CapabilityId::from_static("arxiv.download_pdf"),
                    CapabilityId::from_static("arxiv.get_paper"),
                ],
            },
        ),
        op_info(
            "arxiv.download_pdf",
            "Download a paper's PDF content (base64-encoded)",
            json!({
                "type": "object",
                "required": ["arxiv_id"],
                "properties": {
                    "arxiv_id": { "type": "string", "description": "arXiv paper ID" }
                }
            }),
            json!({
                "type": "object",
                "required": ["content"],
                "properties": {
                    "content": { "type": "string", "description": "PDF content (base64-encoded)" },
                    "size_bytes": { "type": "integer" }
                }
            }),
            "arxiv.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Download the full PDF of a paper for text extraction or analysis.".into(),
                common_mistakes: vec![
                    "Downloading many PDFs in rapid succession (respect arXiv rate limits).".into(),
                    "Not checking paper size before download.".into(),
                ],
                examples: vec![r#"{"arxiv_id": "1706.03762"}"#.into()],
                related: vec![
                    CapabilityId::from_static("arxiv.get_paper"),
                    CapabilityId::from_static("arxiv.extract_references"),
                ],
            },
        ),
        op_info(
            "arxiv.get_citations",
            "Get papers that cite a given paper",
            json!({
                "type": "object",
                "required": ["arxiv_id"],
                "properties": {
                    "arxiv_id": { "type": "string", "description": "arXiv paper ID" },
                    "max_results": { "type": "integer", "minimum": 1, "maximum": 500, "description": "Max citing papers to return" }
                }
            }),
            json!({
                "type": "object",
                "required": ["citations", "total"],
                "properties": {
                    "citations": { "type": "array" },
                    "total": { "type": "integer" }
                }
            }),
            "arxiv.citations",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Find papers that cite a given paper (forward citation graph).".into(),
                common_mistakes: vec![
                    "Expecting real-time citation counts — there is a delay in indexing.".into(),
                ],
                examples: vec![r#"{"arxiv_id": "1706.03762", "max_results": 50}"#.into()],
                related: vec![
                    CapabilityId::from_static("arxiv.get_references"),
                    CapabilityId::from_static("arxiv.get_paper"),
                ],
            },
        ),
        op_info(
            "arxiv.get_references",
            "Get papers referenced by a given paper",
            json!({
                "type": "object",
                "required": ["arxiv_id"],
                "properties": {
                    "arxiv_id": { "type": "string", "description": "arXiv paper ID" }
                }
            }),
            json!({
                "type": "object",
                "required": ["references"],
                "properties": {
                    "references": { "type": "array" }
                }
            }),
            "arxiv.citations",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get the bibliography of a paper (backward citation graph).".into(),
                common_mistakes: vec![
                    "Confusing get_references (papers this paper cites) with get_citations (papers that cite this paper).".into(),
                ],
                examples: vec![r#"{"arxiv_id": "1706.03762"}"#.into()],
                related: vec![
                    CapabilityId::from_static("arxiv.get_citations"),
                    CapabilityId::from_static("arxiv.get_paper"),
                ],
            },
        ),
        op_info(
            "arxiv.extract_references",
            "Extract and parse reference entries from a paper",
            json!({
                "type": "object",
                "required": ["arxiv_id"],
                "properties": {
                    "arxiv_id": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["references"],
                "properties": {
                    "references": { "type": "array", "description": "Parsed reference entries with title, authors, year, DOI where available" }
                }
            }),
            "arxiv.citations",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Parse the reference section of a paper to identify cited works.".into(),
                common_mistakes: vec![
                    "Expecting structured DOI/URL links for every reference — many older papers have unresolved plain-text citations.".into(),
                ],
                examples: vec![r#"{"arxiv_id": "1706.03762"}"#.into()],
                related: vec![
                    CapabilityId::from_static("arxiv.get_references"),
                    CapabilityId::from_static("arxiv.download_pdf"),
                ],
            },
        ),
        op_info(
            "arxiv.get_author",
            "Get author information and publication history",
            json!({
                "type": "object",
                "required": ["author_name"],
                "properties": {
                    "author_name": { "type": "string", "description": "Author name to search for" },
                    "max_papers": { "type": "integer", "minimum": 1, "maximum": 200, "description": "Max papers to include in publication list" }
                }
            }),
            json!({
                "type": "object",
                "required": ["author", "papers"],
                "properties": {
                    "author": { "type": "object" },
                    "papers": { "type": "array" }
                }
            }),
            "arxiv.authors",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Look up an author's profile and publication history.".into(),
                common_mistakes: vec![
                    "Author names are not unique — use additional filters (categories, date ranges) to disambiguate.".into(),
                ],
                examples: vec![r#"{"author_name": "Ashish Vaswani", "max_papers": 50}"#.into()],
                related: vec![CapabilityId::from_static("arxiv.search_papers")],
            },
        ),
        op_info(
            "arxiv.list_categories",
            "List arXiv categories and their descriptions",
            json!({
                "type": "object",
                "required": [],
                "properties": {
                    "group": { "type": "string", "description": "Filter by group (e.g., 'cs', 'math', 'physics')" }
                }
            }),
            json!({
                "type": "object",
                "required": ["categories"],
                "properties": {
                    "categories": { "type": "array" }
                }
            }),
            "arxiv.categories",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List available arXiv categories to help users refine searches.".into(),
                common_mistakes: vec![
                    "Confusing group names with category codes — 'cs' is a group, 'cs.AI' is a category.".into(),
                ],
                examples: vec![
                    r#"{}"#.into(),
                    r#"{"group": "cs"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("arxiv.get_new_papers"),
                    CapabilityId::from_static("arxiv.search_papers"),
                ],
            },
        ),
        op_info(
            "arxiv.get_new_papers",
            "Get recently submitted papers in a category",
            json!({
                "type": "object",
                "required": ["category"],
                "properties": {
                    "category": { "type": "string", "description": "arXiv category (e.g., 'cs.AI', 'math.CO')" },
                    "max_results": { "type": "integer", "minimum": 1, "maximum": 100, "description": "Max papers to return (default 25)" }
                }
            }),
            json!({
                "type": "object",
                "required": ["papers"],
                "properties": {
                    "papers": { "type": "array" }
                }
            }),
            "arxiv.categories",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Browse the latest papers in a category — like reading the daily arXiv listings.".into(),
                common_mistakes: vec![
                    "Using an invalid category code (e.g. 'AI' instead of 'cs.AI') — call list_categories first to verify.".into(),
                ],
                examples: vec![r#"{"category": "cs.AI", "max_results": 25}"#.into()],
                related: vec![
                    CapabilityId::from_static("arxiv.list_categories"),
                    CapabilityId::from_static("arxiv.monitor_category"),
                ],
            },
        ),
        op_info(
            "arxiv.monitor_category",
            "Stream new paper notifications for monitored categories",
            json!({
                "type": "object",
                "required": ["categories"],
                "properties": {
                    "categories": { "type": "array", "description": "List of arXiv categories to monitor" },
                    "keyword_filter": { "type": "string", "description": "Optional keyword filter applied to titles and abstracts" },
                    "since_ts": { "type": "string", "description": "ISO 8601 timestamp to resume from" }
                }
            }),
            json!({
                "type": "object",
                "required": ["papers"],
                "properties": {
                    "papers": { "type": "array" },
                    "cursor_ts": { "type": "string", "description": "Cursor timestamp for next poll" }
                }
            }),
            "arxiv.monitor",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Set up a monitor for new papers in specific categories. Polling-backed, not real-time.".into(),
                common_mistakes: vec![
                    "Monitoring too many categories simultaneously (increases API load).".into(),
                    "Not persisting cursor_ts for resumption after restarts.".into(),
                ],
                examples: vec![
                    r#"{"categories": ["cs.AI", "cs.CL"], "keyword_filter": "transformer"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("arxiv.get_new_papers"),
                    CapabilityId::from_static("arxiv.list_categories"),
                ],
            },
        ),
        op_info(
            "arxiv.monitor_query",
            "Stream new papers matching a saved search query",
            json!({
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": { "type": "string", "description": "arXiv search query to monitor" },
                    "since_ts": { "type": "string", "description": "ISO 8601 timestamp to resume from" }
                }
            }),
            json!({
                "type": "object",
                "required": ["papers"],
                "properties": {
                    "papers": { "type": "array" },
                    "cursor_ts": { "type": "string" }
                }
            }),
            "arxiv.monitor",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Monitor for new papers matching a specific search query.".into(),
                common_mistakes: vec![
                    "Not persisting the returned cursor_ts — without it the monitor rescans from the beginning on restart.".into(),
                ],
                examples: vec![
                    r#"{"query": "ti:large language model AND cat:cs.CL"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("arxiv.monitor_category"),
                    CapabilityId::from_static("arxiv.search_papers"),
                ],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to get operations as JSON for backward-compatible test assertions.
    fn ops_json() -> serde_json::Value {
        serde_json::to_value(operations_info()).unwrap()
    }

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
        assert_eq!(ops.len(), 13);
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = ops_json();
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
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_risk_levels_valid() {
        let valid = ["low", "medium", "high"];
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    fn all_operations_are_safe() {
        let ops = ops_json();
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
        let ops = ops_json();
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
        let ids: Vec<&str> = ops.iter().map(|o| o.id.as_ref()).collect();
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
        for op in &ops {
            let cap = op.capability.as_ref();
            assert!(
                valid_caps.contains(&cap),
                "op {} has invalid capability: {cap}",
                op.id.as_ref()
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
