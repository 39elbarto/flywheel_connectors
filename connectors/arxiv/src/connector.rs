//! FCP `arXiv` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, FcpError, FcpResult, IdempotencyClass,
    Introspection, OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep,
    ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, SelfCheckReport, StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::ArxivClient, error::ArxivError, types::arxiv_categories};

/// Parsed and validated arXiv connector configuration.
#[derive(Clone)]
struct ArxivConfig {
    arxiv_base_url: String,
    scholar_base_url: String,
    scholar_api_key: Option<String>,
    rate_limit_rps: f64,
}

impl std::fmt::Debug for ArxivConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArxivConfig")
            .field("arxiv_base_url", &self.arxiv_base_url)
            .field("scholar_base_url", &self.scholar_base_url)
            .field(
                "scholar_api_key",
                &self.scholar_api_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("rate_limit_rps", &self.rate_limit_rps)
            .finish()
    }
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

        let scholar_auth = params
            .get("scholar_api_key")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let rate_limit_rps = params
            .get("rate_limit_rps")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(3.0);

        Self {
            arxiv_base_url,
            scholar_base_url,
            scholar_api_key: scholar_auth,
            rate_limit_rps,
        }
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.arxiv_base_url);
        let rate_limit_configured = self.rate_limit_rps > 0.0 && self.rate_limit_rps <= 10.0;

        ProvisioningReadiness {
            network_ok,
            network_message,
            base_url: self.arxiv_base_url.clone(),
            rate_limit_rps: self.rate_limit_rps,
            rate_limit_configured,
            has_scholar_key: self.scholar_api_key.is_some(),
        }
    }

    fn validate_endpoint_policies(&self) -> FcpResult<()> {
        enforce_base_url_policy(
            "arxiv_base_url",
            &self.arxiv_base_url,
            &["export.arxiv.org"],
        )?;
        enforce_base_url_policy(
            "scholar_base_url",
            &self.scholar_base_url,
            &["api.semanticscholar.org", "scholar.google.com"],
        )
    }
}

/// Provisioning readiness assessment for the arXiv connector.
#[derive(Debug, Clone, Serialize)]
struct ProvisioningReadiness {
    network_ok: bool,
    network_message: String,
    base_url: String,
    rate_limit_rps: f64,
    rate_limit_configured: bool,
    has_scholar_key: bool,
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
        config.validate_endpoint_policies()?;

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

        if self.client.is_none() {
            let mut report = SelfCheckReport::failed(
                "client_missing",
                "API client not initialized; re-run configure",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        if !readiness.rate_limit_configured {
            let mut report = SelfCheckReport::degraded(
                "rate_limit_misconfigured",
                format!(
                    "Rate limit {} req/s is outside safe range (0 < rps <= 10); defaulting to 3 req/s",
                    readiness.rate_limit_rps
                ),
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let mut report = SelfCheckReport::ok();
        report.details = Some(json!({ "provisioning": readiness }));
        Self::serialize_self_check_report(report)
    }

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "arxiv.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "arXiv self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle the `introspect` method.
    #[allow(clippy::too_many_lines)]
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("arxiv.search_papers"),
                    summary: "Search arXiv for papers by keyword, title, author, or abstract".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": {"type": "string", "description": "Search query (supports arXiv query syntax: ti:, au:, abs:, cat:, all:)"},
                            "max_results": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Maximum results to return (default 10, max 100)"},
                            "start": {"type": "integer", "description": "Pagination offset"},
                            "sort_by": {"type": "string", "description": "Sort order: relevance, lastUpdatedDate, submittedDate"},
                            "sort_order": {"type": "string", "description": "ascending or descending"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["papers", "total_results"],
                        "properties": {"papers": {"type": "array"}, "total_results": {"type": "integer"}}
                    }),
                    capability: CapabilityId::from_static("arxiv.search"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
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
                },
                OperationInfo {
                    id: OperationId::from_static("arxiv.search_semantic"),
                    summary: "Semantic search for papers using natural language queries".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": {"type": "string", "description": "Natural language search query"},
                            "max_results": {"type": "integer", "minimum": 1, "maximum": 50, "description": "Maximum results (default 10)"},
                            "categories": {"type": "array", "description": "Restrict to arXiv categories"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["papers"],
                        "properties": {"papers": {"type": "array"}}
                    }),
                    capability: CapabilityId::from_static("arxiv.search"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Search using natural language descriptions rather than keyword queries.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"query": "papers about using graph neural networks for drug discovery", "max_results": 10, "categories": ["cs.LG", "q-bio.QM"]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("arxiv.search_papers")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("arxiv.get_paper"),
                    summary: "Get detailed metadata for a paper by arXiv ID".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["arxiv_id"],
                        "properties": {
                            "arxiv_id": {"type": "string", "description": "arXiv paper ID (e.g., '2301.08745' or '2301.08745v2')"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["paper"],
                        "properties": {"paper": {"type": "object", "description": "Paper metadata: title, authors, abstract, categories, dates, DOI, comments"}}
                    }),
                    capability: CapabilityId::from_static("arxiv.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
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
                },
                OperationInfo {
                    id: OperationId::from_static("arxiv.get_full_text"),
                    summary: "Get extracted plain text from a paper".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["arxiv_id"],
                        "properties": {
                            "arxiv_id": {"type": "string", "description": "arXiv paper ID"},
                            "format": {"type": "string", "description": "Preferred format: text, html (default: text)"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["text"],
                        "properties": {"text": {"type": "string"}}
                    }),
                    capability: CapabilityId::from_static("arxiv.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
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
                },
                OperationInfo {
                    id: OperationId::from_static("arxiv.download_pdf"),
                    summary: "Download a paper's PDF content (base64-encoded)".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["arxiv_id"],
                        "properties": {
                            "arxiv_id": {"type": "string", "description": "arXiv paper ID"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["content"],
                        "properties": {
                            "content": {"type": "string", "description": "PDF content (base64-encoded)"},
                            "size_bytes": {"type": "integer"}
                        }
                    }),
                    capability: CapabilityId::from_static("arxiv.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
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
                },
                OperationInfo {
                    id: OperationId::from_static("arxiv.get_citations"),
                    summary: "Get papers that cite a given paper".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["arxiv_id"],
                        "properties": {
                            "arxiv_id": {"type": "string", "description": "arXiv paper ID"},
                            "max_results": {"type": "integer", "minimum": 1, "maximum": 500, "description": "Max citing papers to return"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["citations", "total"],
                        "properties": {"citations": {"type": "array"}, "total": {"type": "integer"}}
                    }),
                    capability: CapabilityId::from_static("arxiv.citations"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
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
                },
                OperationInfo {
                    id: OperationId::from_static("arxiv.get_references"),
                    summary: "Get papers referenced by a given paper".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["arxiv_id"],
                        "properties": {
                            "arxiv_id": {"type": "string", "description": "arXiv paper ID"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["references"],
                        "properties": {"references": {"type": "array"}}
                    }),
                    capability: CapabilityId::from_static("arxiv.citations"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Get the bibliography of a paper (backward citation graph).".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"arxiv_id": "1706.03762"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("arxiv.get_citations"),
                            CapabilityId::from_static("arxiv.get_paper"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("arxiv.extract_references"),
                    summary: "Extract and parse reference entries from a paper".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["arxiv_id"],
                        "properties": {
                            "arxiv_id": {"type": "string"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["references"],
                        "properties": {"references": {"type": "array", "description": "Parsed reference entries with title, authors, year, DOI where available"}}
                    }),
                    capability: CapabilityId::from_static("arxiv.citations"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Parse the reference section of a paper to identify cited works.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"arxiv_id": "1706.03762"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("arxiv.get_references"),
                            CapabilityId::from_static("arxiv.download_pdf"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("arxiv.get_author"),
                    summary: "Get author information and publication history".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["author_name"],
                        "properties": {
                            "author_name": {"type": "string", "description": "Author name to search for"},
                            "max_papers": {"type": "integer", "minimum": 1, "maximum": 200, "description": "Max papers to include in publication list"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["author", "papers"],
                        "properties": {"author": {"type": "object"}, "papers": {"type": "array"}}
                    }),
                    capability: CapabilityId::from_static("arxiv.authors"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Look up an author's profile and publication history.".into(),
                        common_mistakes: vec![
                            "Author names are not unique — use additional filters (categories, date ranges) to disambiguate.".into(),
                        ],
                        examples: vec![r#"{"author_name": "Ashish Vaswani", "max_papers": 50}"#.into()],
                        related: vec![CapabilityId::from_static("arxiv.search_papers")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("arxiv.list_categories"),
                    summary: "List arXiv categories and their descriptions".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": [],
                        "properties": {
                            "group": {"type": "string", "description": "Filter by group (e.g., 'cs', 'math', 'physics')"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["categories"],
                        "properties": {"categories": {"type": "array"}}
                    }),
                    capability: CapabilityId::from_static("arxiv.categories"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List available arXiv categories to help users refine searches.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            "{}".into(),
                            r#"{"group": "cs"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("arxiv.get_new_papers"),
                            CapabilityId::from_static("arxiv.search_papers"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("arxiv.get_new_papers"),
                    summary: "Get recently submitted papers in a category".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["category"],
                        "properties": {
                            "category": {"type": "string", "description": "arXiv category (e.g., 'cs.AI', 'math.CO')"},
                            "max_results": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Max papers to return (default 25)"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["papers"],
                        "properties": {"papers": {"type": "array"}}
                    }),
                    capability: CapabilityId::from_static("arxiv.categories"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Browse the latest papers in a category — like reading the daily arXiv listings.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"category": "cs.AI", "max_results": 25}"#.into()],
                        related: vec![
                            CapabilityId::from_static("arxiv.list_categories"),
                            CapabilityId::from_static("arxiv.monitor_category"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("arxiv.monitor_category"),
                    summary: "Stream new paper notifications for monitored categories".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["categories"],
                        "properties": {
                            "categories": {"type": "array", "description": "List of arXiv categories to monitor"},
                            "keyword_filter": {"type": "string", "description": "Optional keyword filter applied to titles and abstracts"},
                            "since_ts": {"type": "string", "description": "ISO 8601 timestamp to resume from"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["papers"],
                        "properties": {
                            "papers": {"type": "array"},
                            "cursor_ts": {"type": "string", "description": "Cursor timestamp for next poll"}
                        }
                    }),
                    capability: CapabilityId::from_static("arxiv.monitor"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
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
                },
                OperationInfo {
                    id: OperationId::from_static("arxiv.monitor_query"),
                    summary: "Stream new papers matching a saved search query".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": {"type": "string", "description": "arXiv search query to monitor"},
                            "since_ts": {"type": "string", "description": "ISO 8601 timestamp to resume from"}
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["papers"],
                        "properties": {
                            "papers": {"type": "array"},
                            "cursor_ts": {"type": "string"}
                        }
                    }),
                    capability: CapabilityId::from_static("arxiv.monitor"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Monitor for new papers matching a specific search query.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"query": "ti:large language model AND cat:cs.CL"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("arxiv.monitor_category"),
                            CapabilityId::from_static("arxiv.search_papers"),
                        ],
                    },
                },
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
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
        let Some(operation) = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
        else {
            return Ok(simulate_denied("Missing operation_id", "FCP-1003"));
        };

        if !operation_supported(operation) {
            return Ok(simulate_denied(
                format!("Unknown operation: {operation}"),
                "FCP-1002",
            ));
        }

        if let Err(error) = self.base.check_ready() {
            return Ok(simulate_denied(error.to_string(), error.error_code()));
        }

        let empty_input = json!({});
        let input = params.get("input").unwrap_or(&empty_input);
        if let Err(error) = validate_simulate_input(operation, input) {
            let fcp_error = error.to_fcp_error();
            return Ok(simulate_denied(error.to_string(), fcp_error.error_code()));
        }

        Ok(json!({
            "allowed": true,
            "reason": "Operation supported",
        }))
    }

    /// Handle the `shutdown` method.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("arXiv connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
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

fn require_string_array(input: &serde_json::Value, field: &str) -> Result<(), ArxivError> {
    let values = input
        .get(field)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| ArxivError::InvalidInput {
            message: format!("Missing required field: {field}"),
        })?;

    if values.iter().any(serde_json::Value::is_string) {
        return Ok(());
    }

    Err(ArxivError::InvalidInput {
        message: format!("Field {field} must include at least one string"),
    })
}

fn operation_supported(operation: &str) -> bool {
    matches!(
        operation,
        "arxiv.search_papers"
            | "arxiv.search_semantic"
            | "arxiv.get_paper"
            | "arxiv.get_full_text"
            | "arxiv.download_pdf"
            | "arxiv.get_citations"
            | "arxiv.get_references"
            | "arxiv.extract_references"
            | "arxiv.get_author"
            | "arxiv.list_categories"
            | "arxiv.get_new_papers"
            | "arxiv.monitor_category"
            | "arxiv.monitor_query"
    )
}

fn validate_simulate_input(operation: &str, input: &serde_json::Value) -> Result<(), ArxivError> {
    match operation {
        "arxiv.search_papers" | "arxiv.search_semantic" | "arxiv.monitor_query" => {
            require_str(input, "query")?;
        }
        "arxiv.get_paper"
        | "arxiv.get_full_text"
        | "arxiv.download_pdf"
        | "arxiv.get_citations"
        | "arxiv.get_references"
        | "arxiv.extract_references" => {
            require_str(input, "arxiv_id")?;
        }
        "arxiv.get_author" => {
            require_str(input, "author_name")?;
        }
        "arxiv.list_categories" => {}
        "arxiv.get_new_papers" => {
            require_str(input, "category")?;
        }
        "arxiv.monitor_category" => {
            require_string_array(input, "categories")?;
        }
        _ => {
            return Err(ArxivError::InvalidInput {
                message: format!("Unknown operation: {operation}"),
            });
        }
    }

    Ok(())
}

fn simulate_denied(reason: impl Into<String>, denial_code: impl Into<String>) -> serde_json::Value {
    json!({
        "allowed": false,
        "reason": reason.into(),
        "denial_code": denial_code.into(),
    })
}

/// Build the provisioning recipe for the arXiv connector.
///
/// arXiv is open-access and does not require authentication, so the recipe
/// is simpler than OAuth-based connectors: it just confirms the base URL
/// and rate-limit configuration.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("arxiv.open_access"),
        "1",
        "Provision arXiv connector (open access, no credentials required)",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("confirm_base_url"),
        ProvisioningStepType::PromptUser {
            message: "Confirm arXiv API base URL (default: https://export.arxiv.org)".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("configure_rate_limit"),
            ProvisioningStepType::PromptUser {
                message: "Configure rate limit in requests/second (default: 3, max: 10). arXiv will IP-ban aggressive clients.".into(),
            },
        )
        .depends_on(StepId::new("confirm_base_url")),
    )
}

fn enforce_base_url_policy(field: &str, base_url: &str, allowed_hosts: &[&str]) -> FcpResult<()> {
    let (ok, message) = base_url_policy_for(field, base_url, allowed_hosts);
    if ok {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message,
        })
    }
}

fn base_url_policy(base_url: &str) -> (bool, String) {
    base_url_policy_for("arxiv_base_url", base_url, &["export.arxiv.org"])
}

#[cfg(test)]
fn scholar_base_url_policy(base_url: &str) -> (bool, String) {
    base_url_policy_for(
        "scholar_base_url",
        base_url,
        &["api.semanticscholar.org", "scholar.google.com"],
    )
}

fn base_url_policy_for(field: &str, base_url: &str, allowed_hosts: &[&str]) -> (bool, String) {
    let parsed = match Url::parse(base_url) {
        Ok(parsed) => parsed,
        Err(error) => {
            return (false, format!("{field} could not be parsed: {error}"));
        }
    };

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return (false, format!("{field} must not include userinfo"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return (
            false,
            format!("{field} must not include a query string or fragment"),
        );
    }

    let Some(host) = parsed.host_str() else {
        return (false, format!("{field} must include a host"));
    };

    let local = is_local_test_host(host);
    let allowed_host = allowed_hosts
        .iter()
        .any(|allowed_host| host.eq_ignore_ascii_case(allowed_host))
        || local;
    let secure_or_local = parsed.scheme() == "https" || local;

    if allowed_host && secure_or_local {
        (
            true,
            format!("Endpoint accepted by policy checks: {base_url}"),
        )
    } else {
        let allowed = allowed_hosts.join(" or ");
        (
            false,
            format!(
                "{field} must use https and {allowed} \
                 (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

/// Build the operations info for introspection.
#[allow(clippy::too_many_lines)]
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
        assert!((config.rate_limit_rps - 3.0).abs() < f64::EPSILON);
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

    #[fcp_async_core::runtime::test]
    async fn simulate_denies_unconfigured_supported_operation() {
        let connector = ArxivConnector::new();
        let result = connector
            .handle_simulate(json!({
                "operation_id": "arxiv.search_papers",
                "input": {"query": "capability tokens"},
            }))
            .await
            .unwrap();

        assert_eq!(result["allowed"].as_bool(), Some(false));
        assert_eq!(result["denial_code"].as_str(), Some("FCP-5002"));
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_denies_missing_required_input_when_ready() {
        let mut connector = ArxivConnector::new();
        connector.handle_configure(json!({})).await.unwrap();
        connector
            .handle_handshake(json!({"session_id": "test-session"}))
            .await
            .unwrap();

        let result = connector
            .handle_simulate(json!({
                "operation_id": "arxiv.search_papers",
                "input": {},
            }))
            .await
            .unwrap();

        assert_eq!(result["allowed"].as_bool(), Some(false));
        assert_eq!(result["denial_code"].as_str(), Some("FCP-1003"));
        assert!(
            result["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("Missing required field: query"))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_allows_ready_valid_input() {
        let mut connector = ArxivConnector::new();
        connector.handle_configure(json!({})).await.unwrap();
        connector
            .handle_handshake(json!({"session_id": "test-session"}))
            .await
            .unwrap();

        let result = connector
            .handle_simulate(json!({
                "operation_id": "arxiv.search_papers",
                "input": {"query": "capability tokens"},
            }))
            .await
            .unwrap();

        assert_eq!(result["allowed"].as_bool(), Some(true));
        assert_eq!(result["reason"].as_str(), Some("Operation supported"));
        assert!(result.get("denial_code").is_none());
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

    // ── Provisioning tests ───────────────────────────────────────────

    #[test]
    fn config_rate_limit_custom() {
        let config = ArxivConfig::from_params(&json!({"rate_limit_rps": 5.0}));
        assert!((config.rate_limit_rps - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn provisioning_readiness_default_config() {
        let config = ArxivConfig::from_params(&json!({}));
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_ok);
        assert!(readiness.rate_limit_configured);
        assert!(!readiness.has_scholar_key);
        assert!(readiness.network_message.contains("accepted"));
    }

    #[test]
    fn provisioning_readiness_with_scholar_key() {
        let config = ArxivConfig::from_params(&json!({"scholar_api_key": "key123"}));
        let readiness = config.provisioning_readiness();
        assert!(readiness.has_scholar_key);
    }

    #[test]
    fn provisioning_readiness_bad_rate_limit() {
        let config = ArxivConfig::from_params(&json!({"rate_limit_rps": 0.0}));
        let readiness = config.provisioning_readiness();
        assert!(!readiness.rate_limit_configured);
    }

    #[test]
    fn provisioning_readiness_excessive_rate_limit() {
        let config = ArxivConfig::from_params(&json!({"rate_limit_rps": 20.0}));
        let readiness = config.provisioning_readiness();
        assert!(!readiness.rate_limit_configured);
    }

    #[test]
    fn provisioning_readiness_bad_url_rejected() {
        let config =
            ArxivConfig::from_params(&json!({"arxiv_base_url": "https://evil.example.com"}));
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("export.arxiv.org"));
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = ArxivConfig::from_params(&json!({}));
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["network_ok"], true);
        assert_eq!(v["rate_limit_configured"], true);
        assert_eq!(v["has_scholar_key"], false);
    }

    #[test]
    fn provisioning_recipe_has_2_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "arxiv.open_access");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 2);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "confirm_base_url");
        assert_eq!(recipe.steps[1].id.as_str(), "configure_rate_limit");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "confirm_base_url");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "arxiv.open_access");
        assert_eq!(v["steps"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn base_url_policy_accepts_export_arxiv() {
        let (ok, message) = base_url_policy("https://export.arxiv.org");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn base_url_policy_rejects_arxiv_org() {
        let (ok, message) = base_url_policy("https://arxiv.org");
        assert!(!ok);
        assert!(message.contains("export.arxiv.org"));
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:8080");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_127_0_0_1() {
        let (ok, _) = base_url_policy("http://127.0.0.1:9090");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_http_non_local() {
        let (ok, message) = base_url_policy("http://export.arxiv.org");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("export.arxiv.org"));
    }

    #[test]
    fn base_url_policy_rejects_userinfo_query_and_fragment() {
        let (ok, message) = base_url_policy("https://user@export.arxiv.org");
        assert!(!ok);
        assert!(message.contains("userinfo"));

        let (ok, message) = base_url_policy("https://export.arxiv.org?leak=1");
        assert!(!ok);
        assert!(message.contains("query string or fragment"));

        let (ok, message) = base_url_policy("https://export.arxiv.org#frag");
        assert!(!ok);
        assert!(message.contains("query string or fragment"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn base_url_policy_accepts_ipv6_loopback() {
        let (ok, _) = base_url_policy("http://[::1]:8080");
        assert!(ok);
    }

    #[test]
    fn scholar_base_url_policy_accepts_allowed_hosts() {
        let (ok, message) = scholar_base_url_policy("https://api.semanticscholar.org/graph/v1");
        assert!(ok);
        assert!(message.contains("accepted"));

        let (ok, message) = scholar_base_url_policy("https://scholar.google.com");
        assert!(ok);
        assert!(message.contains("accepted"));
    }

    #[test]
    fn scholar_base_url_policy_rejects_unknown_host() {
        let (ok, message) = scholar_base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("scholar_base_url"));
        assert!(message.contains("scholar.google.com"));
    }
}
