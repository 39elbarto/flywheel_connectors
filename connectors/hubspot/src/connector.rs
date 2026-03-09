//! FCP `HubSpot` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, Introspection, OAuthRecipe, OperationId, OperationInfo, ProvisioningRecipe,
    ProvisioningStep, ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, SelfCheckReport,
    StepId, WebhookRecipe, WebhookVerification,
};
use reqwest::Url;
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

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                HubSpotAuth::BearerToken(_) => "bearer_token",
                HubSpotAuth::CredentialId(_) => "credential_id",
            },
            token_configured: matches!(&self.auth, HubSpotAuth::BearerToken(_)),
            credential_id_configured: self.auth.is_secretless(),
            requires_credential_injection: self.auth.is_secretless(),
            network_ok,
            network_message,
            base_url: self.base_url.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    token_configured: bool,
    credential_id_configured: bool,
    requires_credential_injection: bool,
    network_ok: bool,
    network_message: String,
    base_url: String,
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
                "hubspot.companies.write",
                "hubspot.deals.read",
                "hubspot.deals.write",
                "hubspot.pipelines.read",
                "hubspot.analytics.read",
                "hubspot.events.read",
                "hubspot.associations.read",
                "hubspot.associations.write"
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
        let Some(config) = &self.config else {
            let report =
                SelfCheckReport::degraded("not_configured", "Connector is not configured");
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

        let Some(_client) = &self.client else {
            let mut report = SelfCheckReport::failed(
                "client_missing",
                "API client not initialized; re-run configure",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        };

        if readiness.requires_credential_injection {
            let mut report = SelfCheckReport::degraded(
                "credential_injection_required",
                "credential_id mode requires egress proxy injection; skipping live probe",
            );
            report.details = Some(json!({ "provisioning": readiness }));
            return Self::serialize_self_check_report(report);
        }

        let mut report = SelfCheckReport::ok();
        report.details = Some(json!({ "provisioning": readiness }));
        Self::serialize_self_check_report(report)
    }

    /// Handle the `introspect` method.
    #[allow(clippy::too_many_lines)]
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("hubspot.contacts.list"),
                    summary: "List contacts with optional filtering and property selection".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": [],
                        "properties": {
                            "limit": { "type": "integer", "minimum": 1, "maximum": 100, "description": "Page size (max 100)" },
                            "after": { "type": "string", "description": "Pagination cursor" },
                            "properties": { "type": "array", "description": "List of contact properties to include" },
                            "filter_groups": { "type": "array", "description": "Filter groups for search (HubSpot filter syntax)" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["results"],
                        "properties": {
                            "results": { "type": "array" },
                            "paging": { "type": "object" }
                        }
                    }),
                    capability: CapabilityId::from_static("hubspot.contacts.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List or search contacts in HubSpot CRM.".into(),
                        common_mistakes: vec![
                            "Not specifying properties — only default properties are returned.".into(),
                            "Not handling pagination (use 'after' cursor from paging.next).".into(),
                        ],
                        examples: vec![
                            r#"{"limit": 50, "properties": ["email", "firstname", "lastname", "company"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.contacts.get"),
                            CapabilityId::from_static("hubspot.contacts.create"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.contacts.get"),
                    summary: "Get a single contact by ID".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["contact_id"],
                        "properties": {
                            "contact_id": { "type": "string", "description": "HubSpot contact ID" },
                            "properties": { "type": "array", "description": "List of properties to include" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["contact"],
                        "properties": { "contact": { "type": "object" } }
                    }),
                    capability: CapabilityId::from_static("hubspot.contacts.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Retrieve a specific contact by their HubSpot ID.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"contact_id": "12345", "properties": ["email", "firstname", "lastname"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.contacts.list"),
                            CapabilityId::from_static("hubspot.contacts.update"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.contacts.create"),
                    summary: "Create a new contact".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["properties"],
                        "properties": {
                            "properties": { "type": "object", "description": "Contact properties (email, firstname, lastname, etc.)" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["contact"],
                        "properties": { "contact": { "type": "object" } }
                    }),
                    capability: CapabilityId::from_static("hubspot.contacts.write"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Create a new contact in HubSpot CRM.".into(),
                        common_mistakes: vec![
                            "Creating duplicate contacts — check for existing email first.".into(),
                        ],
                        examples: vec![
                            r#"{"properties": {"email": "alice@example.com", "firstname": "Alice", "lastname": "Smith"}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.contacts.list"),
                            CapabilityId::from_static("hubspot.contacts.update"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.contacts.update"),
                    summary: "Update an existing contact's properties".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["contact_id", "properties"],
                        "properties": {
                            "contact_id": { "type": "string" },
                            "properties": { "type": "object" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["contact"],
                        "properties": { "contact": { "type": "object" } }
                    }),
                    capability: CapabilityId::from_static("hubspot.contacts.write"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Update properties on an existing contact.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"contact_id": "12345", "properties": {"phone": "+1-555-0100"}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.contacts.get"),
                            CapabilityId::from_static("hubspot.contacts.create"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.contacts.delete"),
                    summary: "Delete a contact from HubSpot".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["contact_id"],
                        "properties": { "contact_id": { "type": "string" } }
                    }),
                    output_schema: json!({ "type": "object" }),
                    capability: CapabilityId::from_static("hubspot.contacts.write"),
                    risk_level: RiskLevel::High,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Dangerous,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Permanently delete a contact. Cannot be undone.".into(),
                        common_mistakes: vec![
                            "Deleting contacts with active deals or associations.".into(),
                        ],
                        examples: vec![r#"{"contact_id": "12345"}"#.into()],
                        related: vec![CapabilityId::from_static("hubspot.contacts.get")],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.companies.list"),
                    summary: "List companies".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": [],
                        "properties": {
                            "limit": { "type": "integer", "minimum": 1, "maximum": 100 },
                            "after": { "type": "string" },
                            "properties": { "type": "array" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["results"],
                        "properties": { "results": { "type": "array" } }
                    }),
                    capability: CapabilityId::from_static("hubspot.companies.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List companies in HubSpot CRM.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"limit": 50, "properties": ["name", "domain", "industry"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.contacts.list"),
                            CapabilityId::from_static("hubspot.deals.list"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.companies.get"),
                    summary: "Get a single company by ID".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["company_id"],
                        "properties": {
                            "company_id": { "type": "string", "description": "HubSpot company ID" },
                            "properties": { "type": "array", "description": "List of properties to include" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["company"],
                        "properties": { "company": { "type": "object" } }
                    }),
                    capability: CapabilityId::from_static("hubspot.companies.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Retrieve a specific company by its HubSpot ID.".into(),
                        common_mistakes: vec![
                            "Not requesting specific properties — only default properties are returned without the properties parameter.".into(),
                        ],
                        examples: vec![
                            r#"{"company_id": "12345", "properties": ["name", "domain", "industry"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.companies.list"),
                            CapabilityId::from_static("hubspot.companies.update"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.companies.create"),
                    summary: "Create a new company".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["properties"],
                        "properties": {
                            "properties": { "type": "object", "description": "Company properties (name, domain, industry, etc.)" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["company"],
                        "properties": { "company": { "type": "object" } }
                    }),
                    capability: CapabilityId::from_static("hubspot.companies.write"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Create a new company in HubSpot CRM.".into(),
                        common_mistakes: vec![
                            "Creating duplicate companies — check for existing domain first.".into(),
                        ],
                        examples: vec![
                            r#"{"properties": {"name": "Acme Corp", "domain": "acme.com", "industry": "Technology"}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.companies.list"),
                            CapabilityId::from_static("hubspot.companies.update"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.companies.update"),
                    summary: "Update an existing company's properties".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["company_id", "properties"],
                        "properties": {
                            "company_id": { "type": "string" },
                            "properties": { "type": "object" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["company"],
                        "properties": { "company": { "type": "object" } }
                    }),
                    capability: CapabilityId::from_static("hubspot.companies.write"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Update properties on an existing company.".into(),
                        common_mistakes: vec![
                            "Using display labels instead of internal property names.".into(),
                        ],
                        examples: vec![
                            r#"{"company_id": "12345", "properties": {"industry": "SaaS"}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.companies.get"),
                            CapabilityId::from_static("hubspot.companies.create"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.contacts.search"),
                    summary: "Search contacts using HubSpot filter groups".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": [],
                        "properties": {
                            "filter_groups": { "type": "array", "description": "Filter groups for search (HubSpot filter syntax)" },
                            "query": { "type": "string", "description": "Full-text search query" },
                            "properties": { "type": "array", "description": "List of properties to include in results" },
                            "limit": { "type": "integer", "minimum": 1, "maximum": 100, "description": "Page size (max 100)" },
                            "after": { "type": "string", "description": "Pagination cursor" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["results"],
                        "properties": {
                            "results": { "type": "array" },
                            "paging": { "type": "object" },
                            "total": { "type": "integer" }
                        }
                    }),
                    capability: CapabilityId::from_static("hubspot.contacts.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Search contacts using filter groups or full-text query.".into(),
                        common_mistakes: vec![
                            "Not specifying properties — only default properties are returned.".into(),
                        ],
                        examples: vec![
                            r#"{"filter_groups": [{"filters": [{"propertyName": "email", "operator": "CONTAINS_TOKEN", "value": "example.com"}]}], "properties": ["email", "firstname"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.contacts.list"),
                            CapabilityId::from_static("hubspot.contacts.get"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.companies.search"),
                    summary: "Search companies using HubSpot filter groups".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": [],
                        "properties": {
                            "filter_groups": { "type": "array", "description": "Filter groups for search (HubSpot filter syntax)" },
                            "query": { "type": "string", "description": "Full-text search query" },
                            "properties": { "type": "array", "description": "List of properties to include in results" },
                            "limit": { "type": "integer", "minimum": 1, "maximum": 100, "description": "Page size (max 100)" },
                            "after": { "type": "string", "description": "Pagination cursor" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["results"],
                        "properties": {
                            "results": { "type": "array" },
                            "paging": { "type": "object" },
                            "total": { "type": "integer" }
                        }
                    }),
                    capability: CapabilityId::from_static("hubspot.companies.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Search companies using filter groups or full-text query.".into(),
                        common_mistakes: vec![
                            "Not specifying properties — only default properties are returned.".into(),
                        ],
                        examples: vec![
                            r#"{"filter_groups": [{"filters": [{"propertyName": "domain", "operator": "EQ", "value": "acme.com"}]}], "properties": ["name", "domain"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.companies.list"),
                            CapabilityId::from_static("hubspot.companies.get"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.association.get"),
                    summary: "Get associations between CRM objects".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["from_object_type", "from_object_id", "to_object_type"],
                        "properties": {
                            "from_object_type": { "type": "string", "description": "Source object type (contacts, companies, deals, tickets)" },
                            "from_object_id": { "type": "string", "description": "Source object ID" },
                            "to_object_type": { "type": "string", "description": "Target object type (contacts, companies, deals, tickets)" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["results"],
                        "properties": {
                            "results": { "type": "array" }
                        }
                    }),
                    capability: CapabilityId::from_static("hubspot.associations.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Get associations between CRM objects (e.g. contacts associated with a company).".into(),
                        common_mistakes: vec![
                            "Using wrong object type names — use plural forms: contacts, companies, deals, tickets.".into(),
                        ],
                        examples: vec![
                            r#"{"from_object_type": "companies", "from_object_id": "12345", "to_object_type": "contacts"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.companies.get"),
                            CapabilityId::from_static("hubspot.contacts.get"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.deals.list"),
                    summary: "List deals with optional pipeline and stage filtering".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": [],
                        "properties": {
                            "limit": { "type": "integer", "minimum": 1, "maximum": 100 },
                            "after": { "type": "string" },
                            "properties": { "type": "array" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["results"],
                        "properties": { "results": { "type": "array" } }
                    }),
                    capability: CapabilityId::from_static("hubspot.deals.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List deals in the CRM, optionally filtered by pipeline or stage.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"limit": 50, "properties": ["dealname", "amount", "dealstage", "pipeline"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.deals.create"),
                            CapabilityId::from_static("hubspot.pipelines.list"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.deals.create"),
                    summary: "Create a new deal".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["properties"],
                        "properties": {
                            "properties": { "type": "object", "description": "Deal properties (dealname, amount, pipeline, dealstage, etc.)" },
                            "associations": { "type": "array", "description": "Associate with contacts, companies, etc." }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["deal"],
                        "properties": { "deal": { "type": "object" } }
                    }),
                    capability: CapabilityId::from_static("hubspot.deals.write"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Create a new deal in a sales pipeline.".into(),
                        common_mistakes: vec![
                            "Not specifying pipeline and dealstage (defaults may not match expected workflow).".into(),
                        ],
                        examples: vec![
                            r#"{"properties": {"dealname": "Enterprise License", "amount": "50000", "pipeline": "default", "dealstage": "qualifiedtobuy"}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.deals.list"),
                            CapabilityId::from_static("hubspot.pipelines.list"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.deals.get"),
                    summary: "Get a single deal by ID".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["deal_id"],
                        "properties": {
                            "deal_id": { "type": "string", "description": "HubSpot deal ID" },
                            "properties": { "type": "array", "description": "List of properties to include" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["deal"],
                        "properties": { "deal": { "type": "object" } }
                    }),
                    capability: CapabilityId::from_static("hubspot.deals.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Retrieve a specific deal by its HubSpot ID.".into(),
                        common_mistakes: vec![
                            "Not requesting specific properties — only default properties are returned without the properties parameter.".into(),
                        ],
                        examples: vec![
                            r#"{"deal_id": "12345", "properties": ["dealname", "amount", "dealstage"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.deals.list"),
                            CapabilityId::from_static("hubspot.deals.update"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.deals.update"),
                    summary: "Update an existing deal's properties".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["deal_id", "properties"],
                        "properties": {
                            "deal_id": { "type": "string", "description": "HubSpot deal ID" },
                            "properties": { "type": "object", "description": "Deal properties to update" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["deal"],
                        "properties": { "deal": { "type": "object" } }
                    }),
                    capability: CapabilityId::from_static("hubspot.deals.write"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Update properties on an existing deal.".into(),
                        common_mistakes: vec![
                            "Using display labels instead of internal property names.".into(),
                        ],
                        examples: vec![
                            r#"{"deal_id": "12345", "properties": {"amount": "75000"}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.deals.get"),
                            CapabilityId::from_static("hubspot.deals.create"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.deals.search"),
                    summary: "Search deals using HubSpot filter groups".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": [],
                        "properties": {
                            "filter_groups": { "type": "array", "description": "Filter groups for search (HubSpot filter syntax)" },
                            "query": { "type": "string", "description": "Full-text search query" },
                            "properties": { "type": "array", "description": "List of properties to include in results" },
                            "limit": { "type": "integer", "minimum": 1, "maximum": 100, "description": "Page size (max 100)" },
                            "after": { "type": "string", "description": "Pagination cursor" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["results"],
                        "properties": {
                            "results": { "type": "array" },
                            "paging": { "type": "object" },
                            "total": { "type": "integer" }
                        }
                    }),
                    capability: CapabilityId::from_static("hubspot.deals.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Search deals using filter groups or full-text query.".into(),
                        common_mistakes: vec![
                            "Not specifying properties — only default properties are returned.".into(),
                        ],
                        examples: vec![
                            r#"{"filter_groups": [{"filters": [{"propertyName": "dealstage", "operator": "EQ", "value": "closedwon"}]}], "properties": ["dealname", "amount"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.deals.list"),
                            CapabilityId::from_static("hubspot.deals.get"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.deals.set_stage"),
                    summary: "Move a deal to a specific pipeline stage".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["deal_id", "dealstage"],
                        "properties": {
                            "deal_id": { "type": "string", "description": "HubSpot deal ID" },
                            "dealstage": { "type": "string", "description": "Target pipeline stage ID" },
                            "pipeline": { "type": "string", "description": "Pipeline ID (optional, defaults to current pipeline)" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["deal"],
                        "properties": { "deal": { "type": "object" } }
                    }),
                    capability: CapabilityId::from_static("hubspot.deals.write"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Move a deal to a specific pipeline stage (e.g. qualified, closed-won).".into(),
                        common_mistakes: vec![
                            "Using stage labels instead of stage IDs — use pipelines.list to find stage IDs.".into(),
                        ],
                        examples: vec![
                            r#"{"deal_id": "12345", "dealstage": "closedwon"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.deals.get"),
                            CapabilityId::from_static("hubspot.pipelines.list"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.deals.associate"),
                    summary: "Create an association between a deal and another CRM object".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["deal_id", "to_object_type", "to_object_id", "association_type"],
                        "properties": {
                            "deal_id": { "type": "string", "description": "HubSpot deal ID" },
                            "to_object_type": { "type": "string", "description": "Target object type (contacts, companies, tickets)" },
                            "to_object_id": { "type": "string", "description": "Target object ID" },
                            "association_type": { "type": "string", "description": "HubSpot association type ID (e.g. deal_to_contact)" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": { "result": { "type": "object" } }
                    }),
                    capability: CapabilityId::from_static("hubspot.associations.write"),
                    risk_level: RiskLevel::Medium,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Risky,
                    idempotency: IdempotencyClass::None,
                    ai_hints: AgentHint {
                        when_to_use: "Create an association between a deal and another CRM object (contact, company, ticket).".into(),
                        common_mistakes: vec![
                            "Using wrong association_type — check HubSpot docs for valid association type IDs.".into(),
                        ],
                        examples: vec![
                            r#"{"deal_id": "12345", "to_object_type": "contacts", "to_object_id": "67890", "association_type": "deal_to_contact"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.deals.get"),
                            CapabilityId::from_static("hubspot.association.get"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.pipelines.list"),
                    summary: "List pipelines and their stages".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["object_type"],
                        "properties": {
                            "object_type": { "type": "string", "description": "Object type: deals or tickets" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["pipelines"],
                        "properties": { "pipelines": { "type": "array" } }
                    }),
                    capability: CapabilityId::from_static("hubspot.pipelines.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List available pipelines and their stages to understand the deal/ticket workflow.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"object_type": "deals"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("hubspot.deals.list"),
                            CapabilityId::from_static("hubspot.deals.create"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.analytics.report"),
                    summary: "Get pipeline analytics and reporting data".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": ["report_type"],
                        "properties": {
                            "report_type": { "type": "string", "description": "Report type: deal_forecast, conversion_funnel, activity_summary" },
                            "pipeline_id": { "type": "string", "description": "Restrict to a specific pipeline" },
                            "date_range": { "type": "object", "description": "Date range for the report" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["report"],
                        "properties": { "report": { "type": "object" } }
                    }),
                    capability: CapabilityId::from_static("hubspot.analytics.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Get pipeline analytics reports: forecasts, conversion funnels, activity summaries.".into(),
                        common_mistakes: vec![
                            "Not specifying date_range — defaults may return more data than expected.".into(),
                        ],
                        examples: vec![
                            r#"{"report_type": "deal_forecast", "pipeline_id": "default"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.pipelines.list"),
                            CapabilityId::from_static("hubspot.deals.list"),
                        ],
                    },
                },
                OperationInfo {
                    id: OperationId::from_static("hubspot.events.stream"),
                    summary: "Stream CRM webhook events".into(),
                    input_schema: json!({
                        "type": "object",
                        "required": [],
                        "properties": {
                            "object_types": { "type": "array", "description": "Object types to subscribe to (contacts, deals, companies, tickets)" },
                            "since_ts": { "type": "string", "description": "ISO 8601 timestamp to resume from" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "required": ["events"],
                        "properties": { "events": { "type": "array" } }
                    }),
                    capability: CapabilityId::from_static("hubspot.events.read"),
                    risk_level: RiskLevel::Low,
                    description: None,
                    rate_limit: None,
                    requires_approval: None,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Stream real-time CRM changes via HubSpot webhooks.".into(),
                        common_mistakes: vec![
                            "Not validating webhook signatures.".into(),
                            "Not persisting cursor for idempotent event processing.".into(),
                        ],
                        examples: vec![
                            r#"{"object_types": ["contacts", "deals"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("hubspot.contacts.list"),
                            CapabilityId::from_static("hubspot.deals.list"),
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
            "hubspot.companies.get" => self.invoke_companies_get(client, &input).await,
            "hubspot.companies.create" => self.invoke_companies_create(client, &input).await,
            "hubspot.companies.update" => self.invoke_companies_update(client, &input).await,
            "hubspot.contacts.search" => self.invoke_contacts_search(client, &input).await,
            "hubspot.companies.search" => self.invoke_companies_search(client, &input).await,
            "hubspot.association.get" => self.invoke_association_get(client, &input).await,
            "hubspot.deals.list" => self.invoke_deals_list(client, &input).await,
            "hubspot.deals.create" => self.invoke_deals_create(client, &input).await,
            "hubspot.deals.get" => self.invoke_deals_get(client, &input).await,
            "hubspot.deals.update" => self.invoke_deals_update(client, &input).await,
            "hubspot.deals.search" => self.invoke_deals_search(client, &input).await,
            "hubspot.deals.set_stage" => self.invoke_deals_set_stage(client, &input).await,
            "hubspot.deals.associate" => self.invoke_deals_associate(client, &input).await,
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

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "hubspot.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "HubSpot self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
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

    async fn invoke_companies_get(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let company_id = require_str(input, "company_id")?;
        let properties = extract_string_array(input, "properties");
        let data = client.get_company(company_id, properties.as_deref()).await?;
        Ok(json!({ "company": data }))
    }

    async fn invoke_companies_create(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let properties = input.get("properties").ok_or(HubSpotError::Api {
            status_code: 400,
            message: "Missing required field: properties".into(),
        })?;
        let body = json!({ "properties": properties });
        let data = client.create_company(&body).await?;
        Ok(json!({ "company": data }))
    }

    async fn invoke_companies_update(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let company_id = require_str(input, "company_id")?;
        let properties = input.get("properties").ok_or(HubSpotError::Api {
            status_code: 400,
            message: "Missing required field: properties".into(),
        })?;
        let body = json!({ "properties": properties });
        let data = client.update_company(company_id, &body).await?;
        Ok(json!({ "company": data }))
    }

    async fn invoke_contacts_search(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let mut body = json!({});
        if let Some(filter_groups) = input.get("filter_groups") {
            body["filterGroups"] = filter_groups.clone();
        }
        if let Some(properties) = input.get("properties") {
            body["properties"] = properties.clone();
        }
        if let Some(limit) = input.get("limit") {
            body["limit"] = limit.clone();
        }
        if let Some(after) = input.get("after") {
            body["after"] = after.clone();
        }
        if let Some(query) = input.get("query") {
            body["query"] = query.clone();
        }
        client.search_contacts(&body).await
    }

    async fn invoke_companies_search(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let mut body = json!({});
        if let Some(filter_groups) = input.get("filter_groups") {
            body["filterGroups"] = filter_groups.clone();
        }
        if let Some(properties) = input.get("properties") {
            body["properties"] = properties.clone();
        }
        if let Some(limit) = input.get("limit") {
            body["limit"] = limit.clone();
        }
        if let Some(after) = input.get("after") {
            body["after"] = after.clone();
        }
        if let Some(query) = input.get("query") {
            body["query"] = query.clone();
        }
        client.search_companies(&body).await
    }

    async fn invoke_association_get(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let from_object_type = require_str(input, "from_object_type")?;
        let from_object_id = require_str(input, "from_object_id")?;
        let to_object_type = require_str(input, "to_object_type")?;
        client.get_associations(from_object_type, from_object_id, to_object_type).await
    }

    async fn invoke_deals_list(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let limit = input.get("limit").and_then(|v| v.as_i64());
        let after = input.get("after").and_then(|v| v.as_str());
        let properties = extract_string_array(input, "properties");
        client.list_deals(limit, after, properties.as_deref()).await
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

    async fn invoke_deals_get(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let deal_id = require_str(input, "deal_id")?;
        let properties = extract_string_array(input, "properties");
        let data = client.get_deal(deal_id, properties.as_deref()).await?;
        Ok(json!({ "deal": data }))
    }

    async fn invoke_deals_update(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let deal_id = require_str(input, "deal_id")?;
        let properties = input.get("properties").ok_or(HubSpotError::Api {
            status_code: 400,
            message: "Missing required field: properties".into(),
        })?;
        let body = json!({ "properties": properties });
        let data = client.update_deal(deal_id, &body).await?;
        Ok(json!({ "deal": data }))
    }

    async fn invoke_deals_search(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let mut body = json!({});
        if let Some(filter_groups) = input.get("filter_groups") {
            body["filterGroups"] = filter_groups.clone();
        }
        if let Some(properties) = input.get("properties") {
            body["properties"] = properties.clone();
        }
        if let Some(limit) = input.get("limit") {
            body["limit"] = limit.clone();
        }
        if let Some(after) = input.get("after") {
            body["after"] = after.clone();
        }
        if let Some(query) = input.get("query") {
            body["query"] = query.clone();
        }
        client.search_deals(&body).await
    }

    async fn invoke_deals_set_stage(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let deal_id = require_str(input, "deal_id")?;
        let dealstage = require_str(input, "dealstage")?;
        let mut props = json!({ "dealstage": dealstage });
        if let Some(pipeline) = input.get("pipeline").and_then(|v| v.as_str()) {
            props["pipeline"] = json!(pipeline);
        }
        let body = json!({ "properties": props });
        let data = client.update_deal(deal_id, &body).await?;
        Ok(json!({ "deal": data }))
    }

    async fn invoke_deals_associate(
        &self,
        client: &HubSpotClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, HubSpotError> {
        let deal_id = require_str(input, "deal_id")?;
        let to_object_type = require_str(input, "to_object_type")?;
        let to_object_id = require_str(input, "to_object_id")?;
        let association_type = require_str(input, "association_type")?;
        client
            .create_association("deals", deal_id, to_object_type, to_object_id, association_type)
            .await
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

/// Build the provisioning recipe for the `HubSpot` connector.
///
/// Uses `OAuth2` Authorization Code with PKCE for browser-based interactive
/// setup, plus a webhook registration step for CRM object change notifications.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("hubspot.oauth2_pkce"),
        "1",
        "Provision HubSpot connector with OAuth2 Authorization Code + PKCE",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("oauth_authorize"),
        ProvisioningStepType::Oauth {
            flow: OAuthRecipe::AuthorizationCodePkce {
                authorization_url: "https://app.hubspot.com/oauth/authorize".into(),
                token_url: "https://api.hubapi.com/oauth/v1/token".into(),
                scopes: vec![
                    "crm.objects.contacts.read".into(),
                    "crm.objects.deals.read".into(),
                    "crm.objects.companies.read".into(),
                ],
                auto_browser: true,
                callback_port: 9807,
            },
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_token"),
            ProvisioningStepType::StoreSecret {
                key: "access_token".into(),
                value_from: StepId::new("oauth_authorize"),
                scope: "connector:fcp.hubspot".into(),
            },
        )
        .depends_on(StepId::new("oauth_authorize")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("register_webhooks"),
            ProvisioningStepType::Webhook {
                registration: WebhookRecipe {
                    registration_url:
                        "https://api.hubapi.com/webhooks/v3/{appId}/subscriptions".into(),
                    events: vec![
                        "contact.creation".into(),
                        "contact.propertyChange".into(),
                        "deal.creation".into(),
                        "deal.propertyChange".into(),
                        "company.creation".into(),
                        "company.propertyChange".into(),
                    ],
                    verification: WebhookVerification::HmacSignature {
                        algorithm: "sha256".into(),
                        header: "X-HubSpot-Signature-v3".into(),
                    },
                    retry_policy: fcp_core::RetryConfig::default(),
                },
            },
        )
        .depends_on(StepId::new("store_token")),
    )
}

fn base_url_policy(base_url: &str) -> (bool, String) {
    let parsed = match Url::parse(base_url) {
        Ok(parsed) => parsed,
        Err(error) => {
            return (false, format!("base_url could not be parsed: {error}"));
        }
    };

    let Some(host) = parsed.host_str() else {
        return (false, "base_url must include a host".into());
    };

    let local = is_local_test_host(host);
    let allowed_host = host.eq_ignore_ascii_case("api.hubapi.com")
        || host.eq_ignore_ascii_case("api.hubspot.com")
        || local;
    let secure_or_local = parsed.scheme() == "https" || local;

    if allowed_host && secure_or_local {
        (
            true,
            format!("Endpoint accepted by policy checks: {base_url}"),
        )
    } else {
        (
            false,
            format!(
                "Endpoint must use https and api.hubapi.com or api.hubspot.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
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
            "id": "hubspot.companies.get",
            "summary": "Get a single company by ID",
            "capability": "hubspot.companies.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "hubspot.companies.create",
            "summary": "Create a new company",
            "capability": "hubspot.companies.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "hubspot.companies.update",
            "summary": "Update an existing company's properties",
            "capability": "hubspot.companies.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "strict",
        },
        {
            "id": "hubspot.contacts.search",
            "summary": "Search contacts using HubSpot filter groups",
            "capability": "hubspot.contacts.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "hubspot.companies.search",
            "summary": "Search companies using HubSpot filter groups",
            "capability": "hubspot.companies.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "hubspot.association.get",
            "summary": "Get associations between CRM objects",
            "capability": "hubspot.associations.read",
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
            "id": "hubspot.deals.get",
            "summary": "Get a single deal by ID",
            "capability": "hubspot.deals.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "hubspot.deals.update",
            "summary": "Update an existing deal's properties",
            "capability": "hubspot.deals.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "strict",
        },
        {
            "id": "hubspot.deals.search",
            "summary": "Search deals using HubSpot filter groups",
            "capability": "hubspot.deals.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "hubspot.deals.set_stage",
            "summary": "Move a deal to a specific pipeline stage",
            "capability": "hubspot.deals.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "strict",
        },
        {
            "id": "hubspot.deals.associate",
            "summary": "Create an association between a deal and another CRM object",
            "capability": "hubspot.associations.write",
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
    fn operations_info_has_22_operations() {
        let ops = operations_info();
        assert_eq!(ops.as_array().unwrap().len(), 22);
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
    fn config_trims_token() {
        let config =
            HubSpotConfig::from_params(&json!({ "access_token": "  pat-na1-test  " })).unwrap();
        match &config.auth {
            HubSpotAuth::BearerToken(t) => assert_eq!(t, "pat-na1-test"),
            HubSpotAuth::CredentialId(_) => panic!("expected BearerToken"),
        }
    }

    #[test]
    fn config_rejects_invalid_credential_id() {
        let result = HubSpotConfig::from_params(&json!({ "credential_id": "not-a-uuid" }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = HubSpotConfig::from_params(&json!({ "credential_id": 12345 }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_wrong_type() {
        let input = json!({"field": 42});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"field": null});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn extract_string_array_filters_non_strings() {
        let input = json!({"tags": ["a", 1, "b", null]});
        let arr = extract_string_array(&input, "tags").unwrap();
        assert_eq!(arr, vec!["a", "b"]);
    }

    #[test]
    fn extract_string_array_empty() {
        let input = json!({"tags": []});
        let arr = extract_string_array(&input, "tags").unwrap();
        assert!(arr.is_empty());
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
    fn operations_ids_all_prefixed_hubspot() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("hubspot."),
                "op {id} missing hubspot. prefix"
            );
        }
    }

    #[test]
    fn doctor_result_degraded() {
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
    fn doctor_result_all_pass() {
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
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = HubSpotConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[test]
    fn connector_default_counters() {
        let c = HubSpotConnector::default();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn connector_default_session() {
        let c = HubSpotConnector::default();
        assert!(c.session_id.is_none());
    }

    // ── DoctorStatus serde ──────────────────────────────────────────

    #[test]
    fn doctor_status_healthy_serde() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let ds: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(ds, DoctorStatus::Healthy);
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

    #[test]
    fn doctor_status_eq() {
        assert_eq!(DoctorStatus::Healthy, DoctorStatus::Healthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
        assert_ne!(DoctorStatus::Degraded, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy() {
        let s = DoctorStatus::Degraded;
        let s2 = s;
        assert_eq!(s, s2);
    }

    // ── DoctorCheck serde ───────────────────────────────────────────

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
            message: Some("fail".into()),
            critical: true,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["message"], "fail");
    }

    #[test]
    fn doctor_check_roundtrip() {
        let c = DoctorCheck {
            name: "cfg".into(),
            passed: true,
            message: None,
            critical: true,
        };
        let v = serde_json::to_value(&c).unwrap();
        let c2: DoctorCheck = serde_json::from_value(v).unwrap();
        assert_eq!(c2.name, "cfg");
        assert!(c2.passed);
    }

    // ── DoctorResult serde ──────────────────────────────────────────

    #[test]
    fn doctor_result_roundtrip() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        let r2: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r2.status, DoctorStatus::Healthy);
        assert_eq!(r2.checks.len(), 1);
    }

    #[test]
    fn doctor_result_serializes_message_none() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "cfg".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        assert!(
            v["checks"][0].as_object().unwrap().get("message").is_none()
                || v["checks"][0]["message"].is_null()
        );
    }

    // ── Config edge cases ───────────────────────────────────────────

    #[test]
    fn config_error_both_code() {
        let result = HubSpotConfig::from_params(&json!({
            "access_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }));
        match result.unwrap_err() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert!(message.contains("exactly one"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_error_none_code() {
        let result = HubSpotConfig::from_params(&json!({}));
        match result.unwrap_err() {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert!(message.contains("Missing"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    // ── require_str edge cases ──────────────────────────────────────

    #[test]
    fn require_str_empty_string() {
        let input = json!({"field": ""});
        assert_eq!(require_str(&input, "field").unwrap(), "");
    }

    #[test]
    fn require_str_boolean() {
        let input = json!({"flag": true});
        assert!(require_str(&input, "flag").is_err());
    }

    #[test]
    fn require_str_array() {
        let input = json!({"arr": [1, 2]});
        assert!(require_str(&input, "arr").is_err());
    }

    // ── extract_string_array edge cases ─────────────────────────────

    #[test]
    fn extract_string_array_not_array() {
        let input = json!({"props": "not_array"});
        assert!(extract_string_array(&input, "props").is_none());
    }

    #[test]
    fn extract_string_array_all_non_strings() {
        let input = json!({"tags": [1, 2, null, true]});
        let arr = extract_string_array(&input, "tags").unwrap();
        assert!(arr.is_empty());
    }

    // ── operations edge cases ───────────────────────────────────────

    #[test]
    fn operations_contacts_list_is_safe() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "hubspot.contacts.list")
            .unwrap();
        assert_eq!(op["safety_tier"], "safe");
        assert_eq!(op["risk_level"], "low");
    }

    #[test]
    fn operations_contacts_delete_is_dangerous() {
        let ops = operations_info();
        let op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "hubspot.contacts.delete")
            .unwrap();
        assert_eq!(op["safety_tier"], "dangerous");
        assert_eq!(op["risk_level"], "high");
    }

    #[test]
    fn operations_valid_idempotency_values() {
        let valid = ["strict", "best_effort", "none"];
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
    fn operations_expected_ids_present() {
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        let expected = [
            "hubspot.contacts.list",
            "hubspot.contacts.get",
            "hubspot.contacts.create",
            "hubspot.contacts.update",
            "hubspot.contacts.delete",
            "hubspot.companies.list",
            "hubspot.deals.list",
            "hubspot.deals.create",
            "hubspot.pipelines.list",
            "hubspot.analytics.report",
            "hubspot.events.stream",
        ];
        for e in &expected {
            assert!(ids.contains(e), "missing expected operation {e}");
        }
    }

    // ── Additional connector tests ────────────────────────────────

    #[test]
    fn operations_all_summaries_non_empty() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {:?} has empty summary", op["id"]);
        }
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
    fn doctor_result_debug_format() {
        let r = DoctorResult::from_checks(vec![]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DoctorResult"));
    }

    #[test]
    fn doctor_check_clone() {
        let c = DoctorCheck {
            name: "connectivity".into(),
            passed: true,
            message: Some("connected".into()),
            critical: false,
        };
        let cloned = c.clone();
        assert_eq!(cloned.name, c.name);
        assert_eq!(cloned.passed, c.passed);
        assert_eq!(cloned.message, c.message);
    }

    #[test]
    fn require_str_error_contains_field_name() {
        let input = json!({});
        let err = require_str(&input, "contact_id").unwrap_err();
        match err {
            HubSpotError::Api { message, .. } => {
                assert!(message.contains("contact_id"));
            }
            e => panic!("expected Api, got {e:?}"),
        }
    }

    #[test]
    fn require_str_float_value() {
        let input = json!({"field": 1.23});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_nested_object() {
        let input = json!({"field": {"a": {"b": "c"}}});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn extract_string_array_nested_objects() {
        let input = json!({"tags": [{"key": "val"}, "str"]});
        let arr = extract_string_array(&input, "tags").unwrap();
        assert_eq!(arr, vec!["str"]);
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
    }

    #[test]
    fn doctor_status_deserialize() {
        let s: DoctorStatus = serde_json::from_value(json!("healthy")).unwrap();
        assert_eq!(s, DoctorStatus::Healthy);
        let s: DoctorStatus = serde_json::from_value(json!("degraded")).unwrap();
        assert_eq!(s, DoctorStatus::Degraded);
        let s: DoctorStatus = serde_json::from_value(json!("unhealthy")).unwrap();
        assert_eq!(s, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy_semantics() {
        let status = DoctorStatus::Healthy;
        let copied = status;
        assert_eq!(status, copied);
    }

    #[test]
    fn doctor_status_eq_and_ne() {
        assert_eq!(DoctorStatus::Healthy, DoctorStatus::Healthy);
        assert_ne!(DoctorStatus::Healthy, DoctorStatus::Degraded);
        assert_ne!(DoctorStatus::Degraded, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_check_debug_format() {
        let c = DoctorCheck {
            name: "api_check".into(),
            passed: false,
            message: Some("timeout".into()),
            critical: true,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("api_check"));
        assert!(dbg.contains("timeout"));
    }

    #[test]
    fn doctor_result_clone_preserves_status() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "x".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = r.clone();
        assert_eq!(r.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
    }

    #[test]
    fn operations_all_have_capabilities() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(!cap.is_empty(), "op {:?} has empty capability", op["id"]);
        }
    }

    #[test]
    fn operations_ids_all_start_with_hubspot() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("hubspot."),
                "op {id} should start with hubspot."
            );
        }
    }

    // ── Provisioning tests ───────────────────────────────────────────

    #[test]
    fn provisioning_recipe_has_correct_id() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "hubspot.oauth2_pkce");
    }

    #[test]
    fn provisioning_recipe_has_three_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps.len(), 3);
    }

    #[test]
    fn provisioning_recipe_step_ids() {
        let recipe = provisioning_recipe();
        let ids: Vec<&str> = recipe.steps.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["oauth_authorize", "store_token", "register_webhooks"]);
    }

    #[test]
    fn provisioning_recipe_oauth_step_is_pkce() {
        let recipe = provisioning_recipe();
        let oauth_step = &recipe.steps[0];
        match &oauth_step.kind {
            ProvisioningStepType::Oauth { flow } => match flow {
                OAuthRecipe::AuthorizationCodePkce {
                    authorization_url,
                    token_url,
                    scopes,
                    ..
                } => {
                    assert_eq!(
                        authorization_url,
                        "https://app.hubspot.com/oauth/authorize"
                    );
                    assert_eq!(token_url, "https://api.hubapi.com/oauth/v1/token");
                    assert!(scopes.contains(&"crm.objects.contacts.read".to_string()));
                    assert!(scopes.contains(&"crm.objects.deals.read".to_string()));
                    assert!(scopes.contains(&"crm.objects.companies.read".to_string()));
                }
                other => panic!("expected AuthorizationCodePkce, got {other:?}"),
            },
            other => panic!("expected Oauth step, got {other:?}"),
        }
    }

    #[test]
    fn provisioning_recipe_store_step_depends_on_oauth() {
        let recipe = provisioning_recipe();
        let store_step = &recipe.steps[1];
        assert!(store_step
            .depends_on
            .iter()
            .any(|d| d.as_str() == "oauth_authorize"));
    }

    #[test]
    fn provisioning_recipe_webhook_step_depends_on_store() {
        let recipe = provisioning_recipe();
        let webhook_step = &recipe.steps[2];
        assert!(webhook_step
            .depends_on
            .iter()
            .any(|d| d.as_str() == "store_token"));
    }

    #[test]
    fn provisioning_recipe_webhook_events() {
        let recipe = provisioning_recipe();
        let webhook_step = &recipe.steps[2];
        match &webhook_step.kind {
            ProvisioningStepType::Webhook { registration } => {
                assert!(registration.events.contains(&"contact.creation".to_string()));
                assert!(registration
                    .events
                    .contains(&"deal.propertyChange".to_string()));
                assert_eq!(registration.events.len(), 6);
            }
            other => panic!("expected Webhook step, got {other:?}"),
        }
    }

    #[test]
    fn provisioning_recipe_webhook_hmac_verification() {
        let recipe = provisioning_recipe();
        let webhook_step = &recipe.steps[2];
        match &webhook_step.kind {
            ProvisioningStepType::Webhook { registration } => match &registration.verification {
                WebhookVerification::HmacSignature { algorithm, header } => {
                    assert_eq!(algorithm, "sha256");
                    assert_eq!(header, "X-HubSpot-Signature-v3");
                }
                other => panic!("expected HmacSignature, got {other:?}"),
            },
            other => panic!("expected Webhook step, got {other:?}"),
        }
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "hubspot.oauth2_pkce");
        assert_eq!(v["version"], "1");
        assert!(v["description"]
            .as_str()
            .unwrap()
            .contains("OAuth2"));
    }

    // ── base_url_policy tests ────────────────────────────────────────

    #[test]
    fn base_url_policy_accepts_hubapi() {
        let (ok, msg) = base_url_policy("https://api.hubapi.com");
        assert!(ok, "should accept api.hubapi.com: {msg}");
    }

    #[test]
    fn base_url_policy_accepts_hubspot_api() {
        let (ok, msg) = base_url_policy("https://api.hubspot.com");
        assert!(ok, "should accept api.hubspot.com: {msg}");
    }

    #[test]
    fn base_url_policy_accepts_localhost() {
        let (ok, _) = base_url_policy("http://localhost:8080");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_accepts_loopback() {
        let (ok, _) = base_url_policy("http://127.0.0.1:9999");
        assert!(ok);
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, msg) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(msg.contains("api.hubapi.com"));
    }

    #[test]
    fn base_url_policy_rejects_http_non_local() {
        let (ok, _) = base_url_policy("http://api.hubapi.com");
        assert!(!ok);
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, msg) = base_url_policy("not a url");
        assert!(!ok);
        assert!(msg.contains("could not be parsed"));
    }

    // ── ProvisioningReadiness tests ──────────────────────────────────

    #[test]
    fn provisioning_readiness_bearer_token() {
        let config =
            HubSpotConfig::from_params(&json!({ "access_token": "pat-na1-test" })).unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "bearer_token");
        assert!(readiness.token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
    }

    #[test]
    fn provisioning_readiness_credential_id() {
        let config = HubSpotConfig::from_params(
            &json!({ "credential_id": "550e8400-e29b-41d4-a716-446655440000" }),
        )
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.token_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
    }

    #[test]
    fn provisioning_readiness_network_ok_default_url() {
        let config =
            HubSpotConfig::from_params(&json!({ "access_token": "tok" })).unwrap();
        let readiness = config.provisioning_readiness();
        assert!(readiness.network_ok);
        assert_eq!(readiness.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_network_fail_bad_url() {
        let config = HubSpotConfig::from_params(
            &json!({ "access_token": "tok", "base_url": "https://evil.example.com" }),
        )
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config =
            HubSpotConfig::from_params(&json!({ "access_token": "pat-na1-test" })).unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "bearer_token");
        assert_eq!(v["token_configured"], true);
    }

    #[test]
    fn is_local_test_host_cases() {
        assert!(is_local_test_host("localhost"));
        assert!(is_local_test_host("127.0.0.1"));
        assert!(is_local_test_host("::1"));
        assert!(!is_local_test_host("api.hubapi.com"));
        assert!(!is_local_test_host("example.com"));
    }
}
