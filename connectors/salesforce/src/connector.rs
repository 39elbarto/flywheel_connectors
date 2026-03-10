//! FCP `Salesforce` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, OAuthRecipe, OperationId, OperationInfo, ProvisioningRecipe,
    ProvisioningStep, ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, StepId,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, SalesforceAuth, SalesforceClient},
    error::SalesforceError,
};

/// Parsed and validated `Salesforce` connector configuration.
#[derive(Debug, Clone)]
struct SalesforceConfig {
    auth: SalesforceAuth,
    base_url: String,
}

impl SalesforceConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let access_token = params
            .get("access_token")
            .and_then(serde_json::Value::as_str)
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
            (Some(token), None) => SalesforceAuth::AccessToken(token),
            (None, Some(cred_id)) => SalesforceAuth::CredentialId(cred_id),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

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

/// FCP `Salesforce` Connector.
pub struct SalesforceConnector {
    base: Arc<BaseConnector>,
    config: Option<SalesforceConfig>,
    client: Option<Arc<SalesforceClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl SalesforceConnector {
    /// Create a new `Salesforce` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("salesforce"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for SalesforceConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl SalesforceConnector {
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = SalesforceConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Salesforce connector");
        let client = SalesforceClient::new(config.auth.clone(), Some(&config.base_url))
            .map_err(|e| e.to_fcp_error())?;
        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({}))
    }

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
        self.session_id = params
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        self.base.set_handshaken(true);
        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.salesforce",
            "connector_version": "0.1.0",
            "capabilities": [
                "salesforce.accounts.read",
                "salesforce.contacts.read",
                "salesforce.contacts.write",
                "salesforce.leads.read",
                "salesforce.leads.write",
                "salesforce.opportunities.read",
                "salesforce.opportunities.write",
                "salesforce.cases.read",
                "salesforce.cases.write",
                "salesforce.soql.read",
                "salesforce.reports.read"
            ]
        }))
    }

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
            "errors": self.error_count.load(Ordering::Relaxed)
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_none() {
                Some("Not configured".into())
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

    pub fn provisioning_readiness(&self) -> serde_json::Value {
        let (auth_mode, token_configured, credential_id_configured, base_url) = match &self.config {
            Some(cfg) => {
                let (am, tc, cc) = match &cfg.auth {
                    SalesforceAuth::AccessToken(_) => ("access_token", true, false),
                    SalesforceAuth::CredentialId(_) => ("credential_id", false, true),
                };
                (am, tc, cc, cfg.base_url.as_str())
            }
            None => ("unconfigured", false, false, DEFAULT_BASE_URL),
        };

        let network_ok = is_salesforce_domain(base_url);

        json!({
            "auth_mode": auth_mode,
            "token_configured": token_configured,
            "credential_id_configured": credential_id_configured,
            "network_ok": network_ok,
            "base_url": base_url,
        })
    }

    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let readiness = self.provisioning_readiness();
        Ok(json!({
            "connector_id": "fcp.salesforce",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
            "provisioning": readiness,
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.salesforce",
            "version": "0.1.0",
            "operations": serde_json::to_value(operations_info()).unwrap_or_default(),
        }))
    }

    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;
        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;
        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));
        self.request_count.fetch_add(1, Ordering::Relaxed);
        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "salesforce.accounts.get" => self.invoke_accounts_get(client, &input).await,
            "salesforce.accounts.list" => self.invoke_accounts_list(client, &input).await,
            "salesforce.contacts.list" => self.invoke_contacts_list(client, &input).await,
            "salesforce.contacts.create" => self.invoke_contacts_create(client, &input).await,
            "salesforce.contacts.delete" => self.invoke_contacts_delete(client, &input).await,
            "salesforce.leads.list" => self.invoke_leads_list(client, &input).await,
            "salesforce.leads.convert" => self.invoke_leads_convert(client, &input).await,
            "salesforce.opportunities.list" => self.invoke_opportunities_list(client, &input).await,
            "salesforce.opportunities.create" => {
                self.invoke_opportunities_create(client, &input).await
            }
            "salesforce.cases.list" => self.invoke_cases_list(client, &input).await,
            "salesforce.cases.create" => self.invoke_cases_create(client, &input).await,
            "salesforce.soql.query" => self.invoke_soql_query(client, &input).await,
            "salesforce.reports.get" => self.invoke_reports_get(client, &input).await,
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

    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let allowed = operations_info().iter().any(|o| o.id.as_ref() == operation);

        Ok(json!({
            "allowed": allowed,
            "reason": if allowed { "Operation supported" } else { "Unknown operation" },
        }))
    }

    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Salesforce connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operations --

    async fn invoke_accounts_get(
        &self,
        client: &SalesforceClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SalesforceError> {
        let account_id = require_str(input, "account_id")?;
        let fields = extract_string_array(input, "fields");
        let data = client.get_account(account_id, fields.as_deref()).await?;
        Ok(json!({ "account": data }))
    }

    async fn invoke_accounts_list(
        &self,
        client: &SalesforceClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SalesforceError> {
        let fields = extract_string_array(input, "fields");
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let data = client.list_accounts(fields.as_deref(), limit).await?;
        Ok(soql_to_output(&data))
    }

    async fn invoke_contacts_list(
        &self,
        client: &SalesforceClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SalesforceError> {
        let fields = extract_string_array(input, "fields");
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let account_id = input.get("account_id").and_then(serde_json::Value::as_str);
        let data = client
            .list_contacts(fields.as_deref(), limit, account_id)
            .await?;
        Ok(soql_to_output(&data))
    }

    async fn invoke_contacts_create(
        &self,
        client: &SalesforceClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SalesforceError> {
        let last_name = require_str(input, "last_name")?;
        let mut body = json!({ "LastName": last_name });
        if let Some(first) = input.get("first_name").and_then(serde_json::Value::as_str) {
            body["FirstName"] = json!(first);
        }
        if let Some(email) = input.get("email").and_then(serde_json::Value::as_str) {
            body["Email"] = json!(email);
        }
        if let Some(aid) = input.get("account_id").and_then(serde_json::Value::as_str) {
            body["AccountId"] = json!(aid);
        }
        client.create_contact(&body).await
    }

    async fn invoke_contacts_delete(
        &self,
        client: &SalesforceClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SalesforceError> {
        let contact_id = require_str(input, "contact_id")?;
        client.delete_contact(contact_id).await
    }

    async fn invoke_leads_list(
        &self,
        client: &SalesforceClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SalesforceError> {
        let fields = extract_string_array(input, "fields");
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let status = input.get("status").and_then(serde_json::Value::as_str);
        let data = client.list_leads(fields.as_deref(), limit, status).await?;
        Ok(soql_to_output(&data))
    }

    async fn invoke_leads_convert(
        &self,
        client: &SalesforceClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SalesforceError> {
        let lead_id = require_str(input, "lead_id")?;
        let mut body = json!({
            "inputs": [{ "leadId": lead_id }]
        });
        if let Some(create_opp) = input
            .get("create_opportunity")
            .and_then(serde_json::Value::as_bool)
        {
            body["inputs"][0]["createOpportunity"] = json!(create_opp);
        }
        if let Some(opp_name) = input
            .get("opportunity_name")
            .and_then(serde_json::Value::as_str)
        {
            body["inputs"][0]["opportunityName"] = json!(opp_name);
        }
        client.convert_lead(&body).await
    }

    async fn invoke_opportunities_list(
        &self,
        client: &SalesforceClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SalesforceError> {
        let fields = extract_string_array(input, "fields");
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let stage = input.get("stage").and_then(serde_json::Value::as_str);
        let data = client
            .list_opportunities(fields.as_deref(), limit, stage)
            .await?;
        Ok(soql_to_output(&data))
    }

    async fn invoke_opportunities_create(
        &self,
        client: &SalesforceClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SalesforceError> {
        let name = require_str(input, "name")?;
        let stage_name = require_str(input, "stage_name")?;
        let close_date = require_str(input, "close_date")?;
        let mut body = json!({
            "Name": name,
            "StageName": stage_name,
            "CloseDate": close_date
        });
        if let Some(amount) = input.get("amount") {
            body["Amount"] = amount.clone();
        }
        if let Some(aid) = input.get("account_id").and_then(serde_json::Value::as_str) {
            body["AccountId"] = json!(aid);
        }
        client.create_opportunity(&body).await
    }

    async fn invoke_cases_list(
        &self,
        client: &SalesforceClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SalesforceError> {
        let fields = extract_string_array(input, "fields");
        let limit = input.get("limit").and_then(serde_json::Value::as_i64);
        let status = input.get("status").and_then(serde_json::Value::as_str);
        let data = client.list_cases(fields.as_deref(), limit, status).await?;
        Ok(soql_to_output(&data))
    }

    async fn invoke_cases_create(
        &self,
        client: &SalesforceClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SalesforceError> {
        let subject = require_str(input, "subject")?;
        let mut body = json!({ "Subject": subject });
        if let Some(desc) = input.get("description").and_then(serde_json::Value::as_str) {
            body["Description"] = json!(desc);
        }
        if let Some(priority) = input.get("priority").and_then(serde_json::Value::as_str) {
            body["Priority"] = json!(priority);
        }
        if let Some(aid) = input.get("account_id").and_then(serde_json::Value::as_str) {
            body["AccountId"] = json!(aid);
        }
        if let Some(cid) = input.get("contact_id").and_then(serde_json::Value::as_str) {
            body["ContactId"] = json!(cid);
        }
        client.create_case(&body).await
    }

    async fn invoke_soql_query(
        &self,
        client: &SalesforceClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SalesforceError> {
        let query = require_str(input, "query")?;
        let data = client.soql_query(query).await?;
        Ok(soql_to_output(&data))
    }

    async fn invoke_reports_get(
        &self,
        client: &SalesforceClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SalesforceError> {
        let report_id = require_str(input, "report_id")?;
        let include_details = input
            .get("include_details")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        client.get_report(report_id, include_details).await
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, SalesforceError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| SalesforceError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

fn extract_string_array(input: &serde_json::Value, field: &str) -> Option<Vec<String>> {
    input.get(field).and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect()
    })
}

/// Convert a SOQL query JSON response into the FCP output format.
fn soql_to_output(data: &serde_json::Value) -> serde_json::Value {
    let records = data.get("records").cloned().unwrap_or_else(|| json!([]));
    let total_size = data.get("totalSize").cloned();
    let done = data.get("done").cloned();
    let mut out = json!({ "records": records });
    if let Some(ts) = total_size {
        out["total_size"] = ts;
    }
    if let Some(d) = done {
        out["done"] = d;
    }
    out
}

/// Check whether the given URL looks like a valid Salesforce domain.
fn is_salesforce_domain(url: &str) -> bool {
    let host = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .and_then(|rest| rest.split('/').next())
        .unwrap_or(url);

    host.ends_with(".salesforce.com")
        || host.ends_with(".force.com")
        || host == "salesforce.com"
        || host == "force.com"
}

/// Build the provisioning recipe for the Salesforce connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("salesforce_setup"),
        "1",
        "Salesforce connector provisioning via OAuth2 or credential injection",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("prompt_auth_mode"),
        ProvisioningStepType::PromptUser {
            message: "Choose authentication mode: oauth (interactive browser flow) or credential_id (egress proxy injection)".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("oauth_flow"),
            ProvisioningStepType::Oauth {
                flow: OAuthRecipe::AuthorizationCodePkce {
                    authorization_url: "https://login.salesforce.com/services/oauth2/authorize".into(),
                    token_url: "https://login.salesforce.com/services/oauth2/token".into(),
                    scopes: vec!["api".into(), "refresh_token".into()],
                    auto_browser: true,
                    callback_port: 8400,
                },
            },
        )
        .depends_on(StepId::new("prompt_auth_mode")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_token"),
            ProvisioningStepType::StoreSecret {
                key: "salesforce_oauth_token".into(),
                value_from: StepId::new("oauth_flow"),
                scope: "connector:fcp.salesforce".into(),
            },
        )
        .depends_on(StepId::new("oauth_flow")),
    )
    .with_step(ProvisioningStep::new(
        StepId::new("prompt_instance_url"),
        ProvisioningStepType::PromptUser {
            message: "Enter your Salesforce instance URL (e.g., https://myorg.my.salesforce.com)".into(),
        },
    ))
}

/// Construct a single [`OperationInfo`].
#[allow(clippy::too_many_arguments)]
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
            "salesforce.accounts.get",
            "Get a single account by ID",
            json!({
                "type": "object",
                "required": ["account_id"],
                "properties": {
                    "account_id": {"type": "string"},
                    "fields": {"type": "array"}
                }
            }),
            json!({
                "type": "object",
                "required": ["account"],
                "properties": {"account": {"type": "object"}}
            }),
            "salesforce.accounts.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve a specific Salesforce account by ID.".into(),
                common_mistakes: vec![
                    "Using a 15-character ID instead of the 18-character case-safe ID.".into(),
                ],
                examples: vec![
                    r#"{"account_id": "001xx000003DGbY", "fields": ["Name", "Industry"]}"#.into(),
                ],
                related: vec![CapabilityId::from_static("salesforce.accounts.list")],
            },
        ),
        op_info(
            "salesforce.accounts.list",
            "Query accounts with optional filters",
            json!({
                "type": "object",
                "required": [],
                "properties": {
                    "fields": {"type": "array", "description": "sObject fields to return"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 2000},
                    "offset": {"type": "integer"}
                }
            }),
            json!({
                "type": "object",
                "required": ["records"],
                "properties": {
                    "records": {"type": "array"},
                    "total_size": {"type": "integer"}
                }
            }),
            "salesforce.accounts.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List or search Salesforce accounts.".into(),
                common_mistakes: vec![
                    "Not specifying fields — returns all fields which can be slow.".into(),
                ],
                examples: vec![
                    r#"{"limit": 50, "fields": ["Id", "Name", "Industry", "AnnualRevenue"]}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("salesforce.accounts.get"),
                    CapabilityId::from_static("salesforce.soql.query"),
                ],
            },
        ),
        op_info(
            "salesforce.contacts.list",
            "Query contacts with optional filters",
            json!({
                "type": "object",
                "required": [],
                "properties": {
                    "account_id": {"type": "string", "description": "Filter by parent account"},
                    "fields": {"type": "array"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 2000}
                }
            }),
            json!({
                "type": "object",
                "required": ["records"],
                "properties": {
                    "records": {"type": "array"},
                    "total_size": {"type": "integer"}
                }
            }),
            "salesforce.contacts.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List or search Salesforce contacts.".into(),
                common_mistakes: vec![
                    "Not specifying fields — returns all fields which can be slow and hit response size limits.".into(),
                ],
                examples: vec![
                    r#"{"limit": 50, "fields": ["Id", "FirstName", "LastName", "Email"]}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("salesforce.contacts.create"),
                    CapabilityId::from_static("salesforce.accounts.list"),
                ],
            },
        ),
        op_info(
            "salesforce.contacts.create",
            "Create a new contact",
            json!({
                "type": "object",
                "required": ["last_name"],
                "properties": {
                    "last_name": {"type": "string"},
                    "first_name": {"type": "string"},
                    "email": {"type": "string"},
                    "account_id": {"type": "string"}
                }
            }),
            json!({
                "type": "object",
                "required": ["id"],
                "properties": {"id": {"type": "string"}}
            }),
            "salesforce.contacts.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new contact in Salesforce.".into(),
                common_mistakes: vec![
                    "Creating duplicate contacts — check for existing email first.".into(),
                ],
                examples: vec![
                    r#"{"last_name": "Smith", "first_name": "Alice", "email": "alice@example.com", "account_id": "001xx000003DGbY"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("salesforce.contacts.list")],
            },
        ),
        op_info(
            "salesforce.contacts.delete",
            "Delete a contact",
            json!({
                "type": "object",
                "required": ["contact_id"],
                "properties": {"contact_id": {"type": "string"}}
            }),
            json!({"type": "object"}),
            "salesforce.contacts.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Permanently delete a contact. Cannot be undone.".into(),
                common_mistakes: vec![
                    "Deleting contacts with active opportunities.".into(),
                ],
                examples: vec![
                    r#"{"contact_id": "003xx000004TmiQ"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("salesforce.contacts.list")],
            },
        ),
        op_info(
            "salesforce.leads.list",
            "Query leads with optional status filters",
            json!({
                "type": "object",
                "required": [],
                "properties": {
                    "fields": {"type": "array"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 2000},
                    "status": {"type": "string", "description": "Filter by Status"}
                }
            }),
            json!({
                "type": "object",
                "required": ["records"],
                "properties": {"records": {"type": "array"}}
            }),
            "salesforce.leads.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List or search leads.".into(),
                common_mistakes: vec![
                    "Not filtering by status — includes converted and disqualified leads by default.".into(),
                ],
                examples: vec![
                    r#"{"limit": 50, "fields": ["Id", "FirstName", "LastName", "Company", "Status"]}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("salesforce.leads.convert"),
                    CapabilityId::from_static("salesforce.contacts.list"),
                ],
            },
        ),
        op_info(
            "salesforce.leads.convert",
            "Convert a lead to account/contact/opportunity",
            json!({
                "type": "object",
                "required": ["lead_id"],
                "properties": {
                    "lead_id": {"type": "string"},
                    "create_opportunity": {"type": "boolean"},
                    "opportunity_name": {"type": "string"}
                }
            }),
            json!({
                "type": "object",
                "required": ["account_id", "contact_id"],
                "properties": {
                    "account_id": {"type": "string"},
                    "contact_id": {"type": "string"},
                    "opportunity_id": {"type": "string"}
                }
            }),
            "salesforce.leads.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Convert a qualified lead into an account, contact, and optionally an opportunity.".into(),
                common_mistakes: vec![
                    "Converting leads without checking for duplicate accounts.".into(),
                ],
                examples: vec![
                    r#"{"lead_id": "00Qxx000001LaPt", "create_opportunity": true, "opportunity_name": "New Deal"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("salesforce.leads.list"),
                    CapabilityId::from_static("salesforce.accounts.list"),
                ],
            },
        ),
        op_info(
            "salesforce.opportunities.list",
            "Query opportunities with optional stage/account filters",
            json!({
                "type": "object",
                "required": [],
                "properties": {
                    "fields": {"type": "array"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 2000},
                    "stage": {"type": "string", "description": "Filter by StageName"}
                }
            }),
            json!({
                "type": "object",
                "required": ["records"],
                "properties": {
                    "records": {"type": "array"},
                    "total_size": {"type": "integer"}
                }
            }),
            "salesforce.opportunities.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List or search opportunities in the sales pipeline.".into(),
                common_mistakes: vec![
                    "Not filtering by stage — returns all stages including Closed Lost, which inflates results.".into(),
                ],
                examples: vec![
                    r#"{"limit": 50, "fields": ["Id", "Name", "StageName", "Amount", "CloseDate"]}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("salesforce.opportunities.create"),
                    CapabilityId::from_static("salesforce.accounts.list"),
                ],
            },
        ),
        op_info(
            "salesforce.opportunities.create",
            "Create a new opportunity",
            json!({
                "type": "object",
                "required": ["name", "stage_name", "close_date"],
                "properties": {
                    "name": {"type": "string"},
                    "stage_name": {"type": "string"},
                    "close_date": {"type": "string", "description": "ISO 8601 date"},
                    "amount": {"type": "number"},
                    "account_id": {"type": "string"}
                }
            }),
            json!({
                "type": "object",
                "required": ["id"],
                "properties": {"id": {"type": "string"}}
            }),
            "salesforce.opportunities.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new sales opportunity.".into(),
                common_mistakes: vec![
                    "Not specifying account_id — opportunity won't be linked to an account.".into(),
                ],
                examples: vec![
                    r#"{"name": "Enterprise Deal", "stage_name": "Prospecting", "close_date": "2026-06-30", "amount": 50000}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("salesforce.opportunities.list"),
                    CapabilityId::from_static("salesforce.accounts.list"),
                ],
            },
        ),
        op_info(
            "salesforce.cases.list",
            "Query support cases",
            json!({
                "type": "object",
                "required": [],
                "properties": {
                    "fields": {"type": "array"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 2000},
                    "status": {"type": "string"}
                }
            }),
            json!({
                "type": "object",
                "required": ["records"],
                "properties": {"records": {"type": "array"}}
            }),
            "salesforce.cases.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List or search support cases.".into(),
                common_mistakes: vec![
                    "Not filtering by status — returns all cases including closed, which can be a very large result set.".into(),
                ],
                examples: vec![
                    r#"{"limit": 50, "status": "Open", "fields": ["Id", "Subject", "Status", "Priority"]}"#.into(),
                ],
                related: vec![CapabilityId::from_static("salesforce.cases.create")],
            },
        ),
        op_info(
            "salesforce.cases.create",
            "Create a new support case",
            json!({
                "type": "object",
                "required": ["subject"],
                "properties": {
                    "subject": {"type": "string"},
                    "description": {"type": "string"},
                    "priority": {"type": "string"},
                    "account_id": {"type": "string"},
                    "contact_id": {"type": "string"}
                }
            }),
            json!({
                "type": "object",
                "required": ["id"],
                "properties": {"id": {"type": "string"}}
            }),
            "salesforce.cases.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new support case.".into(),
                common_mistakes: vec![
                    "Not linking the case to an account_id or contact_id — unlinked cases are hard to track.".into(),
                ],
                examples: vec![
                    r#"{"subject": "Login issue", "priority": "High", "account_id": "001xx000003DGbY"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("salesforce.cases.list")],
            },
        ),
        op_info(
            "salesforce.soql.query",
            "Execute a SOQL query",
            json!({
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {"type": "string", "description": "SOQL query string"}
                }
            }),
            json!({
                "type": "object",
                "required": ["records"],
                "properties": {
                    "records": {"type": "array"},
                    "total_size": {"type": "integer"},
                    "done": {"type": "boolean"}
                }
            }),
            "salesforce.soql.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Run a SOQL query for complex or cross-object queries.".into(),
                common_mistakes: vec![
                    "Unbounded queries without LIMIT — can return huge result sets.".into(),
                    "Not handling pagination via nextRecordsUrl when done=false.".into(),
                ],
                examples: vec![
                    r#"{"query": "SELECT Id, Name, Amount FROM Opportunity WHERE StageName = 'Closed Won' LIMIT 100"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("salesforce.accounts.list"),
                    CapabilityId::from_static("salesforce.contacts.list"),
                    CapabilityId::from_static("salesforce.reports.get"),
                ],
            },
        ),
        op_info(
            "salesforce.reports.get",
            "Run a saved Salesforce report by ID",
            json!({
                "type": "object",
                "required": ["report_id"],
                "properties": {
                    "report_id": {"type": "string"},
                    "include_details": {"type": "boolean"}
                }
            }),
            json!({
                "type": "object",
                "required": ["report_metadata", "fact_map"],
                "properties": {
                    "report_metadata": {"type": "object"},
                    "fact_map": {"type": "object"}
                }
            }),
            "salesforce.reports.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Run a saved Salesforce report and get its data.".into(),
                common_mistakes: vec![
                    "Not checking report format — tabular/summary/matrix return different structures.".into(),
                ],
                examples: vec![
                    r#"{"report_id": "00Oxx0000004cGr", "include_details": true}"#.into(),
                ],
                related: vec![CapabilityId::from_static("salesforce.soql.query")],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- SalesforceConfig::from_params --

    #[test]
    fn config_from_access_token() {
        let config =
            SalesforceConfig::from_params(&json!({ "access_token": "00Dxx-test-token" })).unwrap();
        assert!(matches!(config.auth, SalesforceAuth::AccessToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = SalesforceConfig::from_params(
            &json!({ "credential_id": "550e8400-e29b-41d4-a716-446655440000" }),
        )
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_rejects_both() {
        let result = SalesforceConfig::from_params(
            &json!({ "access_token": "tok", "credential_id": "550e8400-e29b-41d4-a716-446655440000" }),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_rejects_none() {
        let result = SalesforceConfig::from_params(&json!({}));
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_rejects_empty_token() {
        assert!(SalesforceConfig::from_params(&json!({ "access_token": "" })).is_err());
    }

    #[test]
    fn config_rejects_whitespace_only_token() {
        assert!(SalesforceConfig::from_params(&json!({ "access_token": "   " })).is_err());
    }

    #[test]
    fn config_trims_token() {
        let config =
            SalesforceConfig::from_params(&json!({ "access_token": "  00Dxx-test  " })).unwrap();
        match &config.auth {
            SalesforceAuth::AccessToken(t) => assert_eq!(t, "00Dxx-test"),
            SalesforceAuth::CredentialId(_) => panic!("expected AccessToken"),
        }
    }

    #[test]
    fn config_custom_base_url() {
        let config = SalesforceConfig::from_params(&json!({
            "access_token": "tok",
            "base_url": "https://myorg.my.salesforce.com"
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://myorg.my.salesforce.com");
    }

    #[test]
    fn config_default_base_url() {
        let config = SalesforceConfig::from_params(&json!({ "access_token": "tok" })).unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_rejects_invalid_credential_id() {
        let result = SalesforceConfig::from_params(&json!({ "credential_id": "not-a-uuid" }));
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("UUID"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = SalesforceConfig::from_params(&json!({ "credential_id": 42 }));
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("string"));
            }
            e => panic!("expected InvalidRequest, got {e:?}"),
        }
    }

    // -- DoctorResult --

    #[test]
    fn doctor_result_healthy() {
        let r = DoctorResult::from_checks(vec![
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
        ]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_degraded_non_critical_fails() {
        let r = DoctorResult::from_checks(vec![
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
        ]);
        assert_eq!(r.status, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_result_unhealthy_critical_fails() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: false,
            message: Some("down".into()),
            critical: true,
        }]);
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
    fn doctor_result_empty_checks_is_healthy() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_serializes() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "config".into(),
            passed: true,
            message: None,
            critical: true,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "healthy");
        assert!(v["checks"][0]["message"].is_null());
    }

    // -- require_str --

    #[test]
    fn require_str_present() {
        let input = json!({ "account_id": "001xx1" });
        assert_eq!(require_str(&input, "account_id").unwrap(), "001xx1");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        let err = require_str(&input, "account_id").unwrap_err();
        match err {
            SalesforceError::Api {
                status_code,
                message,
            } => {
                assert_eq!(status_code, 400);
                assert!(message.contains("account_id"));
            }
            _ => panic!("expected Api error"),
        }
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({ "account_id": 42 });
        assert!(require_str(&input, "account_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({ "account_id": null });
        assert!(require_str(&input, "account_id").is_err());
    }

    // -- extract_string_array --

    #[test]
    fn extract_string_array_present() {
        let input = json!({ "fields": ["Id", "Name"] });
        let arr = extract_string_array(&input, "fields").unwrap();
        assert_eq!(arr, vec!["Id", "Name"]);
    }

    #[test]
    fn extract_string_array_missing() {
        let input = json!({});
        assert!(extract_string_array(&input, "fields").is_none());
    }

    #[test]
    fn extract_string_array_not_array() {
        let input = json!({ "fields": "not an array" });
        assert!(extract_string_array(&input, "fields").is_none());
    }

    // -- soql_to_output --

    #[test]
    fn soql_to_output_full() {
        let data = json!({"totalSize": 2, "done": true, "records": [{"Id": "1"}, {"Id": "2"}]});
        let out = soql_to_output(&data);
        assert_eq!(out["records"].as_array().unwrap().len(), 2);
        assert_eq!(out["total_size"], 2);
        assert_eq!(out["done"], true);
    }

    #[test]
    fn soql_to_output_empty() {
        let data = json!({});
        let out = soql_to_output(&data);
        assert_eq!(out["records"].as_array().unwrap().len(), 0);
    }

    // -- operations_info --

    fn ops_json() -> serde_json::Value {
        serde_json::to_value(operations_info()).unwrap()
    }

    #[test]
    fn operations_info_has_13_operations() {
        let ops = ops_json();
        assert_eq!(ops.as_array().unwrap().len(), 13);
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = ops_json();
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
    fn read_operations_are_safe() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.to_ascii_lowercase().ends_with(".read") {
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
    fn all_operations_have_required_fields() {
        let required = [
            "id",
            "summary",
            "capability",
            "risk_level",
            "safety_tier",
            "idempotency",
        ];
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            for field in &required {
                assert!(
                    op.get(field).is_some(),
                    "op {:?} missing field {field}",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_have_valid_risk_levels() {
        let valid = ["low", "medium", "high", "critical"];
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let level = op["risk_level"].as_str().unwrap();
            assert!(
                valid.contains(&level),
                "invalid risk_level {level} for {:?}",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_have_valid_safety_tiers() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let tier = op["safety_tier"].as_str().unwrap();
            assert!(
                valid.contains(&tier),
                "invalid safety_tier {tier} for {:?}",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = ops_json();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        let expected = [
            "salesforce.accounts.get",
            "salesforce.accounts.list",
            "salesforce.contacts.list",
            "salesforce.contacts.create",
            "salesforce.contacts.delete",
            "salesforce.leads.list",
            "salesforce.leads.convert",
            "salesforce.opportunities.list",
            "salesforce.opportunities.create",
            "salesforce.cases.list",
            "salesforce.cases.create",
            "salesforce.soql.query",
            "salesforce.reports.get",
        ];
        for e in &expected {
            assert!(ids.contains(e), "missing expected operation {e}");
        }
    }

    // -- Connector default --

    #[test]
    fn connector_default() {
        let c = SalesforceConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    // -- Additional connector tests --

    #[test]
    fn connector_new_matches_default() {
        let c = SalesforceConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
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
        let v = json!({"status": "degraded", "checks": [{"name": "a", "passed": false, "critical": false}]});
        let r: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r.status, DoctorStatus::Degraded);
        assert_eq!(r.checks.len(), 1);
    }

    #[test]
    fn operations_write_ops_not_safe() {
        let ops = ops_json();
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
    fn operations_all_have_salesforce_prefix() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            assert!(
                id.starts_with("salesforce."),
                "op {id} missing salesforce prefix"
            );
        }
    }

    #[test]
    fn operations_delete_is_dangerous() {
        let ops = ops_json();
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
    fn soql_to_output_with_records_only() {
        let data = json!({"records": [{"Id": "a"}, {"Id": "b"}]});
        let out = soql_to_output(&data);
        assert_eq!(out["records"].as_array().unwrap().len(), 2);
        assert!(out.get("total_size").is_none() || out["total_size"].is_null());
    }

    #[test]
    fn soql_to_output_preserves_total_size() {
        let data = json!({"totalSize": 0, "done": true, "records": []});
        let out = soql_to_output(&data);
        assert_eq!(out["total_size"], 0);
        assert_eq!(out["done"], true);
    }

    #[test]
    fn extract_string_array_filters_non_strings() {
        let input = json!({ "fields": ["Id", 42, "Name", null] });
        let arr = extract_string_array(&input, "fields").unwrap();
        assert_eq!(arr, vec!["Id", "Name"]);
    }

    #[test]
    fn extract_string_array_empty_array() {
        let input = json!({ "fields": [] });
        let arr = extract_string_array(&input, "fields").unwrap();
        assert!(arr.is_empty());
    }

    #[test]
    fn require_str_empty_string_is_valid() {
        let input = json!({ "field": "" });
        assert_eq!(require_str(&input, "field").unwrap(), "");
    }

    #[test]
    fn require_str_error_message_contains_field_name() {
        let input = json!({});
        let err = require_str(&input, "my_field").unwrap_err();
        match err {
            SalesforceError::Api { message, .. } => assert!(message.contains("my_field")),
            _ => panic!("expected Api error"),
        }
    }

    #[test]
    fn operations_idempotency_values_valid() {
        let valid = ["strict", "none", "idempotent"];
        let ops = ops_json();
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
    fn config_clone_preserves_base_url() {
        let config = SalesforceConfig::from_params(
            &json!({ "access_token": "tok", "base_url": "https://custom.sf.com" }),
        )
        .unwrap();
        let cloned = config.clone();
        assert_eq!(config.base_url, "https://custom.sf.com");
        assert_eq!(cloned.base_url, "https://custom.sf.com");
    }

    #[test]
    fn config_debug_does_not_leak_token() {
        let config =
            SalesforceConfig::from_params(&json!({ "access_token": "super-secret-value" }))
                .unwrap();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("SalesforceConfig"));
        assert!(!dbg.contains("super-secret-value"));
    }

    #[test]
    fn soql_to_output_with_done_false() {
        let data = json!({"totalSize": 100, "done": false, "records": [{"Id": "x"}]});
        let out = soql_to_output(&data);
        assert_eq!(out["done"], false);
        assert_eq!(out["total_size"], 100);
        assert_eq!(out["records"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn operations_summaries_are_non_empty() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {:?} has empty summary", op["id"]);
        }
    }

    #[test]
    fn operations_capabilities_have_salesforce_prefix() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.starts_with("salesforce."),
                "capability {cap} missing salesforce prefix for {:?}",
                op["id"]
            );
        }
    }

    #[test]
    fn doctor_status_copy_semantics() {
        let s = DoctorStatus::Healthy;
        let s2 = s;
        assert_eq!(s, s2);
        assert_eq!(s, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_deserialize_unhealthy() {
        let v = json!({"status": "unhealthy", "checks": [{"name": "cfg", "passed": false, "critical": true}]});
        let r: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert!(!r.checks[0].passed);
        assert!(r.checks[0].critical);
    }

    #[test]
    fn require_str_with_boolean_value() {
        let input = json!({ "field": true });
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_with_array_value() {
        let input = json!({ "field": ["a", "b"] });
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn extract_string_array_null_value() {
        let input = json!({ "fields": null });
        assert!(extract_string_array(&input, "fields").is_none());
    }

    #[test]
    fn soql_to_output_nested_records() {
        let data = json!({
            "totalSize": 1,
            "done": true,
            "records": [{"Id": "001", "Account": {"Name": "Acme"}}]
        });
        let out = soql_to_output(&data);
        assert_eq!(out["records"][0]["Account"]["Name"], "Acme");
    }

    // -- provisioning_recipe --

    #[test]
    fn provisioning_recipe_has_expected_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps.len(), 4);
        let ids: Vec<&str> = recipe.steps.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "prompt_auth_mode",
                "oauth_flow",
                "store_token",
                "prompt_instance_url"
            ]
        );
    }

    #[test]
    fn provisioning_recipe_has_oauth_step() {
        let recipe = provisioning_recipe();
        let oauth_step = recipe
            .steps
            .iter()
            .find(|s| s.id.as_str() == "oauth_flow")
            .expect("oauth_flow step missing");
        match &oauth_step.kind {
            ProvisioningStepType::Oauth { flow } => match flow {
                OAuthRecipe::AuthorizationCodePkce {
                    authorization_url,
                    token_url,
                    scopes,
                    auto_browser,
                    callback_port,
                } => {
                    assert_eq!(
                        authorization_url,
                        "https://login.salesforce.com/services/oauth2/authorize"
                    );
                    assert_eq!(
                        token_url,
                        "https://login.salesforce.com/services/oauth2/token"
                    );
                    assert_eq!(scopes, &["api", "refresh_token"]);
                    assert!(auto_browser);
                    assert_eq!(*callback_port, 8400);
                }
                other => panic!("expected AuthorizationCodePkce, got {other:?}"),
            },
            other => panic!("expected Oauth step, got {other:?}"),
        }
    }

    #[test]
    fn provisioning_recipe_store_secret_scope() {
        let recipe = provisioning_recipe();
        let store_step = recipe
            .steps
            .iter()
            .find(|s| s.id.as_str() == "store_token")
            .expect("store_token step missing");
        match &store_step.kind {
            ProvisioningStepType::StoreSecret {
                scope, value_from, ..
            } => {
                assert_eq!(scope, "connector:fcp.salesforce");
                assert_eq!(value_from.as_str(), "oauth_flow");
            }
            other => panic!("expected StoreSecret step, got {other:?}"),
        }
        assert!(
            store_step
                .depends_on
                .iter()
                .any(|d| d.as_str() == "oauth_flow")
        );
    }

    // -- provisioning_readiness --

    #[test]
    fn provisioning_readiness_unconfigured() {
        let c = SalesforceConnector::new();
        let r = c.provisioning_readiness();
        assert_eq!(r["auth_mode"], "unconfigured");
        assert_eq!(r["token_configured"], false);
        assert_eq!(r["credential_id_configured"], false);
        assert_eq!(r["base_url"], DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_access_token() {
        let mut c = SalesforceConnector::new();
        c.config = Some(SalesforceConfig {
            auth: SalesforceAuth::AccessToken("test-token".into()),
            base_url: "https://myorg.my.salesforce.com".into(),
        });
        let r = c.provisioning_readiness();
        assert_eq!(r["auth_mode"], "access_token");
        assert_eq!(r["token_configured"], true);
        assert_eq!(r["credential_id_configured"], false);
        assert_eq!(r["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_credential_id() {
        let mut c = SalesforceConnector::new();
        c.config = Some(SalesforceConfig {
            auth: SalesforceAuth::CredentialId(
                CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            ),
            base_url: "https://myorg.my.salesforce.com".into(),
        });
        let r = c.provisioning_readiness();
        assert_eq!(r["auth_mode"], "credential_id");
        assert_eq!(r["token_configured"], false);
        assert_eq!(r["credential_id_configured"], true);
        assert_eq!(r["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_network_check() {
        assert!(is_salesforce_domain("https://myorg.my.salesforce.com"));
        assert!(is_salesforce_domain("https://login.salesforce.com"));
        assert!(is_salesforce_domain("https://myorg.lightning.force.com"));
        assert!(!is_salesforce_domain("https://evil.example.com"));
        assert!(!is_salesforce_domain("https://notsalesforce.com"));
        assert!(!is_salesforce_domain("https://salesforce.com.evil.com"));

        let mut c = SalesforceConnector::new();
        c.config = Some(SalesforceConfig {
            auth: SalesforceAuth::AccessToken("tok".into()),
            base_url: "https://evil.example.com".into(),
        });
        let r = c.provisioning_readiness();
        assert_eq!(r["network_ok"], false);
    }

    // -- self_check with provisioning --

    #[test]
    fn self_check_includes_provisioning() {
        let c = SalesforceConnector::new();
        let rt = fcp_async_core::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(c.handle_self_check()).unwrap();
        assert!(result.get("provisioning").is_some());
        let prov = &result["provisioning"];
        assert_eq!(prov["auth_mode"], "unconfigured");
        assert!(prov.get("token_configured").is_some());
        assert!(prov.get("network_ok").is_some());
        assert!(prov.get("base_url").is_some());
    }
}
