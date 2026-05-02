//! FCP Trello Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, OperationId, OperationInfo, ProvisioningRecipe, ProvisioningStep,
    ProvisioningStepType, RecipeId, RiskLevel, SafetyTier, SelfCheckReport, StepId,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, TrelloAuth, TrelloClient},
    error::TrelloError,
};

/// Parsed and validated Trello connector configuration.
#[derive(Debug, Clone)]
struct TrelloConfig {
    auth: TrelloAuth,
    base_url: String,
}

impl TrelloConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_key = params
            .get("api_key")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let token = params
            .get("token")
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

        let auth = match (api_key, token, credential_id) {
            (Some(key), Some(tok), None) => TrelloAuth::ApiKeyToken {
                api_key: key,
                token: tok,
            },
            (None, None, Some(cred_id)) => TrelloAuth::CredentialId(cred_id),
            (Some(_), Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide either api_key+token or credential_id, not both".into(),
                });
            }
            (Some(_), None, None) | (None, Some(_), None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Both api_key and token are required for API key authentication"
                        .into(),
                });
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key+token or credential_id in configuration".into(),
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

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        let (network_ok, network_message) = base_url_policy(&self.base_url);

        ProvisioningReadiness {
            auth_mode: match &self.auth {
                TrelloAuth::ApiKeyToken { .. } => "api_key_token",
                TrelloAuth::CredentialId(_) => "credential_id",
            },
            api_key_configured: matches!(&self.auth, TrelloAuth::ApiKeyToken { .. }),
            token_configured: matches!(&self.auth, TrelloAuth::ApiKeyToken { .. }),
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
    api_key_configured: bool,
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

/// FCP Trello Connector.
pub struct TrelloConnector {
    base: Arc<BaseConnector>,
    config: Option<TrelloConfig>,
    client: Option<Arc<TrelloClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl TrelloConnector {
    /// Create a new Trello connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("trello"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for TrelloConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl TrelloConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = TrelloConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Trello connector");

        let client = TrelloClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.trello",
            "connector_version": "0.1.0",
            "capabilities": [
                "trello.boards.read",
                "trello.cards.read",
                "trello.cards.write",
                "trello.cards.delete",
                "trello.labels.read",
                "trello.members.read"
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
                Some("Not configured -- call configure first".into())
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

    fn serialize_self_check_report(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
        info!(
            event = "trello.provisioning.self_check",
            status = ?report.status,
            reason_code = ?report.reason_code,
            "Trello self-check completed"
        );

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let ops = typed_operations_info();
        let ops_value = serde_json::to_value(&ops).unwrap_or_else(|_| json!([]));
        Ok(json!({
            "connector_id": "fcp.trello",
            "version": "0.1.0",
            "operations": ops_value,
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
            "trello.boards.list" => self.invoke_boards_list(client, &input).await,
            "trello.boards.get" => self.invoke_boards_get(client, &input).await,
            "trello.lists.list" => self.invoke_lists_list(client, &input).await,
            "trello.cards.list" => self.invoke_cards_list(client, &input).await,
            "trello.cards.get" => self.invoke_cards_get(client, &input).await,
            "trello.cards.create" => self.invoke_cards_create(client, &input).await,
            "trello.cards.update" => self.invoke_cards_update(client, &input).await,
            "trello.cards.delete" => self.invoke_cards_delete(client, &input).await,
            "trello.labels.list" => self.invoke_labels_list(client, &input).await,
            "trello.members.list" => self.invoke_members_list(client, &input).await,
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
        info!("Trello connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_boards_list(
        &self,
        client: &TrelloClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TrelloError> {
        let member = input
            .get("member")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("me");
        let resp = client.list_boards(member).await?;
        // Trello returns an array directly for this endpoint.
        let boards = if resp.is_array() { resp } else { json!([]) };
        Ok(json!({ "boards": boards }))
    }

    async fn invoke_boards_get(
        &self,
        client: &TrelloClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TrelloError> {
        let board_id = require_str(input, "board_id")?;
        client.get_board(board_id).await
    }

    async fn invoke_lists_list(
        &self,
        client: &TrelloClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TrelloError> {
        let board_id = require_str(input, "board_id")?;
        let resp = client.list_lists(board_id).await?;
        let lists = if resp.is_array() { resp } else { json!([]) };
        Ok(json!({ "lists": lists }))
    }

    async fn invoke_cards_list(
        &self,
        client: &TrelloClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TrelloError> {
        let list_id = require_str(input, "list_id")?;
        let resp = client.list_cards(list_id).await?;
        let cards = if resp.is_array() { resp } else { json!([]) };
        Ok(json!({ "cards": cards }))
    }

    async fn invoke_cards_get(
        &self,
        client: &TrelloClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TrelloError> {
        let card_id = require_str(input, "card_id")?;
        client.get_card(card_id).await
    }

    async fn invoke_cards_create(
        &self,
        client: &TrelloClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TrelloError> {
        let name = require_str(input, "name")?;
        let id_list = require_str(input, "idList")?;

        let mut body = json!({
            "name": name,
            "idList": id_list,
        });

        // Optional fields
        if let Some(desc) = input.get("desc").and_then(serde_json::Value::as_str) {
            body["desc"] = json!(desc);
        }
        if let Some(due) = input.get("due").and_then(serde_json::Value::as_str) {
            body["due"] = json!(due);
        }

        client.create_card(&body).await
    }

    async fn invoke_cards_update(
        &self,
        client: &TrelloClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TrelloError> {
        let card_id = require_str(input, "card_id")?;

        let mut body = json!({});
        if let Some(name) = input.get("name").and_then(serde_json::Value::as_str) {
            body["name"] = json!(name);
        }
        if let Some(desc) = input.get("desc").and_then(serde_json::Value::as_str) {
            body["desc"] = json!(desc);
        }
        if let Some(closed) = input.get("closed").and_then(serde_json::Value::as_bool) {
            body["closed"] = json!(closed);
        }
        if let Some(id_list) = input.get("idList").and_then(serde_json::Value::as_str) {
            body["idList"] = json!(id_list);
        }
        if let Some(due) = input.get("due").and_then(serde_json::Value::as_str) {
            body["due"] = json!(due);
        }

        client.update_card(card_id, &body).await
    }

    async fn invoke_cards_delete(
        &self,
        client: &TrelloClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TrelloError> {
        let card_id = require_str(input, "card_id")?;
        client.delete_card(card_id).await
    }

    async fn invoke_labels_list(
        &self,
        client: &TrelloClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TrelloError> {
        let board_id = require_str(input, "board_id")?;
        let resp = client.list_labels(board_id).await?;
        let labels = if resp.is_array() { resp } else { json!([]) };
        Ok(json!({ "labels": labels }))
    }

    async fn invoke_members_list(
        &self,
        client: &TrelloClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, TrelloError> {
        let board_id = require_str(input, "board_id")?;
        let resp = client.list_members(board_id).await?;
        let members = if resp.is_array() { resp } else { json!([]) };
        Ok(json!({ "members": members }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, TrelloError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TrelloError::InvalidInput(format!("Missing required field: {field}")))
}

/// Build a single typed `OperationInfo`.
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

/// Build typed operations info for introspection.
fn typed_operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "trello.boards.list",
            "List boards for the authenticated user",
            json!({"type": "object", "required": []}),
            json!({"type": "object", "required": ["boards"], "properties": {"boards": {"type": "array"}}}),
            "trello.boards.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List Trello boards.".into(),
                common_mistakes: vec!["Assuming all organization boards are returned; this only returns boards the authenticated token has access to, which may exclude private boards in shared workspaces.".into()],
                examples: vec!["{}".into()],
                related: vec![
                    CapabilityId::from_static("trello.lists.list"),
                    CapabilityId::from_static("trello.cards.list"),
                ],
            },
        ),
        op_info(
            "trello.boards.get",
            "Get a single board by ID",
            json!({"type": "object", "required": ["board_id"], "properties": {"board_id": {"type": "string"}}}),
            json!({"type": "object"}),
            "trello.boards.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve a single Trello board by its ID.".into(),
                common_mistakes: vec!["Using the board name instead of its alphanumeric ID.".into()],
                examples: vec!["{\"board_id\": \"abc123\"}".into()],
                related: vec![
                    CapabilityId::from_static("trello.boards.list"),
                    CapabilityId::from_static("trello.lists.list"),
                ],
            },
        ),
        op_info(
            "trello.lists.list",
            "List lists on a board",
            json!({"type": "object", "required": ["board_id"], "properties": {"board_id": {"type": "string"}}}),
            json!({"type": "object", "required": ["lists"], "properties": {"lists": {"type": "array"}}}),
            "trello.boards.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get lists on a Trello board.".into(),
                common_mistakes: vec!["Archived lists are not included in the response by default; only open lists are returned unless the filter parameter is set to all.".into()],
                examples: vec!["{\"board_id\": \"abc123\"}".into()],
                related: vec![
                    CapabilityId::from_static("trello.boards.list"),
                    CapabilityId::from_static("trello.cards.list"),
                ],
            },
        ),
        op_info(
            "trello.cards.list",
            "List cards on a list",
            json!({"type": "object", "required": ["list_id"], "properties": {"list_id": {"type": "string"}}}),
            json!({"type": "object", "required": ["cards"], "properties": {"cards": {"type": "array"}}}),
            "trello.cards.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List cards on a board, optionally filtered by list.".into(),
                common_mistakes: vec!["Archived cards are excluded by default; only open cards on the board are returned unless you explicitly request closed cards.".into()],
                examples: vec!["{\"board_id\": \"abc123\"}".into()],
                related: vec![
                    CapabilityId::from_static("trello.cards.create"),
                    CapabilityId::from_static("trello.cards.delete"),
                ],
            },
        ),
        op_info(
            "trello.cards.get",
            "Get a single card by ID",
            json!({"type": "object", "required": ["card_id"], "properties": {"card_id": {"type": "string"}}}),
            json!({"type": "object"}),
            "trello.cards.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve a single Trello card by its ID.".into(),
                common_mistakes: vec!["Using the card name instead of its alphanumeric ID.".into()],
                examples: vec!["{\"card_id\": \"card_abc123\"}".into()],
                related: vec![
                    CapabilityId::from_static("trello.cards.list"),
                    CapabilityId::from_static("trello.cards.update"),
                ],
            },
        ),
        op_info(
            "trello.cards.create",
            "Create a new card",
            json!({"type": "object", "required": ["idList", "name"], "properties": {"idList": {"type": "string", "description": "ID of the list to add the card to"}, "name": {"type": "string"}, "desc": {"type": "string"}}}),
            json!({"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}),
            "trello.cards.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new Trello card.".into(),
                common_mistakes: vec!["Forgetting to specify idList.".into()],
                examples: vec!["{\"idList\": \"list_abc123\", \"name\": \"Fix login bug\", \"desc\": \"Users report intermittent 500 errors\"}".into()],
                related: vec![
                    CapabilityId::from_static("trello.cards.list"),
                    CapabilityId::from_static("trello.lists.list"),
                ],
            },
        ),
        op_info(
            "trello.cards.update",
            "Update an existing card",
            json!({"type": "object", "required": ["card_id"], "properties": {"card_id": {"type": "string"}, "name": {"type": "string"}, "desc": {"type": "string"}, "closed": {"type": "boolean"}, "idList": {"type": "string"}, "due": {"type": "string"}}}),
            json!({"type": "object"}),
            "trello.cards.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Update fields on an existing Trello card (name, description, due date, list, archive status).".into(),
                common_mistakes: vec!["Setting closed=true when you mean to move the card to a different list; closed archives the card entirely.".into()],
                examples: vec!["{\"card_id\": \"card_abc123\", \"name\": \"Updated title\", \"idList\": \"list_xyz789\"}".into()],
                related: vec![
                    CapabilityId::from_static("trello.cards.get"),
                    CapabilityId::from_static("trello.cards.list"),
                ],
            },
        ),
        op_info(
            "trello.cards.delete",
            "Delete a card",
            json!({"type": "object", "required": ["card_id"], "properties": {"card_id": {"type": "string"}}}),
            json!({"type": "object"}),
            "trello.cards.delete",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Delete a Trello card. Cannot be undone.".into(),
                common_mistakes: vec!["Deleting a card when archiving (closing) it would suffice; use the update card API to set closed=true if you want to preserve the card's history.".into()],
                examples: vec!["{\"card_id\": \"card_abc123\"}".into()],
                related: vec![CapabilityId::from_static("trello.cards.list")],
            },
        ),
        op_info(
            "trello.labels.list",
            "List labels on a board",
            json!({"type": "object", "required": ["board_id"], "properties": {"board_id": {"type": "string"}}}),
            json!({"type": "object", "required": ["labels"], "properties": {"labels": {"type": "array"}}}),
            "trello.labels.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all labels available on a Trello board.".into(),
                common_mistakes: vec!["Expecting label assignments per card; this returns available labels on the board, not which cards have which labels.".into()],
                examples: vec!["{\"board_id\": \"abc123\"}".into()],
                related: vec![
                    CapabilityId::from_static("trello.boards.list"),
                    CapabilityId::from_static("trello.cards.list"),
                ],
            },
        ),
        op_info(
            "trello.members.list",
            "List members of a board",
            json!({"type": "object", "required": ["board_id"], "properties": {"board_id": {"type": "string"}}}),
            json!({"type": "object", "required": ["members"], "properties": {"members": {"type": "array"}}}),
            "trello.members.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all members of a Trello board.".into(),
                common_mistakes: vec!["Expecting all organization members; this only returns members who have been explicitly added to the board.".into()],
                examples: vec!["{\"board_id\": \"abc123\"}".into()],
                related: vec![CapabilityId::from_static("trello.boards.list")],
            },
        ),
    ]
}

/// Build the provisioning recipe for the Trello connector.
pub fn provisioning_recipe() -> ProvisioningRecipe {
    ProvisioningRecipe::new(
        RecipeId::new("trello.api_key_token"),
        "1",
        "Provision Trello connector with an API key and token",
    )
    .with_step(ProvisioningStep::new(
        StepId::new("enter_api_key"),
        ProvisioningStepType::PromptSecret {
            message: "Enter your Trello API key (from https://trello.com/power-ups/admin)".into(),
        },
    ))
    .with_step(
        ProvisioningStep::new(
            StepId::new("enter_token"),
            ProvisioningStepType::PromptSecret {
                message: "Enter your Trello token (authorize via https://trello.com/1/authorize)"
                    .into(),
            },
        )
        .depends_on(StepId::new("enter_api_key")),
    )
    .with_step(
        ProvisioningStep::new(
            StepId::new("store_credentials"),
            ProvisioningStepType::StoreSecret {
                key: "api_key_token".into(),
                value_from: StepId::new("enter_token"),
                scope: "connector:fcp.trello".into(),
            },
        )
        .depends_on(StepId::new("enter_token")),
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
    let allowed_host = host.eq_ignore_ascii_case("api.trello.com") || local;
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
                "Endpoint must use https and api.trello.com (localhost/127.0.0.1/::1 allowed for tests): {base_url}"
            ),
        )
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Build the operations info for introspection (JSON format, used by simulate).
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "trello.boards.list",
            "summary": "List boards for the authenticated user",
            "capability": "trello.boards.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "trello.boards.get",
            "summary": "Get a single board by ID",
            "capability": "trello.boards.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "trello.lists.list",
            "summary": "List lists on a board",
            "capability": "trello.boards.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "trello.cards.list",
            "summary": "List cards on a list",
            "capability": "trello.cards.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "trello.cards.get",
            "summary": "Get a single card by ID",
            "capability": "trello.cards.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "trello.cards.create",
            "summary": "Create a new card",
            "capability": "trello.cards.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "trello.cards.update",
            "summary": "Update an existing card",
            "capability": "trello.cards.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "strict",
        },
        {
            "id": "trello.cards.delete",
            "summary": "Delete a card",
            "capability": "trello.cards.delete",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "none",
        },
        {
            "id": "trello.labels.list",
            "summary": "List labels on a board",
            "capability": "trello.labels.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "trello.members.list",
            "summary": "List members of a board",
            "capability": "trello.members.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation_capability<'a>(ops: &'a serde_json::Value, id: &str) -> Option<&'a str> {
        ops.as_array()?
            .iter()
            .find(|op| op["id"] == id)?
            .get("capability")?
            .as_str()
    }

    #[test]
    fn config_from_api_key_token() {
        let config = TrelloConfig::from_params(&json!({
            "api_key": "test-api-key",
            "token": "test-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, TrelloAuth::ApiKeyToken { .. }));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = TrelloConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = TrelloConfig::from_params(&json!({
            "api_key": "key",
            "token": "tok",
            "base_url": "https://trello.example.com/1",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://trello.example.com/1");
    }

    #[test]
    fn config_rejects_all_three_auth_methods() {
        let result = TrelloConfig::from_params(&json!({
            "api_key": "key",
            "token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = TrelloConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_api_key_without_token() {
        let result = TrelloConfig::from_params(&json!({
            "api_key": "key",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_token_without_api_key() {
        let result = TrelloConfig::from_params(&json!({
            "token": "tok",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_key() {
        let result = TrelloConfig::from_params(&json!({
            "api_key": "",
            "token": "tok",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        let result = TrelloConfig::from_params(&json!({
            "api_key": "   ",
            "token": "tok",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_token() {
        let result = TrelloConfig::from_params(&json!({
            "api_key": "key",
            "token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = TrelloConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = TrelloConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"card_id": "card_abc"});
        assert_eq!(require_str(&input, "card_id").unwrap(), "card_abc");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "card_id").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"card_id": 42});
        assert!(require_str(&input, "card_id").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"card_id": null});
        assert!(require_str(&input, "card_id").is_err());
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
        assert!(ids.contains(&"trello.boards.list"));
        assert!(ids.contains(&"trello.boards.get"));
        assert!(ids.contains(&"trello.lists.list"));
        assert!(ids.contains(&"trello.cards.list"));
        assert!(ids.contains(&"trello.cards.get"));
        assert!(ids.contains(&"trello.cards.create"));
        assert!(ids.contains(&"trello.cards.update"));
        assert!(ids.contains(&"trello.cards.delete"));
        assert!(ids.contains(&"trello.labels.list"));
        assert!(ids.contains(&"trello.members.list"));
    }

    #[test]
    fn operations_cards_delete_requires_dedicated_capability() {
        let ops = operations_info();
        let delete = operation_capability(&ops, "trello.cards.delete");
        let create = operation_capability(&ops, "trello.cards.create");
        let update = operation_capability(&ops, "trello.cards.update");

        assert_eq!(delete, Some("trello.cards.delete"));
        assert_eq!(create, Some("trello.cards.write"));
        assert_eq!(update, Some("trello.cards.write"));
        assert_ne!(delete, create);

        let typed = typed_operations_info();
        let typed_delete = typed
            .iter()
            .find(|op| op.id.as_str() == "trello.cards.delete")
            .unwrap();
        let typed_create = typed
            .iter()
            .find(|op| op.id.as_str() == "trello.cards.create")
            .unwrap();
        assert_eq!(typed_delete.capability.as_str(), "trello.cards.delete");
        assert_eq!(typed_create.capability.as_str(), "trello.cards.write");
        assert_ne!(
            typed_delete.capability.as_str(),
            typed_create.capability.as_str()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn handshake_advertises_dedicated_cards_delete_capability() {
        let mut connector = TrelloConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "key",
                "token": "tok",
            }))
            .await
            .unwrap();

        let handshake = connector
            .handle_handshake(json!({"session_id": "test-session"}))
            .await
            .unwrap();
        let capabilities = handshake["capabilities"].as_array().unwrap();

        assert!(
            capabilities
                .iter()
                .any(|cap| cap.as_str() == Some("trello.cards.write"))
        );
        assert!(
            capabilities
                .iter()
                .any(|cap| cap.as_str() == Some("trello.cards.delete"))
        );
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
    fn config_trims_api_key_and_token() {
        let config =
            TrelloConfig::from_params(&json!({ "api_key": "  mykey  ", "token": "  mytok  " }))
                .unwrap();
        match &config.auth {
            TrelloAuth::ApiKeyToken { api_key, token } => {
                assert_eq!(api_key, "mykey");
                assert_eq!(token, "mytok");
            }
            TrelloAuth::CredentialId(_) => panic!("expected ApiKeyToken"),
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
        let c = TrelloConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
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
        let c1 = TrelloConnector::new();
        let c2 = TrelloConnector::default();
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
        let status = DoctorStatus::Unhealthy;
        let copied = status;
        assert_eq!(status, copied);
    }

    #[test]
    fn cards_create_is_risky() {
        let ops = operations_info();
        let create = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "trello.cards.create")
            .unwrap();
        assert_eq!(create["safety_tier"], "risky");
        assert_eq!(create["risk_level"], "medium");
    }

    #[test]
    fn cards_delete_is_dangerous() {
        let ops = operations_info();
        let delete = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "trello.cards.delete")
            .unwrap();
        assert_eq!(delete["safety_tier"], "dangerous");
        assert_eq!(delete["risk_level"], "high");
    }

    #[test]
    fn cards_update_is_risky() {
        let ops = operations_info();
        let update = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "trello.cards.update")
            .unwrap();
        assert_eq!(update["safety_tier"], "risky");
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
    fn config_rejects_whitespace_token() {
        let result = TrelloConfig::from_params(&json!({
            "api_key": "key",
            "token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_with_float_value() {
        let input = json!({"field": 1.23});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_with_object_value() {
        let input = json!({"field": {"nested": "value"}});
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn operations_all_capabilities_prefixed() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.starts_with("trello."),
                "capability {cap} should start with trello."
            );
        }
    }

    #[test]
    fn operations_all_summaries_non_empty() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {} has empty summary", op["id"]);
        }
    }

    #[test]
    fn operations_list_ops_strict_idempotent() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            if id.as_bytes().ends_with(b".list") || id.as_bytes().ends_with(b".get") {
                assert_eq!(
                    op["idempotency"].as_str().unwrap(),
                    "strict",
                    "list/get op {id} should be strictly idempotent"
                );
            }
        }
    }

    // ── Provisioning tests ────────────────────────────────────────

    #[test]
    fn provisioning_readiness_api_key_token_mode() {
        let config = TrelloConfig::from_params(&json!({
            "api_key": "test-key",
            "token": "test-token",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "api_key_token");
        assert!(readiness.api_key_configured);
        assert!(readiness.token_configured);
        assert!(!readiness.credential_id_configured);
        assert!(!readiness.requires_credential_injection);
        assert!(readiness.network_ok);
        assert_eq!(readiness.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn provisioning_readiness_credential_id_mode() {
        let config = TrelloConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert_eq!(readiness.auth_mode, "credential_id");
        assert!(!readiness.api_key_configured);
        assert!(!readiness.token_configured);
        assert!(readiness.credential_id_configured);
        assert!(readiness.requires_credential_injection);
        assert!(readiness.network_ok);
    }

    #[test]
    fn provisioning_readiness_serializes() {
        let config = TrelloConfig::from_params(&json!({
            "api_key": "key",
            "token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let v = serde_json::to_value(&readiness).unwrap();
        assert_eq!(v["auth_mode"], "api_key_token");
        assert_eq!(v["api_key_configured"], true);
        assert_eq!(v["token_configured"], true);
        assert_eq!(v["network_ok"], true);
    }

    #[test]
    fn provisioning_readiness_custom_base_url_rejected() {
        let config = TrelloConfig::from_params(&json!({
            "api_key": "key",
            "token": "tok",
            "base_url": "https://evil.example.com",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        assert!(!readiness.network_ok);
        assert!(readiness.network_message.contains("api.trello.com"));
    }

    #[test]
    fn provisioning_recipe_has_3_steps() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.id.as_str(), "trello.api_key_token");
        assert_eq!(recipe.version, "1");
        assert_eq!(recipe.steps.len(), 3);
    }

    #[test]
    fn provisioning_recipe_step_order() {
        let recipe = provisioning_recipe();
        assert_eq!(recipe.steps[0].id.as_str(), "enter_api_key");
        assert_eq!(recipe.steps[1].id.as_str(), "enter_token");
        assert_eq!(recipe.steps[2].id.as_str(), "store_credentials");
    }

    #[test]
    fn provisioning_recipe_step_dependencies() {
        let recipe = provisioning_recipe();
        assert!(recipe.steps[0].depends_on.is_empty());
        assert_eq!(recipe.steps[1].depends_on.len(), 1);
        assert_eq!(recipe.steps[1].depends_on[0].as_str(), "enter_api_key");
        assert_eq!(recipe.steps[2].depends_on.len(), 1);
        assert_eq!(recipe.steps[2].depends_on[0].as_str(), "enter_token");
    }

    #[test]
    fn provisioning_recipe_serializes() {
        let recipe = provisioning_recipe();
        let v = serde_json::to_value(&recipe).unwrap();
        assert_eq!(v["id"], "trello.api_key_token");
        assert!(v["steps"].as_array().unwrap().len() == 3);
    }

    #[test]
    fn base_url_policy_accepts_trello_https() {
        let (ok, message) = base_url_policy("https://api.trello.com/1");
        assert!(ok);
        assert!(message.contains("accepted"));
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
        let (ok, message) = base_url_policy("http://api.trello.com/1");
        assert!(!ok);
        assert!(message.contains("must use https"));
    }

    #[test]
    fn base_url_policy_rejects_unknown_host() {
        let (ok, message) = base_url_policy("https://evil.example.com");
        assert!(!ok);
        assert!(message.contains("api.trello.com"));
    }

    #[test]
    fn base_url_policy_rejects_invalid_url() {
        let (ok, message) = base_url_policy("not a url");
        assert!(!ok);
        assert!(message.contains("could not be parsed"));
    }

    #[test]
    fn provisioning_readiness_debug() {
        let config = TrelloConfig::from_params(&json!({
            "api_key": "key",
            "token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let dbg = format!("{readiness:?}");
        assert!(dbg.contains("ProvisioningReadiness"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn provisioning_readiness_clone() {
        let config = TrelloConfig::from_params(&json!({
            "api_key": "key",
            "token": "tok",
        }))
        .unwrap();
        let readiness = config.provisioning_readiness();
        let cloned = readiness.clone();
        assert_eq!(readiness.auth_mode, cloned.auth_mode);
        assert_eq!(readiness.base_url, cloned.base_url);
    }

    #[test]
    fn provisioning_recipe_description_non_empty() {
        let recipe = provisioning_recipe();
        assert!(!recipe.description.is_empty());
    }

    #[test]
    fn base_url_policy_accepts_localhost_https() {
        let (ok, _) = base_url_policy("https://localhost:8443");
        assert!(ok);
    }

    #[test]
    fn is_local_test_host_known_hosts() {
        assert!(is_local_test_host("localhost"));
        assert!(is_local_test_host("127.0.0.1"));
        assert!(is_local_test_host("::1"));
        assert!(!is_local_test_host("api.trello.com"));
        assert!(!is_local_test_host("example.com"));
    }

    #[test]
    fn provisioning_recipe_store_step_scope() {
        let recipe = provisioning_recipe();
        let store_step = &recipe.steps[2];
        match &store_step.kind {
            ProvisioningStepType::StoreSecret { scope, .. } => {
                assert_eq!(scope, "connector:fcp.trello");
            }
            _ => panic!("expected StoreSecret step type"),
        }
    }

    #[test]
    fn provisioning_recipe_prompt_steps_are_prompt_secret() {
        let recipe = provisioning_recipe();
        assert!(
            matches!(
                &recipe.steps[0].kind,
                ProvisioningStepType::PromptSecret { .. }
            ),
            "step 0 should be PromptSecret"
        );
        assert!(
            matches!(
                &recipe.steps[1].kind,
                ProvisioningStepType::PromptSecret { .. }
            ),
            "step 1 should be PromptSecret"
        );
    }
}
