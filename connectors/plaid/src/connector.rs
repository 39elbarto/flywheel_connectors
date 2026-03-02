//! FCP Plaid Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::PlaidClient, error::PlaidError};

/// FCP Plaid Connector.
pub struct PlaidConnector {
    base: Arc<BaseConnector>,
    client: Option<PlaidClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl PlaidConnector {
    /// Create a new Plaid connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("plaid"))),
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client_id =
            params
                .get("client_id")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing client_id in configuration".into(),
                })?;

        let secret =
            params
                .get("secret")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing secret in configuration".into(),
                })?;

        let base_url = params.get("base_url").and_then(|v| v.as_str());

        let mut client =
            PlaidClient::new(client_id, secret).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;

        if let Some(url) = base_url {
            client = client.with_base_url(url);
        }

        self.client = Some(client);
        self.base.set_configured(true);
        info!("Plaid connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:plaid-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 100,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle health check.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle introspect method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                op_info(
                    "plaid.link_token_create",
                    "Create a Link token for Plaid Link initialization",
                    json!({
                        "type": "object",
                        "required": ["client_name", "products", "country_codes", "language"],
                        "properties": {
                            "client_name": { "type": "string" },
                            "products": { "type": "array" },
                            "country_codes": { "type": "array" },
                            "language": { "type": "string", "default": "en" },
                            "user": { "type": "object" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["link_token", "expiration"],
                        "properties": {
                            "link_token": { "type": "string" },
                            "expiration": { "type": "string" }
                        }
                    }),
                    "plaid.link",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a Link token to initialize Plaid Link in the client. First step in the Plaid flow.".into(),
                        common_mistakes: vec!["Not including required products for the intended use case.".into()],
                        examples: vec![
                            r#"{"client_name": "MyApp", "products": ["transactions"], "country_codes": ["US"], "language": "en", "user": {"client_user_id": "user-123"}}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("plaid.token_exchange")],
                    },
                ),
                op_info(
                    "plaid.token_exchange",
                    "Exchange a public token from Plaid Link for an access token",
                    json!({
                        "type": "object",
                        "required": ["public_token"],
                        "properties": {
                            "public_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["access_token", "item_id"],
                        "properties": {
                            "access_token": { "type": "string" },
                            "item_id": { "type": "string" }
                        }
                    }),
                    "plaid.link",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Exchange the public_token from Plaid Link for a persistent access_token. Second step in Plaid flow.".into(),
                        common_mistakes: vec!["Calling multiple times with the same public_token (it's single-use).".into()],
                        examples: vec![r#"{"public_token": "public-sandbox-xxxx"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("plaid.link_token_create"),
                            CapabilityId::from_static("plaid.accounts_get"),
                        ],
                    },
                ),
                op_info(
                    "plaid.accounts_get",
                    "Get all accounts for a linked item",
                    json!({
                        "type": "object",
                        "required": ["access_token"],
                        "properties": {
                            "access_token": { "type": "string" },
                            "options": { "type": "object" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["accounts", "item"],
                        "properties": {
                            "accounts": { "type": "array" },
                            "item": { "type": "object" }
                        }
                    }),
                    "plaid.accounts.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all accounts (checking, savings, credit, loan, investment) for a linked institution.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"access_token": "access-sandbox-xxxx"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("plaid.accounts_balance_get"),
                            CapabilityId::from_static("plaid.transactions_sync"),
                        ],
                    },
                ),
                op_info(
                    "plaid.accounts_balance_get",
                    "Get real-time balance for accounts",
                    json!({
                        "type": "object",
                        "required": ["access_token"],
                        "properties": {
                            "access_token": { "type": "string" },
                            "options": { "type": "object" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["accounts"],
                        "properties": {
                            "accounts": { "type": "array" }
                        }
                    }),
                    "plaid.accounts.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get real-time balances (current, available, limit) -- triggers a live connection to the institution.".into(),
                        common_mistakes: vec!["Calling too frequently -- balance checks are rate-limited and may count against API quotas.".into()],
                        examples: vec![r#"{"access_token": "access-sandbox-xxxx"}"#.into()],
                        related: vec![CapabilityId::from_static("plaid.accounts_get")],
                    },
                ),
                op_info(
                    "plaid.transactions_get",
                    "Get transactions for a date range (legacy endpoint)",
                    json!({
                        "type": "object",
                        "required": ["access_token", "start_date", "end_date"],
                        "properties": {
                            "access_token": { "type": "string" },
                            "start_date": { "type": "string" },
                            "end_date": { "type": "string" },
                            "options": { "type": "object" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["accounts", "transactions", "total_transactions"],
                        "properties": {
                            "accounts": { "type": "array" },
                            "transactions": { "type": "array" },
                            "total_transactions": { "type": "integer" }
                        }
                    }),
                    "plaid.transactions.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get transactions for a date range. Prefer transactions_sync for incremental updates.".into(),
                        common_mistakes: vec!["Not paginating -- default returns only 100 transactions.".into()],
                        examples: vec![
                            r#"{"access_token": "access-sandbox-xxxx", "start_date": "2026-01-01", "end_date": "2026-01-31"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("plaid.transactions_sync")],
                    },
                ),
                op_info(
                    "plaid.transactions_sync",
                    "Incrementally sync transactions using a cursor",
                    json!({
                        "type": "object",
                        "required": ["access_token"],
                        "properties": {
                            "access_token": { "type": "string" },
                            "cursor": { "type": "string" },
                            "count": { "type": "integer", "minimum": 1, "maximum": 500 }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["added", "modified", "removed", "next_cursor", "has_more"],
                        "properties": {
                            "added": { "type": "array" },
                            "modified": { "type": "array" },
                            "removed": { "type": "array" },
                            "next_cursor": { "type": "string" },
                            "has_more": { "type": "boolean" }
                        }
                    }),
                    "plaid.transactions.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Incrementally sync transactions -- returns added, modified, and removed since last cursor. Preferred over transactions_get.".into(),
                        common_mistakes: vec![
                            "Not persisting the cursor between syncs.".into(),
                            "Not looping until has_more is false.".into(),
                        ],
                        examples: vec![
                            r#"{"access_token": "access-sandbox-xxxx", "cursor": "", "count": 100}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("plaid.transactions_get")],
                    },
                ),
                op_info(
                    "plaid.auth_get",
                    "Get account and routing numbers for ACH",
                    json!({
                        "type": "object",
                        "required": ["access_token"],
                        "properties": {
                            "access_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["accounts", "numbers"],
                        "properties": {
                            "accounts": { "type": "array" },
                            "numbers": { "type": "object" }
                        }
                    }),
                    "plaid.auth.read",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get account and routing numbers for ACH transfers. Requires 'auth' product.".into(),
                        common_mistakes: vec!["Requesting auth without the 'auth' product enabled in Link.".into()],
                        examples: vec![r#"{"access_token": "access-sandbox-xxxx"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("plaid.identity_get"),
                            CapabilityId::from_static("plaid.accounts_get"),
                        ],
                    },
                ),
                op_info(
                    "plaid.identity_get",
                    "Get account holder identity information (name, address, email, phone)",
                    json!({
                        "type": "object",
                        "required": ["access_token"],
                        "properties": {
                            "access_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["accounts"],
                        "properties": {
                            "accounts": { "type": "array" }
                        }
                    }),
                    "plaid.identity.read",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get PII (name, address, email, phone) for account holders. Requires 'identity' product.".into(),
                        common_mistakes: vec!["Requesting identity without the 'identity' product enabled in Link.".into()],
                        examples: vec![r#"{"access_token": "access-sandbox-xxxx"}"#.into()],
                        related: vec![CapabilityId::from_static("plaid.auth_get")],
                    },
                ),
                op_info(
                    "plaid.investments_holdings_get",
                    "Get investment holdings (securities, quantities, values)",
                    json!({
                        "type": "object",
                        "required": ["access_token"],
                        "properties": {
                            "access_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["accounts", "holdings", "securities"],
                        "properties": {
                            "accounts": { "type": "array" },
                            "holdings": { "type": "array" },
                            "securities": { "type": "array" }
                        }
                    }),
                    "plaid.investments.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get investment portfolio holdings. Requires 'investments' product.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"access_token": "access-sandbox-xxxx"}"#.into()],
                        related: vec![CapabilityId::from_static("plaid.accounts_get")],
                    },
                ),
                op_info(
                    "plaid.liabilities_get",
                    "Get liability details (credit cards, student loans, mortgages)",
                    json!({
                        "type": "object",
                        "required": ["access_token"],
                        "properties": {
                            "access_token": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["accounts", "liabilities"],
                        "properties": {
                            "accounts": { "type": "array" },
                            "liabilities": { "type": "object" }
                        }
                    }),
                    "plaid.liabilities.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get credit card, student loan, and mortgage liability details. Requires 'liabilities' product.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"access_token": "access-sandbox-xxxx"}"#.into()],
                        related: vec![CapabilityId::from_static("plaid.accounts_get")],
                    },
                ),
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

    /// Handle simulate method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle invoke method.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation =
            params
                .get("operation")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id: CapabilityId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "plaid.link_token_create" => self.invoke_link_token_create(input).await,
            "plaid.token_exchange" => self.invoke_token_exchange(input).await,
            "plaid.accounts_get" => self.invoke_accounts_get(input).await,
            "plaid.accounts_balance_get" => self.invoke_accounts_balance_get(input).await,
            "plaid.transactions_get" => self.invoke_transactions_get(input).await,
            "plaid.transactions_sync" => self.invoke_transactions_sync(input).await,
            "plaid.auth_get" => self.invoke_auth_get(input).await,
            "plaid.identity_get" => self.invoke_identity_get(input).await,
            "plaid.investments_holdings_get" => self.invoke_investments_holdings_get(input).await,
            "plaid.liabilities_get" => self.invoke_liabilities_get(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_link_token_create(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let client_name = require_str(&input, "client_name")?;
        let products: Vec<String> = input
            .get("products")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: products".into(),
            })?;
        let country_codes: Vec<String> = input
            .get("country_codes")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: country_codes".into(),
            })?;
        let language = input
            .get("language")
            .and_then(|v| v.as_str())
            .unwrap_or("en");
        let user = input.get("user");
        let result = client
            .link_token_create(client_name, &products, &country_codes, language, user)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(json!({
            "link_token": result.link_token,
            "expiration": result.expiration,
        }))
    }

    async fn invoke_token_exchange(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let public_token = require_str(&input, "public_token")?;
        let result = client
            .token_exchange(public_token)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(json!({
            "access_token": result.access_token,
            "item_id": result.item_id,
        }))
    }

    async fn invoke_accounts_get(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let access_token = require_str(&input, "access_token")?;
        let options = input.get("options");
        let (accounts, item) = client
            .accounts_get(access_token, options)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(json!({ "accounts": accounts, "item": item }))
    }

    async fn invoke_accounts_balance_get(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let access_token = require_str(&input, "access_token")?;
        let options = input.get("options");
        let accounts = client
            .accounts_balance_get(access_token, options)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(json!({ "accounts": accounts }))
    }

    async fn invoke_transactions_get(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let access_token = require_str(&input, "access_token")?;
        let start_date = require_str(&input, "start_date")?;
        let end_date = require_str(&input, "end_date")?;
        let options = input.get("options");
        let result = client
            .transactions_get(access_token, start_date, end_date, options)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_transactions_sync(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let access_token = require_str(&input, "access_token")?;
        let cursor = input.get("cursor").and_then(|v| v.as_str());
        let count = input.get("count").and_then(|v| v.as_u64()).map(|v| v as u32);
        let result = client
            .transactions_sync(access_token, cursor, count)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(json!({
            "added": result.added,
            "modified": result.modified,
            "removed": result.removed,
            "next_cursor": result.next_cursor,
            "has_more": result.has_more,
        }))
    }

    async fn invoke_auth_get(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let access_token = require_str(&input, "access_token")?;
        let (accounts, numbers) = client
            .auth_get(access_token)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(json!({ "accounts": accounts, "numbers": numbers }))
    }

    async fn invoke_identity_get(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let access_token = require_str(&input, "access_token")?;
        let accounts = client
            .identity_get(access_token)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(json!({ "accounts": accounts }))
    }

    async fn invoke_investments_holdings_get(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let access_token = require_str(&input, "access_token")?;
        let result = client
            .investments_holdings_get(access_token)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(result)
    }

    async fn invoke_liabilities_get(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let access_token = require_str(&input, "access_token")?;
        let (accounts, liabilities) = client
            .liabilities_get(access_token)
            .await
            .map_err(|e: PlaidError| e.to_fcp_error())?;
        Ok(json!({ "accounts": accounts, "liabilities": liabilities }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(&self, _params: serde_json::Value) -> FcpResult<serde_json::Value> {
        info!("Plaid connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for PlaidConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::ConnectorManifest;
    use std::path::PathBuf;

    fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> CapabilityToken {
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[cap])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .sign(signing_key)
            .unwrap();
        CapabilityToken { raw: cose }
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = PlaidConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["plaid.accounts.read"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = PlaidConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = PlaidConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["plaid.accounts_get"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "plaid.accounts_get");
        let result = connector
            .handle_invoke(json!({
                "operation": "plaid.accounts_get",
                "input": { "access_token": "access-sandbox-xxx" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = PlaidConnector::new();
        connector.client = Some(
            PlaidClient::new("test_id", "test_secret")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["plaid.transactions_get"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "plaid.transactions_get");
        let result = connector
            .handle_invoke(json!({
                "operation": "plaid.transactions_get",
                "input": { "access_token": "access-sandbox-xxx" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("start_date")),
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = PlaidConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"plaid.link_token_create"));
        assert!(op_ids.contains(&"plaid.token_exchange"));
        assert!(op_ids.contains(&"plaid.accounts_get"));
        assert!(op_ids.contains(&"plaid.accounts_balance_get"));
        assert!(op_ids.contains(&"plaid.transactions_get"));
        assert!(op_ids.contains(&"plaid.transactions_sync"));
        assert!(op_ids.contains(&"plaid.auth_get"));
        assert!(op_ids.contains(&"plaid.identity_get"));
        assert!(op_ids.contains(&"plaid.investments_holdings_get"));
        assert!(op_ids.contains(&"plaid.liabilities_get"));
        assert_eq!(ops.len(), 10);
    }

    #[test]
    fn manifest_interface_hash_is_deterministic() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        if !manifest_path.exists() {
            eprintln!("manifest.toml missing; skipping interface_hash check");
            return;
        }

        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let computed = manifest.compute_interface_hash().expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2.compute_interface_hash().expect("compute interface hash");
        assert_eq!(computed, computed2);
    }
}
