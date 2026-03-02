//! FCP Stripe Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{client::StripeClient, error::StripeError};

/// FCP Stripe Connector.
pub struct StripeConnector {
    base: Arc<BaseConnector>,
    client: Option<StripeClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl StripeConnector {
    /// Create a new Stripe connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("stripe"))),
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
        let secret_key =
            params
                .get("secret_key")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing secret_key in configuration".into(),
                })?;

        let api_url = params.get("api_url").and_then(|v| v.as_str());

        let mut client = StripeClient::new(secret_key).map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;

        if let Some(url) = api_url {
            client = client.with_api_url(url);
        }

        self.client = Some(client);
        self.base.set_configured(true);
        info!("Stripe connector configured");

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
            manifest_hash: "sha256:stripe-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: true,
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
                    "stripe.create_customer",
                    "Create a new Stripe customer",
                    json!({
                        "type": "object",
                        "required": ["email"],
                        "properties": {
                            "email": { "type": "string" },
                            "name": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "customer": { "type": "object" } } }),
                    "stripe.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new customer record in Stripe.".into(),
                        common_mistakes: vec![
                            "Not checking for duplicate customers by email".into(),
                        ],
                        examples: vec![
                            r#"{"email": "user@example.com", "name": "Jane Doe"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("stripe.get_customer"),
                            CapabilityId::from_static("stripe.list_customers"),
                        ],
                    },
                ),
                op_info(
                    "stripe.get_customer",
                    "Retrieve a Stripe customer by ID",
                    json!({
                        "type": "object",
                        "required": ["customer_id"],
                        "properties": { "customer_id": { "type": "string" } }
                    }),
                    json!({ "type": "object", "properties": { "customer": { "type": "object" } } }),
                    "stripe.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Look up a customer by their Stripe ID.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"customer_id": "cus_abc123"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("stripe.create_customer"),
                            CapabilityId::from_static("stripe.list_customers"),
                        ],
                    },
                ),
                op_info(
                    "stripe.list_customers",
                    "List Stripe customers with optional filters",
                    json!({
                        "type": "object",
                        "properties": {
                            "limit": { "type": "integer" },
                            "email": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "data": { "type": "array" }, "has_more": { "type": "boolean" } } }),
                    "stripe.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List customers, optionally filtered by email.".into(),
                        common_mistakes: vec!["Not handling pagination with starting_after".into()],
                        examples: vec![r#"{"limit": 10, "email": "user@example.com"}"#.into()],
                        related: vec![CapabilityId::from_static("stripe.get_customer")],
                    },
                ),
                op_info(
                    "stripe.create_payment_intent",
                    "Create a payment intent",
                    json!({
                        "type": "object",
                        "required": ["amount", "currency"],
                        "properties": {
                            "amount": { "type": "integer" },
                            "currency": { "type": "string" },
                            "customer": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "payment_intent": { "type": "object" } } }),
                    "stripe.payment",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use:
                            "Initiate a payment. Amount is in smallest currency unit (e.g. cents)."
                                .into(),
                        common_mistakes: vec![
                            "Using dollars instead of cents for amount".into(),
                            "Invalid ISO 4217 currency code".into(),
                        ],
                        examples: vec![
                            r#"{"amount": 2000, "currency": "usd", "customer": "cus_abc123"}"#
                                .into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("stripe.get_payment_intent"),
                            CapabilityId::from_static("stripe.create_refund"),
                        ],
                    },
                ),
                op_info(
                    "stripe.get_payment_intent",
                    "Retrieve a payment intent by ID",
                    json!({
                        "type": "object",
                        "required": ["payment_intent_id"],
                        "properties": { "payment_intent_id": { "type": "string" } }
                    }),
                    json!({ "type": "object", "properties": { "payment_intent": { "type": "object" } } }),
                    "stripe.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Check status of a payment intent.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"payment_intent_id": "pi_abc123"}"#.into()],
                        related: vec![CapabilityId::from_static("stripe.create_payment_intent")],
                    },
                ),
                op_info(
                    "stripe.create_refund",
                    "Refund a payment",
                    json!({
                        "type": "object",
                        "required": ["payment_intent"],
                        "properties": {
                            "payment_intent": { "type": "string" },
                            "amount": { "type": "integer" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "refund": { "type": "object" } } }),
                    "stripe.payment",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use:
                            "Refund all or part of a payment. Omit amount for full refund.".into(),
                        common_mistakes: vec![
                            "Refunding more than the original charge amount".into(),
                        ],
                        examples: vec![r#"{"payment_intent": "pi_abc123", "amount": 500}"#.into()],
                        related: vec![CapabilityId::from_static("stripe.get_payment_intent")],
                    },
                ),
                op_info(
                    "stripe.create_subscription",
                    "Create a subscription for a customer",
                    json!({
                        "type": "object",
                        "required": ["customer", "price"],
                        "properties": {
                            "customer": { "type": "string" },
                            "price": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "subscription": { "type": "object" } } }),
                    "stripe.payment",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Start a recurring subscription for a customer.".into(),
                        common_mistakes: vec![
                            "Not attaching a payment method to the customer first".into(),
                        ],
                        examples: vec![
                            r#"{"customer": "cus_abc123", "price": "price_abc123"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("stripe.cancel_subscription"),
                            CapabilityId::from_static("stripe.get_customer"),
                        ],
                    },
                ),
                op_info(
                    "stripe.cancel_subscription",
                    "Cancel an active subscription",
                    json!({
                        "type": "object",
                        "required": ["subscription_id"],
                        "properties": { "subscription_id": { "type": "string" } }
                    }),
                    json!({ "type": "object", "properties": { "subscription": { "type": "object" } } }),
                    "stripe.payment",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Cancel a customer's subscription.".into(),
                        common_mistakes: vec![
                            "Not specifying whether to cancel immediately or at period end".into(),
                        ],
                        examples: vec![r#"{"subscription_id": "sub_abc123"}"#.into()],
                        related: vec![CapabilityId::from_static("stripe.create_subscription")],
                    },
                ),
                op_info(
                    "stripe.list_invoices",
                    "List invoices for a customer",
                    json!({
                        "type": "object",
                        "properties": {
                            "customer": { "type": "string" },
                            "limit": { "type": "integer" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "data": { "type": "array" }, "has_more": { "type": "boolean" } } }),
                    "stripe.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List invoices, optionally filtered by customer.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"customer": "cus_abc123", "limit": 10}"#.into()],
                        related: vec![CapabilityId::from_static("stripe.get_customer")],
                    },
                ),
                op_info(
                    "stripe.get_balance",
                    "Retrieve the current Stripe account balance",
                    json!({ "type": "object", "properties": {} }),
                    json!({ "type": "object", "properties": { "balance": { "type": "object" } } }),
                    "stripe.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Check the current account balance.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("stripe.list_invoices")],
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
            "stripe.create_customer" => self.invoke_create_customer(input).await,
            "stripe.get_customer" => self.invoke_get_customer(input).await,
            "stripe.list_customers" => self.invoke_list_customers(input).await,
            "stripe.create_payment_intent" => self.invoke_create_payment_intent(input).await,
            "stripe.get_payment_intent" => self.invoke_get_payment_intent(input).await,
            "stripe.create_refund" => self.invoke_create_refund(input).await,
            "stripe.create_subscription" => self.invoke_create_subscription(input).await,
            "stripe.cancel_subscription" => self.invoke_cancel_subscription(input).await,
            "stripe.list_invoices" => self.invoke_list_invoices(input).await,
            "stripe.get_balance" => self.invoke_get_balance().await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_create_customer(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let email = require_str(&input, "email")?;
        let name = input.get("name").and_then(|v| v.as_str());
        let customer = client
            .create_customer(email, name)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "customer": customer }))
    }

    async fn invoke_get_customer(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let customer_id = require_str(&input, "customer_id")?;
        let customer = client
            .get_customer(customer_id)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "customer": customer }))
    }

    async fn invoke_list_customers(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let limit = input
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let email = input.get("email").and_then(|v| v.as_str());
        let result = client
            .list_customers(limit, email)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "data": result.data, "has_more": result.has_more }))
    }

    async fn invoke_create_payment_intent(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let amount =
            input
                .get("amount")
                .and_then(|v| v.as_i64())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing required field: amount".into(),
                })?;
        let currency = require_str(&input, "currency")?;
        let customer = input.get("customer").and_then(|v| v.as_str());
        let pi = client
            .create_payment_intent(amount, currency, customer)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "payment_intent": pi }))
    }

    async fn invoke_get_payment_intent(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let pi_id = require_str(&input, "payment_intent_id")?;
        let pi = client
            .get_payment_intent(pi_id)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "payment_intent": pi }))
    }

    async fn invoke_create_refund(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let payment_intent = require_str(&input, "payment_intent")?;
        let amount = input.get("amount").and_then(|v| v.as_i64());
        let refund = client
            .create_refund(payment_intent, amount)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "refund": refund }))
    }

    async fn invoke_create_subscription(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let customer = require_str(&input, "customer")?;
        let price = require_str(&input, "price")?;
        let sub = client
            .create_subscription(customer, price)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "subscription": sub }))
    }

    async fn invoke_cancel_subscription(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let sub_id = require_str(&input, "subscription_id")?;
        let sub = client
            .cancel_subscription(sub_id)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "subscription": sub }))
    }

    async fn invoke_list_invoices(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let customer = input.get("customer").and_then(|v| v.as_str());
        let limit = input
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let result = client
            .list_invoices(customer, limit)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "data": result.data, "has_more": result.has_more }))
    }

    async fn invoke_get_balance(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let balance = client
            .get_balance()
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "balance": balance }))
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Stripe connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for StripeConnector {
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
        let mut connector = StripeConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.read"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = StripeConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = StripeConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.get_customer"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "stripe.get_customer");
        let result = connector
            .handle_invoke(json!({
                "operation": "stripe.get_customer",
                "input": { "customer_id": "cus_123" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = StripeConnector::new();
        connector.client = Some(
            StripeClient::new("sk_test")
                .unwrap()
                .with_api_url("http://localhost:9999/v1"),
        );

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.create_payment_intent"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "stripe.create_payment_intent");
        let result = connector
            .handle_invoke(json!({
                "operation": "stripe.create_payment_intent",
                "input": { "amount": 2000 },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("currency")),
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = StripeConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"stripe.create_customer"));
        assert!(op_ids.contains(&"stripe.get_customer"));
        assert!(op_ids.contains(&"stripe.list_customers"));
        assert!(op_ids.contains(&"stripe.create_payment_intent"));
        assert!(op_ids.contains(&"stripe.get_payment_intent"));
        assert!(op_ids.contains(&"stripe.create_refund"));
        assert!(op_ids.contains(&"stripe.create_subscription"));
        assert!(op_ids.contains(&"stripe.cancel_subscription"));
        assert!(op_ids.contains(&"stripe.list_invoices"));
        assert!(op_ids.contains(&"stripe.get_balance"));
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
        let computed = manifest
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(computed, computed2);
    }
}
