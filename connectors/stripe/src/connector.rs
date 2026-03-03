//! FCP Stripe Connector implementation.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use chrono::Utc;
use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_API_URL, StripeAuth, StripeClient},
    error::StripeError,
    types::StripeWebhookEvent,
};

const DEFAULT_WEBHOOK_TOLERANCE_SECONDS: i64 = 300;
const MAX_WEBHOOK_PAYLOAD_BYTES: usize = 256 * 1024;
const MAX_WEBHOOK_REPLAY_ENTRIES: usize = 4096;

type HmacSha256 = Hmac<Sha256>;

/// Parsed and validated Stripe connector configuration.
#[derive(Debug, Clone)]
struct StripeConfig {
    auth: StripeAuth,
    api_url: String,
    webhook_signing_secret: Option<String>,
    webhook_tolerance_seconds: i64,
}

impl StripeConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let secret_key = params
            .get("secret_key")
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

        let auth = match (secret_key, credential_id) {
            (Some(key), None) => StripeAuth::SecretKey(key),
            (None, Some(cred_id)) => StripeAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of secret_key or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing secret_key or credential_id in configuration".into(),
                });
            }
        };

        let api_url = params
            .get("api_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_API_URL)
            .to_string();

        let webhook_signing_secret = params
            .get("webhook_signing_secret")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let webhook_tolerance_seconds = match params.get("webhook_tolerance_seconds") {
            Some(value) => {
                let tolerance = value.as_i64().ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "webhook_tolerance_seconds must be an integer".into(),
                })?;
                if !(1..=3600).contains(&tolerance) {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "webhook_tolerance_seconds must be between 1 and 3600".into(),
                    });
                }
                tolerance
            }
            None => DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
        };

        Ok(Self {
            auth,
            api_url,
            webhook_signing_secret,
            webhook_tolerance_seconds,
        })
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

/// FCP Stripe Connector.
pub struct StripeConnector {
    base: Arc<BaseConnector>,
    config: Option<StripeConfig>,
    client: Option<StripeClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    webhook_replay_cache: Mutex<HashMap<String, i64>>,
}

impl StripeConnector {
    /// Create a new Stripe connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("stripe"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            webhook_replay_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Handle configure method.
    ///
    /// Accepts either `secret_key` (direct) or `credential_id` (secretless via
    /// egress proxy injection). Exactly one must be provided.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = StripeConfig::from_params(&params)?;

        let client =
            StripeClient::new_with_auth(config.auth.clone()).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;
        let client = client.with_api_url(&config.api_url);

        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);
        info!("Stripe connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle doctor diagnostics.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let result = self.build_doctor_result();
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    fn build_doctor_result(&self) -> DoctorResult {
        let mut checks = Vec::new();

        // Check 1: Configuration loaded
        let configured = self.config.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: configured,
            message: Some(if configured {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });

        let Some(config) = &self.config else {
            return DoctorResult::from_checks(checks);
        };

        // Check 2: HTTP client initialized
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: Some(if self.client.is_some() {
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            critical: true,
        });

        // Check 3: API URL scheme
        let scheme = if config.api_url.starts_with("https://") {
            "https"
        } else if config.api_url.starts_with("http://") {
            "http"
        } else {
            "unknown"
        };
        checks.push(DoctorCheck {
            name: "api_url".into(),
            passed: true,
            message: Some(format!("API URL ({scheme}): {}", config.api_url)),
            critical: false,
        });

        // Check 4: Auth mode
        checks.push(DoctorCheck {
            name: "auth_mode".into(),
            passed: true,
            message: Some(format!("Auth: {}", config.auth.redacted_label())),
            critical: false,
        });

        // Check 5: Network constraints - host must be api.stripe.com (or test override)
        let allowed_hosts = ["api.stripe.com"];
        let host_ok = config.api_url.starts_with("http://localhost")
            || config.api_url.starts_with("http://127.0.0.1")
            || allowed_hosts.iter().any(|h| config.api_url.contains(h));
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            passed: host_ok,
            message: Some(if host_ok {
                "API URL matches allowed host (api.stripe.com)".into()
            } else {
                format!(
                    "API URL {} does not match allowed hosts: {:?}",
                    config.api_url, allowed_hosts
                )
            }),
            critical: true,
        });

        // Check 6: Credential injection status
        let secretless = config.auth.is_secretless();
        checks.push(DoctorCheck {
            name: "credential_injection".into(),
            passed: !secretless,
            message: Some(if secretless {
                "Credential injection required via egress proxy".into()
            } else {
                "Direct secret key configured".into()
            }),
            critical: false,
        });

        DoctorResult::from_checks(checks)
    }

    /// Handle connector self-check.
    ///
    /// Performs a safe, read-only API call (get balance) to validate the secret key
    /// is valid and the Stripe API is reachable.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        if let Some(config) = &self.config {
            if config.auth.is_secretless() {
                let report = SelfCheckReport::degraded(
                    "credential_injection_required",
                    "Configured with credential_id; egress proxy injection required for checks",
                );
                return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize self-check report: {e}"),
                });
            }
        }

        let report = match client.health_check().await {
            Ok(()) => SelfCheckReport::ok(),
            Err(err) => {
                if err.is_retryable() {
                    SelfCheckReport::degraded("self_check_retryable", err.to_string())
                } else {
                    SelfCheckReport::failed("self_check_failed", err.to_string())
                }
            }
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
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
                            "name": { "type": "string" },
                            "idempotency_key": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "customer": { "type": "object" }, "audit": { "type": "object" } } }),
                    "stripe.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
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
                            CapabilityId::from_static("stripe.update_customer"),
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
                    "stripe.update_customer",
                    "Update a Stripe customer",
                    json!({
                        "type": "object",
                        "required": ["customer_id"],
                        "properties": {
                            "customer_id": { "type": "string" },
                            "email": { "type": "string" },
                            "name": { "type": "string" },
                            "idempotency_key": { "type": "string" }
                        },
                        "anyOf": [
                            { "required": ["email"] },
                            { "required": ["name"] }
                        ]
                    }),
                    json!({ "type": "object", "properties": { "customer": { "type": "object" }, "audit": { "type": "object" } } }),
                    "stripe.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Update customer metadata such as email or name.".into(),
                        common_mistakes: vec!["Sending an update without any mutable fields".into()],
                        examples: vec![r#"{"customer_id": "cus_abc123", "email": "new@example.com"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("stripe.get_customer"),
                            CapabilityId::from_static("stripe.create_customer"),
                        ],
                    },
                ),
                op_info(
                    "stripe.delete_customer",
                    "Delete a Stripe customer",
                    json!({
                        "type": "object",
                        "required": ["customer_id"],
                        "properties": {
                            "customer_id": { "type": "string" },
                            "idempotency_key": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "deleted": { "type": "object" }, "audit": { "type": "object" } } }),
                    "stripe.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Permanently remove a customer object from Stripe.".into(),
                        common_mistakes: vec!["Deleting before exporting data needed for audit/reconciliation".into()],
                        examples: vec![r#"{"customer_id": "cus_abc123"}"#.into()],
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
                    IdempotencyClass::Strict,
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
                    "stripe.confirm_payment_intent",
                    "Confirm a payment intent to proceed with payment",
                    json!({
                        "type": "object",
                        "required": ["payment_intent_id"],
                        "properties": {
                            "payment_intent_id": { "type": "string" },
                            "payment_method": { "type": "string" },
                            "idempotency_key": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "payment_intent": { "type": "object" }, "audit": { "type": "object" } } }),
                    "stripe.payment",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Confirm a payment intent after the customer has provided payment details.".into(),
                        common_mistakes: vec!["Confirming without a valid payment method attached".into()],
                        examples: vec![r#"{"payment_intent_id": "pi_abc123", "payment_method": "pm_card_visa"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("stripe.create_payment_intent"),
                            CapabilityId::from_static("stripe.capture_payment_intent"),
                        ],
                    },
                ),
                op_info(
                    "stripe.capture_payment_intent",
                    "Capture a previously authorized payment intent",
                    json!({
                        "type": "object",
                        "required": ["payment_intent_id"],
                        "properties": {
                            "payment_intent_id": { "type": "string" },
                            "amount_to_capture": { "type": "integer" },
                            "idempotency_key": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "payment_intent": { "type": "object" }, "audit": { "type": "object" } } }),
                    "stripe.payment",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Capture funds from a payment intent that was created with capture_method=manual.".into(),
                        common_mistakes: vec!["Capturing more than the authorized amount".into()],
                        examples: vec![r#"{"payment_intent_id": "pi_abc123", "amount_to_capture": 1500}"#.into()],
                        related: vec![
                            CapabilityId::from_static("stripe.confirm_payment_intent"),
                            CapabilityId::from_static("stripe.cancel_payment_intent"),
                        ],
                    },
                ),
                op_info(
                    "stripe.cancel_payment_intent",
                    "Cancel a payment intent",
                    json!({
                        "type": "object",
                        "required": ["payment_intent_id"],
                        "properties": {
                            "payment_intent_id": { "type": "string" },
                            "cancellation_reason": { "type": "string", "enum": ["duplicate", "fraudulent", "requested_by_customer", "abandoned"] },
                            "idempotency_key": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "payment_intent": { "type": "object" }, "audit": { "type": "object" } } }),
                    "stripe.payment",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Cancel a payment intent that has not yet been captured.".into(),
                        common_mistakes: vec!["Cancelling an already captured payment (use refund instead)".into()],
                        examples: vec![r#"{"payment_intent_id": "pi_abc123", "cancellation_reason": "requested_by_customer"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("stripe.create_refund"),
                            CapabilityId::from_static("stripe.get_payment_intent"),
                        ],
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
                    IdempotencyClass::Strict,
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
                            "price": { "type": "string" },
                            "idempotency_key": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "subscription": { "type": "object" }, "audit": { "type": "object" } } }),
                    "stripe.payment",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
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
                    "stripe.get_subscription",
                    "Retrieve a subscription by ID",
                    json!({
                        "type": "object",
                        "required": ["subscription_id"],
                        "properties": { "subscription_id": { "type": "string" } }
                    }),
                    json!({ "type": "object", "properties": { "subscription": { "type": "object" } } }),
                    "stripe.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Check status and billing cycle details for a subscription.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"subscription_id": "sub_abc123"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("stripe.create_subscription"),
                            CapabilityId::from_static("stripe.cancel_subscription"),
                        ],
                    },
                ),
                op_info(
                    "stripe.list_subscriptions",
                    "List subscriptions with optional filters",
                    json!({
                        "type": "object",
                        "properties": {
                            "customer": { "type": "string" },
                            "status": { "type": "string" },
                            "limit": { "type": "integer" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "data": { "type": "array" }, "has_more": { "type": "boolean" } } }),
                    "stripe.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Enumerate subscriptions for a customer or status.".into(),
                        common_mistakes: vec!["Not filtering by status when expecting only active subscriptions".into()],
                        examples: vec![r#"{"customer": "cus_abc123", "status": "active", "limit": 10}"#.into()],
                        related: vec![
                            CapabilityId::from_static("stripe.get_subscription"),
                            CapabilityId::from_static("stripe.list_invoices"),
                        ],
                    },
                ),
                op_info(
                    "stripe.cancel_subscription",
                    "Cancel an active subscription",
                    json!({
                        "type": "object",
                        "required": ["subscription_id"],
                        "properties": {
                            "subscription_id": { "type": "string" },
                            "idempotency_key": { "type": "string" }
                        }
                    }),
                    json!({ "type": "object", "properties": { "subscription": { "type": "object" }, "audit": { "type": "object" } } }),
                    "stripe.payment",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
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
                        related: vec![
                            CapabilityId::from_static("stripe.get_customer"),
                            CapabilityId::from_static("stripe.get_invoice"),
                        ],
                    },
                ),
                op_info(
                    "stripe.get_invoice",
                    "Retrieve an invoice by ID",
                    json!({
                        "type": "object",
                        "required": ["invoice_id"],
                        "properties": { "invoice_id": { "type": "string" } }
                    }),
                    json!({ "type": "object", "properties": { "invoice": { "type": "object" } } }),
                    "stripe.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve full invoice details for reconciliation.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"invoice_id": "in_abc123"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("stripe.list_invoices"),
                            CapabilityId::from_static("stripe.get_subscription"),
                        ],
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
                op_info(
                    "stripe.ingest_webhook_event",
                    "Validate and ingest a Stripe webhook payload forwarded by fcp-host",
                    json!({
                        "type": "object",
                        "required": ["payload", "stripe_signature"],
                        "properties": {
                            "payload": { "type": "string" },
                            "stripe_signature": { "type": "string" },
                            "received_at": { "type": "integer" },
                            "delivery_id": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["event", "delivery"],
                        "properties": {
                            "event": { "type": "object" },
                            "delivery": { "type": "object" }
                        }
                    }),
                    "stripe.webhook",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Process a Stripe webhook that has been forwarded by the host ingress path.".into(),
                        common_mistakes: vec![
                            "Passing parsed JSON instead of the original raw payload string".into(),
                            "Reusing a delivery ID across distinct webhook deliveries".into(),
                        ],
                        examples: vec![
                            r#"{"payload":"{\"id\":\"evt_123\",\"object\":\"event\",\"type\":\"invoice.paid\",\"created\":1700000000,\"data\":{\"object\":{\"id\":\"in_1\",\"object\":\"invoice\"}}}","stripe_signature":"t=1700000000,v1=..."}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("stripe.get_invoice"),
                            CapabilityId::from_static("stripe.get_subscription"),
                        ],
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
        let derived_idempotency_key = derive_invoke_idempotency_key(operation, &params);

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
            "stripe.create_customer" => {
                self.invoke_create_customer(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.get_customer" => self.invoke_get_customer(input).await,
            "stripe.list_customers" => self.invoke_list_customers(input).await,
            "stripe.update_customer" => {
                self.invoke_update_customer(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.delete_customer" => {
                self.invoke_delete_customer(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.create_payment_intent" => {
                self.invoke_create_payment_intent(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.get_payment_intent" => self.invoke_get_payment_intent(input).await,
            "stripe.confirm_payment_intent" => {
                self.invoke_confirm_payment_intent(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.capture_payment_intent" => {
                self.invoke_capture_payment_intent(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.cancel_payment_intent" => {
                self.invoke_cancel_payment_intent(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.create_refund" => {
                self.invoke_create_refund(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.create_subscription" => {
                self.invoke_create_subscription(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.get_subscription" => self.invoke_get_subscription(input).await,
            "stripe.list_subscriptions" => self.invoke_list_subscriptions(input).await,
            "stripe.cancel_subscription" => {
                self.invoke_cancel_subscription(input, derived_idempotency_key.as_deref())
                    .await
            }
            "stripe.list_invoices" => self.invoke_list_invoices(input).await,
            "stripe.get_invoice" => self.invoke_get_invoice(input).await,
            "stripe.get_balance" => self.invoke_get_balance().await,
            "stripe.ingest_webhook_event" => self.invoke_ingest_webhook_event(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_create_customer(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let email = require_str(&input, "email")?;
        let name = input.get("name").and_then(|v| v.as_str());
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let customer = client
            .create_customer_with_idempotency(email, name, idempotency_key.as_deref())
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "customer": customer,
            "audit": {
                "operation": "stripe.create_customer",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": customer.id,
            }
        }))
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

    async fn invoke_update_customer(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let customer_id = require_str(&input, "customer_id")?;
        let email = input.get("email").and_then(|v| v.as_str());
        let name = input.get("name").and_then(|v| v.as_str());
        if email.is_none() && name.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Must provide at least one mutable field: email or name".into(),
            });
        }
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let customer = client
            .update_customer(customer_id, email, name, idempotency_key.as_deref())
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "customer": customer,
            "audit": {
                "operation": "stripe.update_customer",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": customer.id,
            }
        }))
    }

    async fn invoke_delete_customer(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let customer_id = require_str(&input, "customer_id")?;
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let deleted = client
            .delete_customer(customer_id, idempotency_key.as_deref())
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "deleted": deleted,
            "audit": {
                "operation": "stripe.delete_customer",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": deleted.id,
            }
        }))
    }

    async fn invoke_create_payment_intent(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
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
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let pi = client
            .create_payment_intent_with_idempotency(
                amount,
                currency,
                customer,
                idempotency_key.as_deref(),
            )
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "payment_intent": pi,
            "audit": {
                "operation": "stripe.create_payment_intent",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": pi.id,
            }
        }))
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

    async fn invoke_confirm_payment_intent(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let pi_id = require_str(&input, "payment_intent_id")?;
        let payment_method = input.get("payment_method").and_then(|v| v.as_str());
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let pi = client
            .confirm_payment_intent(pi_id, payment_method, idempotency_key.as_deref())
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "payment_intent": pi,
            "audit": {
                "operation": "stripe.confirm_payment_intent",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": pi.id,
            }
        }))
    }

    async fn invoke_capture_payment_intent(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let pi_id = require_str(&input, "payment_intent_id")?;
        let amount_to_capture = input.get("amount_to_capture").and_then(|v| v.as_i64());
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let pi = client
            .capture_payment_intent(pi_id, amount_to_capture, idempotency_key.as_deref())
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "payment_intent": pi,
            "audit": {
                "operation": "stripe.capture_payment_intent",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": pi.id,
            }
        }))
    }

    async fn invoke_cancel_payment_intent(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let pi_id = require_str(&input, "payment_intent_id")?;
        let cancellation_reason = input.get("cancellation_reason").and_then(|v| v.as_str());
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let pi = client
            .cancel_payment_intent(pi_id, cancellation_reason, idempotency_key.as_deref())
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "payment_intent": pi,
            "audit": {
                "operation": "stripe.cancel_payment_intent",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": pi.id,
            }
        }))
    }

    async fn invoke_create_refund(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let payment_intent = require_str(&input, "payment_intent")?;
        let amount = input.get("amount").and_then(|v| v.as_i64());
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let refund = client
            .create_refund_with_idempotency(payment_intent, amount, idempotency_key.as_deref())
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "refund": refund,
            "audit": {
                "operation": "stripe.create_refund",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": refund.id,
            }
        }))
    }

    async fn invoke_create_subscription(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let customer = require_str(&input, "customer")?;
        let price = require_str(&input, "price")?;
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let sub = client
            .create_subscription_with_idempotency(customer, price, idempotency_key.as_deref())
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "subscription": sub,
            "audit": {
                "operation": "stripe.create_subscription",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": sub.id,
            }
        }))
    }

    async fn invoke_get_subscription(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let sub_id = require_str(&input, "subscription_id")?;
        let sub = client
            .get_subscription(sub_id)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "subscription": sub }))
    }

    async fn invoke_list_subscriptions(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let customer = input.get("customer").and_then(|v| v.as_str());
        let status = input.get("status").and_then(|v| v.as_str());
        let limit = input
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let result = client
            .list_subscriptions(customer, status, limit)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "data": result.data, "has_more": result.has_more }))
    }

    async fn invoke_cancel_subscription(
        &self,
        input: serde_json::Value,
        derived_idempotency_key: Option<&str>,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let sub_id = require_str(&input, "subscription_id")?;
        let idempotency_key = input
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| derived_idempotency_key.map(str::to_owned));
        let sub = client
            .cancel_subscription_with_idempotency(sub_id, idempotency_key.as_deref())
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({
            "subscription": sub,
            "audit": {
                "operation": "stripe.cancel_subscription",
                "side_effect": true,
                "idempotency_key": idempotency_key,
                "resource_id": sub.id,
            }
        }))
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

    async fn invoke_get_invoice(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let invoice_id = require_str(&input, "invoice_id")?;
        let invoice = client
            .get_invoice(invoice_id)
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "invoice": invoice }))
    }

    async fn invoke_get_balance(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let balance = client
            .get_balance()
            .await
            .map_err(|e: StripeError| e.to_fcp_error())?;
        Ok(json!({ "balance": balance }))
    }

    async fn invoke_ingest_webhook_event(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let payload = require_str(&input, "payload")?;
        if payload.len() > MAX_WEBHOOK_PAYLOAD_BYTES {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "Webhook payload exceeds maximum size of {MAX_WEBHOOK_PAYLOAD_BYTES} bytes"
                ),
            });
        }

        let signature_header = require_str(&input, "stripe_signature")?;
        let received_at = input
            .get("received_at")
            .and_then(|v| v.as_i64())
            .unwrap_or_else(|| Utc::now().timestamp());

        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let signing_secret =
            config
                .webhook_signing_secret
                .as_deref()
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "webhook_signing_secret must be configured for webhook ingest".into(),
                })?;

        let signature_timestamp = verify_webhook_signature(
            signing_secret,
            payload,
            signature_header,
            received_at,
            config.webhook_tolerance_seconds,
        )?;

        let event: StripeWebhookEvent =
            serde_json::from_str(payload).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "payload must be a valid Stripe event JSON object".into(),
            })?;

        let delivery_id = non_empty_trimmed(input.get("delivery_id").and_then(|v| v.as_str()))
            .map_or_else(|| event.id.clone(), str::to_owned);

        self.register_webhook_delivery(
            &delivery_id,
            received_at,
            config.webhook_tolerance_seconds,
        )?;

        let object_type = event
            .data
            .object
            .get("object")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        Ok(json!({
            "event": {
                "id": event.id,
                "type": event.event_type,
                "created": event.created,
                "livemode": event.livemode,
                "object_type": object_type,
            },
            "delivery": {
                "id": delivery_id,
                "received_at": received_at,
                "signature_timestamp": signature_timestamp,
                "signature_verified": true,
                "replay_protected": true,
            }
        }))
    }

    fn register_webhook_delivery(
        &self,
        delivery_id: &str,
        received_at: i64,
        tolerance_seconds: i64,
    ) -> FcpResult<()> {
        let mut cache = self
            .webhook_replay_cache
            .lock()
            .map_err(|_| FcpError::Internal {
                message: "Webhook replay cache lock poisoned".into(),
            })?;

        let eviction_threshold = received_at.saturating_sub(tolerance_seconds.saturating_mul(2));
        cache.retain(|_, ts| *ts >= eviction_threshold);

        if cache.contains_key(delivery_id) {
            return Err(FcpError::Conflict {
                message: "Webhook replay detected for delivery".into(),
            });
        }

        if cache.len() >= MAX_WEBHOOK_REPLAY_ENTRIES {
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, ts)| *ts)
                .map(|(key, _)| key.clone())
            {
                cache.remove(&oldest_key);
            }
        }

        cache.insert(delivery_id.to_string(), received_at);
        drop(cache);
        Ok(())
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

#[derive(Debug, Clone)]
struct StripeSignatureValues<'a> {
    timestamp: i64,
    v1_signatures: Vec<&'a str>,
}

fn parse_stripe_signature_header(header: &str) -> FcpResult<StripeSignatureValues<'_>> {
    let mut timestamp = None;
    let mut v1_signatures = Vec::new();

    for part in header.split(',') {
        let part = part.trim();
        if let Some(raw) = part.strip_prefix("t=") {
            let parsed = raw.parse::<i64>().map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "stripe_signature has invalid timestamp".into(),
            })?;
            timestamp = Some(parsed);
        } else if let Some(sig) = part.strip_prefix("v1=") {
            let sig = sig.trim();
            if !sig.is_empty() {
                v1_signatures.push(sig);
            }
        }
    }

    let timestamp = timestamp.ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "stripe_signature is missing required t= timestamp".into(),
    })?;
    if v1_signatures.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "stripe_signature is missing required v1 signature".into(),
        });
    }

    Ok(StripeSignatureValues {
        timestamp,
        v1_signatures,
    })
}

fn verify_webhook_signature(
    signing_secret: &str,
    payload: &str,
    signature_header: &str,
    received_at: i64,
    tolerance_seconds: i64,
) -> FcpResult<i64> {
    let parsed = parse_stripe_signature_header(signature_header)?;
    let clock_skew = received_at.saturating_sub(parsed.timestamp).abs();
    if clock_skew > tolerance_seconds {
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: "Webhook signature timestamp is outside allowed tolerance".into(),
        });
    }

    let signed_payload = format!("{}.{}", parsed.timestamp, payload);
    let mut mac =
        HmacSha256::new_from_slice(signing_secret.as_bytes()).map_err(|_| FcpError::Internal {
            message: "Failed to initialize webhook signature verifier".into(),
        })?;
    mac.update(signed_payload.as_bytes());
    let expected = mac.finalize().into_bytes();

    let mut verified = false;
    for candidate in parsed.v1_signatures {
        let Ok(decoded) = hex::decode(candidate) else {
            continue;
        };
        if decoded.len() == expected.len() && expected.as_slice().ct_eq(decoded.as_slice()).into() {
            verified = true;
            break;
        }
    }

    if !verified {
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: "Webhook signature verification failed".into(),
        });
    }

    Ok(parsed.timestamp)
}

fn derive_invoke_idempotency_key(operation: &str, params: &serde_json::Value) -> Option<String> {
    if let Some(explicit) =
        non_empty_trimmed(params.get("idempotency_key").and_then(|v| v.as_str()))
    {
        return Some(explicit.to_string());
    }

    let seed = non_empty_trimmed(params.get("operation_id").and_then(|v| v.as_str()))
        .or_else(|| non_empty_trimmed(params.get("request_id").and_then(|v| v.as_str())))?;

    let op = sanitize_idempotency_component(operation, "op");
    let seed = sanitize_idempotency_component(seed, "seed");
    Some(format!("fcp2:{op}:{seed}"))
}

fn non_empty_trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

fn sanitize_idempotency_component(component: &str, fallback: &str) -> String {
    let sanitized: String = component
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect();

    let trimmed = sanitized.trim_matches('-');
    let selected = if trimmed.is_empty() {
        fallback
    } else {
        trimmed
    };
    selected.chars().take(64).collect()
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
    async fn test_invoke_update_customer_requires_mutable_field() {
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
                "capabilities_requested": ["stripe.update_customer"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "stripe.update_customer");
        let result = connector
            .handle_invoke(json!({
                "operation": "stripe.update_customer",
                "input": { "customer_id": "cus_123" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("email or name"));
            }
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
        assert!(op_ids.contains(&"stripe.update_customer"));
        assert!(op_ids.contains(&"stripe.delete_customer"));
        assert!(op_ids.contains(&"stripe.create_payment_intent"));
        assert!(op_ids.contains(&"stripe.get_payment_intent"));
        assert!(op_ids.contains(&"stripe.create_refund"));
        assert!(op_ids.contains(&"stripe.create_subscription"));
        assert!(op_ids.contains(&"stripe.get_subscription"));
        assert!(op_ids.contains(&"stripe.list_subscriptions"));
        assert!(op_ids.contains(&"stripe.cancel_subscription"));
        assert!(op_ids.contains(&"stripe.list_invoices"));
        assert!(op_ids.contains(&"stripe.get_invoice"));
        assert!(op_ids.contains(&"stripe.get_balance"));
        assert!(op_ids.contains(&"stripe.ingest_webhook_event"));
        assert!(op_ids.contains(&"stripe.confirm_payment_intent"));
        assert!(op_ids.contains(&"stripe.capture_payment_intent"));
        assert!(op_ids.contains(&"stripe.cancel_payment_intent"));
        assert_eq!(ops.len(), 19);
    }

    #[test]
    fn test_derive_invoke_idempotency_key_prefers_explicit_key() {
        let params = json!({
            "operation_id": "op-123",
            "idempotency_key": "idem-explicit"
        });
        let key = derive_invoke_idempotency_key("stripe.create_refund", &params);
        assert_eq!(key.as_deref(), Some("idem-explicit"));
    }

    #[test]
    fn test_derive_invoke_idempotency_key_from_operation_id() {
        let params = json!({
            "operation_id": "op 123/unsafe"
        });
        let key = derive_invoke_idempotency_key("stripe.create_refund", &params);
        assert_eq!(
            key.as_deref(),
            Some("fcp2:stripe.create_refund:op-123-unsafe")
        );
    }

    #[test]
    fn test_derive_invoke_idempotency_key_from_request_id() {
        let params = json!({
            "request_id": "req:42"
        });
        let key = derive_invoke_idempotency_key("stripe.capture_payment_intent", &params);
        assert_eq!(
            key.as_deref(),
            Some("fcp2:stripe.capture_payment_intent:req-42")
        );
    }

    #[test]
    fn test_derive_invoke_idempotency_key_none_without_seed() {
        let params = json!({ "operation": "stripe.create_payment_intent" });
        let key = derive_invoke_idempotency_key("stripe.create_payment_intent", &params);
        assert!(key.is_none());
    }

    fn build_test_webhook_signature(secret: &str, payload: &str, timestamp: i64) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac init");
        mac.update(format!("{timestamp}.{payload}").as_bytes());
        let digest = mac.finalize().into_bytes();
        format!("t={timestamp},v1={}", hex::encode(digest))
    }

    #[test]
    fn test_parse_stripe_signature_header() {
        let parsed = parse_stripe_signature_header("t=1700000000, v1=abc, v1=def").unwrap();
        assert_eq!(parsed.timestamp, 1_700_000_000);
        assert_eq!(parsed.v1_signatures, vec!["abc", "def"]);
    }

    #[test]
    fn test_verify_webhook_signature_success() {
        let payload = r#"{"id":"evt_1","object":"event","type":"invoice.paid","created":1700000000,"data":{"object":{"id":"in_1","object":"invoice"}}}"#;
        let header = build_test_webhook_signature("whsec_test", payload, 1_700_000_000);

        let timestamp = verify_webhook_signature(
            "whsec_test",
            payload,
            &header,
            1_700_000_010,
            DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
        )
        .unwrap();
        assert_eq!(timestamp, 1_700_000_000);
    }

    #[test]
    fn test_verify_webhook_signature_rejects_invalid_signature() {
        let payload = r#"{"id":"evt_1","object":"event","type":"invoice.paid","created":1700000000,"data":{"object":{"id":"in_1","object":"invoice"}}}"#;
        let err = verify_webhook_signature(
            "whsec_test",
            payload,
            "t=1700000000,v1=deadbeef",
            1_700_000_000,
            DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
        )
        .unwrap_err();
        assert!(matches!(err, FcpError::Unauthorized { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_success() {
        let mut connector = StripeConnector::new();
        connector
            .handle_configure(json!({
                "secret_key": "sk_test",
                "webhook_signing_secret": "whsec_test",
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.ingest_webhook_event"]
            }))
            .await
            .unwrap();

        let payload = r#"{"id":"evt_123","object":"event","type":"invoice.paid","created":1700000000,"data":{"object":{"id":"in_123","object":"invoice"}}}"#;
        let header = build_test_webhook_signature("whsec_test", payload, 1_700_000_000);
        let token = generate_valid_token(&signing_key, "stripe.ingest_webhook_event");

        let result = connector
            .handle_invoke(json!({
                "operation": "stripe.ingest_webhook_event",
                "input": {
                    "payload": payload,
                    "stripe_signature": header,
                    "received_at": 1_700_000_005
                },
                "capability_token": token
            }))
            .await
            .unwrap();

        assert_eq!(result["event"]["id"], "evt_123");
        assert_eq!(result["event"]["type"], "invoice.paid");
        assert_eq!(result["delivery"]["signature_verified"], true);
        assert_eq!(result["delivery"]["replay_protected"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_replay_rejected() {
        let mut connector = StripeConnector::new();
        connector
            .handle_configure(json!({
                "secret_key": "sk_test",
                "webhook_signing_secret": "whsec_test",
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.ingest_webhook_event"]
            }))
            .await
            .unwrap();

        let payload = r#"{"id":"evt_replay","object":"event","type":"invoice.paid","created":1700000000,"data":{"object":{"id":"in_123","object":"invoice"}}}"#;
        let header = build_test_webhook_signature("whsec_test", payload, 1_700_000_000);
        let token = generate_valid_token(&signing_key, "stripe.ingest_webhook_event");
        let invoke = json!({
            "operation": "stripe.ingest_webhook_event",
            "input": {
                "payload": payload,
                "stripe_signature": header,
                "received_at": 1_700_000_005
            },
            "capability_token": token
        });

        connector.handle_invoke(invoke.clone()).await.unwrap();
        let err = connector.handle_invoke(invoke).await.unwrap_err();
        assert!(matches!(err, FcpError::Conflict { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_ingest_webhook_event_signature_failure_is_redacted() {
        let mut connector = StripeConnector::new();
        connector
            .handle_configure(json!({
                "secret_key": "sk_test",
                "webhook_signing_secret": "whsec_super_secret_123",
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["stripe.ingest_webhook_event"]
            }))
            .await
            .unwrap();

        let payload = r#"{"id":"evt_bad","object":"event","type":"invoice.paid","created":1700000000,"data":{"object":{"id":"in_123","object":"invoice"}}}"#;
        let token = generate_valid_token(&signing_key, "stripe.ingest_webhook_event");
        let err = connector
            .handle_invoke(json!({
                "operation": "stripe.ingest_webhook_event",
                "input": {
                    "payload": payload,
                    "stripe_signature": "t=1700000000,v1=badbadbad"
                },
                "capability_token": token
            }))
            .await
            .unwrap_err();

        let msg = format!("{err:?}");
        assert!(!msg.contains("whsec_super_secret_123"));
        assert!(matches!(err, FcpError::Unauthorized { .. }));
    }

    // ── Doctor tests ──────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = StripeConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        let config_check = &checks[0];
        assert_eq!(config_check["name"], "configuration");
        assert!(!config_check["passed"].as_bool().unwrap());
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_secret_key() {
        let mut connector = StripeConnector::new();
        connector
            .handle_configure(json!({ "secret_key": "sk_test_123" }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        let auth_check = checks.iter().find(|c| c["name"] == "auth_mode").unwrap();
        assert!(
            auth_check["message"]
                .as_str()
                .unwrap()
                .contains("secret_key:redacted")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_credential_id() {
        let mut connector = StripeConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert!(!cred_check["passed"].as_bool().unwrap());
        assert!(!cred_check["critical"].as_bool().unwrap());
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_bad_network_host() {
        let mut connector = StripeConnector::new();
        connector
            .handle_configure(json!({
                "secret_key": "sk_test",
                "api_url": "https://evil.example.com/v1"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
    }

    // ── Self-check tests ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        use fcp_core::SelfCheckStatus;
        let connector = StripeConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_mode() {
        use fcp_core::SelfCheckStatus;
        let mut connector = StripeConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
        assert_eq!(
            report.reason_code.as_deref(),
            Some("credential_injection_required")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_unreachable_api() {
        use fcp_core::SelfCheckStatus;
        let mut connector = StripeConnector::new();
        connector
            .handle_configure(json!({
                "secret_key": "sk_test",
                "api_url": "http://127.0.0.1:1/v1"
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        let report: SelfCheckReport = serde_json::from_value(result).unwrap();
        assert!(
            report.status == SelfCheckStatus::Degraded || report.status == SelfCheckStatus::Failed
        );
    }

    // ── Configure multi-auth tests ──────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_secret_key() {
        let mut connector = StripeConnector::new();
        let result = connector
            .handle_configure(json!({ "secret_key": "sk_test_123" }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_credential_id() {
        let mut connector = StripeConnector::new();
        let result = connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_both_rejected() {
        let mut connector = StripeConnector::new();
        let result = connector
            .handle_configure(json!({
                "secret_key": "sk_test",
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_none_rejected() {
        let mut connector = StripeConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    // ── Invoke dispatch tests for new operations ────────────────

    #[fcp_async_core::runtime::test]
    async fn test_invoke_confirm_missing_payment_intent_id() {
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
                "capabilities_requested": ["stripe.confirm_payment_intent"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "stripe.confirm_payment_intent");
        let result = connector
            .handle_invoke(json!({
                "operation": "stripe.confirm_payment_intent",
                "input": {},
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("payment_intent_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_capture_missing_payment_intent_id() {
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
                "capabilities_requested": ["stripe.capture_payment_intent"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "stripe.capture_payment_intent");
        let result = connector
            .handle_invoke(json!({
                "operation": "stripe.capture_payment_intent",
                "input": {},
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("payment_intent_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_cancel_missing_payment_intent_id() {
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
                "capabilities_requested": ["stripe.cancel_payment_intent"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "stripe.cancel_payment_intent");
        let result = connector
            .handle_invoke(json!({
                "operation": "stripe.cancel_payment_intent",
                "input": {},
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("payment_intent_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    // ── Introspect schema detail tests ────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_introspect_new_ops_have_idempotency_class() {
        let connector = StripeConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op_id in [
            "stripe.confirm_payment_intent",
            "stripe.capture_payment_intent",
            "stripe.cancel_payment_intent",
        ] {
            let op = ops.iter().find(|o| o["id"] == op_id).unwrap();
            assert_eq!(
                op["idempotency"], "strict",
                "{op_id} should have strict idempotency"
            );
            assert_eq!(op["risk_level"], "high", "{op_id} should be high risk");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_mutation_ops_have_idempotency_class() {
        let connector = StripeConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let create_pi = ops
            .iter()
            .find(|o| o["id"] == "stripe.create_payment_intent")
            .unwrap();
        assert_eq!(create_pi["idempotency"], "strict");

        let create_refund = ops
            .iter()
            .find(|o| o["id"] == "stripe.create_refund")
            .unwrap();
        assert_eq!(create_refund["idempotency"], "strict");

        let create_customer = ops
            .iter()
            .find(|o| o["id"] == "stripe.create_customer")
            .unwrap();
        assert_eq!(create_customer["idempotency"], "strict");

        let create_subscription = ops
            .iter()
            .find(|o| o["id"] == "stripe.create_subscription")
            .unwrap();
        assert_eq!(create_subscription["idempotency"], "strict");

        let cancel_subscription = ops
            .iter()
            .find(|o| o["id"] == "stripe.cancel_subscription")
            .unwrap();
        assert_eq!(cancel_subscription["idempotency"], "strict");
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
