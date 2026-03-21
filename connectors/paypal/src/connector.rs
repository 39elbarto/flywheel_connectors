//! PayPal connector implementation.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, FcpConnector, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse,
    UnsubscribeRequest,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::client::PayPalClient;
use crate::types::{
    Amount, CreateBillingInfo, CreateInvoice, CreateInvoiceDetail, CreateInvoiceItem, CreateOrder,
    CreatePurchaseUnit, CreateRecipient, RefundRequest,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const PAYPAL_SANDBOX_BASE_URL: &str = "https://api-m.sandbox.paypal.com";
const PAYPAL_PRODUCTION_BASE_URL: &str = "https://api-m.paypal.com";
const PAYPAL_IMPLEMENTATION_API: &str = "paypal_rest_v2";
const PAYPAL_IMPLEMENTATION_STATUS: &str = "first_slice";
const PAYPAL_AUTH_MODEL: &str = "oauth2_client_credentials";
const PAYPAL_BINDING_MODEL: &str = "single_merchant_environment";
const PAYPAL_FIRST_SLICE_NON_GOALS: &[&str] = &[
    "Payouts, subscriptions, disputes, and partner onboarding",
    "Webhook ingestion or streaming event delivery",
    "Multi-merchant routing from a single connector instance",
    "Vault and saved-payment-method flows",
];

const OP_ORDERS_CREATE: &str = "paypal.orders.create";
const OP_ORDERS_GET: &str = "paypal.orders.get";
const OP_ORDERS_CAPTURE: &str = "paypal.orders.capture";
const OP_PAYMENTS_LIST: &str = "paypal.payments.list";
const OP_PAYMENTS_GET: &str = "paypal.payments.get";
const OP_PAYMENTS_REFUND: &str = "paypal.payments.refund";
const OP_INVOICES_CREATE: &str = "paypal.invoices.create";
const OP_INVOICES_LIST: &str = "paypal.invoices.list";
const OP_INVOICES_SEND: &str = "paypal.invoices.send";
const OP_HEALTH: &str = "paypal.health";

const CAP_ORDERS_READ: &str = "paypal.orders.read";
const CAP_ORDERS_WRITE: &str = "paypal.orders.write";
const CAP_PAYMENTS_READ: &str = "paypal.payments.read";
const CAP_PAYMENTS_WRITE: &str = "paypal.payments.write";
const CAP_INVOICES_READ: &str = "paypal.invoices.read";
const CAP_INVOICES_WRITE: &str = "paypal.invoices.write";

#[derive(Clone, serde::Deserialize)]
pub struct PayPalConfig {
    pub client_id: String,
    pub client_secret: String,
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default)]
    pub sandbox: bool,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}

fn default_base_url() -> String {
    PAYPAL_SANDBOX_BASE_URL.into()
}

const fn default_timeout_ms() -> u64 {
    30_000
}

impl std::fmt::Debug for PayPalConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PayPalConfig")
            .field("client_id", &"[REDACTED]")
            .field("client_secret", &"[REDACTED]")
            .field("base_url", &self.base_url)
            .field("sandbox", &self.sandbox)
            .finish()
    }
}

impl PayPalConfig {
    fn validate(&self) -> Result<(), String> {
        if self.client_id.is_empty() {
            return Err("client_id is required".into());
        }
        if self.client_secret.is_empty() {
            return Err("client_secret is required".into());
        }
        let parsed = reqwest::Url::parse(&self.base_url)
            .map_err(|err| format!("base_url must be a valid absolute URL: {err}"))?;
        if parsed.scheme() != "https" {
            return Err("base_url must use https".into());
        }
        if parsed.path() != "/" && !parsed.path().is_empty() {
            return Err("base_url must not include an API path".into());
        }
        let Some(host) = parsed.host_str() else {
            return Err("base_url must include a hostname".into());
        };
        match (self.sandbox, host) {
            (true, "api-m.sandbox.paypal.com") | (false, "api-m.paypal.com") => {}
            (true, _) => {
                return Err(
                    "sandbox=true requires base_url https://api-m.sandbox.paypal.com".into(),
                );
            }
            (false, _) => {
                return Err("sandbox=false requires base_url https://api-m.paypal.com".into());
            }
        }
        Ok(())
    }

    fn from_value(val: serde_json::Value) -> FcpResult<Self> {
        let mut config: Self =
            serde_json::from_value(val).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid configuration: {e}"),
            })?;
        config.client_id = config.client_id.trim().to_owned();
        config.client_secret = config.client_secret.trim().to_owned();
        config.base_url = config.base_url.trim().trim_end_matches('/').to_owned();
        if config.base_url.is_empty() || config.base_url == default_base_url() {
            config.base_url = if config.sandbox {
                PAYPAL_SANDBOX_BASE_URL.into()
            } else {
                PAYPAL_PRODUCTION_BASE_URL.into()
            };
        }
        config.validate().map_err(|e| FcpError::InvalidRequest {
            code: 1001,
            message: e,
        })?;
        Ok(config)
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorResult {
    pub ready: bool,
    pub status: DoctorStatus,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let ready = checks.iter().filter(|c| c.critical).all(|c| c.passed);
        let status = if checks.iter().any(|c| c.critical && !c.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| !c.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self {
            ready,
            status,
            checks,
        }
    }
}

fn contract_details(config: Option<&PayPalConfig>) -> serde_json::Value {
    json!({
        "implementation": {
            "api": PAYPAL_IMPLEMENTATION_API,
            "status": PAYPAL_IMPLEMENTATION_STATUS,
            "notes": [
                "The connector targets PayPal REST endpoints for checkout orders, reporting transactions, captures, refunds, and invoicing.",
                "The first slice is deliberately request-response only; there is no webhook or subscription event ingestion yet."
            ],
        },
        "auth_boundary": {
            "binding": PAYPAL_BINDING_MODEL,
            "token_type": PAYPAL_AUTH_MODEL,
            "environment": config.map(|cfg| if cfg.sandbox { "sandbox" } else { "production" }),
            "base_url": config.map(|cfg| cfg.base_url.clone()),
            "multi_merchant_supported": false,
            "delegated_user_auth_supported": false,
        },
        "service_inventory": {
            "orders": {
                "supported_operations": [OP_ORDERS_CREATE, OP_ORDERS_GET, OP_ORDERS_CAPTURE],
                "notes": [
                    "The connector supports order creation, lookup, and capture only.",
                    "Authorize-only, void, and order-update workflows are not exposed in the first slice."
                ],
            },
            "payments": {
                "supported_operations": [OP_PAYMENTS_LIST, OP_PAYMENTS_GET, OP_PAYMENTS_REFUND],
                "notes": [
                    "Payment reads are centered on reporting transactions and capture lookup.",
                    "Refunds operate on captures only."
                ],
            },
            "invoices": {
                "supported_operations": [OP_INVOICES_CREATE, OP_INVOICES_LIST, OP_INVOICES_SEND],
                "notes": [
                    "Invoice creation produces a draft invoice; sending is a separate operation.",
                    "The connector does not manage recurring subscriptions or automatic billing plans."
                ],
            },
            "payouts": {
                "supported": false,
                "notes": [
                    "Payout APIs are intentionally out of scope for this first slice."
                ],
            },
            "subscriptions": {
                "supported": false,
                "notes": [
                    "Subscription plans, billing agreements, and vault flows are deferred."
                ],
            },
            "webhooks": {
                "supported": false,
                "notes": [
                    "There is no inbound webhook verification or event delivery path yet."
                ],
            },
        },
        "non_goals": PAYPAL_FIRST_SLICE_NON_GOALS,
    })
}

fn with_self_check_details(
    mut report: SelfCheckReport,
    config: Option<&PayPalConfig>,
    probe: serde_json::Value,
) -> SelfCheckReport {
    report.details = Some(json!({
        "contract": contract_details(config),
        "probe": probe,
    }));
    report
}

#[derive(Debug)]
pub struct PayPalConnector {
    base: BaseConnector,
    config: Option<PayPalConfig>,
    client: Option<PayPalClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl PayPalConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.paypal")),
            config: None,
            client: None,
            runtime: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    fn manifest_hash() -> String {
        let mut h = Sha256::new();
        h.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(h.finalize()))
    }

    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_some() {
                None
            } else {
                Some("Not configured; run configure before handshake or invoke".into())
            },
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: if self.client.is_some() {
                None
            } else {
                Some("HTTP client not initialized; re-run configure".into())
            },
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "runtime_initialized".into(),
            passed: self.runtime.is_some(),
            message: if self.runtime.is_some() {
                None
            } else {
                Some("ConnectorRuntime not initialized; re-run configure".into())
            },
            critical: true,
        });
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "environment".into(),
                passed: true,
                message: Some(if config.sandbox {
                    "PayPal sandbox mode".into()
                } else {
                    "PayPal production mode".into()
                }),
                critical: false,
            });
        }
        checks.push(DoctorCheck {
            name: "auth_boundary".into(),
            passed: true,
            message: Some(
                "Uses OAuth2 client_credentials for one merchant context in one environment; delegated user auth and multi-merchant routing are out of scope."
                    .into(),
            ),
            critical: false,
        });
        checks.push(DoctorCheck {
            name: "first_slice_inventory".into(),
            passed: true,
            message: Some(
                "Supported today: checkout orders, capture lookups/refunds, and invoicing. Payouts, subscriptions, disputes, and webhooks are intentionally deferred."
                    .into(),
            ),
            critical: false,
        });
        DoctorResult::from_checks(checks)
    }

    fn require_str<'a>(input: &'a serde_json::Value, key: &str) -> FcpResult<&'a str> {
        let value =
            input
                .get(key)
                .and_then(|v| v.as_str())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("Missing: {key}"),
                })?;
        if value.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must not be empty"),
            });
        }
        Ok(value)
    }
}

impl Default for PayPalConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::too_many_lines)]
fn operations_info() -> Vec<OperationInfo> {
    let hint = |when: &str, mistakes: Vec<String>, related: Vec<&'static str>| -> AgentHint {
        AgentHint {
            when_to_use: when.into(),
            common_mistakes: mistakes,
            examples: vec![],
            related: related.into_iter().map(CapabilityId::from_static).collect(),
        }
    };
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_ORDERS_CREATE),
            summary: "Create a PayPal order".into(),
            description: None,
            input_schema: json!({"type":"object","required":["intent","currency_code","value"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_ORDERS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Create a PayPal checkout order",
                vec!["intent must be CAPTURE or AUTHORIZE".into()],
                vec![CAP_ORDERS_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ORDERS_GET),
            summary: "Get order details".into(),
            description: None,
            input_schema: json!({"type":"object","required":["order_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_ORDERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Check status of a PayPal order",
                vec!["Use the PayPal order ID".into()],
                vec![CAP_ORDERS_WRITE],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ORDERS_CAPTURE),
            summary: "Capture payment for order".into(),
            description: None,
            input_schema: json!({"type":"object","required":["order_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_ORDERS_WRITE),
            risk_level: RiskLevel::Critical,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Capture funds for an approved order",
                vec!["Order must be in APPROVED status".into()],
                vec![CAP_ORDERS_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PAYMENTS_LIST),
            summary: "List payments/transactions".into(),
            description: None,
            input_schema: json!({"type":"object","required":["start_date","end_date"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_PAYMENTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Search transaction history",
                vec!["Dates in ISO 8601 format".into()],
                vec![],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PAYMENTS_GET),
            summary: "Get capture details".into(),
            description: None,
            input_schema: json!({"type":"object","required":["capture_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_PAYMENTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Get details of a specific payment capture",
                vec!["Use the capture ID, not order ID".into()],
                vec![CAP_PAYMENTS_WRITE],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PAYMENTS_REFUND),
            summary: "Refund a captured payment".into(),
            description: None,
            input_schema: json!({"type":"object","required":["capture_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_PAYMENTS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Refund a captured payment",
                vec!["Capture must be COMPLETED".into()],
                vec![CAP_PAYMENTS_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_INVOICES_CREATE),
            summary: "Create an invoice".into(),
            description: None,
            input_schema: json!({"type":"object","required":["currency_code","items"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_INVOICES_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Create a draft PayPal invoice",
                vec!["Items must include name, quantity, unit_amount".into()],
                vec![CAP_INVOICES_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_INVOICES_LIST),
            summary: "List invoices".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_INVOICES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("List PayPal invoices", vec![], vec![CAP_INVOICES_WRITE]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_INVOICES_SEND),
            summary: "Send an invoice".into(),
            description: None,
            input_schema: json!({"type":"object","required":["invoice_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_INVOICES_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Send a draft invoice to the recipient",
                vec!["Invoice must be in DRAFT status".into()],
                vec![CAP_INVOICES_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Check API credentials".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_ORDERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Verify PayPal credentials", vec![], vec![]),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

#[async_trait]
impl FcpConnector for PayPalConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let cfg = PayPalConfig::from_value(config)?;
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(cfg.request_timeout_ms)),
        ));
        let client = PayPalClient::new(
            &cfg.base_url,
            cfg.client_id.clone(),
            cfg.client_secret.clone(),
            cfg.request_timeout_ms,
            cfg.retry.clone(),
        )
        .await
        .map_err(|e| FcpError::Internal {
            message: format!("Client init: {e}"),
        })?;
        self.client = Some(client);
        self.config = Some(cfg);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        info!(event = "paypal.configure", "Configured PayPal connector");
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        let caps = req
            .capabilities_requested
            .into_iter()
            .map(|c| CapabilityGrant {
                capability: c,
                operation: None,
            })
            .collect();
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: caps,
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let mut snap = if self.config.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snap.uptime_ms = u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snap.details = Some(json!({
            "configured": self.config.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "sandbox": self.config.as_ref().map(|c| c.sandbox).unwrap_or(false),
            "base_url": self.config.as_ref().map(|c| c.base_url.clone()),
            "manifest_hash": Self::manifest_hash(),
            "contract": contract_details(self.config.as_ref()),
        }));
        snap
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(config) = &self.config else {
            return Ok(with_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                None,
                json!({
                    "ready": false,
                    "reason": "configure one PayPal client_id/client_secret pair and environment before running self_check",
                }),
            ));
        };

        let Some(client) = &self.client else {
            return Ok(with_self_check_details(
                SelfCheckReport::failed(
                    "client_missing",
                    "PayPal HTTP client not initialized; re-run configure",
                ),
                Some(config),
                json!({
                    "ready": false,
                    "reason": "client_missing",
                }),
            ));
        };
        let Some(runtime) = &self.runtime else {
            return Ok(with_self_check_details(
                SelfCheckReport::failed(
                    "runtime_missing",
                    "ConnectorRuntime not initialized; re-run configure",
                ),
                Some(config),
                json!({
                    "ready": false,
                    "reason": "runtime_missing",
                }),
            ));
        };

        match client.health_check(runtime).await {
            Ok(true) => {
                info!(event = "paypal.self_check", "PayPal self_check passed");
                Ok(with_self_check_details(
                    SelfCheckReport::ok(),
                    Some(config),
                    json!({
                        "healthy": true,
                        "base_url": client.base_url(),
                        "environment": if config.sandbox { "sandbox" } else { "production" },
                    }),
                ))
            }
            Ok(false) => Ok(with_self_check_details(
                SelfCheckReport::degraded("api_degraded", "PayPal API returned server error"),
                Some(config),
                json!({
                    "healthy": false,
                    "base_url": client.base_url(),
                    "environment": if config.sandbox { "sandbox" } else { "production" },
                }),
            )),
            Err(error) if error.is_retryable() => Ok(with_self_check_details(
                SelfCheckReport::degraded("self_check_retryable", error.to_string()),
                Some(config),
                json!({
                    "healthy": false,
                    "base_url": client.base_url(),
                    "environment": if config.sandbox { "sandbox" } else { "production" },
                    "retryable": true,
                }),
            )),
            Err(error) => Ok(with_self_check_details(
                SelfCheckReport::failed("self_check_failed", error.to_string()),
                Some(config),
                json!({
                    "healthy": false,
                    "base_url": client.base_url(),
                    "environment": if config.sandbox { "sandbox" } else { "production" },
                    "retryable": false,
                }),
            )),
        }
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        Ok(SimulateResponse::allowed(req.id))
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        self.runtime = None;
        self.client = None;
        self.config = None;
        self.verifier = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(req).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }
    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

impl PayPalConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        if let Some(verifier) = &self.verifier {
            let cap = match operation {
                OP_ORDERS_GET | OP_HEALTH => CapabilityId::from_static(CAP_ORDERS_READ),
                OP_ORDERS_CREATE | OP_ORDERS_CAPTURE => CapabilityId::from_static(CAP_ORDERS_WRITE),
                OP_PAYMENTS_LIST | OP_PAYMENTS_GET => CapabilityId::from_static(CAP_PAYMENTS_READ),
                OP_PAYMENTS_REFUND => CapabilityId::from_static(CAP_PAYMENTS_WRITE),
                OP_INVOICES_LIST => CapabilityId::from_static(CAP_INVOICES_READ),
                OP_INVOICES_CREATE | OP_INVOICES_SEND => {
                    CapabilityId::from_static(CAP_INVOICES_WRITE)
                }
                _ => {
                    return Err(FcpError::InvalidRequest {
                        code: 1004,
                        message: format!("Unknown operation: {operation}"),
                    });
                }
            };
            verifier.verify(&req.capability_token, &cap, &req.operation, &[])?;
        } else {
            return Err(FcpError::Internal {
                message: "connector ready state missing capability verifier".into(),
            });
        }

        let runtime = self.runtime.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing runtime".into(),
        })?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing PayPal client".into(),
        })?;

        let output = match operation {
            OP_ORDERS_CREATE => {
                let intent = Self::require_str(&req.input, "intent")?;
                let currency = Self::require_str(&req.input, "currency_code")?;
                let value = Self::require_str(&req.input, "value")?;
                let description = req
                    .input
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let order = CreateOrder {
                    intent: intent.into(),
                    purchase_units: vec![CreatePurchaseUnit {
                        amount: Amount {
                            currency_code: currency.into(),
                            value: value.into(),
                        },
                        description,
                        reference_id: req
                            .input
                            .get("reference_id")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                    }],
                };
                let created = client
                    .create_order(runtime, &order)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&created).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_ORDERS_GET => {
                let oid = Self::require_str(&req.input, "order_id")?;
                let order = client
                    .get_order(runtime, oid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&order).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_ORDERS_CAPTURE => {
                let oid = Self::require_str(&req.input, "order_id")?;
                let captured = client
                    .capture_order(runtime, oid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&captured).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_PAYMENTS_LIST => {
                let start = Self::require_str(&req.input, "start_date")?;
                let end = Self::require_str(&req.input, "end_date")?;
                let results = client
                    .list_payments(runtime, start, end)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&results.transaction_details).map_err(|e| {
                    FcpError::Internal {
                        message: e.to_string(),
                    }
                })?
            }
            OP_PAYMENTS_GET => {
                let cid = Self::require_str(&req.input, "capture_id")?;
                let capture = client
                    .get_capture(runtime, cid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&capture).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_PAYMENTS_REFUND => {
                let cid = Self::require_str(&req.input, "capture_id")?;
                let refund_req = RefundRequest {
                    amount: req.input.get("amount").and_then(|a| {
                        Some(Amount {
                            currency_code: a.get("currency_code")?.as_str()?.into(),
                            value: a.get("value")?.as_str()?.into(),
                        })
                    }),
                    note_to_payer: req
                        .input
                        .get("note_to_payer")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                };
                let refund = client
                    .refund_capture(runtime, cid, &refund_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&refund).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_INVOICES_CREATE => {
                let currency = Self::require_str(&req.input, "currency_code")?;
                let items_arr = req
                    .input
                    .get("items")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing: items array".into(),
                    })?;
                let items: Vec<CreateInvoiceItem> = items_arr
                    .iter()
                    .map(|item| {
                        Ok(CreateInvoiceItem {
                            name: item
                                .get("name")
                                .and_then(|v| v.as_str())
                                .ok_or_else(|| FcpError::InvalidRequest {
                                    code: 1005,
                                    message: "items[].name required".into(),
                                })?
                                .into(),
                            quantity: item
                                .get("quantity")
                                .and_then(|v| v.as_str())
                                .unwrap_or("1")
                                .into(),
                            unit_amount: Amount {
                                currency_code: currency.into(),
                                value: item
                                    .get("unit_amount")
                                    .and_then(|v| v.as_str())
                                    .ok_or_else(|| FcpError::InvalidRequest {
                                        code: 1005,
                                        message: "items[].unit_amount required".into(),
                                    })?
                                    .into(),
                            },
                        })
                    })
                    .collect::<FcpResult<Vec<_>>>()?;
                let recipients = req
                    .input
                    .get("recipient_email")
                    .and_then(|v| v.as_str())
                    .map(|email| {
                        vec![CreateRecipient {
                            billing_info: CreateBillingInfo {
                                email_address: email.into(),
                            },
                        }]
                    })
                    .unwrap_or_default();
                let invoice = CreateInvoice {
                    detail: CreateInvoiceDetail {
                        currency_code: currency.into(),
                        invoice_number: req
                            .input
                            .get("invoice_number")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        memo: req
                            .input
                            .get("memo")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                    },
                    primary_recipients: recipients,
                    items,
                };
                let created = client
                    .create_invoice(runtime, &invoice)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&created).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_INVOICES_LIST => {
                let result = client
                    .list_invoices(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&result.items).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_INVOICES_SEND => {
                let iid = Self::require_str(&req.input, "invoice_id")?;
                client
                    .send_invoice(runtime, iid)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_HEALTH => {
                let healthy = client
                    .health_check(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({"healthy": healthy, "sandbox": self.config.as_ref().map(|c| c.sandbox).unwrap_or(false)})
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        Ok(InvokeResponse::ok(req.id, output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{CapabilityToken, RequestId, ZoneId};

    fn tc() -> serde_json::Value {
        json!({
            "client_id": "test_client_id",
            "client_secret": "test_client_secret",
            "sandbox": true
        })
    }

    fn handshake_req() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_ORDERS_READ),
                CapabilityId::from_static(CAP_ORDERS_WRITE),
                CapabilityId::from_static(CAP_PAYMENTS_READ),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn invoke_req(op: &'static str, input: serde_json::Value) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("r1"),
            connector_id: ConnectorId::from_static("fcp.paypal"),
            operation: OperationId::from_static(op),
            zone_id: ZoneId::work(),
            input,
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        }
    }

    #[test]
    fn new_ok() {
        assert!(PayPalConnector::new().config.is_none());
    }

    #[test]
    fn default_ok() {
        assert!(PayPalConnector::default().config.is_none());
    }

    #[test]
    fn manifest_hash_stable() {
        assert_eq!(
            PayPalConnector::manifest_hash(),
            PayPalConnector::manifest_hash()
        );
    }

    #[test]
    fn configure_valid() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = PayPalConnector::new();
                c.configure(tc()).await
            })
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn configure_empty_client_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = PayPalConnector::new();
                c.configure(json!({"client_id":"","client_secret":"s"}))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_empty_secret() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = PayPalConnector::new();
                c.configure(json!({"client_id":"id","client_secret":""}))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_bad() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = PayPalConnector::new();
                c.configure(json!("bad")).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_production_url() {
        let c = fcp_async_core::runtime::block_on_sync(async {
            let mut c = PayPalConnector::new();
            c.configure(json!({
                "client_id": "id",
                "client_secret": "secret",
                "sandbox": false
            }))
            .await
            .unwrap();
            c
        })
        .unwrap();
        assert_eq!(
            c.config.as_ref().unwrap().base_url,
            PAYPAL_PRODUCTION_BASE_URL
        );
    }

    #[test]
    fn configure_rejects_non_paypal_host() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = PayPalConnector::new();
                c.configure(json!({
                    "client_id": "id",
                    "client_secret": "secret",
                    "sandbox": false,
                    "base_url": "https://example.com"
                }))
                .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_rejects_base_url_with_path() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = PayPalConnector::new();
                c.configure(json!({
                    "client_id": "id",
                    "client_secret": "secret",
                    "sandbox": true,
                    "base_url": "https://api-m.sandbox.paypal.com/v2"
                }))
                .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn doctor_unconfigured() {
        assert!(!PayPalConnector::new().doctor().ready);
    }

    #[test]
    fn doctor_configured() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = PayPalConnector::new();
                c.configure(tc()).await.unwrap();
                c.doctor()
            })
            .unwrap()
            .ready
        );
    }

    #[test]
    fn doctor_configured_has_env_check() {
        let result = fcp_async_core::runtime::block_on_sync(async {
            let mut c = PayPalConnector::new();
            c.configure(tc()).await.unwrap();
            c.doctor()
        })
        .unwrap();
        assert!(result.checks.iter().any(|c| c.name == "environment"));
    }

    #[test]
    fn doctor_exposes_contract_checks() {
        let result = fcp_async_core::runtime::block_on_sync(async {
            let mut c = PayPalConnector::new();
            c.configure(tc()).await.unwrap();
            c.doctor()
        })
        .unwrap();
        assert!(result.checks.iter().any(|c| c.name == "auth_boundary"));
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "first_slice_inventory")
        );
    }

    #[test]
    fn introspect_ops() {
        assert_eq!(PayPalConnector::new().introspect().operations.len(), 10);
    }

    #[test]
    fn read_operations_are_strictly_idempotent() {
        for operation in operations_info() {
            if matches!(
                operation.id.as_str(),
                OP_ORDERS_GET | OP_PAYMENTS_LIST | OP_PAYMENTS_GET | OP_INVOICES_LIST | OP_HEALTH
            ) {
                assert_eq!(
                    operation.idempotency,
                    IdempotencyClass::Strict,
                    "{}",
                    operation.id
                );
            }
        }
    }

    #[test]
    fn ops_all_have_hints() {
        for op in operations_info() {
            assert!(!op.ai_hints.when_to_use.is_empty(), "{}", op.id);
        }
    }

    #[test]
    fn invoke_unknown() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = PayPalConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req("paypal.nope", json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_get_order_missing_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = PayPalConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_ORDERS_GET, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_capture_missing_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = PayPalConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_ORDERS_CAPTURE, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_create_order_missing_fields() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = PayPalConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_ORDERS_CREATE, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_payments_list_missing_dates() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = PayPalConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_PAYMENTS_LIST, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_payments_get_missing_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = PayPalConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_PAYMENTS_GET, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_refund_missing_capture_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = PayPalConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_PAYMENTS_REFUND, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_invoice_create_missing_items() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = PayPalConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(
                    OP_INVOICES_CREATE,
                    json!({"currency_code": "USD"}),
                ))
                .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_invoice_send_missing_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = PayPalConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_INVOICES_SEND, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_invoice_create_missing_item_name() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = PayPalConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(
                    OP_INVOICES_CREATE,
                    json!({"currency_code": "USD", "items": [{"unit_amount": "10.00"}]}),
                ))
                .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn simulate_ok() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            PayPalConnector::new()
                .simulate(SimulateRequest::new(
                    ConnectorId::from_static("fcp.paypal"),
                    OperationId::from_static(OP_ORDERS_GET),
                    ZoneId::work(),
                    json!({}),
                    CapabilityToken::test_token(),
                ))
                .await
        })
        .unwrap()
        .unwrap();
        assert!(r.would_succeed);
    }

    #[test]
    fn subscribe_unsupported() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                PayPalConnector::new()
                    .subscribe(SubscribeRequest {
                        r#type: "subscribe".into(),
                        id: RequestId::new("sub1"),
                        topics: vec![],
                        since: None,
                        max_events_per_sec: None,
                        batch_ms: None,
                        window_size: None,
                        capability_token: None,
                    })
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn shutdown_ok() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut c = PayPalConnector::new();
            c.configure(tc()).await.unwrap();
            c.shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 10_000,
                drain: false,
                reason: None,
            })
            .await
            .unwrap();
        })
        .unwrap();
    }

    #[test]
    fn handshake_ok() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            let mut c = PayPalConnector::new();
            c.configure(tc()).await.unwrap();
            c.handshake(handshake_req()).await.unwrap()
        })
        .unwrap();
        assert_eq!(r.status, "accepted");
        assert_eq!(r.capabilities_granted.len(), 3);
    }

    #[test]
    fn require_str_ok() {
        assert_eq!(
            PayPalConnector::require_str(&json!({"k": "v"}), "k").unwrap(),
            "v"
        );
    }

    #[test]
    fn require_str_miss() {
        assert!(PayPalConnector::require_str(&json!({}), "k").is_err());
    }

    #[test]
    fn require_str_empty() {
        assert!(PayPalConnector::require_str(&json!({"k": ""}), "k").is_err());
        assert!(PayPalConnector::require_str(&json!({"k": "  "}), "k").is_err());
    }

    #[test]
    fn health_unconfigured() {
        let h =
            fcp_async_core::runtime::block_on_sync(async { PayPalConnector::new().health().await })
                .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Degraded { .. }));
    }

    #[test]
    fn health_configured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            let mut c = PayPalConnector::new();
            c.configure(tc()).await.unwrap();
            c.health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Ready));
        assert!(
            h.details
                .as_ref()
                .and_then(|details| details.get("contract"))
                .is_some()
        );
    }

    #[test]
    fn self_check_unconfigured_includes_contract_details() {
        let report = fcp_async_core::runtime::block_on_sync(async {
            PayPalConnector::new().self_check().await.unwrap()
        })
        .unwrap();
        assert!(
            report
                .details
                .as_ref()
                .and_then(|details| details.get("contract"))
                .is_some()
        );
    }

    #[test]
    fn config_debug_redacts() {
        let cfg = PayPalConfig {
            client_id: "AeB2cXyZ".into(),
            client_secret: "secret_456".into(),
            base_url: "https://api-m.sandbox.paypal.com".into(),
            sandbox: true,
            retry: HttpRetryConfig::default(),
            request_timeout_ms: 30_000,
        };
        let debug = format!("{cfg:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("AeB2cXyZ"));
        assert!(!debug.contains("secret_456"));
    }

    #[test]
    fn ops_count_matches_spec() {
        let ops = operations_info();
        assert_eq!(ops.len(), 10, "Expected 10 operations");
        let safe_count = ops
            .iter()
            .filter(|o| o.safety_tier == SafetyTier::Safe)
            .count();
        assert_eq!(safe_count, 5, "Expected 5 safe operations");
        let risky_count = ops
            .iter()
            .filter(|o| o.safety_tier == SafetyTier::Risky)
            .count();
        assert_eq!(risky_count, 5, "Expected 5 risky operations");
    }
}
