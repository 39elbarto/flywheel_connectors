//! Square connector implementation.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, RiskLevel, SafetyTier, SelfCheckReport, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use fcp_sdk::prelude::*;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::client::SquareClient;
use crate::types::*;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const SQUARE_PRODUCTION_BASE_URL: &str = "https://connect.squareup.com/v2";
#[cfg(test)]
const SQUARE_SANDBOX_BASE_URL: &str = "https://connect.squareupsandbox.com/v2";
const SQUARE_ALLOWED_HOSTS: [&str; 2] = ["connect.squareup.com", "connect.squareupsandbox.com"];

// Operation IDs
const OP_PAYMENTS_LIST: &str = "square.payments.list";
const OP_PAYMENTS_GET: &str = "square.payments.get";
const OP_PAYMENTS_CREATE: &str = "square.payments.create";
const OP_PAYMENTS_REFUND: &str = "square.payments.refund";
const OP_ORDERS_LIST: &str = "square.orders.list";
const OP_ORDERS_GET: &str = "square.orders.get";
const OP_ORDERS_CREATE: &str = "square.orders.create";
const OP_CATALOG_LIST: &str = "square.catalog.list";
const OP_CUSTOMERS_LIST: &str = "square.customers.list";
const OP_CUSTOMERS_GET: &str = "square.customers.get";
const OP_LOCATIONS_LIST: &str = "square.locations.list";
const OP_HEALTH: &str = "square.health";

// Capability IDs
const CAP_PAYMENTS_READ: &str = "square.payments.read";
const CAP_PAYMENTS_WRITE: &str = "square.payments.write";
const CAP_ORDERS_READ: &str = "square.orders.read";
const CAP_ORDERS_WRITE: &str = "square.orders.write";
const CAP_CATALOG_READ: &str = "square.catalog.read";
const CAP_CUSTOMERS_READ: &str = "square.customers.read";
const CAP_LOCATIONS_READ: &str = "square.locations.read";

/// Square connector configuration.
#[derive(Clone, Deserialize)]
struct SquareConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    access_token: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl std::fmt::Debug for SquareConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SquareConfig")
            .field("base_url", &self.base_url)
            .field("access_token", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    SQUARE_PRODUCTION_BASE_URL.into()
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

fn normalize_square_base_url(base_url: &str) -> Result<String, String> {
    let parsed =
        reqwest::Url::parse(base_url).map_err(|e| format!("Invalid Square base_url: {e}"))?;
    if parsed.scheme() != "https" {
        return Err("Square base_url must use https".into());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "Square base_url must include a host".to_string())?;
    if !SQUARE_ALLOWED_HOSTS.contains(&host) {
        return Err(format!(
            "Square base_url host must be connect.squareup.com or connect.squareupsandbox.com, got {host}"
        ));
    }
    if parsed.port_or_known_default() != Some(443) {
        return Err("Square base_url must use port 443".into());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("Square base_url must not include query parameters or fragments".into());
    }
    let path = parsed.path().trim_end_matches('/');
    if path != "/v2" {
        return Err(format!(
            "Square base_url must be https://{host}/v2 for the selected environment"
        ));
    }

    Ok(format!("https://{host}/v2"))
}

// Doctor types
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks.iter().filter(|c| c.critical).all(|c| c.passed);
        Self { passed, checks }
    }
}

/// Square connector state.
#[derive(Debug)]
pub struct SquareConnector {
    base: BaseConnector,
    config: Option<SquareConfig>,
    client: Option<SquareClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl SquareConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.square")),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            started_at: Instant::now(),
            verifier: None,
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Run connector diagnostics.
    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();

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

        let client_ok = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: client_ok,
            message: Some(if client_ok {
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            critical: true,
        });

        let runtime_ok = self.runtime.is_some();
        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: runtime_ok,
            message: Some(if runtime_ok {
                "ConnectorRuntime initialized".into()
            } else {
                "Runtime missing".into()
            }),
            critical: true,
        });

        if let Some(config) = &self.config {
            let scheme = if config.base_url.starts_with("https://") {
                "https"
            } else {
                "http"
            };
            checks.push(DoctorCheck {
                name: "base_url".into(),
                passed: true,
                message: Some(format!("Base URL ({scheme}): {}", config.base_url)),
                critical: false,
            });

            let normalized_base_url = normalize_square_base_url(&config.base_url);
            let network_ok = normalized_base_url.is_ok();
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: network_ok,
                message: Some(match normalized_base_url {
                    Ok(base_url) => {
                        format!("Base URL matches required Square REST base: {base_url}")
                    }
                    Err(err) => err,
                }),
                critical: true,
            });

            let secretless = self.client.as_ref().is_some_and(|c| c.is_secretless());
            checks.push(DoctorCheck {
                name: "credential_mode".into(),
                passed: !secretless,
                message: Some(if secretless {
                    "Credential injection required via egress proxy".into()
                } else {
                    "Bearer access token configured".into()
                }),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks)
    }
}

impl Default for SquareConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the typed operations catalog.
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_PAYMENTS_LIST),
            summary: "List payments".into(),
            description: Some("Lists payments processed by the Square account".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "cursor": { "type": "string", "description": "Pagination cursor" },
                    "location_id": { "type": "string", "description": "Filter by location" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "payments": { "type": "array" },
                    "cursor": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PAYMENTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When listing payments processed by Square".into(),
                common_mistakes: vec![
                    "Use cursor for pagination, not page numbers".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_PAYMENTS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PAYMENTS_GET),
            summary: "Get a payment by ID".into(),
            description: Some("Retrieves details of a specific payment".into()),
            input_schema: json!({
                "type": "object",
                "required": ["payment_id"],
                "properties": {
                    "payment_id": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "payment": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PAYMENTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When retrieving details of a specific payment".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_PAYMENTS_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PAYMENTS_CREATE),
            summary: "Create a payment".into(),
            description: Some("Creates a new payment".into()),
            input_schema: json!({
                "type": "object",
                "required": ["source_id", "idempotency_key", "amount_money"],
                "properties": {
                    "source_id": { "type": "string", "description": "Payment source (nonce or card ID)" },
                    "idempotency_key": { "type": "string", "description": "Unique key to prevent duplicate payments" },
                    "amount_money": {
                        "type": "object",
                        "properties": {
                            "amount": { "type": "integer", "description": "Amount in smallest denomination" },
                            "currency": { "type": "string" }
                        }
                    },
                    "location_id": { "type": "string" },
                    "customer_id": { "type": "string" },
                    "note": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "payment": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PAYMENTS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When creating a new payment charge".into(),
                common_mistakes: vec![
                    "Always provide a unique idempotency_key to prevent duplicate charges".into(),
                    "Amount is in the smallest currency denomination (e.g., cents for USD)".into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PAYMENTS_REFUND),
            summary: "Refund a payment".into(),
            description: Some("Creates a refund for a completed payment".into()),
            input_schema: json!({
                "type": "object",
                "required": ["idempotency_key", "payment_id", "amount_money"],
                "properties": {
                    "idempotency_key": { "type": "string" },
                    "payment_id": { "type": "string" },
                    "amount_money": {
                        "type": "object",
                        "properties": {
                            "amount": { "type": "integer" },
                            "currency": { "type": "string" }
                        }
                    },
                    "reason": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "refund": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PAYMENTS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When refunding a completed payment".into(),
                common_mistakes: vec![
                    "Refund amount cannot exceed the original payment amount".into(),
                    "Always provide a unique idempotency_key".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_PAYMENTS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ORDERS_LIST),
            summary: "Search/list orders".into(),
            description: Some("Searches orders for given locations".into()),
            input_schema: json!({
                "type": "object",
                "required": ["location_ids"],
                "properties": {
                    "location_ids": { "type": "array", "items": { "type": "string" } },
                    "cursor": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "orders": { "type": "array" },
                    "cursor": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_ORDERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When searching or listing orders".into(),
                common_mistakes: vec![
                    "At least one location_id is required".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_ORDERS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ORDERS_GET),
            summary: "Get an order by ID".into(),
            description: Some("Retrieves details of a specific order".into()),
            input_schema: json!({
                "type": "object",
                "required": ["order_id"],
                "properties": {
                    "order_id": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "order": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_ORDERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When retrieving details of a specific order".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_ORDERS_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ORDERS_CREATE),
            summary: "Create an order".into(),
            description: Some("Creates a new order".into()),
            input_schema: json!({
                "type": "object",
                "required": ["location_id", "line_items"],
                "properties": {
                    "location_id": { "type": "string" },
                    "line_items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": { "type": "string" },
                                "quantity": { "type": "string" },
                                "base_price_money": { "type": "object" }
                            }
                        }
                    },
                    "idempotency_key": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "order": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_ORDERS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When creating a new order".into(),
                common_mistakes: vec![
                    "Quantity must be a string, not a number".into(),
                    "Amount is in smallest denomination (cents for USD)".into(),
                    "Provide idempotency_key when retrying order creation to reduce duplicate side effects".into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CATALOG_LIST),
            summary: "List catalog objects".into(),
            description: Some("Lists catalog items, categories, and variations".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "cursor": { "type": "string" },
                    "types": { "type": "string", "description": "Comma-separated types (ITEM, CATEGORY, etc.)" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "objects": { "type": "array" },
                    "cursor": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_CATALOG_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When listing catalog items, categories, or variations".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CUSTOMERS_LIST),
            summary: "List customers".into(),
            description: Some("Lists all customers in the Square account".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "cursor": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "customers": { "type": "array" },
                    "cursor": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_CUSTOMERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When listing customers".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_CUSTOMERS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CUSTOMERS_GET),
            summary: "Get a customer by ID".into(),
            description: Some("Retrieves details of a specific customer".into()),
            input_schema: json!({
                "type": "object",
                "required": ["customer_id"],
                "properties": {
                    "customer_id": { "type": "string" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "customer": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_CUSTOMERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When retrieving details of a specific customer".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_CUSTOMERS_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_LOCATIONS_LIST),
            summary: "List locations".into(),
            description: Some("Lists all business locations in the Square account".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "locations": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static(CAP_LOCATIONS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When listing business locations".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Check Square API connectivity".into(),
            description: Some("Validates API reachability and authentication".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_LOCATIONS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When checking if the Square API is reachable and credentials are valid".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

#[async_trait]
impl FcpConnector for SquareConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let mut config: SquareConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Square config: {e}"),
            })?;
        config.base_url = normalize_square_base_url(&config.base_url).map_err(|message| {
            FcpError::InvalidRequest {
                code: 1001,
                message,
            }
        })?;

        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client =
            SquareClient::new(&config.base_url, &config.access_token, config.retry.clone())
                .map_err(|e| FcpError::Internal {
                    message: format!("Failed to create Square client: {e}"),
                })?;

        self.client = Some(client);
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
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
        let mut snapshot = if self.config.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = &self.client else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };

        if client.is_secretless() {
            return Ok(SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with empty token; egress proxy injection required",
            ));
        }

        match client.health_check().await {
            Ok(()) => Ok(SelfCheckReport::ok()),
            Err(err) => {
                if err.is_retryable() {
                    Ok(SelfCheckReport::degraded(
                        "self_check_retryable",
                        err.to_string(),
                    ))
                } else {
                    Ok(SelfCheckReport::failed(
                        "self_check_failed",
                        err.to_string(),
                    ))
                }
            }
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

impl SquareConnector {
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap = match operation {
            OP_PAYMENTS_LIST | OP_PAYMENTS_GET => CapabilityId::from_static(CAP_PAYMENTS_READ),
            OP_PAYMENTS_CREATE | OP_PAYMENTS_REFUND => {
                CapabilityId::from_static(CAP_PAYMENTS_WRITE)
            }
            OP_ORDERS_LIST | OP_ORDERS_GET => CapabilityId::from_static(CAP_ORDERS_READ),
            OP_ORDERS_CREATE => CapabilityId::from_static(CAP_ORDERS_WRITE),
            OP_CATALOG_LIST => CapabilityId::from_static(CAP_CATALOG_READ),
            OP_CUSTOMERS_LIST | OP_CUSTOMERS_GET => CapabilityId::from_static(CAP_CUSTOMERS_READ),
            OP_LOCATIONS_LIST | OP_HEALTH => CapabilityId::from_static(CAP_LOCATIONS_READ),
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        verifier.verify(&req.capability_token, &required_cap, &req.operation, &[])?;

        let runtime = self.runtime.as_ref().ok_or(FcpError::Internal {
            message: "Connector runtime missing after configure".into(),
        })?;
        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "Square client missing after configure".into(),
        })?;

        let output = match operation {
            OP_PAYMENTS_LIST => {
                let cursor = req.input.get("cursor").and_then(|v| v.as_str());
                let location_id = req.input.get("location_id").and_then(|v| v.as_str());
                let list = client
                    .list_payments(runtime, cursor, location_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(list).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_PAYMENTS_GET => {
                let payment_id = req.input.get("payment_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'payment_id' field".into(),
                    },
                )?;
                let resp = client
                    .get_payment(runtime, payment_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_PAYMENTS_CREATE => {
                let source_id = req.input.get("source_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'source_id' field".into(),
                    },
                )?;
                let idempotency_key = req
                    .input
                    .get("idempotency_key")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'idempotency_key' field".into(),
                    })?;
                let amount_money_val =
                    req.input
                        .get("amount_money")
                        .ok_or(FcpError::InvalidRequest {
                            code: 1005,
                            message: "Missing 'amount_money' field".into(),
                        })?;
                let amount_money: Money = serde_json::from_value(amount_money_val.clone())
                    .map_err(|e| FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("Invalid 'amount_money': {e}"),
                    })?;

                let create_req = CreatePaymentRequest {
                    source_id: source_id.to_string(),
                    idempotency_key: idempotency_key.to_string(),
                    amount_money,
                    location_id: req
                        .input
                        .get("location_id")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    customer_id: req
                        .input
                        .get("customer_id")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    note: req
                        .input
                        .get("note")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                };

                let resp = client
                    .create_payment(runtime, &create_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_PAYMENTS_REFUND => {
                let idempotency_key = req
                    .input
                    .get("idempotency_key")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'idempotency_key' field".into(),
                    })?;
                let payment_id = req.input.get("payment_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'payment_id' field".into(),
                    },
                )?;
                let amount_money_val =
                    req.input
                        .get("amount_money")
                        .ok_or(FcpError::InvalidRequest {
                            code: 1005,
                            message: "Missing 'amount_money' field".into(),
                        })?;
                let amount_money: Money = serde_json::from_value(amount_money_val.clone())
                    .map_err(|e| FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("Invalid 'amount_money': {e}"),
                    })?;

                let refund_req = RefundPaymentRequest {
                    idempotency_key: idempotency_key.to_string(),
                    payment_id: payment_id.to_string(),
                    amount_money,
                    reason: req
                        .input
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                };

                let resp = client
                    .refund_payment(runtime, &refund_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_ORDERS_LIST => {
                let location_ids_val =
                    req.input
                        .get("location_ids")
                        .ok_or(FcpError::InvalidRequest {
                            code: 1005,
                            message: "Missing 'location_ids' field".into(),
                        })?;
                let location_ids: Vec<String> = serde_json::from_value(location_ids_val.clone())
                    .map_err(|e| FcpError::InvalidRequest {
                        code: 1005,
                        message: format!("Invalid 'location_ids': {e}"),
                    })?;
                let cursor = req.input.get("cursor").and_then(|v| v.as_str());

                let list = client
                    .list_orders(runtime, &location_ids, cursor)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(list).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_ORDERS_GET => {
                let order_id = req.input.get("order_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'order_id' field".into(),
                    },
                )?;
                let resp = client
                    .get_order(runtime, order_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_ORDERS_CREATE => {
                let location_id = req
                    .input
                    .get("location_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'location_id' field".into(),
                    })?;
                let line_items_val =
                    req.input
                        .get("line_items")
                        .ok_or(FcpError::InvalidRequest {
                            code: 1005,
                            message: "Missing 'line_items' field".into(),
                        })?;
                let line_items: Vec<OrderLineItemInput> =
                    serde_json::from_value(line_items_val.clone()).map_err(|e| {
                        FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid 'line_items': {e}"),
                        }
                    })?;

                let create_req = CreateOrderRequest {
                    order: OrderInput {
                        location_id: location_id.to_string(),
                        line_items,
                    },
                    idempotency_key: req
                        .input
                        .get("idempotency_key")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                };

                let resp = client
                    .create_order(runtime, &create_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_CATALOG_LIST => {
                let cursor = req.input.get("cursor").and_then(|v| v.as_str());
                let types = req.input.get("types").and_then(|v| v.as_str());
                let list = client
                    .list_catalog(runtime, cursor, types)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(list).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_CUSTOMERS_LIST => {
                let cursor = req.input.get("cursor").and_then(|v| v.as_str());
                let list = client
                    .list_customers(runtime, cursor)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(list).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_CUSTOMERS_GET => {
                let customer_id = req
                    .input
                    .get("customer_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'customer_id' field".into(),
                    })?;
                let resp = client
                    .get_customer(runtime, customer_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_LOCATIONS_LIST => {
                let list = client
                    .list_locations(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(list).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize: {e}"),
                })?
            }
            OP_HEALTH => {
                client.health_check().await.map_err(|e| e.to_fcp_error())?;
                json!({ "status": "ok" })
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
    use std::path::PathBuf;

    use fcp_manifest::ConnectorManifest;

    fn all_caps() -> Vec<CapabilityId> {
        vec![
            CapabilityId::from_static(CAP_PAYMENTS_READ),
            CapabilityId::from_static(CAP_PAYMENTS_WRITE),
            CapabilityId::from_static(CAP_ORDERS_READ),
            CapabilityId::from_static(CAP_ORDERS_WRITE),
            CapabilityId::from_static(CAP_CATALOG_READ),
            CapabilityId::from_static(CAP_CUSTOMERS_READ),
            CapabilityId::from_static(CAP_LOCATIONS_READ),
        ]
    }

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: all_caps(),
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn base_invoke(connector_id: &ConnectorId, operation: &'static str) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_1"),
            connector_id: connector_id.clone(),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    fn test_config() -> serde_json::Value {
        json!({
            "access_token": "test_square_token"
        })
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = SquareConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = SquareConnector::new();
        let result = connector.configure(test_config()).await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = SquareConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = SquareConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = SquareConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        let report = connector.doctor();
        assert!(report.passed);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "network_constraints" && check.passed)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_accepts_sandbox_base_url() {
        let mut connector = SquareConnector::new();
        connector
            .configure(json!({
                "base_url": SQUARE_SANDBOX_BASE_URL,
                "access_token": "test_square_token"
            }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.passed);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "network_constraints" && check.passed)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_localhost_base_url() {
        let mut connector = SquareConnector::new();
        let err = connector
            .configure(json!({
                "base_url": "https://localhost/v2",
                "access_token": "test_square_token"
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_http_base_url() {
        let mut connector = SquareConnector::new();
        let err = connector
            .configure(json!({
                "base_url": "http://connect.squareup.com/v2",
                "access_token": "test_square_token"
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_missing_v2_base_path() {
        let mut connector = SquareConnector::new();
        let err = connector
            .configure(json!({
                "base_url": "https://connect.squareup.com",
                "access_token": "test_square_token"
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_normalizes_trailing_slash_on_base_url() {
        let mut connector = SquareConnector::new();
        connector
            .configure(json!({
                "base_url": "https://connect.squareupsandbox.com/v2/",
                "access_token": "test_square_token"
            }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.passed);
        assert!(report.checks.iter().any(|check| check.name == "base_url"
            && check.message.as_deref()
                == Some("Base URL (https): https://connect.squareupsandbox.com/v2")));
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = SquareConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = SquareConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_PAYMENTS_LIST),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = SquareConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 12);
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_PAYMENTS_LIST)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_PAYMENTS_GET)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_PAYMENTS_CREATE)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_PAYMENTS_REFUND)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_ORDERS_LIST)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_ORDERS_GET)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_ORDERS_CREATE)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_CATALOG_LIST)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_CUSTOMERS_LIST)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_CUSTOMERS_GET)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_LOCATIONS_LIST)
        );
        assert!(
            intro
                .operations
                .iter()
                .any(|op| op.id.as_str() == OP_HEALTH)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "square.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = SquareConnector::new();
        let req = base_invoke(connector.id(), OP_PAYMENTS_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_before_handshake_returns_not_handshaken() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        let result = connector
            .invoke(base_invoke(connector.id(), OP_PAYMENTS_LIST))
            .await;
        assert!(matches!(result, Err(FcpError::NotHandshaken)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_payments_get_missing_id() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_PAYMENTS_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_payments_create_missing_source_id() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_PAYMENTS_CREATE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_refund_missing_fields() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_PAYMENTS_REFUND);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_orders_list_missing_location_ids() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_ORDERS_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_orders_get_missing_id() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_ORDERS_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_orders_create_missing_fields() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_ORDERS_CREATE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_customers_get_missing_id() {
        let mut connector = SquareConnector::new();
        connector.configure(test_config()).await.unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_CUSTOMERS_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 12);
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_payments_list_is_safe() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PAYMENTS_LIST)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.risk_level, RiskLevel::Low);
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
        assert_eq!(op.requires_approval, Some(ApprovalMode::None));
    }

    #[test]
    fn test_payments_create_is_risky_high() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PAYMENTS_CREATE)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.risk_level, RiskLevel::High);
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
        assert_eq!(op.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn test_payments_refund_is_risky_high() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PAYMENTS_REFUND)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.risk_level, RiskLevel::High);
        assert_eq!(op.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn test_orders_create_contract_semantics() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_ORDERS_CREATE)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.risk_level, RiskLevel::Medium);
        assert_eq!(op.idempotency, IdempotencyClass::BestEffort);
        assert_eq!(op.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = SquareConnector::manifest_hash();
        let hash2 = SquareConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn manifest_interface_hash_is_deterministic() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        if !manifest_path.exists() {
            eprintln!("manifest.toml missing; skipping interface_hash check");
            return;
        }

        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed = manifest
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(
            manifest.manifest.interface_hash, computed,
            "update connectors/square/manifest.toml interface_hash to {computed}"
        );

        let manifest2 = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let computed2 = manifest2
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(computed, computed2);
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = SquareConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[test]
    fn debug_redacts_config_secrets() {
        let config = SquareConfig {
            base_url: default_base_url(),
            access_token: "secret_square_token".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: default_request_timeout_ms(),
        };
        let debug_output = format!("{config:?}");
        assert!(!debug_output.contains("secret_square_token"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn test_health_op_is_safe_with_strict_idempotency() {
        let ops = operations_info();
        let op = ops.iter().find(|op| op.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_default_connector() {
        let connector = SquareConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.square");
    }

    #[test]
    fn test_capability_mapping() {
        let ops = operations_info();
        let payments_list = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PAYMENTS_LIST)
            .unwrap();
        assert_eq!(payments_list.capability.as_str(), CAP_PAYMENTS_READ);

        let payments_create = ops
            .iter()
            .find(|op| op.id.as_str() == OP_PAYMENTS_CREATE)
            .unwrap();
        assert_eq!(payments_create.capability.as_str(), CAP_PAYMENTS_WRITE);

        let orders_list = ops
            .iter()
            .find(|op| op.id.as_str() == OP_ORDERS_LIST)
            .unwrap();
        assert_eq!(orders_list.capability.as_str(), CAP_ORDERS_READ);

        let catalog = ops
            .iter()
            .find(|op| op.id.as_str() == OP_CATALOG_LIST)
            .unwrap();
        assert_eq!(catalog.capability.as_str(), CAP_CATALOG_READ);

        let customers = ops
            .iter()
            .find(|op| op.id.as_str() == OP_CUSTOMERS_LIST)
            .unwrap();
        assert_eq!(customers.capability.as_str(), CAP_CUSTOMERS_READ);

        let locations = ops
            .iter()
            .find(|op| op.id.as_str() == OP_LOCATIONS_LIST)
            .unwrap();
        assert_eq!(locations.capability.as_str(), CAP_LOCATIONS_READ);

        let health = ops.iter().find(|op| op.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(health.capability.as_str(), CAP_LOCATIONS_READ);
    }

    #[test]
    fn test_orders_create_is_risky() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_ORDERS_CREATE)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.risk_level, RiskLevel::Medium);
        assert_eq!(op.idempotency, IdempotencyClass::BestEffort);
        assert_eq!(op.requires_approval, Some(ApprovalMode::Interactive));
    }
}
