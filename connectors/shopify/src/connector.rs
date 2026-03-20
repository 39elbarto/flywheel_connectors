//! Shopify connector implementation.

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

use crate::client::ShopifyClient;
use crate::types::{CreateLineItem, CreateOrder, CreateProduct, CreateVariant, UpdateProduct};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_PRODUCTS_LIST: &str = "shopify.products.list";
const OP_PRODUCTS_GET: &str = "shopify.products.get";
const OP_PRODUCTS_CREATE: &str = "shopify.products.create";
const OP_PRODUCTS_UPDATE: &str = "shopify.products.update";
const OP_PRODUCTS_DELETE: &str = "shopify.products.delete";
const OP_ORDERS_LIST: &str = "shopify.orders.list";
const OP_ORDERS_GET: &str = "shopify.orders.get";
const OP_ORDERS_CREATE: &str = "shopify.orders.create";
const OP_CUSTOMERS_LIST: &str = "shopify.customers.list";
const OP_CUSTOMERS_GET: &str = "shopify.customers.get";
const OP_INVENTORY_LIST: &str = "shopify.inventory.list";
const OP_HEALTH: &str = "shopify.health";

const CAP_PRODUCTS_READ: &str = "shopify.products.read";
const CAP_PRODUCTS_WRITE: &str = "shopify.products.write";
const CAP_ORDERS_READ: &str = "shopify.orders.read";
const CAP_ORDERS_WRITE: &str = "shopify.orders.write";
const CAP_CUSTOMERS_READ: &str = "shopify.customers.read";
const CAP_INVENTORY_READ: &str = "shopify.inventory.read";

#[derive(Clone, serde::Deserialize)]
pub struct ShopifyConfig {
    pub shop_domain: String,
    pub access_token: String,
    #[serde(default = "default_api_version")]
    pub api_version: String,
    #[serde(default)]
    pub retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}

fn default_api_version() -> String {
    "2024-01".into()
}

const fn default_timeout_ms() -> u64 {
    30_000
}

impl std::fmt::Debug for ShopifyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShopifyConfig")
            .field("shop_domain", &self.shop_domain)
            .field("access_token", &"[REDACTED]")
            .field("api_version", &self.api_version)
            .finish()
    }
}

impl ShopifyConfig {
    fn validate(&self) -> Result<(), String> {
        if self.shop_domain.is_empty() {
            return Err("shop_domain is required".into());
        }
        if self.access_token.is_empty() {
            return Err("access_token is required".into());
        }
        Ok(())
    }

    fn from_value(val: serde_json::Value) -> FcpResult<Self> {
        let config: Self = serde_json::from_value(val).map_err(|e| FcpError::InvalidRequest {
            code: 1001,
            message: format!("Invalid configuration: {e}"),
        })?;
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

#[derive(Debug)]
pub struct ShopifyConnector {
    base: BaseConnector,
    config: Option<ShopifyConfig>,
    client: Option<ShopifyClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl ShopifyConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.shopify")),
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

    fn require_u64(input: &serde_json::Value, key: &str) -> FcpResult<u64> {
        input
            .get(key)
            .and_then(|v| v.as_u64())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: format!("Missing or invalid integer: {key}"),
            })
    }
}

impl Default for ShopifyConnector {
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
            id: OperationId::from_static(OP_PRODUCTS_LIST),
            summary: "List products".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_PRODUCTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "List products in the store",
                vec![],
                vec![CAP_PRODUCTS_WRITE],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_PRODUCTS_GET),
            summary: "Get product by ID".into(),
            description: None,
            input_schema: json!({"type":"object","required":["product_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_PRODUCTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Get details of a specific product",
                vec!["Use numeric product_id not handle".into()],
                vec![CAP_PRODUCTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_PRODUCTS_CREATE),
            summary: "Create a product".into(),
            description: None,
            input_schema: json!({"type":"object","required":["title"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_PRODUCTS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Create a new product",
                vec!["title is required".into()],
                vec![CAP_PRODUCTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_PRODUCTS_UPDATE),
            summary: "Update a product".into(),
            description: None,
            input_schema: json!({"type":"object","required":["product_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_PRODUCTS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Update an existing product",
                vec!["product_id is required".into()],
                vec![CAP_PRODUCTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_PRODUCTS_DELETE),
            summary: "Delete a product".into(),
            description: None,
            input_schema: json!({"type":"object","required":["product_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_PRODUCTS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Delete a product (irreversible)",
                vec!["Verify product_id first".into()],
                vec![CAP_PRODUCTS_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ORDERS_LIST),
            summary: "List orders".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_ORDERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint("List recent orders", vec![], vec![CAP_ORDERS_WRITE]),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_ORDERS_GET),
            summary: "Get order by ID".into(),
            description: None,
            input_schema: json!({"type":"object","required":["order_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_ORDERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Get details of a specific order",
                vec!["Use numeric order_id".into()],
                vec![CAP_ORDERS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_ORDERS_CREATE),
            summary: "Create an order".into(),
            description: None,
            input_schema: json!({"type":"object","required":["line_items"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_ORDERS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Create a new order",
                vec!["line_items with variant_id and quantity required".into()],
                vec![CAP_ORDERS_READ, CAP_PRODUCTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_CUSTOMERS_LIST),
            summary: "List customers".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_CUSTOMERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint("List store customers", vec![], vec![]),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_CUSTOMERS_GET),
            summary: "Get customer by ID".into(),
            description: None,
            input_schema: json!({"type":"object","required":["customer_id"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_CUSTOMERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Get a specific customer",
                vec!["Use numeric customer_id".into()],
                vec![],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_INVENTORY_LIST),
            summary: "List inventory levels".into(),
            description: None,
            input_schema: json!({"type":"object","required":["location_id"]}),
            output_schema: json!({"type":"array"}),
            capability: CapabilityId::from_static(CAP_INVENTORY_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Check inventory at a location",
                vec!["location_id is required".into()],
                vec![CAP_PRODUCTS_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Check API credentials".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_PRODUCTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint("Verify Shopify credentials", vec![], vec![]),
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

#[async_trait]
impl FcpConnector for ShopifyConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let cfg = ShopifyConfig::from_value(config)?;
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(cfg.request_timeout_ms)),
        ));
        let client = ShopifyClient::new(
            &cfg.shop_domain,
            cfg.access_token.clone(),
            &cfg.api_version,
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
        info!(event = "shopify.configure", "Configured Shopify connector");
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
            "manifest_hash": Self::manifest_hash(),
        }));
        snap
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(_config) = &self.config else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };

        let Some(client) = &self.client else {
            return Ok(SelfCheckReport::failed(
                "client_missing",
                "Shopify HTTP client not initialized; re-run configure",
            ));
        };
        let Some(runtime) = &self.runtime else {
            return Ok(SelfCheckReport::failed(
                "runtime_missing",
                "ConnectorRuntime not initialized; re-run configure",
            ));
        };

        match client.health_check(runtime).await {
            Ok(shop) => {
                info!(
                    event = "shopify.self_check",
                    shop_name = %shop.name,
                    "Shopify self_check passed"
                );
                Ok(SelfCheckReport::ok())
            }
            Err(error) if error.is_retryable() => Ok(SelfCheckReport::degraded(
                "self_check_retryable",
                error.to_string(),
            )),
            Err(error) => Ok(SelfCheckReport::failed(
                "self_check_failed",
                error.to_string(),
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

impl ShopifyConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        if let Some(verifier) = &self.verifier {
            let cap = match operation {
                OP_PRODUCTS_LIST | OP_PRODUCTS_GET | OP_HEALTH => {
                    CapabilityId::from_static(CAP_PRODUCTS_READ)
                }
                OP_PRODUCTS_CREATE | OP_PRODUCTS_UPDATE | OP_PRODUCTS_DELETE => {
                    CapabilityId::from_static(CAP_PRODUCTS_WRITE)
                }
                OP_ORDERS_LIST | OP_ORDERS_GET => CapabilityId::from_static(CAP_ORDERS_READ),
                OP_ORDERS_CREATE => CapabilityId::from_static(CAP_ORDERS_WRITE),
                OP_CUSTOMERS_LIST | OP_CUSTOMERS_GET => {
                    CapabilityId::from_static(CAP_CUSTOMERS_READ)
                }
                OP_INVENTORY_LIST => CapabilityId::from_static(CAP_INVENTORY_READ),
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
            message: "connector ready state missing Shopify client".into(),
        })?;

        let output = match operation {
            OP_PRODUCTS_LIST => {
                let products = client
                    .list_products(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&products).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_PRODUCTS_GET => {
                let pid = Self::require_u64(&req.input, "product_id")?;
                let product = client
                    .get_product(runtime, pid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&product).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_PRODUCTS_CREATE => {
                let title = Self::require_str(&req.input, "title")?;
                let product = CreateProduct {
                    title: title.into(),
                    body_html: req
                        .input
                        .get("body_html")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    vendor: req
                        .input
                        .get("vendor")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    product_type: req
                        .input
                        .get("product_type")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    status: req
                        .input
                        .get("status")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    tags: req
                        .input
                        .get("tags")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    variants: req
                        .input
                        .get("variants")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .map(|v| CreateVariant {
                                    title: v
                                        .get("title")
                                        .and_then(|t| t.as_str())
                                        .map(String::from),
                                    price: v
                                        .get("price")
                                        .and_then(|p| p.as_str())
                                        .map(String::from),
                                    sku: v.get("sku").and_then(|s| s.as_str()).map(String::from),
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                };
                let created = client
                    .create_product(runtime, &product)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&created).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_PRODUCTS_UPDATE => {
                let pid = Self::require_u64(&req.input, "product_id")?;
                let update = UpdateProduct {
                    title: req
                        .input
                        .get("title")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    body_html: req
                        .input
                        .get("body_html")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    vendor: req
                        .input
                        .get("vendor")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    product_type: req
                        .input
                        .get("product_type")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    status: req
                        .input
                        .get("status")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    tags: req
                        .input
                        .get("tags")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                };
                let updated = client
                    .update_product(runtime, pid, &update)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&updated).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_PRODUCTS_DELETE => {
                let pid = Self::require_u64(&req.input, "product_id")?;
                client
                    .delete_product(runtime, pid)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_ORDERS_LIST => {
                let orders = client
                    .list_orders(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&orders).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_ORDERS_GET => {
                let oid = Self::require_u64(&req.input, "order_id")?;
                let order = client
                    .get_order(runtime, oid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&order).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_ORDERS_CREATE => {
                let items = req
                    .input
                    .get("line_items")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing: line_items array".into(),
                    })?;
                let line_items: Vec<CreateLineItem> = items
                    .iter()
                    .map(|item| {
                        Ok(CreateLineItem {
                            variant_id: item
                                .get("variant_id")
                                .and_then(|v| v.as_u64())
                                .ok_or_else(|| FcpError::InvalidRequest {
                                    code: 1005,
                                    message: "line_items[].variant_id required".into(),
                                })?,
                            quantity: item.get("quantity").and_then(|v| v.as_i64()).unwrap_or(1),
                        })
                    })
                    .collect::<FcpResult<Vec<_>>>()?;
                let order = CreateOrder {
                    line_items,
                    email: req
                        .input
                        .get("email")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    financial_status: req
                        .input
                        .get("financial_status")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                };
                let created = client
                    .create_order(runtime, &order)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&created).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_CUSTOMERS_LIST => {
                let customers = client
                    .list_customers(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&customers).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_CUSTOMERS_GET => {
                let cid = Self::require_u64(&req.input, "customer_id")?;
                let customer = client
                    .get_customer(runtime, cid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&customer).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_INVENTORY_LIST => {
                let lid = Self::require_u64(&req.input, "location_id")?;
                let levels = client
                    .list_inventory_levels(runtime, lid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&levels).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_HEALTH => {
                let shop = client
                    .health_check(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({"healthy": true, "shop_name": shop.name, "shop_id": shop.id})
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
            "shop_domain": "test.myshopify.com",
            "access_token": "shpat_test123"
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
                CapabilityId::from_static(CAP_PRODUCTS_READ),
                CapabilityId::from_static(CAP_PRODUCTS_WRITE),
                CapabilityId::from_static(CAP_ORDERS_READ),
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
            connector_id: ConnectorId::from_static("fcp.shopify"),
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
        assert!(ShopifyConnector::new().config.is_none());
    }

    #[test]
    fn default_ok() {
        assert!(ShopifyConnector::default().config.is_none());
    }

    #[test]
    fn manifest_hash_stable() {
        assert_eq!(
            ShopifyConnector::manifest_hash(),
            ShopifyConnector::manifest_hash()
        );
    }

    #[test]
    fn configure_valid() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await
            })
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn configure_empty_domain() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(json!({"shop_domain":"","access_token":"t"}))
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
                let mut c = ShopifyConnector::new();
                c.configure(json!("bad")).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_missing_token() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(json!({"shop_domain":"test.myshopify.com","access_token":""}))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn doctor_unconfigured() {
        assert!(!ShopifyConnector::new().doctor().ready);
    }

    #[test]
    fn doctor_configured() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.doctor()
            })
            .unwrap()
            .ready
        );
    }

    #[test]
    fn introspect_ops() {
        assert_eq!(ShopifyConnector::new().introspect().operations.len(), 12);
    }

    #[test]
    fn ops_all_have_hints() {
        for op in operations_info() {
            assert!(!op.ai_hints.when_to_use.is_empty(), "{}", op.id);
        }
    }

    #[test]
    fn dangerous_ops_need_approval() {
        for op in operations_info() {
            if op.safety_tier == SafetyTier::Dangerous {
                assert!(op.requires_approval.is_some(), "{}", op.id);
            }
        }
    }

    #[test]
    fn invoke_unknown() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req("shopify.nope", json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_product_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_PRODUCTS_GET, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_order_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_ORDERS_GET, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_customer_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_CUSTOMERS_GET, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_location_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_INVENTORY_LIST, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_create_order_missing_line_items() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_ORDERS_CREATE, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_create_order_missing_variant_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(
                    OP_ORDERS_CREATE,
                    json!({"line_items": [{"quantity": 1}]}),
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
            ShopifyConnector::new()
                .simulate(SimulateRequest::new(
                    ConnectorId::from_static("fcp.shopify"),
                    OperationId::from_static(OP_PRODUCTS_LIST),
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
                ShopifyConnector::new()
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
            let mut c = ShopifyConnector::new();
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
            let mut c = ShopifyConnector::new();
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
            ShopifyConnector::require_str(&json!({"k":"v"}), "k").unwrap(),
            "v"
        );
    }

    #[test]
    fn require_str_miss() {
        assert!(ShopifyConnector::require_str(&json!({}), "k").is_err());
    }

    #[test]
    fn require_str_empty() {
        assert!(ShopifyConnector::require_str(&json!({"k": ""}), "k").is_err());
        assert!(ShopifyConnector::require_str(&json!({"k": "  "}), "k").is_err());
    }

    #[test]
    fn require_u64_ok() {
        assert_eq!(
            ShopifyConnector::require_u64(&json!({"id": 42}), "id").unwrap(),
            42
        );
    }

    #[test]
    fn require_u64_miss() {
        assert!(ShopifyConnector::require_u64(&json!({}), "id").is_err());
    }

    #[test]
    fn health_unconfigured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            ShopifyConnector::new().health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Degraded { .. }));
    }

    #[test]
    fn health_configured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            let mut c = ShopifyConnector::new();
            c.configure(tc()).await.unwrap();
            c.health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Ready));
    }

    #[test]
    fn config_debug_redacts_token() {
        let cfg = ShopifyConfig {
            shop_domain: "test.myshopify.com".into(),
            access_token: "shpat_secret".into(),
            api_version: "2024-01".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: 30_000,
        };
        let debug = format!("{cfg:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("shpat_secret"));
    }

    #[test]
    fn invoke_create_product_missing_title() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_PRODUCTS_CREATE, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_update_missing_product_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_PRODUCTS_UPDATE, json!({"title":"x"})))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_delete_missing_product_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_PRODUCTS_DELETE, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn ops_count_matches_spec() {
        let ops = operations_info();
        assert_eq!(ops.len(), 12, "Expected 12 operations");
        let safe_count = ops
            .iter()
            .filter(|o| o.safety_tier == SafetyTier::Safe)
            .count();
        assert_eq!(safe_count, 8, "Expected 8 safe operations");
        let risky_count = ops
            .iter()
            .filter(|o| o.safety_tier == SafetyTier::Risky)
            .count();
        assert_eq!(risky_count, 3, "Expected 3 risky operations");
        let dangerous_count = ops
            .iter()
            .filter(|o| o.safety_tier == SafetyTier::Dangerous)
            .count();
        assert_eq!(dangerous_count, 1, "Expected 1 dangerous operation");
    }
}
