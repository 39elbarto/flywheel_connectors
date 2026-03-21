//! Coda connector implementation.

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

use crate::client::CodaClient;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// Operation IDs
const OP_DOCS_LIST: &str = "coda.docs.list";
const OP_DOCS_GET: &str = "coda.docs.get";
const OP_DOCS_CREATE: &str = "coda.docs.create";
const OP_PAGES_LIST: &str = "coda.pages.list";
const OP_TABLES_LIST: &str = "coda.tables.list";
const OP_ROWS_LIST: &str = "coda.rows.list";
const OP_ROWS_UPSERT: &str = "coda.rows.upsert";
const OP_ROWS_DELETE: &str = "coda.rows.delete";
const OP_FORMULAS_LIST: &str = "coda.formulas.list";
const OP_HEALTH: &str = "coda.health";

// Capability IDs
const CAP_DOCS_READ: &str = "coda.docs.read";
const CAP_DOCS_WRITE: &str = "coda.docs.write";
const CAP_TABLES_READ: &str = "coda.tables.read";
const CAP_TABLES_WRITE: &str = "coda.tables.write";

/// Coda connector configuration.
#[derive(Clone, Deserialize)]
struct CodaConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    api_token: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl std::fmt::Debug for CodaConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodaConfig")
            .field("base_url", &self.base_url)
            .field("api_token", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    "https://coda.io/apis/v1".into()
}

const fn default_request_timeout_ms() -> u64 {
    30_000
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

/// Coda connector state.
#[derive(Debug)]
pub struct CodaConnector {
    base: BaseConnector,
    config: Option<CodaConfig>,
    client: Option<CodaClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl CodaConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.coda")),
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

            let allowed_hosts = ["coda.io"];
            let host_part = config
                .base_url
                .split("://")
                .nth(1)
                .unwrap_or("")
                .split('/')
                .next()
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("");
            let host_ok = host_part == "localhost"
                || host_part == "127.0.0.1"
                || allowed_hosts.contains(&host_part);
            checks.push(DoctorCheck {
                name: "network_constraints".into(),
                passed: host_ok,
                message: Some(if host_ok {
                    "Base URL matches allowed host (coda.io)".into()
                } else {
                    format!(
                        "Base URL {} does not match allowed hosts",
                        config.base_url
                    )
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
                    "API token configured".into()
                }),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks)
    }
}

impl Default for CodaConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the typed operations catalog.
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_DOCS_LIST),
            summary: "List documents".into(),
            description: Some("Lists Coda documents accessible to the authenticated user".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "description": "Max results per page (default 25)" },
                    "page_token": { "type": "string", "description": "Pagination token" },
                    "query": { "type": "string", "description": "Search query to filter docs" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "items": { "type": "array" },
                    "nextPageToken": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_DOCS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to list Coda documents accessible to the user".into(),
                common_mistakes: vec![
                    "Use page_token for pagination, not offset".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_DOCS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_DOCS_GET),
            summary: "Get a single document".into(),
            description: Some("Retrieves details about a specific Coda document".into()),
            input_schema: json!({
                "type": "object",
                "required": ["doc_id"],
                "properties": {
                    "doc_id": { "type": "string", "description": "Document ID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "name": { "type": "string" },
                    "owner": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_DOCS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need details about a specific Coda document".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_DOCS_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_DOCS_CREATE),
            summary: "Create a new document".into(),
            description: Some("Creates a new Coda document, optionally from a template".into()),
            input_schema: json!({
                "type": "object",
                "required": ["title"],
                "properties": {
                    "title": { "type": "string", "description": "Document title" },
                    "source_doc": { "type": "string", "description": "Source doc ID to copy from" },
                    "folder_id": { "type": "string", "description": "Folder ID to place the doc in" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "name": { "type": "string" },
                    "browserLink": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_DOCS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to create a new Coda document".into(),
                common_mistakes: vec![
                    "source_doc must be a valid doc ID if specified".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_DOCS_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PAGES_LIST),
            summary: "List pages in a document".into(),
            description: Some("Lists all pages (sections) within a Coda document".into()),
            input_schema: json!({
                "type": "object",
                "required": ["doc_id"],
                "properties": {
                    "doc_id": { "type": "string", "description": "Document ID" },
                    "limit": { "type": "integer", "description": "Max results per page" },
                    "page_token": { "type": "string", "description": "Pagination token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "items": { "type": "array" },
                    "nextPageToken": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_DOCS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to list pages/sections in a Coda document".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_DOCS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_TABLES_LIST),
            summary: "List tables in a document".into(),
            description: Some("Lists all tables and views within a Coda document".into()),
            input_schema: json!({
                "type": "object",
                "required": ["doc_id"],
                "properties": {
                    "doc_id": { "type": "string", "description": "Document ID" },
                    "limit": { "type": "integer", "description": "Max results per page" },
                    "page_token": { "type": "string", "description": "Pagination token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "items": { "type": "array" },
                    "nextPageToken": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_TABLES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to list tables and views in a Coda document".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_ROWS_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ROWS_LIST),
            summary: "List rows in a table".into(),
            description: Some("Lists rows in a Coda table with optional filtering".into()),
            input_schema: json!({
                "type": "object",
                "required": ["doc_id", "table_id"],
                "properties": {
                    "doc_id": { "type": "string", "description": "Document ID" },
                    "table_id": { "type": "string", "description": "Table or view ID" },
                    "limit": { "type": "integer", "description": "Max results per page" },
                    "page_token": { "type": "string", "description": "Pagination token" },
                    "query": { "type": "string", "description": "Filter query" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "items": { "type": "array" },
                    "nextPageToken": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_TABLES_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to read rows from a Coda table".into(),
                common_mistakes: vec![
                    "table_id can be a table ID or a view ID".into(),
                    "Row values are keyed by column ID, not column name".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_TABLES_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ROWS_UPSERT),
            summary: "Upsert rows in a table".into(),
            description: Some("Inserts or updates rows in a Coda table based on key columns".into()),
            input_schema: json!({
                "type": "object",
                "required": ["doc_id", "table_id", "rows"],
                "properties": {
                    "doc_id": { "type": "string", "description": "Document ID" },
                    "table_id": { "type": "string", "description": "Table ID" },
                    "rows": {
                        "type": "array",
                        "description": "Array of row objects with cells",
                        "items": {
                            "type": "object",
                            "properties": {
                                "cells": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "column": { "type": "string" },
                                            "value": {}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "key_columns": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Columns to use as upsert key"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "requestId": { "type": "string" },
                    "addedRowIds": { "type": "array", "items": { "type": "string" } }
                }
            }),
            capability: CapabilityId::from_static(CAP_TABLES_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to insert or update rows in a Coda table".into(),
                common_mistakes: vec![
                    "Columns must be referenced by column ID or name".into(),
                    "key_columns enables upsert behavior; without it, rows are always inserted".into(),
                ],
                examples: Vec::new(),
                related: vec![
                    CapabilityId::from_static(OP_ROWS_LIST),
                    CapabilityId::from_static(OP_ROWS_DELETE),
                ],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ROWS_DELETE),
            summary: "Delete rows from a table".into(),
            description: Some("Deletes specified rows from a Coda table".into()),
            input_schema: json!({
                "type": "object",
                "required": ["doc_id", "table_id", "row_ids"],
                "properties": {
                    "doc_id": { "type": "string", "description": "Document ID" },
                    "table_id": { "type": "string", "description": "Table ID" },
                    "row_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "IDs of rows to delete"
                    }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "requestId": { "type": "string" },
                    "row_ids": { "type": "array", "items": { "type": "string" } }
                }
            }),
            capability: CapabilityId::from_static(CAP_TABLES_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to delete rows from a Coda table".into(),
                common_mistakes: vec![
                    "Deleted rows cannot be recovered".into(),
                    "Verify row_ids before deleting".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_ROWS_LIST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_FORMULAS_LIST),
            summary: "List formulas in a document".into(),
            description: Some("Lists named formulas in a Coda document".into()),
            input_schema: json!({
                "type": "object",
                "required": ["doc_id"],
                "properties": {
                    "doc_id": { "type": "string", "description": "Document ID" },
                    "limit": { "type": "integer", "description": "Max results per page" },
                    "page_token": { "type": "string", "description": "Pagination token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "items": { "type": "array" },
                    "nextPageToken": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_DOCS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to list named formulas in a Coda document".into(),
                common_mistakes: Vec::new(),
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(OP_DOCS_GET)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Coda health check".into(),
            description: Some("Checks Coda API reachability and authentication".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_DOCS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to verify that the Coda API is reachable".into(),
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
impl FcpConnector for CodaConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: CodaConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Coda config: {e}"),
            })?;

        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.request_timeout_ms)),
        ));

        let client =
            CodaClient::new(&config.base_url, &config.api_token, config.retry.clone()).map_err(
                |e| FcpError::Internal {
                    message: format!("Failed to create Coda client: {e}"),
                },
            )?;

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

impl CodaConnector {
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap = match operation {
            OP_DOCS_LIST | OP_DOCS_GET | OP_PAGES_LIST | OP_FORMULAS_LIST | OP_HEALTH => {
                CapabilityId::from_static(CAP_DOCS_READ)
            }
            OP_DOCS_CREATE => CapabilityId::from_static(CAP_DOCS_WRITE),
            OP_TABLES_LIST | OP_ROWS_LIST => CapabilityId::from_static(CAP_TABLES_READ),
            OP_ROWS_UPSERT | OP_ROWS_DELETE => CapabilityId::from_static(CAP_TABLES_WRITE),
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
            message: "Coda client missing after configure".into(),
        })?;

        let output = match operation {
            OP_DOCS_LIST => {
                let limit = req.input.get("limit").and_then(|v| v.as_u64()).map(|v| v as u32);
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let query = req.input.get("query").and_then(|v| v.as_str());
                let resp = client
                    .list_docs(runtime, limit, page_token, query)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize docs: {e}"),
                })?
            }
            OP_DOCS_GET => {
                let doc_id = req
                    .input
                    .get("doc_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'doc_id' field".into(),
                    })?;
                let resp = client
                    .get_doc(runtime, doc_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize doc: {e}"),
                })?
            }
            OP_DOCS_CREATE => {
                let title = req
                    .input
                    .get("title")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'title' field".into(),
                    })?;
                let source_doc = req.input.get("source_doc").and_then(|v| v.as_str());
                let folder_id = req.input.get("folder_id").and_then(|v| v.as_str());
                let resp = client
                    .create_doc(runtime, title, source_doc, folder_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize doc: {e}"),
                })?
            }
            OP_PAGES_LIST => {
                let doc_id = req
                    .input
                    .get("doc_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'doc_id' field".into(),
                    })?;
                let limit = req.input.get("limit").and_then(|v| v.as_u64()).map(|v| v as u32);
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_pages(runtime, doc_id, limit, page_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize pages: {e}"),
                })?
            }
            OP_TABLES_LIST => {
                let doc_id = req
                    .input
                    .get("doc_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'doc_id' field".into(),
                    })?;
                let limit = req.input.get("limit").and_then(|v| v.as_u64()).map(|v| v as u32);
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_tables(runtime, doc_id, limit, page_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize tables: {e}"),
                })?
            }
            OP_ROWS_LIST => {
                let doc_id = req
                    .input
                    .get("doc_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'doc_id' field".into(),
                    })?;
                let table_id = req
                    .input
                    .get("table_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'table_id' field".into(),
                    })?;
                let limit = req.input.get("limit").and_then(|v| v.as_u64()).map(|v| v as u32);
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let query = req.input.get("query").and_then(|v| v.as_str());
                let resp = client
                    .list_rows(runtime, doc_id, table_id, limit, page_token, query)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize rows: {e}"),
                })?
            }
            OP_ROWS_UPSERT => {
                let doc_id = req
                    .input
                    .get("doc_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'doc_id' field".into(),
                    })?;
                let table_id = req
                    .input
                    .get("table_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'table_id' field".into(),
                    })?;
                let rows = req.input.get("rows").ok_or(FcpError::InvalidRequest {
                    code: 1005,
                    message: "Missing 'rows' field".into(),
                })?;

                let key_columns = req.input.get("key_columns");
                let mut body = json!({ "rows": rows });
                if let Some(kc) = key_columns {
                    body["keyColumns"] = kc.clone();
                }

                let resp = client
                    .upsert_rows(runtime, doc_id, table_id, &body)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize upsert response: {e}"),
                })?
            }
            OP_ROWS_DELETE => {
                let doc_id = req
                    .input
                    .get("doc_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'doc_id' field".into(),
                    })?;
                let table_id = req
                    .input
                    .get("table_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'table_id' field".into(),
                    })?;
                let row_ids: Vec<String> = req
                    .input
                    .get("row_ids")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing or invalid 'row_ids' field".into(),
                    })?;

                let resp = client
                    .delete_rows(runtime, doc_id, table_id, &row_ids)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize delete response: {e}"),
                })?
            }
            OP_FORMULAS_LIST => {
                let doc_id = req
                    .input
                    .get("doc_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'doc_id' field".into(),
                    })?;
                let limit = req.input.get("limit").and_then(|v| v.as_u64()).map(|v| v as u32);
                let page_token = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_formulas(runtime, doc_id, limit, page_token)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize formulas: {e}"),
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

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_DOCS_READ),
                CapabilityId::from_static(CAP_DOCS_WRITE),
                CapabilityId::from_static(CAP_TABLES_READ),
                CapabilityId::from_static(CAP_TABLES_WRITE),
            ],
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

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = CodaConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_valid() {
        let mut connector = CodaConnector::new();
        let config = json!({
            "api_token": "test_token"
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
        assert!(connector.runtime.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = CodaConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = CodaConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = CodaConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = CodaConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = CodaConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = CodaConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = CodaConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_DOCS_LIST),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[test]
    fn test_introspection_operations() {
        let connector = CodaConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 10);
        for op_id in &[
            OP_DOCS_LIST,
            OP_DOCS_GET,
            OP_DOCS_CREATE,
            OP_PAGES_LIST,
            OP_TABLES_LIST,
            OP_ROWS_LIST,
            OP_ROWS_UPSERT,
            OP_ROWS_DELETE,
            OP_FORMULAS_LIST,
            OP_HEALTH,
        ] {
            assert!(
                intro.operations.iter().any(|op| op.id.as_str() == *op_id),
                "Missing operation: {op_id}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = CodaConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), "coda.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = CodaConnector::new();
        let req = base_invoke(connector.id(), OP_DOCS_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_docs_get_missing_id() {
        let mut connector = CodaConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_DOCS_GET);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_docs_create_missing_title() {
        let mut connector = CodaConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_DOCS_CREATE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_pages_list_missing_doc_id() {
        let mut connector = CodaConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_PAGES_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_tables_list_missing_doc_id() {
        let mut connector = CodaConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_TABLES_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_rows_list_missing_fields() {
        let mut connector = CodaConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_ROWS_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_rows_upsert_missing_fields() {
        let mut connector = CodaConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_ROWS_UPSERT);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_rows_delete_missing_fields() {
        let mut connector = CodaConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_ROWS_DELETE);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_formulas_list_missing_doc_id() {
        let mut connector = CodaConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        connector.handshake(base_handshake()).await.unwrap();
        let req = base_invoke(connector.id(), OP_FORMULAS_LIST);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 10);
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_docs_list_is_safe() {
        let ops = operations_info();
        let op = ops.iter().find(|op| op.id.as_str() == OP_DOCS_LIST).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_docs_create_is_risky() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_DOCS_CREATE)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_rows_delete_is_dangerous() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_ROWS_DELETE)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Dangerous);
        assert_eq!(op.risk_level, RiskLevel::High);
        assert_eq!(op.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn test_rows_upsert_is_risky() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_ROWS_UPSERT)
            .unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Risky);
        assert_eq!(op.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = CodaConnector::manifest_hash();
        let hash2 = CodaConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = CodaConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_before_handshake_returns_not_handshaken() {
        let mut connector = CodaConnector::new();
        connector
            .configure(json!({ "api_token": "tok" }))
            .await
            .unwrap();
        let result = connector
            .invoke(base_invoke(connector.id(), OP_DOCS_LIST))
            .await;
        assert!(matches!(result, Err(FcpError::NotHandshaken)));
    }

    #[test]
    fn debug_redacts_config_secrets() {
        let config = CodaConfig {
            base_url: default_base_url(),
            api_token: "super_secret_token".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: default_request_timeout_ms(),
        };
        let debug_output = format!("{config:?}");
        assert!(
            !debug_output.contains("super_secret_token"),
            "Debug output must not contain the raw api_token"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should show [REDACTED] for sensitive fields"
        );
    }

    #[test]
    fn test_health_operation_is_safe() {
        let ops = operations_info();
        let op = ops.iter().find(|op| op.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(op.safety_tier, SafetyTier::Safe);
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_connector_default() {
        let connector = CodaConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.coda");
    }

    #[test]
    fn test_capability_mapping() {
        let ops = operations_info();
        for op in &ops {
            let cap_str = op.capability.as_str();
            assert!(
                cap_str.starts_with("coda."),
                "Capability {cap_str} should start with 'coda.'"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_base_url() {
        let mut connector = CodaConnector::new();
        let config = json!({
            "api_token": "tok",
            "base_url": "https://custom.coda.io/apis/v1"
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_timeout() {
        let mut connector = CodaConnector::new();
        let config = json!({
            "api_token": "tok",
            "request_timeout_ms": 60000
        });
        let result = connector.configure(config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_formulas_list_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_FORMULAS_LIST)
            .unwrap();
        assert_eq!(op.capability, CapabilityId::from_static(CAP_DOCS_READ));
    }

    #[test]
    fn test_tables_list_capability() {
        let ops = operations_info();
        let op = ops
            .iter()
            .find(|op| op.id.as_str() == OP_TABLES_LIST)
            .unwrap();
        assert_eq!(op.capability, CapabilityId::from_static(CAP_TABLES_READ));
    }
}
