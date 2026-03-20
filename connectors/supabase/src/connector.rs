//! Supabase connector implementation.

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
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::client::{SupabaseAuth, SupabaseClient, DEFAULT_PROJECT_URL};
use crate::types::{
    DeleteRequest, InsertRequest, RpcRequest, SchemaTablesRequest, StorageDeleteRequest,
    StorageDownloadRequest, StorageUploadRequest, TableQueryRequest, UpdateRequest, UpsertRequest,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_QUERY: &str = "supabase.query";
const OP_INSERT: &str = "supabase.insert";
const OP_UPDATE: &str = "supabase.update";
const OP_UPSERT: &str = "supabase.upsert";
const OP_DELETE: &str = "supabase.delete";
const OP_RPC: &str = "supabase.rpc";
const OP_SCHEMA_TABLES: &str = "supabase.schema.tables";
const OP_STORAGE_UPLOAD: &str = "supabase.storage.upload";
const OP_STORAGE_DOWNLOAD: &str = "supabase.storage.download";
const OP_STORAGE_DELETE: &str = "supabase.storage.delete";
const OP_HEALTH: &str = "supabase.health";

const CAP_READ: &str = "supabase.read";
const CAP_WRITE: &str = "supabase.write";
const CAP_STORAGE: &str = "supabase.storage";

#[derive(Clone, serde::Deserialize)]
pub struct SupabaseConfig {
    #[serde(default = "default_project_url")]
    pub project_url: String,
    pub api_key: Option<String>,
    #[serde(default = "default_schema")]
    pub schema: String,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
}

fn default_project_url() -> String {
    DEFAULT_PROJECT_URL.into()
}
fn default_schema() -> String {
    "public".into()
}
const fn default_timeout_ms() -> u64 {
    30_000
}

impl std::fmt::Debug for SupabaseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupabaseConfig")
            .field("project_url", &self.project_url)
            .field("api_key", &"[REDACTED]")
            .field("schema", &self.schema)
            .finish()
    }
}

impl SupabaseConfig {
    fn validate(&self) -> Result<(), String> {
        if self.project_url.is_empty() {
            return Err("project_url cannot be empty".into());
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

    fn auth(&self) -> SupabaseAuth {
        match &self.api_key {
            Some(key) if !key.trim().is_empty() => SupabaseAuth::ApiKey(key.clone()),
            _ => SupabaseAuth::Secretless,
        }
    }
}

#[derive(Debug)]
pub struct SupabaseConnector {
    base: BaseConnector,
    config: Option<SupabaseConfig>,
    client: Option<SupabaseClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl SupabaseConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.supabase")),
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

    #[allow(dead_code)]
    fn require_str<'a>(input: &'a serde_json::Value, key: &str) -> FcpResult<&'a str> {
        input
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: format!("Missing: {key}"),
            })
    }
}

impl Default for SupabaseConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::too_many_lines)]
fn operations_info() -> Vec<OperationInfo> {
    let hint = |when: &str,
                mistakes: Vec<String>,
                examples: Vec<String>,
                related: Vec<&'static str>|
     -> AgentHint {
        AgentHint {
            when_to_use: when.into(),
            common_mistakes: mistakes,
            examples,
            related: related.into_iter().map(CapabilityId::from_static).collect(),
        }
    };
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_QUERY),
            summary: "Query a Supabase table or view through PostgREST".into(),
            description: None,
            input_schema: json!({"type":"object","required":["table"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Read rows from a PostgREST table or view",
                vec!["Forgetting to add a limit for wide tables".into()],
                vec![],
                vec![CAP_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_INSERT),
            summary: "Insert rows into a Supabase table".into(),
            description: None,
            input_schema: json!({"type":"object","required":["table","rows"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Create new rows via PostgREST",
                vec!["Sending an empty rows array".into()],
                vec![],
                vec![CAP_WRITE],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_UPDATE),
            summary: "Update rows in a Supabase table".into(),
            description: None,
            input_schema: json!({"type":"object","required":["table","values","filters"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Patch rows matching explicit filters",
                vec!["Omitting filters broadens the mutation surface".into()],
                vec![],
                vec![CAP_WRITE],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_UPSERT),
            summary: "Upsert rows in a Supabase table".into(),
            description: None,
            input_schema: json!({"type":"object","required":["table","rows"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Merge rows using conflict resolution",
                vec!["Forgetting on_conflict for non-primary-key merges".into()],
                vec![],
                vec![CAP_WRITE],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_DELETE),
            summary: "Delete rows from a Supabase table".into(),
            description: None,
            input_schema: json!({"type":"object","required":["table","filters"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Hard-delete rows (irreversible)",
                vec!["Running delete without a narrow filter".into()],
                vec![],
                vec![CAP_WRITE],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_RPC),
            summary: "Invoke a Supabase Postgres function through PostgREST RPC".into(),
            description: None,
            input_schema: json!({"type":"object","required":["function"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: hint(
                "Call a server-side Postgres function via /rpc",
                vec!["Assuming RPC is read-only without checking function semantics".into()],
                vec![],
                vec![CAP_WRITE],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_SCHEMA_TABLES),
            summary: "List exposed PostgREST table and view resources".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Inspect what relations the PostgREST surface exposes",
                vec!["Assuming system tables will appear".into()],
                vec![],
                vec![CAP_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_STORAGE_UPLOAD),
            summary: "Upload a file into Supabase Storage".into(),
            description: None,
            input_schema: json!({"type":"object","required":["bucket","path","content_base64"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_STORAGE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: hint(
                "Upload an object into a Storage bucket",
                vec!["Sending raw bytes instead of base64".into()],
                vec![],
                vec![CAP_STORAGE],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_STORAGE_DOWNLOAD),
            summary: "Download a file from Supabase Storage".into(),
            description: None,
            input_schema: json!({"type":"object","required":["bucket","path"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_STORAGE),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Retrieve a stored object from Supabase Storage",
                vec!["Using the public path for a private bucket".into()],
                vec![],
                vec![CAP_STORAGE],
            ),
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static(OP_STORAGE_DELETE),
            summary: "Delete a file from Supabase Storage".into(),
            description: None,
            input_schema: json!({"type":"object","required":["bucket","path"]}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_STORAGE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Permanently remove a Storage object (irreversible)",
                vec!["Deleting wrong path due to missing folder segments".into()],
                vec![],
                vec![CAP_STORAGE],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Check Supabase PostgREST reachability".into(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            capability: CapabilityId::from_static(CAP_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Verify that the Supabase REST surface is reachable",
                vec!["Assuming health proves every table policy is correct".into()],
                vec![],
                vec![CAP_READ],
            ),
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

fn json_response(key: &str, response: crate::types::JsonHttpResponse) -> serde_json::Value {
    let count = response
        .content_range
        .as_deref()
        .and_then(parse_content_range_total);

    let mut output = json!({
        key: response.data,
        "status_code": response.status_code,
    });
    if let Some(content_range) = response.content_range {
        output["content_range"] = json!(content_range);
    }
    if let Some(content_type) = response.content_type {
        output["content_type"] = json!(content_type);
    }
    if let Some(count) = count {
        output["count"] = json!(count);
    }
    output
}

fn parse_content_range_total(content_range: &str) -> Option<u64> {
    content_range.split('/').nth(1)?.parse::<u64>().ok()
}

#[async_trait]
impl FcpConnector for SupabaseConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let cfg = SupabaseConfig::from_value(config)?;
        let auth = cfg.auth();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(cfg.request_timeout_ms)),
        ));
        let client = SupabaseClient::new(auth, &cfg.project_url, &cfg.schema, cfg.request_timeout_ms)
            .map_err(|e| FcpError::Internal {
                message: format!("Client init: {e}"),
            })?;
        self.client = Some(client);
        self.config = Some(cfg);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        info!(event = "supabase.configure", "Configured Supabase connector");
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
        let Some(config) = &self.config else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };
        let Some(client) = &self.client else {
            return Ok(SelfCheckReport::failed(
                "client_missing",
                "Supabase HTTP client not initialized; re-run configure",
            ));
        };

        let auth = config.auth();
        if auth.is_secretless() {
            return Ok(SelfCheckReport::degraded(
                "credential_injection_required",
                "No API key configured; egress proxy must inject credentials",
            ));
        }

        match client.health().await {
            Ok(v) if v.get("status").and_then(|s| s.as_str()) == Some("ok") => {
                Ok(SelfCheckReport::ok())
            }
            Ok(_) => Ok(SelfCheckReport::degraded(
                "health_unknown",
                "PostgREST responded but health status is unclear",
            )),
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
        if let Some(client) = &self.client {
            client.shutdown();
        }
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

impl SupabaseConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        if let Some(verifier) = &self.verifier {
            let cap = match operation {
                OP_QUERY | OP_SCHEMA_TABLES | OP_HEALTH => CapabilityId::from_static(CAP_READ),
                OP_INSERT | OP_UPDATE | OP_UPSERT | OP_DELETE | OP_RPC => {
                    CapabilityId::from_static(CAP_WRITE)
                }
                OP_STORAGE_UPLOAD | OP_STORAGE_DOWNLOAD | OP_STORAGE_DELETE => {
                    CapabilityId::from_static(CAP_STORAGE)
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

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Supabase client".into(),
        })?;

        let output = match operation {
            OP_QUERY => {
                let request: TableQueryRequest =
                    serde_json::from_value(req.input.clone()).map_err(|e| {
                        FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid query input: {e}"),
                        }
                    })?;
                let result = client.query(&request).await.map_err(|e| e.to_fcp_error())?;
                json_response("data", result)
            }
            OP_INSERT => {
                let request: InsertRequest =
                    serde_json::from_value(req.input.clone()).map_err(|e| {
                        FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid insert input: {e}"),
                        }
                    })?;
                let result = client
                    .insert(&request)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json_response("data", result)
            }
            OP_UPDATE => {
                let request: UpdateRequest =
                    serde_json::from_value(req.input.clone()).map_err(|e| {
                        FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid update input: {e}"),
                        }
                    })?;
                let result = client
                    .update(&request)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json_response("data", result)
            }
            OP_UPSERT => {
                let request: UpsertRequest =
                    serde_json::from_value(req.input.clone()).map_err(|e| {
                        FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid upsert input: {e}"),
                        }
                    })?;
                let result = client
                    .upsert(&request)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json_response("data", result)
            }
            OP_DELETE => {
                let request: DeleteRequest =
                    serde_json::from_value(req.input.clone()).map_err(|e| {
                        FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid delete input: {e}"),
                        }
                    })?;
                let result = client
                    .delete(&request)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json_response("data", result)
            }
            OP_RPC => {
                let request: RpcRequest =
                    serde_json::from_value(req.input.clone()).map_err(|e| {
                        FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid RPC input: {e}"),
                        }
                    })?;
                let result = client.rpc(&request).await.map_err(|e| e.to_fcp_error())?;
                json_response("data", result)
            }
            OP_SCHEMA_TABLES => {
                let request: SchemaTablesRequest =
                    serde_json::from_value(req.input.clone()).map_err(|e| {
                        FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid schema_tables input: {e}"),
                        }
                    })?;
                let result = client
                    .schema_tables(&request)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(result).unwrap_or(json!({"tables": []}))
            }
            OP_STORAGE_UPLOAD => {
                let request: StorageUploadRequest =
                    serde_json::from_value(req.input.clone()).map_err(|e| {
                        FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid storage_upload input: {e}"),
                        }
                    })?;
                let result = client
                    .storage_upload(&request)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json_response("object", result)
            }
            OP_STORAGE_DOWNLOAD => {
                let request: StorageDownloadRequest =
                    serde_json::from_value(req.input.clone()).map_err(|e| {
                        FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid storage_download input: {e}"),
                        }
                    })?;
                let result = client
                    .storage_download(&request)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(result).unwrap_or(json!({}))
            }
            OP_STORAGE_DELETE => {
                let request: StorageDeleteRequest =
                    serde_json::from_value(req.input.clone()).map_err(|e| {
                        FcpError::InvalidRequest {
                            code: 1005,
                            message: format!("Invalid storage_delete input: {e}"),
                        }
                    })?;
                let result = client
                    .storage_delete(&request)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json_response("result", result)
            }
            OP_HEALTH => {
                let health = client.health().await.map_err(|e| e.to_fcp_error())?;
                json!({ "health": health })
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
        json!({"api_key": "sb-test-key", "project_url": "https://demo.supabase.co"})
    }

    fn handshake_req() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_WRITE),
                CapabilityId::from_static(CAP_STORAGE),
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
            connector_id: ConnectorId::from_static("fcp.supabase"),
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
        assert!(SupabaseConnector::new().config.is_none());
    }

    #[test]
    fn default_ok() {
        assert!(SupabaseConnector::default().config.is_none());
    }

    #[test]
    fn manifest_hash_stable() {
        assert_eq!(
            SupabaseConnector::manifest_hash(),
            SupabaseConnector::manifest_hash()
        );
    }

    #[test]
    fn configure_valid() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = SupabaseConnector::new();
                c.configure(tc()).await
            })
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn configure_no_key_succeeds() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = SupabaseConnector::new();
                c.configure(json!({"project_url": "https://demo.supabase.co"}))
                    .await
            })
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn configure_bad() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = SupabaseConnector::new();
                c.configure(json!("bad")).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn introspect_ops() {
        assert_eq!(SupabaseConnector::new().introspect().operations.len(), 11);
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
                let mut c = SupabaseConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req("supabase.nope", json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_table() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = SupabaseConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_QUERY, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn simulate_ok() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            SupabaseConnector::new()
                .simulate(SimulateRequest::new(
                    ConnectorId::from_static("fcp.supabase"),
                    OperationId::from_static(OP_QUERY),
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
                SupabaseConnector::new()
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
            let mut c = SupabaseConnector::new();
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
            let mut c = SupabaseConnector::new();
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
            SupabaseConnector::require_str(&json!({"k": "v"}), "k").unwrap(),
            "v"
        );
    }

    #[test]
    fn require_str_miss() {
        assert!(SupabaseConnector::require_str(&json!({}), "k").is_err());
    }

    #[test]
    fn health_unconfigured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            SupabaseConnector::new().health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Degraded { .. }));
    }

    #[test]
    fn health_configured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            let mut c = SupabaseConnector::new();
            c.configure(tc()).await.unwrap();
            c.health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Ready));
    }

    #[test]
    fn config_debug_redacts_api_key() {
        let config = SupabaseConfig::from_value(tc()).unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("sb-test-key"));
    }

    #[test]
    fn parse_content_range_total_works() {
        assert_eq!(parse_content_range_total("0-9/100"), Some(100));
        assert_eq!(parse_content_range_total("0-9/*"), None);
        assert_eq!(parse_content_range_total("*/42"), Some(42));
    }

    #[test]
    fn parse_content_range_total_empty() {
        assert_eq!(parse_content_range_total(""), None);
    }

    #[test]
    fn operations_match_v3_contract() {
        let ops = operations_info();

        let find = |id: &str| ops.iter().find(|o| o.id.as_str() == id).unwrap();

        let query = find(OP_QUERY);
        assert_eq!(query.safety_tier, SafetyTier::Safe);
        assert_eq!(query.risk_level, RiskLevel::Low);
        assert_eq!(query.idempotency, IdempotencyClass::Strict);

        let insert = find(OP_INSERT);
        assert_eq!(insert.safety_tier, SafetyTier::Risky);
        assert_eq!(insert.risk_level, RiskLevel::Medium);

        let delete = find(OP_DELETE);
        assert_eq!(delete.safety_tier, SafetyTier::Dangerous);
        assert_eq!(delete.risk_level, RiskLevel::High);
        assert!(delete.requires_approval.is_some());

        let rpc = find(OP_RPC);
        assert_eq!(rpc.idempotency, IdempotencyClass::BestEffort);

        let download = find(OP_STORAGE_DOWNLOAD);
        assert_eq!(download.idempotency, IdempotencyClass::None);

        let upload = find(OP_STORAGE_UPLOAD);
        assert_eq!(upload.idempotency, IdempotencyClass::BestEffort);

        let storage_delete = find(OP_STORAGE_DELETE);
        assert_eq!(storage_delete.safety_tier, SafetyTier::Dangerous);
        assert!(storage_delete.requires_approval.is_some());
    }

    #[test]
    fn event_caps_disabled() {
        let intro = SupabaseConnector::new().introspect();
        let caps = intro.event_caps.unwrap();
        assert!(!caps.streaming);
        assert!(!caps.replay);
    }

    #[test]
    fn connector_id_correct() {
        let c = SupabaseConnector::new();
        assert_eq!(c.id().as_str(), "fcp.supabase");
    }
}
