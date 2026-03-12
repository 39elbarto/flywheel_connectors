//! FCP Airtable Connector implementation.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, EventData, EventEnvelope, FcpError, FcpResult,
    HandshakeRequest, HandshakeResponse, IdempotencyClass, Introspection, OperationId,
    OperationInfo, OrderingPolicy, Principal, RiskLevel, SafetyTier, SelfCheckReport, SessionId,
    SimulateRequest, SimulateResponse, TrustLevel, ZoneId,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{AirtableAuth, AirtableClient, DEFAULT_BASE_URL},
    error::AirtableError,
    types::{
        BaseSchemaResponse, FieldSchema, ListWebhookPayloadsResponse, Record, SortSpec,
        TableSchema, ViewSchema,
    },
};

const SCHEMA_CACHE_TTL: Duration = Duration::from_secs(300);
const DEFAULT_LINKED_RECORD_DEPTH: u32 = 1;
const MAX_LINKED_RECORD_DEPTH: u32 = 3;
const DEFAULT_LINKED_RECORD_LIMIT: u32 = 25;
const MAX_LINKED_RECORD_LIMIT: u32 = 50;

/// Validated configuration for the Airtable connector.
struct AirtableConfig {
    auth: AirtableAuth,
    base_url: String,
}

impl AirtableConfig {
    /// Parse and validate configuration from FCP params.
    ///
    /// Strict auth: exactly one of `token` or `credential_id` must be supplied.
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let token = params
            .get("token")
            .and_then(|v| v.as_str())
            .map(String::from);
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

        let auth = match (token, credential_id) {
            (Some(t), None) => AirtableAuth::Token(t),
            (None, Some(cid)) => AirtableAuth::CredentialId(cid),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Supply exactly one of `token` or `credential_id`, not both".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing authentication: supply `token` or `credential_id`".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        Ok(Self { auth, base_url })
    }
}

/// Structured readiness diagnostic for the doctor command.
#[derive(Debug, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone)]
struct CachedSchema {
    fetched_at: Instant,
    schema: BaseSchemaResponse,
}

#[derive(Debug, Clone)]
struct LinkedExpansionConfig {
    field_names: Option<HashSet<String>>,
    max_depth: usize,
    max_records: usize,
}

impl LinkedExpansionConfig {
    fn expands_field(&self, field_name: &str) -> bool {
        self.field_names
            .as_ref()
            .is_none_or(|field_names| field_names.contains(field_name))
    }
}

#[derive(Debug)]
struct LinkedExpansionState {
    remaining_records: usize,
    path: HashSet<(String, String)>,
}

impl LinkedExpansionState {
    fn new(max_records: usize) -> Self {
        Self {
            remaining_records: max_records,
            path: HashSet::new(),
        }
    }
}

type BoxFcpFuture<'a, T> = Pin<Box<dyn Future<Output = FcpResult<T>> + 'a>>;

/// FCP Airtable Connector.
pub struct AirtableConnector {
    base: Arc<BaseConnector>,
    config: Option<AirtableConfig>,
    client: Option<AirtableClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    zone_id: Option<ZoneId>,
    schema_cache: Arc<fcp_async_core::sync::Mutex<HashMap<String, CachedSchema>>>,
}

impl AirtableConnector {
    /// Create a new Airtable connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("airtable"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            zone_id: None,
            schema_cache: Arc::new(fcp_async_core::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Handle configure method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the configuration is invalid or client creation fails.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = AirtableConfig::from_params(&params)?;

        let client = AirtableClient::new_with_auth(config.auth.clone())
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?
            .with_base_url(&config.base_url);

        info!(auth = %config.auth.redacted_label(), "Airtable connector configured");

        self.config = Some(config);
        self.client = Some(client);
        self.schema_cache.lock().await.clear();
        self.base.set_configured(true);

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
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
        self.zone_id = Some(req.zone.clone());

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
            manifest_hash: "sha256:airtable-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: true,
                min_buffer_events: 50,
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
    ///
    /// # Errors
    /// Returns [`FcpError`] if the health status cannot be determined.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        let mut health = json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        });
        if let Some(config) = &self.config {
            health["auth_mode"] = json!(config.auth.redacted_label());
            health["base_url"] = json!(config.base_url);
        }
        Ok(health)
    }

    /// Handle doctor readiness check.
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization fails.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // 1. Configuration
        checks.push(if self.config.is_some() {
            DoctorCheck {
                name: "configuration".into(),
                status: DoctorStatus::Healthy,
                message: "Connector is configured".into(),
            }
        } else {
            DoctorCheck {
                name: "configuration".into(),
                status: DoctorStatus::Unhealthy,
                message: "Connector is not configured – call `configure` first".into(),
            }
        });

        // 2. Client initialized
        checks.push(if self.client.is_some() {
            DoctorCheck {
                name: "client_initialized".into(),
                status: DoctorStatus::Healthy,
                message: "HTTP client is ready".into(),
            }
        } else {
            DoctorCheck {
                name: "client_initialized".into(),
                status: DoctorStatus::Unhealthy,
                message: "HTTP client is not initialized".into(),
            }
        });

        // 3. Base URL
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Healthy,
                message: format!("Base URL: {}", config.base_url),
            });
        } else {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Unhealthy,
                message: "Base URL not set (not configured)".into(),
            });
        }

        // 4. Auth mode
        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Healthy,
                message: format!("Auth: {}", config.auth.redacted_label()),
            });
        } else {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Unhealthy,
                message: "Auth mode not set (not configured)".into(),
            });
        }

        // 5. Network constraints
        let egress_target = self.config.as_ref().map_or("api.airtable.com", |c| {
            c.base_url
                .strip_prefix("https://")
                .or_else(|| c.base_url.strip_prefix("http://"))
                .and_then(|s| s.split('/').next())
                .unwrap_or("api.airtable.com")
        });
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            status: DoctorStatus::Healthy,
            message: format!("Egress target: {egress_target}"),
        });

        // 6. Credential injection
        if let Some(config) = &self.config {
            if config.auth.is_secretless() {
                checks.push(DoctorCheck {
                    name: "credential_injection".into(),
                    status: DoctorStatus::Healthy,
                    message: "Secretless mode – egress proxy will inject credentials".into(),
                });
            } else {
                checks.push(DoctorCheck {
                    name: "credential_injection".into(),
                    status: DoctorStatus::Healthy,
                    message: "Direct token mode – no proxy injection needed".into(),
                });
            }
        } else {
            checks.push(DoctorCheck {
                name: "credential_injection".into(),
                status: DoctorStatus::Unhealthy,
                message: "Cannot assess – not configured".into(),
            });
        }

        let overall = if checks.iter().any(|c| c.status == DoctorStatus::Unhealthy) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| c.status == DoctorStatus::Degraded) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };

        let result = DoctorResult {
            status: overall,
            checks,
        };

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    /// Handle self-check connectivity probe.
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization fails.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report =
                SelfCheckReport::failed("not_configured", "Connector is not configured yet");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        // In credential_id mode, we can't verify connectivity without the egress proxy
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

    /// Handle introspect method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization of the introspection data fails.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                op_info(
                    "airtable.list_bases",
                    "List all accessible Airtable bases",
                    json!({
                        "type": "object",
                        "properties": {
                            "offset": { "type": "string", "description": "Pagination cursor from previous response" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["bases"],
                        "properties": {
                            "bases": { "type": "array" },
                            "offset": { "type": "string" }
                        }
                    }),
                    "airtable.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Discover available Airtable bases the user has access to.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("airtable.get_base_schema")],
                    },
                ),
                op_info(
                    "airtable.get_base_schema",
                    "Get the schema of an Airtable base including all tables and fields",
                    json!({
                        "type": "object",
                        "required": ["base_id"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID (starts with 'app')" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["tables"],
                        "properties": {
                            "tables": { "type": "array", "description": "Tables with fields enriched by read_only/computed metadata for formula and other derived columns." }
                        }
                    }),
                    "airtable.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Discover table structure and field types before querying records.".into(),
                        common_mistakes: vec!["Using table name instead of base_id to get schema.".into()],
                        examples: vec![r#"{"base_id": "appXXXXXXXXXXXXXX"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("airtable.list_bases"),
                            CapabilityId::from_static("airtable.list_records"),
                        ],
                    },
                ),
                op_info(
                    "airtable.list_tables",
                    "List tables in an Airtable base using stable table IDs",
                    json!({
                        "type": "object",
                        "required": ["base_id"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID (starts with 'app')" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["tables"],
                        "properties": {
                            "tables": { "type": "array", "description": "Tables with id, name, and summary metadata" }
                        }
                    }),
                    "airtable.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Discover table IDs and names before record operations.".into(),
                        common_mistakes: vec!["Using guessed table names without discovery.".into()],
                        examples: vec![r#"{"base_id": "appXXXXXXXXXXXXXX"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("airtable.get_base_schema"),
                            CapabilityId::from_static("airtable.get_table"),
                        ],
                    },
                ),
                op_info(
                    "airtable.get_table",
                    "Get one table definition by stable table ID or exact table name",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_ref"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID (starts with 'app')" },
                            "table_ref": { "type": "string", "description": "Table ID (tbl...) or exact table name" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["table"],
                        "properties": {
                            "table": { "type": "object", "description": "Resolved table with fields enriched by read_only/computed metadata." }
                        }
                    }),
                    "airtable.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Fetch a specific table schema for downstream field-safe operations.".into(),
                        common_mistakes: vec!["Using non-exact table names that match multiple tables.".into()],
                        examples: vec![
                            r#"{"base_id": "appXXXXXXXXXXXXXX", "table_ref": "tblXXXXXXXXXXXXXX"}"#.into(),
                            r#"{"base_id": "appXXXXXXXXXXXXXX", "table_ref": "Tasks"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("airtable.list_tables"),
                            CapabilityId::from_static("airtable.list_fields"),
                        ],
                    },
                ),
                op_info(
                    "airtable.list_fields",
                    "List fields for a table with support for field ID or exact name references",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_ref"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID (starts with 'app')" },
                            "table_ref": { "type": "string", "description": "Table ID (tbl...) or exact table name" },
                            "field_refs": {
                                "type": "array",
                                "description": "Optional subset of field IDs/names to resolve with ambiguity checks",
                                "items": { "type": "string" }
                            }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["fields"],
                        "properties": {
                            "fields": { "type": "array", "description": "Resolved field definitions with explicit read_only/computed metadata and linked-table summaries where relevant." }
                        }
                    }),
                    "airtable.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Resolve stable field IDs before CRUD to stay robust to field renames.".into(),
                        common_mistakes: vec![
                            "Using only field names and ignoring stable field IDs.".into(),
                            "Passing ambiguous duplicate field names.".into(),
                        ],
                        examples: vec![
                            r#"{"base_id": "appXXXXXXXXXXXXXX", "table_ref": "Tasks"}"#.into(),
                            r#"{"base_id": "appXXXXXXXXXXXXXX", "table_ref": "tblXXXXXXXXXXXXXX", "field_refs": ["fldABC", "Status"]}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("airtable.get_table"),
                            CapabilityId::from_static("airtable.get_base_schema"),
                        ],
                    },
                ),
                op_info(
                    "airtable.list_views",
                    "List saved views for a table using stable view IDs",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_ref"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID (starts with 'app')" },
                            "table_ref": { "type": "string", "description": "Table ID (tbl...) or exact table name" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["table", "views"],
                        "properties": {
                            "table": { "type": "object", "description": "Resolved table summary" },
                            "views": { "type": "array", "description": "Resolved views with stable IDs" }
                        }
                    }),
                    "airtable.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Discover stable Airtable view IDs before querying through a curated view.".into(),
                        common_mistakes: vec![
                            "Guessing a view name without verifying it exists.".into(),
                            "Using ambiguous duplicate view names instead of stable view IDs.".into(),
                        ],
                        examples: vec![
                            r#"{"base_id": "appXXXXXXXXXXXXXX", "table_ref": "Tasks"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("airtable.get_view"),
                            CapabilityId::from_static("airtable.list_view_records"),
                        ],
                    },
                ),
                op_info(
                    "airtable.get_view",
                    "Resolve one Airtable view by stable ID or exact view name",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_ref", "view_ref"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID (starts with 'app')" },
                            "table_ref": { "type": "string", "description": "Table ID (tbl...) or exact table name" },
                            "view_ref": { "type": "string", "description": "View ID (viw...) or exact view name" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["table", "view"],
                        "properties": {
                            "table": { "type": "object", "description": "Resolved table summary" },
                            "view": { "type": "object", "description": "Resolved view definition" }
                        }
                    }),
                    "airtable.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Resolve one view before paginating records through it.".into(),
                        common_mistakes: vec![
                            "Using a fuzzy or partial view name.".into(),
                            "Ignoring ambiguity when multiple views share the same name.".into(),
                        ],
                        examples: vec![
                            r#"{"base_id": "appXXXXXXXXXXXXXX", "table_ref": "Tasks", "view_ref": "viwXXXXXXXXXXXXXX"}"#.into(),
                            r#"{"base_id": "appXXXXXXXXXXXXXX", "table_ref": "Tasks", "view_ref": "Open Tasks"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("airtable.list_views"),
                            CapabilityId::from_static("airtable.list_view_records"),
                        ],
                    },
                ),
                op_info(
                    "airtable.list_view_records",
                    "List records through a saved Airtable view without broadening beyond the chosen query preset",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_ref", "view_ref", "fields"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID" },
                            "table_ref": { "type": "string", "description": "Table ID (tbl...) or exact table name" },
                            "view_ref": { "type": "string", "description": "View ID (viw...) or exact view name" },
                            "fields": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Explicit field IDs or exact field names to project so the connector does not broaden beyond the intended result shape"
                            },
                            "filter_by_formula": { "type": "string", "description": "Optional additional Airtable formula that only narrows the chosen view" },
                            "max_records": { "type": "integer", "description": "Maximum records to return (1-100)" },
                            "page_size": { "type": "integer", "description": "Records per page (1-100)" },
                            "offset": { "type": "string", "description": "Pagination cursor from a previous response" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["table", "view", "records"],
                        "properties": {
                            "table": { "type": "object" },
                            "view": { "type": "object" },
                            "records": { "type": "array" },
                            "field_metadata": { "type": "object", "description": "Per-field type metadata including read_only/computed markers and linked-table summaries." },
                            "offset": { "type": "string" }
                        }
                    }),
                    "airtable.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Paginate records through a human-curated Airtable view while keeping the view's filter and sort semantics intact.".into(),
                        common_mistakes: vec![
                            "Omitting the fields list and accidentally broadening the returned payload.".into(),
                            "Passing custom sort values instead of relying on the view's saved ordering.".into(),
                            "Using invalid Airtable formulas or field IDs in filter_by_formula.".into(),
                        ],
                        examples: vec![
                            r#"{"base_id": "appXXX", "table_ref": "Tasks", "view_ref": "Open Tasks", "fields": ["fldABC", "Status"], "page_size": 25}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("airtable.list_views"),
                            CapabilityId::from_static("airtable.list_records"),
                        ],
                    },
                ),
                op_info(
                    "airtable.list_records",
                    "List records from an Airtable table with validated filtering, sorting, optional view selection, and bounded linked-record expansion",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_id"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID" },
                            "table_id": { "type": "string", "description": "Table ID (tbl...) or exact table name" },
                            "fields": { "type": "array", "items": { "type": "string" }, "description": "Optional field IDs or exact field names to project" },
                            "filter_by_formula": { "type": "string", "description": "Airtable formula to filter records (field names only; control characters rejected)" },
                            "max_records": { "type": "integer", "description": "Maximum records to return (1-100)" },
                            "page_size": { "type": "integer", "description": "Records per page (1-100)" },
                            "sort": { "type": "array", "items": { "type": "object" }, "description": "Optional sort fields (field IDs or exact names). If combined with view, sort overrides the view ordering." },
                            "view": { "type": "string", "description": "Optional view ID (viw...) or exact view name used as a query preset" },
                            "offset": { "type": "string", "description": "Pagination cursor" },
                            "expand_linked_records": { "type": "boolean", "description": "If true, resolve linked-record fields into bounded nested record objects." },
                            "linked_field_refs": { "type": "array", "items": { "type": "string" }, "description": "Optional subset of linked-record field IDs or exact names to expand." },
                            "linked_record_depth": { "type": "integer", "description": "Maximum linked-record traversal depth (1-3)." },
                            "linked_record_limit": { "type": "integer", "description": "Maximum linked records to resolve across the response (1-50)." }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["records"],
                        "properties": {
                            "records": { "type": "array" },
                            "field_metadata": { "type": "object", "description": "Per-field type metadata including read_only/computed markers and linked-table summaries." },
                            "offset": { "type": "string" }
                        }
                    }),
                    "airtable.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Query Airtable records with validated filters and optionally expand linked-record chains without unbounded joins.".into(),
                        common_mistakes: vec![
                            "Using SQL syntax instead of Airtable formula syntax.".into(),
                            "Using field IDs directly inside filter_by_formula instead of Airtable field names.".into(),
                            "Not handling pagination for large datasets.".into(),
                            "Requesting linked_field_refs that are excluded from the projected fields list.".into(),
                        ],
                        examples: vec![
                            r#"{"base_id": "appXXX", "table_id": "Tasks", "filter_by_formula": "{Status} = \"Active\""}"#.into(),
                            r#"{"base_id": "appXXX", "table_id": "Tasks", "sort": [{"field": "Priority", "direction": "desc"}], "page_size": 50}"#.into(),
                            r#"{"base_id": "appXXX", "table_id": "Tasks", "expand_linked_records": true, "linked_field_refs": ["Parent Task"], "linked_record_depth": 2}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("airtable.list_view_records"),
                            CapabilityId::from_static("airtable.get_record"),
                            CapabilityId::from_static("airtable.get_base_schema"),
                        ],
                    },
                ),
                op_info(
                    "airtable.get_record",
                    "Get a single record by ID from an Airtable table with optional linked-record expansion",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_id", "record_id"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID" },
                            "table_id": { "type": "string", "description": "Table name or ID" },
                            "record_id": { "type": "string", "description": "Record ID (starts with 'rec')" },
                            "expand_linked_records": { "type": "boolean", "description": "If true, resolve linked-record fields into bounded nested record objects." },
                            "linked_field_refs": { "type": "array", "items": { "type": "string" }, "description": "Optional subset of linked-record field IDs or exact names to expand." },
                            "linked_record_depth": { "type": "integer", "description": "Maximum linked-record traversal depth (1-3)." },
                            "linked_record_limit": { "type": "integer", "description": "Maximum linked records to resolve across the response (1-50)." }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["id", "fields"],
                        "properties": {
                            "id": { "type": "string" },
                            "fields": { "type": "object" },
                            "createdTime": { "type": "string" },
                            "field_metadata": { "type": "object", "description": "Per-field type metadata including read_only/computed markers and linked-table summaries." },
                            "linked_records": { "type": "object", "description": "Expanded linked-record chains grouped by linked field name." }
                        }
                    }),
                    "airtable.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve one Airtable record when you know its ID and optionally need a bounded expansion of linked records.".into(),
                        common_mistakes: vec![
                            "Using row number instead of record ID.".into(),
                            "Forgetting to cap linked_record_depth for cyclic relationship graphs.".into(),
                        ],
                        examples: vec![
                            r#"{"base_id": "appXXX", "table_id": "Tasks", "record_id": "recYYY"}"#.into(),
                            r#"{"base_id": "appXXX", "table_id": "Tasks", "record_id": "recYYY", "expand_linked_records": true, "linked_record_limit": 10}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("airtable.list_records"),
                            CapabilityId::from_static("airtable.update_record"),
                        ],
                    },
                ),
                op_info(
                    "airtable.create_record",
                    "Create a new record in an Airtable table",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_id", "fields"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID" },
                            "table_id": { "type": "string", "description": "Table name or ID" },
                            "fields": { "type": "object", "description": "Field values for the new record" },
                            "typecast": { "type": "boolean", "description": "If true, try to convert string values to appropriate types" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["id", "fields"],
                        "properties": {
                            "id": { "type": "string" },
                            "fields": { "type": "object" },
                            "createdTime": { "type": "string" }
                        }
                    }),
                    "airtable.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Add a new record to an Airtable table.".into(),
                        common_mistakes: vec![
                            "Using field IDs instead of field names.".into(),
                            "Not matching field types.".into(),
                        ],
                        examples: vec![r#"{"base_id": "appXXX", "table_id": "Tasks", "fields": {"Name": "New Task", "Status": "Todo"}}"#.into()],
                        related: vec![
                            CapabilityId::from_static("airtable.get_base_schema"),
                            CapabilityId::from_static("airtable.update_record"),
                        ],
                    },
                ),
                op_info(
                    "airtable.create_records",
                    "Create multiple records in an Airtable table (batch, max 10)",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_id", "records"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID" },
                            "table_id": { "type": "string", "description": "Table name or ID" },
                            "records": { "type": "array", "description": "Array of records to create (max 10)", "maxItems": 10 },
                            "typecast": { "type": "boolean", "description": "If true, try to convert string values" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["records"],
                        "properties": {
                            "records": { "type": "array" }
                        }
                    }),
                    "airtable.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create multiple records efficiently. Limited to 10 records per call.".into(),
                        common_mistakes: vec!["Exceeding 10 record limit per batch.".into()],
                        examples: vec![r#"{"base_id": "appXXX", "table_id": "Tasks", "records": [{"fields": {"Name": "Task 1"}}, {"fields": {"Name": "Task 2"}}]}"#.into()],
                        related: vec![CapabilityId::from_static("airtable.create_record")],
                    },
                ),
                op_info(
                    "airtable.update_records",
                    "Update multiple Airtable records in one batch PATCH request (max 10)",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_id", "records"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID" },
                            "table_id": { "type": "string", "description": "Table name or ID" },
                            "records": { "type": "array", "description": "Array of record patches with id + fields (max 10)", "maxItems": 10 },
                            "typecast": { "type": "boolean", "description": "If true, try to convert string values" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["records"],
                        "properties": {
                            "records": { "type": "array" }
                        }
                    }),
                    "airtable.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Patch multiple existing Airtable records efficiently while keeping record identities stable.".into(),
                        common_mistakes: vec![
                            "Omitting the record id for one of the batch items.".into(),
                            "Sending more than 10 records in a single request.".into(),
                        ],
                        examples: vec![r#"{"base_id": "appXXX", "table_id": "Tasks", "records": [{"id": "recA", "fields": {"Status": "Done"}}]}"#.into()],
                        related: vec![
                            CapabilityId::from_static("airtable.update_record"),
                            CapabilityId::from_static("airtable.upsert_records"),
                        ],
                    },
                ),
                op_info(
                    "airtable.upsert_records",
                    "Upsert multiple Airtable records using merge fields for retry-safe workflows",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_id", "records", "fields_to_merge_on"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID" },
                            "table_id": { "type": "string", "description": "Table name or ID" },
                            "records": { "type": "array", "description": "Array of records with fields payloads (max 10)", "maxItems": 10 },
                            "fields_to_merge_on": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Field IDs or exact field names used to match existing Airtable records"
                            },
                            "typecast": { "type": "boolean", "description": "If true, try to convert string values" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["records", "createdRecords", "updatedRecords"],
                        "properties": {
                            "records": { "type": "array" },
                            "createdRecords": { "type": "array" },
                            "updatedRecords": { "type": "array" }
                        }
                    }),
                    "airtable.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Create-or-update Airtable records when retries must stay deterministic.".into(),
                        common_mistakes: vec![
                            "Using merge fields that do not exist in the table schema.".into(),
                            "Assuming upsert is safe without stable merge keys.".into(),
                        ],
                        examples: vec![r#"{"base_id": "appXXX", "table_id": "Tasks", "fields_to_merge_on": ["External ID"], "records": [{"fields": {"External ID": "ext-1", "Name": "Alpha"}}]}"#.into()],
                        related: vec![
                            CapabilityId::from_static("airtable.create_records"),
                            CapabilityId::from_static("airtable.update_records"),
                        ],
                    },
                ),
                op_info(
                    "airtable.update_record",
                    "Update an existing record in an Airtable table (PATCH)",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_id", "record_id", "fields"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID" },
                            "table_id": { "type": "string", "description": "Table name or ID" },
                            "record_id": { "type": "string", "description": "Record ID to update" },
                            "fields": { "type": "object", "description": "Field values to update (partial)" },
                            "typecast": { "type": "boolean", "description": "If true, try to convert string values" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["id", "fields"],
                        "properties": {
                            "id": { "type": "string" },
                            "fields": { "type": "object" }
                        }
                    }),
                    "airtable.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Modify specific fields of an existing record. Only specified fields are updated.".into(),
                        common_mistakes: vec![
                            "Trying to update the record ID field.".into(),
                            "Not quoting linked record IDs correctly.".into(),
                        ],
                        examples: vec![r#"{"base_id": "appXXX", "table_id": "Tasks", "record_id": "recYYY", "fields": {"Status": "Done"}}"#.into()],
                        related: vec![
                            CapabilityId::from_static("airtable.get_record"),
                            CapabilityId::from_static("airtable.replace_record"),
                        ],
                    },
                ),
                op_info(
                    "airtable.replace_record",
                    "Replace all fields of a record (PUT - destructive update)",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_id", "record_id", "fields"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID" },
                            "table_id": { "type": "string", "description": "Table name or ID" },
                            "record_id": { "type": "string", "description": "Record ID to replace" },
                            "fields": { "type": "object", "description": "Complete field values (replaces all existing)" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["id", "fields"],
                        "properties": {
                            "id": { "type": "string" },
                            "fields": { "type": "object" }
                        }
                    }),
                    "airtable.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Replace all fields of a record. Fields not included will be cleared. Prefer update_record for partial updates.".into(),
                        common_mistakes: vec![
                            "Using replace when update_record would suffice.".into(),
                            "Accidentally clearing fields by not including them.".into(),
                        ],
                        examples: vec![],
                        related: vec![CapabilityId::from_static("airtable.update_record")],
                    },
                ),
                op_info(
                    "airtable.delete_record",
                    "Delete a record from an Airtable table (irreversible)",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_id", "record_id"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID" },
                            "table_id": { "type": "string", "description": "Table name or ID" },
                            "record_id": { "type": "string", "description": "Record ID to delete" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["id", "deleted"],
                        "properties": {
                            "id": { "type": "string" },
                            "deleted": { "type": "boolean" }
                        }
                    }),
                    "airtable.delete",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Permanently delete a record. This cannot be undone.".into(),
                        common_mistakes: vec![
                            "Deleting without confirmation.".into(),
                            "Deleting records linked from other tables.".into(),
                        ],
                        examples: vec![r#"{"base_id": "appXXX", "table_id": "Tasks", "record_id": "recYYY"}"#.into()],
                        related: vec![CapabilityId::from_static("airtable.get_record")],
                    },
                ),
                op_info(
                    "airtable.delete_records",
                    "Delete multiple Airtable records in one request (irreversible, max 10)",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_id", "record_ids"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID" },
                            "table_id": { "type": "string", "description": "Table name or ID" },
                            "record_ids": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Record IDs to delete (max 10)"
                            }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["records"],
                        "properties": {
                            "records": { "type": "array" }
                        }
                    }),
                    "airtable.delete",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Remove a bounded set of Airtable records after explicit confirmation.".into(),
                        common_mistakes: vec![
                            "Sending more than 10 record IDs in one destructive batch.".into(),
                            "Deleting records that are still referenced by linked-record fields.".into(),
                        ],
                        examples: vec![r#"{"base_id": "appXXX", "table_id": "Tasks", "record_ids": ["recA", "recB"]}"#.into()],
                        related: vec![
                            CapabilityId::from_static("airtable.delete_record"),
                            CapabilityId::from_static("airtable.get_record"),
                        ],
                    },
                ),
                op_info(
                    "airtable.list_webhooks",
                    "List webhook registrations for an Airtable base",
                    json!({
                        "type": "object",
                        "required": ["base_id"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID (starts with 'app')" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["webhooks"],
                        "properties": {
                            "webhooks": { "type": "array", "description": "Webhook registrations with notification status, expiry, and cursor metadata." }
                        }
                    }),
                    "airtable.webhooks.manage",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Inspect existing Airtable webhook registrations and their next payload cursor.".into(),
                        common_mistakes: vec![
                            "Assuming the webhook metadata includes the MAC secret; Airtable only returns that at creation time.".into(),
                        ],
                        examples: vec![r#"{"base_id": "appXXXXXXXXXXXXXX"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("airtable.create_webhook"),
                            CapabilityId::from_static("airtable.list_webhook_payloads"),
                        ],
                    },
                ),
                op_info(
                    "airtable.create_webhook",
                    "Create a managed Airtable webhook for a base",
                    json!({
                        "type": "object",
                        "required": ["base_id", "notification_url", "specification"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID (starts with 'app')" },
                            "notification_url": { "type": "string", "description": "HTTPS endpoint owned by the host/webhook receiver for notification pings" },
                            "specification": {
                                "type": "object",
                                "description": "Airtable webhook specification object containing an options.filters tree"
                            }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["id", "macSecretBase64"],
                        "properties": {
                            "id": { "type": "string" },
                            "macSecretBase64": { "type": "string" },
                            "expirationTime": { "type": ["string", "null"] }
                        }
                    }),
                    "airtable.webhooks.manage",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Register Airtable change notifications so the host can ingest real-time updates.".into(),
                        common_mistakes: vec![
                            "Passing a notification_url that is not HTTPS.".into(),
                            "Forgetting that the MAC secret is only returned once at creation time.".into(),
                            "Using table or field names inside the specification instead of stable Airtable IDs.".into(),
                        ],
                        examples: vec![r#"{"base_id": "appXXXXXXXXXXXXXX", "notification_url": "https://hooks.flywheel.dev/airtable", "specification": {"options": {"filters": {"dataTypes": ["tableData"], "recordChangeScope": "tblXXXXXXXXXXXXXX"}}}}"#.into()],
                        related: vec![
                            CapabilityId::from_static("airtable.list_webhooks"),
                            CapabilityId::from_static("airtable.refresh_webhook"),
                            CapabilityId::from_static("airtable.delete_webhook"),
                        ],
                    },
                ),
                op_info(
                    "airtable.refresh_webhook",
                    "Extend the lifetime of an active Airtable webhook by another 7 days",
                    json!({
                        "type": "object",
                        "required": ["base_id", "webhook_id"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID (starts with 'app')" },
                            "webhook_id": { "type": "string", "description": "Webhook ID (starts with 'ach')" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["expirationTime"],
                        "properties": {
                            "expirationTime": { "type": ["string", "null"] }
                        }
                    }),
                    "airtable.webhooks.manage",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Keep an existing webhook alive before Airtable disables it at expiry.".into(),
                        common_mistakes: vec![
                            "Refreshing after the webhook has already expired instead of re-creating it.".into(),
                        ],
                        examples: vec![r#"{"base_id": "appXXXXXXXXXXXXXX", "webhook_id": "achXXXXXXXXXXXXXX"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("airtable.create_webhook"),
                            CapabilityId::from_static("airtable.list_webhooks"),
                        ],
                    },
                ),
                op_info(
                    "airtable.set_webhook_notifications",
                    "Enable or disable Airtable notification pings for a webhook",
                    json!({
                        "type": "object",
                        "required": ["base_id", "webhook_id", "enable"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID (starts with 'app')" },
                            "webhook_id": { "type": "string", "description": "Webhook ID (starts with 'ach')" },
                            "enable": { "type": "boolean", "description": "Whether Airtable should send notification pings" }
                        }
                    }),
                    json!({
                        "type": "object"
                    }),
                    "airtable.webhooks.manage",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Pause or resume notification pings without deleting the webhook registration.".into(),
                        common_mistakes: vec![
                            "Disabling notifications and assuming Airtable will keep retrying missed deliveries.".into(),
                        ],
                        examples: vec![r#"{"base_id": "appXXXXXXXXXXXXXX", "webhook_id": "achXXXXXXXXXXXXXX", "enable": false}"#.into()],
                        related: vec![
                            CapabilityId::from_static("airtable.list_webhooks"),
                            CapabilityId::from_static("airtable.delete_webhook"),
                        ],
                    },
                ),
                op_info(
                    "airtable.delete_webhook",
                    "Delete an Airtable webhook registration",
                    json!({
                        "type": "object",
                        "required": ["base_id", "webhook_id"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID (starts with 'app')" },
                            "webhook_id": { "type": "string", "description": "Webhook ID (starts with 'ach')" }
                        }
                    }),
                    json!({
                        "type": "object"
                    }),
                    "airtable.webhooks.manage",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Remove a webhook when the integration no longer needs change notifications.".into(),
                        common_mistakes: vec![
                            "Deleting the webhook before capturing any final cursor state you still need.".into(),
                        ],
                        examples: vec![r#"{"base_id": "appXXXXXXXXXXXXXX", "webhook_id": "achXXXXXXXXXXXXXX"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("airtable.list_webhooks"),
                            CapabilityId::from_static("airtable.create_webhook"),
                        ],
                    },
                ),
                op_info(
                    "airtable.list_webhook_payloads",
                    "Fetch Airtable webhook payload history and normalize it into event envelopes",
                    json!({
                        "type": "object",
                        "required": ["base_id", "webhook_id"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID (starts with 'app')" },
                            "webhook_id": { "type": "string", "description": "Webhook ID (starts with 'ach')" },
                            "cursor": { "type": "integer", "description": "Payload cursor to continue from; omit for the first read" },
                            "limit": { "type": "integer", "description": "Maximum payloads to return (1-50)" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["payloads", "mightHaveMore", "events"],
                        "properties": {
                            "payloads": { "type": "array" },
                            "cursor": { "type": "integer" },
                            "mightHaveMore": { "type": "boolean" },
                            "events": { "type": "array", "description": "Normalized EventEnvelope objects derived from the Airtable payload batch." }
                        }
                    }),
                    "airtable.webhooks.manage",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Drain webhook payload history after Airtable notifies the host that new changes are available.".into(),
                        common_mistakes: vec![
                            "Failing to persist the returned cursor before the next poll.".into(),
                            "Ignoring mightHaveMore when Airtable splits a single transaction across multiple payload batches.".into(),
                        ],
                        examples: vec![
                            r#"{"base_id": "appXXXXXXXXXXXXXX", "webhook_id": "achXXXXXXXXXXXXXX"}"#.into(),
                            r#"{"base_id": "appXXXXXXXXXXXXXX", "webhook_id": "achXXXXXXXXXXXXXX", "cursor": 41, "limit": 10}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("airtable.list_webhooks"),
                            CapabilityId::from_static("airtable.refresh_webhook"),
                        ],
                    },
                ),
                op_info(
                    "airtable.download_attachment",
                    "Download an attachment file from an Airtable record",
                    json!({
                        "type": "object",
                        "required": ["url"],
                        "properties": {
                            "url": { "type": "string", "description": "Attachment URL from a record's attachment field" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["data", "content_type"],
                        "properties": {
                            "data": { "type": "string", "description": "Base64-encoded file data" },
                            "content_type": { "type": "string", "description": "MIME type" },
                            "filename": { "type": "string", "description": "Original filename" }
                        }
                    }),
                    "airtable.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Download attachment files (images, documents) from Airtable records.".into(),
                        common_mistakes: vec![
                            "Using the thumbnail URL instead of the full URL.".into(),
                            "Not handling large files appropriately.".into(),
                        ],
                        examples: vec![r#"{"url": "https://dl.airtable.com/.attachments/..."}"#.into()],
                        related: vec![CapabilityId::from_static("airtable.get_record")],
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
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
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
    ///
    /// # Errors
    /// Returns [`FcpError`] if the operation fails or capability verification fails.
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
        let intro = self.handle_introspect().await?;
        let cap_str = intro.get("operations")
            .and_then(|ops| ops.as_array())
            .and_then(|ops| ops.iter().find(|o| o.get("id").and_then(|id| id.as_str()) == Some(operation)))
            .and_then(|op| op.get("capability"))
            .and_then(|cap| cap.as_str())
            .ok_or_else(|| FcpError::OperationNotGranted {
                operation: operation.into(),
            })?;

        let cap_id: CapabilityId = cap_str.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "airtable.list_bases" => self.invoke_list_bases(input).await,
            "airtable.get_base_schema" => self.invoke_get_base_schema(input).await,
            "airtable.list_tables" => self.invoke_list_tables(input).await,
            "airtable.get_table" => self.invoke_get_table(input).await,
            "airtable.list_fields" => self.invoke_list_fields(input).await,
            "airtable.list_views" => self.invoke_list_views(input).await,
            "airtable.get_view" => self.invoke_get_view(input).await,
            "airtable.list_view_records" => self.invoke_list_view_records(input).await,
            "airtable.list_records" => self.invoke_list_records(input).await,
            "airtable.get_record" => self.invoke_get_record(input).await,
            "airtable.create_record" => self.invoke_create_record(input).await,
            "airtable.create_records" => self.invoke_create_records(input).await,
            "airtable.update_records" => self.invoke_update_records(input).await,
            "airtable.upsert_records" => self.invoke_upsert_records(input).await,
            "airtable.update_record" => self.invoke_update_record(input).await,
            "airtable.replace_record" => self.invoke_replace_record(input).await,
            "airtable.delete_record" => self.invoke_delete_record(input).await,
            "airtable.delete_records" => self.invoke_delete_records(input).await,
            "airtable.create_webhook" => self.invoke_create_webhook(input).await,
            "airtable.list_webhooks" => self.invoke_list_webhooks(input).await,
            "airtable.delete_webhook" => self.invoke_delete_webhook(input).await,
            "airtable.list_webhook_payloads" => self.invoke_list_webhook_payloads(input).await,
            "airtable.refresh_webhook" => self.invoke_refresh_webhook(input).await,
            "airtable.set_webhook_notifications" => {
                self.invoke_set_webhook_notifications(input).await
            }
            "airtable.download_attachment" => self.invoke_download_attachment(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_list_bases(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let offset = input.get("offset").and_then(|v| v.as_str());

        let result = client
            .list_bases(offset)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        let mut resp = json!({ "bases": result.bases });
        if let Some(offset) = result.offset {
            resp["offset"] = json!(offset);
        }
        Ok(resp)
    }

    async fn invoke_get_base_schema(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let base_id = require_base_id(&input)?;
        let result = self.get_base_schema_cached(base_id).await?;

        let tables = result
            .tables
            .iter()
            .map(|table| serialize_table_schema(table, &result))
            .collect::<Vec<_>>();
        Ok(json!({ "tables": tables }))
    }

    async fn invoke_list_tables(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let base_id = require_base_id(&input)?;
        let schema = self.get_base_schema_cached(base_id).await?;

        let tables: Vec<serde_json::Value> = schema
            .tables
            .iter()
            .map(|table| {
                json!({
                    "id": table.id,
                    "name": table.name,
                    "description": table.description,
                    "primaryFieldId": table.primary_field_id,
                    "fieldCount": table.fields.len(),
                    "viewCount": table.views.len(),
                })
            })
            .collect();

        Ok(json!({ "tables": tables }))
    }

    async fn invoke_get_table(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let base_id = require_base_id(&input)?;
        let table_ref = require_nonempty_str(&input, "table_ref")?;
        let schema = self.get_base_schema_cached(base_id).await?;
        let table = resolve_table(&schema.tables, table_ref)?;

        Ok(json!({ "table": serialize_table_schema(table, &schema) }))
    }

    async fn invoke_list_fields(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let base_id = require_base_id(&input)?;
        let table_ref = require_nonempty_str(&input, "table_ref")?;
        let schema = self.get_base_schema_cached(base_id).await?;
        let table = resolve_table(&schema.tables, table_ref)?;

        let fields = if let Some(field_refs) = input.get("field_refs") {
            let refs = field_refs.as_array().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "field_refs must be an array of strings".into(),
            })?;
            resolve_fields(table, refs)?
        } else {
            table.fields.clone()
        };

        let fields = fields
            .iter()
            .map(|field| serialize_field_schema(field, &schema))
            .collect::<Vec<_>>();
        Ok(json!({ "fields": fields }))
    }

    async fn invoke_list_views(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let base_id = require_base_id(&input)?;
        let table_ref = require_nonempty_str(&input, "table_ref")?;
        let schema = self.get_base_schema_cached(base_id).await?;
        let table = resolve_table(&schema.tables, table_ref)?;

        Ok(json!({
            "table": {
                "id": table.id,
                "name": table.name,
            },
            "views": table.views,
        }))
    }

    async fn invoke_get_view(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let base_id = require_base_id(&input)?;
        let table_ref = require_nonempty_str(&input, "table_ref")?;
        let view_ref = require_nonempty_str(&input, "view_ref")?;
        let schema = self.get_base_schema_cached(base_id).await?;
        let table = resolve_table(&schema.tables, table_ref)?;
        let view = resolve_view(&table.views, view_ref)?;

        Ok(json!({
            "table": {
                "id": table.id,
                "name": table.name,
            },
            "view": view,
        }))
    }

    async fn invoke_list_view_records(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_base_id(&input)?;
        let table_ref = require_nonempty_str(&input, "table_ref")?;
        let view_ref = require_nonempty_str(&input, "view_ref")?;
        let schema = self.get_base_schema_cached(base_id).await?;
        let table = resolve_table(&schema.tables, table_ref)?;
        let view = resolve_view(&table.views, view_ref)?;

        let fields =
            resolve_requested_fields(&input, table, true)?.ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "fields must include at least one field ID or exact field name".into(),
            })?;
        let filter_by_formula = parse_filter_by_formula(&input)?;
        let max_records = parse_record_bound(&input, "max_records")?;
        let page_size = parse_record_bound(&input, "page_size")?;
        let offset = optional_nonempty_string(&input, "offset")?;

        let result = client
            .list_records(
                base_id,
                &table.id,
                Some(fields.as_slice()),
                filter_by_formula.as_deref(),
                max_records,
                page_size,
                None,
                Some(&view.id),
                offset.as_deref(),
            )
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        let mut resp = json!({
            "table": {
                "id": table.id,
                "name": table.name,
            },
            "view": view,
            "records": result.records,
            "field_metadata": build_field_metadata(
                table,
                &schema,
                &fields.iter().cloned().collect(),
            ),
        });
        if let Some(offset) = result.offset {
            resp["offset"] = json!(offset);
        }
        Ok(resp)
    }

    async fn invoke_list_records(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_base_id(&input)?;
        let table_ref = require_nonempty_str(&input, "table_id")?;
        let schema = self.get_base_schema_cached(base_id).await?;
        let table = resolve_table(&schema.tables, table_ref)?;

        let fields = resolve_requested_fields(&input, table, false)?;
        let linked_expansion = parse_linked_expansion_config(&input, table)?;
        validate_linked_projection(fields.as_deref(), linked_expansion.as_ref())?;
        let filter_by_formula = parse_filter_by_formula(&input)?;
        let max_records = parse_record_bound(&input, "max_records")?;
        let page_size = parse_record_bound(&input, "page_size")?;
        let sort = parse_sort_specs(&input, table)?;
        let view = optional_nonempty_string(&input, "view")?
            .map(|view_ref| resolve_view(&table.views, &view_ref).map(|view| view.id.clone()))
            .transpose()?;
        let offset = optional_nonempty_string(&input, "offset")?;

        let result = client
            .list_records(
                base_id,
                &table.id,
                fields.as_deref(),
                filter_by_formula.as_deref(),
                max_records,
                page_size,
                sort.as_deref(),
                view.as_deref(),
                offset.as_deref(),
            )
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        let mut expansion_state = linked_expansion
            .as_ref()
            .map(|config| LinkedExpansionState::new(config.max_records));
        let records = self
            .serialize_record_list(
                base_id,
                &schema,
                table,
                result.records,
                linked_expansion.as_ref(),
                expansion_state.as_mut(),
            )
            .await?;
        let visible_fields = collect_visible_fields_for_list(table, fields.as_deref(), &records);
        let mut resp = json!({
            "records": records,
            "field_metadata": build_field_metadata(table, &schema, &visible_fields),
        });
        if let Some(offset) = result.offset {
            resp["offset"] = json!(offset);
        }
        Ok(resp)
    }

    async fn invoke_get_record(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let (base_id, table_id) = self.require_table_id(&input).await?;
        let record_id = require_nonempty_str(&input, "record_id")?;

        let record = client
            .get_record(&base_id, &table_id, record_id)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        let schema = self.get_base_schema_cached(&base_id).await?;
        let table = resolve_table(&schema.tables, &table_id)?;
        let linked_expansion = parse_linked_expansion_config(&input, table)?;
        let mut expansion_state = linked_expansion
            .as_ref()
            .map(|config| LinkedExpansionState::new(config.max_records));
        self.serialize_record_with_links(
            &base_id,
            &schema,
            table,
            record,
            linked_expansion.as_ref(),
            expansion_state.as_mut(),
            linked_expansion
                .as_ref()
                .map_or(0, |config| config.max_depth),
            true,
        )
        .await
    }

    async fn invoke_create_record(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let (base_id, table_id) = self.require_table_id(&input).await?;
        let fields = require_fields_object(&input)?;
        let typecast = input.get("typecast").and_then(|v| v.as_bool());

        let record = client
            .create_record(&base_id, &table_id, fields, typecast)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        serde_json::to_value(record).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize record: {e}"),
        })
    }

    async fn invoke_create_records(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let (base_id, table_id) = self.require_table_id(&input).await?;
        let records = parse_record_payloads(&input, false)?;
        let typecast = input.get("typecast").and_then(|v| v.as_bool());

        let result = client
            .create_records(&base_id, &table_id, &records, typecast)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        Ok(json!({ "records": result.records }))
    }

    async fn invoke_update_records(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_base_id(&input)?;
        let table_ref = require_nonempty_str(&input, "table_id")?;
        let schema = self.get_base_schema_cached(base_id).await?;
        let table = resolve_table(&schema.tables, table_ref)?;
        let records = parse_record_payloads(&input, true)?;
        let typecast = input.get("typecast").and_then(|v| v.as_bool());

        let result = client
            .update_records(base_id, &table.id, &records, typecast)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        Ok(json!({ "records": result.records }))
    }

    async fn invoke_upsert_records(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_base_id(&input)?;
        let table_ref = require_nonempty_str(&input, "table_id")?;
        let schema = self.get_base_schema_cached(base_id).await?;
        let table = resolve_table(&schema.tables, table_ref)?;
        let records = parse_record_payloads(&input, false)?;
        let fields_to_merge_on = parse_fields_to_merge_on(&input, table)?;
        let typecast = input.get("typecast").and_then(|v| v.as_bool());

        let result = client
            .upsert_records(
                base_id,
                &table.id,
                &records,
                fields_to_merge_on.as_slice(),
                typecast,
            )
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize result: {e}"),
        })
    }

    async fn invoke_update_record(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let (base_id, table_id) = self.require_table_id(&input).await?;
        let record_id = require_nonempty_str(&input, "record_id")?;
        let fields = require_fields_object(&input)?;
        let typecast = input.get("typecast").and_then(|v| v.as_bool());

        let record = client
            .update_record(&base_id, &table_id, record_id, fields, typecast)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        serde_json::to_value(record).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize record: {e}"),
        })
    }

    async fn invoke_replace_record(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let (base_id, table_id) = self.require_table_id(&input).await?;
        let record_id = require_nonempty_str(&input, "record_id")?;
        let fields = require_fields_object(&input)?;

        let record = client
            .replace_record(&base_id, &table_id, record_id, fields)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        serde_json::to_value(record).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize record: {e}"),
        })
    }

    async fn invoke_delete_record(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let (base_id, table_id) = self.require_table_id(&input).await?;
        let record_id = require_nonempty_str(&input, "record_id")?;

        let result = client
            .delete_record(&base_id, &table_id, record_id)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize result: {e}"),
        })
    }

    async fn invoke_delete_records(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_base_id(&input)?;
        let table_ref = require_nonempty_str(&input, "table_id")?;
        let schema = self.get_base_schema_cached(base_id).await?;
        let table = resolve_table(&schema.tables, table_ref)?;
        let record_ids = parse_record_ids(&input, "record_ids")?;

        let result = client
            .delete_records(base_id, &table.id, record_ids.as_slice())
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize result: {e}"),
        })
    }

    async fn invoke_create_webhook(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_base_id(&input)?;
        let notification_url = require_https_url(&input, "notification_url")?;
        let specification = require_object_field(&input, "specification")?;

        let result = client
            .create_webhook(base_id, Some(notification_url), specification)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize result: {e}"),
        })
    }

    async fn invoke_list_webhooks(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_base_id(&input)?;

        let result = client
            .list_webhooks(base_id)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        Ok(json!({ "webhooks": result.webhooks }))
    }

    async fn invoke_delete_webhook(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_base_id(&input)?;
        let webhook_id = require_webhook_id(&input)?;

        let result = client
            .delete_webhook(base_id, webhook_id)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize result: {e}"),
        })
    }

    async fn invoke_list_webhook_payloads(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_base_id(&input)?;
        let webhook_id = require_webhook_id(&input)?;
        let cursor = parse_optional_u64(input.get("cursor"), "cursor")?;
        let limit = parse_bounded_integer(&input, "limit", 1, 50)?;

        let result = client
            .list_webhook_payloads(base_id, webhook_id, cursor, limit)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;
        let events = self.normalize_webhook_payload_events(base_id, webhook_id, cursor, &result)?;

        Ok(json!({
            "payloads": result.payloads,
            "cursor": result.cursor,
            "mightHaveMore": result.might_have_more,
            "events": events,
        }))
    }

    async fn invoke_refresh_webhook(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_base_id(&input)?;
        let webhook_id = require_webhook_id(&input)?;

        let result = client
            .refresh_webhook(base_id, webhook_id)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize result: {e}"),
        })
    }

    async fn invoke_set_webhook_notifications(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_base_id(&input)?;
        let webhook_id = require_webhook_id(&input)?;
        let enable = require_bool(&input, "enable")?;

        let result = client
            .set_webhook_notifications(base_id, webhook_id, enable)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize result: {e}"),
        })
    }

    fn normalize_webhook_payload_events(
        &self,
        base_id: &str,
        webhook_id: &str,
        requested_cursor: Option<u64>,
        response: &ListWebhookPayloadsResponse,
    ) -> FcpResult<Vec<EventEnvelope>> {
        let zone_id = self.zone_id.clone().ok_or(FcpError::NotHandshaken)?;
        let connector_id = self.base.id.clone();
        let instance_id = self.base.instance_id.clone();
        let principal = Principal {
            kind: "webhook".into(),
            id: format!("airtable:webhook:{webhook_id}"),
            trust: TrustLevel::Paired,
            display: Some("Airtable Webhook".into()),
        };
        let resource_uris = vec![
            format!("airtable:base:{base_id}"),
            format!("airtable:webhook:{webhook_id}"),
        ];
        let stream_key = format!("{base_id}:{webhook_id}");
        let fallback_seq = requested_cursor.unwrap_or(1);
        let base_seq = response
            .cursor
            .and_then(|next_cursor| next_cursor.checked_sub(response.payloads.len() as u64))
            .filter(|seq| *seq > 0)
            .unwrap_or(fallback_seq);

        Ok(response
            .payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| {
                let seq = base_seq.saturating_add(index as u64);
                let event_payload = json!({
                    "base_id": base_id,
                    "webhook_id": webhook_id,
                    "payload_cursor": seq,
                    "payload": payload,
                });
                let event_data = EventData::new(
                    connector_id.clone(),
                    instance_id.clone(),
                    zone_id.clone(),
                    principal.clone(),
                    event_payload,
                )
                .with_resource_uris(resource_uris.clone());

                let mut event = EventEnvelope::new(webhook_payload_topic(payload), event_data)
                    .with_seq(seq)
                    .with_cursor(seq.saturating_add(1).to_string())
                    .with_stream_key(stream_key.clone())
                    .with_ordering(OrderingPolicy::PerKey);
                if let Some(timestamp) = webhook_payload_timestamp(payload) {
                    event.timestamp = timestamp;
                }
                event
            })
            .collect())
    }

    async fn invoke_download_attachment(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let url = require_str(&input, "url")?;

        let result = client
            .download_attachment(url)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize result: {e}"),
        })
    }

    async fn get_base_schema_cached(&self, base_id: &str) -> FcpResult<BaseSchemaResponse> {
        let now = Instant::now();
        let cached = {
            let cache = self.schema_cache.lock().await;
            cache.get(base_id).cloned()
        };
        if let Some(cached) = cached {
            if now.saturating_duration_since(cached.fetched_at) <= SCHEMA_CACHE_TTL {
                return Ok(cached.schema);
            }
        }

        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let schema = client
            .get_base_schema(base_id)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        self.schema_cache.lock().await.insert(
            base_id.to_string(),
            CachedSchema {
                fetched_at: now,
                schema: schema.clone(),
            },
        );

        Ok(schema)
    }

    async fn require_table_id(&self, input: &serde_json::Value) -> FcpResult<(String, String)> {
        let base_id = require_base_id(input)?.to_string();
        let table_ref = require_nonempty_str(input, "table_id")?;
        let schema = self.get_base_schema_cached(&base_id).await?;
        let table = resolve_table(&schema.tables, table_ref)?;
        Ok((base_id, table.id.clone()))
    }

    async fn serialize_record_list(
        &self,
        base_id: &str,
        schema: &BaseSchemaResponse,
        table: &TableSchema,
        records: Vec<Record>,
        linked_expansion: Option<&LinkedExpansionConfig>,
        mut expansion_state: Option<&mut LinkedExpansionState>,
    ) -> FcpResult<Vec<serde_json::Value>> {
        let mut serialized = Vec::with_capacity(records.len());
        for record in records {
            serialized.push(
                self.serialize_record_with_links(
                    base_id,
                    schema,
                    table,
                    record,
                    linked_expansion,
                    expansion_state.as_deref_mut(),
                    linked_expansion
                        .as_ref()
                        .map_or(0, |config| config.max_depth),
                    false,
                )
                .await?,
            );
        }
        Ok(serialized)
    }

    fn serialize_record_with_links<'a>(
        &'a self,
        base_id: &'a str,
        schema: &'a BaseSchemaResponse,
        table: &'a TableSchema,
        record: Record,
        linked_expansion: Option<&'a LinkedExpansionConfig>,
        mut expansion_state: Option<&'a mut LinkedExpansionState>,
        depth_remaining: usize,
        include_field_metadata: bool,
    ) -> BoxFcpFuture<'a, serde_json::Value> {
        Box::pin(async move {
            let record_path = (table.id.clone(), record.id.clone());
            let path_inserted = expansion_state
                .as_deref_mut()
                .is_some_and(|state| state.path.insert(record_path.clone()));

            let mut value = serde_json::to_value(&record).map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize record: {error}"),
            })?;
            let object = value.as_object_mut().ok_or(FcpError::Internal {
                message: "Serialized Airtable record was not an object".into(),
            })?;

            if include_field_metadata {
                let visible_fields = collect_record_field_names(&record);
                object.insert(
                    "field_metadata".into(),
                    build_field_metadata(table, schema, &visible_fields),
                );
            }

            if let (Some(config), Some(state)) = (linked_expansion, expansion_state.as_deref_mut())
            {
                let linked_records = self
                    .build_linked_records(
                        base_id,
                        schema,
                        table,
                        &record,
                        config,
                        state,
                        depth_remaining,
                    )
                    .await?;
                if !linked_records.is_empty() {
                    object.insert(
                        "linked_records".into(),
                        serde_json::Value::Object(linked_records),
                    );
                }
            }

            if path_inserted {
                if let Some(state) = expansion_state.as_deref_mut() {
                    state.path.remove(&record_path);
                }
            }

            Ok(value)
        })
    }

    fn build_linked_records<'a>(
        &'a self,
        base_id: &'a str,
        schema: &'a BaseSchemaResponse,
        table: &'a TableSchema,
        record: &'a Record,
        config: &'a LinkedExpansionConfig,
        state: &'a mut LinkedExpansionState,
        depth_remaining: usize,
    ) -> BoxFcpFuture<'a, serde_json::Map<String, serde_json::Value>> {
        Box::pin(async move {
            if depth_remaining == 0 {
                return Ok(serde_json::Map::new());
            }

            let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
            let Some(fields) = record.fields.as_object() else {
                return Ok(serde_json::Map::new());
            };

            let mut linked_records = serde_json::Map::new();
            for field in table
                .fields
                .iter()
                .filter(|field| is_linked_record_field(field) && config.expands_field(&field.name))
            {
                let Some(raw_value) = fields.get(&field.name) else {
                    continue;
                };
                let Some(linked_table_id) = linked_table_id(field) else {
                    continue;
                };
                let target_table = resolve_table_by_id(&schema.tables, linked_table_id)?;
                let linked_ids = linked_record_ids(raw_value);
                let mut partial = false;
                let mut resolved_records = Vec::with_capacity(linked_ids.len());

                for linked_id in linked_ids {
                    let linked_path = (target_table.id.clone(), linked_id.clone());
                    if state.path.contains(&linked_path) {
                        resolved_records.push(json!({ "id": linked_id, "status": "cycle" }));
                        continue;
                    }
                    if state.remaining_records == 0 {
                        partial = true;
                        resolved_records.push(json!({ "id": linked_id, "status": "truncated" }));
                        continue;
                    }

                    state.remaining_records -= 1;
                    match client
                        .get_record(base_id, &target_table.id, &linked_id)
                        .await
                    {
                        Ok(linked_record) => {
                            resolved_records.push(
                                self.serialize_record_with_links(
                                    base_id,
                                    schema,
                                    target_table,
                                    linked_record,
                                    Some(config),
                                    Some(state),
                                    depth_remaining.saturating_sub(1),
                                    true,
                                )
                                .await?,
                            );
                        }
                        Err(
                            AirtableError::Api {
                                status_code: Some(404),
                                ..
                            }
                            | AirtableError::RecordNotFound { .. },
                        ) => {
                            resolved_records.push(json!({ "id": linked_id, "status": "missing" }));
                        }
                        Err(error) => return Err(error.to_fcp_error()),
                    }
                }

                linked_records.insert(
                    field.name.clone(),
                    json!({
                        "field_id": field.id,
                        "field_type": field.field_type,
                        "linked_table": {
                            "id": target_table.id,
                            "name": target_table.name,
                        },
                        "partial": partial,
                        "records": resolved_records,
                    }),
                );
            }

            Ok(linked_records)
        })
    }

    /// Handle shutdown.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the shutdown process fails.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Airtable connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for AirtableConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ──────────────────────────────────────────────

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

fn require_nonempty_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    let value = require_str(input, field)?;
    if value.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be a non-empty string"),
        });
    }
    Ok(value)
}

fn require_base_id(input: &serde_json::Value) -> FcpResult<&str> {
    let base_id = require_nonempty_str(input, "base_id")?;
    let valid_format = base_id.starts_with("app")
        && base_id.len() >= 6
        && base_id.chars().all(|c| c.is_ascii_alphanumeric());
    if !valid_format {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_id must match Airtable base format (e.g., appXXXXXXXXXXXXXX)".into(),
        });
    }
    Ok(base_id)
}

fn require_webhook_id(input: &serde_json::Value) -> FcpResult<&str> {
    let webhook_id = require_nonempty_str(input, "webhook_id")?;
    let valid_format = webhook_id.starts_with("ach")
        && webhook_id.len() >= 6
        && webhook_id.chars().all(|c| c.is_ascii_alphanumeric());
    if !valid_format {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "webhook_id must match Airtable webhook format (e.g., achXXXXXXXXXXXXXX)"
                .into(),
        });
    }
    Ok(webhook_id)
}

fn require_https_url<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    let url = require_nonempty_str(input, field)?;
    if !url.starts_with("https://") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be an HTTPS URL"),
        });
    }
    Ok(url)
}

fn require_bool(input: &serde_json::Value, field: &str) -> FcpResult<bool> {
    input
        .get(field)
        .and_then(|value| value.as_bool())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be a boolean"),
        })
}

fn require_fields_object(input: &serde_json::Value) -> FcpResult<&serde_json::Value> {
    let fields = input.get("fields").ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "Missing required field: fields".into(),
    })?;
    if !fields.is_object() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "fields must be an object".into(),
        });
    }
    Ok(fields)
}

fn require_object_field<'a>(
    input: &'a serde_json::Value,
    field: &str,
) -> FcpResult<&'a serde_json::Value> {
    let value = input.get(field).ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("Missing required field: {field}"),
    })?;
    if !value.is_object() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be an object"),
        });
    }
    Ok(value)
}

fn parse_linked_expansion_config(
    input: &serde_json::Value,
    table: &TableSchema,
) -> FcpResult<Option<LinkedExpansionConfig>> {
    let expand_flag = match input.get("expand_linked_records") {
        Some(value) => Some(value.as_bool().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "expand_linked_records must be a boolean".into(),
        })?),
        None => None,
    };
    let linked_field_refs = parse_optional_string_array(input, "linked_field_refs")?;
    let max_depth = parse_bounded_integer(input, "linked_record_depth", 1, MAX_LINKED_RECORD_DEPTH)?
        .unwrap_or(DEFAULT_LINKED_RECORD_DEPTH) as usize;
    let max_records =
        parse_bounded_integer(input, "linked_record_limit", 1, MAX_LINKED_RECORD_LIMIT)?
            .unwrap_or(DEFAULT_LINKED_RECORD_LIMIT) as usize;

    let enabled = expand_flag.unwrap_or(false)
        || linked_field_refs.is_some()
        || input.get("linked_record_depth").is_some()
        || input.get("linked_record_limit").is_some();
    if !enabled {
        return Ok(None);
    }

    let field_names = linked_field_refs
        .as_ref()
        .map(|field_refs| {
            let selectors = field_refs
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect::<Vec<_>>();
            let resolved = resolve_fields(table, selectors.as_slice())?;
            if let Some(non_linked) = resolved.iter().find(|field| !is_linked_record_field(field)) {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!(
                        "linked_field_refs may only reference linked-record fields; '{}' is {}",
                        non_linked.name, non_linked.field_type
                    ),
                });
            }
            Ok::<HashSet<String>, FcpError>(resolved.into_iter().map(|field| field.name).collect())
        })
        .transpose()?;

    Ok(Some(LinkedExpansionConfig {
        field_names,
        max_depth,
        max_records,
    }))
}

fn validate_linked_projection(
    projected_fields: Option<&[String]>,
    linked_expansion: Option<&LinkedExpansionConfig>,
) -> FcpResult<()> {
    let Some(projected_fields) = projected_fields else {
        return Ok(());
    };
    let Some(linked_field_names) = linked_expansion.and_then(|config| config.field_names.as_ref())
    else {
        return Ok(());
    };

    if let Some(missing_field) = linked_field_names
        .iter()
        .find(|field_name| !projected_fields.iter().any(|field| field == *field_name))
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "fields projection must include linked field '{missing_field}' when linked_field_refs are requested"
            ),
        });
    }

    Ok(())
}

fn collect_visible_fields_for_list(
    table: &TableSchema,
    projected_fields: Option<&[String]>,
    records: &[serde_json::Value],
) -> HashSet<String> {
    let mut visible_fields = records
        .iter()
        .filter_map(serde_json::Value::as_object)
        .filter_map(|record| record.get("fields"))
        .filter_map(serde_json::Value::as_object)
        .flat_map(|fields| fields.keys().cloned())
        .collect::<HashSet<_>>();

    if visible_fields.is_empty() {
        if let Some(projected_fields) = projected_fields {
            visible_fields.extend(projected_fields.iter().cloned());
        } else {
            visible_fields.extend(table.fields.iter().map(|field| field.name.clone()));
        }
    }

    visible_fields
}

fn collect_record_field_names(record: &Record) -> HashSet<String> {
    record
        .fields
        .as_object()
        .map(|fields| fields.keys().cloned().collect())
        .unwrap_or_default()
}

fn build_field_metadata(
    table: &TableSchema,
    schema: &BaseSchemaResponse,
    visible_fields: &HashSet<String>,
) -> serde_json::Value {
    let mut metadata = serde_json::Map::new();
    for field in table
        .fields
        .iter()
        .filter(|field| visible_fields.contains(&field.name))
    {
        let access = classify_field_access(field);
        let mut entry = serde_json::Map::new();
        entry.insert("field_id".into(), json!(field.id));
        entry.insert("field_type".into(), json!(field.field_type));
        entry.insert("read_only".into(), json!(access.read_only));
        entry.insert("computed".into(), json!(access.computed));
        if let Some(kind) = access.computed_kind {
            entry.insert("computed_kind".into(), json!(kind));
        }
        if let Some(reason) = access.read_only_reason {
            entry.insert("read_only_reason".into(), json!(reason));
        }

        if let Some(linked_table_id) = linked_table_id(field) {
            if let Ok(linked_table) = resolve_table_by_id(&schema.tables, linked_table_id) {
                entry.insert(
                    "linked_table".into(),
                    json!({
                        "id": linked_table.id,
                        "name": linked_table.name,
                    }),
                );
            }
        }

        metadata.insert(field.name.clone(), serde_json::Value::Object(entry));
    }
    serde_json::Value::Object(metadata)
}

#[derive(Clone, Copy)]
struct FieldAccessProfile {
    read_only: bool,
    computed: bool,
    computed_kind: Option<&'static str>,
    read_only_reason: Option<&'static str>,
}

fn serialize_table_schema(table: &TableSchema, schema: &BaseSchemaResponse) -> serde_json::Value {
    json!({
        "id": table.id,
        "name": table.name,
        "description": table.description,
        "primaryFieldId": table.primary_field_id,
        "fields": table
            .fields
            .iter()
            .map(|field| serialize_field_schema(field, schema))
            .collect::<Vec<_>>(),
        "views": table.views,
    })
}

fn serialize_field_schema(field: &FieldSchema, schema: &BaseSchemaResponse) -> serde_json::Value {
    let access = classify_field_access(field);
    let mut entry = serde_json::Map::new();
    entry.insert("id".into(), json!(field.id));
    entry.insert("name".into(), json!(field.name));
    entry.insert("type".into(), json!(field.field_type));
    entry.insert("description".into(), json!(field.description));
    entry.insert("options".into(), json!(field.options));
    entry.insert("read_only".into(), json!(access.read_only));
    entry.insert("computed".into(), json!(access.computed));

    if let Some(kind) = access.computed_kind {
        entry.insert("computed_kind".into(), json!(kind));
    }
    if let Some(reason) = access.read_only_reason {
        entry.insert("read_only_reason".into(), json!(reason));
    }
    if let Some(linked_table_id) = linked_table_id(field) {
        if let Ok(linked_table) = resolve_table_by_id(&schema.tables, linked_table_id) {
            entry.insert(
                "linked_table".into(),
                json!({
                    "id": linked_table.id,
                    "name": linked_table.name,
                }),
            );
        }
    }

    serde_json::Value::Object(entry)
}

fn resolve_table<'a>(tables: &'a [TableSchema], table_ref: &str) -> FcpResult<&'a TableSchema> {
    if let Some(table) = tables.iter().find(|table| table.id == table_ref) {
        return Ok(table);
    }

    let matches: Vec<&TableSchema> = tables
        .iter()
        .filter(|table| table.name == table_ref)
        .collect();
    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(FcpError::ResourceNotFound {
            resource: format!("airtable.table:{table_ref}"),
        }),
        _ => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "Ambiguous table_ref '{table_ref}': multiple tables have this name; use stable table ID"
            ),
        }),
    }
}

fn resolve_table_by_id<'a>(
    tables: &'a [TableSchema],
    table_id: &str,
) -> FcpResult<&'a TableSchema> {
    tables
        .iter()
        .find(|table| table.id == table_id)
        .ok_or(FcpError::ResourceNotFound {
            resource: format!("airtable.table:{table_id}"),
        })
}

fn resolve_view<'a>(views: &'a [ViewSchema], view_ref: &str) -> FcpResult<&'a ViewSchema> {
    if let Some(view) = views.iter().find(|view| view.id == view_ref) {
        return Ok(view);
    }

    let matches: Vec<&ViewSchema> = views.iter().filter(|view| view.name == view_ref).collect();
    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(FcpError::ResourceNotFound {
            resource: format!("airtable.view:{view_ref}"),
        }),
        _ => Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "Ambiguous view_ref '{view_ref}': multiple views have this name; use stable view ID"
            ),
        }),
    }
}

fn resolve_fields(table: &TableSchema, refs: &[serde_json::Value]) -> FcpResult<Vec<FieldSchema>> {
    refs.iter()
        .map(|field_ref| {
            let selector = field_ref.as_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "field_refs must contain only strings".into(),
            })?;
            if selector.trim().is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "field_refs entries must be non-empty strings".into(),
                });
            }

            if let Some(field) = table.fields.iter().find(|field| field.id == selector) {
                return Ok(field.clone());
            }

            let matches: Vec<&FieldSchema> = table
                .fields
                .iter()
                .filter(|field| field.name == selector)
                .collect();
            match matches.len() {
                1 => Ok(matches[0].clone()),
                0 => Err(FcpError::ResourceNotFound {
                    resource: format!("airtable.field:{selector}"),
                }),
                _ => Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!(
                        "Ambiguous field ref '{selector}': multiple fields share this name; use field ID"
                    ),
                }),
            }
        })
        .collect()
}

fn resolve_requested_fields(
    input: &serde_json::Value,
    table: &TableSchema,
    required: bool,
) -> FcpResult<Option<Vec<String>>> {
    let Some(field_refs) = input.get("fields") else {
        if required {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: fields".into(),
            });
        }
        return Ok(None);
    };

    let refs = field_refs.as_array().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "fields must be an array of strings".into(),
    })?;
    if refs.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "fields must include at least one field ID or exact field name".into(),
        });
    }

    let resolved = resolve_fields(table, refs)?;
    Ok(Some(resolved.into_iter().map(|field| field.name).collect()))
}

fn parse_filter_by_formula(input: &serde_json::Value) -> FcpResult<Option<String>> {
    let Some(value) = input.get("filter_by_formula") else {
        return Ok(None);
    };

    let formula = value.as_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "filter_by_formula must be a string".into(),
    })?;
    let trimmed = formula.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "filter_by_formula must be a non-empty string".into(),
        });
    }
    if trimmed.chars().any(char::is_control) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message:
                "filter_by_formula must not contain control characters; provide a single Airtable formula expression".into(),
        });
    }

    Ok(Some(trimmed.to_string()))
}

fn parse_record_bound(input: &serde_json::Value, field: &str) -> FcpResult<Option<u32>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };

    let raw = value.as_u64().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be an integer between 1 and 100"),
    })?;
    if !(1..=100).contains(&raw) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be between 1 and 100"),
        });
    }

    Ok(Some(raw as u32))
}

fn parse_bounded_integer(
    input: &serde_json::Value,
    field: &str,
    min: u32,
    max: u32,
) -> FcpResult<Option<u32>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };

    let raw = value.as_u64().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be an integer between {min} and {max}"),
    })?;
    if raw < u64::from(min) || raw > u64::from(max) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be between {min} and {max}"),
        });
    }

    Ok(Some(raw as u32))
}

fn parse_record_payloads(
    input: &serde_json::Value,
    require_ids: bool,
) -> FcpResult<Vec<serde_json::Value>> {
    let records = input
        .get("records")
        .and_then(|value| value.as_array())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: records (must be an array)".into(),
        })?;
    if records.is_empty() || records.len() > 10 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "records must contain between 1 and 10 items".into(),
        });
    }

    records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            let object = record.as_object().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: format!("records[{index}] must be an object"),
            })?;
            if require_ids {
                let id = object.get("id").and_then(|value| value.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("records[{index}].id must be a non-empty string"),
                    },
                )?;
                if id.trim().is_empty() {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("records[{index}].id must be a non-empty string"),
                    });
                }
            }

            if !object
                .get("fields")
                .is_some_and(serde_json::Value::is_object)
            {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("records[{index}].fields must be an object"),
                });
            }

            Ok(record.clone())
        })
        .collect()
}

fn optional_nonempty_string(input: &serde_json::Value, field: &str) -> FcpResult<Option<String>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };

    let raw = value.as_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be a string"),
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be a non-empty string"),
        });
    }

    Ok(Some(trimmed.to_string()))
}

fn parse_optional_u64(value: Option<&serde_json::Value>, field: &str) -> FcpResult<Option<u64>> {
    let Some(value) = value else {
        return Ok(None);
    };
    value.as_u64().map(Some).ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be an unsigned integer"),
    })
}

fn webhook_payload_topic(payload: &serde_json::Value) -> &'static str {
    if payload.get("error").and_then(serde_json::Value::as_bool) == Some(true) {
        "airtable.webhook.error"
    } else {
        "airtable.webhook.payload"
    }
}

fn webhook_payload_timestamp(payload: &serde_json::Value) -> Option<chrono::DateTime<chrono::Utc>> {
    payload
        .get("timestamp")
        .and_then(serde_json::Value::as_str)
        .and_then(|timestamp| chrono::DateTime::parse_from_rfc3339(timestamp).ok())
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
}

fn parse_optional_string_array(
    input: &serde_json::Value,
    field: &str,
) -> FcpResult<Option<Vec<String>>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    let items = value.as_array().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be an array of non-empty strings"),
    })?;
    if items.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must contain at least one linked field"),
        });
    }

    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let raw = item.as_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field}[{index}] must be a non-empty string"),
            })?;
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("{field}[{index}] must be a non-empty string"),
                });
            }
            Ok(trimmed.to_string())
        })
        .collect::<FcpResult<Vec<_>>>()
        .map(Some)
}

fn parse_record_ids(input: &serde_json::Value, field: &str) -> FcpResult<Vec<String>> {
    let values =
        input
            .get(field)
            .and_then(|value| value.as_array())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: format!("Missing required field: {field} (must be an array)"),
            })?;
    if values.is_empty() || values.len() > 10 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must contain between 1 and 10 record IDs"),
        });
    }

    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let record_id = value.as_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: format!("{field}[{index}] must be a non-empty string"),
            })?;
            let trimmed = record_id.trim();
            if trimmed.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("{field}[{index}] must be a non-empty string"),
                });
            }
            Ok(trimmed.to_string())
        })
        .collect()
}

fn linked_table_id(field: &FieldSchema) -> Option<&str> {
    field
        .options
        .as_ref()
        .and_then(|options| options.get("linkedTableId"))
        .and_then(serde_json::Value::as_str)
}

fn linked_record_ids(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .collect()
}

fn is_linked_record_field(field: &FieldSchema) -> bool {
    field.field_type == "multipleRecordLinks"
}

fn classify_field_access(field: &FieldSchema) -> FieldAccessProfile {
    let computed_kind = match field.field_type.as_str() {
        "formula" => Some("formula"),
        "lookup" | "multipleLookupValues" => Some("lookup"),
        "rollup" => Some("rollup"),
        "count" => Some("count"),
        "createdTime" => Some("created_time"),
        "lastModifiedTime" => Some("last_modified_time"),
        "createdBy" => Some("created_by"),
        "lastModifiedBy" => Some("last_modified_by"),
        _ => None,
    };
    let read_only_reason = if computed_kind.is_some() {
        Some("computed")
    } else if matches!(field.field_type.as_str(), "autoNumber" | "button") {
        Some("system_managed")
    } else {
        None
    };

    FieldAccessProfile {
        read_only: read_only_reason.is_some(),
        computed: computed_kind.is_some(),
        computed_kind,
        read_only_reason,
    }
}

fn parse_sort_specs(
    input: &serde_json::Value,
    table: &TableSchema,
) -> FcpResult<Option<Vec<SortSpec>>> {
    let Some(value) = input.get("sort") else {
        return Ok(None);
    };

    let items = value.as_array().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "sort must be an array of objects".into(),
    })?;
    if items.len() > 3 {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "sort supports at most 3 Airtable sort clauses".into(),
        });
    }

    items
        .iter()
        .map(|item| {
            let mut spec: SortSpec =
                serde_json::from_value(item.clone()).map_err(|error| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid sort specification: {error}"),
                })?;
            if spec.field.trim().is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "sort.field must be a non-empty string".into(),
                });
            }

            let direction = spec.direction.to_ascii_lowercase();
            if !matches!(direction.as_str(), "asc" | "desc") {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "sort.direction must be either 'asc' or 'desc'".into(),
                });
            }

            let field_selector = vec![serde_json::Value::String(spec.field.clone())];
            let resolved_field = resolve_fields(table, &field_selector)?
                .into_iter()
                .next()
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "sort.field must reference an existing Airtable field".into(),
                })?;

            spec.field = resolved_field.name;
            spec.direction = direction;
            Ok(spec)
        })
        .collect::<FcpResult<Vec<_>>>()
        .map(Some)
}

fn parse_fields_to_merge_on(
    input: &serde_json::Value,
    table: &TableSchema,
) -> FcpResult<Vec<String>> {
    let field_refs = input
        .get("fields_to_merge_on")
        .and_then(|value| value.as_array())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: fields_to_merge_on (must be an array)".into(),
        })?;
    if field_refs.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "fields_to_merge_on must contain at least one Airtable field".into(),
        });
    }

    let resolved = resolve_fields(table, field_refs)?;
    Ok(resolved.into_iter().map(|field| field.name).collect())
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

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        cap: &str,
        op: &str,
    ) -> CapabilityToken {
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .sign(signing_key)
            .unwrap();
        CapabilityToken { raw: cose }
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = AirtableConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["airtable.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
        assert_eq!(result["event_caps"]["streaming"], true);
        assert_eq!(result["event_caps"]["replay"], true);
        assert_eq!(result["event_caps"]["min_buffer_events"], 50);
    }

    #[test]
    fn test_normalize_webhook_payload_events() {
        let mut connector = AirtableConnector::new();
        connector.zone_id = Some(ZoneId::work());

        let payloads = ListWebhookPayloadsResponse {
            payloads: vec![
                json!({
                    "timestamp": "2026-03-09T00:00:00.000Z",
                    "baseTransactionNumber": 1001,
                    "payloadFormat": "v0"
                }),
                json!({
                    "timestamp": "2026-03-09T00:00:01.000Z",
                    "error": true,
                    "code": "INVALID_HOOK"
                }),
            ],
            cursor: Some(43),
            might_have_more: false,
        };

        let events = connector
            .normalize_webhook_payload_events("appABC", "achXYZ", Some(41), &payloads)
            .unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].topic, "airtable.webhook.payload");
        assert_eq!(events[0].seq, 41);
        assert_eq!(events[0].cursor, "42");
        assert_eq!(events[0].stream_key.as_deref(), Some("appABC:achXYZ"));
        assert_eq!(events[0].ordering, Some(OrderingPolicy::PerKey));
        assert_eq!(events[0].data.zone_id, ZoneId::work());
        assert_eq!(events[0].data.principal.kind, "webhook");
        assert_eq!(events[0].data.payload["base_id"], "appABC");
        assert_eq!(events[0].data.payload["webhook_id"], "achXYZ");
        assert_eq!(events[0].data.payload["payload_cursor"], 41);
        assert_eq!(
            events[0].data.payload["payload"]["baseTransactionNumber"],
            1001
        );
        assert_eq!(events[1].topic, "airtable.webhook.error");
        assert_eq!(events[1].seq, 42);
        assert_eq!(events[1].cursor, "43");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = AirtableConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = AirtableConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["airtable.list_bases"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "airtable.read", "airtable.list_bases");

        let result = connector
            .handle_invoke(json!({
                "operation": "airtable.list_bases",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = AirtableConnector::new();
        connector
            .handle_configure(json!({
                "token": "fake_key",
                "base_url": "http://localhost:9999"
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
                "capabilities_requested": ["airtable.get_record"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "airtable.read", "airtable.get_record");

        let result = connector
            .handle_invoke(json!({
                "operation": "airtable.get_record",
                "input": { "base_id": "appXXX" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("table_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = AirtableConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"airtable.list_bases"));
        assert!(op_ids.contains(&"airtable.get_base_schema"));
        assert!(op_ids.contains(&"airtable.list_tables"));
        assert!(op_ids.contains(&"airtable.get_table"));
        assert!(op_ids.contains(&"airtable.list_fields"));
        assert!(op_ids.contains(&"airtable.list_views"));
        assert!(op_ids.contains(&"airtable.get_view"));
        assert!(op_ids.contains(&"airtable.list_view_records"));
        assert!(op_ids.contains(&"airtable.list_records"));
        assert!(op_ids.contains(&"airtable.get_record"));
        assert!(op_ids.contains(&"airtable.create_record"));
        assert!(op_ids.contains(&"airtable.create_records"));
        assert!(op_ids.contains(&"airtable.update_records"));
        assert!(op_ids.contains(&"airtable.upsert_records"));
        assert!(op_ids.contains(&"airtable.update_record"));
        assert!(op_ids.contains(&"airtable.replace_record"));
        assert!(op_ids.contains(&"airtable.delete_record"));
        assert!(op_ids.contains(&"airtable.delete_records"));
        assert!(op_ids.contains(&"airtable.create_webhook"));
        assert!(op_ids.contains(&"airtable.list_webhooks"));
        assert!(op_ids.contains(&"airtable.delete_webhook"));
        assert!(op_ids.contains(&"airtable.list_webhook_payloads"));
        assert!(op_ids.contains(&"airtable.refresh_webhook"));
        assert!(op_ids.contains(&"airtable.set_webhook_notifications"));
        assert!(op_ids.contains(&"airtable.download_attachment"));
        assert_eq!(ops.len(), 25);
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure() {
        let mut connector = AirtableConnector::new();
        let result = connector
            .handle_configure(json!({
                "token": "pat_test_token_123"
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");
        assert!(connector.client.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_no_auth() {
        let mut connector = AirtableConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing authentication"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown() {
        let connector = AirtableConnector::new();
        let result = connector.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(result["status"], "shutdown");
    }

    // ── Provisioning automation tests ──────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id() {
        let mut connector = AirtableConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.config.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_both_auth() {
        let mut connector = AirtableConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        let result = connector
            .handle_configure(json!({
                "token": "tok",
                "credential_id": cid
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
    async fn test_configure_custom_base_url() {
        let mut connector = AirtableConnector::new();
        connector
            .handle_configure(json!({
                "token": "tok",
                "base_url": "http://localhost:8080"
            }))
            .await
            .unwrap();
        let config = connector.config.as_ref().unwrap();
        assert_eq!(config.base_url, "http://localhost:8080");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_shows_auth_info() {
        let mut connector = AirtableConnector::new();
        connector
            .handle_configure(json!({ "token": "tok" }))
            .await
            .unwrap();
        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "healthy");
        assert_eq!(health["auth_mode"], "token:redacted");
        assert!(health["base_url"].as_str().is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_unconfigured() {
        let connector = AirtableConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        assert!(checks.len() >= 6);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured() {
        let mut connector = AirtableConnector::new();
        connector
            .handle_configure(json!({ "token": "tok" }))
            .await
            .unwrap();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        assert!(checks.iter().all(|c| c["status"] == "healthy"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_credential_id_mode() {
        let mut connector = AirtableConnector::new();
        let cid = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({ "credential_id": cid }))
            .await
            .unwrap();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert!(
            cred_check["message"]
                .as_str()
                .unwrap()
                .contains("Secretless")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = AirtableConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_returns_degraded() {
        let mut connector = AirtableConnector::new();
        connector
            .handle_configure(json!({
                "credential_id": "550e8400-e29b-41d4-a716-446655440000"
            }))
            .await
            .unwrap();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "credential_injection_required");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_connection_failure() {
        let mut connector = AirtableConnector::new();
        connector
            .handle_configure(json!({
                "token": "tok",
                "base_url": "http://127.0.0.1:1"
            }))
            .await
            .unwrap();
        let result = connector.handle_self_check().await.unwrap();
        assert!(
            result["status"] == "failed" || result["status"] == "degraded",
            "Expected failed or degraded, got: {}",
            result["status"]
        );
    }
}
