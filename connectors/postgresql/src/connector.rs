//! FCP `PostgreSQL` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, OperationId, OperationInfo, RiskLevel, SafetyTier,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, PostgresAuth, PostgresClient},
    error::PostgresError,
};

/// Parsed and validated `PostgreSQL` connector configuration.
#[derive(Debug, Clone)]
struct PostgresConfig {
    auth: PostgresAuth,
    base_url: String,
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

fn validate_postgres_base_url(raw: &str) -> FcpResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not be empty".into(),
        });
    }

    let parsed = Url::parse(trimmed).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("base_url could not be parsed: {error}"),
    })?;

    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use http or https".into(),
        });
    }

    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "base_url must include a host".into(),
    })?;
    let local = is_local_test_host(host);
    if parsed.scheme() == "http" && !local {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use https unless targeting localhost/127.0.0.1/::1 for tests"
                .into(),
        });
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include userinfo".into(),
        });
    }

    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include a query string or fragment".into(),
        });
    }

    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

impl PostgresConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let rest_key = params
            .get("api_key")
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

        let auth = match (rest_key, credential_id) {
            (Some(key), None) => PostgresAuth::ApiKey(key),
            (None, Some(cred_id)) => PostgresAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_key or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key or credential_id in configuration".into(),
                });
            }
        };

        let base_url = match params.get("base_url") {
            Some(value) => validate_postgres_base_url(value.as_str().ok_or_else(|| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: "base_url must be a string".into(),
                }
            })?)?,
            None => DEFAULT_BASE_URL.to_string(),
        };

        Ok(Self { auth, base_url })
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

/// FCP `PostgreSQL` Connector.
pub struct PostgreSqlConnector {
    base: Arc<BaseConnector>,
    config: Option<PostgresConfig>,
    client: Option<Arc<PostgresClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl PostgreSqlConnector {
    /// Create a new `PostgreSQL` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("postgresql"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for PostgreSqlConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl PostgreSqlConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = PostgresConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring PostgreSQL connector");

        let client = PostgresClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.postgresql",
            "connector_version": "0.1.0",
            "capabilities": [
                "pg.query",
                "pg.execute",
                "pg.explain",
                "pg.schema.tables",
                "pg.schema.columns",
                "pg.schema.indexes",
                "pg.transaction.begin",
                "pg.transaction.commit",
                "pg.transaction.rollback",
                "pg.batch",
                "pg.prepared",
                "pg.health"
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
                Some("Not configured — call configure first".into())
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
        Ok(json!({
            "connector_id": "fcp.postgresql",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ok" } else { "degraded" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let ops = typed_operations_info();
        Ok(json!({
            "connector_id": "fcp.postgresql",
            "version": "0.1.0",
            "operations": serde_json::to_value(&ops).unwrap_or_default(),
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
            "pg.query" => self.invoke_query(client, &input).await,
            "pg.execute" => self.invoke_execute(client, &input).await,
            "pg.explain" => self.invoke_explain(client, &input).await,
            "pg.schema.tables" => self.invoke_schema_tables(client, &input).await,
            "pg.schema.columns" => self.invoke_schema_columns(client, &input).await,
            "pg.schema.indexes" => self.invoke_schema_indexes(client, &input).await,
            "pg.transaction.begin" => self.invoke_transaction_begin(client, &input).await,
            "pg.transaction.commit" => self.invoke_transaction_commit(client, &input).await,
            "pg.transaction.rollback" => self.invoke_transaction_rollback(client, &input).await,
            "pg.batch" => self.invoke_batch(client, &input).await,
            "pg.prepared" => self.invoke_prepared(client, &input).await,
            "pg.health" => self.invoke_health(client).await,
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
        info!("PostgreSQL connector shutting down");
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

    async fn invoke_query(
        &self,
        client: &PostgresClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PostgresError> {
        let sql = require_str(input, "sql")?;
        let params = input
            .get("params")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        let timeout_ms = input.get("timeout_ms").and_then(serde_json::Value::as_u64);
        let result = client.query(sql, &params, timeout_ms).await?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_execute(
        &self,
        client: &PostgresClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PostgresError> {
        let sql = require_str(input, "sql")?;
        let params = input
            .get("params")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        let result = client.execute(sql, &params).await?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_explain(
        &self,
        client: &PostgresClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PostgresError> {
        let sql = require_str(input, "sql")?;
        let params = input
            .get("params")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        let result = client.explain(sql, &params).await?;
        Ok(json!({ "plan": result }))
    }

    async fn invoke_schema_tables(
        &self,
        client: &PostgresClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PostgresError> {
        let schema = input.get("schema").and_then(serde_json::Value::as_str);
        let result = client.schema_tables(schema).await?;
        Ok(json!({ "tables": result }))
    }

    async fn invoke_schema_columns(
        &self,
        client: &PostgresClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PostgresError> {
        let table = require_str(input, "table")?;
        let result = client.schema_columns(table).await?;
        Ok(json!({ "columns": result }))
    }

    async fn invoke_schema_indexes(
        &self,
        client: &PostgresClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PostgresError> {
        let table = require_str(input, "table")?;
        let result = client.schema_indexes(table).await?;
        Ok(json!({ "indexes": result }))
    }

    async fn invoke_transaction_begin(
        &self,
        client: &PostgresClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PostgresError> {
        let isolation_level = input
            .get("isolation_level")
            .and_then(serde_json::Value::as_str);
        let result = client.transaction_begin(isolation_level).await?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_transaction_commit(
        &self,
        client: &PostgresClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PostgresError> {
        let txn_id = require_str(input, "txn_id")?;
        let result = client.transaction_commit(txn_id).await?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_transaction_rollback(
        &self,
        client: &PostgresClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PostgresError> {
        let txn_id = require_str(input, "txn_id")?;
        let result = client.transaction_rollback(txn_id).await?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_batch(
        &self,
        client: &PostgresClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PostgresError> {
        let statements_val = input
            .get("statements")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| PostgresError::Query("Missing required field: statements".into()))?;
        let statements: Vec<String> = statements_val
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| PostgresError::Query("All statements must be strings".into()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let params = input
            .get("params")
            .and_then(serde_json::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .map(|v| v.as_array().cloned().unwrap_or_default())
                    .collect::<Vec<Vec<serde_json::Value>>>()
            })
            .unwrap_or_default();
        let result = client.batch(&statements, &params).await?;
        Ok(json!({ "results": result }))
    }

    async fn invoke_prepared(
        &self,
        client: &PostgresClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, PostgresError> {
        let name = require_str(input, "name")?;
        let params = input
            .get("params")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        let result = client.prepared(name, &params).await?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_health(
        &self,
        client: &PostgresClient,
    ) -> Result<serde_json::Value, PostgresError> {
        let result = client.health().await?;
        Ok(json!({ "health": result }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, PostgresError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| PostgresError::Query(format!("Missing required field: {field}")))
}

/// Build typed operations info for introspection.
#[allow(clippy::too_many_lines)]
fn typed_operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static("pg.query"),
            summary: "Execute a parameterized SQL query (returns rows)".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"sql": {"type": "string", "description": "SQL query to execute"}, "params": {"type": "array", "description": "Positional parameters for the query"}, "timeout_ms": {"type": "integer", "description": "Query timeout in milliseconds"}}, "required": ["sql"]}),
            output_schema: json!({"type": "object", "properties": {"result": {"description": "Query result with rows and metadata"}}}),
            capability: CapabilityId::from_static("pg.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to execute SELECT queries and retrieve rows from the database"
                    .into(),
                common_mistakes: vec![
                    "Using string interpolation instead of parameterized queries".into(),
                ],
                examples: vec![],
                related: vec![CapabilityId::from_static("pg.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("pg.execute"),
            summary: "Execute a non-returning SQL statement (returns affected_rows)".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"sql": {"type": "string", "description": "SQL statement to execute"}, "params": {"type": "array", "description": "Positional parameters for the statement"}}, "required": ["sql"]}),
            output_schema: json!({"type": "object", "properties": {"result": {"description": "Execution result with affected_rows"}}}),
            capability: CapabilityId::from_static("pg.write"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use for INSERT, UPDATE, DELETE or DDL statements that modify data"
                    .into(),
                common_mistakes: vec![
                    "Running destructive statements without a WHERE clause".into(),
                ],
                examples: vec![],
                related: vec![CapabilityId::from_static("pg.write")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("pg.explain"),
            summary: "Explain query plan for a SQL query".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"sql": {"type": "string", "description": "SQL query to explain"}, "params": {"type": "array", "description": "Positional parameters for the query"}}, "required": ["sql"]}),
            output_schema: json!({"type": "object", "properties": {"plan": {"description": "Query execution plan"}}}),
            capability: CapabilityId::from_static("pg.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to analyze query performance before running expensive queries"
                    .into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![CapabilityId::from_static("pg.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("pg.schema.tables"),
            summary: "List tables in a database schema".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"schema": {"type": "string", "description": "Schema name (default: public)"}}}),
            output_schema: json!({"type": "object", "properties": {"tables": {"type": "array", "description": "List of tables"}}}),
            capability: CapabilityId::from_static("pg.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to discover what tables exist in a schema".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![CapabilityId::from_static("pg.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("pg.schema.columns"),
            summary: "Get column details for a table".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"table": {"type": "string", "description": "Table name"}}, "required": ["table"]}),
            output_schema: json!({"type": "object", "properties": {"columns": {"type": "array", "description": "Column details"}}}),
            capability: CapabilityId::from_static("pg.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to inspect column names, types, and constraints for a table"
                    .into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![CapabilityId::from_static("pg.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("pg.schema.indexes"),
            summary: "List indexes for a table".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"table": {"type": "string", "description": "Table name"}}, "required": ["table"]}),
            output_schema: json!({"type": "object", "properties": {"indexes": {"type": "array", "description": "Index details"}}}),
            capability: CapabilityId::from_static("pg.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to inspect indexes on a table for performance analysis".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![CapabilityId::from_static("pg.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("pg.transaction.begin"),
            summary: "Start a new database transaction".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"isolation_level": {"type": "string", "description": "Isolation level: read_committed, repeatable_read, serializable"}}}),
            output_schema: json!({"type": "object", "properties": {"result": {"description": "Transaction info including txn_id"}}}),
            capability: CapabilityId::from_static("pg.write"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use to start a transaction for atomic multi-statement operations"
                    .into(),
                common_mistakes: vec!["Forgetting to commit or rollback the transaction".into()],
                examples: vec![],
                related: vec![CapabilityId::from_static("pg.write")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("pg.transaction.commit"),
            summary: "Commit a database transaction".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"txn_id": {"type": "string", "description": "Transaction ID to commit"}}, "required": ["txn_id"]}),
            output_schema: json!({"type": "object", "properties": {"result": {"description": "Commit confirmation"}}}),
            capability: CapabilityId::from_static("pg.write"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "Use to commit an open transaction and persist changes".into(),
                common_mistakes: vec!["Committing an already closed transaction".into()],
                examples: vec![],
                related: vec![CapabilityId::from_static("pg.write")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("pg.transaction.rollback"),
            summary: "Rollback a database transaction".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"txn_id": {"type": "string", "description": "Transaction ID to rollback"}}, "required": ["txn_id"]}),
            output_schema: json!({"type": "object", "properties": {"result": {"description": "Rollback confirmation"}}}),
            capability: CapabilityId::from_static("pg.write"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "Use to rollback an open transaction and discard changes".into(),
                common_mistakes: vec!["Rolling back an already committed transaction".into()],
                examples: vec![],
                related: vec![CapabilityId::from_static("pg.write")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("pg.batch"),
            summary: "Execute multiple SQL statements in order".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"statements": {"type": "array", "items": {"type": "string"}, "description": "SQL statements to execute"}, "params": {"type": "array", "description": "Parameters for each statement"}}, "required": ["statements"]}),
            output_schema: json!({"type": "object", "properties": {"results": {"description": "Results for each statement"}}}),
            capability: CapabilityId::from_static("pg.write"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "Use to execute multiple related statements sequentially".into(),
                common_mistakes: vec!["Not wrapping in a transaction for atomicity".into()],
                examples: vec![],
                related: vec![CapabilityId::from_static("pg.write")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("pg.prepared"),
            summary: "Execute a named prepared statement".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {"name": {"type": "string", "description": "Name of the prepared statement"}, "params": {"type": "array", "description": "Parameters to bind"}}, "required": ["name"]}),
            output_schema: json!({"type": "object", "properties": {"result": {"description": "Prepared statement execution result"}}}),
            capability: CapabilityId::from_static("pg.write"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "Use to execute a pre-registered prepared statement by name".into(),
                common_mistakes: vec!["Using a statement name that has not been prepared".into()],
                examples: vec![],
                related: vec![CapabilityId::from_static("pg.write")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("pg.health"),
            summary: "Check database connectivity and health".into(),
            description: None,
            input_schema: json!({"type": "object", "properties": {}}),
            output_schema: json!({"type": "object", "properties": {"health": {"description": "Database health status"}}}),
            capability: CapabilityId::from_static("pg.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to verify the database connection is alive and responsive".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![CapabilityId::from_static("pg.read")],
            },
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

/// Build the operations info for introspection (JSON format for simulate).
fn operations_info() -> serde_json::Value {
    serde_json::to_value(typed_operations_info()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configure_with_base_url(base_url: &str) -> FcpResult<PostgresConfig> {
        PostgresConfig::from_params(&json!({
            "api_key": "test-key",
            "base_url": base_url
        }))
    }

    fn require_invalid_base_url(base_url: &str, expected: &str) -> Result<(), String> {
        match configure_with_base_url(base_url) {
            Err(FcpError::InvalidRequest { message, .. }) if message.contains(expected) => Ok(()),
            Err(FcpError::InvalidRequest { message, .. }) => Err(format!(
                "expected error containing {expected:?}, got {message:?}"
            )),
            Err(other) => Err(format!("expected InvalidRequest, got {other:?}")),
            Ok(config) => Err(format!(
                "base_url should be rejected, got {:?}",
                config.base_url
            )),
        }
    }

    #[test]
    fn configure_accepts_https_postgrest_base_url() -> Result<(), String> {
        let config = configure_with_base_url(" https://project.supabase.co/rest/v1/ ")
            .map_err(|error| format!("{error:?}"))?;

        if config.base_url != "https://project.supabase.co/rest/v1" {
            return Err(format!("unexpected base_url {:?}", config.base_url));
        }
        Ok(())
    }

    #[test]
    fn configure_accepts_local_http_test_base_url() -> Result<(), String> {
        let config = configure_with_base_url("http://127.0.0.1:54321/rest/v1/")
            .map_err(|error| format!("{error:?}"))?;

        if config.base_url != "http://127.0.0.1:54321/rest/v1" {
            return Err(format!("unexpected base_url {:?}", config.base_url));
        }
        Ok(())
    }

    #[test]
    fn configure_rejects_base_url_userinfo() -> Result<(), String> {
        require_invalid_base_url("https://user:pass@project.supabase.co/rest/v1", "userinfo")
    }

    #[test]
    fn configure_rejects_base_url_query_and_fragment() -> Result<(), String> {
        require_invalid_base_url(
            "https://project.supabase.co/rest/v1?select=value",
            "query string or fragment",
        )?;
        require_invalid_base_url(
            "https://project.supabase.co/rest/v1#section",
            "query string or fragment",
        )
    }

    #[test]
    fn configure_rejects_non_local_http_base_url() -> Result<(), String> {
        require_invalid_base_url(
            "http://project.supabase.co/rest/v1",
            "https unless targeting localhost",
        )
    }

    #[test]
    fn configure_rejects_invalid_base_url_scheme() -> Result<(), String> {
        require_invalid_base_url("ftp://project.supabase.co/rest/v1", "http or https")
    }
}
