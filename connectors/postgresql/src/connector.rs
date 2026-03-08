//! FCP `PostgreSQL` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, CredentialId, FcpError, FcpResult,
    IdempotencyClass, OperationId, OperationInfo, RiskLevel, SafetyTier,
};
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

impl PostgresConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_key = params
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

        let auth = match (api_key, credential_id) {
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

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

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
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.postgresql",
            "version": "0.1.0",
            "operations": serde_json::to_value(operations_info()).unwrap_or_default(),
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

        let allowed = operations_info().iter().any(|o| o.id.as_ref() == operation);

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

/// Construct a single [`OperationInfo`].
#[allow(clippy::too_many_arguments)]
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

/// Build the operations info for introspection.
fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "pg.query",
            "Execute a parameterized SQL query (returns rows)",
            json!({"type":"object","required":["sql"],"properties":{"sql":{"type":"string","description":"SQL query to execute"},"params":{"type":"array","description":"Positional parameters for the query"},"timeout_ms":{"type":"integer","description":"Query timeout in milliseconds"}}}),
            json!({"type":"object","required":["result"],"properties":{"result":{"description":"Query result with rows and metadata"}}}),
            "pg.read", RiskLevel::Low, SafetyTier::Safe, IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Execute a read-only SQL query with optional parameterized values. Use for SELECT statements.".into(),
                common_mistakes: vec!["Forgetting to use parameterized queries ($1, $2) — never interpolate user input into SQL strings.".into(), "Omitting timeout_ms for long-running analytical queries.".into()],
                examples: vec![r#"{"sql": "SELECT id, name FROM users WHERE status = $1 LIMIT 100", "params": ["active"], "timeout_ms": 5000}"#.into()],
                related: vec![CapabilityId::from_static("pg.explain"), CapabilityId::from_static("pg.schema.tables")],
            },
        ),
        op_info(
            "pg.execute",
            "Execute a non-returning SQL statement (returns affected_rows)",
            json!({"type":"object","required":["sql"],"properties":{"sql":{"type":"string","description":"SQL statement to execute"},"params":{"type":"array","description":"Positional parameters for the statement"}}}),
            json!({"type":"object","required":["result"],"properties":{"result":{"description":"Execution result with affected_rows"}}}),
            "pg.write", RiskLevel::Medium, SafetyTier::Risky, IdempotencyClass::None,
            AgentHint {
                when_to_use: "Execute INSERT, UPDATE, DELETE, or DDL statements that do not return rows.".into(),
                common_mistakes: vec!["Using pg.execute for SELECT — use pg.query instead to get rows back.".into(), "Running destructive DDL (DROP TABLE) without confirmation.".into()],
                examples: vec![r#"{"sql": "UPDATE users SET status = $1 WHERE last_login < $2", "params": ["inactive", "2025-01-01"]}"#.into()],
                related: vec![CapabilityId::from_static("pg.query"), CapabilityId::from_static("pg.batch"), CapabilityId::from_static("pg.transaction.begin")],
            },
        ),
        op_info(
            "pg.explain",
            "Explain query plan for a SQL query",
            json!({"type":"object","required":["sql"],"properties":{"sql":{"type":"string","description":"SQL query to explain"},"params":{"type":"array","description":"Positional parameters for the query"}}}),
            json!({"type":"object","required":["plan"],"properties":{"plan":{"description":"Query execution plan"}}}),
            "pg.read", RiskLevel::Low, SafetyTier::Safe, IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Analyze the query execution plan before running an expensive query. Use to debug slow queries.".into(),
                common_mistakes: vec!["Running EXPLAIN on trivial queries where the plan is obvious.".into()],
                examples: vec![r#"{"sql": "SELECT * FROM orders WHERE customer_id = $1 AND created_at > $2", "params": ["cust_123", "2025-01-01"]}"#.into()],
                related: vec![CapabilityId::from_static("pg.query")],
            },
        ),
        op_info(
            "pg.schema.tables",
            "List tables in a database schema",
            json!({"type":"object","required":[],"properties":{"schema":{"type":"string","description":"Schema name (default: public)"}}}),
            json!({"type":"object","required":["tables"],"properties":{"tables":{"type":"array","description":"List of tables with name, schema, and row_count_estimate"}}}),
            "pg.read", RiskLevel::Low, SafetyTier::Safe, IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Discover available tables in the database. Start here when exploring an unfamiliar schema.".into(),
                common_mistakes: vec!["Assuming tables are in the public schema — always check with schema parameter if unsure.".into()],
                examples: vec![r#"{"schema": "public"}"#.into(), r"{}".into()],
                related: vec![CapabilityId::from_static("pg.schema.columns"), CapabilityId::from_static("pg.schema.indexes")],
            },
        ),
        op_info(
            "pg.schema.columns",
            "Get column details for a table",
            json!({"type":"object","required":["table"],"properties":{"table":{"type":"string","description":"Table name"}}}),
            json!({"type":"object","required":["columns"],"properties":{"columns":{"type":"array","description":"List of columns with name, data_type, nullable, default_value, is_primary_key"}}}),
            "pg.read", RiskLevel::Low, SafetyTier::Safe, IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Inspect column names, types, and constraints for a specific table before writing queries.".into(),
                common_mistakes: vec!["Not checking column types before inserting data — type mismatches cause runtime errors.".into()],
                examples: vec![r#"{"table": "users"}"#.into()],
                related: vec![CapabilityId::from_static("pg.schema.tables"), CapabilityId::from_static("pg.schema.indexes")],
            },
        ),
        op_info(
            "pg.schema.indexes",
            "List indexes for a table",
            json!({"type":"object","required":["table"],"properties":{"table":{"type":"string","description":"Table name"}}}),
            json!({"type":"object","required":["indexes"],"properties":{"indexes":{"type":"array","description":"List of indexes with name, table, columns, unique, type"}}}),
            "pg.read", RiskLevel::Low, SafetyTier::Safe, IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Check available indexes on a table to understand query performance characteristics.".into(),
                common_mistakes: vec!["Assuming an index exists — always verify before relying on indexed lookups in queries.".into()],
                examples: vec![r#"{"table": "orders"}"#.into()],
                related: vec![CapabilityId::from_static("pg.schema.tables"), CapabilityId::from_static("pg.schema.columns")],
            },
        ),
        op_info(
            "pg.transaction.begin",
            "Start a new database transaction",
            json!({"type":"object","required":[],"properties":{"isolation_level":{"type":"string","description":"Isolation level: read_committed, repeatable_read, serializable"}}}),
            json!({"type":"object","required":["result"],"properties":{"result":{"description":"Transaction info including txn_id"}}}),
            "pg.write", RiskLevel::Low, SafetyTier::Safe, IdempotencyClass::None,
            AgentHint {
                when_to_use: "Start a transaction when you need atomicity across multiple statements. Always commit or rollback.".into(),
                common_mistakes: vec!["Forgetting to commit or rollback — abandoned transactions hold locks.".into(), "Using serializable isolation when read_committed suffices — causes unnecessary contention.".into()],
                examples: vec![r#"{"isolation_level": "read_committed"}"#.into(), r"{}".into()],
                related: vec![CapabilityId::from_static("pg.transaction.commit"), CapabilityId::from_static("pg.transaction.rollback"), CapabilityId::from_static("pg.execute")],
            },
        ),
        op_info(
            "pg.transaction.commit",
            "Commit a database transaction",
            json!({"type":"object","required":["txn_id"],"properties":{"txn_id":{"type":"string","description":"Transaction ID to commit"}}}),
            json!({"type":"object","required":["result"],"properties":{"result":{"description":"Commit confirmation"}}}),
            "pg.write", RiskLevel::Low, SafetyTier::Safe, IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Commit a previously started transaction to make all changes permanent.".into(),
                common_mistakes: vec!["Committing a transaction that has already been rolled back.".into()],
                examples: vec![r#"{"txn_id": "txn_abc123"}"#.into()],
                related: vec![CapabilityId::from_static("pg.transaction.begin"), CapabilityId::from_static("pg.transaction.rollback")],
            },
        ),
        op_info(
            "pg.transaction.rollback",
            "Rollback a database transaction",
            json!({"type":"object","required":["txn_id"],"properties":{"txn_id":{"type":"string","description":"Transaction ID to rollback"}}}),
            json!({"type":"object","required":["result"],"properties":{"result":{"description":"Rollback confirmation"}}}),
            "pg.write", RiskLevel::Low, SafetyTier::Safe, IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Undo all changes in a transaction. Use when an error occurs mid-transaction.".into(),
                common_mistakes: vec!["Rolling back a transaction that has already been committed.".into()],
                examples: vec![r#"{"txn_id": "txn_abc123"}"#.into()],
                related: vec![CapabilityId::from_static("pg.transaction.begin"), CapabilityId::from_static("pg.transaction.commit")],
            },
        ),
        op_info(
            "pg.batch",
            "Execute multiple SQL statements in order",
            json!({"type":"object","required":["statements"],"properties":{"statements":{"type":"array","description":"SQL statements to execute in order"},"params":{"type":"array","description":"Parameters for each statement"}}}),
            json!({"type":"object","required":["results"],"properties":{"results":{"description":"Results for each statement"}}}),
            "pg.write", RiskLevel::Medium, SafetyTier::Risky, IdempotencyClass::None,
            AgentHint {
                when_to_use: "Execute multiple SQL statements sequentially in a single call. More efficient than separate pg.execute calls.".into(),
                common_mistakes: vec!["Not wrapping batch in a transaction — partial failures leave data in an inconsistent state.".into(), "Sending too many statements in one batch — keep batches under 100 statements.".into()],
                examples: vec![r#"{"statements": ["INSERT INTO logs (msg) VALUES ($1)", "UPDATE counters SET n = n + 1 WHERE name = $1"], "params": [["hello"], ["log_count"]]}"#.into()],
                related: vec![CapabilityId::from_static("pg.execute"), CapabilityId::from_static("pg.transaction.begin")],
            },
        ),
        op_info(
            "pg.prepared",
            "Execute a named prepared statement",
            json!({"type":"object","required":["name"],"properties":{"name":{"type":"string","description":"Name of the prepared statement"},"params":{"type":"array","description":"Parameters to bind"}}}),
            json!({"type":"object","required":["result"],"properties":{"result":{"description":"Prepared statement execution result"}}}),
            "pg.write", RiskLevel::Medium, SafetyTier::Risky, IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Execute a server-side prepared statement by name. More efficient for repeated queries with different parameters.".into(),
                common_mistakes: vec!["Referencing a prepared statement name that does not exist on the server.".into(), "Not providing all required parameters for the prepared statement.".into()],
                examples: vec![r#"{"name": "get_user_by_id", "params": [42]}"#.into()],
                related: vec![CapabilityId::from_static("pg.query"), CapabilityId::from_static("pg.execute")],
            },
        ),
        op_info(
            "pg.health",
            "Check database connectivity and health",
            json!({"type":"object","required":[]}),
            json!({"type":"object","required":["health"],"properties":{"health":{"description":"Database health status"}}}),
            "pg.read", RiskLevel::Low, SafetyTier::Safe, IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Verify the database is reachable and responding before running queries.".into(),
                common_mistakes: vec!["Polling health too frequently — once before a batch of work is sufficient.".into()],
                examples: vec![r"{}".into()],
                related: vec![CapabilityId::from_static("pg.query")],
            },
        ),
    ]
}
