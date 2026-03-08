//! FCP `Snowflake` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, FcpError, FcpResult, IdempotencyClass,
    OperationId, OperationInfo, RiskLevel, SafetyTier,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{SnowflakeAuth, SnowflakeClient},
    error::SnowflakeError,
};

/// Parsed and validated `Snowflake` connector configuration.
#[derive(Debug, Clone)]
struct SnowflakeConfig {
    auth: SnowflakeAuth,
    base_url: Option<String>,
    warehouse: Option<String>,
    database: Option<String>,
    schema: Option<String>,
}

impl SnowflakeConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let access_token = params
            .get("access_token")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing or empty access_token in configuration".into(),
            })?
            .to_string();

        let account_identifier = params
            .get("account_identifier")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing or empty account_identifier in configuration".into(),
            })?
            .to_string();

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        let warehouse = params
            .get("warehouse")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        let database = params
            .get("database")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        let schema = params
            .get("schema")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        Ok(Self {
            auth: SnowflakeAuth {
                access_token,
                account_identifier,
            },
            base_url,
            warehouse,
            database,
            schema,
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

/// FCP `Snowflake` Connector.
pub struct SnowflakeConnector {
    base: Arc<BaseConnector>,
    config: Option<SnowflakeConfig>,
    client: Option<Arc<SnowflakeClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl SnowflakeConnector {
    /// Create a new `Snowflake` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("snowflake"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for SnowflakeConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl SnowflakeConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = SnowflakeConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), "Configuring Snowflake connector");

        let client = SnowflakeClient::new(
            config.auth.clone(),
            config.base_url.as_deref(),
            config.warehouse.clone(),
            config.database.clone(),
            config.schema.clone(),
        )
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
            "connector_id": "fcp.snowflake",
            "connector_version": "0.1.0",
            "capabilities": [
                "snowflake.databases.read",
                "snowflake.warehouses.read",
                "snowflake.sql.read",
                "snowflake.sql.write"
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
        Ok(serde_json::to_value(result).unwrap_or(json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.snowflake",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.snowflake",
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

        let input = params.get("input").cloned().unwrap_or(json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "snowflake.databases.list" => self.invoke_databases_list(client).await,
            "snowflake.warehouses.list" => self.invoke_warehouses_list(client).await,
            "snowflake.sql.query" => self.invoke_sql_query(client, &input).await,
            "snowflake.sql.execute" => self.invoke_sql_execute(client, &input).await,
            "snowflake.tables.list" => self.invoke_tables_list(client, &input).await,
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
        info!("Snowflake connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_databases_list(
        &self,
        client: &SnowflakeClient,
    ) -> Result<serde_json::Value, SnowflakeError> {
        let data = client.list_databases().await?;
        Ok(json!({ "databases": data }))
    }

    async fn invoke_warehouses_list(
        &self,
        client: &SnowflakeClient,
    ) -> Result<serde_json::Value, SnowflakeError> {
        let data = client.list_warehouses().await?;
        Ok(json!({ "warehouses": data }))
    }

    async fn invoke_sql_query(
        &self,
        client: &SnowflakeClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SnowflakeError> {
        let statement = require_str(input, "statement")?;
        let warehouse = input.get("warehouse").and_then(serde_json::Value::as_str);
        let database = input.get("database").and_then(serde_json::Value::as_str);
        let schema = input.get("schema").and_then(serde_json::Value::as_str);

        let data = client
            .sql_query(statement, warehouse, database, schema)
            .await?;

        // Wrap the response to match the output schema
        let rows = data.get("data").cloned().unwrap_or(serde_json::Value::Null);
        let metadata = data
            .get("resultSetMetaData")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let handle = data
            .get("statementHandle")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        Ok(json!({
            "data": rows,
            "metadata": metadata,
            "statement_handle": handle,
        }))
    }

    async fn invoke_sql_execute(
        &self,
        client: &SnowflakeClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SnowflakeError> {
        let statement = require_str(input, "statement")?;
        let warehouse = input.get("warehouse").and_then(serde_json::Value::as_str);
        let database = input.get("database").and_then(serde_json::Value::as_str);
        let schema = input.get("schema").and_then(serde_json::Value::as_str);

        let data = client
            .sql_execute(statement, warehouse, database, schema)
            .await?;

        let status = data
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("executed")
            .to_string();
        let handle = data
            .get("statementHandle")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        Ok(json!({
            "status": status,
            "statement_handle": handle,
        }))
    }

    async fn invoke_tables_list(
        &self,
        client: &SnowflakeClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SnowflakeError> {
        let database = require_str(input, "database")?;
        let schema = input.get("schema").and_then(serde_json::Value::as_str);

        let data = client.list_tables(database, schema).await?;

        let rows = data.get("data").cloned().unwrap_or(serde_json::Value::Null);
        Ok(json!({ "tables": rows }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, SnowflakeError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| SnowflakeError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build a single [`OperationInfo`].
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
        description: None,
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints,
        rate_limit: None,
        requires_approval: None,
    }
}

/// Build the operations info for introspection.
fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "snowflake.databases.list",
            "List databases",
            json!({
                "type": "object",
                "required": [],
                "properties": {}
            }),
            json!({
                "type": "object",
                "required": ["databases"],
                "properties": {
                    "databases": { "type": "array" }
                }
            }),
            "snowflake.databases.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List available Snowflake databases.".into(),
                common_mistakes: vec![
                    "Forgetting that database names in Snowflake are case-insensitive but stored as uppercase by default.".into(),
                ],
                examples: vec![r#"{}"#.into()],
                related: vec![
                    CapabilityId::from_static("snowflake.sql.query"),
                    CapabilityId::from_static("snowflake.warehouses.list"),
                ],
            },
        ),
        op_info(
            "snowflake.warehouses.list",
            "List available warehouses",
            json!({
                "type": "object",
                "required": [],
                "properties": {}
            }),
            json!({
                "type": "object",
                "required": ["warehouses"],
                "properties": {
                    "warehouses": { "type": "array" }
                }
            }),
            "snowflake.warehouses.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List available Snowflake warehouses.".into(),
                common_mistakes: vec![
                    "Assuming listed warehouses are running — suspended warehouses will auto-resume on query but incur startup latency.".into(),
                ],
                examples: vec![r#"{}"#.into()],
                related: vec![CapabilityId::from_static("snowflake.sql.query")],
            },
        ),
        op_info(
            "snowflake.sql.query",
            "Execute a SQL query",
            json!({
                "type": "object",
                "required": ["statement"],
                "properties": {
                    "statement": { "type": "string", "description": "SQL statement to execute" },
                    "warehouse": { "type": "string" },
                    "database": { "type": "string" },
                    "schema": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["data"],
                "properties": {
                    "data": { "type": "array" }
                }
            }),
            "snowflake.sql.read",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Execute a SQL query against Snowflake.".into(),
                common_mistakes: vec![
                    "Running unbounded queries without LIMIT.".into(),
                    "Forgetting to specify warehouse.".into(),
                ],
                examples: vec![
                    r#"{"statement": "SELECT * FROM orders LIMIT 100", "warehouse": "COMPUTE_WH", "database": "ANALYTICS"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("snowflake.databases.list"),
                    CapabilityId::from_static("snowflake.warehouses.list"),
                ],
            },
        ),
        op_info(
            "snowflake.sql.execute",
            "Execute a SQL statement (DDL/DML)",
            json!({
                "type": "object",
                "required": ["statement"],
                "properties": {
                    "statement": { "type": "string", "description": "SQL DDL/DML statement" },
                    "warehouse": { "type": "string" },
                    "database": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["status"],
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            "snowflake.sql.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Execute DDL/DML statements (CREATE, INSERT, UPDATE, DELETE, DROP).".into(),
                common_mistakes: vec![
                    "Running DROP without confirmation.".into(),
                    "Forgetting to specify the correct database context.".into(),
                ],
                examples: vec![
                    r#"{"statement": "CREATE TABLE test (id INT, name VARCHAR)", "warehouse": "COMPUTE_WH", "database": "DEV"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("snowflake.sql.query")],
            },
        ),
        op_info(
            "snowflake.tables.list",
            "List tables in a database/schema",
            json!({
                "type": "object",
                "required": ["database"],
                "properties": {
                    "database": { "type": "string" },
                    "schema": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["tables"],
                "properties": {
                    "tables": { "type": "array" }
                }
            }),
            "snowflake.databases.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List tables in a database, optionally filtered by schema.".into(),
                common_mistakes: vec![
                    "Omitting the schema parameter and getting tables from all schemas, including INFORMATION_SCHEMA.".into(),
                ],
                examples: vec![
                    r#"{"database": "ANALYTICS", "schema": "PUBLIC"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("snowflake.databases.list"),
                    CapabilityId::from_static("snowflake.sql.query"),
                ],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ops_json() -> serde_json::Value {
        serde_json::to_value(operations_info()).unwrap()
    }

    #[test]
    fn config_from_valid_params() {
        let config = SnowflakeConfig::from_params(&json!({
            "access_token": "token123",
            "account_identifier": "myaccount",
        }))
        .unwrap();
        assert_eq!(config.auth.access_token, "token123");
        assert_eq!(config.auth.account_identifier, "myaccount");
        assert!(config.base_url.is_none());
        assert!(config.warehouse.is_none());
    }

    #[test]
    fn config_with_all_options() {
        let config = SnowflakeConfig::from_params(&json!({
            "access_token": "token",
            "account_identifier": "acc",
            "base_url": "https://test.snowflakecomputing.com/api/v2",
            "warehouse": "COMPUTE_WH",
            "database": "ANALYTICS",
            "schema": "PUBLIC",
        }))
        .unwrap();
        assert_eq!(
            config.base_url,
            Some("https://test.snowflakecomputing.com/api/v2".into())
        );
        assert_eq!(config.warehouse, Some("COMPUTE_WH".into()));
        assert_eq!(config.database, Some("ANALYTICS".into()));
        assert_eq!(config.schema, Some("PUBLIC".into()));
    }

    #[test]
    fn config_rejects_missing_access_token() {
        let result = SnowflakeConfig::from_params(&json!({
            "account_identifier": "myaccount",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_missing_account_identifier() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": "token",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_access_token() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": "",
            "account_identifier": "acc",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_account_identifier() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": "token",
            "account_identifier": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_access_token() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": "   ",
            "account_identifier": "acc",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_account_identifier() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": "token",
            "account_identifier": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_params() {
        let result = SnowflakeConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_access_token() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": 12345,
            "account_identifier": "acc",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_account_identifier() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": "token",
            "account_identifier": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_trims_access_token() {
        let config = SnowflakeConfig::from_params(&json!({
            "access_token": "  token  ",
            "account_identifier": "acc",
        }))
        .unwrap();
        assert_eq!(config.auth.access_token, "token");
    }

    #[test]
    fn config_trims_account_identifier() {
        let config = SnowflakeConfig::from_params(&json!({
            "access_token": "token",
            "account_identifier": "  acc  ",
        }))
        .unwrap();
        assert_eq!(config.auth.account_identifier, "acc");
    }

    #[test]
    fn config_rejects_null_access_token() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": null,
            "account_identifier": "acc",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_null_account_identifier() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": "token",
            "account_identifier": null,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"statement": "SELECT 1"});
        assert_eq!(require_str(&input, "statement").unwrap(), "SELECT 1");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "statement").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"statement": 42});
        assert!(require_str(&input, "statement").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"statement": null});
        assert!(require_str(&input, "statement").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"statement": true});
        assert!(require_str(&input, "statement").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"statement": ["a", "b"]});
        assert!(require_str(&input, "statement").is_err());
    }

    #[test]
    fn operations_info_has_5_operations() {
        let ops = ops_json();
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 5);
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            assert!(op.get("id").is_some(), "missing id");
            assert!(op.get("summary").is_some(), "missing summary");
            assert!(op.get("capability").is_some(), "missing capability");
            assert!(op.get("risk_level").is_some(), "missing risk_level");
            assert!(op.get("safety_tier").is_some(), "missing safety_tier");
        }
    }

    #[test]
    fn operations_ids_are_unique() {
        let ops = ops_json();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "duplicate operation IDs found");
    }

    #[test]
    fn operations_risk_levels_valid() {
        let valid = ["low", "medium", "high"];
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_operations_are_safe_or_risky() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".read") {
                let tier = op["safety_tier"].as_str().unwrap();
                assert!(
                    tier == "safe" || tier == "risky",
                    "read op {} should be safe or risky, got {tier}",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn operations_contain_expected_ids() {
        let ops = ops_json();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        assert!(ids.contains(&"snowflake.databases.list"));
        assert!(ids.contains(&"snowflake.warehouses.list"));
        assert!(ids.contains(&"snowflake.sql.query"));
        assert!(ids.contains(&"snowflake.sql.execute"));
        assert!(ids.contains(&"snowflake.tables.list"));
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            assert!(
                op.get("idempotency").is_some(),
                "op {:?} missing idempotency",
                op["id"]
            );
        }
    }

    #[test]
    fn operations_execute_is_dangerous() {
        let ops = ops_json();
        let exec_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "snowflake.sql.execute")
            .unwrap();
        assert_eq!(exec_op["safety_tier"], "dangerous");
        assert_eq!(exec_op["risk_level"], "high");
    }

    #[test]
    fn operations_query_is_risky() {
        let ops = ops_json();
        let query_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "snowflake.sql.query")
            .unwrap();
        assert_eq!(query_op["safety_tier"], "risky");
        assert_eq!(query_op["risk_level"], "medium");
    }

    #[test]
    fn operations_databases_list_capability() {
        let ops = ops_json();
        let db_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "snowflake.databases.list")
            .unwrap();
        assert_eq!(db_op["capability"], "snowflake.databases.read");
    }

    #[test]
    fn operations_warehouses_list_capability() {
        let ops = ops_json();
        let wh_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "snowflake.warehouses.list")
            .unwrap();
        assert_eq!(wh_op["capability"], "snowflake.warehouses.read");
    }

    #[test]
    fn doctor_result_healthy_when_all_pass() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_degraded_when_non_critical_fails() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("warn".into()),
                critical: false,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_result_unhealthy_when_critical_fails() {
        let checks = vec![DoctorCheck {
            name: "config".into(),
            passed: false,
            message: Some("not configured".into()),
            critical: true,
        }];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_serializes() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "healthy");
        assert!(v["checks"][0]["message"].is_null());
    }

    #[test]
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_multiple_critical_failures() {
        let checks = vec![
            DoctorCheck {
                name: "a".into(),
                passed: false,
                message: Some("fail a".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: Some("fail b".into()),
                critical: true,
            },
        ];
        let r = DoctorResult::from_checks(checks);
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 2);
    }

    #[test]
    fn connector_default() {
        let c = SnowflakeConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn connector_new_has_no_config() {
        let c = SnowflakeConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[test]
    fn connector_new_zero_counters() {
        let c = SnowflakeConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn doctor_status_serde_roundtrip_healthy() {
        let v = serde_json::to_value(DoctorStatus::Healthy).unwrap();
        assert_eq!(v, "healthy");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_status_serde_roundtrip_degraded() {
        let v = serde_json::to_value(DoctorStatus::Degraded).unwrap();
        assert_eq!(v, "degraded");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Degraded);
    }

    #[test]
    fn doctor_status_serde_roundtrip_unhealthy() {
        let v = serde_json::to_value(DoctorStatus::Unhealthy).unwrap();
        assert_eq!(v, "unhealthy");
        let back: DoctorStatus = serde_json::from_value(v).unwrap();
        assert_eq!(back, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_status_copy() {
        let s = DoctorStatus::Healthy;
        let copied = s;
        assert_eq!(s, copied);
    }

    #[test]
    fn doctor_status_debug() {
        let dbg = format!("{:?}", DoctorStatus::Degraded);
        assert!(dbg.contains("Degraded"));
    }

    #[test]
    fn doctor_result_deserializes() {
        let v = json!({
            "status": "unhealthy",
            "checks": [
                {"name": "config", "passed": false, "message": "fail", "critical": true}
            ]
        });
        let r: DoctorResult = serde_json::from_value(v).unwrap();
        assert_eq!(r.status, DoctorStatus::Unhealthy);
        assert_eq!(r.checks.len(), 1);
    }

    #[test]
    fn doctor_check_deserializes() {
        let v = json!({"name": "test", "passed": true, "critical": false});
        let c: DoctorCheck = serde_json::from_value(v).unwrap();
        assert_eq!(c.name, "test");
        assert!(c.passed);
        assert!(c.message.is_none());
    }

    #[test]
    fn doctor_check_clone() {
        let c = DoctorCheck {
            name: "cfg".into(),
            passed: true,
            message: Some("ok".into()),
            critical: true,
        };
        let cloned = DoctorCheck::clone(&c);
        assert_eq!(cloned.name, "cfg");
        assert_eq!(cloned.message, Some("ok".into()));
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "a".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let cloned = DoctorResult::clone(&r);
        assert_eq!(cloned.status, DoctorStatus::Healthy);
        assert_eq!(cloned.checks.len(), 1);
    }

    #[test]
    fn config_rejects_boolean_access_token() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": true,
            "account_identifier": "acc",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_boolean_account_identifier() {
        let result = SnowflakeConfig::from_params(&json!({
            "access_token": "token",
            "account_identifier": true,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_with_empty_string() {
        let input = json!({"statement": ""});
        assert_eq!(require_str(&input, "statement").unwrap(), "");
    }

    #[test]
    fn require_str_with_object_value() {
        let input = json!({"statement": {"nested": true}});
        assert!(require_str(&input, "statement").is_err());
    }

    #[test]
    fn operations_summaries_non_empty() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let summary = op["summary"].as_str().unwrap();
            assert!(!summary.is_empty(), "op {} has empty summary", op["id"]);
        }
    }

    #[test]
    fn operations_tables_list_capability() {
        let ops = ops_json();
        let t_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "snowflake.tables.list")
            .unwrap();
        assert_eq!(t_op["capability"], "snowflake.databases.read");
    }

    #[test]
    fn doctor_check_serializes_without_message_when_none() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_check_serializes_with_message_when_some() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failed".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["message"], "failed");
    }
}
