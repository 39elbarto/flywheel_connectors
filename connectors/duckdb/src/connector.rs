//! FCP `DuckDB` `MotherDuck` Connector implementation.

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
    client::{DEFAULT_BASE_URL, DuckDbAuth, DuckDbClient},
    error::DuckDbError,
};

/// Parsed and validated `DuckDB` connector configuration.
#[derive(Debug, Clone)]
struct DuckDbConfig {
    auth: DuckDbAuth,
    base_url: String,
    default_database: Option<String>,
}

impl DuckDbConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let service_token = params
            .get("service_token")
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

        let auth = match (service_token, credential_id) {
            (Some(key), None) => DuckDbAuth::ServiceToken(key),
            (None, Some(cred_id)) => DuckDbAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of service_token or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing service_token or credential_id in configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        let default_database = params
            .get("database")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        Ok(Self {
            auth,
            base_url,
            default_database,
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

/// FCP `DuckDB` `MotherDuck` Connector.
pub struct DuckDbConnector {
    base: Arc<BaseConnector>,
    config: Option<DuckDbConfig>,
    client: Option<Arc<DuckDbClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl DuckDbConnector {
    /// Create a new `DuckDB` `MotherDuck` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("duckdb"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for DuckDbConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl DuckDbConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = DuckDbConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring DuckDB MotherDuck connector");

        let client = DuckDbClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.duckdb",
            "connector_version": "0.1.0",
            "capabilities": [
                "duckdb.read",
                "duckdb.write"
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
            "connector_id": "fcp.duckdb",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.duckdb",
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
            "duckdb.query.execute" => self.invoke_query_execute(client, &input).await,
            "duckdb.databases.list" => self.invoke_databases_list(client).await,
            "duckdb.databases.get" => self.invoke_databases_get(client, &input).await,
            "duckdb.tables.list" => self.invoke_tables_list(client, &input).await,
            "duckdb.tables.get" => self.invoke_tables_get(client, &input).await,
            "duckdb.schemas.list" => self.invoke_schemas_list(client, &input).await,
            "duckdb.queries.status" => self.invoke_queries_status(client, &input).await,
            "duckdb.shares.list" => self.invoke_shares_list(client).await,
            "duckdb.shares.create" => self.invoke_shares_create(client, &input).await,
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
        info!("DuckDB MotherDuck connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_query_execute(
        &self,
        client: &DuckDbClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DuckDbError> {
        let sql = require_str(input, "sql")?;
        let database = input
            .get("database")
            .and_then(serde_json::Value::as_str)
            .or(self
                .config
                .as_ref()
                .and_then(|c| c.default_database.as_deref()));

        let mut body = json!({ "sql": sql });
        if let Some(db) = database {
            body["database"] = json!(db);
        }

        client.execute_query(&body).await
    }

    async fn invoke_databases_list(
        &self,
        client: &DuckDbClient,
    ) -> Result<serde_json::Value, DuckDbError> {
        let resp = client.list_databases().await?;
        let databases = resp.get("databases").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "databases": databases }))
    }

    async fn invoke_databases_get(
        &self,
        client: &DuckDbClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DuckDbError> {
        let database = require_str(input, "database")?;
        let resp = client.get_database(database).await?;
        Ok(json!({ "database": resp }))
    }

    async fn invoke_tables_list(
        &self,
        client: &DuckDbClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DuckDbError> {
        let database = require_str(input, "database")?;
        let resp = client.list_tables(database).await?;
        let tables = resp.get("tables").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "tables": tables }))
    }

    async fn invoke_tables_get(
        &self,
        client: &DuckDbClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DuckDbError> {
        let database = require_str(input, "database")?;
        let table = require_str(input, "table")?;
        let resp = client.get_table(database, table).await?;
        Ok(json!({ "table": resp }))
    }

    async fn invoke_schemas_list(
        &self,
        client: &DuckDbClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DuckDbError> {
        let database = require_str(input, "database")?;
        let resp = client.list_schemas(database).await?;
        let schemas = resp.get("schemas").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "schemas": schemas }))
    }

    async fn invoke_queries_status(
        &self,
        client: &DuckDbClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DuckDbError> {
        let query_id = require_str(input, "query_id")?;
        let resp = client.get_query_status(query_id).await?;
        Ok(json!({ "status": resp }))
    }

    async fn invoke_shares_list(
        &self,
        client: &DuckDbClient,
    ) -> Result<serde_json::Value, DuckDbError> {
        let resp = client.list_shares().await?;
        let shares = resp.get("shares").cloned().unwrap_or_else(|| json!([]));
        Ok(json!({ "shares": shares }))
    }

    async fn invoke_shares_create(
        &self,
        client: &DuckDbClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, DuckDbError> {
        let name = require_str(input, "name")?;
        let database = require_str(input, "database")?;
        let body = json!({
            "name": name,
            "database": database,
        });
        let resp = client.create_share(&body).await?;
        Ok(json!({ "share": resp }))
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, DuckDbError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| DuckDbError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build a single `OperationInfo` entry.
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
            "duckdb.query.execute",
            "Execute a SQL query via MotherDuck",
            json!({
                "type": "object",
                "required": ["sql"],
                "properties": {
                    "sql": { "type": "string", "description": "SQL query to execute" },
                    "database": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["rows"],
                "properties": { "rows": { "type": "array" } }
            }),
            "duckdb.write",
            RiskLevel::High,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Execute a SQL query against DuckDB via MotherDuck.".into(),
                common_mistakes: vec![
                    "Executing destructive DDL without confirmation".into(),
                ],
                examples: vec![
                    r#"{"sql": "SELECT count(*) FROM sales WHERE year = 2025"}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("duckdb.databases.list"),
                    CapabilityId::from_static("duckdb.tables.list"),
                ],
            },
        ),
        op_info(
            "duckdb.databases.list",
            "List databases in MotherDuck",
            json!({ "type": "object", "required": [] }),
            json!({
                "type": "object",
                "required": ["databases"],
                "properties": { "databases": { "type": "array" } }
            }),
            "duckdb.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all databases in MotherDuck.".into(),
                common_mistakes: vec![],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static("duckdb.tables.list")],
            },
        ),
        op_info(
            "duckdb.databases.get",
            "Get details of a specific database",
            json!({
                "type": "object",
                "required": ["database"],
                "properties": { "database": { "type": "string" } }
            }),
            json!({
                "type": "object",
                "required": ["database"],
                "properties": { "database": { "type": "object" } }
            }),
            "duckdb.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get details of a specific MotherDuck database.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"database": "analytics"}"#.into()],
                related: vec![CapabilityId::from_static("duckdb.databases.list")],
            },
        ),
        op_info(
            "duckdb.tables.list",
            "List tables in a database",
            json!({
                "type": "object",
                "required": ["database"],
                "properties": { "database": { "type": "string" } }
            }),
            json!({
                "type": "object",
                "required": ["tables"],
                "properties": { "tables": { "type": "array" } }
            }),
            "duckdb.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all tables in a DuckDB database.".into(),
                common_mistakes: vec![
                    "Expecting views and temporary tables to appear — only persistent base tables are listed.".into(),
                ],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static("duckdb.query")],
            },
        ),
        op_info(
            "duckdb.tables.get",
            "Get details of a specific table",
            json!({
                "type": "object",
                "required": ["database", "table"],
                "properties": {
                    "database": { "type": "string" },
                    "table": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["table"],
                "properties": { "table": { "type": "object" } }
            }),
            "duckdb.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get details of a specific table in a database.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"database": "analytics", "table": "events"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("duckdb.tables.list")],
            },
        ),
        op_info(
            "duckdb.schemas.list",
            "List schemas in a database",
            json!({
                "type": "object",
                "required": ["database"],
                "properties": { "database": { "type": "string" } }
            }),
            json!({
                "type": "object",
                "required": ["schemas"],
                "properties": { "schemas": { "type": "array" } }
            }),
            "duckdb.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all schemas in a DuckDB database.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"database": "analytics"}"#.into()],
                related: vec![CapabilityId::from_static("duckdb.tables.list")],
            },
        ),
        op_info(
            "duckdb.queries.status",
            "Get the status of a previously submitted query",
            json!({
                "type": "object",
                "required": ["query_id"],
                "properties": { "query_id": { "type": "string" } }
            }),
            json!({
                "type": "object",
                "required": ["status"],
                "properties": { "status": { "type": "object" } }
            }),
            "duckdb.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Check the status of a previously submitted query.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"query_id": "q-12345"}"#.into()],
                related: vec![CapabilityId::from_static("duckdb.query.execute")],
            },
        ),
        op_info(
            "duckdb.shares.list",
            "List shared databases",
            json!({ "type": "object", "required": [] }),
            json!({
                "type": "object",
                "required": ["shares"],
                "properties": { "shares": { "type": "array" } }
            }),
            "duckdb.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all shared databases in MotherDuck.".into(),
                common_mistakes: vec![],
                examples: vec!["{}".into()],
                related: vec![CapabilityId::from_static("duckdb.shares.create")],
            },
        ),
        op_info(
            "duckdb.shares.create",
            "Create a database share",
            json!({
                "type": "object",
                "required": ["name", "database"],
                "properties": {
                    "name": { "type": "string" },
                    "database": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["share"],
                "properties": { "share": { "type": "object" } }
            }),
            "duckdb.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new database share in MotherDuck.".into(),
                common_mistakes: vec![],
                examples: vec![
                    r#"{"name": "my_share", "database": "analytics"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("duckdb.shares.list")],
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
    fn config_from_service_token() {
        let config = DuckDbConfig::from_params(&json!({
            "service_token": "test-service-token",
        }))
        .unwrap();
        assert!(matches!(config.auth, DuckDbAuth::ServiceToken(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let config = DuckDbConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = DuckDbConfig::from_params(&json!({
            "service_token": "tok",
            "base_url": "https://motherduck.example.com/v0",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://motherduck.example.com/v0");
    }

    #[test]
    fn config_default_database() {
        let config = DuckDbConfig::from_params(&json!({
            "service_token": "tok",
            "database": "analytics",
        }))
        .unwrap();
        assert_eq!(config.default_database, Some("analytics".into()));
    }

    #[test]
    fn config_no_default_database() {
        let config = DuckDbConfig::from_params(&json!({
            "service_token": "tok",
        }))
        .unwrap();
        assert!(config.default_database.is_none());
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = DuckDbConfig::from_params(&json!({
            "service_token": "tok",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = DuckDbConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_service_token() {
        let result = DuckDbConfig::from_params(&json!({
            "service_token": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_service_token() {
        let result = DuckDbConfig::from_params(&json!({
            "service_token": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = DuckDbConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = DuckDbConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"database": "my_db"});
        assert_eq!(require_str(&input, "database").unwrap(), "my_db");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "database").is_err());
    }

    #[test]
    fn require_str_not_string() {
        let input = json!({"database": 42});
        assert!(require_str(&input, "database").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({"database": null});
        assert!(require_str(&input, "database").is_err());
    }

    #[test]
    fn operations_info_has_9_operations() {
        let ops = operations_info();
        assert_eq!(ops.len(), 9);
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
    fn read_operations_are_safe() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".read") {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "read op {} should be safe",
                    op["id"]
                );
                assert_eq!(
                    op["risk_level"].as_str().unwrap(),
                    "low",
                    "read op {} should be low risk",
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
        assert!(ids.contains(&"duckdb.query.execute"));
        assert!(ids.contains(&"duckdb.databases.list"));
        assert!(ids.contains(&"duckdb.databases.get"));
        assert!(ids.contains(&"duckdb.tables.list"));
        assert!(ids.contains(&"duckdb.tables.get"));
        assert!(ids.contains(&"duckdb.schemas.list"));
        assert!(ids.contains(&"duckdb.queries.status"));
        assert!(ids.contains(&"duckdb.shares.list"));
        assert!(ids.contains(&"duckdb.shares.create"));
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
    fn config_trims_service_token() {
        let config = DuckDbConfig::from_params(&json!({ "service_token": "  sk_test  " })).unwrap();
        match &config.auth {
            DuckDbAuth::ServiceToken(t) => assert_eq!(t, "sk_test"),
            DuckDbAuth::CredentialId(_) => panic!("expected ServiceToken"),
        }
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
    fn doctor_result_empty_checks() {
        let r = DoctorResult::from_checks(vec![]);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn connector_default() {
        let c = DuckDbConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn write_operations_are_risky() {
        let ops = ops_json();
        for op in ops.as_array().unwrap() {
            let cap = op["capability"].as_str().unwrap();
            if cap.ends_with(".write") {
                let tier = op["safety_tier"].as_str().unwrap();
                assert!(
                    tier == "risky" || tier == "dangerous",
                    "write op {} should be risky or dangerous, got {tier}",
                    op["id"]
                );
            }
        }
    }

    #[test]
    fn connector_new_has_no_config() {
        let c = DuckDbConnector::new();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
    }

    #[test]
    fn connector_request_count_starts_at_zero() {
        let c = DuckDbConnector::new();
        assert_eq!(c.request_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn connector_error_count_starts_at_zero() {
        let c = DuckDbConnector::new();
        assert_eq!(c.error_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn doctor_check_serializes_with_message() {
        let check = DoctorCheck {
            name: "test_check".into(),
            passed: false,
            message: Some("failure reason".into()),
            critical: true,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["name"], "test_check");
        assert_eq!(v["passed"], false);
        assert_eq!(v["message"], "failure reason");
        assert_eq!(v["critical"], true);
    }

    #[test]
    fn doctor_check_serializes_without_message() {
        let check = DoctorCheck {
            name: "ok_check".into(),
            passed: true,
            message: None,
            critical: false,
        };
        let v = serde_json::to_value(&check).unwrap();
        assert_eq!(v["name"], "ok_check");
        assert_eq!(v["passed"], true);
        assert!(!v.as_object().unwrap().contains_key("message"));
    }

    #[test]
    fn doctor_status_serde_roundtrip() {
        let statuses = [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ];
        for status in &statuses {
            let v = serde_json::to_value(status).unwrap();
            let back: DoctorStatus = serde_json::from_value(v).unwrap();
            assert_eq!(*status, back);
        }
    }

    #[test]
    fn doctor_result_clone() {
        let r = DoctorResult::from_checks(vec![DoctorCheck {
            name: "x".into(),
            passed: true,
            message: None,
            critical: false,
        }]);
        let c = r.clone();
        assert_eq!(c.status, DoctorStatus::Healthy);
        assert_eq!(c.checks.len(), 1);
        assert_eq!(r.status, DoctorStatus::Healthy);
    }

    #[test]
    fn operations_query_execute_is_risky() {
        let ops = ops_json();
        let query_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "duckdb.query.execute")
            .unwrap();
        assert_eq!(query_op["safety_tier"], "risky");
        assert_eq!(query_op["risk_level"], "high");
    }

    #[test]
    fn operations_shares_create_is_risky() {
        let ops = ops_json();
        let share_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "duckdb.shares.create")
            .unwrap();
        assert_eq!(share_op["safety_tier"], "risky");
        assert_eq!(share_op["risk_level"], "medium");
    }

    #[test]
    fn operations_databases_list_summary() {
        let ops = ops_json();
        let db_op = ops
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["id"] == "duckdb.databases.list")
            .unwrap();
        assert!(db_op["summary"].as_str().unwrap().len() > 5);
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({"database": true});
        assert!(require_str(&input, "database").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({"database": ["a", "b"]});
        assert!(require_str(&input, "database").is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({"database": {"nested": true}});
        assert!(require_str(&input, "database").is_err());
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
    fn config_with_database_and_custom_url() {
        let config = DuckDbConfig::from_params(&json!({
            "service_token": "tok",
            "base_url": "https://custom.motherduck.com/v0",
            "database": "my_db",
        }))
        .unwrap();
        assert_eq!(config.base_url, "https://custom.motherduck.com/v0");
        assert_eq!(config.default_database, Some("my_db".into()));
    }
}
