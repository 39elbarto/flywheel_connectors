//! FCP MySQL Connector implementation.

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
    client::{DEFAULT_BASE_URL, MysqlAuth, MysqlClient},
    error::MysqlError,
};

/// Parsed and validated MySQL connector configuration.
#[derive(Debug, Clone)]
struct MysqlConfig {
    auth: MysqlAuth,
    base_url: String,
}

impl MysqlConfig {
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
            (Some(key), None) => MysqlAuth::ApiKey(key),
            (None, Some(cred_id)) => MysqlAuth::CredentialId(cred_id),
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

/// FCP MySQL Connector.
pub struct MysqlConnector {
    base: Arc<BaseConnector>,
    config: Option<MysqlConfig>,
    client: Option<MysqlClient>,
    handshaken: bool,
    requests: AtomicU64,
    errors: AtomicU64,
}

impl MysqlConnector {
    /// Create a new unconfigured MySQL connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("mysql"))),
            config: None,
            client: None,
            handshaken: false,
            requests: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    fn require_str<'a>(params: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
        params
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: format!("missing required field: {field}"),
            })
    }

    /// Handle configure request.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = MysqlConfig::from_params(&params)?;
        let client =
            MysqlClient::new(config.auth.clone(), Some(&config.base_url)).map_err(|e| {
                FcpError::Internal {
                    message: format!("Failed to create MySQL client: {e}"),
                }
            })?;

        info!(base_url = %config.base_url, auth = %config.auth.redacted_label(), "MySQL connector configured");

        self.config = Some(config);
        self.client = Some(client);

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake request.
    pub async fn handle_handshake(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        self.handshaken = true;
        Ok(json!({
            "protocol_version": "2.0.0",
            "connector_id": "mysql",
            "connector_version": "0.1.0",
        }))
    }

    /// Handle health check.
    ///
    /// Reports truthful health: actually probes the database when configured
    /// rather than merely reporting config presence.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();

        let status = if let Some(ref client) = self.client {
            match client.health_check().await {
                Ok(true) => "healthy",
                Ok(false) => "degraded",
                Err(_) => "degraded",
            }
        } else {
            "not_configured"
        };

        Ok(json!({
            "status": status,
            "configured": configured,
            "handshaken": self.handshaken,
            "requests": self.requests.load(Ordering::Relaxed),
            "errors": self.errors.load(Ordering::Relaxed),
        }))
    }

    /// Handle doctor check.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        let configured = self.config.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: configured,
            message: Some(if configured {
                "Configuration loaded".into()
            } else {
                "Not configured. Provide api_key or credential_id and base_url.".into()
            }),
            critical: true,
        });

        let client_ok = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: client_ok,
            message: Some(if client_ok {
                "MySQL client initialized".into()
            } else {
                "MySQL client not initialized. Run configure first.".into()
            }),
            critical: true,
        });

        let handshake_ok = self.handshaken;
        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: handshake_ok,
            message: Some(if handshake_ok {
                "Handshake completed".into()
            } else {
                "Handshake not completed. Non-critical for basic operations.".into()
            }),
            critical: false,
        });

        let result = DoctorResult::from_checks(checks);
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    /// Handle self_check.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let status = if self.config.is_some() {
            "ok"
        } else {
            "degraded"
        };
        Ok(json!({
            "status": status,
            "version": "0.1.0",
            "connector_id": "mysql",
        }))
    }

    /// Handle introspect request.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let operations = operations_info();
        Ok(json!({
            "connector_id": "mysql",
            "version": "0.1.0",
            "archetypes": ["database"],
            "operations": operations.iter().map(|op| {
                // Use serde serialization for enum values to get canonical snake_case
                let safety = serde_json::to_value(&op.safety_tier).unwrap_or(json!("unknown"));
                let risk = serde_json::to_value(&op.risk_level).unwrap_or(json!("unknown"));
                let idem = serde_json::to_value(&op.idempotency).unwrap_or(json!("unknown"));
                json!({
                    "id": op.id.as_str(),
                    "summary": op.summary,
                    "safety_tier": safety,
                    "risk_level": risk,
                    "idempotency": idem,
                    "capability": op.capability.as_str(),
                })
            }).collect::<Vec<_>>(),
            "operation_count": operations.len(),
        }))
    }

    /// Handle invoke request.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.requests.fetch_add(1, Ordering::Relaxed);

        let operation = Self::require_str(&params, "operation")?;
        let input = params.get("input").cloned().unwrap_or(json!({}));

        let client = self
            .client
            .as_ref()
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 5001,
                message: "Connector not configured. Call configure first.".into(),
            })?;

        let result = match operation {
            "mysql.query" => {
                let sql = Self::require_str(&input, "sql")?;
                let params_arr = input
                    .get("params")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                client.query(sql, &params_arr).await
            }
            "mysql.execute" => {
                let sql = Self::require_str(&input, "sql")?;
                let params_arr = input
                    .get("params")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                client.execute(sql, &params_arr).await
            }
            "mysql.explain" => {
                let sql = Self::require_str(&input, "sql")?;
                client.explain(sql).await
            }
            "mysql.schema.tables" => client.list_tables().await,
            "mysql.schema.columns" => {
                let table = Self::require_str(&input, "table")?;
                client.list_columns(table).await
            }
            "mysql.schema.indexes" => {
                let table = Self::require_str(&input, "table")?;
                client.list_indexes(table).await
            }
            "mysql.health" => {
                let healthy = client.health_check().await.unwrap_or(false);
                Ok(json!({ "healthy": healthy }))
            }
            other => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {other}"),
                });
            }
        };

        result.map_err(|e: MysqlError| {
            self.errors.fetch_add(1, Ordering::Relaxed);
            e.to_fcp_error()
        })
    }

    /// Handle simulate request.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = Self::require_str(&params, "operation")?;
        let configured = self.client.is_some();

        let ops = operations_info();
        let operation_known = ops.iter().any(|op| op.id.as_str() == operation);

        Ok(json!({
            "would_succeed": configured && operation_known,
            "configured": configured,
            "operation_known": operation_known,
        }))
    }

    /// Handle shutdown request.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if let Some(ref client) = self.client {
            client.shutdown();
        }
        info!("MySQL connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for MysqlConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// All operations provided by the MySQL connector.
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static("mysql.query"),
            summary: "Execute a read-only SQL query".into(),
            description: Some("Execute a parameterized SELECT query against the MySQL database. Returns rows, columns, and row count.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "sql": { "type": "string", "description": "SQL query (use ? placeholders)" },
                    "params": { "type": "array", "items": {}, "description": "Positional parameters" },
                    "timeout_ms": { "type": "integer", "description": "Query timeout in milliseconds" }
                },
                "required": ["sql"]
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "rows": { "type": "array" },
                    "columns": { "type": "array" },
                    "row_count": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static("mysql.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use for SELECT queries, read-only data retrieval".into(),
                common_mistakes: vec![
                    "Using string interpolation instead of parameterized queries".into(),
                    "Not setting a timeout for long-running queries".into(),
                ],
                examples: vec![],
                related: vec![CapabilityId::from_static("mysql.execute")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("mysql.execute"),
            summary: "Execute a SQL statement (INSERT/UPDATE/DELETE)".into(),
            description: Some("Execute a parameterized mutation statement. Returns affected row count.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "sql": { "type": "string", "description": "SQL statement (use ? placeholders)" },
                    "params": { "type": "array", "items": {}, "description": "Positional parameters" }
                },
                "required": ["sql"]
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "affected_rows": { "type": "integer" }
                }
            }),
            capability: CapabilityId::from_static("mysql.write"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "Use for INSERT, UPDATE, DELETE statements that modify data".into(),
                common_mistakes: vec![
                    "Using raw SQL without parameterized queries (SQL injection risk)".into(),
                    "Executing DDL (CREATE/ALTER/DROP) through execute instead of dedicated ops".into(),
                ],
                examples: vec![],
                related: vec![CapabilityId::from_static("mysql.query")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("mysql.explain"),
            summary: "Explain a query execution plan".into(),
            description: Some("Run EXPLAIN on a query to analyze its execution plan without executing it.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "sql": { "type": "string", "description": "SQL query to explain" }
                },
                "required": ["sql"]
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "plan": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static("mysql.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to analyze query performance before execution".into(),
                common_mistakes: vec!["Confusing EXPLAIN with actual query execution".into()],
                examples: vec![],
                related: vec![CapabilityId::from_static("mysql.query")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("mysql.schema.tables"),
            summary: "List database tables".into(),
            description: Some("List all tables in the current database with metadata (engine, row count estimate).".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "database": { "type": "string" },
                        "engine": { "type": "string" },
                        "row_count_estimate": { "type": "integer" }
                    }
                }
            }),
            capability: CapabilityId::from_static("mysql.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to discover tables in the database before querying".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![
                    CapabilityId::from_static("mysql.schema.columns"),
                    CapabilityId::from_static("mysql.schema.indexes"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("mysql.schema.columns"),
            summary: "List columns for a table".into(),
            description: Some("List all columns in a table with types, nullability, defaults, and primary key info.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "table": { "type": "string", "description": "Table name" }
                },
                "required": ["table"]
            }),
            output_schema: json!({
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "data_type": { "type": "string" },
                        "nullable": { "type": "boolean" },
                        "is_primary_key": { "type": "boolean" }
                    }
                }
            }),
            capability: CapabilityId::from_static("mysql.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to understand table structure before writing queries".into(),
                common_mistakes: vec!["Querying columns for a non-existent table".into()],
                examples: vec![],
                related: vec![CapabilityId::from_static("mysql.schema.tables")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("mysql.schema.indexes"),
            summary: "List indexes for a table".into(),
            description: Some("List all indexes on a table with columns, uniqueness, and index type.".into()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "table": { "type": "string", "description": "Table name" }
                },
                "required": ["table"]
            }),
            output_schema: json!({
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "columns": { "type": "array", "items": { "type": "string" } },
                        "unique": { "type": "boolean" },
                        "type": { "type": "string" }
                    }
                }
            }),
            capability: CapabilityId::from_static("mysql.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to check query optimization opportunities".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![CapabilityId::from_static("mysql.schema.columns")],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("mysql.health"),
            summary: "Check MySQL database health".into(),
            description: Some("Probe the MySQL database to verify connectivity and basic functionality.".into()),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "healthy": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static("mysql.read"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to verify database is accessible before running queries".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_new_defaults() {
        let connector = MysqlConnector::new();
        assert!(connector.config.is_none());
        assert!(connector.client.is_none());
        assert!(!connector.handshaken);
    }

    #[test]
    fn connector_default_same_as_new() {
        let connector = MysqlConnector::default();
        assert!(connector.config.is_none());
    }

    #[test]
    fn config_from_api_key() {
        let params = json!({ "api_key": "test-key-123" });
        let config = MysqlConfig::from_params(&params).unwrap();
        assert!(matches!(config.auth, MysqlAuth::ApiKey(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn config_from_credential_id() {
        let params = json!({ "credential_id": "550e8400-e29b-41d4-a716-446655440000" });
        let config = MysqlConfig::from_params(&params).unwrap();
        assert!(matches!(config.auth, MysqlAuth::CredentialId(_)));
    }

    #[test]
    fn config_with_custom_base_url() {
        let params = json!({
            "api_key": "test-key",
            "base_url": "https://my-mysql-proxy.example.com"
        });
        let config = MysqlConfig::from_params(&params).unwrap();
        assert_eq!(config.base_url, "https://my-mysql-proxy.example.com");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let params = json!({
            "api_key": "key",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        });
        assert!(MysqlConfig::from_params(&params).is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let params = json!({});
        assert!(MysqlConfig::from_params(&params).is_err());
    }

    #[test]
    fn config_rejects_empty_api_key() {
        let params = json!({ "api_key": "" });
        assert!(MysqlConfig::from_params(&params).is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        let params = json!({ "api_key": "  " });
        assert!(MysqlConfig::from_params(&params).is_err());
    }

    #[test]
    fn config_trims_api_key() {
        let params = json!({ "api_key": "  test-key  " });
        let config = MysqlConfig::from_params(&params).unwrap();
        match config.auth {
            MysqlAuth::ApiKey(key) => assert_eq!(key, "test-key"),
            _ => panic!("expected ApiKey"),
        }
    }

    #[test]
    fn operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 7);
    }

    #[test]
    fn operations_all_have_ids() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.id.as_str().is_empty(), "operation must have an ID");
        }
    }

    #[test]
    fn operations_all_have_summaries() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                !op.summary.is_empty(),
                "operation {} must have a summary",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn operations_all_have_capabilities() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                !op.capability.as_str().is_empty(),
                "operation {} must have a capability",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn operations_read_ops_are_safe() {
        let ops = operations_info();
        let read_ops: Vec<&OperationInfo> = ops
            .iter()
            .filter(|op| op.capability.as_str() == "mysql.read")
            .collect();
        assert!(!read_ops.is_empty());
        for op in read_ops {
            assert_eq!(
                op.safety_tier,
                SafetyTier::Safe,
                "read operation {} should be Safe",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn operations_write_ops_are_risky() {
        let ops = operations_info();
        let write_ops: Vec<&OperationInfo> = ops
            .iter()
            .filter(|op| op.capability.as_str() == "mysql.write")
            .collect();
        assert!(!write_ops.is_empty());
        for op in write_ops {
            assert_eq!(
                op.safety_tier,
                SafetyTier::Risky,
                "write operation {} should be Risky",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn operations_no_dangerous_none_violation() {
        let ops = operations_info();
        for op in &ops {
            if op.safety_tier == SafetyTier::Dangerous {
                assert_ne!(
                    op.idempotency,
                    IdempotencyClass::None,
                    "Dangerous operation {} must not have IdempotencyClass::None",
                    op.id.as_str()
                );
            }
        }
    }

    #[test]
    fn operations_all_have_schemas() {
        let ops = operations_info();
        for op in &ops {
            assert!(
                op.input_schema.is_object(),
                "operation {} must have input schema",
                op.id.as_str()
            );
            assert!(
                op.output_schema.is_object() || op.output_schema.is_array(),
                "operation {} must have output schema",
                op.id.as_str()
            );
        }
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
        let result = DoctorResult::from_checks(checks);
        assert_eq!(result.status, DoctorStatus::Healthy);
    }

    #[test]
    fn doctor_result_unhealthy_when_critical_fails() {
        let checks = vec![DoctorCheck {
            name: "a".into(),
            passed: false,
            message: None,
            critical: true,
        }];
        let result = DoctorResult::from_checks(checks);
        assert_eq!(result.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn doctor_result_degraded_when_noncritical_fails() {
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
                message: None,
                critical: false,
            },
        ];
        let result = DoctorResult::from_checks(checks);
        assert_eq!(result.status, DoctorStatus::Degraded);
    }

    #[test]
    fn require_str_returns_value() {
        let params = json!({ "sql": "SELECT 1" });
        let sql = MysqlConnector::require_str(&params, "sql").unwrap();
        assert_eq!(sql, "SELECT 1");
    }

    #[test]
    fn require_str_errors_on_missing() {
        let params = json!({});
        assert!(MysqlConnector::require_str(&params, "sql").is_err());
    }

    #[test]
    fn require_str_errors_on_non_string() {
        let params = json!({ "sql": 42 });
        assert!(MysqlConnector::require_str(&params, "sql").is_err());
    }
}
