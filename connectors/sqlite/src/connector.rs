//! FCP SQLite Connector implementation.

#![allow(clippy::doc_markdown)]

use std::path::{Component, Path};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityId, ConnectorId, FcpError, FcpResult, IdempotencyClass,
    OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};
use uuid::Uuid;

use crate::{
    client::SqliteClient,
    error::SqliteError,
    types::{BatchStatement, SqliteConfig, SqliteHealth, TransactionMode, TransactionState},
};

/// Doctor check result.
#[derive(Debug, Clone, Serialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning: Option<ProvisioningReadiness>,
    guidance: OperatorGuidance,
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

/// Provisioning/readiness snapshot for the configured database.
#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProvisioningReadiness {
    database_path: String,
    path_kind: &'static str,
    database_exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_directory: Option<String>,
    parent_directory_exists: bool,
    filesystem_ready: bool,
    filesystem_message: String,
    read_only: bool,
    create_if_missing: bool,
    busy_timeout_ms: u64,
    wal_requested: bool,
    wal_possible: bool,
    enforce_foreign_keys: bool,
    network_required: bool,
}

/// Operator guidance bundled with diagnostics.
#[derive(Debug, Clone, Serialize)]
struct OperatorGuidance {
    prerequisites: Vec<String>,
    redaction_rules: Vec<String>,
    remediation: Vec<String>,
    rerun_commands: Vec<String>,
}

impl DoctorResult {
    #[must_use]
    fn from_checks(checks: Vec<DoctorCheck>, provisioning: Option<ProvisioningReadiness>) -> Self {
        let status = if checks.iter().any(|check| check.critical && !check.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|check| !check.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };

        Self {
            status,
            checks,
            provisioning,
            guidance: operator_guidance(),
        }
    }
}

/// FCP SQLite Connector.
pub struct SqliteConnector {
    base: Arc<BaseConnector>,
    config: Option<SqliteConfig>,
    client: Option<SqliteClient>,
    session_id: Option<String>,
    active_transaction_id: Option<String>,
    active_transaction_mode: Option<TransactionMode>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl SqliteConnector {
    /// Create a new SQLite connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("sqlite"))),
            config: None,
            client: None,
            session_id: None,
            active_transaction_id: None,
            active_transaction_mode: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = SqliteConfig::from_params(&params)?;
        let client = SqliteClient::new(config.clone()).map_err(|error| error.to_fcp_error())?;

        info!(
            database_path = %config.database_path,
            read_only = config.read_only,
            enable_wal = config.enable_wal,
            "Configuring SQLite connector"
        );

        self.config = Some(config);
        self.client = Some(client);
        self.session_id = None;
        self.active_transaction_id = None;
        self.active_transaction_mode = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);

        Ok(json!({ "status": "configured" }))
    }

    /// Handle the `handshake` method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.config.is_none() || self.client.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Connector not configured".into(),
            });
        }

        self.session_id = params
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.sqlite",
            "connector_version": "0.1.0",
            "capabilities": ["sqlite.read", "sqlite.write", "sqlite.admin"],
        }))
    }

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            return Ok(json!({
                "status": "unconfigured",
                "configured": false,
                "handshaken": false,
                "requests": self.request_count.load(Ordering::Relaxed),
                "errors": self.error_count.load(Ordering::Relaxed),
            }));
        };

        let probe = client.health_check();
        let status = match (&self.session_id, &probe) {
            (Some(_), Ok(health)) if health.query_ok => "healthy",
            (_, Ok(_)) => "degraded",
            _ => "degraded",
        };

        Ok(json!({
            "status": status,
            "configured": true,
            "handshaken": self.session_id.is_some(),
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
            "active_transaction_id": self.active_transaction_id,
            "health": probe.ok(),
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let provisioning = self
            .config
            .as_ref()
            .map(SqliteConfig::provisioning_readiness);
        let probe = self.client.as_ref().map(SqliteClient::health_check);
        let checks = vec![
            DoctorCheck {
                name: "configuration".into(),
                passed: self.config.is_some(),
                message: self
                    .config
                    .is_none()
                    .then_some("connector not configured".into()),
                critical: true,
            },
            DoctorCheck {
                name: "client_initialized".into(),
                passed: self.client.is_some(),
                message: self
                    .client
                    .is_none()
                    .then_some("SQLite client not initialized".into()),
                critical: true,
            },
            DoctorCheck {
                name: "database_probe".into(),
                passed: probe.as_ref().is_some_and(Result::is_ok),
                message: match probe {
                    Some(Ok(_)) => None,
                    Some(Err(error)) => Some(error.to_string()),
                    None => Some("database probe unavailable before configure".into()),
                },
                critical: self.client.is_some(),
            },
            DoctorCheck {
                name: "filesystem_ready".into(),
                passed: provisioning
                    .as_ref()
                    .is_none_or(|readiness| readiness.filesystem_ready),
                message: provisioning.as_ref().and_then(|readiness| {
                    (!readiness.filesystem_ready).then_some(readiness.filesystem_message.clone())
                }),
                critical: self.config.is_some(),
            },
            DoctorCheck {
                name: "wal_preconditions".into(),
                passed: provisioning
                    .as_ref()
                    .is_none_or(|readiness| !readiness.wal_requested || readiness.wal_possible),
                message: provisioning.as_ref().and_then(|readiness| {
                    (readiness.wal_requested && !readiness.wal_possible).then_some(
                        "WAL requires a writable file-backed database path inside the sandbox"
                            .into(),
                    )
                }),
                critical: false,
            },
            DoctorCheck {
                name: "handshake".into(),
                passed: self.session_id.is_some(),
                message: self
                    .session_id
                    .is_none()
                    .then_some("handshake not completed".into()),
                critical: false,
            },
        ];

        let result = DoctorResult::from_checks(checks, provisioning);
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            return serialize_self_check(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };
        let provisioning = config.provisioning_readiness();
        let guidance = operator_guidance();

        if !provisioning.filesystem_ready {
            let mut report = SelfCheckReport::failed(
                "filesystem_not_ready",
                provisioning.filesystem_message.clone(),
            );
            report.details = Some(self_check_details(
                config,
                &provisioning,
                &guidance,
                None,
                self.active_transaction_id.as_deref(),
                self.session_id.as_deref(),
            ));
            return serialize_self_check(report);
        }

        let Some(client) = &self.client else {
            return serialize_self_check(SelfCheckReport::failed(
                "client_missing",
                "SQLite client is missing; re-run configure",
            ));
        };

        if self.session_id.is_none() {
            let mut report = SelfCheckReport::degraded(
                "handshake_pending",
                "Connector configured but handshake has not completed",
            );
            report.details = Some(self_check_details(
                config,
                &provisioning,
                &guidance,
                None,
                self.active_transaction_id.as_deref(),
                self.session_id.as_deref(),
            ));
            return serialize_self_check(report);
        }

        match client.health_check() {
            Ok(health) if health.query_ok => {
                let mut report = SelfCheckReport::ok();
                report.details = Some(self_check_details(
                    config,
                    &provisioning,
                    &guidance,
                    Some(&health),
                    self.active_transaction_id.as_deref(),
                    self.session_id.as_deref(),
                ));
                serialize_self_check(report)
            }
            Ok(health) => {
                let mut report = SelfCheckReport::degraded(
                    "probe_failed",
                    "SQLite health probe returned an unexpected result",
                );
                report.details = Some(self_check_details(
                    config,
                    &provisioning,
                    &guidance,
                    Some(&health),
                    self.active_transaction_id.as_deref(),
                    self.session_id.as_deref(),
                ));
                serialize_self_check(report)
            }
            Err(error) => {
                let mut report = SelfCheckReport::failed(
                    "probe_error",
                    format!("SQLite health probe failed: {error}"),
                );
                report.details = Some(self_check_details(
                    config,
                    &provisioning,
                    &guidance,
                    None,
                    self.active_transaction_id.as_deref(),
                    self.session_id.as_deref(),
                ));
                serialize_self_check(report)
            }
        }
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.sqlite",
            "version": "0.1.0",
            "operations": serde_json::to_value(operations_info()).unwrap_or_default(),
            "provisioning": self.config.as_ref().map(SqliteConfig::provisioning_readiness),
            "guidance": operator_guidance(),
            "compliance": {
                "protocol_version": "2.0",
                "network_required": false,
                "local_filesystem_only": true,
                "supported_methods": [
                    "configure",
                    "handshake",
                    "health",
                    "doctor",
                    "self_check",
                    "introspect",
                    "invoke",
                    "simulate",
                    "shutdown"
                ],
                "transaction_model": "single_active_transaction",
            }
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
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

        let result = match operation {
            "sqlite.query" => self.invoke_query(&input).await,
            "sqlite.execute" => self.invoke_execute(&input).await,
            "sqlite.explain" => self.invoke_explain(&input).await,
            "sqlite.schema.tables" => self.invoke_schema_tables(&input).await,
            "sqlite.schema.columns" => self.invoke_schema_columns(&input).await,
            "sqlite.transaction.begin" => self.invoke_transaction_begin(&input).await,
            "sqlite.transaction.commit" => self.invoke_transaction_commit(&input).await,
            "sqlite.transaction.rollback" => self.invoke_transaction_rollback(&input).await,
            "sqlite.batch" => self.invoke_batch(&input).await,
            "sqlite.health" => self.invoke_sqlite_health().await,
            "sqlite.vacuum" => self.invoke_vacuum(&input).await,
            "sqlite.pragma" => self.invoke_pragma(&input).await,
            _ => Err(SqliteError::InvalidInput(format!(
                "unknown SQLite operation `{operation}`"
            ))),
        };

        result.map_err(|error| {
            self.error_count.fetch_add(1, Ordering::Relaxed);
            error.to_fcp_error()
        })
    }

    /// Handle the `simulate` method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let allowed = operations_info()
            .iter()
            .any(|operation_info| operation_info.id.as_ref() == operation);

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
        info!("SQLite connector shutting down");
        self.client = None;
        self.config = None;
        self.session_id = None;
        self.active_transaction_id = None;
        self.active_transaction_mode = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    async fn invoke_query(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        self.ensure_transaction_context(optional_str(input, "txn_id"))?;
        let sql = require_str(input, "sql")?;
        let params = optional_array(input, "params");
        let client = self.require_client()?;
        let result = client.query(sql, &params)?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_execute(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        self.ensure_transaction_context(optional_str(input, "txn_id"))?;
        let sql = require_str(input, "sql")?;
        let params = optional_array(input, "params");
        let client = self.require_client()?;
        let result = client.execute(sql, &params)?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_explain(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        self.ensure_transaction_context(optional_str(input, "txn_id"))?;
        let sql = require_str(input, "sql")?;
        let params = optional_array(input, "params");
        let client = self.require_client()?;
        let result = client.explain(sql, &params)?;
        Ok(json!({ "plan": result }))
    }

    async fn invoke_schema_tables(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        self.ensure_transaction_context(optional_str(input, "txn_id"))?;
        let client = self.require_client()?;
        let tables = client.list_tables()?;
        Ok(json!({ "tables": tables }))
    }

    async fn invoke_schema_columns(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        self.ensure_transaction_context(optional_str(input, "txn_id"))?;
        let table = require_str(input, "table")?;
        let client = self.require_client()?;
        let columns = client.list_columns(table)?;
        Ok(json!({ "columns": columns }))
    }

    async fn invoke_transaction_begin(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        if self.active_transaction_id.is_some() {
            return Err(SqliteError::Transaction(
                "an SQLite transaction is already active".into(),
            ));
        }

        let mode = TransactionMode::parse(optional_str(input, "mode"))
            .map_err(SqliteError::Transaction)?;
        let client = self.require_client()?;
        client.begin_transaction(mode)?;

        let txn_id = Uuid::new_v4().to_string();
        self.active_transaction_id = Some(txn_id.clone());
        self.active_transaction_mode = Some(mode);

        Ok(json!({
            "transaction": TransactionState {
                txn_id,
                mode,
                active: true,
            }
        }))
    }

    async fn invoke_transaction_commit(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        let txn_id = require_str(input, "txn_id")?;
        self.require_active_transaction(txn_id)?;

        let client = self.require_client()?;
        client.commit_transaction()?;

        self.active_transaction_id = None;
        self.active_transaction_mode = None;

        Ok(json!({
            "result": {
                "txn_id": txn_id,
                "status": "committed",
            }
        }))
    }

    async fn invoke_transaction_rollback(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        let txn_id = require_str(input, "txn_id")?;
        self.require_active_transaction(txn_id)?;

        let client = self.require_client()?;
        client.rollback_transaction()?;

        self.active_transaction_id = None;
        self.active_transaction_mode = None;

        Ok(json!({
            "result": {
                "txn_id": txn_id,
                "status": "rolled_back",
            }
        }))
    }

    async fn invoke_batch(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        self.ensure_transaction_context(optional_str(input, "txn_id"))?;
        let statements_value = input
            .get("statements")
            .cloned()
            .ok_or_else(|| SqliteError::InvalidInput("sqlite.batch requires statements".into()))?;
        let statements: Vec<BatchStatement> = serde_json::from_value(statements_value)
            .map_err(|error| SqliteError::InvalidInput(format!("invalid statements: {error}")))?;
        let client = self.require_client()?;
        let results = client.batch(&statements)?;
        Ok(json!({ "results": results }))
    }

    async fn invoke_sqlite_health(&self) -> Result<serde_json::Value, SqliteError> {
        let client = self.require_client()?;
        let health = client.health_check()?;
        Ok(json!({
            "health": health,
            "active_transaction_id": self.active_transaction_id,
        }))
    }

    async fn invoke_vacuum(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        if input.get("txn_id").is_some() {
            return Err(SqliteError::InvalidInput(
                "sqlite.vacuum does not accept txn_id".into(),
            ));
        }
        if self.active_transaction_id.is_some() {
            return Err(SqliteError::Transaction(
                "sqlite.vacuum cannot run while a transaction is active".into(),
            ));
        }
        let client = self.require_client()?;
        let result = client.vacuum()?;
        Ok(json!({ "result": result }))
    }

    async fn invoke_pragma(
        &self,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SqliteError> {
        self.ensure_transaction_context(optional_str(input, "txn_id"))?;
        let name = require_str(input, "name")?;
        let client = self.require_client()?;
        let result = client.read_pragma(name)?;
        Ok(json!({ "result": result }))
    }

    fn require_client(&self) -> Result<&SqliteClient, SqliteError> {
        self.client
            .as_ref()
            .ok_or_else(|| SqliteError::InvalidConfig("SQLite client not initialized".into()))
    }

    fn ensure_transaction_context(&self, txn_id: Option<&str>) -> Result<(), SqliteError> {
        match (self.active_transaction_id.as_deref(), txn_id) {
            (Some(active), Some(provided)) if active == provided => Ok(()),
            (Some(active), Some(provided)) => Err(SqliteError::Transaction(format!(
                "active transaction `{active}` does not match provided txn_id `{provided}`"
            ))),
            (Some(active), None) => Err(SqliteError::Transaction(format!(
                "operation requires txn_id `{active}` while a transaction is active"
            ))),
            (None, Some(provided)) => Err(SqliteError::Transaction(format!(
                "no active SQLite transaction matches txn_id `{provided}`"
            ))),
            (None, None) => Ok(()),
        }
    }

    fn require_active_transaction(&self, txn_id: &str) -> Result<(), SqliteError> {
        let active = self.active_transaction_id.as_deref().ok_or_else(|| {
            SqliteError::Transaction("no SQLite transaction is currently active".into())
        })?;
        if active == txn_id {
            Ok(())
        } else {
            Err(SqliteError::Transaction(format!(
                "active transaction `{active}` does not match provided txn_id `{txn_id}`"
            )))
        }
    }
}

impl Default for SqliteConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl SqliteConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let database_path = params
            .get("database_path")
            .or_else(|| params.get("path"))
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing database_path".into(),
            })?;

        validate_database_path(database_path).map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: error,
        })?;

        let read_only = params
            .get("read_only")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let create_if_missing = params
            .get("create_if_missing")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(!read_only);
        let busy_timeout_ms = params
            .get("busy_timeout_ms")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(5_000);
        if busy_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "busy_timeout_ms must be greater than zero".into(),
            });
        }
        let enable_wal = params
            .get("enable_wal")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        let enforce_foreign_keys = params
            .get("enforce_foreign_keys")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);

        Ok(Self {
            database_path: database_path.to_string(),
            read_only,
            create_if_missing,
            busy_timeout_ms,
            enable_wal,
            enforce_foreign_keys,
        })
    }

    fn provisioning_readiness(&self) -> ProvisioningReadiness {
        if self.database_path == ":memory:" {
            return ProvisioningReadiness {
                database_path: self.database_path.clone(),
                path_kind: "memory",
                database_exists: true,
                parent_directory: None,
                parent_directory_exists: true,
                filesystem_ready: true,
                filesystem_message: "in-memory mode requires no filesystem prerequisites".into(),
                read_only: self.read_only,
                create_if_missing: self.create_if_missing,
                busy_timeout_ms: self.busy_timeout_ms,
                wal_requested: self.enable_wal,
                wal_possible: false,
                enforce_foreign_keys: self.enforce_foreign_keys,
                network_required: false,
            };
        }

        let path = Path::new(&self.database_path);
        let database_exists = path.exists();
        let parent = path.parent().and_then(|value| {
            (!value.as_os_str().is_empty()).then(|| value.to_string_lossy().to_string())
        });
        let parent_directory_exists = parent
            .as_deref()
            .is_none_or(|value| Path::new(value).exists());

        let (filesystem_ready, filesystem_message) = if database_exists {
            (true, "database file is reachable".to_string())
        } else if self.read_only {
            (
                false,
                "read_only mode requires an existing database file".to_string(),
            )
        } else if !parent_directory_exists {
            (
                false,
                "database parent directory does not exist; create it inside the sandbox first"
                    .to_string(),
            )
        } else if self.create_if_missing {
            (
                true,
                "database file will be created on first write/open".to_string(),
            )
        } else {
            (
                false,
                "database file is missing and create_if_missing is false".to_string(),
            )
        };

        ProvisioningReadiness {
            database_path: self.database_path.clone(),
            path_kind: "file",
            database_exists,
            parent_directory: parent,
            parent_directory_exists,
            filesystem_ready,
            filesystem_message,
            read_only: self.read_only,
            create_if_missing: self.create_if_missing,
            busy_timeout_ms: self.busy_timeout_ms,
            wal_requested: self.enable_wal,
            wal_possible: self.enable_wal && !self.read_only && filesystem_ready,
            enforce_foreign_keys: self.enforce_foreign_keys,
            network_required: false,
        }
    }
}

fn config_summary(config: &SqliteConfig) -> serde_json::Value {
    json!({
        "database_path": config.database_path,
        "read_only": config.read_only,
        "create_if_missing": config.create_if_missing,
        "busy_timeout_ms": config.busy_timeout_ms,
        "enable_wal": config.enable_wal,
        "enforce_foreign_keys": config.enforce_foreign_keys,
    })
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use a filesystem path inside the connector sandbox or `:memory:` for ephemeral runs."
                .into(),
            "In `read_only` mode, pre-create the database file before calling configure.".into(),
            "If WAL is enabled, allow the paired `-wal` and `-shm` sidecar files in the same writable directory.".into(),
        ],
        redaction_rules: vec![
            "Redact absolute user or workspace path prefixes before sharing diagnostics.".into(),
            "Do not paste query text, blob payloads, or row values that may contain sensitive data into tickets.".into(),
        ],
        remediation: vec![
            "For `database is locked` errors, close competing writers or raise `busy_timeout_ms` before retrying.".into(),
            "For `unable to open database file`, verify the parent directory exists and is within the sandbox allowlist.".into(),
            "For unexpected read-only failures, verify file permissions and the connector `read_only` setting.".into(),
            "Run `sqlite.vacuum` only when no transaction is active.".into(),
        ],
        rerun_commands: vec![
            "rch exec -- cargo check -p fcp-sqlite --all-targets".into(),
            "rch exec -- cargo clippy -p fcp-sqlite --all-targets -- -D warnings".into(),
            "rch exec -- cargo test -p fcp-sqlite -- --nocapture".into(),
        ],
    }
}

fn self_check_details(
    config: &SqliteConfig,
    provisioning: &ProvisioningReadiness,
    guidance: &OperatorGuidance,
    health: Option<&SqliteHealth>,
    active_transaction_id: Option<&str>,
    session_id: Option<&str>,
) -> serde_json::Value {
    json!({
        "config": config_summary(config),
        "provisioning": provisioning,
        "guidance": guidance,
        "health": health,
        "active_transaction_id": active_transaction_id,
        "session_id": session_id,
    })
}

fn serialize_self_check(report: SelfCheckReport) -> FcpResult<serde_json::Value> {
    serde_json::to_value(report).map_err(|error| FcpError::Internal {
        message: format!("failed to serialize self-check report: {error}"),
    })
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, SqliteError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| SqliteError::InvalidInput(format!("missing required field: {field}")))
}

fn optional_str<'a>(input: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn optional_array(input: &serde_json::Value, field: &str) -> Vec<serde_json::Value> {
    input
        .get(field)
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn validate_database_path(database_path: &str) -> Result<(), String> {
    if database_path == ":memory:" {
        return Ok(());
    }
    if database_path.starts_with("file:") {
        return Err("file: URIs are not supported; use a filesystem path or :memory:".into());
    }
    let path = Path::new(database_path);
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("database paths containing `..` are not allowed".into());
    }
    Ok(())
}

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

fn operations_info() -> Vec<OperationInfo> {
    vec![
        op_info(
            "sqlite.query",
            "Execute a parameterized read-only SQL query",
            json!({
                "type": "object",
                "required": ["sql"],
                "properties": {
                    "sql": { "type": "string", "description": "A single read-only SQL statement" },
                    "params": { "type": "array", "description": "Positional query parameters" },
                    "txn_id": { "type": "string", "description": "Active transaction id when querying inside a transaction" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "result": { "description": "Query result with columns, rows, and row_count" }
                }
            }),
            "sqlite.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Use for SELECT statements or other read-only queries against a local SQLite database.".into(),
                common_mistakes: vec![
                    "Passing a mutating statement to sqlite.query instead of sqlite.execute.".into(),
                    "Omitting txn_id while a transaction is active.".into(),
                ],
                examples: vec![
                    r#"{"sql":"SELECT id, name FROM tasks WHERE status = ?1","params":["open"]}"#
                        .into(),
                ],
                related: vec![CapabilityId::from_static("sqlite.read")],
            },
        ),
        op_info(
            "sqlite.execute",
            "Execute a parameterized mutating SQL statement",
            json!({
                "type": "object",
                "required": ["sql"],
                "properties": {
                    "sql": { "type": "string", "description": "A single non-returning mutating or DDL SQL statement" },
                    "params": { "type": "array", "description": "Positional statement parameters" },
                    "txn_id": { "type": "string", "description": "Active transaction id when executing inside a transaction" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "result": { "description": "Execution result with rows_affected and last_insert_rowid" }
                }
            }),
            "sqlite.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Use for INSERT, UPDATE, DELETE, CREATE TABLE, and other mutating SQLite statements.".into(),
                common_mistakes: vec![
                    "Using sqlite.execute for statements that return rows.".into(),
                    "Trying to run ATTACH, DETACH, PRAGMA writes, or explicit transaction SQL.".into(),
                ],
                examples: vec![
                    r#"{"sql":"UPDATE tasks SET status = ?1 WHERE id = ?2","params":["done",42]}"#
                        .into(),
                ],
                related: vec![CapabilityId::from_static("sqlite.write")],
            },
        ),
        op_info(
            "sqlite.explain",
            "Explain the query plan for a read-only SQL statement",
            json!({
                "type": "object",
                "required": ["sql"],
                "properties": {
                    "sql": { "type": "string", "description": "A single read-only SQL statement" },
                    "params": { "type": "array", "description": "Positional query parameters" },
                    "txn_id": { "type": "string", "description": "Active transaction id when explaining inside a transaction" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "plan": { "description": "EXPLAIN QUERY PLAN output" }
                }
            }),
            "sqlite.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Use to inspect query plans before executing or tuning read-only SQLite queries.".into(),
                common_mistakes: vec!["Explaining a mutating statement instead of a read-only query.".into()],
                examples: vec![
                    r#"{"sql":"SELECT * FROM tasks WHERE due_at < ?1","params":["2026-06-01T00:00:00Z"]}"#
                        .into(),
                ],
                related: vec![CapabilityId::from_static("sqlite.read")],
            },
        ),
        op_info(
            "sqlite.schema.tables",
            "List application tables in the configured SQLite database",
            json!({
                "type": "object",
                "properties": {
                    "txn_id": { "type": "string", "description": "Active transaction id when introspecting inside a transaction" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "tables": { "type": "array", "description": "Tables in the main database" }
                }
            }),
            "sqlite.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Use to discover tables in the configured SQLite database.".into(),
                common_mistakes: vec!["Expecting attached databases to appear in the first slice.".into()],
                examples: vec![r#"{"scope":"main"}"#.into()],
                related: vec![CapabilityId::from_static("sqlite.read")],
            },
        ),
        op_info(
            "sqlite.schema.columns",
            "Describe the columns for a SQLite table",
            json!({
                "type": "object",
                "required": ["table"],
                "properties": {
                    "table": { "type": "string", "description": "Table name" },
                    "txn_id": { "type": "string", "description": "Active transaction id when introspecting inside a transaction" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "columns": { "type": "array", "description": "Detailed column metadata" }
                }
            }),
            "sqlite.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Use to inspect the declared schema for a specific SQLite table.".into(),
                common_mistakes: vec!["Requesting columns for a non-existent table.".into()],
                examples: vec![r#"{"table":"tasks"}"#.into()],
                related: vec![CapabilityId::from_static("sqlite.read")],
            },
        ),
        op_info(
            "sqlite.transaction.begin",
            "Begin a SQLite transaction",
            json!({
                "type": "object",
                "properties": {
                    "mode": { "type": "string", "description": "Transaction mode: deferred, immediate, or exclusive" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "transaction": { "description": "Active transaction id and mode" }
                }
            }),
            "sqlite.write",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Use to start an explicit transaction before multiple related writes.".into(),
                common_mistakes: vec!["Starting a new transaction while one is already active.".into()],
                examples: vec![r#"{"mode":"immediate"}"#.into()],
                related: vec![CapabilityId::from_static("sqlite.write")],
            },
        ),
        op_info(
            "sqlite.transaction.commit",
            "Commit the active SQLite transaction",
            json!({
                "type": "object",
                "required": ["txn_id"],
                "properties": {
                    "txn_id": { "type": "string", "description": "Transaction id returned by sqlite.transaction.begin" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "result": { "description": "Commit status and transaction id" }
                }
            }),
            "sqlite.write",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Use to persist all writes performed inside the active transaction.".into(),
                common_mistakes: vec!["Committing with the wrong txn_id.".into()],
                examples: vec![r#"{"txn_id":"txn_01HZY7R5V8E4Q3"}"#.into()],
                related: vec![CapabilityId::from_static("sqlite.write")],
            },
        ),
        op_info(
            "sqlite.transaction.rollback",
            "Rollback the active SQLite transaction",
            json!({
                "type": "object",
                "required": ["txn_id"],
                "properties": {
                    "txn_id": { "type": "string", "description": "Transaction id returned by sqlite.transaction.begin" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "result": { "description": "Rollback status and transaction id" }
                }
            }),
            "sqlite.write",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Use to discard writes in the active SQLite transaction.".into(),
                common_mistakes: vec!["Rolling back a transaction that is no longer active.".into()],
                examples: vec![r#"{"txn_id":"txn_01HZY7R5V8E4Q3"}"#.into()],
                related: vec![CapabilityId::from_static("sqlite.write")],
            },
        ),
        op_info(
            "sqlite.batch",
            "Execute multiple SQLite statements atomically via a savepoint",
            json!({
                "type": "object",
                "required": ["statements"],
                "properties": {
                    "statements": { "type": "array", "description": "Statements to execute, each with sql and params" },
                    "txn_id": { "type": "string", "description": "Active transaction id when batching inside a transaction" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "results": { "description": "Per-statement execution results" }
                }
            }),
            "sqlite.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Use to run multiple related writes atomically in one SQLite batch.".into(),
                common_mistakes: vec!["Providing an empty batch.".into()],
                examples: vec![
                    r#"{"statements":[{"sql":"INSERT INTO tasks(name) VALUES (?1)","params":["write release notes"]},{"sql":"UPDATE counters SET value = value + 1 WHERE name = ?1","params":["tasks_created"]}]}"#
                        .into(),
                ],
                related: vec![CapabilityId::from_static("sqlite.write")],
            },
        ),
        op_info(
            "sqlite.health",
            "Run a local SQLite health probe",
            json!({
                "type": "object",
                "properties": {}
            }),
            json!({
                "type": "object",
                "properties": {
                    "health": { "description": "Health probe details for the configured database" }
                }
            }),
            "sqlite.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Use to confirm the configured SQLite database is reachable and responsive.".into(),
                common_mistakes: vec![
                    "Treating health success as proof that a specific table or pragma exists.".into(),
                ],
                examples: vec![r#"{"check":"local-database"}"#.into()],
                related: vec![CapabilityId::from_static("sqlite.read")],
            },
        ),
        op_info(
            "sqlite.vacuum",
            "Run VACUUM against the configured SQLite database",
            json!({
                "type": "object",
                "properties": {}
            }),
            json!({
                "type": "object",
                "properties": {
                    "result": { "description": "VACUUM completion result" }
                }
            }),
            "sqlite.admin",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Use to rebuild and compact the SQLite database when no transaction is active.".into(),
                common_mistakes: vec!["Running VACUUM while a transaction is active.".into()],
                examples: vec![r#"{"confirm":"compact-local-database"}"#.into()],
                related: vec![CapabilityId::from_static("sqlite.admin")],
            },
        ),
        op_info(
            "sqlite.pragma",
            "Read an allowlisted SQLite pragma value",
            json!({
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": { "type": "string", "description": "Allowlisted pragma name" },
                    "txn_id": { "type": "string", "description": "Active transaction id when reading pragmas inside a transaction" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "result": { "description": "Pragma query result" }
                }
            }),
            "sqlite.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Use to inspect safe SQLite configuration values such as journal_mode or user_version.".into(),
                common_mistakes: vec!["Trying to write a pragma via sqlite.pragma instead of using a supported admin flow.".into()],
                examples: vec![r#"{"name":"journal_mode"}"#.into()],
                related: vec![CapabilityId::from_static("sqlite.read")],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_database_path_allows_memory() {
        assert!(validate_database_path(":memory:").is_ok());
    }

    #[test]
    fn validate_database_path_rejects_parent_dir() {
        let error = validate_database_path("../secret.db").unwrap_err();
        assert!(error.contains(".."));
    }

    #[test]
    fn ensure_transaction_context_requires_matching_txn_id() {
        let mut connector = SqliteConnector::new();
        connector.active_transaction_id = Some("txn-123".into());

        let error = connector.ensure_transaction_context(None).unwrap_err();
        assert!(matches!(error, SqliteError::Transaction(_)));

        connector
            .ensure_transaction_context(Some("txn-123"))
            .unwrap();
    }

    #[test]
    fn sqlite_config_from_params_sets_defaults() {
        let config = SqliteConfig::from_params(&json!({
            "database_path": ":memory:"
        }))
        .unwrap();

        assert_eq!(config.database_path, ":memory:");
        assert!(!config.read_only);
        assert!(config.create_if_missing);
        assert_eq!(config.busy_timeout_ms, 5_000);
        assert!(config.enable_wal);
        assert!(config.enforce_foreign_keys);
    }

    #[test]
    fn operations_include_first_slice_sqlite_surface() {
        let ids = operations_info()
            .into_iter()
            .map(|operation| operation.id.to_string())
            .collect::<Vec<_>>();

        for expected in [
            "sqlite.query",
            "sqlite.execute",
            "sqlite.explain",
            "sqlite.schema.tables",
            "sqlite.schema.columns",
            "sqlite.transaction.begin",
            "sqlite.transaction.commit",
            "sqlite.transaction.rollback",
            "sqlite.batch",
            "sqlite.health",
            "sqlite.vacuum",
            "sqlite.pragma",
        ] {
            assert!(ids.iter().any(|id| id == expected), "missing {expected}");
        }
    }

    #[test]
    fn operation_hints_are_agent_actionable_and_synthetic() {
        let sensitive_markers = ["api_key", "password", "secret", "token", "@example.com"];

        for operation in operations_info() {
            assert!(
                !operation.ai_hints.when_to_use.trim().is_empty(),
                "{} must explain when to use the operation",
                operation.id
            );
            assert!(
                !operation.ai_hints.common_mistakes.is_empty(),
                "{} must document a concrete mistake",
                operation.id
            );
            assert!(
                !operation.ai_hints.examples.is_empty(),
                "{} must include a synthetic example",
                operation.id
            );
            for example in &operation.ai_hints.examples {
                let parsed = serde_json::from_str::<serde_json::Value>(example);
                assert!(
                    matches!(parsed.as_ref(), Ok(value) if value.is_object()),
                    "{} example should be a JSON object: {example}",
                    operation.id
                );
                let lower = example.to_ascii_lowercase();
                for marker in sensitive_markers {
                    assert!(
                        !lower.contains(marker),
                        "{} example should not include sensitive marker {marker}",
                        operation.id
                    );
                }
            }
        }
    }

    #[test]
    fn manifest_ai_hints_match_runtime_catalog() {
        let manifest = toml::from_str::<toml::Table>(include_str!("../manifest.toml"))
            .expect("SQLite manifest should parse as TOML");
        let operations = manifest
            .get("provides")
            .and_then(toml::Value::as_table)
            .and_then(|provides| provides.get("operations"))
            .and_then(toml::Value::as_table)
            .expect("SQLite manifest must declare operations");
        let runtime_ids = operations_info()
            .into_iter()
            .map(|operation| operation.id.to_string())
            .collect::<Vec<_>>();
        let sensitive_markers = ["api_key", "password", "secret", "token", "@example.com"];

        assert_eq!(operations.len(), runtime_ids.len());
        for (operation_id, operation) in operations {
            let operation = operation
                .as_table()
                .expect("manifest operation entry must be a table");
            let ai_hints = operation
                .get("ai_hints")
                .and_then(toml::Value::as_table)
                .expect("manifest operation must include ai_hints");
            assert!(
                runtime_ids.contains(operation_id),
                "manifest operation {operation_id} missing from runtime catalog"
            );
            assert!(
                ai_hints
                    .get("when_to_use")
                    .and_then(toml::Value::as_str)
                    .is_some_and(|when_to_use| !when_to_use.trim().is_empty()),
                "{operation_id} must explain when to use the operation"
            );
            let common_mistakes = ai_hints
                .get("common_mistakes")
                .and_then(toml::Value::as_array)
                .expect("manifest ai_hints must declare common_mistakes");
            assert!(
                common_mistakes
                    .iter()
                    .any(|mistake| mistake.as_str().is_some_and(|text| !text.trim().is_empty())),
                "{operation_id} must document a concrete mistake"
            );
            let examples = ai_hints
                .get("examples")
                .and_then(toml::Value::as_array)
                .expect("manifest ai_hints must declare examples");
            assert!(
                examples
                    .iter()
                    .any(|example| example.as_str().is_some_and(|text| !text.trim().is_empty())),
                "{operation_id} must include a synthetic example"
            );
            for example in examples {
                assert!(example.is_str(), "{operation_id} example must be a string");
                let example = example.as_str().unwrap_or("");
                let parsed = serde_json::from_str::<serde_json::Value>(example);
                assert!(
                    matches!(parsed.as_ref(), Ok(value) if value.is_object()),
                    "{operation_id} example should be a JSON object: {example}"
                );
                let lower = example.to_ascii_lowercase();
                for marker in sensitive_markers {
                    assert!(
                        !lower.contains(marker),
                        "{operation_id} example should not include sensitive marker {marker}"
                    );
                }
            }
        }
    }

    #[test]
    fn provisioning_readiness_marks_memory_mode_as_ready() {
        let readiness = SqliteConfig {
            database_path: ":memory:".into(),
            read_only: false,
            create_if_missing: true,
            busy_timeout_ms: 5_000,
            enable_wal: true,
            enforce_foreign_keys: true,
        }
        .provisioning_readiness();

        assert_eq!(readiness.path_kind, "memory");
        assert!(readiness.filesystem_ready);
        assert!(!readiness.wal_possible);
    }

    #[test]
    fn provisioning_readiness_rejects_missing_read_only_file() {
        let readiness = SqliteConfig {
            database_path: "missing.sqlite".into(),
            read_only: true,
            create_if_missing: false,
            busy_timeout_ms: 5_000,
            enable_wal: false,
            enforce_foreign_keys: true,
        }
        .provisioning_readiness();

        assert!(!readiness.filesystem_ready);
        assert!(readiness.filesystem_message.contains("read_only"));
    }

    #[test]
    fn operator_guidance_uses_rch_commands() {
        let guidance = operator_guidance();
        assert!(
            guidance
                .rerun_commands
                .iter()
                .all(|command| command.starts_with("rch exec -- cargo "))
        );
    }
}
