//! FCP `MongoDB` Connector implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_core::{BaseConnector, ConnectorId, CredentialId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, MongoDbAuth, MongoDbClient},
    error::MongoDbError,
};

/// Parsed and validated `MongoDB` connector configuration.
#[derive(Debug, Clone)]
struct MongoDbConfig {
    auth: MongoDbAuth,
    base_url: String,
    data_source: String,
}

impl MongoDbConfig {
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
            (Some(key), None) => MongoDbAuth::ApiKey(key),
            (None, Some(cred_id)) => MongoDbAuth::CredentialId(cred_id),
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

        let data_source = params
            .get("data_source")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Cluster0")
            .to_string();

        Ok(Self {
            auth,
            base_url,
            data_source,
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

/// FCP `MongoDB` Connector.
pub struct MongoDbConnector {
    base: Arc<BaseConnector>,
    config: Option<MongoDbConfig>,
    client: Option<Arc<MongoDbClient>>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl MongoDbConnector {
    /// Create a new `MongoDB` connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("mongodb"))),
            config: None,
            client: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for MongoDbConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl MongoDbConnector {
    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = MongoDbConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, data_source = %config.data_source, "Configuring MongoDB connector");

        let client = MongoDbClient::new(config.auth.clone(), Some(&config.base_url))
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
            "connector_id": "fcp.mongodb",
            "connector_version": "0.1.0",
            "capabilities": [
                "mongodb.find_one",
                "mongodb.find",
                "mongodb.insert_one",
                "mongodb.insert_many",
                "mongodb.update_one",
                "mongodb.update_many",
                "mongodb.delete_one",
                "mongodb.delete_many",
                "mongodb.aggregate"
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
            "connector_id": "fcp.mongodb",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ready" } else { "unconfigured" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.mongodb",
            "version": "0.1.0",
            "operations": operations_info(),
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

        let data_source = self
            .config
            .as_ref()
            .map_or_else(|| "Cluster0".into(), |c| c.data_source.clone());

        let result = match operation {
            "mongodb.find_one" => self.invoke_find_one(client, &input, &data_source).await,
            "mongodb.find" => self.invoke_find(client, &input, &data_source).await,
            "mongodb.insert_one" => self.invoke_insert_one(client, &input, &data_source).await,
            "mongodb.insert_many" => self.invoke_insert_many(client, &input, &data_source).await,
            "mongodb.update_one" => self.invoke_update_one(client, &input, &data_source).await,
            "mongodb.update_many" => self.invoke_update_many(client, &input, &data_source).await,
            "mongodb.delete_one" => self.invoke_delete_one(client, &input, &data_source).await,
            "mongodb.delete_many" => self.invoke_delete_many(client, &input, &data_source).await,
            "mongodb.aggregate" => self.invoke_aggregate(client, &input, &data_source).await,
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
        info!("MongoDB connector shutting down");
        self.client = None;
        self.config = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_find_one(
        &self,
        client: &MongoDbClient,
        input: &serde_json::Value,
        data_source: &str,
    ) -> Result<serde_json::Value, MongoDbError> {
        let database = require_str(input, "database")?;
        let collection = require_str(input, "collection")?;
        let filter = input.get("filter").cloned().unwrap_or_else(|| json!({}));

        let body = json!({
            "dataSource": data_source,
            "database": database,
            "collection": collection,
            "filter": filter,
        });
        client.find_one(&body).await
    }

    async fn invoke_find(
        &self,
        client: &MongoDbClient,
        input: &serde_json::Value,
        data_source: &str,
    ) -> Result<serde_json::Value, MongoDbError> {
        let database = require_str(input, "database")?;
        let collection = require_str(input, "collection")?;
        let filter = input.get("filter").cloned().unwrap_or_else(|| json!({}));

        let mut body = json!({
            "dataSource": data_source,
            "database": database,
            "collection": collection,
            "filter": filter,
        });

        if let Some(limit) = input.get("limit") {
            body["limit"] = limit.clone();
        }
        if let Some(sort) = input.get("sort") {
            body["sort"] = sort.clone();
        }
        if let Some(projection) = input.get("projection") {
            body["projection"] = projection.clone();
        }

        client.find(&body).await
    }

    async fn invoke_insert_one(
        &self,
        client: &MongoDbClient,
        input: &serde_json::Value,
        data_source: &str,
    ) -> Result<serde_json::Value, MongoDbError> {
        let database = require_str(input, "database")?;
        let collection = require_str(input, "collection")?;
        let document = input.get("document").ok_or_else(|| MongoDbError::Api {
            status_code: 400,
            message: "Missing required field: document".into(),
        })?;

        let body = json!({
            "dataSource": data_source,
            "database": database,
            "collection": collection,
            "document": document,
        });
        client.insert_one(&body).await
    }

    async fn invoke_insert_many(
        &self,
        client: &MongoDbClient,
        input: &serde_json::Value,
        data_source: &str,
    ) -> Result<serde_json::Value, MongoDbError> {
        let database = require_str(input, "database")?;
        let collection = require_str(input, "collection")?;
        let documents = input.get("documents").ok_or_else(|| MongoDbError::Api {
            status_code: 400,
            message: "Missing required field: documents".into(),
        })?;

        let body = json!({
            "dataSource": data_source,
            "database": database,
            "collection": collection,
            "documents": documents,
        });
        client.insert_many(&body).await
    }

    async fn invoke_update_one(
        &self,
        client: &MongoDbClient,
        input: &serde_json::Value,
        data_source: &str,
    ) -> Result<serde_json::Value, MongoDbError> {
        let database = require_str(input, "database")?;
        let collection = require_str(input, "collection")?;
        let filter = input.get("filter").ok_or_else(|| MongoDbError::Api {
            status_code: 400,
            message: "Missing required field: filter".into(),
        })?;
        let update = input.get("update").ok_or_else(|| MongoDbError::Api {
            status_code: 400,
            message: "Missing required field: update".into(),
        })?;

        let body = json!({
            "dataSource": data_source,
            "database": database,
            "collection": collection,
            "filter": filter,
            "update": update,
        });
        client.update_one(&body).await
    }

    async fn invoke_update_many(
        &self,
        client: &MongoDbClient,
        input: &serde_json::Value,
        data_source: &str,
    ) -> Result<serde_json::Value, MongoDbError> {
        let database = require_str(input, "database")?;
        let collection = require_str(input, "collection")?;
        let filter = input.get("filter").ok_or_else(|| MongoDbError::Api {
            status_code: 400,
            message: "Missing required field: filter".into(),
        })?;
        let update = input.get("update").ok_or_else(|| MongoDbError::Api {
            status_code: 400,
            message: "Missing required field: update".into(),
        })?;

        let body = json!({
            "dataSource": data_source,
            "database": database,
            "collection": collection,
            "filter": filter,
            "update": update,
        });
        client.update_many(&body).await
    }

    async fn invoke_delete_one(
        &self,
        client: &MongoDbClient,
        input: &serde_json::Value,
        data_source: &str,
    ) -> Result<serde_json::Value, MongoDbError> {
        let database = require_str(input, "database")?;
        let collection = require_str(input, "collection")?;
        let filter = input.get("filter").ok_or_else(|| MongoDbError::Api {
            status_code: 400,
            message: "Missing required field: filter".into(),
        })?;

        let body = json!({
            "dataSource": data_source,
            "database": database,
            "collection": collection,
            "filter": filter,
        });
        client.delete_one(&body).await
    }

    async fn invoke_delete_many(
        &self,
        client: &MongoDbClient,
        input: &serde_json::Value,
        data_source: &str,
    ) -> Result<serde_json::Value, MongoDbError> {
        let database = require_str(input, "database")?;
        let collection = require_str(input, "collection")?;
        let filter = input.get("filter").ok_or_else(|| MongoDbError::Api {
            status_code: 400,
            message: "Missing required field: filter".into(),
        })?;

        let body = json!({
            "dataSource": data_source,
            "database": database,
            "collection": collection,
            "filter": filter,
        });
        client.delete_many(&body).await
    }

    async fn invoke_aggregate(
        &self,
        client: &MongoDbClient,
        input: &serde_json::Value,
        data_source: &str,
    ) -> Result<serde_json::Value, MongoDbError> {
        let database = require_str(input, "database")?;
        let collection = require_str(input, "collection")?;
        let pipeline = input.get("pipeline").ok_or_else(|| MongoDbError::Api {
            status_code: 400,
            message: "Missing required field: pipeline".into(),
        })?;

        let body = json!({
            "dataSource": data_source,
            "database": database,
            "collection": collection,
            "pipeline": pipeline,
        });
        client.aggregate(&body).await
    }
}

/// Extract a required string field from input.
fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> Result<&'a str, MongoDbError> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| MongoDbError::Api {
            status_code: 400,
            message: format!("Missing required field: {field}"),
        })
}

/// Build the operations info for introspection.
fn operations_info() -> serde_json::Value {
    json!([
        {
            "id": "mongodb.find_one",
            "summary": "Find a single document in a collection",
            "capability": "mongodb.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "mongodb.find",
            "summary": "Find documents in a collection",
            "capability": "mongodb.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
        {
            "id": "mongodb.insert_one",
            "summary": "Insert a single document into a collection",
            "capability": "mongodb.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "mongodb.insert_many",
            "summary": "Insert multiple documents into a collection",
            "capability": "mongodb.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "mongodb.update_one",
            "summary": "Update a single document in a collection",
            "capability": "mongodb.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "mongodb.update_many",
            "summary": "Update multiple documents in a collection",
            "capability": "mongodb.write",
            "risk_level": "medium",
            "safety_tier": "risky",
            "idempotency": "none",
        },
        {
            "id": "mongodb.delete_one",
            "summary": "Delete a single document from a collection",
            "capability": "mongodb.write",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "none",
        },
        {
            "id": "mongodb.delete_many",
            "summary": "Delete multiple documents from a collection",
            "capability": "mongodb.write",
            "risk_level": "high",
            "safety_tier": "dangerous",
            "idempotency": "none",
        },
        {
            "id": "mongodb.aggregate",
            "summary": "Run an aggregation pipeline on a collection",
            "capability": "mongodb.read",
            "risk_level": "low",
            "safety_tier": "safe",
            "idempotency": "strict",
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_api_key() {
        let config = MongoDbConfig::from_params(&json!({
            "api_key": "test-api-key",
        }))
        .unwrap();
        assert!(matches!(config.auth, MongoDbAuth::ApiKey(_)));
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(config.data_source, "Cluster0");
    }

    #[test]
    fn config_from_credential_id() {
        let config = MongoDbConfig::from_params(&json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }))
        .unwrap();
        assert!(config.auth.is_secretless());
    }

    #[test]
    fn config_custom_base_url() {
        let config = MongoDbConfig::from_params(&json!({
            "api_key": "key",
            "base_url": "https://data.mongodb-api.com/app/my-app/endpoint/data/v1",
        }))
        .unwrap();
        assert_eq!(
            config.base_url,
            "https://data.mongodb-api.com/app/my-app/endpoint/data/v1"
        );
    }

    #[test]
    fn config_custom_data_source() {
        let config = MongoDbConfig::from_params(&json!({
            "api_key": "key",
            "data_source": "MyAtlasCluster",
        }))
        .unwrap();
        assert_eq!(config.data_source, "MyAtlasCluster");
    }

    #[test]
    fn config_rejects_both_auth_methods() {
        let result = MongoDbConfig::from_params(&json!({
            "api_key": "key",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_no_auth() {
        let result = MongoDbConfig::from_params(&json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_empty_api_key() {
        let result = MongoDbConfig::from_params(&json!({
            "api_key": "",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_whitespace_api_key() {
        let result = MongoDbConfig::from_params(&json!({
            "api_key": "   ",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_non_string_credential_id() {
        let result = MongoDbConfig::from_params(&json!({
            "credential_id": 12345,
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_invalid_uuid_credential_id() {
        let result = MongoDbConfig::from_params(&json!({
            "credential_id": "not-a-uuid",
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_str_present() {
        let input = json!({"database": "mydb"});
        assert_eq!(require_str(&input, "database").unwrap(), "mydb");
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
        let arr = ops.as_array().unwrap();
        assert_eq!(arr.len(), 9);
    }

    #[test]
    fn operations_all_have_required_fields() {
        let ops = operations_info();
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
        let ops = operations_info();
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
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let rl = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&rl), "invalid risk_level: {rl}");
        }
    }

    #[test]
    fn operations_safety_tiers_valid() {
        let valid = ["safe", "risky", "dangerous"];
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let st = op["safety_tier"].as_str().unwrap();
            assert!(valid.contains(&st), "invalid safety_tier: {st}");
        }
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn read_operations_are_safe() {
        let ops = operations_info();
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
        let ops = operations_info();
        let ids: Vec<&str> = ops
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["id"].as_str())
            .collect();
        assert!(ids.contains(&"mongodb.find_one"));
        assert!(ids.contains(&"mongodb.find"));
        assert!(ids.contains(&"mongodb.insert_one"));
        assert!(ids.contains(&"mongodb.insert_many"));
        assert!(ids.contains(&"mongodb.update_one"));
        assert!(ids.contains(&"mongodb.update_many"));
        assert!(ids.contains(&"mongodb.delete_one"));
        assert!(ids.contains(&"mongodb.delete_many"));
        assert!(ids.contains(&"mongodb.aggregate"));
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
    fn config_trims_api_key() {
        let config = MongoDbConfig::from_params(&json!({ "api_key": "  my_key  " })).unwrap();
        match &config.auth {
            MongoDbAuth::ApiKey(k) => assert_eq!(k, "my_key"),
            MongoDbAuth::CredentialId(_) => panic!("expected ApiKey"),
        }
    }

    #[test]
    fn operations_all_have_idempotency() {
        let ops = operations_info();
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
        let c = MongoDbConnector::default();
        assert!(c.config.is_none());
        assert!(c.client.is_none());
        assert!(c.session_id.is_none());
    }

    #[test]
    fn delete_operations_are_dangerous() {
        let ops = operations_info();
        for op in ops.as_array().unwrap() {
            let id = op["id"].as_str().unwrap();
            if id.contains("delete") {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "dangerous",
                    "delete op {id} should be dangerous"
                );
                assert_eq!(
                    op["risk_level"].as_str().unwrap(),
                    "high",
                    "delete op {id} should be high risk"
                );
            }
        }
    }

    #[test]
    fn config_default_data_source_is_cluster0() {
        let config = MongoDbConfig::from_params(&json!({ "api_key": "k" })).unwrap();
        assert_eq!(config.data_source, "Cluster0");
    }
}
